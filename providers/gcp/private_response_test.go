package gcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/providers/gcp/internal/httptransport"
	"google.golang.org/api/cloudkms/v1"
)

// full_only: false
func TestPrivateResponseBoundariesAndCustody(t *testing.T) {
	for _, length := range []uint16{68, 100} {
		p := &privateDecrypt{protection: "HSM", packetLength: length}
		packet := make([]byte, length)
		raw := []byte(` {"plaintext":"` + base64.StdEncoding.EncodeToString(packet) + `", "plaintextCrc32c":"` + strconv.FormatUint(uint64(crc(packet)), 10) + `", "verifiedCiphertextCrc32c":true,"protectionLevel":"HSM"}`)
		raw = append(raw, bytes.Repeat([]byte{' '}, 4096-len(raw))...)
		got, err := p.response(response(200, string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		original := p.raw[:cap(p.raw)]
		body, err := io.ReadAll(got.Body)
		if err != nil || !bytes.Equal(raw, body) {
			t.Fatal("success bytes changed before SDK")
		}
		p.clear()
		if !bytes.Equal(original, make([]byte, len(original))) || p.raw != nil {
			t.Fatal("owned raw capacity not cleared")
		}
	}
	for _, tc := range []struct {
		name, body string
		want       privateFailure
	}{
		{"depth16", `{"error":{"code":403,"status":"PERMISSION_DENIED","details":` + strings.Repeat("[", 14) + `0` + strings.Repeat("]", 14) + `}}`, 0},
		{"depth17", `{"error":{"code":403,"status":"PERMISSION_DENIED","details":` + strings.Repeat("[", 15) + `0` + strings.Repeat("]", 15) + `}}`, privateLimit},
		{"nodes4096", `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[` + strings.Repeat("0,", 4086) + `0]}}`, 0},
		{"nodes4097", `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[` + strings.Repeat("0,", 4087) + `0]}}`, privateLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, kind := inspectPrivateError([]byte(tc.body))
			if kind != tc.want {
				t.Fatalf("kind=%d want=%d", kind, tc.want)
			}
		})
	}
	for _, body := range []string{`[]`, `null`, `{"error":null}`, `{"error":{"code":403,"status":"PERMISSION_DENIED"}} {}`, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":{}}}`} {
		p := &privateDecrypt{packetLength: 68}
		_, err := p.response(response(403, body))
		if err == nil || privateStatus(err) != enkvcrypto.KeyUnknown {
			t.Fatal("malformed error became denial")
		}
	}
}

// full_only: false
func TestPrivateErrorNeverReachesSDKFormatter(t *testing.T) {
	for _, body := range []string{`{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel","details":[{"secret":"private-sentinel"}]}}`, `{"error":{"code":403,"status":"private-sentinel","message":"private-sentinel"}}`, `{"plaintext":123456,"protectionLevel":"SOFTWARE"}`} {
		status := 403
		if strings.Contains(body, "plaintext") {
			status = 200
		}
		c := makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(status, body), nil }), &credentials{})
		k, err := NewKeyAccess(context.Background(), encryptionConfig(c))
		if err != nil {
			t.Fatal(err)
		}
		p := &privateDecrypt{packetLength: 68, protection: "SOFTWARE"}
		ctx, ok := c.begin(context.Background(), k.host, 4096)
		if !ok {
			t.Fatal("credential setup")
		}
		ctx.Value(operationKey{}).(*operation).private = p
		out, err := k.service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricDecrypt("projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", &cloudkms.AsymmetricDecryptRequest{Ciphertext: base64.StdEncoding.EncodeToString(make([]byte, 384))}).Context(ctx).Do()
		var safe *privateResponseError
		if out != nil || !errors.As(err, &safe) || safe.httpStatus != status || strings.Contains(fmt.Sprintf("%+v", err), "private-sentinel") || p.raw != nil {
			t.Fatal("raw private failure escaped the transport")
		}
	}
}

// full_only: false
func TestPrivateDecryptZeroCRCPresence(t *testing.T) {
	b := encryptionBinding(t)
	// These CRC32C zero suffixes were independently solved with the reflected
	// 0x82f63b78 polynomial, starting from all zero bytes.
	ciphertext := make([]byte, 384)
	copy(ciphertext[380:], []byte{0x46, 0x03, 0x5d, 0x6f})
	for _, tc := range []struct {
		length int
		suffix []byte
	}{{68, []byte{0xcc, 0x70, 0x28, 0x98}}, {100, []byte{0x00, 0x9f, 0x12, 0xca}}} {
		packet := make([]byte, tc.length)
		copy(packet[tc.length-4:], tc.suffix)
		if crc(ciphertext) != 0 || crc(packet) != 0 {
			t.Fatal("independent zero CRC fixture changed")
		}
		k, err := NewKeyAccess(context.Background(), encryptionConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var fields map[string]json.RawMessage
			if json.NewDecoder(r.Body).Decode(&fields) != nil || string(fields["ciphertextCrc32c"]) != `"0"` {
				t.Fatal("zero request CRC omitted")
			}
			return response(200, `{"plaintext":"`+base64.StdEncoding.EncodeToString(packet)+`","plaintextCrc32c":"0","verifiedCiphertextCrc32c":true,"protectionLevel":"SOFTWARE"}`), nil
		}), &credentials{})))
		if err != nil {
			t.Fatal(err)
		}
		got := k.Decrypt(context.Background(), b, ciphertext, uint16(tc.length))
		if got.Status != enkvcrypto.KeyOK || !bytes.Equal(got.Packet, packet) {
			t.Fatal("zero CRC packet refused")
		}
		clear(got.Packet[:cap(got.Packet)])
	}
}

type privateJoinBody struct {
	entered, closed, release chan struct{}
	once                     sync.Once
}

func (b *privateJoinBody) Read([]byte) (int, error) { close(b.entered); <-b.release; return 0, io.EOF }
func (b *privateJoinBody) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

type privateReadStartTransport struct {
	body     *privateJoinBody
	readDone chan struct{}
}

func (s privateReadStartTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// The single-send wrapper materialized the ciphertext. Substitute only the
	// controlled network reader, inside its existing completion tracker.
	r.Body.(*httptransport.RequestCompletion).ReadCloser = s.body
	go func() { _, _ = r.Body.Read(make([]byte, 1)); close(s.readDone) }()
	<-s.body.entered
	return nil, io.ErrUnexpectedEOF
}

// full_only: false
func TestPrivateCancellationJoinsRequestOwners(t *testing.T) {
	body := &privateJoinBody{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	op := &operation{host: "us-central1-cloudkms.googleapis.com", token: "fixture-token", limit: 4096, private: &privateDecrypt{packetLength: 68}}
	ctx = context.WithValue(ctx, operationKey{}, op)
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://us-central1-cloudkms.googleapis.com/v1/key:asymmetricDecrypt", strings.NewReader("{}"))
	readDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_, _ = (&singleSend{base: privateReadStartTransport{body: body, readDone: readDone}}).RoundTrip(r)
		close(done)
	}()
	<-body.entered
	cancel()
	<-body.closed
	select {
	case <-done:
		t.Fatal("cancel released an active request owner")
	case <-time.After(20 * time.Millisecond):
	}
	close(body.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request owner did not join")
	}
	<-readDone
}

// full_only: false
func TestPrivateDecryptRefusesBeforeCredentialAccess(t *testing.T) {
	b := encryptionBinding(t)
	creds := &credentials{}
	k, err := NewKeyAccess(context.Background(), encryptionConfig(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("invalid call reached HTTP"); return nil, nil }), creds)))
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []uint16{0, 67, 69, 99, 101} {
		if got := k.Decrypt(context.Background(), b, make([]byte, 384), length); got.Status != enkvcrypto.KeyInvalid {
			t.Fatal("invalid packet size accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := k.Decrypt(ctx, b, make([]byte, 384), 68); got.Status != enkvcrypto.KeyCancelled || got.Uses != (enkvcrypto.KeyUses{}) {
		t.Fatal("pre-call cancellation gained evidence")
	}
	if creds.calls != 0 {
		t.Fatal("invalid admission fetched credentials")
	}
}

// full_only: false
func TestPrivateRefusedTransportIsNotProviderAttempt(t *testing.T) {
	b := encryptionBinding(t)
	k, err := NewKeyAccess(context.Background(), encryptionConfig(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("refused route reached HTTP"); return nil, nil }), &credentials{})))
	if err != nil {
		t.Fatal(err)
	}
	k.host = "refused-host"
	got := k.Decrypt(context.Background(), b, make([]byte, 384), 68)
	if got.Status != enkvcrypto.KeyUnavailable || got.Uses != (enkvcrypto.KeyUses{}) {
		t.Fatal("transport refusal was counted as provider work")
	}
}

// full_only: false
func TestPrivateCancellationPreservesObservedDenial(t *testing.T) {
	b := encryptionBinding(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k, err := NewKeyAccess(context.Background(), encryptionConfig(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return response(403, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel"}}`), nil
	}), &credentials{})))
	if err != nil {
		t.Fatal(err)
	}
	got := k.Decrypt(ctx, b, make([]byte, 384), 68)
	if got.Status != enkvcrypto.KeyCancelled || got.Uses.Denied != 1 || got.Uses.Unknown != 0 || len(got.Packet) != 0 {
		t.Fatal("cancellation discarded authenticated denial evidence")
	}
}

// full_only: false
func TestKeyAccessCancellationPreservesObservedDenial(t *testing.T) {
	b := encryptionBinding(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k, err := NewKeyAccess(context.Background(), encryptionConfig(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return response(403, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel"}}`), nil
	}), &credentials{})))
	if err != nil {
		t.Fatal(err)
	}
	got := k.Qualify(ctx, b)
	if got.Status != enkvcrypto.KeyCancelled || got.Uses.Denied != 1 || got.Uses.Unknown != 0 {
		t.Fatal("qualification cancellation discarded authenticated denial evidence")
	}
}
