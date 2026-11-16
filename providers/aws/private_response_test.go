package awsprovider

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	enkvcrypto "enkv.sh/crypto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// full_only: false
func TestPrivateResponseBoundariesAndCustody(t *testing.T) {
	for _, length := range []uint16{68, 100} {
		p := &privateDecrypt{selector: "selected", packetLength: length}
		raw := []byte(` {"Plaintext":"` + base64.StdEncoding.EncodeToString(make([]byte, length)) + `", "EncryptionAlgorithm":"RSAES_OAEP_SHA_256", "KeyId":"selected"}`)
		raw = append(raw, bytes.Repeat([]byte{' '}, 4096-len(raw))...)
		got, err := p.response(response(200, string(raw), nil))
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
		{"depth16", `{"__type":"AccessDeniedException","details":` + strings.Repeat("[", 15) + `0` + strings.Repeat("]", 15) + `}`, 0},
		{"depth17", `{"__type":"AccessDeniedException","details":` + strings.Repeat("[", 16) + `0` + strings.Repeat("]", 16) + `}`, privateLimit},
		{"nodes4096", `{"__type":"AccessDeniedException","details":[` + strings.Repeat("0,", 4090) + `0]}`, 0},
		{"nodes4097", `{"__type":"AccessDeniedException","details":[` + strings.Repeat("0,", 4091) + `0]}`, privateLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, kind := inspectPrivateError([]byte(tc.body))
			if kind != tc.want {
				t.Fatalf("kind=%d want=%d", kind, tc.want)
			}
		})
	}
	for _, body := range []string{`[]`, `null`, `{"__type":null}`, `{"__type":"AccessDeniedException"} {}`, `{"__type":"AccessDeniedException","message":{}}`} {
		p := &privateDecrypt{packetLength: 68}
		_, err := p.response(response(400, body, nil))
		if err == nil || privateStatus(err) != enkvcrypto.KeyUnknown {
			t.Fatal("malformed error became denial")
		}
	}
}

// full_only: false
func TestPrivateErrorNeverReachesSDKFormatter(t *testing.T) {
	binding := encryptionBinding(t)
	for _, tc := range []struct {
		name, discriminator, header, body string
		httpStatus                        int
		want                              enkvcrypto.KeyStatus
		kind                              privateFailure
	}{
		{name: "bare", discriminator: "AccessDeniedException", want: enkvcrypto.KeyDenied},
		{name: "kms-namespace", discriminator: "com.amazonaws.kms#AccessDeniedException", want: enkvcrypto.KeyDenied},
		{name: "other-namespace", discriminator: "smithy.example#AccessDeniedException", want: enkvcrypto.KeyDenied},
		{name: "suffix", discriminator: "AccessDeniedException:http://internal.example/private-sentinel", want: enkvcrypto.KeyDenied},
		{name: "namespace-and-suffix", discriminator: "smithy.example#AccessDeniedException:http://internal.example/private-sentinel", want: enkvcrypto.KeyDenied},
		{name: "normalized-agreement", discriminator: "smithy.example#AccessDeniedException", header: "AccessDeniedException:http://internal.example/private-sentinel", want: enkvcrypto.KeyDenied},
		{name: "normalized-header", discriminator: "AccessDeniedException", header: "smithy.example#AccessDeniedException:http://internal.example/private-sentinel", want: enkvcrypto.KeyDenied},
		{name: "normalized-mismatch", discriminator: "AccessDeniedException", header: "smithy.example#InvalidCiphertextException:http://internal.example/private-sentinel", want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "unknown-header", discriminator: "AccessDeniedException", header: "smithy.example#private-sentinel", want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "unknown", discriminator: "smithy.example#private-sentinel:http://internal.example/", want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "case-sensitive", discriminator: "accessdeniedexception", want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "multiple-hash", discriminator: "smithy.example#private-sentinel#AccessDeniedException", want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "empty-code", discriminator: "smithy.example#:AccessDeniedException", want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "trailing-code", discriminator: "AccessDeniedException private-sentinel", want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "wrong-status", discriminator: "AccessDeniedException", httpStatus: 500, want: enkvcrypto.KeyUnknown, kind: privateUnknownCode},
		{name: "authentication-failure", discriminator: "smithy.example#InvalidCiphertextException:http://internal.example/", want: enkvcrypto.KeyAuthenticationFailed},
		{name: "provider-unavailable", discriminator: "smithy.example#KMSInternalException:http://internal.example/", httpStatus: 500, want: enkvcrypto.KeyUnavailable},
		{name: "duplicate-code", body: `{"__type":"AccessDeniedException","__type":"AccessDeniedException","message":"private-sentinel"}`, want: enkvcrypto.KeyUnknown, kind: privateMalformed},
		{name: "wrong-type", body: `{"__type":123,"message":"private-sentinel"}`, want: enkvcrypto.KeyUnknown, kind: privateMalformed},
		{name: "trailing-object", body: `{"__type":"AccessDeniedException","message":"private-sentinel"} {}`, want: enkvcrypto.KeyUnknown, kind: privateMalformed},
		{name: "malformed-success", httpStatus: 200, body: `{"Plaintext":123456,"KeyId":"selected","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"}`, want: enkvcrypto.KeyUnknown, kind: privateMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := tc.httpStatus, tc.body
			if status == 0 {
				status = 400
			}
			if body == "" {
				body = `{"__type":"` + tc.discriminator + `","message":"private-sentinel","Details":{"secret":"private-sentinel"}}`
			}
			headers := http.Header{}
			if tc.header != "" {
				headers.Set("X-Amzn-ErrorType", tc.header)
			}
			c := encryptionConfig()
			p := &privateDecrypt{selector: "selected", packetLength: 68}
			ctx := operationContext(context.Background(), 4096)
			ctx.Value(attemptKey{}).(*attempt).private = p
			client := kms.New(kms.Options{Region: c.Region, Credentials: c.Credentials, Retryer: aws.NopRetryer{}, HTTPClient: ownedClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(status, body, headers.Clone()), nil }), "kms.us-east-1.amazonaws.com", c.Timeout)})
			out, err := client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String("selected"), CiphertextBlob: make([]byte, 384), EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256})
			var safe *privateResponseError
			if out != nil || !errors.As(err, &safe) || safe.httpStatus != status || safe.status != tc.want || strings.Contains(fmt.Sprintf("%+v", err), "private-sentinel") || p.raw != nil {
				t.Fatalf("private response outcome differs: safe=%+v expected=%d", safe, tc.want)
			}
			kind := tc.kind
			if kind == 0 {
				kind = privateProviderFailure
			}
			if safe.kind != kind {
				t.Fatalf("failure kind=%d expected=%d", safe.kind, kind)
			}
			calls := 0
			key, err := newKeyAccess(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(status, body, headers.Clone()), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := key.Decrypt(context.Background(), binding, make([]byte, 384), 68)
			uses := enkvcrypto.KeyUses{Unknown: 1}
			switch tc.want {
			case enkvcrypto.KeyDenied:
				uses = enkvcrypto.KeyUses{Denied: 1}
			case enkvcrypto.KeyAuthenticationFailed, enkvcrypto.KeyUnavailable:
				uses = enkvcrypto.KeyUses{Failed: 1}
			}
			if got.Status != tc.want || got.Uses != uses || len(got.Packet) != 0 || calls != 1 {
				t.Fatalf("private caller outcome=%+v expected status=%d uses=%+v calls=%d", got, tc.want, uses, calls)
			}
		})
	}
}

type privateJoinBody struct {
	entered, closed, release chan struct{}
	once                     sync.Once
}

func (b *privateJoinBody) Read([]byte) (int, error) { close(b.entered); <-b.release; return 0, io.EOF }
func (b *privateJoinBody) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

// full_only: false
func TestPrivateCancellationJoinsRequestOwners(t *testing.T) {
	body := &privateJoinBody{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = operationContext(ctx, 4096)
	ctx.Value(attemptKey{}).(*attempt).private = &privateDecrypt{packetLength: 68}
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://kms.us-east-1.amazonaws.com/", body)
	readDone := make(chan struct{})
	done := make(chan struct{})
	// The transport must establish its read before returning the lost reply.
	rt := privateReadStartTransport{body: body, readDone: readDone}
	go func() { _, _ = (boundedTransport{next: rt, host: r.URL.Host}).RoundTrip(r); close(done) }()
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

type privateReadStartTransport struct {
	body     *privateJoinBody
	readDone chan struct{}
}

func (s privateReadStartTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	go func() { _, _ = r.Body.Read(make([]byte, 1)); close(s.readDone) }()
	<-s.body.entered
	return nil, io.ErrUnexpectedEOF
}

// full_only: false
func TestPrivateDecryptRefusesBeforeCredentialAccess(t *testing.T) {
	b := encryptionBinding(t)
	c := encryptionConfig()
	calls := 0
	c.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		calls++
		return aws.Credentials{}, errors.New("private-sentinel")
	})
	k, err := newKeyAccess(c, roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("invalid call reached HTTP"); return nil, nil }))
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
	if calls != 0 {
		t.Fatal("invalid admission fetched credentials")
	}
}

// full_only: false
func TestPrivateRefusedTransportIsNotProviderAttempt(t *testing.T) {
	b := encryptionBinding(t)
	k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("refused route reached HTTP"); return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	k.client.Transport = boundedTransport{host: "refused-host", next: k.client.Transport}
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
	k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return response(400, `{"__type":"AccessDeniedException","message":"private-sentinel"}`, nil), nil
	}))
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
	k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return response(400, `{"__type":"AccessDeniedException","message":"private-sentinel"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := k.Qualify(ctx, b)
	if got.Status != enkvcrypto.KeyCancelled || got.Uses.Denied != 1 || got.Uses.Unknown != 0 {
		t.Fatal("qualification cancellation discarded authenticated denial evidence")
	}
}

// full_only: false
func TestPrivateDecryptProofPacket(t *testing.T) {
	b := encryptionBinding(t)
	packet := bytes.Repeat([]byte{0x2b}, 68)
	k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(200, `{"KeyId":"`+b.KeySelector+`","EncryptionAlgorithm":"RSAES_OAEP_SHA_256","Plaintext":"`+base64.StdEncoding.EncodeToString(packet)+`"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := k.Decrypt(context.Background(), b, make([]byte, 384), 68)
	if got.Status != enkvcrypto.KeyOK || !bytes.Equal(got.Packet, packet) || cap(got.Packet) != 68 || got.Uses.Completed != 1 {
		t.Fatal("proof packet or its exact owner refused")
	}
	clear(got.Packet[:cap(got.Packet)])
}
