package recovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

func relayTestConfig() AWSRelayConfig {
	return AWSRelayConfig{Bucket: "bucket", Prefix: "prefix", Region: "us-east-1", Normal: installedarchive.SigningResource{Selector: "normal", Region: "us-east-1"}, Recovery: installedarchive.SigningResource{Selector: "recovery", Region: "us-east-1"}, AuthoritySelector: "authority", AuthorityRegion: "us-east-1", Requests: 3, ResponseBytes: 1024, BodyBytes: 4096}
}
func relayTestTransport(t *testing.T, address string, certificate []byte) *http.Transport {
	t.Helper()
	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}
}
func relayRequest(t *testing.T, transport *http.Transport, method, host, path, rawPath, query, target string, body []byte) int {
	t.Helper()
	q, err := http.NewRequestWithContext(t.Context(), method, "https://"+host+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	q.URL.RawPath, q.URL.RawQuery = rawPath, query
	q.Host = host
	q.Header.Set("Authorization", "local-signature")
	q.Header.Set("X-Amz-Target", target)
	q.Header.Set("X-Amz-Date", "20261002T000000Z")
	q.Header.Set("X-Amz-Security-Token", "local-session")
	q.Header.Set("X-Custom-Signed", "opaque value")
	q.Header.Set("Content-Type", "application/x-amz-json-1.1")
	response, err := transport.RoundTrip(q)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

// full_only: false
func TestAWSReadRelayPreservesSignedRequestAndFiniteForwarding(t *testing.T) {
	var sends atomic.Uint64
	config := relayTestConfig()
	type observed struct {
		method, host, path, rawPath, query, authorization, date, token, custom, target, contentType string
		length                                                                                      int64
		body                                                                                        []byte
	}
	observations := make(chan observed, 3)
	origin, certificate := startAWSRecoveryServer(t, []string{"s3.us-east-1.amazonaws.com", "kms.us-east-1.amazonaws.com"}, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		sends.Add(1)
		body, err := io.ReadAll(q.Body)
		if err != nil {
			t.Error(err)
		}
		observations <- observed{q.Method, q.Host, q.URL.Path, q.URL.RawPath, q.URL.RawQuery, q.Header.Get("Authorization"), q.Header.Get("X-Amz-Date"), q.Header.Get("X-Amz-Security-Token"), q.Header.Get("X-Custom-Signed"), q.Header.Get("X-Amz-Target"), q.Header.Get("Content-Type"), q.ContentLength, body}
		w.Header().Set("ETag", `"exact-token"`)
		w.WriteHeader(200)
		if _, err = w.Write([]byte("encrypted-response")); err != nil {
			t.Error(err)
		}
	}))
	outbound := relayTestTransport(t, origin.Listener.Addr().String(), certificate)
	relay, err := newAWSReadRelay(t, config, outbound)
	if err != nil {
		t.Fatal(err)
	}
	inbound := relayTestTransport(t, relay.Address(), relay.Certificate())
	defer inbound.CloseIdleConnections()
	for _, row := range []struct {
		method, host, path, rawPath, query, target string
		body                                       []byte
	}{
		{http.MethodGet, "s3.us-east-1.amazonaws.com", "/bucket/prefix/a/b", "/bucket/prefix/a%2Fb", "x-id=GetObject", "", nil},
		{http.MethodPost, "kms.us-east-1.amazonaws.com", "/", "", "", "TrentService.GetPublicKey", []byte(`{"KeyId":"normal"}`)},
		{http.MethodPost, "kms.us-east-1.amazonaws.com", "/", "", "", "TrentService.Decrypt", []byte(`{"KeyId":"authority","EncryptionAlgorithm":"RSAES_OAEP_SHA_256","CiphertextBlob":"AA=="}`)},
	} {
		if status := relayRequest(t, inbound, row.method, row.host, row.path, row.rawPath, row.query, row.target, row.body); status != 200 {
			t.Fatal("permitted request refused", status)
		}
		got := <-observations
		if got.method != row.method || got.host != row.host || got.path != row.path || got.rawPath != row.rawPath || got.query != row.query || got.authorization != "local-signature" || got.date != "20261002T000000Z" || got.token != "local-session" || got.custom != "opaque value" || got.target != row.target || got.contentType != "application/x-amz-json-1.1" || got.length != int64(len(row.body)) || !bytes.Equal(got.body, row.body) {
			t.Fatal("signature-relevant request changed")
		}
		clear(got.body)
	}
	if sends.Load() != 3 {
		t.Fatal("outbound physical count differs")
	}
	if status := relayRequest(t, inbound, http.MethodGet, "s3.us-east-1.amazonaws.com", "/bucket/prefix/HEAD", "", "", "", nil); status != 403 || sends.Load() != 3 {
		t.Fatal("finite cap sent another request")
	}
	counts := relay.Counts()
	if counts.Reads != 2 || counts.PublicLookups != 1 || counts.AuthorityDecrypts != 1 || counts.Unknown != 1 {
		t.Fatal("relay operation counters differ", counts)
	}
	requests, charged := relay.Usage()
	if requests != 3 || charged <= 3*1024 || charged > config.BodyBytes {
		t.Fatal("physical/body reservation differs")
	}
}

// full_only: false
func TestAWSReadRelayRefusesUnknownAndMutationsBeforeForward(t *testing.T) {
	var sends atomic.Uint64
	origin, certificate := startAWSRecoveryServer(t, []string{"s3.us-east-1.amazonaws.com", "kms.us-east-1.amazonaws.com"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { sends.Add(1); w.WriteHeader(200) }))
	relay, err := newAWSReadRelay(t, relayTestConfig(), relayTestTransport(t, origin.Listener.Addr().String(), certificate))
	if err != nil {
		t.Fatal(err)
	}
	// The relay's TLS is checked separately; classify controls call its handler
	// directly so an unapproved host reaches admission without a TLS name error.
	for _, row := range []struct{ name, method, host, path, query, target, body string }{
		{"write", "PUT", "s3.us-east-1.amazonaws.com", "/bucket/prefix/x", "", "", ""},
		{"delete", "DELETE", "s3.us-east-1.amazonaws.com", "/bucket/prefix/x", "", "", ""},
		{"list", "GET", "s3.us-east-1.amazonaws.com", "/bucket/prefix/x", "list-type=2", "", ""},
		{"other-prefix", "GET", "s3.us-east-1.amazonaws.com", "/bucket/other/x", "", "", ""},
		{"other-bucket", "GET", "s3.us-east-1.amazonaws.com", "/other/prefix/x", "", "", ""},
		{"other-host", "GET", "s3.us-east-1.amazonaws.com.evil", "/bucket/prefix/x", "", "", ""},
		{"sign", "POST", "kms.us-east-1.amazonaws.com", "/", "", "TrentService.Sign", `{"KeyId":"normal"}`},
		{"grant", "POST", "kms.us-east-1.amazonaws.com", "/", "", "TrentService.CreateGrant", `{"KeyId":"normal"}`},
		{"key", "POST", "kms.us-east-1.amazonaws.com", "/", "", "TrentService.DisableKey", `{"KeyId":"normal"}`},
		{"other-decrypt", "POST", "kms.us-east-1.amazonaws.com", "/", "", "TrentService.Decrypt", `{"KeyId":"reader","CiphertextBlob":"AA==","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"}`},
		{"unknown", "POST", "kms.us-east-1.amazonaws.com", "/", "", "TrentService.ListKeys", `{}`},
		{"duplicate-framing", "POST", "kms.us-east-1.amazonaws.com", "/", "", "TrentService.GetPublicKey", `{"KeyId":"normal"}{}`},
		{"redirect-target", "POST", "kms.us-east-1.amazonaws.com:443", "/", "", "TrentService.GetPublicKey", `{"KeyId":"normal"}`},
	} {
		t.Run(row.name, func(t *testing.T) {
			q := &http.Request{Method: row.method, Host: row.host, URL: &url.URL{Path: row.path, RawQuery: row.query}, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(row.body))}
			q = q.WithContext(t.Context())
			q.Header.Set("Authorization", "local-signature")
			q.Header.Set("X-Amz-Target", row.target)
			w := httptest.NewRecorder()
			relay.serve(w, q)
			if w.Code != 403 || sends.Load() != 0 {
				t.Fatal("refused request reached outbound transport")
			}
		})
	}
	requests, _ := relay.Usage()
	if requests != 0 {
		t.Fatal("refused request reserved an outbound send")
	}
	counts := relay.Counts()
	if counts.StoreWrites != 1 || counts.Delete != 1 || counts.Discovery != 1 || counts.Sign != 1 || counts.GrantChanges != 1 || counts.KeyChanges != 1 || counts.OtherDecrypts != 1 {
		t.Fatal("forbidden operation counters differ", counts)
	}
}

// full_only: false
func TestAWSReadRelaySeparatesInjectedDenialFromPhysicalSend(t *testing.T) {
	for _, name := range []string{"normal", "recovery", "authority", "later"} {
		t.Run(name, func(t *testing.T) {
			var sends atomic.Uint64
			origin, certificate := startAWSRecoveryServer(t, []string{"kms.us-east-1.amazonaws.com"}, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { sends.Add(1); w.WriteHeader(200) }))
			config := relayTestConfig()
			config.Requests = 10
			config.BodyBytes = 20 << 10
			target, key := "TrentService.GetPublicKey", "normal"
			count := 1
			switch name {
			case "normal":
				config.Policy.DenyNormal = true
			case "recovery":
				config.Policy.DenyRecovery = true
				key = "recovery"
			case "authority":
				config.Policy.DenyAuthority = true
				target, key = "TrentService.Decrypt", "authority"
			case "later":
				config.Policy.DenySecretOrdinal = 2
				target, key = "TrentService.Decrypt", "authority"
				count = 2
			}
			relay, err := newAWSReadRelay(t, config, relayTestTransport(t, origin.Listener.Addr().String(), certificate))
			if err != nil {
				t.Fatal(err)
			}
			inbound := relayTestTransport(t, relay.Address(), relay.Certificate())
			defer inbound.CloseIdleConnections()
			for i := 1; i <= count; i++ {
				body := []byte(`{"KeyId":"` + key + `"}`)
				if target == "TrentService.Decrypt" {
					body = []byte(`{"KeyId":"authority","EncryptionAlgorithm":"RSAES_OAEP_SHA_256","CiphertextBlob":"AA=="}`)
				}
				status := relayRequest(t, inbound, "POST", "kms.us-east-1.amazonaws.com", "/", "", "", target, body)
				want := 200
				if i == count {
					want = 403
				}
				if status != want {
					t.Fatal("injected disposition differs")
				}
			}
			evidence := relay.Evidence()
			if sends.Load() != uint64(count-1) || evidence.ReservedRequests != uint64(count-1) || evidence.Sent.Unknown != 0 {
				t.Fatal("injection counted as upstream send", evidence)
			}
			if name == "normal" && (evidence.Attempted.NormalLookups != 1 || evidence.Injected.NormalLookups != 1 || evidence.Sent.NormalLookups != 0) || name == "recovery" && evidence.Injected.RecoveryLookups != 1 || (name == "authority" || name == "later") && (evidence.Attempted.AuthorityDecrypts != uint64(count) || evidence.Injected.AuthorityDecrypts != 1 || evidence.Sent.AuthorityDecrypts != uint64(count-1)) {
				t.Fatal("operation epochs differ", evidence)
			}
		})
	}
}

// full_only: false
func TestAWSReadRelayJoinsSeparateExternalMutation(t *testing.T) {
	var mutated atomic.Uint64
	origin, certificate := startAWSRecoveryServer(t, []string{"kms.us-east-1.amazonaws.com"}, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { w.WriteHeader(200) }))
	config := relayTestConfig()
	config.AfterPublic = func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		mutated.Add(1)
		return nil
	}
	relay, err := newAWSReadRelay(t, config, relayTestTransport(t, origin.Listener.Addr().String(), certificate))
	if err != nil {
		t.Fatal(err)
	}
	inbound := relayTestTransport(t, relay.Address(), relay.Certificate())
	defer inbound.CloseIdleConnections()
	for range 2 {
		if status := relayRequest(t, inbound, "POST", "kms.us-east-1.amazonaws.com", "/", "", "", "TrentService.GetPublicKey", []byte(`{"KeyId":"normal"}`)); status != 200 {
			t.Fatal("public request refused")
		}
	}
	if mutated.Load() != 1 || relay.ExternalMutations() != 1 || relay.Evidence().Sent.NormalLookups != 2 || relay.Evidence().Attempted.Delete != 0 {
		t.Fatal("external mutation was not separately joined")
	}
}

// This upstream control returns a complete bounded body and fails only at close.
// The relay must not release its bytes, headers or post-public mutation.
type relayCloseFailure struct {
	*bytes.Reader
	closes uint8
}

func (body *relayCloseFailure) Close() error {
	body.closes++
	return errors.New("private upstream close detail")
}

type relayCloseFailureTransport struct{ body *relayCloseFailure }

func (transport relayCloseFailureTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(q.Context()); trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Private-Upstream": []string{"private"}}, Body: transport.body}, nil
}

// full_only: false
func TestReadRelaysRefuseResponseCloseFailure(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(map[contract.Family]string{contract.AWS: "aws", contract.GCP: "gcp"}[family], func(t *testing.T) {
			body := &relayCloseFailure{Reader: bytes.NewReader([]byte("private response bytes"))}
			outbound := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
			outbound.RegisterProtocol("https", relayCloseFailureTransport{body: body})
			var mutations uint8
			afterPublic := func(context.Context) error { mutations++; return nil }
			var relay parentReadRelay
			var serve http.HandlerFunc
			var err error
			host, path, query, target, requestBody := "kms.us-east-1.amazonaws.com", "/", "", "TrentService.GetPublicKey", `{"KeyId":"normal"}`
			if family == contract.AWS {
				config := relayTestConfig()
				config.AfterPublic = afterPublic
				owner, e := newAWSReadRelay(t, config, outbound)
				err = e
				relay = owner
				serve = owner.serve
			} else {
				normal := "projects/p/locations/us-central1/keyRings/r/cryptoKeys/normal/cryptoKeyVersions/1"
				transport, e := newGCPReadTransport(outbound, "bucket", "prefix", "us-central1", normal, "", 3, 4096, 1024)
				if e != nil {
					t.Fatal(e)
				}
				owner, e := newGCPReadRelay(t, GCPRelayConfig{Bucket: "bucket", Prefix: "prefix", Region: "us-central1", Normal: installedarchive.SigningResource{Selector: normal, Region: "us-central1"}, AuthoritySelector: "projects/p/locations/us-central1/keyRings/r/cryptoKeys/authority/cryptoKeyVersions/1", Requests: 3, BodyBytes: 4096, ResponseBytes: 1024, AfterPublic: afterPublic}, transport)
				err = e
				relay = owner
				serve = owner.serve
				host, path, query, target, requestBody = "us-central1-cloudkms.googleapis.com", "/v1/"+normal+"/publicKey", "alt=json&prettyPrint=false", "", ""
			}
			if err != nil {
				t.Fatal(err)
			}
			method := http.MethodPost
			if family == contract.GCP {
				method = http.MethodGet
			}
			q, err := http.NewRequestWithContext(t.Context(), method, "https://"+host+path, bytes.NewBufferString(requestBody))
			if err != nil {
				t.Fatal(err)
			}
			q.Host = host
			q.URL.RawQuery = query
			q.Header.Set("Authorization", "synthetic")
			q.Header.Set("X-Amz-Target", target)
			result := httptest.NewRecorder()
			serve(result, q)
			if result.Code != http.StatusBadGateway || result.Header().Get("X-Private-Upstream") != "" || bytes.Contains(result.Body.Bytes(), []byte("private response bytes")) || bytes.Contains(result.Body.Bytes(), []byte("private upstream close detail")) {
				t.Fatal("incomplete private response was forwarded")
			}
			evidence := relay.Evidence()
			if body.closes != 1 || mutations != 0 || relay.ExternalMutations() != 0 || evidence.Failures != 1 || evidence.Attempted.NormalLookups != 1 || evidence.Sent.NormalLookups != 1 || evidence.ReservedRequests != 1 {
				t.Fatal("response failure completion or physical evidence differs", evidence)
			}
		})
	}
}
