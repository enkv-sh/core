package gcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (reply *http.Response, err error) {
	if r.Body != nil {
		defer func() { err = errors.Join(err, r.Body.Close()) }()
	}
	return f(r)
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func apiFailure(status int, reason string) *http.Response {
	return response(status, fmt.Sprintf(`{"error":{"code":%d,"message":"bounded test only","errors":[{"reason":%q}]}}`, status, reason))
}

// Return the failure with the final bytes so the bounded reader must observe
// it, including when those bytes also exceed the requested object length.
type interruptedBody struct{ body string }

func (b *interruptedBody) Read(p []byte) (int, error) {
	n := copy(p, b.body)
	b.body = b.body[n:]
	if len(b.body) == 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

// full_only: false
func TestOwnedTransportSendsOnceOnLostReplyAndRedirect(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status, code int
		want         contract.WriteStatus
	}{
		{"lost reply", 0, 0, contract.WriteUnknown},
		{"redirect", 0, 0, contract.WriteUnknown},
		{"retryable response", 503, 503, contract.WriteUnknown},
		{"503 body 412", 503, 412, contract.WriteUnknown},
		{"503 body 403", 503, 403, contract.WriteUnknown},
		{"503 body 404", 503, 404, contract.WriteUnknown},
		{"exact 412", 412, 412, contract.WritePrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			var physical atomic.Int32
			var requestBytes atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				physical.Add(1)
				if r.Method != "POST" || r.ContentLength <= 0 || r.GetBody != nil {
					t.Error("physical request shape")
				}
				n, err := io.Copy(io.Discard, r.Body)
				requestBytes.Add(n)
				if err != nil {
					t.Error(err)
				}
				switch tc.name {
				case "lost reply":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					if err := conn.Close(); err != nil {
						t.Error(err)
					}
				case "redirect":
					w.Header().Set("Location", "https://storage.us-central1.rep.googleapis.com/upload/storage/v1/b/fixture-bucket/o")
					w.WriteHeader(307)
				default:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)
					if _, err := fmt.Fprintf(w, `{"error":{"code":%d,"errors":[{"reason":"conditionNotMet"}]}}`, tc.code); err != nil {
						t.Error(err)
					}
				}
			}))
			defer server.Close()
			creds := &credentials{}
			supplied := &http.Transport{}
			client, err := NewClient(supplied, creds)
			if err != nil {
				t.Fatal(err)
			}
			owned := client.http.Transport.(*singleSend).base.(*http.Transport)
			if owned == supplied || !owned.DisableKeepAlives || !owned.DisableCompression || owned.ForceAttemptHTTP2 || owned.Proxy != nil || owned.TLSNextProto == nil {
				t.Fatal("transport is not owned and bounded")
			}
			// These local routing and TLS changes exist only in this same-package test.
			// The exported constructor rejects both hooks in production.
			owned.TLSClientConfig.InsecureSkipVerify = true
			owned.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			s, err := NewStore(ctx, config(client))
			if err != nil {
				t.Fatal(err)
			}
			got := s.CompareAndSwap(ctx, s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "42"}, []byte("candidate"))
			if got.Status != tc.want {
				t.Fatal(got)
			}
			if physical.Load() != 1 || creds.calls != 1 {
				t.Fatalf("physical requests=%d credential resolutions=%d", physical.Load(), creds.calls)
			}
			data := snapshot()
			observedBytes := telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCompareAndSwap, "", "complete")
			if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreCompareAndSwap, "", "") != 1 || observedBytes != requestBytes.Load() || observedBytes <= int64(len("candidate")) {
				t.Fatalf("telemetry body bytes=%d, physical multipart bytes=%d", observedBytes, requestBytes.Load())
			}
		})
	}
}

// full_only: false
func TestSingleSendRejectsSecondAttemptAndCallerHeaders(t *testing.T) {
	calls := 0
	client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Range") != "" || r.Header.Get("X-Goog-User-Project") != "" || r.Header.Get("X-Goog-Encryption-Key") != "" || r.Header.Get("If-Match") != "" {
			t.Fatal("caller headers changed construction")
		}
		return response(200, "ok"), nil
	}), &credentials{})
	ctx, ok := client.begin(context.Background(), "storage.us-central1.rep.googleapis.com", 32)
	if !ok {
		t.Fatal("credential")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://storage.us-central1.rep.googleapis.com/download/storage/v1/b/fixture-bucket/o/fixture%2FHEAD", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Range", "X-Goog-User-Project", "X-Goog-Encryption-Key", "If-Match"} {
		request.Header.Set(name, "not admitted")
	}
	first, err := client.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Body.Close(); err != nil {
		t.Error(err)
	}
	if second, err := client.http.Do(request); err == nil {
		if err := second.Body.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("second SDK send was accepted")
	}
	if calls != 1 {
		t.Fatalf("physical attempts %d", calls)
	}
}

type traceCredentialFunc func(context.Context) (string, error)

func (f traceCredentialFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

type traceBaggageKey struct{}

// full_only: false
func TestPrivateRequestsExcludeCallerTracingAndPreserveTelemetry(t *testing.T) {
	for _, mode := range []string{"candidate-head", "candidate-configuration", "candidate-root", "store-read", "store-write", "trust-sign", "service-error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			parent, snapshot := collectTelemetry(t)
			var hooks atomic.Int32
			parent = httptrace.WithClientTrace(context.WithValue(parent, traceBaggageKey{}, "caller-value"), &httptrace.ClientTrace{
				WroteHeaderField: func(string, []string) { hooks.Add(1) },
				ConnectStart:     func(string, string) { hooks.Add(1) },
			})
			ctx, cancel := context.WithTimeout(parent, 5*time.Second)
			defer cancel()
			credentialCalls := 0
			credential := traceCredentialFunc(func(private context.Context) (string, error) {
				credentialCalls++
				if httptrace.ContextClientTrace(private) != nil || private.Value(traceBaggageKey{}) != nil {
					t.Error("credential acquisition inherits caller callbacks/baggage")
				}
				if got, ok := private.Deadline(); !ok {
					t.Error("private deadline absent")
				} else if want, _ := ctx.Deadline(); !got.Equal(want) {
					t.Error("private deadline changed")
				}
				return "dummy-bearer", nil
			})
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer dummy-bearer" {
					t.Error("authentication absent")
				}
				if mode == "service-error" {
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `{}`)
					return
				}
				if mode == "store-write" || mode == "trust-sign" {
					_, _ = io.Copy(io.Discard, r.Body)
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `{}`)
					return
				}
				w.Header().Set("X-Goog-Generation", "24")
				_, _ = io.WriteString(w, "head")
			}))
			defer server.Close()
			client := makeClient(server.Client().Transport, credential)
			owned := client.http.Transport.(*singleSend).base.(*http.Transport)
			// The production guard still fixes the logical HTTPS host. This
			// test routes it to a loopback certificate with a different name.
			owned.TLSClientConfig.InsecureSkipVerify = true
			owned.DialContext = func(c context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(c, network, server.Listener.Addr().String())
			}
			reader, err := NewCandidateReader(ctx, candidateConfig(client))
			if err != nil {
				t.Fatal(err)
			}
			store, err := NewStore(ctx, config(client))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "canceled" {
				cancel()
			}
			var got contract.ReadResult
			switch mode {
			case "candidate-configuration":
				got = reader.ReadConfiguration(ctx, contract.Hash([]byte("domain")), contract.Hash([]byte("store")))
			case "candidate-root":
				got = reader.ReadRoot(ctx, contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: contract.Hash([]byte("domain")), Object: contract.Hash([]byte("object")), Digest: contract.Hash([]byte("head")), Length: 4})
			case "store-read":
				got = store.Read(ctx, store.Descriptor().HeadKey, contract.MaxHeadLength)
			case "trust-sign":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				trust, err := NewTrust(ctx, trustConfig(client, public))
				if err != nil {
					t.Fatal(err)
				}
				if result := trust.Sign(ctx, signRequest(t)); result.Reason != contract.ReasonTransport {
					t.Fatal("sign failure changed result", result)
				}
			case "store-write":
				write := store.CompareAndSwap(ctx, store.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "24"}, []byte("new"))
				if write.Status != contract.WriteUnknown {
					t.Error("service error changed uncertainty", write)
				}
			default:
				got = reader.ReadHEAD(ctx)
			}
			if mode != "store-write" && mode != "trust-sign" {
				want := contract.ReadOK
				if mode == "service-error" || mode == "canceled" {
					want = contract.ReadUnavailable
				}
				if got.Status != want {
					t.Errorf("read=%+v want=%d", got, want)
				}
			}
			expected := 1
			if mode == "canceled" {
				expected = 0
			}
			op := telemetry.OpStoreRead
			if mode == "store-write" {
				op = telemetry.OpStoreCompareAndSwap
			}
			if mode == "trust-sign" {
				op = telemetry.OpTrustSign
			}
			if requests.Load() != int32(expected) || credentialCalls != expected || hooks.Load() != 0 || telemetrySum(snapshot(), telemetry.HTTPAttempts, op, "", "") != int64(expected) {
				t.Fatalf("requests=%d credentials=%d hooks=%d", requests.Load(), credentialCalls, hooks.Load())
			}
		})
	}
}
