package awsprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// full_only: false
func TestProductionTransportLostReplyAndRedirectNeverReplay(t *testing.T) {
	for _, mode := range []string{"lost-reply", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			var requests atomic.Int32
			c := testStoreConfig()
			c.Transport = testStoreTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "PUT" || r.Header.Get("If-Match") != `"old"` {
					t.Error("wrong physical request")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "frozen" {
					t.Error("incomplete physical body")
				}
				if mode == "redirect" {
					w.Header().Set("Location", "https://s3.us-east-1.amazonaws.com/redirected")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			}))
			s, err := NewStore(c)
			if err != nil {
				t.Fatal(err)
			}
			got := s.CompareAndSwap(ctx, s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"old"`}, []byte("frozen"))
			if got.Status != contract.WriteUnknown || requests.Load() != 1 {
				t.Fatalf("result=%+v physical requests=%d", got, requests.Load())
			}
			data := snapshot()
			if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreCompareAndSwap, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCompareAndSwap, "", "complete") != int64(len("frozen")) || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpStoreCompareAndSwap, "", "") != 0 {
				t.Fatal("telemetry differs from the physical request")
			}
		})
	}
}

// full_only: false
func TestProductionTransportConditionalPreconditionEvidence(t *testing.T) {
	for _, name := range []string{"bodyless", "empty-error", "contradictory-code", "malformed", "truncated"} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			c := testStoreConfig()
			c.Transport = testStoreTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "frozen" || r.Method != http.MethodPut || r.URL.Path != "/fixture-bucket/enkv/domain/HEAD" || r.Header.Get("If-Match") != `"original"` {
					t.Error("physical conditional request changed")
				}
				envelope := ""
				switch name {
				case "empty-error":
					envelope = "<Error><Code></Code></Error>"
				case "contradictory-code":
					envelope = "<Error><Code>AccessDenied</Code></Error>"
				case "malformed":
					envelope = "<Error><Code>PreconditionFailed"
				case "truncated":
					envelope = "<Error><Code>PreconditionFailed</Code></Error>"
				}
				length := len(envelope)
				if name == "truncated" {
					length++
				}
				w.Header().Set("Content-Length", strconv.Itoa(length))
				w.WriteHeader(http.StatusPreconditionFailed)
				if _, err := io.WriteString(w, envelope); err != nil {
					t.Error(err)
				}
			}))
			s, err := NewStore(c)
			if err != nil {
				t.Fatal(err)
			}
			got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"original"`}, []byte("frozen"))
			want := contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
			switch name {
			case "contradictory-code", "malformed":
				want = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
			case "truncated":
				want = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			}
			if got != want || requests.Load() != 1 {
				t.Fatalf("result=%+v want=%+v physical requests=%d", got, want, requests.Load())
			}
		})
	}
}

// full_only: false
func TestProductionTransportRejectsDuplicateGetObjectETags(t *testing.T) {
	for _, values := range [][]string{{`"one"`, `"two"`}, {`"same"`, `"same"`}} {
		t.Run(strings.Join(values, "/"), func(t *testing.T) {
			var requests atomic.Int32
			c := testStoreConfig()
			c.Transport = testStoreTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				for _, value := range values {
					w.Header().Add("ETag", value)
				}
				w.Header().Set("Content-Length", "4")
				_, _ = io.WriteString(w, "body")
			}))
			s, err := NewStore(c)
			if err != nil {
				t.Fatal(err)
			}
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 32)
			if got.Status != contract.ReadInvalid || got.Reason != contract.ReasonMalformed || got.Token != (contract.Token{}) || len(got.Body) != 0 || requests.Load() != 1 {
				t.Fatalf("result=%+v physical requests=%d", got, requests.Load())
			}
		})
	}
}

// full_only: false
func TestProductionTransportReadErrorBoundsNeverRetry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		code       string
		wantStatus contract.ReadStatus
		wantReason contract.Reason
	}{
		{"access", 403, "AccessDenied", contract.ReadUnavailable, contract.ReasonAccess},
		{"missing", 404, "NoSuchKey", contract.ReadMissing, contract.ReasonNone},
		{"server", 500, "InternalError", contract.ReadUnavailable, contract.ReasonTransport},
		{"oversized-error", 404, "NoSuchKey", contract.ReadUnavailable, contract.ReasonTransport},
		{"truncated-error", 404, "NoSuchKey", contract.ReadUnavailable, contract.ReasonTransport},
		{"oversized-object", 200, "", contract.ReadInvalid, contract.ReasonMalformed},
		{"truncated-object", 200, "", contract.ReadUnavailable, contract.ReasonTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			c := testStoreConfig()
			c.Transport = testStoreTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" || r.URL.Path != "/fixture-bucket/enkv/domain/HEAD" || r.Header.Get("Range") != "" {
					t.Error("wrong physical request")
				}
				body := "<Error><Code>" + tc.code + "</Code><Message>private diagnostic</Message></Error>"
				switch tc.name {
				case "oversized-error":
					body = "<Error><Code>NoSuchKey</Code><Message>" + strings.Repeat("x", 16<<10) + "</Message></Error>"
				case "oversized-object":
					body = strings.Repeat("x", 33)
				case "truncated-object":
					body = "body"
				}
				length := len(body)
				if strings.HasPrefix(tc.name, "truncated-") {
					length += 64
				}
				w.Header().Set("Content-Length", strconv.Itoa(length))
				w.Header().Set("ETag", "\"object\"")
				w.WriteHeader(tc.status)
				if _, err := io.WriteString(w, body); err != nil {
					t.Error(err)
				}
			}))
			s, err := NewStore(c)
			if err != nil {
				t.Fatal(err)
			}
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 32)
			if got.Status != tc.wantStatus || got.Reason != tc.wantReason || len(got.Body) != 0 || got.Token.Value != "" || requests.Load() != 1 {
				t.Fatalf("result=%+v physical requests=%d", got, requests.Load())
			}
		})
	}
}

// full_only: false
func TestProductionConstructorsEnforceTLSPolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	storeConfig := testStoreConfig()
	keyAccessConfig := encryptionConfig()
	trustConfig := TrustConfig{
		Region: storeConfig.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		PublicKeyDER: public, CredentialRoute: storeConfig.CredentialRoute, Credentials: storeConfig.Credentials, Timeout: storeConfig.Timeout,
	}
	constructors := map[string]func(*http.Transport, aws.CredentialsProvider) error{
		"store": func(transport *http.Transport, credentials aws.CredentialsProvider) error {
			config := storeConfig
			config.Transport, config.Credentials = transport, credentials
			_, err := NewStore(config)
			return err
		},
		"key-access": func(transport *http.Transport, credentials aws.CredentialsProvider) error {
			config := keyAccessConfig
			config.Transport, config.Credentials = transport, credentials
			_, err := NewKeyAccess(config)
			return err
		},
		"trust": func(transport *http.Transport, credentials aws.CredentialsProvider) error {
			config := trustConfig
			config.Transport, config.Credentials = transport, credentials
			_, err := NewTrust(config)
			return err
		},
	}
	constructors["candidate-reader"] = func(transport *http.Transport, credentials aws.CredentialsProvider) error {
		config := candidateConfig()
		config.Transport, config.Credentials = transport, credentials
		_, err := NewCandidateReader(config)
		return err
	}
	constructors["public-reader"] = func(transport *http.Transport, credentials aws.CredentialsProvider) error {
		config := storeConfig
		config.Transport, config.Credentials = transport, credentials
		_, err := NewPublicReader(config)
		return err
	}
	constructors["public-signing-anchor"] = func(transport *http.Transport, credentials aws.CredentialsProvider) error {
		_, err := NewPublicSigningAnchor(PublicSigningAnchorConfig{Role: contract.NormalSigningRole,
			Region: trustConfig.Region, KeyARN: trustConfig.KeyARN, CredentialRoute: trustConfig.CredentialRoute,
			Credentials: credentials, Transport: transport, Timeout: trustConfig.Timeout})
		return err
	}
	for name, construct := range constructors {
		for _, mode := range []string{"nil-tls", "ordinary", "restricted", "key-log", "deprecated-dial", "both-dials", "peer-verifier", "connection-verifier", "client-certificate", "client-certificate-callback", "session-cache", "random-source", "clock", "ech", "alpn", "old-minimum", "inverted-versions", "insecure-cipher", "server-name", "insecure-verification"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				credentials, dials := 0, 0
				provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					credentials++
					return aws.Credentials{AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret"}, nil
				})
				var keyLog bytes.Buffer
				transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials++
					return nil, io.ErrUnexpectedEOF
				}}
				if mode != "nil-tls" {
					transport.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool()}
				}
				switch mode {
				case "restricted":
					transport.TLSClientConfig.MinVersion = tls.VersionTLS13
					transport.TLSClientConfig.MaxVersion = tls.VersionTLS13
					transport.TLSClientConfig.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
					transport.TLSClientConfig.CurvePreferences = []tls.CurveID{tls.CurveP256}
				case "key-log":
					transport.TLSClientConfig.KeyLogWriter = &keyLog
				case "peer-verifier":
					transport.TLSClientConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return errors.New("private callback") }
				case "connection-verifier":
					transport.TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error { return errors.New("private callback") }
				case "client-certificate":
					transport.TLSClientConfig.Certificates = []tls.Certificate{{}}
				case "client-certificate-callback":
					transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
						return nil, errors.New("private callback")
					}
				case "session-cache":
					transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
				case "random-source":
					field := reflect.ValueOf(transport.TLSClientConfig).Elem().FieldByName("Rand")
					reader := reflect.ValueOf(rand.Reader)
					if !field.IsValid() || !field.CanSet() || !reader.Type().AssignableTo(field.Type()) {
						t.Fatal("TLS random-source fixture field changed")
					}
					field.Set(reader)
				case "clock":
					transport.TLSClientConfig.Time = time.Now
				case "ech":
					transport.TLSClientConfig.EncryptedClientHelloConfigList = []byte{1}
				case "alpn":
					transport.TLSClientConfig.NextProtos = []string{"h2"}
				case "old-minimum":
					transport.TLSClientConfig.MinVersion = tls.VersionTLS10
				case "inverted-versions":
					transport.TLSClientConfig.MinVersion = tls.VersionTLS13
					transport.TLSClientConfig.MaxVersion = tls.VersionTLS12
				case "insecure-cipher":
					transport.TLSClientConfig.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}
				case "server-name":
					transport.TLSClientConfig.ServerName = "other.invalid"
				case "insecure-verification":
					transport.TLSClientConfig.InsecureSkipVerify = true
				}
				if mode == "deprecated-dial" || mode == "both-dials" {
					transport.Dial = func(string, string) (net.Conn, error) { //nolint:staticcheck // Tests refusal of the deprecated hook.
						dials++
						return nil, io.ErrUnexpectedEOF
					}
					if mode == "deprecated-dial" {
						transport.DialContext = nil
					}
				}
				err := construct(transport, provider)
				if mode != "nil-tls" && mode != "ordinary" && mode != "restricted" {
					if !errors.Is(err, ErrConstruction) {
						t.Fatalf("unsupported TLS construction returned %v", err)
					}
				} else if err != nil {
					t.Fatalf("valid construction returned %v", err)
				}
				if credentials != 0 || dials != 0 || keyLog.Len() != 0 {
					t.Fatalf("construction side effects: credentials=%d dials=%d key-log-bytes=%d", credentials, dials, keyLog.Len())
				}
			})
		}
	}
}

// full_only: false
func TestProductionTransportOwnsOnlyAdmittedTLSState(t *testing.T) {
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{Raw: []byte("first"), RawSubject: []byte("first")})
	source := &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		CurvePreferences: []tls.CurveID{tls.CurveP256}, NextProtos: []string{"http/1.1"},
		SessionTicketsDisabled: true, DynamicRecordSizingDisabled: true,
	}
	owned, err := privateTransport(&http.Transport{TLSClientConfig: source})
	if err != nil {
		t.Fatal(err)
	}
	if owned.TLSClientConfig == source || owned.TLSClientConfig.RootCAs == roots {
		t.Fatal("transport retained caller-owned TLS state")
	}
	if owned.TLSClientConfig.MinVersion != tls.VersionTLS13 || owned.TLSClientConfig.MaxVersion != tls.VersionTLS13 || len(owned.TLSClientConfig.NextProtos) != 1 || owned.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatal("owned TLS policy differs")
	}
	if len(owned.TLSClientConfig.Certificates) != 0 || owned.TLSClientConfig.ClientSessionCache != nil || owned.TLSClientConfig.GetClientCertificate != nil || owned.TLSClientConfig.VerifyPeerCertificate != nil || owned.TLSClientConfig.VerifyConnection != nil || owned.TLSClientConfig.KeyLogWriter != nil {
		t.Fatal("transport inherited TLS callbacks or session state")
	}
	if len(owned.TLSClientConfig.CipherSuites) != 1 || owned.TLSClientConfig.CipherSuites[0] != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 || len(owned.TLSClientConfig.CurvePreferences) != 1 || owned.TLSClientConfig.CurvePreferences[0] != tls.CurveP256 || !owned.TLSClientConfig.SessionTicketsDisabled || !owned.TLSClientConfig.DynamicRecordSizingDisabled {
		t.Fatal("owned TLS restrictions differ")
	}
	before := owned.TLSClientConfig.RootCAs.Clone()
	roots.AddCert(&x509.Certificate{Raw: []byte("second"), RawSubject: []byte("second")})
	source.KeyLogWriter = io.Discard
	source.MinVersion, source.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	source.CipherSuites[0], source.CurvePreferences[0], source.NextProtos[0] = tls.TLS_RSA_WITH_RC4_128_SHA, tls.CurveP384, "h2"
	if !owned.TLSClientConfig.RootCAs.Equal(before) || owned.TLSClientConfig.KeyLogWriter != nil || owned.TLSClientConfig.MinVersion != tls.VersionTLS13 || owned.TLSClientConfig.MaxVersion != tls.VersionTLS13 || owned.TLSClientConfig.CipherSuites[0] != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 || owned.TLSClientConfig.CurvePreferences[0] != tls.CurveP256 || owned.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatal("caller mutation changed owned TLS state")
	}
}

// full_only: false
func TestProductionTransportPreservesTLSMinimumAtHandshake(t *testing.T) {
	for _, minimum := range []uint16{0, tls.VersionTLS13} {
		t.Run(strconv.Itoa(int(minimum)), func(t *testing.T) {
			var requests atomic.Int32
			c := testStoreConfig()
			c.Transport = testStoreTransportVersion(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.Header().Set("ETag", `"selected"`)
				_, _ = io.WriteString(w, "body")
			}), tls.VersionTLS12)
			c.Transport.TLSClientConfig.MinVersion = minimum
			store, err := NewStore(c)
			if err != nil {
				t.Fatal(err)
			}
			got := store.Read(context.Background(), store.Descriptor().HeadKey, 32)
			if minimum == 0 {
				if got.Status != contract.ReadOK || string(got.Body) != "body" || got.Token.Value != `"selected"` || requests.Load() != 1 {
					t.Fatalf("default TLS failed: result=%+v requests=%d", got, requests.Load())
				}
			} else if got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonTransport || len(got.Body) != 0 || requests.Load() != 0 {
				t.Fatalf("TLS minimum weakened: result=%+v requests=%d", got, requests.Load())
			}
		})
	}
}

func testStoreTransport(t *testing.T, handler http.Handler) *http.Transport {
	t.Helper()
	return testStoreTransportVersion(t, handler, 0)
}

func testStoreTransportVersion(t *testing.T, handler http.Handler, maximumVersion uint16) *http.Transport {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "s3.us-east-1.amazonaws.com"}, DNSNames: []string{"s3.us-east-1.amazonaws.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, MaxVersion: maximumVersion}
	server.StartTLS()
	t.Cleanup(server.Close)
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (reply *http.Response, err error) {
	if r.Body != nil {
		defer func() { err = errors.Join(err, r.Body.Close()) }()
	}
	return f(r)
}
func response(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

type countedBody struct {
	io.ReadCloser
	bytes  int
	closed bool
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes += n
	return n, err
}
func (b *countedBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

type failingBody struct{ data []byte }

func (b *failingBody) Read(p []byte) (int, error) {
	n := copy(p, b.data)
	b.data = nil
	return n, io.ErrUnexpectedEOF
}
func (*failingBody) Close() error { return nil }
