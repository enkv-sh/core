package gcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

const tokenURL = "https://oauth2.googleapis.com/token"
const credentialTimeout = 30 * time.Second
const credentialLimit = 64 << 10

func serviceAccountFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func serviceAccountJSON(t *testing.T) (map[string]string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"type": "service_account", "client_email": "fixture@example.iam.gserviceaccount.com",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"private_key_id": "synthetic-key-id", "token_uri": tokenURL, "universe_domain": "googleapis.com",
	}, key
}

func serviceAccountPath(t *testing.T, fields map[string]string) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return serviceAccountFile(t, b)
}

// full_only: false
func TestServiceAccountFileValidatesKeyAndAuthenticationRoute(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	for _, field := range []string{"type", "client_email", "private_key", "token_uri", "universe_domain"} {
		t.Run(field, func(t *testing.T) {
			copy := maps.Clone(fields)
			copy[field] = "unsupported"
			if field == "client_email" {
				copy[field] = ""
			}
			if _, err := LoadServiceAccountFile(context.Background(), serviceAccountPath(t, copy)); err != ErrCredentials {
				t.Fatal("invalid file did not return redacted refusal")
			}
		})
	}
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing"), t.TempDir(), serviceAccountFile(t, []byte(strings.Repeat("x", 65537)))} {
		if _, err := LoadServiceAccountFile(context.Background(), path); err != ErrCredentials {
			t.Fatal("invalid file accepted")
		}
	}
	delete(fields, "universe_domain")
	if _, err := LoadServiceAccountFile(context.Background(), serviceAccountPath(t, fields)); err != nil {
		t.Fatal("standard default universe refused")
	}
}

// full_only: false
func TestServiceAccountFileRejectsRSAKeyBelow2048Bits(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	fields["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := LoadServiceAccountFile(context.Background(), serviceAccountPath(t, fields)); err != ErrCredentials {
		t.Fatal("RSA key below 2048 bits accepted")
	}
}

// full_only: false
func TestServiceAccountFileAcceptsSupportedRSAKeyEncodings(t *testing.T) {
	for _, bits := range []int{2048, 3072} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		for name, block := range map[string]*pem.Block{
			"pkcs8": {Type: "PRIVATE KEY", Bytes: pkcs8},
			"pkcs1": {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
		} {
			t.Run(fmt.Sprintf("%d/%s", bits, name), func(t *testing.T) {
				fields, _ := serviceAccountJSON(t)
				fields["private_key"] = string(pem.EncodeToMemory(block))
				p, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(*http.Request) (*http.Response, error) {
					return response(200, `{"access_token":"token","token_type":"Bearer","expires_in":3600}`), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				if token, err := p.Token(context.Background()); err != nil || token != "token" {
					t.Fatal("supported RSA key encoding did not authenticate")
				}
			})
		}
	}
}

// full_only: false
func TestServiceAccountFileAcceptsRSAKeyWithNonDefaultExponent(t *testing.T) {
	key := rsaKeyWithExponent(t, 2048, 3)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := serviceAccountJSON(t)
	fields["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	p, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(200, `{"access_token":"token","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if token, err := p.Token(context.Background()); err != nil || token != "token" {
		t.Fatal("supported RSA exponent did not authenticate")
	}
}

func rsaKeyWithExponent(t *testing.T, bits, exponent int) *rsa.PrivateKey {
	t.Helper()
	one := big.NewInt(1)
	for {
		generated, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		phi := new(big.Int).Mul(
			new(big.Int).Sub(generated.Primes[0], one),
			new(big.Int).Sub(generated.Primes[1], one),
		)
		d := new(big.Int).ModInverse(big.NewInt(int64(exponent)), phi)
		if d == nil {
			continue
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: generated.N, E: exponent},
			D:         d,
			Primes:    generated.Primes,
		}
		key.Precompute()
		if key.Validate() == nil {
			return key
		}
	}
}

// full_only: false
func TestServiceAccountFileSizeBoundary(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	exact := append(b, bytes.Repeat([]byte{' '}, credentialLimit-len(b))...)
	if len(exact) != credentialLimit {
		t.Fatal("invalid exact-boundary fixture")
	}
	if _, err := LoadServiceAccountFile(context.Background(), serviceAccountFile(t, exact)); err != nil {
		t.Fatal("exact credential-file boundary refused")
	}
	if _, err := LoadServiceAccountFile(context.Background(), serviceAccountFile(t, append(exact, ' '))); err != ErrCredentials {
		t.Fatal("credential file above boundary accepted")
	}
}

// full_only: false
func TestServiceAccountSignsAndRefreshesBeforeServiceRequests(t *testing.T) {
	fields, key := serviceAccountJSON(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", serviceAccountFile(t, []byte(`{"type":"authorized_user"}`)))
	authCalls, serviceCalls := 0, 0
	p, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		authCalls++
		if serviceCalls != authCalls-1 || r.URL.String() != tokenURL || r.GetBody != nil {
			t.Fatal("authentication occurred outside its operation boundary")
		}
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > credentialTimeout {
			t.Fatal("authentication request has no bounded deadline")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Fatal("missing signed assertion")
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal("invalid assertion signature encoding")
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) != nil {
			t.Fatal("assertion signature does not match file key")
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		if err != nil || json.Unmarshal(payload, &claims) != nil || claims["iss"] != fields["client_email"] || claims["aud"] != tokenURL || claims["scope"] != "https://www.googleapis.com/auth/cloud-platform" || claims["sub"] != nil {
			t.Fatal("assertion claims differ")
		}
		return response(200, fmt.Sprintf(`{"access_token":"token-%d","token_type":"Bearer","expires_in":1}`, authCalls)), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(context.Background(), config(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		serviceCalls++
		if authCalls != serviceCalls || r.Header.Get("Authorization") != fmt.Sprintf("Bearer token-%d", authCalls) {
			t.Fatal("service credentials were not frozen before send")
		}
		return apiFailure(401, "authError"), nil
	}), p)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		result := s.Create(context.Background(), childKey(s), []byte("plain"))
		if result.Status == contract.WriteAcknowledged || authCalls != i || serviceCalls != i {
			t.Fatal("service refusal triggered refresh or replay")
		}
	}
}

// full_only: false
func TestServiceAccountReusesUnexpiredToken(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	calls := 0
	p, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(200, `{"access_token":"cached-token","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if token, err := p.Token(context.Background()); err != nil || token != "cached-token" {
			t.Fatal("valid token was not returned")
		}
	}
	if calls != 1 {
		t.Fatal("fresh token caused another authentication request")
	}
}

// full_only: false
func TestServiceAccountRefreshBlocksAndHonorsCancellation(t *testing.T) {
	for _, caller := range []string{"Token", "Capture"} {
		t.Run(caller, func(t *testing.T) {
			fields, _ := serviceAccountJSON(t)
			started := make(chan struct{})
			var calls atomic.Int32
			p, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					return response(200, `{"access_token":"initial","token_type":"Bearer","expires_in":1}`), nil
				}
				close(started)
				<-r.Context().Done()
				return nil, r.Context().Err()
			}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Token(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if caller == "Token" {
					value, err := p.Token(ctx)
					if value != "" {
						t.Error("canceled refresh retained token")
					}
					done <- err
					return
				}
				value, expiry, err := CaptureServiceAccountTokenForTest(ctx, p)
				if value != "" || !expiry.IsZero() {
					t.Error("canceled refresh retained token facts")
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("refresh did not start")
			}
			select {
			case <-done:
				t.Fatal("stale token returned while refresh runs in background")
			default:
			}
			waiter, stop := context.WithCancel(context.Background())
			stop()
			if _, err := p.Token(waiter); !errors.Is(err, context.Canceled) {
				t.Fatal("canceled waiter did not stop")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("refresh did not preserve cancellation")
				}
			case <-time.After(time.Second):
				t.Fatal("canceled refresh still running")
			}
			if calls.Load() != 2 {
				t.Fatal("unexpected authentication request")
			}

		})
	}
}

// full_only: false
func TestServiceAccountTokenFailureDoesNotReachStore(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	path := serviceAccountPath(t, fields)
	for name, reply := range map[string]*http.Response{
		"denied":   response(401, `{"error":"private diagnostic"}`),
		"redirect": {StatusCode: 302, Header: http.Header{"Location": {"https://example.invalid/token"}}, Body: io.NopCloser(strings.NewReader(""))},
		"empty":    response(200, `{}`), "invalid-json": response(200, "private diagnostic"),
		"no-expiry":            response(200, `{"access_token":"value","token_type":"Bearer"}`),
		"wrong-type":           response(200, `{"access_token":"value","token_type":"other","expires_in":3600}`),
		"zero-expiry":          response(200, `{"access_token":"value","token_type":"Bearer","expires_in":0}`),
		"negative-expiry":      response(200, `{"access_token":"value","token_type":"Bearer","expires_in":-1}`),
		"excess-expiry":        response(200, `{"access_token":"value","token_type":"Bearer","expires_in":3601}`),
		"overflow-expiry":      response(200, `{"access_token":"value","token_type":"Bearer","expires_in":9223372036854775808}`),
		"unrequested-id-token": response(200, `{"access_token":"value","token_type":"Bearer","expires_in":1,"id_token":"unrequested"}`),
		"wrong-success-status": response(202, `{"access_token":"value","token_type":"Bearer","expires_in":3600}`),
		"oversized":            response(200, strings.Repeat("x", 65537)),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			p, err := LoadServiceAccountFileForTest(context.Background(), path, roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return reply, nil }))
			if err != nil {
				t.Fatal(err)
			}
			s, err := NewStore(context.Background(), config(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("failed authentication reached storage")
				return nil, nil
			}), p)))
			if err != nil {
				t.Fatal(err)
			}
			result := s.Create(context.Background(), childKey(s), []byte("plain"))
			if result.Status != contract.WriteRefused || result.Reason != contract.ReasonAccess || calls != 1 {
				t.Fatal("authentication failure did not stop the write")
			}
		})
	}
}

// full_only: false
func TestServiceAccountRejectsBadTokenBeforeCache(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	calls := 0
	p, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"access_token":"bad","token_type":"Bearer","expires_in":315360000}`), nil
		}
		return response(200, `{"access_token":"good","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if value, err := p.Token(context.Background()); err == nil || value != "" || calls != 1 {
		t.Fatalf("bad token reached cache: value=%q err=%v requests=%d", value, err, calls)
	}
	for i := 0; i < 2; i++ {
		if value, err := p.Token(context.Background()); err != nil || value != "good" {
			t.Fatalf("corrected token refused: value=%q err=%v", value, err)
		}
	}
	if calls != 2 {
		t.Fatalf("valid token was not cached: requests=%d", calls)
	}
}

// full_only: false
func TestServiceAccountDebugLoggingDoesNotExposeCredentials(t *testing.T) {
	if os.Getenv("ENKV_AUTH_LOG_CHILD") == "1" {
		fields, _ := serviceAccountJSON(t)
		path := serviceAccountPath(t, fields)
		for _, status := range []int{200, 400} {
			p, err := LoadServiceAccountFileForTest(context.Background(), path, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(status, `{"access_token":"synthetic-private-token","token_type":"Bearer","expires_in":3600,"error":"synthetic-private-error"}`), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Token(context.Background())
			if (status == 200 && err != nil) || (status != 200 && err != ErrCredentials) {
				t.Fatal("unexpected token result")
			}
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestServiceAccountDebugLoggingDoesNotExposeCredentials$")
	cmd.Env = append(os.Environ(), "ENKV_AUTH_LOG_CHILD=1", "GOOGLE_SDK_GO_LOGGING_LEVEL=debug")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("credential logging subprocess failed")
	}
	for _, forbidden := range []string{"synthetic-private", "synthetic-key-id", "2LO token", "access_token", "assertion", "eyJ"} {
		if strings.Contains(string(out), forbidden) {
			t.Fatal("credential material escaped to process output")
		}
	}
}

// full_only: false
func TestServiceAccountFileRejectsUnsupportedIdentity(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", serviceAccountFile(t, []byte(`{"type":"authorized_user"}`)))
	for _, value := range []string{"", "{", `{}`, `{"type":"authorized_user"}`, `{"type":"external_account"}`} {
		if _, err := LoadServiceAccountFile(context.Background(), serviceAccountFile(t, []byte(value))); !errors.Is(err, ErrCredentials) {
			t.Fatal("unsupported credential file did not refuse")
		}
	}
}

type credentials struct {
	calls int
	err   error
}

func (c *credentials) Token(context.Context) (string, error) {
	c.calls++
	return "fixture-token", c.err
}

// full_only: false
func TestCredentialsFailureBeforeSend(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	s, creds := newStore(t, func(*http.Request) (*http.Response, error) { t.Fatal("sent without credential"); return nil, nil })
	creds.err = errors.New("credential unavailable")
	if got := s.Create(ctx, childKey(s), []byte("x")); got.Status != contract.WriteRefused || got.Reason != contract.ReasonAccess {
		t.Fatal(got)
	}
	if telemetrySum(snapshot(), telemetry.HTTPAttempts, telemetry.OpStoreCreate, "", "") != 0 {
		t.Fatal("pre-send credential refusal was counted as HTTP traffic")
	}
}

type credentialCallback func(context.Context) (string, error)

func (c credentialCallback) Token(ctx context.Context) (string, error) { return c(ctx) }

// full_only: false
func TestCredentialRetrievalRejectsCanceledContextBeforeAndAfterCallback(t *testing.T) {
	for _, mode := range []string{"active", "canceled-before", "expired-before", "canceled-during"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "expired-before":
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer deadlineCancel()
			case "canceled-before":
				cancel()
			}
			calls := 0
			client := makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("credential boundary sent HTTP")
				return nil, nil
			}), credentialCallback(func(context.Context) (string, error) {
				calls++
				if mode == "canceled-during" {
					cancel()
				}
				return "fixture-token", nil
			}))
			_, ok := client.retrieveCredential(ctx)
			wantCalls := 1
			if mode == "canceled-before" || mode == "expired-before" {
				wantCalls = 0
			}
			if ok != (mode == "active") || calls != wantCalls {
				t.Fatal("credential cancellation boundary differs", ok, calls)
			}
		})
	}
}

// full_only: false
func TestServiceAccountCapturePreservesTokenExpiryAndIdentity(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	fields, _ := serviceAccountJSON(t)
	path := serviceAccountPath(t, fields)
	var physicalCalls atomic.Int32
	source, err := LoadServiceAccountFileForTest(ctx, path, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		physicalCalls.Add(1)
		if r.URL.String() != tokenURL || r.Method != http.MethodPost || r.GetBody != nil {
			t.Error("captured authentication route changed")
		}
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > credentialTimeout {
			t.Error("captured authentication deadline is not bounded")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal("synthetic assertion form invalid")
		}
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Fatal("synthetic assertion missing")
		}
		claimsBody, err := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Issuer string `json:"iss"`
		}
		if err != nil || json.Unmarshal(claimsBody, &claims) != nil || claims.Issuer != fields["client_email"] {
			t.Error("token source identity changed after its file changed")
		}
		return response(200, `{"access_token":"captured-token","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal("synthetic source refused")
	}
	changed := maps.Clone(fields)
	changed["client_email"] = "replacement@example.iam.gserviceaccount.com"
	body, err := json.Marshal(changed)
	if err != nil || os.WriteFile(path, body, 0600) != nil {
		t.Fatal("cannot change synthetic file")
	}
	if email, err := ServiceAccountEmailForTest(source); err != nil || email != fields["client_email"] {
		t.Fatal("source identity changed after its file changed")
	}
	before := time.Now()
	value, expiry, err := CaptureServiceAccountTokenForTest(ctx, source)
	after := time.Now()
	if err != nil || value != "captured-token" || expiry.Before(before.Add(time.Hour)) || expiry.After(after.Add(time.Hour)) {
		t.Fatalf("captured token facts differ: error=%t value_matches=%t expiry_in_bounds=%t", err != nil, value == "captured-token", !expiry.Before(before.Add(time.Hour)) && !expiry.After(after.Add(time.Hour)))
	}
	cached, cachedExpiry, err := CaptureServiceAccountTokenForTest(ctx, source)
	if err != nil || cached != value || !cachedExpiry.Equal(expiry) {
		t.Fatal("cached capture did not preserve the exact token and expiry")
	}
	if token, err := source.Token(ctx); err != nil || token != value {
		t.Fatal("public Token differs from the captured token")
	}
	data := snapshot()
	if physicalCalls.Load() != 1 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != 1 || telemetrySum(data, telemetry.OperationCalls, telemetry.OpAuthentication, "", "") != 4 || telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "success", "") != 4 {
		t.Fatal("capture duplicated authentication or physical request accounting")
	}
	assertSafeTelemetry(t, data)
}

// full_only: false
func TestServiceAccountCaptureSharesGateAndCacheWithToken(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseRequest := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseRequest()
	var physicalCalls atomic.Int32
	source, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if physicalCalls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return response(200, `{"access_token":"shared-token","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal("synthetic source refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		value  string
		expiry time.Time
		err    error
	}
	captured, public := make(chan result, 1), make(chan result, 1)
	go func() {
		value, expiry, err := CaptureServiceAccountTokenForTest(ctx, source)
		captured <- result{value, expiry, err}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("capture request did not start")
	}
	go func() {
		value, err := source.Token(ctx)
		public <- result{value: value, err: err}
	}()
	waiter, stop := context.WithCancel(ctx)
	stop()
	if value, expiry, err := CaptureServiceAccountTokenForTest(waiter, source); !errors.Is(err, context.Canceled) || value != "" || !expiry.IsZero() {
		t.Error("canceled capture waiter retained facts")
	}
	releaseRequest()
	var first, second result
	select {
	case first = <-captured:
	case <-ctx.Done():
		t.Fatal("capture did not join")
	}
	select {
	case second = <-public:
	case <-ctx.Done():
		t.Fatal("public Token did not join")
	}
	if first.err != nil || second.err != nil || first.value != "shared-token" || second.value != first.value || first.expiry.IsZero() || physicalCalls.Load() != 1 {
		t.Fatal("capture and public Token did not share one cache and gate")
	}
}

// full_only: false
func TestDefaultCredentialsBindSelectedUniverse(t *testing.T) {
	if mode := os.Getenv("ENKV_GCP_UNIVERSE_CHILD"); mode != "" {
		checkDefaultCredentialsUniverse(t, mode)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{
		"configured/absent", "configured/empty", "configured/matching", "configured/mismatching",
		"well-known/matching", "well-known/mismatching",
		"configured-precedence/matching", "configured-precedence/mismatching", "configured-precedence/invalid",
		"authorized-user/absent", "authorized-user/matching", "authorized-user/mismatching",
		"metadata/absent", "metadata/empty", "metadata/matching", "metadata/mismatching", "metadata/failure", "metadata/canceled",
	} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDefaultCredentialsBindSelectedUniverse$")
			cmd.Env = append(os.Environ(), "ENKV_GCP_UNIVERSE_CHILD="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("isolated ADC check failed: %v\n%s", err, output)
			}
		})
	}
}

func checkDefaultCredentialsUniverse(t *testing.T, mode string) {
	t.Helper()
	route, universe, ok := strings.Cut(mode, "/")
	if !ok {
		t.Fatal("invalid ADC case")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var propertyCalls, metadataTokenCalls, fileTokenCalls, unexpectedCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/computeMetadata/v1/universe/universe-domain":
			propertyCalls.Add(1)
			w.Header().Set("Metadata-Flavor", "Google")
			switch universe {
			case "absent":
				w.WriteHeader(http.StatusNotFound)
			case "empty":
			case "matching":
				if _, err := fmt.Fprint(w, "googleapis.com"); err != nil {
					t.Error(err)
				}
			case "mismatching":
				if _, err := fmt.Fprint(w, "other-universe.invalid"); err != nil {
					t.Error(err)
				}
			case "failure":
				w.WriteHeader(http.StatusForbidden)
				if _, err := fmt.Fprint(w, "synthetic-private-property-error"); err != nil {
					t.Error(err)
				}
			case "canceled":
				cancel()
				w.WriteHeader(http.StatusForbidden)
			default:
				unexpectedCalls.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}
		case "/computeMetadata/v1/instance/service-accounts/default/token":
			metadataTokenCalls.Add(1)
			if propertyCalls.Load() != 1 {
				t.Error("token retrieval preceded selected universe admission")
			}
			w.Header().Set("Metadata-Flavor", "Google")
			if _, err := fmt.Fprint(w, `{"access_token":"synthetic-adc-token","token_type":"Bearer","expires_in":3600}`); err != nil {
				t.Error(err)
			}
		case "/file-token":
			fileTokenCalls.Add(1)
			if _, err := fmt.Fprint(w, `{"access_token":"synthetic-adc-token","token_type":"Bearer","expires_in":3600}`); err != nil {
				t.Error(err)
			}
		default:
			unexpectedCalls.Add(1)
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", home)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(server.URL, "http://"))
	if route != "metadata" {
		var fields map[string]string
		if route == "authorized-user" {
			fields = map[string]string{"type": "authorized_user", "client_id": "synthetic-client", "client_secret": "synthetic-secret", "refresh_token": "synthetic-refresh"}
		} else {
			fields, _ = serviceAccountJSON(t)
			fields["token_uri"] = server.URL + "/file-token"
		}
		switch universe {
		case "absent":
			delete(fields, "universe_domain")
		case "empty":
			fields["universe_domain"] = ""
		case "matching":
			fields["universe_domain"] = "googleapis.com"
		case "mismatching":
			fields["universe_domain"] = "other-universe.invalid"
		}
		if route == "well-known" || route == "configured-precedence" {
			wellKnown := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
			if err := os.MkdirAll(filepath.Dir(wellKnown), 0700); err != nil {
				t.Fatal(err)
			}
			wellKnownFields := maps.Clone(fields)
			if route == "configured-precedence" {
				wellKnownFields["universe_domain"] = "googleapis.com"
				if universe == "matching" {
					wellKnownFields["universe_domain"] = "other-universe.invalid"
				}
			}
			body, err := json.Marshal(wellKnownFields)
			if err != nil || os.WriteFile(wellKnown, body, 0600) != nil {
				t.Fatal("cannot write synthetic well-known ADC")
			}
		}
		if route != "well-known" {
			path := serviceAccountPath(t, fields)
			if universe == "invalid" {
				path = serviceAccountFile(t, []byte("{"))
			}
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
		}
	}
	wantAccepted := universe != "mismatching" && universe != "failure" && universe != "canceled" && universe != "invalid"
	source, err := LoadDefaultCredentials(ctx)
	serviceCalls := 0
	if source != nil {
		if err != nil {
			t.Fatal("failed ADC retained a usable source")
		}
		if route != "authorized-user" {
			store, err := NewStore(ctx, config(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				serviceCalls++
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					t.Error("service call has no bearer")
				}
				if wantAccepted && r.Header.Get("Authorization") != "Bearer synthetic-adc-token" {
					t.Error("selected credential did not supply the service bearer")
				}
				return apiFailure(401, "authError"), nil
			}), source)))
			if err != nil {
				t.Fatal("synthetic store construction failed")
			}
			result := store.Create(ctx, childKey(store), []byte("plain"))
			if result.Status != contract.WriteRefused || result.Reason != contract.ReasonAccess {
				t.Fatal("synthetic service refusal changed")
			}
		}
	}
	if !wantAccepted {
		if source != nil || err != ErrCredentials || serviceCalls != 0 || fileTokenCalls.Load() != 0 || metadataTokenCalls.Load() != 0 {
			t.Fatal("unadmitted selected credentials reached bearer use or changed the safe refusal")
		}
	} else {
		if source == nil || err != nil {
			t.Fatal("matching selected ADC refused")
		}
		wantService, wantFileToken, wantMetadataToken := 1, int32(1), int32(0)
		switch route {
		case "metadata":
			wantFileToken, wantMetadataToken = 0, 1
		case "authorized-user":
			wantService, wantFileToken = 0, 0
		}
		if serviceCalls != wantService || fileTokenCalls.Load() != wantFileToken || metadataTokenCalls.Load() != wantMetadataToken {
			t.Fatal("selected credential or single-send count changed")
		}
	}
	wantPropertyCalls := int32(0)
	if route == "metadata" {
		wantPropertyCalls = 1
	}
	if propertyCalls.Load() != wantPropertyCalls || unexpectedCalls.Load() != 0 {
		t.Fatal("ADC selection fell through or selected universe was not checked")
	}
	if universe == "canceled" && ctx.Err() != context.Canceled {
		t.Fatal("universe lookup did not observe cancellation")
	}
}

// full_only: false
func TestServiceAccountFileQuotaProjectReachesService(t *testing.T) {
	for _, tc := range []struct {
		name, project              string
		absent, refused, nonString bool
	}{
		{name: "absent", absent: true},
		{name: "empty"},
		{name: "file", project: "fixture-quota"},
		{name: "domain-scoped", project: "example.com:fixture"},
		{name: "maximum", project: strings.Repeat("a", 253)},
		{name: "over-maximum", project: strings.Repeat("a", 254), refused: true},
		{name: "newline", project: "private\r\nheader", refused: true},
		{name: "space", project: "private project", refused: true},
		{name: "slash", project: "private/project", refused: true},
		{name: "non-ascii", project: "prójèct", refused: true},
		{name: "non-string", nonString: true, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "ambient-project")
			fields, _ := serviceAccountJSON(t)
			if !tc.absent {
				fields["quota_project_id"] = tc.project
			}
			encodedFields := make(map[string]any, len(fields))
			for key, value := range fields {
				encodedFields[key] = value
			}
			if tc.nonString {
				encodedFields["quota_project_id"] = 17
			}
			encoded, err := json.Marshal(encodedFields)
			if err != nil {
				t.Fatal("credential fixture encoding failed")
			}
			path := serviceAccountFile(t, encoded)
			var tokens, sends int
			source, err := LoadServiceAccountFileForTest(t.Context(), path, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				tokens++
				if r.URL.String() != tokenURL || r.Method != http.MethodPost {
					t.Error("explicit-file authentication route changed")
				}
				return response(200, `{"access_token":"captured-token","token_type":"Bearer","expires_in":3600}`), nil
			}))
			if tc.refused {
				if err != ErrCredentials || source != nil || tokens != 0 {
					t.Fatal("malformed quota project retained a source or reached authentication")
				}
				return
			}
			if err != nil || source == nil || tokens != 0 {
				t.Fatal("explicit credential source did not capture without authentication", err)
			}
			fields["quota_project_id"] = "replacement-file-project"
			body, err := json.Marshal(fields)
			if err != nil || os.WriteFile(path, body, 0600) != nil {
				t.Fatal("fixture file replacement failed", err)
			}
			t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "replacement-environment-project")
			captured, err := CaptureCredentials(t.Context(), source)
			if err != nil || captured.Token != "captured-token" || captured.QuotaProject != tc.project || !time.Now().Before(captured.Expiry) {
				t.Fatal("public capture lost the selected file token, quota or expiry")
			}
			value, err := source.Token(t.Context())
			if err != nil || value != captured.Token {
				t.Fatal("Token did not share the captured source")
			}
			cached, err := CaptureCredentials(t.Context(), source)
			if err != nil || cached.Token != captured.Token || cached.QuotaProject != captured.QuotaProject || !cached.Expiry.Equal(captured.Expiry) {
				t.Fatal("cached capture changed the selected credential facts")
			}
			client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				sends++
				if r.Header.Get("X-Goog-User-Project") != tc.project || r.Header.Get("Authorization") != "Bearer captured-token" {
					t.Error("service did not retain the exact file bearer and quota project")
				}
				return apiFailure(401, "authError"), nil
			}), source)
			ctx, ok := client.begin(t.Context(), "cloudkms.googleapis.com", maxJSON)
			if !ok {
				t.Fatal("explicit credential capture refused")
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudkms.googleapis.com/v1/projects/fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Goog-User-Project", "caller-project")
			request.Header.Set("Authorization", "Bearer caller-token")
			reply, err := client.http.Do(request)
			if err != nil {
				t.Fatal("service request failed before controlled denial")
			}
			if err := reply.Body.Close(); err != nil {
				t.Error(err)
			}
			if reply, err := client.http.Do(request); err == nil {
				if err := reply.Body.Close(); err != nil {
					t.Error(err)
				}
				t.Error("controlled service denial permitted a second send")
			}
			if tokens != 1 || sends != 1 {
				t.Fatal("explicit source capture or service was replayed", tokens, sends)
			}
		})
	}
}
