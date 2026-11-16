package core

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type delayedAWSSetupTransport struct {
	started, release, consumed chan struct{}
	calls                      *atomic.Int32
}

func (d delayedAWSSetupTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	go func() {
		close(d.started)
		<-d.release
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		close(d.consumed)
	}()
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), ContentLength: 2}, nil
}

// full_only: false
func TestAWSSetupWaitsForRequestBodyCompletion(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancelled"}[cancelled], func(t *testing.T) {
			collector := liveTelemetry(t)
			var calls atomic.Int32
			delayed := delayedAWSSetupTransport{make(chan struct{}), make(chan struct{}), make(chan struct{}), &calls}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(delayed.release) }) }
			defer func() {
				release()
				select {
				case <-delayed.consumed:
				case <-time.After(time.Second):
					t.Error("AWS setup body worker cleanup was not joined")
				}
			}()
			base := &http.Transport{}
			base.RegisterProtocol("https", delayed)
			defer base.CloseIdleConnections()
			transport := &awsSetupTransport{base: base}
			ctx, cancel := context.WithTimeout(collector.Context, time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, awsSetupContextKey{}, &awsSetupOperation{host: "fixture.invalid", metric: telemetry.OpSetupCreate})
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/", strings.NewReader("abc"))
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				response, err := transport.RoundTrip(request)
				if response != nil {
					_ = response.Body.Close()
				}
				returned <- err
			}()
			select {
			case <-delayed.started:
			case <-time.After(time.Second):
				t.Fatal("AWS setup body worker did not start")
			}
			waitReturned := func() error {
				select {
				case err := <-returned:
					return err
				case <-time.After(time.Second):
					t.Fatal("AWS setup call was not joined")
					return nil
				}
			}
			if cancelled {
				cancel()
				err := waitReturned()
				owned := request.Body.(*setupRequestBody)
				owned.mu.Lock()
				closed, reads := owned.closed, owned.reads
				owned.mu.Unlock()
				select {
				case <-owned.done:
				default:
					t.Error("caller returned before owned AWS body completion")
				}
				if !closed || reads != 0 {
					t.Errorf("caller returned with owned AWS body closed=%v reads=%d", closed, reads)
				}
				var failure *awsSetupFailure
				if !errors.Is(err, errAWSSetup) || !errors.As(err, &failure) {
					t.Errorf("cancelled AWS call lost safe failure: %v", err)
				} else if facts := failure.SafeHarnessFailure(); !facts.Validate() || facts.Cause != "cancelled" || facts.Effect != "unknown" || facts.Attempt != 1 {
					t.Errorf("cancelled entered AWS create facts differ: %+v", facts)
				}
				metrics := liveTelemetrySnapshot(t, collector)
				if liveMetricSum(metrics, telemetry.HTTPResults, "setup.create", "failure", "") != 1 || liveMetricSum(metrics, telemetry.HTTPRequestBodyObservations, "setup.create", "", "incomplete") != 1 {
					t.Error("cancelled AWS body telemetry differs")
				}
				release()
			} else {
				select {
				case <-returned:
					t.Fatal("AWS transport returned before request body close")
				case <-time.After(20 * time.Millisecond):
				}
				release()
				if err := waitReturned(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-delayed.consumed:
			case <-time.After(time.Second):
				t.Fatal("AWS setup body worker was not joined")
			}
			if calls.Load() != 1 {
				t.Fatal("body join replayed the AWS physical request")
			}
			metrics := liveTelemetrySnapshot(t, collector)
			if cancelled {
				if liveMetricSum(metrics, telemetry.HTTPRequestBodyBytes, "setup.create", "", "") != 0 || liveMetricSum(metrics, telemetry.HTTPRequestBodyObservations, "setup.create", "", "") != 0 {
					t.Fatal("late AWS reads changed returned incomplete telemetry")
				}
			} else if liveMetricSum(metrics, telemetry.HTTPRequestBodyBytes, "setup.create", "", "complete") != 3 || liveMetricSum(metrics, telemetry.HTTPResults, "setup.create", "success", "") != 1 {
				t.Fatal("completed AWS body telemetry differs")
			}
		})
	}
}

// full_only: false
func TestAWSRecoverySupportPaths(t *testing.T) {
	domain := contract.Hash([]byte("domain"))
	object := contract.Hash([]byte("receipt-page"))
	s := &awsSetup{head: "run/HEAD", objects: "run/" + hex.EncodeToString(domain[:]) + "/"}
	for _, kind := range []string{"member", "recipient", "access", "support", "admin-index", "root", "seed", "retained"} {
		for _, index := range []int{-1, 0, 31, 32, 255, 256} {
			want := (kind == "member" || kind == "recipient") && index >= 0 && index < 32 || (kind == "access" || kind == "support" || kind == "admin-index") && index >= 0 && index < 256 || kind == "root" && index == 0
			key := s.objects + kind + "/" + strconv.Itoa(index) + "/" + hex.EncodeToString(object[:])
			if s.validKey(key) != want {
				t.Fatalf("%s index %d admission differs", kind, index)
			}
		}
	}
	for _, index := range []string{"00", "+1", "01", "1.0"} {
		if s.validKey(s.objects + "support/" + index + "/" + hex.EncodeToString(object[:])) {
			t.Fatal("noncanonical support index admitted")
		}
	}
}

// full_only: false
func TestAWSProtectedObjectConditionalCleanup(t *testing.T) {
	c, publicKey := awsLiveTestSettings(t)
	domain := contract.Hash([]byte("domain"))
	object := contract.Hash([]byte("receipt-page"))
	resultKey, err := format.GeneratedResultKey("run", domain, contract.Hash([]byte("result-coordinate")))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"run/" + hex.EncodeToString(domain[:]) + "/support/0/" + hex.EncodeToString(object[:]),
		"run/" + hex.EncodeToString(domain[:]) + "/support/255/" + hex.EncodeToString(object[:]),
		resultKey,
	} {
		var requests atomic.Int32
		transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.URL.Path != "/"+c.Bucket+"/"+key || r.Header.Get("X-Amz-Expected-Bucket-Owner") != c.Account {
				t.Error("support request changed its bound path or owner")
			}
			switch r.Method {
			case http.MethodPut:
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "receipt-page" || r.Header.Get("If-None-Match") != "*" {
					t.Error("support write changed its body or create condition")
				}
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				if r.Header.Get("If-Match") != `"observed-etag"` {
					t.Error("support cleanup changed the observed token")
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Error("unexpected support operation")
			}
		}))
		credentials := &awsLiveTestCredentials{}
		s := newAWSSetup(c, "run", domain, publicKey, credentials, transport)
		if got := s.put(context.Background(), key, []byte("receipt-page")); got.Status != contract.WriteAcknowledged {
			t.Fatal("support create refused", got)
		}
		if err := s.delete(context.Background(), key, contract.Token{Family: contract.AWS, Value: `"observed-etag"`}); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{key + "/extra", "foreign/" + key, key[:len(key)-64] + strings.Repeat("0", 64), key[:len(key)-64] + strings.ToUpper(key[len(key)-64:])} {
			if err := s.delete(context.Background(), bad, contract.Token{Family: contract.AWS, Value: `"observed-etag"`}); !errors.Is(err, errAWSDelete) {
				t.Fatal("cleanup accepted a malformed or foreign key", err)
			}
		}
		if requests.Load() != 2 || credentials.calls.Load() != 2 {
			t.Fatal("support operations did not remain one attempt each")
		}
	}
}

// full_only: false
func TestAWSLiveConditionalSetupAndCleanup(t *testing.T) {
	collector := liveTelemetry(t)
	c, publicKey := awsLiveTestSettings(t)
	var requests atomic.Int32
	transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "s3.us-east-1.amazonaws.com" || r.URL.Path != "/fixture-bucket/run/HEAD" || r.URL.RawQuery != "x-id=PutObject" && r.URL.RawQuery != "x-id=DeleteObject" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != c.Account || r.Header.Get("X-Amz-Security-Token") != "test-session" {
			t.Error("request does not bind the bucket, object, owner, and selected credential")
		}
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != "initial-head" || r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "" {
				t.Error("setup is not an exact create-only write")
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			if r.Header.Get("If-Match") != `"observed-etag"` || r.Header.Get("If-None-Match") != "" || r.Header.Get("X-Amz-Bypass-Governance-Retention") != "" {
				t.Error("cleanup did not preserve the exact observed token")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected request method")
		}
	}))
	credentials := &awsLiveTestCredentials{}
	s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), publicKey, credentials, transport)
	if got := s.put(collector.Context, "run/HEAD", []byte("initial-head")); got.Status != contract.WriteAcknowledged {
		t.Fatalf("setup failed: %+v", got)
	}
	if err := s.delete(collector.Context, "run/HEAD", contract.Token{Family: contract.AWS, Value: `"observed-etag"`}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || credentials.calls.Load() != 2 {
		t.Fatal("operations did not send and acquire credentials exactly once")
	}
	got := liveTelemetrySnapshot(t, collector)
	if liveMetricSum(got, telemetry.HTTPAttempts, "", "", "") != 2 || liveMetricSum(got, telemetry.HTTPRequestBodyBytes, "", "", "complete") != 12 || liveMetricSum(got, telemetry.HTTPResponseBodyBytes, "", "", "") != 0 || liveMetricSum(got, telemetry.HTTPResults, "", "failure", "") != 0 || liveHTTPErrorCount(got) != 0 {
		t.Fatalf("incorrect HTTP measurements: %+v", got)
	}
	if liveMetricSum(got, telemetry.OperationResults, "setup.create", "write_acknowledged", "") != 1 || liveMetricSum(got, telemetry.OperationResults, "setup.delete", "success", "") != 1 {
		t.Fatal("setup logical results missing")
	}
}

// full_only: false
func TestAWSLiveWriteErrorsRemainSingleAttempt(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		status     int
		want       contract.WriteStatus
	}{
		{"precondition", "PreconditionFailed", 412, contract.WritePrecondition},
		{"conflict", "ConditionalRequestConflict", 409, contract.WriteConflict},
		{"access", "AccessDenied", 403, contract.WriteUnknown},
		{"server", "InternalError", 500, contract.WriteUnknown},
		{"redirect", "TemporaryRedirect", 307, contract.WriteUnknown},
		{"truncated", "", 200, contract.WriteUnknown},
		{"oversized", "", 200, contract.WriteUnknown},
		{"lost-reply", "", 200, contract.WriteUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			collector := liveTelemetry(t)
			c, der := awsLiveTestSettings(t)
			var requests atomic.Int32
			body := "<Error><Code>" + tc.code + "</Code><Message>private diagnostic</Message></Error>"
			if tc.name == "oversized" {
				body = strings.Repeat("x", awsSetupLimit+1)
			}
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
				}
				if tc.name == "lost-reply" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				if tc.name == "redirect" {
					w.Header().Set("Location", "https://s3.us-east-1.amazonaws.com/elsewhere")
				}
				length := len(body)
				if tc.name == "truncated" {
					length++
				}
				w.Header().Set("Content-Length", strconv.Itoa(length))
				w.WriteHeader(tc.status)
				if _, err := io.WriteString(w, body); err != nil {
					t.Error(err)
				}
			}))
			credentials := &awsLiveTestCredentials{}
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
			if got := s.put(collector.Context, "run/HEAD", []byte("body")); got.Status != tc.want {
				t.Fatalf("result: %+v", got)
			}
			if requests.Load() != 1 || credentials.calls.Load() != 1 {
				t.Fatal("operation replayed or reacquired credentials")
			}
			m := liveTelemetrySnapshot(t, collector)
			responseBytes := uint64(len(body))
			if tc.name == "lost-reply" {
				responseBytes = 0
			}
			if liveMetricSum(m, telemetry.HTTPAttempts, "setup.create", "", "") != 1 || liveMetricSum(m, telemetry.HTTPRequestBodyBytes, "setup.create", "", "complete") != 4 || liveMetricSum(m, telemetry.HTTPResponseBodyBytes, "setup.create", "", "") != responseBytes {
				t.Fatalf("measurements: %+v", m)
			}
			if (tc.status >= 300) != (liveHTTPErrorCount(m) == 1) || (tc.name == "lost-reply" || tc.name == "truncated" || tc.name == "oversized") != (liveMetricSum(m, telemetry.HTTPResults, "setup.create", "failure", "") == 1) {
				t.Fatalf("error measurements: %+v", m)
			}
		})
	}
}

// full_only: false
func TestAWSLiveCleanupFailureIsNeverSuccess(t *testing.T) {
	for _, mode := range []string{"changed-token", "denied", "lost-reply", "version-marker"} {
		t.Run(mode, func(t *testing.T) {
			collector := liveTelemetry(t)
			c, der := awsLiveTestSettings(t)
			var requests atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "DELETE" || r.Header.Get("If-Match") != `"observed"` || r.Header.Get("X-Amz-Expected-Bucket-Owner") != c.Account {
					t.Error("cleanup request changed its condition")
				}
				switch mode {
				case "changed-token":
					w.WriteHeader(412)
					io.WriteString(w, "<Error><Code>PreconditionFailed</Code></Error>")
				case "denied":
					w.WriteHeader(403)
					io.WriteString(w, "<Error><Code>AccessDenied</Code></Error>")
				case "version-marker":
					w.Header().Set("X-Amz-Delete-Marker", "true")
					w.Header().Set("X-Amz-Version-Id", "version")
					w.WriteHeader(204)
				case "lost-reply":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
				}
			}))
			credentials := &awsLiveTestCredentials{}
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
			if err := s.delete(collector.Context, "run/HEAD", contract.Token{Family: contract.AWS, Value: `"observed"`}); !errors.Is(err, errAWSDelete) {
				t.Fatal("failed or incomplete cleanup was reported as success")
			}
			m := liveTelemetrySnapshot(t, collector)
			if requests.Load() != 1 || credentials.calls.Load() != 1 || liveMetricSum(m, telemetry.HTTPAttempts, "setup.delete", "", "") != 1 || liveMetricSum(m, telemetry.OperationResults, "setup.delete", "failure", "") != 1 {
				t.Fatal("cleanup retried or reacquired credentials")
			}
		})
	}
}

// full_only: false
func TestAWSLiveRefusesUnsafeCleanupAndAuthentication(t *testing.T) {
	collector := liveTelemetry(t)
	c, der := awsLiveTestSettings(t)
	var requests atomic.Int32
	transport := awsLiveTestTransport(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	credentials := &awsLiveTestCredentials{}
	s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
	for _, value := range []string{"", "*", `"a", "b"`, "unquoted", "W/\"weak\""} {
		if err := s.delete(collector.Context, "run/HEAD", contract.Token{Family: contract.AWS, Value: value}); err == nil {
			t.Errorf("accepted unsafe token %q", value)
		}
	}
	for _, key := range []string{"another/HEAD", "run/HEAD/extra", s.objects + "root/0/../HEAD"} {
		if err := s.delete(collector.Context, key, contract.Token{Family: contract.AWS, Value: `"etag"`}); err == nil {
			t.Error("accepted an unbound key")
		}
		if got := s.put(collector.Context, key, []byte("body")); got.Status != contract.WriteRefused {
			t.Error("accepted an unbound write")
		}
	}
	if credentials.calls.Load() != 0 {
		t.Fatal("invalid request acquired credentials")
	}
	credentials.err = errors.New("private credential diagnostic")
	if got := s.put(collector.Context, "run/HEAD", []byte("body")); got.Status != contract.WriteRefused || got.Reason != contract.ReasonAccess {
		t.Fatalf("auth result: %+v", got)
	}
	if err := s.delete(collector.Context, "run/HEAD", contract.Token{Family: contract.AWS, Value: `"etag"`}); !errors.Is(err, errAWSDelete) {
		t.Fatal("cleanup did not return a safe refusal")
	}
	if requests.Load() != 0 || liveMetricSum(liveTelemetrySnapshot(t, collector), telemetry.HTTPAttempts, "", "", "") != 0 {
		t.Fatal("refused request reached HTTP")
	}
}

// full_only: false
func TestAWSLiveConstructorUsesOnlyTheSelectedFile(t *testing.T) {
	collector := liveTelemetry(t)
	c, _ := awsLiveTestSettings(t)
	c.CredentialsFile = filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(c.CredentialsFile, []byte("[enkv-test]\naws_access_key_id = selected-key\naws_secret_access_key = selected-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	b, err := openLiveBackend(collector.Context, c, "run", contract.Hash([]byte("domain")))
	if err != nil {
		t.Fatal(err)
	}
	if b.Store.Descriptor().Family != contract.AWS || b.Trust.Family() != contract.AWS {
		t.Fatal("wrong production provider")
	}
	if liveMetricSum(liveTelemetrySnapshot(t, collector), telemetry.HTTPAttempts, "", "", "") != 0 {
		t.Fatal("constructor made an HTTP call")
	}

	c.KeyID = strings.Replace(c.KeyID, c.Account, "987654321098", 1)
	if _, err := openLiveBackend(collector.Context, c, "run", contract.Hash([]byte("domain"))); err == nil {
		t.Fatal("accepted another key account")
	}
	c.KeyID = strings.Replace(c.KeyID, "987654321098", c.Account, 1)
	c.CredentialsFile = filepath.Join(t.TempDir(), "missing")
	if _, err := openLiveBackend(collector.Context, c, "run", contract.Hash([]byte("domain"))); err == nil {
		t.Fatal("ambient credentials replaced the selected missing file")
	}
}

// full_only: false
func TestAWSLiveResourceChecks(t *testing.T) {
	for _, invalid := range []string{"", "region", "versioning", "suspended", "lifecycle", "replication", "lock", "public", "ownership", "encryption", "account", "disabled", "key-spec", "key-usage", "key-arn", "public-key", "algorithm", "denied"} {
		t.Run("configuration-"+invalid, func(t *testing.T) {
			collector := liveTelemetry(t)
			c, der := awsLiveTestSettings(t)
			credentials := &awsLiveTestCredentials{}
			var requests atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				status, body := awsLiveConfigurationReply(t, c, der, r, invalid)
				w.WriteHeader(status)
				if _, err := io.WriteString(w, body); err != nil {
					t.Error(err)
				}
			}))
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
			err := s.check(collector.Context)
			if (err == nil) != (invalid == "") {
				t.Fatalf("configuration %q: %v", invalid, err)
			}
			if invalid == "" && requests.Load() != 10 {
				t.Fatalf("incomplete configuration check: %d requests", requests.Load())
			}
			m := liveTelemetrySnapshot(t, collector)
			if credentials.calls.Load() != requests.Load() || liveMetricSum(m, telemetry.HTTPAttempts, "", "", "") != uint64(requests.Load()) {
				t.Fatal("configuration requests were not singly measured and authenticated")
			}
			if invalid == "" && (liveMetricSum(m, telemetry.OperationResults, "setup.read", "success", "") != 9 || liveMetricSum(m, telemetry.OperationResults, "setup.public_key", "success", "") != 1) {
				t.Fatal("resource check logical results missing")
			}
		})
	}
}

// full_only: false
func TestAWSLiveResourceCheckRetriesOnlyTransportTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name         string
		failAt       int32
		permanent    bool
		nonTimeout   bool
		wantDials    int32
		wantRequests int32
		wantPass     bool
	}{
		{name: "s3-timeout", failAt: 7, wantDials: 11, wantRequests: 10, wantPass: true},
		{name: "kms-timeout", failAt: 9, wantDials: 11, wantRequests: 10, wantPass: true},
		{name: "persistent-timeout", failAt: 7, permanent: true, wantDials: 9, wantRequests: 6},
		{name: "non-timeout-refusal", failAt: 7, nonTimeout: true, wantDials: 7, wantRequests: 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			collector := liveTelemetry(t)
			c, der := awsLiveTestSettings(t)
			credentials := &awsLiveTestCredentials{}
			var requests, dials atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				status, body := awsLiveConfigurationReply(t, c, der, r, "")
				w.WriteHeader(status)
				if _, err := io.WriteString(w, body); err != nil {
					t.Error(err)
				}
			}))
			dial := transport.DialContext
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				ordinal := dials.Add(1)
				if ordinal == tc.failAt || tc.permanent && ordinal > tc.failAt {
					if tc.nonTimeout {
						return nil, errors.New("controlled permanent refusal")
					}
					return nil, &net.DNSError{Err: "controlled timeout", IsTimeout: true}
				}
				return dial(ctx, network, address)
			}
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
			err := s.check(collector.Context)
			if (err == nil) != tc.wantPass || dials.Load() != tc.wantDials || requests.Load() != tc.wantRequests || credentials.calls.Load() != tc.wantDials {
				t.Fatalf("read-only timeout admission: err=%v dials=%d requests=%d credentials=%d", err, dials.Load(), requests.Load(), credentials.calls.Load())
			}
			if liveMetricSum(liveTelemetrySnapshot(t, collector), telemetry.HTTPAttempts, "", "", "") != uint64(tc.wantDials) {
				t.Fatal("timeout retry physical calls were not measured")
			}
		})
	}
}

func awsLiveConfigurationReply(t *testing.T, c liveSettings, der []byte, r *http.Request, invalid string) (int, string) {
	t.Helper()
	if r.Host == "kms.us-east-1.amazonaws.com" {
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in["KeyId"] != c.KeyID {
			t.Error("KMS request omitted the exact key ARN")
		}
		var out any
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.DescribeKey":
			key := map[string]any{"Arn": c.KeyID, "AWSAccountId": c.Account, "Enabled": true, "KeyState": "Enabled", "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "MultiRegion": false}
			switch invalid {
			case "account":
				key["AWSAccountId"] = "987654321098"
			case "disabled":
				key["Enabled"] = false
			case "key-spec":
				key["KeySpec"] = "ECC_NIST_P384"
			case "key-usage":
				key["KeyUsage"] = "ENCRYPT_DECRYPT"
			case "key-arn":
				key["Arn"] = "other"
			}
			out = map[string]any{"KeyMetadata": key}
		case "TrentService.GetPublicKey":
			public := base64.StdEncoding.EncodeToString(der)
			if invalid == "public-key" {
				public = base64.StdEncoding.EncodeToString([]byte("other"))
			}
			algorithm := "ECDSA_SHA_256"
			if invalid == "algorithm" {
				algorithm = "ECDSA_SHA_384"
			}
			out = map[string]any{"KeyId": c.KeyID, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{algorithm}, "PublicKey": public}
		default:
			t.Error("unexpected KMS operation")
		}
		body, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return 200, string(body)
	}
	if r.Method != "GET" || r.URL.Path != "/"+c.Bucket || r.Header.Get("X-Amz-Expected-Bucket-Owner") != c.Account {
		t.Error("configuration read did not bind the bucket and owner")
	}
	if invalid == "denied" {
		return 403, "<Error><Code>AccessDenied</Code></Error>"
	}
	q := r.URL.Query()
	switch {
	case q.Has("location"):
		region := ""
		if invalid == "region" {
			region = "us-west-2"
		}
		return 200, "<LocationConstraint>" + region + "</LocationConstraint>"
	case q.Has("versioning"):
		status := ""
		if invalid == "versioning" {
			status = "<Status>Enabled</Status>"
		}
		if invalid == "suspended" {
			status = "<Status>Suspended</Status>"
		}
		return 200, "<VersioningConfiguration>" + status + "</VersioningConfiguration>"
	case q.Has("lifecycle"):
		if invalid == "lifecycle" {
			return 200, "<LifecycleConfiguration/>"
		}
		return 404, "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>"
	case q.Has("replication"):
		if invalid == "replication" {
			return 200, "<ReplicationConfiguration/>"
		}
		return 404, "<Error><Code>ReplicationConfigurationNotFoundError</Code></Error>"
	case q.Has("object-lock"):
		if invalid == "lock" {
			return 200, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"
		}
		return 404, "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>"
	case q.Has("publicAccessBlock"):
		block := "true"
		if invalid == "public" {
			block = "false"
		}
		return 200, "<PublicAccessBlockConfiguration><BlockPublicAcls>" + block + "</BlockPublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><IgnorePublicAcls>true</IgnorePublicAcls><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
	case q.Has("ownershipControls"):
		ownership := "BucketOwnerEnforced"
		if invalid == "ownership" {
			ownership = "ObjectWriter"
		}
		return 200, "<OwnershipControls><Rule><ObjectOwnership>" + ownership + "</ObjectOwnership></Rule></OwnershipControls>"
	case q.Has("encryption"):
		algorithm := "AES256"
		if invalid == "encryption" {
			algorithm = "aws:kms"
		}
		return 200, "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>" + algorithm + "</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
	default:
		t.Error("unexpected bucket operation")
		return 500, ""
	}
}

type awsLiveTestCredentials struct {
	calls atomic.Int32
	err   error
}

func (c *awsLiveTestCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls.Add(1)
	return aws.Credentials{AccessKeyID: "test-access", SecretAccessKey: "test-secret", SessionToken: "test-session"}, c.err
}

func awsLiveTestSettings(t *testing.T) (liveSettings, []byte) {
	t.Helper()
	der := testtrust.New(t, contract.AWS, contract.ID{1}).PublicKey()
	return liveSettings{Provider: "aws", Account: "123456789012", Region: "us-east-1", Bucket: "fixture-bucket", Profile: "enkv-test", KeyID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}, der
}

func awsLiveTestTransport(t *testing.T, handler http.Handler) *http.Transport {
	t.Helper()
	return testtrust.PublicHTTPSTransport(t, []string{"s3.us-east-1.amazonaws.com", "kms.us-east-1.amazonaws.com"}, handler)
}

// full_only: false
func TestAWSSetupTelemetryFailureDoesNotChangeWrite(t *testing.T) {
	for _, mode := range []string{"disabled", "enabled", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			collector := liveTelemetry(t)
			ctx := collector.Context
			if mode == "disabled" {
				ctx = context.Background()
			}
			if mode == "shutdown" && !collector.Close(collector.Context) {
				t.Fatal("controlled telemetry shutdown failed")
			}
			c, der := awsLiveTestSettings(t)
			var requests atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "owned" || r.Method != "PUT" || r.Header.Get("If-None-Match") != "*" {
					t.Error("telemetry mode changed the conditional setup request")
				}
				w.WriteHeader(http.StatusOK)
			}))
			credentials := &awsLiveTestCredentials{}
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
			if result := s.put(ctx, "run/HEAD", []byte("owned")); result.Status != contract.WriteAcknowledged || requests.Load() != 1 || credentials.calls.Load() != 1 {
				t.Fatal("telemetry mode changed the acknowledged setup write")
			}
			if mode == "shutdown" {
				if got := collector.Collect(collector.Context, "legacy-baseline", "setup-check", "setup"); got.Status != "incomplete" || got.FailureClass != "collection_failed" {
					t.Fatal("failed collector was reported as complete")
				}
				return
			}
			got := liveTelemetrySnapshot(t, collector)
			want := uint64(1)
			if mode == "disabled" {
				want = 0
				if len(got.Metrics) != 0 {
					t.Fatal("disabled setup telemetry emitted metrics")
				}
			}
			if liveMetricSum(got, telemetry.OperationResults, "setup.create", "write_acknowledged", "") != want {
				t.Fatal("setup write telemetry does not match its enabled state")
			}
		})
	}
}
