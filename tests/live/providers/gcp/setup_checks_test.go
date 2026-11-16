package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/providers/gcp"
	"enkv.sh/telemetry"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/storage/v1"
)

type gcpSetupRoundTrip func(*http.Request) (*http.Response, error)

func (f gcpSetupRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		defer r.Body.Close()
	}
	return f(r)
}

type gcpSetupCredential struct {
	calls int
	err   error
}

func (c *gcpSetupCredential) Token(context.Context) (string, error) {
	c.calls++
	return "synthetic-access-token", c.err
}

func gcpSetupReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

type delayedGCPSetupTransport struct {
	started, release, consumed chan struct{}
	body                       chan *setupRequestBody
}

func (d delayedGCPSetupTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	go func() {
		d.body <- r.Body.(*setupRequestBody)
		close(d.started)
		<-d.release
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		close(d.consumed)
	}()
	return gcpSetupReply(200, "{}"), nil
}

// full_only: false
func TestGCPSetupWaitsForRequestBodyCompletion(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancelled"}[cancelEarly], func(t *testing.T) {
			collector := liveTelemetry(t)
			base := delayedGCPSetupTransport{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan *setupRequestBody, 1)}
			var releaseOnce sync.Once
			releaseWorker := func() { releaseOnce.Do(func() { close(base.release) }) }
			defer func() {
				releaseWorker()
				select {
				case <-base.consumed:
				case <-time.After(time.Second):
					t.Error("setup body worker cleanup was not joined")
				}
			}()
			transport := &gcpSetupTransport{base: base}
			ctx, cancel := context.WithTimeout(collector.Context, time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, gcpSetupContextKey{}, &gcpSetupOperation{host: "fixture.invalid", token: "synthetic", metric: telemetry.OpSetupCreate})
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/", strings.NewReader("abc"))
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				resp, err := transport.RoundTrip(r)
				if resp != nil {
					_ = resp.Body.Close()
				}
				returned <- err
			}()
			select {
			case <-base.started:
			case <-time.After(time.Second):
				t.Fatal("setup body worker did not start")
			}
			if cancelEarly {
				cancel()
				select {
				case err := <-returned:
					var failure *gcpSetupFailure
					if !errors.Is(err, errGCPSetup) || !errors.As(err, &failure) {
						t.Errorf("incomplete request did not return the safe error: %v", err)
					} else if facts := failure.SafeHarnessFailure(); !facts.Validate() || facts.Cause != "cancelled" || facts.Effect != "unknown" || facts.Attempt != 1 {
						t.Errorf("cancelled entered create facts differ: %+v", facts)
					}
				case <-time.After(time.Second):
					t.Error("request body completion exceeded its context bound")
				}
				owned := <-base.body
				owned.mu.Lock()
				closed, reads := owned.closed, owned.reads
				owned.mu.Unlock()
				select {
				case <-owned.done:
				default:
					t.Error("caller returned before owned setup body completion")
				}
				if !closed || reads != 0 {
					t.Errorf("caller returned with owned setup body closed=%v reads=%d", closed, reads)
				}
				got := liveTelemetrySnapshot(t, collector)
				if liveMetricSum(got, telemetry.HTTPRequestBodyBytes, "setup.create", "", "") != 0 || liveMetricSum(got, telemetry.HTTPResults, "setup.create", "failure", "") != 1 || liveMetricSum(got, telemetry.HTTPRequestBodyObservations, "setup.create", "", "incomplete") != 1 {
					t.Errorf("partial request measurements are incorrect: %+v", got)
				}
				releaseWorker()
			} else {
				early := false
				select {
				case <-returned:
					early = true
					t.Error("transport returned before request body completion")
				case <-time.After(20 * time.Millisecond):
				}
				releaseWorker()
				if !early {
					select {
					case err := <-returned:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("completed setup call was not joined")
					}
				}
			}
			select {
			case <-base.consumed:
			case <-time.After(time.Second):
				t.Fatal("setup body worker was not joined")
			}
			got := liveTelemetrySnapshot(t, collector)
			if cancelEarly {
				if liveMetricSum(got, telemetry.HTTPRequestBodyBytes, "setup.create", "", "") != 0 || liveMetricSum(got, telemetry.HTTPRequestBodyObservations, "setup.create", "", "") != 0 {
					t.Fatal("late reads changed the already returned partial observation")
				}
			} else if liveMetricSum(got, telemetry.HTTPRequestBodyBytes, "setup.create", "", "complete") != 3 || liveMetricSum(got, telemetry.HTTPRequestBodyObservations, "setup.create", "", "complete") != 1 {
				t.Fatalf("final request measurements are incorrect: %+v", got)
			}
		})
	}
}

type gcpAdmissionStore struct {
	contract.Store
	admission *gcp.Store
}

func (s gcpAdmissionStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	result := s.admission.Read(ctx, key, limit)
	if result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonAccess {
		return result
	}
	return s.Store.Read(ctx, key, limit)
}

// full_only: false
func TestGCPCleanupAdmitsEveryObjectKind(t *testing.T) {
	ctx := context.Background()
	env := memoryScenarioEnvironment(t)
	store := env.Store.(*memoryStore)
	credentials := &gcpSetupCredential{err: errors.New("controlled token refusal")}
	client, err := gcp.NewClient(&http.Transport{}, credentials)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := gcp.NewStore(ctx, gcp.StoreConfig{Client: client, Domain: env.Domain, Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "test-bucket", Prefix: store.desc.Prefix, CredentialRoute: "test-credential"})
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{store.desc.HeadKey}
	for _, kind := range []format.Kind{format.ValueEntryPageKind, format.RecipientKind, format.RootKind} {
		ref := format.Ref{Kind: kind, Domain: env.Domain, Object: contract.Hash([]byte{byte(kind)}), Digest: contract.Hash([]byte("owned")), Format: format.Version, Length: 5}
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			inventory := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{Prefix: store.desc.Prefix, Deleted: make(map[string]int)}}
			inventory.write(ctx, key, []byte("owned"), "create", func() contract.WriteResult { return store.Create(ctx, key, []byte("owned")) })
			inventory.stop()
			before := credentials.calls
			if err := inventory.cleanup(ctx, gcpAdmissionStore{Store: store, admission: admission}, testDelete(store)); err != nil {
				t.Fatal("cleanup failed provider admission")
			}
			if credentials.calls-before != 2 || store.Read(ctx, key, 1024).Status != contract.ReadMissing {
				t.Fatal("cleanup did not admit both reads and remove the object")
			}
		})
	}
}

func newGCPControlledSetup(t *testing.T, credentials *gcpSetupCredential, roundTrip gcpSetupRoundTrip) *gcpSetup {
	t.Helper()
	s, err := newGCPSetup(context.Background(), credentials, roundTrip, "test-bucket", "test-run", contract.Hash([]byte("test-domain")), "https://storage.us-central1.rep.googleapis.com/storage/v1/", "https://us-central1-cloudkms.googleapis.com/")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func gcpControlledRootKey(s *gcpSetup) string {
	object := contract.Hash([]byte("controlled-root"))
	return s.objects + "root/0/" + hex.EncodeToString(object[:])
}

// full_only: false
func TestGCPSetupConditionalCreateAndDelete(t *testing.T) {
	collector := liveTelemetry(t)
	credentials := &gcpSetupCredential{}
	body := []byte("synthetic value")
	calls := 0
	var requestBytes, responseBytes uint64
	var createdAt time.Time
	s := newGCPControlledSetup(t, credentials, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "storage.us-central1.rep.googleapis.com" || r.Header.Get("Authorization") != "Bearer synthetic-access-token" || r.GetBody != nil || !r.Close {
			t.Fatal("request did not retain the fixed endpoint and credential")
		}
		if calls == 1 {
			createdAt = time.Now()
			if r.Method != "POST" || r.URL.Path != "/upload/storage/v1/b/test-bucket/o" || r.URL.Query().Get("uploadType") != "multipart" || r.URL.Query().Get("ifGenerationMatch") != "0" {
				t.Fatalf("unexpected create route: %s", r.URL)
			}
			wire, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			requestBytes += uint64(len(wire))
			if r.ContentLength != int64(len(wire)) {
				t.Fatal("missing exact content length")
			}
			_, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				t.Fatal(err)
			}
			parts := multipart.NewReader(bytes.NewReader(wire), parameters["boundary"])
			metadata, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			var object storage.Object
			if json.NewDecoder(metadata).Decode(&object) != nil || object.Name != "test-run/HEAD" || object.Crc32c != gcpChecksum(body) {
				t.Fatal("incorrect metadata")
			}
			media, err := parts.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			actual, err := io.ReadAll(media)
			if err != nil || !bytes.Equal(actual, body) {
				t.Fatal("incorrect media")
			}
			object.Bucket, object.Generation, object.Size = "test-bucket", 27, uint64(len(body))
			reply, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			responseBytes += uint64(len(reply))
			return gcpSetupReply(200, string(reply)), nil
		}
		if calls != 2 || r.Method != "DELETE" || r.URL.EscapedPath() != "/storage/v1/b/test-bucket/o/test-run%2FHEAD" || r.URL.Query().Get("generation") != "27" || r.URL.Query().Get("ifGenerationMatch") != "27" {
			t.Fatalf("unexpected delete route: %s", r.URL)
		}
		if time.Since(createdAt) < time.Second {
			t.Fatal("HEAD cleanup did not wait for the same-object write interval")
		}
		return gcpSetupReply(204, ""), nil
	})
	if result := s.put(collector.Context, s.head, body); result.Status != contract.WriteAcknowledged {
		t.Fatalf("create status: %+v", result)
	}
	if err := s.delete(collector.Context, s.head, contract.Token{Family: contract.GCP, Value: "27"}); err != nil {
		t.Fatal(err)
	}
	m := liveTelemetrySnapshot(t, collector)
	if calls != 2 || credentials.calls != 2 || liveMetricSum(m, telemetry.HTTPAttempts, "", "", "") != 2 || liveMetricSum(m, telemetry.HTTPRequestBodyBytes, "", "", "complete") != requestBytes || liveMetricSum(m, telemetry.HTTPResponseBodyBytes, "", "", "complete") != responseBytes || liveMetricSum(m, telemetry.HTTPResults, "", "failure", "") != 0 || liveHTTPErrorCount(m) != 0 {
		t.Fatalf("incorrect measurements: %+v", m)
	}
	if liveMetricSum(m, telemetry.OperationResults, "setup.create", "write_acknowledged", "") != 1 || liveMetricSum(m, telemetry.OperationResults, "setup.delete", "success", "") != 1 {
		t.Fatal("setup logical results missing")
	}
}

// full_only: false
func TestGCPSetupRefusalAndUnknownDoNotReplay(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		reply   string
		sendErr error
		want    contract.WriteStatus
	}{
		{"precondition", 412, `{"error":{"code":412,"errors":[{"reason":"conditionNotMet"}]}}`, nil, contract.WritePrecondition},
		{"denied", 403, `{"error":{"code":403}}`, nil, contract.WriteRefused},
		{"expired token", 401, `{"error":{"code":401}}`, nil, contract.WriteRefused},
		{"contradictory status", 500, `{"error":{"code":412,"errors":[{"reason":"conditionNotMet"}]}}`, nil, contract.WriteUnknown},
		{"service failure", 503, `{"error":{"code":503}}`, nil, contract.WriteUnknown},
		{"transport failure", 0, "", errors.New("controlled send failure"), contract.WriteUnknown},
		{"malformed success", 200, `{}`, nil, contract.WriteUnknown},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			collector := liveTelemetry(t)
			credentials := &gcpSetupCredential{}
			calls := 0
			s := newGCPControlledSetup(t, credentials, func(r *http.Request) (*http.Response, error) {
				calls++
				_, _ = io.Copy(io.Discard, r.Body)
				if test.sendErr != nil {
					return nil, test.sendErr
				}
				return gcpSetupReply(test.status, test.reply), nil
			})
			if result := s.put(collector.Context, s.head, []byte("value")); result.Status != test.want {
				t.Fatalf("status = %+v; want %v", result, test.want)
			}
			measurements := liveTelemetrySnapshot(t, collector)
			if calls != 1 || credentials.calls != 1 || liveMetricSum(measurements, telemetry.HTTPAttempts, "setup.create", "", "") != 1 {
				t.Fatal("write was replayed or credential refreshed after send")
			}
			if liveMetricSum(measurements, telemetry.HTTPRequestBodyBytes, "setup.create", "", "complete") == 0 || liveMetricSum(measurements, telemetry.HTTPResponseBodyBytes, "setup.create", "", "") != uint64(len(test.reply)) {
				t.Fatalf("failed request body accounting: %+v", measurements)
			}
			if (liveMetricSum(measurements, telemetry.HTTPResults, "setup.create", "failure", "") != 0) != (test.sendErr != nil) || (liveHTTPErrorCount(measurements) != 0) != (test.status >= 300) {
				t.Fatalf("failed request outcome accounting: %+v", measurements)
			}
		})
	}
}

// full_only: false
func TestGCPSetupAuthenticationFailurePreventsSend(t *testing.T) {
	collector := liveTelemetry(t)
	credentials := &gcpSetupCredential{err: errors.New("controlled token refusal")}
	s := newGCPControlledSetup(t, credentials, func(*http.Request) (*http.Response, error) {
		t.Fatal("request sent after authentication failed")
		return nil, nil
	})
	if result := s.put(collector.Context, s.head, []byte("value")); result.Status != contract.WriteRefused || result.Reason != contract.ReasonAccess {
		t.Fatalf("unexpected result: %+v", result)
	}
	if err := s.delete(collector.Context, s.head, contract.Token{Family: contract.GCP, Value: "27"}); err == nil {
		t.Fatal("cleanup falsely acknowledged")
	}
	if liveMetricSum(liveTelemetrySnapshot(t, collector), telemetry.HTTPAttempts, "", "", "") != 0 {
		t.Fatal("pre-send refusal counted as transport attempt")
	}
}

// full_only: false
func TestGCPSetupReadRetainsAuthenticationCause(t *testing.T) {
	credentials := &gcpSetupCredential{err: errors.New("private credential refusal")}
	s := newGCPControlledSetup(t, credentials, func(*http.Request) (*http.Response, error) {
		t.Fatal("unauthenticated setup check sent a request")
		return nil, nil
	})
	err := s.read(context.Background(), s.storageHost, telemetry.OpSetupRead, func(context.Context) error {
		t.Fatal("unauthenticated setup check entered SDK read")
		return nil
	})
	var failure *gcpSetupFailure
	if !errors.Is(err, errGCPSetup) || !errors.Is(err, credentials.err) || !errors.As(err, &failure) {
		t.Fatalf("setup check lost its authentication cause: %v", err)
	}
	facts := failure.SafeHarnessFailure()
	if !facts.Validate() || facts.Operation != "setup_check" || facts.Stage != "authentication" || facts.Cause != "authentication_refused" || facts.Effect != "no_send" || facts.Attempt != 0 || facts.HTTPStatus != nil || credentials.calls != 1 || strings.Contains(err.Error(), "private") {
		t.Fatalf("setup check facts are incorrect: %+v", facts)
	}
}

// full_only: false
func TestGCPSetupDeleteRefusesChangedOrInvalidGeneration(t *testing.T) {
	credentials := &gcpSetupCredential{}
	calls := 0
	s := newGCPControlledSetup(t, credentials, func(*http.Request) (*http.Response, error) {
		calls++
		return gcpSetupReply(412, `{"error":{"code":412}}`), nil
	})
	if err := s.delete(context.Background(), s.head, contract.Token{Family: contract.GCP, Value: "27"}); err == nil {
		t.Fatal("changed generation was deleted")
	}
	for _, token := range []contract.Token{{Family: contract.GCP, Value: "0"}, {Family: contract.GCP, Value: "027"}, {Family: contract.AWS, Value: `"etag"`}} {
		if err := s.delete(context.Background(), s.head, token); err == nil {
			t.Fatal("invalid generation admitted")
		}
	}
	if err := s.delete(context.Background(), "other-run/HEAD", contract.Token{Family: contract.GCP, Value: "27"}); err == nil {
		t.Fatal("foreign object admitted")
	}
	if calls != 1 || credentials.calls != 1 {
		t.Fatal("refused delete sent or retried")
	}
}

type gcpEarlyEOFBody struct{}

func (gcpEarlyEOFBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (gcpEarlyEOFBody) Close() error             { return nil }

// full_only: false
func TestGCPCleanupRetainsSafeFailureCause(t *testing.T) {
	for _, test := range []struct {
		name, stage, cause, effect string
		status                     int
		credentialErr              error
		sendErr                    error
		reply                      *http.Response
		cancel                     bool
		deadline                   bool
		foreignTarget              bool
		wantSends                  int
	}{
		{name: "foreign target", stage: "admission", cause: "invalid_request", effect: "no_send", foreignTarget: true},
		{name: "credential", stage: "authentication", cause: "authentication_refused", effect: "no_send", credentialErr: errors.New("private credential sentinel")},
		{name: "cancelled", stage: "authentication", cause: "cancelled", effect: "no_send", cancel: true},
		{name: "deadline before send", stage: "authentication", cause: "deadline", effect: "no_send", deadline: true},
		{name: "transport", stage: "conditional_delete", cause: "transport", effect: "unknown", sendErr: errors.New("private transport sentinel"), wantSends: 1},
		{name: "cancel after send", stage: "conditional_delete", cause: "cancelled", effect: "unknown", sendErr: context.Canceled, wantSends: 1},
		{name: "deadline after send", stage: "conditional_delete", cause: "deadline", effect: "unknown", sendErr: context.DeadlineExceeded, wantSends: 1},
		{name: "missing response", stage: "conditional_delete", cause: "missing_response", effect: "unknown", wantSends: 1},
		{name: "early EOF", stage: "response_intake", cause: "early_eof", effect: "unknown", status: 204, reply: &http.Response{StatusCode: 204, Header: make(http.Header), Body: gcpEarlyEOFBody{}, ContentLength: -1}, wantSends: 1},
		{name: "body overflow", stage: "response_intake", cause: "body_overflow", effect: "unknown", status: 204, reply: gcpSetupReply(204, strings.Repeat("x", gcpSetupLimit+1)), wantSends: 1},
		{name: "invalid encoding", stage: "response_intake", cause: "invalid_encoding", effect: "unknown", status: 204, reply: func() *http.Response { r := gcpSetupReply(204, ""); r.Header.Set("Content-Encoding", "gzip"); return r }(), wantSends: 1},
		{name: "invalid length", stage: "response_intake", cause: "invalid_length", effect: "unknown", status: 204, reply: func() *http.Response { r := gcpSetupReply(204, ""); r.ContentLength = 1; return r }(), wantSends: 1},
		{name: "condition", stage: "conditional_delete", cause: "condition_refused", effect: "unknown", status: 412, reply: gcpSetupReply(412, `{"error":{"code":412}}`), wantSends: 1},
		{name: "access", stage: "conditional_delete", cause: "access_refused", effect: "unknown", status: 403, reply: gcpSetupReply(403, `{"error":{"code":403}}`), wantSends: 1},
		{name: "rate limit", stage: "conditional_delete", cause: "provider_refused", effect: "unknown", status: 429, reply: gcpSetupReply(429, `{"error":{"code":429}}`), wantSends: 1},
		{name: "service unavailable", stage: "conditional_delete", cause: "provider_refused", effect: "unknown", status: 503, reply: gcpSetupReply(503, `{"error":{"code":503}}`), wantSends: 1},
		{name: "contradictory envelope", stage: "conditional_delete", cause: "malformed_envelope", effect: "unknown", status: 403, reply: gcpSetupReply(403, `{"error":{"code":412}}`), wantSends: 1},
		{name: "malformed envelope", stage: "conditional_delete", cause: "malformed_envelope", effect: "unknown", status: 403, reply: gcpSetupReply(403, "private invalid body"), wantSends: 1},
		{name: "invalid acknowledgement", stage: "acknowledgement", cause: "invalid_acknowledgement", effect: "unknown", status: 204, reply: gcpSetupReply(204, "unexpected"), wantSends: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentials := &gcpSetupCredential{err: test.credentialErr}
			sends := 0
			s := newGCPControlledSetup(t, credentials, func(*http.Request) (*http.Response, error) {
				sends++
				return test.reply, test.sendErr
			})
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if test.deadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			key := gcpControlledRootKey(s)
			if test.foreignTarget {
				key = "foreign/" + strings.TrimPrefix(key, s.objects)
			}
			err := s.delete(ctx, key, contract.Token{Family: contract.GCP, Value: "27"})
			var typed *gcpSetupFailure
			if !errors.Is(err, errGCPDelete) || !errors.As(err, &typed) {
				t.Fatalf("cleanup did not retain typed cause: %v", err)
			}
			if typed.stage != test.stage || typed.cause != test.cause || typed.status != test.status || typed.effect != test.effect || sends != test.wantSends {
				t.Fatalf("facts = %q/%q/%d/%q, sends = %d; want %q/%q/%d/%q, sends = %d", typed.stage, typed.cause, typed.status, typed.effect, sends, test.stage, test.cause, test.status, test.effect, test.wantSends)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "unexpected") {
				t.Fatal("raw provider or credential text escaped through cleanup error")
			}
			safe := typed.SafeHarnessFailure()
			if !safe.Validate() || safe.Operation != "object_cleanup" || safe.Attempt != uint8(test.wantSends) || (safe.HTTPStatus == nil) != (test.status == 0) {
				t.Fatalf("safe failure facts are invalid: %+v", safe)
			}
			validatedEnvelope := test.cause == "condition_refused" || test.cause == "access_refused" || test.cause == "provider_refused"
			if (safe.EnvelopeStatus != nil) != validatedEnvelope || safe.EnvelopeStatus != nil && int(*safe.EnvelopeStatus) != test.status {
				t.Fatalf("observed and validated status were conflated: %+v", safe)
			}
			if test.sendErr != nil && !errors.Is(err, test.sendErr) || test.credentialErr != nil && !errors.Is(err, test.credentialErr) {
				t.Fatal("in-process underlying cause was lost")
			}
			if test.cancel && !errors.Is(err, context.Canceled) || test.deadline && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("in-process context cause was lost")
			}
			encoded, err := json.Marshal(safe)
			if err != nil || bytes.Contains(encoded, []byte("private")) || bytes.Contains(encoded, []byte("unexpected")) {
				t.Fatal("unsafe cleanup facts were serialised")
			}
		})
	}
}

func gcpAdmittedTestBucket() *storage.Bucket {
	return &storage.Bucket{Name: "test-bucket", ProjectNumber: 123, Location: "US-CENTRAL1", LocationType: "region", StorageClass: "STANDARD", SoftDeletePolicy: &storage.BucketSoftDeletePolicy{RetentionDurationSeconds: 0}}
}

// full_only: false
func TestGCPSetupBucketCompatibility(t *testing.T) {
	c := liveSettings{Bucket: "test-bucket", ProjectNumber: "123", Region: "us-central1"}
	if !gcpBucketAdmitted(gcpAdmittedTestBucket(), c) {
		t.Fatal("simple regional bucket refused")
	}
	cases := []struct {
		name   string
		change func(*storage.Bucket)
	}{
		{"project", func(b *storage.Bucket) { b.ProjectNumber++ }},
		{"bucket", func(b *storage.Bucket) { b.Name = "other-bucket" }},
		{"location", func(b *storage.Bucket) { b.Location = "EU" }},
		{"multi region", func(b *storage.Bucket) { b.LocationType = "multi-region" }},
		{"soft delete", func(b *storage.Bucket) { b.SoftDeletePolicy.RetentionDurationSeconds = 604800 }},
		{"versioning", func(b *storage.Bucket) { b.Versioning = &storage.BucketVersioning{Enabled: true} }},
		{"retention", func(b *storage.Bucket) { b.RetentionPolicy = &storage.BucketRetentionPolicy{RetentionPeriod: 1} }},
		{"object retention", func(b *storage.Bucket) { b.ObjectRetention = &storage.BucketObjectRetention{Mode: "Enabled"} }},
		{"hold", func(b *storage.Bucket) { b.DefaultEventBasedHold = true }},
		{"lifecycle", func(b *storage.Bucket) {
			b.Lifecycle = &storage.BucketLifecycle{Rule: []*storage.BucketLifecycleRule{{}}}
		}},
		{"replication", func(b *storage.Bucket) { b.Rpo = "ASYNC_TURBO" }},
		{"placement", func(b *storage.Bucket) { b.CustomPlacementConfig = &storage.BucketCustomPlacementConfig{} }},
		{"storage class", func(b *storage.Bucket) { b.StorageClass = "ARCHIVE" }},
		{"automatic class", func(b *storage.Bucket) { b.Autoclass = &storage.BucketAutoclass{Enabled: true} }},
		{"hierarchical namespace", func(b *storage.Bucket) { b.HierarchicalNamespace = &storage.BucketHierarchicalNamespace{Enabled: true} }},
		{"requester pays", func(b *storage.Bucket) { b.Billing = &storage.BucketBilling{RequesterPays: true} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			bucket := gcpAdmittedTestBucket()
			test.change(bucket)
			if gcpBucketAdmitted(bucket, c) {
				t.Fatal("incompatible bucket admitted")
			}
		})
	}
}

// full_only: false
func TestGCPSetupChecksIndependentPublicKey(t *testing.T) {
	der := testtrust.New(t, contract.GCP, contract.ID{1}).PublicKey()
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	otherDER := testtrust.New(t, contract.GCP, contract.ID{2}).PublicKey()
	c := liveSettings{Bucket: "test-bucket", ProjectNumber: "123", Region: "us-central1", KeyID: "projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1"}
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching key", true: "different key"}[mismatch], func(t *testing.T) {
			collector := liveTelemetry(t)
			credentials := &gcpSetupCredential{}
			calls := 0
			s := newGCPControlledSetup(t, credentials, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" {
					t.Fatal("configuration check attempted a write")
				}
				if calls > 1 && r.URL.Host != "us-central1-cloudkms.googleapis.com" {
					t.Fatalf("unexpected KMS resource-check route: %s", r.URL)
				}
				var reply any
				switch calls {
				case 1:
					reply = gcpAdmittedTestBucket()
				case 2:
					reply = &cloudkms.CryptoKey{Name: strings.TrimSuffix(c.KeyID, "/cryptoKeyVersions/1"), Purpose: "ASYMMETRIC_SIGN"}
				case 3:
					reply = &cloudkms.CryptoKeyVersion{Name: c.KeyID, State: "ENABLED", Algorithm: "EC_SIGN_P256_SHA256"}
				case 4:
					reply = &cloudkms.PublicKey{Name: c.KeyID, Algorithm: "EC_SIGN_P256_SHA256", Pem: keyPEM, PemCrc32c: int64(crc32.Checksum([]byte(keyPEM), crc32.MakeTable(crc32.Castagnoli)))}
				default:
					t.Fatal("configuration request replayed")
				}
				body, err := json.Marshal(reply)
				if err != nil {
					t.Fatal(err)
				}
				return gcpSetupReply(200, string(body)), nil
			})
			expected := bytes.Clone(der)
			if mismatch {
				expected = otherDER
			}
			err := s.check(collector.Context, c, expected)
			if (err != nil) != mismatch {
				t.Fatalf("key comparison result: %v", err)
			}
			if mismatch {
				var failure *gcpSetupFailure
				if !errors.Is(err, errGCPSetup) || !errors.As(err, &failure) {
					t.Fatal("configuration mismatch lost its typed cause")
				}
				facts := failure.SafeHarnessFailure()
				if !facts.Validate() || facts.Operation != "setup_check" || facts.Stage != "ownership_check" || facts.Cause != "ownership_mismatch" || facts.Effect != "no_effect" || facts.Attempt != 1 || facts.HTTPStatus == nil || *facts.HTTPStatus != 200 {
					t.Fatalf("configuration mismatch facts are incorrect: %+v", facts)
				}
			}
			m := liveTelemetrySnapshot(t, collector)
			publicResult := "success"
			if mismatch {
				publicResult = "failure"
			}
			if calls != 4 || credentials.calls != 4 || liveMetricSum(m, telemetry.HTTPAttempts, "", "", "") != 4 || liveMetricSum(m, telemetry.OperationResults, "setup.read", "success", "") != 3 || liveMetricSum(m, telemetry.OperationResults, "setup.public_key", publicResult, "") != 1 {
				t.Fatal("not all configured resources were checked and measured")
			}
		})
	}
}

// full_only: false
func TestGCPSetupTransportRejectsReplayAndTruncation(t *testing.T) {
	collector := liveTelemetry(t)
	credentials := &gcpSetupCredential{}
	s := newGCPControlledSetup(t, credentials, func(*http.Request) (*http.Response, error) {
		reply := gcpSetupReply(200, "truncated")
		reply.ContentLength++
		return reply, nil
	})
	ctx, _, err := s.begin(collector.Context, s.storageHost, telemetry.OpSetupRead)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+s.storageHost+"/storage/v1/b/test-bucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.transport.RoundTrip(req); err == nil {
		t.Fatal("truncated response admitted")
	}
	if _, err := s.transport.RoundTrip(req); err == nil {
		t.Fatal("replay admitted")
	}
	m := liveTelemetrySnapshot(t, collector)
	if liveMetricSum(m, telemetry.HTTPAttempts, "setup.read", "", "") != 1 || liveMetricSum(m, telemetry.HTTPResults, "setup.read", "failure", "") != 1 || liveMetricSum(m, telemetry.HTTPResponseBodyBytes, "setup.read", "", "incomplete") != uint64(len("truncated")) {
		t.Fatalf("incorrect failed-body measurements: %+v", m)
	}
}

// full_only: false
func TestGCPSetupTelemetryFailureDoesNotChangeWrite(t *testing.T) {
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
			credentials := &gcpSetupCredential{}
			calls := 0
			s := newGCPControlledSetup(t, credentials, func(r *http.Request) (*http.Response, error) {
				calls++
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Fatal(err)
				}
				body, err := json.Marshal(storage.Object{Name: "test-run/HEAD", Bucket: "test-bucket", Generation: 27, Size: 5, Crc32c: gcpChecksum([]byte("owned"))})
				if err != nil {
					t.Fatal(err)
				}
				return gcpSetupReply(200, string(body)), nil
			})
			if result := s.put(ctx, s.head, []byte("owned")); result.Status != contract.WriteAcknowledged || calls != 1 || credentials.calls != 1 {
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
