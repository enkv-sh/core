package awsprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectTelemetry(t *testing.T) (context.Context, func() metricdata.ResourceMetrics) {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"exporters":[]},"metrics":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: t.TempDir(), ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	ready, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.AwaitMetrics(ready); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(closeContext); err != nil {
			t.Error(err)
		}
	})
	return runtime.Context(context.Background()), func() metricdata.ResourceMetrics {
		flushContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.FlushMetrics(flushContext); err != nil {
			t.Fatal(err)
		}
		var data metricdata.ResourceMetrics
		if err := runtime.ManualReader().Collect(flushContext, &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
}

func telemetrySum(data metricdata.ResourceMetrics, name string, operation telemetry.Operation, result, status string) int64 {
	var sum int64
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			for _, point := range metric.Data.(metricdata.Sum[int64]).DataPoints {
				provider, _ := point.Attributes.Value("provider")
				op, _ := point.Attributes.Value("operation")
				r, _ := point.Attributes.Value("result")
				s, _ := point.Attributes.Value("status")
				if provider.AsString() == "aws" && op.AsString() == string(operation) && (result == "" || r.AsString() == result) && (status == "" || s.AsString() == status) {
					sum += point.Value
				}
			}
		}
	}
	return sum
}

// full_only: false
func TestTelemetryStoreReadIncludesCredentialsAndHTTP(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	calls := 0
	s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(200, "body", http.Header{"Etag": []string{`"opaque"`}}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := s.Read(ctx, s.Descriptor().HeadKey, 32)
	if got.Status != contract.ReadOK || string(got.Body) != "body" || calls != 1 {
		t.Fatalf("read=%+v calls=%d", got, calls)
	}
	data := snapshot()
	for _, tc := range []struct {
		name           string
		op             telemetry.Operation
		result, status string
		want           int64
	}{
		{telemetry.OperationCalls, telemetry.OpStoreRead, "", "", 1},
		{telemetry.OperationResults, telemetry.OpStoreRead, "read_ok", "", 1},
		{telemetry.OperationOutputBytes, telemetry.OpStoreRead, "read_ok", "", 4},
		{telemetry.OperationResults, telemetry.OpAuthentication, "success", "", 1},
		{telemetry.HTTPAttempts, telemetry.OpStoreRead, "", "", 1},
		{telemetry.HTTPResults, telemetry.OpStoreRead, "success", "2xx", 1},
		{telemetry.HTTPRequestBodyObservations, telemetry.OpStoreRead, "", "complete", 1},
		{telemetry.HTTPResponseBodyObservations, telemetry.OpStoreRead, "", "complete", 1},
		{telemetry.HTTPResponseBodyBytes, telemetry.OpStoreRead, "", "complete", 4},
	} {
		if got := telemetrySum(data, tc.name, tc.op, tc.result, tc.status); got != tc.want {
			t.Errorf("%s %s %s %s = %d, want %d", tc.name, tc.op, tc.result, tc.status, got, tc.want)
		}
	}
}

// full_only: false
func TestTelemetryStoreListKeepsBoundedResultsAndNoNames(t *testing.T) {
	for _, mode := range []string{"success", "malformed", "refused", "lost-reply", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			if mode == "disabled" {
				ctx = context.Background()
			}
			c := testStoreConfig()
			key := c.Prefix + "/" + fmt.Sprintf("%x", c.Domain) + "/synthetic-private-key"
			body := listReply(c, []string{key}, "", "synthetic-private-cursor")
			calls := 0
			s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if mode == "lost-reply" {
					return nil, errors.New("synthetic-private-provider-error")
				}
				if mode == "malformed" {
					return response(200, "synthetic-private-malformed", nil), nil
				}
				return response(200, body, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			cursor := ""
			if mode == "refused" {
				cursor = strings.Repeat("synthetic-private-cursor", 200)
			}
			got := s.ListPage(ctx, cursor)
			want, result, wantCalls := contract.ListPageOK, "read_ok", 1
			if mode == "malformed" || mode == "refused" {
				want, result = contract.ListPageInvalid, "read_invalid"
			}
			if mode == "refused" {
				wantCalls = 0
			}
			if mode == "lost-reply" {
				want, result = contract.ListPageUnavailable, "read_unavailable"
			}
			if got.Status != want || calls != wantCalls {
				t.Fatal("telemetry changed Store listing outcome", got.Status, calls)
			}
			data := snapshot()
			if mode == "disabled" {
				if len(data.ScopeMetrics) != 0 {
					t.Fatal("disabled listing emitted metrics")
				}
				return
			}
			if telemetrySum(data, telemetry.OperationCalls, telemetry.OpStoreList, "", "") != 1 || telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreList, result, "") != 1 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreList, "", "") != int64(wantCalls) {
				t.Fatal("listing call/result/physical-attempt count differs")
			}
			if want == contract.ListPageOK && telemetrySum(data, telemetry.OperationOutputBytes, telemetry.OpStoreList, result, "") != int64(len(key)+len("synthetic-private-cursor")) {
				t.Fatal("listing owned-byte count differs")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

// full_only: false
func TestTelemetryStoreWriteResultsAndActualBodies(t *testing.T) {
	for _, op := range []telemetry.Operation{telemetry.OpStoreCreate, telemetry.OpStoreCompareAndSwap} {
		for _, mode := range []string{"success", "precondition", "conflict", "lost-reply", "partial-request"} {
			t.Run(string(op)+"/"+mode, func(t *testing.T) {
				t.Setenv("ENKV_TELEMETRY", "1")
				ctx, snapshot := collectTelemetry(t)
				calls := 0
				body := []byte("synthetic-private-object-content")
				requestBytes := len(body)
				requestStatus := "complete"
				if mode == "partial-request" {
					requestBytes, requestStatus = 2, "incomplete"
				}
				responseBody := ""
				s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if n, err := io.CopyN(io.Discard, r.Body, int64(requestBytes)); err != nil || n != int64(requestBytes) {
						t.Errorf("request bytes=%d err=%v", n, err)
					}
					switch mode {
					case "precondition":
						responseBody = "<Error><Code>PreconditionFailed</Code><Message>synthetic-private-error</Message></Error>"
						return response(412, responseBody, nil), nil
					case "conflict":
						responseBody = "<Error><Code>ConditionalRequestConflict</Code></Error>"
						return response(409, responseBody, nil), nil
					case "lost-reply":
						return nil, errors.New("synthetic-private-lost-reply")
					default:
						return response(200, "", nil), nil
					}
				}))
				if err != nil {
					t.Fatal(err)
				}
				var got contract.WriteResult
				if op == telemetry.OpStoreCreate {
					got = s.Create(ctx, testImmutableKey("member", 0), body)
				} else {
					got = s.CompareAndSwap(ctx, s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"synthetic-private-token"`}, body)
				}
				wantResult := "write_acknowledged"
				wantStatus := contract.WriteAcknowledged
				switch mode {
				case "precondition":
					wantResult, wantStatus = "write_precondition", contract.WritePrecondition
				case "conflict":
					wantResult, wantStatus = "write_conflict", contract.WriteConflict
				case "lost-reply":
					wantResult, wantStatus = "write_unknown", contract.WriteUnknown
				}
				if got.Status != wantStatus || calls != 1 {
					t.Fatalf("write=%+v calls=%d", got, calls)
				}
				data := snapshot()
				if telemetrySum(data, telemetry.OperationResults, op, wantResult, "") != 1 || telemetrySum(data, telemetry.OperationInputBytes, op, wantResult, "") != int64(len(body)) {
					t.Error("logical write result or input bytes were lost")
				}
				if telemetrySum(data, telemetry.HTTPAttempts, op, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", requestStatus) != int64(requestBytes) || telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", requestStatus) != 1 {
					t.Error("actual request bytes or completeness differ")
				}
				responseStatus := "complete"
				if mode == "lost-reply" {
					responseStatus = "incomplete"
				}
				if telemetrySum(data, telemetry.HTTPResponseBodyBytes, op, "", responseStatus) != int64(len(responseBody)) || telemetrySum(data, telemetry.HTTPResponseBodyObservations, op, "", responseStatus) != 1 {
					t.Error("actual response bytes or completeness differ")
				}
				assertSafeTelemetry(t, data)
			})
		}
	}
}

// full_only: false
func TestTelemetryReadIncompleteResponsesRemainIncomplete(t *testing.T) {
	for _, mode := range []string{"truncated", "body-error", "oversized", "encoded", "missing"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			var body *countedBody
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				r := response(404, "<Error><Code>NoSuchKey</Code></Error>", nil)
				switch mode {
				case "truncated":
					r.ContentLength++
				case "body-error":
					r.Body = &failingBody{data: []byte("partial")}
				case "oversized":
					r = response(404, strings.Repeat("x", maxErrorResponse+10), nil)
				case "encoded":
					r.Header.Set("Content-Encoding", "gzip")
				}
				body = &countedBody{ReadCloser: r.Body}
				r.Body = body
				return r, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.Read(ctx, s.Descriptor().HeadKey, 1)
			wantStatus, result, complete, httpResult := contract.ReadUnavailable, "read_unavailable", "incomplete", "failure"
			if mode == "missing" {
				wantStatus, result, complete, httpResult = contract.ReadMissing, "read_missing", "complete", "success"
			}
			if got.Status != wantStatus || calls != 1 || body == nil || !body.closed || body.bytes > maxErrorResponse+1 {
				t.Fatalf("read=%+v calls=%d body=%+v", got, calls, body)
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreRead, result, "") != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreRead, httpResult, "4xx") != 1 {
				t.Error("bounded read or transport result differs")
			}
			if telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpStoreRead, "", complete) != int64(body.bytes) || telemetrySum(data, telemetry.HTTPResponseBodyObservations, telemetry.OpStoreRead, "", complete) != 1 {
				t.Error("response completeness or actual byte count differs")
			}
		})
	}
}

// full_only: false
func TestTelemetryRefusalDoesNotAcquireCredentialsOrAttemptHTTP(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	c := testStoreConfig()
	credentials, calls := 0, 0
	c.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		credentials++
		return aws.Credentials{}, errors.New("synthetic-private-credential-error")
	})
	s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Read(ctx, "synthetic-private-key", 10).Status != contract.ReadInvalid || s.Create(ctx, s.Descriptor().HeadKey, []byte("private")).Status != contract.WriteRefused || s.CompareAndSwap(ctx, "synthetic-private-key", contract.Token{}, []byte("private")).Status != contract.WriteRefused {
		t.Fatal("construction refusal changed")
	}
	if credentials != 0 || calls != 0 {
		t.Fatal("refusal acquired credentials or attempted HTTP")
	}
	if s.Read(ctx, s.Descriptor().HeadKey, 10).Status != contract.ReadUnavailable || credentials != 1 || calls != 0 {
		t.Fatal("credential failure changed")
	}
	data := snapshot()
	for _, op := range []telemetry.Operation{telemetry.OpStoreRead, telemetry.OpStoreCreate, telemetry.OpStoreCompareAndSwap} {
		if telemetrySum(data, telemetry.HTTPAttempts, op, "", "") != 0 {
			t.Error("local refusal counted an HTTP attempt")
		}
	}
	if telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "failure", "") != 1 || telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreRead, "read_invalid", "") != 1 || telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreCreate, "write_refused", "") != 1 || telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreCompareAndSwap, "write_refused", "") != 1 {
		t.Error("refusal or authentication result was lost")
	}
	assertSafeTelemetry(t, data)
}

// full_only: false
func TestTelemetryTrustSignUsesLogicalDigestAndActualHTTPBodies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sc := testStoreConfig()
	c := TrustConfig{Region: sc.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: der, CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: sc.Timeout}
	id := contract.Hash([]byte("synthetic-private-subject"))
	req, err := contract.NewBindingRequest(contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: id, PublicKey: id, Interpretation: id, ControlIncarnationID: id, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "invalid-signature", "unavailable", "invalid-request"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			calls, requestBytes, responseBytes := 0, 0, 0
			trust, err := newTrust(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				requestBytes += len(body)
				if mode == "unavailable" {
					return nil, errors.New("synthetic-private-sign-error")
				}
				digest := req.Digest()
				sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
				if err != nil {
					t.Fatal(err)
				}
				if mode == "invalid-signature" {
					sig = []byte("synthetic-private-invalid-signature")
				}
				encoded, err := json.Marshal(map[string]any{"KeyId": c.KeyARN, "SigningAlgorithm": "ECDSA_SHA_256", "Signature": base64.StdEncoding.EncodeToString(sig)})
				if err != nil {
					t.Fatal(err)
				}
				responseBytes += len(encoded)
				return response(200, string(encoded), http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			input := req
			wantCalls, inputBytes, result := int64(1), int64(32), "sign_ok"
			switch mode {
			case "invalid-request":
				input, wantCalls, inputBytes, result = contract.SignRequest{}, 0, 0, "sign_invalid"
			case "invalid-signature":
				result = "sign_invalid"
			case "unavailable":
				result = "sign_unavailable"
			}
			got := trust.Sign(ctx, input)
			if mode == "success" {
				digest := req.Digest()
				if got.Reason != contract.ReasonNone || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], got.Signature) {
					t.Fatal("valid signature refused")
				}
			} else if got.Reason == contract.ReasonNone || len(got.Signature) != 0 {
				t.Fatal("invalid signature accepted")
			}
			data := snapshot()
			if int64(calls) != wantCalls || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpTrustSign, "", "") != wantCalls || telemetrySum(data, telemetry.OperationResults, telemetry.OpTrustSign, result, "") != 1 {
				t.Error("sign result or HTTP attempts differ")
			}
			if telemetrySum(data, telemetry.OperationInputBytes, telemetry.OpTrustSign, result, "") != inputBytes || telemetrySum(data, telemetry.OperationOutputBytes, telemetry.OpTrustSign, result, "") != int64(len(got.Signature)) {
				t.Error("logical digest or signature bytes differ")
			}
			if telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpTrustSign, "", "") != int64(requestBytes) || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpTrustSign, "", "") != int64(responseBytes) {
				t.Error("actual HTTP body bytes differ")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

func assertSafeTelemetry(t *testing.T, data metricdata.ResourceMetrics) {
	t.Helper()
	check := func(attrs attribute.Set) {
		for _, attr := range attrs.ToSlice() {
			if !telemetry.AllowedAttribute(string(attr.Key), attr.Value.AsString()) {
				t.Errorf("unbounded metric attribute: %s", attr.Key)
			}
		}
	}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if !telemetry.ValidMetric(m.Name, m.Unit) {
				t.Errorf("unbounded metric: %s", m.Name)
			}
			switch values := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range values.DataPoints {
					check(point.Attributes)
				}
			case metricdata.Histogram[float64]:
				for _, point := range values.DataPoints {
					check(point.Attributes)
				}
			}
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"synthetic-private", "fixture-bucket", "fixture-access", "fixture-secret", "enkv/domain", "arn:aws:", "amazonaws.com"} {
		if strings.Contains(string(encoded), secret) {
			t.Error("sensitive data entered telemetry")
		}
	}
}

// full_only: false
func TestTelemetryDisabledAndFullQueuePreserveCorrectness(t *testing.T) {
	for _, mode := range []string{"", "0", "true", "1", "full-queue"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", mode)
			ctx, snapshot := collectTelemetry(t)
			var fullQueue *telemetry.Capability
			if mode == "full-queue" {
				fullQueue = telemetry.NewCapability(make(chan telemetry.MetricPoint), nil)
				ctx = telemetry.WithCapability(context.Background(), fullQueue)
			} else if mode != "1" {
				ctx = context.Background()
			}
			calls := 0
			s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Body != nil && r.Body != http.NoBody {
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != "synthetic-private-body" {
						t.Error("request body changed")
					}
				}
				return response(200, "", nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if s.Create(ctx, testImmutableKey("member", 0), []byte("synthetic-private-body")).Status != contract.WriteAcknowledged || calls != 1 {
				t.Fatal("telemetry changed write correctness")
			}
			data := snapshot()
			if mode == "1" {
				if telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreCreate, "write_acknowledged", "") != 1 {
					t.Error("enabled telemetry absent")
				}
			} else if len(data.ScopeMetrics) != 0 {
				t.Error("disabled or saturated instrumentation recorded metrics")
			}
			if mode == "full-queue" && fullQueue.LostMetrics() == 0 {
				t.Error("saturated metric handoff did not count loss")
			}
		})
	}
}

// full_only: false
func TestTelemetrySharedFileAcquisitionHasNoCredentialData(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	path := sharedCredentialFile(t, "[explicit]\naws_access_key_id=synthetic-private-access\naws_secret_access_key=synthetic-private-secret\n")
	if _, err := LoadSharedCredentialsFile(ctx, path, "explicit", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSharedCredentialsFile(ctx, path, "missing", time.Time{}); !errors.Is(err, ErrCredentials) {
		t.Fatal("invalid credential profile accepted")
	}
	data := snapshot()
	if telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "success", "") != 1 || telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "failure", "") != 1 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != 0 {
		t.Error("file credential acquisition boundaries differ")
	}
	assertSafeTelemetry(t, data)
}

// full_only: false
func TestTelemetryHTTPWaitsForRequestCompletion(t *testing.T) {
	for _, mode := range []string{"complete", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			s, err := newStore(testStoreConfig(), base)
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan contract.WriteResult, 1)
			go func() {
				returned <- s.Create(ctx, testImmutableKey("member", 0), []byte("abc"))
			}()
			<-base.started
			data := snapshot()
			if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreCreate, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreCreate, "", "") != 0 {
				t.Error("HTTP result preceded request completion")
			}
			if mode == "cancelled" {
				cancel()
				if got := <-returned; got.Status != contract.WriteUnknown {
					t.Errorf("cancelled write=%+v", got)
				}
				data = snapshot()
				if telemetrySum(data, telemetry.HTTPRequestBodyObservations, telemetry.OpStoreCreate, "", "incomplete") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCreate, "", "") != 0 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreCreate, "failure", "2xx") != 1 {
					t.Error("cancelled transfer was marked complete")
				}
				close(base.release)
			} else {
				close(base.release)
				if got := <-returned; got.Status != contract.WriteAcknowledged {
					t.Errorf("complete write=%+v", got)
				}
				data = snapshot()
				if telemetrySum(data, telemetry.HTTPRequestBodyObservations, telemetry.OpStoreCreate, "", "complete") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCreate, "", "complete") != 3 {
					t.Error("joined request bytes were lost")
				}
			}
			<-base.consumed
			if mode == "cancelled" {
				data = snapshot()
				if telemetrySum(data, telemetry.HTTPRequestBodyObservations, telemetry.OpStoreCreate, "", "incomplete") != 0 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCreate, "", "") != 0 {
					t.Error("late reads changed a completed partial observation")
				}
			}
		})
	}
}

// full_only: false
func TestTelemetryDisabledDoesNotAllocateOrWrapBodies(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	_, snapshot := collectTelemetry(t)
	ctx := context.Background()
	body := io.NopCloser(strings.NewReader("abc"))
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/", body)
	if err != nil {
		t.Fatal(err)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		gotCtx, call := startTelemetry(ctx, telemetry.OpStoreCreate)
		if gotCtx != ctx || call != nil || startHTTPTelemetry(r) != nil {
			panic("disabled telemetry changed context or created observers")
		}
	}); allocations != 0 {
		t.Fatalf("disabled telemetry allocations=%g", allocations)
	}
	if r.Body != body || len(snapshot().ScopeMetrics) != 0 {
		t.Fatal("disabled telemetry wrapped body or produced metrics")
	}
}

// full_only: false
func TestTelemetryRejectsReplayBeforeCountingHTTPAttempts(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	ctx, call := startTelemetry(ctx, telemetry.OpStoreRead)
	defer call.Finish(telemetry.ResultReadOK)
	calls := 0
	transport := boundedTransport{host: "fixture.invalid", next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(200, "body", nil), nil
	})}
	r, err := http.NewRequestWithContext(operationContext(ctx, 8), http.MethodGet, "https://fixture.invalid/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(r); !errors.Is(err, errTransport) || calls != 1 {
		t.Fatalf("replay error=%v calls=%d", err, calls)
	}
	if r.Body != http.NoBody {
		t.Fatal("telemetry changed known-empty request framing")
	}
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreRead, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreRead, "", "") != 1 {
		t.Fatal("refused replay counted as a physical attempt")
	}
}
