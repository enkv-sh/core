package gcp

import (
	"bytes"
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
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
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
				if provider.AsString() == "gcp" && op.AsString() == string(operation) && (result == "" || r.AsString() == result) && (status == "" || s.AsString() == status) {
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
	s, creds := newStore(t, func(*http.Request) (*http.Response, error) {
		calls++
		out := response(200, "body")
		out.Header.Set("X-Goog-Generation", "42")
		return out, nil
	})
	got := s.Read(ctx, s.Descriptor().HeadKey, 32)
	if got.Status != contract.ReadOK || string(got.Body) != "body" || got.Token.Value != "42" || calls != 1 || creds.calls != 1 {
		t.Fatalf("read=%+v sends=%d credentials=%d", got, calls, creds.calls)
	}
	data := snapshot()
	assertTelemetryDuration(t, data, telemetry.OperationDuration, telemetry.OpStoreRead)
	assertTelemetryDuration(t, data, telemetry.OperationDuration, telemetry.OpAuthentication)
	assertTelemetryDuration(t, data, telemetry.HTTPDuration, telemetry.OpStoreRead)
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
			var key, body string
			calls := 0
			s, _ := newStore(t, func(*http.Request) (*http.Response, error) {
				calls++
				if mode == "lost-reply" {
					return nil, errors.New("synthetic-private-provider-error")
				}
				if mode == "malformed" {
					return response(200, "synthetic-private-malformed"), nil
				}
				return response(200, body), nil
			})
			key = s.config.Prefix + "/" + fmt.Sprintf("%x", s.config.Domain) + "/synthetic-private-key"
			body = listReply([]string{key}, "synthetic-private-cursor")
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
	for _, secret := range []string{"synthetic-private", "fixture-bucket", "fixture-token", "fixture@example", "synthetic-key-id", "fixture-project", "googleapis.com"} {
		if strings.Contains(string(encoded), secret) {
			t.Error("sensitive data entered telemetry")
		}
	}
}

func assertTelemetryDuration(t *testing.T, data metricdata.ResourceMetrics, name string, operation telemetry.Operation) {
	t.Helper()
	var count uint64
	for _, scope := range data.ScopeMetrics {
		for _, measurement := range scope.Metrics {
			if measurement.Name != name {
				continue
			}
			if measurement.Unit != "s" {
				t.Error("duration unit differs")
			}
			for _, point := range measurement.Data.(metricdata.Histogram[float64]).DataPoints {
				provider, _ := point.Attributes.Value("provider")
				op, _ := point.Attributes.Value("operation")
				if provider.AsString() == "gcp" && op.AsString() == string(operation) {
					count += point.Count
					if point.Sum < 0 {
						t.Error("negative operation duration")
					}
				}
			}
		}
	}
	if count != 1 {
		t.Errorf("%s %s duration count=%d", name, operation, count)
	}
}

// full_only: false
func TestTelemetryStoreWriteResultsAndActualMultipart(t *testing.T) {
	for _, op := range []telemetry.Operation{telemetry.OpStoreCreate, telemetry.OpStoreCompareAndSwap} {
		for _, mode := range []string{"success", "precondition", "refused", "lost-reply", "partial-request", "partial-response"} {
			t.Run(string(op)+"/"+mode, func(t *testing.T) {
				t.Setenv("ENKV_TELEMETRY", "1")
				ctx, snapshot := collectTelemetry(t)
				body := []byte("synthetic-private-object-content")
				calls, requestBytes, responseBytes := 0, 0, 0
				var s *Store
				s, _ = newStore(t, func(r *http.Request) (*http.Response, error) {
					calls++
					expectedGeneration, key := "0", childKey(s)
					if op == telemetry.OpStoreCompareAndSwap {
						expectedGeneration, key = "42", s.Descriptor().HeadKey
					}
					if r.URL.Query().Get("ifGenerationMatch") != expectedGeneration || r.GetBody != nil || !r.Close {
						t.Error("conditional request or replay policy changed")
					}
					reader := io.Reader(r.Body)
					if mode == "partial-request" {
						reader = io.LimitReader(reader, 5)
					}
					raw, err := io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
					requestBytes += len(raw)
					if mode == "partial-request" || mode == "lost-reply" {
						return nil, errors.New("synthetic-private-send-error")
					}
					kind, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
					if err != nil || kind != "multipart/related" {
						t.Fatal("invalid multipart request")
					}
					parts := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
					metadata, err := parts.NextPart()
					if err != nil {
						t.Fatal(err)
					}
					var fields map[string]any
					if json.NewDecoder(metadata).Decode(&fields) != nil || fields["name"] != key || fields["crc32c"] != crcBase64(body) {
						t.Fatal("multipart metadata changed")
					}
					media, err := parts.NextPart()
					if err != nil {
						t.Fatal(err)
					}
					actual, err := io.ReadAll(media)
					if err != nil || !bytes.Equal(actual, body) || int64(len(raw)) != r.ContentLength {
						t.Fatal("multipart payload or length changed")
					}
					if _, err := parts.NextPart(); err != io.EOF {
						t.Fatal("unexpected multipart part")
					}
					var reply *http.Response
					switch mode {
					case "precondition":
						reply = apiFailure(412, "conditionNotMet")
					case "refused":
						reply = apiFailure(403, "forbidden")
					default:
						encoded, err := json.Marshal(map[string]string{"bucket": s.config.Bucket, "name": key, "generation": "43", "size": strconv.Itoa(len(body)), "crc32c": crcBase64(body)})
						if err != nil {
							t.Fatal(err)
						}
						reply = response(200, string(encoded))
					}
					responseBytes += int(reply.ContentLength)
					if mode == "partial-response" {
						reply.ContentLength++
					}
					return reply, nil
				})
				var got contract.WriteResult
				if op == telemetry.OpStoreCreate {
					got = s.Create(ctx, childKey(s), body)
				} else {
					got = s.CompareAndSwap(ctx, s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "42"}, body)
				}
				want, result, httpResult, requestStatus, responseStatus := contract.WriteAcknowledged, "write_acknowledged", "success", "complete", "complete"
				switch mode {
				case "precondition":
					want, result = contract.WritePrecondition, "write_precondition"
					if op == telemetry.OpStoreCreate {
						result = string(telemetry.ResultVerificationPending)
					}
				case "refused":
					want, result = contract.WriteRefused, "write_refused"
				case "lost-reply", "partial-request", "partial-response":
					want, result, httpResult, responseStatus = contract.WriteUnknown, "write_unknown", "failure", "incomplete"
				}
				if mode == "partial-request" {
					requestStatus = "incomplete"
				}
				if got.Status != want || calls != 1 {
					t.Fatalf("write=%+v sends=%d", got, calls)
				}
				data := snapshot()
				if telemetrySum(data, telemetry.OperationResults, op, result, "") != 1 || telemetrySum(data, telemetry.OperationInputBytes, op, result, "") != int64(len(body)) || telemetrySum(data, telemetry.HTTPAttempts, op, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, op, httpResult, "") != 1 {
					t.Error("write result, logical input or physical attempt differs")
				}
				if telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", requestStatus) != int64(requestBytes) || telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", requestStatus) != 1 {
					t.Error("actual multipart bytes or completeness differs")
				}
				if telemetrySum(data, telemetry.HTTPResponseBodyBytes, op, "", responseStatus) != int64(responseBytes) || telemetrySum(data, telemetry.HTTPResponseBodyObservations, op, "", responseStatus) != 1 {
					t.Error("response bytes or completeness differs")
				}
				if mode != "partial-request" && requestBytes <= len(body) {
					t.Fatal("multipart overhead was not observed")
				}
				assertSafeTelemetry(t, data)
			})
		}
	}
}

// full_only: false
func TestTelemetryReadKeepsIncompleteBodiesUnknown(t *testing.T) {
	for _, mode := range []string{"missing", "short", "interrupted", "oversized", "encoded", "close-error"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			calls := 0
			var observed *telemetryTestBody
			s, _ := newStore(t, func(*http.Request) (*http.Response, error) {
				calls++
				reply := response(200, "body")
				reply.Header.Set("X-Goog-Generation", "42")
				switch mode {
				case "missing":
					reply = apiFailure(404, "notFound")
				case "short":
					reply.ContentLength++
				case "interrupted":
					reply.ContentLength = -1
					reply.Body = io.NopCloser(&interruptedBody{body: "body"})
				case "oversized":
					reply = response(200, strings.Repeat("x", 100))
				case "encoded":
					reply.Header.Set("Content-Encoding", "gzip")
				}
				observed = &telemetryTestBody{ReadCloser: reply.Body}
				if mode == "close-error" {
					observed.closeErr = errors.New("synthetic-private-close-error")
				}
				reply.Body = observed
				return reply, nil
			})
			got := s.Read(ctx, s.Descriptor().HeadKey, 4)
			want, result, httpResult, status := contract.ReadUnavailable, "read_unavailable", "failure", "incomplete"
			switch mode {
			case "missing":
				want, result, httpResult, status = contract.ReadMissing, "read_missing", "success", "complete"
			case "oversized":
				want, result = contract.ReadInvalid, "read_invalid"
			case "close-error":
				want, result, httpResult = contract.ReadOK, "read_ok", "success"
			}
			if got.Status != want || calls != 1 || observed == nil || !observed.closed || (mode == "oversized" && observed.bytes != 5) {
				t.Fatalf("read=%+v sends=%d body=%+v", got, calls, observed)
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreRead, result, "") != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreRead, httpResult, "") != 1 || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpStoreRead, "", status) != int64(observed.bytes) || telemetrySum(data, telemetry.HTTPResponseBodyObservations, telemetry.OpStoreRead, "", status) != 1 {
				t.Error("read result or incomplete observation differs")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

type telemetryTestBody struct {
	io.ReadCloser
	bytes    int
	closed   bool
	closeErr error
}

func (body *telemetryTestBody) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	body.bytes += n
	return n, err
}
func (body *telemetryTestBody) Close() error {
	body.closed = true
	err := body.ReadCloser.Close()
	if err != nil {
		return err
	}
	return body.closeErr
}

// full_only: false
func TestTelemetryRefusalDoesNotAcquireCredentialsOrAttemptHTTP(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	calls := 0
	s, creds := newStore(t, func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })
	if s.Read(ctx, "synthetic-private-key", 10).Status != contract.ReadInvalid || s.Create(ctx, s.Descriptor().HeadKey, []byte("private")).Status != contract.WriteRefused || s.CompareAndSwap(ctx, "synthetic-private-key", contract.Token{}, []byte("private")).Status != contract.WriteRefused {
		t.Fatal("construction refusal changed")
	}
	if creds.calls != 0 || calls != 0 {
		t.Fatal("refusal acquired credentials or attempted HTTP")
	}
	creds.err = errors.New("synthetic-private-credential-error")
	if s.Read(ctx, s.Descriptor().HeadKey, 10).Status != contract.ReadUnavailable || creds.calls != 1 || calls != 0 {
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
func TestTelemetryTrustSignUsesDigestAndActualHTTPBodies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	req := signRequest(t)
	for _, mode := range []string{"success", "invalid-signature", "lost-reply", "invalid-request"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			calls, requestBytes, responseBytes := 0, 0, 0
			var c TrustConfig
			c = trustConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				requestBytes += len(raw)
				var input struct {
					Digest struct {
						SHA256 string `json:"sha256"`
					} `json:"digest"`
					CRC string `json:"digestCrc32c"`
				}
				digest := req.Digest()
				if json.Unmarshal(raw, &input) != nil || input.Digest.SHA256 != base64.StdEncoding.EncodeToString(digest[:]) || input.CRC != strconv.FormatUint(uint64(crc(digest[:])), 10) {
					t.Fatal("signing digest or checksum changed")
				}
				if mode == "lost-reply" {
					return nil, errors.New("synthetic-private-sign-error")
				}
				sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
				if err != nil {
					t.Fatal(err)
				}
				if mode == "invalid-signature" {
					sig[0] ^= 1
				}
				encoded, err := json.Marshal(map[string]any{"name": c.KeyVersion, "verifiedDigestCrc32c": true, "signature": base64.StdEncoding.EncodeToString(sig), "signatureCrc32c": strconv.FormatUint(uint64(crc(sig)), 10)})
				if err != nil {
					t.Fatal(err)
				}
				responseBytes += len(encoded)
				return response(200, string(encoded)), nil
			}), &credentials{}), der)
			trust, err := NewTrust(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			input, wantCalls, inputBytes, result := req, int64(1), int64(32), "sign_ok"
			switch mode {
			case "invalid-request":
				input, wantCalls, inputBytes, result = contract.SignRequest{}, 0, 0, "sign_invalid"
			case "invalid-signature":
				result = "sign_invalid"
			case "lost-reply":
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
			if int64(calls) != wantCalls || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpTrustSign, "", "") != wantCalls || telemetrySum(data, telemetry.OperationResults, telemetry.OpTrustSign, result, "") != 1 || telemetrySum(data, telemetry.OperationInputBytes, telemetry.OpTrustSign, result, "") != inputBytes || telemetrySum(data, telemetry.OperationOutputBytes, telemetry.OpTrustSign, result, "") != int64(len(got.Signature)) {
				t.Error("sign result or logical sizes differ")
			}
			if telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpTrustSign, "", "") != int64(requestBytes) || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpTrustSign, "", "") != int64(responseBytes) {
				t.Error("actual HTTP body bytes differ")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

// full_only: false
func TestTelemetryAuthenticationCountsEachRetrievalOnce(t *testing.T) {
	fields, _ := serviceAccountJSON(t)
	path := serviceAccountPath(t, fields)
	for _, mode := range []string{"cached-success", "denied", "incomplete", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			authCalls, serviceCalls, requestBytes, responseBytes := 0, 0, 0, 0
			source, err := LoadServiceAccountFileForTest(ctx, path, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				authCalls++
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				requestBytes += len(raw)
				if r.URL.String() != tokenURL || r.GetBody != nil || !strings.Contains(string(raw), "assertion=") {
					t.Fatal("token request changed")
				}
				if mode == "cancelled" {
					return nil, r.Context().Err()
				}
				reply := response(200, `{"access_token":"synthetic-private-token","token_type":"Bearer","expires_in":3600}`)
				if mode == "denied" {
					reply = response(401, `{"error":"synthetic-private-auth-error"}`)
				}
				responseBytes += int(reply.ContentLength)
				if mode == "incomplete" {
					reply.ContentLength++
				}
				return reply, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			value, err := source.Token(ctx)
			expectedAuthCalls, expectedRetrievals, expectedFailures := int64(1), int64(1), int64(1)
			if mode == "cached-success" {
				if err != nil || value != "synthetic-private-token" {
					t.Fatal("valid token was not returned")
				}
				if value, err := source.Token(ctx); err != nil || value != "synthetic-private-token" {
					t.Fatal("cached token changed")
				}
				s, err := NewStore(ctx, config(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
					serviceCalls++
					if r.Header.Get("Authorization") != "Bearer synthetic-private-token" {
						t.Error("frozen token changed")
					}
					out := response(200, "body")
					out.Header.Set("X-Goog-Generation", "42")
					return out, nil
				}), source)))
				if err != nil {
					t.Fatal(err)
				}
				if got := s.Read(ctx, s.Descriptor().HeadKey, 4); got.Status != contract.ReadOK || string(got.Body) != "body" || serviceCalls != 1 {
					t.Fatal("authenticated read changed")
				}
				expectedRetrievals, expectedFailures = 3, 0
			} else if err == nil || value != "" {
				t.Fatal("failed authentication returned a token")
			}
			if mode == "cancelled" {
				expectedAuthCalls = 0
				if !errors.Is(err, context.Canceled) {
					t.Fatal("authentication cancellation changed")
				}
			}
			data := snapshot()
			if int64(authCalls) != expectedAuthCalls || telemetrySum(data, telemetry.OperationCalls, telemetry.OpAuthentication, "", "") != expectedRetrievals+1 || telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "success", "") != expectedRetrievals+1-expectedFailures || telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "failure", "") != expectedFailures {
				t.Error("credential acquisition and retrieval counts differ")
			}
			if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != expectedAuthCalls || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpAuthentication, "", "") != int64(requestBytes) || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpAuthentication, "", "") != int64(responseBytes) {
				t.Error("authentication HTTP attribution differs")
			}
			if mode == "incomplete" && telemetrySum(data, telemetry.HTTPResponseBodyObservations, telemetry.OpAuthentication, "", "incomplete") != 1 {
				t.Error("incomplete token response counted as complete")
			}
			if mode != "cached-success" && serviceCalls != 0 {
				t.Fatal("failed authentication reached storage")
			}
			assertSafeTelemetry(t, data)
		})
	}
	t.Run("invalid-file", func(t *testing.T) {
		t.Setenv("ENKV_TELEMETRY", "1")
		ctx, snapshot := collectTelemetry(t)
		if _, err := LoadServiceAccountFile(ctx, serviceAccountFile(t, []byte(`{"type":"synthetic-private-unsupported"}`))); !errors.Is(err, ErrCredentials) {
			t.Fatal("invalid credential file accepted")
		}
		data := snapshot()
		if telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "failure", "") != 1 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != 0 {
			t.Error("invalid file acquisition result differs")
		}
		assertSafeTelemetry(t, data)
	})
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
			s, creds := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("credential changed")
				}
				out := response(200, "synthetic-private-body")
				out.Header.Set("X-Goog-Generation", "42")
				return out, nil
			})
			got := s.Read(ctx, s.Descriptor().HeadKey, 32)
			if got.Status != contract.ReadOK || string(got.Body) != "synthetic-private-body" || got.Token.Value != "42" || calls != 1 || creds.calls != 1 {
				t.Fatal("telemetry changed read correctness")
			}
			data := snapshot()
			if mode == "1" {
				if telemetrySum(data, telemetry.OperationResults, telemetry.OpStoreRead, "read_ok", "") != 1 {
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
func TestTelemetryHTTPWaitsForRequestCompletion(t *testing.T) {
	for _, route := range []string{"service"} {
		for _, mode := range []string{"complete", "cancelled"} {
			t.Run(route+"/"+mode, func(t *testing.T) {
				t.Setenv("ENKV_TELEMETRY", "1")
				ctx, snapshot := collectTelemetry(t)
				base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
				ctx, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				op, endpoint, wantErr := telemetry.OpStoreCreate, "https://fixture.invalid/", errTransport
				transport := &singleSend{base: base}
				ctx = context.WithValue(ctx, operationKey{}, &operation{host: "fixture.invalid", token: "synthetic", limit: 8})
				ctx, call := startTelemetry(ctx, op)
				defer call.Finish(telemetry.ResultSuccess)
				r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("abc"))
				if err != nil {
					t.Fatal(err)
				}
				returned := make(chan error, 1)
				go func() {
					reply, err := transport.RoundTrip(r)
					if reply != nil {
						_ = reply.Body.Close()
					}
					returned <- err
				}()
				<-base.started
				data := snapshot()
				if telemetrySum(data, telemetry.HTTPAttempts, op, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, op, "", "") != 0 {
					t.Error("HTTP result preceded request completion")
				}
				if mode == "cancelled" {
					cancel()
					if err := <-returned; err != wantErr {
						t.Errorf("cancelled request error=%v", err)
					}
					data = snapshot()
					if telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", "incomplete") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", "") != 0 || telemetrySum(data, telemetry.HTTPResults, op, "failure", "2xx") != 1 {
						t.Error("cancelled transfer was marked complete")
					}
					close(base.release)
				} else {
					close(base.release)
					if err := <-returned; err != nil {
						t.Errorf("complete request error=%v", err)
					}
					data = snapshot()
					if telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", "complete") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", "complete") != 3 {
						t.Error("joined request bytes were lost")
					}
				}
				<-base.consumed
				if mode == "cancelled" {
					data = snapshot()
					if telemetrySum(data, telemetry.HTTPRequestBodyObservations, op, "", "incomplete") != 0 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, op, "", "") != 0 {
						t.Error("late reads changed a completed partial observation")
					}
				}
			})
		}
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
		authCtx, authCall := startTelemetry(ctx, telemetry.OpAuthentication)
		if gotCtx != ctx || call != nil || authCtx != ctx || authCall != nil || startHTTPTelemetry(r) != nil {
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
func TestRecorderOnlyAuthenticationKeepsDirectAndNestedCalls(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	fields, _ := serviceAccountJSON(t)
	tokenCalls := 0
	source, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(*http.Request) (*http.Response, error) {
		tokenCalls++
		return response(200, `{"access_token":"recorder-token","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	direct := telemetry.NewRecorder()
	directCtx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, direct))
	for i := 0; i < 2; i++ {
		if value, err := source.Token(directCtx); err != nil || value != "recorder-token" {
			t.Fatalf("direct token=%q err=%v", value, err)
		}
	}
	if tokenCalls != 1 {
		t.Fatalf("token request count=%d", tokenCalls)
	}
	directRows := direct.Drain(make([]telemetry.DiagnosticRecord, 0, 6))
	if len(directRows) != 6 {
		t.Fatalf("direct diagnostic rows=%+v", directRows)
	}
	for i := 0; i < len(directRows); i += 3 {
		if directRows[i].Operation != telemetry.OpAuthentication || directRows[i].Event != telemetry.DiagnosticStart ||
			directRows[i+1].Event != telemetry.DiagnosticCheckpoint || directRows[i+1].Stage != telemetry.DiagnosticProviderCall ||
			directRows[i+2].Event != telemetry.DiagnosticReturn || directRows[i+2].Result != telemetry.ResultSuccess ||
			directRows[i].Call != directRows[i+1].Call || directRows[i].Call != directRows[i+2].Call {
			t.Fatalf("direct authentication diagnostic=%+v", directRows[i:i+3])
		}
	}
	nested := telemetry.NewRecorder()
	serviceCalls := 0
	s, err := NewStore(context.Background(), config(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		serviceCalls++
		out := response(200, "body")
		out.Header.Set("X-Goog-Generation", "42")
		return out, nil
	}), source)))
	if err != nil {
		t.Fatal(err)
	}
	if result := s.Read(telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, nested)), s.Descriptor().HeadKey, 4); result.Status != contract.ReadOK || string(result.Body) != "body" {
		t.Fatalf("nested read=%+v", result)
	}
	if tokenCalls != 1 || serviceCalls != 1 {
		t.Fatalf("requests: token=%d service=%d", tokenCalls, serviceCalls)
	}
	rows := nested.Drain(make([]telemetry.DiagnosticRecord, 0, 6))
	if len(rows) != 6 || rows[0].Operation != telemetry.OpStoreRead || rows[0].Event != telemetry.DiagnosticStart ||
		rows[2].Operation != telemetry.OpAuthentication || rows[2].Event != telemetry.DiagnosticStart || rows[2].ParentCall != rows[0].Call ||
		rows[3].Stage != telemetry.DiagnosticProviderCall || rows[4].Event != telemetry.DiagnosticReturn || rows[4].Result != telemetry.ResultSuccess ||
		rows[5].Operation != telemetry.OpStoreRead || rows[5].Event != telemetry.DiagnosticReturn {
		t.Fatalf("nested authentication diagnostic=%+v", rows)
	}
}

// full_only: false
func TestTelemetryRejectsReplayBeforeCountingHTTPAttempts(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	ctx, call := startTelemetry(ctx, telemetry.OpStoreRead)
	defer call.Finish(telemetry.ResultReadOK)
	calls := 0
	transport := singleSend{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Body != http.NoBody || r.ContentLength != 0 {
			t.Error("empty request framing changed")
		}
		return response(200, "body"), nil
	})}
	ctx = context.WithValue(ctx, operationKey{}, &operation{host: "fixture.invalid", token: "synthetic", limit: 8})
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fixture.invalid/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := reply.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(r); !errors.Is(err, errTransport) || calls != 1 {
		t.Fatalf("replay error=%v calls=%d", err, calls)
	}
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreRead, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreRead, "", "") != 1 {
		t.Fatal("refused replay counted as a physical attempt")
	}
}

// full_only: false
func TestTelemetryCapturedCredentialsExcludeBearerAndQuotaProject(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	var captures, sends int
	fields, _ := serviceAccountJSON(t)
	fields["quota_project_id"] = "private-quota-project"
	source, err := LoadServiceAccountFileForTest(context.Background(), serviceAccountPath(t, fields), roundTripFunc(func(*http.Request) (*http.Response, error) {
		captures++
		return response(200, `{"access_token":"private-bearer-token","token_type":"Bearer","expires_in":3600}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(ctx, config(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sends++
		if r.Header.Get("Authorization") != "Bearer private-bearer-token" || r.Header.Get("X-Goog-User-Project") != "private-quota-project" {
			t.Error("captured credential metadata changed")
		}
		return apiFailure(403, "forbidden"), nil
	}), source)))
	if err != nil {
		t.Fatal(err)
	}
	result := store.Read(ctx, store.Descriptor().HeadKey, 32)
	if result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonAccess || captures != 1 || sends != 1 {
		t.Fatal("credential capture changed service refusal or request count")
	}
	data := snapshot()
	authenticationCalls := telemetrySum(data, telemetry.OperationCalls, telemetry.OpAuthentication, "", "")
	authenticationResults := telemetrySum(data, telemetry.OperationResults, telemetry.OpAuthentication, "success", "")
	httpAttempts := telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreRead, "", "")
	if authenticationCalls != 1 || authenticationResults != 1 || httpAttempts != 1 {
		t.Fatalf("authentication calls=%d results=%d, service attempts=%d; want one each", authenticationCalls, authenticationResults, httpAttempts)
	}
	assertSafeTelemetry(t, data)
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("private-bearer-token")) || bytes.Contains(encoded, []byte("private-quota-project")) {
		t.Fatal("credential metadata entered telemetry")
	}
}
