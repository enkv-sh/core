package observability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/telemetry"
	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type receivedOTLP struct {
	path, contentType, credential, dataset, leak, compression string
	body                                                      []byte
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

// full_only: false
func TestHTTPAndFileRoutesExportThreeSignalsFromOneInvocation(t *testing.T) {
	t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://ambient.invalid")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-ambient-leak=private-sentinel")
	t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")
	var baseline map[string]int
	for _, route := range []struct {
		name       string
		file, http bool
	}{{"file", true, false}, {"http", false, true}, {"both", true, true}} {
		t.Run(route.name, func(t *testing.T) {
			received := make(chan receivedOTLP, 16)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, maximumOTLPRequestBytes+1))
				if err != nil || len(body) > maximumOTLPRequestBytes {
					t.Error("local OTLP request read failed or exceeded bound")
				}
				request := receivedOTLP{path: r.URL.Path, contentType: r.Header.Get("Content-Type"), credential: r.Header.Get("x-honeycomb-team"), dataset: r.Header.Get("x-honeycomb-dataset"), leak: r.Header.Get("x-ambient-leak"), compression: r.Header.Get("Content-Encoding"), body: body}
				select {
				case received <- request:
				default:
					t.Error("local OTLP receiver overflow")
				}
				w.Header().Set("Content-Type", "application/x-protobuf")
			}))
			defer server.Close()
			names := []string{}
			if route.file {
				names = append(names, "capture")
			}
			if route.http {
				names = append(names, "hosted")
			}
			selected, err := json.Marshal(names)
			if err != nil {
				t.Fatal(err)
			}
			document := fmt.Sprintf(`{"schema_version":1,"resource":{"attributes":{"service.name":"enkv-smoke","deployment.environment.name":"local"}},"scopes":{"core":{"name":"example.core"},"application":{"name":"example.application"}},"logs":{"level":"warn","exporters":%s},"metrics":{"exporters":%s},"traces":{"sample_ratio":1,"exporters":%s},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"},"hosted":{"type":"otlp_http","endpoint":%q,"api_key_env":"ENKV_HONEYCOMB_TEST_KEY","dataset":"synthetic"}}}`, selected, selected, selected, server.URL)
			settings, err := Decode([]byte(document), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if settings.LogLevel != Warn || settings.TraceSampleRatio != 1 || settings.Console {
				t.Fatal("collection policy changed with route")
			}
			root := t.TempDir()
			runtime, err := Start(settings, SetupOptions{BaseDirectory: root, remoteBase: server.Client().Transport})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := runtime.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			if err := runtime.AwaitMetrics(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := runtime.AwaitTraces(context.Background()); err != nil {
				t.Fatal(err)
			}
			invocation := telemetry.StartWithDetails(runtime.Context(context.Background()), telemetry.ProviderApplication, telemetry.OpApplicationInvocation,
				(telemetry.DiagnosticDetails{}).WithInvocationID("0123456789abcdef0123456789abcdef"))
			operation := telemetry.Start(invocation.Context(), telemetry.ProviderCore, telemetry.OpCoreOpen)
			operation.Finish(telemetry.ResultAdmissionRefused)
			invocation.Finish(telemetry.ResultSuccess)
			if err := runtime.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			server.Close()
			close(received)
			file, remote := routeOTLP{}, routeOTLP{}
			for request := range received {
				if !route.http || request.credential != "synthetic-token" || request.dataset != "synthetic" || request.contentType != "application/x-protobuf" || request.leak != "" || request.compression != "" || len(request.body) == 0 || len(request.body) > maximumOTLPRequestBytes {
					t.Fatalf("unsafe or unselected HTTP envelope at %s", request.path)
				}
				remote.decode(t, strings.TrimPrefix(request.path, "/v1/"), request.body, false)
			}
			for _, signal := range []string{"logs", "metrics", "traces"} {
				path := filepath.Join(root, "telemetry", signal+".jsonl")
				if route.file {
					for _, line := range fileLines(t, path) {
						file.decode(t, signal, line, true)
					}
				} else if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("unselected file route created output", err)
				}
				for _, name := range names {
					status, present := runtime.DeliveryStatuses()[signal+"."+name]
					if !present || status.Written == 0 || status.Accepted != status.Written || status.Dropped != 0 || status.Failed != 0 || status.Incomplete {
						t.Fatalf("%s %s delivery lost evidence: %+v", signal, name, status)
					}
				}
			}
			if len(runtime.DeliveryStatuses()) != 3*len(names) {
				t.Fatal("unselected delivery route became active")
			}
			var sameInvocation map[string]routeHistogram
			for _, capture := range []struct {
				enabled bool
				data    *routeOTLP
			}{{route.file, &file}, {route.http, &remote}} {
				if !capture.enabled {
					continue
				}
				facts, histograms := capture.data.facts(t)
				if sameInvocation == nil {
					sameInvocation = histograms
				} else if !reflect.DeepEqual(histograms, sameInvocation) {
					t.Fatal("file and HTTP changed duration observations from the same invocation")
				}
				if baseline == nil {
					baseline = facts
				} else if !reflect.DeepEqual(facts, baseline) {
					t.Fatalf("route changed semantic signals: got %v, want %v", facts, baseline)
				}
			}
		})
	}
}

type routeOTLP struct {
	logs    collectlogs.ExportLogsServiceRequest
	metrics collectmetrics.ExportMetricsServiceRequest
	traces  collecttrace.ExportTraceServiceRequest
}

// OTLP JSON uses hex IDs, while protojson expects base64 bytes. Adapt only
// those three wire fields, independently of the production file encoder.
var routeFileID = regexp.MustCompile(`"(traceId|spanId|parentSpanId)"\s*:\s*"([0-9a-f]+)"`)

func (data *routeOTLP) decode(t *testing.T, signal string, body []byte, file bool) {
	t.Helper()
	if bytes.Contains(body, []byte("synthetic-token")) || bytes.Contains(body, []byte("private-sentinel")) {
		t.Fatal("private HTTP settings reached signal payload")
	}
	var message, target proto.Message
	switch signal {
	case "logs":
		message, target = new(collectlogs.ExportLogsServiceRequest), &data.logs
	case "metrics":
		message, target = new(collectmetrics.ExportMetricsServiceRequest), &data.metrics
	case "traces":
		message, target = new(collecttrace.ExportTraceServiceRequest), &data.traces
	default:
		t.Fatal("unexpected OTLP signal", signal)
	}
	if file {
		body = routeFileID.ReplaceAllFunc(body, func(field []byte) []byte {
			parts := routeFileID.FindSubmatch(field)
			id, err := hex.DecodeString(string(parts[2]))
			want := 8
			if string(parts[1]) == "traceId" {
				want = 16
			}
			if err != nil || len(id) != want {
				t.Fatal("invalid file OTLP ID")
			}
			return []byte(fmt.Sprintf("%q:%q", parts[1], base64.StdEncoding.EncodeToString(id)))
		})
		if err := protojson.Unmarshal(body, message); err != nil {
			t.Fatal("file OTLP decode", err)
		}
	} else if err := proto.Unmarshal(body, message); err != nil {
		t.Fatal("HTTP OTLP decode", err)
	}
	proto.Merge(target, message)
}

type routeHistogram struct {
	sum     float64
	buckets []uint64
}

func (data *routeOTLP) facts(t *testing.T) (map[string]int, map[string]routeHistogram) {
	t.Helper()
	facts := map[string]int{}
	histograms := map[string]routeHistogram{}
	resource := func(attrs []*common.KeyValue) {
		t.Helper()
		if otlpString(attrs, "service.name") != "enkv-smoke" || otlpString(attrs, "deployment.environment.name") != "local" {
			t.Fatal("configured resource attributes changed")
		}
	}
	spans := map[string]string{}
	parents := map[string]string{}
	traceIDs := map[string]string{}
	for _, batch := range data.traces.ResourceSpans {
		resource(batch.GetResource().GetAttributes())
		for _, scope := range batch.ScopeSpans {
			for _, span := range scope.Spans {
				attrs := span.GetAttributes()
				provider, op := otlpString(attrs, "provider"), otlpString(attrs, "operation")
				if span.GetStartTimeUnixNano() == 0 || span.GetEndTimeUnixNano() < span.GetStartTimeUnixNano() || len(span.GetTraceId()) != 16 || len(span.GetSpanId()) != 8 || span.GetName() != op || span.GetDroppedAttributesCount() != 0 {
					t.Fatal("span lost fields or identity")
				}
				if op == "application.invocation" && otlpString(attrs, "invocation.id") != "0123456789abcdef0123456789abcdef" {
					t.Fatal("invocation span lost its supplied ID")
				}
				id := fmt.Sprintf("%x/%x", span.GetTraceId(), span.GetSpanId())
				if _, duplicate := spans[id]; duplicate {
					t.Fatal("duplicate span identity")
				}
				spans[id] = op
				parents[op], traceIDs[op] = fmt.Sprintf("%x", span.GetParentSpanId()), fmt.Sprintf("%x", span.GetTraceId())
				facts[fmt.Sprintf("span|%s|%s|%s|%s|%s", scope.GetScope().GetName(), provider, op, otlpString(attrs, "result"), otlpString(attrs, "reason"))]++
			}
		}
	}
	if len(spans) != 2 || parents["application.invocation"] != "" || parents["core.open"] == "" || traceIDs["core.open"] != traceIDs["application.invocation"] || spans[traceIDs["core.open"]+"/"+parents["core.open"]] != "application.invocation" {
		t.Fatal("operation did not retain its invocation parent")
	}
	for _, batch := range data.logs.ResourceLogs {
		resource(batch.GetResource().GetAttributes())
		for _, scope := range batch.ScopeLogs {
			for _, record := range scope.LogRecords {
				attrs := record.GetAttributes()
				op := otlpString(attrs, "operation")
				if record.GetTimeUnixNano() == 0 || record.GetSeverityText() != "WARN" || record.GetSeverityNumber() != 13 || record.GetDroppedAttributesCount() != 0 || len(record.GetTraceId()) != 16 || len(record.GetSpanId()) != 8 || spans[fmt.Sprintf("%x/%x", record.GetTraceId(), record.GetSpanId())] != op {
					t.Fatal("warning lost severity or matching span")
				}
				facts[fmt.Sprintf("log|%s|%s|%s|%s|%s|%s", scope.GetScope().GetName(), otlpString(attrs, "provider"), op, otlpString(attrs, "event"), otlpString(attrs, "result"), otlpString(attrs, "reason"))]++
			}
		}
	}
	bounds := []float64{0.000001, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.5, 0.75, 1, 1.5, 2.5, 5, 10, 30, 60}
	for _, batch := range data.metrics.ResourceMetrics {
		resource(batch.GetResource().GetAttributes())
		for _, scope := range batch.ScopeMetrics {
			for _, metric := range scope.Metrics {
				switch metric.GetName() {
				case "enkv.operation.calls", "enkv.operation.results":
					if metric.GetSum() == nil {
						t.Fatal("operation counter changed metric kind")
					}
				case "enkv.operation.duration":
					if metric.GetHistogram() == nil {
						t.Fatal("duration changed metric kind")
					}
				default:
					t.Fatal("unexpected metric name")
				}
				add := func(attrs []*common.KeyValue) {
					if otlpString(attrs, "invocation.id") != "" {
						t.Fatal("metric gained invocation dimension")
					}
					facts[fmt.Sprintf("metric|%s|%s|%s|%s|%s|%s", scope.GetScope().GetName(), metric.GetName(), metric.GetUnit(), otlpString(attrs, "provider"), otlpString(attrs, "operation"), otlpString(attrs, "result"))]++
				}
				if sum := metric.GetSum(); sum != nil {
					if sum.GetAggregationTemporality() != 2 || !sum.GetIsMonotonic() {
						t.Fatal("operation counter lost cumulative monotonic shape")
					}
					for _, point := range sum.DataPoints {
						if point.GetTimeUnixNano() == 0 || point.GetAsInt() != 1 {
							t.Fatal("operation counter lost one observation")
						}
						add(point.GetAttributes())
					}
				} else if histogram := metric.GetHistogram(); histogram != nil {
					if histogram.GetAggregationTemporality() != 2 {
						t.Fatal("duration lost cumulative shape")
					}
					for _, point := range histogram.DataPoints {
						var count uint64
						for _, value := range point.GetBucketCounts() {
							count += value
						}
						if point.Sum == nil || math.IsNaN(point.GetSum()) || math.IsInf(point.GetSum(), 0) || point.GetSum() < 0 || point.GetTimeUnixNano() == 0 || point.GetCount() != 1 || count != 1 || len(point.GetBucketCounts()) != len(bounds)+1 || !slices.Equal(point.GetExplicitBounds(), bounds) {
							t.Fatal("duration lost count or declared bounds")
						}
						add(point.GetAttributes())
						attrs := point.GetAttributes()
						histograms[otlpString(attrs, "provider")+"/"+otlpString(attrs, "operation")+"/"+otlpString(attrs, "result")] = routeHistogram{point.GetSum(), slices.Clone(point.GetBucketCounts())}
					}
				} else {
					t.Fatal("unexpected metric shape")
				}
			}
		}
	}
	want := map[string]int{
		"log|example.core|core|core.open|return|admission_refused|admission_refused":                          1,
		"span|example.core|core|core.open|admission_refused|admission_refused":                                1,
		"span|example.application|application|application.invocation|success|":                                1,
		"metric|example.core|enkv.operation.calls|{call}|core|core.open|":                                     1,
		"metric|example.core|enkv.operation.results|{call}|core|core.open|admission_refused":                  1,
		"metric|example.core|enkv.operation.duration|s|core|core.open|admission_refused":                      1,
		"metric|example.application|enkv.operation.calls|{call}|application|application.invocation|":          1,
		"metric|example.application|enkv.operation.results|{call}|application|application.invocation|success": 1,
		"metric|example.application|enkv.operation.duration|s|application|application.invocation|success":     1,
	}
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("signal facts differ: got %v, want %v", facts, want)
	}
	return facts, histograms
}

func otlpString(attributes []*common.KeyValue, name string) string {
	for _, attribute := range attributes {
		if attribute.GetKey() == name {
			return attribute.GetValue().GetStringValue()
		}
	}
	return ""
}

// full_only: false
func TestSelectedHTTPRouteMissingCredentialCannotChangeProductReturn(t *testing.T) {
	t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "")
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":["hosted"]},"metrics":{"exporters":["hosted"]},"traces":{"exporters":["hosted"]},"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	runtime, err := Start(settings, SetupOptions{remoteBase: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errRemoteDelivery
	})})
	if err != nil {
		t.Fatal(err)
	}
	call := telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen)
	call.Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(context.Background()); err == nil {
		t.Fatal("missing credential reported complete export")
	}
	if !runtime.LogStatus("hosted").Incomplete || !runtime.MetricStatus("hosted").Incomplete || !runtime.TraceStatus("hosted").Incomplete {
		t.Fatalf("missing per-signal failure: %+v", runtime.DeliveryStatuses())
	}
	if requests != 0 {
		t.Fatal("missing credential sent a request")
	}
}

// full_only: false
func TestUnusedHTTPDefinitionsNeverConnect(t *testing.T) {
	t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
	for _, test := range []struct {
		name     string
		document string
		options  Options
	}{
		{"default", ``, Options{}},
		{"credentials_present", `{"schema_version":1}`, Options{}},
		{"unused_http", `{"schema_version":1,"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`, Options{}},
		{"metadata_only", `{"schema_version":1,"resource":{"attributes":{"service.name":"enkv-smoke"}},"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`, Options{}},
		{"log_override_only", `{"schema_version":1,"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`, Options{LogLevel: "debug"}},
		{"file_only", `{"schema_version":1,"logs":{"exporters":["capture"]},"metrics":{"exporters":["capture"]},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"},"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`, Options{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings, err := Decode([]byte(test.document), test.options)
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			runtime, err := Start(settings, SetupOptions{BaseDirectory: t.TempDir(), Console: io.Discard, remoteBase: roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, errRemoteDelivery
			})})
			if err != nil {
				t.Fatal(err)
			}
			telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
			if err := runtime.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 0 {
				t.Fatal("inactive HTTP destination received a request")
			}
		})
	}
}

// full_only: false
func TestRemoteTransportRejectsUnreviewedResponseAndRedirect(t *testing.T) {
	for _, result := range []struct {
		name   string
		status int
		body   []byte
	}{
		{"auth", http.StatusUnauthorized, []byte("private-sentinel")},
		{"throttle", http.StatusTooManyRequests, []byte("private-sentinel")},
		{"redirect", http.StatusTemporaryRedirect, []byte("private-sentinel")},
		{"invalid_success", http.StatusOK, []byte("private-sentinel")},
		{"oversized_success", http.StatusOK, []byte(strings.Repeat("x", maximumRemoteResponseBytes+1))},
	} {
		t.Run(result.name, func(t *testing.T) {
			t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Location", "https://other.invalid/")
				w.WriteHeader(result.status)
				_, _ = w.Write(result.body)
			}))
			defer server.Close()
			settings, err := Decode([]byte(`{"schema_version":1,"logs":{"exporters":["hosted"]},"exporters":{"hosted":{"type":"otlp_http","endpoint":"`+server.URL+`","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`), Options{})
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := Start(settings, SetupOptions{remoteBase: server.Client().Transport})
			if err != nil {
				t.Fatal(err)
			}
			telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
			_ = runtime.Close(context.Background())
			status := runtime.LogStatus("hosted")
			if status.Written != 0 || !status.Incomplete || status.Failed == 0 {
				t.Fatalf("HTTP failure not counted: %+v", status)
			}
			if requests.Load() != 1 {
				t.Fatalf("HTTP delivery retried or redirected: %d requests", requests.Load())
			}
		})
	}
}

// full_only: false
func TestRemoteTransportRejectsPartialSuccessWithoutResponseText(t *testing.T) {
	t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"exporters":["hosted"]},"metrics":{"exporters":["hosted"]},"traces":{"exporters":["hosted"]},"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path     string
		response proto.Message
	}{
		{"/v1/logs", &collectlogs.ExportLogsServiceResponse{PartialSuccess: &collectlogs.ExportLogsPartialSuccess{RejectedLogRecords: 1, ErrorMessage: "private-sentinel"}}},
		{"/v1/metrics", &collectmetrics.ExportMetricsServiceResponse{PartialSuccess: &collectmetrics.ExportMetricsPartialSuccess{RejectedDataPoints: 1, ErrorMessage: "private-sentinel"}}},
		{"/v1/traces", &collecttrace.ExportTraceServiceResponse{PartialSuccess: &collecttrace.ExportTracePartialSuccess{RejectedSpans: 1, ErrorMessage: "private-sentinel"}}},
	} {
		t.Run(test.path, func(t *testing.T) {
			wire, err := proto.Marshal(test.response)
			if err != nil {
				t.Fatal(err)
			}
			transport := newRemoteTransport(settings, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire)), Header: make(http.Header), Request: request}, nil
			}))
			request, err := http.NewRequest(http.MethodPost, "https://local.invalid"+test.path, bytes.NewReader([]byte{1}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = transport.RoundTrip(request)
			if !errors.Is(err, errRemoteDelivery) || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatalf("partial acceptance was not rejected safely: %v", err)
			}
		})
	}
}

// full_only: false
func TestBlockedHTTPLogOutputCannotDelayOperationOrShutdownDeadline(t *testing.T) {
	t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"exporters":["hosted"]},"exporters":{"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	runtime, err := Start(settings, SetupOptions{remoteBase: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil, errRemoteDelivery
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx := runtime.Context(context.Background())
	telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("HTTP worker did not enter the blocked transport")
	}
	done := make(chan struct{})
	go func() {
		telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("operation waited for blocked HTTP output")
	}
	deadline, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if runtime.Close(deadline) == nil || !runtime.LogStatus("hosted").Incomplete {
		t.Fatalf("blocked HTTP shutdown appeared complete: %+v", runtime.LogStatus("hosted"))
	}
	close(release)
	select {
	case <-runtime.logOutputs[0].done:
	case <-time.After(time.Second):
		t.Fatal("HTTP worker stayed alive after sink release")
	}
}

// full_only: false
func TestStalledHTTPKeepsHealthyFileRoutesComplete(t *testing.T) {
	for _, order := range []struct{ name, exporters string }{
		{"file_first", `"capture","hosted"`},
		{"remote_first", `"hosted","capture"`},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
			settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":[`+order.exporters+`]},"metrics":{"exporters":[`+order.exporters+`]},"traces":{"exporters":[`+order.exporters+`]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"},"hosted":{"type":"otlp_http","endpoint":"https://local.invalid","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`), Options{})
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{}, 8)
			release := make(chan struct{})
			root := t.TempDir()
			runtime, err := Start(settings, SetupOptions{BaseDirectory: root, Console: io.Discard, remoteBase: roundTripFunc(func(*http.Request) (*http.Response, error) {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-release
				return nil, errRemoteDelivery
			})})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				close(release)
				_ = runtime.Close(context.Background())
				select {
				case <-runtime.closeDone:
				default:
					t.Error("released remote cleanup did not join")
				}
			}()
			if err := runtime.AwaitMetrics(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := runtime.AwaitTraces(context.Background()); err != nil {
				t.Fatal(err)
			}
			call := telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen)
			call.Finish(telemetry.ResultAdmissionRefused)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("remote route did not start")
			}
			deadline, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if runtime.Close(deadline) == nil {
				t.Fatal("stalled remote route reported complete shutdown")
			}
			for _, signal := range []string{"logs", "metrics", "traces"} {
				var local, hosted DeliveryStatus
				switch signal {
				case "logs":
					local, hosted = runtime.LogStatus("capture"), runtime.LogStatus("hosted")
				case "metrics":
					local, hosted = runtime.MetricStatus("capture"), runtime.MetricStatus("hosted")
				case "traces":
					local, hosted = runtime.TraceStatus("capture"), runtime.TraceStatus("hosted")
				}
				if local.Written == 0 || local.Incomplete || !hosted.Incomplete {
					t.Fatalf("%s routes lost independent status: file=%+v hosted=%+v", signal, local, hosted)
				}
				if _, err := os.Stat(filepath.Join(root, "telemetry", signal+".jsonl")); err != nil {
					t.Fatalf("%s local file missing: %v", signal, err)
				}
			}
		})
	}
}
