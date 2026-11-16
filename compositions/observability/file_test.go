package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/telemetry"
	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	tracedata "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type trackedRequestBody struct {
	io.Reader
	closed bool
}

func (body *trackedRequestBody) Close() error { body.closed = true; return nil }

// full_only: false
func TestFileTransportClosesRejectedRequestBodies(t *testing.T) {
	sink := newFileTransport(t.TempDir(), "telemetry", "metrics")
	for _, test := range []struct {
		method string
		body   []byte
	}{
		{http.MethodGet, []byte(`{}`)},
		{http.MethodPost, bytes.Repeat([]byte("x"), maximumOTLPRequestBytes+1)},
	} {
		body := &trackedRequestBody{Reader: bytes.NewReader(test.body)}
		_, err := sink.RoundTrip(&http.Request{Method: test.method, Body: body})
		if err == nil || !body.closed {
			t.Fatalf("rejected request body was not closed: %s", test.method)
		}
	}
}

// full_only: false
func TestExplicitLogFileContainsOTLPFieldsAndKeepsConsole(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"exporters":["console","capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var console strings.Builder
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root, Console: &console})
	if err != nil {
		t.Fatal(err)
	}
	telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(console.String(), "WARN (13)") {
		t.Fatal("console route lost the warning")
	}
	data, err := os.ReadFile(filepath.Join(root, "telemetry", "logs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || strings.Count(string(data), "\n") != 1 {
		t.Fatalf("invalid JSONL prefix: %q", data)
	}
	var line struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []struct {
					Key   string         `json:"key"`
					Value map[string]any `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				Scope struct {
					Name string `json:"name"`
				} `json:"scope"`
				LogRecords []struct {
					SeverityNumber int    `json:"severityNumber"`
					SeverityText   string `json:"severityText"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(data, &line); err != nil {
		t.Fatal(err)
	}
	if len(line.ResourceLogs) != 1 || len(line.ResourceLogs[0].ScopeLogs) != 1 || len(line.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("missing OTLP log fields: %+v", line)
	}
	logs := line.ResourceLogs[0].ScopeLogs[0]
	if logs.Scope.Name != settings.Scopes["core"].Name || logs.LogRecords[0].SeverityText != "WARN" || logs.LogRecords[0].SeverityNumber != 13 {
		t.Fatalf("wrong OTLP scope/severity: %+v", logs)
	}
	info, err := os.Stat(filepath.Join(root, "telemetry", "logs.jsonl"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v, %v", info, err)
	}
}

// full_only: false
func TestOTLPJSONUsesHexIDsAndNumericEnums(t *testing.T) {
	wire, err := proto.Marshal(&collecttrace.ExportTraceServiceRequest{ResourceSpans: []*tracedata.ResourceSpans{{ScopeSpans: []*tracedata.ScopeSpans{{Spans: []*tracedata.Span{{TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, SpanId: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Name: "safe", Kind: tracedata.Span_SPAN_KIND_CLIENT, Attributes: []*common.KeyValue{{Key: "safe", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "value"}}}}}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	line, err := encodeOTLPJSON("traces", wire)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), `"traceId":"0102030405060708090a0b0c0d0e0f10"`) || !strings.Contains(string(line), `"spanId":"0102030405060708"`) || !strings.Contains(string(line), `"kind":3`) || strings.Contains(string(line), "AQIDBA") {
		t.Fatalf("wrong OTLP JSON encoding: %s", line)
	}
}

// full_only: false
func TestExplicitMetricFileKeepsResolvedResourceAndScope(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"resource":{"attributes":{"service.name":"example","custom.team":"safe"}},"scopes":{"core":{"name":"example.core"}},"metrics":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root, ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitMetrics(context.Background()); err != nil {
		t.Fatal(err)
	}
	telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultSuccess)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "telemetry", "metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"service.name"`) || !strings.Contains(string(data), `"example.core"`) || !strings.Contains(string(data), `"enkv.operation.calls"`) {
		t.Fatalf("missing metric OTLP fields: %s", data)
	}
	if strings.Contains(string(data), `"scope.name"`) {
		t.Fatal("scope leaked into resource")
	}
}

// full_only: false
func TestExplicitTraceFileUsesOTLPIDsAndConfiguredScope(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"scopes":{"core":{"name":"example.core"}},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitTraces(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, span := runtime.TracerProvider().Tracer(settings.Scopes["core"].Name).Start(context.Background(), "safe-operation")
	span.End()
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "telemetry", "traces.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var line struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Scope struct {
					Name string `json:"name"`
				} `json:"scope"`
				Spans []struct {
					TraceID string `json:"traceId"`
					SpanID  string `json:"spanId"`
					Name    string `json:"name"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(data, &line); err != nil {
		t.Fatal(err)
	}
	if len(line.ResourceSpans) != 1 || len(line.ResourceSpans[0].ScopeSpans) != 1 || len(line.ResourceSpans[0].ScopeSpans[0].Spans) != 1 {
		t.Fatalf("missing trace: %s", data)
	}
	scope := line.ResourceSpans[0].ScopeSpans[0]
	spanLine := scope.Spans[0]
	if scope.Scope.Name != "example.core" || spanLine.Name != "safe-operation" || len(spanLine.TraceID) != 32 || len(spanLine.SpanID) != 16 {
		t.Fatalf("wrong trace fields: %+v", scope)
	}
}

// full_only: false
func TestFileRouteRejectsUnsafePathAndQuotaWithoutSplittingLine(t *testing.T) {
	root := t.TempDir()
	unsafe := newFileTransport(root, "../outside", "logs")
	if unsafe.writeLine([]byte(`{}`)) == nil {
		t.Fatal("unsafe directory accepted")
	}
	sink := newFileTransport(root, "telemetry", "logs")
	first := []byte(`{"resourceLogs":[]}`)
	if err := sink.writeLine(first); err != nil {
		t.Fatal(err)
	}
	if err := sink.writeLine(make([]byte, fileQuotaBytes)); !errors.Is(err, errFileDelivery) {
		t.Fatalf("quota error = %v, want file delivery failure", err)
	}
	assertFailedFileTransportRetainsPrefix(t, sink, string(first)+"\n")
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "telemetry", "logs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(first)+"\n" {
		t.Fatalf("quota changed valid prefix: %q", data)
	}
}

// full_only: false
func TestFileTransportClosedFileShutdownRetainsCompletePrefix(t *testing.T) {
	sink := newFileTransport(t.TempDir(), "telemetry", "logs")
	first := []byte(`{"resourceLogs":[]}`)
	if err := sink.writeLine(first); err != nil {
		t.Fatal(err)
	}
	if err := sink.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.file.Sync(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed-file sync error = %v, want closed file", err)
	}
	if err := sink.file.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed-file close error = %v, want closed file", err)
	}
	if sink.failed {
		t.Fatal("delivery failed before shutdown")
	}
	if err := sink.Close(); !errors.Is(err, errFileDelivery) {
		t.Fatalf("shutdown error = %v, want file delivery failure", err)
	}
	if sink.file != nil {
		t.Fatal("shutdown retained the failed handle")
	}
	assertFailedFileTransportRetainsPrefix(t, sink, string(first)+"\n")
}

func assertFailedFileTransportRetainsPrefix(t *testing.T, sink *fileTransport, prefix string) {
	t.Helper()
	if !sink.failed || sink.bytes != int64(len(prefix)) {
		t.Fatalf("file delivery state: failed=%t bytes=%d, want failed and %d complete bytes", sink.failed, sink.bytes, len(prefix))
	}
	body := &trackedRequestBody{Reader: bytes.NewReader(nil)}
	response, err := sink.RoundTrip(&http.Request{Method: http.MethodPost, Body: body})
	if !errors.Is(err, errFileDelivery) || response != nil || !body.closed {
		t.Fatalf("later request: response=%v error=%v body closed=%t", response, err, body.closed)
	}
	if sink.bytes != int64(len(prefix)) {
		t.Fatalf("later request changed complete byte count: got %d, want %d", sink.bytes, len(prefix))
	}
	data, err := os.ReadFile(filepath.Join(sink.base, sink.directory, sink.signal+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != prefix {
		t.Fatalf("file failure changed complete prefix: got %q, want %q", data, prefix)
	}
}

// full_only: false
func TestFailedLocalDestinationsKeepIndependentSignalStatus(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"exporters":["console","local"]},"metrics":{"exporters":["local"]},"traces":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if os.Symlink("outside", filepath.Join(root, "telemetry")) != nil {
		t.Fatal("symlink fixture")
	}
	var console strings.Builder
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root, Console: &console, ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.AwaitMetrics(context.Background()) != nil || runtime.AwaitTraces(context.Background()) != nil {
		t.Fatal("setup")
	}
	telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	_, span := runtime.TracerProvider().Tracer(settings.Scopes["core"].Name).Start(context.Background(), "safe")
	span.End()
	_ = runtime.Close(context.Background())
	if !runtime.LogStatus("local").Incomplete || !runtime.MetricStatus("local").Incomplete || !runtime.TraceStatus("local").Incomplete {
		t.Fatalf("missing failure status: log=%+v metric=%+v trace=%+v", runtime.LogStatus("local"), runtime.MetricStatus("local"), runtime.TraceStatus("local"))
	}
	if runtime.LogStatus("console").Incomplete || !strings.Contains(console.String(), "WARN (13)") {
		t.Fatal("healthy console route was lost")
	}
}

// full_only: false
func TestOutputHostSignalsUseResolvedScope(t *testing.T) {
	for _, tc := range []struct {
		name, scopes, scopeName, scopeVersion string
		provider                              telemetry.Provider
		operation                             telemetry.Operation
	}{
		{"default", "", "enkv.sh/compositions/outputhost", "", telemetry.ProviderOutputHost, telemetry.OpOutputHostPublicCheck},
		{"override", `,"scopes":{"outputhost":{"name":"example.outputhost","version":"7.2"}}`, "example.outputhost", "7.2", telemetry.ProviderOutputHost, telemetry.OpOutputHostPublicCheck},
		{"manifest-default", "", "enkv.sh/compositions/manifesthost", "", telemetry.ProviderManifestHost, telemetry.OpManifestHostCheck},
		{"manifest-override", `,"scopes":{"manifesthost":{"name":"example.manifesthost","version":"7.2"}}`, "example.manifesthost", "7.2", telemetry.ProviderManifestHost, telemetry.OpManifestHostCheck},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := `{"schema_version":1` + tc.scopes + `,"logs":{"exporters":["capture"]},"metrics":{"exporters":["capture"]},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`
			settings, err := Decode([]byte(document), Options{})
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			runtime, err := Start(settings, SetupOptions{BaseDirectory: root, ManualMetrics: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := runtime.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			ctx := context.Background()
			if err := runtime.AwaitMetrics(ctx); err != nil {
				t.Fatal(err)
			}
			if err := runtime.AwaitTraces(ctx); err != nil {
				t.Fatal(err)
			}
			call := telemetry.Start(runtime.Context(ctx), tc.provider, tc.operation)
			if call == nil {
				t.Fatal("configured outputhost telemetry is disabled")
			}
			call.Finish(telemetry.ResultAdmissionRefused)
			if err := runtime.Close(ctx); err != nil {
				t.Fatal(err)
			}
			for _, signal := range []string{"logs", "metrics", "traces"} {
				status, present := runtime.DeliveryStatuses()[signal+".capture"]
				if !present || status.Written == 0 || status.Failed != 0 || status.Dropped != 0 || status.Incomplete {
					t.Errorf("%s delivery: present=%t status=%+v", signal, present, status)
				}
			}
			checkScope := func(scope *common.InstrumentationScope) {
				t.Helper()
				if scope.GetName() != tc.scopeName || scope.GetVersion() != tc.scopeVersion {
					t.Errorf("signal scope=%q version=%q want=%q version=%q", scope.GetName(), scope.GetVersion(), tc.scopeName, tc.scopeVersion)
				}
			}
			checkAttributes := func(attributes []*common.KeyValue, result bool) {
				t.Helper()
				values := map[string]string{}
				for _, attribute := range attributes {
					values[attribute.GetKey()] = attribute.GetValue().GetStringValue()
				}
				if values["provider"] != string(tc.provider) || values["operation"] != string(tc.operation) || result && values["result"] != "admission_refused" {
					t.Errorf("signal attributes=%v", values)
				}
			}
			logs := 0
			var logTraceID, logSpanID []byte
			for _, line := range fileLines(t, filepath.Join(root, "telemetry", "logs.jsonl")) {
				var batch collectlogs.ExportLogsServiceRequest
				if err := protojson.Unmarshal(line, &batch); err != nil {
					t.Fatal(err)
				}
				for _, resource := range batch.GetResourceLogs() {
					for _, scope := range resource.GetScopeLogs() {
						checkScope(scope.GetScope())
						for _, record := range scope.GetLogRecords() {
							logs++
							checkAttributes(record.GetAttributes(), true)
							if int(record.GetSeverityNumber()) != 13 || record.GetSeverityText() != "WARN" || record.GetBody().GetStringValue() != "return" {
								t.Errorf("unexpected outputhost return log: %v", record)
							}
							logTraceID, logSpanID = record.GetTraceId(), record.GetSpanId()
						}
					}
				}
			}
			counts := map[string]uint64{}
			for _, line := range fileLines(t, filepath.Join(root, "telemetry", "metrics.jsonl")) {
				var batch collectmetrics.ExportMetricsServiceRequest
				if err := protojson.Unmarshal(line, &batch); err != nil {
					t.Fatal(err)
				}
				for _, resource := range batch.GetResourceMetrics() {
					for _, scope := range resource.GetScopeMetrics() {
						checkScope(scope.GetScope())
						for _, metric := range scope.GetMetrics() {
							switch metric.GetName() {
							case "enkv.operation.calls", "enkv.operation.results":
								for _, point := range metric.GetSum().GetDataPoints() {
									checkAttributes(point.GetAttributes(), metric.GetName() == "enkv.operation.results")
									if point.GetAsInt() != 1 {
										t.Errorf("%s value=%d want=1", metric.GetName(), point.GetAsInt())
									}
									counts[metric.GetName()]++
								}
							case "enkv.operation.duration":
								for _, point := range metric.GetHistogram().GetDataPoints() {
									checkAttributes(point.GetAttributes(), true)
									counts[metric.GetName()] += point.GetCount()
								}
							default:
								t.Errorf("unexpected outputhost metric: %s", metric.GetName())
							}
						}
					}
				}
			}
			for _, name := range []string{"enkv.operation.calls", "enkv.operation.results", "enkv.operation.duration"} {
				if counts[name] != 1 {
					t.Errorf("%s observation count=%d want=1", name, counts[name])
				}
			}
			spans := 0
			for _, line := range fileLines(t, filepath.Join(root, "telemetry", "traces.jsonl")) {
				var batch collecttrace.ExportTraceServiceRequest
				if err := protojson.Unmarshal(line, &batch); err != nil {
					t.Fatal(err)
				}
				for _, resource := range batch.GetResourceSpans() {
					for _, scope := range resource.GetScopeSpans() {
						checkScope(scope.GetScope())
						for _, span := range scope.GetSpans() {
							spans++
							checkAttributes(span.GetAttributes(), true)
							if span.GetName() != string(tc.operation) || len(span.GetTraceId()) == 0 || len(span.GetSpanId()) == 0 || !bytes.Equal(span.GetTraceId(), logTraceID) || !bytes.Equal(span.GetSpanId(), logSpanID) {
								t.Errorf("outputhost span does not match return log: %v", span)
							}
						}
					}
				}
			}
			if logs != 1 || spans != 1 {
				t.Errorf("outputhost log/span counts=%d/%d want=1/1", logs, spans)
			}
		})
	}
}
