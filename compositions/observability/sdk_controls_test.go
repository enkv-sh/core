package observability

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"enkv.sh/telemetry"
	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricdata "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// full_only: false
func TestExportersOverrideAmbientMetricAndLogLimits(t *testing.T) {
	t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION", "base2_exponential_bucket_histogram")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE", "delta")
	t.Setenv("OTEL_LOGRECORD_ATTRIBUTE_COUNT_LIMIT", "0")
	t.Setenv("OTEL_LOGRECORD_ATTRIBUTE_VALUE_LENGTH_LIMIT", "1")
	received := make(chan receivedOTLP, 16)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, maximumOTLPRequestBytes+1))
		received <- receivedOTLP{path: r.URL.Path, body: body}
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":["capture","hosted"]},"metrics":{"exporters":["capture","hosted"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"},"hosted":{"type":"otlp_http","endpoint":"`+server.URL+`","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root, Console: io.Discard, remoteBase: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitMetrics(context.Background()); err != nil {
		t.Fatal(err)
	}
	errorText := strings.Repeat("e", telemetry.MaximumErrorBytes)
	details := (telemetry.DiagnosticDetails{}).
		WithEntryName("LOG_LEVEL").WithKeyID(strings.Repeat("1", 64)).
		WithCommandID(strings.Repeat("2", 64)).WithAttemptID(strings.Repeat("3", 64)).
		WithInvocationID("invocation.example").WithWorkerID("worker.example").
		WithPathKind("state_head").WithReviewedPath("domain/HEAD").WithConfigField("domain").
		WithErrorFacts(telemetry.DiagnosticReasonDenied, http.StatusForbidden).WithReviewedErrorText(errorText)
	invocation := telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderApplication, telemetry.OpApplicationInvocation)
	telemetry.StartWithDetails(invocation.Context(), telemetry.ProviderCore, telemetry.OpCoreOpen, details).Finish(telemetry.ResultAdmissionRefused)
	invocation.Finish(telemetry.ResultSuccess)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(received)
	for _, route := range []string{"capture", "hosted"} {
		for _, status := range []DeliveryStatus{runtime.LogStatus(route), runtime.MetricStatus(route)} {
			if status.Written == 0 || status.Incomplete {
				t.Fatalf("%s delivery: %+v", route, status)
			}
		}
	}
	logFound, metricFound := map[string]bool{}, map[string]bool{}
	checkLogs := func(route string, message *collectlogs.ExportLogsServiceRequest) {
		t.Helper()
		for _, resource := range message.ResourceLogs {
			for _, scope := range resource.ScopeLogs {
				for _, record := range scope.LogRecords {
					attrs := record.GetAttributes()
					if otlpString(attrs, "operation") != string(telemetry.OpCoreOpen) || otlpString(attrs, "event") != "return" {
						continue
					}
					for key, want := range map[string]string{
						"component": "core", "provider": "core", "result": "admission_refused", "reason": "admission_refused",
						"member.name": "LOG_LEVEL", "key.id": strings.Repeat("1", 64), "command.id": strings.Repeat("2", 64), "attempt.id": strings.Repeat("3", 64),
						"invocation.id": "invocation.example", "worker.id": "worker.example", "path.kind": "state_head", "path": "domain/HEAD", "config.field": "domain",
						"error.class": "denied", "error.detail": errorText, "error.detail_status": "reviewed",
					} {
						if otlpString(attrs, key) != want {
							t.Errorf("%s log field %s was dropped or truncated", route, key)
						}
					}
					if len(attrs) != 24 || record.GetDroppedAttributesCount() != 0 || record.GetSeverityText() != "WARN" || int(record.GetSeverityNumber()) != 13 {
						t.Errorf("%s log attributes or severity changed", route)
					}
					logFound[route] = true
				}
			}
		}
	}
	checkMetrics := func(route string, message *collectmetrics.ExportMetricsServiceRequest) {
		t.Helper()
		for _, resource := range message.ResourceMetrics {
			for _, scope := range resource.ScopeMetrics {
				for _, metric := range scope.Metrics {
					if sum := metric.GetSum(); sum != nil && sum.GetAggregationTemporality() != metricdata.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE {
						t.Errorf("%s counter inherited ambient temporality", route)
					}
					if metric.GetName() != string(telemetry.OperationDuration) {
						continue
					}
					histogram := metric.GetHistogram()
					if histogram == nil || histogram.GetAggregationTemporality() != metricdata.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE {
						t.Errorf("%s duration lost explicit cumulative histogram", route)
						continue
					}
					for _, point := range histogram.DataPoints {
						// These are the declared duration boundaries, independent of the SDK selector.
						want := []float64{0.000001, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.5, 0.75, 1, 1.5, 2.5, 5, 10, 30, 60}
						if !slices.Equal(point.GetExplicitBounds(), want) || point.GetCount() != 1 || len(point.GetBucketCounts()) != len(want)+1 {
							t.Errorf("%s duration boundaries or observations changed", route)
						}
						metricFound[route] = true
					}
				}
			}
		}
	}
	for request := range received {
		switch request.path {
		case "/v1/logs":
			message := new(collectlogs.ExportLogsServiceRequest)
			if err := proto.Unmarshal(request.body, message); err != nil {
				t.Fatal(err)
			}
			checkLogs("hosted", message)
		case "/v1/metrics":
			message := new(collectmetrics.ExportMetricsServiceRequest)
			if err := proto.Unmarshal(request.body, message); err != nil {
				t.Fatal(err)
			}
			checkMetrics("hosted", message)
		default:
			t.Fatalf("unexpected signal: %s", request.path)
		}
	}
	for _, signal := range []string{"logs", "metrics"} {
		data, err := os.ReadFile(filepath.Join(root, "telemetry", signal+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			if signal == "logs" {
				message := new(collectlogs.ExportLogsServiceRequest)
				if err := protojson.Unmarshal(line, message); err != nil {
					t.Fatal(err)
				}
				checkLogs("capture", message)
			} else {
				message := new(collectmetrics.ExportMetricsServiceRequest)
				if err := protojson.Unmarshal(line, message); err != nil {
					t.Fatal(err)
				}
				checkMetrics("capture", message)
			}
		}
	}
	for _, route := range []string{"capture", "hosted"} {
		if !logFound[route] || !metricFound[route] {
			t.Errorf("%s missing log or histogram: log=%t histogram=%t", route, logFound[route], metricFound[route])
		}
	}
}

// full_only: false
func TestLogLevelOffPreservesRoutedMetricsAndTraces(t *testing.T) {
	t.Setenv("ENKV_HONEYCOMB_TEST_KEY", "synthetic-token")
	received := make(chan string, 16)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maximumOTLPRequestBytes+1))
		received <- r.URL.Path
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"off","exporters":["console","capture","hosted"]},"metrics":{"exporters":["capture","hosted"]},"traces":{"exporters":["capture","hosted"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"},"hosted":{"type":"otlp_http","endpoint":"`+server.URL+`","api_key_env":"ENKV_HONEYCOMB_TEST_KEY"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var console bytes.Buffer
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root, Console: &console, remoteBase: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitMetrics(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitTraces(context.Background()); err != nil {
		t.Fatal(err)
	}
	telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if console.Len() != 0 || runtime.recorder != nil {
		t.Fatal("disabled logs retained a recorder or wrote console output")
	}
	if _, err := os.Stat(filepath.Join(root, "telemetry", "logs.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("disabled log file: %v", err)
	}
	for _, signal := range []string{"metrics", "traces"} {
		info, err := os.Stat(filepath.Join(root, "telemetry", signal+".jsonl"))
		if err != nil || info.Size() == 0 {
			t.Fatalf("enabled %s file missing or empty: %v", signal, err)
		}
	}
	for _, name := range []string{"console", "capture", "hosted"} {
		if runtime.LogStatus(name) != (DeliveryStatus{}) {
			t.Errorf("disabled %s logs have delivery status: %+v", name, runtime.LogStatus(name))
		}
	}
	for _, name := range []string{"capture", "hosted"} {
		for _, status := range []DeliveryStatus{runtime.MetricStatus(name), runtime.TraceStatus(name)} {
			if status.Written == 0 || status.Incomplete {
				t.Errorf("enabled %s signal failed: %+v", name, status)
			}
		}
	}
	close(received)
	seen := map[string]bool{}
	for path := range received {
		seen[path] = true
	}
	if seen["/v1/logs"] || !seen["/v1/metrics"] || !seen["/v1/traces"] {
		t.Fatalf("off changed the wrong HTTP signals: %v", seen)
	}
}
