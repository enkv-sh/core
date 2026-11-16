package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestInvocationAndOperationLogsMatchExportedSpans(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":["capture"]},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root})
	if err != nil {
		t.Fatal(err)
	}
	ctx := runtime.Context(context.Background())
	invocation := telemetry.StartWithDetails(ctx, telemetry.ProviderApplication, telemetry.OpApplicationInvocation,
		(telemetry.DiagnosticDetails{}).WithInvocationID("0123456789abcdef0123456789abcdef"))
	operation := telemetry.Start(invocation.Context(), telemetry.ProviderCore, telemetry.OpCoreOpen)
	source, cancel := context.WithCancel(operation.Context())
	private := telemetry.PrivateContext(context.Background(), source)
	cancel()
	child := telemetry.Start(private, telemetry.ProviderCrypto, telemetry.OpCryptoConsume)
	child.Finish(telemetry.ResultSuccess)
	operation.Finish(telemetry.ResultAdmissionRefused)
	invocation.Finish(telemetry.ResultSuccess)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	type spanRow struct {
		TraceID      string `json:"traceId"`
		SpanID       string `json:"spanId"`
		ParentSpanID string `json:"parentSpanId"`
		Name         string `json:"name"`
	}
	spans := map[string]spanRow{}
	for _, line := range fileLines(t, filepath.Join(root, "telemetry", "traces.jsonl")) {
		var batch struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []spanRow `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal(line, &batch); err != nil {
			t.Fatal(err)
		}
		for _, resource := range batch.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					spans[span.Name] = span
				}
			}
		}
	}
	parent, parentOK := spans[string(telemetry.OpApplicationInvocation)]
	coreSpan, coreOK := spans[string(telemetry.OpCoreOpen)]
	cryptoSpan, cryptoOK := spans[string(telemetry.OpCryptoConsume)]
	if !parentOK || !coreOK || !cryptoOK || parent.TraceID == "" || coreSpan.TraceID != parent.TraceID || coreSpan.ParentSpanID != parent.SpanID ||
		cryptoSpan.TraceID != parent.TraceID || cryptoSpan.ParentSpanID != coreSpan.SpanID {
		t.Fatalf("invocation and operation spans = %+v", spans)
	}
	logSpans := map[string]bool{}
	for _, line := range fileLines(t, filepath.Join(root, "telemetry", "logs.jsonl")) {
		var batch struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						TraceID string `json:"traceId"`
						SpanID  string `json:"spanId"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.Unmarshal(line, &batch); err != nil {
			t.Fatal(err)
		}
		for _, resource := range batch.ResourceLogs {
			for _, scope := range resource.ScopeLogs {
				for _, record := range scope.LogRecords {
					if record.TraceID == parent.TraceID {
						logSpans[record.SpanID] = true
					}
				}
			}
		}
	}
	if !logSpans[parent.SpanID] || !logSpans[coreSpan.SpanID] || !logSpans[cryptoSpan.SpanID] {
		t.Fatalf("log-to-span correlation missing: parent=%+v core=%+v crypto=%+v log spans=%+v", parent, coreSpan, cryptoSpan, logSpans)
	}
}

// full_only: false
func TestUnsampledTraceKeepsCorrelatedLogsWithoutExportedSpan(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":["capture"]},"traces":{"exporters":["capture"],"sample_ratio":0},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	runtime, err := Start(settings, SetupOptions{BaseDirectory: root})
	if err != nil {
		t.Fatal(err)
	}
	call := telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen)
	call.Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "telemetry", "traces.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("unsampled trace wrote a span: %v", err)
	}
	matched := false
	for _, line := range fileLines(t, filepath.Join(root, "telemetry", "logs.jsonl")) {
		var batch struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						TraceID    string `json:"traceId"`
						SpanID     string `json:"spanId"`
						TraceFlags string `json:"flags"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.Unmarshal(line, &batch); err != nil {
			t.Fatal(err)
		}
		for _, resource := range batch.ResourceLogs {
			for _, scope := range resource.ScopeLogs {
				for _, record := range scope.LogRecords {
					if len(record.TraceID) == 32 && len(record.SpanID) == 16 {
						matched = true
					}
				}
			}
		}
	}
	if !matched {
		t.Fatal("unsampled operation lost valid log correlation")
	}
}

func fileLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		t.Fatal("empty OTLP file", path)
	}
	return bytes.Split(data, []byte("\n"))
}
