package records

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/compositions/observability"
	"enkv.sh/telemetry"
)

func localLogSettings(t *testing.T) *observability.Resolved {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return &settings
}

// full_only: false
func TestWorkerUsesSelectedOTLPLogFile(t *testing.T) {
	inv := testInvocation(t)
	inv.TelemetrySettings = localLogSettings(t)
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	call := telemetry.Start(worker.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	call.Finish(telemetry.ResultObservedCurrent)
	if err := worker.Finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	result := loadWorker(t, inv)
	if result.Outcome != "passed" || result.Telemetry.Enabled || !result.Diagnostics.Enabled {
		t.Fatalf("worker evidence: %+v", result)
	}
	diagnostics := result.Diagnostics
	if diagnostics.Accepted+diagnostics.DroppedContention != 5 || diagnostics.Accepted == 0 ||
		diagnostics.DroppedFull != 0 || diagnostics.DroppedClosed != 0 || diagnostics.DroppedWriter != diagnostics.DroppedContention || diagnostics.Rejected != 0 ||
		diagnostics.Written != diagnostics.Accepted {
		t.Fatalf("diagnostic capture or delivery lost unaccounted records: %+v", diagnostics)
	}
	if diagnostics.DroppedContention == 0 {
		if diagnostics.Status != "complete" || diagnostics.FailureClass != "" {
			t.Fatalf("complete diagnostic capture: %+v", diagnostics)
		}
	} else if diagnostics.Status != "incomplete" || diagnostics.FailureClass != "delivery_failed" {
		t.Fatalf("contention loss was not retained: %+v", diagnostics)
	}
	if len(result.Deliveries) != 1 {
		t.Fatalf("unexpected delivery routes: %+v", result.Deliveries)
	}
	fileDelivery, ok := result.Deliveries["logs.local"]
	if !ok || fileDelivery.Accepted == nil || fileDelivery.Written == nil || fileDelivery.Dropped == nil || fileDelivery.Failed == nil || fileDelivery.Incomplete == nil ||
		*fileDelivery.Accepted != diagnostics.Accepted || *fileDelivery.Written != diagnostics.Accepted ||
		*fileDelivery.Dropped != diagnostics.DroppedContention || *fileDelivery.Failed != 0 || *fileDelivery.Incomplete != (diagnostics.DroppedContention != 0) {
		t.Fatalf("selected OTLP file delivery: %+v", result.Deliveries)
	}
	inspected := InspectLogs(inv, diagnostics)
	if inspected != diagnostics || inspected.Source != "telemetry/logs.jsonl" {
		t.Fatalf("log evidence: %+v", inspected)
	}
	info, err := os.Stat(filepath.Join(inv.OutputDir, inspected.Source))
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() > maximumLogFileBytes {
		t.Fatal("OTLP log file is not private and bounded", err)
	}
	content, err := os.ReadFile(filepath.Join(inv.OutputDir, inspected.Source))
	if err != nil {
		t.Fatal(err)
	}
	var records uint64
	for _, line := range bytes.Split(bytes.TrimSuffix(content, []byte{'\n'}), []byte{'\n'}) {
		var batch struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []json.RawMessage `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.Unmarshal(line, &batch); err != nil {
			t.Fatal(err)
		}
		for _, resource := range batch.ResourceLogs {
			for _, scope := range resource.ScopeLogs {
				records += uint64(len(scope.LogRecords))
			}
		}
	}
	if records != diagnostics.Accepted {
		t.Fatalf("OTLP file has %d records, capture accepted %d", records, diagnostics.Accepted)
	}
}

// full_only: false
func TestDefaultWorkerCreatesNoTelemetryFile(t *testing.T) {
	inv := testInvocation(t)
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil || worker.Finish(context.Background(), true) != nil {
		t.Fatal("default worker failed", err)
	}
	if _, err := os.Lstat(filepath.Join(inv.OutputDir, "telemetry")); !os.IsNotExist(err) {
		t.Fatal("default created export directory")
	}
}

// full_only: false
func TestLogImportRejectsOldSchemaAndTruncatedLine(t *testing.T) {
	inv := testInvocation(t)
	inv.TelemetrySettings = localLogSettings(t)
	if os.Mkdir(filepath.Join(inv.OutputDir, "telemetry"), 0o700) != nil {
		t.Fatal("directory")
	}
	path := filepath.Join(inv.OutputDir, "telemetry", "logs.jsonl")
	claim := Diagnostics{Enabled: true, Status: "complete", Source: "telemetry/logs.jsonl", Written: 1}
	for _, test := range []struct{ body, failure string }{
		{`{"schema_version":2,"kind":"record"}` + "\n", "format_refused"},
		{`{"resourceLogs":[{}]}` + "\n{", "truncated"},
	} {
		if os.WriteFile(path, []byte(test.body), 0o600) != nil {
			t.Fatal("fixture")
		}
		got := InspectLogs(inv, claim)
		if got.Status != "incomplete" || got.FailureClass != test.failure {
			t.Fatalf("import of %q: %+v", test.body, got)
		}
	}
	claim.Source = "diagnostics.ndjson"
	if got := InspectLogs(inv, claim); got.FailureClass != "source_refused" {
		t.Fatalf("legacy format admitted: %+v", got)
	}
}

// full_only: false
func TestLogSinkOpenFailureDoesNotChangeProductOutcome(t *testing.T) {
	inv := testInvocation(t)
	inv.TelemetrySettings = localLogSettings(t)
	if os.Symlink("outside", filepath.Join(inv.OutputDir, "telemetry")) != nil {
		t.Fatal("symlink fixture")
	}
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	call := telemetry.Start(worker.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen)
	call.Finish(telemetry.ResultObservedCurrent)
	if err := worker.Finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	result := loadWorker(t, inv)
	if result.Outcome != "passed" || result.Diagnostics.Status != "incomplete" || !strings.Contains(result.Diagnostics.FailureClass, "delivery") {
		t.Fatalf("sink failure changed Product evidence: %+v", result)
	}
}
