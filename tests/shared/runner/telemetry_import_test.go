package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

func telemetryImportFixture(t *testing.T) (records.Invocation, records.WorkerResult, []records.Snapshot) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runID := strings.Repeat("a", 32)
	private := filepath.Join(root, "runs", runID, "private")
	inv := records.Invocation{
		SchemaVersion: records.SchemaVersion, Scenario: "state.single-value-update-preserves-other-values/members_32", Nonce: "0123456789abcdef0123456789abcdef", RunID: runID, Worker: "writer-1", Role: "writer",
		Input: filepath.Join(private, "input.json"), StateDir: filepath.Join(private, "state"), OutputDir: filepath.Join(private, "writer"),
	}
	for _, directory := range []string{inv.StateDir, inv.OutputDir} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := records.WriteJSON(inv.Input, map[string]string{"run_id": runID}, 0400); err != nil {
		t.Fatal(err)
	}
	worker := records.WorkerResult{
		SchemaVersion: records.SchemaVersion, RunID: runID, Worker: inv.Worker, Role: inv.Role, Scenario: "state.single-value-update-preserves-other-values/members_32", Outcome: "passed",
		Phases: []records.PhaseResult{
			{Sequence: 1, Name: "setup", Outcome: "passed", MeasurementsExpected: true},
			{Sequence: 2, Name: "setup", Outcome: "passed", MeasurementsExpected: true},
		},
		Telemetry: records.Telemetry{Enabled: true, Status: "complete", Source: "telemetry.json"},
	}
	snapshots := []records.Snapshot{}
	for index, count := range []float64{3, 2, 0} {
		phase := "setup"
		metrics := []records.Metric{telemetryImportCounter(count)}
		if index == 2 {
			phase, metrics = "final", []records.Metric{}
		}
		snapshots = append(snapshots, records.Snapshot{
			SchemaVersion: records.TelemetryVersion, RunID: runID, Worker: inv.Worker, Sequence: uint64(index + 1), Phase: phase,
			Status: "complete", CollectedAt: time.Date(2026, 9, 7, 1, 2, index, 0, time.UTC), Temporality: "delta", Metrics: metrics,
		})
	}
	return inv, worker, snapshots
}

func telemetryImportCounter(value float64) records.Metric {
	return records.Metric{
		Name: "enkv.future.observations", Unit: "{observation}", Kind: "sum", Value: &value,
		Attributes: map[string]string{"provider": "core", "operation": "core.open"},
	}
}

func writeImportedTelemetry(t *testing.T, inv records.Invocation, value any) {
	t.Helper()
	if err := records.WriteJSON(filepath.Join(inv.OutputDir, "telemetry.json"), value, 0600); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestTelemetryImportBindsRepeatedPhasesAndFutureMetrics(t *testing.T) {
	inv, worker, snapshots := telemetryImportFixture(t)
	writeImportedTelemetry(t, inv, snapshots)
	actual, summary := loadWorkerTelemetry(inv, worker, true)
	if !reflect.DeepEqual(actual, snapshots) || !summary.Enabled || summary.Status != "complete" || summary.Source != "telemetry.json" || !reflect.DeepEqual(summary.Definitions, telemetry.Definitions()) {
		t.Fatalf("valid repeated delta history changed: %+v, %+v", actual, summary)
	}
	// The importer owns its result. A later caller mutation cannot change the
	// rows, pointers, or attribute maps retained by a report.
	combined, _ := combineTelemetry(true, actual)
	*actual[0].Metrics[0].Value = 100
	actual[0].Metrics[0].Attributes["provider"] = "aws"
	if *combined[0].Metrics[0].Value != 3 || combined[0].Metrics[0].Attributes["provider"] != "core" {
		t.Fatal("aggregate aliases its input")
	}
}

// full_only: false
func TestTelemetryImportKeepsValidatedResourceAndScope(t *testing.T) {
	_, _, snapshots := telemetryImportFixture(t)
	settings, err := observability.Resolve(observability.Config{SchemaVersion: 1, Resource: observability.ResourceConfig{Attributes: map[string]any{"deployment.environment": "local"}}, Scopes: map[string]observability.Scope{"core": {Name: "custom.core"}}}, observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	snapshots[0].Resource = settings.Resource
	snapshots[0].Scopes = map[string]string{}
	for component, scope := range settings.Scopes {
		snapshots[0].Scopes[component] = scope.Name
	}
	got, valid := projectTelemetrySnapshot(snapshots[0])
	if !valid || got.Status != "complete" || got.Resource["deployment.environment"] != "local" || got.Scopes["core"] != "custom.core" {
		t.Fatalf("selected metadata was lost: %+v", got)
	}
	snapshots[0].Resource["deployment.environment"] = "SYNTHETIC_SECRET\nnext-line"
	got, valid = projectTelemetrySnapshot(snapshots[0])
	if !valid || got.Status != "incomplete" || got.Resource != nil {
		t.Fatalf("unsafe metadata was retained: %+v", got)
	}
}

// full_only: false
func TestTelemetryDisabledDoesNotReadOrProjectInput(t *testing.T) {
	inv := records.Invocation{OutputDir: "/does/not/exist/SYNTHETIC_SECRET"}
	worker := records.WorkerResult{Telemetry: records.Telemetry{Enabled: true, Status: "incomplete", FailureClass: "SYNTHETIC_SECRET"}}
	snapshots, summary := loadWorkerTelemetry(inv, worker, false)
	if len(snapshots) != 0 || summary.Enabled || summary.Status != "disabled" || summary.Source != "" || summary.Definitions != nil || summary.FailureClass != "" {
		t.Fatal("disabled import inspected input or created telemetry evidence")
	}
	snapshots, summary = combineTelemetry(false, []records.Snapshot{{Worker: "SYNTHETIC_SECRET"}})
	if len(snapshots) != 0 || summary.Enabled || summary.Status != "disabled" || summary.Definitions != nil {
		t.Fatal("disabled combination projected telemetry")
	}
}

// full_only: false
func TestTelemetryImportProjectsSafePartialEvidence(t *testing.T) {
	inv, worker, snapshots := telemetryImportFixture(t)
	secret := "SYNTHETIC_SECRET_TOKEN"
	worker.Telemetry.Source = "../../" + secret
	worker.Telemetry.Definitions = []telemetry.Definition{{Description: secret}}
	worker.Telemetry.Status, worker.Telemetry.FailureClass = "incomplete", secret
	worker.Failure = &records.Failure{Class: secret, Stage: secret}
	encoded, err := json.Marshal(snapshots)
	if err != nil {
		t.Fatal(err)
	}
	var raw []map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	raw[0]["failure_class"], raw[0]["raw_error"], raw[0]["definitions"] = secret, secret, secret
	rows := raw[0]["metrics"].([]any)
	rows[0].(map[string]any)["raw_error"] = secret
	raw[0]["metrics"] = append(rows,
		map[string]any{"name": "enkv.future.unsafe", "unit": "1", "kind": "sum", "value": 5, "attributes": map[string]string{"credential": secret}},
		map[string]any{"name": "enkv.future.malformed", "unit": "1", "kind": "sum", "value": secret},
	)
	writeImportedTelemetry(t, inv, raw)
	actual, summary := loadWorkerTelemetry(inv, worker, true)
	if summary.Status != "incomplete" || len(actual) != 3 || len(actual[0].Metrics) != 1 || *actual[0].Metrics[0].Value != 3 || actual[0].Status != "incomplete" {
		t.Fatal("unsafe rows erased safe partial observations or escaped refusal")
	}
	public, err := json.Marshal(struct {
		Snapshots []records.Snapshot
		Summary   records.Telemetry
	}{actual, summary})
	if err != nil || strings.Contains(string(public), secret) || strings.Contains(string(public), "raw_error") || strings.Contains(string(public), "credential") {
		t.Fatal("private telemetry content reached projected evidence")
	}
	if !reflect.DeepEqual(summary.Definitions, telemetry.Definitions()) || summary.Source != "telemetry.json" {
		t.Fatal("untrusted definitions or path reached projected evidence")
	}
	if worker.Outcome != "passed" || worker.Failure.Class != secret {
		t.Fatal("telemetry import changed correctness evidence")
	}
}

// full_only: false
func TestTelemetryImportRetainsHistoryWhenEvidenceIsIncomplete(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*records.WorkerResult, *[]records.Snapshot)
		kept   int
	}{
		{"missing_final", func(_ *records.WorkerResult, s *[]records.Snapshot) { *s = (*s)[:2] }, 2},
		{"missing_middle", func(_ *records.WorkerResult, s *[]records.Snapshot) { *s = append((*s)[:1], (*s)[2]) }, 2},
		{"stale_run", func(_ *records.WorkerResult, s *[]records.Snapshot) { (*s)[1].RunID = strings.Repeat("b", 32) }, 2},
		{"stale_worker", func(_ *records.WorkerResult, s *[]records.Snapshot) { (*s)[1].Worker = "another-worker" }, 2},
		{"wrong_phase", func(_ *records.WorkerResult, s *[]records.Snapshot) { (*s)[1].Phase = "transition" }, 2},
		{"reordered", func(_ *records.WorkerResult, s *[]records.Snapshot) { (*s)[0], (*s)[1] = (*s)[1], (*s)[0] }, 3},
		{"duplicate", func(_ *records.WorkerResult, s *[]records.Snapshot) { *s = append(*s, (*s)[1]) }, 2},
		{"final_reuses_sequence", func(_ *records.WorkerResult, s *[]records.Snapshot) { (*s)[2].Sequence = 2 }, 2},
		{"phase_unfinished", func(w *records.WorkerResult, _ *[]records.Snapshot) { w.Phases[1].Outcome = "incomplete" }, 3},
		{"empty_expected", func(_ *records.WorkerResult, s *[]records.Snapshot) { (*s)[1].Metrics = []records.Metric{} }, 3},
		{"zero_expected", func(_ *records.WorkerResult, s *[]records.Snapshot) { *(*s)[1].Metrics[0].Value = 0 }, 3},
		{"invocation_only_sum", func(_ *records.WorkerResult, s *[]records.Snapshot) {
			metric := telemetryImportCounter(3)
			metric.Attributes = map[string]string{"provider": string(telemetry.ProviderWorker), "operation": string(telemetry.OpWorkerInvocation)}
			(*s)[1].Metrics = []records.Metric{metric}
		}, 3},
		{"invocation_only_histogram", func(_ *records.WorkerResult, s *[]records.Snapshot) {
			metric := telemetryImportHistogram()
			metric.Attributes = map[string]string{"provider": string(telemetry.ProviderWorker), "operation": string(telemetry.OpWorkerInvocation)}
			(*s)[1].Metrics = []records.Metric{metric}
		}, 3},
		{"collection_failed", func(_ *records.WorkerResult, s *[]records.Snapshot) {
			(*s)[1].Status, (*s)[1].FailureClass = "incomplete", "collection_failed"
		}, 3},
		{"worker_shutdown_failed", func(w *records.WorkerResult, _ *[]records.Snapshot) {
			w.Telemetry.Status, w.Telemetry.FailureClass = "incomplete", "shutdown_failed"
		}, 3},
		{"worker_disabled", func(w *records.WorkerResult, _ *[]records.Snapshot) {
			w.Telemetry.Enabled, w.Telemetry.Status = false, "disabled"
		}, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			inv, worker, snapshots := telemetryImportFixture(t)
			test.mutate(&worker, &snapshots)
			writeImportedTelemetry(t, inv, snapshots)
			actual, summary := loadWorkerTelemetry(inv, worker, true)
			if summary.Status != "incomplete" || len(actual) != test.kept {
				t.Fatalf("incomplete history not retained: count %d, summary %+v", len(actual), summary)
			}
			if strings.HasPrefix(test.name, "invocation_only_") && (summary.FailureClass != "no_observations" || actual[1].Status != "incomplete" || actual[1].FailureClass != "no_observations" || !reflect.DeepEqual(actual[1].Metrics, snapshots[1].Metrics)) {
				t.Fatal("invocation-only phase lost its retained metrics or observation failure")
			}
			if worker.Outcome != "passed" {
				t.Fatal("telemetry status changed correctness")
			}
		})
	}
}

// full_only: false
func TestTelemetryImportRefusesMissingAndUnownedSources(t *testing.T) {
	for _, problem := range []string{"missing", "malformed", "symlink", "wrong_identity", "wrong_role"} {
		t.Run(problem, func(t *testing.T) {
			inv, worker, snapshots := telemetryImportFixture(t)
			path := filepath.Join(inv.OutputDir, "telemetry.json")
			switch problem {
			case "malformed":
				if err := os.WriteFile(path, []byte(`[{"raw_error":"SYNTHETIC_SECRET"`), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(inv.StateDir, "unowned-telemetry.json")
				if err := records.WriteJSON(target, snapshots, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "wrong_identity":
				writeImportedTelemetry(t, inv, snapshots)
				worker.RunID = strings.Repeat("b", 32)
			case "wrong_role":
				writeImportedTelemetry(t, inv, snapshots)
				worker.Role = "cleanup"
			}
			actual, summary := loadWorkerTelemetry(inv, worker, true)
			if len(actual) != 0 || summary.Status != "incomplete" || strings.Contains(summary.FailureClass, "SYNTHETIC_SECRET") {
				t.Fatal("unavailable or unowned telemetry was admitted")
			}
		})
	}
}

// full_only: false
func TestTelemetryCombinationIsOrderedAndRejectsDuplicateCollections(t *testing.T) {
	_, _, snapshots := telemetryImportFixture(t)
	a := snapshots[0]
	a.Worker = "a-worker"
	b := snapshots[1]
	b.Worker = "b-worker"
	conflict := snapshots[0]
	conflict.Metrics = []records.Metric{telemetryImportCounter(500)}
	actual, summary := combineTelemetry(true, []records.Snapshot{b, snapshots[0]}, []records.Snapshot{snapshots[2], conflict, a})
	if summary.Status != "incomplete" || len(actual) != 3 || actual[0].Worker != "a-worker" || actual[1].Worker != "b-worker" || actual[2].Sequence != 3 {
		t.Fatal("combination reordered identities or selected a conflicting delta")
	}
	for _, snapshot := range actual {
		if snapshot.Worker == snapshots[0].Worker && snapshot.Sequence == 1 {
			t.Fatal("duplicate collection was retained")
		}
	}
	reversed, reversedSummary := combineTelemetry(true, []records.Snapshot{a, conflict, snapshots[2]}, []records.Snapshot{snapshots[0], b})
	if !reflect.DeepEqual(actual, reversed) || !reflect.DeepEqual(summary, reversedSummary) {
		t.Fatal("collection arrival order changed the aggregate")
	}
	if actual, summary := combineTelemetry(true); len(actual) != 0 || summary.Status != "incomplete" || summary.FailureClass != "no_observations" {
		t.Fatal("empty telemetry became an observed zero")
	}
}

func telemetryImportHistogram() records.Metric {
	count, sum := uint64(4), float64(8)
	return records.Metric{
		Name: "enkv.future.histogram", Unit: "s", Kind: "histogram", Count: &count, Sum: &sum,
		Bounds: []float64{1, 3}, Buckets: []uint64{1, 2, 1}, Attributes: map[string]string{"provider": "core"},
	}
}

// full_only: false
func TestTelemetryImportValidatesMetricShapesWithoutNameAllowlist(t *testing.T) {
	for _, test := range []struct {
		name   string
		metric func() records.Metric
		valid  bool
	}{
		{"future_sum", func() records.Metric { return telemetryImportCounter(2) }, true},
		{"future_gauge", func() records.Metric { m := telemetryImportCounter(2); m.Kind = "gauge"; return m }, true},
		{"future_histogram", telemetryImportHistogram, true},
		{"negative_scalar", func() records.Metric { return telemetryImportCounter(-1) }, false},
		{"nan_scalar", func() records.Metric { return telemetryImportCounter(math.NaN()) }, false},
		{"infinite_scalar", func() records.Metric { return telemetryImportCounter(math.Inf(1)) }, false},
		{"missing_scalar", func() records.Metric { m := telemetryImportCounter(2); m.Value = nil; return m }, false},
		{"mixed_scalar", func() records.Metric { m := telemetryImportCounter(2); n := uint64(1); m.Count = &n; return m }, false},
		{"unsafe_name", func() records.Metric {
			m := telemetryImportCounter(2)
			m.Name = "enkv.future.\nSYNTHETIC_SECRET"
			return m
		}, false},
		{"long_name", func() records.Metric { m := telemetryImportCounter(2); m.Name = strings.Repeat("x", 256); return m }, false},
		{"unsafe_unit", func() records.Metric { m := telemetryImportCounter(2); m.Unit = "B|SYNTHETIC_SECRET"; return m }, false},
		{"unknown_attribute", func() records.Metric {
			m := telemetryImportCounter(2)
			m.Attributes["token"] = "SYNTHETIC_SECRET"
			return m
		}, false},
		{"unsafe_attribute_value", func() records.Metric {
			m := telemetryImportCounter(2)
			m.Attributes["provider"] = "SYNTHETIC_SECRET"
			return m
		}, false},
		{"missing_count", func() records.Metric { m := telemetryImportHistogram(); m.Count = nil; return m }, false},
		{"missing_sum", func() records.Metric { m := telemetryImportHistogram(); m.Sum = nil; return m }, false},
		{"negative_sum", func() records.Metric { m := telemetryImportHistogram(); *m.Sum = -1; return m }, false},
		{"infinite_sum", func() records.Metric { m := telemetryImportHistogram(); *m.Sum = math.Inf(1); return m }, false},
		{"nan_bound", func() records.Metric { m := telemetryImportHistogram(); m.Bounds[0] = math.NaN(); return m }, false},
		{"negative_bound", func() records.Metric { m := telemetryImportHistogram(); m.Bounds[0] = -1; return m }, false},
		{"unordered_bounds", func() records.Metric { m := telemetryImportHistogram(); m.Bounds = []float64{3, 1}; return m }, false},
		{"duplicate_bounds", func() records.Metric { m := telemetryImportHistogram(); m.Bounds = []float64{1, 1}; return m }, false},
		{"bucket_length", func() records.Metric { m := telemetryImportHistogram(); m.Buckets = []uint64{1, 3}; return m }, false},
		{"bucket_count", func() records.Metric { m := telemetryImportHistogram(); *m.Count = 5; return m }, false},
		{"bucket_overflow", func() records.Metric {
			m := telemetryImportHistogram()
			m.Buckets = []uint64{math.MaxUint64, 2, 3}
			return m
		}, false},
		{"empty_nonzero_sum", func() records.Metric {
			m := telemetryImportHistogram()
			*m.Count = 0
			m.Buckets = []uint64{0, 0, 0}
			return m
		}, false},
		{"mixed_histogram", func() records.Metric { m := telemetryImportHistogram(); v := float64(1); m.Value = &v; return m }, false},
		{"unsupported_kind", func() records.Metric { m := telemetryImportCounter(2); m.Kind = "SYNTHETIC_SECRET"; return m }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, snapshots := telemetryImportFixture(t)
			snapshots[0].Metrics = []records.Metric{test.metric()}
			actual, summary := combineTelemetry(true, snapshots[:1])
			if len(actual) != 1 || (summary.Status == "complete") != test.valid || (len(actual[0].Metrics) == 1) != test.valid {
				t.Fatalf("metric shape validation differs: %+v, %+v", actual, summary)
			}
			body, err := json.Marshal(actual)
			if err != nil || strings.Contains(string(body), "SYNTHETIC_SECRET") {
				t.Fatal("unsafe or non-serializable metric reached evidence")
			}
		})
	}
}

// full_only: false
func TestTelemetryImportPreservesIncompleteHTTPBodyObservations(t *testing.T) {
	inv, worker, snapshots := telemetryImportFixture(t)
	bytes := telemetryImportCounter(17)
	bytes.Name, bytes.Unit = telemetry.HTTPResponseBodyBytes, "B"
	bytes.Attributes = map[string]string{"provider": "gcp", "operation": "store.read", "status": "incomplete"}
	observations := telemetryImportCounter(1)
	observations.Name = telemetry.HTTPResponseBodyObservations
	observations.Attributes = map[string]string{"provider": "gcp", "operation": "store.read", "status": "incomplete"}
	snapshots[0].Metrics = []records.Metric{bytes, observations}
	writeImportedTelemetry(t, inv, snapshots)
	actual, summary := loadWorkerTelemetry(inv, worker, true)
	if summary.Status != "complete" || len(actual[0].Metrics) != 2 || *actual[0].Metrics[0].Value != 17 || actual[0].Metrics[0].Attributes["status"] != "incomplete" || actual[0].Metrics[1].Attributes["status"] != "incomplete" {
		t.Fatal("collection status erased partial HTTP body evidence")
	}
}

// full_only: false
func TestTelemetryImportRefusesMalformedSnapshotHeaders(t *testing.T) {
	for _, mutate := range []func(*records.Snapshot){
		func(s *records.Snapshot) { s.SchemaVersion++ },
		func(s *records.Snapshot) { s.RunID = "../SYNTHETIC_SECRET" },
		func(s *records.Snapshot) { s.Worker = "bad\nSYNTHETIC_SECRET" },
		func(s *records.Snapshot) { s.Sequence = 0 },
		func(s *records.Snapshot) { s.Phase = "bad\nSYNTHETIC_SECRET" },
		func(s *records.Snapshot) { s.Status = "SYNTHETIC_SECRET" },
		func(s *records.Snapshot) { s.Temporality = "cumulative" },
		func(s *records.Snapshot) { s.CollectedAt = time.Time{} },
	} {
		_, _, snapshots := telemetryImportFixture(t)
		mutate(&snapshots[0])
		actual, summary := combineTelemetry(true, snapshots)
		if len(actual) != 2 || summary.Status != "incomplete" {
			t.Fatal("invalid collection header admitted or safe collections erased")
		}
	}
}
