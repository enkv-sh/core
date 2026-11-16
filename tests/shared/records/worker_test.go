package records

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// full_only: false
func TestWorkerRecordsAssertionsAndPreservesExplicitObservations(t *testing.T) {
	for _, actual := range []string{"", "access-refused", "success", "incomplete"} {
		t.Run("actual_"+actual, func(t *testing.T) {
			inv := testInvocation(t)
			inv.Scenario = "access.provider-refuses-observer/members_32_denied_observer"
			worker, err := NewWorker(inv, "core", "access.provider-refuses-observer/members_32_denied_observer", nil)
			if err != nil {
				t.Fatal(err)
			}
			execution, known := catalog.ExecutionFor("access.provider-refuses-observer/members_32_denied_observer", "hermetic")
			if !known {
				t.Fatal("execution facts unavailable")
			}
			var step catalog.Step
			for position, phase := range execution.Writer {
				if phase.Step.Expected == "access-refused" && phase.Step.RecoveryMode == "disabled" {
					worker.catalogPosition, step = position, phase.Step
					break
				}
			}
			sequence, err := worker.BeginStep(step, "auditor")
			if err != nil {
				t.Fatal(err)
			}
			if saved := loadWorker(t, inv); saved.Phases[0].Actor != "auditor" || saved.Phases[0].Expected != "access-refused" || saved.Phases[0].Actual != "incomplete" {
				t.Fatal("scenario expectation was not saved before work")
			}
			if actual != "" && worker.ObservePhase(sequence, actual) != nil {
				t.Fatal("observation was not saved")
			}
			if worker.EndPhase(context.Background(), sequence, true) != nil || worker.Finish(context.Background(), true) != nil {
				t.Fatal("worker result was not saved")
			}
			want := actual
			if want == "" {
				want = "access-refused"
			}
			result := loadWorker(t, inv)
			if result.Phases[0].Actual != want || (result.Outcome == "passed") != (want == "access-refused") {
				t.Fatal("an observation was rewritten or a mismatch passed")
			}
			evidence := InspectAssertions(inv, result.Outcome == "passed")
			if want == "access-refused" {
				if evidence.Checkpoint != "valid_checkpoint" || evidence.Completed != (CompletedCheckpoint{Code: step.Name, Sequence: sequence}) {
					t.Fatal("expected refusal lost completed checkpoint", evidence)
				}
			} else if evidence.Checkpoint != "no_checkpoint" || evidence.Completed.Code != "none" {
				t.Fatal("incomplete or unexpected outcome became completion", evidence)
			}
		})
	}
}

// full_only: false
func TestWorkerRecoverySelectionStartsAtFilteredPosition(t *testing.T) {
	for _, recovery := range []string{"", "both", "disabled", "enabled"} {
		t.Run("mode_"+recovery, func(t *testing.T) {
			inv := testInvocation(t)
			inv.RecoveryMode = recovery
			worker, err := NewWorker(inv, "core", inv.Scenario, nil)
			if err != nil {
				t.Fatal("declared writer recovery selection refused", err)
			}
			defer func() {
				if err := worker.Finish(context.Background(), false); err != nil {
					t.Error(err)
				}
			}()
			execution, known := catalog.ExecutionFor(inv.Scenario, "hermetic")
			if !known {
				t.Fatal("full execution unavailable")
			}
			var expected []catalog.Step
			for _, step := range execution.WriterSteps() {
				if recovery == "" || recovery == "both" || step.RecoveryMode == "" || step.RecoveryMode == recovery {
					expected = append(expected, step)
				}
			}
			if len(expected) == 0 {
				t.Fatal("selected writer has no declared steps")
			}
			for _, step := range expected {
				sequence, err := worker.BeginStep(step, step.Role)
				if err != nil {
					t.Fatal("filtered writer position rejected declared step", step, err)
				}
				if worker.ObservePhase(sequence, step.Expected) != nil || worker.EndPhase(context.Background(), sequence, true) != nil {
					t.Fatal("selected writer evidence was not saved")
				}
			}
			if worker.Finish(context.Background(), true) != nil {
				t.Fatal("selected writer completion refused")
			}
			result := loadWorker(t, inv)
			if result.Outcome != "passed" || len(result.Phases) != len(expected) || result.Phases[0].Sequence != 1 {
				t.Fatal("selected writer did not start at filtered position zero", result)
			}
			for position, phase := range result.Phases {
				if phase.RecoveryMode != expected[position].RecoveryMode || phase.Name != expected[position].Name {
					t.Fatal("writer saved an omitted or reordered recovery phase")
				}
			}
		})
	}
}

// full_only: false
func TestWorkerRecoverySelectionRefusesUndeclaredExecution(t *testing.T) {
	for _, test := range []struct {
		name, scenario, recovery string
	}{
		{"unsupported", "state.single-value-update-preserves-other-values/members_32", "unsupported"},
		{"enabled_only", "access.recovery-combined-k2-current-material/plain1_secret1_exact_successor", "disabled"},
		{"undeclared_reconstruction", "reconstruction.zero-secret-genesis/complete_loss_zero_secret_genesis", "enabled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inv := testInvocation(t)
			inv.Scenario, inv.RecoveryMode = test.scenario, test.recovery
			before := otel.GetMeterProvider()
			worker, err := NewWorker(inv, "core", inv.Scenario, nil)
			if err == nil || worker != nil || otel.GetMeterProvider() != before {
				t.Fatal("undeclared selected execution started a worker or SDK")
			}
			for _, name := range []string{"worker.json", "telemetry.json"} {
				if _, err := os.Lstat(filepath.Join(inv.OutputDir, name)); !os.IsNotExist(err) {
					t.Fatal("refused selection created worker evidence", name, err)
				}
			}
		})
	}
}

// full_only: false
func TestWorkerFreshBeforeDoesNotRequireAfterReader(t *testing.T) {
	for _, scenario := range []string{"state.single-value-update-preserves-other-values/members_32", "access.observer-sees-selected-state/members_32_observer", "reconstruction.generated-retiring/complete_loss_generated_retiring", "reconstruction.generated-uncertain/complete_loss_generated_uncertain"} {
		for _, role := range []string{"fresh_before", "fresh_after"} {
			t.Run(scenario+"/"+role, func(t *testing.T) {
				inv := testInvocation(t)
				inv.Scenario, inv.Role, inv.Facts = scenario, role, "facts.json"
				if err := WriteJSON(filepath.Join(inv.StateDir, inv.Facts), struct{}{}, 0400); err != nil {
					t.Fatal(err)
				}
				inv.TelemetrySettings = localMetricSettings(t)
				before := otel.GetMeterProvider()
				worker, err := NewWorker(inv, "gcp", scenario, nil)
				if role == "fresh_after" && strings.HasPrefix(scenario, "reconstruction.") {
					if err == nil || worker != nil || otel.GetMeterProvider() != before {
						t.Fatal("absent after reader was admitted or changed telemetry")
					}
					if _, err := os.Lstat(filepath.Join(inv.OutputDir, "worker.json")); !os.IsNotExist(err) {
						t.Fatal("refused after reader saved a worker")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := worker.Finish(context.Background(), false); err != nil {
						t.Error(err)
					}
				}()
				wantActor := "authority"
				if role == "fresh_after" && scenario == "access.observer-sees-selected-state/members_32_observer" {
					wantActor = "observer"
				}
				if saved := loadWorker(t, inv); saved.Actor != wantActor || saved.Outcome != "incomplete" {
					t.Fatal("fresh worker did not save provisional authority before work")
				}
			})
		}
	}
}

func beginPhase(t *testing.T, worker *WorkerRecorder, name string, expected bool) uint64 {
	t.Helper()
	sequence, err := worker.BeginPhase(name, expected)
	if err != nil {
		t.Fatal(err)
	}
	return sequence
}

func localMetricSettings(t *testing.T) *observability.Resolved {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return &settings
}

func recordCalls(t *testing.T, worker *WorkerRecorder, count int64) {
	t.Helper()
	if err := worker.runtime.AwaitMetrics(context.Background()); err != nil {
		t.Fatal(err)
	}
	counter, err := worker.runtime.MeterProvider().Meter(worker.runtime.ScopeNames()["core"]).Int64Counter("enkv.future.calls", metric.WithUnit("{call}"))
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), count, metric.WithAttributes(attribute.String("provider", "core")))
}

func loadWorker(t *testing.T, inv Invocation) WorkerResult {
	t.Helper()
	var result WorkerResult
	if err := ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func loadSnapshots(t *testing.T, inv Invocation) []Snapshot {
	t.Helper()
	var snapshots []Snapshot
	if err := ReadJSON(filepath.Join(inv.OutputDir, "telemetry.json"), &snapshots); err != nil {
		t.Fatal(err)
	}
	return snapshots
}

// full_only: false
func TestWorkerDisabledKeepsCorrectnessWithoutSDKOrTelemetryFiles(t *testing.T) {
	inv := testInvocation(t)
	before := otel.GetMeterProvider()
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	seq := beginPhase(t, worker, "transition", true)
	if saved := loadWorker(t, inv); saved.Outcome != "incomplete" || len(saved.Phases) != 1 || saved.Phases[0].Outcome != "incomplete" {
		t.Fatal("phase was not persisted before work")
	}
	if err := worker.EndPhase(context.Background(), seq, true); err != nil {
		t.Fatal(err)
	}
	if err := worker.Finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	result := loadWorker(t, inv)
	if result.Outcome != "passed" || result.Telemetry.Enabled || result.Telemetry.Status != "disabled" || result.Telemetry.Source != "" || otel.GetMeterProvider() != before {
		t.Fatalf("disabled worker changed SDK or correctness: %+v", result)
	}
	if _, err := os.Lstat(filepath.Join(inv.OutputDir, "telemetry.json")); !os.IsNotExist(err) {
		t.Fatal("disabled worker created telemetry source")
	}
}

// full_only: false
func TestWorkerRepeatedPhasesKeepDeltaSequenceAndFinishOnce(t *testing.T) {
	inv := testInvocation(t)
	inv.TelemetrySettings = localMetricSettings(t)
	before := otel.GetMeterProvider()
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := worker.Finish(context.Background(), false); err != nil {
			t.Error(err)
		}
	})
	for _, calls := range []int64{3, 2} {
		seq := beginPhase(t, worker, "setup", true)
		recordCalls(t, worker, calls)
		if err := worker.EndPhase(context.Background(), seq, true); err != nil {
			t.Fatal(err)
		}
		if err := worker.EndPhase(context.Background(), seq, true); err == nil {
			t.Fatal("one phase ended twice")
		}
	}
	if err := worker.Finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(inv.OutputDir, "telemetry.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Finish(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(inv.OutputDir, "telemetry.json"))
	if err != nil || string(first) != string(second) {
		t.Fatal("finish duplicated collection")
	}
	result := loadWorker(t, inv)
	snapshots := loadSnapshots(t, inv)
	if result.Outcome != "passed" || result.Telemetry.Status != "complete" || len(snapshots) != 3 || otel.GetMeterProvider() != before {
		t.Fatalf("worker did not complete: %+v, %+v", result, snapshots)
	}
	for index, snapshot := range snapshots {
		if snapshot.Sequence != uint64(index+1) || snapshot.RunID != inv.RunID || snapshot.Worker != inv.Worker || snapshot.Status != "complete" {
			t.Fatal("snapshot identity or sequence changed")
		}
	}
	if *snapshots[0].Metrics[0].Value != 3 || *snapshots[1].Metrics[0].Value != 2 {
		t.Fatal("phase totals reused prior delta")
	}
	for _, metric := range snapshots[2].Metrics {
		if metric.Name == "enkv.future.calls" && (metric.Value != nil && *metric.Value != 0 || metric.Count != nil && *metric.Count != 0) {
			t.Fatal("final collection duplicated phase observations")
		}
	}
}

// full_only: false
func TestWorkerIncompleteMeasurementsDoNotChangePassedCorrectness(t *testing.T) {
	for _, failure := range []string{"no_observations", "zero_observations", "collection_failed", "write_failed"} {
		t.Run(failure, func(t *testing.T) {
			inv := testInvocation(t)
			inv.TelemetrySettings = localMetricSettings(t)
			worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := worker.Finish(context.Background(), false); err != nil {
					t.Error(err)
				}
			})
			seq := beginPhase(t, worker, "transition", true)
			if failure == "zero_observations" {
				recordCalls(t, worker, 0)
			} else if failure != "no_observations" {
				recordCalls(t, worker, 1)
			}
			if failure == "collection_failed" {
				worker.collector.Close(context.Background())
			}
			if failure == "write_failed" {
				if err := os.Mkdir(filepath.Join(inv.OutputDir, "telemetry.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := worker.EndPhase(context.Background(), seq, true); err != nil {
				t.Fatalf("telemetry failure entered correctness path: %v", err)
			}
			if err := worker.Finish(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			result := loadWorker(t, inv)
			expectedClass := failure
			if expectedClass == "zero_observations" {
				expectedClass = "no_observations"
			}
			if result.Outcome != "passed" || result.Failure != nil || result.Telemetry.Status != "incomplete" || result.Telemetry.FailureClass != expectedClass {
				t.Fatalf("failure changed correctness or lost its class: %+v", result)
			}
			body, err := os.ReadFile(filepath.Join(inv.OutputDir, "worker.json"))
			if err != nil || strings.Contains(string(body), "SYNTHETIC_SECRET") {
				t.Fatal("raw failure input entered worker record")
			}
		})
	}
}

// full_only: false
func TestWorkerUnfinishedPhaseAndFailedAssertionsRemainVisible(t *testing.T) {
	inv := testInvocation(t)
	inv.TelemetrySettings = localMetricSettings(t)
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	beginPhase(t, worker, "transition", true)
	recordCalls(t, worker, 1)
	worker.Result.Failure = &Failure{Class: "assertion_failed", Stage: "transition"}
	if err := worker.Finish(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	result := loadWorker(t, inv)
	if result.Outcome != "failed" || result.Failure.Class != "assertion_failed" || result.Phases[0].Outcome != "incomplete" || result.Telemetry.Status != "incomplete" || result.Telemetry.FailureClass != "phase_not_finished" {
		t.Fatal("unfinished phase was reported complete")
	}
	snapshots := loadSnapshots(t, inv)
	if snapshots[0].Sequence != result.Phases[0].Sequence || snapshots[0].Status != "incomplete" || snapshots[0].FailureClass != "phase_not_finished" {
		t.Fatal("partial observations were treated as complete")
	}
}

// full_only: false
func TestWorkerControlWriteFailureIsReturnedBeforeWork(t *testing.T) {
	inv := testInvocation(t)
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inv.OutputDir, "worker.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.BeginPhase("transition", true); err == nil {
		t.Fatal("control write failure permitted unrecorded work")
	}
	if err := worker.Finish(context.Background(), false); err == nil {
		t.Fatal("final control write failure was hidden")
	}
}

// full_only: false
func TestWorkerRegistersChildInputsBeforeExecution(t *testing.T) {
	inv := testInvocation(t)
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	facts := filepath.Join(inv.StateDir, "facts.json")
	if err := WriteJSON(facts, struct{}{}, 0o400); err != nil {
		t.Fatal(err)
	}
	worker.Result.FreshChecks = []FreshCheck{{Facts: "facts.json"}}
	child := inv
	child.FreshBefore = nil
	child.Nonce = "fedcba9876543210fedcba9876543210"
	child.Worker, child.Role, child.Facts = "0000-point-fresh-0000-before", "fresh_before", "facts.json"
	child.OutputDir = filepath.Join(filepath.Dir(inv.OutputDir), "fresh-before")
	if err := os.Mkdir(child.OutputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(child.OutputDir, "invocation.json")
	owner, _, _, err := PrivateOwner(inv.OutputDir)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(owner, path)
	if err != nil {
		t.Fatal(err)
	}
	worker.Result.Children = []ChildInvocation{{Worker: child.Worker, Invocation: relative}}
	if worker.Save() == nil {
		t.Fatal("child registered without retained invocation")
	}
	if err := WriteJSON(path, child, 0o400); err != nil {
		t.Fatal(err)
	}
	worker.Result.BudgetReserved = &BudgetReservation{Requests: 4, BodyBytes: 123}
	remaining, unknown := int64(0), int64(0)
	worker.Result.Cleanup = &Cleanup{Outcome: "passed", RemainingOwnedObjects: &remaining, UnknownEffects: &unknown}
	if err := worker.Save(); err != nil {
		t.Fatal(err)
	}
	saved := loadWorker(t, inv)
	if len(saved.Children) != 1 || saved.Children[0].Worker != child.Worker || saved.Children[0].Invocation != relative || len(saved.FreshChecks) != 1 || saved.BudgetReserved.Requests != 4 || saved.Cleanup.Outcome != "passed" {
		t.Fatal("worker omitted registered work or independent budget and cleanup")
	}
	worker.Result.Children[0].Worker = "different-worker"
	if worker.Save() == nil {
		t.Fatal("child identity mismatch accepted")
	}
	worker.Result.Children[0].Worker = child.Worker
	worker.Result.Children[0].Invocation = "../invocation.json"
	if worker.Save() == nil {
		t.Fatal("child invocation path escape accepted")
	}
	worker.Result.Children = nil
	worker.Result.FreshChecks[0].Facts = "../facts.json"
	if worker.Save() == nil {
		t.Fatal("fresh facts path escape accepted")
	}
}

// full_only: false
func TestWorkerRejectsOverlappingPhasesAndPreservesFailedPhase(t *testing.T) {
	inv := testInvocation(t)
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	sequence := beginPhase(t, worker, "transition", true)
	if _, err := worker.BeginPhase("verification", true); err == nil {
		t.Fatal("overlapping phases admitted")
	}
	if err := worker.EndPhase(context.Background(), sequence+1, true); err == nil {
		t.Fatal("wrong phase sequence accepted")
	}
	if err := worker.EndPhase(context.Background(), sequence, false); err != nil {
		t.Fatal(err)
	}
	if err := worker.Finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	saved := loadWorker(t, inv)
	if saved.Outcome != "failed" || saved.Phases[0].Outcome != "failed" {
		t.Fatal("later success hid a failed assertion")
	}
}

// full_only: false
func TestWorkerRestoresSDKWhenFinalControlSaveFails(t *testing.T) {
	inv := testInvocation(t)
	inv.TelemetrySettings = localMetricSettings(t)
	before := otel.GetMeterProvider()
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	seq := beginPhase(t, worker, "transition", true)
	recordCalls(t, worker, 1)
	if err := worker.EndPhase(context.Background(), seq, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inv.OutputDir, "worker.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if worker.Finish(context.Background(), true) == nil || otel.GetMeterProvider() != before {
		t.Fatal("final control save error was hidden or prevented SDK restoration")
	}
	if worker.Finish(context.Background(), true) == nil {
		t.Fatal("repeated finish lost the original control error")
	}
}

// full_only: false
func TestWorkerRefusesReusedInvocationEvidence(t *testing.T) {
	for _, name := range []string{"worker.json", "telemetry.json", "failure.json", "checkpoint.json"} {
		t.Run(name, func(t *testing.T) {
			inv := testInvocation(t)
			inv.TelemetrySettings = localMetricSettings(t)
			path := filepath.Join(inv.OutputDir, name)
			if err := WriteJSON(path, struct{}{}, 0o600); err != nil {
				t.Fatal(err)
			}
			before := otel.GetMeterProvider()
			if _, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil); err == nil || otel.GetMeterProvider() != before {
				t.Fatal("worker reset prior evidence or changed SDK before admission")
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "{}\n" {
				t.Fatal("refused invocation changed its prior evidence")
			}
		})
	}
}

// full_only: false
func TestHarnessFailureAcceptsOnlyClosedCauseAndPrivateRowReference(t *testing.T) {
	status, target := uint16(503), uint32(3)
	fact := HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "provider_refused",
		Effect: "unknown", HTTPStatus: &status, TargetKind: "inventory", TargetIndex: &target, Attempt: 1}
	if !fact.Validate() {
		t.Fatal("closed cleanup failure refused")
	}
	for _, operation := range []string{"setup_check", "object_cleanup", "generator_cleanup", "output_cleanup", "raw operation"} {
		for _, kind := range []string{"", "inventory", "generator_ledger", "output_inventory", "raw identifier"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				candidate := fact
				candidate.Operation, candidate.TargetKind = operation, kind
				if kind == "" {
					candidate.TargetIndex = nil
				}
				valid := operation == "setup_check" && kind == "" || operation == "object_cleanup" && (kind == "" || kind == "inventory") || operation == "generator_cleanup" && (kind == "" || kind == "generator_ledger") || operation == "output_cleanup" && kind == "output_inventory"
				if candidate.Validate() != valid {
					t.Fatal("operation and private row relation differs", operation, kind, valid)
				}
			})
		}
	}
	output := fact
	output.Operation, output.TargetKind = "output_cleanup", "output_inventory"
	maximum, overflow := uint32(1000000), uint32(1000001)
	output.TargetIndex = &maximum
	if !output.Validate() {
		t.Fatal("bounded output row refused")
	}
	output.TargetIndex = &target
	for _, index := range []*uint32{nil, &overflow} {
		bad := output
		bad.TargetIndex = index
		if bad.Validate() {
			t.Fatal("missing or unbounded output index accepted")
		}
	}
	for _, change := range []string{"stage", "cause", "status", "provider_code", "target", "attempt"} {
		t.Run(change, func(t *testing.T) {
			bad := fact
			switch change {
			case "stage":
				bad.Stage = "raw SDK error"
			case "cause":
				bad.Cause = "raw provider message"
			case "status":
				invalid := uint16(600)
				bad.HTTPStatus = &invalid
			case "provider_code":
				bad.ProviderCode = "UnreviewedCode"
			case "target":
				bad.TargetKind = "raw object key"
			case "attempt":
				bad.Attempt = 4
			}
			if bad.Validate() {
				t.Fatal("unclosed provider content accepted", change)
			}
		})
	}
	inv := testInvocation(t)
	worker, err := NewWorker(inv, "core", "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	worker.Result.HarnessFailure = &output
	if worker.Save() != nil {
		t.Fatal("closed failure was not saved")
	}
	bad := fact
	bad.Cause = "raw provider message"
	worker.Result.HarnessFailure = &bad
	if worker.Save() == nil {
		t.Fatal("raw provider cause entered worker record")
	}
}
