package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

const controlledAssertionCaller = "enkv.sh/core/internal/testmain/coordinator_test.go"

func controlledFailureSources(t *testing.T, directory string) *records.FailureSourceBinding {
	t.Helper()
	sources := records.FailureSources{SchemaVersion: 1, BinarySHA256: strings.Repeat("1", 64), OverlaySHA256: strings.Repeat("2", 64), Paths: map[string]string{controlledAssertionCaller: "tests/shared/runner/coordinator_test.go"}}
	file := filepath.Join(directory, "failure-sources.json")
	if records.WriteJSON(file, sources, 0400) != nil {
		t.Fatal("controlled source binding")
	}
	digest, err := assemblyFileSHA256(file)
	if err != nil {
		t.Fatal(err)
	}
	return &records.FailureSourceBinding{Path: file, SHA256: digest}
}

// full_only: false
func TestCoordinatorRetainsAssertionEvidenceAndIndependentCleanup(t *testing.T) {
	for _, mode := range []string{"failed_writer", "assertion_missing_result", "assertion_malformed_result", "assertion_writer_cleanup", "assertion_child_parent", "assertion_malformed_marker", "assertion_passing_marker", "assertion_cleanup_callback", "assertion_write_fault", "timeout", "timeout_checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			state, binary := coordinatorFixture(t)
			allowance := testLimits()
			allowance.ElapsedSeconds = 10
			if strings.HasPrefix(mode, "timeout") {
				allowance.ElapsedSeconds = 1
			}
			result := &state.record.Scenarios[0]
			if state.executeScenario(context.Background(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": mode}, allowance, result) == nil {
				t.Fatal("controlled failure passed")
			}
			if result.Writer == nil || !result.Writer.Joined || result.Writer.Assertions == nil {
				t.Fatal("joined process and independent assertion evidence were lost")
			}
			got := *result.Writer.Assertions
			want := "valid_failure_marker"
			switch mode {
			case "failed_writer", "timeout", "timeout_checkpoint":
				want = "no_failure_marker"
			case "assertion_malformed_marker", "assertion_write_fault":
				want = "invalid_failure_marker"
			case "assertion_passing_marker", "assertion_cleanup_callback":
				want = "contradictory_failure_marker"
			}
			if got.Marker != want {
				t.Fatal("marker availability or contradiction differs", got)
			}
			if strings.HasPrefix(mode, "timeout") && result.Writer.Process != "timed_out" {
				t.Fatal("termination exit class was rewritten")
			}
			if mode == "timeout_checkpoint" && (got.Checkpoint != "valid_checkpoint" || got.Completed != (records.CompletedCheckpoint{Code: "authentication", Sequence: 1})) {
				t.Fatal("kill lost last completed checkpoint", got)
			}
			if mode == "timeout" && (got.Checkpoint != "no_checkpoint" || got.Completed.Code != "none") {
				t.Fatal("kill invented a completed operation", got)
			}
			if got.MarkerWriteError != (mode == "assertion_write_fault") {
				t.Fatal("write error fact was invented or lost", got)
			}
			if mode == "assertion_writer_cleanup" {
				if cleanupPassed(result.Cleanup) || result.CleanupWorker == nil || result.CleanupWorker.Assertions == nil || result.CleanupWorker.Assertions.Marker != "valid_failure_marker" {
					t.Fatal("cleanup failure replaced or lost writer failure")
				}
			} else if !cleanupPassed(result.Cleanup) {
				t.Fatal("marker failure suppressed independent joined cleanup")
			}
			if mode == "assertion_child_parent" {
				if len(result.Children) == 0 || result.Children[0].Assertions == nil || result.Children[0].Assertions.Marker != "valid_failure_marker" || result.Children[0].Worker == result.Writer.Worker {
					t.Fatal("child and parent failure ownership merged")
				}
			}
			if state.save() != nil {
				t.Fatal("public result unavailable")
			}
			body, err := os.ReadFile(filepath.Join(state.directory, "run.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{"synthetic-secret", controlledAssertionCaller, "coordinator_test.go", `"nonce"`, `"line"`, `"fatal"`} {
				if bytes.Contains(body, []byte(private)) {
					t.Fatal("private assertion detail reached public records")
				}
			}
		})
	}
}

// full_only: false
func TestWorkerImportsMarkerWithoutWorkerResult(t *testing.T) {
	for _, resultState := range []string{"missing", "malformed"} {
		t.Run(resultState, func(t *testing.T) {
			inv, _, _ := telemetryImportFixture(t)
			inv.FailureSources = controlledFailureSources(t, inv.StateDir)
			recorder, err := records.NewFailureRecorder(inv)
			if err != nil {
				t.Fatal(err)
			}
			recorder.Record("fatal", controlledAssertionCaller, 1)
			if resultState == "malformed" && os.WriteFile(filepath.Join(inv.OutputDir, "worker.json"), []byte("{"), 0600) != nil {
				t.Fatal("malformed result fixture")
			}
			state := &runState{record: runRecord{Suite: "live"}}
			evidence, _, err := state.importWorker(inv, inv.Scenario, processResult{Status: "process_failed", Joined: true}, nil)
			if err == nil || evidence.Outcome != "failed" || evidence.Process != "process_failed" || !evidence.Joined || evidence.Assertions == nil || evidence.Assertions.Marker != "valid_failure_marker" {
				t.Fatal("worker result availability hid independent marker or process facts", evidence)
			}
		})
	}
}

// full_only: false
func TestAssertionEvidenceDoesNotCreateOrRemoveTypedRecovery(t *testing.T) {
	original := records.WorkerResult{Role: "writer", Outcome: "failed", Failure: &records.Failure{Class: "store_transport_exhausted", Stage: "transition"}, StoreFailure: &records.StoreFailure{StoreReason: "transport", Outcome: "evidence-unavailable", Reason: "write-uncertain"}, Phases: []records.PhaseResult{{Sequence: 1, Name: "transition", Outcome: "failed", Actual: "failed"}}}
	process := processResult{Status: "process_failed", Joined: true}
	for _, marker := range []string{"no_failure_marker", "valid_failure_marker", "invalid_failure_marker"} {
		for _, test := range []struct{ typed, completeDelivery bool }{{true, true}, {true, false}, {false, true}, {false, false}} {
			name := marker + "/untyped"
			if test.typed {
				name = marker + "/typed"
			}
			if test.completeDelivery {
				name += "/complete_delivery"
			} else {
				name += "/missing_delivery"
			}
			t.Run(name, func(t *testing.T) {
				inv, _, _ := telemetryImportFixture(t)
				inv.Scenario = sameDomainRecoveryScenario
				inv.FailureSources = controlledFailureSources(t, inv.StateDir)
				participants := map[string]string{"authority": "operator"}
				input := workerInput{RecoveryMode: "disabled", Participants: participants, Scenarios: []string{inv.Scenario}}
				if records.WriteJSON(inv.Input, input, 0400) != nil {
					t.Fatal("recovery input fixture unavailable")
				}
				switch marker {
				case "valid_failure_marker":
					recorder, err := records.NewFailureRecorder(inv)
					if err != nil {
						t.Fatal(err)
					}
					recorder.Record("fatal", controlledAssertionCaller, 1)
				case "invalid_failure_marker":
					if os.WriteFile(filepath.Join(inv.OutputDir, "failure.json"), []byte("{"), 0600) != nil {
						t.Fatal("invalid recovery marker fixture unavailable")
					}
				}
				worker := original
				worker.SchemaVersion, worker.RunID, worker.Worker = records.SchemaVersion, inv.RunID, inv.Worker
				worker.Scenario, worker.Actor = inv.Scenario, "operator"
				if !test.typed {
					worker.StoreFailure = nil
				}
				if test.completeDelivery {
					worker.Deliveries = map[string]records.DeliveryStatus{"logs.console": completeDeliveryStatus(0, 0, 0, 0, false)}
				}
				if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), worker, 0600) != nil {
					t.Fatal("recovery result fixture unavailable")
				}
				state := &runState{record: runRecord{Suite: "live", Resolved: &resolvedRequest{Mode: "live", RecoveryMode: "disabled", RoleBindings: participants}}}
				evidence, imported, err := state.importWorker(inv, inv.Scenario, process, nil)
				if err == nil || evidence.Outcome != "failed" || evidence.Process != "process_failed" || !evidence.Joined || evidence.Assertions == nil || evidence.Assertions.Marker != marker {
					t.Fatal("private marker changed the failed process evidence", evidence)
				}
				if test.typed {
					if imported.StoreFailure == nil || *imported.StoreFailure != *original.StoreFailure || evidence.StoreFailure == nil || *evidence.StoreFailure != *original.StoreFailure || imported.Failure == nil || *imported.Failure != *original.Failure {
						t.Fatal("private marker removed the original typed transport failure")
					}
				} else if imported.StoreFailure != nil || evidence.StoreFailure != nil {
					t.Fatal("private marker supplied missing transport evidence")
				}
				if eligibleSameDomainRerun(inv.Scenario, process, imported, nil) != test.typed {
					t.Fatal("private marker changed typed recovery eligibility")
				}
				if state.telemetryIncomplete != (!test.typed || !test.completeDelivery) {
					t.Fatal("private marker changed the typed-failure telemetry exception")
				}
			})
		}
	}
}

// full_only: false
func TestCleanupCauseSurvivesImportAndUsesClosedReport(t *testing.T) {
	status, target, remaining, unknown := uint16(503), uint32(2), int64(1), int64(1)
	fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "provider_refused",
		Effect: "unknown", HTTPStatus: &status, TargetKind: "inventory", TargetIndex: &target, Attempt: 1}
	worker := records.WorkerResult{Cleanup: &records.Cleanup{Outcome: "unresolved", RemainingOwnedObjects: &remaining,
		UnknownEffects: &unknown, HarnessFailure: &fact}}
	imported := safeCleanup(worker, workerEvidence{Outcome: "failed"})
	if imported.HarnessFailure == nil || *imported.HarnessFailure != fact {
		t.Fatal("closed cleanup cause was lost at import")
	}
	body, err := json.Marshal(imported)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"remaining_owned_objects":1`, `"unknown_effects":1`, `"stage":"conditional_delete"`, `"cause":"provider_refused"`, `"http_status":503`, `"target_index":2`} {
		if !bytes.Contains(body, []byte(want)) {
			t.Error("closed imported cleanup fact missing", want)
		}
	}
	if imported.Outcome != "unresolved" || imported.UnknownEffects == nil || *imported.UnknownEffects != 1 || imported.RemainingOwnedObjects == nil || *imported.RemainingOwnedObjects != 1 {
		t.Fatal("cleanup import lost exact unresolved counts")
	}
	worker.Cleanup.UnknownEffects = nil
	worker.Cleanup.Outcome, remaining = "passed", 0
	if invalid := safeCleanup(worker, workerEvidence{Outcome: "passed", Process: "passed", Joined: true}); invalid.UnknownEffects != nil || invalid.Outcome != "unresolved" {
		t.Fatal("unknown cleanup evidence became a known count or success")
	}
	fact.Cause = "RAW_PROVIDER_SECRET_SENTINEL"
	if fact.Validate() {
		t.Error("unclosed provider cause was admitted")
	}
}

func completeDeliveryStatus(accepted, written, dropped, failed uint64, incomplete bool) records.DeliveryStatus {
	return records.DeliveryStatus{Accepted: &accepted, Written: &written, Dropped: &dropped, Failed: &failed, Incomplete: &incomplete}
}
