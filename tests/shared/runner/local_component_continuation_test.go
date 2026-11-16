package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestHermeticWorkerFailureContainmentKeepsInvalidEvidenceFatal(t *testing.T) {
	parent := t.Context()
	native := runProcess(parent, "/bin/sh", t.TempDir(), []string{"-c", "exit 7"}, os.Environ(), time.Second)
	if !native.Started || !native.Joined || native.Status != "process_failed" {
		t.Fatal("native failure did not settle", native)
	}
	native.diagnostic = &toolFailure{operation: "controlled writer", process: native}
	for _, imported := range []bool{false, true} {
		for _, name := range []string{"contained", "missing_result", "malformed_result", "wrong_identity", "wrong_input", "wrong_phase", "passing_result", "invalid_assertion", "delivery_failure", "log_write_failure", "initial_log_tail", "telemetry_missing_tail", "telemetry_malformed", "telemetry_invalid_snapshot", "unjoined", "unknown_anchor", "parent_cancel"} {
			t.Run(map[bool]string{false: "native", true: "imported"}[imported]+"/"+name, func(t *testing.T) {
				inv, result, _ := telemetryImportFixture(t)
				inv.Scenario, inv.RecoveryMode = "state.single-value-update-preserves-other-values", "disabled"
				participants := map[string]string{"authority": "operator"}
				input := workerInput{RunID: inv.RunID, Scenarios: []string{inv.Scenario}, Repetitions: 1, RecoveryMode: "disabled", Participants: participants}
				result.Scenario, result.Actor, result.Outcome = inv.Scenario, "operator", "failed"
				result.Phases, result.Children, result.FreshChecks = nil, nil, nil
				result.Telemetry = records.Telemetry{Status: "disabled"}
				var before *catalog.Step
				if imported {
					execution, known := recordedExecutionForRecovery(inv.Scenario, "hermetic", "disabled")
					if !known || len(execution.ExpandedFreshBefore()) == 0 {
						t.Fatal("bound child step unavailable")
					}
					step := execution.ExpandedFreshBefore()[0].Step
					before = &step
					inv.Role, inv.RecoveryMode, result.Role = "fresh_before", step.RecoveryMode, "fresh_before"
					result.Actor = participants[step.Role]
				}
				s := &runState{record: runRecord{Suite: "hermetic", Resolved: &resolvedRequest{Mode: "hermetic", RecoveryMode: "disabled", RoleBindings: participants}}}
				process, anchor := native, native
				if imported {
					process = processResult{Status: "process_failed", Started: true, Joined: true}
				}
				ctx := parent
				switch name {
				case "wrong_identity":
					result.RunID = "different"
				case "wrong_input":
					input.RunID = "different"
				case "wrong_phase":
					result.Phases = []records.PhaseResult{{Sequence: 1, Name: "wrong", Actor: "operator", Outcome: "failed", Expected: "success", Actual: "failed"}}
				case "passing_result":
					result.Outcome = "passed"
				case "invalid_assertion":
					if err := os.WriteFile(filepath.Join(inv.OutputDir, "failure.json"), []byte("{"), 0600); err != nil {
						t.Fatal(err)
					}
				case "delivery_failure":
					failed := uint64(1)
					result.Deliveries = map[string]records.DeliveryStatus{"logs.console": {Failed: &failed}}
				case "log_write_failure":
					result.Diagnostics = records.Diagnostics{Enabled: true, Status: "incomplete", FailureClass: "delivery_failed"}
				case "initial_log_tail":
					result.Diagnostics = records.Diagnostics{Enabled: true, Status: "incomplete"}
				case "telemetry_missing_tail", "telemetry_malformed", "telemetry_invalid_snapshot":
					s.record.Telemetry.Enabled = true
					result.Telemetry = records.Telemetry{Enabled: true, Status: "incomplete", Source: "telemetry.json"}
					if name == "telemetry_malformed" {
						if err := os.WriteFile(filepath.Join(inv.OutputDir, "telemetry.json"), []byte("{"), 0600); err != nil {
							t.Fatal(err)
						}
					} else if name == "telemetry_invalid_snapshot" {
						if err := records.WriteJSON(filepath.Join(inv.OutputDir, "telemetry.json"), []records.Snapshot{{}}, 0600); err != nil {
							t.Fatal(err)
						}
					}
				case "unjoined":
					process.Joined = false
				case "unknown_anchor":
					anchor.Cause = errors.New("unknown native ownership")
					if !imported {
						process.Cause = anchor.Cause
					}
				case "parent_cancel":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(parent)
					cancel()
				}
				if err := records.WriteJSON(inv.Input, input, 0400); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(inv.OutputDir, "worker.json")
				if name == "malformed_result" {
					if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
						t.Fatal(err)
					}
				} else if name != "missing_result" {
					if err := records.WriteJSON(path, result, 0600); err != nil {
						t.Fatal(err)
					}
				}
				var cause error
				if imported {
					_, _, cause = s.importWorkerWithAnchor(ctx, inv, inv.Scenario, process, before, &anchor)
				} else {
					_, _, cause = s.importWorkerOwned(ctx, inv, inv.Scenario, process, before)
				}
				if cause == nil || containedCheckFailure(ctx, cause) != (name == "contained" || name == "initial_log_tail" || name == "telemetry_missing_tail") {
					t.Fatal("native failure concealed invalid evidence or lost containment", cause)
				}
			})
		}
	}
}
