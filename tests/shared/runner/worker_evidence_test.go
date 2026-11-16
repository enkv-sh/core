package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestWorkerAdmissionRequiresTheExactScenarioEvidence(t *testing.T) {
	for _, mode := range []string{"hermetic", "live"} {
		for _, scenario := range []string{"state.single-value-update-preserves-other-values/members_32", "access.provider-refuses-observer/members_32_denied_observer", "evidence.missing-selected-child-prevents-open/members_32_missing_page", "evidence.corrupt-selected-child-prevents-open/members_32_corrupt_page", "state.historical-bytes-get-new-identities/members_32_three_generations"} {
			for _, test := range []struct {
				name   string
				change func(*records.WorkerResult)
			}{
				{"complete", func(*records.WorkerResult) {}},
				{"missing_step", func(r *records.WorkerResult) { r.Phases = r.Phases[:len(r.Phases)-1] }},
				{"reordered_steps", func(r *records.WorkerResult) {
					r.Phases[0], r.Phases[1] = r.Phases[1], r.Phases[0]
					r.Phases[0].Sequence, r.Phases[1].Sequence = 1, 2
				}},
				{"wrong_worker_participant", func(r *records.WorkerResult) { r.Actor = "other" }},
				{"wrong_step_participant", func(r *records.WorkerResult) { r.Phases[0].Actor = "other" }},
				{"wrong_expected", func(r *records.WorkerResult) { r.Phases[0].Expected = "unavailable" }},
				{"wrong_actual", func(r *records.WorkerResult) { r.Phases[0].Actual = "access-refused" }},
				{"incomplete_actual", func(r *records.WorkerResult) { r.Phases[0].Actual = "incomplete" }},
				{"unobserved_actual", func(r *records.WorkerResult) { r.Phases[0].Actual = "" }},
				{"missing_after_facts", func(r *records.WorkerResult) { r.FreshChecks = nil }},
				{"extra_before_child", func(r *records.WorkerResult) {
					r.Children = append(r.Children, records.ChildInvocation{Worker: "extra"})
				}},
			} {
				t.Run(mode+"/"+scenario+"/"+test.name, func(t *testing.T) {
					inv, result, _ := telemetryImportFixture(t)
					inv.Scenario = scenario
					participants := map[string]string{"authority": "operator"}
					execution := executionFixture(scenario, mode)
					if catalog.HasFixtureCapability(scenario, catalog.FixtureObserver) {
						participants[execution.FreshAfter[0].Role] = "auditor"
					}
					recoveryMode := "disabled"
					if mode == "hermetic" {
						recoveryMode = "both"
						participants["recovery"] = "recovery"
					}
					input := workerInput{RecoveryMode: recoveryMode, Participants: participants, Scenarios: []string{scenario}}
					if records.WriteJSON(inv.Input, input, 0400) != nil {
						t.Fatal("worker input fixture")
					}
					result.Scenario, result.Actor = scenario, "operator"
					result.Phases = passedPhases(scenario, mode, "writer", participants, nil)
					result.Children = make([]records.ChildInvocation, len(execution.ExpandedFreshBefore()))
					result.FreshChecks = nil
					for i := range freshAfterCount(scenario, mode, "") {
						result.FreshChecks = append(result.FreshChecks, records.FreshCheck{Facts: fmt.Sprintf("facts-%d.json", i), RecoveryMode: expectedFreshMode(scenario, mode, "fresh_after", i, "")})
					}
					test.change(&result)
					if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), result, 0600) != nil {
						t.Fatal("worker evidence fixture")
					}
					partial, err := readWorkerResult(inv, scenario)
					if err != nil || !reflect.DeepEqual(partial.Phases, result.Phases) || partial.Actor != result.Actor {
						t.Fatal("valid diagnostic evidence was lost or rewritten")
					}
					s := &runState{record: runRecord{Suite: mode, Resolved: &resolvedRequest{Mode: mode, RecoveryMode: recoveryMode, RoleBindings: participants}}}
					evidence, _, err := s.importWorker(inv, scenario, processResult{Status: "passed", Joined: true}, nil)
					if (err == nil) != (test.name == "complete") || (evidence.Outcome == "passed") != (test.name == "complete") || !reflect.DeepEqual(evidence.Phases, result.Phases) || evidence.Actor != result.Actor {
						t.Fatal("success admission accepted incomplete evidence or changed an observation")
					}
				})
			}
		}
	}
}

// full_only: false
func TestTypedTransportFailureRejectsMissingOrOtherEvidence(t *testing.T) {
	base := records.WorkerResult{
		Role: "writer", Outcome: "failed",
		Failure:      &records.Failure{Class: "store_transport_exhausted", Stage: "transition"},
		StoreFailure: &records.StoreFailure{StoreReason: "transport", Outcome: "evidence-unavailable", Reason: "write-uncertain"},
		Phases:       []records.PhaseResult{{Sequence: 1, Name: "transition", Outcome: "failed", Actual: "failed"}},
	}
	if !validTransportFailure(base) {
		t.Fatal("complete typed transport failure refused")
	}
	for _, change := range []func(*records.WorkerResult){
		func(r *records.WorkerResult) { r.StoreFailure = nil },
		func(r *records.WorkerResult) { r.StoreFailure.StoreReason = "access" },
		func(r *records.WorkerResult) { r.StoreFailure.Outcome = "integrity-failure" },
		func(r *records.WorkerResult) { r.StoreFailure.CommitMayHaveOccurred = true },
		func(r *records.WorkerResult) { r.Failure.Class = "assertion_failed" },
		func(r *records.WorkerResult) { r.Role = "fresh_after" },
		func(r *records.WorkerResult) { r.Phases[0].Outcome = "incomplete" },
	} {
		value := base
		failure, storeFailure := *base.Failure, *base.StoreFailure
		value.Failure, value.StoreFailure = &failure, &storeFailure
		value.Phases = append([]records.PhaseResult(nil), base.Phases...)
		change(&value)
		if validTransportFailure(value) {
			t.Fatal("incomplete or different failure admitted for rerun", value)
		}
	}
	base.StoreFailure = &records.StoreFailure{StoreReason: "transport", Outcome: "unresolved-commit", Reason: "write-uncertain", CommitMayHaveOccurred: true}
	if !validTransportFailure(base) {
		t.Fatal("possible committed write cannot enter a fresh invocation")
	}
}

// full_only: false
func TestFreshWorkerAdmissionPreservesRefusalAndParticipantRoutes(t *testing.T) {
	participants := map[string]string{"authority": "operator", "denied-observer": "auditor"}
	for _, mode := range []string{"hermetic", "live"} {
		for _, role := range []string{"fresh_before", "fresh_after"} {
			for _, scenario := range []string{"access.provider-refuses-observer/members_32_denied_observer", "evidence.missing-selected-child-prevents-open/members_32_missing_page", "evidence.corrupt-selected-child-prevents-open/members_32_corrupt_page"} {
				execution := executionFixture(scenario, mode)
				var before *catalog.Step
				actor := participants[execution.FreshAfter[0].Role]
				if role == "fresh_before" {
					children := execution.ExpandedFreshBefore()
					if len(children) == 0 {
						continue
					}
					before = &children[0].Step
					actor = participants[before.Role]
				}
				result := records.WorkerResult{Role: role, Actor: actor, Scenario: scenario, Outcome: "passed", Phases: passedWorkerPhases(scenario, mode, role, participants, nil, before)}
				recovery := ""
				if mode == "hermetic" {
					recovery = "disabled"
					for i := range result.Phases {
						result.Phases[i].RecoveryMode = recovery
					}
				}
				if !completeWorker(result, mode, participants, recovery, before) {
					t.Fatal("complete refusal witness was rejected")
				}
				for index := range result.Phases {
					if result.Phases[index].Name != "reopen" {
						continue
					}
					wrong := result
					wrong.Phases = slices.Clone(result.Phases)
					wrong.Phases[index].Actual = "success"
					if completeWorker(wrong, mode, participants, recovery, before) || wrong.Phases[index].Actual != "success" {
						t.Fatal("successful open became the required refusal")
					}
					wrong.Phases[index].Actual = "incomplete"
					if completeWorker(wrong, mode, participants, recovery, before) {
						t.Fatal("an incomplete observation passed")
					}
				}
				result.Actor = "other"
				if completeWorker(result, mode, participants, recovery, before) {
					t.Fatal("another participant supplied the fresh result")
				}
			}
		}
	}
}

// full_only: false
func TestCleanupRequiresAdmittedWorkerEvidence(t *testing.T) {
	for _, test := range []struct {
		name     string
		accepted bool
		change   func(*records.WorkerResult)
	}{
		{"complete", true, func(*records.WorkerResult) {}},
		{"empty_inventory", true, func(r *records.WorkerResult) {
			r.Cleanup.BudgetReserved = &records.BudgetReservation{}
			r.Phases = r.Phases[2:]
			r.Phases[0].Sequence = 1
			r.Phases[0].MeasurementsExpected = false
		}},
		{"missing_authentication", false, func(r *records.WorkerResult) {
			r.Phases = r.Phases[2:]
			r.Phases[0].Sequence = 1
		}},
		{"wrong_participant", false, func(r *records.WorkerResult) { r.Actor = "old_operator" }},
		{"wrong_result", false, func(r *records.WorkerResult) { r.Phases[2].Actual = "incomplete" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			inv, result, _ := telemetryImportFixture(t)
			inv.Role, result.Role, result.Actor = "cleanup", "cleanup", "operator"
			participants := map[string]string{"authority": "operator"}
			if records.WriteJSON(inv.Input, workerInput{RecoveryMode: "disabled", Participants: participants}, 0400) != nil {
				t.Fatal("cleanup input fixture")
			}
			result.Cleanup = &records.Cleanup{Outcome: "passed", RemainingOwnedObjects: new(int64), UnknownEffects: new(int64), BudgetReserved: &records.BudgetReservation{Requests: 5}}
			result.Phases = passedPhases(result.Scenario, "live", "cleanup", participants, result.Cleanup)
			test.change(&result)
			if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), result, 0600) != nil {
				t.Fatal("cleanup evidence fixture")
			}
			s := &runState{record: runRecord{Suite: "live", Resolved: &resolvedRequest{Mode: "live", RecoveryMode: "disabled", RoleBindings: participants}}}
			evidence, raw, err := s.importWorker(inv, result.Scenario, processResult{Status: "passed", Joined: true}, nil)
			if (err == nil) != test.accepted || cleanupPassed(safeCleanup(raw, evidence)) != test.accepted {
				t.Fatal("cleanup success bypassed worker evidence admission")
			}
		})
	}
}

// full_only: false
func TestFullCoverageRejectsMissingOrChangedWorkerEvidence(t *testing.T) {
	for _, provider := range []string{"memory", "gcp", "aws"} {
		for _, test := range []struct {
			name   string
			change func(*scenarioResult)
		}{
			{"missing_phase", func(r *scenarioResult) { r.Writer.Phases = r.Writer.Phases[:len(r.Writer.Phases)-1] }},
			{"wrong_phase_actor", func(r *scenarioResult) { r.Writer.Phases[0].Actor = "other" }},
			{"wrong_worker_actor", func(r *scenarioResult) { r.Writer.Actor = "other" }},
			{"wrong_expected", func(r *scenarioResult) { r.Writer.Phases[0].Expected = "access-refused" }},
			{"wrong_actual", func(r *scenarioResult) { r.Writer.Phases[0].Actual = "access-refused" }},
			{"incomplete_actual", func(r *scenarioResult) { r.Writer.Phases[0].Actual = "incomplete" }},
			{"contradictory_assertion", func(r *scenarioResult) {
				r.Writer.Assertions = &records.AssertionEvidence{Marker: "contradictory_failure_marker", Checkpoint: "no_checkpoint", Completed: records.CompletedCheckpoint{Code: "none"}}
			}},
			{"invalid_checkpoint", func(r *scenarioResult) {
				r.Writer.Assertions = &records.AssertionEvidence{Marker: "no_failure_marker", Checkpoint: "invalid_checkpoint", Completed: records.CompletedCheckpoint{Code: "none"}}
			}},
			{"missing_child", func(r *scenarioResult) { r.Children = nil }},
			{"extra_after", func(r *scenarioResult) { r.PostExit = append(r.PostExit, r.PostExit[0]) }},
		} {
			t.Run(provider+"/"+test.name, func(t *testing.T) {
				_, value := completeRunFixture(t, provider)
				if !fullCoverage(value) {
					t.Fatal("valid full regression fixture was refused")
				}
				test.change(&value.Scenarios[0])
				if fullCoverage(value) {
					t.Fatal("incomplete or contradictory evidence claimed full coverage")
				}
			})
		}
	}
}

// full_only: false
func TestHermeticFullCoverageRequiresBothRecoveryModesInOrder(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*scenarioResult)
	}{
		{"missing_writer_mode", func(r *scenarioResult) { r.Writer.Phases[0].RecoveryMode = "" }},
		{"repeated_writer_mode", func(r *scenarioResult) {
			for i := range r.Writer.Phases {
				r.Writer.Phases[i].RecoveryMode = "enabled"
			}
		}},
		{"missing_after_mode", func(r *scenarioResult) { r.PostExit = r.PostExit[:1] }},
		{"repeated_after_mode", func(r *scenarioResult) {
			r.PostExit[1].RecoveryMode = r.PostExit[0].RecoveryMode
			for i := range r.PostExit[1].Phases {
				r.PostExit[1].Phases[i].RecoveryMode = r.PostExit[0].RecoveryMode
			}
		}},
		{"reordered_after_modes", func(r *scenarioResult) { r.PostExit[0], r.PostExit[1] = r.PostExit[1], r.PostExit[0] }},
		{"changed_before_mode", func(r *scenarioResult) {
			r.Children[0].RecoveryMode = "enabled"
			for i := range r.Children[0].Phases {
				r.Children[0].Phases[i].RecoveryMode = "enabled"
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, value := completeRunFixture(t, "memory")
			if !fullCoverage(value) {
				t.Fatal("complete two-mode fixture refused")
			}
			test.change(&value.Scenarios[0])
			if fullCoverage(value) {
				t.Fatal("missing or reordered recovery evidence accepted")
			}
		})
	}
}

// full_only: false
func TestHermeticRecoverySelectionEvidenceIsExact(t *testing.T) {
	const scenario = "state.single-value-update-preserves-other-values/members_32"
	for _, recovery := range []string{"disabled", "enabled"} {
		for _, test := range []struct {
			name   string
			change func(*records.WorkerResult)
		}{
			{"complete", func(*records.WorkerResult) {}},
			{"missing_phase", func(r *records.WorkerResult) { r.Phases = r.Phases[:len(r.Phases)-1] }},
			{"opposite_phase", func(r *records.WorkerResult) {
				r.Phases[0].RecoveryMode = "disabled"
				if recovery == "disabled" {
					r.Phases[0].RecoveryMode = "enabled"
				}
			}},
			{"missing_before", func(r *records.WorkerResult) { r.Children = nil }},
			{"missing_after", func(r *records.WorkerResult) { r.FreshChecks = nil }},
			{"repeated_after", func(r *records.WorkerResult) { r.FreshChecks = append(r.FreshChecks, r.FreshChecks[0]) }},
			{"opposite_after", func(r *records.WorkerResult) {
				r.FreshChecks[0].RecoveryMode = "disabled"
				if recovery == "disabled" {
					r.FreshChecks[0].RecoveryMode = "enabled"
				}
			}},
		} {
			t.Run(recovery+"/"+test.name, func(t *testing.T) {
				participants := map[string]string{"authority": "operator", "recovery": "recovery"}
				execution, known := catalog.ExecutionForRecovery(scenario, "hermetic", recovery)
				if !known {
					t.Fatal("declared selected execution unavailable")
				}
				result := records.WorkerResult{Role: "writer", Actor: "operator", Scenario: scenario, Outcome: "passed",
					Children:    make([]records.ChildInvocation, len(execution.ExpandedFreshBefore())),
					FreshChecks: []records.FreshCheck{{Facts: "selected.json", RecoveryMode: recovery}}}
				// The independent full fixture supplies the assertion facts; only
				// the requested mode is retained and sequence starts at one.
				for _, phase := range passedPhases(scenario, "hermetic", "writer", participants, nil) {
					if phase.RecoveryMode == recovery {
						phase.Sequence = uint64(len(result.Phases) + 1)
						result.Phases = append(result.Phases, phase)
					}
				}
				test.change(&result)
				if completeWorker(result, "hermetic", participants, recovery, nil) != (test.name == "complete") {
					t.Fatal("selected recovery evidence accepted omitted or widened execution facts")
				}
			})
		}
	}
}

// full_only: false
func TestCurrentKeyReplacementEvidenceRequiresOnlyDeclaredModes(t *testing.T) {
	for _, name := range []string{"access.normal-signer-k2-zero-material/plain1_no_current_secret", "access.recovery-combined-k2-current-material/plain1_secret1_exact_successor"} {
		definition, _ := catalog.DefinitionFor(name)
		participants := map[string]string{}
		for _, role := range definition.Roles {
			participants[role] = role
		}
		execution := executionFixture(name, "hermetic")
		result := records.WorkerResult{Role: "writer", Actor: "authority", Scenario: name, Outcome: "passed", Phases: passedPhases(name, "hermetic", "writer", participants, nil), Children: make([]records.ChildInvocation, len(execution.ExpandedFreshBefore()))}
		for i, mode := range definition.RecoveryModes {
			if expectedFreshMode(name, "hermetic", "fresh_after", i, "") != mode {
				t.Fatal("post-exit mode differs from declared schedule")
			}
			result.FreshChecks = append(result.FreshChecks, records.FreshCheck{Facts: fmt.Sprintf("facts-%d.json", i), RecoveryMode: mode})
		}
		if !completeWorker(result, "hermetic", participants, "", nil) {
			t.Fatal("complete declared mode evidence refused", name)
		}
		missing := result
		missing.FreshChecks = nil
		if completeWorker(missing, "hermetic", participants, "", nil) {
			t.Fatal("missing declared mode evidence accepted", name)
		}
		wrong := result
		wrong.FreshChecks = append([]records.FreshCheck(nil), result.FreshChecks...)
		wrong.FreshChecks[0].RecoveryMode = ""
		if completeWorker(wrong, "hermetic", participants, "", nil) {
			t.Fatal("unspecified post-exit mode accepted", name)
		}
		if len(definition.RecoveryModes) == 1 {
			wrong.FreshChecks[0].RecoveryMode = "disabled"
			if completeWorker(wrong, "hermetic", participants, "", nil) {
				t.Fatal("unsupported disabled mode substituted for enabled evidence")
			}
			fresh := records.WorkerResult{Role: "fresh_after", Actor: participants[execution.FreshAfter[0].Role], Scenario: name, Outcome: "passed", Phases: passedPhases(name, "hermetic", "fresh_after", participants, nil)}
			for i := range fresh.Phases {
				fresh.Phases[i].RecoveryMode = "disabled"
			}
			if completeWorker(fresh, "hermetic", participants, "disabled", nil) {
				t.Fatal("standalone fresh evidence admitted an unsupported recovery mode")
			}
		}
	}
}

// full_only: false
func TestGeneratedHistoryChildEvidenceRequiresExactStep(t *testing.T) {
	for _, scenario := range []string{"accepted.source-mode0-late-result/source0_late_result", "accepted.source-mode0-reciprocal-loss/source0_four_replacements_late_result"} {
		definition, _ := catalog.DefinitionFor(scenario)
		participants := map[string]string{}
		for _, role := range definition.Roles {
			participants[role] = role
		}
		for _, mode := range definition.Modes {
			for index, child := range executionFixture(scenario, mode).ExpandedFreshBefore() {
				step := child.Step
				t.Run(fmt.Sprintf("%s/%s/%d", scenario, mode, index), func(t *testing.T) {
					result := records.WorkerResult{Role: "fresh_before", Actor: participants[step.Role], Scenario: scenario, Outcome: "passed", Phases: passedWorkerPhases(scenario, mode, "fresh_before", participants, nil, &step)}
					if !completeWorker(result, mode, participants, step.RecoveryMode, &step) {
						t.Fatal("exact current child evidence refused")
					}
					if completeWorker(result, mode, participants, step.RecoveryMode, nil) {
						t.Fatal("generated history child supplied success without its expected step")
					}
					for _, change := range []string{"actor", "phase-actor", "purpose", "actual", "name", "missing-phase", "extra-phase", "nested-child", "after-facts", "wrong-mode", "after-role"} {
						wrong := result
						wrong.Phases = slices.Clone(result.Phases)
						recovery := step.RecoveryMode
						i := 0
						if mode == "live" {
							i = 1
						}
						switch change {
						case "actor":
							wrong.Actor = participants["authority"]
						case "phase-actor":
							wrong.Phases[i].Actor = participants["authority"]
						case "purpose":
							wrong.Phases[i].Expected, wrong.Phases[i].Actual = "closed-work-preserves-current-state", "closed-work-preserves-current-state"
						case "actual":
							wrong.Phases[i].Actual = "incomplete"
						case "name":
							wrong.Phases[i].Name = "verification"
						case "missing-phase":
							wrong.Phases = wrong.Phases[:len(wrong.Phases)-1]
						case "extra-phase":
							wrong.Phases = append(wrong.Phases, wrong.Phases[0])
						case "nested-child":
							wrong.Children = []records.ChildInvocation{{Worker: "unexpected"}}
						case "after-facts":
							wrong.FreshChecks = []records.FreshCheck{{Facts: "facts.json"}}
						case "wrong-mode":
							recovery = "disabled"
							if step.RecoveryMode == "disabled" {
								recovery = "enabled"
							}
							for p := range wrong.Phases {
								wrong.Phases[p].RecoveryMode = recovery
							}
						case "after-role":
							wrong.Role = "fresh_after"
						}
						if completeWorker(wrong, mode, participants, recovery, &step) {
							t.Fatal("changed child evidence admitted", change)
						}
					}
					for _, wrongStep := range []catalog.Step{{}, {Name: step.Name, Role: "authority", Expected: step.Expected, RecoveryMode: step.RecoveryMode}, {Name: "verification", Role: step.Role, Expected: "closed-work-preserves-current-state", RecoveryMode: step.RecoveryMode}} {
						if completeWorker(result, mode, participants, step.RecoveryMode, &wrongStep) {
							t.Fatal("undeclared child step admitted")
						}
					}
				})
			}
		}
	}
}

// full_only: false
func TestLiveGeneratedRecordChildRequiresItsTwoRecordedPhases(t *testing.T) {
	checked := 0
	for _, scenario := range catalog.GeneratedNames() {
		execution, known := catalog.ExecutionFor(scenario, "live")
		if !known {
			continue
		}
		for _, child := range execution.ExpandedFreshBefore() {
			if child.Purpose != catalog.FreshGeneratedRecord {
				continue
			}
			checked++
			participants := map[string]string{child.Role: "operator"}
			phases := passedWorkerPhases(scenario, "live", "fresh_before", participants, nil, &child.Step)
			if len(phases) != 2 {
				t.Fatal("record child fixture differs from its two recorded phases")
			}
			result := records.WorkerResult{Role: "fresh_before", Actor: "operator", Scenario: scenario, Outcome: "passed", Phases: phases}
			if !completeWorker(result, "live", participants, "", &child.Step) {
				t.Fatal("generated record child's complete phases were refused", scenario)
			}
			result.Phases = append(slices.Clone(phases), records.PhaseResult{Sequence: 3, Name: "verification", Actor: "operator", Expected: "success", Actual: "success", Outcome: "passed"})
			if completeWorker(result, "live", participants, "", &child.Step) {
				t.Fatal("generated record child admitted an unrecorded verification phase", scenario)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no live generated record child was checked")
	}
}

// full_only: false
func TestGeneratedHistoryChildInvocationBindsOrdinal(t *testing.T) {
	for _, scenario := range []string{"accepted.source-mode0-late-result/source0_late_result", "accepted.source-mode0-reciprocal-loss/source0_four_replacements_late_result"} {
		definition, _ := catalog.DefinitionFor(scenario)
		for _, mode := range definition.Modes {
			writer, _, _ := telemetryImportFixture(t)
			private := filepath.Dir(writer.Input)
			participants := map[string]string{}
			for _, role := range definition.Roles {
				participants[role] = role
			}
			if records.WriteJSON(writer.Input, workerInput{Participants: participants}, 0400) != nil || records.WriteJSON(filepath.Join(writer.StateDir, "facts.json"), map[string]bool{"persisted": true}, 0400) != nil || os.MkdirAll(filepath.Join(writer.StateDir, "workers"), 0700) != nil {
				t.Fatal("child input fixture")
			}
			writer.Scenario = scenario
			var bindingErr error
			writer.FreshBefore, bindingErr = issueFreshBefore(writer, mode)
			if bindingErr != nil {
				t.Fatal(bindingErr)
			}
			children := executionFixture(scenario, mode).ExpandedFreshBefore()
			steps := make([]catalog.Step, 0, len(children))
			for _, child := range children {
				steps = append(steps, child.Step)
			}
			for index, step := range steps {
				name := fmt.Sprintf("fresh-before-%s-%d", digestBytes([]byte(writer.Worker))[:12], index)
				output := filepath.Join(writer.OutputDir, fmt.Sprintf("fresh-before-%d", index))
				if mode == "hermetic" {
					name = fmt.Sprintf("%s-fresh-%04d-before", filepath.Base(writer.StateDir), index)
					output = filepath.Join(writer.StateDir, "workers", fmt.Sprintf("fresh-%04d-before", index))
				}
				inv, err := makeInvocation(records.Invocation{Scenario: scenario, RunID: writer.RunID, Worker: name, Role: "fresh_before", Input: writer.Input, StateDir: writer.StateDir, OutputDir: output, Facts: "facts.json", RecoveryMode: step.RecoveryMode}, mode)
				if err != nil {
					t.Fatal("child invocation fixture", err)
				}
				inv.Nonce = writer.FreshBefore[index].Nonce
				if records.WriteJSON(filepath.Join(output, "invocation.json"), inv, 0400) != nil {
					t.Fatal("child binding fixture")
				}
				relative, err := filepath.Rel(private, filepath.Join(output, "invocation.json"))
				if err != nil {
					t.Fatal(err)
				}
				child := records.ChildInvocation{Worker: name, Invocation: relative}
				loaded, expected, err := childInvocation(mode, scenario, private, writer, child, index)
				if err != nil || !reflect.DeepEqual(loaded, inv) || expected != step {
					t.Fatal("exact child position refused", mode, scenario, index, err)
				}
				tampered := inv
				tampered.Nonce, err = records.NewInvocationNonce()
				if err != nil || records.WriteJSON(filepath.Join(output, "invocation.json"), tampered, 0400) != nil {
					t.Fatal("nonce replay fixture")
				}
				if _, _, err := childInvocation(mode, scenario, private, writer, child, index); err == nil {
					t.Fatal("child self-report replaced the coordinator nonce")
				}
				if records.WriteJSON(filepath.Join(output, "invocation.json"), inv, 0400) != nil {
					t.Fatal("original child binding unavailable")
				}
				for _, wrong := range []int{-1, len(steps), (index + 1) % len(steps)} {
					if _, _, err := childInvocation(mode, scenario, private, writer, child, wrong); err == nil {
						t.Fatal("wrong child position admitted", wrong)
					}
				}
				result := records.WorkerResult{SchemaVersion: records.SchemaVersion, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Actor: participants[step.Role], Scenario: scenario, Outcome: "passed", Phases: passedWorkerPhases(scenario, mode, inv.Role, participants, nil, &step)}
				if records.WriteJSON(filepath.Join(output, "worker.json"), result, 0600) != nil {
					t.Fatal("child result fixture")
				}
				s := &runState{record: runRecord{Suite: mode}}
				if evidence, _, err := s.importWorker(loaded, scenario, processResult{Status: "passed", Joined: true}, &expected); err != nil || evidence.Outcome != "passed" {
					t.Fatal("exact imported child evidence refused", err)
				}
				if evidence, _, err := s.importWorker(loaded, scenario, processResult{Status: "passed", Joined: false}, &expected); err == nil || evidence.Outcome == "passed" || !s.telemetryIncomplete {
					t.Fatal("unjoined exact child supplied correctness or complete assurance")
				}
				if _, _, err := s.importWorker(loaded, scenario, processResult{Status: "passed", Joined: true}, nil); err == nil {
					t.Fatal("child import omitted its ordinal-bound step")
				}
			}
		}
	}
}

// full_only: false
func TestLiveGeneratedChildInvocationRequiresIsolatedReaderInput(t *testing.T) {
	tests := []struct {
		scenario string
		modes    []string
	}{
		{"generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2", []string{"disabled", "enabled"}},
		{"reconstruction.generated-retiring/complete_loss_generated_retiring", []string{"disabled", "enabled"}},
		{"reconstruction.generated-uncertain/complete_loss_generated_uncertain", []string{"disabled", "enabled"}},
	}
	for _, scenario := range catalog.LivePublicationNames() {
		tests = append(tests, struct {
			scenario string
			modes    []string
		}{scenario, []string{"disabled", "enabled"}})
	}
	for _, test := range tests {
		for _, recovery := range test.modes {
			t.Run(test.scenario+"/"+recovery, func(t *testing.T) {
				writer, _, _ := telemetryImportFixture(t)
				writer.Scenario = test.scenario
				private := filepath.Dir(writer.Input)
				recoveryInput := &installedarchive.RecoveryWriterInput{Domain: contract.ID{1}, OracleDirectory: filepath.Join(private, "recovery-oracle")}
				original := workerInput{
					RecoveryMode: recovery, RunID: writer.RunID, Scenarios: []string{test.scenario},
					Repetitions: 1, Prefix: "owned-prefix",
					Settings:               liveSettings{"credential_file": "authority"},
					ObserverSettings:       liveSettings{"credential_file": "observer"},
					DeniedObserverSettings: liveSettings{"credential_file": "denied-observer"},
					ReaderSettings:         liveSettings{"credential_file": "reader"},
					RecoverySettings:       liveSettings{"credential_file": "recovery"},
					DeniedReaderSettings:   liveSettings{"credential_file": "denied-reader"},
					ReplacementSettings:    map[string]liveSettings{"normal-signer-1": {"credential_file": "replacement"}},
					Participants:           map[string]string{"authority": "operator", "reader": "reader"},
					Generator:              &generatorReference{Account: "account", CredentialsFile: "generator"},
					GeneratorCleanupLedger: "generator-ledger",
				}
				if catalog.HasFixtureCapability(test.scenario, catalog.FixturePublication) {
					original.Generator, original.GeneratorCleanupLedger = nil, ""
					original.Outputs = &records.OutputFixtureInput{InventoryPath: "output-inventory", JoinedPath: "output-joined"}
				}
				if catalog.HasFixtureCapability(test.scenario, catalog.FixtureConfigurationRecovery) {
					original.ConfigurationRecovery = recoveryInput
				}
				if records.WriteJSON(writer.Input, original, 0400) != nil || records.WriteJSON(filepath.Join(writer.StateDir, "facts.json"), struct{}{}, 0400) != nil {
					t.Fatal("writer input fixture unavailable")
				}
				var err error
				writer.FreshBefore, err = issueFreshBefore(writer, "live")
				if err != nil {
					t.Fatal(err)
				}
				for index, expected := range executionFixture(test.scenario, "live").ExpandedFreshBefore() {
					t.Run(fmt.Sprint(index), func(t *testing.T) {
						isolated := original
						isolated.Generator, isolated.GeneratorCleanupLedger = nil, ""
						isolated.ConfigurationRecovery = nil
						isolated.Outputs = nil
						inputPath := filepath.Join(writer.StateDir, fmt.Sprintf("fresh-input-%d.json", index))
						if records.WriteJSON(inputPath, isolated, 0400) != nil {
							t.Fatal("reader input fixture unavailable")
						}
						output := filepath.Join(writer.OutputDir, fmt.Sprintf("fresh-before-%d", index))
						inv, err := makeInvocation(records.Invocation{Scenario: test.scenario, RunID: writer.RunID,
							Worker: writer.FreshBefore[index].Worker, Role: "fresh_before", Input: inputPath,
							StateDir: writer.StateDir, OutputDir: output, Facts: "facts.json"}, "live")
						if err != nil {
							t.Fatal(err)
						}
						inv.Nonce = writer.FreshBefore[index].Nonce
						invocationPath := filepath.Join(output, "invocation.json")
						if records.WriteJSON(invocationPath, inv, 0400) != nil {
							t.Fatal("child invocation fixture unavailable")
						}
						relative, err := filepath.Rel(private, invocationPath)
						if err != nil {
							t.Fatal(err)
						}
						child := records.ChildInvocation{Worker: inv.Worker, Invocation: relative}
						loaded, step, err := childInvocation("live", test.scenario, private, writer, child, index)
						if err != nil || !reflect.DeepEqual(loaded, inv) || step != expected.Step {
							t.Fatal("isolated reader input refused", err)
						}
						for _, change := range []struct {
							name  string
							apply func(*workerInput)
						}{
							{"generator", func(i *workerInput) { i.Generator = &generatorReference{Account: "retained-generator"} }},
							{"generator_cleanup_ledger", func(i *workerInput) { i.GeneratorCleanupLedger = "retained-ledger" }},
							{"outputs", func(i *workerInput) {
								i.Outputs = &records.OutputFixtureInput{InventoryPath: "retained-output-inventory"}
							}},
							{"configuration_recovery", func(i *workerInput) { i.ConfigurationRecovery = recoveryInput }},
							{"recovery_mode", func(i *workerInput) { i.RecoveryMode = "changed" }},
							{"settings", func(i *workerInput) { i.Settings = liveSettings{"credential_file": "changed"} }},
							{"limits", func(i *workerInput) { i.Limits = &limits{} }},
							{"scenarios", func(i *workerInput) { i.Scenarios = []string{"changed"} }},
							{"member_count", func(i *workerInput) { i.MemberCount++ }},
							{"repetitions", func(i *workerInput) { i.Repetitions++ }},
							{"run_id", func(i *workerInput) { i.RunID = "changed" }},
							{"prefix", func(i *workerInput) { i.Prefix = "changed" }},
							{"observer_settings", func(i *workerInput) { i.ObserverSettings = liveSettings{"credential_file": "changed"} }},
							{"denied_observer_settings", func(i *workerInput) { i.DeniedObserverSettings = liveSettings{"credential_file": "changed"} }},
							{"reader_settings", func(i *workerInput) { i.ReaderSettings = liveSettings{"credential_file": "changed"} }},
							{"recovery_settings", func(i *workerInput) { i.RecoverySettings = liveSettings{"credential_file": "changed"} }},
							{"denied_reader_settings", func(i *workerInput) { i.DeniedReaderSettings = liveSettings{"credential_file": "changed"} }},
							{"replacement_settings", func(i *workerInput) {
								i.ReplacementSettings = map[string]liveSettings{"normal-signer-1": {"credential_file": "changed"}}
							}},
							{"participants", func(i *workerInput) { i.Participants = map[string]string{"authority": "changed"} }},
							{"cleanup_retry", func(i *workerInput) { i.CleanupRetry = &cleanupRetryInput{} }},
							{"cleanup_grant", func(i *workerInput) { i.CleanupGrant = &cleanupGrantInput{} }},
						} {
							t.Run(change.name, func(t *testing.T) {
								changed := isolated
								change.apply(&changed)
								if records.WriteJSON(inputPath, changed, 0400) != nil {
									t.Fatal("changed reader fixture unavailable")
								}
								if _, _, err := childInvocation("live", test.scenario, private, writer, child, index); err == nil {
									t.Fatal("changed reader input admitted")
								}
							})
						}
						if records.WriteJSON(inputPath, isolated, 0400) != nil {
							t.Fatal("reader input fixture unavailable")
						}
						inv.Input = writer.Input
						if records.WriteJSON(invocationPath, inv, 0400) != nil {
							t.Fatal("writer input path fixture unavailable")
						}
						if _, _, err := childInvocation("live", test.scenario, private, writer, child, index); err == nil {
							t.Fatal("writer input path admitted for isolated child")
						}
					})
				}
			})
		}
	}
}

// full_only: false
func TestCoordinatorIssuesFreshNonceForEveryInvocation(t *testing.T) {
	writer, _, _ := telemetryImportFixture(t)
	if records.WriteJSON(filepath.Join(writer.StateDir, "facts.json"), struct{}{}, 0400) != nil {
		t.Fatal("fresh facts fixture")
	}
	seen := map[string]bool{writer.Nonce: true}
	for _, role := range []string{"writer", "fresh_before", "fresh_after", "rerun", "cleanup", "checks"} {
		for attempt := 0; attempt < 2; attempt++ {
			candidate := records.Invocation{Scenario: writer.Scenario, RunID: writer.RunID, Worker: fmt.Sprintf("%s-%d", role, attempt), Role: role, Input: writer.Input, StateDir: writer.StateDir, OutputDir: filepath.Join(writer.StateDir, fmt.Sprintf("%s-%d", role, attempt))}
			if role == "fresh_before" || role == "fresh_after" {
				candidate.Facts = "facts.json"
			}
			inv, err := makeInvocation(candidate, "live")
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Nonce) != 32 || seen[inv.Nonce] {
				t.Fatal("invocation reused a nonce")
			}
			seen[inv.Nonce] = true
			for _, child := range inv.FreshBefore {
				if len(child.Nonce) != 32 || seen[child.Nonce] {
					t.Fatal("before child reused an invocation nonce")
				}
				seen[child.Nonce] = true
			}
			loaded, err := records.LoadInvocation(filepath.Join(inv.OutputDir, "invocation.json"))
			if err != nil || !reflect.DeepEqual(inv, loaded) {
				t.Fatal("coordinator binding was not retained")
			}
		}
	}
}

// full_only: false
func TestConfigurationRecoveryFreshBeforeUsesDeclaredProcessStep(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		for _, recovery := range []string{"disabled", "enabled"} {
			for _, scenario := range []string{"reconstruction.generated-retiring/complete_loss_generated_retiring", "reconstruction.generated-uncertain/complete_loss_generated_uncertain"} {
				t.Run(provider+"/"+recovery+"/"+scenario, func(t *testing.T) {
					defer func() {
						if value := recover(); value != nil {
							t.Errorf("valid fresh-before evidence panicked: %T", value)
						}
					}()
					execution, known := catalog.ExecutionFor(scenario, "live")
					if !known || len(execution.FreshAfter) != 0 || len(execution.ExpandedFreshBefore()) != 2 {
						t.Fatal("missing process-only fresh-before regression")
					}
					participants := map[string]string{"authority": provider + "-operator"}
					for _, child := range execution.ExpandedFreshBefore() {
						before := child.Step
						wantSteps := []catalog.Step{{Name: "authentication", Role: "authority", Expected: "success"}, {Name: "transition", Role: "authority", Expected: "joined-complete-process"}}
						if !reflect.DeepEqual(workerSteps(scenario, "live", "fresh_before", nil, &before, ""), wantSteps) {
							t.Fatal("fresh-before process phases differ")
						}
						phases := []records.PhaseResult{
							{Sequence: 1, Name: "authentication", Actor: participants["authority"], Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: true},
							{Sequence: 2, Name: "transition", Actor: participants["authority"], Expected: "joined-complete-process", Actual: "joined-complete-process", Outcome: "passed", MeasurementsExpected: true},
						}
						result := records.WorkerResult{Role: "fresh_before", Actor: participants["authority"], Scenario: scenario, Outcome: "passed", Phases: phases}
						if !completeWorker(result, "live", participants, "", &before) {
							t.Fatal("complete process child refused")
						}
						for _, condition := range []string{"missing-step", "wrong-step", "wrong-role", "wrong-recovery", "wrong-actor", "missing-phase", "unexpected-after"} {
							changed := result
							step := before
							selected := &step
							switch condition {
							case "missing-step":
								selected = nil
							case "wrong-step":
								step.Name = "verification"
							case "wrong-role":
								step.Role = "observer"
							case "wrong-recovery":
								step.RecoveryMode = recovery
							case "wrong-actor":
								changed.Actor = "other"
							case "missing-phase":
								changed.Phases = phases[:1]
							case "unexpected-after":
								changed.Role, selected = "fresh_after", nil
							}
							if completeWorker(changed, "live", participants, "", selected) {
								t.Fatalf("malformed %s evidence admitted", condition)
							}
						}
					}
					if workerSteps(scenario, "live", "fresh_after", nil, nil, "") != nil {
						t.Fatal("missing fresh-after step admitted")
					}
				})
			}
		}
	}
}
