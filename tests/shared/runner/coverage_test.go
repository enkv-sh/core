package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestSavedComponentRowsWithoutElapsedUseConservativeTerminalBound(t *testing.T) {
	_, value := completeRunFixture(t, "memory")
	checks := value.Correctness.ComponentRun.Checks
	checks.Inventory = []string{"TestA", maximumCapacityComponent}
	checks.Tests = []componentTest{{Name: "TestA", Outcome: "passed"}, {Name: maximumCapacityComponent, Outcome: "passed"}}
	setComponentFixtureMetadata(t, checks, "memory")
	body, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.ReplaceAll(body, []byte(`,"elapsed_seconds":0`), nil)
	if bytes.Contains(body, []byte(`"elapsed_seconds"`)) || !bytes.Contains(body, []byte(`{"name":"TestA","outcome":"passed"}`)) {
		t.Fatal("saved fixture did not contain the shortest accepted row")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "checks.json")
	if err := os.WriteFile(path, append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	var retained checkEvidence
	if err := records.ReadJSON(path, &retained); err != nil {
		t.Fatal(err)
	}
	value.Correctness.ComponentRun.Checks = &retained
	if retained.Tests[0].ElapsedSeconds != 0 || !fullCoverage(value) {
		t.Fatal("semantically accepted omitted elapsed field was refused")
	}
	if maximumComponentTests != records.MaximumJSONBytes/len(`{"name":"TestA","outcome":"passed"},`) {
		t.Fatal("terminal count bound excludes the shortest accepted saved row")
	}
}

// full_only: false
func TestFocusedComponentsNeverQualifyCompleteConsumers(t *testing.T) {
	for _, provider := range []string{"memory", "gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			_, value := completeRunFixture(t, provider)
			checks := value.BuildClosure.LocalChecks
			if provider == "memory" {
				checks = value.Correctness.ComponentRun.Checks
			}
			if !fullCoverage(value) {
				t.Fatal("historical full control did not qualify")
			}
			checks.Focus = &componentFocus{Tests: singleTestRequest(checks.Tests[0].Name)}
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var retained runRecord
			if err := json.Unmarshal(body, &retained); err != nil {
				t.Fatal(err)
			}
			if fullCoverage(retained) || selectedLiveCoverage(retained) {
				t.Fatal("focused component record qualified scenario coverage")
			}
			if provider == "memory" && retained.Correctness.ComponentRun.passedFor(retained.Source, retained.Toolchain) {
				t.Fatal("focused component record qualified preparation reuse")
			}
		})
	}
	checks := checkEvidence{TestsComplete: true, Inventory: []string{"TestOnly"}, Tests: []componentTest{{Name: "TestOnly", Outcome: "passed"}}, Selection: "^(TestOnly)$"}
	setComponentFixtureInventory(t, &checks, "aws")
	if !completeComponentEvidence(checks, "live", "aws") {
		t.Fatal("one-owner full control failed")
	}
	checks.Focus = &componentFocus{Tests: singleTestRequest("TestOnly")}
	if completeComponentEvidence(checks, "live", "aws") {
		t.Fatal("one-owner focus qualified full proof")
	}
}

// full_only: false
func TestFullScenarioCoverageKeepsExactControlledAssemblyOwnership(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*checkEvidence)
		valid  bool
	}{
		{"unowned-and-coordinator-omissions", func(*checkEvidence) {}, true},
		{"omit-admitted-root", func(checks *checkEvidence) {
			checks.NotSelected = append(checks.NotSelected, checks.Inventory[0])
			checks.Inventory = checks.Inventory[1:]
			checks.Selection, _ = componentSelection(checks.Inventory)
			checks.Tests = checks.Tests[1:]
		}, false},
		{"missing-ownership", func(checks *checkEvidence) { checks.AssemblySources = nil }, false},
		{"wrong-provider-ownership", func(checks *checkEvidence) {
			checks.AssemblySources["TestControlled"] = "tests/live/providers/aws/fixture_test.go"
		}, false},
		{"malformed-ownership", func(checks *checkEvidence) {
			checks.AssemblySources["TestControlled"] = "tests/live/providers/gcp/../aws/fixture_test.go"
		}, false},
		{"missing-classification", func(checks *checkEvidence) { checks.Classifications = nil }, false},
		{"missing-classification-value", func(checks *checkEvidence) { checks.Classifications[0].FullOnly = nil }, false},
		{"missing-compiled-root", func(checks *checkEvidence) { checks.CompiledInventory = checks.CompiledInventory[1:] }, false},
		{"compiled-inventory-over-bound", func(checks *checkEvidence) {
			for len(checks.CompiledInventory) <= maximumComponentInventory {
				checks.CompiledInventory = append(checks.CompiledInventory, fmt.Sprintf("TestUnowned%04d", len(checks.CompiledInventory)))
			}
			checks.Classifications = componentFixtureClassifications(checks.CompiledInventory)
			checks.NotSelected = slices.DeleteFunc(slices.Clone(checks.CompiledInventory), func(name string) bool { return slices.Contains(checks.Inventory, name) })
		}, false},
		{"changed-ownership-omissions", func(checks *checkEvidence) { checks.NotSelected = []string{"TestControlled"} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, value := completeRunFixture(t, "gcp")
			checks := value.BuildClosure.LocalChecks
			if len(checks.NotSelected) != 2 || checks.NotSelected[0] != "TestCoreUnowned" || checks.NotSelected[1] != "TestLiveRun" {
				t.Fatal("full live fixture lost its explicit compiled ownership omissions")
			}
			if !fullCoverage(value) {
				t.Fatal("full admitted live scope was refused before damage")
			}
			test.change(checks)
			if fullCoverage(value) != test.valid || selectedLiveCoverage(value) != test.valid {
				t.Fatal("full scenario coverage did not validate its exact admitted assembly scope")
			}
		})
	}
	t.Run("hermetic-full-omission", func(t *testing.T) {
		_, value := completeRunFixture(t, "memory")
		if !fullCoverage(value) {
			t.Fatal("complete hermetic fixture was refused")
		}
		value.Correctness.ComponentRun.Checks.NotSelected = []string{maximumCapacityComponent}
		if fullCoverage(value) {
			t.Fatal("hermetic full omission acquired complete coverage")
		}
	})
}

// full_only: false
func TestRetainedComponentSubtestsExceedInventoryCountAcrossSuites(t *testing.T) {
	for _, provider := range []string{"memory", "gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			_, original := completeRunFixture(t, provider)
			checks := original.BuildClosure.LocalChecks
			if provider == "memory" {
				checks = original.Correctness.ComponentRun.Checks
			}
			parent := checks.Tests[0].Name
			for i := 0; i < 4097; i++ {
				checks.Tests = append(checks.Tests, componentTest{Name: fmt.Sprintf("%s/case%d", parent, i), Outcome: "passed"})
			}
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "run.json")
			if err := records.WriteJSON(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			var retained runRecord
			if err := records.ReadJSON(path, &retained); err != nil || !fullCoverage(retained) {
				t.Fatal("complete saved subtest evidence was refused", err)
			}
		})
	}
}

// full_only: false
func TestRetainedComponentEvidenceRequiresInventoryAgreement(t *testing.T) {
	for _, provider := range []string{"memory", "gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			_, original := completeRunFixture(t, provider)
			for _, test := range []struct {
				name   string
				change func(*checkEvidence)
				valid  bool
			}{
				{"complete", func(*checkEvidence) {}, true},
				{"missing_top_level", func(checks *checkEvidence) {
					checks.Inventory = append(checks.Inventory, "TestRequiredOrdinary")
					setComponentFixtureMetadata(t, checks, provider)
					if provider != "memory" {
						checks.Selection, _ = componentSelection(checks.Inventory)
					}
				}, false},
				{"extra_result", func(checks *checkEvidence) {
					checks.Tests = append(checks.Tests, componentTest{Name: "TestUnexpected", Outcome: "passed"})
				}, false},
				{"empty_results", func(checks *checkEvidence) { checks.Tests = nil }, false},
				{"duplicate_top_level", func(checks *checkEvidence) {
					checks.Tests = append(checks.Tests, checks.Tests[0])
				}, false},
				{"invalid_helper_proof", func(checks *checkEvidence) {
					checks.Tests = helperComponentEvidence(provider, "TestFreshProcessChild")
					checks.Tests = append(checks.Tests[:2], checks.Tests[3:]...)
					checks.Inventory = componentFixtureInventory(checks.Tests)
					setComponentFixtureMetadata(t, checks, provider)
					if provider != "memory" {
						checks.Selection, _ = componentSelection(checks.Inventory)
					}
				}, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					body, err := json.Marshal(original)
					if err != nil {
						t.Fatal(err)
					}
					var value runRecord
					if err := json.Unmarshal(body, &value); err != nil {
						t.Fatal(err)
					}
					checks := value.BuildClosure.LocalChecks
					if value.Suite == "hermetic" {
						checks = value.Correctness.ComponentRun.Checks
					}
					test.change(checks)
					body, err = json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					var retained runRecord
					if err := json.Unmarshal(body, &retained); err != nil {
						t.Fatal(err)
					}
					if fullCoverage(retained) != test.valid {
						t.Fatal("retained component coverage or rendered claim differs from inventory agreement")
					}
				})
			}
			if provider == "memory" {
				t.Run("missing_required_subtest", func(t *testing.T) {
					original.Correctness.ComponentRun.Checks.Tests = helperComponentEvidence(provider, "TestWriterTerminationChild")
					checks := original.Correctness.ComponentRun.Checks
					checks.Inventory = componentFixtureInventory(checks.Tests)
					setComponentFixtureMetadata(t, checks, "memory")
					if !fullCoverage(original) {
						t.Fatal("complete writer termination barriers were refused")
					}
					checks.Tests = append(checks.Tests[:4], checks.Tests[5:]...)
					if !componentEvidenceMatchesInventory(checks.Inventory, checks.Tests) {
						t.Fatal("subtest omission also damaged top-level inventory agreement")
					}
					body, err := json.Marshal(original)
					if err != nil {
						t.Fatal(err)
					}
					var retained runRecord
					if err := json.Unmarshal(body, &retained); err != nil {
						t.Fatal(err)
					}
					if fullCoverage(retained) {
						t.Fatal("missing writer termination barrier qualified")
					}
				})
			}
		})
	}
}

// full_only: false
func TestFullCoverageRejectsChangedRacePolicyRecords(t *testing.T) {
	for _, test := range []struct {
		name, provider string
		change         func(*runRecord)
	}{
		{"live_assembly_missing", "gcp", func(r *runRecord) { r.BuildClosure.RaceOptions = "" }},
		{"live_assembly_changed", "gcp", func(r *runRecord) { r.BuildClosure.RaceOptions = "exitcode=0 halt_on_error=1" }},
		{"live_exit_sleep_changed", "gcp", func(r *runRecord) { r.BuildClosure.RaceExitSleepMillis = 0 }},
		{"live_checks_missing", "gcp", func(r *runRecord) { r.BuildClosure.LocalChecks.RaceOptions = "" }},
		{"live_worker_changed", "gcp", func(r *runRecord) { r.Scenarios[0].Writer.RaceOptions = "exitcode=0" }},
		{"hermetic_assembly_missing", "memory", func(r *runRecord) { r.Correctness.ComponentRun.BuildClosure.RaceOptions = "" }},
		{"hermetic_checks_changed", "memory", func(r *runRecord) { r.Correctness.ComponentRun.Checks.RaceOptions = "exitcode=0" }},
		{"hermetic_fresh_worker_missing", "memory", func(r *runRecord) { r.Scenarios[0].PostExit[0].RaceOptions = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, record := completeRunFixture(t, test.provider)
			if !fullCoverage(record) {
				t.Fatal("accepted fixture was not qualified")
			}
			test.change(&record)
			body, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var retained runRecord
			if err := json.Unmarshal(body, &retained); err != nil || fullCoverage(retained) {
				t.Fatal("changed retained race policy qualified full coverage", err)
			}
		})
	}
}

func executionFixture(scenario, mode string) catalog.Execution {
	execution, known := catalog.ExecutionFor(scenario, mode)
	if !known {
		panic("invalid scenario execution fixture")
	}
	return execution
}

func passedPhases(scenario, mode, role string, participants map[string]string, cleanup *records.Cleanup) []records.PhaseResult {
	return passedWorkerPhases(scenario, mode, role, participants, cleanup, nil)
}

func passedWorkerPhases(scenario, mode, role string, participants map[string]string, cleanup *records.Cleanup, before *catalog.Step) []records.PhaseResult {
	steps := workerSteps(scenario, mode, role, cleanup, before, "")
	execution, known := recordedExecution(scenario, mode)
	if !known {
		panic("invalid test execution fixture")
	}
	phases := passedStepPhases(steps, participants)
	position := 0
	for index, step := range steps {
		expected := true
		switch {
		case step.Name == "authentication" || step.Name == "resource_check":
		case role == "cleanup":
			expected = step.Name != "cleanup" || cleanup != nil && cleanup.BudgetReserved != nil && *cleanup.BudgetReserved != (records.BudgetReservation{})
		case mode == "live" && (role == "fresh_before" || role == "fresh_after") && step.Name == "verification":
			expected = false
		case role == "rerun":
			expected = true
		default:
			var valid bool
			expected, valid = execution.MeasurementFor(role, position, step)
			if !valid {
				panic("invalid test phase fixture")
			}
			position++
		}
		phases[index].MeasurementsExpected = expected
	}
	return phases
}

func passedStepPhases(steps []catalog.Step, participants map[string]string) []records.PhaseResult {
	var phases []records.PhaseResult
	for index, step := range steps {
		phases = append(phases, records.PhaseResult{RecoveryMode: step.RecoveryMode, Sequence: uint64(index + 1), Name: step.Name, Actor: participants[step.Role], Expected: step.Expected, Actual: step.Expected, Outcome: "passed"})
	}
	return phases
}

func setScenarioWorkerEvidence(result *scenarioResult, mode string, participants map[string]string) {
	result.FirstFailure, result.Rerun = nil, nil
	execution, known := catalog.ExecutionFor(result.Scenario, mode)
	if !known {
		panic("invalid scenario execution fixture")
	}
	if execution.Family == catalog.FamilyConfigurationRecovery && mode == "hermetic" {
		result.Writer, result.CleanupWorker = nil, nil
		result.Children, result.PostExit = nil, nil
		return
	}
	worker := func(role string, index int) workerEvidence {
		var before *catalog.Step
		participant := participants["authority"]
		if role == "fresh_before" || role == "fresh_after" {
			participant = participants[execution.FreshAfter[0].Role]
		}
		if role == "fresh_before" {
			children := execution.ExpandedFreshBefore()
			before = &children[index].Step
			participant = participants[before.Role]
		}
		recovery := ""
		if role == "fresh_before" || role == "fresh_after" {
			recovery = expectedFreshMode(result.Scenario, mode, role, index, "")
		}
		phases := passedWorkerPhases(result.Scenario, mode, role, participants, &result.Cleanup, before)
		if recovery != "" {
			for i := range phases {
				phases[i].RecoveryMode = recovery
			}
		}
		var assertions *records.AssertionEvidence
		if execution.Family == catalog.FamilyConfigurationRecovery {
			assertions = &records.AssertionEvidence{Marker: "no_failure_marker", Checkpoint: "no_checkpoint", Completed: records.CompletedCheckpoint{Code: "none"}}
		}
		return workerEvidence{Assertions: assertions, RaceOptions: raceOptions, RecoveryMode: recovery, Worker: fmt.Sprintf("%04d-%s-%d", result.Sequence, role, index), Role: role, Actor: participant, Outcome: "passed", Process: "passed", Joined: true, Phases: phases}
	}
	writer := worker("writer", 0)
	result.Writer = &writer
	result.Children = nil
	for index := range len(execution.ExpandedFreshBefore()) {
		result.Children = append(result.Children, worker("fresh_before", index))
	}
	result.PostExit = nil
	for index := range freshAfterCount(result.Scenario, mode, "") {
		result.PostExit = append(result.PostExit, worker("fresh_after", index))
	}
	result.CleanupWorker = nil
	if mode == "live" {
		cleanup := worker("cleanup", 0)
		result.CleanupWorker = &cleanup
		if result.Scenario == sameDomainRecoveryScenario {
			failure := records.Failure{Class: "store_transport_exhausted", Stage: "transition"}
			result.FirstFailure = &failure
			result.Writer.Failure = &failure
			result.Writer.StoreFailure = &records.StoreFailure{StoreReason: "transport", Outcome: "evidence-unavailable", Reason: "write-uncertain"}
			result.Writer.Outcome, result.Writer.Process = "failed", "process_failed"
			for len(result.Writer.Phases) > 0 && result.Writer.Phases[len(result.Writer.Phases)-1].Name != "transition" {
				result.Writer.Phases = result.Writer.Phases[:len(result.Writer.Phases)-1]
			}
			last := &result.Writer.Phases[len(result.Writer.Phases)-1]
			last.Actual, last.Outcome = "failed", "failed"
			result.Children = nil
			rerun := worker("rerun", 0)
			result.Rerun = &rerun
		}
	}
}

func coverageFixture(t *testing.T) (string, runRecord) {
	return coverageFixtureRecovery(t, "disabled")
}

func coverageFixtureRecovery(t *testing.T, recovery string) (string, runRecord) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: catalog.RegressionNamesForRecovery(recovery), Repetitions: 1, RecoveryMode: recovery})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	zero := int64(0)
	cleanup := records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &zero, UnknownEffects: &zero}
	record := runRecord{Profile: "full", CoverageScope: "live_scenarios", SchemaVersion: records.SchemaVersion, RunID: strings.Repeat("a", 32), Suite: "live", Provider: "gcp", Outcome: "passed", StartedAt: now, FinishedAt: &now, Toolchain: "go test toolchain", Source: records.Source{Revision: strings.Repeat("b", 40)}, Schedule: schedule, FullCoverage: true, Correctness: correctnessEvidence{Passed: true, EvidenceComplete: true}, Cleanup: cleanup, BuildClosure: &assemblyClosure{Race: true, RaceOptions: raceOptions, RaceExitSleepMillis: 1000, Suite: "live", Provider: "gcp", BinarySHA256: strings.Repeat("c", 64), OverlaySHA256: strings.Repeat("d", 64), LocalChecks: &checkEvidence{Profile: "full", Race: true, RaceOptions: raceOptions, Outcome: "passed"}}}
	record.Resolved = &resolvedRequest{Profile: "full", Race: true, Mode: "live", RecoveryMode: recovery, Provider: "gcp", Schedule: schedule, Participants: []string{"operator", "reader", "denied-reader"}, RoleBindings: map[string]string{"authority": "operator", "reader": "reader", "denied-reader": "denied-reader"}}
	for _, name := range schedule.Selected {
		definition, _ := catalog.DefinitionFor(name)
		for _, role := range definition.RolesForRecovery(recovery) {
			if record.Resolved.RoleBindings[role] == "" {
				record.Resolved.RoleBindings[role] = role
				record.Resolved.Participants = append(record.Resolved.Participants, role)
			}
		}
	}
	record.BuildClosure.LocalChecks.TestsComplete = true
	record.BuildClosure.LocalChecks.Inventory = []string{"TestControlled"}
	record.BuildClosure.LocalChecks.Selection, err = componentSelection(record.BuildClosure.LocalChecks.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	record.BuildClosure.LocalChecks.Tests = []componentTest{{Name: "TestControlled", Outcome: "passed"}}
	setComponentFixtureInventory(t, record.BuildClosure.LocalChecks, "gcp")
	setRecoveryAssemblyFixture(&record)
	for _, entry := range schedule.Entries {
		shape, err := recordedFixture(entry.Scenario, entry.Members)
		if err != nil {
			t.Fatal(err)
		}
		result := scenarioResult{Entry: entry, Fixture: shape, CorrectnessPassed: true, Outcome: "passed", Cleanup: cleanup}
		setScenarioWorkerEvidence(&result, "live", record.Resolved.RoleBindings)
		setScenarioReconstructionFixture(&result, record)
		record.Scenarios = append(record.Scenarios, result)
	}
	return root, record
}

// full_only: false
func TestCurrentKeyReplacementCoverageKeepsRecoveryScope(t *testing.T) {
	_, value := coverageFixture(t)
	if !fullCoverage(value) {
		t.Fatal("complete disabled-mode cumulative regression refused")
	}
	value.Schedule.RecoveryMode = "both"
	if fullCoverage(value) {
		t.Fatal("disabled-only evidence claimed both recovery modes")
	}
}

// full_only: false
func TestRecoveredScenarioNeedsFirstFailureRerunColdCheckAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*scenarioResult)
	}{
		{"missing_first_failure", func(r *scenarioResult) { r.FirstFailure = nil }},
		{"missing_store_failure", func(r *scenarioResult) { r.Writer.StoreFailure = nil }},
		{"unjoined_first_writer", func(r *scenarioResult) { r.Writer.Joined = false }},
		{"missing_rerun", func(r *scenarioResult) { r.Rerun = nil }},
		{"failed_rerun", func(r *scenarioResult) { r.Rerun.Outcome = "failed" }},
		{"missing_cold_check", func(r *scenarioResult) { r.PostExit = nil }},
		{"unknown_cleanup", func(r *scenarioResult) { one := int64(1); r.Cleanup.UnknownEffects = &one }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, value := coverageFixture(t)
			if !fullCoverage(value) {
				t.Fatal("complete recovered fixture refused")
			}
			found := false
			for i := range value.Scenarios {
				if value.Scenarios[i].Scenario == sameDomainRecoveryScenario {
					test.change(&value.Scenarios[i])
					found = true
					break
				}
			}
			if !found || fullCoverage(value) {
				t.Fatal("incomplete recovery became full coverage")
			}
		})
	}
}

// full_only: false
func TestFullCoverageRequiresCompleteRunEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*runRecord)
	}{
		{"complete", func(*runRecord) {}},
		{"wrong_provider", func(r *runRecord) { r.Provider = "aws" }},
		{"failed", func(r *runRecord) { r.Outcome = "failed" }},
		{"focused", func(r *runRecord) { r.FullCoverage = false }},
		{"local_scope", func(r *runRecord) { r.CoverageScope = "local_qualification" }},
		{"changed_binary_identity", func(r *runRecord) { r.BuildClosure.BinarySHA256 = "" }},
		{"changed_overlay_identity", func(r *runRecord) { r.BuildClosure.OverlaySHA256 = "" }},
		{"different_source", func(r *runRecord) {
			r.Source.Revision = strings.Repeat("c", 40)
			for i := range r.BuildClosure.ReconstructionArtifacts {
				r.BuildClosure.ReconstructionArtifacts[i].Source = r.Source
			}
			for i := range r.Scenarios {
				for j := range r.Scenarios[i].Reconstruction {
					r.Scenarios[i].Reconstruction[j].Source = r.Source
				}
			}
		}},
		{"recovery_source_mismatch", func(r *runRecord) { r.Source.Revision = strings.Repeat("c", 40) }},
		{"dirty_without_hash", func(r *runRecord) { r.Source.Dirty = true }},
		{"missing_scenario", func(r *runRecord) { r.Scenarios = r.Scenarios[1:] }},
		{"wrong_order", func(r *runRecord) { r.Scenarios[0], r.Scenarios[1] = r.Scenarios[1], r.Scenarios[0] }},
		{"missing_smoke", func(r *runRecord) { r.Schedule.Entries[0].Smoke = false }},
		{"missing_after", func(r *runRecord) { r.Scenarios[0].PostExit = nil }},
		{"scenario_incorrect", func(r *runRecord) { r.Scenarios[0].CorrectnessPassed = false }},
		{"wrong_writer_role", func(r *runRecord) { r.Scenarios[0].Writer.Role = "cleanup" }},
		{"wrong_cleanup_role", func(r *runRecord) { r.Scenarios[0].CleanupWorker.Role = "writer" }},
		{"wrong_after_role", func(r *runRecord) { r.Scenarios[0].PostExit[0].Role = "writer" }},
		{"phase_failed", func(r *runRecord) { r.Scenarios[0].Writer.Phases[0].Outcome = "failed" }},
		{"phase_name", func(r *runRecord) { r.Scenarios[0].Writer.Phases[0].Name = "not_a_phase" }},
		{"phase_sequence", func(r *runRecord) { r.Scenarios[0].Writer.Phases[0].Sequence = 2 }},
		{"phase_history_too_long", func(r *runRecord) {
			r.Scenarios[0].Writer.Phases = make([]records.PhaseResult, 257)
			for i := range r.Scenarios[0].Writer.Phases {
				r.Scenarios[0].Writer.Phases[i] = records.PhaseResult{Sequence: uint64(i + 1), Name: "verification", Outcome: "passed"}
			}
		}},
		{"worker_name", func(r *runRecord) { r.Scenarios[0].Writer.Worker = "bad/worker" }},
		{"worker_name_too_long", func(r *runRecord) { r.Scenarios[0].Writer.Worker = strings.Repeat("w", 97) }},
		{"not_joined", func(r *runRecord) { r.Scenarios[0].Writer.Joined = false }},
		{"duplicate_worker", func(r *runRecord) { r.Scenarios[1].Writer.Worker = r.Scenarios[0].Writer.Worker }},
		{"cleanup_failure", func(r *runRecord) {
			r.Cleanup.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
		}},
		{"scenario_cleanup_failure", func(r *runRecord) {
			r.Scenarios[0].Cleanup.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
		}},
		{"cleanup_unknown", func(r *runRecord) { r.Scenarios[0].Cleanup.UnknownEffects = nil }},
		{"cleanup_remaining", func(r *runRecord) { one := int64(1); r.Scenarios[0].Cleanup.RemainingOwnedObjects = &one }},
		{"wrong_closure_suite", func(r *runRecord) { r.BuildClosure.Suite = "hermetic" }},
		{"missing_checks", func(r *runRecord) { r.BuildClosure.LocalChecks = nil }},
		{"missing_check_selection", func(r *runRecord) { r.BuildClosure.LocalChecks.Selection = "" }},
		{"telemetry_incomplete", func(r *runRecord) { r.Telemetry = records.Telemetry{Enabled: true, Status: "incomplete"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, value := coverageFixture(t)
			test.change(&value)
			valid := test.name == "complete" || test.name == "telemetry_incomplete" || test.name == "different_source"
			if fullCoverage(value) != valid {
				t.Fatal("full coverage differs from this run's evidence")
			}
		})
	}
}

// full_only: false
func TestRunEvidenceResolvesNestedRecordAndRejectsDuplicateID(t *testing.T) {
	root, value := coverageFixture(t)
	directory, err := createRunDirectory(root, "live", value.RunID, value.StartedAt)
	if err != nil || records.WriteJSON(filepath.Join(directory, "run.json"), value, 0600) != nil {
		t.Fatal("nested record fixture")
	}
	body, err := os.ReadFile(filepath.Join(directory, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	path, err := runPath(root, "live", "runs", value.RunID)
	if err != nil || path != directory {
		t.Fatal("nested record not resolved")
	}
	actual, err := readRecordBytes(filepath.Join(path, "run.json"))
	if err != nil || string(actual) != string(body) {
		t.Fatal("retained record bytes changed")
	}
	duplicate := filepath.Join(root, "tests/live/runs", value.RunID)
	if os.Mkdir(duplicate, 0700) != nil || records.WriteJSON(filepath.Join(duplicate, "run.json"), value, 0600) != nil {
		t.Fatal("ambiguous record fixture")
	}
	if _, err := runPath(root, "live", "runs", value.RunID); err == nil {
		t.Fatal("accepted ambiguous raw identity")
	}
}

// full_only: false
func TestFullCoverageRejectsSkippedChecksAndIncompleteHelperInvocations(t *testing.T) {
	for _, condition := range []string{"complete", "missing-parent", "wrong-parent", "failed-parent", "skipped-parent", "ordinary-subtest", "missing-worker", "unjoined-worker", "wrong-assembly", "all-skipped"} {
		t.Run(condition, func(t *testing.T) {
			_, value := coverageFixture(t)
			checks := value.BuildClosure.LocalChecks
			checks.Tests = helperComponentEvidence("gcp", "TestFreshProcessChild")
			setComponentFixtureInventory(t, checks, "gcp")
			changeSkippedEvidence(&value, checks, condition)
			if fullCoverage(value) != (condition == "complete") {
				t.Fatal("full coverage ignored skipped or incomplete checks")
			}
		})
	}
}

func setRecoveryAssemblyFixture(parent *runRecord) {
	parent.BuildClosure.ReconstructionArtifacts = nil
	for _, provider := range []string{"aws", "gcp"} {
		parent.BuildClosure.ReconstructionArtifacts = append(parent.BuildClosure.ReconstructionArtifacts, reconstructionArtifactClosure{Provider: provider, Source: parent.Source, BinarySHA256: strings.Repeat("e", 64), RaceOptions: raceOptions, VetPassed: true, NoCoreOverlay: true, ResolvedModules: []moduleIdentity{{Path: "enkv.sh/crypto", Version: "v0.0.0"}}, CompiledImports: []string{"enkv.sh/crypto"}})
	}
}

// These fixture facts follow the case's fixed success/refusal and resource
// inputs. They do not call either recovery evidence validator.
func setScenarioReconstructionFixture(result *scenarioResult, parent runRecord) {
	row, known := catalog.ConfigurationRecovery(result.Scenario)
	if !known {
		return
	}
	result.Reconstruction = nil
	cells := catalog.ConfigurationRecoveryCells(result.Scenario, parent.Resolved.RecoveryMode)
	if parent.Suite == "live" {
		cells = []catalog.RecoveryProcessCell{{Provider: parent.Provider, Recovery: parent.Resolved.RecoveryMode}}
	}
	for _, cell := range cells {
		terminal, driver := strings.Repeat("f", 64), strings.Repeat("e", 64)
		opened := 5
		if parent.Suite == "live" {
			opened = 3
		}
		switch row.Condition {
		case "zero-secret-genesis":
			opened = 0
		case "generated-active":
			if parent.Suite == "hermetic" {
				opened = 3
			}
		case "mixed-generated", "generated-repeated-later":
			opened = 5
		case "generated-retiring", "generated-uncertain":
			opened = 1
		}
		outcome := installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}
		refused := false
		switch row.Condition {
		case "prior-domain-pin", "copied-location", "wrong-domain-pin":
			outcome = installedarchive.RecoveryResult{Outcome: 5, Reason: 2}
			refused = true
		case "wrong-anchor", "recovery-proof-two-normal":
			outcome = installedarchive.RecoveryResult{Outcome: 5, Reason: 4}
			refused = true
		case "recovery-only-inadequate", "recovery-proof-normal-only":
			outcome = installedarchive.RecoveryResult{Outcome: 6, Reason: 12}
			refused = true
		case "required-public-denied":
			outcome = installedarchive.RecoveryResult{Outcome: 6, Reason: 12}
			refused = true
		case "required-authority-denied", "recovery-key-only", "later-secret-denied", "wrong-kek-pin":
			outcome = installedarchive.RecoveryResult{Outcome: 6, Reason: 17}
			refused = true
		case "wrong-owner":
			outcome = installedarchive.RecoveryResult{Outcome: 6, Reason: 8}
			refused = true
		case "selected-object-disappears":
			outcome = installedarchive.RecoveryResult{Outcome: 6, Reason: 7}
			refused = true
		case "wrong-locator":
			outcome = installedarchive.RecoveryResult{Outcome: 7, Reason: 7}
			refused = true
		}
		normal, recovery, decrypts := uint64(1), uint64(0), uint64(opened)
		if refused {
			opened = 0
			normal, decrypts = 0, 0
			switch row.Condition {
			case "required-public-denied", "wrong-kek-pin", "selected-object-disappears":
				normal = 1
			case "required-authority-denied", "recovery-key-only":
				normal, decrypts = 1, 1
			case "later-secret-denied":
				normal, decrypts = 1, 5
			}
		} else {
			switch row.Condition {
			case "authority-kek-by-recovery", "recovery-kek-by-recovery", "recovery-signer-by-recovery", "recovery-combined-by-recovery", "recovery-proof-recovery-only", "recovery-proof-both":
				normal, recovery = 0, 1
			case "adequate-anchor-fallback":
				recovery = 1
			}
		}
		counts := installedarchive.RecoveryCounts{Reads: 12, NormalLookups: normal, RecoveryLookups: recovery, PublicLookups: normal + recovery, RecoveryMetadata: recovery, AuthorityDecrypts: decrypts}
		checks := installedarchive.RecoveryReport{ChildStarted: true, ChildJoined: true, ChildTerminalsSHA256: terminal, Result: outcome, Refused: refused, Opened: opened, RemoteEffectsZero: true, OracleEpochSeparate: true, Counts: counts}
		if row.Condition == "selected-object-disappears" {
			checks.ExternalMutations = 1
		}
		phases := []string{"resource-owner", "setup", "writer", "reconstruction-parent", "restricted-child"}
		if parent.Suite == "live" {
			phases = phases[3:]
			checks.Attempted = counts
			checks.SnapshotReadsBefore, checks.SnapshotReadsAfter = 11, 11
			checks.ReservedRequests, checks.ReservedBytes = 50, 1000
			switch row.Condition {
			case "adequate-anchor-fallback", "required-public-denied":
				checks.Injected = installedarchive.RecoveryCounts{PublicLookups: 1, NormalLookups: 1}
				checks.Counts.NormalLookups--
				checks.Counts.PublicLookups--
			case "required-authority-denied", "recovery-key-only", "later-secret-denied":
				checks.Injected = installedarchive.RecoveryCounts{AuthorityDecrypts: 1}
				checks.Counts.AuthorityDecrypts--
			}
			if !refused {
				checks.OracleCounts.AuthorityDecrypts = uint64(opened)
			}
			if row.Condition == "selected-object-disappears" {
				checks.MutationJoined = true
				checks.MutationCounts.Delete = 1
			}
		}
		value := configurationRecoveryEvidence{Provider: cell.Provider, RecoveryMode: cell.Recovery, Source: parent.Source, RaceOptions: raceOptions, LossBarrier: true, Checks: checks}
		for _, phase := range phases {
			binary := driver
			if phase == "setup" || phase == "writer" {
				binary = parent.BuildClosure.BinarySHA256
			}
			value.Phases = append(value.Phases, records.ProcessCompletion{Phase: phase, Helper: recoveryPhaseHelper(cell.Provider, phase), BinarySHA256: binary, TerminalsSHA256: terminal, Started: true, Joined: true, Outcome: "passed"})
		}
		result.Reconstruction = append(result.Reconstruction, value)
	}
}

func completeRunFixture(t *testing.T, provider string) (string, runRecord) {
	t.Helper()
	recoveryMode := "disabled"
	if provider == "memory" {
		recoveryMode = "both"
	}
	root, value := coverageFixtureRecovery(t, recoveryMode)
	value.Provider, value.Target = provider, provider
	value.Toolchain = "go version go1.27.0 darwin/arm64"
	value.BuildClosure.Provider = provider
	if provider == "memory" {
		value.Suite = "hermetic"
		value.CoverageScope = "hermetic_scenarios"
		value.Cleanup = noCleanup()
		value.BuildClosure.LocalChecks = nil
		finished := value.StartedAt
		value.Correctness.ComponentRun = &componentRunRecord{
			SchemaVersion: records.SchemaVersion, RunID: strings.Repeat("c", 32), Source: value.Source, Toolchain: value.Toolchain,
			StartedAt: finished.Add(-time.Second), FinishedAt: &finished, Outcome: "passed",
			BuildClosure: &assemblyClosure{Suite: "hermetic", Provider: "memory", Race: true, RaceOptions: raceOptions, RaceExitSleepMillis: 1000},
			Checks:       &checkEvidence{Profile: "full", Race: true, RaceOptions: raceOptions, Outcome: "passed", Selection: "all component and worker control tests"},
		}
	}
	value.BuildClosure.Suite = value.Suite
	value.Resolved.Mode, value.Resolved.Provider = value.Suite, value.Provider
	value.Resolved.RecoveryMode = "disabled"
	if value.Suite == "hermetic" {
		value.Resolved.RecoveryMode = "both"
	}
	if provider == "memory" {
		value.Correctness.ComponentRun.Checks.TestsComplete = true
		value.Correctness.ComponentRun.Checks.Inventory = []string{"TestControlled", maximumCapacityComponent}
		value.Correctness.ComponentRun.Checks.Tests = []componentTest{{Name: "TestControlled", Outcome: "passed"}, {Name: maximumCapacityComponent, Outcome: "passed"}}
		setComponentFixtureMetadata(t, value.Correctness.ComponentRun.Checks, "memory")
	}
	if provider != "memory" {
		setComponentFixtureMetadata(t, value.BuildClosure.LocalChecks, provider)
	}
	setRecoveryAssemblyFixture(&value)
	for index := range value.Scenarios {
		result := &value.Scenarios[index]
		if provider == "memory" {
			result.Cleanup = noCleanup()
		}
		setScenarioWorkerEvidence(result, value.Suite, value.Resolved.RoleBindings)
		setScenarioReconstructionFixture(result, value)
	}
	return root, value
}

func changeSkippedEvidence(value *runRecord, checks *checkEvidence, condition string) {
	switch condition {
	case "missing-parent":
		checks.Tests = checks.Tests[:2]
	case "wrong-parent":
		checks.Tests[2].Name += "Extra"
	case "failed-parent":
		checks.Tests[2].Outcome = "failed"
	case "skipped-parent":
		checks.Tests[2].Outcome = "skipped"
	case "ordinary-subtest":
		checks.Tests = append(checks.Tests, componentTest{Name: "TestControlled/required", Outcome: "skipped"})
	case "missing-worker":
		value.Scenarios[0].PostExit = nil
	case "unjoined-worker":
		value.Scenarios[0].PostExit[0].Joined = false
	case "wrong-assembly":
		if value.Suite == "hermetic" {
			checks.Tests[2].Name = "TestInventoryRepresentativeScenarios"
		} else {
			checks.Tests = append(checks.Tests, componentTest{Name: "TestHermeticRun", Outcome: "skipped"})
		}
	case "all-skipped":
		for i := range checks.Tests {
			checks.Tests[i].Outcome = "skipped"
		}
	}
}

// full_only: false
func TestFullCoverageRequiresCompleteComponentAndResolvedEvidence(t *testing.T) {
	tests := []struct {
		name     string
		accepted bool
		change   func(*runRecord, *checkEvidence)
	}{
		{"complete", true, func(*runRecord, *checkEvidence) {}},
		{"skipped_component", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests[1].Outcome = "skipped" }},
		{"missing_component_results", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests = nil }},
		{"empty_component_results", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests = []componentTest{} }},
		{"incomplete_component_evidence", false, func(_ *runRecord, checks *checkEvidence) { checks.TestsComplete = false }},
		{"duplicate_component", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests = append(checks.Tests, checks.Tests[0]) }},
		{"failed_component", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests[0].Outcome = "failed" }},
		{"incomplete_component", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests[0].Outcome = "incomplete" }},
		{"invalid_component_name", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests[0].Name = "private synthetic-secret" }},
		{"invalid_component_outcome", false, func(_ *runRecord, checks *checkEvidence) { checks.Tests[0].Outcome = "synthetic-secret" }},
		{"component_result_limit", true, func(value *runRecord, checks *checkEvidence) {
			checks.Tests = make([]componentTest, 4096)
			for i := range checks.Tests {
				checks.Tests[i] = componentTest{Name: fmt.Sprintf("TestC%04d", i), Outcome: "passed"}
			}
			if checks.Profile == "full" && slices.Contains(checks.Inventory, maximumCapacityComponent) {
				checks.Tests[len(checks.Tests)-1].Name = maximumCapacityComponent
			}
			if value.Provider != "memory" {
				// Keep exactly 4096 terminals while reserving compiled inventory
				// room for the two unowned roots. Required fresh-process controls
				// replace ordinary roots, and two terminals belong to their parent.
				checks.Tests[0] = componentTest{Name: "TestFreshProcessChild", Outcome: "skipped"}
				checks.Tests[1] = componentTest{Name: "TestLiveInventoryFreshProcess", Outcome: "passed"}
				checks.Tests[2] = componentTest{Name: "TestLiveInventoryFreshProcess/first", Outcome: "passed"}
				checks.Tests[3] = componentTest{Name: "TestLiveInventoryFreshProcess/second", Outcome: "passed"}
			}
			setComponentFixtureInventory(t, checks, value.Provider)
			if len(checks.Tests) != 4096 || len(checks.Inventory) > maximumComponentInventory || len(checks.CompiledInventory) > maximumComponentInventory {
				t.Fatal("result-limit fixture changed its terminal count or exceeded compiled inventory")
			}
		}},
		{"too_many_component_results", false, func(_ *runRecord, checks *checkEvidence) {
			checks.Tests = make([]componentTest, 4097)
			for i := range checks.Tests {
				checks.Tests[i] = componentTest{Name: fmt.Sprintf("TestComponent%04d", i), Outcome: "passed"}
			}
		}},

		{"wrong_mode", false, func(r *runRecord, _ *checkEvidence) {
			r.Resolved.Mode = "hermetic"
			if r.Suite == "hermetic" {
				r.Resolved.Mode = "live"
			}
		}},
		{"wrong_provider", false, func(r *runRecord, _ *checkEvidence) {
			r.Resolved.Provider = "gcp"
			if r.Provider == "gcp" {
				r.Resolved.Provider = "aws"
			}
		}},
		{"wrong_schedule_selection", false, func(r *runRecord, _ *checkEvidence) {
			r.Resolved.Schedule.Selected[0] = "state.historical-bytes-get-new-identities/members_32_three_generations"
		}},
		{"wrong_schedule_members", false, func(r *runRecord, _ *checkEvidence) { r.Resolved.Schedule.MemberCounts = []int{32} }},
		{"wrong_schedule_repetitions", false, func(r *runRecord, _ *checkEvidence) { r.Resolved.Schedule.Repetitions++ }},
		{"wrong_schedule_entry", false, func(r *runRecord, _ *checkEvidence) { r.Resolved.Schedule.Entries[0].Members++ }},
		{"wrong_schedule_coverage", false, func(r *runRecord, _ *checkEvidence) { r.Resolved.Schedule.FullCoverage = false }},
	}
	for _, provider := range []string{"memory", "gcp", "aws"} {
		for _, test := range tests {
			t.Run(provider+"/"+test.name, func(t *testing.T) {
				_, value := completeRunFixture(t, provider)
				checks := value.BuildClosure.LocalChecks
				if value.Suite == "hermetic" {
					checks = value.Correctness.ComponentRun.Checks
				}
				checks.TestsComplete = true
				checks.Tests = []componentTest{{Name: "TestReader", Outcome: "passed"}, {Name: "TestReader/complete-state", Outcome: "passed"}}
				if value.Suite == "hermetic" {
					checks.Tests = append(checks.Tests, componentTest{Name: maximumCapacityComponent, Outcome: "passed"})
				}
				setComponentFixtureInventory(t, checks, provider)
				value.Resolved.Schedule.Selected = slices.Clone(value.Schedule.Selected)
				value.Resolved.Schedule.MemberCounts = slices.Clone(value.Schedule.MemberCounts)
				value.Resolved.Schedule.Entries = slices.Clone(value.Schedule.Entries)
				if !fullCoverage(value) {
					t.Fatal("complete component and resolved evidence fixture rejected")
				}
				test.change(&value, checks)
				if got := fullCoverage(value); got != test.accepted {
					t.Fatalf("full coverage: got %t, want %t", got, test.accepted)
				}
			})
		}
	}
}

// full_only: false
func TestFullCoverageRequiresConsistentEvidenceForEachSuite(t *testing.T) {
	tests := []struct {
		name     string
		accepted bool
		change   func(*runRecord)
	}{
		{"complete_disabled", true, func(*runRecord) {}},
		{"complete_incomplete_telemetry", true, func(r *runRecord) { r.Telemetry = records.Telemetry{Enabled: true, Status: "incomplete"} }},
		{"writer_role", false, func(r *runRecord) { r.Scenarios[0].Writer.Role = "cleanup" }},
		{"before_role", false, func(r *runRecord) { r.Scenarios[0].Children[0].Role = "writer" }},
		{"after_role", false, func(r *runRecord) { r.Scenarios[0].PostExit[0].Role = "fresh_before" }},
		{"fixture", false, func(r *runRecord) { r.Scenarios[0].Fixture.RawValueBytes++ }},
		{"run_failure", false, func(r *runRecord) { r.Failure = &records.Failure{Class: "scenario_failed", Stage: "execution"} }},
		{"scenario_failure", false, func(r *runRecord) { r.Scenarios[0].Failure = &records.Failure{Class: "writer_failed", Stage: "writer"} }},
		{"worker_failure", false, func(r *runRecord) {
			r.Scenarios[0].Writer.Failure = &records.Failure{Class: "worker_failed", Stage: "writer"}
		}},
		{"cleanup_failure", false, func(r *runRecord) {
			r.Cleanup.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
		}},
		{"scenario_cleanup_failure", false, func(r *runRecord) {
			r.Scenarios[0].Cleanup.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
		}},
		{"cleanup_unknown", false, func(r *runRecord) { r.Cleanup.Outcome = "unresolved" }},
		{"scenario_cleanup_unknown", false, func(r *runRecord) { r.Scenarios[0].Cleanup.Outcome = "unresolved" }},
		{"duplicate_worker", false, func(r *runRecord) { r.Scenarios[1].Writer.Worker = r.Scenarios[0].Writer.Worker }},
		{"missing_closure", false, func(r *runRecord) { r.BuildClosure = nil }},
		{"wrong_closure_suite", false, func(r *runRecord) { r.BuildClosure.Suite = "other" }},
		{"wrong_closure_provider", false, func(r *runRecord) { r.BuildClosure.Provider = "other" }},
		{"missing_checks", false, func(r *runRecord) {
			if r.Correctness.ComponentRun != nil {
				r.Correctness.ComponentRun.Checks = nil
			}
			r.BuildClosure.LocalChecks = nil
		}},
		{"failed_checks", false, func(r *runRecord) {
			if r.Suite == "hermetic" {
				r.Correctness.ComponentRun.Checks.Outcome = "failed"
			} else {
				r.BuildClosure.LocalChecks.Outcome = "failed"
			}
		}},
		{"missing_check_selection", false, func(r *runRecord) {
			if r.Suite == "hermetic" {
				r.Correctness.ComponentRun.Checks.Selection = ""
			} else {
				r.BuildClosure.LocalChecks.Selection = ""
			}
		}},
		{"invalid_source", false, func(r *runRecord) { r.Source.Revision = "unavailable" }},
		{"missing_finish", false, func(r *runRecord) { r.FinishedAt = nil }},
		{"missing_smoke", false, func(r *runRecord) { r.Schedule.Entries[0].Smoke = false }},
		{"missing_scenario", false, func(r *runRecord) { r.Scenarios = r.Scenarios[1:] }},
		{"failed_phase", false, func(r *runRecord) { r.Scenarios[0].Writer.Phases[0].Outcome = "failed" }},
		{"invalid_phase", false, func(r *runRecord) { r.Scenarios[0].Writer.Phases[0].Name = "not_a_phase" }},
		{"phase_sequence", false, func(r *runRecord) { r.Scenarios[0].Writer.Phases[0].Sequence = 2 }},
		{"phase_history_too_long", false, func(r *runRecord) {
			r.Scenarios[0].Writer.Phases = make([]records.PhaseResult, 257)
			for i := range r.Scenarios[0].Writer.Phases {
				r.Scenarios[0].Writer.Phases[i] = records.PhaseResult{Sequence: uint64(i + 1), Name: "verification", Outcome: "passed"}
			}
		}},
		{"invalid_worker", false, func(r *runRecord) { r.Scenarios[0].Writer.Worker = "bad/worker" }},
		{"worker_name_too_long", false, func(r *runRecord) { r.Scenarios[0].Writer.Worker = strings.Repeat("w", 97) }},
		{"unjoined_worker", false, func(r *runRecord) { r.Scenarios[0].Writer.Joined = false }},
	}
	for _, provider := range []string{"memory", "gcp", "aws"} {
		for _, test := range tests {
			t.Run(provider+"/"+test.name, func(t *testing.T) {
				_, value := completeRunFixture(t, provider)
				test.change(&value)
				if fullCoverage(value) != test.accepted {
					t.Fatal("coverage did not match retained evidence")
				}
			})
		}
	}
}

// full_only: false
func TestFullCoverageBindsCleanupToApplicableSuite(t *testing.T) {
	for _, provider := range []string{"memory", "gcp", "aws"} {
		_, value := completeRunFixture(t, provider)
		if provider == "memory" {
			extra := *value.Scenarios[0].Writer
			extra.Role, extra.Worker = "cleanup", "unexpected-cleanup"
			value.Scenarios[0].CleanupWorker = &extra
		} else {
			value.Scenarios[0].CleanupWorker.Role = "writer"
		}
		if fullCoverage(value) {
			t.Fatal("wrong cleanup role accepted")
		}
	}
}
