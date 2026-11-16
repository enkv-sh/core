package main

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func boolPointer(value bool) *bool { return &value }

// full_only: false
func TestCompleteScenarioSelectionDoesNotScheduleComponents(t *testing.T) {
	_, suite, environment := savedSelectionFixture(t)
	saveSelection(t, suite, suiteFixture("regression", catalog.RegressionNames()))
	request, err := parseRunRequest([]string{"run", "--suite", suite, "--environment", environment})
	if err != nil {
		t.Fatal(err)
	}
	for _, preparation := range request.Resolved.Preparation {
		if strings.Contains(preparation, "component") {
			t.Fatal("scenario selection still schedules component tests", preparation)
		}
	}
}

// full_only: false
func TestWorkflowSelectsComponentsWithoutScenarios(t *testing.T) {
	root, _, _ := savedSelectionFixture(t)
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, map[string]any{
		"schema_version": 1, "name": "explicit", "profile": "dev",
		"steps": []map[string]any{
			{"id": "components", "kind": "component-tests", "profile": "dev"},
			{"id": "scenarios", "kind": "run", "suites": []string{"missing.json"}, "environment": "missing.json", "recovery_mode": "both"},
		},
	})
	plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: "components"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 2 || !plan.Steps[0].Selected || plan.Steps[1].Selected || plan.Steps[0].Run != nil {
		t.Fatal("component-only selection includes a scenario run", plan)
	}
}

// full_only: false
func TestComponentStepRequiresExplicitProfileAndRejectsRace(t *testing.T) {
	for _, condition := range []string{"missing-profile", "unknown-profile", "retired-platform-profile", "per-step-race", "plain", "scenario-field"} {
		t.Run(condition, func(t *testing.T) {
			root, _, _ := savedSelectionFixture(t)
			step := workflowStep{ID: "components", Kind: "component-tests", Profile: "dev"}
			switch condition {
			case "missing-profile":
				step.Profile = ""
			case "unknown-profile":
				step.Profile = "minimal"
			case "retired-platform-profile":
				step.Profile = "linux-native"
			case "scenario-field":
				step.Suites = []string{"unused.json"}
			}
			path := filepath.Join(root, "workflow.json")
			saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "invalid", Steps: []workflowStep{step}})
			if condition == "per-step-race" || condition == "plain" {
				saveSelection(t, path, map[string]any{"schema_version": 1, "name": "invalid", "steps": []map[string]any{{"id": step.ID, "kind": step.Kind, "profile": step.Profile, "race": condition == "per-step-race"}}})
			}
			if _, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path}); err == nil {
				t.Fatal("incomplete component settings accepted")
			}
		})
	}
}

// full_only: false
func TestScenarioOnlyCompletionDoesNotClaimFullQualification(t *testing.T) {
	root, record := completeRunFixture(t, "memory")
	record.Correctness.ComponentRun = nil
	s := runState{root: root, record: record}
	s.finish()
	if s.record.Outcome != "passed" || !s.record.ScenarioCoverage || s.record.FullCoverage {
		t.Fatal("scenario-only completion changed scenario success or claimed full qualification")
	}
	path := savedWorkflowPath(t, "dev")
	plan, err := resolveWorkflow(context.Background(), filepath.Dir(filepath.Dir(filepath.Dir(path))), workflowRequest{Path: path, SelectedStep: "scenarios"})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Selected != (step.ID == "scenarios") || step.request.components != nil {
			t.Fatal("scenario-only selection included components")
		}
	}
}

// full_only: false
func TestDailyWorkflowRetainsCatalogAndSeparatesExecutionModes(t *testing.T) {
	path := savedWorkflowPath(t, "dev")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	ctx := withExecutionCapacity(t.Context(), defaultExecutionPolicy())
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalWorkflow(plan, "dev"); err != nil {
		t.Fatal(err)
	}
	if validateCheckWorkflow(plan) == nil {
		t.Fatal("daily workflow satisfied complete qualification")
	}
	full, err := resolveWorkflow(ctx, root, workflowRequest{Path: savedWorkflowPath(t, "check")})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCheckWorkflow(full); err != nil {
		t.Fatal(err)
	}
	canonical, err := resolveWorkflow(ctx, root, workflowRequest{Path: savedWorkflowPath(t, "canonical"), SelectedStep: "components"})
	if err != nil {
		t.Fatal(err)
	}
	canonicalComponents := 0
	for _, step := range canonical.Steps {
		if step.Kind != "component-tests" {
			continue
		}
		canonicalComponents++
		if step.Profile != "full" || step.Race != nil || canonical.Race || canonical.Execution.Resolved.Parallel != 4 {
			t.Fatal("canonical component profile, race, or execution capacity differs")
		}
	}
	for _, capacity := range []executionCapacity{{Parallel: 0, MemoryLimitMiB: 24576}, {Parallel: 3, MemoryLimitMiB: 0}} {
		original := plan.Execution.Resolved
		plan.Execution.Resolved = capacity
		if validateLocalWorkflow(plan, "dev") == nil {
			t.Fatal("daily verification accepted invalid execution capacity")
		}
		plan.Execution.Resolved = original
	}
	if canonicalComponents != 1 {
		t.Fatal("canonical workflow lost its component step")
	}
	if len(plan.Steps) != len(full.Steps) {
		t.Fatal("daily workflow dropped a verification activity")
	}
	for index, step := range plan.Steps {
		if step.Kind != full.Steps[index].Kind || !step.Selected {
			t.Fatal("daily verification activities differ")
		}
		if step.Kind == "component-tests" {
			if step.Profile != "dev" || step.Race != nil || plan.Race || full.Race || full.Steps[index].Profile != "full" || plan.Execution.Resolved.Parallel != 4 || full.Execution.Resolved.Parallel != 4 {
				t.Fatal("component profile or race contract differs")
			}
			original := plan.Steps[index]
			plan.Steps[index].Profile = "full"
			if validateLocalWorkflow(plan, "dev") == nil {
				t.Fatal("daily verification accepted changed component settings")
			}
			plan.Steps[index] = original
		}
		if step.Run == nil {
			continue
		}
		if !reflect.DeepEqual(step.Run.Schedule, full.Steps[index].Run.Schedule) || step.Run.Race != plan.Race || step.Run.Race != full.Steps[index].Run.Race || step.request.Profile != "dev" {
			t.Fatal("daily catalog or race/component contract differs")
		}
		for _, change := range []func(*resolvedRequest){
			func(r *resolvedRequest) { r.Profile = "full" },
			func(r *resolvedRequest) { r.Race = !plan.Race },
			func(r *resolvedRequest) { r.Schedule.Selected = r.Schedule.Selected[1:] },
		} {
			original := *step.Run
			change(step.Run)
			if validateLocalWorkflow(plan, "dev") == nil {
				t.Fatal("daily verification accepted a changed contract")
			}
			*step.Run = original
		}
	}
}

// full_only: false
func TestVerificationProfileRejectsUnknownAndLiveDailyModes(t *testing.T) {
	for _, profile := range []string{"unknown", "DEV", "plain", "full ", "none"} {
		if _, err := resolveVerificationProfile(profile); err == nil {
			t.Fatal("unknown verification profile accepted", profile)
		}
	}
	request := runRequest{Suite: "live", Resolved: &resolvedRequest{}}
	if setVerificationProfile(&request, "dev") == nil {
		t.Fatal("daily workflow admitted live provider effects")
	}
}

// full_only: false
func TestFullCoverageRejectsDailyOrPlainEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*runRecord)
	}{
		{"daily-record", func(r *runRecord) { r.Profile = "dev" }},
		{"daily-request", func(r *runRecord) { r.Resolved.Profile = "dev" }},
		{"missing-component-step", func(r *runRecord) { r.Correctness.ComponentRun = nil }},
		{"changed-component-source", func(r *runRecord) { r.Correctness.ComponentRun.Source.Revision = strings.Repeat("d", 40) }},
		{"changed-component-diff", func(r *runRecord) {
			digest := strings.Repeat("c", 64)
			r.Correctness.ComponentRun.Source.Dirty = true
			r.Correctness.ComponentRun.Source.DirtyDiffSHA256 = &digest
		}},
		{"changed-component-toolchain", func(r *runRecord) { r.Correctness.ComponentRun.Toolchain = "different" }},
		{"failed-component-step", func(r *runRecord) { r.Correctness.ComponentRun.Outcome = "failed" }},
		{"component-step-failure", func(r *runRecord) {
			r.Correctness.ComponentRun.Failure = &records.Failure{Class: "component_step_failed", Stage: "checks"}
		}},
		{"unfinished-components", func(r *runRecord) { r.Correctness.ComponentRun.FinishedAt = nil }},
		{"components-after-scenarios", func(r *runRecord) {
			finished := r.StartedAt.Add(time.Second)
			r.Correctness.ComponentRun.FinishedAt = &finished
		}},
		{"missing-component-build", func(r *runRecord) { r.Correctness.ComponentRun.BuildClosure = nil }},
		{"plain-component-build", func(r *runRecord) { r.Correctness.ComponentRun.BuildClosure.Race = false }},
		{"plain-request", func(r *runRecord) { r.Resolved.Race = false }},
		{"plain-binary", func(r *runRecord) { r.BuildClosure.Race = false }},
		{"daily-component-evidence", func(r *runRecord) { r.Correctness.ComponentRun.Checks.Profile = "dev" }},
		{"plain-component-evidence", func(r *runRecord) { r.Correctness.ComponentRun.Checks.Race = false }},
		{"omitted-capacity", func(r *runRecord) { r.Correctness.ComponentRun.Checks.NotSelected = []string{maximumCapacityComponent} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, record := completeRunFixture(t, "memory")
			if !fullCoverage(record) {
				t.Fatal("complete fixture is not valid")
			}
			test.change(&record)
			if fullCoverage(record) {
				t.Fatal("daily or plain evidence established complete qualification")
			}
		})
	}
}

// full_only: false
func TestAssemblySelectionsRetainProviderProofAndRunNeutralInventoryOnce(t *testing.T) {
	names := []string{"TestCore", "TestLiveAssembly", "TestLiveInventoryFreshProcess", "TestFreshProcessChild", "TestGCPWiring", "TestAWSWiring", "TestInventoryFailureCannotStartWrite", "TestGenesisHEADUsesBudgetAndInventory", "TestInventoryRepresentativeScenarios"}
	sources := map[string]string{
		"TestLiveAssembly":                      "tests/live/shared/assembly_test.go",
		"TestLiveInventoryFreshProcess":         "tests/live/runner/inventory_checks_test.go",
		"TestFreshProcessChild":                 "tests/shared/process_fixture_test.go",
		"TestGCPWiring":                         "tests/live/providers/gcp/wiring_test.go",
		"TestAWSWiring":                         "tests/live/providers/aws/wiring_test.go",
		"TestInventoryFailureCannotStartWrite":  "tests/live/runner/inventory_checks_test.go",
		"TestGenesisHEADUsesBudgetAndInventory": "tests/live/runner/inventory_checks_test.go",
		"TestInventoryRepresentativeScenarios":  "tests/live/runner/inventory_checks_test.go",
	}
	for _, profile := range []string{"dev", "full"} {
		for _, neutral := range []bool{true, false} {
			selected, err := liveAssemblyCheckNames(names, sources, componentProfileFixtureClassifications(names), profile, neutral)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"TestLiveAssembly", "TestLiveInventoryFreshProcess", "TestFreshProcessChild", "TestGCPWiring", "TestAWSWiring"} {
				if !slices.Contains(selected, name) {
					t.Fatal("provider proof disappeared", profile, neutral, name)
				}
			}
			if slices.Contains(selected, "TestCore") || slices.Contains(selected, "TestInventoryFailureCannotStartWrite") != neutral || slices.Contains(selected, "TestGenesisHEADUsesBudgetAndInventory") != neutral || slices.Contains(selected, "TestInventoryRepresentativeScenarios") != (neutral && profile == "full") {
				t.Fatal("neutral inventory selection differs", profile, neutral, selected)
			}
		}
	}
	if _, err := liveAssemblyCheckNames([]string{"TestFreshProcessChild"}, sources, componentProfileFixtureClassifications([]string{"TestFreshProcessChild"}), "dev", false); err == nil {
		t.Fatal("unproved helper skip accepted")
	}
}

// full_only: false
func TestLivePreflightSelectsProviderChecksWithoutSharedInventory(t *testing.T) {
	names := []string{
		"TestInventoryRepresentativeScenarios", "TestInventoryFailureCannotStartWrite", "TestGenesisHEADUsesBudgetAndInventory",
		"TestLiveAssemblyCredentialRoutesBindExplicitParticipants", "TestLiveInventoryFreshProcess", "TestFreshProcessChild",
		"TestLiveProtocolInputAndRoleBinding", "TestLiveFreshAccessRefusalNeedsExactProviderEvidence",
		"TestRunBudgetStopsBeforeConcurrentSends", "TestGCPSetupConditionalCreateAndDelete", "TestAWSLiveConditionalSetupAndCleanup",
	}
	sources := map[string]string{}
	for _, name := range names {
		sources[name] = "tests/live/runner/protocol_checks_test.go"
	}
	for _, name := range names[:3] {
		sources[name] = "tests/live/runner/inventory_checks_test.go"
	}
	sources["TestLiveInventoryFreshProcess"] = "tests/live/runner/inventory_checks_test.go"
	sources["TestFreshProcessChild"] = "tests/shared/process_fixture_test.go"
	selected, err := liveAssemblyCheckNames(names, sources, componentProfileFixtureClassifications(names), "full", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names[3:] {
		if !slices.Contains(selected, name) {
			t.Fatal("provider check missing from live preflight", name)
		}
	}
	for _, name := range names[:3] {
		if slices.Contains(selected, name) {
			t.Fatal("shared inventory replayed by live preflight", name)
		}
	}
}

// full_only: false
func TestLiveAssemblySelectsOrdinaryOwnedTestsByDefault(t *testing.T) {
	names := []string{
		"TestLiveInventoryFreshProcess", "TestFreshProcessChild",
		"TestLiveGeneratorCleanupCredentialRequiresOwnedPrivateFile",
		"TestLiveGeneratorCleanupRequiresPositiveWriterJoin",
		"TestLiveGeneratorFixtureDeleteRequiresExactAcknowledgement",
		"TestRecoveryGoalIsDurableBeforeMutation",
		"TestGeneratedFreshChildPreservesReaderInput",
		"TestUnprefixedLiveOnlyCheck",
	}
	sources := map[string]string{}
	for _, name := range names {
		sources[name] = "tests/live/runner/protocol_checks_test.go"
	}
	sources["TestLiveInventoryFreshProcess"] = "tests/live/runner/inventory_checks_test.go"
	sources["TestFreshProcessChild"] = "tests/shared/process_fixture_test.go"
	selected, err := liveAssemblyCheckNames(names, sources, componentProfileFixtureClassifications(names), "dev", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if !slices.Contains(selected, name) {
			t.Fatal("ordinary live-only test omitted", name)
		}
	}
}
