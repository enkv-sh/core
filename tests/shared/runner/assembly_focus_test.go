package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestWorkflowAssemblyResponsibilityAndFocusAdmission(t *testing.T) {
	path := savedWorkflowPath(t, "dev")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	for _, id := range []string{"assemblies-aws", "assemblies-gcp"} {
		plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: id, Test: "TestParent/child[a]+"})
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range plan.Steps {
			if step.Selected && (step.AssemblyFocus == nil || step.AssemblyPreparation == nil || step.AssemblyFocus.Provider != step.Responsibility || step.AssemblyFocus.Requested != "TestParent/child[a]+") || !step.Selected && (step.AssemblyFocus != nil || step.AssemblyPreparation != nil) {
				t.Fatal("provider focus lost its responsibility or selected scope", step)
			}
		}
	}
	for _, request := range []workflowRequest{
		{Path: path, SelectedStep: "assembly-common", Test: "TestParent"},
		{Path: path, SelectedStep: "assembly-common", Package: "core"},
		{Path: path, SelectedStep: "assemblies-aws", Package: "core", Test: "TestParent"},
		{Path: path, SelectedStep: "assemblies-gcp", Package: "core"},
		{Path: path, SelectedStep: "assemblies-aws", Test: "Example"},
		{Path: path, SelectedStep: "assemblies", Test: "TestParent"},
	} {
		if _, err := resolveWorkflow(t.Context(), root, request); err == nil {
			t.Fatal("invalid assembly focus was admitted", request)
		}
	}
	for _, step := range []workflowStep{
		{ID: "assembly", Kind: "assembly-checks"},
		{ID: "assembly", Kind: "assembly-checks", Responsibility: "unknown"},
		{ID: "runner", Kind: "runner-tests", Responsibility: "aws"},
	} {
		directory, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		invalid := filepath.Join(directory, "workflow.json")
		saveSelection(t, invalid, workflowFile{SchemaVersion: 1, Name: "controlled", Steps: []workflowStep{step}})
		if _, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: invalid}); err == nil {
			t.Fatal("invalid responsibility was admitted", step)
		}
	}
}

// full_only: false
func TestAssemblyFocusResolvesCompleteOwnedInventoryBeforeNarrowing(t *testing.T) {
	names := []string{"TestLiveRun", "TestLiveChild", "TestLiveCleanup", "TestLiveRecovery", "TestFreshProcessChild", "TestLiveInventoryFreshProcess", "TestAWSProtectedObjectConditionalCleanup", "TestInventoryRepresentativeScenarios", "TestCoreUnowned"}
	sources := map[string]string{}
	for _, name := range names[:4] {
		sources[name] = "tests/live/runner/worker_test.go"
	}
	sources["TestFreshProcessChild"] = "tests/shared/process_fixture_test.go"
	sources["TestLiveInventoryFreshProcess"] = "tests/live/runner/inventory_checks_test.go"
	sources["TestAWSProtectedObjectConditionalCleanup"] = "tests/live/providers/aws/setup_checks_test.go"
	sources["TestInventoryRepresentativeScenarios"] = "tests/live/runner/inventory_checks_test.go"
	admitted, focus, err := resolveAssemblyFocus(names, sources, componentProfileFixtureClassifications(names), "aws", "dev", false, "TestAWSProtectedObjectConditionalCleanup/child[a]+")
	if err != nil || focus == nil || focus.Owner != "TestAWSProtectedObjectConditionalCleanup" || focus.Package != componentPackage || !slices.Equal(admitted, names[4:7]) {
		t.Fatal("assembly focus changed the complete admitted controlled inventory", admitted, focus, err)
	}
	for _, request := range append(slices.Clone(names[:5]), "TestUnknown", "TestCoreUnowned", "TestInventoryRepresentativeScenarios") {
		if _, _, err := resolveAssemblyFocus(names, sources, componentProfileFixtureClassifications(names), "aws", "dev", false, request); err == nil {
			t.Fatal("excluded or independent helper focus admitted", request)
		}
	}
	if _, _, err := resolveAssemblyFocus(names, sources, componentProfileFixtureClassifications(names), "gcp", "full", true, "TestAWSProtectedObjectConditionalCleanup"); err == nil {
		t.Fatal("AWS test admitted to GCP focus")
	}
	if _, _, err := resolveAssemblyFocus(names[1:], sources, componentProfileFixtureClassifications(names[1:]), "aws", "dev", false, "TestAWSProtectedObjectConditionalCleanup"); err == nil {
		t.Fatal("focus hid an owned-root inventory gap")
	}
	operatorInventory := []string{
		"TestFreshProcessChild", "TestLiveInventoryFreshProcess",
		"TestOperatorCaptureCrashChild", "TestOperatorCaptureReadOnlyChild",
		"TestOperatorCaptureCrashBeforeReturnKeepsMutationUncertain", "TestOperatorCaptureReadOnlyCreateRefusesAfterEvidence",
	}
	operatorSources := map[string]string{}
	for _, name := range operatorInventory[2:] {
		operatorSources[name] = "tests/live/runner/operator_scenario_test.go"
	}
	operatorSources["TestFreshProcessChild"] = "tests/shared/process_fixture_test.go"
	operatorSources["TestLiveInventoryFreshProcess"] = "tests/live/runner/inventory_checks_test.go"
	for _, provider := range []string{"aws", "gcp"} {
		for _, profile := range []string{"dev", "full"} {
			admitted, err := liveAssemblyCheckNames(operatorInventory, operatorSources, componentProfileFixtureClassifications(operatorInventory), profile, provider == "gcp")
			if err != nil || !slices.Equal(admitted, operatorInventory) {
				t.Fatal("operator helper focus restrictions changed complete controlled membership", provider, profile, admitted, err)
			}
			for _, owner := range operatorInventory[4:] {
				for _, suffix := range []string{"", "/provisional-child"} {
					selected, focus, err := resolveAssemblyFocus(operatorInventory, operatorSources, componentProfileFixtureClassifications(operatorInventory), provider, profile, provider == "gcp", owner+suffix)
					if err != nil || focus == nil || focus.Owner != owner || !slices.Equal(selected, operatorInventory) {
						t.Fatal("operator owning control lost focus admission or full inventory", provider, profile, owner+suffix, err)
					}
				}
			}
			for _, helper := range operatorInventory[2:4] {
				for _, suffix := range []string{"", "/provisional-child"} {
					t.Run("helper/"+provider+"/"+profile+"/"+helper+suffix, func(t *testing.T) {
						if _, _, err := resolveAssemblyFocus(operatorInventory, operatorSources, componentProfileFixtureClassifications(operatorInventory), provider, profile, provider == "gcp", helper+suffix); err == nil {
							t.Fatal("operator child helper was admitted as an independent assembly focus")
						}
					})
				}
			}
		}
	}
}

// full_only: false
func TestFocusedAssemblyEvidenceRequiresExactNodeAndRefusesCompleteScope(t *testing.T) {
	const owner = "TestAWSProtectedObjectConditionalCleanup"
	const request = owner + "/child[a]+"
	fixture := func() checkEvidence {
		inventory := []string{"TestFreshProcessChild", "TestLiveInventoryFreshProcess", owner}
		omitted := inventory[:2]
		checks := checkEvidence{Profile: "dev", Race: true, RaceOptions: raceOptions, Outcome: "passed", TestsComplete: true,
			AssemblyFocus:       &assemblyFocus{Requested: request, Owner: owner, Provider: "aws", Package: componentPackage},
			AssemblyPreparation: &assemblyPreparation{Source: records.Source{Revision: strings.Repeat("a", 40)}, Toolchain: "go1.27.0", BinarySHA256: strings.Repeat("b", 64), OverlaySHA256: strings.Repeat("c", 64), FailureSourcesSHA256: strings.Repeat("d", 64), Inventory: inventory, NotSelected: omitted, Selection: literalTestSelection(request)},
			Inventory:           inventory, NotSelected: omitted, Selection: literalTestSelection(request),
			Tests: []componentTest{{Name: owner, Outcome: "passed"}, {Name: request, Outcome: "passed"}},
		}
		setFocusedAssemblyFixtureMetadata(&checks)
		return checks
	}
	for _, condition := range []string{"valid", "unavailable-source", "malformed-source", "ancestor-only", "sibling", "failed-parent", "skipped-child", "failed-child", "missing-preparation", "wrong-provider", "changed-selection", "missing-inventory", "missing-omitted", "missing-artifact"} {
		t.Run(condition, func(t *testing.T) {
			checks := fixture()
			switch condition {
			case "unavailable-source":
				checks.AssemblyPreparation.Source = records.Source{ObservationIncomplete: true}
			case "malformed-source":
				checks.AssemblyPreparation.Source = records.Source{ObservationIncomplete: true, Revision: "invalid"}
			case "ancestor-only":
				checks.Tests = checks.Tests[:1]
			case "sibling":
				checks.Tests[1].Name = owner + "/other"
			case "failed-parent":
				checks.Tests[0].Outcome = "failed"
			case "skipped-child":
				checks.Tests[1].Outcome = "skipped"
			case "failed-child":
				checks.Tests[1].Outcome = "failed"
			case "missing-preparation":
				checks.AssemblyPreparation = nil
			case "wrong-provider":
				checks.AssemblyFocus.Provider = "gcp"
			case "changed-selection":
				checks.Selection = "^TestOther$"
			case "missing-inventory":
				checks.Inventory = []string{owner}
			case "missing-omitted":
				checks.NotSelected = nil
			case "missing-artifact":
				checks.AssemblyPreparation.BinarySHA256 = ""
			}
			body, err := json.Marshal(checks)
			var saved checkEvidence
			if err != nil || json.Unmarshal(body, &saved) != nil || completeFocusedAssemblyEvidence(saved, "aws") != (condition == "valid" || condition == "unavailable-source") {
				t.Fatal("exact focused evidence admission differs", condition)
			}
			if completeComponentEvidence(saved, "live", "aws") {
				t.Fatal("focus established complete live preflight")
			}
			saved.AssemblyFocus = nil
			if completeComponentEvidence(saved, "live", "aws") {
				t.Fatal("removed focus marker established complete preflight")
			}
			saved.AssemblyPreparation = nil
			if completeComponentEvidence(saved, "live", "aws") {
				t.Fatal("remaining selection facts established complete preflight")
			}
		})
	}
	for _, provider := range []string{"aws", "gcp"} {
		for _, root := range []string{"TestOperatorCaptureCrashChild", "TestOperatorCaptureReadOnlyChild", "TestOperatorCaptureCrashBeforeReturnKeepsMutationUncertain", "TestOperatorCaptureReadOnlyCreateRefusesAfterEvidence"} {
			for _, suffix := range []string{"", "/child[a]+"} {
				t.Run("operator/"+provider+"/"+root+suffix, func(t *testing.T) {
					checks := fixture()
					requested := root + suffix
					checks.AssemblyFocus = &assemblyFocus{Requested: requested, Owner: root, Provider: provider, Package: componentPackage}
					checks.Inventory = []string{"TestFreshProcessChild", "TestLiveInventoryFreshProcess", root}
					checks.NotSelected = checks.Inventory[:2]
					checks.Selection = literalTestSelection(requested)
					checks.AssemblyPreparation.Inventory = checks.Inventory
					checks.AssemblyPreparation.NotSelected = checks.NotSelected
					checks.AssemblyPreparation.Selection = checks.Selection
					setFocusedAssemblyFixtureMetadata(&checks)
					checks.Tests = []componentTest{{Name: root, Outcome: "passed"}}
					if suffix != "" {
						checks.Tests = append(checks.Tests, componentTest{Name: requested, Outcome: "passed"})
					}
					owner := root == "TestOperatorCaptureCrashBeforeReturnKeepsMutationUncertain" || root == "TestOperatorCaptureReadOnlyCreateRefusesAfterEvidence"
					if completeFocusedAssemblyEvidence(checks, provider) != owner {
						t.Fatal("focused evidence did not distinguish operator child helper from its owning control", requested)
					}
				})
			}
		}
	}

}

// full_only: false
func TestAssemblyFocusPlanAndRunUseBoundBinaryAndLiteralSelection(t *testing.T) {
	root, bootstrap, build := overlayFixture(t)
	const owner = "TestComponentFocusRuntimeFixture"
	for path, body := range map[string]string{
		"tests/live/providers/aws/provider_test.go": "package core\n// full_only: false\nfunc " + owner + "() {}\n",
		"tests/live/runner/worker_test.go":          "package core\n// full_only: false\nfunc TestLiveInventoryFreshProcess() {}\n",
		"tests/shared/process_fixture_test.go":      "package core\n// full_only: false\nfunc TestFreshProcessChild() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	overlay, err := buildOverlay(root, "live", "aws", bootstrap, build)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(build, "state.test")
	inventory := []string{"TestFreshProcessChild", "TestLiveInventoryFreshProcess", owner}
	script := "#!/bin/sh\ncase \"$*\" in\n *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\nesac\nexec '" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	binaryDigest, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	overlayDigest, err := assemblyFileSHA256(overlay)
	if err != nil {
		t.Fatal(err)
	}
	value := assembly{root: root, Binary: binary, buildFlags: []string{"-overlay=" + overlay}, Closure: assemblyClosure{Suite: "live", Provider: "aws", BinarySHA256: binaryDigest, OverlaySHA256: overlayDigest}}
	bindAssemblyFailureSources(t, &value, build)
	source := records.Source{Revision: strings.Repeat("a", 40)}
	t.Run("failed-selection-retains-inventory-prefix", func(t *testing.T) {
		directory, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		var terminal bytes.Buffer
		err = checkLiveAssemblySelection(t.Context(), root, directory, &value, "dev", false, "TestUnavailablePreparationRoot", source, "go1.27.0", &terminal)
		checks := value.Closure.LocalChecks
		if err == nil || value.providerSelection != nil || checks == nil || checks.TestsComplete || len(checks.Tests) != 0 {
			t.Fatal("failed provider selection published execution or a runnable selection", err, checks)
		}
		if checks.Diagnostics == nil || checks.Diagnostics.Preparation != "failed" || len(checks.Diagnostics.Commands) != 1 {
			t.Fatal("failed provider selection lost its acquired inventory prefix", checks.Diagnostics)
		}
		for index, scope := range []string{"assembly-inventory"} {
			fact := checks.Diagnostics.Commands[index]
			if fact.Phase != "preparation" || fact.Scope != scope || fact.Process != "passed" || !fact.Started || !fact.Joined {
				t.Fatal("provider prefix no longer describes its completed preparation commands", fact)
			}
			if strings.Count(terminal.String(), "Check phase=preparation scope="+scope+" process=passed started=true joined=true ") != 1 {
				t.Fatal("provider early return omitted or repeated its actual terminal preparation facts", scope, terminal.String())
			}
		}
		terminalRows := 0
		for _, line := range strings.Split(terminal.String(), "\n") {
			if strings.HasPrefix(line, "Check phase=preparation ") && strings.Contains(line, " process=") {
				terminalRows++
			}
		}
		if terminalRows != 1 {
			t.Fatal("provider early-return terminal fact count differs from its acquired inventory prefix", terminal.String())
		}

	})
	t.Run("offline-precheck-retains-prepared-prefix", func(t *testing.T) {
		initializeWorkflowExecutionFixture(t, root)
		ctx := withExecutionParallel(t.Context(), 1)
		control := t.TempDir()
		realGo, err := exec.LookPath("go")
		if err != nil {
			t.Fatal(err)
		}
		realGo, err = filepath.EvalSymlinks(realGo)
		if err != nil {
			t.Fatal(err)
		}
		operations := filepath.Join(control, "operations")
		script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> " + shellQuote(operations) + " || exit 91\ncase \"$1\" in version) exec " + shellQuote(realGo) + " \"$@\" ;; *) printf 'unexpected provider preparation command\\n' >&2; exit 92 ;; esac\n"
		if err := os.WriteFile(filepath.Join(control, "go"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
		// A mismatched accepted race policy must retain the acquired prefix.
		prefix := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{
			{Phase: "preparation", Scope: "retained-binding-version", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"},
			{Phase: "preparation", Scope: "retained-binding-environment", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"},
		}}
		candidate := value
		candidate.Closure.LocalChecks = nil
		candidate.Closure.Race = !raceEnabled(ctx)
		candidate.providerSelection = &preparedProviderChecks{evidence: checkEvidence{Diagnostics: prefix}}
		var terminal bytes.Buffer
		record, err := runOfflineResponsibilityPrepared(nil, ctx, root, bootstrap, "dev", "aws", "", &terminal, &candidate, nil)
		if err == nil || !strings.Contains(err.Error(), "assembly race policy differs") || !toolCommandsJoined(err) || !sourceCommandsJoined(err) || record == nil || record.Outcome != "failed" || len(record.Assemblies) != 0 {
			t.Fatal("outer provider control did not refuse before the inner check", record, err, terminal.String())
		}
		observed, readErr := os.ReadFile(operations)
		if readErr != nil || string(observed) != "version\n" || strings.Contains(terminal.String(), "Check phase=preparation scope=assembly-inventory") {
			t.Fatal("outer provider control started extra preparation or a test body", string(observed), readErr, terminal.String())
		}
		if record.Diagnostics == nil || len(record.Diagnostics.Commands) != 3 {
			t.Fatal("outer provider failure lost its already acquired prepared prefix", record.Diagnostics)
		}
		for _, scope := range []string{"retained-binding-version", "retained-binding-environment"} {
			if strings.Count(terminal.String(), "Check phase=preparation scope="+scope+" process=passed started=true joined=true ") != 1 {
				t.Fatal("outer provider failure omitted or repeated its closed terminal prefix", scope, terminal.String())
			}
		}
		version := record.Diagnostics.Commands[2]
		if version.Phase != "preparation" || version.Scope != "core" || version.Process != "passed" || !version.Started || !version.Joined {
			t.Fatal("outer provider lost its actual toolchain-version command", version)
		}

		var failure *toolFailure
		if errors.As(err, &failure) {
			t.Fatal("race refusal became an invented provider command failure", failure)
		}
	})
	t.Run("diagnostic-output-failure-keeps-original-refusal", func(t *testing.T) {
		directory, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(t.TempDir(), "provider-body")
		t.Setenv("ENKV_FOCUS_FIXTURE_PATH", marker)
		original := errors.New("controlled provider progress refusal")
		outputFailure := errors.New("controlled provider diagnostic refusal")
		terminal := &providerDiagnosticFailureWriter{original: original, diagnostic: outputFailure}
		candidate := value
		candidate.Closure.LocalChecks = nil
		err = checkLiveAssemblySelection(withExecutionParallel(t.Context(), 1), root, directory, &candidate, "dev", false, owner+"/punct[a]+b.c", source, "go1.27.0", terminal)
		checks := candidate.Closure.LocalChecks
		if !errors.Is(err, original) || !errors.Is(err, outputFailure) || terminal.factAttempts != 1 || checks == nil || checks.Outcome != "process_failed" || checks.TestsComplete || len(checks.Tests) != 0 {
			t.Fatal("provider diagnostic failure lost its original cause, retried output, or invented execution", err, terminal.factAttempts, checks)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("provider output refusal started a test body", err)
		}
		if checks.Diagnostics == nil || len(checks.Diagnostics.Commands) != 2 {
			t.Fatal("provider output refusal lost inventory or converter preparation", checks.Diagnostics)
		}
		for index, scope := range []string{"assembly-inventory", "test2json"} {
			fact := checks.Diagnostics.Commands[index]
			if fact.Phase != "preparation" || fact.Scope != scope || fact.Process != "passed" || !fact.Started || !fact.Joined {
				t.Fatal("provider output refusal changed its acquired preparation fact", fact)
			}
		}

	})
	t.Run("failed-body-keeps-independent-assembly-and-later-step", func(t *testing.T) {
		t.Setenv("ENKV_FOCUS_FIXTURE_FAILURE", "1")
		t.Setenv("ENKV_FOCUS_FIXTURE_PATH", filepath.Join(t.TempDir(), "provider-body"))
		plan := assemblyGroupExecutionPlan(1)
		plan.Steps = []resolvedWorkflowStep{
			{ID: "failed", Kind: "assembly-checks", Responsibility: "aws", Selected: true},
			{ID: "peer", Kind: "assembly-checks", Responsibility: "aws", Selected: true},
			{ID: "later", Kind: "unit", Selected: true},
		}
		attempts := map[string]int{}
		var terminal bytes.Buffer
		result, workflowErr := executeWorkflow(t.Context(), assemblyGroupExecutionRoot(t), plan, &terminal, nil, nil,
			func(ctx context.Context, step resolvedWorkflowStep, out io.Writer, directory string) (workflowStepExecution, error) {
				attempts[step.ID]++
				if step.ID == "later" {
					return workflowStepExecution{}, ctx.Err()
				}
				candidate := value
				request := owner + "/punct[a]+b.c"
				if step.ID == "failed" {
					request = owner + "/failure"
				}
				checkErr := checkLiveAssemblySelection(ctx, root, directory, &candidate, "dev", false, request, source, "go1.27.0", out)
				checks := candidate.Closure.LocalChecks
				if step.ID == "failed" {
					if !containedCheckFailure(ctx, checkErr) {
						t.Error("joined assembly assertion was not contained", checkErr)
					}
					if repetitionBarrierFromContext(ctx, nil).stopped.Load() {
						t.Error("joined assembly assertion stopped the shared barrier")
					}

				}
				return workflowStepExecution{Assembly: &offlineEvidence{Outcome: checks.Outcome, Assemblies: []assemblyClosure{candidate.Closure}, Diagnostics: checks.Diagnostics}}, checkErr
			})
		if workflowErr == nil || result.Outcome != "failed" || !toolCommandsJoined(workflowErr) {
			t.Fatal("workflow lost the original failure or positive joins", workflowErr, result.Outcome)
		}
		for index, step := range result.Steps {
			want := "passed"
			if index == 0 {
				want = "failed"
			}
			if attempts[step.ID] != 1 || step.Outcome != want || step.FinishedAt == nil {
				t.Error("independent step omitted, repeated or changed", step.ID, attempts, result.Steps)
			}
		}
	})
	t.Run("failed-body-does-not-revalidate-completed-binary", func(t *testing.T) {
		t.Setenv("ENKV_FOCUS_FIXTURE_FAILURE", "1")
		t.Setenv("ENKV_FOCUS_FIXTURE_PATH", binary)
		t.Cleanup(func() {
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Error("restore bound assembly fixture", err)
			}
		})
		barrier := &repetitionBarrier{}
		ctx := context.WithValue(withExecutionParallel(t.Context(), 1), workflowTestBarrierContextKey{}, barrier)
		candidate := value
		var terminal bytes.Buffer
		err := checkLiveAssemblySelection(ctx, root, t.TempDir(), &candidate, "dev", false, owner+"/failure", source, "go1.27.0", &terminal)
		if err == nil || !containedCheckFailure(ctx, err) || barrier.stopped.Load() {
			t.Fatal("joined assertion lost its failure or triggered artifact revalidation", err, barrier.stopped.Load())
		}
	})
	t.Run("after-body-diagnostic-failure-stops-shared-barrier", func(t *testing.T) {
		directory, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(t.TempDir(), "provider-body")
		t.Setenv("ENKV_FOCUS_FIXTURE_PATH", marker)
		outputFailure := errors.New("controlled after-body diagnostic refusal")
		terminal := &providerDiagnosticFailureWriter{diagnostic: outputFailure}
		barrier := &repetitionBarrier{}
		ctx := context.WithValue(withExecutionParallel(t.Context(), 1), workflowTestBarrierContextKey{}, barrier)
		candidate := value
		candidate.Closure.LocalChecks = nil
		request := owner + "/punct[a]+b.c"
		err = checkLiveAssemblySelection(ctx, root, directory, &candidate, "dev", false, request, source, "go1.27.0", terminal)
		checks := candidate.Closure.LocalChecks
		if !errors.Is(err, outputFailure) || terminal.factAttempts != 1 || !barrier.stopped.Load() || checks == nil || checks.Outcome != "process_failed" || !checks.TestsComplete {
			t.Fatal("after-body diagnostic failure did not stop later repetitions or lost current results", err, terminal.factAttempts, barrier.stopped.Load(), checks)
		}
		body, readErr := os.ReadFile(marker)
		if readErr != nil || string(body) != "setup\nsuffix\n" {
			t.Fatal("after-body refusal did not retain real completed setup and suffix", string(body), readErr)
		}
		for _, name := range []string{owner, request} {
			if !slices.ContainsFunc(checks.Tests, func(test componentTest) bool { return test.Name == name && test.Outcome == "passed" }) {
				t.Fatal("after-body diagnostic failure discarded an actual passed terminal", name, checks.Tests)
			}
		}
		if checks.Diagnostics == nil || len(checks.Diagnostics.Commands) != 4 {
			t.Fatal("after-body refusal lost preparation, test or conversion facts", checks.Diagnostics)
		}

	})
	for _, child := range []string{"punct[a]+b.c", "repeat#01", "path/leaf", "path", "missing"} {
		t.Run(child, func(t *testing.T) {
			evidenceDirectory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "parent-work")
			t.Setenv("ENKV_FOCUS_FIXTURE_PATH", path)
			request := owner + "/" + child
			admitted, focus, preparation, err := prepareAssemblySelection(t.Context(), root, value, "dev", false, request, source, "go1.27.0", nil, nil)
			if err != nil || focus == nil || preparation == nil || !slices.Equal(admitted, inventory) || preparation.Selection != literalTestSelection(request) || preparation.BinarySHA256 != binaryDigest || preparation.OverlaySHA256 != overlayDigest {
				t.Fatal("plan lost bound artifact or admitted scope", preparation, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("planning executed a requested test")
			}
			var terminal bytes.Buffer
			err = checkLiveAssemblySelection(context.Background(), root, evidenceDirectory, &value, "dev", false, request, source, "go1.27.0", &terminal)
			valid := child != "path" && child != "missing"
			checks := value.Closure.LocalChecks
			if (err == nil) != valid || checks == nil || completeFocusedAssemblyEvidence(*checks, "aws") != valid || !slices.Equal(checks.Inventory, admitted) || checks.Selection != preparation.Selection || checks.AssemblyPreparation.BinarySHA256 != preparation.BinarySHA256 {
				t.Fatal("plan/run exact selection or completion differs", checks, err)
			}
			if valid {
				factRows := 0
				for _, line := range strings.Split(terminal.String(), "\n") {
					if strings.HasPrefix(line, "Check phase=") && strings.Contains(line, " process=") {
						factRows++
					}
				}
				if factRows != 5 || strings.Count(terminal.String(), "Check phase=preparation scope=assembly-inventory process=") != 1 || strings.Count(terminal.String(), "Check phase=preparation scope=core process=") != 0 || strings.Count(terminal.String(), "Check phase=preparation scope=test2json process=") != 1 || strings.Count(terminal.String(), "Check phase=module-preparation scope=core process=") != 0 || strings.Count(terminal.String(), "Check phase=module-preparation scope=test2json process=") != 1 || strings.Count(terminal.String(), "Check phase=test scope="+componentPackage+" process=") != 1 || strings.Count(terminal.String(), "Check phase=conversion scope="+componentPackage+" process=") != 1 {
					t.Fatal("successful provider output omitted or repeated acquired command facts", terminal.String())
				}
			}
			if !valid {
				body, err := os.ReadFile(filepath.Join(evidenceDirectory, "private", "assembly-checks.log"))
				if err != nil || len(body) == 0 {
					t.Fatal("assembly diagnostics were not retained outside disposable build files")
				}
				if _, err := os.Lstat(filepath.Join(build, "private")); !os.IsNotExist(err) {
					t.Fatal("assembly diagnostics still use the disposable build directory")
				}
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil || string(body) != "setup\nsuffix\n" {
				t.Fatal("focus omitted parent setup or suffix", string(body), readErr)
			}
		})
	}
}

// Refuse pre-dispatch progress, then one terminal fact write. Other output is
// retained so this control cannot conceal progress or retry a partial record.
type providerDiagnosticFailureWriter struct {
	bytes.Buffer
	original, diagnostic error
	factAttempts         int
}

func (writer *providerDiagnosticFailureWriter) Write(body []byte) (int, error) {
	if writer.original != nil && bytes.HasPrefix(body, []byte("Check phase=test scope=")) {
		return 0, writer.original
	}
	if bytes.HasPrefix(body, []byte("Check phase=preparation ")) && bytes.Contains(body, []byte(" process=")) {
		writer.factAttempts++
		return 0, writer.diagnostic
	}
	return writer.Buffer.Write(body)
}
