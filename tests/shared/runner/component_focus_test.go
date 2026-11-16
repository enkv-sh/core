package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestWorkflowComponentFocusArguments(t *testing.T) {
	for _, command := range []string{"plan", "run"} {
		t.Run(command, func(t *testing.T) {
			for _, args := range [][]string{
				{command, "--workflow", "check.json", "--step", "components", "--test", "TestParent/child"},
				{command, "--workflow=check.json", "--step=components", "--test=TestParent"},
			} {
				if _, err := workflowArguments(args); err != nil {
					t.Errorf("valid exact component request refused: %v", err)
				}
			}
			for _, flags := range [][]string{
				{"--test", "TestParent"},
				{"--step=", "--test=TestParent"},
				{"--step=components", "--test="},
				{"--step=components", "--test=TestParent", "--test=TestOther"},
				{"--step=components", "--step=components", "--test=TestParent"},
				{"--step=components", "--test=TestParent", "--resume=0123456789abcdef0123456789abcdef"},
				{"--step=components", "--test=TestParent//child"},
				{"--step=components", "--test=TestParent/"},
			} {
				args := append([]string{command, "--workflow=check.json"}, flags...)
				if _, err := workflowArguments(args); err == nil {
					t.Errorf("invalid exact component request accepted: %v", flags)
				}
			}
		})
	}
}

// full_only: false
func TestFocusedWriterParentRequiresExistingBarriers(t *testing.T) {
	const parent = "TestWriterTerminationPreservesCompleteSelection"
	pass := func(name string) componentTest { return componentTest{Name: name, Outcome: "passed"} }
	rows := []componentTest{pass(parent)}
	for _, barrier := range []string{"before-first-create", "after-first-page-readback", "after-root-readback", "after-cas-acceptance", "after-authenticated-observation"} {
		rows = append(rows, pass(parent+"/"+barrier))
	}
	if !completeFocusedComponentEvidence(focusedEvidenceFixture(t, parent, rows...)) {
		t.Fatal("complete writer-parent proof refused")
	}
	if completeFocusedComponentEvidence(focusedEvidenceFixture(t, parent, rows[0])) {
		t.Error("writer parent qualified without its barrier children")
	}
	for i := 1; i < len(rows); i++ {
		t.Run(strings.TrimPrefix(rows[i].Name, parent+"/"), func(t *testing.T) {
			missing := append(slices.Clone(rows[:i]), rows[i+1:]...)
			if completeFocusedComponentEvidence(focusedEvidenceFixture(t, parent, missing...)) {
				t.Error("writer parent qualified with a missing barrier")
			}
			if !completeFocusedComponentEvidence(focusedEvidenceFixture(t, rows[i].Name, rows[0], rows[i])) {
				t.Error("single barrier required unrelated sibling execution")
			}
		})
	}
}

func focusedEvidenceFixture(t *testing.T, request string, tests ...componentTest) checkEvidence {
	t.Helper()
	owner, _, _ := strings.Cut(request, "/")
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent)
	if !slices.Contains(inventory, owner) {
		inventory = append(inventory, owner)
	}
	if owner == "TestHermeticWorkerEntrypointsNeedExplicitInvocation" {
		inventory = append(inventory, "TestThreeGenerationHistoryAndStaleCandidate")
	}
	_, excluded, groups, focus, err := resolveComponentGroups(inventory, componentFixtureClassifications(inventory), "full", singleTestRequest(request), 4, componentEstimates)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := componentFocusSelection(request)
	if err != nil {
		t.Fatal(err)
	}
	seconds := 0.01
	diagnostics := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{
		{Phase: "preparation", Scope: "inventory", Process: "passed", Started: true, Joined: true, WallSeconds: &seconds, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"},
		{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true, WallSeconds: &seconds, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"},
		{Phase: "test", Scope: groups[0].Name, Process: "passed", Started: true, Joined: true, WallSeconds: &seconds, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed", RequestedNode: "passed"},
		{Phase: "conversion", Scope: groups[0].Name, Process: "passed", Started: true, Joined: true, WallSeconds: &seconds, Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"},
	}}
	return checkEvidence{Profile: "full", Inventory: inventory, Classifications: componentFixtureClassifications(inventory), NotSelected: excluded, Focus: focus,
		Selection: selection, TestsComplete: true, Tests: tests, Outcome: "passed", Race: true, RaceOptions: raceOptions,
		EventTimeSource: "post_join_test2json", Diagnostics: diagnostics, Parallelism: 4,
		Groups: []componentGroupEvidence{componentGroupResult(groups[0], "passed", 0)}}
}

// full_only: false
func TestFocusedComponentEvidenceRequiresExactNodeAndRequiredChildren(t *testing.T) {
	pass := func(name string) componentTest { return componentTest{Name: name, Outcome: "passed"} }
	t.Run("preparation-scopes", func(t *testing.T) {
		for _, module := range moduleSources {
			for _, scope := range []string{module.Selector, module.Module} {
				checks := focusedEvidenceFixture(t, "TestParent", pass("TestParent"))
				checks.Diagnostics.Commands[1].Scope = scope
				if !completeFocusedComponentEvidence(checks) {
					t.Error("registered preparation module refused", scope)
				}
			}
		}
		for _, scope := range []string{"", "plugins/unregistered", "/core", "../core", "plugins/../core", "core\n"} {
			checks := focusedEvidenceFixture(t, "TestParent", pass("TestParent"))
			checks.Diagnostics.Commands[1].Scope = scope
			if completeFocusedComponentEvidence(checks) {
				t.Error("invalid preparation scope accepted", scope)
			}
		}
	})
	const negative = "TestHermeticWorkerEntrypointsNeedExplicitInvocation"
	const pruning = "TestCompletedIntentSourceStorePrune"
	for _, spec := range []struct {
		name, request string
		tests         []componentTest
		valid         bool
	}{
		{"top", "TestParent", []componentTest{pass("TestParent")}, true},
		{"child", "TestParent/child", []componentTest{pass("TestParent"), pass("TestParent/child")}, true},
		{"slash-name", "TestParent/path/leaf", []componentTest{pass("TestParent"), pass("TestParent/path/leaf")}, true},
		{"virtual-prefix", "TestParent/path", []componentTest{pass("TestParent"), pass("TestParent/path/leaf")}, false},
		{"missing-child", "TestParent/child", []componentTest{pass("TestParent")}, false},
		{"skipped-request", "TestParent", []componentTest{{Name: "TestParent", Outcome: "skipped"}}, false},
		{"failed-ancestor", "TestParent/child", []componentTest{{Name: "TestParent", Outcome: "failed"}, pass("TestParent/child")}, false},
		{"sibling", "TestParent/child", []componentTest{pass("TestParent"), pass("TestParent/child"), pass("TestParent/other")}, false},
		{"unrelated-top", "TestParent", []componentTest{pass("TestParent"), pass("TestOther")}, false},
		{"duplicate", "TestParent", []componentTest{pass("TestParent"), pass("TestParent")}, false},
		{"negative-helper", negative, []componentTest{pass(negative), {Name: negative + "/writer", Outcome: "skipped"}, {Name: negative + "/fresh", Outcome: "skipped"}, {Name: negative + "/fixture", Outcome: "skipped"}}, true},
		{"missing-probe", negative, []componentTest{pass(negative), {Name: negative + "/writer", Outcome: "skipped"}, {Name: negative + "/fresh", Outcome: "skipped"}}, false},
		{"unknown-probe", negative, []componentTest{pass(negative), {Name: negative + "/unknown", Outcome: "skipped"}}, false},
		{"pruning-parent", pruning, []componentTest{pass(pruning), pass(pruning + "/results_8"), pass(pruning + "/results_16")}, true},
		{"pruning-missing-size", pruning, []componentTest{pass(pruning), pass(pruning + "/results_8")}, false},
		{"pruning-one-size", pruning + "/results_8", []componentTest{pass(pruning), pass(pruning + "/results_8")}, true},
	} {
		t.Run(spec.name, func(t *testing.T) {
			checks := focusedEvidenceFixture(t, spec.request, spec.tests...)
			body, err := json.Marshal(checks)
			var saved checkEvidence
			if err != nil || json.Unmarshal(body, &saved) != nil || completeFocusedComponentEvidence(saved) != spec.valid {
				t.Fatalf("focused proof differs after round trip: valid=%t saved=%+v err=%v", spec.valid, saved, err)
			}
			if completeComponentEvidence(saved, "hermetic", "memory") {
				t.Fatal("focused evidence qualified the complete profile")
			}
			saved.Focus = nil
			if completeComponentEvidence(saved, "hermetic", "memory") {
				t.Fatal("removing focus hid the incomplete profile inventory")
			}
		})
	}
	checks := focusedEvidenceFixture(t, "TestParent", pass("TestParent"))
	for _, change := range []func(*checkEvidence){
		func(c *checkEvidence) { c.Outcome = "failed" },
		func(c *checkEvidence) { c.TestsComplete = false },
		func(c *checkEvidence) { c.Focus.Tests[0] = "TestOther" },
		func(c *checkEvidence) { c.Focus.Package = "invalid" },
		func(c *checkEvidence) { c.Focus.Package = "wrong/package" },
		func(c *checkEvidence) { c.Selection = "TestParent" },
		func(c *checkEvidence) { c.Groups = nil },
		func(c *checkEvidence) { c.Groups[0].TestCount = 2 },
		func(c *checkEvidence) { c.Inventory = []string{"TestParent"} },
		func(c *checkEvidence) { c.NotSelected = []string{"TestParent"} },
		func(c *checkEvidence) { c.RaceOptions = "exitcode=0" },
	} {
		body, _ := json.Marshal(checks)
		var damaged checkEvidence
		if err := json.Unmarshal(body, &damaged); err != nil {
			t.Fatal(err)
		}
		change(&damaged)
		if completeFocusedComponentEvidence(damaged) {
			t.Fatal("damaged focused evidence passed", damaged)
		}
	}
	t.Run("retained-placement-after-estimate-refresh", func(t *testing.T) {
		estimates := componentEstimates
		t.Cleanup(func() { componentEstimates = estimates })
		componentEstimates = map[string]float64{maximumCapacityComponent: 200, "TestParent": 1}
		retained := focusedEvidenceFixture(t, "TestParent", pass("TestParent"))
		body, err := json.Marshal(retained)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*checkEvidence){
			func(c *checkEvidence) { c.Groups[0].Name = "other-group" },
			func(c *checkEvidence) { c.Diagnostics.Commands[2].Scope = "other-group" },
			func(c *checkEvidence) { c.Diagnostics.Commands[3].Scope = "other-group" },
			func(c *checkEvidence) { c.Diagnostics.Commands[2].RequestedNode = "missing" },
			func(c *checkEvidence) { c.Diagnostics.Commands[2].Joined = false },
			func(c *checkEvidence) { c.Diagnostics.Commands[2].RaceObservation = "observed" },
			func(c *checkEvidence) { c.Diagnostics.Commands[3].Events = "incomplete" },
			func(c *checkEvidence) { c.Diagnostics.Commands[3].ToolCleanup = "failed" },
			func(c *checkEvidence) {
				c.Diagnostics.Commands = append(c.Diagnostics.Commands, c.Diagnostics.Commands[2])
			},
			func(c *checkEvidence) { c.Diagnostics = nil },
		} {
			var damaged checkEvidence
			if err := json.Unmarshal(body, &damaged); err != nil {
				t.Fatal(err)
			}
			change(&damaged)
			if completeFocusedComponentEvidence(damaged) {
				t.Error("retained group/command identity or completion mismatch passed", damaged)
			}
		}
		// New eligible complete-parent observations can change the next plan.
		// They cannot change which literal node the retained execution proved.
		componentEstimates = map[string]float64{maximumCapacityComponent: 1, "TestParent": 6000}
		_, _, currentGroups, _, err := resolveComponentGroups(retained.Inventory, retained.Classifications, retained.Profile, retained.Focus.Tests, 4, componentEstimates)
		if err != nil || len(currentGroups) != 1 || currentGroups[0].Name != retained.Groups[0].Name {
			t.Fatal("estimate refresh changed package ownership", err, currentGroups)
		}
		if !completeFocusedComponentEvidence(retained) {
			t.Fatal("later scheduling estimates erased valid retained literal evidence")
		}
	})
	t.Run("retained-helper-proof-selection", func(t *testing.T) {
		for _, dependency := range []struct{ dependent, parent string }{
			{"TestFreshProcessChild", "TestThreeGenerationHistoryAndStaleCandidate"},
			{"TestHermeticWorkerEntrypointsNeedExplicitInvocation", "TestThreeGenerationHistoryAndStaleCandidate"},
			{"TestScenarioPhaseFailureChild", "TestScenarioPhaseRetainsFailureEvidence"},
			{"TestWriterTerminationChild", "TestWriterTerminationPreservesCompleteSelection"},
		} {
			for _, conflict := range []string{"missing-parent", "full-only-dependent", "full-only-parent"} {
				t.Run(dependency.dependent+"/"+conflict, func(t *testing.T) {
					retained := focusedEvidenceFixture(t, "TestParent", pass("TestParent"))
					retained.Inventory = append(retained.Inventory, dependency.dependent, dependency.parent)
					retained.Classifications = componentFixtureClassifications(retained.Inventory)
					if !completeFocusedComponentEvidence(retained) {
						t.Fatal("complete helper/proof inventory invalidated an unrelated retained literal focus")
					}
					if conflict == "missing-parent" {
						retained.Inventory = slices.DeleteFunc(retained.Inventory, func(name string) bool { return name == dependency.parent })
						retained.Classifications = componentFixtureClassifications(retained.Inventory)
					} else {
						marked := dependency.dependent
						if conflict == "full-only-parent" {
							marked = dependency.parent
						}
						for i := range retained.Classifications {
							if retained.Classifications[i].Name == marked {
								value := true
								retained.Classifications[i].FullOnly = &value
							}
						}
					}
					want := conflict != "missing-parent"
					if completeFocusedComponentEvidence(retained) != want {
						t.Fatal("retained focus confused helper closure with coverage profile", conflict)
					}
				})
			}
		}
	})

}

// full_only: false
func TestComponentFocusRuntimeFixture(t *testing.T) {
	path := os.Getenv("ENKV_FOCUS_FIXTURE_PATH")
	if path == "" {
		return
	}
	writeComponentSelectedSetWitness(t, "first")
	if err := os.WriteFile(path, []byte("setup\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"punct[a]+b.c", "repeat", "repeat", "path/leaf"} {
		t.Run(name, func(t *testing.T) {})
	}
	for _, side := range []string{"left", "right"} {
		t.Run(side, func(t *testing.T) {
			for _, child := range []string{"one", "two"} {
				t.Run(child, func(t *testing.T) {
					if side == "left" && child == "one" && os.Getenv("ENKV_FOCUS_SET_PANIC") == "1" {
						panic("controlled selected child panic")
					}
				})
			}
		})
	}
	if os.Getenv("ENKV_FOCUS_FIXTURE_FAILURE") == "1" {
		t.Run("failure", func(t *testing.T) { t.Error("controlled assembly assertion") })
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("suffix\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
}

// full_only: false
func TestComponentFocusRuntimeUsesLiteralGoSelection(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const owner = "TestComponentFocusRuntimeFixture"
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, owner)
	binary := filepath.Join(root, "component-focus")
	script := "#!/bin/sh\ncase \"$*\" in\n *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\nesac\nexec '" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, child := range []string{"punct[a]+b.c", "repeat#01", "path/leaf", "path", "missing"} {
		t.Run(child, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "preparation")
			request := owner + "/" + child
			process, checks, _, _ := executeFixtureProfileComponentChecks(t, nil, t.Context(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentFixtureClassifications(inventory)), environment(os.Environ(), map[string]string{"ENKV_FOCUS_FIXTURE_PATH": path}), "full", singleTestRequest(request), 3, nil, nil)
			valid := child != "path" && child != "missing"
			if (process.Status == "passed") != valid || !process.Joined || completeFocusedComponentEvidence(checks) != valid || len(checks.Groups) != 1 || !slices.Equal(checks.Inventory, inventory) {
				t.Fatalf("literal selection result differs: process=%+v cause=%v checks=%+v", process, process.Cause, checks)
			}
			if valid && (len(checks.Tests) != 2 || checks.Tests[1].Name != request) {
				t.Fatal("literal selection ran another child", checks.Tests)
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "setup\nsuffix\n" {
				t.Fatal("focus omitted parent setup or suffix", err, string(body))
			}
		})
	}
}

// full_only: false
func TestComponentFocusPlacementAndLiteralSelection(t *testing.T) {
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestParent", "TestFreshProcessChild", "TestHermeticWorkerEntrypointsNeedExplicitInvocation", "TestThreeGenerationHistoryAndStaleCandidate")
	before := slices.Clone(inventory)
	for _, test := range []struct{ request, class string }{
		{"TestParent", "ordinary"},
		{"TestParent/a[1]+b.c#02", "ordinary"},
		{"TestOutputConfigurationGeneratedMaximumTransitionMemory/lifecycle/record_pre_canceled", "fresh-exclusive"},
		{"TestHermeticWorkerEntrypointsNeedExplicitInvocation", "ordinary"},
	} {
		selected, excluded, groups, focus, err := resolveComponentGroups(inventory, componentFixtureClassifications(inventory), "full", singleTestRequest(test.request), 4, componentEstimates)
		if err != nil || focus == nil || focus.Tests[0] != test.request || componentFocusProcessClass(focus.Tests[0]) != test.class || focus.Package != componentPackage || len(groups) != 1 || len(groups[0].Tests) != 1 || groups[0].Tests[0] != requestedTestRoots(focus.Tests)[0] || !slices.Equal(selected, inventory) || len(excluded) != 0 {
			t.Fatalf("focus lost placement or inventory: %+v %+v %v", focus, groups, err)
		}
		if groups[0].Exclusive != (test.class == "fresh-exclusive") {
			t.Fatal("focus changed process class")
		}
		pattern, err := componentFocusSelection(test.request)
		if err != nil {
			t.Fatal(err)
		}
		for i, segment := range strings.Split(pattern, "/") {
			literal := strings.Split(test.request, "/")[i]
			matcher := regexp.MustCompile(segment)
			if !matcher.MatchString(literal) || matcher.MatchString(literal+"extra") || matcher.MatchString("extra"+literal) {
				t.Fatal("focus is not an exact literal segment", segment)
			}
		}
	}
	if !reflect.DeepEqual(inventory, before) {
		t.Fatal("focus mutated the discovered inventory")
	}
	for _, request := range []string{"TestUnknown", "TestFreshProcessChild", "TestFreshProcessChild/child", "TestHermeticWorkerEntrypointsNeedExplicitInvocation/writer"} {
		if _, _, _, _, err := resolveComponentGroups(inventory, componentFixtureClassifications(inventory), "full", singleTestRequest(request), 4, componentEstimates); err == nil {
			t.Error("invalid focus admitted", request)
		}
	}
	if _, _, _, _, err := resolveComponentGroups(inventory, componentProfileFixtureClassifications(inventory), "dev", singleTestRequest(maximumCapacityComponent), 4, componentEstimates); err == nil {
		t.Fatal("dev exclusion admitted")
	}
	if _, _, _, _, err := resolveComponentGroups([]string{maximumCapacityComponent, "TestParent"}, componentFixtureClassifications([]string{maximumCapacityComponent, "TestParent"}), "full", singleTestRequest("TestParent"), 4, componentEstimates); err != nil {
		t.Fatal("active focus required absent native memory owners", err)
	}
	if _, _, _, _, err := resolveComponentGroups([]string{"TestParent"}, componentFixtureClassifications([]string{"TestParent"}), "linux-native", singleTestRequest("TestParent"), 4, componentEstimates); err == nil {
		t.Fatal("retired platform focus profile was accepted")
	}
}

// full_only: false
func TestWorkflowComponentFocusRejectsOtherKinds(t *testing.T) {
	path := savedWorkflowPath(t, "check")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	for _, step := range []string{"unit", "assembly-common", "scenarios", "missing"} {
		if _, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: step, Test: "TestParent"}); err == nil {
			t.Error("focus accepted outside component step", step)
		}
	}
	plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: "components", Test: "TestParent/child"})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Selected {
			if step.Kind != "component-tests" || step.Focus == nil || step.Focus.Tests[0] != "TestParent/child" {
				t.Fatal("resolved focus differs", step)
			}
		} else if step.Focus != nil || step.Run != nil {
			t.Fatal("focus loaded an unrelated step")
		}
	}
}

func writeComponentSelectedSetWitness(t *testing.T, name string) {
	t.Helper()
	path := os.Getenv("ENKV_FOCUS_SET_WITNESS")
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := fmt.Fprintf(file, "%s %d\n", name, os.Getpid())
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
}

// full_only: false
func TestComponentSelectedSetSecondRuntimeFixture(t *testing.T) {
	writeComponentSelectedSetWitness(t, "second")
}

// full_only: false
func TestComponentSelectedSetUsesExactNativeGroups(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const first, second = "TestComponentFocusRuntimeFixture", "TestComponentSelectedSetSecondRuntimeFixture"
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, first, second)
	binary := filepath.Join(root, "selected-set")
	script := "#!/bin/sh\ncase \"$*\" in\n *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\nesac\nexec " + shellQuote(executable) + " \"$@\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name      string
		requests  []string
		processes int
		passed    bool
	}{
		{"roots", []string{first, second}, 1, true},
		{"literal-siblings", []string{first + "/punct[a]+b.c", first + "/repeat#01"}, 1, true},
		{"separate-parents", []string{first + "/left/one", first + "/right/two"}, 2, true},
		{"absent-exact-child", []string{first + "/punct[a]+b.c", first + "/missing"}, 1, false},
		{"panic-does-not-restart", []string{first + "/left/one", first + "/right/two"}, 1, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			witness := filepath.Join(t.TempDir(), "processes")
			env := environment(os.Environ(), map[string]string{"ENKV_FOCUS_FIXTURE_PATH": filepath.Join(t.TempDir(), "body"), "ENKV_FOCUS_SET_WITNESS": witness})
			if row.name == "panic-does-not-restart" {
				env = environment(env, map[string]string{"ENKV_FOCUS_SET_PANIC": "1"})
			}
			partitions, err := literalTestGroups(row.requests)
			if err != nil {
				t.Fatal(err)
			}
			process, checks, _, _ := executeFixtureProfileComponentChecks(t, nil, t.Context(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentFixtureClassifications(inventory)), env, "full", row.requests, 1, nil, nil)
			if (process.Status == "passed") != row.passed || !process.Joined || len(checks.Groups) != len(partitions) || completeFocusedComponentEvidence(checks) != row.passed {
				t.Fatalf("selected set differs: process=%+v cause=%v checks=%+v", process, process.Cause, checks)
			}
			body, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal(err)
			}
			pids := map[string]bool{}
			for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 2 {
					t.Fatal("invalid process witness", line)
				}
				pids[fields[1]] = true
			}
			if len(pids) != row.processes {
				t.Fatal("selected roots lost package ownership or child partitions restarted", string(body))
			}
			if row.name == "panic-does-not-restart" {
				if checks.Groups[1].Outcome != "not_run" {
					t.Fatal("package panic dispatched a replacement child partition", checks.Groups)
				}
			}
			if row.name == "separate-parents" {
				for _, test := range checks.Tests {
					if test.Name == first+"/left/two" || test.Name == first+"/right/one" {
						t.Fatal("native selection added an unrequested cross-product child", test.Name)
					}
				}
			}
		})
	}
}

// full_only: false
func TestSelectedComponentHelpersRequireCompleteInvokingParent(t *testing.T) {
	const parent, helper = "TestScenarioPhaseRetainsFailureEvidence", "TestScenarioPhaseFailureChild"
	inventory := []string{maximumCapacityComponent, parent, helper}
	rows := componentFixtureClassifications(inventory)
	for _, requests := range [][]string{{helper}, {parent + "/child", helper}, {parent, helper + "/child"}} {
		if _, _, _, _, err := resolveComponentGroups(inventory, rows, "full", requests, 4, componentEstimates); err == nil {
			t.Fatal("helper ran without its complete invoking parent", requests)
		}
	}
	requests := []string{parent, helper}
	_, _, groups, focus, err := resolveComponentGroups(inventory, rows, "full", requests, 4, componentEstimates)
	if err != nil || focus == nil || !slices.Equal(focus.Tests, requests) || len(groups) != 1 || len(groups[0].Tests) != 2 {
		t.Fatal("declared helper and complete parent were separated or refused", groups, err)
	}
	terminals := []componentTest{{Name: parent, Outcome: "passed"}, {Name: helper, Outcome: "skipped"}}
	if !completeRequestedComponentTerminals(requests, terminals) {
		t.Fatal("existing positive helper-invocation proof did not explain its skip")
	}
	for _, damaged := range [][]componentTest{
		{{Name: parent, Outcome: "failed"}, {Name: helper, Outcome: "skipped"}},
		{{Name: parent, Outcome: "passed"}},
		{{Name: helper, Outcome: "skipped"}},
	} {
		if completeRequestedComponentTerminals(requests, damaged) {
			t.Fatal("missing or failed invocation proof explained a helper skip", damaged)
		}
	}
}

// full_only: false
func TestFocusedComponentEvidenceRetainsMultipleWorkerOwnership(t *testing.T) {
	requests := []string{"TestAlpha/left/a", "TestAlpha/right/b", "TestBeta", "TestGamma", "TestDelta"}
	inventory := []string{maximumCapacityComponent, "TestAlpha", "TestBeta", "TestGamma", "TestDelta"}
	groups := []componentGroup{
		{Name: "selected-1", Worker: 1, Tests: []string{"TestAlpha"}, Requests: []string{requests[0]}, Selection: "^TestAlpha$/^left$/^a$"},
		{Name: "selected-2", Worker: 1, Tests: []string{"TestAlpha"}, Requests: []string{requests[1]}, Selection: "^TestAlpha$/^right$/^b$"},
		{Name: "selected-3", Worker: 2, Tests: []string{"TestBeta", "TestGamma", "TestDelta"}, Requests: requests[2:], Selection: "^(TestBeta|TestGamma|TestDelta)$"},
	}
	terminals := []componentTest{}
	for _, name := range []string{"TestAlpha", "TestAlpha/left", "TestAlpha/left/a", "TestAlpha", "TestAlpha/right", "TestAlpha/right/b", "TestBeta", "TestGamma", "TestDelta"} {
		terminals = append(terminals, componentTest{Name: name, Outcome: "passed"})
	}
	checks := checkEvidence{Profile: "full", Inventory: inventory, Classifications: componentFixtureClassifications(inventory), Focus: &componentFocus{Package: componentPackage, Tests: requests}, Parallelism: 2,
		Selection: "literal requested test paths in exact process groups", TestsComplete: true, Tests: terminals, Outcome: "passed", Race: true, RaceOptions: raceOptions,
		EventTimeSource: "post_join_test2json", Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	for _, group := range groups {
		checks.Groups = append(checks.Groups, componentGroupResult(group, "passed", 0))
		checks.Diagnostics.Commands = append(checks.Diagnostics.Commands,
			checkCommandFacts{Phase: "test", Scope: group.Name, Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed", RequestedNode: "passed"},
			checkCommandFacts{Phase: "conversion", Scope: group.Name, Process: "passed", Started: true, Joined: true, Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"})
	}
	body, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	var retained checkEvidence
	if err := json.Unmarshal(body, &retained); err != nil || !completeFocusedComponentEvidence(retained) {
		t.Fatal("multiple workers or legitimate repeated ancestor events lost their retained proof", err, retained)
	}
	estimates := componentEstimates
	t.Cleanup(func() { componentEstimates = estimates })
	componentEstimates = map[string]float64{"TestAlpha": 9999, "TestBeta": 1, "TestGamma": 10, "TestDelta": 100}
	_, _, later, _, err := resolveComponentGroups(inventory, checks.Classifications, "full", requests, 4, componentEstimates)
	if err != nil || len(later) == len(groups) {
		t.Fatal("later capacity did not provide a different placement control", err, later)
	}
	if !completeFocusedComponentEvidence(retained) {
		t.Fatal("later capacity and estimates erased completed ownership")
	}
	for _, change := range []func(*checkEvidence){
		func(c *checkEvidence) { c.Groups[1].Worker = 2 },
		func(c *checkEvidence) { c.Groups[0].Worker = 0 },
		func(c *checkEvidence) { c.Groups[0].Exclusive = true },
		func(c *checkEvidence) { c.Groups[0].Tests[0] = "TestBeta" },
		func(c *checkEvidence) { c.Groups[0].Requests[0] = "TestAlpha/left/other" },
		func(c *checkEvidence) { c.Groups[0].Selection = "^TestAlpha$/^left$/.*" },
		func(c *checkEvidence) { c.Groups = c.Groups[:2] },
		func(c *checkEvidence) {
			c.Diagnostics.Commands = c.Diagnostics.Commands[:len(c.Diagnostics.Commands)-1]
		},
		func(c *checkEvidence) { c.Tests = append(c.Tests, componentTest{Name: "TestAlpha", Outcome: "passed"}) },
	} {
		var damaged checkEvidence
		if err := json.Unmarshal(body, &damaged); err != nil {
			t.Fatal(err)
		}
		change(&damaged)
		if completeFocusedComponentEvidence(damaged) {
			t.Fatal("damaged physical ownership or terminal inventory passed", damaged)
		}
	}
	t.Run("helper-and-parent-need-the-same-process", func(t *testing.T) {
		const parent, helper = "TestScenarioPhaseRetainsFailureEvidence", "TestScenarioPhaseFailureChild"
		split := checks
		split.Inventory = []string{maximumCapacityComponent, parent, helper}
		split.Classifications = componentFixtureClassifications(split.Inventory)
		split.Focus = &componentFocus{Package: componentPackage, Tests: []string{parent, helper}}
		split.Tests = []componentTest{{Name: parent, Outcome: "passed"}, {Name: helper, Outcome: "passed"}}
		split.Groups = nil
		split.Diagnostics = &checkDiagnostics{Preparation: "passed"}
		for i, name := range []string{parent, helper} {
			group := componentGroup{Name: fmt.Sprintf("selected-%d", i+1), Worker: 1, Tests: []string{name}, Requests: []string{name}, Selection: "^" + name + "$"}
			split.Groups = append(split.Groups, componentGroupResult(group, "passed", 0))
			split.Diagnostics.Commands = append(split.Diagnostics.Commands,
				checkCommandFacts{Phase: "test", Scope: group.Name, Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed", RequestedNode: "passed"},
				checkCommandFacts{Phase: "conversion", Scope: group.Name, Process: "passed", Started: true, Joined: true, Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"})
		}
		if !completeRequestedComponentTerminals(split.Focus.Tests, split.Tests) || completeFocusedComponentEvidence(split) {
			t.Fatal("separate physical processes acquired a required helper bundle's proof", split)
		}
	})
}
