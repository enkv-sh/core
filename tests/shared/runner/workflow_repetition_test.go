package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestWorkflowRepetitionCompletionUsesCurrentResults(t *testing.T) {
	for _, kind := range []string{"unit", "component-tests"} {
		for _, row := range []struct {
			name, outcome, groupOutcome string
			started, completed          int
			unjoined, missing, noTest   bool
			wantError                   bool
		}{
			{name: "passed", outcome: "passed", groupOutcome: "passed", started: 3, completed: 3},
			{name: "failed-second", outcome: "failed", groupOutcome: "failed", started: 2, completed: 2},
			{name: "unjoined-second", outcome: "failed", groupOutcome: "failed", started: 2, completed: 1, unjoined: true, wantError: true},
			{name: "missing-second", outcome: "failed", groupOutcome: "failed", started: 2, completed: 1, missing: true, wantError: true},
			{name: "no-test-command", outcome: "failed", groupOutcome: "failed", started: 2, completed: 1, noTest: true, wantError: true},
		} {
			t.Run(kind+"/"+row.name, func(t *testing.T) {
				now := time.Now().UTC()
				result := workflowResult{Outcome: row.outcome, FinishedAt: &now, executions: map[string]workflowStepExecution{}}
				var ids []string
				for index := 0; index < 3; index++ {
					id := fmt.Sprintf("focused-%d", index+1)
					step := workflowStepResult{resolvedWorkflowStep: resolvedWorkflowStep{ID: id, ConfiguredStep: "focused", Kind: kind, Selected: true, Repetition: index + 1, Repetitions: 3}, Outcome: "not_run"}
					if index < row.started {
						step.StartedAt, step.FinishedAt, step.Outcome = &now, &now, "passed"
						ids = append(ids, id)
						if row.name == "failed-second" && index == 1 {
							step.Outcome = "failed"
						}
						if !row.missing || index != 1 {
							phase := "test"
							if row.noTest && index == 1 {
								phase = "preparation"
							}
							diagnostics := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{{Phase: phase, Started: true, Joined: !row.unjoined || index != 1}}}
							if kind == "component-tests" {
								result.executions[id] = workflowStepExecution{Component: &componentRunRecord{Checks: &checkEvidence{Diagnostics: diagnostics}}}
							} else {
								result.executions[id] = workflowStepExecution{Ordinary: &ordinaryStepEvidence{Diagnostics: diagnostics}}
							}
						}
					}
					result.Steps = append(result.Steps, step)
				}
				groups, err := workflowRepetitionGroups(t.TempDir(), result)
				want := []workflowRepetitionGroup{{ConfiguredStep: "focused", RequestedExecutions: 3, CompletedExecutions: row.completed, Outcome: row.groupOutcome, StepIDs: ids}}
				if (err != nil) != row.wantError || !reflect.DeepEqual(groups, want) {
					t.Fatalf("current repetition result = %#v, error=%v; want %#v, error=%t", groups, err, want, row.wantError)
				}
			})
		}
	}
}

func savedRepetitionWorkflow(t *testing.T, kind string, repetitions *int) (string, string, map[string]any) {
	t.Helper()
	root := t.TempDir()
	step := map[string]any{"id": "focused", "kind": kind, "tests": singleTestRequest("TestParent/child[a]+b")}
	switch kind {
	case "unit":
		writeWorkflowUnitPackages(t, root)
		step["packages"] = []string{"core/contract"}
		step["package"] = "core/contract"
	case "component-tests":
		step["profile"] = "dev"
	}
	if repetitions != nil {
		step["repetitions"] = *repetitions
	}
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "bounded", "steps": []any{
		step, map[string]any{"id": "later", "kind": "runner-tests"},
	}})
	return root, path, step
}

// full_only: false
func TestWorkflowSavedFocusRepetitionsResolveExactSelection(t *testing.T) {
	for _, kind := range []string{"unit", "runner-tests", "component-tests"} {
		for _, count := range []int{0, 1, 3, 100} {
			name := fmt.Sprintf("%s/%d", kind, count)
			if count == 0 {
				name = kind + "/default"
			}
			t.Run(name, func(t *testing.T) {
				var repetitions *int
				if count != 0 {
					repetitions = &count
				}
				root, path, _ := savedRepetitionWorkflow(t, kind, repetitions)
				plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "focused"})
				if err != nil {
					t.Fatal("saved literal focus and bounded repetitions were refused", err)
				}
				want := count
				if want == 0 {
					want = 1
				}
				if len(plan.Steps) != want+1 {
					t.Fatal("resolved workflow lost the requested repetition count", len(plan.Steps), want)
				}
				ids := map[string]bool{}
				for index, step := range plan.Steps[:want] {
					if !step.Selected || step.Kind != kind || ids[step.ID] || want > 1 && step.ConfiguredStep != "focused" || want == 1 && step.ID != "focused" {
						t.Fatal("repetition lost configured selection or distinct identity", step)
					}
					ids[step.ID] = true
					if want > 1 && (step.Repetitions != want || step.Repetition != index+1) {
						t.Fatal("expanded selection changed requested N or execution index", step)
					}
					if kind == "component-tests" {
						if step.Focus == nil || step.Focus.Tests[0] != "TestParent/child[a]+b" || step.Profile != "dev" || plan.Race || step.Race != nil {
							t.Fatal("saved component focus became a whole profile or changed race", step)
						}
					} else if step.OrdinaryFocus == nil || step.OrdinaryFocus.Tests[0] != "TestParent/child[a]+b" || kind == "unit" && step.OrdinaryFocus.PackagePath != "core/contract" {
						t.Fatal("saved ordinary focus changed test or package bounds", step)
					}
				}
				later := plan.Steps[want]
				if later.Selected || later.ID != "later" || later.Focus != nil || later.OrdinaryFocus != nil {
					t.Fatal("repetition selected or focused another configured step", later)
				}
				if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !os.IsNotExist(err) {
					t.Fatal("resolution created execution state", err)
				}
				if want > 1 {
					before, err := json.Marshal(plan.Steps[1:want])
					if err != nil {
						t.Fatal(err)
					}
					first := &plan.Steps[0]
					if kind == "component-tests" {
						first.Focus.Tests[0] = "TestChanged/first-only"
					} else {
						first.OrdinaryFocus.Tests[0] = "TestChanged/first-only"
						first.OrdinaryPreparation.ExecutionProof = "first-only preparation observation"
						first.OrdinarySelection = append(first.OrdinarySelection, ordinaryExecution{Artifact: "first-only execution observation"})
					}
					after, err := json.Marshal(plan.Steps[1:want])
					if err != nil || string(before) != string(after) {
						t.Fatal("first execution changed another returned selection or preparation", err)
					}
				}
			})
		}
	}
}

// full_only: false
func TestWorkflowSavedFocusOnlyAllowsNarrowing(t *testing.T) {
	for _, kind := range []string{"unit", "runner-tests", "component-tests"} {
		for _, row := range []struct {
			name, test, pkg string
			valid           bool
		}{
			{"saved", "", "", true},
			{"same", "TestParent/child[a]+b", "", true},
			{"descendant", "TestParent/child[a]+b/leaf", "", true},
			{"ancestor", "TestParent", "", false},
			{"sibling", "TestParent/other", "", false},
			{"replacement", "TestOther", "", false},
			{"different-package", "TestParent/child[a]+b", "crypto/internal/custody", false},
		} {
			t.Run(kind+"/"+row.name, func(t *testing.T) {
				root, path, _ := savedRepetitionWorkflow(t, kind, nil)
				plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "focused", Test: row.test, Package: row.pkg})
				if (err == nil) != row.valid {
					t.Fatal("CLI focus replaced or widened saved bounds, or refused narrowing", err)
				}
				if !row.valid {
					return
				}
				want := row.test
				if want == "" {
					want = "TestParent/child[a]+b"
				}
				if len(plan.Steps) != 2 || kind == "component-tests" && (plan.Steps[0].Focus == nil || plan.Steps[0].Focus.Tests[0] != want) || kind != "component-tests" && (plan.Steps[0].OrdinaryFocus == nil || plan.Steps[0].OrdinaryFocus.Tests[0] != want) {
					t.Fatal("resolved focus lost the saved or narrowed literal request", plan)
				}
			})
		}
	}
}

// full_only: false
func TestWorkflowRepetitionsRejectBoundsAndExpandedIDCollision(t *testing.T) {
	for _, kind := range []string{"unit", "runner-tests", "component-tests"} {
		for _, count := range []int{-1, 0, 101} {
			t.Run(fmt.Sprintf("%s/%d", kind, count), func(t *testing.T) {
				root, path, _ := savedRepetitionWorkflow(t, kind, &count)
				if _, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "focused"}); err == nil {
					t.Fatal("out-of-range repetition count resolved work")
				}
			})
		}
	}
	t.Run("inapplicable-kind", func(t *testing.T) {
		root, path, step := savedRepetitionWorkflow(t, "runner-tests", nil)
		delete(step, "test")
		step["kind"], step["repetitions"] = "lint", 3
		saveSelection(t, path, map[string]any{"schema_version": 1, "name": "bounded", "steps": []any{step}})
		if _, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path}); err == nil {
			t.Fatal("lint admitted finite test repetitions")
		}
	})
	t.Run("expanded-id-collision", func(t *testing.T) {
		count := 3
		root, path, step := savedRepetitionWorkflow(t, "runner-tests", &count)
		plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "focused"})
		if err != nil || len(plan.Steps) != 4 {
			t.Fatal("bounded repetition plan unavailable for collision control", err)
		}
		collision := map[string]any{"id": plan.Steps[0].ID, "kind": "runner-tests"}
		saveSelection(t, path, map[string]any{"schema_version": 1, "name": "bounded", "steps": []any{step, collision}})
		if _, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "focused"}); err == nil {
			t.Fatal("expanded identity collided with another configured step")
		}
	})
	for _, length := range []int{91, 92, 96} {
		t.Run(fmt.Sprintf("configured-label-%d", length), func(t *testing.T) {
			count := 100
			root, path, step := savedRepetitionWorkflow(t, "runner-tests", &count)
			configured := strings.Repeat("a", length)
			step["id"] = configured
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "bounded", "steps": []any{step}})
			request := workflowRequest{Path: path, SelectedStep: configured}
			first, err := resolveWorkflow(t.Context(), root, request)
			if err != nil || len(first.Steps) != count {
				t.Fatal("formerly valid configured label lost bounded repetition", err)
			}
			second, err := resolveWorkflow(t.Context(), root, request)
			if err != nil || len(second.Steps) != count {
				t.Fatal("same configured label failed repeated resolution", err)
			}
			seen := map[string]bool{}
			for index, execution := range first.Steps {
				if !telemetryLabel.MatchString(execution.ID) || seen[execution.ID] || execution.ID != second.Steps[index].ID || execution.ConfiguredStep != configured || execution.Repetitions != count || execution.Repetition != index+1 {
					t.Fatal("expanded label is illegal, unstable, repeated or unbound", execution)
				}
				seen[execution.ID] = true
			}
			collision := map[string]any{"id": first.Steps[count-1].ID, "kind": "runner-tests"}
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "bounded", "steps": []any{step, collision}})
			if _, err := resolveWorkflow(t.Context(), root, request); err == nil {
				t.Fatal("compacted execution label collided with a configured label")
			}
		})
	}
}

// full_only: false
func TestPlanRunCLIRepetitionsAreRefused(t *testing.T) {
	for _, command := range []string{"plan", "run"} {
		for _, route := range []string{"direct", "workflow"} {
			t.Run(command+"/"+route, func(t *testing.T) {
				args := []string{command, "--suite=suite.json", "--environment=environment.json"}
				if route == "workflow" {
					args = []string{command, "--workflow=workflow.json"}
				}
				if _, err := parsePlanRunArguments(args); err != nil {
					t.Fatal("ordinary CLI default refused", err)
				}
				for _, count := range []string{"1", "3", "100"} {
					if _, err := parsePlanRunArguments(append(args, "--repetitions="+count)); err == nil {
						t.Error("CLI repetition override accepted", count)
					}
				}
			})
		}
	}
}

// full_only: false
func TestWorkflowSavedPackageFocusKeepsExactPackage(t *testing.T) {
	root, path, step := savedRepetitionWorkflow(t, "unit", nil)
	delete(step, "tests")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "bounded", "steps": []any{step}})
	for _, requested := range []string{"", "TestParent/child[a]+b"} {
		plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "focused", Test: requested})
		var tests []string
		if requested != "" {
			tests = []string{requested}
		}
		if err != nil || len(plan.Steps) != 1 || plan.Steps[0].OrdinaryFocus == nil || plan.Steps[0].OrdinaryFocus.PackagePath != "core/contract" ||
			!slices.Equal(plan.Steps[0].OrdinaryFocus.Tests, tests) || !reflect.DeepEqual(plan.Steps[0].Packages, map[string][]string{"core": {"./contract"}}) {
			t.Fatal("saved exact package did not supply ordinary package bounds", err, plan)
		}
	}
}
