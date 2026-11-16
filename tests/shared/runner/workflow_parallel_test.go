package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
)

// full_only: false
func TestWorkflowAssemblyGroupSelection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "workflow.json")
	data := []byte(`{"schema_version":1,"name":"assemblies","steps":[
		{"id":"common","kind":"assembly-checks","responsibility":"common","parallel_group":"assemblies"},
		{"id":"gcp","kind":"assembly-checks","responsibility":"gcp","parallel_group":"assemblies"},
		{"id":"aws","kind":"assembly-checks","responsibility":"aws","parallel_group":"assemblies"}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, selected := range []string{"", "gcp"} {
		t.Run("selected="+selected, func(t *testing.T) {
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: selected})
			if err != nil {
				t.Fatal("valid assembly group refused", err)
			}
			body, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			var saved struct{ Steps []map[string]any }
			if err := json.Unmarshal(body, &saved); err != nil || len(saved.Steps) != 3 {
				t.Fatal("group changed step inventory", err)
			}
			for i, id := range []string{"common", "gcp", "aws"} {
				step := saved.Steps[i]
				wantSelected := selected == "" || selected == id
				if step["id"] != id || step["selected"] != wantSelected {
					t.Fatal("group changed order or selection", step)
				}
				if wantSelected && step["parallel_group"] != "assemblies" || !wantSelected && step["parallel_group"] != nil {
					t.Fatal("group is not limited to selected rows", step)
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowAssemblyGroupsRejectMalformedConfiguration(t *testing.T) {
	member := func(id, responsibility string) workflowStep {
		return workflowStep{ID: id, Kind: "assembly-checks", Responsibility: responsibility, ParallelGroup: "assemblies"}
	}
	for _, condition := range []string{"label", "singleton", "separated", "wrong-kind", "duplicate", "unknown-responsibility", "repeated"} {
		t.Run(condition, func(t *testing.T) {
			steps := []workflowStep{member("common", "common"), member("gcp", "gcp"), member("aws", "aws")}
			switch condition {
			case "label":
				for i := range steps {
					steps[i].ParallelGroup = "../bad"
				}
			case "singleton":
				steps = steps[:1]
			case "separated":
				steps = append(steps[:1], append([]workflowStep{{ID: "between", Kind: "lint"}}, steps[1:]...)...)
			case "wrong-kind":
				steps[1].Kind, steps[1].Responsibility = "lint", ""
			case "duplicate":
				steps[2].Responsibility = "gcp"
			case "unknown-responsibility":
				steps[2].Responsibility = "memory"
			case "repeated":
				n := 1
				steps[0].Repetitions = &n
			}
			root := t.TempDir()
			path := filepath.Join(root, "workflow.json")
			saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "assemblies", Steps: steps})
			if _, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path}); err == nil {
				t.Fatal("malformed group admitted")
			}
		})
	}
}

// full_only: false
func TestWorkflowUnselectedAssemblyGroupsPreserveHistoricalPlan(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "workflow.json")
	file := workflowFile{SchemaVersion: 1, Name: "selection", Steps: []workflowStep{
		{ID: "common", Kind: "assembly-checks", Responsibility: "common"},
		{ID: "gcp", Kind: "assembly-checks", Responsibility: "gcp"},
		{ID: "aws", Kind: "assembly-checks", Responsibility: "aws"},
		{ID: "selected", Kind: "lint"},
	}}
	saveSelection(t, path, file)
	before, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "selected"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		file.Steps[i].ParallelGroup = "assemblies"
	}
	saveSelection(t, path, file)
	after, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "selected"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range before.Steps {
		if !reflect.DeepEqual(before.Steps[i], after.Steps[i]) {
			t.Fatal("unselected group changed the selected plan", i)
		}
	}
	focused, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "gcp", Test: "TestControlled/leaf"})
	if err != nil || focused.Steps[1].AssemblyFocus == nil || focused.Steps[1].AssemblyFocus.Requested != "TestControlled/leaf" || focused.Steps[0].Selected || focused.Steps[2].Selected {
		t.Fatal("assembly group changed literal focus", focused, err)
	}
}

// full_only: false
func TestSavedWorkflowsDeclareSupportedParallelGroups(t *testing.T) {
	t.Run("current-files-decode", func(t *testing.T) {
		directory := filepath.Dir(savedWorkflowPath(t, "canonical"))
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			t.Run(entry.Name(), func(t *testing.T) {
				var file workflowFile
				if err := readSelectionFile(filepath.Join(directory, entry.Name()), &file); err != nil {
					t.Fatal("current workflow fields refused", err)
				}
			})
		}
	})
	for _, name := range []string{"canonical", "check", "dev"} {
		t.Run(name, func(t *testing.T) {
			var file workflowFile
			if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, step := range file.Steps {
				if step.ParallelGroup != "" {
					if step.ParallelGroup == "assemblies" && step.Kind == "assembly-checks" {
						ids = append(ids, step.ID)
					} else if name != "canonical" || step.Kind != "run" || step.ParallelGroup != "recovery-"+step.RecoveryMode {
						t.Fatal("unsupported workflow work grouped", step)
					}
				}
			}
			if !reflect.DeepEqual(ids, []string{"assembly-common", "assemblies-gcp", "assemblies-aws"}) {
				t.Fatal("assembly group membership changed", ids)
			}
		})
	}
}

// full_only: false
func TestWorkflowAssemblyGroupsRejectInvalidPlanBeforeCallbacks(t *testing.T) {
	for _, condition := range []string{"wrong-kind", "unselected", "repeated", "separated", "duplicate"} {
		t.Run(condition, func(t *testing.T) {
			root := workflowExecutionFixture(t)
			steps := []resolvedWorkflowStep{
				{ID: "common", Kind: "assembly-checks", Responsibility: "common", Selected: true, ParallelGroup: "assemblies"},
				{ID: "gcp", Kind: "assembly-checks", Responsibility: "gcp", Selected: true, ParallelGroup: "assemblies"},
				{ID: "aws", Kind: "assembly-checks", Responsibility: "aws", Selected: true, ParallelGroup: "assemblies"},
			}
			switch condition {
			case "wrong-kind":
				steps[1].Kind = "unit"
			case "unselected":
				steps[1].Selected = false
			case "repeated":
				steps[1].Repetitions = 2
			case "separated":
				steps[1].ParallelGroup = ""
			case "duplicate":
				steps[1].Responsibility = "common"
			}
			called := false
			_, err := executeWorkflow(t.Context(), root, workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "assemblies", Steps: steps}, io.Discard, nil, nil,
				func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
					called = true
					return workflowStepExecution{}, nil
				})
			if err == nil || called {
				t.Fatal("invalid group reached execution", err, called)
			}
			if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !os.IsNotExist(err) {
				t.Fatal("invalid plan acquired workflow files", err)
			}
		})
	}
}

// full_only: false
func TestWorkflowAssemblyGroupsRejectInvalidCapacityBeforeCallbacks(t *testing.T) {
	for _, capacity := range []executionCapacity{{Parallel: 0, MemoryLimitMiB: 3072}, {Parallel: -1, MemoryLimitMiB: 3072}, {Parallel: 5, MemoryLimitMiB: 3072}, {Parallel: 2, MemoryLimitMiB: 0}, {Parallel: 2, MemoryLimitMiB: -1}, {Parallel: 2, MemoryLimitMiB: 24577}} {
		t.Run(fmt.Sprintf("parallel_%d_memory_%d", capacity.Parallel, capacity.MemoryLimitMiB), func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := assemblyGroupExecutionPlan(2)
			plan.Execution.Resolved = capacity
			plan.Steps = append([]resolvedWorkflowStep{{ID: "preceding", Kind: "unit", Selected: true}}, plan.Steps...)
			var calls atomic.Int32
			_, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil, func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
				calls.Add(1)
				return workflowStepExecution{}, nil
			})
			if err == nil || calls.Load() != 0 {
				t.Errorf("invalid capacity admitted execution: error=%v callbacks=%d", err, calls.Load())
			}
			if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !os.IsNotExist(err) {
				t.Error("invalid group capacity acquired workflow files", err)
			}
		})
	}
}

// full_only: false
func TestWorkflowFocusedComponentGroupSelection(t *testing.T) {
	for _, profile := range []string{"dev", "full"} {
		for _, selected := range []string{"", "second"} {
			t.Run(profile+"/selected="+selected, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "workflow.json")
				file := workflowFile{SchemaVersion: 1, Name: "focused", Steps: []workflowStep{
					{ID: "first", Kind: "component-tests", Profile: profile, Tests: singleTestRequest("TestFirst"), ParallelGroup: "ordinary"},
					{ID: "second", Kind: "component-tests", Profile: profile, Tests: singleTestRequest("TestSecond/a[1]+b.c#02"), ParallelGroup: "ordinary"},
				}}
				saveSelection(t, path, file)
				plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: selected})
				if err != nil || len(plan.Steps) != 2 {
					t.Fatal("ordinary focused component group refused", err)
				}
				for i, step := range plan.Steps {
					wantSelected := selected == "" || selected == step.ID
					if step.ID != file.Steps[i].ID || step.Selected != wantSelected || step.Profile != profile || plan.Race || step.Race != nil ||
						step.Focus == nil || step.Focus.Tests[0] != file.Steps[i].Tests[0] || step.Preparation != nil {
						t.Fatal("focus plan changed identity, literal path, profile or preparation ownership", step)
					}
					if wantSelected && step.ParallelGroup != "ordinary" || !wantSelected && step.ParallelGroup != "" {
						t.Fatal("focus group widened step selection", step)
					}
				}
			})
		}
	}
}

// full_only: false
func TestWorkflowFocusedComponentGroupsRefuseBroadOrMalformedWork(t *testing.T) {
	for _, condition := range []string{"missing focus", "invalid literal", "missing profile", "invalid profile", "package", "repeated", "mixed kind", "separated", "singleton"} {
		t.Run(condition, func(t *testing.T) {
			steps := []workflowStep{
				{ID: "first", Kind: "component-tests", Profile: "full", Tests: singleTestRequest("TestFirst"), ParallelGroup: "ordinary"},
				{ID: "second", Kind: "component-tests", Profile: "dev", Tests: singleTestRequest("TestSecond/leaf"), ParallelGroup: "ordinary"},
			}
			switch condition {
			case "missing focus":
				steps[1].Tests = nil
			case "invalid literal":
				steps[1].Tests = []string{"TestSecond//leaf"}
			case "missing profile":
				steps[1].Profile = ""
			case "invalid profile":
				steps[1].Profile = "unknown"
			case "package":
				steps[1].Package = "core"
			case "repeated":
				one := 1
				steps[1].Repetitions = &one
			case "mixed kind":
				steps[1] = workflowStep{ID: "second", Kind: "assembly-checks", Responsibility: "gcp", ParallelGroup: "ordinary"}
			case "separated":
				steps = append(steps[:1], append([]workflowStep{{ID: "between", Kind: "lint"}}, steps[1:]...)...)
			case "singleton":
				steps = steps[:1]
			}
			root := t.TempDir()
			path := filepath.Join(root, "workflow.json")
			saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "focused", Steps: steps})
			if _, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path}); err == nil {
				t.Fatal("broad or malformed focus group admitted")
			}
		})
	}
}

// full_only: false
func TestWorkflowFocusedComponentGroupsKeepMemoryOwnersExclusive(t *testing.T) {
	// These twelve process owners are the retained memory-proof contract.
	// Scheduling estimates must not change their admission class.
	owners := []string{
		"TestOutputConfigurationMaximumPolicyTransitionMemory",
		"TestOutputConfigurationMaximumRoutingTransitionMemory",
		"TestOutputConfigurationMaximumEqualSourceConversionMemory",
		"TestOutputConfigurationMaximumPreparationPreCanceledMemory",
		"TestOutputConfigurationMaximumLastConfigurationReadCanceledMemory",
		"TestOutputConfigurationMaximumLastLargeReadbackUnavailableMemory",
		"TestOutputConfigurationMaximumSigningRefusedMemory",
		"TestOutputConfigurationMaximumSelectionPreCanceledMemory",
		"TestOutputConfigurationMaximumSelectionUnknownWithEffectMemory",
		"TestOutputConfigurationMaximumSelectionUnknownWithoutEffectMemory",
		"TestOrdinaryOutputMemoryNativeArtifact",
		"TestOutputConfigurationGeneratedMaximumTransitionMemory",
	}
	estimates := componentEstimates
	t.Cleanup(func() { componentEstimates = estimates })
	for _, estimate := range []float64{1, 10000} {
		componentEstimates = map[string]float64{"TestOrdinaryPeer": estimate}
		for _, owner := range owners {
			componentEstimates[owner] = estimate
			for _, request := range []string{owner, owner + "/leaf"} {
				t.Run(fmt.Sprintf("estimate=%.0f/%s", estimate, request), func(t *testing.T) {
					steps := []workflowStep{
						{ID: "ordinary", Kind: "component-tests", Profile: "full", Tests: singleTestRequest("TestOrdinaryPeer"), ParallelGroup: "focused"},
						{ID: "memory", Kind: "component-tests", Profile: "full", Tests: singleTestRequest(request), ParallelGroup: "focused"},
					}
					if err := validateConfiguredParallelGroups(steps); err == nil {
						t.Fatal("memory parent or descendant entered a shared workflow group")
					}
					plan := focusedComponentGroupExecutionPlan(2)
					plan.Steps[1].Tests = singleTestRequest(request)
					plan.Steps[1].Focus = &componentFocus{Tests: singleTestRequest(request)}
					if err := validateResolvedParallelGroups(plan); err == nil {
						t.Fatal("resolved focus trusted a forged ordinary class or scheduling weight")
					}
				})
			}
		}
	}
}

// full_only: false
func TestWorkflowFocusedComponentGroupsRejectInvalidPlanBeforeCallbacks(t *testing.T) {
	for _, condition := range []string{"missing focus", "invalid literal", "missing profile", "invalid profile", "unselected", "repeated", "repetition", "mixed kind", "separated"} {
		t.Run(condition, func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := focusedComponentGroupExecutionPlan(2)
			switch condition {
			case "missing focus":
				plan.Steps[1].Focus = nil
			case "invalid literal":
				plan.Steps[1].Tests = singleTestRequest("TestSecond//leaf")
				plan.Steps[1].Focus = &componentFocus{Tests: singleTestRequest("TestSecond//leaf")}
			case "missing profile":
				plan.Steps[1].Profile = ""
			case "invalid profile":
				plan.Steps[1].Profile = "unknown"
			case "unselected":
				plan.Steps[1].Selected = false
			case "repeated":
				plan.Steps[1].Repetitions = 1
			case "repetition":
				plan.Steps[1].Repetition = 1
			case "mixed kind":
				plan.Steps[1].Kind, plan.Steps[1].Responsibility = "assembly-checks", "gcp"
			case "separated":
				plan.Steps[1].ParallelGroup = ""
			}
			var calls atomic.Int32
			_, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil, func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
				calls.Add(1)
				return workflowStepExecution{}, nil
			})
			if err == nil || calls.Load() != 0 {
				t.Fatal("invalid resolved focus reached a callback", err, calls.Load())
			}
			if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !os.IsNotExist(err) {
				t.Fatal("invalid resolved focus acquired workflow files", err)
			}
		})
	}
}
