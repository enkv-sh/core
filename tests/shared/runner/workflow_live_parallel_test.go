package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func liveGroupPlan(parallel int) workflowPlan {
	plan := assemblyGroupExecutionPlan(parallel)
	plan.Race = true
	requestedParallel, requestedMemory := parallel, plan.Execution.Resolved.MemoryLimitMiB
	plan.Execution.Requested = executionRequest{Parallel: &requestedParallel, MemoryLimitMiB: &requestedMemory}
	for i := range plan.Steps[:3] {
		step := &plan.Steps[i]
		step.ID = []string{"gcp", "aws", "gcp-generated"}[i]
		step.Kind, step.Responsibility, step.ParallelGroup = "run", "", "recovery-disabled"
		step.Run = &resolvedRequest{Mode: "live", Profile: "full", Race: plan.Race, RecoveryMode: "disabled"}
		step.Limits = &limits{Requests: 100000, BodyBytes: 1 << 30, Objects: 10000, ObjectBytes: 1 << 30,
			ElapsedSeconds: 3600, CleanupRequests: 100000, CleanupBytes: 1 << 30, CleanupSeconds: 3600,
			GeneratorCreates: 10000, GeneratorRetires: 10000}
		step.request = runRequest{Suite: "live", Profile: "full", Resolved: step.Run, Allowance: step.Limits, execution: plan.Execution.clone()}
	}
	return plan
}

// full_only: false
func TestWorkflowLiveGroupBindsOriginalRootAndCapacity(t *testing.T) {
	root := assemblyGroupExecutionRoot(t)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("tests/workflows/runs/\ntests/hermetic/runs/\ntests/live/runs/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := liveGroupPlan(3)
	var mu sync.Mutex
	roots := map[string]string{}
	runs := map[string]bool{}
	directories := map[string]bool{}
	result, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil,
		func(ctx context.Context, step resolvedWorkflowStep, out io.Writer, _ string) (workflowStepExecution, error) {
			if step.Kind != "run" {
				return workflowStepExecution{}, nil
			}
			mu.Lock()
			defer mu.Unlock()
			roots[step.ID] = step.request.workflowRunID
			if !records.ValidRunID(step.request.workflowRunID) {
				t.Error("grouped live step has no original workflow owner")
			}
			if got := executionCapacityFromContext(ctx); got != (executionCapacity{Parallel: 1, MemoryLimitMiB: 3072}) {
				t.Error("grouped live step lost its one-lane allowance", got)
			}
			if step.request.execution.Resolved != executionCapacityFromContext(ctx) {
				t.Error("live run receipt would restore the outer lane allowance", step.request.execution)
			}
			state, err := newRunState(root, step.request, records.Source{}, "controlled")
			if err != nil {
				return workflowStepExecution{}, err
			}
			if state.record.Execution.Resolved != executionCapacityFromContext(ctx) || state.record.ContinuationRootRunID != step.request.workflowRunID {
				t.Error("retained live run restored outer capacity or lost workflow owner")
			}
			if runs[state.record.RunID] || directories[state.private] {
				t.Error("live peers share a run identity or private directory")
			}
			runs[state.record.RunID], directories[state.private] = true, true
			_, err = out.Write([]byte("owned-" + step.ID))
			return workflowStepExecution{}, err
		})
	if err != nil {
		t.Fatal("valid grouped live workflow refused", err)
	}
	for _, owner := range roots {
		if owner != result.RunID {
			t.Error("live step bound to another workflow", owner, result.RunID)
		}
	}
	if len(roots) != 3 {
		t.Fatal("grouped live work lost selected steps", roots)
	}
}

// full_only: false
func TestWorkflowLiveGroupResolutionKeepsSelection(t *testing.T) {
	root := filepath.Dir(filepath.Dir(filepath.Dir(savedWorkflowPath(t, "live"))))
	var saved workflowFile
	if err := readSelectionFile(savedWorkflowPath(t, "live"), &saved); err != nil {
		t.Fatal(err)
	}
	file := workflowFile{SchemaVersion: 1, Name: "grouped-live"}
	for _, step := range saved.Steps {
		if step.ID != "gcp-recovery-disabled" && step.ID != "aws-recovery-disabled" {
			continue
		}
		step.ParallelGroup = "recovery-disabled"
		step.Environment = filepath.Join(root, "tests/environments", strings.Split(step.ID, "-")[0]+".example.json")
		for i := range step.Suites {
			step.Suites[i] = filepath.Join(root, "tests/workflows", step.Suites[i])
		}
		step.Limits = filepath.Join(root, "tests/workflows", step.Limits)
		step.TelemetryConfig = filepath.Join(root, "tests/telemetry/local.json")
		file.Steps = append(file.Steps, step)
	}
	path := filepath.Join(t.TempDir(), "workflow.json")
	saveSelection(t, path, file)
	for _, selected := range []string{"", "gcp-recovery-disabled"} {
		plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: selected})
		if err != nil || len(plan.Steps) != 2 {
			t.Fatal("explicit live group refused or changed inventory", selected, err)
		}
		for _, step := range plan.Steps {
			if step.Selected && (step.ParallelGroup != "recovery-disabled" || step.Run.RecoveryMode != "disabled") {
				t.Fatal("resolved live selection dropped group or recovery mode", step)
			}
		}
	}
}

// full_only: false

// full_only: false
func TestWorkflowLiveGroupsRejectInvalidMembersBeforeEffects(t *testing.T) {
	for _, condition := range []string{"hermetic", "profile", "race", "limits", "both", "mixed-mode", "mixed-kind", "separated", "repetition"} {
		t.Run(condition, func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := liveGroupPlan(2)
			switch condition {
			case "hermetic":
				plan.Steps[1].Run.Mode = "hermetic"
			case "profile":
				plan.Profile = "dev"
			case "race":
				plan.Steps[1].Run.Race = false
			case "limits":
				plan.Steps[1].Limits.CleanupSeconds = 0
			case "both":
				for i := range plan.Steps[:3] {
					plan.Steps[i].Run.RecoveryMode = "both"
				}
			case "mixed-mode":
				plan.Steps[1].Run.RecoveryMode = "enabled"
			case "mixed-kind":
				plan.Steps[1].Kind, plan.Steps[1].Responsibility = "assembly-checks", "gcp"
			case "separated":
				plan.Steps[1].ParallelGroup = ""
			case "repetition":
				plan.Steps[1].Repetitions = 2
			}
			called := false
			if _, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil, func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
				called = true
				return workflowStepExecution{}, nil
			}); err == nil || called {
				t.Fatal("invalid live group reached execution", condition, err, called)
			}
		})
	}
}
