package main

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"time"
)

// The existing finish callback models the owning terminal checkpoint failure.
// No provider effect or physical process result is supplied by this control.
// full_only: false
func TestWorkflowLiveTerminalSaveFailureStopsQueuedMember(t *testing.T) {
	root := assemblyGroupExecutionRoot(t)
	plan := liveGroupPlan(1)
	ctx, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), plan.Execution), 10*time.Second)
	defer cancel()
	failure := errors.New("controlled live terminal checkpoint failure")
	var started, executed, finished []int
	joined, err := executeWorkflowGroup(ctx, root, plan.Steps[:3], 0, "",
		func(index int) (io.Writer, error) { started = append(started, index); return io.Discard, nil },
		func(index int, _ workflowStepExecution, err error) error {
			finished = append(finished, index)
			return errors.Join(err, failure)
		},
		func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
			for index, candidate := range plan.Steps[:3] {
				if candidate.ID == step.ID {
					executed = append(executed, index)
				}
			}
			return workflowStepExecution{}, nil
		})
	if !joined || !errors.Is(err, failure) || !slices.Equal(started, []int{0}) || !slices.Equal(executed, []int{0}) || !slices.Equal(finished, []int{0}) {
		t.Fatal("live checkpoint failure admitted queued member or lost failure", joined, err, started, executed, finished)
	}
}
