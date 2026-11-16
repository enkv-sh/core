package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// full_only: false
func TestPreparedWorkflowDiagnosticsPreserveJoinedFailure(t *testing.T) {
	ctx := withRacePolicy(t.Context(), false)
	ctx, artifacts := withInvocationArtifacts(ctx)
	t.Cleanup(func() {
		if err := artifacts.close(t.Context(), true); err != nil {
			t.Error(err)
		}
	})
	plan := workflowPlan{SchemaVersion: 1, Name: "diagnostic-fold", Profile: "dev"}
	for i := range 101 {
		plan.Steps = append(plan.Steps, resolvedWorkflowStep{ID: fmt.Sprintf("phase-%03d", i), Kind: "unit", Selected: true})
	}
	owner := &preparedWorkflow{assemblyPreparations: ctx, binding: preparationBinding{ctx: ctx, race: false}, plan: plan, planIdentity: "different-plan-identity", joined: true}
	var result workflowResult
	err := owner.verifyResult(ctx, t.TempDir(), &result, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "prepared workflow selection changed") {
		t.Fatalf("fixture did not reach plan-identity refusal: %v", err)
	}
	if len(result.executions) != len(plan.Steps) || !owner.joined || !toolCommandsJoined(err) {
		t.Fatalf("joined refusal lost execution or settlement facts: executions=%d joined=%t error=%v", len(result.executions), owner.joined, err)
	}
}

type failureChildren []error

func (failureChildren) Error() string            { return "failure branches" }
func (children failureChildren) Unwrap() []error { return children }

// full_only: false
func TestDeepFailureTreesPreserveJoinAndContainment(t *testing.T) {
	parent := context.Background()
	exit := &exec.ExitError{}
	valid := processResult{Status: "process_failed", Started: true, Joined: true, Cause: exit}
	for _, depth := range []int{0, 62, 63, 64, 65, 257} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			for _, row := range []struct {
				name              string
				leaf              error
				joined, contained bool
			}{
				{"settled", &toolFailure{process: valid}, true, true},
				{"unjoined", &toolFailure{process: processResult{Status: "process_failed", Started: true, Cause: exit}}, false, false},
				{"unknown", errors.New("unknown failure"), true, false},
				{"cleanup", &toolFailure{process: valid, cleanup: errors.New("cleanup failed")}, true, false},
				{"overflow", &toolFailure{process: valid, overflow: true}, true, false},
				{"observation", &toolFailure{process: processResult{Status: "process_failed", Started: true, Joined: true, Cause: errors.Join(exit, errors.New("observation failed"))}}, true, false},
				{"source-unjoined", &sourceCommandFailure{process: processResult{Started: true}}, false, false},
			} {
				t.Run(row.name, func(t *testing.T) {
					cause := row.leaf
					for range depth {
						cause = fmt.Errorf("wrapped: %w", cause)
					}
					for position := range 3 {
						good := &toolFailure{process: valid}
						branches := failureChildren{nil, good, good, good, nil}
						branches[position+1] = cause
						classified := containProcessFailure(parent, branches)
						if toolCommandsJoined(branches) != row.joined || containedCheckFailure(parent, classified) != row.contained || !errors.Is(classified, row.leaf) {
							t.Fatalf("branch %d lost original failure, join or containment", position)
						}
						if row.contained {
							var original *toolFailure
							if !errors.As(classified, &original) || original == nil {
								t.Fatal("contained failure lost typed cause")
							}
							cancelled, cancel := context.WithCancel(parent)
							cancel()
							if containedCheckFailure(cancelled, classified) {
								t.Fatal("parent cancellation permitted continuation")
							}
						}
					}
				})
			}
		})
	}
	if containedCheckFailure(parent, failureChildren{nil}) || containedCheckFailure(parent, containProcessFailure(parent, failureChildren{nil})) {
		t.Fatal("empty branches supplied containment evidence")
	}
}
