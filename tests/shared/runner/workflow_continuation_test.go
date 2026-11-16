package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// full_only: false
func TestWorkflowContinuesContainedFailures(t *testing.T) {
	for _, parallel := range []int{1, 2} {
		t.Run(fmt.Sprintf("parallel-%d", parallel), func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := focusedComponentGroupExecutionPlan(parallel)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			firstFailure, laterFailure := errors.New("first assertion failed"), errors.New("later assertion failed")
			healthyStarted, laterStarted := make(chan struct{}), make(chan struct{})
			var mu sync.Mutex
			attempts := map[string]int{}
			var output bytes.Buffer
			result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(child context.Context, step resolvedWorkflowStep, out io.Writer, directory string) (workflowStepExecution, error) {
				mu.Lock()
				attempts[step.ID]++
				mu.Unlock()
				switch step.ID {
				case "component-0":
					if parallel > 1 {
						select {
						case <-healthyStarted:
						case <-child.Done():
							return workflowStepExecution{}, child.Err()
						}
					}
					return workflowStepExecution{}, &localCheckFailure{cause: firstFailure}
				case "component-1":
					close(healthyStarted)
					if parallel > 1 {
						select {
						case <-laterStarted:
						case <-child.Done():
							return workflowStepExecution{}, child.Err()
						}
					}
				case "component-2":
					close(laterStarted)
					return workflowStepExecution{}, &localCheckFailure{cause: laterFailure}
				}
				return workflowStepExecution{}, child.Err()
			})
			if !errors.Is(err, firstFailure) || !errors.Is(err, laterFailure) || result.Outcome != "failed" {
				t.Fatal("workflow did not preserve both failures", err, result.Steps)
			}
			for index, step := range result.Steps {
				want := "passed"
				if index == 0 || index == 2 {
					want = "failed"
				}
				if attempts[step.ID] != 1 || step.Outcome != want || step.FinishedAt == nil {
					t.Fatal("independent step lost, repeated or reordered", step.ID, attempts, result.Steps)
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowFailureSettlementKeepsIndependentOwners(t *testing.T) {
	t.Run("private_owners", func(t *testing.T) {
		root := assemblyGroupExecutionRoot(t)
		var owned []privateDirectory
		for range 96 {
			owner, err := createPrivateDirectory("", "hermetic", "00112233445566778899aabbccddeeff", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			owned = append(owned, owner)
		}
		failure := errors.New("private owner assertion failed")
		_, err := executeWorkflow(t.Context(), root, assemblyGroupExecutionPlan(1), io.Discard, &owned, nil,
			func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
				return workflowStepExecution{}, &localCheckFailure{cause: failure}
			})
		if !errors.Is(err, failure) || !toolCommandsJoined(err) {
			t.Fatal("private owner count changed settled failure", err)
		}
		for _, owner := range owned {
			if _, err := os.Lstat(owner.path); !os.IsNotExist(err) {
				t.Fatal("settled private owner was not removed", err)
			}
		}
	})
	for _, owners := range []int{1, 96} {
		for _, unjoined := range []bool{false, true} {
			t.Run(fmt.Sprintf("owners_%d/unjoined_%t", owners, unjoined), func(t *testing.T) {
				root := assemblyGroupExecutionRoot(t)
				plan := assemblyGroupExecutionPlan(1)
				failure, cleanupFailure := errors.New("local assertion failed"), errors.New("cleanup settlement unavailable")
				groups := map[string]*preparedOrdinaryGroup{}
				closed, leases := 0, 0
				for index := range owners {
					groups[fmt.Sprint(index)] = &preparedOrdinaryGroup{ctx: t.Context(), joined: true,
						cancel: func() { closed++ },
						lease: func(context.Context, bool) error {
							leases++
							if unjoined && index == owners-1 {
								return &toolFailure{operation: "cleanup", process: processResult{Status: "unknown", Started: true, Joined: false, Cause: cleanupFailure}}
							}
							return nil
						}}
				}
				calls := 0
				result, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, groups,
					func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
						calls++
						return workflowStepExecution{}, &localCheckFailure{cause: failure}
					})
				if !errors.Is(err, failure) || result.Outcome != "failed" || calls != len(plan.Steps) || closed != owners || leases != owners {
					t.Fatalf("failed result or owner close lost: calls=%d closed=%d leases=%d result=%s error=%v", calls, closed, leases, result.Outcome, err)
				}
				if toolCommandsJoined(err) == unjoined || errors.Is(err, cleanupFailure) != unjoined {
					t.Fatalf("owner count changed settlement or cleanup cause: joined=%t error=%v", toolCommandsJoined(err), err)
				}
			})
		}
	}
}

// full_only: false
func TestMixedLiveWorkflowContinuesContainedLocalFailures(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(fmt.Sprintf("grouped-%t", grouped), func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := assemblyGroupExecutionPlan(1)
			if !grouped {
				plan.Steps = plan.Steps[:1]
				plan.Steps[0].ParallelGroup = ""
			}
			live := liveGroupPlan(1).Steps[0]
			live.ID, live.ParallelGroup = "live-later", ""
			plan.Steps = append(plan.Steps, live)
			cause := errors.New("contained local assertion")
			var steps, bodies []string
			var output bytes.Buffer
			result, err := executeWorkflow(t.Context(), root, plan, &output, nil, nil,
				func(ctx context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
					steps = append(steps, step.ID)
					if step.ID != plan.Steps[0].ID {
						return workflowStepExecution{}, nil
					}
					var evidence ordinaryStepEvidence
					err := runRunnerGroups(ctx, []runnerGroup{{Name: "first"}, {Name: "queued"}}, io.Discard, &evidence,
						func(_ context.Context, group runnerGroup) (ordinaryStepEvidence, error) {
							bodies = append(bodies, group.Name)
							if group.Name == "first" {
								return unitModuleTerminal(group.Name), &localCheckFailure{cause: cause}
							}
							return unitModuleTerminal(group.Name), nil
						})
					return workflowStepExecution{}, err
				})
			wantSteps := make([]string, len(plan.Steps))
			for index, step := range plan.Steps {
				wantSteps[index] = step.ID
			}
			if !errors.Is(err, cause) || result.Outcome != "failed" || !toolCommandsJoined(err) || !slices.Equal(steps, wantSteps) || !slices.Equal(bodies, []string{"first", "queued"}) || len(result.Steps) != len(plan.Steps) {
				t.Fatal("mixed workflow lost its failure or independent work", steps, bodies, err, result.Outcome)
			}
			for index, step := range result.Steps {
				want := "passed"
				if index == 0 {
					want = "failed"
				}
				if step.ID != wantSteps[index] || step.Outcome != want || step.StartedAt == nil || step.FinishedAt == nil {
					t.Fatal("mixed workflow lost an actual independent-step terminal", step)
				}
			}
			if err.Error() != "check failed; phase=workflow; diagnostics: no durable run owner" || strings.Contains(output.String(), cause.Error()) {
				t.Fatal("mixed live workflow exposed the original local failure")
			}
		})
	}
}

// full_only: false
func TestPreparedOrdinaryVerificationKeepsCacheOnlyEnvironment(t *testing.T) {
	ctx, root, bootstrap, marker, workflow, _ := completePreparationFixture(t, "")
	t.Setenv("GONOPROXY", "*")
	var output bytes.Buffer
	if err := runCommand(ctx, root, bootstrap, []string{"run", "--workflow", workflow}, &output); err != nil {
		t.Fatal("verification lost preparation's cache-only environment", err, output.String())
	}
	body, err := os.ReadFile(marker)
	if err != nil || string(body) != "1" {
		t.Fatal("prepared body did not execute", string(body), err)
	}
}

// full_only: false
func TestWorkflowComponentReuseRequiresPassingOwner(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed-%t", failed), func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			source, err := sourceRevision(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			_, full := completeRunFixture(t, "memory")
			owner := &componentRun{record: *full.Correctness.ComponentRun}
			owner.record.Source = source
			if !owner.record.passedFor(source, owner.record.Toolchain) {
				t.Fatal("passing owner fixture invalid")
			}
			plan := assemblyGroupExecutionPlan(1)
			plan.Race = owner.record.BuildClosure.Race
			plan.Steps = []resolvedWorkflowStep{
				{ID: "components", Kind: "component-tests", Selected: true},
				{ID: "scenario", Kind: "run", Selected: true, request: runRequest{Suite: "hermetic"}},
			}
			cause := errors.New("component assertion failed")
			calls := 0
			result, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil,
				func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
					calls++
					if step.ID == "components" {
						if failed {
							owner.record.Outcome = "failed"
							return workflowStepExecution{componentOwner: owner, Component: &owner.record}, &localCheckFailure{cause: cause}
						}
						return workflowStepExecution{componentOwner: owner, Component: &owner.record}, nil
					}
					if failed && step.request.components != nil || !failed && step.request.components != owner {
						t.Fatal("scenario received wrong component proof", failed)
					}
					return workflowStepExecution{}, nil
				})
			if calls != 2 || result.Steps[1].Outcome != "passed" || failed && (!errors.Is(err, cause) || result.Steps[0].Outcome != "failed" || result.executions["components"].Component.Outcome != "failed") || !failed && err != nil {
				t.Fatal("workflow lost failed component or later scenario", calls, result.Steps, err)
			}
		})
	}
}
