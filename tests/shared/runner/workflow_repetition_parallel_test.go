package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// Scalar callback controls establish queue and result ownership, not OS joins.
func repetitionControlEvidence(kind string, joined bool) workflowStepExecution {
	diagnostics := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{{Phase: "test", Scope: "controlled-repetition", Process: "passed", Started: true, Joined: joined, Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"}}}
	if kind == "component-tests" {
		return workflowStepExecution{Component: &componentRunRecord{Checks: &checkEvidence{Diagnostics: diagnostics}}}
	}
	return workflowStepExecution{Ordinary: &ordinaryStepEvidence{Diagnostics: diagnostics}}
}

// full_only: false
func TestWorkflowRepetitionsShareAllowanceAndKeepSelectedOrder(t *testing.T) {
	for _, kind := range []string{"unit", "runner-tests", "component-tests"} {
		t.Run(kind, func(t *testing.T) {
			for _, parallel := range []int{1, 2, 4} {
				t.Run(fmt.Sprintf("parallel_%d", parallel), func(t *testing.T) {
					root := assemblyGroupExecutionRoot(t)
					steps := expandWorkflowRepetitions(resolvedWorkflowStep{ID: "repeated", Kind: kind, Selected: true}, 4)
					steps = append(steps, resolvedWorkflowStep{ID: "later", Kind: "unit", Selected: true})
					plan := workflowPlan{Execution: executionPolicy{Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 3072}}, Name: "repetition-capacity", Profile: "dev", Steps: steps}
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					started := make(chan int, 4)
					departed := make(chan int, 4)
					done := make(chan assemblyGroupCompletion, 1)
					gates := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})}
					var activeShares, peakShares, activeJobs, joined atomic.Int32
					var badCapacity, earlyLater atomic.Bool
					var output bytes.Buffer
					go func() {
						defer close(done)
						result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(child context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
							if step.ID == "later" {
								earlyLater.Store(joined.Load() != 4 || activeJobs.Load() != 0)
								return workflowStepExecution{}, nil
							}
							share := executionCapacityFromContext(child).Parallel
							if share < 1 || executionCapacityFromContext(child).MemoryLimitMiB != 3072 {
								badCapacity.Store(true)
							}
							now := activeShares.Add(int32(share))
							activeJobs.Add(1)
							for old := peakShares.Load(); now > old; old = peakShares.Load() {
								if peakShares.CompareAndSwap(old, now) {
									break
								}
							}
							defer func() {
								activeShares.Add(-int32(share))
								activeJobs.Add(-1)
								joined.Add(1)
								departed <- step.Repetition
							}()
							started <- step.Repetition
							select {
							case <-gates[step.Repetition-1]:
							case <-child.Done():
								return repetitionControlEvidence(kind, true), child.Err()
							}
							return repetitionControlEvidence(kind, true), nil
						})
						done <- assemblyGroupCompletion{result, err}
					}()
					t.Cleanup(func() {
						cancel()
						select {
						case <-done:
						case <-time.After(10 * time.Second):
							t.Error("repetition invocation did not settle")
						}
					})
					wave := make([]int, 0, 4)
					for range parallel {
						wave = append(wave, awaitAssemblyGroupValue(t, ctx, started))
					}
					first := slices.Clone(wave)
					slices.Sort(first)
					wantFirst := []int{1}
					if parallel == 2 {
						wantFirst = []int{1, 2}
					}
					if parallel == 4 {
						wantFirst = []int{1, 2, 3, 4}
					}
					if !slices.Equal(first, wantFirst) {
						t.Fatal("wrong admitted repetition prefix", first, wantFirst)
					}
					released := map[int]bool{}
					for len(wave) < 4 {
						rep := wave[len(wave)-parallel]
						close(gates[rep-1])
						released[rep] = true
						if got := awaitAssemblyGroupValue(t, ctx, departed); got != rep {
							t.Fatal("controlled release changed callback completion", got, rep)
						}
						wave = append(wave, awaitAssemblyGroupValue(t, ctx, started))
					}
					// At four slots the highest-numbered borrower returns while all earlier
					// borrowers still hold the shared lifetime.
					var finalOrder []int
					for rep := 4; rep >= 1; rep-- {
						if !released[rep] {
							close(gates[rep-1])
							finalOrder = append(finalOrder, awaitAssemblyGroupValue(t, ctx, departed))
						}
					}
					wantOrder := []int{4}
					if parallel == 2 {
						wantOrder = []int{4, 3}
					}
					if parallel == 4 {
						wantOrder = []int{4, 3, 2, 1}
					}
					if !slices.Equal(finalOrder, wantOrder) {
						t.Fatal("last held callbacks did not finish in reverse selection order", finalOrder, wantOrder)
					}
					completion := awaitAssemblyGroupValue(t, ctx, done)
					if completion.err != nil {
						t.Fatal(completion.err, output.String())
					}
					if activeShares.Load() != 0 || activeJobs.Load() != 0 || peakShares.Load() != int32(parallel) || joined.Load() != 4 || badCapacity.Load() || earlyLater.Load() {
						t.Fatal("repetition allowance or step barrier failed", activeShares.Load(), peakShares.Load(), joined.Load(), badCapacity.Load(), earlyLater.Load())
					}
					result := completion.result
					if result.Outcome != "passed" || len(result.RepetitionGroups) != 1 {
						t.Fatal("missing completed repetition result", result)
					}
					group := result.RepetitionGroups[0]
					if group.RequestedExecutions != 4 || group.CompletedExecutions != 4 || group.Outcome != "passed" || !slices.Equal(group.StepIDs, []string{"repeated-r1", "repeated-r2", "repeated-r3", "repeated-r4"}) {
						t.Fatal("N/K or selected order changed", group)
					}
					for index, step := range result.Steps {
						if step.ID != steps[index].ID || step.Outcome != "passed" || step.StartedAt == nil || step.FinishedAt == nil {
							t.Error("scalar result lost ordered terminal", step)
						}
						if parallel == 1 && index > 0 && result.Steps[index-1].FinishedAt != nil && step.StartedAt != nil && result.Steps[index-1].FinishedAt.After(*step.StartedAt) {
							t.Error("serial callback intervals falsely overlap", result.Steps[index-1], step)
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestWorkflowRepetitionFailureCancelsPeersAndKeepsQueuedNotRun(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprintf("uncertain_%t", uncertain), func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			steps := expandWorkflowRepetitions(resolvedWorkflowStep{ID: "repeated", Kind: "unit", Selected: true}, 4)
			steps = append(steps, resolvedWorkflowStep{ID: "later", Kind: "unit", Selected: true})
			plan := workflowPlan{Execution: executionPolicy{Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 3072}}, Name: "repetition-failure", Profile: "dev", Steps: steps}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			secondStarted := make(chan struct{})
			failure := errors.New("selected repetition one failed")
			peerFailure := errors.New("selected repetition two returned after cancellation")
			var calls, settled atomic.Int32
			var output bytes.Buffer
			result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(child context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
				calls.Add(1)
				defer settled.Add(1)
				switch step.Repetition {
				case 1:
					select {
					case <-secondStarted:
					case <-child.Done():
						return repetitionControlEvidence("unit", true), child.Err()
					}
					return repetitionControlEvidence("unit", true), failure
				case 2:
					close(secondStarted)
					<-child.Done()
					return repetitionControlEvidence("unit", !uncertain), peerFailure
				default:
					return workflowStepExecution{}, errors.New("queued work started")
				}
			})
			if !errors.Is(err, failure) || !errors.Is(err, peerFailure) || calls.Load() != 2 || settled.Load() != 2 || result.Outcome != "failed" {
				t.Fatal("failure lost peers or started queued work", err, calls.Load(), settled.Load())
			}
			for _, step := range result.Steps[:2] {
				if step.Outcome != "failed" || step.StartedAt == nil || step.FinishedAt == nil {
					t.Error("started failure disappeared", step)
				}
			}
			for _, step := range result.Steps[2:] {
				if step.Outcome != "not_run" || step.StartedAt != nil || step.FinishedAt != nil {
					t.Error("queued work gained an execution", step)
				}
			}
			if len(result.RepetitionGroups) != 1 {
				t.Fatal("missing failed repetition group", result.RepetitionGroups)
			}
			group := result.RepetitionGroups[0]
			wantK := 2
			if uncertain {
				wantK = 1
			}
			if group.RequestedExecutions != 4 || group.CompletedExecutions != wantK || group.Outcome != "failed" || !slices.Equal(group.StepIDs, []string{"repeated-r1", "repeated-r2"}) {
				t.Fatal("failed repetitions changed N/K or ordered attempts", group)
			}
		})
	}
}

// full_only: false
func TestWorkflowGroupFoldsReverseCompletionInSelectedOrder(t *testing.T) {
	root := assemblyGroupExecutionRoot(t)
	parent := withExecutionCapacity(context.Background(), executionPolicy{Resolved: executionCapacity{Parallel: 4, MemoryLimitMiB: 3072}})
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	steps := expandWorkflowRepetitions(resolvedWorkflowStep{ID: "repeated", Kind: "component-tests", Selected: true}, 8)
	started := make(chan int, 8)
	gates := make([]chan struct{}, 8)
	for i := range gates {
		gates[i] = make(chan struct{})
	}
	done := make(chan error, 1)
	var order []int
	go func() {
		defer close(done)
		_, err := executeWorkflowGroup(ctx, root, steps, 0, "", func(int) (io.Writer, error) { return io.Discard, nil },
			func(index int, _ workflowStepExecution, err error) error { order = append(order, index+1); return err },
			func(child context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
				started <- step.Repetition
				select {
				case <-gates[step.Repetition-1]:
				case <-child.Done():
					return workflowStepExecution{}, child.Err()
				}
				return repetitionControlEvidence("component-tests", true), nil
			})
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("reverse completion did not settle")
		}
	})
	first := []int{}
	for range 4 {
		first = append(first, awaitAssemblyGroupValue(t, ctx, started))
	}
	slices.Sort(first)
	if !slices.Equal(first, []int{1, 2, 3, 4}) {
		t.Fatal("wrong initial queue prefix", first)
	}
	// Each new admission proves that the coordinator consumed the released
	// callback's completion before the next controlled callback is released.
	for rep := 4; rep >= 1; rep-- {
		close(gates[rep-1])
		if got := awaitAssemblyGroupValue(t, ctx, started); got != 9-rep {
			t.Fatal("controlled reverse completion changed queue order", got, 9-rep)
		}
	}
	for rep := 5; rep <= 8; rep++ {
		close(gates[rep-1])
	}
	if err := awaitAssemblyGroupValue(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("coordinator folded callback completion order", order)
	}
}
