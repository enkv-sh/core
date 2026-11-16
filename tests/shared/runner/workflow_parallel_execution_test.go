package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func assemblyGroupExecutionPlan(parallel int) workflowPlan {
	policy := executionPolicy{Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 3072}}
	return workflowPlan{Execution: policy, SchemaVersion: 1, Name: "grouped", Profile: "full", Steps: []resolvedWorkflowStep{
		{ID: "assembly-common", Kind: "assembly-checks", Responsibility: "common", ParallelGroup: "assemblies", Selected: true},
		{ID: "assemblies-gcp", Kind: "assembly-checks", Responsibility: "gcp", ParallelGroup: "assemblies", Selected: true},
		{ID: "assemblies-aws", Kind: "assembly-checks", Responsibility: "aws", ParallelGroup: "assemblies", Selected: true},
		{ID: "later", Kind: "unit", Selected: true},
	}}
}

func focusedComponentGroupExecutionPlan(parallel int) workflowPlan {
	plan := assemblyGroupExecutionPlan(parallel)
	plan.Steps = make([]resolvedWorkflowStep, 5)
	plan.Steps[4] = resolvedWorkflowStep{ID: "later", Kind: "unit", Selected: true}
	for i, request := range []string{"TestFirst", "TestSecond/a[1]+b.c#02", "TestThird/leaf", "TestFourth"} {
		plan.Steps[i] = resolvedWorkflowStep{ID: fmt.Sprintf("component-%d", i), Kind: "component-tests", Profile: "full",
			ParallelGroup: "focused", Selected: true, Tests: singleTestRequest(request), Focus: &componentFocus{Tests: singleTestRequest(request)}}
	}
	return plan
}

func assemblyGroupExecutionRoot(t *testing.T) string {
	t.Helper()
	root := workflowExecutionFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func awaitAssemblyGroupValue[T any](t *testing.T, ctx context.Context, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-ctx.Done():
		t.Fatal("controlled assembly group did not reach its barrier", ctx.Err())
		var zero T
		return zero
	}
}

type assemblyGroupCompletion struct {
	result workflowResult
	err    error
}

func awaitWorkflowGroupBarrier[T any](t *testing.T, ctx context.Context, values <-chan T, completed <-chan assemblyGroupCompletion) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case completion := <-completed:
		var failure *checkFailure
		if errors.As(completion.err, &failure) {
			t.Fatalf("controlled workflow stopped before its barrier: %v", failure)
		}
		t.Fatalf("controlled workflow stopped before its barrier: error=%t", completion.err != nil)
	case <-ctx.Done():
		t.Fatal("controlled workflow group did not reach its barrier", ctx.Err())
	}
	var zero T
	return zero
}

// full_only: false
func TestWorkflowAssemblyGroupCapacityOrderAndBarrier(t *testing.T) {
	testWorkflowGroupCapacityOrderAndBarrier(t, assemblyGroupExecutionPlan)
}

// full_only: false
func TestWorkflowLiveGroupCapacityOrderAndBarrier(t *testing.T) {
	testWorkflowGroupCapacityOrderAndBarrier(t, liveGroupPlan)
}

func testWorkflowGroupCapacityOrderAndBarrier(t *testing.T, makePlan func(int) workflowPlan) {
	for _, parallel := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("parallel_%d", parallel), func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := makePlan(parallel)
			groupCount := len(plan.Steps) - 1
			waveSize := min(parallel, groupCount)
			shares := make(map[string]int, groupCount)
			for index, step := range plan.Steps[:groupCount] {
				shares[step.ID] = parallel / waveSize
				if index < parallel%waveSize {
					shares[step.ID]++
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			started := make(chan string, groupCount)
			done := make(chan assemblyGroupCompletion, 1)
			directories := make(chan string, len(plan.Steps))
			releases := map[string]chan struct{}{}
			for _, step := range plan.Steps[:groupCount] {
				releases[step.ID] = make(chan struct{})
			}
			var output bytes.Buffer
			var active, peak, joined atomic.Int32
			var wrongCapacity, missingLease, earlyLater atomic.Bool
			go func() {
				defer close(done)
				result, workflowErr := executeWorkflow(ctx, root, plan, &output, nil, nil, func(child context.Context, step resolvedWorkflowStep, out io.Writer, directory string) (workflowStepExecution, error) {
					directories <- directory
					if step.ID == "later" {
						earlyLater.Store(joined.Load() != int32(groupCount) || active.Load() != 0)
						if executionCapacityFromContext(child) != plan.Execution.Resolved {
							wrongCapacity.Store(true)
							return workflowStepExecution{}, errors.New("later step lost invocation capacity")
						}
						return workflowStepExecution{}, nil
					}
					if executionCapacityFromContext(child) != (executionCapacity{Parallel: shares[step.ID], MemoryLimitMiB: 3072}) {
						wrongCapacity.Store(true)
					}
					if info, err := os.Stat(filepath.Join(root, "core/internal/testmain")); err != nil || !info.IsDir() {
						missingLease.Store(true)
					}
					live := active.Add(1)
					for old := peak.Load(); live > old; old = peak.Load() {
						if peak.CompareAndSwap(old, live) {
							break
						}
					}
					defer func() { active.Add(-1); joined.Add(1) }()
					started <- step.ID
					select {
					case <-releases[step.ID]:
					case <-child.Done():
						return workflowStepExecution{}, child.Err()
					}
					_, err := fmt.Fprintf(out, "callback-%s\n", step.ID)
					return workflowStepExecution{}, err
				})
				done <- assemblyGroupCompletion{result, workflowErr}
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("assembly invocation did not join")
				}
			})
			wave := make([]string, 0, groupCount)
			for range waveSize {
				wave = append(wave, awaitWorkflowGroupBarrier(t, ctx, started, done))
			}
			first := slices.Clone(wave)
			slices.Sort(first)
			want := []string{}
			for _, step := range plan.Steps[:waveSize] {
				want = append(want, step.ID)
			}
			slices.Sort(want)
			if !slices.Equal(first, want) {
				t.Error("group admission changed the planned queue prefix", first, want)
			}
			released := map[string]bool{}
			for len(wave) < groupCount {
				id := wave[len(wave)-waveSize]
				close(releases[id])
				released[id] = true
				wave = append(wave, awaitWorkflowGroupBarrier(t, ctx, started, done))
			}
			for _, id := range wave {
				if !released[id] {
					close(releases[id])
				}
			}
			completion := awaitAssemblyGroupValue(t, ctx, done)
			if completion.err != nil {
				t.Fatal(completion.err)
			}
			if peak.Load() != int32(waveSize) || active.Load() != 0 || joined.Load() != int32(groupCount) || wrongCapacity.Load() || missingLease.Load() || earlyLater.Load() {
				t.Errorf("capacity/lifetime: peak=%d active=%d joined=%d wrong=%t missing=%t early=%t", peak.Load(), active.Load(), joined.Load(), wrongCapacity.Load(), missingLease.Load(), earlyLater.Load())
			}
			result := completion.result
			if result.Outcome != "passed" || len(result.Steps) != len(plan.Steps) {
				t.Fatal("complete grouped result missing", result.Outcome)
			}
			for index, step := range result.Steps {
				if step.ID != plan.Steps[index].ID || step.Outcome != "passed" || step.StartedAt == nil || step.FinishedAt == nil || step.ElapsedSeconds < 0 {
					t.Error("group result lost deterministic scalar order or terminal timing", step)
				}
				if index < groupCount && bytes.Count(output.Bytes(), []byte("callback-"+step.ID+"\n")) != 1 {
					t.Error("group output lost or duplicated a callback", step.ID)
				}
			}
			close(directories)
			for directory := range directories {
				if directory == root || strings.HasPrefix(directory, root+string(filepath.Separator)) {
					t.Error("ordinary callback scratch is inside the checkout", directory)
				}
				if _, err := os.Lstat(directory); !os.IsNotExist(err) {
					t.Error("joined group retained callback scratch", err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "core/internal")); !os.IsNotExist(err) {
				t.Error("joined group did not remove created tool directories", err)
			}
		})
	}
}

type assemblyGroupFailureOutput struct {
	failOn string
	cause  error
}

func (output assemblyGroupFailureOutput) Write(body []byte) (int, error) {
	if strings.Contains(string(body), output.failOn) {
		return 0, output.cause
	}
	return len(body), nil
}

// full_only: false
func TestWorkflowAssemblyGroupFailureCancelsAndJoins(t *testing.T) {
	testWorkflowGroupFailureCancelsAndJoins(t, assemblyGroupExecutionPlan)
}

// full_only: false
func TestWorkflowLiveGroupFailureCancelsAndJoins(t *testing.T) {
	testWorkflowGroupFailureCancelsAndJoins(t, liveGroupPlan)
}

func testWorkflowGroupFailureCancelsAndJoins(t *testing.T, makePlan func(int) workflowPlan) {
	for _, condition := range []string{"callback_failure", "cancellation", "output_failure", "panic", "goexit", "unjoined"} {
		t.Run(condition, func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			plan := makePlan(2)
			guard, guardCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer guardCancel()
			started := make(chan string, 3)
			fail := make(chan struct{})
			cancelled := make(chan struct{})
			joinPeer := make(chan struct{})
			done := make(chan assemblyGroupCompletion, 1)
			directories := make(chan string, len(plan.Steps))
			var called atomic.Int32
			var peerJoined atomic.Bool
			cause := errors.New("synthetic-secret assembly failure")
			var output bytes.Buffer
			var writer io.Writer = &output
			if condition == "output_failure" {
				writer = assemblyGroupFailureOutput{failOn: "controlled-output", cause: cause}
			}
			go func() {
				defer close(done)
				result, workflowErr := executeWorkflow(ctx, root, plan, writer, nil, nil, func(child context.Context, step resolvedWorkflowStep, out io.Writer, directory string) (workflowStepExecution, error) {
					directories <- directory
					called.Add(1)
					started <- step.ID
					if step.ID == plan.Steps[1].ID {
						<-child.Done()
						close(cancelled)
						select {
						case <-joinPeer:
						case <-guard.Done():
						}
						peerJoined.Store(true)
						return workflowStepExecution{}, child.Err()
					}
					if step.ID != plan.Steps[0].ID {
						return workflowStepExecution{}, errors.New("queued step unexpectedly ran")
					}
					select {
					case <-fail:
					case <-child.Done():
						return workflowStepExecution{}, child.Err()
					}
					switch condition {
					case "callback_failure":
						return workflowStepExecution{}, cause
					case "unjoined":
						return workflowStepExecution{}, &toolFailure{operation: "controlled callback", process: processResult{Status: "process_failed", Cause: cause, Joined: false}}
					case "output_failure":
						_, err := io.WriteString(out, "controlled-output\n")
						return workflowStepExecution{}, err
					case "panic":
						panic(cause)
					case "goexit":
						runtime.Goexit()
					}
					return workflowStepExecution{}, child.Err()
				})
				done <- assemblyGroupCompletion{result, workflowErr}
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("failed assembly invocation did not join")
				}
			})
			first := []string{awaitWorkflowGroupBarrier(t, ctx, started, done), awaitWorkflowGroupBarrier(t, ctx, started, done)}
			slices.Sort(first)
			wantPair := []string{plan.Steps[0].ID, plan.Steps[1].ID}
			slices.Sort(wantPair)
			if !slices.Equal(first, wantPair) {
				t.Fatal("wrong admitted assembly pair", first)
			}
			if condition == "cancellation" {
				cancel()
			} else {
				close(fail)
			}
			if condition == "cancellation" {
				select {
				case <-cancelled:
				case <-time.After(10 * time.Second):
					t.Fatal("peer did not receive cancellation")
				}
			} else {
				awaitWorkflowGroupBarrier(t, ctx, cancelled, done)
			}
			select {
			case completion := <-done:
				t.Fatal("workflow returned before active peer joined", completion.err)
			default:
			}
			close(joinPeer)
			var completion assemblyGroupCompletion
			select {
			case completion = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("failed group did not finish")
			}
			err := completion.err
			if err == nil || called.Load() != 2 || !peerJoined.Load() {
				t.Fatal("failure lost cancellation, queued stop or positive callback join", err, called.Load(), peerJoined.Load())
			}
			if condition == "callback_failure" && !errors.Is(err, cause) {
				t.Error("workflow lost the failure cause")
			}
			if strings.Contains(err.Error(), "synthetic-secret") || bytes.Contains(output.Bytes(), []byte("synthetic-secret")) {
				t.Error("raw failure reached public diagnostics")
			}
			result := completion.result
			if result.Outcome != "failed" || result.FinishedAt == nil {
				t.Fatal("failed group did not return terminal workflow")
			}
			for index, step := range result.Steps {
				if index < 2 {
					if step.Outcome != "failed" || step.StartedAt == nil || step.FinishedAt == nil {
						t.Error("started assembly lost failed terminal facts", step)
					}
				} else if step.Outcome != "not_run" || step.StartedAt != nil || step.FinishedAt != nil || step.Log != "" {
					t.Error("queued step gained execution facts", step)
				}
			}
			uncertain := condition == "panic" || condition == "goexit" || condition == "unjoined"
			close(directories)
			for directory := range directories {
				_, statErr := os.Lstat(directory)
				if uncertain {
					if statErr != nil {
						t.Error("uncertain group lost current scratch", statErr)
					}
					t.Cleanup(func() {
						if err := os.RemoveAll(directory); err != nil {
							t.Error("controlled scratch cleanup failed", err)
						}
					})
				} else if !os.IsNotExist(statErr) {
					t.Error("joined failed group retained current scratch", statErr)
				}
			}
			if condition == "panic" || condition == "goexit" || condition == "unjoined" {
				if _, err := os.Stat(filepath.Join(root, "core/internal/testmain")); err != nil {
					t.Error("abnormal callback falsely established tool ownership quiescence", err)
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowAssemblyGroupSingleSelectedKeepsCapacity(t *testing.T) {
	testWorkflowGroupSingleSelectedKeepsCapacity(t, assemblyGroupExecutionPlan)
}

// full_only: false
func TestWorkflowFocusedComponentGroupSingleSelectedKeepsCapacity(t *testing.T) {
	testWorkflowGroupSingleSelectedKeepsCapacity(t, focusedComponentGroupExecutionPlan)
}

func testWorkflowGroupSingleSelectedKeepsCapacity(t *testing.T, makePlan func(int) workflowPlan) {
	root := assemblyGroupExecutionRoot(t)
	plan := makePlan(4)
	for index := range plan.Steps {
		if index != 1 {
			plan.Steps[index].Selected = false
			plan.Steps[index].ParallelGroup = ""
		}
	}
	var calls []string
	var output bytes.Buffer
	result, err := executeWorkflow(t.Context(), root, plan, &output, nil, nil, func(ctx context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
		calls = append(calls, step.ID)
		if executionCapacityFromContext(ctx) != plan.Execution.Resolved {
			return workflowStepExecution{}, errors.New("single selected assembly lost full invocation capacity")
		}
		return workflowStepExecution{}, nil
	})
	if err != nil || !slices.Equal(calls, []string{plan.Steps[1].ID}) {
		t.Fatal("single-step group selection changed execution", calls, err)
	}
	for index, step := range result.Steps {
		if index == 1 {
			if step.Outcome != "passed" || step.StartedAt == nil {
				t.Error("selected singleton lost completion", step)
			}
		} else if step.Outcome != "not_selected" || step.StartedAt != nil || step.Log != "" {
			t.Error("group selected an unrequested peer", step)
		}
	}
}

// full_only: false
func TestWorkflowAssemblyGroupLeaseCleanupAndEarlyOutputFailure(t *testing.T) {
	testWorkflowGroupLeaseCleanupAndEarlyOutputFailure(t, assemblyGroupExecutionPlan)
}

// full_only: false
func TestWorkflowFocusedComponentGroupLeaseCleanupAndEarlyOutputFailure(t *testing.T) {
	testWorkflowGroupLeaseCleanupAndEarlyOutputFailure(t, focusedComponentGroupExecutionPlan)
}

func testWorkflowGroupLeaseCleanupAndEarlyOutputFailure(t *testing.T, makePlan func(int) workflowPlan) {
	for _, condition := range []string{"cleanup_failure", "output_before_dispatch", "cancel_before_dispatch"} {
		t.Run(condition, func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := makePlan(3)
			var calls atomic.Int32
			var output bytes.Buffer
			var writer io.Writer = &output
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if condition == "output_before_dispatch" {
				writer = assemblyGroupFailureOutput{failOn: "Step ", cause: errors.New("controlled output refusal")}
			}
			if condition == "cancel_before_dispatch" {
				cancel()
			}
			if condition == "cleanup_failure" {
				// Fixture metadata keeps the unexpected directory entry outside
				// source identity, so cleanup is the only failing boundary.
				if err := os.WriteFile(filepath.Join(root, ".git/info/exclude"), []byte("core/internal/testmain/unexpected\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := executeWorkflow(ctx, root, plan, writer, nil, nil, func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
				calls.Add(1)
				if condition == "cleanup_failure" && step.ID == plan.Steps[0].ID {
					return workflowStepExecution{}, os.WriteFile(filepath.Join(root, "core/internal/testmain", "unexpected"), []byte("retained fixture"), 0600)
				}
				return workflowStepExecution{}, nil
			})
			if err == nil {
				t.Fatal("boundary failure passed")
			}
			if condition != "cleanup_failure" && calls.Load() != 0 {
				t.Error("failed admission output or cancellation started callbacks", calls.Load())
			}
			if condition == "cleanup_failure" && calls.Load() != int32(len(plan.Steps)-1) {
				t.Error("group did not finish all jobs before cleanup refusal", calls.Load())
			}
			if condition == "cancel_before_dispatch" {
				paths, err := filepath.Glob(filepath.Join(root, "tests/workflows/runs/*/*/workflow.json"))
				if err != nil || len(paths) != 0 {
					t.Error("pre-cancelled workflow published execution evidence", paths, err)
				}
				return
			}
			if result.Outcome != "failed" || result.Steps[len(plan.Steps)-1].Outcome != "not_run" {
				t.Error("group boundary failure continued workflow", result)
			}
			if condition == "cleanup_failure" && result.Failure == "source_changed" {
				t.Error("cleanup fixture accidentally exercised source change")
			}
			if condition == "cleanup_failure" {
				for _, step := range result.Steps[:len(plan.Steps)-1] {
					if step.Outcome != "passed" || step.FinishedAt == nil {
						t.Error("cleanup failure overwrote completed callback facts", step)
					}
				}
				if _, err := os.Lstat(filepath.Join(root, "core/internal/testmain", "unexpected")); err != nil {
					t.Error("unexpected tool content was removed", err)
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowFocusedComponentGroupCapacityOrderAndBarrier(t *testing.T) {
	testWorkflowGroupCapacityOrderAndBarrier(t, focusedComponentGroupExecutionPlan)
}

// full_only: false
func TestWorkflowFocusedComponentGroupFailureCancelsAndJoins(t *testing.T) {
	testWorkflowGroupFailureCancelsAndJoins(t, focusedComponentGroupExecutionPlan)
}
