package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

func validateConfiguredParallelGroups(steps []workflowStep) error {
	return validateParallelGroups(steps, 2)
}

func validateResolvedParallelGroups(plan workflowPlan) error {
	configured := make([]workflowStep, len(plan.Steps))
	for i, step := range plan.Steps {
		member := workflowStep{ParallelGroup: step.ParallelGroup, Kind: step.Kind, Responsibility: step.Responsibility}
		if step.ParallelGroup != "" {
			if err := validateExecutionCapacity(plan.Execution.Resolved); err != nil {
				return err
			}
			if !step.Selected || step.Repetitions != 0 || step.Repetition != 0 {
				return errors.New("parallel groups require selected, unrepeated steps")
			}
			if step.Kind == "component-tests" {
				if step.Focus == nil {
					return errors.New("component groups require a literal ordinary focus")
				}
				member.Tests, member.Profile = slices.Clone(step.Tests), step.Profile
			}
			if step.Kind == "run" {
				if plan.Profile != "full" || step.Run == nil || step.Run.Mode != "live" || step.Run.Profile != "full" ||
					step.Run.Race != plan.Race || step.Limits == nil || !step.Limits.valid() {
					return errors.New("live groups require full live runs with the invocation race policy with finite limits")
				}
				member.RecoveryMode, member.Limits = step.Run.RecoveryMode, "resolved"
			}
		}
		configured[i] = member
	}
	// A literal --step selection can leave just one configured group member.
	return validateParallelGroups(configured, 1)
}

func validateParallelGroups(steps []workflowStep, minimum int) error {
	return validateWorkflowParallelGroups(steps, minimum, func(name string) bool {
		return componentFocusProcessClass(name) == "ordinary"
	})
}

type workflowOutputWriter func([]byte) (int, error)

func (writer workflowOutputWriter) Write(data []byte) (int, error) { return writer(data) }

type workflowGroupWrite struct {
	index int
	data  []byte
	reply chan workflowGroupWriteResult
}

type workflowGroupWriteResult struct {
	n   int
	err error
}

type workflowGroupWriter struct {
	index    int
	requests chan<- workflowGroupWrite
}

func (writer workflowGroupWriter) Write(data []byte) (int, error) {
	reply := make(chan workflowGroupWriteResult)
	writer.requests <- workflowGroupWrite{index: writer.index, data: data, reply: reply}
	result := <-reply
	return result.n, result.err
}

type workflowGroupCompletion struct {
	index     int
	share     int
	execution workflowStepExecution
	err       error
	returned  bool
}

// The workflow owner publishes every step transition and handles output while
// callbacks run. It drains started callbacks even after cancellation or a write
// failure, before releasing the shared physical overlay directories.
func executeWorkflowGroup(parent context.Context, root string, steps []resolvedWorkflowStep, offset int, directory string,
	start func(int) (io.Writer, error), finish func(int, workflowStepExecution, error) error,
	execute func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error),
) (joined bool, err error) {
	joined = true
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	capacity := executionCapacityFromContext(ctx)
	if err := validateExecutionCapacity(capacity); err != nil {
		return joined, err
	}
	if len(steps) == 0 {
		return joined, nil
	}
	phase, _ := ctx.Value(toolDirectoryPhaseContextKey{}).(*toolDirectoryPhase)
	if phase == nil || phase.lease != nil {
		reportJoin, borrowed, borrowErr := borrowToolDirectoryPhase(ctx, root)
		if borrowErr != nil {
			return joined, borrowErr
		}
		var phase *toolDirectoryPhase
		if !borrowed {
			locks, lockErr := resourceLocksFromContext(ctx)
			if lockErr != nil {
				return joined, lockErr
			}
			ctx, phase, err = prepareToolDirectoryPhase(ctx, locks, root)
			if err != nil {
				return joined, err
			}
		}
		defer func() {
			settled := joined && toolCommandsJoined(err)
			if reportJoin != nil {
				reportJoin(settled)
			}
			if phase != nil {
				finish, release := finalizationContext(ctx)
				err = errors.Join(err, phase.Release(finish, settled))
				release()
			}
		}()
	}

	workers := min(capacity.Parallel, len(steps))
	shares := make([]int, workers)
	for i := range shares {
		shares[i] = capacity.Parallel / workers
		if i < capacity.Parallel%workers {
			shares[i]++
		}
	}
	writes := make(chan workflowGroupWrite)
	completed := make(chan workflowGroupCompletion, len(steps))
	outputs := make(map[int]io.Writer)
	results := make([]*workflowGroupCompletion, len(steps))
	live := steps[0].Kind == "run" && steps[0].Run != nil && steps[0].Run.Mode == "live"
	var outputErr error
	var failures []error
	retain := func(cause error) {
		if cause == nil {
			return
		}
		failures = append(failures, cause)
		if !containedCheckFailure(ctx, cause) {
			cancel()
		}
	}
	nextFinish := 0
	next, active := 0, 0
	stopped := ctx.Done()
	for next < len(steps) || active != 0 {
		for next < len(steps) && len(shares) != 0 && ctx.Err() == nil {
			index := next
			share := shares[0]
			shares = shares[1:]
			out, startErr := start(offset + index)
			if startErr != nil {
				failures = append(failures, startErr)
				cancel()
				break
			}
			outputs[index] = out
			next++
			active++
			go func() {
				result := workflowGroupCompletion{index: index, share: share}
				defer func() {
					if !result.returned {
						result.err = fmt.Errorf("workflow group callback did not return: %v", recover())
					}
					if !workflowExecutionJoined(result.execution, result.err) {
						result.err = errors.Join(result.err, errors.New("workflow has an unjoined consumer"))
					}
					if result.err != nil && (!containedCheckFailure(ctx, result.err)) {
						cancel()
					}
					result.execution.finishedAt = time.Now().UTC()
					completed <- result
				}()
				child := withExecutionParallel(ctx, share)
				step := steps[index]
				step.request.execution = step.request.execution.clone()
				step.request.execution.Resolved = executionCapacityFromContext(child)
				result.execution, result.err = execute(child, step, workflowGroupWriter{index: index, requests: writes}, directory)
				result.returned = true
			}()
		}
		if active == 0 {
			break
		}
		select {
		case request := <-writes:
			var n int
			if outputErr == nil {
				n, outputErr = outputs[request.index].Write(request.data)
				if n != len(request.data) && outputErr == nil {
					outputErr = io.ErrShortWrite
				}
				if outputErr != nil {
					failures = append(failures, outputErr)
					cancel()
				}
			}
			request.reply <- workflowGroupWriteResult{n: n, err: outputErr}
		case result := <-completed:
			active--
			shares = append(shares, result.share)
			joined = joined && result.returned && workflowExecutionJoined(result.execution, result.err)
			if live {
				retain(finish(offset+result.index, result.execution, result.err))
			} else {
				results[result.index] = &result
				for nextFinish < len(results) && results[nextFinish] != nil {
					ready := results[nextFinish]
					retain(finish(offset+nextFinish, ready.execution, ready.err))
					results[nextFinish] = nil
					nextFinish++
				}
			}
			delete(outputs, result.index)
		case <-stopped:
			stopped = nil
		}
	}
	for index, result := range results {
		if result != nil {
			retain(finish(offset+index, result.execution, result.err))
		}
	}
	return joined, errors.Join(append(failures, ctx.Err())...)
}
