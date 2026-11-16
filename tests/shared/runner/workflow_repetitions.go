package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"

	records "enkv.sh/core/internal/testrecords"
)

type workflowRepetitionGroup struct {
	ConfiguredStep      string   `json:"configured_step"`
	RequestedExecutions int      `json:"requested_executions"`
	CompletedExecutions int      `json:"completed_executions"`
	Outcome             string   `json:"outcome"`
	StepIDs             []string `json:"step_ids"`
}

func workflowRepetitionGroups(root string, result workflowResult) ([]workflowRepetitionGroup, error) {
	var groups []workflowRepetitionGroup
	positions := map[string]int{}
	var err error
	for _, step := range result.Steps {
		if step.Repetitions < 2 || !step.Selected || step.Kind != "unit" && step.Kind != "runner-tests" && step.Kind != "component-tests" {
			continue
		}
		position, found := positions[step.ConfiguredStep]
		if !found {
			position = len(groups)
			positions[step.ConfiguredStep] = position
			groups = append(groups, workflowRepetitionGroup{ConfiguredStep: step.ConfiguredStep, RequestedExecutions: step.Repetitions, Outcome: "not_run", StepIDs: []string{}})
		}
		group := &groups[position]
		if step.StartedAt == nil {
			continue
		}
		group.StepIDs = append(group.StepIDs, step.ID)
		if group.Outcome != "failed" {
			group.Outcome = "running"
		}
		if step.Outcome == "failed" {
			group.Outcome = "failed"
		}
		if step.Outcome != "passed" && step.Outcome != "failed" {
			continue
		}
		var diagnostics *checkDiagnostics
		if result.executions != nil {
			diagnostics = result.executions[step.ID].diagnostics()
		} else {
			path, pathErr := records.SafePath(root, filepath.FromSlash(step.Evidence))
			if step.Evidence == "" || pathErr != nil {
				group.Outcome = "failed"
				err = errors.Join(err, errors.New("repetition scalar evidence unavailable"))
				continue
			}
			if step.Kind == "component-tests" {
				var evidence componentRunRecord
				if readErr := records.ReadJSON(path, &evidence); readErr != nil {
					group.Outcome = "failed"
					err = errors.Join(err, errors.New("component repetition scalar evidence unavailable"))
					continue
				}
				if evidence.Checks != nil {
					diagnostics = evidence.Checks.Diagnostics
				}
			} else {
				var evidence ordinaryStepEvidence
				if readErr := records.ReadJSON(path, &evidence); readErr != nil {
					group.Outcome = "failed"
					err = errors.Join(err, errors.New("ordinary repetition scalar evidence unavailable"))
					continue
				}
				diagnostics = evidence.Diagnostics
			}
		}
		started, joined := false, diagnostics != nil
		if diagnostics != nil {
			for _, command := range diagnostics.Commands {
				joined = joined && command.Joined
				if command.Phase == "test" {
					started = started || command.Started
				}
			}
		}
		if started && joined {
			group.CompletedExecutions++
		} else if step.Outcome == "passed" {
			group.Outcome = "failed"
			err = errors.Join(err, errors.New("repetition lacks started/joined execution proof"))
		}
		if group.Outcome != "failed" && group.CompletedExecutions == group.RequestedExecutions {
			group.Outcome = "passed"
		}
	}
	for index := range groups {
		group := &groups[index]
		if result.FinishedAt != nil && group.Outcome == "running" {
			group.Outcome = "failed"
		}
		if result.Outcome == "passed" && group.Outcome != "passed" {
			err = errors.Join(err, errors.New("requested repetitions did not complete"))
		}
	}
	return groups, err
}

type repetitionBarrier struct {
	processes sync.RWMutex
	stopped   atomic.Bool
}

func (barrier *repetitionBarrier) enter(ctx context.Context, exclusive bool) (func(bool), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if exclusive {
		barrier.processes.Lock()
	} else {
		barrier.processes.RLock()
	}
	unlock := barrier.processes.RUnlock
	if exclusive {
		unlock = barrier.processes.Unlock
	}
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, err
	}
	if barrier.stopped.Load() {
		unlock()
		return nil, errors.New("prepared repetition selection stopped")
	}
	return func(canContinue bool) {
		if !canContinue {
			barrier.stopped.Store(true)
		}
		unlock()
	}, nil
}

type workflowTestBarrierContextKey struct{}

func repetitionBarrierFromContext(ctx context.Context, standalone *repetitionBarrier) *repetitionBarrier {
	if barrier, ok := ctx.Value(workflowTestBarrierContextKey{}).(*repetitionBarrier); ok {
		return barrier
	}
	return standalone
}
