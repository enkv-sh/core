package main

import (
	"errors"
	"reflect"
)

type scenarioRepetitionGroup struct {
	Scenario            string `json:"scenario"`
	RequestedExecutions int    `json:"requested_executions"`
	CompletedExecutions int    `json:"completed_executions"`
	Outcome             string `json:"outcome"`
	CaseSequences       []int  `json:"case_sequences"`
}

// This projection describes this run's scalar attempts. It cannot grant
// correctness, complete coverage, cleanup, or continuation authority.
func scenarioRepetitionGroups(value runRecord) ([]scenarioRepetitionGroup, error) {
	if value.Schedule.Repetitions < 2 || value.RecoveryRunID != "" {
		return nil, nil
	}
	refused := errors.New("scenario repetition scalar evidence differs")
	if value.Schedule.Repetitions > 100 || len(value.Schedule.Selected) == 0 {
		return nil, refused
	}
	groups := make([]scenarioRepetitionGroup, 0, len(value.Schedule.Selected))
	positions := map[string]int{}
	for _, name := range value.Schedule.Selected {
		if _, found := positions[name]; found {
			return nil, refused
		}
		positions[name] = len(groups)
		groups = append(groups, scenarioRepetitionGroup{Scenario: name,
			RequestedExecutions: value.Schedule.Repetitions, Outcome: "not_run", CaseSequences: []int{}})
	}
	lastSequence := -1
	for _, result := range value.Scenarios {
		if result.Sequence <= lastSequence || result.Sequence < 0 || result.Sequence >= len(value.Schedule.Entries) ||
			result.Entry != value.Schedule.Entries[result.Sequence] {
			return nil, refused
		}
		lastSequence = result.Sequence
		if result.Outcome == "not_run" {
			if value.Suite != "hermetic" || !scenarioNotRun(result) {
				return nil, refused
			}
			continue
		}
		// The auxiliary smoke has no selected repetition. A selected point
		// smoke carries repetition one and counts exactly like any other case.
		if result.Smoke && result.Repetition == 0 {
			continue
		}
		position, found := positions[result.Scenario]
		if !found || result.Repetition < 1 || result.Repetition > value.Schedule.Repetitions {
			return nil, refused
		}
		group := &groups[position]
		group.CaseSequences = append(group.CaseSequences, result.Sequence)
		if group.Outcome != "failed" {
			group.Outcome = "running"
		}
		if result.Outcome != "passed" && result.Outcome != "failed" {
			continue
		}
		completed := scenarioRepetitionCompleted(result)
		if completed {
			group.CompletedExecutions++
		}
		if result.Outcome == "failed" || !completed {
			group.Outcome = "failed"
		}
		if group.Outcome != "failed" && group.CompletedExecutions == group.RequestedExecutions {
			group.Outcome = "passed"
		}
	}
	for index := range groups {
		group := &groups[index]
		if group.CompletedExecutions > group.RequestedExecutions || len(group.CaseSequences) > group.RequestedExecutions {
			return nil, refused
		}
		if value.FinishedAt != nil && group.Outcome == "running" {
			group.Outcome = "failed"
		}
	}
	return groups, nil
}

func scenarioRepetitionCompleted(result scenarioResult) bool {
	started, joined := result.Writer != nil && result.Writer.Started, true
	for _, worker := range scenarioWorkers(result) {
		joined = joined && worker.Joined
	}
	for _, attempt := range result.CleanupAttempts {
		joined = joined && attempt.Worker != nil && attempt.Worker.Joined
	}
	for _, reconstruction := range result.Reconstruction {
		for _, phase := range reconstruction.Phases {
			if result.Writer == nil {
				started = started || phase.Started
			}
			joined = joined && phase.Joined
		}
	}
	return started && joined
}

// Missing groups remain optional for retained records. Present groups must
// match their original scalar facts; no missing start or join is inferred.
func validateScenarioRepetitionGroups(value runRecord) error {
	if value.RepetitionGroups == nil {
		return nil
	}
	expected, err := scenarioRepetitionGroups(value)
	if err != nil || !reflect.DeepEqual(expected, value.RepetitionGroups) {
		return errors.New("scenario repetition accounting differs from scalar evidence")
	}
	return nil
}
