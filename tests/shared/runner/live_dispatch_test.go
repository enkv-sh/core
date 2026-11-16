package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestLiveScheduleContinuesOnlyAfterSettledFailure(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		objects    uint64
		started    int
		saveFails  bool
	}{
		{"clean_failure", "first_writer_failure", 256, 2, false},
		{"cleanup_failure", "failed_cleanup", 256, 1, false},
		{"unknown_effect", "cleanup_unknown_effect", 256, 1, false},
		{"exhausted_allowance", "passed", 1, 1, false},
		{"terminal_save_failure", "passed", 256, 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, binary := coordinatorFixture(t)
			schedule, err := catalog.Resolve(catalog.Request{
				Include:      []string{"state.single-value-update-preserves-other-values/members_1", "state.single-value-update-preserves-other-values/members_2"},
				RecoveryMode: "disabled", SmokePolicy: catalog.SmokeFirstSelectedPoint, Repetitions: 1,
			})
			if err != nil || len(schedule.Entries) != 2 {
				t.Fatal("controlled live selection unavailable", err)
			}
			s.record.Schedule, s.record.Resolved.Schedule, s.record.Scenarios = schedule, schedule, nil
			if test.saveFails {
				if err := os.MkdirAll(filepath.Join(s.directory, "cases", "0000.json"), 0700); err != nil {
					t.Fatal("controlled terminal save collision unavailable", err)
				}
			}
			allowance := testLimits()
			allowance.Objects, allowance.ElapsedSeconds, allowance.CleanupSeconds = test.objects, 30, 30
			err = s.executeSchedule(t.Context(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": test.mode}, allowance)
			if test.saveFails {
				if err == nil || !strings.Contains(err.Error(), "terminal case receipt unavailable") {
					t.Fatal("terminal save failure was not retained", err)
				}
			} else if err != nil {
				t.Fatal("controlled live results could not be retained", err)
			}
			if len(s.record.Scenarios) != test.started {
				t.Fatalf("live dispatch started %d cases, want %d", len(s.record.Scenarios), test.started)
			}
			for index, result := range s.record.Scenarios {
				if result.Entry != schedule.Entries[index] || result.Writer == nil || !result.Writer.Started || !result.Writer.Joined || result.Rerun != nil || result.CleanupWorker == nil || !result.CleanupWorker.Joined {
					t.Fatal("dispatch changed selected identity, repeated a case or lost participant settlement", index, result)
				}
			}
			if test.name == "clean_failure" {
				first, second := s.record.Scenarios[0], s.record.Scenarios[1]
				if first.Outcome != "failed" || first.CorrectnessPassed || first.Failure == nil || !scenarioCleanupPassed(first) || second.Outcome != "passed" || !second.CorrectnessPassed || !scenarioCleanupPassed(second) || s.record.Failure == nil {
					t.Fatal("later success hid the original failure or cleanup did not precede continuation")
				}
				if len(s.record.CaseReceipts) != 2 {
					t.Fatal("continuation lost one terminal case receipt")
				}
				var saved runRecord
				if records.ReadJSON(filepath.Join(s.directory, "run.json"), &saved) != nil || !reflect.DeepEqual(saved.Scenarios, s.record.Scenarios) || saved.Failure == nil {
					t.Fatal("durable results lost the failed case or later success")
				}
				s.finish()
				if s.record.Outcome != "failed" || s.record.Correctness.Passed || !runCleanupPassed(s.record) {
					t.Fatal("complete cleanup turned a failed live invocation into a pass")
				}
			}
			if test.started < len(schedule.Entries) {
				name, err := currentCaseDirectory(schedule.Entries[test.started])
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(s.private, name)); !os.IsNotExist(err) {
					t.Fatal("unsafe continuation prepared the next case", err)
				}
			}
		})
	}
}

// full_only: false
func TestLiveScheduleRetainsBudgetAccountingFailure(t *testing.T) {
	s, binary := singleScenarioOutcomeFixture(t)
	allowance := testLimits()
	allowance.Requests = 1
	err := s.executeSchedule(t.Context(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": "failed_writer"}, allowance)
	if err == nil || len(s.record.Scenarios) != 1 || len(s.record.CaseReceipts) != 1 {
		t.Fatal("unavailable budget accounting lost its error or terminal case", err)
	}
	result := s.record.Scenarios[0]
	if s.record.Failure == nil || s.record.Failure.Class != "scenario_failed" || result.Outcome != "failed" || !scenarioCleanupPassed(result) || result.BudgetReserved == nil || result.BudgetReserved.Requests <= allowance.Requests {
		t.Fatal("budget failure erased the original failed case or its consumed allowance")
	}
	var saved runRecord
	if records.ReadJSON(filepath.Join(s.directory, "run.json"), &saved) != nil || len(saved.Scenarios) != 1 || saved.Failure == nil || saved.Scenarios[0].BudgetReserved == nil || saved.Scenarios[0].BudgetReserved.Requests != result.BudgetReserved.Requests {
		t.Fatal("budget failure was not saved before dispatch stopped")
	}
}

// full_only: false
func TestWorkflowKeepsContainedLiveFailureAndRunsIndependentSteps(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequential", true: "declared_group"}[grouped], func(t *testing.T) {
			root := assemblyGroupExecutionRoot(t)
			plan := liveGroupPlan(1)
			if !grouped {
				for index := range plan.Steps {
					plan.Steps[index].ParallelGroup = ""
				}
			}
			failure := errors.New("controlled fully cleaned live assertion failure")
			var entered []string
			result, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil,
				func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
					entered = append(entered, step.ID)
					if step.ID == plan.Steps[0].ID {
						return workflowStepExecution{}, &liveCheckFailure{cause: failure}
					}
					return workflowStepExecution{}, nil
				})
			want := []string{plan.Steps[0].ID, plan.Steps[1].ID, plan.Steps[2].ID, plan.Steps[3].ID}
			if !errors.Is(err, failure) || result.Outcome != "failed" || !slices.Equal(entered, want) || len(result.Steps) != len(want) || result.Steps[0].Outcome != "failed" {
				t.Fatal("workflow dropped a safe independent step or the original failure", entered, result.Outcome, err)
			}
			for _, step := range result.Steps[1:] {
				if step.Outcome != "passed" {
					t.Fatal("independent live/local step lost its result", step.ID, step.Outcome)
				}
			}
		})
	}
}
