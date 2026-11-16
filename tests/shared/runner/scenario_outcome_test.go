package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func singleScenarioOutcomeFixture(t *testing.T) (*runState, string) {
	t.Helper()
	s, binary := coordinatorFixture(t)
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{s.record.Scenarios[0].Scenario}, RecoveryMode: "disabled", Repetitions: 1, SmokePolicy: catalog.SmokeFirstSelectedPoint})
	if err != nil || len(schedule.Entries) != 1 {
		t.Fatal("single controlled scenario unavailable", err)
	}
	s.record.Schedule, s.record.Resolved.Schedule = schedule, schedule
	s.record.Scenarios = nil
	return s, binary
}

func inspectSettledOutcome(t *testing.T, s *runState, correct, clean, passed bool) runRecord {
	t.Helper()
	s.finish()
	if s.record.Correctness.Passed != correct || s.record.Correctness.EvidenceComplete != correct || (s.record.Outcome == "passed") != passed || cleanupPassed(s.record.Cleanup) != clean {
		t.Fatal("run aggregation changed independent correctness or cleanup facts")
	}
	if s.save() != nil {
		t.Fatal("settled outcome could not be saved")
	}
	var saved runRecord
	if records.ReadJSON(filepath.Join(s.directory, "run.json"), &saved) != nil || len(saved.Scenarios) != 1 || saved.Correctness != s.record.Correctness || saved.Outcome != s.record.Outcome || !reflect.DeepEqual(saved.Scenarios[0], s.record.Scenarios[0]) {
		t.Fatal("saved outcome differs from the settled scenario")
	}
	body, err := json.Marshal(saved)
	if err != nil || bytes.Contains(body, []byte("synthetic-secret")) || bytes.Contains(body, []byte(controlledAssertionCaller)) {
		t.Fatal("private assertion details entered closed current facts", err)
	}
	return saved
}

// full_only: false
func TestCoordinatorOutcomeKeepsAssertionsAndCleanupSeparate(t *testing.T) {
	for _, test := range []struct {
		mode           string
		correct, clean bool
	}{
		{"passed", true, true},
		{"failed_cleanup", true, false},
		{"failed_writer", false, true},
		{"assertion_writer_cleanup", false, false},
	} {
		t.Run(test.mode, func(t *testing.T) {
			s, binary := singleScenarioOutcomeFixture(t)
			if err := s.executeSchedule(t.Context(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": test.mode}, testLimits()); err != nil {
				t.Fatal("controlled schedule could not retain its terminal case", err)
			}
			if len(s.record.Scenarios) != 1 {
				t.Fatal("controlled schedule changed its selected count")
			}
			result := s.record.Scenarios[0]
			passed := test.correct && test.clean
			if result.CorrectnessPassed != test.correct || cleanupPassed(result.Cleanup) != test.clean || (result.Outcome == "passed") != passed || result.Writer == nil || !result.Writer.Joined || result.Writer.Assertions == nil || result.CleanupWorker == nil || !result.CleanupWorker.Joined {
				t.Fatal("scenario merged assertion, join or cleanup results")
			}
			if test.correct {
				if result.Failure != nil || result.Writer.Assertions.Marker != "no_failure_marker" {
					t.Fatal("cleanup failure replaced valid workload assertions")
				}
			} else if result.Failure == nil || *result.Failure != (records.Failure{Class: "writer_failed", Stage: "writer"}) {
				t.Fatal("cleanup replaced the original workload failure")
			}
			if test.mode == "assertion_writer_cleanup" && (result.Writer.Assertions.Marker != "valid_failure_marker" || result.CleanupWorker.Assertions == nil || result.CleanupWorker.Assertions.Marker != "valid_failure_marker") {
				t.Fatal("independent assertion failure markers were lost")
			}
			inspectSettledOutcome(t, s, test.correct, test.clean, passed)
		})
	}
}

// full_only: false
func TestCoordinatorUnknownEffectPreventsCleanupSuccess(t *testing.T) {
	s, binary := singleScenarioOutcomeFixture(t)
	if err := s.executeSchedule(t.Context(), binary, liveSettings{"recovery_mode": "disabled", "test_mode": "cleanup_unknown_effect"}, testLimits()); err != nil {
		t.Fatal(err)
	}
	result := s.record.Scenarios[0]
	if result.Outcome != "failed" || !result.CorrectnessPassed || result.Failure != nil || result.Cleanup.Outcome != "unresolved" || result.Cleanup.RemainingOwnedObjects == nil || *result.Cleanup.RemainingOwnedObjects != 0 || result.Cleanup.UnknownEffects == nil || *result.Cleanup.UnknownEffects != 1 || result.CleanupWorker == nil || !result.CleanupWorker.Joined || len(result.CleanupAttempts) != 0 {
		t.Fatal("zero known objects hid an unknown effect or changed correctness")
	}
	saved := inspectSettledOutcome(t, s, true, false, false)
	cleanup := saved.Scenarios[0].Cleanup
	if cleanup.Outcome != "unresolved" || cleanup.RemainingOwnedObjects == nil || *cleanup.RemainingOwnedObjects != 0 || cleanup.UnknownEffects == nil || *cleanup.UnknownEffects != 1 {
		t.Fatal("saved case implies known empty ownership despite unknown effects")
	}
}

// full_only: false
func TestCoordinatorPriorFailureSurvivesCancellation(t *testing.T) {
	s, binary := singleScenarioOutcomeFixture(t)
	name, err := currentCaseDirectory(s.record.Schedule.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(s.private, name)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	watchResult := make(chan error, 1)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		waitCtx, stop := context.WithTimeout(t.Context(), 5*time.Second)
		defer stop()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, markerErr := os.Stat(filepath.Join(state, "cleanup-called.json")); markerErr == nil {
				var retained runRecord
				if records.ReadJSON(filepath.Join(s.directory, "run.json"), &retained) != nil || len(retained.Scenarios) != 1 || retained.Scenarios[0].Writer == nil || !retained.Scenarios[0].Writer.Joined || retained.Scenarios[0].Writer.Assertions == nil || retained.Scenarios[0].Writer.Assertions.Marker != "valid_failure_marker" {
					cancel()
					watchResult <- errors.New("cleanup began without the saved joined writer assertion")
					return
				}
				cancel()
				watchResult <- os.WriteFile(filepath.Join(state, "cleanup-cancel-ack"), []byte("cancelled"), 0600)
				return
			}
			select {
			case <-waitCtx.Done():
				cancel()
				watchResult <- errors.New("controlled initial cleanup did not start")
				return
			case <-tick.C:
			}
		}
	}()
	allowance := testLimits()
	allowance.CleanupSeconds, allowance.CleanupRequests, allowance.CleanupBytes = 15, 100, 1000
	scheduleErr := s.executeSchedule(ctx, binary, liveSettings{"recovery_mode": "disabled", "test_mode": "cleanup_retry_prior_failure_cancelled"}, allowance)
	watchErr := <-watchResult
	<-watchDone
	if watchErr != nil {
		t.Fatal(watchErr)
	}
	if scheduleErr != nil || ctx.Err() == nil || len(s.record.Scenarios) != 1 {
		t.Fatal("cancelled schedule did not retain the original failed case", scheduleErr)
	}
	result := s.record.Scenarios[0]
	if result.Outcome != "failed" || result.CorrectnessPassed || result.Failure == nil || *result.Failure != (records.Failure{Class: "writer_failed", Stage: "writer"}) || result.Writer == nil || !result.Writer.Joined || result.Writer.Assertions == nil || result.Writer.Assertions.Marker != "valid_failure_marker" || result.CleanupWorker == nil || !result.CleanupWorker.Joined || result.CleanupRetryBlocker != "interrupted" || len(result.CleanupAttempts) != 0 {
		t.Fatal("later cancellation or cleanup replaced the prior joined assertion failure")
	}
	if _, err := os.Stat(filepath.Join(state, "workers", "cleanup-retry-2")); !os.IsNotExist(err) {
		t.Fatal("cancellation started another cleanup worker", err)
	}
	inspectSettledOutcome(t, s, false, false, false)
}

// full_only: false
func TestCoordinatorMissingJoinRefusesCleanup(t *testing.T) {
	s, binary := coordinatorFixture(t)
	result := &s.record.Scenarios[0]
	name, err := currentCaseDirectory(result.Entry)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(s.private, name)
	if os.MkdirAll(filepath.Join(state, "workers"), 0700) != nil {
		t.Fatal("controlled participant owner unavailable")
	}
	input := workerInput{RunID: s.record.RunID, Scenarios: []string{result.Scenario}, Repetitions: 1, RecoveryMode: "disabled", Participants: map[string]string{"authority": "operator"}, Settings: liveSettings{"test_mode": "passed"}}
	inputPath := filepath.Join(state, "input.json")
	if records.WriteJSON(inputPath, input, 0400) != nil {
		t.Fatal("controlled participant input unavailable")
	}
	inv, err := makeInvocation(records.Invocation{Scenario: result.Scenario, FailureSources: s.failureSources, RunID: s.record.RunID, Worker: name + "-writer", Role: "writer", Input: inputPath, StateDir: state, OutputDir: filepath.Join(state, "workers", "writer")}, "live")
	if err != nil {
		t.Fatal(err)
	}
	failure, err := records.NewFailureRecorder(inv)
	if err != nil {
		t.Fatal(err)
	}
	failure.Record("fatal", controlledAssertionCaller, 1)
	assertions := records.InspectAssertions(inv, false)
	if assertions.Marker != "valid_failure_marker" {
		t.Fatal("controlled original assertion marker unavailable")
	}
	result.Writer = &workerEvidence{Worker: inv.Worker, Role: "writer", Outcome: "failed", Process: "process_failed", Assertions: &assertions}
	original := &records.Failure{Class: "writer_failed", Stage: "writer"}
	prior := errors.New("controlled original workload failure")
	completion := scenarioCompletion{entered: true, started: time.Now(), failure: original,
		participants: &scenarioParticipants{state: state, input: input, cleanupInput: input.authorityOnly(), writer: inv, writerProcess: processResult{Status: "process_failed"}}}
	if err := s.completeScenario(t.Context(), binary, testLimits(), result, &completion, prior); !errors.Is(err, prior) || result.CorrectnessPassed || result.Outcome != "failed" || result.Failure != original || result.CleanupRetryBlocker != "worker_unjoined" || result.CleanupWorker != nil || result.Cleanup.Failure == nil || result.Cleanup.Failure.Class != "worker_group_not_joined" || result.Writer.Assertions != &assertions {
		t.Fatal("unjoined synthetic participant lost the original failure or admitted cleanup", err)
	}
	if _, err := os.Stat(filepath.Join(state, "cleanup-called.json")); !os.IsNotExist(err) {
		t.Fatal("missing positive join started a cleanup worker", err)
	}
}

// full_only: false
func TestCoordinatorOracleDisposalDoesNotRewriteAssertions(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("prior_failure_%t", failed), func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "owned-parent")
			oracle := filepath.Join(parent, "oracle")
			if os.MkdirAll(oracle, 0700) != nil || os.Remove(oracle) != nil || os.Remove(parent) != nil || os.WriteFile(parent, []byte("owned replacement"), 0600) != nil {
				t.Fatal("local disposal error fixture unavailable")
			}
			if _, err := os.Lstat(oracle); err == nil || os.IsNotExist(err) {
				t.Fatal("control must produce an actual local path error")
			}
			s := &runState{record: runRecord{Suite: "hermetic"}}
			result := scenarioResult{Outcome: "incomplete", Cleanup: noCleanup()}
			completion := scenarioCompletion{entered: true, completed: true, joined: true, started: time.Now(), oracleDirectory: oracle}
			var prior error
			if failed {
				prior = errors.New("original assertion failure")
				completion.completed = false
				completion.failure = &records.Failure{Class: "writer_failed", Stage: "writer"}
			}
			err := s.completeScenario(t.Context(), "", limits{}, &result, &completion, prior)
			if err == nil || result.Outcome != "failed" || result.CorrectnessPassed != !failed || result.Failure == nil || !strings.Contains(err.Error(), "private oracle") || strings.Contains(err.Error(), parent) {
				t.Fatal("local disposal failure changed assertion correctness or leaked a private path", err)
			}
			if failed {
				if !errors.Is(err, prior) || result.Failure != completion.failure {
					t.Fatal("oracle disposal replaced the original workload failure")
				}
			} else if *result.Failure != (records.Failure{Class: "private_oracle_cleanup_failed", Stage: "cleanup"}) {
				t.Fatal("oracle disposal lost its independent cleanup classification")
			}
		})
	}
}

// full_only: false
func TestScenarioCompletionRequiresPositiveWorkloadFacts(t *testing.T) {
	for _, missing := range []string{"entry", "completion", "join", "failure"} {
		t.Run(missing, func(t *testing.T) {
			s := &runState{record: runRecord{Suite: "hermetic"}}
			result := scenarioResult{Outcome: "incomplete", Cleanup: noCleanup()}
			completion := scenarioCompletion{entered: true, completed: true, joined: true, started: time.Now()}
			switch missing {
			case "entry":
				completion.entered = false
			case "completion":
				completion.completed = false
			case "join":
				completion.joined = false
			case "failure":
				completion.failure = &records.Failure{Class: "writer_failed", Stage: "writer"}
			}
			if err := s.completeScenario(t.Context(), "", limits{}, &result, &completion, nil); err == nil || result.Outcome != "failed" || result.CorrectnessPassed || result.Failure == nil {
				t.Fatal("nil returned error invented completed workload success")
			}
			if completion.failure != nil && result.Failure != completion.failure {
				t.Fatal("completion replaced an explicit original failure fact")
			}
		})
	}
}
