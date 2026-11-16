package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// These fixtures retain facts from actual Start/Wait calls independently of the
// record type under test, so the regression compiles before that field exists.
func runControlledFreshProcess(t *testing.T, inv records.Invocation, result records.WorkerResult, mode string) {
	t.Helper()
	if records.WriteJSON(filepath.Join(inv.OutputDir, "expected-worker.json"), result, 0600) != nil {
		t.Fatal("controlled child input unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if mode == "actual_fresh_start_failed" {
		binary = filepath.Join(inv.OutputDir, "absent-executable")
	}
	fixtureMode := mode
	if fixtureMode == "" {
		fixtureMode = "controlled"
	}
	command := exec.Command(binary, "-test.run=^TestLiveChild$")
	command.Env = environment(os.Environ(), map[string]string{"ENKV_TEST_INVOCATION": filepath.Join(inv.OutputDir, "invocation.json"), "ENKV_FRESH_BEFORE_FIXTURE": fixtureMode})
	runErr := command.Run()
	started, joined, outcome := command.Process != nil, command.ProcessState != nil, "unknown"
	switch {
	case !started:
		joined, outcome = true, "not_started"
	case joined && runErr == nil:
		outcome = "passed"
	case joined:
		outcome = "process_failed"
	}
	if mode == "actual_fresh_unjoined" {
		joined, outcome = false, "unknown"
	}
	if mode == "actual_fresh_impossible_pass" {
		started, joined, outcome = false, true, "passed"
	}
	if mode != "actual_fresh_missing_fact" {
		fact := map[string]any{"started": started, "joined": joined, "outcome": outcome}
		if records.WriteJSON(filepath.Join(inv.OutputDir, "process-fixture.json"), fact, 0600) != nil {
			t.Fatal("controlled process observation unavailable")
		}
	}
	if mode == "actual_fresh_missing_result" {
		if err := os.Remove(filepath.Join(inv.OutputDir, "worker.json")); err != nil {
			t.Fatal(err)
		}
	}
}

func runControlledFreshProcessChild(t *testing.T) {
	t.Helper()
	inv, err := records.LoadInvocation(os.Getenv("ENKV_TEST_INVOCATION"))
	if err != nil || inv.Role != "fresh_before" {
		t.Fatal("controlled fresh invocation refused", err)
	}
	var result records.WorkerResult
	if records.ReadJSON(filepath.Join(inv.OutputDir, "expected-worker.json"), &result) != nil || result.Worker != inv.Worker {
		t.Fatal("controlled fresh result refused")
	}
	if os.Getenv("ENKV_FRESH_BEFORE_FIXTURE") == "assertion_child_parent" {
		failure, err := records.NewFailureRecorder(inv)
		if err != nil {
			t.Fatal(err)
		}
		failure.Record("fatal", controlledAssertionCaller, 3)
	}
	if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), result, 0600) != nil {
		t.Fatal("controlled fresh result unavailable")
	}
	if result.Outcome == "failed" {
		t.Fatal("synthetic-secret child assertion")
	}
	if os.Getenv("ENKV_FRESH_BEFORE_FIXTURE") == "actual_fresh_exit_failed" {
		t.Error("controlled child writes pass then exits with failure")
	}
}

func retainControlledFreshProcessFacts(t *testing.T, inv records.Invocation) {
	t.Helper()
	path := filepath.Join(inv.OutputDir, "worker.json")
	var raw map[string]json.RawMessage
	if records.ReadJSON(path, &raw) != nil {
		t.Fatal("controlled writer result unavailable")
	}
	childrenBody, present := raw["children"]
	if !present {
		return
	}
	var children []map[string]json.RawMessage
	if json.Unmarshal(childrenBody, &children) != nil {
		t.Fatal("controlled children unavailable")
	}
	if len(children) == 0 {
		return
	}
	for index := range children {
		fact, err := os.ReadFile(filepath.Join(inv.OutputDir, fmt.Sprintf("fresh-before-%d", index), "process-fixture.json"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		children[index]["process"] = fact
	}
	body, err := json.Marshal(children)
	if err != nil {
		t.Fatal(err)
	}
	raw["children"] = body
	if records.WriteJSON(path, raw, 0600) != nil {
		t.Fatal("controlled process facts unavailable")
	}
}

// full_only: false
func TestCoordinatorFreshBeforeRetainsProcessFacts(t *testing.T) {
	for _, race := range []bool{false, true} {
		for _, row := range []struct {
			name, process, actor                  string
			started, joined, passed, parentPassed bool
		}{
			{"passed", "passed", "operator", true, true, true, true},
			{"parent_failed", "passed", "operator", true, true, true, false},
			{"exit_failed", "process_failed", "operator", true, true, false, false},
			{"start_failed", "not_started", "", false, true, false, false},
			{"missing_fact", "unknown", "operator", false, false, false, false},
			{"impossible_pass", "unknown", "operator", false, false, false, false},
			{"missing_result", "passed", "", true, true, false, false},
			{"unjoined", "unknown", "operator", true, false, false, false},
		} {
			name := row.name + "/plain"
			options := ""
			if race {
				name = row.name + "/race"
				options = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000"
			}
			t.Run(name, func(t *testing.T) {
				s, binary := coordinatorFixture(t)
				s.record.BuildClosure = &assemblyClosure{Race: race, RaceOptions: options}
				s.record.Resolved.Race = race
				result := &s.record.Scenarios[0]
				runErr := s.executeScenario(withRacePolicy(t.Context(), race), binary, liveSettings{"recovery_mode": "disabled", "test_mode": "actual_fresh_" + row.name}, testLimits(), result)
				if (runErr == nil) != row.parentPassed {
					t.Fatalf("scenario outcome differs: %v", runErr)
				}
				if len(result.Children) != 1 {
					t.Fatalf("fresh child count = %d, want 1", len(result.Children))
				}
				child := result.Children[0]
				if child.Role != "fresh_before" || child.Actor != row.actor || child.Started != row.started || child.Joined != row.joined || child.Process != row.process || (child.Outcome == "passed") != row.passed {
					t.Fatalf("actual child process facts lost or invented: %+v", child)
				}
				if row.started {
					if child.Race == nil || *child.Race != race || child.RaceOptions != options {
						t.Errorf("actual child race facts = %v %q, want %t %q", child.Race, child.RaceOptions, race, options)
					}
				} else if child.Race != nil || child.RaceOptions != "" {
					t.Error("unestablished start acquired a race observation")
				}
				if row.name == "parent_failed" && (result.Writer == nil || result.Writer.Process != "process_failed" || !result.Writer.Joined) {
					t.Fatal("earlier child pass lost its later independent writer failure")
				}
				if row.name == "exit_failed" && child.Failure == nil {
					t.Error("pass result hid the child's nonzero process exit")
				}
			})
		}
	}
}
