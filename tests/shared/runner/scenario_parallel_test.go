package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestHermeticCaseDispatchCancelsPeersAndRetainsSelectedOrder(t *testing.T) {
	for _, parallel := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("parallel_%d", parallel), func(t *testing.T) {
			runHermeticCaseDispatchControl(t, parallel, 3, false, false)
		})
	}
	t.Run("parent_cancel", func(t *testing.T) { runHermeticCaseDispatchControl(t, 4, 3, true, false) })
}

// full_only: false
func TestHermeticCaseDispatchContinuesContainedFailures(t *testing.T) {
	for _, parallel := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("parallel_%d", parallel), func(t *testing.T) {
			runHermeticCaseDispatchControl(t, parallel, 3, false, true)
		})
	}
	t.Run("many_cases", func(t *testing.T) { runHermeticCaseDispatchControl(t, 4, 40, false, true) })
}

func runHermeticCaseDispatchControl(t *testing.T, parallel, repetitions int, parentCancel, contained bool) {
	t.Helper()
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{
		"state.single-value-update-preserves-other-values/members_1",
		"state.single-value-update-preserves-other-values/members_2",
	}, Repetitions: repetitions, RecoveryMode: "disabled", SmokePolicy: catalog.SmokeFirstSelectedPoint})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	state, err := newRunState(root, runRequest{Suite: "hermetic", Provider: "memory", Schedule: schedule}, records.Source{}, "controlled")
	if err != nil {
		t.Fatal(err)
	}
	state.record.Resolved = &resolvedRequest{Mode: "hermetic", RecoveryMode: "disabled", Provider: "memory", Schedule: schedule,
		RoleBindings: map[string]string{"authority": "operator"}, Participants: []string{"operator"}}
	state.failureSources = controlledFailureSources(t, state.private)
	witness := t.TempDir()
	binary := filepath.Join(t.TempDir(), "controlled-writer")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	script := "#!/bin/sh\nset -C\nstate=$(dirname \"$(dirname \"$(dirname \"$ENKV_TEST_INVOCATION\")\")\")\nname=$(basename \"$state\")\n" +
		"printf '%s\\n' \"$$\" > " + quote(witness) + "/\"$name.pid\"\n" +
		"printf 'case-start-%s\\n' \"$name\"\n" +
		"while [ ! -f " + quote(witness) + "/\"$name.release\" ]; do sleep 0.01; done\nexit 7\n"
	if contained {
		templates := t.TempDir()
		for _, entry := range schedule.Entries {
			name, err := currentCaseDirectory(entry)
			if err != nil {
				t.Fatal(err)
			}
			result := records.WorkerResult{SchemaVersion: records.SchemaVersion, RunID: state.record.RunID,
				Worker: name + "-writer", Role: "writer", Scenario: entry.Scenario, Actor: "operator",
				Outcome: "failed", Phases: []records.PhaseResult{}}
			if err := records.WriteJSON(filepath.Join(templates, name+".json"), result, 0600); err != nil {
				t.Fatal(err)
			}
		}
		script = strings.Replace(script, "exit 7\n", "cat "+quote(templates)+"/\"$name.json\" > \"$state/workers/writer/worker.json\"\nexit 7\n", 1)
	}
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(withExecutionParallel(t.Context(), parallel))
	done := make(chan error, 1)
	go func() { done <- state.executeSchedule(ctx, binary, nil, limits{}) }()
	var executionErr error
	settled := false
	defer func() {
		cancel()
		if !settled {
			executionErr = <-done
		}
		if _, err := os.Lstat(state.current.path); err == nil {
			if err := state.current.remove(runProcessesJoined(state.record) && toolCommandsJoined(executionErr)); err != nil {
				t.Error("controlled dispatch owner retained after uncertain settlement", err)
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, readErr := os.ReadDir(witness)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) == parallel {
			break
		}
		select {
		case executionErr = <-done:
			settled = true
			t.Fatal("dispatch returned before its assigned cases entered", executionErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("started %d independent cases; want %d before release", len(entries), parallel)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Each initially assigned job remains blocked until this test selects a failure.
	// No completion ordinal is used to choose the failing selected case.
	if parentCancel {
		cancel()
	} else {
		name, err := currentCaseDirectory(schedule.Entries[parallel-1])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(witness, name+".release"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if contained {
		for !settled {
			entries, err := os.ReadDir(witness)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".pid") {
					if err := os.WriteFile(filepath.Join(witness, strings.TrimSuffix(entry.Name(), ".pid")+".release"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			select {
			case executionErr = <-done:
				settled = true
			case <-time.After(10 * time.Millisecond):
				if time.Now().After(deadline.Add(10 * time.Second)) {
					t.Fatal("contained case queue did not drain")
				}
			}
		}
	}
	if !settled {
		select {
		case executionErr = <-done:
			settled = true
		case <-time.After(15 * time.Second):
			t.Fatal("started case processes did not drain")
		}
	}
	if executionErr == nil || parentCancel && !errors.Is(executionErr, context.Canceled) {
		t.Fatal("failed dispatch lost its error", executionErr)
	}
	if len(state.record.Scenarios) != len(schedule.Entries) {
		t.Fatalf("selected result slots = %d; want %d including queued not_run", len(state.record.Scenarios), len(schedule.Entries))
	}
	wantStarted := parallel
	if contained {
		wantStarted = len(schedule.Entries)
	}
	if len(state.snapshots) != wantStarted || len(state.diagnostics) != wantStarted || !state.telemetryIncomplete {
		t.Fatalf("started case-local observations: snapshots=%d diagnostics=%d want=%d incomplete=%t; error=%v", len(state.snapshots), len(state.diagnostics), wantStarted, state.telemetryIncomplete, executionErr)
	}
	nonces := map[string]bool{}
	pids := map[int]bool{}
	var terminal bytes.Buffer
	if err := writeAssemblyDiagnosticBody(&terminal, executionErr); err != nil {
		t.Fatal(err)
	}
	lastDiagnostic := -1
	lastRetained := -1
	retained := executionErr.Error()
	diagnosticTailMissing := false
	for index, result := range state.record.Scenarios {
		if result.Entry != schedule.Entries[index] {
			t.Fatal("completion order changed selected result order", index, result.Entry)
		}
		name, err := currentCaseDirectory(result.Entry)
		if err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(state.private, name)
		if index >= wantStarted {
			if result.Outcome != "not_run" || result.Writer != nil || len(result.Children) != 0 || len(result.PostExit) != 0 || result.CorrectnessPassed || scenarioRepetitionCompleted(result) {
				t.Fatal("queued case acquired execution or completion facts", result)
			}
			if _, err := os.Lstat(directory); !os.IsNotExist(err) {
				t.Fatal("queued case created a fixture", directory, err)
			}
			continue
		}
		if result.Outcome != "failed" || result.Writer == nil || !result.Writer.Started || !result.Writer.Joined {
			t.Fatal("started peer result or positive join lost", index, result)
		}
		if contained && result.Writer.Process != "process_failed" {
			t.Fatal("contained failure canceled an independent case", index, result.Writer.Process)
		}
		var inv records.Invocation
		var input workerInput
		if records.ReadJSON(filepath.Join(directory, "workers", "writer", "invocation.json"), &inv) != nil || records.ReadJSON(inv.Input, &input) != nil {
			t.Fatal("case-owned invocation/input unavailable", index)
		}
		if inv.StateDir != directory || inv.Input != filepath.Join(directory, "input.json") || inv.Worker != name+"-writer" || inv.Nonce == "" || nonces[inv.Nonce] || input.Repetitions != 1 || input.Limits != nil || len(input.Scenarios) != 1 || input.Scenarios[0] != result.Scenario {
			t.Fatal("case reused mutable input, nonce or temporary paths", inv, input)
		}
		nonces[inv.Nonce] = true
		body, err := os.ReadFile(filepath.Join(witness, name+".pid"))
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(body)))
		if err != nil || parseErr != nil || pid <= 0 || pids[pid] {
			t.Fatal("fresh real process observation missing", err, parseErr, pid)
		}
		pids[pid] = true
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatal("dispatch returned while a started writer remained", pid, err)
		}
		position := strings.Index(retained, "case-start-"+name)
		if position <= lastRetained {
			t.Fatal("typed peer errors or selected order lost", index, retained)
		}
		lastRetained = position
		position = strings.Index(terminal.String(), "case-start-"+name)
		if position < 0 {
			diagnosticTailMissing = true
			if lastDiagnostic < 0 || !strings.Contains(terminal.String(), "Additional cause branches truncated: true") {
				t.Fatal("diagnostic prefix or truncation status lost", index, terminal.String())
			}
		} else {
			if diagnosticTailMissing || position <= lastDiagnostic {
				t.Fatal("selected diagnostic prefix order lost", index, terminal.String())
			}
			lastDiagnostic = position
		}
	}
	state.finish()
	groups, err := scenarioRepetitionGroups(state.record)
	if err != nil || len(groups) != 2 {
		t.Fatal("repetition groups unavailable", groups, err)
	}
	for index, group := range groups {
		wantCompleted := (wantStarted + 1 - index) / 2
		wantOutcome := "failed"
		if wantCompleted == 0 {
			wantOutcome = "not_run"
		}
		if group.RequestedExecutions != repetitions || group.CompletedExecutions != wantCompleted || len(group.CaseSequences) != wantCompleted || group.Outcome != wantOutcome {
			t.Fatal("queue or canceled peer changed requested N / joined K", group, wantCompleted)
		}
	}
	if !runProcessesJoined(state.record) || !toolCommandsJoined(executionErr) {
		t.Fatal("all started process/error joins were not retained")
	}
	current := state.current.path
	if err := state.finishCurrentRun(&bytes.Buffer{}, executionErr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(current); !os.IsNotExist(err) {
		t.Fatal("joined failed dispatch did not dispose current scratch", err)
	}
}
