package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// Shared by repetition fixtures that need the real assembly overlay, without
// running a preliminary build. Its directory belongs to the calling test.
func repetitionTestBootstrap(t *testing.T, root, directory string) string {
	t.Helper()
	replacements := map[string]string{}
	for _, owner := range []string{"catalog", "records"} {
		entries, err := os.ReadDir(filepath.Join(root, "tests/shared", owner))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				replacements[filepath.Join(root, "core/internal/test"+owner, entry.Name())] = filepath.Join(root, "tests/shared", owner, entry.Name())
			}
		}
	}
	path := filepath.Join(directory, "bootstrap.json")
	if err := records.WriteJSON(path, struct{ Replace map[string]string }{replacements}, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type componentRepetitionOutput struct {
	bytes.Buffer
	before  string
	change  func()
	changed bool
}

func (output *componentRepetitionOutput) Write(body []byte) (int, error) {
	if output.change != nil && !output.changed && strings.HasPrefix(string(body), output.before) {
		output.changed = true
		output.change()
	}

	return output.Buffer.Write(body)
}

// full_only: false
func TestComponentWorkflowRepetitionsKeepFreshExecutionAndOnePreparation(t *testing.T) {
	t.Setenv("GONOPROXY", "*")
	for _, row := range []struct {
		name, failure        string
		executions, attempts int
		outcome              string
	}{{"passed", "", 3, 3, "passed"}, {"assertion2", "assertion", 4, 4, "failed"}, {"race2", "race", 4, 4, "failed"}, {"bootstrap2", "", 3, 3, "passed"}} {
		t.Run(row.name, func(t *testing.T) {
			fixtureCtx, root, bootstrap := componentRepetitionAssemblyFixture(t)
			observations := t.TempDir()
			witness := filepath.Join(observations, "executions.jsonl")
			commands := filepath.Join(observations, "go-commands")
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			observer := "#!/bin/sh\nprintf 'BEGIN\\n' >> \"$ENKV_COMPONENT_GO_COMMAND_LOG\"\nprintf '%s\\n' \"$PWD\" \"$@\" >> \"$ENKV_COMPONENT_GO_COMMAND_LOG\"\nprintf 'END\\n' >> \"$ENKV_COMPONENT_GO_COMMAND_LOG\"\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_COMPONENT_GO_COMMAND_LOG", commands)
			t.Setenv("ENKV_COMPONENT_REPETITION_WITNESS", witness)
			t.Setenv("ENKV_COMPONENT_REPETITION_SECOND_FAILURE", row.failure)
			const request = "TestFiniteRepetitionProcessWitness/leaf[a]+b"
			path := filepath.Join(observations, "workflow.json")
			steps := []any{map[string]any{"id": "components", "kind": "component-tests", "profile": "dev", "tests": singleTestRequest(request), "repetitions": 3}}
			if row.failure != "" {
				steps = append(steps, map[string]any{"id": "later", "kind": "component-tests", "profile": "dev", "tests": singleTestRequest(request)})
			}
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "fresh-component", "execution": map[string]any{"parallel": 1}, "steps": steps})
			ctx, cancel := context.WithTimeout(withRacePolicy(fixtureCtx, true), 5*time.Minute)
			defer cancel()
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			planned := 3
			if row.failure != "" {
				planned++
			}
			if err != nil || len(plan.Steps) != planned {
				t.Fatal("real component repetition selection unavailable", err)
			}
			output := &componentRepetitionOutput{}
			defer func() {
				if t.Failed() {
					t.Log(output.String())
				}
			}()
			if row.name == "bootstrap2" {
				output.before = fmt.Sprintf("Step %s (%s)\n", plan.Steps[1].ID, plan.Steps[1].Kind)
				output.change = func() {
					body, err := os.ReadFile(bootstrap)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(bootstrap, append(body, '\n'), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			result, runErr := runWorkflow(ctx, root, bootstrap, plan, output)
			if row.name == "assertion2" && !strings.Contains(output.String(), "controlled joined component execution two assertion") {
				t.Error("component terminal omitted the failed assertion value")
			}

			if (runErr != nil) != (row.outcome == "failed") {
				t.Error("actual workflow did not preserve required failure/refusal", row.name, runErr)
			}
			if row.name == "bootstrap2" && !output.changed {
				t.Fatal("bootstrap change did not reach public step2 boundary", runErr)
			}
			if row.name == "race2" {
				// Go testing marks the race as a test failure and M.Run exits1.
				// The configured detector exitcode remains66 for its runtime path.
				if raceOptions != "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000" {
					t.Error("testing race changed the accepted detector configuration", raceOptions)
				}
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
					t.Error("actual testing race2 did not retain its test failure exit1", runErr)
				}
			}
			witnessBody, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal("actual core component witness did not run", err)
			}
			actual, err := decodeObjects[ordinaryRepetitionObservation](witnessBody)
			if err != nil || len(actual) == 0 {
				t.Fatal("real component process evidence unavailable", err)
			}
			if len(actual) != row.executions {
				t.Error("component executed wrong selected attempts", len(actual), row.executions)
			}
			pids, fixtures, binaries := map[int]bool{}, map[string]bool{}, map[string]bool{}
			for _, observation := range actual {
				if observation.PID <= 0 || pids[observation.PID] || observation.InitialState != 1 || observation.Fixture == "" || fixtures[observation.Fixture] || !observation.ChildEntered || !observation.ParentSuffix || !hexString(observation.BinarySHA256, 64) {
					t.Error("component reused mutable state or lost literal child/suffix", observation)
				}
				pids[observation.PID], fixtures[observation.Fixture], binaries[observation.Binary] = true, true, true
				if observation.Binary != actual[0].Binary {
					t.Error("compatible component executions did not share their immutable binary", observation)
				}
				if observation.BinarySHA256 != actual[0].BinarySHA256 {
					t.Error("identical component preparation changed executing binary bytes", observation)
				}
				if _, err := os.Stat(observation.Fixture); !os.IsNotExist(err) {
					t.Error("joined component retained disposable fixture", observation.Fixture, err)
				}
			}
			if len(binaries) != 1 {
				t.Error("compatible component steps did not share one immutable binary", binaries)
			}
			commandBody, err := os.ReadFile(commands)
			if err != nil {
				t.Fatal(err)
			}
			compiles := 0
			for _, block := range strings.Split(string(commandBody), "BEGIN\n")[1:] {
				lines := strings.Split(strings.TrimSuffix(block, "END\n"), "\n")
				if len(lines) > 2 && lines[1] == "test" && slices.Contains(lines[2:], "-c") {
					compiles++
					if !slices.Contains(lines[2:], "-race") {
						t.Error("actual component test compile lost race", lines)
					}
				}
			}
			if compiles != 1 {
				t.Error("compatible component steps repeated assembly construction", compiles)
			}
			if result.Outcome != row.outcome {
				t.Error("workflow result lost assertion/race outcome", result.Outcome, row.outcome)
			}
			ids, paths := map[string]bool{}, map[string]bool{}
			for index, step := range result.Steps {
				if step.ID != plan.Steps[index].ID {
					t.Fatal("component result changed planned execution identity", step)
				}
				if index >= row.attempts {
					if step.Outcome != "not_run" || step.StartedAt != nil || step.Evidence != "" {
						t.Error("failure2 started remaining repetition/configured step", step)
					}
					continue
				}
				wantOutcome := "passed"
				if index == 1 && row.outcome == "failed" {
					wantOutcome = "failed"
				}
				if step.Outcome != wantOutcome || result.executions[step.ID].Component == nil || paths[step.ID] {
					t.Error("component attempt lacks independent truthful scalar result", step)
				}
				paths[step.ID] = true
				component := result.executions[step.ID].Component
				if component == nil || !records.ValidRunID(component.RunID) || ids[component.RunID] || component.FinishedAt == nil || !sameSource(component.Source, result.Source) {
					t.Fatal("component scalar identity/source unavailable", step.ID)
				}
				ids[component.RunID] = true

				if component.Outcome != wantOutcome {
					t.Error("component scalar terminal differs from actual attempt", component.Outcome, wantOutcome)
				}
				checks := component.Checks
				if index >= len(actual) || component.BuildClosure == nil || checks == nil {
					t.Fatal("actual executing component lacks build/check facts", step.ID)
				}
				if component.BuildClosure.BinarySHA256 != actual[index].BinarySHA256 || !component.BuildClosure.Race || component.BuildClosure.RaceOptions != raceOptions || component.BuildClosure.RaceExitSleepMillis != 1000 || checks.Profile != "dev" || !checks.Race || checks.RaceOptions != raceOptions || checks.Focus == nil || checks.Focus.Tests[0] != request || checks.Selection != literalTestSelection(request) {
					t.Error("component changed source-bound race/profile/literal selection", step.ID, checks)
				}
				if component.passedFor(result.Source, component.Toolchain) {
					t.Error("focused repetition acquired full component/scenario reuse credit", step.ID)
				}
				if wantOutcome == "passed" && !completeFocusedComponentEvidence(*checks) {
					t.Error("successful literal node lacks focused completion", step.ID)
				}
				if wantOutcome == "failed" {
					terminals := map[string]string{}
					for _, terminal := range checks.Tests {
						if terminals[terminal.Name] != "" {
							t.Error("failed component repeated terminal", terminal)
						}
						terminals[terminal.Name] = terminal.Outcome
					}
					if len(terminals) != 2 || terminals["TestFiniteRepetitionProcessWitness"] != "failed" || terminals[request] != "failed" {
						t.Error("joined failed component lost exact child/parent assertion terminals", terminals)
					}
				}
				if checks.EventTimeSource != "post_join_test2json" || checks.Diagnostics == nil {
					t.Fatal("component lost timing provenance/command facts", step.ID)
				}
				tests, conversions := 0, 0
				for _, command := range checks.Diagnostics.Commands {
					if !command.Joined {
						t.Error("actual component command lacks positive join", command)
					}
					if command.Phase == "test" || command.Phase == "conversion" {
						if !command.Started || command.WallSeconds == nil || *command.WallSeconds <= 0 {
							t.Error("component lost actual test/conversion wall timing", command)
						}
					}
					if command.Phase == "test" {
						tests++
						expectedProcess, expectedRace := "passed", "not_observed"
						if wantOutcome == "failed" {
							expectedProcess = "process_failed"
						}
						if row.name == "race2" && index == 1 {
							expectedRace = "observed"
						}
						if command.Process != expectedProcess || command.RaceObservation != expectedRace {
							t.Error("component conflated assertion/race/process outcome", command)
						}
					}
					if command.Phase == "conversion" {
						conversions++
						if command.Process != "passed" || command.Events != "valid" {
							t.Error("component conversion lost exact failed/passed events", command)
						}
					}
				}
				if tests != 1 || conversions != 1 {
					t.Error("focused component repeated whole profile or lost converter", tests, conversions)
				}
			}
			if row.executions >= 2 {
				first := result.executions[result.Steps[0].ID].Component
				second := result.executions[result.Steps[1].ID].Component
				before, err := json.Marshal(first)
				if err != nil || first == second || second == nil || second.Checks == nil || len(second.Checks.Tests) == 0 {
					t.Fatal("component attempts share or lack current results", err)
				}
				outcome := second.Checks.Tests[0].Outcome
				second.Checks.Tests[0].Outcome = "incomplete"
				after, err := json.Marshal(first)
				second.Checks.Tests[0].Outcome = outcome
				if err != nil || !bytes.Equal(before, after) {
					t.Error("later current result aliases the first scalar result", err)
				}
			}
			if len(result.RepetitionGroups) != 1 {
				t.Error("component lacks one exact repetition group", result.RepetitionGroups)
			} else {
				group := result.RepetitionGroups[0]
				stepIDs := []string{}
				for _, step := range result.Steps[:min(row.attempts, 3)] {
					stepIDs = append(stepIDs, step.ID)
				}
				if group.ConfiguredStep != "components" || group.RequestedExecutions != 3 || group.CompletedExecutions != min(row.executions, 3) || group.Outcome != row.outcome || !slices.Equal(group.StepIDs, stepIDs) {
					t.Error("component changed N/K/outcome or attempted scalar references", group, stepIDs)
				}
			}
		})
	}
}

// full_only: false
func TestComponentPreparationFailureExposesTerminalContext(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprint(prepared), func(t *testing.T) {
			root := testRepositoryRoot(t)
			bootstrap := filepath.Join(t.TempDir(), "controlled-missing-bootstrap.json")
			ctx := workflowTestContext(t, root)
			controlOwner, err := newCurrentDirectory("enkv-component-environment-control-")
			if err != nil {
				t.Fatal(err)
			}
			control := controlOwner.path
			consumed, collected := false, false
			var commandErr error
			defer func() {
				if consumed && (!collected || !toolCommandsJoined(commandErr) || !sourceCommandsJoined(commandErr)) {
					t.Log("retained component environment control inputs:", control)
					return
				}
				if err := controlOwner.remove(true); err != nil {
					t.Error(err)
				}
			}()
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			operations := filepath.Join(control, "operations")
			// Permit the real metadata command only. Missing bootstrap must
			// refuse before compilation, inventory or any component body.
			script := "#!/bin/sh\nprintf '%s\\n' \"$1 $2\" >> " + shellQuote(operations) + " || exit 91\ncase \"$1 $2\" in \"env -json\") exec " + shellQuote(realGo) + " \"$@\" ;; *) printf 'unexpected component preparation command\\n' >&2; exit 92 ;; esac\n"
			if err := os.WriteFile(filepath.Join(control, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
			var group *preparedComponentGroup
			if prepared {
				group = newPreparedComponentGroup(ctx)
				defer group.cancel()
			}
			var output bytes.Buffer
			consumed = true
			run, err := runComponents(ctx, root, bootstrap, "dev", singleTestRequest("TestFiniteRepetitionProcessWitness"), 1, &output, group)
			collected, commandErr = true, err
			if err == nil || run == nil || run.record.Outcome != "failed" || run.record.Checks != nil {
				t.Fatal("missing bootstrap did not stop component preparation", err)
			}
			if !toolCommandsJoined(err) || !sourceCommandsJoined(err) {
				t.Fatal("missing bootstrap lost an actual preparation process join", err)
			}
			t.Cleanup(func() {
				if err := run.privateOwner.remove(); err != nil {
					t.Error(err)
				}
			})
			observed, readErr := os.ReadFile(operations)
			if readErr != nil || string(observed) != "env -json\n" || run.record.Toolchain == "" || run.record.BuildClosure != nil {
				t.Fatal("missing bootstrap crossed compilation or lost its real metadata prefix", string(observed), readErr, run.record)
			}
			if !errors.Is(err, os.ErrNotExist) {
				t.Error("component preparation lost the missing-input cause", err)
			}
			if !strings.Contains(output.String(), bootstrap) {
				t.Error("component preparation omitted the failed input from the terminal", output.String())
			}
			if run.record.preparation == nil || run.record.preparation.Preparation != "failed" || len(run.record.preparation.Commands) != 0 {
				t.Error("missing bootstrap invented build or body commands", run.record.preparation)
			}
			factRows := 0
			for _, line := range strings.Split(output.String(), "\n") {
				if strings.HasPrefix(line, "Check phase=") && strings.Contains(line, " process=") {
					factRows++
				}
			}
			if factRows != 0 {
				t.Error("component preparation terminal invented command facts after the invocation metadata capture", factRows, output.String())
			}

		})
	}
	for _, condition := range []string{"environment-exit", "environment-canceled", "environment-start-refused"} {
		for _, prepared := range []bool{false, true} {
			t.Run(condition+"/"+fmt.Sprint(prepared), func(t *testing.T) {
				testComponentEarlyEnvironmentResult(t, condition, prepared)
			})
		}
	}

}

func testComponentEarlyEnvironmentResult(t *testing.T, condition string, prepared bool) {
	t.Helper()
	root := testRepositoryRoot(t)
	ctx, cancel := context.WithTimeout(workflowTestContext(t, root), 10*time.Second)
	defer cancel()
	controlOwner, err := newCurrentDirectory("enkv-component-environment-control-")
	if err != nil {
		t.Fatal(err)
	}
	control := controlOwner.path
	consumed := false
	defer func() {
		if !consumed {
			if err := controlOwner.remove(true); err != nil {
				t.Error(err)
			}
		}
	}()
	operations, ready := filepath.Join(control, "operations"), filepath.Join(control, "ready")
	body := []byte("invalid executable format\x00")
	if condition != "environment-start-refused" {
		script := "#!/bin/sh\nprintf '%s\\n' \"$1 $2\" >> " + shellQuote(operations) + " || exit 91\n[ \"$1 $2\" = \"env -json\" ] || exit 92\n"
		if condition == "environment-exit" {
			script += "printf 'controlled environment failure\\n' >&2\nexit 19\n"
		} else {
			script += "printf '%s' \"$$\" > " + shellQuote(ready) + " || exit 93\nwhile :; do sleep 0.01; done\n"
		}
		body = []byte(script)
	}
	if err := os.WriteFile(filepath.Join(control, "go"), body, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
	var group *preparedComponentGroup
	if prepared {
		group = newPreparedComponentGroup(ctx)
		defer group.cancel()
	}
	type result struct {
		run *componentRun
		err error
	}
	done := make(chan result, 1)
	var terminal bytes.Buffer
	consumed = true
	go func() {
		run, err := runComponents(ctx, root, filepath.Join(control, "missing-bootstrap.json"), "dev", singleTestRequest("TestFiniteRepetitionProcessWitness"), 1, &terminal, group)
		done <- result{run, err}
	}()
	var returned result
	collected := false
	defer func() {
		cancel()
		if !collected {
			select {
			case returned = <-done:
				collected = true
			case <-time.After(3 * processGroupSettlementTimeout):
				t.Error("controlled environment invocation did not join after cancellation")
				return
			}
		}
		if !collected || !toolCommandsJoined(returned.err) || !sourceCommandsJoined(returned.err) {
			t.Log("retained component environment control inputs:", control)
			return
		}
		if returned.run != nil {
			if err := returned.run.privateOwner.remove(); err != nil {
				t.Error(err)
			}
		}
		if err := controlOwner.remove(true); err != nil {
			t.Error(err)
		}
	}()
	if condition == "environment-canceled" {
		waitProcessMarker(t, ctx, ready)
		cancel()
	}
	select {
	case returned = <-done:
		collected = true
	case <-ctx.Done():
		select {
		case returned = <-done:
			collected = true
		case <-time.After(3 * processGroupSettlementTimeout):
			t.Fatal("controlled environment invocation did not settle")
		}
	}
	status, started := "process_failed", condition != "environment-start-refused"
	if condition == "environment-canceled" {
		status = "interrupted"
	}
	var failure *toolFailure
	if !errors.As(returned.err, &failure) || failure.operation != "go env" || failure.process.Status != status || failure.process.Started != started || !failure.process.Joined || !toolCommandsJoined(returned.err) || !sourceCommandsJoined(returned.err) {
		t.Fatal("environment control failed before its actual expected process state", returned.err)
	}
	switch condition {
	case "environment-exit":
		var exit *exec.ExitError
		if !errors.As(returned.err, &exit) || exit.ExitCode() != 19 || string(failure.stderr) != "controlled environment failure\n" {
			t.Fatal("environment refusal lost its original exit or stderr", returned.err)
		}
	case "environment-canceled":
		if !errors.Is(returned.err, context.Canceled) {
			t.Fatal("in-flight environment cancellation lost its original cause", returned.err)
		}
	case "environment-start-refused":
		if !errors.Is(returned.err, syscall.ENOEXEC) {
			t.Fatal("never-started environment command lost its executable-format refusal", returned.err)
		}
	}
	observed, readErr := os.ReadFile(operations)
	if started && (readErr != nil || string(observed) != "env -json\n") || !started && !os.IsNotExist(readErr) {
		t.Fatal("environment control dispatched an unexpected command", string(observed), readErr)
	}
	if returned.run != nil {
		t.Fatal("failed invocation metadata allocated a component result before binding", returned.run.record)
	}
	if failure.facts == nil || failure.facts.Process != status || failure.facts.Started != started || !failure.facts.Joined || failure.facts.Scope != "core" {
		t.Fatal("environment failure lost its actual command facts", failure.facts)
	}
	block := fmt.Sprintf("Operation: go env\nProcess: %s\nStarted: %t\nJoined: true\n", status, started)
	if strings.Count(terminal.String(), block) != 1 || strings.Count(terminal.String(), "Operation:") != 1 || strings.Contains(terminal.String(), "Check phase=") || strings.Contains(terminal.String(), "Components ") {
		t.Fatal("environment failure omitted its actual diagnostic or invented later component work", terminal.String())
	}

}
