package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

func componentRepetitionAssemblyFixture(t *testing.T) (context.Context, string, string) {
	t.Helper()
	root := sourceFixtureRoot(t)
	fixtureCtx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
	witness, err := os.ReadFile(filepath.Join(root, "tests/shared/repetition_process_fixture_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Ownership and source-change checks need the process witness, module
	// metadata, admissions and output builders, rather than Product test bodies.
	for _, group := range []string{"core", "tests/shared", "tests/hermetic"} {
		directory := filepath.Join(root, group)
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	writeLocalGoFixture(t, root, "core/fixture.go", "package core\n")
	writeLocalGoFixture(t, root, "tests/shared/repetition_process_fixture_test.go", string(witness))
	// Selection metadata only: full focus requires this compiled root, but the
	// exact witness selection must never execute it or claim capacity coverage.
	writeLocalGoFixture(t, root, "tests/hermetic/repetition_profile_fixture_test.go", `package core
import "testing"
// full_only: true
func `+maximumCapacityComponent+`(t *testing.T) {
	t.Fatal("profile inventory fixture must remain outside the focused execution")
}
`)
	return fixtureCtx, root, bootstrap
}

// full_only: false
func TestComponentWorkflowRepetitionGroupsKeepTheirProfilesAndBuilds(t *testing.T) {
	fixtureCtx, root, bootstrap := componentRepetitionAssemblyFixture(t)
	directory := t.TempDir()
	commands := filepath.Join(directory, "go-compiles")
	if err := os.Mkdir(commands, 0700); err != nil {
		t.Fatal(err)
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	// Only real preparation compiles publish observations. Concurrent validation
	// and execution commands do not append to a shared command journal.
	observer := `#!/bin/sh
set -eu
compile=false
for arg do
 if [ "$arg" = -c ]; then compile=true; fi
done
if [ "$compile" = true ] && [ "$PWD" = "$ENKV_COMPONENT_PROFILE_CORE" ]; then
 own="$ENKV_COMPONENT_GO_COMMAND_LOG/$$"
 mkdir "$own"
 printf '%s\n' "$@" > "$own/args.pending"
 mv "$own/args.pending" "$own/args"
fi
exec '` + strings.ReplaceAll(realGo, "'", "'\"'\"'") + `' "$@"
`
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_COMPONENT_GO_COMMAND_LOG", commands)
	t.Setenv("ENKV_COMPONENT_PROFILE_CORE", filepath.Join(root, "core"))
	// The witness's empty mode still checks fresh process globals, a private
	// fixture and the exact literal child. Its optional journal requires serial
	// callers, so it cannot be the observer for concurrent repetitions.
	t.Setenv("ENKV_COMPONENT_REPETITION_WITNESS", "")
	t.Setenv("ENKV_COMPONENT_REPETITION_SECOND_FAILURE", "")
	const requested = "TestFiniteRepetitionProcessWitness/leaf[a]+b"
	const selector = "^TestFiniteRepetitionProcessWitness$/^leaf\\[a\\]\\+b$"
	ids := []string{"development-r1", "development-r2", "complete-profile-r1", "complete-profile-r2"}
	configured := []string{"development", "complete-profile"}
	profiles := []string{"dev", "full"}
	path := filepath.Join(directory, "workflow.json")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "component-profile-groups", "execution": map[string]any{"parallel": 2}, "steps": []any{
		map[string]any{"id": configured[0], "kind": "component-tests", "profile": profiles[0], "tests": singleTestRequest(requested), "repetitions": 2},
		map[string]any{"id": configured[1], "kind": "component-tests", "profile": profiles[1], "tests": singleTestRequest(requested), "repetitions": 2},
	}})
	ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(fixtureCtx, true), 2), 5*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil || len(plan.Steps) != 4 || plan.Execution.Resolved.Parallel != 2 {
		t.Fatal("actual profile group plan lost its four executions or admitted parallel2", err, plan.Execution)
	}
	var output bytes.Buffer
	t.Cleanup(func() {
		if t.Failed() {
			body := output.Bytes()
			if len(body) > 8192 {
				body = body[len(body)-8192:]
			}
			t.Log("bounded actual profile workflow output:", string(body))
		}
	})
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
	if prepared != nil {
		t.Cleanup(func() {
			tail, release := finalizationContext(ctx)
			defer release()
			if err := prepared.close(tail); err != nil {
				t.Error("close prepared profile groups", err)
			}
		})
	}
	if err != nil {
		t.Fatal("actual profile group preparation failed", err)
	}
	if prepared.plan.Execution.Resolved.Parallel != 2 || len(prepared.components) != 1 {
		t.Fatal("first ready profile group lost its allocation or prepared later work", prepared.plan.Execution, len(prepared.components))
	}
	compiled, err := filepath.Glob(filepath.Join(commands, "*", "args"))
	if err != nil || len(compiled) != 1 {
		t.Fatal("first ready group did not construct one binary", compiled, err)
	}
	preparedOwnerPath := prepared.current.path
	result, runErr := runPreparedWorkflow(ctx, root, bootstrap, prepared, &output)
	if runErr != nil {
		t.Fatal("actual focused profile groups failed", runErr)
	}
	if len(prepared.components) != 2 {
		t.Fatal("later profile group was not acquired at dispatch", len(prepared.components))
	}
	expectedBuilds := map[string]bool{}
	buildHashes := map[string]string{}
	for _, name := range configured {
		group := prepared.components[name]
		if group == nil || group.assembled.Binary == "" || group.assembled.Closure.BinarySHA256 == "" || executionCapacityFromContext(group.ctx).Parallel != 2 {
			t.Fatal("configured profile lacks its prepared build/allocation", name)
		}
		expectedBuilds[group.assembled.Binary] = true
		buildHashes[name] = group.assembled.Closure.BinarySHA256
		if _, err := os.Stat(group.assembled.Binary); err != nil {
			t.Fatal("prepared profile build is not live before dispatch", name, err)
		}
	}
	if len(expectedBuilds) != 1 {
		t.Fatal("compatible profiles constructed separate binaries", expectedBuilds)
	}
	observedCompiles := map[string]bool{}
	for _, file := range compiled {
		body, err := os.ReadFile(file)
		args := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
		index := slices.Index(args, "-o")
		if err != nil || len(args) == 0 || args[0] != "test" || !slices.Contains(args, "-c") || !slices.Contains(args, "-race") || index < 0 || index+1 >= len(args) || !expectedBuilds[args[index+1]] || observedCompiles[args[index+1]] {
			t.Fatal("actual compile lost its race build or configured prepared owner", args, err)
		}
		observedCompiles[args[index+1]] = true
	}
	tail, release := finalizationContext(ctx)
	runErr = errors.Join(runErr, prepared.close(tail))
	release()
	if runErr != nil {
		t.Fatal("actual focused profile groups failed", runErr)
	}
	if result.Outcome != "passed" || len(result.Steps) != 4 {
		t.Fatal("actual profile groups did not complete all four executions", result.Outcome, result.Steps)
	}
	completedCompiles, err := filepath.Glob(filepath.Join(commands, "*", "args"))
	if err != nil || !slices.Equal(completedCompiles, compiled) {
		t.Fatal("repetitions rebuilt a prepared profile binary", compiled, completedCompiles, err)
	}
	runIDs := map[string]bool{}
	privatePaths := map[string]bool{}
	for index, step := range result.Steps {
		name, profile := configured[index/2], profiles[index/2]
		execution := result.executions[step.ID]
		scalar, owner := execution.Component, execution.componentOwner
		if step.ID != ids[index] || step.ConfiguredStep != name || step.Repetition != index%2+1 || step.Repetitions != 2 || step.Outcome != "passed" || step.StartedAt == nil || step.FinishedAt == nil || scalar == nil || owner == nil {
			t.Fatal("profile group lost one distinct scalar execution", step)
		}
		if !records.ValidRunID(scalar.RunID) || runIDs[scalar.RunID] || scalar.Outcome != "passed" || scalar.FinishedAt == nil || !sameSource(scalar.Source, result.Source) {
			t.Fatal("profile execution lost its independent identity/source", step.ID)
		}
		runIDs[scalar.RunID] = true
		checks := scalar.Checks
		if checks == nil || checks.Diagnostics == nil || checks.Profile != profile || checks.Focus == nil || checks.Focus.Tests[0] != requested || checks.Selection != selector || !completeFocusedComponentEvidence(*checks) {
			t.Fatal("profile execution changed exact profile/literal selection", step.ID, checks)
		}
		if scalar.BuildClosure == nil || !scalar.BuildClosure.Race || scalar.BuildClosure.RaceOptions != raceOptions || !checks.Race || checks.RaceOptions != raceOptions || scalar.BuildClosure.BinarySHA256 != buildHashes[name] || !expectedBuilds[owner.assembled.Binary] {
			t.Fatal("profile execution rebuilt the shared binary or lost race facts", step.ID)
		}
		if scalar.passedFor(result.Source, scalar.Toolchain) || completeComponentEvidence(*checks, "hermetic", "memory") {
			t.Fatal("focused profile execution gained complete-profile authority", step.ID)
		}
		terminals := map[string]bool{}
		for _, terminal := range checks.Tests {
			if terminal.Outcome != "passed" || terminals[terminal.Name] || terminal.Name != "TestFiniteRepetitionProcessWitness" && terminal.Name != requested {
				t.Fatal("profile execution lost exact passing parent/child terminals", step.ID, terminal)
			}
			terminals[terminal.Name] = true
		}
		if len(terminals) != 2 || !terminals["TestFiniteRepetitionProcessWitness"] || !terminals[requested] {
			t.Fatal("profile execution omitted its real parent/child", step.ID)
		}
		tests, converted, converterBuilds := 0, 0, 0
		for _, command := range checks.Diagnostics.Commands {
			if !command.Started || !command.Joined || command.Process != "passed" || command.RaceObservation != "not_observed" {
				t.Fatal("profile execution lacks race-clean positive joins", step.ID, command)
			}
			if command.ToolCleanup != "passed" && command.ToolCleanup != "not_required" && (command.Phase != "preparation" || command.ToolCleanup != "not_owner") {
				t.Fatal("profile execution lacks owned/borrowed tool disposition", step.ID, command)
			}
			switch command.Phase {
			case "preparation":
				if command.Scope == "test2json" {
					converterBuilds++
				}
			case "test":
				tests++
			case "conversion":
				converted++
			}
		}
		if tests != 1 || converted != 1 {
			t.Fatal("profile execution lost one actual test/converter", step.ID, tests, converted)
		}
		wantConverterBuilds := 0
		if index == 0 {
			wantConverterBuilds = 1
		}
		if converterBuilds != wantConverterBuilds {
			t.Fatal("profile execution repeated or omitted original converter preparation", step.ID, converterBuilds, wantConverterBuilds)
		}
		if owner.privateOwner.path == "" || privatePaths[owner.privateOwner.path] {
			t.Fatal("profile executions share mutable private ownership", step.ID)
		}
		privatePaths[owner.privateOwner.path] = true
		if _, err := os.Stat(owner.privateOwner.path); !os.IsNotExist(err) {
			t.Fatal("joined profile execution retained mutable files", step.ID, err)
		}
		if index >= 2 {
			for _, earlier := range result.Steps[:2] {
				if step.StartedAt.Before(*earlier.FinishedAt) {
					t.Fatal("ungrouped full profile began before dev group settled", earlier.ID, step.ID)
				}
			}
		}
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {0, 3}, {1, 2}, {1, 3}, {2, 3}} {
		first := result.executions[ids[pair[0]]].Component
		other := result.executions[ids[pair[1]]].Component
		before, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		outcome := other.Checks.Tests[0].Outcome
		other.Checks.Tests[0].Outcome = "incomplete"
		after, marshalErr := json.Marshal(first)
		other.Checks.Tests[0].Outcome = outcome
		if marshalErr != nil || !bytes.Equal(before, after) {
			t.Fatal("profile executions share mutable check state", ids[pair[0]], ids[pair[1]], marshalErr)
		}
	}
	if len(result.RepetitionGroups) != 2 {
		t.Fatal("wrong configured group count", result.RepetitionGroups)
	}
	for index, name := range configured {
		group := result.RepetitionGroups[index]
		if group.ConfiguredStep != name || group.RequestedExecutions != 2 || group.CompletedExecutions != 2 || group.Outcome != "passed" || !slices.Equal(group.StepIDs, ids[2*index:2*index+2]) {
			t.Error("profile group lost independent exact N/K/references", group)
		}
	}
	for binary := range expectedBuilds {
		if _, err := os.Stat(binary); !os.IsNotExist(err) {
			t.Error("joined profile group retained immutable build", binary, err)
		}
	}
	if _, err := os.Stat(preparedOwnerPath); !os.IsNotExist(err) {
		t.Error("joined profile groups retained shared preparation owner", err)
	}
}

// full_only: false
func TestComponentPreparedGroupKeepsDeadlineAndParentCancellation(t *testing.T) {
	fixed := newPreparedComponentGroup(context.WithoutCancel(t.Context()))
	preparation, finishPreparation := fixed.duration.preparationContext(fixed.ctx)
	_, preparationBounded := preparation.Deadline()
	finishPreparation()
	fixed.cancel()
	if preparationBounded || componentGroupAllowance != 0 {
		t.Fatal("default component group added a cumulative deadline")
	}
	fixtureCtx, root, bootstrap := componentRepetitionAssemblyFixture(t)
	fixtureCtx, artifactOwner := withInvocationArtifacts(fixtureCtx)
	directory := t.TempDir()
	witness := filepath.Join(directory, "executions.jsonl")
	t.Setenv("ENKV_COMPONENT_REPETITION_WITNESS", witness)
	t.Setenv("ENKV_COMPONENT_REPETITION_SECOND_FAILURE", "")
	bounded, boundedCancel := context.WithTimeout(t.Context(), 5*time.Minute)
	capped := newPreparedComponentGroup(bounded)
	parentDeadline, _ := bounded.Deadline()
	cappedDeadline, ok := capped.ctx.Deadline()
	capped.cancel()
	boundedCancel()
	if !ok || !cappedDeadline.Equal(parentDeadline) {
		t.Fatal("component group extended its parent's deadline", cappedDeadline, parentDeadline)
	}
	// Reuse the default unlimited group without adding a deadline on a later call.
	parent, cancel := context.WithCancel(fixtureCtx)
	defer cancel()
	group := newPreparedComponentGroup(parent)
	defer group.cancel()
	const requested = "TestFiniteRepetitionProcessWitness/leaf[a]+b"
	var first *componentRun
	joined := true
	defer func() {
		tail, finish := finalizationContext(fixtureCtx)
		defer finish()
		if err := artifactOwner.close(tail, joined); err != nil {
			t.Error("component invocation owner did not close after its consumers", err)
		}
		if first != nil && joined {
			if _, err := os.Stat(first.assembled.Binary); !os.IsNotExist(err) {
				t.Error("joined invocation retained its shared component build", err)
			}
		}
	}()
	var owned []privateDirectory
	path := filepath.Join(directory, "workflow.json")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "component-owner-cancellation", "profile": "dev", "steps": []any{
		map[string]any{"id": "first", "kind": "component-tests", "profile": "dev", "tests": singleTestRequest(requested)},
		map[string]any{"id": "second", "kind": "component-tests", "profile": "dev", "tests": singleTestRequest(requested)},
	}})
	plan, err := resolveWorkflow(parent, root, workflowRequest{Path: path})
	if err != nil || len(plan.Steps) != 2 {
		t.Fatal("actual component owner workflow plan unavailable", err)
	}
	var output bytes.Buffer
	currentResult, workflowErr := executeWorkflow(parent, root, plan, &output, &owned, nil, func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
		run, err := runComponents(parent, root, bootstrap, "dev", singleTestRequest(requested), 1, io.Discard, group)
		joined = joined && toolCommandsJoined(err)
		if run == nil {
			return workflowStepExecution{}, errors.Join(err, errors.New("actual repeated owner unavailable"))
		}
		owned = append(owned, run.privateOwner)
		if err != nil || run.record.Checks == nil || run.record.Checks.Diagnostics == nil || !completeFocusedComponentEvidence(*run.record.Checks) {
			t.Error("actual repeated owner execution failed", step.ID, err)
			return workflowStepExecution{Evidence: run.evidencePath, Component: &run.record}, errors.Join(err, errors.New("actual repeated owner evidence incomplete"))
		}
		if step.ID == "first" {
			first = run
		} else if run.assembled.Binary != first.assembled.Binary || run.privateOwner.path == first.privateOwner.path {
			t.Error("actual reused owner changed the build or scalar owner")
		}
		if group.duration.execution == nil {
			return workflowStepExecution{Evidence: run.evidencePath, Component: &run.record}, errors.New("runComponents did not activate the configured execution allowance")
		}
		if deadline, bounded := group.duration.execution.Deadline(); bounded {
			t.Error("repeated execution added a cumulative deadline", deadline)
		}
		for _, command := range run.record.Checks.Diagnostics.Commands {
			if !command.Joined {
				t.Error("completed owner execution has an unjoined command", command)
			}
		}
		if step.ID == "second" {
			cancel()
			canceledRun, canceledErr := runComponents(parent, root, bootstrap, "dev", singleTestRequest(requested), 1, io.Discard, group)
			joined = joined && toolCommandsJoined(canceledErr)
			if canceledErr == nil || group.ctx.Err() != context.Canceled || canceledRun != nil && canceledRun.record.Checks != nil {
				t.Error("parent cancellation admitted another component execution", canceledRun, canceledErr)
			}
			if _, err := os.Stat(first.assembled.Binary); err != nil {
				t.Error("group cancellation disposed the first build before its owner", err)
			}
		}
		return workflowStepExecution{Evidence: run.evidencePath, Component: &run.record}, nil
	})
	if workflowErr != nil || len(owned) != 2 {
		t.Fatal("actual component owner workflow failed", workflowErr, output.String())
	}
	body, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := decodeObjects[ordinaryRepetitionObservation](body)
	if err != nil || len(actual) != 2 || actual[0].PID == actual[1].PID || actual[0].Binary != actual[1].Binary {
		t.Error("cancellation did not stop at two real joined executions", actual, err)
	}
	for index, private := range owned {
		if _, err := os.Stat(private.path); !os.IsNotExist(err) {
			t.Error("completed component workflow retained disposable files", private.path, err)
		}
		if currentResult.executions[currentResult.Steps[index].ID].Component == nil {
			t.Error("component cancellation lost its current result")
		}

	}
}

// full_only: false
func TestWorkflowFocusedComponentGroupOwnsConcurrentRecordsAndCleanup(t *testing.T) {
	fixtureCtx, root, bootstrap := componentRepetitionAssemblyFixture(t)
	directory := t.TempDir()
	compiles, bodies := filepath.Join(directory, "compiles"), filepath.Join(directory, "bodies")
	for _, path := range []string{compiles, bodies} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	// The real compiler is observed; the two selected bodies prove overlapping
	// use of the shared executable and retain their actual process identities.
	observer := `#!/bin/sh
set -eu
compile=false
for arg do
 if [ "$arg" = -c ]; then compile=true; fi
done
if [ "$compile" = true ] && [ "$PWD" = "$ENKV_FOCUSED_PARALLEL_CORE" ]; then
 own="$ENKV_FOCUSED_PARALLEL_COMPILES/$$"
 mkdir "$own"
 printf '%s\n' "$@" > "$own/args.pending"
 mv "$own/args.pending" "$own/args"
fi
exec '` + strings.ReplaceAll(realGo, "'", "'\"'\"'") + `' "$@"
`
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_FOCUSED_PARALLEL_CORE", filepath.Join(root, "core"))
	t.Setenv("ENKV_FOCUSED_PARALLEL_COMPILES", compiles)
	t.Setenv("ENKV_FOCUSED_PARALLEL_BODIES", bodies)
	t.Setenv("ENKV_COMPONENT_REPETITION_WITNESS", "")
	t.Setenv("ENKV_COMPONENT_REPETITION_SECOND_FAILURE", "")
	sourcePath := filepath.Join(root, "tests/shared/repetition_process_fixture_test.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(source), "\"testing\"", "\"testing\"\n\"time\"", 1)
	body = strings.Replace(body, "func TestFiniteRepetitionProcessWitness(t *testing.T) {", "func TestFiniteRepetitionProcessWitness(t *testing.T) {\nwaitForConcurrentComponent(t)", 1)
	body += `
func waitForConcurrentComponent(t *testing.T) {
 t.Helper()
 directory := os.Getenv("ENKV_FOCUSED_PARALLEL_BODIES")
 binary, err := os.Executable()
 if err != nil { t.Fatal(err) }
 own := filepath.Join(directory, fmt.Sprint(os.Getpid()))
 if err := os.Mkdir(own, 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(own, "binary"), []byte(binary), 0600); err != nil { t.Fatal(err) }
 deadline := time.Now().Add(10*time.Second)
 for {
  ready, err := filepath.Glob(filepath.Join(directory, "*", "binary"))
  if err != nil { t.Fatal(err) }
  if len(ready) == 2 { break }
  if time.Now().After(deadline) { t.Fatal("second component body did not enter") }
  time.Sleep(10*time.Millisecond)
 }
 if _, err := os.Stat(binary); err != nil { t.Fatal("shared executable was removed while borrowed", err) }
}
`
	if err := os.WriteFile(sourcePath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	requests := []string{"TestFiniteRepetitionProcessWitness/leaf[a]+b", "TestFiniteRepetitionProcessWitness"}
	selectors := []string{`^TestFiniteRepetitionProcessWitness$/^leaf\[a\]\+b$`, `^TestFiniteRepetitionProcessWitness$`}
	profiles := []string{"dev", "full"}
	ids := []string{"literal-child", "whole-parent"}
	path := filepath.Join(directory, "workflow.json")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "focused-component-owners", "execution": map[string]any{"parallel": 2}, "steps": []any{
		map[string]any{"id": ids[0], "kind": "component-tests", "profile": profiles[0], "tests": singleTestRequest(requests[0]), "parallel_group": "focused"},
		map[string]any{"id": ids[1], "kind": "component-tests", "profile": profiles[1], "tests": singleTestRequest(requests[1]), "parallel_group": "focused"},
	}})
	ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(fixtureCtx, true), 2), 5*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil || len(plan.Steps) != 2 || plan.Execution.Resolved.Parallel != 2 {
		t.Fatal("real focused group did not retain its admitted parallel2", err, plan.Execution)
	}
	var output bytes.Buffer
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
	if prepared != nil {
		t.Cleanup(func() {
			tail, release := finalizationContext(ctx)
			defer release()
			if err := prepared.close(tail); err != nil {
				t.Error("close prepared focused-group owner", err)
			}
		})
	}
	if err != nil {
		body := output.Bytes()
		if len(body) > 8192 {
			body = body[len(body)-8192:]
		}
		t.Fatal("actual component preparations failed", err, string(body))
	}
	if prepared.plan.Execution.Resolved.Parallel != 2 || len(prepared.components) != 2 {
		t.Fatal("prepared focused group lost its admitted owners", prepared.plan.Execution, len(prepared.components))
	}
	expectedBuilds := map[string]bool{}
	for _, id := range ids {
		group := prepared.components[id]
		if group == nil || group.assembled.Binary == "" || executionCapacityFromContext(group.ctx).Parallel != 2 {
			t.Fatal("configured focus lacks its prepared build/allocation", id)
		}
		expectedBuilds[group.assembled.Binary] = true
	}
	compiled, err := filepath.Glob(filepath.Join(compiles, "*", "args"))
	if err != nil || len(compiled) != 1 || len(expectedBuilds) != 1 {
		t.Fatal("compatible focuses did not share one actual binary", compiled, err)
	}
	observedCompiles := map[string]bool{}
	for _, file := range compiled {
		body, err := os.ReadFile(file)
		args := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
		index := slices.Index(args, "-o")
		if err != nil || !slices.Contains(args, "-race") || index < 0 || index+1 >= len(args) || !expectedBuilds[args[index+1]] || observedCompiles[args[index+1]] {
			t.Fatal("observed compile lost its race build or prepared owner", args, err)
		}
		observedCompiles[args[index+1]] = true
	}
	preparedOwnerPath := prepared.current.path
	result, runErr := runPreparedWorkflow(ctx, root, bootstrap, prepared, &output)
	tail, release := finalizationContext(ctx)
	runErr = errors.Join(runErr, prepared.close(tail))
	release()
	if runErr != nil {
		body := output.Bytes()
		if len(body) > 8192 {
			body = body[len(body)-8192:]
		}
		t.Fatal("real concurrent validation/execution failed", runErr, string(body))
	}
	if result.Outcome != "passed" || len(result.Steps) != 2 {
		t.Fatal("focused workflow lost one of its selected results", result.Outcome, result.Steps)
	}
	observedBodies, err := filepath.Glob(filepath.Join(bodies, "*", "binary"))
	if err != nil || len(observedBodies) != 2 {
		t.Fatal("two real selected bodies did not reach their gate", observedBodies, err)
	}
	pids := []int{}
	for _, file := range observedBodies {
		binary, readErr := os.ReadFile(file)
		pid, parseErr := strconv.Atoi(filepath.Base(filepath.Dir(file)))
		if readErr != nil || parseErr != nil || pid <= 0 || !expectedBuilds[string(binary)] {
			t.Fatal("invalid component process observation", file, readErr, parseErr, string(binary), pid)
		}
		pids = append(pids, pid)
	}
	if pids[0] == pids[1] {
		t.Fatal("concurrent executions reused a process", pids)
	}
	runIDs := map[string]bool{}
	privatePaths := map[string]bool{}
	for index, step := range result.Steps {
		scalar := result.executions[step.ID].Component
		if step.ID != ids[index] || step.Outcome != "passed" || step.StartedAt == nil || step.FinishedAt == nil || scalar == nil {
			t.Fatal("concurrent focus lost its distinct scalar result", step)
		}
		if !records.ValidRunID(scalar.RunID) || runIDs[scalar.RunID] || scalar.Outcome != "passed" || scalar.FinishedAt == nil || !sameSource(scalar.Source, result.Source) {
			t.Fatal("component record identity/source changed", step.ID)
		}
		runIDs[scalar.RunID] = true
		checks := scalar.Checks
		if checks == nil || !completeFocusedComponentEvidence(*checks) || checks.Focus == nil || checks.Focus.Tests[0] != requests[index] || checks.Selection != selectors[index] || checks.Profile != profiles[index] {
			t.Fatal("concurrent focus changed its exact selection/profile", step.ID, checks)
		}
		if scalar.BuildClosure == nil || !scalar.BuildClosure.Race || scalar.BuildClosure.RaceOptions != raceOptions || !checks.Race || checks.RaceOptions != raceOptions {
			t.Fatal("actual component lost its accepted race facts", step.ID)
		}

		terminals := map[string]bool{}
		for _, terminal := range checks.Tests {
			if terminal.Outcome != "passed" || terminals[terminal.Name] || terminal.Name != "TestFiniteRepetitionProcessWitness" && terminal.Name != "TestFiniteRepetitionProcessWitness/leaf[a]+b" {
				t.Fatal("focus lost exact passing parent/leaf terminals", step.ID, terminal)
			}
			terminals[terminal.Name] = true
		}
		if len(terminals) != 2 || !terminals["TestFiniteRepetitionProcessWitness"] || !terminals["TestFiniteRepetitionProcessWitness/leaf[a]+b"] {
			t.Fatal("focus omitted required parent/leaf", step.ID)
		}
		if scalar.passedFor(result.Source, scalar.Toolchain) || completeComponentEvidence(*checks, "hermetic", "memory") {
			t.Fatal("focused execution acquired complete-profile borrowing authority", step.ID)
		}
		tests, converted := 0, 0
		for _, command := range checks.Diagnostics.Commands {
			if !command.Started || !command.Joined || command.Process != "passed" || command.RaceObservation != "not_observed" {
				t.Fatal("actual command lacks race-clean positive join", step.ID, command)
			}
			if command.ToolCleanup != "passed" && command.ToolCleanup != "not_required" && (command.Phase != "preparation" || command.ToolCleanup != "not_owner") {
				t.Fatal("actual command lacks its owned or borrowed tool disposition", step.ID, command)
			}
			switch command.Phase {
			case "test":
				tests++
			case "conversion":
				converted++
			}
		}
		if tests != 1 || converted != 1 {
			t.Fatal("focus lost its one actual test/converter", step.ID, tests, converted)
		}
		owner := result.executions[step.ID].componentOwner
		if owner == nil || !expectedBuilds[owner.assembled.Binary] {
			t.Fatal("scalar result lost its shared prepared build", step.ID)
		}
		if owner.privateOwner.path == "" || privatePaths[owner.privateOwner.path] {
			t.Fatal("parallel callbacks share mutable private state", step.ID, owner.privateOwner.path)
		}
		privatePaths[owner.privateOwner.path] = true
		if _, err := os.Stat(owner.privateOwner.path); !os.IsNotExist(err) {
			t.Fatal("joined callback retained its mutable private directory", step.ID, err)
		}
		published := 0
		for _, line := range bytes.Split(output.Bytes(), []byte{'\n'}) {
			if !bytes.HasPrefix(line, []byte(`{"type":"test_result"`)) {
				continue
			}
			var result currentTestResult
			if err := json.Unmarshal(line, &result); err != nil {
				t.Fatal("current result output is invalid", err)
			}
			if result.Step != step.ID {
				continue
			}
			published++
			if result.Outcome != "passed" || result.Component == nil || result.Component.Checks == nil || result.Component.Checks.Focus == nil || !slices.Equal(result.Component.Checks.Focus.Tests, []string{requests[index]}) {
				t.Fatal("current result changed the selected focus", step.ID)
			}
		}
		if published != 1 {
			t.Fatal("current focus result was lost or repeated", step.ID, published)
		}
	}
	first := result.executions[ids[0]].Component
	second := result.executions[ids[1]].Component
	before, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	outcome := second.Checks.Tests[0].Outcome
	second.Checks.Tests[0].Outcome = "incomplete"
	after, marshalErr := json.Marshal(first)
	second.Checks.Tests[0].Outcome = outcome
	if marshalErr != nil || !bytes.Equal(before, after) {
		t.Fatal("parallel result owners share mutable check state", marshalErr)
	}
	if !result.Steps[0].StartedAt.Before(*result.Steps[1].FinishedAt) || !result.Steps[1].StartedAt.Before(*result.Steps[0].FinishedAt) {
		t.Fatal("actual focused callback intervals did not overlap")
	}
	for _, pid := range pids {
		if probe := syscall.Kill(pid, 0); !errors.Is(probe, syscall.ESRCH) {
			t.Fatal("component process survived joined workflow", pid, probe)
		}
	}
	for binary := range expectedBuilds {
		if _, err := os.Stat(binary); !os.IsNotExist(err) {
			t.Fatal("joined workflow retained immutable prepared build", binary, err)
		}
	}
	if _, err := os.Stat(preparedOwnerPath); !os.IsNotExist(err) {
		t.Fatal("joined workflow retained shared preparation owner", err)
	}
}

// full_only: false
func TestPreparedComponentKeepsBuildAfterSourceChangedAtGroupProgress(t *testing.T) {
	fixtureCtx, root, bootstrap := componentRepetitionAssemblyFixture(t)
	observations := t.TempDir()
	witness := filepath.Join(observations, "executions.jsonl")
	t.Setenv("ENKV_COMPONENT_REPETITION_WITNESS", witness)
	t.Setenv("ENKV_COMPONENT_REPETITION_SECOND_FAILURE", "")
	workflow := filepath.Join(observations, "workflow.json")
	saveSelection(t, workflow, map[string]any{"schema_version": 1, "name": "current-component-inputs", "steps": []any{
		map[string]any{"id": "components", "kind": "component-tests", "profile": "dev", "tests": singleTestRequest("TestFiniteRepetitionProcessWitness/leaf[a]+b"), "repetitions": 4},
	}})
	ctx, cancel := context.WithTimeout(withRacePolicy(fixtureCtx, false), 5*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: workflow})
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"components-r1", "components-r2", "components-r3", "components-r4"}
	if len(plan.Steps) != len(ids) {
		t.Fatal("source control lost its four planned repetitions", plan.Steps)
	}
	for index, step := range plan.Steps {
		if step.ID != ids[index] || step.ConfiguredStep != "components" || step.Repetition != index+1 || step.Repetitions != 4 || !step.Selected || step.Kind != "component-tests" || step.Profile != "dev" {
			t.Fatal("source control changed its configured execution identities", step)
		}
	}
	// Prove active membership from the retained compiled inventory and build flags.
	var control bytes.Buffer
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, &control)
	if prepared != nil {
		defer func() {
			if err := prepared.close(ctx); err != nil {
				t.Error("close prepared component source control", err)
			}
		}()
	}
	if err != nil {
		t.Fatal("prepare component source control", err, control.String())
	}
	group := prepared.components["components"]
	if len(prepared.components) != 1 || group == nil || group.assembled.componentSelection == nil {
		t.Fatal("source control lost its configured component owner")
	}
	selected := group.assembled.componentSelection
	_, _, selectedGroups, _, placementErr := resolveComponentGroups(selected.evidence.Inventory, selected.evidence.Classifications, selected.profile, selected.requested, 1, selected.estimates)
	if group.assembled.Closure.Race || selected.evidence.Race || placementErr != nil || len(selectedGroups) != 1 {
		t.Fatal("source control changed its race policy or exact process group")
	}
	input := filepath.Join(root, "tests/shared/repetition_process_fixture_test.go")
	original, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	// Edit source at the third execution boundary, after two positive controls.
	writer := &ordinaryReviewEnvironmentWriter{before: "\x00", change: func() {
		body, err := os.ReadFile(witness)
		if err != nil {
			t.Fatal("source mutation preceded its positive body controls", err)
		}
		observed, err := decodeObjects[ordinaryRepetitionObservation](body)
		if err != nil || len(observed) != 2 {
			t.Fatal("source mutation lost its two completed positive controls", observed, err)
		}
		if err := os.WriteFile(input, append(original, []byte("\n// changed after the third execution's final group progress boundary\n")...), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	arm := &ordinaryReviewEnvironmentWriter{before: "Step components-r3 (component-tests)\n", change: func() {
		writer.before = "Check phase=test scope=" + selectedGroups[0].Name + "\n"
	}}
	result, err := runPreparedWorkflow(ctx, root, bootstrap, prepared, io.MultiWriter(&control, arm, writer))
	if !arm.done || !writer.done {
		t.Fatal("third component execution never reached its final group progress boundary", err, control.String())
	}
	if len(result.Steps) != len(ids) {
		t.Fatal("source edit lost its four planned repetitions", result.Steps, err)
	}
	outcomes := []string{"passed", "passed", "passed", "passed"}
	for index, step := range result.Steps {
		if step.ID != ids[index] || step.Outcome != outcomes[index] {
			t.Fatal("source edit changed its exact execution outcomes", result.Steps, err)
		}
	}
	if err != nil || result.Outcome != "passed" || !toolCommandsJoined(err) || !sourceCommandsJoined(err) {
		t.Fatal("source edit blocked a prepared component or lost its join", err)
	}
	if err := prepared.close(ctx); err != nil {
		t.Fatal("close prepared component source control", err)
	}
	for _, step := range result.Steps {
		component := result.executions[step.ID].Component
		if component == nil || component.Checks == nil || component.Checks.Race || component.Checks.Diagnostics == nil || component.Checks.Focus == nil || component.Checks.Focus.Tests[0] != "TestFiniteRepetitionProcessWitness/leaf[a]+b" {
			t.Fatal("unchanged control lost its exact component selection or race policy", step.ID)
		}
		classified := false
		for _, row := range component.Checks.Classifications {
			if row.Name == "TestFiniteRepetitionProcessWitness" {
				classified = row.FullOnly != nil && !*row.FullOnly
			}
		}
		if !classified {
			t.Fatal("unchanged control lost the ordinary fixture classification", step.ID)
		}
		for _, command := range component.Checks.Diagnostics.Commands {
			if command.Started && !command.Joined {
				t.Fatal("unchanged control did not join its command", command)
			}
		}
	}
	body, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := decodeObjects[ordinaryRepetitionObservation](body)
	if err != nil || len(observed) != 4 {
		t.Fatal("source edit did not preserve all four executions", observed, err)
	}
	pids := map[int]bool{}
	for _, observation := range observed {
		if observation.PID <= 0 || pids[observation.PID] || observation.Binary != observed[0].Binary {
			t.Fatal("component repetitions lost fresh processes or shared build", observation)
		}
		pids[observation.PID] = true
		if !observation.ChildEntered || !observation.ParentSuffix || observation.InitialState != 1 {
			t.Fatal("unchanged control lost its child or suffix", observation)
		}
		if _, err := os.Stat(observation.Fixture); !os.IsNotExist(err) {
			t.Fatal("unchanged joined control retained its fixture", err)
		}
	}
}
