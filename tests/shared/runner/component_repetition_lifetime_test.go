package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type componentBorrowerOutput struct {
	bytes.Buffer
	controls string
	highest  chan struct{}
	reported bool
}

func (output *componentBorrowerOutput) Write(body []byte) (int, error) {
	if bytes.HasPrefix(body, []byte("Step repeated-r1 (")) {
		if err := os.WriteFile(filepath.Join(output.controls, "armed"), nil, 0600); err != nil {
			return 0, err
		}
	}
	if bytes.HasPrefix(body, []byte("Components passed")) && !output.reported {
		output.reported = true
		close(output.highest)
	}
	return output.Buffer.Write(body)
}

// full_only: false
func TestComponentLastRepetitionFinishesFirstKeepsPreparedBorrower(t *testing.T) {
	fixtureCtx, root, bootstrap := componentRepetitionAssemblyFixture(t)
	directory := t.TempDir()
	controls := t.TempDir()
	sourcePath := filepath.Join(root, "tests/shared/repetition_process_fixture_test.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	const entry = "func TestFiniteRepetitionProcessWitness(t *testing.T) {"
	if strings.Count(string(source), entry) != 1 {
		t.Fatal("actual component witness entry is unavailable")
	}
	body := strings.Replace(string(source), "\"testing\"", "\"testing\"\n\"time\"", 1)
	body = strings.Replace(body, entry, entry+`
 if controls := os.Getenv("ENKV_COMPONENT_BORROW_CONTROLS"); controls != "" {
  if _, err := os.Stat(filepath.Join(controls, "armed")); err != nil { t.Fatal("component body preceded its workflow dispatch", err) }
  first := filepath.Join(controls, "first-body")
  if err := os.Mkdir(first, 0700); err == nil {
   pending, ready := filepath.Join(first, "pid.pending"), filepath.Join(first, "pid.ready")
   if err := os.WriteFile(pending, []byte(fmt.Sprint(os.Getpid())+"\n"), 0600); err != nil { t.Fatal(err) }
   if err := os.Rename(pending, ready); err != nil { t.Fatal(err) }
   for {
    if _, err := os.Stat(filepath.Join(controls, "release-first")); err == nil { break } else if !os.IsNotExist(err) { t.Fatal(err) }
    select { case <-t.Context().Done(): t.Fatal(t.Context().Err()); case <-time.After(5*time.Millisecond): }
   }
  } else if !os.IsExist(err) { t.Fatal(err) }
 }
`, 1)
	if err := os.WriteFile(sourcePath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_COMPONENT_BORROW_CONTROLS", controls)
	witness := filepath.Join(directory, "executions.jsonl")
	t.Setenv("ENKV_COMPONENT_REPETITION_WITNESS", witness)
	t.Setenv("ENKV_COMPONENT_REPETITION_SECOND_FAILURE", "")
	path := filepath.Join(directory, "workflow.json")
	const request = "TestFiniteRepetitionProcessWitness/leaf[a]+b"
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "component-borrower", "execution": map[string]any{"parallel": 2}, "steps": []any{map[string]any{"id": "repeated", "kind": "component-tests", "profile": "dev", "tests": singleTestRequest(request), "repetitions": 2}}})
	ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(fixtureCtx, false), 2), 5*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Execution.Resolved.Parallel != 2 {
		t.Fatal("fixture did not resolve its admitted parallel2", plan.Execution)
	}

	launched, settled := false, false
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
	if prepared != nil {
		t.Cleanup(func() {
			if launched && !settled {
				t.Log("prepared fixture owner retained because callback settlement is unknown")
				return
			}
			tail, release := finalizationContext(ctx)
			defer release()
			if err := prepared.close(tail); err != nil {
				t.Error("close prepared component owner", err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	if prepared.plan.Execution.Resolved.Parallel != 2 {
		t.Fatal("fixture preparation lost its admitted parallel2", prepared.plan.Execution)
	}
	group := prepared.components["repeated"]
	if group == nil || group.assembled.Binary == "" || executionCapacityFromContext(group.ctx).Parallel != 2 {
		t.Fatal("actual configured group was not prepared")
	}
	sharedBinary := group.assembled.Binary
	output := &componentBorrowerOutput{controls: controls, highest: make(chan struct{})}
	done := make(chan assemblyGroupCompletion, 1)
	launched = true
	go func() {
		defer close(done)
		defer group.cancel()
		child := useLocalPreparationPhase(prepared.binding.context(ctx), prepared.phase)
		child = useInvocationArtifacts(child, prepared.assemblyPreparations)
		currentPlan := prepared.plan
		currentPlan.prepared = prepared
		var owned []privateDirectory
		result, err := executeWorkflow(child, root, currentPlan, output, &owned, nil, func(callback context.Context, step resolvedWorkflowStep, writer io.Writer, _ string) (workflowStepExecution, error) {
			if step.Repetition == 2 {
				// Wait inside this worker so the coordinator can still serve
				// the first worker's progress before its native body enters.
				for {
					if _, err := os.Stat(filepath.Join(controls, "first-body", "pid.ready")); err == nil {
						break
					} else if !os.IsNotExist(err) {
						return workflowStepExecution{}, err
					}
					select {
					case <-callback.Done():
						return workflowStepExecution{}, callback.Err()
					case <-time.After(5 * time.Millisecond):
					}
				}
			}
			run, err := runComponentsOwned(step.currentPrefix, callback, root, bootstrap, step.Profile, step.Tests, executionCapacityFromContext(callback).Parallel, writer, group)
			if run == nil {
				return workflowStepExecution{}, err
			}
			return workflowStepExecution{Evidence: run.evidencePath, Component: &run.record, componentOwner: run}, err
		})
		prepared.joined = prepared.joined && toolCommandsJoined(err)
		done <- assemblyGroupCompletion{result, err}
	}()
	t.Cleanup(func() {
		cancel()
		if !settled {
			select {
			case _, returned := <-done:
				settled = returned
				if !returned {
					t.Error("fixture callback closed without normal completion")
				}
			case <-time.After(10 * time.Second):
				t.Error("component borrowers did not settle")
			}
		}
		if settled && t.Failed() {
			body := output.Bytes()
			if len(body) > 8192 {
				body = body[len(body)-8192:]
			}
			t.Logf("workflow output (last at most 8192 bytes):\n%s", body)
		}
	})
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(filepath.Join(controls, "first-body", "pid.ready")); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("first actual component body did not enter", ctx.Err())
		case result, returned := <-done:
			settled = returned
			t.Fatal("workflow stopped before first actual borrower", result.err)
		}
	}
	// The first body remains held before creating its mutable fixture. The first
	// completed witness must come from the second repetition. Start the short
	// completion window after that body has produced its selected-child witness.
	var firstRow ordinaryRepetitionObservation
	for {
		body, readErr := os.ReadFile(witness)
		if readErr == nil && len(body) != 0 && body[len(body)-1] == '\n' {
			lines := bytes.Split(body[:len(body)-1], []byte{'\n'})
			if len(lines) != 1 {
				t.Fatal("held first borrower observed multiple actual component witnesses", len(lines))
			}
			if err := json.Unmarshal(lines[0], &firstRow); err != nil {
				t.Fatal("invalid actual component witness", err)
			}
			break
		}
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("second borrower did not produce its actual component witness", ctx.Err())
		case result, returned := <-done:
			settled = returned
			t.Fatal("workflow stopped before second borrower's actual witness", result.err)
		}
	}
	if firstRow.PID <= 0 || firstRow.InitialState != 1 || firstRow.Fixture == "" || firstRow.Binary != sharedBinary || firstRow.BinarySHA256 != group.assembled.Closure.BinarySHA256 || !firstRow.ChildEntered || !firstRow.ParentSuffix {
		t.Fatal("first actual component witness lost fresh process/fixture, shared binary or exact child/suffix", firstRow)
	}
	peer := time.NewTimer(10 * time.Second)
	defer peer.Stop()
	select {
	case <-output.highest:
	case <-peer.C:
		t.Fatal("highest-numbered repetition did not finish while first component body was held")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case result, returned := <-done:
		settled = returned
		t.Fatal("workflow stopped before highest-numbered completion", result.err)
	}
	// The first native body remains active. The second result must not cancel
	// the configured owner or remove its shared binary.
	settle := time.NewTimer(30 * time.Millisecond)
	defer settle.Stop()
	select {
	case <-group.ctx.Done():
		t.Fatal("highest-numbered completion canceled an active prepared borrower", group.ctx.Err())
	case <-settle.C:
	}
	if _, err := os.Stat(firstRow.Fixture); !os.IsNotExist(err) {
		t.Fatal("completed second borrower retained its mutable fixture before first release", err)
	}
	if _, err := os.Stat(sharedBinary); err != nil {
		t.Fatal("shared binary disappeared while first borrower remained", err)
	}
	pidBody, err := os.ReadFile(filepath.Join(controls, "first-body", "pid.ready"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBody)))
	if err != nil || pid <= 0 {
		t.Fatal("invalid held process", pid, err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatal("first actual borrower exited before its release", err)
	}
	releaseFirstAt := time.Now().UTC()
	if err := os.WriteFile(filepath.Join(controls, "release-first"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	var completion assemblyGroupCompletion
	select {
	case value, returned := <-done:
		if !returned {
			t.Fatal("fixture callback closed without normal completion")
		}
		settled = true
		completion = value
	case <-ctx.Done():
		t.Fatal("component callback did not complete", ctx.Err())
	}
	if completion.err != nil || completion.result.Outcome != "passed" {
		t.Fatal(completion.err, output.String())
	}
	if len(completion.result.Steps) != 2 || completion.result.Steps[1].FinishedAt == nil || completion.result.Steps[0].FinishedAt == nil || !completion.result.Steps[1].FinishedAt.Before(releaseFirstAt) || !completion.result.Steps[1].FinishedAt.Before(*completion.result.Steps[0].FinishedAt) {
		t.Fatal("highest-numbered callback did not finish before first borrower release", completion.result.Steps)
	}
	for _, step := range completion.result.Steps {
		record := completion.result.executions[step.ID].Component
		if step.Outcome != "passed" || record == nil || record.Checks == nil || !completeFocusedComponentEvidence(*record.Checks) || record.BuildClosure == nil || record.BuildClosure.BinarySHA256 != group.assembled.Closure.BinarySHA256 {
			t.Fatal("actual borrower lost exact component completion", step.ID)
		}
		for _, fact := range record.Checks.Diagnostics.Commands {
			if !fact.Joined {
				t.Error("actual component borrower lost positive join", fact)
			}
		}
	}
	if len(completion.result.RepetitionGroups) != 1 || completion.result.RepetitionGroups[0].RequestedExecutions != 2 || completion.result.RepetitionGroups[0].CompletedExecutions != 2 || completion.result.RepetitionGroups[0].Outcome != "passed" {
		t.Fatal("actual component borrower lost N/K", fmt.Sprint(completion.result.RepetitionGroups))
	}
	witnessBody, err := os.ReadFile(witness)
	if err != nil || len(witnessBody) == 0 || witnessBody[len(witnessBody)-1] != '\n' {
		t.Fatal("final actual component witnesses unavailable or incomplete", err)
	}
	lines := bytes.Split(witnessBody[:len(witnessBody)-1], []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal("actual component witness count differs from requested2", len(lines))
	}
	var rows [2]ordinaryRepetitionObservation
	for index, line := range lines {
		if err := json.Unmarshal(line, &rows[index]); err != nil {
			t.Fatal(err)
		}
		row := rows[index]
		if row.PID <= 0 || row.InitialState != 1 || row.Fixture == "" || row.Binary != sharedBinary || row.BinarySHA256 != firstRow.BinarySHA256 || !row.ChildEntered || !row.ParentSuffix {
			t.Fatal("actual component borrower lost fresh state, shared binary or exact child/suffix", row)
		}
		if _, err := os.Stat(row.Fixture); !os.IsNotExist(err) {
			t.Error("joined component borrower retained mutable fixture", row.Fixture, err)
		}
		if probe := syscall.Kill(row.PID, 0); !errors.Is(probe, syscall.ESRCH) {
			t.Error("actual component process survived joined workflow", row.PID, probe)
		}
	}
	if rows[0].PID != firstRow.PID || rows[1].PID != pid || rows[0].PID == rows[1].PID || rows[0].Fixture == rows[1].Fixture {
		t.Fatal("component arrival order or independent process/fixture identity changed", rows)
	}
	if probe := syscall.Kill(pid, 0); !errors.Is(probe, syscall.ESRCH) {
		t.Fatal("held process survived joined workflow", probe)
	}
}
