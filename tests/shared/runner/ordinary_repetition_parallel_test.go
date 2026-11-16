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
	"syscall"
	"testing"
	"time"
)

const ordinaryParallelRepetitionSource = `package witness
import (
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "testing"
 "time"
)
var entered int
// full_only: false
func TestParallelRepetitionWitness(t *testing.T) {
 entered++
 if entered != 1 { t.Fatal("reused mutable process state") }
 fixture := t.TempDir()
 if err := os.WriteFile(filepath.Join(fixture, "mutable"), []byte("fresh"), 0600); err != nil { t.Fatal(err) }
 binary, err := os.Executable(); if err != nil { t.Fatal(err) }
 body, err := os.ReadFile(binary); if err != nil { t.Fatal(err) }
 row := struct { PID int; Fixture, Binary, SHA256 string }{os.Getpid(), fixture, binary, fmt.Sprintf("%x", sha256.Sum256(body))}
 encoded, err := json.Marshal(row); if err != nil { t.Fatal(err) }
 directory := os.Getenv("ENKV_PARALLEL_REPETITION_WITNESS")
 if directory == "" { t.Fatal("missing witness directory") }
 temporary := filepath.Join(directory, fmt.Sprintf("%d.pending", os.Getpid()))
 if err := os.WriteFile(temporary, encoded, 0600); err != nil { t.Fatal(err) }
 if err := os.Rename(temporary,filepath.Join(directory,fmt.Sprintf("%d.json",os.Getpid()))); err != nil { t.Fatal(err) }
 until := time.Now().Add(30*time.Second)
 for {
  if _, err := os.Stat(filepath.Join(directory, fmt.Sprintf("%d.release", os.Getpid()))); err == nil { break } else if !os.IsNotExist(err) { t.Fatal(err) }
  if time.Now().After(until) { t.Fatal("controller did not release parallel witnesses") }
  time.Sleep(5*time.Millisecond)
 }
 again, err := os.ReadFile(binary); if err != nil || fmt.Sprintf("%x", sha256.Sum256(again)) != row.SHA256 { t.Fatal("shared immutable build disappeared before borrower settled", err) }
 t.Run("leaf[a]+b", func(t *testing.T) { if entered != 1 { t.Fatal("changed process state") } })
}
`

// full_only: false
func TestOrdinaryParallelRepetitionsKeepOneBuildAndSeparateMutableState(t *testing.T) {
	root, _, _ := overlayFixture(t)
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", ordinaryParallelRepetitionSource)
	initializeWorkflowExecutionFixture(t, root)
	directory := t.TempDir()
	t.Setenv("ENKV_PARALLEL_REPETITION_WITNESS", directory)
	path := filepath.Join(directory, "workflow.json")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "parallel-fresh-ordinary", "execution": map[string]any{"parallel": 2}, "steps": []any{map[string]any{"id": "repeated", "kind": "unit", "packages": []string{"telemetry/witness"}, "package": "telemetry/witness", "tests": []string{"TestParallelRepetitionWitness/leaf[a]+b"}, "repetitions": 2}}})
	ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 2), time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Execution.Resolved.Parallel != 2 {
		t.Fatal("fixture did not resolve its admitted parallel2", plan.Execution)
	}

	var output bytes.Buffer
	launched, settled := false, false
	prepared, err := prepareWorkflow(ctx, root, "", plan, &output)
	if prepared != nil {
		t.Cleanup(func() {
			if launched && !settled {
				t.Log("prepared fixture owner retained because callback settlement is unknown")
				return
			}
			tail, release := finalizationContext(ctx)
			defer release()
			if err := prepared.close(tail); err != nil {
				t.Error("close prepared fixture owner", err)
			}
		})
	}
	if err != nil {
		t.Fatal("prepare actual ordinary fixture", err)
	}
	if prepared.plan.Execution.Resolved.Parallel != 2 || prepared.ordinary["repeated"] == nil || executionCapacityFromContext(prepared.ordinary["repeated"].ctx).Parallel != 2 {
		t.Fatal("fixture preparation lost its admitted parallel2", prepared.plan.Execution)
	}
	done := make(chan assemblyGroupCompletion, 1)
	launched = true
	go func() {
		defer close(done)
		result, err := runPreparedWorkflow(ctx, root, "", prepared, &output)
		tail, release := finalizationContext(ctx)
		err = errors.Join(err, prepared.close(tail))
		release()
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
				t.Error("parallel process invocation did not settle")
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
	var witnesses []string
	var deadline <-chan time.Time
	var peerTimer *time.Timer
	defer func() {
		if peerTimer != nil {
			peerTimer.Stop()
		}
	}()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		witnesses, err = filepath.Glob(filepath.Join(directory, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		// The workflow selection file is not a process observation.
		var processFiles []string
		for _, file := range witnesses {
			if filepath.Base(file) != "workflow.json" {
				processFiles = append(processFiles, file)
			}
		}
		witnesses = processFiles
		if len(witnesses) == 2 {
			break
		}
		if len(witnesses) == 1 && peerTimer == nil {
			peerTimer = time.NewTimer(10 * time.Second)
			deadline = peerTimer.C
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("both fresh repetition processes did not overlap", len(witnesses))
		case <-ctx.Done():
			t.Fatal("preparation or overlap failed", ctx.Err())
		case result, returned := <-done:
			settled = returned
			t.Fatal("workflow ended before both witnesses entered", result.err)
		}
	}
	var observations []struct {
		PID                     int
		Fixture, Binary, SHA256 string
	}
	for _, file := range witnesses {
		var row struct {
			PID                     int
			Fixture, Binary, SHA256 string
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &row); err != nil {
			t.Fatal(err)
		}
		observations = append(observations, row)
	}
	if observations[0].PID <= 0 || observations[1].PID <= 0 || observations[0].PID == observations[1].PID || observations[0].Fixture == observations[1].Fixture || observations[0].Binary != observations[1].Binary || observations[0].SHA256 != observations[1].SHA256 || !hexString(observations[0].SHA256, 64) {
		t.Fatal("parallel repetitions did not share only immutable build", fmt.Sprint(observations))
	}
	first := observations[0]
	if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("%d.release", first.PID)), []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		probe := syscall.Kill(first.PID, 0)
		if errors.Is(probe, syscall.ESRCH) {
			break
		}
		if probe != nil {
			t.Fatal(probe)
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("first process did not exit", ctx.Err())
		}
	}
	if _, err := os.Stat(first.Binary); err != nil {
		t.Fatal("shared build disposed while peer still borrows it", err)
	}
	if _, err := os.Stat(observations[1].Fixture); err != nil {
		t.Fatal("peer fixture disposed while peer is blocked", err)
	}
	if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("%d.release", observations[1].PID)), []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	var result assemblyGroupCompletion
	select {
	case value, returned := <-done:
		if !returned {
			t.Fatal("fixture callback closed without normal completion")
		}
		settled = true
		result = value
	case <-ctx.Done():
		t.Fatal("ordinary callback did not complete", ctx.Err())
	}
	if result.err != nil || result.result.Outcome != "passed" {
		t.Fatal(result.err, output.String())
	}
	for _, row := range observations {
		if _, err := os.Stat(row.Fixture); !os.IsNotExist(err) {
			t.Error("joined process retained mutable fixture", row.Fixture, err)
		}
		if _, err := os.Stat(row.Binary); !os.IsNotExist(err) {
			t.Error("joined workflow retained shared build", err)
		}
	}
	acquired := prepared.ordinary["repeated"].preparation
	if acquired == nil || acquired.Preparation != "passed" || len(acquired.Commands) == 0 {
		t.Fatal("parallel acquisition unavailable", acquired)
	}
	preparationOwners := 0
	for index, step := range result.result.Steps {
		execution := result.result.executions[step.ID]
		evidence := execution.Ordinary
		if evidence == nil || evidence.Diagnostics == nil || !evidence.SelectedComplete {
			t.Fatal("parallel result lacks exact completion", step)
		}
		prefix := execution.Preparation
		if prefix == nil || prefix == acquired || prefix == evidence.Diagnostics || prefix.Preparation != "passed" {
			t.Fatal("parallel result lost separate passed preparation", prefix)
		}
		for _, fact := range prefix.Commands {
			if !fact.Joined {
				t.Error("parallel preparation lost positive join", fact)
			}
		}
		for start := 0; start+len(acquired.Commands) <= len(prefix.Commands); start++ {
			if reflect.DeepEqual(prefix.Commands[start:start+len(acquired.Commands)], acquired.Commands) {
				preparationOwners++
				if index != 0 || start != 0 {
					t.Error("acquisition projected outside the first configured prefix")
				}
			}
		}
		for _, fact := range evidence.Diagnostics.Commands {
			if !fact.Joined {
				t.Error("actual parallel command lost positive join", fact)
			}
			if fact.Phase == "preparation" {
				t.Error("ordinary body duplicated immutable acquisition", fact)
			}
		}
	}
	if preparationOwners != 1 {
		t.Error("preparation was not reported once", preparationOwners)
	}
	if len(result.result.RepetitionGroups) != 1 || result.result.RepetitionGroups[0].RequestedExecutions != 2 || result.result.RepetitionGroups[0].CompletedExecutions != 2 || result.result.RepetitionGroups[0].Outcome != "passed" {
		t.Fatal("parallel N/K changed", result.result.RepetitionGroups)
	}
}
