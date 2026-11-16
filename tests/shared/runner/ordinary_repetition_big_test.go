package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const ordinaryMixedRepetitionSource = `package witness
import (
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func gated(t *testing.T, big bool) {
 directory := os.Getenv("ENKV_MIXED_REPETITION_WITNESS")
 key := fmt.Sprintf("%d.%s", os.Getpid(), t.Name())
 active := filepath.Join(directory, "active."+key)
 if err := os.WriteFile(active, []byte("active"), 0600); err != nil { t.Fatal(err) }
 t.Cleanup(func() { if err := os.Remove(active); err != nil { t.Error(err) } })
 rows, err := filepath.Glob(filepath.Join(directory,"active.*")); if err != nil { t.Fatal(err) }
 for _, row := range rows { if row != active && (big || strings.HasSuffix(row,".TestBig")) { t.Error("Big test overlapped a sibling", filepath.Base(row)) } }
 body, err := json.Marshal(struct{PID int; Name string}{os.Getpid(),t.Name()}); if err != nil { t.Fatal(err) }
 temporary := filepath.Join(directory,key+".pending")
 if err := os.WriteFile(temporary,body,0600); err != nil { t.Fatal(err) }
 if err := os.Rename(temporary,filepath.Join(directory,key+".json")); err != nil { t.Fatal(err) }
 until := time.Now().Add(30*time.Second)
 for {
  if _,err := os.Stat(filepath.Join(directory,"release."+key)); err == nil { break } else if !os.IsNotExist(err) { t.Fatal(err) }
  if time.Now().After(until) { t.Fatal("controller did not release test") }
  time.Sleep(5*time.Millisecond)
 }
}
// full_only: false
func TestNormalA(t *testing.T) { gated(t,false) }
// full_only: true
// exclusive: true
func TestBig(t *testing.T) { gated(t,true) }
`

type ordinaryMixedObservation struct {
	PID  int
	Name string
}

// full_only: false
func TestOrdinaryRepetitionsOverlapNormalRootsAndIsolateBig(t *testing.T) {
	root, _, _ := overlayFixture(t)
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", ordinaryMixedRepetitionSource)
	initializeWorkflowExecutionFixture(t, root)
	directory := t.TempDir()
	t.Setenv("ENKV_MIXED_REPETITION_WITNESS", directory)
	path := filepath.Join(directory, "workflow.json")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "mixed-repetition", "profile": "full", "execution": map[string]any{"parallel": 2}, "steps": []any{map[string]any{"id": "mixed", "kind": "unit", "packages": []string{"telemetry/witness"}, "repetitions": 2}}})
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
	if prepared.plan.Execution.Resolved.Parallel != 2 || prepared.ordinary["mixed"] == nil || executionCapacityFromContext(prepared.ordinary["mixed"].ctx).Parallel != 2 {
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
				t.Error("mixed repetitions did not settle")
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
	seen := map[string]bool{}
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	next := func(waitCtx context.Context, want string) ordinaryMixedObservation {
		t.Helper()
		for {
			paths, err := filepath.Glob(filepath.Join(directory, "*.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range paths {
				if file == path || seen[file] {
					continue
				}
				var row ordinaryMixedObservation
				body, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(body, &row); err != nil {
					t.Fatal(err)
				}
				if row.PID <= 0 || row.Name != want {
					t.Fatal("unexpected actual root admission", row, want)
				}
				seen[file] = true
				return row
			}
			select {
			case <-tick.C:
			case <-waitCtx.Done():
				t.Fatal("expected actual root did not start", want, waitCtx.Err())
			case result, returned := <-done:
				settled = returned
				t.Fatal("workflow stopped before expected root", want, result.err, output.String())
			}
		}
	}
	release := func(row ordinaryMixedObservation) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("release.%d.%s", row.PID, row.Name)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	first := next(ctx, "TestNormalA")
	peerCtx, stopPeer := context.WithTimeout(ctx, 10*time.Second)
	defer stopPeer()
	// The short overlap bound begins only after actual preparation has finished.
	second := next(peerCtx, "TestNormalA")
	if first.PID == second.PID {
		t.Fatal("normal repetitions reused one process")
	}
	release(first)
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
			t.Fatal("first normal process did not exit", ctx.Err())
		}
	}
	// Once repetition1's normal process exits, repetition2 still holds its normal
	// gate. No Big process can start at this actual cross-repetition boundary.
	until := time.NewTimer(30 * time.Millisecond)
check:
	for {
		active, err := filepath.Glob(filepath.Join(directory, "active.*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(active) != 1 || !strings.HasSuffix(active[0], fmt.Sprintf(".%d.TestNormalA", second.PID)) {
			t.Fatal("Big overlapped the held normal peer", active)
		}
		select {
		case <-tick.C:
		case <-until.C:
			break check
		}
	}
	release(second)
	firstBig := next(ctx, "TestBig")
	active, err := filepath.Glob(filepath.Join(directory, "active.*"))
	if err != nil || len(active) != 1 || !strings.HasSuffix(active[0], ".TestBig") {
		t.Fatal("Big did not enter alone", active, err)
	}
	release(firstBig)
	secondBig := next(ctx, "TestBig")
	if firstBig.PID == secondBig.PID {
		t.Fatal("Big repetitions reused process")
	}
	release(secondBig)
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
	for _, step := range result.result.Steps {
		evidence := result.result.executions[step.ID].Ordinary
		if evidence == nil || evidence.Diagnostics == nil || evidence.Diagnostics.Preparation != "passed" {
			t.Fatal("successful unfocused execution lost passed preparation", step.ID)
		}
	}
	if len(seen) != 4 {
		t.Fatal("selected root set did not execute exactly twice", len(seen))
	}
	if len(result.result.RepetitionGroups) != 1 || result.result.RepetitionGroups[0].RequestedExecutions != 2 || result.result.RepetitionGroups[0].CompletedExecutions != 2 || result.result.RepetitionGroups[0].Outcome != "passed" {
		t.Fatal("mixed repetitions lost N/K", result.result.RepetitionGroups)
	}
}
