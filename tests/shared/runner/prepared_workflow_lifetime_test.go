package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func completedWorkflowRecoveryPacket(t *testing.T, root, owner string) (*runState, map[string][]byte) {
	t.Helper()
	s := completedPrivateFixtureAt(t, root, "live")
	s.record.ContinuationRootRunID = owner
	identity, err := caseIdentitySHA256(s.record)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range s.record.Scenarios {
		if err := s.writeCaseReceipt(result, identity); err != nil {
			t.Fatal(err)
		}
	}
	files := privateRecoveryPacket(t, s)
	if err := s.finishCurrentRun(io.Discard, nil); err != nil {
		t.Fatal("normal successful live finalization failed", err)
	}
	if s.record.Outcome != "passed" {
		t.Fatal("completed local fixture did not pass")
	}
	for _, relative := range []string{"run.json", caseReceiptPath(s.record.Scenarios[0].Sequence)} {
		path := filepath.Join(s.directory, relative)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("successful workflow child lost its recovery packet", err)
		}
		files[path] = body
	}
	assertPrivateRecoveryUnchanged(t, files)
	return s, files
}

// The actual prepared callback and runSuite create the child run record. The
// shared build runs a local failing writer stub without provider/service code.
// The completed local fixture then checks the common successful finalizer with
// the exact observed owner, independently of provider execution.
// full_only: false
func TestPreparedWorkflowLiveOwnerReachesRunState(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	ctx, root, bootstrap := localLivePreparationFixture(t, "gcp")
	ctx = withRacePolicy(ctx, true)
	input := t.TempDir()
	writerMarker := filepath.Join(input, "local-writer-entered")
	t.Setenv("ENKV_PREPARED_LIVE_WRITER", writerMarker)
	writeLocalGoFixture(t, root, "tests/live/runner/fixture_test.go", `package core
import ("os"; "testing")
// full_only: false
func TestLiveRun(t *testing.T) {
 if err := os.WriteFile(os.Getenv("ENKV_PREPARED_LIVE_WRITER"), []byte("entered\n"), 0600); err != nil { t.Fatal(err) }
 t.Fatal("controlled prepared live writer refusal")
}
// full_only: false
func TestLiveChild(t *testing.T) { t.Fatal("local fixture child must not execute") }
// full_only: false
func TestLiveCleanup(t *testing.T) { t.Fatal("local fixture cleanup has no service implementation") }
`)
	environment, settings := configurationFixture(t, "gcp")
	settings["credentials_file"] = filepath.Join(filepath.Dir(environment), "identity.json")
	saveSelection(t, environment, environmentFor(settings))
	suite, limitPath, path := filepath.Join(input, "suite.json"), filepath.Join(input, "limits.json"), filepath.Join(input, "workflow.json")
	saveSelection(t, suite, suiteFixture("prepared-live-owner", []string{"state.single-value-update-preserves-other-values/members_32"}))
	saveSelection(t, limitPath, testLimits())
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "prepared-live-owner", "profile": "full", "execution": map[string]int{"parallel": 1}, "steps": []any{
		map[string]any{"id": "local", "kind": "run", "suites": []string{suite}, "environment": environment, "limits": limitPath, "recovery_mode": "disabled"},
	}})
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	refuse := filepath.Join(input, "refuse-run-compile")
	compileAttempts := filepath.Join(input, "unexpected-run-compile")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	wrapper := "#!/bin/sh\nif [ -f " + quote(refuse) + " ]; then\n for argument do\n  if [ \"$argument\" = -c ]; then printf 'attempted\\n' >> " + quote(compileAttempts) + "; printf '%s\\n' 'controlled local run compile refusal' >&2; exit 73; fi\n done\nfi\nexec " + quote(realGo) + " \"$@\"\n"
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path, Race: raceEnabled(ctx)})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
	if prepared != nil {
		defer func() {
			if err := prepared.close(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	selected := prepared.suites["local"]
	if selected == nil || selected.request.workflowRunID != "" {
		t.Fatal("fresh suite preparation already has a workflow owner")
	}
	before, err := suiteRequestIdentity(selected.request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refuse, []byte("local refusal\n"), 0600); err != nil {
		t.Fatal(err)
	}
	admitted, err := admitPreparedExecution(ctx, prepared.admission())
	if err != nil {
		t.Fatal(err)
	}
	result, runErr := runPreparedWorkflow(admitted, root, bootstrap, prepared, io.Discard)
	child := result.executions["local"].Suite
	if runErr == nil || !toolCommandsJoined(runErr) || !sourceCommandsJoined(runErr) || result.Outcome != "failed" || child == nil || child.Failure == nil || !runProcessesJoined(*child) || len(child.Scenarios) != 1 {
		t.Fatal("actual prepared dispatch did not retain its joined local writer failure", runErr, result.Outcome, child)
	}
	writer := child.Scenarios[0].Writer
	if writer == nil || !writer.Started || !writer.Joined || writer.Process != "process_failed" || writer.Outcome != "failed" {
		t.Fatal("local writer refusal lost its actual started/joined result", writer)
	}
	if body, err := os.ReadFile(writerMarker); err != nil || string(body) != "entered\n" {
		t.Fatal("prepared child did not enter the local writer stub", string(body), err)
	}
	if _, err := os.Stat(compileAttempts); !os.IsNotExist(err) {
		t.Fatal("prepared child rebuilt its compatible assembly", err)
	}
	if child.BuildClosure == nil || child.BuildClosure.BinarySHA256 != selected.inventory.Closure.BinarySHA256 {
		t.Fatal("prepared child lost its captured executable identity")
	}
	if !records.ValidRunID(result.RunID) || child.ContinuationRootRunID != result.RunID {
		t.Fatalf("actual prepared child owner = %q; workflow owner = %q", child.ContinuationRootRunID, result.RunID)
	}
	if !sameSource(child.Source, selected.binding.source) || child.Resolved == nil || child.Resolved.Race != plan.Race || selected.inventory.Closure.Race != plan.Race {
		t.Fatal("prepared live child lost its frozen source or accepted race binding")
	}
	after, err := suiteRequestIdentity(selected.request)
	if err != nil || after != before || selected.requestIdentity != before || selected.request.workflowRunID != "" {
		t.Fatal("execution changed the frozen prepared request", err)
	}
	if child.Execution.Resolved != result.Execution.Resolved {
		t.Fatal("prepared live child lost its assigned execution share")
	}
	passed, packet := completedWorkflowRecoveryPacket(t, root, child.ContinuationRootRunID)
	assertPrivateRecoveryUnchanged(t, packet)
	if err := passed.recovery.complete(passed.record); err != nil {
		t.Fatal("completed workflow recovery could not finish", err)
	}
	if _, err := os.Stat(passed.directory); !os.IsNotExist(err) {
		t.Fatal("completed workflow recovery retained its exact child", err)
	}
	original := selected.request.Target
	selected.request.Target = "changed-after-preparation"
	defer func() { selected.request.Target = original }()
	beforeRefusal := preparationRecoverySnapshot(t, root)
	_, refusal := runPreparedSuite(ctx, root, bootstrap, selected, io.Discard)
	cause := refusal
	var closed *checkFailure
	if errors.As(refusal, &closed) {
		if refusal.Error() != closed.Error() || strings.Contains(refusal.Error(), "prepared scenario selection changed") {
			t.Fatal("live prepared refusal exposed its internal cause")
		}
		for errors.As(cause, &closed) {
			cause = closed.cause
		}
	}
	if cause == nil || !strings.Contains(cause.Error(), "prepared scenario selection changed") {
		t.Fatal("changed semantic request bypassed prepared verification", refusal)
	}
	afterRefusal := preparationRecoverySnapshot(t, root)
	if len(beforeRefusal) != len(afterRefusal) {
		t.Fatal("changed semantic request created durable work")
	}
	for path, want := range beforeRefusal {
		if afterRefusal[path] != want {
			t.Fatal("changed semantic request altered durable work", path)
		}
	}
}

// full_only: false
func TestSuccessfulLiveChildUsesEnclosingWorkflowLifetime(t *testing.T) {
	for _, condition := range []string{"workflow-passed", "later-sibling-failed", "standalone"} {
		t.Run(condition, func(t *testing.T) {
			root := workflowExecutionFixture(t)
			if condition == "standalone" {
				standalone := completedPrivateFixtureAt(t, root, "live")
				if err := standalone.finishCurrentRun(io.Discard, nil); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(standalone.directory); !os.IsNotExist(err) {
					t.Fatal("standalone success retained disposable recovery", err)
				}
				return
			}
			plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "live-owner-lifetime", Steps: []resolvedWorkflowStep{
				{ID: "passed", Kind: "run", Selected: true, request: runRequest{Suite: "live"}},
				{ID: "later", Kind: "run", Selected: true, request: runRequest{Suite: "live"}},
			}}
			var passed *runState
			var packet map[string][]byte
			result, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil, func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
				if step.ID == "passed" {
					passed, packet = completedWorkflowRecoveryPacket(t, root, step.request.workflowRunID)
					return workflowStepExecution{Suite: &passed.record, Recovery: passed.recovery}, nil
				}
				assertPrivateRecoveryUnchanged(t, packet)
				if condition == "later-sibling-failed" {
					return workflowStepExecution{}, errors.New("controlled later sibling failure")
				}
				return workflowStepExecution{}, nil
			})
			if passed == nil || passed.record.ContinuationRootRunID != result.RunID || result.Steps[0].Outcome != "passed" {
				t.Fatal("successful child lost its workflow identity")
			}
			if condition == "later-sibling-failed" {
				if err == nil || result.Outcome != "failed" || result.Steps[1].Outcome != "failed" {
					t.Fatal("controlled later failure did not fail workflow", err)
				}
				assertPrivateRecoveryUnchanged(t, packet)
				return
			}
			if err != nil || result.Outcome != "passed" {
				t.Fatal("successful workflow failed to complete its live child", err)
			}
			if _, err := os.Stat(passed.directory); !os.IsNotExist(err) {
				t.Fatal("successful workflow retained its completed child", err)
			}
			relative, err := records.RunRelative(result.RunID, result.StartedAt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs", relative)); !os.IsNotExist(err) {
				t.Fatal("successful workflow retained its recovery owner", err)
			}
		})
	}
}
