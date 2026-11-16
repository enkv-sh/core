package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestOrdinaryWorkflowDisposesJoinedCurrentFiles(t *testing.T) {
	for _, condition := range []string{"passed", "failed", "cancelled", "unjoined"} {
		t.Run(condition, func(t *testing.T) {
			root := workflowExecutionFixture(t)
			plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "current", Steps: []resolvedWorkflowStep{
				{ID: "first", Kind: "unit", Selected: true},
				{ID: "second", Kind: "unit", Selected: true},
			}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var output bytes.Buffer
			var calls []string
			var scratch string
			failure := errors.New("hermetic assertion: expected 7, observed 9")
			_, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(_ context.Context, step resolvedWorkflowStep, out io.Writer, directory string) (workflowStepExecution, error) {
				calls = append(calls, step.ID)
				scratch = directory
				if err := os.WriteFile(filepath.Join(directory, "current-consumer.bin"), []byte("current input"), 0600); err != nil {
					t.Fatal(err)
				}
				current := &ordinaryStepEvidence{Profile: "dev", RaceOptions: raceOptions, Diagnostics: &checkDiagnostics{
					Preparation: "passed", Commands: []checkCommandFacts{{Phase: "test", Scope: "fixture", Process: "passed", Started: true, Joined: condition != "unjoined", Events: "valid", ToolCleanup: "passed"}},
				}, Tests: []ordinaryTest{{Package: "example.invalid/fixture", Name: "TestCurrent", Outcome: "pass"}}}
				if condition == "failed" {
					current.Tests[0].Outcome = "fail"
					if _, err := io.WriteString(out, failure.Error()+"\n"); err != nil {
						t.Fatal(err)
					}
					return workflowStepExecution{Ordinary: current}, failure
				}
				if condition == "cancelled" {
					cancel()
					return workflowStepExecution{Ordinary: current}, context.Canceled
				}
				return workflowStepExecution{Ordinary: current}, nil
			})
			wantCalls := []string{"first"}
			if condition == "passed" {
				wantCalls = append(wantCalls, "second")
			}
			if !slices.Equal(calls, wantCalls) {
				t.Errorf("executed steps = %v; want %v", calls, wantCalls)
			}
			if (err == nil) != (condition == "passed") {
				t.Errorf("ordinary outcome = %v for %s", err, condition)
			}
			if condition == "failed" && !strings.Contains(output.String(), failure.Error()) {
				t.Error("terminal lost the hermetic assertion details")
			}
			if scratch == "" {
				t.Fatal("current execution did not obtain scratch")
			}
			_, scratchErr := os.Lstat(scratch)
			if condition == "unjoined" {
				if scratchErr != nil {
					t.Error("unjoined consumer lost its current scratch", scratchErr)
				}
			} else if !errors.Is(scratchErr, os.ErrNotExist) {
				t.Error("joined consumers retained ordinary scratch", scratchErr)
			}
			for _, relative := range []string{"tests/workflows/runs", "tests/hermetic/runs", "tests/qualification"} {
				if _, err := os.Lstat(filepath.Join(root, relative)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("ordinary execution created persistent result path %s: %v", relative, err)
				}
			}
		})
	}
}

// full_only: false
func TestCurrentPrivateDirectoryDoesNotResolveHistoricalRuns(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	run, err := createRunDirectory(root, "live", id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	history := filepath.Join(root, "tests/live/runs", "2000-01-01")
	if err := os.Symlink(t.TempDir(), history); err != nil {
		t.Fatal(err)
	}
	owned, err := createPrivateDirectory(root, "live", id, run)
	if err != nil {
		t.Fatal("exact newly created directory depended on historical lookup", err)
	}
	if err := owned.verify(); err != nil {
		t.Fatal("current ownership verification depended on history", err)
	}
	if err := owned.remove(); err != nil {
		t.Fatal("current ownership disposal depended on history", err)
	}
	if _, err := os.Lstat(history); err != nil {
		t.Fatal("current disposal changed the historical entry", err)
	}
	// Exact recovery still uses the historical lookup and must refuse this
	// unsafe historical layout. The new current owner cannot weaken that reader.
	if _, err := records.ResolveRun(filepath.Join(root, "tests/live/runs"), id); err == nil {
		t.Fatal("historical recovery lookup admitted a symlink")
	}
}

// full_only: false
func TestPassedLiveSiblingKeepsWorkflowRecoveryInputs(t *testing.T) {
	for _, condition := range []string{"failed", "interrupted", "unknown-effect", "journal-save"} {
		t.Run(condition, func(t *testing.T) {
			root := workflowExecutionFixture(t)
			initializePublicSourceGitFixture(t, root)
			plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "live-packet", Steps: []resolvedWorkflowStep{
				{ID: "passed", Kind: "run", Selected: true, request: runRequest{Suite: "live"}},
				{ID: "failed", Kind: "run", Selected: true, request: runRequest{Suite: "live"}},
			}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var output bytes.Buffer
			var scratch string
			packets := map[string][]byte{}
			result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, directory string) (workflowStepExecution, error) {
				scratch = directory
				var run *runState
				var files map[string][]byte
				if step.ID == "passed" {
					run = completedPrivateFixtureAt(t, root, "live")
					run.record.ContinuationRootRunID = step.request.workflowRunID
					if err := run.save(); err != nil {
						t.Fatal(err)
					}
					files = privateRecoveryPacket(t, run)
					path := filepath.Join(run.directory, "run.json")
					body, readErr := os.ReadFile(path)
					if readErr != nil {
						t.Fatal(readErr)
					}
					files[path] = body
				} else {
					run, files = unresolvedPrivateRecoveryFixture(t, root)
				}
				for path, body := range files {
					packets[path] = body
				}
				current := workflowStepExecution{Suite: &run.record, Recovery: run.recovery}
				if step.ID == "passed" {
					return current, nil
				}
				if condition == "interrupted" {
					cancel()
					return current, context.Canceled
				}
				if condition == "journal-save" {
					path := filepath.Join(run.directory, "run.json")
					if err := os.Rename(path, path+".original"); err != nil {
						t.Fatal(err)
					}
					packets[path+".original"] = packets[path]
					delete(packets, path)
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
					return current, run.save()
				}
				return current, errors.New("controlled unresolved live work")
			})
			if err == nil || result.Outcome != "failed" || len(result.Steps) != 2 || result.Steps[0].Outcome != "passed" || result.Steps[1].Outcome != "failed" {
				t.Fatal("failed live workflow lost its completed sibling", result, err)
			}
			assertPrivateRecoveryUnchanged(t, packets)
			if _, err := os.Stat(scratch); !os.IsNotExist(err) {
				t.Error("joined failed workflow retained current scratch", err)
			}
			current, err := newRunState(root, runRequest{Suite: "hermetic", Provider: "memory"}, records.Source{}, "controlled")
			if err != nil {
				t.Fatal(err)
			}
			if err := current.finishCurrentRun(io.Discard, nil); err != nil {
				t.Fatal(err)
			}
			assertPrivateRecoveryUnchanged(t, packets)
		})
	}
}

// full_only: false
func TestWorkflowDisposalFailureCannotPass(t *testing.T) {
	root := workflowExecutionFixture(t)
	plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "disposal", Steps: []resolvedWorkflowStep{{ID: "current", Kind: "unit", Selected: true}}}
	var output bytes.Buffer
	var scratch string
	result, err := executeWorkflow(t.Context(), root, plan, &output, nil, nil, func(_ context.Context, _ resolvedWorkflowStep, _ io.Writer, directory string) (workflowStepExecution, error) {
		scratch = directory
		// A changed owner mode must refuse disposal, even after Product passed.
		if err := os.Chmod(scratch, 0755); err != nil {
			t.Fatal(err)
		}
		return workflowStepExecution{}, nil
	})
	if scratch == "" {
		t.Fatal("workflow never obtained current scratch")
	}
	t.Cleanup(func() {
		if err := os.Chmod(scratch, 0700); err != nil {
			t.Error(err)
			return
		}
		if err := os.RemoveAll(scratch); err != nil {
			t.Error(err)
		}
	})
	if err == nil || result.Outcome == "passed" || strings.Contains(output.String(), "Workflow passed") {
		t.Fatal("disposal failure retained a successful workflow result or terminal", result.Outcome, err, output.String())
	}
	if len(result.Steps) != 1 || result.Steps[0].Outcome != "passed" {
		t.Fatal("finalization failure erased the Product step outcome", result.Steps)
	}
	if _, err := os.Stat(scratch); err != nil {
		t.Fatal("uncertain owner was removed", err)
	}
}

// full_only: false
func TestJoinedCurrentRunDisposesAfterConsumerFailure(t *testing.T) {
	for _, condition := range []string{"output", "configuration", "save"} {
		t.Run(condition, func(t *testing.T) {
			state := completedPrivateFixture(t, "hermetic")
			var writer io.Writer = io.Discard
			var cause error
			switch condition {
			case "output":
				writer = failingUnitOutput{}
				cause = &toolFailure{operation: "fixture", process: processResult{Status: "process_failed", Joined: true}, stderr: []byte("hermetic assertion: expected 7, observed 9")}
			case "configuration":
				state.publicConfigurationFiles = map[string]retainedPublicConfigurationFile{"missing.json": {}}
			case "save":
				state.record.Schedule.Repetitions = 101
			}
			if err := state.finishCurrentRun(writer, cause); err == nil {
				t.Fatal("consumer failure lost its failure signal")
			}
			if _, err := os.Stat(state.current.path); !os.IsNotExist(err) {
				t.Fatal("joined current owner survived a consumer failure", condition, err)
			}
		})
	}
}
