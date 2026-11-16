package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestPreparedOrdinaryRefusedDispatchRetainsFacts(t *testing.T) {
	for _, condition := range []string{"canceled-before-dispatch", "canceled-while-waiting", "deadline-while-waiting", "stopped"} {
		t.Run(condition, func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, "started")
			binary := filepath.Join(root, "command")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf started > "+shellQuote(marker)+"\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
			const pkg = "example.test/dispatch"
			const requested = "TestDispatch/child"
			barrier := &repetitionBarrier{}
			artifact := preparedOrdinaryArtifact{
				ordinaryArtifact: ordinaryArtifact{Package: pkg, Tests: []string{"TestDispatch"}},
				binary:           binary, cwd: root, converter: boundTestEventConverterFixture(t, binary), barrier: barrier,
			}
			setPreparedOrdinaryFixtureMetadata(t, &artifact)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wantCause, wantStatus := error(context.Canceled), "interrupted"
			if condition == "deadline-while-waiting" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, time.Second)
				defer stop()
				wantCause, wantStatus = context.DeadlineExceeded, "timed_out"
			}
			if condition == "canceled-before-dispatch" {
				cancel()
			}
			if condition == "stopped" {
				barrier.stopped.Store(true)
			}
			waiting := condition == "canceled-while-waiting" || condition == "deadline-while-waiting"
			locked := false
			if waiting {
				barrier.processes.Lock()
				locked = true
			}
			evidence := ordinaryStepEvidence{Focus: &ordinaryFocus{Package: pkg, Tests: singleTestRequest(requested)}, Diagnostics: &checkDiagnostics{Preparation: "passed"}}
			done := make(chan error, 1)
			returned := false
			t.Cleanup(func() {
				cancel()
				if locked {
					barrier.processes.Unlock()
					locked = false
				}
				if !returned {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("dispatch did not join after barrier cleanup")
					}
				}
			})
			go func() {
				done <- executePreparedOrdinary(ctx, root, artifact, root, map[string][]string{pkg: {"TestDispatch"}}, &evidence)
			}()
			if waiting {
				select {
				case err := <-done:
					returned = true
					t.Fatal("dispatch returned while its repetition barrier was held", err)
				case <-time.After(20 * time.Millisecond):
				}
				if condition == "canceled-while-waiting" {
					cancel()
				}
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("waiting dispatch context did not finish")
				}
				barrier.processes.Unlock()
				locked = false
			}
			var err error
			select {
			case err = <-done:
				returned = true
			case <-time.After(time.Second):
				t.Fatal("refused dispatch did not return")
			}
			if err == nil || condition != "stopped" && !errors.Is(err, wantCause) {
				t.Fatal("refused dispatch lost its failure cause", err)
			}
			if len(evidence.Diagnostics.Commands) != 1 {
				t.Fatal("refused dispatch lacks one test command fact", evidence.Diagnostics.Commands)
			}
			fact := evidence.Diagnostics.Commands[0]
			if fact.Phase != "test" || fact.Scope != pkg || fact.Started || !fact.Joined || fact.Process != wantStatus || fact.Events != "not_run" || fact.RequestedNode != "unavailable" || fact.RaceObservation != "unavailable" || fact.ToolCleanup != "not_required" {
				t.Error("refused dispatch changed command facts", fact)
			}
			want := []ordinaryTest{{Package: pkg, Name: "TestDispatch", Outcome: "not_run"}}
			if evidence.Complete || evidence.SelectedComplete || !slices.Equal(evidence.Tests, want) || evidence.Diagnostics.Preparation != "passed" {
				t.Error("refused dispatch invented execution or changed preparation", evidence)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Error("refused dispatch started a test or converter", err)
			}
		})
	}
}

// full_only: false
func TestPreparedOrdinaryTestlessRefusedDispatchRetainsFacts(t *testing.T) {
	root, _, _ := overlayFixture(t)
	const directory = "plugins/output-contract-test"
	const command = directory + "/cmd/enkv-output-contract-test"
	writeLocalGoFixture(t, root, directory+"/go.mod", "module "+modulePrefix+directory+"\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, command+"/main.go", "package main\nfunc main() {}\n")
	initializeWorkflowExecutionFixture(t, root)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source, err := sourceRevision(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Directory: directory, Package: modulePrefix + command, Patterns: []string{"./cmd/enkv-output-contract-test"}}}
	group := preparedOrdinaryGroup{source: source}
	group.barrier.stopped.Store(true)
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	err = group.executeArtifacts(ctx, root, []preparedOrdinaryArtifact{artifact}, &evidence, nil)
	if err == nil || !strings.Contains(err.Error(), "prepared repetition selection stopped") {
		t.Fatal("stopped testless dispatch lost its refusal cause", err)
	}
	if len(evidence.Diagnostics.Commands) != 1 {
		t.Fatal("refused testless dispatch lacks one command fact", evidence.Diagnostics.Commands)
	}
	fact := evidence.Diagnostics.Commands[0]
	if fact.Phase != "test" || fact.Scope != directory || fact.Process != "interrupted" || fact.Started || !fact.Joined || fact.Events != "not_run" || fact.RequestedNode != "" || fact.RaceObservation != "unavailable" || fact.ToolCleanup != "not_required" {
		t.Error("refused testless dispatch changed command facts", fact)
	}
	if evidence.Complete || evidence.SelectedComplete || len(evidence.Tests) != 0 || evidence.Diagnostics.Preparation != "passed" {
		t.Error("refused testless dispatch invented execution or changed preparation", evidence)
	}
}
