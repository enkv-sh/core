package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func runnerLifetimeFixture(t *testing.T) (string, string, preparedOrdinaryArtifact) {
	t.Helper()
	root := t.TempDir()
	const pkg = modulePrefix + "core/internal/runnerlifetime"
	writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "core/internal/runnerlifetime/lifetime_test.go", `package runnerlifetime
import ("flag"; "os"; "strconv"; "testing")
// full_only: false
func TestFirst(t *testing.T) {
 if err := os.WriteFile(os.Getenv("ENKV_RUNNER_FIRST_PID"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil { t.Fatal(err) }
 if err := os.WriteFile(os.Getenv("ENKV_RUNNER_TIMEOUT"), []byte(flag.Lookup("test.timeout").Value.String()), 0600); err != nil { t.Fatal(err) }
 t.Run("leaf[a]+b", func(t *testing.T) {})
}
// full_only: true
// exclusive: true
func TestLater(t *testing.T) { if err := os.WriteFile(os.Getenv("ENKV_RUNNER_LATER_MARKER"), []byte("started"), 0600); err != nil { t.Fatal(err) } }
`)
	ctx, cancel := context.WithTimeout(withRacePolicy(t.Context(), true), time.Minute)
	defer cancel()
	values, err := testBuildEnvironment(runGoEnvironment, ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "lifetime.test")
	if _, err := runGo(ctx, root, "core", "test", "-race", "-c", "-o", binary, "./internal/runnerlifetime"); err != nil {
		t.Fatal(err)
	}
	hash, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	normal, big := false, true
	artifact := preparedOrdinaryArtifact{
		ordinaryArtifact: ordinaryArtifact{Directory: "core", Package: pkg, Patterns: []string{"./internal/runnerlifetime"}, Tests: []string{"TestFirst", "TestLater"}, Classifications: []testClassification{{Name: "TestFirst", FullOnly: &normal}, {Name: "TestLater", FullOnly: &big, Exclusive: true}}, TestFlags: []string{"-timeout=15m"}},
		binary:           binary, binaryHash: hash, cwd: filepath.Join(root, "core/internal/runnerlifetime"), converter: testEventConverterFixture(t, root), selection: runnerGroupSelection([]string{"TestFirst", "TestLater"}),
	}
	return root, values["GOROOT"], artifact
}

// full_only: false
func TestRunnerPhysicalTimeoutAdmissionKeepsFocusAndRepetitions(t *testing.T) {
	root, goroot, original := runnerLifetimeFixture(t)
	for _, mode := range []string{"prepared", "literal-child", "repetitions"} {
		for _, flag := range []string{"-timeout=0", "-timeout=16m", "-timeout=15m"} {
			t.Run(mode+"/"+flag, func(t *testing.T) {
				first, timeout, later := filepath.Join(t.TempDir(), "first.pid"), filepath.Join(t.TempDir(), "timeout"), filepath.Join(t.TempDir(), "later")
				t.Setenv("ENKV_RUNNER_FIRST_PID", first)
				t.Setenv("ENKV_RUNNER_TIMEOUT", timeout)
				t.Setenv("ENKV_RUNNER_LATER_MARKER", later)
				artifact := original
				artifact.Tests, artifact.TestFlags, artifact.selection = []string{"TestFirst"}, []string{flag}, literalTestSelection("TestFirst")
				artifact.Classifications = artifact.Classifications[:1]
				var focus *ordinaryFocus
				if mode == "literal-child" {
					requested := "TestFirst/leaf[a]+b"
					focus = &ordinaryFocus{Package: artifact.Package, Tests: []string{requested}}
					artifact.selection = literalTestSelection(focus.Tests[0])
				}
				ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), true), 1), time.Minute)
				defer cancel()
				var executions []ordinaryStepEvidence
				attempts := 1
				if mode == "repetitions" {
					attempts = 2
				}
				for range attempts {
					evidence := ordinaryStepEvidence{Focus: focus, Diagnostics: &checkDiagnostics{Preparation: "passed"}}
					var err error
					if focus != nil {
						artifact.requests = slices.Clone(focus.Tests)
					}
					err = executePreparedOrdinary(ctx, root, artifact, goroot, map[string][]string{artifact.Package: artifact.Tests}, &evidence)

					if flag != "-timeout=15m" {
						if err == nil || !strings.Contains(err.Error(), "process timeout is outside its bound") || len(evidence.Diagnostics.Commands) != 0 || len(evidence.Tests) != 0 {
							t.Fatal("runner admitted an invalid physical timeout or body", err, evidence)
						}
					} else if err != nil {
						t.Fatal("runner refused its supported physical timeout", err)
					} else {
						if len(evidence.Tests) != 2 || evidence.Tests[0].Package != artifact.Package || evidence.Tests[0].Name != "TestFirst" || evidence.Tests[0].Outcome != "pass" || evidence.Tests[1].Package != artifact.Package || evidence.Tests[1].Name != "TestFirst/leaf[a]+b" || evidence.Tests[1].Outcome != "pass" {
							t.Fatal("runner timeout lost exact per-activity literal terminals", evidence.Tests)
						}
						wantCommands := 2
						if mode == "direct" {
							wantCommands = 1
						}
						if len(evidence.Diagnostics.Commands) != wantCommands {
							t.Fatal("runner timeout lost exact per-activity command facts", evidence.Diagnostics.Commands)
						}
						for i, fact := range evidence.Diagnostics.Commands {
							phase := "test"
							if i == 1 {
								phase = "conversion"
							}
							if fact.Phase != phase || !fact.Started || !fact.Joined || fact.Process != "passed" || fact.Events != "valid" || fact.RaceObservation != "not_observed" {
								t.Fatal("runner timeout lost accepted race or joined process facts", fact)
							}
						}
					}
					executions = append(executions, evidence)
				}
				if flag == "-timeout=15m" {
					body, err := os.ReadFile(timeout)
					terminals, commands := 0, 0
					for _, execution := range executions {
						terminals += len(execution.Tests)
						commands += len(execution.Diagnostics.Commands)
					}
					wantCommands := 2 * attempts
					// One 15-minute root plus three 15-minute idle intervals.
					if err != nil || string(body) != "1h0m0s" || len(executions) != attempts || terminals != 2*attempts || commands != wantCommands {
						t.Fatal("runner lost its package alarm or ordered activity totals", string(body), err, len(executions), terminals, commands)
					}
				} else if _, err := os.Stat(first); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("invalid runner timeout started its test body", err)
				}
				if _, err := os.Stat(later); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("runner physical timeout widened its selection", err)
				}
			})
		}
	}
}

// full_only: false
func TestRunnerCumulativeExpiryKeepsJoinedRootAndRefusesNext(t *testing.T) {
	root, goroot, artifact := runnerLifetimeFixture(t)
	first, later := filepath.Join(t.TempDir(), "first.pid"), filepath.Join(t.TempDir(), "later")
	t.Setenv("ENKV_RUNNER_FIRST_PID", first)
	t.Setenv("ENKV_RUNNER_TIMEOUT", filepath.Join(t.TempDir(), "timeout"))
	t.Setenv("ENKV_RUNNER_LATER_MARKER", later)
	parent := withExecutionParallel(withRacePolicy(t.Context(), true), 1)
	duration := newPreparedGroupDuration(parent, 30*time.Second)
	defer duration.cancel()
	ctx, finish := duration.executionContext(parent)
	defer finish()
	barrier := &repetitionBarrier{}
	artifact.barrier = barrier
	leave, err := barrier.enter(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { leave(true) }) }
	defer release()
	done := make(chan struct{})
	go func() { <-ctx.Done(); release(); close(done) }()
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	err = executePreparedOrdinary(ctx, root, artifact, goroot, map[string][]string{artifact.Package: artifact.Tests}, &evidence)
	finish()
	<-done
	if !errors.Is(err, context.DeadlineExceeded) || len(evidence.Tests) != 3 || evidence.Tests[0].Name != "TestFirst" || evidence.Tests[0].Outcome != "pass" || evidence.Tests[1].Name != "TestFirst/leaf[a]+b" || evidence.Tests[1].Outcome != "pass" || evidence.Tests[2].Name != "TestLater" || evidence.Tests[2].Outcome != "not_run" {
		t.Fatal("runner expiry lost the completed root or its literal child", err, evidence.Tests)
	}
	commands := evidence.Diagnostics.Commands
	if len(commands) != 3 || commands[0].Phase != "test" || !commands[0].Started || !commands[0].Joined || commands[0].Process != "passed" || commands[1].Phase != "conversion" || !commands[1].Started || !commands[1].Joined || commands[1].Process != "passed" || commands[2].Phase != "test" || commands[2].Started || !commands[2].Joined || commands[2].Process != "timed_out" || commands[2].Events != "not_run" {
		t.Fatal("runner expiry lost completed or refused process facts", commands)
	}
	pid := waitProcessMarker(t, t.Context(), first)
	if !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		t.Fatal("completed runner root did not join its real process", pid)
	}
	if _, err := os.Stat(later); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired runner owner started its later root", err)
	}
}
