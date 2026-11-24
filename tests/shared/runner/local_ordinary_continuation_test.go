package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These callbacks supply the owner's local decision. Native process settlement
// is covered by the physical ordinary process regression.
// full_only: false
func TestLocalOrdinaryQueuesContinueContainedFailures(t *testing.T) {
	for _, scheduler := range []string{"modules", "runner-groups"} {
		for _, parallel := range []int{1, 2} {
			for _, fatal := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/parallel_%d/fatal_%t", scheduler, parallel, fatal), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), parallel), 5*time.Second)
					defer cancel()
					first := errors.New("controlled local first failure")
					later := errors.New("controlled local later failure")
					unknown := errors.New("controlled unknown ownership")
					names := []string{"failed", "healthy", "later-failed", "later-passed"}
					var lock sync.Mutex
					calls := map[string]int{}
					healthyEntered := make(chan struct{})
					failedReturned := make(chan struct{})
					run := func(child context.Context, name string) (ordinaryStepEvidence, error) {
						lock.Lock()
						calls[name]++
						lock.Unlock()
						local := unitModuleTerminal(name)
						if name == "healthy" && parallel > 1 {
							close(healthyEntered)
							if fatal {
								<-child.Done()
								return local, child.Err()
							}
							select {
							case <-failedReturned:
							case <-child.Done():
								return local, child.Err()
							}
						}
						if name == "failed" {
							if parallel > 1 {
								select {
								case <-healthyEntered:
								case <-child.Done():
									return local, child.Err()
								}
							}
							defer close(failedReturned)
							failure := error(&localCheckFailure{cause: first})
							if fatal {
								failure = errors.Join(failure, unknown)
							}
							return local, failure
						}
						if name == "later-failed" {
							return local, &localCheckFailure{cause: later}
						}
						return local, child.Err()
					}
					var err error
					var got []string
					if scheduler == "modules" {
						var runs []unitPackageRun
						runs, err = runUnitPackages(ctx, names, io.Discard, run)
						for _, item := range runs {
							if item.started {
								got = append(got, item.pkg)
							}
						}
					} else {
						var groups []runnerGroup
						for _, name := range names {
							groups = append(groups, runnerGroup{Name: name})
						}
						var evidence ordinaryStepEvidence
						err = runRunnerGroups(ctx, groups, io.Discard, &evidence, func(child context.Context, group runnerGroup) (ordinaryStepEvidence, error) {
							return run(child, group.Name)
						})
						for _, item := range evidence.RunnerGroups {
							if item.Outcome != "not_run" {
								got = append(got, item.Name)
							}
						}
					}
					if !errors.Is(err, first) || ctx.Err() != nil {
						t.Fatal("local result lost or parent cancelled", err, ctx.Err())
					}
					if fatal {
						if !errors.Is(err, unknown) || calls["later-failed"] != 0 || calls["later-passed"] != 0 {
							t.Fatal("unknown joined branch admitted queued work", calls, err)
						}
					} else {
						if !errors.Is(err, later) || !containedCheckFailure(ctx, err) || !slices.Equal(got, names) {
							t.Fatal("local failure stopped or reordered independent work", got, err)
						}
						for _, name := range names {
							if calls[name] != 1 {
								t.Fatal("selected owner was omitted or retried", calls)
							}
						}
					}
				})
			}
		}
	}
}

// full_only: false
func TestLocalOrdinaryPackageTerminationKeepsResultsWithoutRestart(t *testing.T) {
	root := t.TempDir()
	const failedPackage = modulePrefix + "core/internal/testmain"
	const healthyPackage = modulePrefix + "core/internal/zindependent"
	writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "core/internal/testmain/fixture_test.go", `package fixture
import ("encoding/json"; "os"; "testing"; "time")
func record(t *testing.T) {
 t.Helper()
 f, err := os.OpenFile(os.Getenv("ENKV_PACKAGE_TERMINATION_WITNESS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 err = json.NewEncoder(f).Encode(struct{Name string; PID int}{t.Name(), os.Getpid()})
 if closeErr := f.Close(); err != nil || closeErr != nil { t.Fatal(err, closeErr) }
}
// full_only: false
func TestACompleted(t *testing.T) {
 if path := os.Getenv("ENKV_PACKAGE_TERMINATION_HOLD"); path != "" {
  t.Run("first/leaf", func(t *testing.T) {
   record(t)
   if err := os.WriteFile(path+".started", nil, 0600); err != nil { t.Fatal(err) }
   for { if _, err := os.Stat(path); err == nil { break }; time.Sleep(time.Millisecond) }
  })
  t.Run("last/leaf", func(t *testing.T) { record(t); t.Fatal("queued same-package partition executed after termination") })
  return
 }
 record(t)
}
// full_only: false
func TestBTerminated(t *testing.T) {
 if path := os.Getenv("ENKV_PACKAGE_TERMINATION_HOLD"); path != "" { for { if _, err := os.Stat(path+".started"); err == nil { break }; time.Sleep(time.Millisecond) } }
 record(t)
 if os.Getenv("ENKV_PACKAGE_TERMINATION_MODE") == "panic" { panic("controlled package panic") }
 time.Sleep(time.Hour)
}
// full_only: false
func TestCNever(t *testing.T) { record(t); t.Fatal("unfinished root restarted") }
// full_only: false
func TestSupervisorInstalledInvocationBoundaries(t *testing.T) { record(t); t.Fatal("unfinished isolated partition restarted") }
`)
	writeLocalGoFixture(t, root, "core/internal/zindependent/fixture_test.go", `package independent
import ("encoding/json"; "os"; "testing")
// full_only: false
func TestHealthy(t *testing.T) {
 f, err := os.OpenFile(os.Getenv("ENKV_PACKAGE_TERMINATION_WITNESS"), os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 err = json.NewEncoder(f).Encode(struct{Name string; PID int}{t.Name(), os.Getpid()})
 if closeErr := f.Close(); err != nil || closeErr != nil { t.Fatal(err, closeErr) }
}
`)
	ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), false), 1), time.Minute)
	defer cancel()
	values, err := testBuildEnvironment(runGoEnvironment, ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_PACKAGE_TERMINATION_HOLD", "")
	converter := testEventConverterFixture(t, root)
	var artifacts []preparedOrdinaryArtifact
	for _, row := range []struct {
		pkg   string
		tests []string
	}{
		{failedPackage, []string{"TestACompleted", "TestBTerminated", "TestCNever", "TestSupervisorInstalledInvocationBoundaries"}},
		{healthyPackage, []string{"TestHealthy"}},
	} {
		binary := filepath.Join(t.TempDir(), "fixture.test")
		if _, err := runGo(ctx, root, "core", "test", "-c", "-o", binary, row.pkg); err != nil {
			t.Fatal(err)
		}
		directory := strings.TrimPrefix(row.pkg, modulePrefix+"core/")
		artifacts = append(artifacts, preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Directory: "core", Package: row.pkg, Tests: row.tests, CompiledTests: slices.Clone(row.tests), Classifications: runnerIsolationClassifications(row.tests), TestFlags: []string{"-timeout=200ms"}}, binary: binary, cwd: filepath.Join(root, "core", directory), converter: converter, unit: true})
	}
	for _, mode := range []string{"panic", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observations.jsonl")
			t.Setenv("ENKV_PACKAGE_TERMINATION_WITNESS", path)
			t.Setenv("ENKV_PACKAGE_TERMINATION_MODE", mode)
			group := preparedOrdinaryGroup{goenv: values, step: resolvedWorkflowStep{Kind: "unit"}}
			evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
			err := group.executeArtifacts(ctx, root, artifacts, &evidence, io.Discard)
			if err == nil || !containedCheckFailure(ctx, err) || ctx.Err() != nil {
				t.Fatal("joined package termination stopped independent work", err, ctx.Err())
			}
			body, readErr := os.ReadFile(path)
			rows, decodeErr := decodeObjects[struct {
				Name string
				PID  int
			}](body)
			if readErr != nil || decodeErr != nil || len(rows) != 3 || rows[0].Name != "TestACompleted" || rows[1].Name != "TestBTerminated" || rows[2].Name != "TestHealthy" || rows[0].PID != rows[1].PID || rows[1].PID == rows[2].PID {
				t.Fatal("package restarted unfinished work or lost independent execution", rows, readErr, decodeErr)
			}
			if !errors.Is(syscall.Kill(rows[0].PID, 0), syscall.ESRCH) || !errors.Is(syscall.Kill(rows[2].PID, 0), syscall.ESRCH) {
				t.Fatal("package process did not positively settle", rows)
			}
			outcomes := map[string]ordinaryTest{}
			for _, row := range evidence.Tests {
				if _, repeated := outcomes[row.Name]; repeated {
					t.Fatal("package repeated a result", row)
				}
				outcomes[row.Name] = row
			}
			if len(outcomes) != 5 || outcomes["TestACompleted"].Outcome != "pass" || outcomes["TestHealthy"].Outcome != "pass" || outcomes["TestBTerminated"].Outcome == "pass" {
				t.Fatal("termination erased completed or failed results", outcomes)
			}
			for _, name := range []string{"TestCNever", "TestSupervisorInstalledInvocationBoundaries"} {
				row := outcomes[name]
				if row.Outcome != "not_run" || row.StartedAt != nil || row.FinishedAt != nil || row.ElapsedSeconds != nil {
					t.Fatal("unfinished root acquired invented execution facts", row)
				}
			}
			tests, conversions := 0, 0
			for _, fact := range evidence.Diagnostics.Commands {
				if !fact.Started || !fact.Joined {
					t.Fatal("continuation lacks a positive process join", fact)
				}
				if fact.Phase == "test" {
					tests++
				}
				if fact.Phase == "conversion" {
					conversions++
				}
			}
			if tests != 2 || conversions != 2 {
				t.Fatal("package execution was restarted or its conversion was omitted", tests, conversions)
			}
		})
	}
	t.Run("peer-drains-before-queued-partition", func(t *testing.T) {
		artifact := artifacts[0]
		artifact.Tests = []string{"TestACompleted", "TestBTerminated"}
		artifact.requests = []string{"TestACompleted/first/leaf", "TestACompleted/last/leaf", "TestBTerminated"}
		artifact.TestFlags = []string{"-timeout=5s"}
		placement, err := prepareOrdinaryPlacement([]preparedOrdinaryArtifact{artifact}, 2, false, nil)
		if err != nil || len(placement.workers) != 2 {
			t.Fatal("two selected roots did not receive two workers", err)
		}
		path, release := filepath.Join(t.TempDir(), "observations.jsonl"), filepath.Join(t.TempDir(), "release")
		t.Setenv("ENKV_PACKAGE_TERMINATION_WITNESS", path)
		t.Setenv("ENKV_PACKAGE_TERMINATION_HOLD", release)
		t.Setenv("ENKV_PACKAGE_TERMINATION_MODE", "panic")
		child, cancel := context.WithTimeout(withExecutionParallel(ctx, 1), 15*time.Second)
		defer cancel()
		stops := &ordinaryPackageStops{stopped: map[string]bool{}}
		group := preparedOrdinaryGroup{goenv: values}
		type completedWorker struct {
			evidence ordinaryStepEvidence
			err      error
		}
		completed := make(chan completedWorker, 2)
		received := 0
		t.Cleanup(func() {
			cancel()
			tail, stop := context.WithTimeout(context.WithoutCancel(child), processGroupSettlementTimeout+time.Second)
			defer stop()
			for received < 2 {
				select {
				case result := <-completed:
					received++
					if !toolCommandsJoined(result.err) {
						t.Error("controlled peer did not join", result.err)
					}
				case <-tail.Done():
					t.Error("controlled workers did not settle")
					return
				}
			}
		})
		for _, worker := range placement.workers {
			go func() {
				local := ordinaryStepEvidence{Focus: &ordinaryFocus{Package: failedPackage, Tests: artifact.requests}, Diagnostics: &checkDiagnostics{Preparation: "passed"}}
				planned := (preparedOrdinaryPlacement{workers: []preparedOrdinaryWorker{worker}}).commands()
				if err := local.Diagnostics.reserveOrdinaryCommands(planned); err != nil {
					completed <- completedWorker{local, err}
					return
				}
				err := group.executeWorker(child, root, worker, stops, &local, io.Discard)
				completed <- completedWorker{local, err}
			}()
		}
		for {
			_, startedErr := os.Stat(release + ".started")
			if startedErr == nil && stops.isStopped(failedPackage) {
				break
			}
			select {
			case <-child.Done():
				t.Fatal("terminated worker did not stop its package while the peer remained active", child.Err())
			case <-time.After(time.Millisecond):
			}
		}
		if err := os.WriteFile(release, nil, 0600); err != nil {
			t.Fatal(err)
		}
		var rows []ordinaryTest
		commands := 0
		for received < 2 {
			select {
			case result := <-completed:
				received++
				if result.err != nil && !containedCheckFailure(child, result.err) || !toolCommandsJoined(result.err) {
					t.Fatal("controlled worker did not retain a safely settled result", result.err)
				}
				rows = append(rows, result.evidence.Tests...)
				for _, fact := range result.evidence.Diagnostics.Commands {
					if !fact.Started || !fact.Joined {
						t.Fatal("controlled worker lost positive join", fact)
					}
					if fact.Phase == "test" {
						commands++
					}
				}
			case <-child.Done():
				t.Fatal("controlled peers did not finish", child.Err())
			}
		}
		childPass, queued := false, false
		for _, row := range rows {
			childPass = childPass || row.Name == "TestACompleted/first/leaf" && row.Outcome == "pass"
			queued = queued || row.Name == "TestACompleted/last/leaf" && row.Outcome == "not_run" && row.StartedAt == nil
		}
		if !childPass || !queued || commands != 2 {
			t.Fatal("terminated worker restarted a queued partition or erased its draining peer", commands, rows)
		}
		body, err := os.ReadFile(path)
		observed, decodeErr := decodeObjects[struct {
			Name string
			PID  int
		}](body)
		if err != nil || decodeErr != nil || len(observed) != 2 || observed[0].PID == observed[1].PID {
			t.Fatal("controlled execution repeated a root or failed to use two native workers", observed, err, decodeErr)
		}
	})

}

// full_only: false
func TestOrdinaryInventorySeparatesChildAndParentTimeout(t *testing.T) {
	root, bin := t.TempDir(), t.TempDir()
	const pkg = "example.org/timeout"
	writeLocalGoFixture(t, root, "go.mod", "module "+pkg+"\n\ngo 1.27.0\n")
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	command := "#!/bin/sh\nif [ \"$1\" = mod ]; then exec " + shellQuote(realGo) + " \"$@\"; fi\nprintf '{\"Action\":\"start\",\"Package\":\"" + pkg + "\"}\\n'\nprintf '{\"Action\":\"run\",\"Package\":\"" + pkg + "\",\"Test\":\"TestBlocked\"}\\n'\nprintf '%s\\n' \"$$\" > \"$ENKV_TEST_TIMEOUT_MARKER\"\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(command), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, timeout := range []string{"child", "parent"} {
		t.Run(timeout, func(t *testing.T) {
			watch, stop := context.WithTimeout(t.Context(), 30*time.Second)
			defer stop()
			marker := filepath.Join(t.TempDir(), "started")
			t.Setenv("ENKV_TEST_TIMEOUT_MARKER", marker)
			expiring, expire := context.WithCancelCause(watch)
			parent := watch
			if timeout == "parent" {
				parent = nativeDeadlineContext{expiring}
			}
			child, cancel := context.WithCancel(expiring)
			defer cancel()
			var evidence ordinaryStepEvidence
			var err error
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				err = executeOrdinaryInventory(parent, nativeDeadlineContext{child}, root, ".", nil, []string{"."}, "", map[string][]string{pkg: {"TestBlocked"}}, nil, nil, &evidence)
			}()
			defer func() {
				expire(context.Canceled)
				<-joined
			}()
			// Expire the owned deadline after the test command starts. Module
			// preparation uses the real Go executable and may take longer under load.
			waitProcessMarker(t, watch, marker)
			timer := time.AfterFunc(time.Second, func() { expire(context.DeadlineExceeded) })
			defer timer.Stop()
			<-joined
			if err == nil || containedCheckFailure(parent, err) != (timeout == "child") {
				t.Fatal("owned timeout and parent deadline were not distinguished", err, parent.Err())
			}
			if evidence.Diagnostics == nil || len(evidence.Diagnostics.Commands) != 1 {
				t.Fatal("timeout command facts unavailable", evidence)
			}
			facts := evidence.Diagnostics.Commands[0]
			if !facts.Started || !facts.Joined || facts.Process != "timed_out" {
				t.Fatal("timeout lacks actual positive process settlement", facts)
			}
		})
	}
}

// full_only: false
func TestDirectUnitContinuesAfterSameModulePackageCompileFailure(t *testing.T) {
	for _, broken := range []struct {
		name, source string
		count        int
	}{
		{"type-check", "package failing\nimport \"testing\"\n// full_only: false\nfunc TestUnavailable(t *testing.T) { undefinedPreparationFixture() }\n", 1},
		{"syntax", "package failing\nimport \"testing\"\n// full_only: false\nfunc TestUnavailable(t *testing.T) { syntax failure }\n", 1},
		{"many-type-errors", "package failing\nimport \"testing\"\n// full_only: false\nfunc TestUnavailable(t *testing.T) { undefinedPreparationFixture() }\n", 81},
	} {
		t.Run(broken.name, func(t *testing.T) {
			ctx, root, _, marker, _, _ := completePreparationFixture(t, "")
			writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
			patterns := []string{"./healthy"}
			var failedPackages []string
			for index := range broken.count {
				name := fmt.Sprintf("failing%02d", index)
				writeLocalGoFixture(t, root, "core/"+name+"/failing_test.go", broken.source)
				patterns = append(patterns, "./"+name)
				failedPackages = append(failedPackages, componentPackage+"/"+name)
			}
			writeLocalGoFixture(t, root, "core/healthy/healthy_test.go", `package healthy
import ("os"; "testing")
// full_only: false
func TestNormal(t *testing.T) {
 if err:=os.WriteFile(os.Getenv("ENKV_PREPARATION_WITNESS"),[]byte("executed\n"),0600);err!=nil { t.Fatal(err) }
}
`)
			var evidence ordinaryStepEvidence
			err := runUnitProfileEvidence(ctx, root, map[string][]string{"core": patterns}, "dev", io.Discard, &evidence)
			if err == nil || !containedCheckFailure(ctx, err) || !toolCommandsJoined(err) || evidence.Complete || evidence.SelectedComplete {
				t.Fatal("failed package lost its contained compilation failure", err, evidence)
			}
			body, readErr := os.ReadFile(marker)
			if readErr != nil || string(body) != "executed\n" || len(evidence.Tests) != 1 || evidence.Tests[0].Name != "TestNormal" || evidence.Tests[0].Outcome != "pass" {
				t.Fatal("package compile failure prevented its healthy sibling", string(body), readErr, evidence.Tests)
			}
			if len(evidence.PreparationFailures) != broken.count {
				t.Fatal("failed package invented or widened unavailable inventory", evidence.PreparationFailures)
			}
			for index, failure := range evidence.PreparationFailures {
				if failure.Directory != "core" || failure.Inventory != "unavailable" || !slices.Equal(failure.Patterns, []string{failedPackages[index]}) {
					t.Fatal("failed package changed unavailable inventory ownership", failure)
				}
			}
			for _, fact := range evidence.Diagnostics.Commands {
				if !fact.Started || !fact.Joined {
					t.Fatal("preparation failure lost a command's positive join", fact)
				}
			}
		})
	}
}

// full_only: false
func TestRunnerGroupCustodyFailureStopsDispatch(t *testing.T) {
	for _, contained := range []bool{false, true} {
		t.Run(fmt.Sprintf("contained_%t", contained), func(t *testing.T) {
			ctx := withExecutionParallel(t.Context(), 1)
			failure := errors.New("controlled contained test failure")
			evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed", Commands: make([]checkCommandFacts, maximumCheckCommands)}}
			groups := []runnerGroup{{Name: "first"}, {Name: "queued"}}
			calls := 0
			err := runRunnerGroups(ctx, groups, io.Discard, &evidence, func(context.Context, runnerGroup) (ordinaryStepEvidence, error) {
				calls++
				process := "passed"
				var checkErr error
				if contained {
					process, checkErr = "process_failed", &localCheckFailure{cause: failure}
				}
				local := unitModuleTerminal("first")
				local.Diagnostics = &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{{Phase: "test", Scope: "first", Process: process, Started: true, Joined: true, Events: "valid"}}}
				return local, checkErr
			})
			outcome := "passed"
			if contained {
				outcome = "failed"
			}
			if err == nil || contained && !errors.Is(err, failure) || containedCheckFailure(ctx, err) || calls != 1 || len(evidence.RunnerGroups) != 2 || evidence.RunnerGroups[0].Outcome != outcome || evidence.RunnerGroups[1].Outcome != "not_run" {
				t.Fatal("diagnostic custody failure admitted queued work or lost the check failure", calls, err, evidence.RunnerGroups)
			}
		})
	}
}

// full_only: false
func TestLocalOrdinaryQueueFailureCollectionRemainsFlat(t *testing.T) {
	t.Run("physical-unit-evidence", func(t *testing.T) {
		root := testEventConverterSourceFixture(t)
		ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), false), 1), time.Minute)
		defer cancel()
		converter := testEventConverterFixture(t, root)
		values, err := testBuildEnvironment(runGoEnvironment, ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		const marker = "controlled unit evidence merge failure"
		var artifacts []preparedOrdinaryArtifact
		small := false
		for index := range 41 {
			binary := filepath.Join(root, "passed")
			if index < 2 {
				status, exit := "PASS", "0"
				if index == 0 {
					binary, status, exit = filepath.Join(root, "failed"), "FAIL", "1"
				}
				body := "#!/bin/sh\nprintf '%s\\n' '=== RUN   TestCase' '    fixture_test.go:1: " + marker + "' '--- " + status + ": TestCase (0.01s)' '" + status + "'\nexit " + exit + "\n"
				if err := os.WriteFile(binary, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			artifacts = append(artifacts, preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{
				Directory: ".", Package: fmt.Sprintf("example.invalid/unit%02d", index), Tests: []string{"TestCase"}, CompiledTests: []string{"TestCase"}, Classifications: []testClassification{{Name: "TestCase", FullOnly: &small}},
			}, binary: binary, cwd: root, converter: converter, unit: true})
		}
		group := preparedOrdinaryGroup{goenv: values}
		var evidence ordinaryStepEvidence
		runErr := group.executeArtifacts(ctx, root, artifacts, &evidence, io.Discard)
		if len(evidence.Tests) != len(artifacts) || len(evidence.Diagnostics.Commands) != 2*len(artifacts) {
			t.Fatal("physical unit merge omitted terminal or command facts", len(evidence.Tests), len(evidence.Diagnostics.Commands))
		}
		for index, result := range evidence.Tests {
			want := "pass"
			if index == 0 {
				want = "fail"
			}
			if result.Package != artifacts[index].Package || result.Name != "TestCase" || result.Outcome != want {
				t.Fatal("physical unit merge changed exact terminal ownership", result)
			}
		}
		for _, fact := range evidence.Diagnostics.Commands {
			if !fact.Started || !fact.Joined {
				t.Fatal("physical unit command did not join", fact)
			}
		}
		if runErr == nil || !containedCheckFailure(ctx, runErr) || !toolCommandsJoined(runErr) {
			t.Fatal("successful command facts changed the joined failure classification", runErr)
		}
		var failure *toolFailure
		if !errors.As(runErr, &failure) || !bytes.Contains(failure.stdout, []byte(marker)) {
			t.Fatal("physical unit merge lost its original assertion", runErr)
		}
		var diagnostic bytes.Buffer
		if err := writeAssemblyDiagnosticBody(&diagnostic, runErr); err != nil || !strings.Contains(diagnostic.String(), marker) || strings.Contains(diagnostic.String(), "Additional cause branches truncated") {
			t.Fatal("physical unit merge hid its original diagnostic", err, diagnostic.String())
		}
	})
	for _, scheduler := range []string{"modules", "runner-groups"} {
		t.Run(scheduler, func(t *testing.T) {
			ctx := withExecutionParallel(t.Context(), 1)
			failure := errors.New("controlled repeated local failure")
			var names []string
			var groups []runnerGroup
			for i := range 81 {
				name := fmt.Sprintf("owner-%d", i)
				names = append(names, name)
				groups = append(groups, runnerGroup{Name: name})
			}
			calls := 0
			run := func(context.Context, string) (ordinaryStepEvidence, error) {
				calls++
				if calls == len(names) {
					return ordinaryStepEvidence{}, nil
				}
				return ordinaryStepEvidence{}, &localCheckFailure{cause: failure}
			}
			var err error
			if scheduler == "modules" {
				_, err = runUnitPackages(ctx, names, io.Discard, run)
			} else {
				var evidence ordinaryStepEvidence
				err = runRunnerGroups(ctx, groups, io.Discard, &evidence, func(child context.Context, group runnerGroup) (ordinaryStepEvidence, error) {
					return run(child, group.Name)
				})
			}
			if calls != len(names) || !errors.Is(err, failure) || !containedCheckFailure(ctx, err) {
				t.Fatal("a long local collection lost its classification or omitted work", calls, err)
			}
		})
	}
}
