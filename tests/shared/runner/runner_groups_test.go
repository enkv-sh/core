package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// full_only: false
func TestRunnerToolDirectoriesCoverInventoryThroughLauncher(t *testing.T) {
	for _, condition := range []string{"pass", "contained_failure", "output_failure", "cleanup_failure"} {
		t.Run(condition, func(t *testing.T) {
			root, overlay := runnerProcessFixture(t)
			t.Setenv("ENKV_RUNNER_PROCESS_WITNESS", filepath.Join(t.TempDir(), "processes.jsonl"))
			t.Setenv("ENKV_RUNNER_HELPER_CHILD", "")
			if condition == "contained_failure" {
				path := filepath.Join(root, "tests/shared/runner/process_test.go")
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				const original = "func TestAProcess0(t *testing.T) { independentRunner(t) }"
				if strings.Count(string(body), original) != 1 {
					t.Fatal("controlled runner declaration changed")
				}
				if err := os.WriteFile(path, []byte(strings.Replace(string(body), original, "func TestAProcess0(t *testing.T) { independentRunner(t); t.Error(\"controlled runner failure\") }", 1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			output := &runnerDirectoryOutput{directory: filepath.Join(root, "core/internal/testmain"), condition: condition}
			var evidence ordinaryStepEvidence
			ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 1), 2*time.Minute)
			defer cancel()
			err := runToolTestsProfileEvidence(ctx, root, overlay, "full", output, &evidence)
			if !output.observed || output.missing {
				t.Fatal("runner did not own directories between inventory and group execution", err)
			}
			if condition == "pass" {
				if err != nil || !evidence.Complete || len(evidence.Tests) != 35 {
					t.Fatal("complete runner failed", err, evidence.Tests)
				}
			} else if err == nil || condition != "cleanup_failure" && evidence.Complete {
				t.Fatal("output or cleanup failure granted completion", err)
			}
			if condition == "contained_failure" {
				outcomes := map[string]string{}
				for _, test := range evidence.Tests {
					outcomes[test.Package+"\x00"+test.Name] = test.Outcome
				}
				if !containedCheckFailure(ctx, err) || len(evidence.Tests) != 35 || outcomes[modulePrefix+"core/internal/testmain\x00TestAProcess0"] != "fail" || outcomes["command-line-arguments\x00TestLauncher"] != "pass" {
					t.Fatal("contained runner failure prevented the independent launcher", err, evidence.Tests)
				}
			}
			_, statErr := os.Stat(output.directory)
			if condition == "cleanup_failure" {
				if statErr != nil || !strings.Contains(err.Error(), "test tool directory cleanup failed") || len(evidence.Tests) != 35 || !completeOrdinaryEvidence(evidence) || !toolCommandsJoined(err) {
					t.Fatal("cleanup failure lost completed tests or retained directory", err, statErr)
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("joined runner retained empty tool directories", statErr)
			}
			if condition == "output_failure" {
				for _, fact := range evidence.Diagnostics.Commands {
					if fact.Phase == "test" && fact.Started {
						t.Fatal("failed progress started tests", fact)
					}
				}
				for _, test := range evidence.Tests {
					if test.Outcome != "not_run" || test.StartedAt != nil || test.FinishedAt != nil || test.ElapsedSeconds != nil {
						t.Fatal("failed progress invented execution", test)
					}
				}
			} else {
				tests, conversions := 0, 0
				for _, fact := range evidence.Diagnostics.Commands {
					if fact.Phase == "test" || fact.Phase == "conversion" {
						if !fact.Started || !fact.Joined || fact.Events != "valid" {
							t.Fatal("runner lifecycle lost positive process settlement or valid events", fact)
						}
						if fact.Phase == "test" {
							tests++
						} else {
							conversions++
						}
					}
				}
				if tests != 4 || conversions != 4 {
					t.Fatal("runner lifecycle changed one-process-per-package ownership", tests, conversions)
				}
			}
		})
	}
}

type runnerDirectoryOutput struct {
	directory, condition string
	observed, missing    bool
}

func (w *runnerDirectoryOutput) Write(body []byte) (int, error) {
	startingGroup := strings.HasPrefix(string(body), "runner: starting group ")
	startingLauncher := strings.HasPrefix(string(body), "Check phase=test scope=command-line-arguments\n")
	if startingGroup || startingLauncher {
		w.observed = true
		_, err := os.Stat(w.directory)
		w.missing = w.missing || err != nil
		if w.condition == "output_failure" && startingGroup {
			return 0, errors.New("controlled progress failure")
		}
	}
	if w.condition == "cleanup_failure" && startingLauncher {
		if err := os.WriteFile(filepath.Join(w.directory, "unexpected"), []byte("retain"), 0600); err != nil {
			return 0, err
		}
	}
	return len(body), nil
}

// full_only: false
func TestRunnerGroupsBalanceDurationsAndKeepUnknownRoots(t *testing.T) {
	want := map[string][]string{"example.org/tests": {"TestA", "TestB", "TestC", "TestD", "TestE", "TestF", "TestUnknown"}}
	weights := map[string]float64{}
	for name, weight := range map[string]float64{"TestA": 8, "TestB": 7, "TestC": 6, "TestD": 5, "TestE": 4, "TestF": 3} {
		weights["example.org/tests\x00"+name] = weight
	}
	groups, err := runnerTestGroups(want, weights, 4)
	if err != nil {
		t.Fatal(err)
	}
	expected := [][]string{{"TestA"}, {"TestB", "TestUnknown"}, {"TestC", "TestF"}, {"TestD", "TestE"}}
	if len(groups) != len(expected) {
		t.Fatal("one package did not use all available normal workers", groups)
	}
	for index, group := range groups {
		if len(group.Packages) != 1 || group.Packages[0].Name != "example.org/tests" || !slices.Equal(group.Packages[0].Tests, expected[index]) {
			t.Fatal("normal placement lost stable weighted root ownership", groups)
		}
	}
	for count := 1; count <= 4; count++ {
		groups, err := runnerTestGroups(map[string][]string{"example.org/tests": want["example.org/tests"][:count]}, nil, 4)
		if err != nil || len(groups) != count {
			t.Fatal("small package inventory did not use its available workers", groups, err)
		}
	}
	for _, inventory := range []map[string][]string{nil, {"example.org/tests": nil}, {"example.org/tests": {"TestA", "TestA"}}, {"example.org/tests": {"TestA/child"}}} {
		if _, err := runnerTestGroups(inventory, nil, 4); err == nil {
			t.Fatal("invalid inventory accepted", inventory)
		}
	}
}

// full_only: false
func TestRunnerGroupConcurrencyPreservesEvidenceAndJoins(t *testing.T) {
	groups := []runnerGroup{{Name: "one"}, {Name: "two"}, {Name: "three"}, {Name: "four"}, {Name: "queued"}}
	for _, parallel := range []int{1, 2, 3, 4} {
		for _, outcome := range []string{"pass", "failure", "cancel"} {
			t.Run(fmt.Sprintf("%s/parallel_%d", outcome, parallel), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 4096}}), 5*time.Second)
				defer cancel()
				started := make(chan string, len(groups))
				release := make(chan struct{})
				done := make(chan error, 1)
				var evidence ordinaryStepEvidence
				var output bytes.Buffer
				var active, peak atomic.Int32
				var wrongAllocation atomic.Bool
				failure := errors.New("controlled group failure")
				go func() {
					defer close(done)
					done <- runRunnerGroups(ctx, groups, &output, &evidence, func(child context.Context, group runnerGroup) (ordinaryStepEvidence, error) {
						if executionCapacityFromContext(child) != (executionCapacity{Parallel: 1, MemoryLimitMiB: 4096}) {
							wrongAllocation.Store(true)
						}
						live := active.Add(1)
						defer active.Add(-1)
						for old := peak.Load(); live > old; old = peak.Load() {
							if peak.CompareAndSwap(old, live) {
								break
							}
						}
						started <- group.Name
						local := unitModuleTerminal(group.Name)
						local.EventTimeSource = "go_test_json"
						local.Diagnostics = &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{{Scope: "package", Joined: true}}}
						select {
						case <-release:
						case <-child.Done():
							return local, child.Err()
						}
						if outcome == "failure" {
							if group.Name == "one" {
								return local, failure
							}
							<-child.Done()
							return local, child.Err()
						}
						return local, nil
					})
				}()
				t.Cleanup(func() {
					cancel()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("group scheduler did not join")
					}
				})
				for range parallel {
					select {
					case <-started:
					case <-ctx.Done():
						t.Fatal("admitted wave did not start")
					}
				}
				select {
				case name := <-started:
					t.Fatal("lane bound exceeded", name)
				default:
				}
				if outcome == "cancel" {
					cancel()
				} else {
					close(release)
				}
				var err error
				select {
				case err = <-done:
				case <-ctx.Done():
					select {
					case err = <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("group cancellation did not join")
					}
				}
				if outcome == "pass" && err != nil || outcome == "failure" && !errors.Is(err, failure) || outcome == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("wrong group outcome", err)
				}
				if active.Load() != 0 || peak.Load() != int32(parallel) || wrongAllocation.Load() {
					t.Fatal("invalid lane allocation or unjoined callback")
				}
				count := parallel
				if outcome == "pass" {
					count = len(groups)
				}
				if len(evidence.Tests) != count || len(evidence.Diagnostics.Commands) != count || len(evidence.RunnerGroups) != len(groups) || evidence.Complete {
					t.Fatal("lost evidence or premature completeness", evidence)
				}
				for i, fact := range evidence.RunnerGroups {
					if fact.Name != groups[i].Name {
						t.Fatal("group order changed")
					}
					if i >= count {
						if fact.Outcome != "not_run" {
							t.Fatal("queued group ran")
						}
						continue
					}
					wantOutcome := "passed"
					if outcome != "pass" {
						wantOutcome = "failed"
					}
					if fact.Outcome != wantOutcome {
						t.Fatal("group lost its execution outcome", fact.Name, fact.Outcome, wantOutcome)
					}
					if evidence.Tests[i].Package != groups[i].Name || evidence.Diagnostics.Commands[i].Scope != groups[i].Name+"/package" || !evidence.Diagnostics.Commands[i].Joined {
						t.Fatal("ordered evidence changed")
					}
				}
			})
		}
	}
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("output_failure_%d", failAt), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 4), 5*time.Second)
			defer cancel()
			started := make(chan struct{})
			output := &runnerGroupFailOutput{failAt: failAt, started: started, ctx: ctx}
			var evidence ordinaryStepEvidence
			var calls, joined atomic.Int32
			err := runRunnerGroups(ctx, groups, output, &evidence, func(child context.Context, _ runnerGroup) (ordinaryStepEvidence, error) {
				calls.Add(1)
				close(started)
				<-child.Done()
				joined.Add(1)
				return ordinaryStepEvidence{}, child.Err()
			})
			if err == nil || calls.Load() != int32(failAt-1) || joined.Load() != calls.Load() {
				t.Fatal("output failure launched extra work or lost a join", err)
			}
			for _, group := range evidence.RunnerGroups[failAt-1:] {
				if group.Outcome != "not_run" {
					t.Fatal("queued group ran after output failure")
				}
			}
		})
	}
	t.Run("cancelled_before_admission", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var evidence ordinaryStepEvidence
		err := runRunnerGroups(ctx, groups, io.Discard, &evidence, func(context.Context, runnerGroup) (ordinaryStepEvidence, error) {
			t.Error("cancelled work started")
			return ordinaryStepEvidence{}, nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

type runnerGroupFailOutput struct {
	failAt, calls int
	started       <-chan struct{}
	ctx           context.Context
}

func (w *runnerGroupFailOutput) Write(body []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		if w.failAt > 1 {
			select {
			case <-w.started:
			case <-w.ctx.Done():
			}
		}
		return 0, errors.New("controlled output failure")
	}
	return len(body), nil
}

// full_only: false
func TestRunnerGroupsKeepDisjointCompletePackageInventories(t *testing.T) {
	for _, count := range []int{4, 127, 128, 129} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			want := map[string][]string{}
			for _, pkg := range []string{"example.org/third", "example.org/first", "example.org/second"} {
				names := []string{"TestShared", "ExampleRead", "FuzzDecode", "TestLiteral.a+$"}
				for i := len(names); i < count; i++ {
					names = append(names, fmt.Sprintf("TestRoot%03d", i))
				}
				want[pkg] = names
			}
			before := map[string][]string{}
			for pkg, names := range want {
				before[pkg] = slices.Clone(names)
			}
			groups, err := runnerTestGroups(want, nil, 4)
			if err != nil {
				t.Fatal(err)
			}
			if len(groups) != 4 || !reflect.DeepEqual(want, before) {
				t.Fatal("group boundary or caller inventory changed", groups)
			}
			seen := map[string]bool{}
			var packages []ordinaryPackage
			for _, group := range groups {
				packages = append(packages, group.Packages...)
			}
			for _, group := range packages {
				if len(group.Tests) == 0 {
					t.Fatal("empty runner group", group)
				}
				selection := regexp.MustCompile(runnerGroupSelection(group.Tests))
				for _, name := range want[group.Name] {
					if selection.MatchString(name) != slices.Contains(group.Tests, name) || selection.MatchString(name+"Extra") {
						t.Fatal("group selector widened or omitted a root", group.Name, name)
					}
				}
				for _, name := range group.Tests {
					key := group.Name + "\x00" + name
					if !slices.Contains(want[group.Name], name) || seen[key] {
						t.Fatal("group root is unexpected or repeated", key)
					}
					seen[key] = true
				}
			}
			for pkg, names := range want {
				for _, name := range names {
					if !seen[pkg+"\x00"+name] {
						t.Fatal("group union omitted a package root", pkg, name)
					}
				}
			}
			if len(seen) != 3*count {
				t.Fatal("same root names collided across packages", len(seen))
			}
			for _, names := range want {
				slices.Reverse(names)
			}
			again, err := runnerTestGroups(want, nil, 4)
			if err != nil || !reflect.DeepEqual(groups, again) {
				t.Fatal("map iteration changed group membership", err)
			}
		})
	}
}

// full_only: false
func TestRunnerGroupsKeepHelpersWithExactProofParents(t *testing.T) {
	const pkg = "enkv.sh/core/internal/testmain"
	names := []string{
		"TestLiveRun", "TestLiveChild", "TestLiveCleanup", "TestLiveRecovery",
		"TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent",
		"TestCoordinatorAssertionEvidencePreservesTypedRerun",
	}
	for i := 0; i < 251; i++ {
		names = append(names, fmt.Sprintf("TestA%03d", i))
	}
	groups, err := runnerTestGroups(map[string][]string{pkg: names}, nil, 4)
	if err != nil || len(groups) != 4 {
		t.Fatal("helper package grouping failed", groups, err)
	}
	positions := map[string]int{}
	for i, group := range groups {
		for _, name := range group.Packages[0].Tests {
			if _, repeated := positions[name]; repeated {
				t.Fatal("helper package root appears twice", name)
			}
			positions[name] = i
		}
	}
	for key, proof := range ordinaryRunnerHelperProofs {
		_, helper, _ := strings.Cut(key, "\x00")
		parent, _, _ := strings.Cut(proof, "/")
		if positions[helper] != positions[parent] {
			t.Fatal("helper lost its exact proving parent", helper, parent)
		}
	}
	// The original parser still requires each exact proving subcase, not just
	// a passing top-level parent in the same group.
	for _, group := range groups {
		first := group.Packages[0]
		events := []ordinaryEvent{{Action: "start", Package: pkg}}
		for _, name := range first.Tests {
			events = append(events, ordinaryEvent{Action: "run", Package: pkg, Test: name})
			if _, helper := ordinaryRunnerHelperProofs[pkg+"\x00"+name]; helper {
				events = append(events, ordinaryEvent{Action: "skip", Package: pkg, Test: name})
				continue
			}
			proofs := map[string]bool{}
			for _, proof := range ordinaryRunnerHelperProofs {
				parent, _, _ := strings.Cut(proof, "/")
				if parent == name && !proofs[proof] {
					proofs[proof] = true
					events = append(events, ordinaryEvent{Action: "run", Package: pkg, Test: proof}, ordinaryEvent{Action: "pass", Package: pkg, Test: proof})
				}
			}
			events = append(events, ordinaryEvent{Action: "pass", Package: pkg, Test: name})
		}
		events = append(events, ordinaryEvent{Action: "pass", Package: pkg})
		if _, err := validateOrdinaryEvents(ordinaryEvents(events...), map[string][]string{pkg: first.Tests}, ordinaryRunnerHelperProofs); err != nil {
			t.Fatal("group lost valid exact helper proof", err)
		}
		if !slices.Contains(first.Tests, "TestLiveRecovery") {
			continue
		}
		var withoutRole []ordinaryEvent
		for _, event := range events {
			if event.Test != "TestCoordinatorAssertionEvidencePreservesTypedRerun/valid_marker" {
				withoutRole = append(withoutRole, event)
			}
		}
		if _, err := validateOrdinaryEvents(ordinaryEvents(withoutRole...), map[string][]string{pkg: first.Tests}, ordinaryRunnerHelperProofs); err == nil {
			t.Fatal("group accepted a helper without its exact role proof")
		}
	}
	for _, missing := range names[:6] {
		t.Run("missing/"+missing, func(t *testing.T) {
			inventory := slices.DeleteFunc(slices.Clone(names), func(name string) bool { return name == missing })
			if _, err := runnerTestGroups(map[string][]string{pkg: inventory}, nil, 4); err == nil {
				t.Fatal("incomplete helper/proof inventory reached execution", missing)
			}
		})
	}
	for _, duplicate := range []string{names[0], names[4], names[6]} {
		t.Run("duplicate/"+duplicate, func(t *testing.T) {
			if _, err := runnerTestGroups(map[string][]string{pkg: append(slices.Clone(names), duplicate)}, nil, 4); err == nil {
				t.Fatal("duplicate root reached packages", duplicate)
			}
		})
	}
}
