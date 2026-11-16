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
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

type runnerProcessObservation struct {
	Name, Binary, Timeout string
	PID, ParentPID, State int
	ChildJoined           bool
}

const runnerProcessWitnessSource = `package main
import ("bytes"; "encoding/json"; "flag"; "os"; "os/exec"; "testing")
var entered int
func observeRunner(t *testing.T, name string, advance, joined bool) {
 t.Helper()
 binary, err := os.Executable(); if err != nil { t.Fatal(err) }
 f, err := os.OpenFile(os.Getenv("ENKV_RUNNER_PROCESS_WITNESS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); if err != nil { t.Fatal(err) }
 err = json.NewEncoder(f).Encode(struct { Name, Binary, Timeout string; PID, ParentPID, State int; ChildJoined bool }{name, binary, flag.Lookup("test.timeout").Value.String(), os.Getpid(), os.Getppid(), entered, joined})
 closeErr := f.Close(); if err != nil || closeErr != nil { t.Fatal(err, closeErr) }
 if advance { entered++ }
}
func independentRunner(t *testing.T) { observeRunner(t, t.Name(), true, false); t.Run("leaf[a]+b", func(t *testing.T) {}); t.Run("omitted.sibling", func(t *testing.T) {}) }
func helperRunner(t *testing.T) {
 if os.Getenv("ENKV_RUNNER_HELPER_CHILD") == "1" { observeRunner(t, t.Name()+"/child", false, false); t.Log("real runner helper joined"); return }
 observeRunner(t, t.Name(), false, false); t.Skip("owned by a real joined proving parent")
}
func provingRunner(t *testing.T, child string, helpers ...string) {
 t.Helper()
 for _, name := range helpers {
  command := exec.Command(os.Args[0], "-test.v", "-test.timeout=15m", "-test.run=^"+name+"$")
  command.Env = append(os.Environ(), "ENKV_RUNNER_HELPER_CHILD=1")
  body, err := command.CombinedOutput(); if err != nil || !bytes.Contains(body, []byte("real runner helper joined")) { t.Fatalf("helper did not complete and join: %v\n%s", err, body) }
 }
 observeRunner(t, t.Name(), true, true); t.Run(child, func(t *testing.T) {})
}
// full_only: false
func TestLiveRun(t *testing.T) { helperRunner(t) }
// full_only: false
func TestLiveChild(t *testing.T) { helperRunner(t) }
// full_only: false
func TestLiveCleanup(t *testing.T) { helperRunner(t) }
// full_only: false
func TestLiveRecovery(t *testing.T) { helperRunner(t) }
// full_only: false
func TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent(t *testing.T) { provingRunner(t, "passed", "TestLiveRun", "TestLiveChild", "TestLiveCleanup") }
// full_only: false
func TestCoordinatorAssertionEvidencePreservesTypedRerun(t *testing.T) { provingRunner(t, "valid_marker", "TestLiveRecovery") }
`

func runnerProcessFixture(t *testing.T) (string, string) {
	t.Helper()
	root := sourceFixtureRoot(t)
	module := "module " + modulePrefix + "core\n\ngo 1.27.0\n"
	writeLocalGoFixture(t, root, "core/go.mod", module)
	writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", module)
	source := runnerProcessWitnessSource
	for i := range 8 {
		source += fmt.Sprintf("\n// full_only: false\nfunc TestAProcess%d(t *testing.T) { independentRunner(t) }\n", i)
	}
	replacements := map[string]string{}
	for _, row := range []struct{ owner, target, pkg, body string }{
		{"runner", "testmain", "main", source},
		{"records", "testrecords", "records", "package records\nimport \"testing\"\n// full_only: false\nfunc TestPeer(t *testing.T) {}\n"},
		{"catalog", "testcatalog", "catalog", "package catalog\nimport \"testing\"\n// full_only: false\nfunc TestPeer(t *testing.T) {}\n"},
	} {
		file := writeLocalGoFixture(t, root, "tests/shared/"+row.owner+"/process_test.go", row.body)
		replacements[filepath.Join(root, "core/internal", row.target, "process_test.go")] = file
		file = writeLocalGoFixture(t, root, "tests/shared/"+row.owner+"/process.go", "package "+row.pkg+"\n")
		replacements[filepath.Join(root, "core/internal", row.target, "process.go")] = file
	}
	writeLocalGoFixture(t, root, "tests/scripts/bootstrap.go", "package main\nfunc main() {}\n")
	writeLocalGoFixture(t, root, "tests/scripts/bootstrap_test.go", "package main\nimport \"testing\"\n// full_only: false\nfunc TestLauncher(t *testing.T) {}\n")
	body, err := json.Marshal(struct{ Replace map[string]string }{replacements})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(bootstrap, body, 0600); err != nil {
		t.Fatal(err)
	}
	initializeWorkflowExecutionFixture(t, root)
	return root, bootstrap
}

// full_only: false
func TestRunnerCompleteGroupsKeepProcessesAndHelperProof(t *testing.T) {
	const pkg = modulePrefix + "core/internal/testmain"
	const firstParent = "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent"
	const secondParent = "TestCoordinatorAssertionEvidencePreservesTypedRerun"
	helpers := map[string]string{"TestLiveRun": firstParent, "TestLiveChild": firstParent, "TestLiveCleanup": firstParent, "TestLiveRecovery": secondParent}
	wantRoots := []string{firstParent, secondParent}
	for i := range 8 {
		wantRoots = append(wantRoots, fmt.Sprintf("TestAProcess%d", i))
	}
	for helper := range helpers {
		wantRoots = append(wantRoots, helper)
	}
	slices.Sort(wantRoots)
	for _, mode := range []string{"direct", "prepared", "repetitions", "literal-child"} {
		t.Run(mode, func(t *testing.T) {
			root, bootstrap := runnerProcessFixture(t)
			witness := filepath.Join(t.TempDir(), "processes.jsonl")
			t.Setenv("ENKV_RUNNER_PROCESS_WITNESS", witness)
			t.Setenv("ENKV_RUNNER_HELPER_CHILD", "")
			ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), true), 4), 3*time.Minute)
			defer cancel()
			repetitions := 1
			if mode == "repetitions" || mode == "literal-child" {
				repetitions = 2
			}
			var executions []ordinaryStepEvidence
			if mode == "direct" {
				var evidence ordinaryStepEvidence
				if err := runToolTestsProfileEvidence(ctx, root, bootstrap, "full", io.Discard, &evidence); err != nil {
					t.Fatal("direct runner fixture failed", err)
				}
				executions = append(executions, evidence)
			} else {
				step := map[string]any{"id": "runner", "kind": "runner-tests", "repetitions": repetitions}
				if mode == "literal-child" {
					step["tests"] = []string{"TestAProcess0/leaf[a]+b"}
				}
				path := filepath.Join(t.TempDir(), "workflow.json")
				saveSelection(t, path, map[string]any{"schema_version": 1, "name": "runner-processes", "profile": "full", "execution": map[string]any{"parallel": 4}, "steps": []any{step}})
				plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				result, err := runWorkflow(ctx, root, bootstrap, plan, &output)
				if err != nil || result.Outcome != "passed" || len(result.Steps) != repetitions {
					t.Fatal("prepared runner fixture failed", err, output.String())
				}
				for _, selected := range result.Steps {
					if result.executions[selected.ID].Ordinary == nil {
						t.Fatal("runner activity lost its current result")
					}
					executions = append(executions, *result.executions[selected.ID].Ordinary)
				}
			}
			var wantPackageGroups [][]string
			for _, evidence := range executions {
				wantProcesses := 1
				if evidence.Race == nil || !*evidence.Race || evidence.RaceOptions != acceptedRaceOptions(true) {
					t.Fatal("runner process placement lost accepted race policy", evidence.Race, evidence.RaceOptions)
				}
				if mode == "literal-child" {
					wantPackageGroups = append(wantPackageGroups, []string{"TestAProcess0"})
					if !validOrdinaryFocusedEvidence(evidence) || evidence.Complete || len(evidence.Tests) != 2 || !ordinaryFocusedTerminals(evidence.Tests, *evidence.Focus) {
						t.Fatal("runner literal child widened selection or lost partial proof", evidence)
					}
				} else {
					if !completeOrdinaryEvidence(evidence) || len(evidence.Packages) != 4 || len(evidence.Tests) != 35 {
						t.Fatal("runner groups lost canonical inventory or exact terminals", evidence)
					}
					groupedPackages := map[string]bool{}
					groupedRoots := map[string]bool{}
					for _, group := range evidence.RunnerGroups {
						if group.Outcome != "passed" || len(group.Packages) == 0 {
							t.Fatal("runner group lost its joined package result", group)
						}
						for _, selected := range group.Packages {
							wantProcesses++
							groupedPackages[selected.Name] = true
							for _, name := range selected.Tests {
								key := selected.Name + "\x00" + name
								if groupedRoots[key] {
									t.Fatal("runner root has more than one worker owner", key)
								}
								groupedRoots[key] = true
							}
							if selected.Name == pkg {
								wantPackageGroups = append(wantPackageGroups, slices.Clone(selected.Tests))
							}
						}
					}
					if len(groupedPackages) != 3 || !groupedPackages[modulePrefix+"core/internal/testcatalog"] || !groupedPackages[pkg] || !groupedPackages[modulePrefix+"core/internal/testrecords"] {
						t.Fatal("runner groups changed their exact imported package set", groupedPackages)
					}
					for _, selected := range evidence.Packages {
						if selected.Name == "command-line-arguments" {
							continue
						}
						for _, name := range selected.Tests {
							if !groupedRoots[selected.Name+"\x00"+name] {
								t.Fatal("selected runner root has no worker owner", selected.Name, name)
							}
						}
					}
				}
				tests := 0
				for _, fact := range evidence.Diagnostics.Commands {
					if !fact.Started || !fact.Joined || fact.Process != "passed" || fact.RaceObservation != "not_observed" {
						t.Fatal("runner placement lost positive joins or race observations", fact)
					}
					if fact.Phase == "test" {
						tests++
						if fact.Events != "valid" {
							t.Fatal("runner process lost structured terminals", fact)
						}
					}
				}
				if tests != wantProcesses {
					t.Error("runner commands differ from retained worker package ownership", tests, wantProcesses)
				}
				foundRunner := false
				for _, inventory := range evidence.Packages {
					if inventory.Name != pkg {
						continue
					}
					foundRunner = true
					actualRoots := slices.Clone(inventory.Inventory)
					slices.Sort(actualRoots)
					if !slices.Equal(actualRoots, wantRoots) {
						t.Fatal("runner changed its canonical compiled inventory", inventory)
					}
					actualTests := slices.Clone(inventory.Tests)
					slices.Sort(actualTests)
					if mode == "literal-child" {
						omitted := slices.DeleteFunc(slices.Clone(wantRoots), func(name string) bool { return name == "TestAProcess0" })
						actualOmitted := slices.Clone(inventory.NotSelected)
						slices.Sort(actualOmitted)
						if !slices.Equal(actualTests, []string{"TestAProcess0"}) || !slices.Equal(actualOmitted, omitted) {
							t.Fatal("runner literal child changed selected or omitted roots", inventory)
						}
					} else if !slices.Equal(actualTests, wantRoots) || !validOrdinaryPackageSelection(inventory, "full") {
						t.Fatal("runner package lost its complete selection", inventory)
					}
				}
				if !foundRunner {
					t.Fatal("runner package inventory disappeared")
				}
			}
			body, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := decodeObjects[runnerProcessObservation](body)
			wantRows := 18 * repetitions
			if mode == "literal-child" {
				wantRows = repetitions
			}
			if err != nil || len(rows) != wantRows {
				t.Fatal("runner omitted or repeated actual root/helper observations", len(rows), wantRows, err)
			}
			wantGroups := map[string]int{}
			wantAlarms := map[string]string{}
			for _, names := range wantPackageGroups {
				slices.Sort(names)
				wantGroups[strings.Join(names, "\x00")]++
				for _, name := range names {
					wantAlarms[name] = (time.Duration(3*len(names)+1) * 15 * time.Minute).String()
				}
			}
			parents, binaries := map[string][]int{}, map[string]bool{}
			packageRoots, states, children := map[int][]string{}, map[int]int{}, map[int]bool{}
			counts := map[string]int{}
			for _, row := range rows {
				counts[row.Name]++
				wantAlarm := wantAlarms[row.Name]
				if strings.HasSuffix(row.Name, "/child") {
					wantAlarm = "15m0s"
				}
				if row.PID <= 0 || row.Timeout != wantAlarm {
					t.Error("runner process lost its identity or package alarm", row)
				}
				if !errors.Is(syscall.Kill(row.PID, 0), syscall.ESRCH) {
					t.Error("runner witness process was not joined", row)
				}
				binaries[row.Binary] = true
				if strings.HasSuffix(row.Name, "/child") {
					if children[row.PID] || row.State != 0 || row.ChildJoined {
						t.Error("runner helper child reused a process or inherited package state", row)
					}
					children[row.PID] = true
				} else {
					packageRoots[row.PID] = append(packageRoots[row.PID], row.Name)
					if row.State != states[row.PID] {
						t.Error("runner package did not preserve its actual shared state", row, states[row.PID])
					}
					if strings.HasPrefix(row.Name, "TestAProcess") || row.Name == firstParent || row.Name == secondParent {
						states[row.PID]++
					}
				}
				if row.Name == firstParent || row.Name == secondParent {
					if !row.ChildJoined {
						t.Error("runner parent did not join its actual helper", row)
					}
					parents[row.Name] = append(parents[row.Name], row.PID)
				}
			}
			for _, row := range rows {
				if parent, ok := helpers[row.Name]; ok && !slices.Contains(parents[parent], row.PID) {
					t.Error("runner helper and proving parent were split", row)
				}
				if helper, child := strings.CutSuffix(row.Name, "/child"); child && (!slices.Contains(parents[helpers[helper]], row.ParentPID) || row.PID == row.ParentPID) {
					t.Error("runner helper lacks its real distinct joined child", row)
				}
			}
			wantNames := map[string]bool{}
			for i := range 8 {
				wantNames[fmt.Sprintf("TestAProcess%d", i)] = true
			}
			for helper, parent := range helpers {
				wantNames[helper], wantNames[helper+"/child"], wantNames[parent] = true, true, true
			}
			if mode == "literal-child" {
				wantNames = map[string]bool{"TestAProcess0": true}
			}
			if len(counts) != len(wantNames) {
				t.Error("runner observation set differs from the literal root/helper set", counts)
			}
			for name := range wantNames {
				if counts[name] != repetitions {
					t.Error("runner root/helper repeated or disappeared", name, counts[name], repetitions)
				}
			}
			if len(packageRoots) != len(wantPackageGroups) {
				t.Error("runner workers did not use fresh processes for their selected roots", packageRoots, wantPackageGroups)
			}
			wantChildren := 4 * repetitions
			if mode == "literal-child" {
				wantChildren = 0
			}
			for pid, names := range packageRoots {
				slices.Sort(names)
				key := strings.Join(names, "\x00")
				wantState := 0
				for _, name := range names {
					if _, helper := helpers[name]; !helper {
						wantState++
					}
				}
				if wantGroups[key] == 0 || states[pid] != wantState || children[pid] {
					t.Error("runner worker changed root ownership, reused a helper child, or lost state advances", pid, names, states[pid])
				}
				wantGroups[key]--
			}
			for key, remaining := range wantGroups {
				if remaining != 0 {
					t.Error("runner worker process ownership is missing or repeated", key, remaining)
				}
			}
			if len(children) != wantChildren {
				t.Error("runner helper children were omitted or reused", children)
			}
			if len(binaries) != 1 {
				t.Error("runner package and helper processes did not reuse one immutable binary", binaries)
			}
		})
	}
}
