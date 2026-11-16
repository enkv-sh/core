package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const unitProcessWitnessSource = `package aws

import (
 "bytes"
 "encoding/json"
 "flag"
 "os"
 "os/exec"
 "testing"
)

var entered int

func record(t *testing.T, name string, childJoined bool) {
 t.Helper()
 output, err := os.OpenFile(os.Getenv("ENKV_UNIT_PROCESS_WITNESS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 err = json.NewEncoder(output).Encode(struct { Name string; PID, InitialState int; ChildJoined bool; Timeout string }{name, os.Getpid(), entered, childJoined, flag.Lookup("test.timeout").Value.String()})
 closeErr := output.Close()
 if err != nil || closeErr != nil { t.Fatal(err, closeErr) }
}

func independent(t *testing.T) {
 t.Helper()
 record(t, t.Name(), false)
 entered++
 t.Run("leaf[a]+b", func(t *testing.T) {})
}

// full_only: false
func TestAUnitProcess(t *testing.T) { independent(t) }

// full_only: false
func TestBUnitProcess(t *testing.T) { independent(t) }

// full_only: false
func TestConfigurationRecoveryLiveParentControl(t *testing.T) {
 if os.Getenv("ENKV_UNIT_PROCESS_HELPER_CHILD") == "1" {
  record(t, "helper-child", false)
  t.Log("unit helper completed")
  return
 }
 record(t, t.Name(), false)
 t.Skip("owned by the joined unit process parent")
}

// full_only: false
func TestConfigurationRecoveryLiveParentInvokesControl(t *testing.T) {
 child := exec.Command(os.Args[0], "-test.v", "-test.timeout=30s", "-test.run=^TestConfigurationRecoveryLiveParentControl$")
 child.Env = append(os.Environ(), "ENKV_UNIT_PROCESS_HELPER_CHILD=1")
 output, err := child.CombinedOutput()
 if err != nil || !bytes.Contains(output, []byte("unit helper completed")) { t.Fatalf("helper did not complete and join: %v\n%s", err, output) }
 record(t, t.Name(), true)
 entered++
 t.Run("leaf[a]+b", func(t *testing.T) {})
}

// full_only: true
func TestFullOnlyUnitProcessMustNotRun(t *testing.T) { t.Fatal("full-only root executed in dev") }
`

// full_only: false
func TestUnitPackageProcessKeepsRootsAndHelperProof(t *testing.T) {
	const pkg = modulePrefix + "compositions/aws"
	const helper = "TestConfigurationRecoveryLiveParentControl"
	const parent = "TestConfigurationRecoveryLiveParentInvokesControl"
	selected := []string{"TestAUnitProcess", "TestBUnitProcess", helper, parent}
	listed := append(slices.Clone(selected), "TestFullOnlyUnitProcessMustNotRun")
	slices.Sort(listed)
	for _, mode := range []string{"direct", "prepared-unit", "prepared-package"} {
		t.Run(mode, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			module := "module " + pkg + "\n\ngo 1.27.0\n"
			writeLocalGoFixture(t, root, "compositions/aws/go.mod", module)
			writeLocalGoFixture(t, root, "compositions/aws/process_test.go", unitProcessWitnessSource)
			initializeWorkflowExecutionFixture(t, root)
			witness := filepath.Join(t.TempDir(), "processes.jsonl")
			t.Setenv("ENKV_UNIT_PROCESS_WITNESS", witness)
			t.Setenv("ENKV_UNIT_PROCESS_HELPER_CHILD", "")
			ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), true), 1), 2*time.Minute)
			defer cancel()
			var evidence ordinaryStepEvidence
			var result workflowResult
			if mode == "direct" {
				if err := runUnitProfileEvidence(ctx, root, map[string][]string{"compositions/aws": {"."}}, "dev", io.Discard, &evidence); err != nil {
					t.Fatal("direct unit fixture failed", err)
				}
			} else {
				path := filepath.Join(t.TempDir(), "workflow.json")
				step := map[string]any{"id": "unit", "kind": "unit", "packages": []string{"compositions/aws"}}
				if mode == "prepared-package" {
					step["package"] = "compositions/aws"
				}
				saveSelection(t, path, map[string]any{"schema_version": 1, "name": "unit-processes", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{step}})
				plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
				if err != nil {
					t.Fatal("resolve actual unit workflow", err)
				}
				var output bytes.Buffer
				result, err = runWorkflow(ctx, root, "", plan, &output)
				if err != nil || result.Outcome != "passed" || result.executions["unit"].Ordinary == nil {
					t.Fatal("prepared unit fixture failed", err, output.String())
				}
				evidence = *result.executions["unit"].Ordinary
			}
			if evidence.Race == nil || !*evidence.Race || evidence.RaceOptions != acceptedRaceOptions(true) {
				t.Fatal("unit grouping lost accepted race policy", evidence.Race, evidence.RaceOptions)
			}
			if len(evidence.Packages) != 1 {
				t.Fatal("unit partitions repeated or omitted the package inventory", evidence.Packages)
			}
			inventory := evidence.Packages[0]
			actualListed, actualSelected := slices.Clone(inventory.Inventory), slices.Clone(inventory.Tests)
			slices.Sort(actualListed)
			slices.Sort(actualSelected)
			if inventory.Name != pkg || !slices.Equal(actualListed, listed) || !slices.Equal(actualSelected, selected) || !slices.Equal(inventory.NotSelected, []string{"TestFullOnlyUnitProcessMustNotRun"}) {
				t.Fatal("unit grouping changed exact compiled or profile-selected inventory", inventory)
			}
			terminals := map[string]string{}
			for _, test := range evidence.Tests {
				if test.Package != pkg || terminals[test.Name] != "" {
					t.Fatal("unit grouping changed package ownership or duplicated a terminal", test)
				}
				terminals[test.Name] = test.Outcome
			}
			if len(terminals) != 7 || terminals[helper] != "skip" {
				t.Fatal("unit grouping lost exact root/helper and child terminals", terminals)
			}
			for _, name := range []string{selected[0], selected[0] + "/leaf[a]+b", selected[1], selected[1] + "/leaf[a]+b", parent, parent + "/leaf[a]+b"} {
				if terminals[name] != "pass" {
					t.Fatal("unit grouping lost a required parent or literal child pass", name, terminals)
				}
			}
			if evidence.Diagnostics == nil {
				t.Fatal("unit grouping lost command facts")
			}
			testCommands, conversions := 0, 0
			owners := []*checkDiagnostics{evidence.Diagnostics}
			if mode != "direct" {
				preparation := result.executions["unit"].Preparation
				if preparation == nil || preparation.Preparation != "passed" {
					t.Fatal("unit workflow lost its completed preparation owner", preparation)
				}
				owners = append(owners, preparation)
			}
			for _, owner := range owners {
				for _, command := range owner.Commands {
					if !command.Started || !command.Joined || command.Process != "passed" || command.RaceObservation != "not_observed" {
						t.Fatal("unit grouping lost accepted race or a joined command", command)
					}
					if preparation := command.ModulePreparation; preparation != nil && (preparation.Process != "passed" || !preparation.Started || !preparation.Joined) {
						t.Fatal("unit module preparation did not complete and join", preparation)
					}
					if command.Phase == "test" || command.Phase == "conversion" {
						if command.Events != "valid" || command.Scope != pkg {
							t.Fatal("unit process lost its exact structured execution", command)
						}
						if command.Phase == "test" {
							testCommands++
						} else {
							conversions++
						}
					}
				}
			}
			body, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := decodeObjects[struct {
				Name              string
				PID, InitialState int
				ChildJoined       bool
			}](body)
			if err != nil || len(rows) != 5 {
				t.Fatal("unit fixture lost actual root/helper process observations", rows, err)
			}
			processOwners := map[string]int{}
			initial := map[string]int{selected[0]: 0, selected[1]: 1, helper: 2, "helper-child": 0, parent: 2}
			for _, row := range rows {
				if row.PID <= 0 || processOwners[row.Name] != 0 || row.InitialState != initial[row.Name] {
					t.Fatal("unit fixture lost shared package state or repeated a process observation", row)
				}
				processOwners[row.Name] = row.PID
				if row.Name == parent && !row.ChildJoined {
					t.Error("helper parent did not record its real joined child", row)
				}
			}
			if processOwners[selected[0]] != processOwners[selected[1]] || processOwners[selected[0]] != processOwners[parent] || processOwners[helper] != processOwners[parent] || processOwners["helper-child"] == processOwners[parent] {
				t.Error("unit package process or required helper child ownership differs", processOwners)
			}
			if testCommands != 1 || conversions != 1 {
				t.Error("unit roots did not share one test and conversion", testCommands, conversions)
			}

			if mode == "prepared-package" {
				if !validOrdinaryFocusedEvidence(evidence) || evidence.Complete || !evidence.SelectedComplete {
					t.Error("package focus gained whole-workflow completion or lost selected proof")
				}
			} else if !completeOrdinaryEvidence(evidence) {
				t.Error("complete unit selection lost its whole-scope terminal proof")
			}
		})
	}
}

// full_only: false
func TestUnitProcessTimeoutUsesSelectedGroupsAcrossExecutionRoutes(t *testing.T) {
	const directory = "compositions/aws"
	const pkg = modulePrefix + directory
	const helper = "TestConfigurationRecoveryLiveParentControl"
	const parent = "TestConfigurationRecoveryLiveParentInvokesControl"
	parentDeclaration := "// full_only: false\nfunc " + parent
	fullDeclaration := "func TestFullOnlyUnitProcessMustNotRun(t *testing.T) { t.Fatal(\"full-only root executed in dev\") }"
	if strings.Count(unitProcessWitnessSource, parentDeclaration) != 1 || strings.Count(unitProcessWitnessSource, fullDeclaration) != 1 {
		t.Fatal("unit timeout source declarations changed")
	}
	source := strings.Replace(unitProcessWitnessSource, parentDeclaration, "// full_only: true\nfunc "+parent, 1)
	source = strings.Replace(source, fullDeclaration, "func TestOtherFullOnlyUnitProcess(t *testing.T) { independent(t) }", 1)
	for _, route := range []struct {
		name, requested, timeout string
		prepared                 bool
		repetitions              int
	}{
		{name: "direct", repetitions: 1},
		{name: "direct-ordinary-focus", requested: "TestAUnitProcess/leaf[a]+b", repetitions: 1},
		{name: "direct-full-only-focus", requested: parent + "/leaf[a]+b", repetitions: 1},
		{name: "prepared", prepared: true, repetitions: 1},
		{name: "prepared-full-only-focus", requested: parent + "/leaf[a]+b", prepared: true, repetitions: 1},
		{name: "prepared-full-only-shorter", requested: parent + "/leaf[a]+b", timeout: "11m", prepared: true, repetitions: 1},
		{name: "repetitions", prepared: true, repetitions: 2},
	} {
		t.Run(route.name, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			writeLocalGoFixture(t, root, directory+"/go.mod", "module "+pkg+"\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, directory+"/process_test.go", source)
			initializeWorkflowExecutionFixture(t, root)
			witness := filepath.Join(t.TempDir(), "timeouts.jsonl")
			t.Setenv("ENKV_UNIT_PROCESS_WITNESS", witness)
			t.Setenv("ENKV_UNIT_PROCESS_HELPER_CHILD", "")
			ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), true), 1), 3*time.Minute)
			defer cancel()
			var executions []ordinaryStepEvidence
			if !route.prepared {
				var evidence ordinaryStepEvidence
				var err error
				if route.requested == "" {
					err = runUnitProfileEvidence(ctx, root, map[string][]string{directory: {"."}}, "full", io.Discard, &evidence)
				} else {
					step := resolvedWorkflowStep{ID: "unit", Kind: "unit", Packages: map[string][]string{directory: {"./..."}}, OrdinaryFocus: &ordinaryFocus{PackagePath: directory, Tests: []string{route.requested}}}
					err = prepareOrdinaryFocus(ctx, root, "", "full", &step, &evidence, io.Discard)
				}
				if err != nil {
					t.Fatal("direct unit timeout fixture failed", err)
				}
				executions = append(executions, evidence)
			} else {
				path := filepath.Join(t.TempDir(), "workflow.json")
				step := map[string]any{"id": "unit", "kind": "unit", "packages": []string{directory}, "repetitions": route.repetitions}
				if route.requested != "" {
					step["package"], step["tests"] = directory, []string{route.requested}
				}
				saveSelection(t, path, map[string]any{"schema_version": 1, "name": "unit-timeouts", "profile": "full", "execution": map[string]any{"parallel": 1}, "steps": []any{step}})
				plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				var result workflowResult
				if route.timeout == "" {
					result, err = runWorkflow(ctx, root, "", plan, &output)
				} else {
					prepared, prepareErr := prepareWorkflow(ctx, root, "", plan, &output)
					if prepared != nil {
						defer func() {
							tail, release := finalizationContext(ctx)
							defer release()
							if err := prepared.close(tail); err != nil {
								t.Error("close explicit-timeout prepared owner", err)
							}
						}()
					}
					if prepareErr != nil || prepared == nil || prepared.ordinary["unit"] == nil || len(prepared.ordinary["unit"].artifacts) != 1 {
						t.Fatal("explicit-timeout prepared artifact unavailable", prepareErr)
					}
					prepared.ordinary["unit"].artifacts[0].TestFlags = []string{"-timeout=" + route.timeout}
					result, err = runPreparedWorkflow(ctx, root, "", prepared, &output)
				}
				if err != nil || result.Outcome != "passed" || len(result.Steps) != route.repetitions {
					t.Fatal("prepared unit timeout fixture failed", err, output.String())
				}
				for _, step := range result.Steps {
					evidence := result.executions[step.ID].Ordinary
					if step.Outcome != "passed" || evidence == nil {
						t.Fatal("unit repetition lost its current results", step)
					}
					executions = append(executions, *evidence)
				}
				if route.repetitions == 2 && (len(result.RepetitionGroups) != 1 || result.RepetitionGroups[0].RequestedExecutions != 2 || result.RepetitionGroups[0].CompletedExecutions != 2 || result.RepetitionGroups[0].Outcome != "passed") {
					t.Fatal("unit timeout repetitions lost complete execution ownership", result.RepetitionGroups)
				}
			}
			wantRoots := []string{"TestAUnitProcess", "TestBUnitProcess", helper, parent, "TestOtherFullOnlyUnitProcess"}
			// The native alarm covers five roots (10+10+30+30+30 minutes)
			// and eleven idle intervals of 30 minutes: 440 minutes total.
			wantTimeouts := map[string]string{"TestAUnitProcess": "7h20m0s", "TestBUnitProcess": "7h20m0s", helper: "7h20m0s", parent: "7h20m0s", "TestOtherFullOnlyUnitProcess": "7h20m0s", "helper-child": "30s"}
			if route.requested != "" {
				owner, _, _ := strings.Cut(route.requested, "/")
				wantRoots = []string{owner}
				wantTimeouts = map[string]string{owner: "40m0s"}
				if owner == parent {
					wantTimeouts[owner], wantTimeouts["helper-child"] = "2h0m0s", "30s"
					if route.timeout != "" {
						wantTimeouts[owner] = "44m0s"
					}
				}
			}
			for _, evidence := range executions {
				if evidence.Race == nil || !*evidence.Race || evidence.RaceOptions != acceptedRaceOptions(true) || evidence.Profile != "full" || len(evidence.Packages) != 1 || evidence.Packages[0].Name != pkg || !slices.Equal(evidence.Packages[0].Tests, wantRoots) {
					t.Fatal("unit timeout changed its selected roots or accepted race settings", evidence)
				}
				if route.requested == "" && !completeOrdinaryEvidence(evidence) || route.requested != "" && (!validOrdinaryFocusedEvidence(evidence) || evidence.Complete) {
					t.Fatal("unit timeout lost complete selected terminal proof", evidence)
				}
				terminals := map[string]string{}
				for _, terminal := range evidence.Tests {
					if terminal.Package != pkg || terminals[terminal.Name] != "" {
						t.Fatal("unit timeout changed terminal ownership", terminal)
					}
					terminals[terminal.Name] = terminal.Outcome
				}
				wantTerminals := 2 * len(wantRoots)
				for _, root := range wantRoots {
					if root == helper {
						wantTerminals--
						if terminals[root] != "skip" {
							t.Fatal("unit timeout lost its helper skip", terminals)
						}
					} else if terminals[root] != "pass" || terminals[root+"/leaf[a]+b"] != "pass" {
						t.Fatal("unit timeout lost a root or literal child pass", terminals)
					}
				}
				if len(terminals) != wantTerminals {
					t.Fatal("unit timeout changed the exact terminal set", terminals)
				}
				tests, conversions := 0, 0
				for _, command := range evidence.Diagnostics.Commands {
					if command.Process != "passed" || !command.Started || !command.Joined || command.RaceObservation != "not_observed" {
						t.Fatal("unit timeout lost a positive command join or race observation", command)
					}
					if preparation := command.ModulePreparation; preparation != nil && (preparation.Process != "passed" || !preparation.Started || !preparation.Joined) {
						t.Fatal("unit timeout lost a positive module prerequisite join", preparation)
					}
					if command.Phase == "test" {
						tests++
					}
					if command.Phase == "conversion" {
						conversions++
					}
					if command.Phase != "preparation" && command.Events != "valid" {
						t.Fatal("unit timeout lost valid test events", command)
					}
				}
				wantTests, wantConversions := 1, 1
				if tests != wantTests || conversions != wantConversions {
					t.Fatal("unit timeout changed physical test or conversion ownership", tests, conversions)
				}
			}
			body, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := decodeObjects[struct {
				Name, Timeout     string
				PID, InitialState int
				ChildJoined       bool
			}](body)
			if err != nil || len(rows) != len(wantTimeouts)*route.repetitions {
				t.Fatal("unit timeout lost exact real process observations", len(rows), err)
			}
			initial := map[string]int{"TestAUnitProcess": 0, "TestBUnitProcess": 1, helper: 2, parent: 2, "TestOtherFullOnlyUnitProcess": 3, "helper-child": 0}
			if route.requested != "" {
				initial = map[string]int{requestedTestRoots([]string{route.requested})[0]: 0, "helper-child": 0}
			}
			observed := map[string]map[int]bool{}
			for _, row := range rows {
				want, known := wantTimeouts[row.Name]
				if !known || row.Timeout != want || row.PID <= 0 || row.InitialState != initial[row.Name] || row.Name == parent && !row.ChildJoined {
					t.Error("real unit process received the wrong package alarm or lost fresh state/helper join", row, want)
				}
				if observed[row.Name] == nil {
					observed[row.Name] = map[int]bool{}
				}
				if observed[row.Name][row.PID] {
					t.Error("unit repetition reused its process", row)
				}
				observed[row.Name][row.PID] = true
			}
			for name := range wantTimeouts {
				if len(observed[name]) != route.repetitions {
					t.Error("unit timeout lost an exact process owner", name, observed[name])
				}
			}
		})
	}
}

// full_only: false
func TestUnitPackageWorkersShareBuildAndBoundOverlap(t *testing.T) {
	for _, parallel := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(parallel), func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			const directory = "compositions/aws"
			const pkg = modulePrefix + directory
			writeLocalGoFixture(t, root, directory+"/go.mod", "module "+pkg+"\n\ngo 1.27.0\n")
			source := `package aws
import ("crypto/sha256"; "encoding/json"; "flag"; "fmt"; "os"; "path/filepath"; "strconv"; "strings"; "testing"; "time")
var entered int
func observe(t *testing.T) {
 t.Helper()
 if flag.Lookup("test.parallel").Value.String() != "1" { t.Fatal("worker received more than one inner slot") }
 directory := os.Getenv("ENKV_UNIT_WORKER_OBSERVATIONS")
 count, err := strconv.Atoi(os.Getenv("ENKV_UNIT_WORKER_COUNT"))
 if err != nil { t.Fatal(err) }
 start := time.Now().UnixNano()
 marker := filepath.Join(directory, fmt.Sprintf("worker-%d", os.Getpid()))
 if err := os.WriteFile(marker, nil, 0600); err != nil { t.Fatal(err) }
 deadline := time.Now().Add(10*time.Second)
 for {
  entries, err := os.ReadDir(directory)
  if err != nil { t.Fatal(err) }
  found := 0
  for _, entry := range entries { if strings.HasPrefix(entry.Name(), "worker-") { found++ } }
  if found == count { break }
  if found > count || time.Now().After(deadline) { t.Fatal("selected package workers did not overlap", found, count) }
  time.Sleep(time.Millisecond)
 }
 binary, err := os.Executable()
 if err != nil { t.Fatal(err) }
 body, err := os.ReadFile(binary)
 if err != nil { t.Fatal(err) }
 time.Sleep(20*time.Millisecond)
 row := struct{Name string; PID, Initial int; Binary, Hash string; Start, Finish int64}{t.Name(), os.Getpid(), entered, binary, fmt.Sprintf("%x", sha256.Sum256(body)), start, time.Now().UnixNano()}
 entered++
 output, err := os.OpenFile(filepath.Join(directory, "observations.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 err = json.NewEncoder(output).Encode(row)
 closeErr := output.Close()
 if err != nil || closeErr != nil { t.Fatal(err, closeErr) }
 t.Run("literal[a]+b", func(t *testing.T) {})
}
`
			for index := range 8 {
				source += fmt.Sprintf("// full_only: false\nfunc TestWorker%02d(t *testing.T) { observe(t) }\n", index)
			}
			writeLocalGoFixture(t, root, directory+"/workers_test.go", source)
			initializeWorkflowExecutionFixture(t, root)
			observations := t.TempDir()
			t.Setenv("ENKV_UNIT_WORKER_OBSERVATIONS", observations)
			t.Setenv("ENKV_UNIT_WORKER_COUNT", fmt.Sprint(parallel))
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			commands, bin := filepath.Join(observations, "commands"), t.TempDir()
			observer := "#!/bin/sh\ncase \" $* \" in *' -c '*) printf '%s\\n' \"$PWD|$*\" >> \"$ENKV_UNIT_WORKER_COMMANDS\";; esac\nexec " + shellQuote(realGo) + " \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_UNIT_WORKER_COMMANDS", commands)
			ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), false), parallel), 2*time.Minute)
			defer cancel()
			var evidence ordinaryStepEvidence
			if err := runUnitProfileEvidence(ctx, root, map[string][]string{directory: {"."}}, "dev", io.Discard, &evidence); err != nil {
				t.Fatal(err)
			}
			if !completeOrdinaryEvidence(evidence) || len(evidence.Packages) != 1 || len(evidence.Packages[0].Tests) != 8 || len(evidence.Tests) != 16 {
				t.Fatal("worker merge changed canonical selected inventory", evidence.Packages, evidence.Tests)
			}
			body, err := os.ReadFile(filepath.Join(observations, "observations.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			rows, err := decodeObjects[struct {
				Name          string
				PID, Initial  int
				Binary, Hash  string
				Start, Finish int64
			}](body)
			if err != nil || len(rows) != 8 {
				t.Fatal("worker evidence lost or repeated roots", rows, err)
			}
			owners, roots := map[int]int{}, map[string]bool{}
			binary, hash := rows[0].Binary, rows[0].Hash
			var firstStarts, firstFinishes []int64
			for _, row := range rows {
				if roots[row.Name] || row.PID <= 0 || row.Initial != owners[row.PID] || row.Binary != binary || row.Hash != hash || row.Start >= row.Finish {
					t.Fatal("worker lost exact root ownership, sharing or process lifetime", row, owners)
				}
				if row.Initial == 0 {
					firstStarts = append(firstStarts, row.Start)
					firstFinishes = append(firstFinishes, row.Finish)
				}
				roots[row.Name] = true
				owners[row.PID]++
			}
			if len(owners) != parallel || slices.Max(firstStarts) >= slices.Min(firstFinishes) {
				t.Fatal("normal package did not overlap its assigned worker processes", owners, firstStarts, firstFinishes)
			}
			for _, count := range owners {
				if count != 8/parallel {
					t.Fatal("compatible roots did not share worker processes", owners)
				}
			}
			tests, conversions := 0, 0
			for _, fact := range evidence.Diagnostics.Commands {
				if !fact.Started || !fact.Joined || fact.Process != "passed" {
					t.Fatal("worker command did not positively settle", fact)
				}
				if fact.Phase == "test" {
					tests++
				}
				if fact.Phase == "conversion" {
					conversions++
				}
			}
			if tests != parallel || conversions != parallel {
				t.Fatal("worker command ownership differs from prepared placement", tests, conversions)
			}
			body, err = os.ReadFile(commands)
			if err != nil || len(strings.Split(strings.TrimSpace(string(body)), "\n")) != 1 {
				t.Fatal("compatible workers did not borrow one completed build", string(body), err)
			}
			t.Logf("one compiled binary %s served %d overlapping normal PIDs with %d roots each", hash, parallel, 8/parallel)
			if path := os.Getenv("ENKV_ARTIFACT_MEASUREMENT"); path != "" {
				file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				row := map[string]any{"kind": "ordinary_parallel", "parallel": parallel, "roots": 8, "builds": 1, "binary": binary, "binary_sha256": hash, "workers": rows, "test_commands": tests, "conversion_commands": conversions, "race": false, "toolchain": evidence.Toolchain}
				if err := errors.Join(json.NewEncoder(file).Encode(row), file.Close()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
