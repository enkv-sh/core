package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The mutable counter exposes state retained across independent test roots.
const ordinaryMemoryFixtureSource = `package fixture
import ("encoding/json"; "os"; "testing")
var history int
func observe(t *testing.T, want int) {
 t.Helper()
 f, err := os.OpenFile(os.Getenv("ENKV_MEMORY_FIXTURE_OBSERVATIONS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 err = json.NewEncoder(f).Encode(struct{Name string; PID, History int}{t.Name(), os.Getpid(), history})
 closeErr := f.Close()
 if err != nil || closeErr != nil { t.Fatal(err, closeErr) }
 if history != want { t.Fatalf("earlier root state reached fixture: got %d want %d", history, want) }
 history++
 if os.Getenv("ENKV_MEMORY_FIXTURE_FAIL_ROOT") == t.Name() { t.Error("controlled later partition failure") }
 t.Run("leaf[a]+b", func(t *testing.T) {})
 t.Run("omitted.sibling", func(t *testing.T) {})
}
// full_only: false
func TestAOrdinaryPredecessor(t *testing.T) { observe(t, 0) }
// full_only: false
func TestBOrdinarySuccessor(t *testing.T) { observe(t, 1) }
// full_only: false
func TestSupervisorRegisteredCancellationReleasesAdmission(t *testing.T) { observe(t, 0) }
// full_only: false
func TestSupervisorInstalledInvocationBoundaries(t *testing.T) { observe(t, 0) }
`

// full_only: false
func TestOrdinaryRunnerProcessesSharePackageAndKeepRequiredIsolation(t *testing.T) {
	root := t.TempDir()
	const pkg = modulePrefix + "core/internal/testmain"
	t.Setenv("ENKV_MEMORY_FIXTURE_FAIL_ROOT", "")
	t.Run("partition-contract", func(t *testing.T) {
		for _, test := range []struct {
			name, pkg string
			names     []string
			want      [][]string
			big       []bool
		}{
			{"exact-package", pkg, []string{"TestA", "TestSupervisorInstalledInvocationBoundaries", "TestB"}, [][]string{{"TestA", "TestB"}, {"TestSupervisorInstalledInvocationBoundaries"}}, []bool{false, true}},
			{"foreign-package", pkg + "other", []string{"TestA", "TestSupervisorInstalledInvocationBoundaries"}, [][]string{{"TestA", "TestSupervisorInstalledInvocationBoundaries"}}, []bool{false}},
			{"no-native", pkg, []string{"TestA", "TestB"}, [][]string{{"TestA", "TestB"}}, []bool{false}},
			{"single-native", pkg, []string{"TestSupervisorInstalledInvocationBoundaries"}, [][]string{{"TestSupervisorInstalledInvocationBoundaries"}}, []bool{true}},
			{"all-native", pkg, []string{"TestSupervisorRegisteredCancellationReleasesAdmission", "TestSupervisorInstalledInvocationBoundaries"}, [][]string{{"TestSupervisorRegisteredCancellationReleasesAdmission"}, {"TestSupervisorInstalledInvocationBoundaries"}}, []bool{true, true}},
			{"helper-colocation", pkg, []string{"TestLiveRun", "TestSupervisorInstalledInvocationBoundaries", "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent"}, [][]string{{"TestLiveRun", "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent"}, {"TestSupervisorInstalledInvocationBoundaries"}}, []bool{false, true}},
		} {
			t.Run(test.name, func(t *testing.T) {
				before := slices.Clone(test.names)
				artifact := ordinaryArtifact{Package: test.pkg, Tests: test.names, Classifications: runnerIsolationClassifications(test.names)}
				groups, err := ordinaryProcessGroups(artifact, ordinaryRunnerHelperProofs)
				var got [][]string
				var big []bool
				for _, group := range groups {
					got, big = append(got, group.tests), append(big, group.big)
				}
				if err != nil || !reflect.DeepEqual(got, test.want) || !reflect.DeepEqual(big, test.big) || !slices.Equal(test.names, before) {
					t.Fatal("partition changed exact ownership, native classification, helper placement or caller input", got, big, err)
				}
			})
		}
	})
	writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "core/internal/testmain/fixture_test.go", ordinaryMemoryFixtureSource)
	names := []string{"TestAOrdinaryPredecessor", "TestBOrdinarySuccessor", "TestSupervisorRegisteredCancellationReleasesAdmission", "TestSupervisorInstalledInvocationBoundaries"}
	ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), true), 1), 2*time.Minute)
	defer cancel()
	values, err := testBuildEnvironment(runGoEnvironment, ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "fixture.test")
	if _, err := runGo(ctx, root, "core", "test", "-race", "-c", "-o", binary, "./internal/testmain"); err != nil {
		t.Fatal(err)
	}
	binaryHash, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ordinary", "native-selection", "prepared"} {
		t.Run(mode, func(t *testing.T) {
			selected := slices.Clone(names)
			if mode == "native-selection" {
				selected = []string{names[0], names[1], names[3]}
			}
			repetitions := 1
			if mode == "prepared" {
				repetitions = 2
			}
			for attempt := range repetitions {
				path := filepath.Join(t.TempDir(), "observations.jsonl")
				t.Setenv("ENKV_MEMORY_FIXTURE_OBSERVATIONS", path)
				evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
				want := map[string][]string{pkg: selected}
				if mode == "prepared" {
					artifact := preparedOrdinaryArtifact{
						ordinaryArtifact: ordinaryArtifact{Directory: "core", Package: pkg, Tests: selected, Classifications: runnerIsolationClassifications(selected), TestFlags: []string{"-timeout=30s"}},
						binary:           binary, binaryHash: binaryHash, converter: testEventConverterFixture(t, root), cwd: filepath.Join(root, "core/internal/testmain"), selection: runnerGroupSelection(selected),
					}
					err = executePreparedOrdinary(ctx, root, artifact, values["GOROOT"], want, &evidence)
				} else {
					err = executeRunnerIsolationFixture(ctx, root, want, nil, &evidence)
				}
				if err != nil {
					t.Fatalf("%s execution %d reused fixture process state: %v", mode, attempt+1, err)
				}
				if len(evidence.Tests) != 3*len(selected) {
					t.Fatal("process partition lost parent or literal subtest terminals", evidence.Tests)
				}
				for _, result := range evidence.Tests {
					if result.Outcome != "pass" {
						t.Fatal("process partition did not pass every terminal", result)
					}
				}
				commands := 0
				for _, command := range evidence.Diagnostics.Commands {
					if !command.Started || !command.Joined || command.Process != "passed" || command.Events != "valid" || command.RaceObservation != "not_observed" {
						t.Fatal("process partition lost race, terminal or join proof", command)
					}
					if command.Phase == "test" {
						commands++
					}
				}
				if commands != len(selected)-1 {
					t.Fatal("ordinary or native singleton process count changed", commands)
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				rows, err := decodeObjects[struct {
					Name         string
					PID, History int
				}](body)
				if err != nil || len(rows) != len(selected) {
					t.Fatal("native observations omit or repeat a selected root", err)
				}
				owners := map[string]int{}
				seen := map[int]bool{}
				for _, row := range rows {
					if row.PID <= 0 || owners[row.Name] != 0 || !slices.Contains(selected, row.Name) {
						t.Fatal("invalid process ownership observation", row)
					}
					owners[row.Name] = row.PID
					seen[row.PID] = true
				}
				if owners[names[0]] != owners[names[1]] || len(seen) != commands {
					t.Fatal("ordinary roots did not share a package process or native isolation was lost", owners)
				}
			}
		})
	}
	for _, mode := range []string{"ordinary", "prepared"} {
		t.Run("literal-child/"+mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observations.jsonl")
			t.Setenv("ENKV_MEMORY_FIXTURE_OBSERVATIONS", path)
			requested := names[3] + "/leaf[a]+b"
			focus := &ordinaryFocus{Tests: []string{requested}, Package: pkg}
			evidence := ordinaryStepEvidence{Focus: focus, Diagnostics: &checkDiagnostics{Preparation: "passed"}}
			want := map[string][]string{pkg: {names[3]}}
			selection := literalTestSelection(requested)
			if mode == "prepared" {
				artifact := preparedOrdinaryArtifact{
					ordinaryArtifact: ordinaryArtifact{Directory: "core", Package: pkg, Tests: want[pkg], Classifications: runnerIsolationClassifications(want[pkg]), TestFlags: []string{"-timeout=30s"}},
					binary:           binary, binaryHash: binaryHash, converter: testEventConverterFixture(t, root), cwd: filepath.Join(root, "core/internal/testmain"), selection: selection, requests: []string{requested},
				}
				err = executePreparedOrdinary(ctx, root, artifact, values["GOROOT"], want, &evidence)
			} else {
				err = executeRunnerIsolationFixture(ctx, root, want, focus, &evidence)
			}
			if err != nil || len(evidence.Tests) != 2 || !ordinaryFocusedTerminals(evidence.Tests, *focus) {
				t.Fatal("literal child selection lost its parent or selected suffix", err, evidence.Tests)
			}
			for _, command := range evidence.Diagnostics.Commands {
				if !command.Started || !command.Joined || command.Process != "passed" || command.Events != "valid" || command.RaceObservation != "not_observed" || command.Phase == "test" && command.RequestedNode != "passed" {
					t.Fatal("literal child lost race, terminal or positive join evidence", command)
				}
			}
		})
		t.Run("later-failure/"+mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observations.jsonl")
			t.Setenv("ENKV_MEMORY_FIXTURE_OBSERVATIONS", path)
			t.Setenv("ENKV_MEMORY_FIXTURE_FAIL_ROOT", names[3])
			evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
			want := map[string][]string{pkg: slices.Clone(names)}
			if mode == "prepared" {
				artifact := preparedOrdinaryArtifact{
					ordinaryArtifact: ordinaryArtifact{Directory: "core", Package: pkg, Tests: want[pkg], Classifications: runnerIsolationClassifications(want[pkg]), TestFlags: []string{"-timeout=30s"}},
					binary:           binary, binaryHash: binaryHash, converter: testEventConverterFixture(t, root), cwd: filepath.Join(root, "core/internal/testmain"), selection: runnerGroupSelection(names),
				}
				err = executePreparedOrdinary(ctx, root, artifact, values["GOROOT"], want, &evidence)
			} else {
				err = executeRunnerIsolationFixture(ctx, root, want, nil, &evidence)
			}
			var failed *toolFailure
			if !errors.As(err, &failed) || !failed.process.Started || !failed.process.Joined || failed.process.Status != "process_failed" || !containedCheckFailure(ctx, err) || len(evidence.Tests) != 12 {
				t.Fatal("later failure lost earlier terminals or its joined command error", err, evidence.Tests)
			}
			for _, result := range evidence.Tests {
				wantOutcome := "pass"
				if result.Name == names[3] {
					wantOutcome = "fail"
				}
				if result.Outcome != wantOutcome {
					t.Fatal("failure changed completed or later independent terminals", result)
				}
			}
			commands := 0
			for _, command := range evidence.Diagnostics.Commands {
				if !command.Started || !command.Joined || command.Events != "valid" || command.RaceObservation != "not_observed" {
					t.Fatal("failure lost race, terminal or positive join evidence", command)
				}
				wantProcess := "passed"
				if command.Phase == "test" {
					commands++
					if commands == 2 {
						wantProcess = "process_failed"
					}
				}
				if command.Process != wantProcess {
					t.Fatal("later test failure changed an earlier command or converter outcome", command)
				}
			}
			body, readErr := os.ReadFile(path)
			rows, decodeErr := decodeObjects[struct {
				Name         string
				PID, History int
			}](body)
			if readErr != nil || decodeErr != nil || commands != 3 || len(rows) != 4 {
				t.Fatal("failure started an extra process or omitted actual root observations", commands, rows, readErr, decodeErr)
			}
			expectedOrder := []string{names[0], names[1], names[3], names[2]}
			for i, row := range rows {
				if row.Name != expectedOrder[i] || row.PID <= 0 || i == 1 && row.PID != rows[0].PID || i > 1 && row.PID == rows[0].PID {
					t.Fatal("later failure lost exact root order or package/native process ownership", rows)
				}
			}
		})
	}
	t.Run("ordinary-multiple-packages", func(t *testing.T) {
		const foreign = modulePrefix + "core/internal/zfixture"
		foreignSource := strings.ReplaceAll(ordinaryMemoryFixtureSource, "}{t.Name(), os.Getpid(), history}", "}{\"foreign/\"+t.Name(), os.Getpid(), history}")
		foreignSource = strings.Replace(foreignSource, "func TestSupervisorInstalledInvocationBoundaries(t *testing.T) { observe(t, 0) }", "func TestSupervisorInstalledInvocationBoundaries(t *testing.T) { observe(t, 1) }", 1)
		writeLocalGoFixture(t, root, "core/internal/zfixture/fixture_test.go", foreignSource)
		path := filepath.Join(t.TempDir(), "observations.jsonl")
		t.Setenv("ENKV_MEMORY_FIXTURE_OBSERVATIONS", path)
		want := map[string][]string{pkg: slices.Clone(names), foreign: {names[0], names[3]}}
		evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
		err := executeRunnerIsolationFixture(ctx, root, want, nil, &evidence)
		if err != nil || len(evidence.Tests) != 18 {
			t.Fatal("multi-package dispatch omitted or widened a package selection", err, evidence.Tests)
		}
		for _, result := range evidence.Tests {
			if result.Outcome != "pass" || result.Package != pkg && result.Package != foreign {
				t.Fatal("multi-package dispatch lost exact package ownership", result)
			}
		}
		commands := 0
		for _, command := range evidence.Diagnostics.Commands {
			if !command.Started || !command.Joined || command.Process != "passed" || command.Events != "valid" || command.RaceObservation != "not_observed" {
				t.Fatal("multi-package dispatch lost race, terminal or positive join evidence", command)
			}
			if command.Phase == "test" {
				commands++
			}
		}
		body, err := os.ReadFile(path)
		rows, decodeErr := decodeObjects[struct {
			Name         string
			PID, History int
		}](body)
		owners := map[string]int{}
		for _, row := range rows {
			if row.PID <= 0 || owners[row.Name] != 0 {
				t.Fatal("multi-package observations repeat or omit a real process", row)
			}
			owners[row.Name] = row.PID
		}
		if err != nil || decodeErr != nil || len(rows) != 6 || commands != 4 || owners["foreign/"+names[0]] != owners["foreign/"+names[3]] || owners["foreign/"+names[3]] == owners[names[3]] {
			t.Fatal("foreign same-named root shared an independent or native owner", owners, commands, err, decodeErr)
		}
	})
	if after, err := assemblyFileSHA256(binary); err != nil || after != binaryHash {
		t.Fatal("prepared repetitions or later controls changed the once-compiled binary", after, err)
	}
}

func runnerIsolationClassifications(names []string) []testClassification {
	full := false
	classifications := make([]testClassification, len(names))
	for i, name := range names {
		classifications[i] = testClassification{Name: name, FullOnly: &full}
	}
	return classifications
}

func executeRunnerIsolationFixture(parent context.Context, root string, want map[string][]string, focus *ordinaryFocus, evidence *ordinaryStepEvidence) (err error) {
	ctx, owner := withInvocationArtifacts(parent)
	defer func() {
		tail, cancel := finalizationContext(ctx)
		defer cancel()
		err = errors.Join(err, owner.close(tail, toolCommandsJoined(err)))
	}()
	values, err := testBuildEnvironment(runGoEnvironment, ctx, root)
	if err != nil {
		return err
	}
	converter, _, err := prepareTestEventConverter(ctx, root, root)
	if err != nil {
		return err
	}
	packages := make([]string, 0, len(want))
	for pkg := range want {
		packages = append(packages, pkg)
	}
	slices.Sort(packages)
	barrier := &repetitionBarrier{}
	var artifacts []preparedOrdinaryArtifact
	for _, pkg := range packages {
		listed, err := listOrdinaryPackages(ctx, root, "core", nil, []string{pkg}, nil)
		if err != nil || len(listed) != 1 {
			return errors.Join(err, errors.New("fixture package placement differs"))
		}
		compiled, err := prepareOrdinaryPackage(ctx, root, "core", nil, []string{pkg}, listed[0], root, nil)
		if err != nil {
			return err
		}
		artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Directory: "core", Package: pkg, Patterns: []string{pkg}, Tests: want[pkg], Classifications: runnerIsolationClassifications(want[pkg]), TestFlags: []string{"-timeout=30s"}}, binary: compiled.binary, cwd: compiled.cwd, converter: converter, barrier: barrier}
		if focus != nil {
			artifact.requests = slices.Clone(focus.Tests)
		}
		artifacts = append(artifacts, artifact)
	}
	planned, err := preparedOrdinaryCommands(artifacts, "", 1)
	if err != nil {
		return err
	}
	if err := evidence.Diagnostics.reserveOrdinaryCommands(planned); err != nil {
		return err
	}
	var failures []error
	for _, artifact := range artifacts {
		if err := executePreparedOrdinary(ctx, root, artifact, values["GOROOT"], map[string][]string{artifact.Package: artifact.Tests}, evidence); err != nil {
			failures = append(failures, err)
			if !containedCheckFailure(ctx, err) {
				return errors.Join(failures...)
			}
		}
	}
	return errors.Join(failures...)
}
