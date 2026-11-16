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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestUnitProcessPolicyKeepsCompleteGroupsAndBounds(t *testing.T) {
	t.Run("helper-components-and-order", func(t *testing.T) {
		const pkg = "example.org/unit"
		names := []string{"TestNormalA", "TestHelperA", "TestNormalB", "TestParent", "TestHelperB", "ExampleValue", "FuzzValue"}
		before := slices.Clone(names)
		classifications := make([]testClassification, len(names))
		for i, name := range names {
			full := name == "TestParent"
			classifications[i] = testClassification{Name: name, FullOnly: &full}
		}
		helpers := map[string]string{pkg + "\x00TestHelperA": "TestParent/child[a]+b", pkg + "\x00TestHelperB": "TestHelperA", "other\x00TestNormalA": "TestNormalB"}
		artifact := ordinaryArtifact{Package: pkg, Tests: names, Classifications: classifications}
		want := []ordinaryProcessGroup{{tests: []string{"TestNormalA", "TestHelperA", "TestParent", "TestHelperB", "TestNormalB", "ExampleValue", "FuzzValue"}, fullOnly: true}}
		for range 3 {
			got, err := ordinaryProcessGroups(artifact, helpers)
			if err != nil || !reflect.DeepEqual(got, want) || !slices.Equal(names, before) {
				t.Fatal("unit groups changed exact union, helper closure, order or caller input", got, err)
			}
		}
		artifact.Tests = []string{"TestHelperA"}
		if _, err := ordinaryProcessGroups(artifact, helpers); err == nil {
			t.Fatal("unit helper admitted without its selected proof")
		}
		artifact.Tests = []string{"TestNormalA", "TestNormalA"}
		if _, err := ordinaryProcessGroups(artifact, helpers); err == nil {
			t.Fatal("unit process planner admitted a duplicate root")
		}
		artifact.Tests = nil
		if got, err := ordinaryProcessGroups(artifact, helpers); err != nil || len(got) != 1 || len(got[0].tests) != 0 {
			t.Fatal("empty profile selection lost its admitted package execution", got, err)
		}
	})
	t.Run("process-count-bound", func(t *testing.T) {
		names := make([]string, 8193)
		classifications := make([]testClassification, len(names))
		for i := range names {
			names[i] = fmt.Sprintf("TestRoot%04d", i)
			full := false
			classifications[i] = testClassification{Name: names[i], FullOnly: &full}
		}
		artifact := ordinaryArtifact{Package: "example.org/unit", Tests: names[:8192], Classifications: classifications}
		if got, err := ordinaryProcessGroups(artifact, nil); err != nil || len(got) != 1 || len(got[0].tests) != 8192 {
			t.Fatal("last supported unit process count was refused", len(got), err)
		}
		artifact.Tests = names
		if _, err := ordinaryProcessGroups(artifact, nil); err == nil {
			t.Fatal("unit process count exceeded the finite allowance")
		}
	})
}

// full_only: false
func TestUnitCommandReservationKeepsEveryFactAndJoin(t *testing.T) {
	t.Run("preparation-last-slot-before-dispatch", testPreparationLastCommandSlot)
	t.Run("preparation-byte-refusal-before-dispatch", testPreparationCommandByteRefusal)
	// Synthetic facts check capacity and serialization, not process execution.
	preparation := []checkCommandFacts{{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"}}
	t.Run("complete-fold-and-projection", func(t *testing.T) {
		diagnostics := &checkDiagnostics{Preparation: "passed", Commands: slices.Clone(preparation)}
		planned := []ordinaryCommandReservation{{scope: "example.org/unit", processes: 160, factsPerProcess: 2}, {scope: "core", processes: 1, factsPerProcess: 1}}
		if err := diagnostics.reserveOrdinaryCommands(planned); err != nil || diagnostics.commandLimit() != 322 {
			t.Fatal("reservation omitted preparation, conversion or testless facts", diagnostics.commandLimit(), err)
		}
		local := &checkDiagnostics{Preparation: "passed"}
		if err := local.reserveOrdinaryCommands(planned); err != nil {
			t.Fatal(err)
		}
		for i := range 321 {
			phase, scope := "test", "example.org/unit"
			if i < 320 && i%2 != 0 {
				phase = "conversion"
			}
			if i == 320 {
				scope = "core"
			}
			if err := local.append(checkCommandFacts{Phase: phase, Scope: scope, Process: "passed", Started: true, Joined: true, Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"}); err != nil {
				t.Fatal("local unit collector lost a reserved fact", i, err)
			}
		}
		for _, fact := range local.Commands {
			if err := diagnostics.append(fact); err != nil {
				t.Fatal("unit module fold lost a reserved fact", err)
			}
		}
		execution := &checkDiagnostics{Preparation: "passed", Commands: slices.Clone(local.Commands), ordinaryCommandLimit: 322}
		if err := execution.prepend(preparation); err != nil || !reflect.DeepEqual(execution.Commands, diagnostics.Commands) {
			t.Fatal("first repetition did not attach preparation exactly once", err)
		}
		if err := execution.append(preparation[0]); err == nil || len(execution.Commands) != 322 {
			t.Fatal("exact diagnostic reservation was exceeded")
		}
		var terminal bytes.Buffer
		if err := writeCheckDiagnostics(&terminal, execution); err != nil || bytes.Count(terminal.Bytes(), []byte("Check phase=")) != 322 {
			t.Fatal("ordinary terminal omitted reserved process facts", err)
		}

	})
	t.Run("last-process-and-one-over", func(t *testing.T) {
		diagnostics := &checkDiagnostics{Preparation: "passed", Commands: make([]checkCommandFacts, 256)}
		if err := diagnostics.reserveOrdinaryCommands([]ordinaryCommandReservation{{scope: "example.org/unit", processes: 8192, factsPerProcess: 2}}); err != nil || diagnostics.commandLimit() != 16640 {
			t.Fatal("last unit reservation was refused", diagnostics.commandLimit(), err)
		}
		for _, planned := range [][]ordinaryCommandReservation{
			{{scope: "unit", processes: 8193, factsPerProcess: 2}},
			{{scope: "unit", processes: 8192, factsPerProcess: 2}, {scope: "empty", processes: 1, factsPerProcess: 1}},
		} {
			refused := &checkDiagnostics{Commands: slices.Clone(preparation)}
			if err := refused.reserveOrdinaryCommands(planned); err == nil || refused.ordinaryCommandLimit != 0 || !reflect.DeepEqual(refused.Commands, preparation) {
				t.Fatal("oversized reservation was partly admitted", err)
			}
		}
		defaults := &checkDiagnostics{Commands: make([]checkCommandFacts, 256)}
		if err := defaults.append(preparation[0]); err == nil || defaults.commandLimit() != 256 {
			t.Fatal("unit reservation changed the generic/component command bound")
		}
	})
	t.Run("encoded-scope-byte-bound", func(t *testing.T) {
		fits := func(size int) bool {
			diagnostics := &checkDiagnostics{}
			return diagnostics.reserveOrdinaryCommands([]ordinaryCommandReservation{{scope: strings.Repeat("x", size), processes: 8192, factsPerProcess: 2}}) == nil
		}
		low, high := 0, 4096
		if !fits(low) || fits(high) {
			t.Fatal("byte-bound fixture does not straddle the record envelope")
		}
		for high-low > 1 {
			middle := low + (high-low)/2
			if fits(middle) {
				low = middle
			} else {
				high = middle
			}
		}
		if !fits(low) || fits(low+1) {
			t.Fatal("unit diagnostics do not refuse the first unsupported encoded scope")
		}
	})
}

func preparationCapacityGoFixture(t *testing.T) (context.Context, string, string, string) {
	t.Helper()
	root := t.TempDir()
	writeLocalGoFixture(t, root, "core/go.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	control := t.TempDir()
	marker, refuse := filepath.Join(control, "started"), filepath.Join(control, "refuse")
	script := "#!/bin/sh\nprintf 'started\\n' >> " + shellQuote(marker) + " || exit 91\nif [ -f " + shellQuote(refuse) + " ]; then printf 'controlled preparation failure\\n' >&2; exit 19; fi\nexec " + shellQuote(realGo) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(control, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
	return withExecutionParallel(t.Context(), 1), root, marker, refuse
}

// The stored prefix is synthetic; the last slot runs a real owned Go command.
func testPreparationLastCommandSlot(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed=%t", failed), func(t *testing.T) {
			ctx, root, marker, refuse := preparationCapacityGoFixture(t)
			diagnostics := &checkDiagnostics{Preparation: "pending", Commands: make([]checkCommandFacts, 255)}
			for index := range diagnostics.Commands {
				diagnostics.Commands[index] = checkCommandFacts{Phase: "preparation", Scope: "prefix", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"}
			}
			if failed {
				if err := os.WriteFile(refuse, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := diagnostics.runGo(ctx, root, "core", "version")
			if (err != nil) != failed || len(diagnostics.Commands) != 256 {
				t.Fatal("last preparation slot was lost or refused", len(diagnostics.Commands), err)
			}
			last := diagnostics.Commands[255]
			status := "passed"
			if failed {
				status = "process_failed"
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 19 {
					t.Fatal("failed preparation lost its original process cause", err)
				}
			}
			if last.Phase != "preparation" || last.Scope != "core" || last.Process != status || !last.Started || !last.Joined || last.WallSeconds == nil {
				t.Fatal("last preparation slot lost actual process facts", last)
			}
			before := slices.Clone(diagnostics.Commands)
			if _, err := diagnostics.runGo(ctx, root, "core", "version"); err == nil || !reflect.DeepEqual(before, diagnostics.Commands) {
				t.Fatal("full preparation diagnostic owner admitted or changed an extra command", err)
			}
			started, err := os.ReadFile(marker)
			if err != nil || string(started) != "started\n" {
				t.Fatal("first unsupported command started before diagnostic refusal", string(started), err)
			}
		})
	}
}

func testPreparationCommandByteRefusal(t *testing.T) {
	ctx, root, marker, _ := preparationCapacityGoFixture(t)
	if records.MaximumJSONBytes != 32<<20 {
		t.Fatal("qualification record byte ceiling changed")
	}
	fact := checkCommandFacts{Phase: "preparation", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"}
	diagnostics := &checkDiagnostics{Preparation: "pending", Commands: []checkCommandFacts{fact}}
	// Plain ASCII adds one JSON byte per character. Derive the exact existing
	// envelope with the standard encoder, independently of command reservation.
	body, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics.Commands[0].Scope = strings.Repeat("x", (32<<20)-len(body)-1)
	body, err = json.Marshal(diagnostics)
	if err != nil || len(body)+1 != 32<<20 {
		t.Fatal("byte-bound fixture did not fill exactly one record", len(body), err)
	}
	before := diagnostics.Commands[0]
	if _, err := diagnostics.runGo(ctx, root, "core", "version"); err == nil || len(diagnostics.Commands) != 1 || !reflect.DeepEqual(before, diagnostics.Commands[0]) {
		t.Fatal("preparation command crossed the encoded byte ceiling", len(diagnostics.Commands), err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("preparation command started before encoded-byte refusal", err)
	}
}

// full_only: false
func TestJoinedUnitProcessFailureContinuesIndependentGroupsAndKeepsResults(t *testing.T) {
	const pkg = modulePrefix + "compositions/aws"
	const helper = "TestConfigurationRecoveryLiveParentControl"
	const parent = "TestConfigurationRecoveryLiveParentInvokesControl"
	const later = "TestLaterUnitProcess"
	selected := []string{"TestAUnitProcess", "TestBUnitProcess", helper, parent, later}
	listed := append(slices.Clone(selected), "TestFullOnlyUnitProcessMustNotRun")
	slices.Sort(listed)
	source := strings.Replace(unitProcessWitnessSource, "func TestBUnitProcess(t *testing.T) { independent(t) }", "func TestBUnitProcess(t *testing.T) { independent(t); t.Error(\"controlled second unit group failure\") }", 1)
	source += "\n// full_only: false\nfunc TestLaterUnitProcess(t *testing.T) { independent(t) }\n"
	for _, mode := range []string{"direct", "prepared"} {
		t.Run(mode, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			module := "module " + pkg + "\n\ngo 1.27.0\n"
			writeLocalGoFixture(t, root, "compositions/aws/go.mod", module)
			writeLocalGoFixture(t, root, "compositions/aws/process_test.go", source)
			initializeWorkflowExecutionFixture(t, root)
			witness := filepath.Join(t.TempDir(), "processes.jsonl")
			t.Setenv("ENKV_UNIT_PROCESS_WITNESS", witness)
			t.Setenv("ENKV_UNIT_PROCESS_HELPER_CHILD", "")
			ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), true), 1), 2*time.Minute)
			defer cancel()
			var evidence ordinaryStepEvidence
			var runErr error
			if mode == "direct" {
				runErr = runUnitProfileEvidence(ctx, root, map[string][]string{"compositions/aws": {"."}}, "dev", io.Discard, &evidence)
			} else {
				path := filepath.Join(t.TempDir(), "workflow.json")
				saveSelection(t, path, map[string]any{"schema_version": 1, "name": "failed-unit-processes", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{map[string]any{"id": "unit", "kind": "unit", "packages": []string{"compositions/aws"}}}})
				plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				result, err := runWorkflow(ctx, root, "", plan, &output)
				runErr = err
				if result.executions["unit"].Ordinary == nil {
					t.Fatal("failed unit lost current results", err, output.String())
				}
				evidence = *result.executions["unit"].Ordinary
			}
			var failure *toolFailure
			if !errors.As(runErr, &failure) || !failure.process.Started || !failure.process.Joined || failure.process.Status != "process_failed" || !bytes.Contains(failure.stdout, []byte("controlled second unit group failure")) {
				t.Fatal("later unit process lost its actual joined assertion failure", runErr)
			}
			if evidence.Complete || evidence.SelectedComplete || len(evidence.Packages) != 1 || len(evidence.Tests) != 9 {
				t.Fatal("failed unit lost its canonical inventory or independent terminals", evidence)
			}
			inventory := evidence.Packages[0]
			actualListed, actualSelected := slices.Clone(inventory.Inventory), slices.Clone(inventory.Tests)
			slices.Sort(actualListed)
			slices.Sort(actualSelected)
			if inventory.Name != pkg || !slices.Equal(actualListed, listed) || !slices.Equal(actualSelected, selected) || !slices.Equal(inventory.NotSelected, []string{"TestFullOnlyUnitProcessMustNotRun"}) {
				t.Fatal("failed unit changed exact compiled or profile-selected inventory", inventory)
			}
			outcomes := map[string]string{}
			for _, result := range evidence.Tests {
				if result.Package != pkg || outcomes[result.Name] != "" {
					t.Fatal("failed unit changed package ownership or repeated a terminal", result)
				}
				outcomes[result.Name] = result.Outcome
			}
			for _, name := range []string{"TestAUnitProcess", "TestAUnitProcess/leaf[a]+b", "TestBUnitProcess/leaf[a]+b", parent, parent + "/leaf[a]+b", later, later + "/leaf[a]+b"} {
				if outcomes[name] != "pass" {
					t.Fatal("joined failure lost an independent unit terminal", name, outcomes)
				}
			}
			if outcomes["TestBUnitProcess"] != "fail" || outcomes[helper] != "skip" {
				t.Fatal("actual failed root or helper terminal was lost", outcomes)
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
			wantRows := []string{"TestAUnitProcess", "TestBUnitProcess", helper, "helper-child", parent, later}
			if err != nil || len(rows) != len(wantRows) {
				t.Fatal("joined failure omitted or retried an independent unit group", rows, err)
			}
			owners := map[string]int{}
			for index, row := range rows {
				initial := map[string]int{"TestAUnitProcess": 0, "TestBUnitProcess": 1, helper: 2, "helper-child": 0, parent: 2, later: 3}
				if row.Name != wantRows[index] || row.PID <= 0 || row.InitialState != initial[row.Name] || owners[row.Name] != 0 || row.ChildJoined != (row.Name == parent) {
					t.Fatal("joined failure lost fresh unit processes or a joined helper child", rows)
				}
				owners[row.Name] = row.PID
			}
			for _, name := range []string{"TestAUnitProcess", "TestBUnitProcess", parent, later} {
				if owners[name] != owners["TestAUnitProcess"] {
					t.Fatal("assertion failure split the package process", owners)
				}
			}
			if owners[helper] != owners[parent] || owners["helper-child"] == owners[parent] {
				t.Fatal("joined failure split a helper group or lost its separate child", owners)
			}
			if evidence.Diagnostics == nil {
				t.Fatal("joined failure lost required command facts")
			}
			tests, conversions, failedTests := 0, 0, 0
			for _, command := range evidence.Diagnostics.Commands {
				if !command.Started || !command.Joined {
					t.Fatal("failed unit lost a required command join", command)
				}
				if command.Phase == "test" {
					tests++
					if command.Process != "passed" {
						if command.Process != "process_failed" {
							t.Fatal("joined unit failure changed process disposition", command)
						}
						failedTests++
					}
				} else if command.Process != "passed" {
					t.Fatal("joined unit failure changed another command disposition", command)
				}
				if command.Phase == "conversion" {
					conversions++
				}
			}
			if tests != 1 || failedTests != 1 || conversions != 1 {
				t.Fatal("joined unit failure omitted groups, repeated work or lost a failure", tests, conversions, failedTests)
			}
		})
	}
}

// full_only: false
func TestUnitCapacityCountsPackageProcessesInsteadOfRoots(t *testing.T) {
	artifacts := []preparedOrdinaryArtifact{runnerReservationArtifact("example.org/unit/first", 8192), runnerReservationArtifact("example.org/unit/second", 1)}
	for index := range artifacts {
		artifacts[index].unit = true
	}
	planned, err := preparedOrdinaryCommands(artifacts, "", 1)
	if err != nil || len(planned) != 2 || planned[0].processes != 1 || planned[1].processes != 1 {
		t.Fatal("compatible roots multiplied package process ownership", planned, err)
	}
	diagnostics := &checkDiagnostics{}
	if err := diagnostics.reserveOrdinaryCommands(planned); err != nil || diagnostics.commandLimit() != 4 {
		t.Fatal("two package processes lost their test and conversion capacity", diagnostics.commandLimit(), err)
	}
}

// full_only: false
func TestUnitProcessTimeoutPolicyUsesSelectedCompleteGroup(t *testing.T) {
	normal, full := false, true
	for _, row := range []struct {
		name, pkg       string
		selected        []string
		classifications []testClassification
		helpers         map[string]string
		unit            bool
		wantGroup       ordinaryProcessGroup
		wantMaximum     time.Duration
		wantError       bool
	}{
		{name: "ordinary-with-unselected-full-only", pkg: "example.org/unit", selected: []string{"TestOrdinary"}, classifications: []testClassification{{Name: "TestOrdinary", FullOnly: &normal}, {Name: "TestUnselected", FullOnly: &full}}, unit: true, wantGroup: ordinaryProcessGroup{tests: []string{"TestOrdinary"}}, wantMaximum: 10 * time.Minute},
		{name: "selected-full-only", pkg: "example.org/unit", selected: []string{"TestFull"}, classifications: []testClassification{{Name: "TestFull", FullOnly: &full}}, unit: true, wantGroup: ordinaryProcessGroup{tests: []string{"TestFull"}, fullOnly: true}, wantMaximum: 30 * time.Minute},
		{name: "full-only-helper-keeps-complete-group", pkg: "example.org/unit", selected: []string{"TestHelper", "TestParent"}, classifications: []testClassification{{Name: "TestHelper", FullOnly: &full}, {Name: "TestParent", FullOnly: &normal}}, helpers: map[string]string{"example.org/unit\x00TestHelper": "TestParent/leaf"}, unit: true, wantGroup: ordinaryProcessGroup{tests: []string{"TestHelper", "TestParent"}, fullOnly: true}, wantMaximum: 30 * time.Minute},
		{name: "exclusive-without-full-only", pkg: modulePrefix + "core/internal/testmain", selected: []string{"TestSupervisorInstalledInvocationBoundaries"}, classifications: []testClassification{{Name: "TestSupervisorInstalledInvocationBoundaries", FullOnly: &normal}}, unit: true, wantGroup: ordinaryProcessGroup{tests: []string{"TestSupervisorInstalledInvocationBoundaries"}, big: true}, wantMaximum: 10 * time.Minute},
		{name: "runner-full-only", pkg: "example.org/runner", selected: []string{"TestFull"}, classifications: []testClassification{{Name: "TestFull", FullOnly: &full}}, wantGroup: ordinaryProcessGroup{tests: []string{"TestFull"}, fullOnly: true}, wantMaximum: 15 * time.Minute},
		{name: "testless-with-unselected-full-only", pkg: "example.org/unit", classifications: []testClassification{{Name: "TestUnselected", FullOnly: &full}}, unit: true, wantGroup: ordinaryProcessGroup{}, wantMaximum: 10 * time.Minute},
		{name: "missing-selected-classification", pkg: "example.org/unit", selected: []string{"TestMissing"}, classifications: []testClassification{{Name: "TestUnselected", FullOnly: &full}}, unit: true, wantError: true},
		{name: "nil-selected-classification", pkg: "example.org/unit", selected: []string{"TestMissing"}, classifications: []testClassification{{Name: "TestMissing"}}, unit: true, wantError: true},
		{name: "duplicate-selected-classification", pkg: "example.org/unit", selected: []string{"TestDuplicate"}, classifications: []testClassification{{Name: "TestDuplicate", FullOnly: &normal}, {Name: "TestDuplicate", FullOnly: &full}}, unit: true, wantError: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			artifact := ordinaryArtifact{Package: row.pkg, Tests: row.selected, Classifications: row.classifications}
			groups, err := ordinaryProcessGroups(artifact, row.helpers)
			if row.wantError {
				if err == nil || len(groups) != 0 {
					t.Fatal("invalid classification acquired a process budget", groups, err)
				}
				return
			}
			if err != nil || len(groups) != 1 || !reflect.DeepEqual(groups[0], row.wantGroup) {
				t.Fatal("timeout policy changed the exact complete group or scheduling class", groups, err, row.wantGroup)
			}
			maximum := ordinaryProcessMaximum(row.unit, groups[0])
			if maximum != row.wantMaximum {
				t.Fatal("selected group acquired the wrong physical timeout", maximum, row.wantMaximum)
			}
			for _, flag := range []struct {
				name string
				args []string
				want time.Duration
			}{
				{name: "default", want: row.wantMaximum},
				{name: "shorter", args: []string{"-timeout=1m"}, want: time.Minute},
				{name: "last-shorter", args: []string{"-timeout=" + row.wantMaximum.String(), "-timeout=1m"}, want: time.Minute},
				{name: "exact-boundary", args: []string{"-timeout=" + row.wantMaximum.String()}, want: row.wantMaximum},
				{name: "first-excess", args: []string{"-timeout=" + (row.wantMaximum + time.Nanosecond).String()}},
				{name: "zero", args: []string{"-timeout=0"}},
				{name: "negative", args: []string{"-timeout=-1ns"}},
				{name: "malformed", args: []string{"-timeout=invalid"}},
			} {
				t.Run(flag.name, func(t *testing.T) {
					got, err := ordinaryProcessTimeout(flag.args, maximum)
					if flag.want == 0 {
						if err == nil || got != 0 {
							t.Fatal("invalid explicit timeout was admitted", got, err)
						}
					} else if err != nil || got != flag.want {
						t.Fatal("explicit timeout changed its selected group bound", got, err, flag.want)
					}
				})
			}
		})
	}
	if unitGroupAllowance != 0 || runnerGroupAllowance != 0 {
		t.Fatal("cumulative limits are enabled by default", unitGroupAllowance, runnerGroupAllowance)
	}
}
