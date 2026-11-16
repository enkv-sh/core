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
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestNativeTestDeadlineConversionRetainsExpiredShutdownFailure(t *testing.T) {
	root := t.TempDir()
	converter := testEventConverterFixture(t, root)
	path := filepath.Join(root, "delayed-converter")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\nsleep 0.3\nexec "+shellQuote(converter.binary)+" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	const name = "TestShutdownConversion"
	var native bytes.Buffer
	owner, err := newNativeTestDeadline(t.Context(), map[string]time.Duration{name: time.Second}, 100*time.Millisecond, &native)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.cancel(context.Canceled)
	_, _ = io.WriteString(owner, "\x16=== RUN   "+name+"\n\x16--- PASS: "+name+" (0.00s)\n\x16PASS\n")
	process := owner.joined(processResult{Status: "passed", Started: true, Joined: true})
	if process.Status != "passed" || process.Cause != nil {
		t.Fatal("healthy native fixture did not join before shutdown allowance", process)
	}
	work, cancel := owner.conversionContext()
	defer cancel()
	var converted bytes.Buffer
	command := exec.Command(path, "-t", "-p", componentPackage)
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(native.Bytes()), &converted, &bytes.Buffer{}
	process = owner.converted(work, superviseTestEventConversion(work, command))
	rows, events, parseErr := parseOrdinaryEvents(converted.Bytes(), map[string][]string{componentPackage: {name}}, nil)
	if !process.Started || !process.Joined || process.Status != "timed_out" || !errors.Is(process.Cause, context.DeadlineExceeded) || owner.ctx.Err() != nil {
		t.Fatal("converter completion in cancellation tail concealed shutdown expiry", process, owner.ctx.Err())
	}
	if parseErr != nil || events != "valid" || len(rows) != 1 || rows[0].Name != name || rows[0].Outcome != "pass" {
		t.Fatal("expired shutdown discarded positively joined conversion rows", rows, events, parseErr)
	}
}

// full_only: false
func TestPreparedOrdinaryPreservesRaceExitAfterShortTestTimeout(t *testing.T) {
	root := raceFixtureRoot(t)
	goroot, err := runGo(t.Context(), root, ".", "env", "GOROOT")
	goRoot := strings.TrimSpace(string(goroot))
	if err != nil || goRoot == "" {
		t.Fatal("fixture Go root unavailable", err)
	}
	binary := filepath.Join(t.TempDir(), "race-exit.test")
	if _, err := runGo(withRacePolicy(t.Context(), true), root, ".", "test", "-mod=readonly", "-race", "-c", "-o", binary, "."); err != nil {
		t.Fatal("compile race-exit control", err)
	}
	compiledRace, err := binaryRace(binary)
	if err != nil || !compiledRace {
		t.Fatal("race-exit control lacks actual race instrumentation", compiledRace, err)
	}
	const test = "TestRaceFree"
	const pkg = "example.test/racefixture"
	artifact := preparedOrdinaryArtifact{
		ordinaryArtifact: ordinaryArtifact{Package: pkg, Tests: []string{test}, TestFlags: []string{"-timeout=100ms"}},
		binary:           binary, converter: testEventConverterFixture(t, root), cwd: filepath.Dir(binary), selection: literalTestSelection(test),
	}
	setPreparedOrdinaryFixtureMetadata(t, &artifact)
	ctx, cancel := context.WithTimeout(withRacePolicy(t.Context(), true), 5*time.Second)
	defer cancel()
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	err = executePreparedOrdinary(ctx, root, artifact, goRoot, map[string][]string{pkg: {test}}, &evidence)
	if err != nil {
		t.Errorf("outer deadline killed an immediately passing test during required race exit wait: %v", err)
	}
	if len(evidence.Tests) != 1 || evidence.Tests[0].Name != test || evidence.Tests[0].Outcome != "pass" {
		t.Error("short-timeout control did not retain the actual immediate pass", evidence.Tests)
	}
	tests, conversions := 0, 0
	for _, command := range evidence.Diagnostics.Commands {
		switch command.Phase {
		case "test":
			tests++
			if !command.Started || !command.Joined || command.Process != "passed" || command.Events != "valid" {
				t.Error("race exit wait was cut short despite a passing test terminal", command)
			}
		case "conversion":
			conversions++
			if !command.Started || !command.Joined || command.Process != "passed" || command.Events != "valid" {
				t.Error("joined immediate-pass output did not convert completely", command)
			}
		}
	}
	if tests != 1 || conversions != 1 {
		t.Error("short-timeout proof lacks separate binary/converter commands", tests, conversions)
	}
}

// full_only: false
func TestPreparedOrdinaryConversionUsesRemainingWorkBudget(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ENKV_COMPONENT_CHECK_HELPER", "")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepared := testEventConverterFixture(t, root)
	converterPath := filepath.Join(root, "delayed-converter")
	script := "#!/bin/sh\nset -eu\nsleep 6\nexec " + shellQuote(prepared.binary) + " \"$@\"\n"
	if err := os.WriteFile(converterPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	const name = "TestComponentCheckHelper"
	artifact := preparedOrdinaryArtifact{
		ordinaryArtifact: ordinaryArtifact{Package: componentPackage, Tests: []string{name}},
		binary:           binary, converter: boundTestEventConverterFixture(t, converterPath), cwd: root, selection: literalTestSelection(name),
	}
	setPreparedOrdinaryFixtureMetadata(t, &artifact)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	if err := executePreparedOrdinary(ctx, root, artifact, "", map[string][]string{componentPackage: {name}}, &evidence); err != nil {
		t.Error("healthy ordinary conversion within the active work budget failed", err)
	}
	if len(evidence.Tests) != 1 || evidence.Tests[0].Name != name || evidence.Tests[0].Outcome != "pass" {
		t.Error("healthy ordinary conversion lost the exact actual test terminal", evidence.Tests)
	}
	checkRecordedCommand(t, evidence, "test", "passed", "valid")
	checkRecordedCommand(t, evidence, "conversion", "passed", "valid")
	if len(evidence.Diagnostics.Commands) != 2 {
		t.Fatal("healthy ordinary conversion did not retain exactly one test and converter", evidence.Diagnostics.Commands)
	}
	conversion := evidence.Diagnostics.Commands[1]
	if conversion.WallSeconds == nil || *conversion.WallSeconds < 6 {
		t.Error("ordinary converter did not complete the controlled six-second work", conversion)
	}
}

// full_only: false
func TestPreparedOrdinaryCancellationDuringConversionKeepsJoinedRows(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ENKV_COMPONENT_CHECK_HELPER", "")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepared := testEventConverterFixture(t, root)
	entered, release := filepath.Join(root, "converter-entered"), filepath.Join(root, "converter-release")
	converterPath := filepath.Join(root, "controlled-converter")
	script := "#!/bin/sh\nset -eu\nprintf entered > " + shellQuote(entered) + "\nwhile [ ! -f " + shellQuote(release) + " ]; do sleep 0.01; done\nexec " + shellQuote(prepared.binary) + " \"$@\"\n"
	if err := os.WriteFile(converterPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	const name = "TestComponentCheckHelper"
	artifact := preparedOrdinaryArtifact{
		ordinaryArtifact: ordinaryArtifact{Package: componentPackage, Tests: []string{name}},
		binary:           binary, converter: boundTestEventConverterFixture(t, converterPath), cwd: root, selection: literalTestSelection(name),
	}
	setPreparedOrdinaryFixtureMetadata(t, &artifact)
	deadline, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(deadline)
	defer cancel()
	watcher := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := os.Stat(entered); err == nil {
				cancel()
				watcher <- os.WriteFile(release, []byte("release after cancellation"), 0600)
				return
			} else if !errors.Is(err, os.ErrNotExist) {
				watcher <- err
				return
			}
			select {
			case <-deadline.Done():
				watcher <- deadline.Err()
				return
			case <-ticker.C:
			}
		}
	}()
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	runErr := executePreparedOrdinary(ctx, root, artifact, "", map[string][]string{componentPackage: {name}}, &evidence)
	if err := <-watcher; err != nil {
		t.Fatal("converter did not reach the controlled cancellation boundary", err)
	}
	if !errors.Is(runErr, context.Canceled) || !errors.Is(ctx.Err(), context.Canceled) {
		t.Error("successful conversion replaced known work cancellation", runErr, ctx.Err())
	}
	if len(evidence.Tests) != 1 || evidence.Tests[0].Name != name || evidence.Tests[0].Outcome != "pass" {
		t.Error("canceled replay lost the exact actual passed terminal", evidence.Tests)
	}
	checkRecordedCommand(t, evidence, "test", "passed", "valid")
	checkRecordedCommand(t, evidence, "conversion", "passed", "valid")
	if len(evidence.Diagnostics.Commands) != 2 {
		t.Error("canceled replay did not retain exactly one joined test and converter", evidence.Diagnostics.Commands)
	}
}

type ordinaryReviewEnvironmentWriter struct {
	output bytes.Buffer
	change func()
	before string
	done   bool
	skip   int
}

func (writer *ordinaryReviewEnvironmentWriter) Write(body []byte) (int, error) {
	if !writer.done && strings.HasPrefix(string(body), writer.before) {
		if writer.skip > 0 {
			writer.skip--
		} else {
			writer.done = true
			writer.change()
		}
	}
	return writer.output.Write(body)
}

// full_only: false
func TestPreparedOrdinaryGroupKeepsBuildAfterSourceEdits(t *testing.T) {
	for _, row := range []struct{ name, key, first, second string }{{"source-after-step-precheck", "", "", ""}, {"source-after-test-progress", "", "", ""}} {
		t.Run(row.name, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", ordinaryRepetitionWitnessSource)
			initializeWorkflowExecutionFixture(t, root)
			observations := t.TempDir()
			witness := filepath.Join(observations, "executions.jsonl")
			t.Setenv("ENKV_ORDINARY_REPETITION_WITNESS", witness)
			t.Setenv("ENKV_ORDINARY_REPETITION_FAIL_SECOND", "0")
			if row.key != "" {
				t.Setenv(row.key, row.first)
			}
			path := filepath.Join(observations, "workflow.json")
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "native-reuse", "execution": map[string]any{"parallel": 1}, "steps": []any{
				map[string]any{"id": "focused", "kind": "unit", "packages": []string{"telemetry/witness"}, "package": "telemetry/witness", "tests": []string{"TestRepetitionProcessWitness/leaf[a]+b"}, "repetitions": 3},
			}})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			if err != nil || len(plan.Steps) != 3 {
				t.Fatal("real prepared selection unavailable", err)
			}
			writer := &ordinaryReviewEnvironmentWriter{
				before: fmt.Sprintf("Step %s (%s)\n", plan.Steps[1].ID, plan.Steps[1].Kind),
				change: func() {
					if row.key != "" {
						t.Setenv(row.key, row.second)
						return
					}
					// Change the source after the first completed execution.
					source := filepath.Join(root, "telemetry/witness/witness_test.go")
					if err := os.WriteFile(source, []byte(ordinaryRepetitionWitnessSource+"\n// source changed after the step precheck\n"), 0600); err != nil {
						t.Fatal(err)
					}
				},
			}
			if row.name == "source-after-test-progress" {
				writer.before = "Check phase=test scope=" + modulePrefix + "telemetry/witness\n"
				writer.skip = 1
			}
			result, runErr := runWorkflow(ctx, root, "", plan, writer)
			if !writer.done {
				t.Fatal("first execution did not reach the next public step boundary", runErr)
			}
			if runErr != nil {
				t.Error("source edit stopped the prepared execution", runErr)
			}
			body, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal("actual execution observations unavailable", err)
			}
			actual, err := decodeObjects[ordinaryRepetitionObservation](body)
			if err != nil || len(actual) != 3 {
				t.Fatal("source edit lost a requested repetition", len(actual), err)
			}
			for _, observation := range actual {
				if !observation.ChildEntered || !observation.ParentSuffix {
					t.Error("source edit lost the exact selected child or parent suffix", observation)
				}
			}
			if result.Outcome != "passed" || len(result.Steps) != 3 {
				t.Fatal("source edit changed the workflow result", result.Outcome, result.Steps)
			}
			for _, step := range result.Steps {
				if step.Outcome != "passed" {
					t.Error("source edit stopped a selected execution", step)
				}
			}
			if !strings.Contains(writer.output.String(), "Source changed during execution") {
				t.Error("source edit has no informational observation")
			}
			if len(result.RepetitionGroups) != 1 || result.RepetitionGroups[0].CompletedExecutions != 3 || result.RepetitionGroups[0].Outcome != "passed" {
				t.Error("source edit lost the complete repetition result", result.RepetitionGroups)
			}

		})
	}
}
