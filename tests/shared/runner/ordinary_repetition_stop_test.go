package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Cancel only after the first real execution has returned all command facts.
// Output is a normal workflow boundary; no process result is supplied here.
type cancelOrdinaryRepetitionOutput struct {
	bytes.Buffer
	cancel       context.CancelFunc
	directory    string
	fired        bool
	leasePresent bool
}

func (output *cancelOrdinaryRepetitionOutput) Write(body []byte) (int, error) {
	n, err := output.Buffer.Write(body)
	if !output.fired && bytes.HasPrefix(body, []byte("Check phase=conversion scope=")) && bytes.Contains(body, []byte("process=passed started=true joined=true")) {
		output.fired = true
		info, statErr := os.Stat(output.directory)
		output.leasePresent = statErr == nil && info.IsDir()
		output.cancel()
	}
	return n, err
}

// full_only: false
func TestOrdinaryRepetitionCancellationBetweenExecutionsClosesOwner(t *testing.T) {
	root, _, _ := overlayFixture(t)
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", ordinaryRepetitionWitnessSource)
	initializeWorkflowExecutionFixture(t, root)
	observations := t.TempDir()
	witness := filepath.Join(observations, "executions.jsonl")
	t.Setenv("ENKV_ORDINARY_REPETITION_WITNESS", witness)
	t.Setenv("ENKV_ORDINARY_REPETITION_FAIL_SECOND", "0")
	path := filepath.Join(observations, "workflow.json")
	saveSelection(t, path, map[string]any{
		"schema_version": 1, "name": "canceled-ordinary", "execution": map[string]any{"parallel": 1},
		"steps": []any{map[string]any{
			"id": "focused", "kind": "unit", "packages": []string{"telemetry/witness"},
			"package": "telemetry/witness", "tests": []string{"TestRepetitionProcessWitness/leaf[a]+b"}, "repetitions": 3,
		}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil || len(plan.Steps) != 3 {
		t.Fatal("actual repetition selection unavailable", err)
	}
	directory := filepath.Join(root, "core/internal/testmain")
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("fixture already owns the temporary tool directory", err)
	}
	output := &cancelOrdinaryRepetitionOutput{cancel: cancel, directory: directory}
	result, runErr := runWorkflow(ctx, root, "", plan, output)
	if runErr == nil || !output.fired || !output.leasePresent {
		t.Fatal("cancellation did not occur after an actual execution with its active tool owner", runErr, output.String())
	}
	body, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal("the first real execution did not produce its observation", err, output.String())
	}
	rows, err := decodeObjects[ordinaryRepetitionObservation](body)
	if err != nil || len(rows) != 1 || !rows[0].ChildEntered || !rows[0].ParentSuffix {
		t.Fatal("cancellation did not preserve exactly one completed execution", rows, err)
	}
	if result.Outcome != "failed" || result.FinishedAt == nil || len(result.Steps) != 3 {
		t.Fatal("canceled workflow lost terminal outcome", result)
	}
	if result.Steps[0].Outcome != "passed" {
		t.Fatal("the first completed execution was changed by later cancellation", result.Steps[0])
	}
	for _, step := range result.Steps[1:] {
		if step.Outcome != "not_run" || step.StartedAt != nil || result.executions[step.ID].Ordinary != nil {
			t.Error("canceled workflow started a later execution", step)
		}
	}
	evidence := result.executions[result.Steps[0].ID].Ordinary
	if evidence == nil || !evidence.SelectedComplete || evidence.Diagnostics == nil {
		t.Fatal("completed current execution result unavailable")
	}
	for _, command := range evidence.Diagnostics.Commands {
		if !command.Started || !command.Joined || command.Process != "passed" {
			t.Fatal("first execution lacks actual positive command joins", command)
		}
	}
	if len(result.RepetitionGroups) != 1 {
		t.Fatal("canceled group summary unavailable", result.RepetitionGroups)
	}
	group := result.RepetitionGroups[0]
	if group.RequestedExecutions != 3 || group.CompletedExecutions != 1 || group.Outcome != "failed" || !slices.Equal(group.StepIDs, []string{result.Steps[0].ID}) {
		t.Error("finished canceled workflow left an active or miscounted repetition group", group)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Error("joined repetition tool directory lease was not closed between callbacks", err)
	}
}

// full_only: false
func TestOrdinaryRepetitionTestlessFailurePreservesEarlierTiming(t *testing.T) {
	root, _, _ := overlayFixture(t)
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", ordinaryRepetitionWitnessSource)
	// Use an already admitted testless command; no inventory exception is added.
	const commandOwner = "plugins/output-contract-test/cmd/enkv-output-contract-test"
	commandImport := modulePath("plugins/output-contract-test") + "/cmd/enkv-output-contract-test"
	writeLocalGoFixture(t, root, "plugins/output-contract-test/go.mod", "module "+"enkv.sh/tests/fixtures/output-contract-test\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, commandOwner+"/main.go", "package main\nfunc main() {}\n")
	initializeWorkflowExecutionFixture(t, root)
	observations := t.TempDir()
	witness := filepath.Join(observations, "executions.jsonl")
	t.Setenv("ENKV_ORDINARY_REPETITION_WITNESS", witness)
	t.Setenv("ENKV_ORDINARY_REPETITION_FAIL_SECOND", "0")
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	// Preparation and the first binary are real. Only the later testless Go
	// command fails, after the binary has produced its own observation.
	command := "#!/bin/sh\nif [ \"$1\" = test ] && [ -s \"$ENKV_ORDINARY_REPETITION_WITNESS\" ]; then\n for argument in \"$@\"; do\n  if [ \"$argument\" = '" + commandImport + "' ]; then\n   printf 'controlled testless command failure\\n' >&2\n   exit 1\n  fi\n done\nfi\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(command), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	path := filepath.Join(observations, "workflow.json")
	saveSelection(t, path, map[string]any{
		"schema_version": 1, "name": "testless-ordinary", "execution": map[string]any{"parallel": 1},
		"steps": []any{map[string]any{
			"id": "mixed", "kind": "unit", "packages": []string{"telemetry/witness", commandOwner}, "repetitions": 3,
		}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil || len(plan.Steps) != 3 {
		t.Fatal("actual mixed repetition selection unavailable", err)
	}
	var output bytes.Buffer
	result, runErr := runWorkflow(ctx, root, "", plan, &output)
	if runErr == nil {
		t.Fatal("controlled testless command failure passed")
	}
	body, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal("the real binary did not run before the testless failure", err, output.String())
	}
	rows, err := decodeObjects[ordinaryRepetitionObservation](body)
	if err != nil || len(rows) != 1 || !rows[0].ChildEntered || !rows[0].ParentSuffix {
		t.Fatal("failure did not preserve exactly one actual binary execution", rows, err)
	}
	if result.Outcome != "failed" || len(result.Steps) != 3 || result.Steps[0].Outcome != "failed" {
		t.Fatal("testless failure lost its workflow outcome", result)
	}
	evidence := result.executions[result.Steps[0].ID].Ordinary
	if evidence == nil || evidence.Diagnostics == nil || evidence.Diagnostics.Preparation != "passed" || len(evidence.Tests) != 2 {
		t.Fatal("earlier real binary results unavailable", evidence)
	}
	for _, terminal := range evidence.Tests {
		if terminal.Outcome != "pass" || terminal.StartedAt == nil || terminal.FinishedAt == nil {
			t.Fatal("testless failure changed earlier binary terminals", terminal)
		}
	}
	failedCommands := 0
	for _, command := range evidence.Diagnostics.Commands {
		if !command.Started || !command.Joined {
			t.Fatal("controlled failure lost its actual process join", command)
		}
		if command.Process != "passed" {
			failedCommands++
			if command.Phase != "test" || command.Process != "process_failed" || command.Scope != "plugins/output-contract-test" {
				t.Fatal("a different command failed", command)
			}
		}
	}
	if failedCommands != 1 || evidence.Complete || evidence.SelectedComplete {
		t.Fatal("failed mixed execution gained completion or lost its failed command", failedCommands, evidence.Complete, evidence.SelectedComplete)
	}
	for _, step := range result.Steps[1:] {
		if step.Outcome != "not_run" || step.StartedAt != nil {
			t.Error("testless failure did not stop subsequent executions", step)
		}
	}
	if evidence.EventTimeSource != "post_join_test2json" {
		t.Error("later testless failure replaced the earlier binary timing source", evidence.EventTimeSource)
	}
}

// The callback supplies declared scalar command facts. No OS process is made
// unjoined here, and these facts do not claim a measured process start or join.
// Native join and uncertain-owner controls remain separate qualified evidence.
// full_only: false
func TestOrdinaryRepetitionSuppliedMissingJoinStopsAndRetainsOwner(t *testing.T) {
	root := assemblyGroupExecutionRoot(t)
	steps := expandWorkflowRepetitions(resolvedWorkflowStep{ID: "controlled", Kind: "runner-tests", Selected: true}, 3)
	steps = append(steps, resolvedWorkflowStep{ID: "later", Kind: "runner-tests", Selected: true})
	plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "controlled-missing-join", Profile: "dev", Steps: steps}
	plan.Execution.Resolved.Parallel = 1
	negativeCause := errors.New("controlled supplied negative join proof")
	var output bytes.Buffer
	var calls []string
	var owned []privateDirectory
	var private privateDirectory
	var first *ordinaryStepEvidence
	var firstBytes []byte
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	result, runErr := executeWorkflow(ctx, root, plan, &output, &owned, nil,
		func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, directory string) (workflowStepExecution, error) {
			calls = append(calls, step.ID)
			if len(calls) > 2 || step.ID != steps[len(calls)-1].ID {
				t.Fatal("negative join started a third or later callback", calls)
			}
			if len(calls) == 1 {
				id := strings.Repeat("a", 32)
				ownerRun := filepath.Join(directory, "controlled-owner")
				if err := os.Mkdir(ownerRun, 0700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.RemoveAll(directory); err != nil {
						t.Error("remove controlled scratch after supplied missing-join observation", err)
					}
				})
				var err error
				private, err = createPrivateDirectory("", "hermetic", id, ownerRun)
				if err != nil {
					t.Fatal(err)
				}
				owned = append(owned, private)
				if err := os.WriteFile(filepath.Join(private.path, "shared-build"), []byte("controlled shared preparation"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := private.verify(); err != nil {
				t.Fatal("second callback lost the original private owner", err)
			}
			// Both rows are supplied fixtures at the existing callback seam.
			// The second explicitly withholds positive join evidence.
			command := checkCommandFacts{Phase: "test", Scope: "controlled-callback", Process: "passed", Started: true, Joined: true,
				Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"}
			evidence := ordinaryStepEvidence{Profile: "dev", Race: raceSetting(plan.Race), RaceOptions: acceptedRaceOptions(plan.Race), Complete: len(calls) == 1,
				Packages:    []ordinaryPackage{{Name: "example.org/supplied", Tests: []string{"TestSupplied"}, Inventory: []string{"TestSupplied"}, Classifications: componentFixtureClassifications([]string{"TestSupplied"})}},
				Tests:       []ordinaryTest{{Package: "example.org/supplied", Name: "TestSupplied", Outcome: "pass"}},
				Diagnostics: &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{command}}}
			var stepErr error
			if len(calls) == 2 {
				evidence.Diagnostics.Commands[0].Process = "process_failed"
				evidence.Diagnostics.Commands[0].Joined = false
				evidence.Diagnostics.Commands[0].Events = "unavailable"
				evidence.Diagnostics.Commands[0].RaceObservation = "unavailable"
				stepErr = negativeCause
			}
			if len(calls) == 1 {
				first = &evidence
				var err error
				firstBytes, err = json.Marshal(first)
				if err != nil {
					t.Fatal(err)
				}
			}
			return workflowStepExecution{Ordinary: &evidence}, stepErr
		})
	if runErr == nil || !errors.Is(runErr, negativeCause) || !slices.Equal(calls, []string{steps[0].ID, steps[1].ID}) {
		t.Fatal("supplied negative join lost its cause or failed to stop at two callbacks", calls, runErr)
	}
	if result.Outcome != "failed" || result.Failure != "step_failed" || result.FinishedAt == nil || len(result.Steps) != 4 {
		t.Fatal("negative join did not return a failed terminal workflow", result)
	}
	second := result.executions[result.Steps[1].ID].Ordinary
	if result.Steps[0].Outcome != "passed" || result.Steps[1].Outcome != "failed" || result.executions[result.Steps[0].ID].Ordinary != first || first == nil || second == nil || first == second {
		t.Fatal("two attempted callbacks lost independent current outcomes", result.Steps[:2])
	}
	for _, step := range result.Steps[2:] {
		if step.Outcome != "not_run" || step.StartedAt != nil || step.FinishedAt != nil || result.executions[step.ID].Ordinary != nil {
			t.Error("supplied negative join started or invented later work", step)
		}
	}
	if len(result.RepetitionGroups) != 1 {
		t.Fatal("controlled repetition group unavailable", result.RepetitionGroups)
	}
	group := result.RepetitionGroups[0]
	if group.ConfiguredStep != "controlled" || group.RequestedExecutions != 3 || group.CompletedExecutions != 1 || group.Outcome != "failed" || !slices.Equal(group.StepIDs, calls) {
		t.Error("negative join changed requested N, completed K or attempted references", group)
	}
	if second.Diagnostics == nil || len(second.Diagnostics.Commands) != 1 || second.Complete || second.SelectedComplete {
		t.Fatal("supplied incomplete command evidence unavailable", second)
	}
	command := second.Diagnostics.Commands[0]
	if command.Phase != "test" || !command.Started || command.Joined || command.Process != "process_failed" || command.Events != "unavailable" {
		t.Error("supplied negative join fact was upgraded or lost", command)
	}
	afterFirst, err := json.Marshal(result.executions[result.Steps[0].ID].Ordinary)
	if err != nil || !bytes.Equal(firstBytes, afterFirst) {
		t.Error("second callback changed the first successful current result", err)
	}
	if private.verify() != nil {
		t.Error("failed workflow lost the original private owner")
	}
	if body, err := os.ReadFile(filepath.Join(private.path, "shared-build")); err != nil || string(body) != "controlled shared preparation" {
		t.Error("negative join removed the controlled shared private bytes", err)
	}
}
