package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func runnerReservationArtifact(pkg string, count int) preparedOrdinaryArtifact {
	artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Directory: "core", Package: pkg}, binary: "fixture.test"}
	for i := range count {
		name := fmt.Sprintf("TestRoot%04d", i)
		artifact.Tests = append(artifact.Tests, name)
		artifact.Classifications = append(artifact.Classifications, testClassification{Name: name, FullOnly: new(bool)})
	}
	if count == 0 {
		artifact.binary = ""
	}
	return artifact
}

// full_only: false
func TestRunnerCommandReservationIncludesQueuesLauncherAndTestless(t *testing.T) {
	const pkg = modulePrefix + "core/internal/testrecords"
	for _, count := range []int{160, 8190, 8191} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			artifacts := []preparedOrdinaryArtifact{
				runnerReservationArtifact(pkg, count),
				runnerReservationArtifact("command-line-arguments", 1),
				runnerReservationArtifact(modulePrefix+"core/internal/empty", 0),
			}
			planned, err := preparedRunnerCommands(artifacts, 4)
			if err != nil {
				t.Fatal("runner command plan unavailable", err)
			}
			queues := map[string]int{}
			processes, facts, launcher, testless := 0, 0, 0, 0
			for _, item := range planned {
				processes += item.processes
				facts += item.processes * item.factsPerProcess
				switch {
				case strings.HasSuffix(item.scope, "/"+pkg):
					queue := strings.TrimSuffix(item.scope, "/"+pkg)
					if queue != "balanced-1" && queue != "balanced-2" && queue != "balanced-3" && queue != "balanced-4" || item.factsPerProcess != 2 {
						t.Fatal("runner command plan lost the final queue scope", item)
					}
					queues[queue] += item.processes
				case item.scope == "command-line-arguments":
					launcher += item.processes
					if item.factsPerProcess != 2 {
						t.Fatal("compiled launcher lost its conversion", item)
					}
				case strings.HasSuffix(item.scope, "/core"):
					testless += item.processes
					if item.factsPerProcess != 1 {
						t.Fatal("testless command gained a conversion", item)
					}
				default:
					t.Fatal("runner plan contains an unexpected scope", item)
				}
			}
			if len(queues) != 4 || processes != 6 || facts != 11 || launcher != 1 || testless != 1 {
				t.Fatal("runner reservation lost a queue, launcher or testless process", queues, processes, facts, launcher, testless)
			}
			diagnostics := &checkDiagnostics{}
			err = diagnostics.reserveOrdinaryCommands(planned)
			if err != nil || diagnostics.commandLimit() != facts {
				t.Fatal("admitted package selection lost command capacity", err, diagnostics.commandLimit(), facts)
			}

		})
	}
}

// full_only: false
func TestRunnerCommandReservationKeepsRequiredLiteralPartitions(t *testing.T) {
	artifact := runnerReservationArtifact("example.org/tests", 0)
	artifact.binary = "fixture.test"
	artifact.Tests = []string{"TestA", "TestB", "TestParent"}
	artifact.Classifications = runnerIsolationClassifications(artifact.Tests)
	artifact.requests = []string{"TestA", "TestB", "TestParent/left/one", "TestParent/right/two"}
	planned, err := preparedOrdinaryCommands([]preparedOrdinaryArtifact{artifact}, "selected/", 1)
	if err != nil || len(planned) != 1 || planned[0].scope != "selected/example.org/tests" || planned[0].processes != 3 || planned[0].factsPerProcess != 2 {
		t.Fatal("literal child partitions lost their exact process/conversion capacity", planned, err)
	}
	diagnostics := &checkDiagnostics{}
	if err := diagnostics.reserveOrdinaryCommands(planned); err != nil || diagnostics.commandLimit() != 6 {
		t.Fatal("literal partition admission omitted required command facts", diagnostics.commandLimit(), err)
	}
}

// full_only: false
func TestRunnerReservedFactsSurviveWorkflowFinalization(t *testing.T) {
	// Synthetic facts exercise folding and publication shape, not native joins.
	root := sourceFixtureRoot(t)
	initializeWorkflowExecutionFixture(t, root)
	if err := os.MkdirAll(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx := withResourceLocks(t.Context(), resourceLockFixture(t))
	preparation := checkCommandFacts{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"}
	artifacts := []preparedOrdinaryArtifact{runnerReservationArtifact("example.org/runner", 160)}
	planned, err := preparedRunnerCommands(artifacts, 4)
	if err != nil || len(planned) != 4 {
		t.Fatal("runner package lost its assigned worker owners", planned, err)
	}
	for index, item := range planned {
		if item.scope != fmt.Sprintf("balanced-%d/example.org/runner", index+1) || item.processes != 1 || item.factsPerProcess != 2 {
			t.Fatal("runner fixture changed its balanced process plan", item)
		}
	}
	prepared := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{preparation}}
	if err := prepared.reserveOrdinaryCommands(planned); err != nil {
		t.Fatal(err)
	}
	plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "runner-facts", Profile: "dev", Race: true}
	plan.prepared = &preparedWorkflow{ordinary: map[string]*preparedOrdinaryGroup{"runner": {preparation: prepared, artifacts: artifacts}}, joined: true}
	for i := 1; i <= 2; i++ {
		plan.Steps = append(plan.Steps, resolvedWorkflowStep{ID: fmt.Sprintf("runner-r%d", i), ConfiguredStep: "runner", Repetition: i, Repetitions: 2, Kind: "runner-tests", Selected: true, Profile: "dev"})
	}
	plan.prepared.plan = plan
	var expected []checkCommandFacts
	for _, item := range planned {
		for _, phase := range []string{"test", "conversion"} {
			expected = append(expected, checkCommandFacts{Phase: phase, Scope: item.scope, Process: "passed", Started: true, Joined: true, Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"})
		}
	}
	frozen := slices.Clone(prepared.Commands)
	var output bytes.Buffer
	result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(_ context.Context, step resolvedWorkflowStep, writer io.Writer, _ string) (workflowStepExecution, error) {
		if step.currentPrefix == nil {
			t.Fatal("callback lost current preparation owner")
		}
		diagnostics := &checkDiagnostics{Preparation: "passed"}
		if err := diagnostics.reserveOrdinaryCommands(planned); err != nil {
			t.Fatal(err)
		}
		for _, fact := range expected {
			if err := diagnostics.append(fact); err != nil {
				t.Fatal(err)
			}
		}
		if err := writeCheckDiagnostics(writer, diagnostics); err != nil {
			t.Fatal(err)
		}
		return workflowStepExecution{Ordinary: &ordinaryStepEvidence{Diagnostics: diagnostics}}, nil
	})
	if err != nil || result.Outcome != "passed" || len(result.Steps) != 2 {
		t.Fatal("workflow finalization refused reserved runner facts", err, output.String())
	}
	for index, step := range result.Steps {
		current := result.executions[step.ID]
		execution := current.Ordinary
		if execution == nil || !reflect.DeepEqual(execution.Diagnostics.Commands, expected) {
			t.Fatal("workflow changed reserved runner body facts", step.ID)
		}
		prefix := current.Preparation
		if index == 0 {
			if prefix == nil || prefix == prepared || prefix == execution.Diagnostics || prefix.ordinaryCommandLimit != 0 || prefix.ordinaryCommandBytes != 0 || !reflect.DeepEqual(prefix.Commands, []checkCommandFacts{preparation}) {
				t.Fatal("first runner result lost separate fact-only acquisition", prefix)
			}
		} else if prefix != nil && len(prefix.Commands) != 0 {
			t.Fatal("later runner result copied acquisition", step.ID)
		}

	}

	if !reflect.DeepEqual(prepared.Commands, frozen) {
		t.Fatal("workflow finalization changed immutable acquisition")
	}
	if strings.Count(output.String(), "Check phase=preparation scope=core process=passed started=true joined=true ") != 1 || bytes.Count(output.Bytes(), []byte("Check phase=test ")) != 8 || bytes.Count(output.Bytes(), []byte("Check phase=conversion ")) != 8 || bytes.Count(output.Bytes(), []byte("Check phase=")) != 17 {
		t.Fatal("terminal omitted or repeated acquisition or body facts", output.String())
	}

}
