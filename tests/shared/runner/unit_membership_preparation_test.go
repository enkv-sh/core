package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func preparedUnitMembershipFixture(t *testing.T, selector string, focused bool, repetitions int) (context.Context, string, string, string, *preparedWorkflow) {
	t.Helper()
	ctx, root, bootstrap, marker, path, _ := completePreparationFixture(t, "")
	ctx = withRacePolicy(ctx, false)
	step := map[string]any{"id": "unit", "kind": "unit", "packages": []string{selector}}
	if focused {
		step["package"], step["tests"] = "telemetry/witness", []string{"TestNormal"}
	}
	if repetitions > 1 {
		step["repetitions"] = repetitions
	}
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "unit-membership", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{step}})
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
	if prepared != nil {
		t.Cleanup(func() {
			finish, cancel := finalizationContext(ctx)
			defer cancel()
			if err := prepared.close(finish); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil || prepared == nil || prepared.admission().Big || prepared.admission().Live || len(prepared.ordinary) != 1 {
		t.Fatal("small ordinary unit preparation failed", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unit preparation executed a test body", err)
	}
	return ctx, root, bootstrap, marker, prepared
}

func addIndependentUnitPackage(t *testing.T, root string) {
	t.Helper()
	writeLocalGoFixture(t, root, "telemetry/added/added_test.go", `package added
import "testing"
// full_only: false
func TestAdded(t *testing.T) { t.Fatal("new selected package must not escape preparation") }
`)
}

func checkUnitMembershipPass(t *testing.T, marker string, evidence *ordinaryStepEvidence, focused bool) {
	t.Helper()
	if evidence == nil || evidence.Diagnostics == nil || evidence.Diagnostics.Preparation != "passed" || len(evidence.Packages) != 1 || evidence.Packages[0].Name != modulePrefix+"telemetry/witness" || !slices.Equal(evidence.Packages[0].Tests, []string{"TestNormal"}) || len(evidence.Tests) != 1 || evidence.Tests[0].Package != modulePrefix+"telemetry/witness" || evidence.Tests[0].Name != "TestNormal" || evidence.Tests[0].Outcome != "pass" || evidence.Race == nil || *evidence.Race || evidence.SelectedComplete != focused || evidence.Complete == focused {
		t.Fatal("unit membership control lost its exact selection or terminal", evidence)
	}
	tests, conversions := 0, 0
	for _, fact := range evidence.Diagnostics.Commands {
		if !fact.Started || !fact.Joined || fact.Process != "passed" {
			t.Fatal("unit membership control lost positive joins", fact)
		}
		switch fact.Phase {
		case "test":
			tests++
		case "conversion":
			conversions++
		}
	}
	if tests != 1 || conversions != 1 {
		t.Fatal("unit membership control lost one physical execution and conversion", tests, conversions)
	}
	body, err := os.ReadFile(marker)
	if err != nil || string(body) != "1" {
		t.Fatal("unit membership control did not run its body with the assigned share", string(body), err)
	}
}

// full_only: false
func TestPreparedUnitMembershipKeepsSelectionAfterMachineWait(t *testing.T) {
	for _, row := range []struct {
		name, selector, mutation string
		focused                  bool
	}{
		{"wildcard-added", "telemetry", "add", false},
		{"wildcard-unchanged", "telemetry", "", false},
		{"literal-unrelated-added", "telemetry/witness", "add", false},
		{"focus-unrelated-added", "telemetry/witness", "add", true},
		{"wildcard-removed", "telemetry", "remove", false},
		{"wildcard-resolution-failed", "telemetry", "invalid", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, root, bootstrap, marker, prepared := preparedUnitMembershipFixture(t, row.selector, row.focused, 1)
			locks, err := resourceLocksFromContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			held, err := locks.acquireMachine(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			wait, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			ready := make(chan struct{})
			type execution struct {
				result   workflowResult
				ordinary *ordinaryStepEvidence
				err      error
			}
			joined := make(chan execution, 1)
			admissions := 0
			var acquired *resourceLease
			wait = context.WithValue(wait, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, request rootAdmission) (context.Context, error) {
				admissions++
				if request.Big || request.Live || request.Execution.Resolved.Parallel != 1 {
					return ctx, errors.New("ordinary unit admission policy changed")
				}
				if admissions == 1 {
					close(ready)
					var err error
					acquired, err = locks.acquireMachine(ctx, request.Big)
					return withExecutionCapacity(ctx, request.Execution), err
				}
				if acquired == nil {
					return ctx, errors.New("ordinary unit lost its admitted machine lease")
				}
				return withExecutionCapacity(ctx, request.Execution), nil
			}))
			go func() {
				admitted, err := admitPreparedExecution(wait, prepared.admission())
				var result workflowResult
				var ordinary *ordinaryStepEvidence
				if err == nil {
					result, err = runPreparedWorkflow(admitted, root, bootstrap, prepared, io.Discard)
				}
				if acquired != nil {
					err = errors.Join(err, acquired.Close())
				}
				joined <- execution{result, ordinary, err}
			}()
			collected := false
			defer func() {
				cancel()
				held.Close()
				if !collected {
					<-joined
				}
			}()
			select {
			case <-ready:
			case actual := <-joined:
				collected = true
				t.Fatal("prepared unit did not reach machine wait", actual.err)
			case <-wait.Done():
				t.Fatal(wait.Err())
			}
			select {
			case actual := <-joined:
				collected = true
				t.Fatal("prepared unit passed the held machine lock", actual.err)
			default:
			}
			switch row.mutation {
			case "add":
				addIndependentUnitPackage(t, root)
			case "remove":
				if err := os.Remove(filepath.Join(root, "telemetry/witness/witness_test.go")); err != nil {
					t.Fatal(err)
				}
			case "invalid":
				writeLocalGoFixture(t, root, "telemetry/added/added_test.go", "package added\n")
				writeLocalGoFixture(t, root, "telemetry/added/conflict_test.go", "package conflicting\n")
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case actual := <-joined:
				collected = true
				if admissions <= 1 || wait.Err() != nil || !toolCommandsJoined(actual.err) || !sourceCommandsJoined(actual.err) {
					t.Fatal("unit membership did not finish with positive joins", actual.err, admissions)
				}

				if actual.err != nil || actual.result.Outcome != "passed" {
					t.Fatal("unit membership control did not pass", actual.err, actual.result.Outcome)
				}
				checkUnitMembershipPass(t, marker, actual.result.executions["unit"].Ordinary, row.focused)
			case <-wait.Done():
				t.Fatal("prepared unit did not join", wait.Err())
			}
		})
	}
}

// full_only: false
func TestPreparedUnitMembershipKeepsSelectionAcrossExecutionBoundaries(t *testing.T) {
	for _, boundary := range []string{"after-group-verification", "after-first-execution", "held-repetition-barrier"} {
		t.Run(boundary, func(t *testing.T) {
			repetitions := 1
			if boundary == "after-first-execution" {
				repetitions = 2
			}
			ctx, root, bootstrap, marker, prepared := preparedUnitMembershipFixture(t, "telemetry", false, repetitions)
			group := prepared.ordinary["unit"]
			var runErr error
			if boundary == "after-first-execution" {
				if len(prepared.plan.Steps) != 2 {
					t.Fatal("unit membership repetition fixture did not resolve two executions")
				}
				firstID, secondID := prepared.plan.Steps[0].ID, prepared.plan.Steps[1].ID
				firstMarker := marker + ".first"
				output := &ordinaryReviewEnvironmentWriter{
					before: fmt.Sprintf("Step %s (unit)\n", secondID),
					change: func() {
						if ctx.Err() != nil || group.closed || group.ctx.Err() != nil {
							t.Fatal("second scalar did not retain its active prepared owner", group.ctx.Err())
						}
						if err := os.Rename(marker, firstMarker); err != nil {
							t.Fatal("first scalar did not leave its body witness", err)
						}
						addIndependentUnitPackage(t, root)
					},
				}
				result, err := runPreparedWorkflow(ctx, root, bootstrap, prepared, output)
				if !output.done || err != nil || ctx.Err() != nil || !toolCommandsJoined(err) || !sourceCommandsJoined(err) || result.Outcome != "passed" || len(result.Steps) != 2 || result.Steps[0].ID != firstID || result.Steps[0].Outcome != "passed" || result.Steps[1].ID != secondID || result.Steps[1].Outcome != "passed" {
					t.Fatal("captured unit selection did not complete both repetitions", err, result.Steps, output.done)
				}
				checkUnitMembershipPass(t, firstMarker, result.executions[firstID].Ordinary, false)
				if len(result.RepetitionGroups) != 1 {
					t.Fatal("unit membership refusal lost its repetition group", result.RepetitionGroups)
				}
				repetition := result.RepetitionGroups[0]
				if repetition.RequestedExecutions != 2 || repetition.CompletedExecutions != 2 || repetition.Outcome != "passed" || !slices.Equal(repetition.StepIDs, []string{firstID, secondID}) {
					t.Fatal("unit membership refusal changed its exact execution count", repetition)
				}
				refusal := result.executions[secondID]
				if refusal.Ordinary == nil || refusal.Ordinary.Diagnostics == nil || refusal.Ordinary.Diagnostics.Preparation != "passed" || len(refusal.Ordinary.Tests) != 1 || group.preparation.Preparation != "passed" {
					t.Fatal("second unit scalar lost local failed preparation or mutated frozen preparation", refusal.Ordinary, group.preparation)
				}
				checkUnitMembershipPass(t, marker, refusal.Ordinary, false)
				runErr = refusal.Err
			} else if boundary == "held-repetition-barrier" {
				ctx = useLocalPreparationPhase(prepared.binding.context(ctx), prepared.phase)
				artifact := group.artifacts[0]
				leave, err := artifact.barrier.enter(ctx, true)
				if err != nil {
					t.Fatal(err)
				}
				ready, joined := make(chan struct{}, 1), make(chan error, 1)
				released, collected := false, false
				defer func() {
					if !released {
						leave(true)
					}
					if !collected {
						<-joined
					}
				}()
				evidence := &ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
				go func() {
					child := unitMembershipBarrierContext{Context: ctx, ready: ready}
					joined <- executePreparedOrdinary(child, root, artifact, group.goenv["GOROOT"], map[string][]string{artifact.Package: artifact.Tests}, evidence)
				}()
				select {
				case <-ready:
				case runErr = <-joined:
					collected = true
					t.Fatal("compiled unit did not reach its held repetition barrier", runErr)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				addIndependentUnitPackage(t, root)
				leave(true)
				released = true
				select {
				case runErr = <-joined:
					collected = true
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if evidence.Diagnostics.Preparation != "passed" || len(evidence.Tests) != 1 {
					t.Fatal("binary owner did not retain selection during barrier edit", runErr, evidence)
				}
			} else {
				ctx = useLocalPreparationPhase(prepared.binding.context(ctx), prepared.phase)
				if err := group.verify(ctx, root, "dev"); err != nil {
					t.Fatal(err)
				}
				output := &ordinaryReviewEnvironmentWriter{before: "Check phase=test ", change: func() { addIndependentUnitPackage(t, root) }}
				evidence := &ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
				runErr = group.executeArtifacts(ctx, root, group.artifacts, evidence, output)
				if !output.done || evidence.Diagnostics.Preparation != "passed" || len(evidence.Tests) != 1 {
					t.Fatal("artifact boundary did not retain captured membership", runErr, output.done, evidence)
				}
			}
			if runErr != nil || !toolCommandsJoined(runErr) || !sourceCommandsJoined(runErr) {
				t.Fatal("later execution did not complete captured package selection", runErr)
			}
			if body, err := os.ReadFile(marker); err != nil || string(body) != "1" {
				t.Fatal("captured prepared unit did not execute its body", err)
			}
		})
	}
}

// Value observes the existing barrier lookup. It cannot supply a selection or result.
type unitMembershipBarrierContext struct {
	context.Context
	ready chan<- struct{}
}

func (ctx unitMembershipBarrierContext) Value(key any) any {
	if _, ok := key.(workflowTestBarrierContextKey); ok {
		select {
		case ctx.ready <- struct{}{}:
		default:
		}
	}
	return ctx.Context.Value(key)
}
