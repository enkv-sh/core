package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestPreparedResourceClassUsesOnlySelectedCompiledRoots(t *testing.T) {
	small, full := false, true
	rows := []testClassification{{Name: "TestSmall", FullOnly: &small}, {Name: "TestFull", FullOnly: &full}, {Name: "TestExclusive", FullOnly: &small, Exclusive: true}, {Name: "TestOrdinaryOutputMemoryNativeArtifact", FullOnly: &small}}
	for _, row := range []struct {
		name        string
		selected    []string
		big, failed bool
	}{
		{"normal-full-profile-focus", []string{"TestSmall"}, false, false},
		{"small-full-only-root", []string{"TestSmall", "TestFull"}, false, false},
		{"explicit-exclusive-root", []string{"TestSmall", "TestExclusive"}, true, false},
		{"small-exclusive-root", []string{"TestOrdinaryOutputMemoryNativeArtifact"}, true, false},
		{"missing-classification", []string{"TestMissing"}, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			big, err := selectedRootsBig(componentPackage, row.selected, rows)
			if (err != nil) != row.failed || err == nil && big != row.big {
				t.Fatalf("selected resource class: big=%t error=%v", big, err)
			}
		})
	}
	if big, err := selectedRootsBig("example.invalid/another", []string{"TestOrdinaryOutputMemoryNativeArtifact"}, rows); err != nil || big {
		t.Fatal("same root name in another package inherited component exclusivity", err)
	}
}

// full_only: false
func TestPreparedExecutionKeepsAssignedShareAndBothCancellations(t *testing.T) {
	parent := withRacePolicy(withExecutionCapacity(t.Context(), defaultExecutionPolicy()), true)
	saved, stopSaved := context.WithTimeout(parent, time.Minute)
	defer stopSaved()
	assigned, stopAssigned := context.WithCancel(withExecutionParallel(parent, 1))
	defer stopAssigned()
	actual, release := preparedExecutionContext(assigned, saved)
	defer release()
	if executionCapacityFromContext(actual).Parallel != 1 || !raceEnabled(actual) {
		t.Fatal("preparation context replaced assigned execution values")
	}
	savedDeadline, _ := saved.Deadline()
	actualDeadline, _ := actual.Deadline()
	if !savedDeadline.Equal(actualDeadline) {
		t.Fatal("prepared lifetime deadline changed")
	}
	stopSaved()
	select {
	case <-actual.Done():
	case <-time.After(time.Second):
		t.Fatal("prepared cancellation did not stop execution")
	}
	saved2, stopSaved2 := context.WithCancel(parent)
	defer stopSaved2()
	actual2, release2 := preparedExecutionContext(assigned, saved2)
	defer release2()
	stopAssigned()
	select {
	case <-actual2.Done():
	case <-time.After(time.Second):
		t.Fatal("assigned caller cancellation did not stop execution")
	}
}

func completePreparationFixture(t *testing.T, later string) (context.Context, string, string, string, string, workflowPlan) {
	t.Helper()
	root, bootstrap, _ := overlayFixture(t)
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
	source := `package witness
import ("flag"; "os"; "testing")
// full_only: false
func TestNormal(t *testing.T) { if err := os.WriteFile(os.Getenv("ENKV_PREPARATION_WITNESS"), []byte(flag.Lookup("test.parallel").Value.String()), 0600); err != nil { t.Fatal(err) } }
// full_only: true
func TestBig(t *testing.T) { if err := os.WriteFile(os.Getenv("ENKV_PREPARATION_WITNESS"), []byte("big"), 0600); err != nil { t.Fatal(err) } }
`
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", source)
	initializeWorkflowExecutionFixture(t, root)
	observations := t.TempDir()
	marker := filepath.Join(observations, "body")
	t.Setenv("ENKV_PREPARATION_WITNESS", marker)
	path := filepath.Join(observations, "workflow.json")
	steps := []any{map[string]any{"id": "first", "kind": "unit", "packages": []string{"telemetry/witness"}, "package": "telemetry/witness", "tests": singleTestRequest("TestNormal")}}
	if later != "" {
		steps = append(steps, map[string]any{"id": "later", "kind": "unit", "packages": []string{"telemetry/witness"}, "package": "telemetry/witness", "tests": singleTestRequest(later)})
	}
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "prepared-selection", "profile": "full", "steps": steps})
	locks, err := openResourceLocks(filepath.Join(root, "resource-locks"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := withResourceLocks(withExecutionParallel(t.Context(), 1), locks)
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, root, bootstrap, marker, path, plan
}

// full_only: false
func TestPreparedWorkflowUsesCapturedSelectionAfterFileEdits(t *testing.T) {
	ctx, root, bootstrap, marker, path, plan := completePreparationFixture(t, "TestBig")
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
	if prepared != nil {
		defer func() {
			if err := prepared.close(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("preparation executed a selected body", err)
	}
	if err := os.WriteFile(path, []byte("invalid workflow after selection\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := runPreparedWorkflow(ctx, root, bootstrap, prepared, io.Discard)
	if err != nil || result.Outcome != "passed" {
		t.Fatal("captured selection was invalidated by a workflow edit", err, result.Outcome)
	}
	body, err := os.ReadFile(marker)
	if err != nil || string(body) != "big" {
		t.Fatal("captured selection did not finish both selected tests", string(body), err)
	}
}

// full_only: false
func TestWorkflowRunsReadyWorkBeforeMissingLaterSelection(t *testing.T) {
	for _, row := range []struct {
		name                       string
		refuseOutput, selectedLive bool
	}{
		{name: "cause-retained"},
		{name: "output-failure", refuseOutput: true},
		{name: "later-selected-live", selectedLive: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, root, bootstrap, marker, _, plan := completePreparationFixture(t, "TestMissing")
			if row.selectedLive {
				live := &resolvedRequest{Mode: "live", Provider: "gcp"}
				plan.Steps = append(plan.Steps, resolvedWorkflowStep{ID: "live", Kind: "run", Selected: true, Run: live, request: runRequest{Suite: "live", Provider: "gcp", Resolved: live}})
			}
			prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				t.Fatal("later selection prevented preparation of ready work", err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("preparation executed the earlier body", err)
			}
			if len(prepared.ordinary) != 1 || prepared.ordinary["later"] != nil {
				t.Fatal("unrelated later selection was prepared ahead of ready work")
			}
			var output bytes.Buffer
			var writer io.Writer = &output
			outputErr := errors.New("later preparation diagnostic output refused")
			if row.refuseOutput {
				writer = assemblyGroupFailureOutput{failOn: "Assembly cause", cause: outputErr}
			}
			result, err := runPreparedWorkflow(ctx, root, bootstrap, prepared, writer)
			if err == nil || result.Outcome != "failed" || len(result.Steps) != len(plan.Steps) || result.Steps[0].Outcome != "passed" || result.Steps[1].Outcome == "passed" {
				t.Fatal("later selection lost the earlier result or passed a missing root", result.Outcome, result.Steps, err)
			}
			if row.refuseOutput {
				if !errors.Is(err, outputErr) {
					t.Fatal("later diagnostic output failure was discarded", err)
				}
			} else if row.selectedLive {
				later := prepared.preparations["later"]
				if !prepared.class.Live || later == nil || later.Preparation != "failed" || len(prepared.suites) != 0 {
					t.Fatal("later local preparation did not fail before live preparation")
				}
				var failure *checkFailure
				if !errors.As(err, &failure) || !strings.Contains(failure.cause.Error(), "ordinary test must resolve exactly one admitted artifact") || err.Error() != "check failed; phase=workflow; diagnostics: no durable run owner" || strings.Contains(output.String(), "ordinary test must resolve exactly one admitted artifact") || strings.Contains(output.String(), "Assembly cause") {
					t.Fatal("later-selected live workflow exposed the preparation cause")
				}
				if result.Steps[2].Outcome != "not_run" || result.Steps[2].StartedAt != nil || result.Steps[2].FinishedAt != nil || strings.Contains(output.String(), "Step live (run)") {
					t.Fatal("live step was dispatched after local preparation failed", result.Steps[2])
				}
			} else if strings.Count(output.String(), "ordinary test must resolve exactly one admitted artifact") != 1 {
				t.Fatal("later preparation lost or repeated its original cause", output.String())
			}
			if result.Steps[1].StartedAt != nil || result.Steps[1].FinishedAt != nil || strings.Contains(output.String(), "Step later (unit)") {
				t.Fatal("failed preparation invented an execution terminal", result.Steps[1])
			}
			body, err := os.ReadFile(marker)
			if err != nil || string(body) != "1" {
				t.Fatal("ready test did not run before later selection failure", string(body), err)
			}
		})
	}
}

// full_only: false
func TestPreparedFullProfileNormalFocusExecutesWithAssignedShare(t *testing.T) {
	ctx, root, bootstrap, marker, _, plan := completePreparationFixture(t, "")
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
	if prepared != nil {
		defer func() {
			if err := prepared.close(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	if prepared.admission().Big {
		t.Fatal("full profile alone required exclusive admission")
	}
	if _, err := runPreparedWorkflow(withExecutionParallel(ctx, 1), root, bootstrap, prepared, io.Discard); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(marker)
	if err != nil || string(body) != "1" {
		t.Fatalf("actual test did not use its assigned share: %q %v", body, err)
	}
}

// full_only: false
func TestPreparedProviderCorrespondenceRefusesDifferentSameClassSelection(t *testing.T) {
	small := false
	left := &preparedProviderChecks{profile: "full", selected: []string{"TestFirst"}, evidence: checkEvidence{CompiledInventory: []string{"TestFirst", "TestSecond"}, Classifications: []testClassification{{Name: "TestFirst", FullOnly: &small}, {Name: "TestSecond", FullOnly: &small}}, AssemblySources: map[string]string{"TestFirst": "tests/live/providers/aws/first_test.go", "TestSecond": "tests/live/providers/aws/second_test.go"}, NotSelected: []string{"TestSecond"}}}
	right := *left
	right.selected = []string{"TestSecond"}
	right.evidence.NotSelected = []string{"TestFirst"}
	if samePreparedProviderChecks(left, &right) {
		t.Fatal("same resource class permitted a different actual provider selection")
	}
	if !samePreparedProviderChecks(left, left) {
		t.Fatal("unchanged provider selection lost correspondence")
	}
}

// full_only: false
func TestPreparedBootstrapIdentityIncludesAddedSourceFiles(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"tests/shared/runner", "tests/shared/records", "tests/shared/catalog"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "bootstrap.json")
	if err := os.WriteFile(path, []byte(`{"Replace":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := componentBootstrapIdentity(root, path)
	if err != nil {
		t.Fatal(err)
	}
	addition := filepath.Join(root, "tests/shared/catalog/added.go")
	if err := os.WriteFile(addition, []byte("package catalog\n"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := componentBootstrapIdentity(root, path)
	if err != nil || after == before {
		t.Fatal("bootstrap identity ignored an added source file", err)
	}
}
