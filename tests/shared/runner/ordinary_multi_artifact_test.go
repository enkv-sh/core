package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestRunnerSelectedPathsResolveAcrossArtifactOwners(t *testing.T) {
	root, bootstrap := runnerProcessFixture(t)
	witness := `
import ("fmt"; "os"; "path/filepath"; "strings"; "testing")
func selectedWitness(t *testing.T) {
 t.Helper()
 name := strings.ReplaceAll(t.Name(), "/", "_")
 if err := os.WriteFile(filepath.Join(os.Getenv("ENKV_SELECTED_ARTIFACT_WITNESS"), name), []byte(fmt.Sprint(os.Getpid())), 0600); err != nil { t.Fatal(err) }
}
`
	for _, fixture := range []struct{ owner, pkg, tests string }{
		{"runner", "main", `
// full_only: false
func TestRunnerFirst(t *testing.T) { selectedWitness(t) }
// full_only: false
func TestRunnerOther(t *testing.T) { selectedWitness(t) }
// full_only: false
func TestRunnerNever(t *testing.T) { t.Fatal("unselected runner root executed") }
`},
		{"records", "records", `
// full_only: false
func TestRecordsParent(t *testing.T) {
 t.Run("child[1]", selectedWitness)
 t.Run("omitted.sibling", func(t *testing.T) { t.Fatal("unselected records child executed") })
}
// full_only: false
func TestRecordsNever(t *testing.T) { t.Fatal("unselected records root executed") }
`},
		{"catalog", "catalog", `
// full_only: false
func TestCatalogSelected(t *testing.T) { selectedWitness(t) }
// full_only: false
func TestCatalogNever(t *testing.T) { t.Fatal("unselected catalog root executed") }
`},
	} {
		writeLocalGoFixture(t, root, "tests/shared/"+fixture.owner+"/process_test.go", "package "+fixture.pkg+"\n"+witness+fixture.tests)
	}
	writeLocalGoFixture(t, root, "tests/scripts/bootstrap_test.go", "package main\nimport \"testing\"\n// full_only: false\nfunc TestLauncher(t *testing.T) { t.Fatal(\"unselected launcher executed\") }\n")
	observations := t.TempDir()
	t.Setenv("ENKV_SELECTED_ARTIFACT_WITNESS", observations)
	requests := []string{"TestRecordsParent/child[1]", "TestRunnerFirst", "TestCatalogSelected", "TestRunnerOther"}
	path := filepath.Join(t.TempDir(), "workflow.json")
	saveSelection(t, path, map[string]any{
		"schema_version": 1, "name": "selected-artifact-owners", "profile": "dev", "execution": map[string]any{"parallel": 2},
		"steps": []map[string]any{{"id": "selected", "kind": "runner-tests", "tests": requests}},
	})
	ctx, cancel := context.WithTimeout(withExecutionParallel(withRacePolicy(t.Context(), true), 2), 2*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
	if prepared != nil {
		defer func() {
			tail, release := finalizationContext(ctx)
			defer release()
			if err := prepared.close(tail); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal("valid paths from distinct artifact owners were refused", err, output.String())
	}
	result, err := runPreparedWorkflow(ctx, root, bootstrap, prepared, &output)
	if err != nil || result.Outcome != "passed" || len(result.Steps) != 1 {
		t.Fatal("selected artifact workflow failed", err, result.Steps, output.String())
	}
	evidence := result.executions["selected"].Ordinary
	if evidence == nil || !validOrdinaryFocusedEvidence(*evidence) || !evidence.SelectedComplete || evidence.Complete || evidence.Race == nil || !*evidence.Race || !slices.Equal(evidence.Focus.Tests, requests) {
		t.Fatal("selected result lost exact focus, race policy or completion", evidence)
	}
	expected := map[string][]string{
		modulePrefix + "core/internal/testmain":    {"TestRunnerFirst", "TestRunnerOther"},
		modulePrefix + "core/internal/testrecords": {"TestRecordsParent"},
		modulePrefix + "core/internal/testcatalog": {"TestCatalogSelected"},
	}
	for _, pkg := range evidence.Packages {
		want, known := expected[pkg.Name]
		if !known || !slices.Equal(pkg.Tests, want) || len(pkg.Inventory) != len(want)+1 || len(pkg.NotSelected) != 1 {
			t.Fatal("selected package lost exact roots, actual inventory or omissions", pkg)
		}
	}
	if len(evidence.Packages) != len(expected) || len(evidence.Tests) != 5 || len(evidence.Preparation.Artifacts) != 4 || !slices.Equal(evidence.Preparation.NotSelectedPackages, []string{"tests/scripts/bootstrap.go+bootstrap_test.go"}) {
		t.Fatal("selected results admitted extra owners or lost requested terminals", evidence)
	}
	processes := map[string]int{}
	for _, fact := range evidence.Diagnostics.Commands {
		if !fact.Started || !fact.Joined || fact.Process != "passed" {
			t.Fatal("selected execution lacks a positive joined result", fact)
		}
		if fact.Phase == "test" {
			processes[fact.Scope]++
			if fact.Events != "valid" || fact.RequestedNode != "passed" {
				t.Fatal("selected package lacks exact terminal proof", fact)
			}
		}
	}
	if len(processes) != len(expected) {
		t.Fatal("selected execution lost a package owner", processes)
	}
	for pkg := range expected {
		if processes[pkg] < 1 || processes[pkg] > 2 {
			t.Fatal("selected package lost its bounded process owners", pkg, processes)
		}
	}
	pids := map[string]string{}
	for _, name := range requests {
		body, err := os.ReadFile(filepath.Join(observations, strings.ReplaceAll(name, "/", "_")))
		if err != nil || len(body) == 0 {
			t.Fatal("requested body did not execute", name, err)
		}
		pids[name] = string(body)
	}
	shared := pids["TestRunnerFirst"] == pids["TestRunnerOther"]
	if shared != (processes[modulePrefix+"core/internal/testmain"] == 1) || pids["TestRunnerFirst"] == pids["TestCatalogSelected"] || pids["TestRunnerFirst"] == pids["TestRecordsParent/child[1]"] {
		t.Fatal("package process ownership differs", pids)
	}
	var published *ordinaryStepEvidence
	for _, line := range bytes.Split(output.Bytes(), []byte{'\n'}) {
		var record struct {
			Type     string                `json:"type"`
			Activity string                `json:"activity"`
			Ordinary *ordinaryStepEvidence `json:"ordinary"`
		}
		if json.Unmarshal(line, &record) == nil && record.Type == "test_result" && record.Activity == "runner-tests" {
			if published != nil {
				t.Fatal("selected current result was published twice")
			}
			published = record.Ordinary
		}
	}
	if published == nil || !validOrdinaryFocusedEvidence(*published) || len(published.Packages) != 3 || len(published.Tests) != 5 {
		t.Fatal("current result lost one of the selected artifact owners", output.String())
	}
	body, err := json.Marshal(published)
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []func(*ordinaryStepEvidence){
		func(e *ordinaryStepEvidence) { e.Execution = e.Execution[:2] },
		func(e *ordinaryStepEvidence) { e.Execution[1] = e.Execution[0] },
		func(e *ordinaryStepEvidence) { e.Execution[0].Tests = append(e.Execution[0].Tests, "TestRunnerNever") },
		func(e *ordinaryStepEvidence) { e.Execution[0].Package = "another/package" },
		func(e *ordinaryStepEvidence) { e.Packages[0].Inventory = e.Packages[0].Inventory[1:] },
		func(e *ordinaryStepEvidence) { e.Packages[1].NotSelected = nil },
		func(e *ordinaryStepEvidence) { e.Tests = e.Tests[1:] },
		func(e *ordinaryStepEvidence) {
			e.Tests = append(e.Tests, ordinaryTest{Package: "another/package", Name: "TestExtra", Outcome: "pass"})
		},
		func(e *ordinaryStepEvidence) { e.Focus.Tests[0] = "TestMissing" },
		func(e *ordinaryStepEvidence) { e.Focus.Package = "another/package" },
		func(e *ordinaryStepEvidence) { e.Preparation.NotSelectedPackages = nil },
		func(e *ordinaryStepEvidence) { e.Complete = true },
	} {
		var changed ordinaryStepEvidence
		if err := json.Unmarshal(body, &changed); err != nil {
			t.Fatal(err)
		}
		damage(&changed)
		if validOrdinaryFocusedEvidence(changed) || completeOrdinaryEvidence(changed) {
			t.Fatal("changed selected owner evidence claimed completion", changed)
		}
	}
}

// full_only: false
func TestOrdinaryFocusPartitionsRequestedOwners(t *testing.T) {
	artifacts := []ordinaryArtifact{
		{Owner: "tests/shared/runner", Package: "example.org/runner", Tests: []string{"TestParent", "TestOther", "TestShared"}},
		{Owner: "tests/shared/records", Package: "example.org/records", Tests: []string{"TestRecord", "TestShared"}},
		{Owner: "tests/shared/catalog", Package: "example.org/catalog", Tests: []string{"TestCatalog"}},
	}
	for index := range artifacts {
		setOrdinaryArtifactFixtureMetadata(&artifacts[index])
	}
	requested := ordinaryFocus{Tests: []string{"TestRecord", "TestParent/child[1]", "TestCatalog", "TestOther"}}
	selections, err := resolveOrdinaryFocusSet(artifacts, requested)
	if err != nil || len(selections) != 3 {
		t.Fatal("paths did not resolve independently", selections, err)
	}
	for index, tests := range [][]string{{"TestParent/child[1]", "TestOther"}, {"TestRecord"}, {"TestCatalog"}} {
		focus := selections[index]
		if focus.Artifact != artifacts[index].Owner || focus.Package != artifacts[index].Package || !slices.Equal(focus.Tests, tests) {
			t.Fatal("paths changed artifact owner or literal bounds", focus)
		}
	}
	selections[0].Tests[0] = "TestChanged"
	if requested.Tests[1] != "TestParent/child[1]" || artifacts[0].Tests[0] != "TestParent" {
		t.Fatal("resolution changed its input inventories or request")
	}
	for _, request := range []ordinaryFocus{
		{Tests: []string{"TestRecord", "TestMissing"}},
		{Tests: []string{"TestRecord", "TestShared/child"}},
		{Tests: []string{"TestRecord", "TestRecord"}},
		{Tests: []string{"TestParent", "TestParent/child"}},
		{PackagePath: "tests/shared/runner", Tests: []string{"TestParent", "TestRecord"}},
		{},
	} {
		if selections, err := resolveOrdinaryFocusSet(artifacts, request); err == nil {
			t.Fatal("missing, ambiguous, repeated, overlapping or unowned path admitted", request, selections)
		}
	}
	selections, err = resolveOrdinaryFocusSet(artifacts, ordinaryFocus{PackagePath: "tests/shared/records"})
	if err != nil || len(selections) != 1 || selections[0].Artifact != "tests/shared/records" || len(selections[0].Tests) != 0 {
		t.Fatal("exact package-only scope changed", selections, err)
	}
}
