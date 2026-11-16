package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestRunnerWorkflowRepetitionsKeepFourArtifactsAndFreshProcesses(t *testing.T) {
	const fixturePackage = "example.org/prepared-runner"
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "core/go.mod", "module "+fixturePackage+"\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+fixturePackage+"\n\ngo 1.27.0\n")
	replacements := map[string]string{}
	for _, fixture := range []struct{ owner, target, pkg string }{
		{"runner", "testmain", "main"},
		{"records", "testrecords", "records"},
		{"catalog", "testcatalog", "catalog"},
	} {
		source := writeLocalGoFixture(t, root, "tests/shared/"+fixture.owner+"/witness_test.go", strings.Replace(ordinaryRepetitionWitnessSource, "package witness", "package "+fixture.pkg, 1))
		replacements[filepath.Join(root, "core/internal", fixture.target, "witness_test.go")] = source
		declaration := writeLocalGoFixture(t, root, "tests/shared/"+fixture.owner+"/witness.go", "package "+fixture.pkg+"\n")
		replacements[filepath.Join(root, "core/internal", fixture.target, "witness.go")] = declaration
	}
	writeLocalGoFixture(t, root, "tests/scripts/bootstrap.go", "package main\nfunc main() {}\n")
	writeLocalGoFixture(t, root, "tests/scripts/bootstrap_test.go", strings.Replace(ordinaryRepetitionWitnessSource, "package witness", "package main", 1))
	bootstrap := filepath.Join(t.TempDir(), "overlay.json")
	body, err := json.Marshal(struct{ Replace map[string]string }{replacements})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootstrap, body, 0600); err != nil {
		t.Fatal(err)
	}
	initializeWorkflowExecutionFixture(t, root)
	observations := t.TempDir()
	witness, commands := filepath.Join(observations, "executions.jsonl"), filepath.Join(observations, "go-commands")
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	observer := "#!/bin/sh\nprintf 'BEGIN\\n' >> \"$ENKV_ORDINARY_GO_COMMAND_LOG\"\nprintf '%s\\n' \"$PWD\" \"$@\" >> \"$ENKV_ORDINARY_GO_COMMAND_LOG\"\nprintf 'END\\n' >> \"$ENKV_ORDINARY_GO_COMMAND_LOG\"\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_ORDINARY_GO_COMMAND_LOG", commands)
	t.Setenv("ENKV_ORDINARY_REPETITION_WITNESS", witness)
	t.Setenv("ENKV_ORDINARY_REPETITION_FAIL_SECOND", "0")
	path := filepath.Join(observations, "workflow.json")
	saveSelection(t, path, map[string]any{
		"schema_version": 1, "name": "runner-repetitions", "profile": "full", "execution": map[string]any{"parallel": 1},
		"steps": []map[string]any{{"id": "runner", "kind": "runner-tests", "repetitions": 2}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil || len(plan.Steps) != 2 {
		t.Fatal("runner repetitions did not resolve", plan, err)
	}
	var output bytes.Buffer
	prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
	if prepared != nil {
		defer func() {
			finish, release := finalizationContext(ctx)
			defer release()
			if err := prepared.close(finish); err != nil {
				t.Error("runner preparation owner did not close", err)
			}
		}()
	}
	if err != nil || prepared == nil || len(prepared.ordinary) != 1 {
		t.Fatal("runner did not prepare one configured group", err, output.String())
	}
	group := prepared.ordinary["runner"]
	if group == nil || len(group.artifacts) != 4 || group.preparation == nil || len(group.preparation.Commands) == 0 {
		t.Fatal("runner preparation lost four artifact owners", group)
	}
	const rootName = "TestRepetitionProcessWitness"
	expected := map[string]string{
		fixturePackage + "/internal/testmain":    filepath.Join(root, "core/internal/testmain"),
		fixturePackage + "/internal/testrecords": filepath.Join(root, "core/internal/testrecords"),
		fixturePackage + "/internal/testcatalog": filepath.Join(root, "core/internal/testcatalog"),
		"command-line-arguments":                 filepath.Join(root, "tests/scripts"),
	}
	artifacts := map[string]preparedOrdinaryArtifact{}
	byDirectory := map[string]string{}
	for _, artifact := range group.artifacts {
		wantDirectory, known := expected[artifact.Package]
		if !known || artifacts[artifact.Package].Package != "" || artifact.Directory != "core" || artifact.cwd != wantDirectory || !slices.Equal(artifact.Tests, []string{rootName}) || !slices.Equal(artifact.CompiledTests, []string{rootName}) || len(artifact.Classifications) != 1 || artifact.Classifications[0].Name != rootName || artifact.Classifications[0].FullOnly == nil || *artifact.Classifications[0].FullOnly || artifact.Profile != "full" || !slices.Contains(artifact.TestFlags, "-timeout=15m") || artifact.binary == "" || !hexString(artifact.binaryHash, 64) {
			t.Fatal("runner artifact lost exact package, source selection, metadata or placement", artifact)
		}
		flags := []string{"-mod=readonly"}
		patterns := []string{"../tests/scripts/bootstrap.go", "../tests/scripts/bootstrap_test.go"}
		if artifact.Package != "command-line-arguments" {
			flags = append(flags, "-modfile="+filepath.Join(root, "tests/hermetic/hermetic.mod"), "-overlay="+bootstrap)
			patterns = []string{artifact.Package}
		}
		if !slices.Equal(artifact.BuildFlags, flags) || !slices.Equal(artifact.Patterns, patterns) {
			t.Fatal("runner artifact changed its bound build inputs", artifact)
		}
		compiledRace, err := binaryRace(artifact.binary)
		if err != nil || compiledRace != plan.Race {
			t.Fatal("runner artifact changed the accepted compiled race setting", compiledRace, plan.Race, err)
		}
		hash, err := assemblyFileSHA256(artifact.binary)
		if err != nil || hash != artifact.binaryHash {
			t.Fatal("prepared binary identity differs", err)
		}
		artifacts[artifact.Package], byDirectory[wantDirectory] = artifact, artifact.Package
	}
	if len(artifacts) != len(expected) {
		t.Fatal("runner artifact package set differs", artifacts)
	}
	for _, fact := range group.preparation.Commands {
		if !fact.Started || !fact.Joined || fact.Process != "passed" || fact.Phase != "preparation" {
			t.Fatal("runner preparation lacks positive joined success", fact)
		}
	}
	if _, err := os.Stat(witness); !os.IsNotExist(err) {
		t.Fatal("runner preparation started a test body", err)
	}
	result, runErr := runPreparedWorkflow(ctx, root, bootstrap, prepared, &output)
	if runErr != nil || result.Outcome != "passed" || len(result.Steps) != 2 || len(result.RepetitionGroups) != 1 {
		t.Fatal("real runner repetitions failed", runErr, result, output.String())
	}
	ids := []string{plan.Steps[0].ID, plan.Steps[1].ID}
	repetition := result.RepetitionGroups[0]
	if repetition.ConfiguredStep != "runner" || repetition.RequestedExecutions != 2 || repetition.CompletedExecutions != 2 || repetition.Outcome != "passed" || !slices.Equal(repetition.StepIDs, ids) {
		t.Fatal("runner repetition group lost exact ordered executions", repetition, ids)
	}
	preparationOwners := 0
	for index, step := range result.Steps {
		execution := result.executions[step.ID]
		evidence := execution.Ordinary
		if step.ID != ids[index] || step.Outcome != "passed" || evidence == nil || evidence.Diagnostics == nil || evidence.Profile != "full" || evidence.Race == nil || *evidence.Race != plan.Race || evidence.RaceOptions != acceptedRaceOptions(plan.Race) || !completeOrdinaryEvidence(*evidence) || len(evidence.Packages) != 4 || len(evidence.Tests) != 8 {
			t.Fatal("runner scalar lost complete accepted execution facts", step, evidence)
		}
		prefix := execution.Preparation
		if prefix == nil || prefix == group.preparation || prefix == evidence.Diagnostics || prefix.Preparation != "passed" {
			t.Fatal("runner scalar lost separate passed preparation", prefix)
		}
		for _, fact := range prefix.Commands {
			if !fact.Started || !fact.Joined || fact.Process != "passed" || fact.Phase != "preparation" {
				t.Fatal("runner prefix lost positive joined preparation facts", fact)
			}
		}
		for start := 0; start+len(group.preparation.Commands) <= len(prefix.Commands); start++ {
			if reflect.DeepEqual(prefix.Commands[start:start+len(group.preparation.Commands)], group.preparation.Commands) {
				preparationOwners++
				if index != 0 || start != 0 {
					t.Fatal("runner acquisition projected outside the first configured prefix")
				}
			}
		}
		packages := map[string]bool{}
		for _, pkg := range evidence.Packages {
			if _, known := expected[pkg.Name]; !known || packages[pkg.Name] || !slices.Equal(pkg.Tests, []string{rootName}) || !slices.Equal(pkg.Inventory, []string{rootName}) || len(pkg.NotSelected) != 0 || !validOrdinaryPackageSelection(pkg, "full") {
				t.Fatal("runner scalar changed exact package selection", pkg)
			}
			packages[pkg.Name] = true
		}
		terminals := map[string]bool{}
		for _, terminal := range evidence.Tests {
			key := terminal.Package + "\x00" + terminal.Name
			if _, known := expected[terminal.Package]; !known || terminal.Name != rootName && terminal.Name != rootName+"/leaf[a]+b" || terminal.Outcome != "pass" || terminals[key] {
				t.Fatal("runner scalar changed a required terminal", terminal)
			}
			terminals[key] = true
		}
		if len(terminals) != 8 {
			t.Fatal("runner scalar lost package-qualified terminals", terminals)
		}
		tests, conversions := map[string]bool{}, map[string]bool{}
		for _, fact := range evidence.Diagnostics.Commands {
			if !fact.Started || !fact.Joined || fact.Process != "passed" {
				t.Fatal("runner scalar lost positive joined process facts", fact)
			}
			switch fact.Phase {
			case "test", "conversion":
				seen := tests
				if fact.Phase == "conversion" {
					seen = conversions
				}
				scope := fact.Scope
				if strings.HasPrefix(scope, "balanced-") {
					_, scope, _ = strings.Cut(scope, "/")
				}
				if _, known := expected[scope]; !known || seen[scope] || fact.Events != "valid" || fact.RaceObservation != "not_observed" {
					t.Fatal("runner scalar changed per-artifact terminal or race facts", fact)
				}
				seen[scope] = true
			default:
				t.Fatal("runner scalar has an unexpected command phase", fact)
			}
		}
		if len(tests) != 4 || len(conversions) != 4 {
			t.Fatal("runner scalar lost per-artifact commands", tests, conversions)
		}
	}
	if preparationOwners != 1 {
		t.Fatal("runner acquisition was not reported once", preparationOwners)
	}
	body, err = os.ReadFile(witness)
	if err != nil {
		t.Fatal("runner bodies did not publish observations", err)
	}
	rows, err := decodeObjects[ordinaryRepetitionObservation](body)
	if err != nil || len(rows) != 8 {
		t.Fatal("runner repeated body count differs", len(rows), err)
	}
	expectedGo, err := filepath.EvalSymlinks(filepath.Join(group.goenv["GOROOT"], "bin/go"))
	if err != nil {
		t.Fatal(err)
	}
	pids, fixtures, packageCounts := map[int]bool{}, map[string]bool{}, map[string]int{}
	for _, row := range rows {
		pkg, known := byDirectory[row.WorkingDirectory]
		artifact := artifacts[pkg]
		if !known || row.PID <= 0 || pids[row.PID] || row.InitialState != 1 || row.Fixture == "" || fixtures[row.Fixture] || row.Binary != artifact.binary || row.BinarySHA256 != artifact.binaryHash || row.PWD != row.WorkingDirectory || row.Go != expectedGo || !row.ChildEntered || !row.ParentSuffix {
			t.Fatal("runner reused process state or changed artifact identity/placement", row)
		}
		pids[row.PID], fixtures[row.Fixture] = true, true
		packageCounts[pkg]++
	}
	for pkg := range expected {
		if packageCounts[pkg] != 2 {
			t.Fatal("runner did not execute each artifact twice", pkg, packageCounts)
		}
	}
	commandBody, err := os.ReadFile(commands)
	if err != nil {
		t.Fatal(err)
	}
	compiled := map[string]bool{}
	for _, block := range strings.Split(string(commandBody), "BEGIN\n")[1:] {
		lines := strings.Split(strings.TrimSuffix(block, "END\n"), "\n")
		if len(lines) < 3 || lines[1] != "test" || !slices.Contains(lines[2:], "-c") {
			continue
		}
		if slices.Contains(lines[2:], "-race") != plan.Race {
			t.Fatal("explicit runner compile changed accepted race", lines)
		}
		position := slices.Index(lines, "-o")
		if position < 0 || position+1 >= len(lines) || compiled[lines[position+1]] {
			t.Fatal("runner compiled a prepared artifact more than once", lines)
		}
		binary := lines[position+1]
		known := false
		for _, artifact := range artifacts {
			known = known || artifact.binary == binary
		}
		if !known {
			t.Fatal("runner compiled an unexpected artifact", binary)
		}
		compiled[binary] = true
	}
	if len(compiled) != 4 {
		t.Fatal("runner did not explicitly compile each artifact once", compiled)
	}
	finish, release := finalizationContext(ctx)
	closeErr := prepared.close(finish)
	release()
	if closeErr != nil {
		t.Fatal("joined runner preparation did not close", closeErr)
	}
	for fixture := range fixtures {
		if _, err := os.Stat(fixture); !os.IsNotExist(err) {
			t.Error("joined runner body retained its mutable fixture", fixture, err)
		}
	}
	for _, artifact := range artifacts {
		if _, err := os.Stat(artifact.binary); !os.IsNotExist(err) {
			t.Error("joined runner owner retained its prepared binary", artifact.binary, err)
		}
	}
}
