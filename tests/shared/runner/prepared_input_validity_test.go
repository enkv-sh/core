package main

import (
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

const preparedInputWitnessSource = `package witness
import ("fmt"; "os"; "testing")
var entered int
func record(t *testing.T) {
 t.Helper()
 file, err := os.OpenFile(os.Getenv("ENKV_PREPARED_INPUT_WITNESS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 _, writeErr := fmt.Fprintf(file, "%s %d %d\n", t.Name(), os.Getpid(), entered)
 closeErr := file.Close()
 if writeErr != nil || closeErr != nil { t.Fatal(writeErr, closeErr) }
 entered++
}
// full_only: false
func TestAInputWitness(t *testing.T) {
 record(t)
 if path := os.Getenv("ENKV_PREPARED_INPUT_MUTATE"); path != "" {
  body, err := os.ReadFile(path)
  if err != nil { t.Fatal(err) }
  if err := os.WriteFile(path, append(body, []byte("\n// changed by the first physical root\n")...), 0600); err != nil { t.Fatal(err) }
 }
}
// full_only: false
func TestBInputWitness(t *testing.T) { record(t) }
`

func preparedInputValidityFixture(t *testing.T) (context.Context, string, string, *preparedWorkflow) {
	t.Helper()
	ctx, root, _, _, _, _ := completePreparationFixture(t, "")
	owned, err := newCurrentDirectory("enkv-prepared-input-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	var prepared *preparedWorkflow
	joined := true
	t.Cleanup(func() {
		if prepared != nil {
			joined = joined && prepared.joined
		}
		if err := owned.remove(joined); err != nil {
			t.Errorf("input fixture retained at %s: %v", owned.path, err)
		}
	})
	if err := os.CopyFS(owned.path, os.DirFS(filepath.Dir(root))); err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(owned.path, filepath.Base(root))
	bootstrap := filepath.Join(root, "bootstrap.json")
	path := filepath.Join(owned.path, "workflow.json")
	locks, err := openResourceLocks(filepath.Join(owned.path, "resource-locks"))
	if err != nil {
		t.Fatal(err)
	}
	ctx = withResourceLocks(ctx, locks)
	ctx, cancel := context.WithTimeout(withRacePolicy(ctx, false), 3*time.Minute)
	t.Cleanup(cancel)
	writeLocalGoFixture(t, root, "crypto/go.mod", "module "+modulePath("crypto")+"\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "crypto/fixture.go", "package crypto\n")
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePath("telemetry")+"\n\ngo 1.27.0\nrequire "+modulePath("crypto")+" v0.0.0\n")
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", strings.Replace(preparedInputWitnessSource, "import (", "import (_ \"enkv.sh/crypto\"; ", 1))
	writeLocalGoFixture(t, root, "telemetry/witness/constraint_test.go", "//go:build enkv_prepared_input_inactive\n\npackage witness\nimport \"testing\"\n// full_only: false\nfunc TestAddedAfterBarrier(t *testing.T) {}\n")
	writeLocalGoFixture(t, root, "compositions/manifesthost/go.mod", "module "+modulePath("compositions/manifesthost")+"\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "compositions/manifesthost/witness/witness_test.go", strings.Replace(preparedInputWitnessSource, "// full_only: false\nfunc TestBInputWitness(t *testing.T) { record(t) }", "", 1))
	writeLocalGoFixture(t, root, "plugins/cloudflare/go.mod", "module "+modulePath("plugins/cloudflare")+"\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/cmd/enkv-generator-cloudflare/main.go", "package main\nfunc main() {}\n")
	witness := filepath.Join(owned.path, "physical-roots")
	t.Setenv("ENKV_PREPARED_INPUT_WITNESS", witness)
	t.Setenv("ENKV_PREPARED_INPUT_MUTATE", "")
	saveSelection(t, path, map[string]any{"schema_version": 1, "name": "prepared-input-validity", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{
		map[string]any{"id": "unit", "kind": "unit", "packages": []string{"telemetry", "compositions/manifesthost", "plugins/cloudflare"}},
	}})
	plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
	joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
	if prepared != nil {
		t.Cleanup(func() {
			finish, cancel := finalizationContext(ctx)
			defer cancel()
			if err := prepared.close(finish); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil || prepared == nil || len(prepared.ordinary) != 1 {
		t.Fatal("multi-module input preparation failed", err)
	}
	if _, err := os.Stat(witness); !os.IsNotExist(err) {
		t.Fatal("input preparation executed a body", err)
	}
	return useLocalPreparationPhase(prepared.binding.context(ctx), prepared.phase), root, witness, prepared
}

func preparedInputRunnerOverlayFixture(t *testing.T, ctx context.Context, root string, prepared *preparedWorkflow, source string) (*preparedOrdinaryGroup, error) {
	t.Helper()
	writeLocalGoFixture(t, root, "tests/shared/runner/witness_test.go", strings.Replace(source, "package witness", "package main", 1))
	for _, owner := range []string{"records", "catalog"} {
		writeLocalGoFixture(t, root, "tests/shared/"+owner+"/witness_test.go", "package "+owner+"\nimport \"testing\"\n// full_only: false\nfunc TestInventoryWitness(t *testing.T) {}\n")
	}
	writeLocalGoFixture(t, root, "tests/scripts/bootstrap.go", "package main\nfunc main() {}\n")
	writeLocalGoFixture(t, root, "tests/scripts/bootstrap_test.go", "package main\nimport \"testing\"\n// full_only: false\nfunc TestBootstrapInventoryWitness(t *testing.T) {}\n")
	writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+modulePath("core")+"\n\ngo 1.27.0\n")
	replacements := map[string]string{}
	for _, owner := range []string{"runner", "records", "catalog"} {
		target := "test" + owner
		packageName := owner
		if owner == "runner" {
			target = "testmain"
			packageName = "main"
		}
		writeLocalGoFixture(t, root, "tests/shared/"+owner+"/witness.go", "package "+packageName+"\n")
		entries, err := os.ReadDir(filepath.Join(root, "tests/shared", owner))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				replacements[filepath.Join(root, "core/internal", target, entry.Name())] = filepath.Join(root, "tests/shared", owner, entry.Name())
			}
		}
	}
	body, err := json.Marshal(struct{ Replace map[string]string }{replacements})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := writeLocalGoFixture(t, root, "bootstrap.json", string(body))
	step := resolvedWorkflowStep{ID: "runner-overlay", Kind: "runner-tests", OrdinaryFocus: &ordinaryFocus{Tests: singleTestRequest("TestAInputWitness")}}
	evidence := ordinaryStepEvidence{}
	ctx = context.WithValue(ctx, workflowScratchContextKey{}, prepared.current)
	group, err := prepareOrdinaryGroup(ctx, root, bootstrap, "dev", prepared.current.path, step, &evidence, io.Discard)
	if group != nil {
		prepared.ordinary[step.ID] = group
	}
	prepared.joined = prepared.joined && toolCommandsJoined(err) && sourceCommandsJoined(err)
	return group, err
}

// full_only: false
func TestPreparedOrdinaryValidationDoesNotMultiplyGoListingByPhysicalRoots(t *testing.T) {
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	commands := filepath.Join(bin, "commands")
	observer := "#!/bin/sh\nprintf 'BEGIN\\n' >> \"$ENKV_PREPARED_INPUT_COMMANDS\"\nprintf '%s\\n' \"$PWD\" \"$@\" >> \"$ENKV_PREPARED_INPUT_COMMANDS\"\nprintf 'END\\n' >> \"$ENKV_PREPARED_INPUT_COMMANDS\"\nexec " + shellQuote(realGo) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_PREPARED_INPUT_COMMANDS", commands)
	ctx, root, witness, prepared := preparedInputValidityFixture(t)
	if err := os.WriteFile(commands, nil, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := ordinaryStepEvidence{}
	if err := prepared.ordinary["unit"].execute(ctx, root, "dev", &evidence, io.Discard); err != nil {
		prepared.joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
		t.Fatal("unchanged real module selection failed", err)
	}
	body, err := os.ReadFile(commands)
	if err != nil {
		t.Fatal(err)
	}
	membership, closure, compiles := 0, 0, 0
	for _, block := range strings.Split(string(body), "BEGIN\n")[1:] {
		lines := strings.Split(strings.TrimSuffix(block, "END\n"), "\n")
		if len(lines) < 3 {
			t.Fatal("incomplete observed Go command", block)
		}
		if lines[1] == "list" {
			if slices.Contains(lines[2:], "-json=ImportPath,Dir,GoFiles,TestGoFiles,XTestGoFiles") {
				membership++
			}
			if slices.Contains(lines[2:], "-deps") || slices.Contains(lines[2:], "-m") {
				closure++
			}
		}
		if lines[1] == "test" && slices.Contains(lines[2:], "-c") {
			compiles++
		}
	}
	if membership != 0 || closure != 0 || compiles != 0 {
		t.Errorf("unchanged dispatch repeated preparation per physical root: membership=%d closure=%d compiles=%d; at most one validation per module/package is sufficient", membership, closure, compiles)
	}
	if !evidence.Complete || len(evidence.Packages) != 3 || len(evidence.Tests) != 3 {
		t.Fatal("multi-module control lost exact selected coverage", evidence.Packages, evidence.Tests)
	}
	want := map[string][]string{
		modulePath("telemetry") + "/witness":                                                {"TestAInputWitness", "TestBInputWitness"},
		modulePath("compositions/manifesthost") + "/witness":                                {"TestAInputWitness"},
		"enkv.sh/plugins/generators/cloudflare-account-token/cmd/enkv-generator-cloudflare": nil,
	}
	for _, pkg := range evidence.Packages {
		names, ok := want[pkg.Name]
		if !ok || !slices.Equal(pkg.Tests, names) || !slices.Equal(pkg.Inventory, names) || len(pkg.NotSelected) != 0 {
			t.Fatal("multi-module control changed selected or compiled inventory", pkg)
		}
		delete(want, pkg.Name)
	}
	if len(want) != 0 || evidence.Race == nil || *evidence.Race {
		t.Fatal("control omitted a package or changed accepted race", want, evidence.Race)
	}
	terminals := map[string]bool{
		modulePath("telemetry") + "/witness\x00TestAInputWitness":                 true,
		modulePath("telemetry") + "/witness\x00TestBInputWitness":                 true,
		modulePath("compositions/manifesthost") + "/witness\x00TestAInputWitness": true,
	}
	for _, test := range evidence.Tests {
		key := test.Package + "\x00" + test.Name
		if !terminals[key] || test.Outcome != "pass" {
			t.Fatal("control changed exact terminal results", test)
		}
		delete(terminals, key)
	}
	if len(terminals) != 0 {
		t.Fatal("control omitted a selected terminal", terminals)
	}
	tests, conversions := 0, 0
	for _, command := range evidence.Diagnostics.Commands {
		if !command.Started || !command.Joined || command.Process != "passed" {
			t.Fatal("control lost positive command completion", command)
		}
		if command.Phase == "test" {
			tests++
		}
		if command.Phase == "conversion" {
			conversions++
		}
	}
	if tests != 3 || conversions != 2 {
		t.Fatal("control changed shared package or testless execution", tests, conversions)
	}
	observed, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal(err)
	}
	pids := map[int][]string{}
	rows := strings.Split(strings.TrimSpace(string(observed)), "\n")
	if len(rows) != 3 {
		t.Fatal("control did not execute three real roots", string(observed))
	}
	for _, row := range rows {
		var name string
		var pid, initial int
		if count, err := fmt.Sscanf(row, "%s %d %d", &name, &pid, &initial); err != nil || count != 3 || pid <= 0 || initial != len(pids[pid]) {
			t.Fatal("package roots lost their shared process state", row, err)
		}
		pids[pid] = append(pids[pid], name)
	}
	shared, independent := 0, 0
	for _, names := range pids {
		switch {
		case slices.Equal(names, []string{"TestAInputWitness", "TestBInputWitness"}):
			shared++
		case slices.Equal(names, []string{"TestAInputWitness"}):
			independent++
		default:
			t.Fatal("package execution repeated or mixed selected roots", pids)
		}
	}
	if len(pids) != 2 || shared != 1 || independent != 1 {
		t.Fatal("independent packages did not keep separate shared processes", pids)
	}
}

// full_only: false
func TestPreparedOrdinaryKeepsBuildAfterBarrierEdits(t *testing.T) {
	for _, mutation := range []string{"source", "overlay", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			ctx, root, witness, prepared := preparedInputValidityFixture(t)
			group := prepared.ordinary["unit"]
			index := slices.IndexFunc(group.artifacts, func(artifact preparedOrdinaryArtifact) bool {
				return artifact.Package == modulePath("telemetry")+"/witness"
			})
			if index < 0 {
				t.Fatal("two-root prepared artifact unavailable")
			}
			artifact := group.artifacts[index]
			leave, err := group.barrier.enter(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			ready, joined := make(chan struct{}, 1), make(chan error, 1)
			wait, cancel := context.WithCancel(ctx)
			defer cancel()
			evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
			go func() {
				child := unitMembershipBarrierContext{Context: wait, ready: ready}
				joined <- group.executeArtifacts(child, root, []preparedOrdinaryArtifact{artifact}, &evidence, io.Discard)
			}()
			released, collected := false, false
			defer func() {
				cancel()
				if !released {
					leave(true)
				}
				if !collected {
					tail, stop := context.WithTimeout(context.WithoutCancel(ctx), processGroupSettlementTimeout)
					defer stop()
					select {
					case runErr := <-joined:
						prepared.joined = prepared.joined && toolCommandsJoined(runErr) && sourceCommandsJoined(runErr)
					case <-tail.Done():
						prepared.joined = false
						t.Error("barrier execution did not join within its settlement tail; inputs retained")
					}
				}
			}()
			select {
			case <-ready:
			case err := <-joined:
				collected = true
				prepared.joined = prepared.joined && toolCommandsJoined(err) && sourceCommandsJoined(err)
				t.Fatal("artifact did not reach its held barrier", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			switch mutation {
			case "source":
				writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", "package witness\ninvalid source after the build\n")
			case "overlay":
				changed := false
				for _, flag := range artifact.BuildFlags {
					if path, ok := strings.CutPrefix(flag, "-overlay="); ok {
						if err := os.WriteFile(path, []byte("invalid overlay after the build\n"), 0600); err != nil {
							t.Fatal(err)
						}
						changed = true
					}
				}
				if !changed {
					t.Fatal("overlay edit had no input")
				}
			case "canceled":
				cancel()
			}
			leave(true)
			released = true
			select {
			case err = <-joined:
				collected = true
				prepared.joined = prepared.joined && toolCommandsJoined(err) && sourceCommandsJoined(err)
			case <-ctx.Done():
				t.Fatal("artifact did not join", ctx.Err())
			}
			if !toolCommandsJoined(err) || !sourceCommandsJoined(err) {
				t.Fatal("barrier execution lost positive settlement", err)
			}
			if mutation == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation cause was lost", err)
				}
				for _, command := range evidence.Diagnostics.Commands {
					if command.Phase == "test" && command.Started {
						t.Error("canceled execution started a test", command)
					}
				}
				want := []ordinaryTest{
					{Package: artifact.Package, Name: "TestAInputWitness", Outcome: "not_run"},
					{Package: artifact.Package, Name: "TestBInputWitness", Outcome: "not_run"},
				}
				if !slices.Equal(evidence.Tests, want) {
					t.Error("canceled execution lost unstarted selections or invented execution", evidence.Tests)
				}
				if _, err := os.Stat(witness); !os.IsNotExist(err) {
					t.Fatal("canceled barrier dispatch ran a body", err)
				}
				return
			}
			if err != nil || evidence.Diagnostics.Preparation != "passed" {
				t.Fatal("source edit invalidated a completed build", err, evidence.Diagnostics)
			}
			assertPreparedInputWitnessResults(t, witness, evidence)
		})
	}
}

func assertPreparedInputWitnessResults(t *testing.T, witness string, evidence ordinaryStepEvidence) {
	t.Helper()
	want := map[string]bool{"TestAInputWitness": true, "TestBInputWitness": true}
	for _, test := range evidence.Tests {
		if !want[test.Name] || test.Package != modulePath("telemetry")+"/witness" || test.Outcome != "pass" {
			t.Fatal("prepared build changed its exact terminal results", test)
		}
		delete(want, test.Name)
	}
	if len(want) != 0 {
		t.Fatal("prepared build omitted selected terminals", want)
	}
	body, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(rows) != 2 || !strings.HasPrefix(rows[0], "TestAInputWitness ") || !strings.HasPrefix(rows[1], "TestBInputWitness ") {
		t.Fatal("prepared build did not execute each selected body once", string(body))
	}
	tests, conversions := 0, 0
	for _, command := range evidence.Diagnostics.Commands {
		if command.Phase != "test" && command.Phase != "conversion" {
			continue
		}
		if !command.Started || !command.Joined || command.Process != "passed" {
			t.Fatal("prepared execution lost positive completion", command)
		}
		if command.Phase == "test" {
			if command.Events != "valid" {
				t.Fatal("prepared execution lost valid events", command)
			}
			tests++
		} else {
			conversions++
		}
	}
	if tests == 0 || tests != conversions {
		t.Fatal("prepared execution lost test or conversion completion", tests, conversions)
	}
}

// full_only: false
func TestPreparedOrdinaryKeepsBuildAfterEarlierTestEdits(t *testing.T) {
	ctx, root, witness, prepared := preparedInputValidityFixture(t)
	group := prepared.ordinary["unit"]
	index := slices.IndexFunc(group.artifacts, func(artifact preparedOrdinaryArtifact) bool {
		return artifact.Package == modulePath("telemetry")+"/witness"
	})
	if index < 0 {
		t.Fatal("two-root artifact unavailable")
	}
	source := filepath.Join(root, "telemetry/witness/witness_test.go")
	t.Setenv("ENKV_PREPARED_INPUT_MUTATE", source)
	evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	err := group.executeArtifacts(ctx, root, []preparedOrdinaryArtifact{group.artifacts[index]}, &evidence, io.Discard)
	prepared.joined = prepared.joined && toolCommandsJoined(err) && sourceCommandsJoined(err)
	if err != nil || evidence.Diagnostics.Preparation != "passed" {
		t.Fatal("source edit by an earlier test blocked later selected work", err, evidence.Diagnostics)
	}
	body, readErr := os.ReadFile(source)
	if readErr != nil || !strings.Contains(string(body), "changed by the first physical root") {
		t.Fatal("first selected body did not edit its source", readErr)
	}
	assertPreparedInputWitnessResults(t, witness, evidence)
}

// full_only: false
func TestPreparedRunnerInventoryUsesActualBinaryAndAllOwners(t *testing.T) {
	for _, condition := range []string{"retained-binary", "unselected-vet"} {
		t.Run(condition, func(t *testing.T) {
			ctx, root, witness, prepared := preparedInputValidityFixture(t)
			dependency := writeLocalGoFixture(t, root, "core/inventoryinput/input.go", "package inventoryinput\nconst Value = 1\n")
			source := strings.Replace(preparedInputWitnessSource, "import (", "import (\"enkv.sh/core/inventoryinput\"; ", 1)
			source = strings.Replace(source, "func TestAInputWitness(t *testing.T) {", "func TestAInputWitness(t *testing.T) {\n if inventoryinput.Value != 1 { t.Fatalf(\"changed dependency reached body: %d\", inventoryinput.Value) }", 1)
			if condition == "unselected-vet" {
				writeLocalGoFixture(t, root, "tests/shared/records/vet_test.go", "package records\nimport (\"fmt\";\"testing\")\n// full_only: false\nfunc TestUnselectedVetDefect(t *testing.T) { fmt.Printf(\"%d\", \"text\") }\n")
			}
			group, err := preparedInputRunnerOverlayFixture(t, ctx, root, prepared, source)
			if condition == "unselected-vet" {
				if err == nil || !strings.Contains(err.Error(), "fmt.Printf format %d") || !toolCommandsJoined(err) {
					t.Fatal("unselected owner lost real default-vet failure", err)
				}
				if _, err := os.Stat(witness); !os.IsNotExist(err) {
					t.Fatal("failed preparation executed a test", err)
				}
				return
			}
			if err != nil {
				t.Fatal("actual runner inventory failed", err)
			}
			if len(group.artifacts) != 1 || len(group.step.OrdinaryPreparation.Artifacts) != 4 {
				t.Fatal("focus lost actual artifact owners")
			}
			binary := group.artifacts[0].binary
			if binary == "" {
				t.Fatal("selected actual binary missing")
			}
			if err := os.WriteFile(dependency, []byte("invalid dependency after construction"), 0600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				evidence := ordinaryStepEvidence{}
				err := group.execute(ctx, root, "dev", &evidence, io.Discard)
				prepared.joined = prepared.joined && toolCommandsJoined(err)
				if err != nil || group.artifacts[0].binary != binary || !evidence.SelectedComplete || len(evidence.Tests) != 1 || evidence.Tests[0].Name != "TestAInputWitness" || evidence.Tests[0].Outcome != "pass" {
					t.Fatal("selected execution did not borrow captured actual binary", err, evidence.Tests)
				}
			}
			body, err := os.ReadFile(witness)
			if err != nil || len(strings.Split(strings.TrimSpace(string(body)), "\n")) != 2 {
				t.Fatal("selected repetitions did not complete", string(body), err)
			}
		})
	}
}
