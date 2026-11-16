package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// full_only: false
func TestCommandWorkflowContinuesAfterModulePreparationFailure(t *testing.T) {
	for _, row := range []struct {
		name             string
		discovery, empty bool
	}{
		{name: "execute"},
		{name: "conflicting-packages-and-known-empty", discovery: true, empty: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, root, bootstrap, marker, path, _ := completePreparationFixture(t, "")
			writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, "core/failing/failing_test.go", `package failing
import "testing"
// full_only: false
func TestUnavailable(t *testing.T) { undefinedPreparationFixture() }
`)
			writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", `package witness
import ("os"; "testing")
// full_only: false
func TestNormal(t *testing.T) {
 f,err:=os.OpenFile(os.Getenv("ENKV_PREPARATION_WITNESS"),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600)
 if err!=nil { t.Fatal(err) }
 if _,err:=f.WriteString("executed\n");err!=nil { t.Fatal(err) }
 if err:=f.Close();err!=nil { t.Fatal(err) }
}
`)
			packages := []string{"core/failing", "telemetry/witness"}
			const emptySelector = "plugins/output-contract-test"
			const emptyPackage = "enkv.sh/tests/fixtures/output-contract-test/cmd/enkv-output-contract-test"
			if row.empty {
				writeLocalGoFixture(t, root, emptySelector+"/go.mod", "module enkv.sh/tests/fixtures/output-contract-test\n\ngo 1.27.0\n")
				writeLocalGoFixture(t, root, emptySelector+"/cmd/enkv-output-contract-test/main.go", "package main\nfunc main() {}\n")
				packages = append(packages, emptySelector+"/cmd/enkv-output-contract-test")
			}
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "partial-preparation", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{map[string]any{"id": "unit", "kind": "unit", "packages": packages}}})
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			if row.discovery {
				writeLocalGoFixture(t, root, "core/failing/conflict_test.go", "package conflicting\n")
			}
			prepared, prepareErr := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
			if prepared == nil || prepareErr == nil || !toolCommandsJoined(prepareErr) || !sourceCommandsJoined(prepareErr) {
				t.Fatal("fixture did not retain a settled real compile failure", prepareErr)
			}
			cause := "undefinedPreparationFixture"
			if row.discovery {
				cause = "found packages"
			}
			if !strings.Contains(prepareErr.Error(), cause) {
				t.Fatal("original package compiler failure was lost", prepareErr)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("preparation executed a selected body", err)
			}
			scratch := prepared.current.path
			var terminal bytes.Buffer
			result, commandErr := executeCommandWorkflow(ctx, root, bootstrap, prepared, prepareErr, &terminal)
			if !errors.Is(commandErr, prepareErr) || !prepared.closed || !prepared.phase.released || !prepared.phase.joined || !toolCommandsJoined(commandErr) || !sourceCommandsJoined(commandErr) {
				t.Fatal("outer owner lost preparation failure or positive cleanup", commandErr)
			}
			if _, err := os.Stat(scratch); !os.IsNotExist(err) {
				t.Fatal("outer owner retained settled preparation scratch", err)
			}
			if len(result.Steps) != 1 || result.Outcome == "passed" {
				t.Fatal("failed selection acquired a passing workflow result", result)
			}
			body, err := os.ReadFile(marker)
			if err != nil || string(body) != "executed\n" {
				t.Fatal("healthy independent module did not execute exactly once", string(body), err, terminal.String())
			}
			execution := result.executions["unit"]
			wantPackages := 1
			if row.empty {
				wantPackages++
			}
			if execution.Ordinary == nil || execution.Ordinary.Complete || execution.Ordinary.SelectedComplete || len(execution.Ordinary.Packages) != wantPackages || execution.Ordinary.Packages[0].Name != modulePrefix+"telemetry/witness" || len(execution.Ordinary.Tests) != 1 || execution.Ordinary.Tests[0].Name != "TestNormal" || execution.Ordinary.Tests[0].Outcome != "pass" {
				t.Fatal("partial preparation lost actual success or invented failed-module inventory", execution.Ordinary)
			}
			if row.empty {
				empty := execution.Ordinary.Packages[1]
				if empty.Name != emptyPackage || len(empty.Tests) != 0 || len(empty.Inventory) != 0 {
					t.Fatal("known empty command became unavailable inventory", empty)
				}
			}
			failures := execution.Ordinary.PreparationFailures
			if len(failures) != 1 || failures[0].Directory != "core" || failures[0].Inventory != "unavailable" || failures[0].Reason != "package_preparation_failed" || len(failures[0].Patterns) != 1 || failures[0].Patterns[0] != modulePrefix+"core/failing" {
				t.Fatal("failed module lost its requested scope or unavailable inventory", failures)
			}
			failed := 0
			seen := map[*checkDiagnostics]bool{}
			for _, diagnostics := range []*checkDiagnostics{execution.Preparation, execution.diagnostics()} {
				if diagnostics == nil || seen[diagnostics] {
					continue
				}
				seen[diagnostics] = true
				for _, fact := range diagnostics.Commands {
					if fact.Scope == "core" && fact.Process == "process_failed" {
						failed++
						if !fact.Started || !fact.Joined || fact.WallSeconds == nil {
							t.Fatal("failed compiler lost its settled timing facts", fact)
						}
					}
				}
			}
			if failed != 1 {
				t.Fatal("failed module was retried or omitted", failed)
			}

		})
	}
}
