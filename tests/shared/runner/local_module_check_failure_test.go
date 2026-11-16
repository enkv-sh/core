package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestLintCommonContinuesIndependentModuleChecks(t *testing.T) {
	for _, condition := range []string{"vet", "discovery", "source-discovery", "lint-diagnostic", "format-diagnostic"} {
		t.Run(condition, func(t *testing.T) {
			root, bootstrap := lintFixture(t, t.TempDir())
			if condition == "source-discovery" {
				writeLocalGoFixture(t, root, "telemetry/unavailable.h", "#define FIXTURE_VALUE 1\n")
			}
			if condition == "format-diagnostic" {
				writeLocalGoFixture(t, root, "telemetry/unformatted.go", "package fixture\nfunc unformatted( ) {}\n")
			}
			initializeWorkflowExecutionFixture(t, root)
			ctx := withResourceLocks(t.Context(), resourceLockFixture(t))
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			commands := filepath.Join(bin, "commands")
			script := `#!/bin/sh
printf '%s|%s\n' "$PWD" "$1" >> "$ENKV_LOCAL_MODULE_COMMANDS"
case "$PWD" in
 */telemetry)
  if [ "$ENKV_LOCAL_MODULE_FAILURE" = vet ] && [ "$1" = vet ]; then
   printf 'failure|%s\n' "$ENKV_LOCAL_MODULE_FAILURE" >> "$ENKV_LOCAL_MODULE_COMMANDS"
   printf '%s\n' 'controlled module vet failure' >&2
   exit 7
  fi
  if [ "$ENKV_LOCAL_MODULE_FAILURE" = source-discovery ] && [ "$1" = list ]; then
   for argument do
    case "$argument" in
     -json=Name,*) printf 'failure|%s\n' "$ENKV_LOCAL_MODULE_FAILURE" >> "$ENKV_LOCAL_MODULE_COMMANDS"; printf '%s\n' 'controlled source discovery failure' >&2; exit 7 ;;
    esac
   done
  fi
  if [ "$ENKV_LOCAL_MODULE_FAILURE" = discovery ] && [ "$1" = list ]; then
   for argument do
    if [ "$argument" = -export ]; then
     printf 'failure|%s\n' "$ENKV_LOCAL_MODULE_FAILURE" >> "$ENKV_LOCAL_MODULE_COMMANDS"
     printf '%s\n' 'controlled module discovery failure' >&2
     exit 7
    fi
   done
  fi
 ;;
esac
exec '` + strings.ReplaceAll(realGo, "'", "'\"'\"'") + `' "$@"
`
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			lint := `#!/bin/sh
case "$1" in
 version) printf '%s\n' '{"version":"2.14.0"}' ;;
 run)
  case "$PWD" in
   */telemetry)
    if [ "$ENKV_LOCAL_MODULE_FAILURE" = lint-diagnostic ]; then
     printf 'failure|%s\n' "$ENKV_LOCAL_MODULE_FAILURE" >> "$ENKV_LOCAL_MODULE_COMMANDS"
     printf '%s\n' 'controlled lint diagnostic' >&2
     exit 1
    fi
   ;;
  esac
 ;;
 *) exit 9 ;;
esac
`
			if err := os.WriteFile(filepath.Join(bin, "golangci-lint"), []byte(lint), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_LOCAL_MODULE_COMMANDS", commands)
			t.Setenv("ENKV_LOCAL_MODULE_FAILURE", condition)
			var lintOutput bytes.Buffer
			facts, lintErr := runLint(ctx, root, bootstrap, &lintOutput)
			if lintErr == nil || !containedCheckFailure(ctx, lintErr) || !toolCommandsJoined(lintErr) || facts == nil {
				t.Fatalf("lint did not retain a contained collection and passing facts: facts=%v error=%v\n%s", facts, lintErr, lintOutput.String())
			}
			modulePassed := condition == "lint-diagnostic" || condition == "format-diagnostic"
			_, telemetryPassed := facts.modules["telemetry"]
			if telemetryPassed != modulePassed || len(facts.modules) < 2 {
				t.Fatalf("partial module proof is incorrect: telemetry=%t modules=%d", telemetryPassed, len(facts.modules))
			}
			if condition == "source-discovery" {
				path, err := sourcePath(root, "telemetry/unavailable.h")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("#define FIXTURE_VALUE 2\n"), 0600); err != nil {
					t.Fatal(err)
				}
				current, err := facts.current(ctx, root)
				if err != nil || !current || facts.unavailableSources["telemetry"] == nil || facts.failed["telemetry"] == nil {
					t.Fatalf("checkout edit changed captured unavailable-module facts: current=%t error=%v", current, err)
				}
				if err := os.WriteFile(path, []byte("#define FIXTURE_VALUE 1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// This independent module has no reusable proof and needs full checks.
			delete(facts.modules, "sdk/artifact")
			var output stopCommonArtifactOutput
			record, commonErr := runOfflineResponsibilityPrepared(nil, ctx, root, bootstrap, "dev", "common", "", &output, nil, facts)
			if !output.reached || !errors.Is(commonErr, commonArtifactStop) || record == nil {
				t.Fatalf("independent common checks did not finish: record=%v error=%v\n%s", record, commonErr, output.String())
			}
			_, telemetryPassed = record.Modules["telemetry"]
			if telemetryPassed != modulePassed {
				t.Fatal("failed prerequisite became passing common module proof")
			}
			if reason := record.ModuleFailures["telemetry"]; modulePassed && reason != "" || !modulePassed && reason != "prerequisite_failed" {
				t.Fatalf("failed module reason=%q for %s", reason, condition)
			}
			if _, exists := record.Modules["sdk/artifact"]; !exists {
				t.Fatal("independent module without lint proof was not checked")
			}
			body, err := os.ReadFile(commands)
			if err != nil {
				t.Fatal(err)
			}
			failureAttempts := 1
			if condition == "format-diagnostic" {
				failureAttempts = 0
				if !strings.Contains(lintErr.Error(), "Go formatting differs") {
					t.Fatal("original formatting failure was lost", lintErr)
				}
			}
			if got := strings.Count(string(body), "failure|"+condition+"\n"); got != failureAttempts {
				t.Errorf("failed command attempts=%d, want %d", got, failureAttempts)
			}
			telemetryAttempts := 1
			if condition == "source-discovery" {
				telemetryAttempts = 0
			}
			for module, want := range map[string]int{"telemetry": telemetryAttempts, "sdk/artifact": 2} {
				directory, err := sourcePath(root, module)
				if err != nil {
					t.Fatal(err)
				}
				if got := strings.Count(string(body), directory+"|vet\n"); got != want {
					t.Errorf("%s module vet attempts=%d, want %d", module, got, want)
				}
			}
		})
	}
}

// full_only: false
func TestCommonModuleFactsKeepSourceEditsAndRejectChangedPolicy(t *testing.T) {
	for _, condition := range []string{"source", "race", "toolchain-policy"} {
		t.Run(condition, func(t *testing.T) {
			root, bootstrap := lintFixture(t, t.TempDir())
			initializeWorkflowExecutionFixture(t, root)
			ctx := withResourceLocks(t.Context(), resourceLockFixture(t))
			facts := moduleFactFixture(t, root)
			switch condition {
			case "source":
				writeLocalGoFixture(t, root, "telemetry/extra.go", "package fixture\n")
			case "race":
				ctx = withRacePolicy(ctx, !facts.race)
			case "toolchain-policy":
				t.Setenv("GONOSUMDB", "example.invalid/changed-policy")
			}
			var output stopCommonArtifactOutput
			record, err := runOfflineResponsibilityPrepared(nil, ctx, root, bootstrap, "dev", "common", "", &output, nil, facts)
			if condition == "source" {
				if !output.reached || !errors.Is(err, commonArtifactStop) || !toolCommandsJoined(err) || record == nil || len(record.Modules) != len(moduleRoots) {
					t.Fatalf("checkout edit stopped compatible module checks: record=%v error=%v\n%s", record, err, output.String())
				}
				return
			}
			if err == nil || containedCheckFailure(ctx, err) || output.reached || record == nil || record.Outcome != "failed" || strings.Contains(output.String(), "Checking dependencies and vet") {
				t.Fatalf("changed %s did not stop module dispatch: record=%v error=%v\n%s", condition, record, err, output.String())
			}
		})
	}
}

// full_only: false
func TestFormattingFailureKeepsOutputAndSourceStops(t *testing.T) {
	for _, condition := range []string{"format-diagnostic", "malformed-source", "output", "filesystem"} {
		t.Run(condition, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			body := "package fixture\nfunc f( ){}\n"
			if condition == "malformed-source" {
				body = "package fixture\nfunc broken(\n"
			}
			writeLocalGoFixture(t, root, "format.go", body)
			var output io.Writer = io.Discard
			if condition == "output" {
				output = failingUnitOutput{}
			}
			if condition == "filesystem" {
				root = filepath.Join(root, "missing")
			}
			err := runCommand(t.Context(), root, "", []string{"fmt-check"}, output)
			wantContained := condition == "format-diagnostic" || condition == "malformed-source"
			if err == nil || containedCheckFailure(t.Context(), err) != wantContained {
				t.Fatalf("%s containment=%t, want %t: %v", condition, containedCheckFailure(t.Context(), err), wantContained, err)
			}
			if condition == "output" && !strings.Contains(err.Error(), "Go formatting differs") {
				t.Fatal("output failure lost earlier formatting diagnostic", err)
			}
		})
	}
}
