package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type invocationRaceObservation struct {
	Race   bool   `json:"race"`
	GORACE string `json:"gorace"`
	Test   string `json:"test"`
}

func invocationRaceFixture(t *testing.T, profile string) (string, string, string) {
	t.Helper()
	root, _, _ := overlayFixture(t)
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "telemetry/witness/race.go", "//go:build race\n\npackage witness\nconst raceEnabled = true\n")
	writeLocalGoFixture(t, root, "telemetry/witness/plain.go", "//go:build !race\n\npackage witness\nconst raceEnabled = false\n")
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", `package witness
import ("encoding/json"; "os"; "testing")
// full_only: false
func TestParent(t *testing.T) {
 t.Run("child", func(t *testing.T) {
  body, err := json.Marshal(struct { Race bool `+"`json:\"race\"`"+`; GORACE string `+"`json:\"gorace\"`"+`; Test string `+"`json:\"test\"`"+` }{raceEnabled, os.Getenv("GORACE"), t.Name()})
  if err != nil { t.Fatal(err) }
  if err := os.WriteFile(os.Getenv("ENKV_RACE_WITNESS"), body, 0600); err != nil { t.Fatal(err) }
 })
}
// full_only: true
func TestFullOnly(t *testing.T) {}
`)
	initializeWorkflowExecutionFixture(t, root)
	output := t.TempDir()
	path := filepath.Join(output, "workflow.json")
	saveSelection(t, path, map[string]any{
		"schema_version": 1, "name": "race-policy", "profile": profile,
		"steps": []map[string]any{{"id": "witness", "kind": "unit", "packages": []string{"telemetry/witness"}}},
	})
	witness := filepath.Join(output, "observation.json")
	t.Setenv("ENKV_RACE_WITNESS", witness)
	t.Setenv("GORACE", "exitcode=0 halt_on_error=1 atexit_sleep_ms=0")
	return root, path, witness
}

func checkInvocationRace(t *testing.T, profile string, enable, focused, want bool) {
	t.Helper()
	root, path, witness := invocationRaceFixture(t, profile)
	args := []string{"run", "--workflow", path, "--step", "witness"}
	if enable {
		args = append(args, "--race")
	}
	if focused {
		args = append(args, "--package", "telemetry/witness", "--test", "TestParent/child")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	var output bytes.Buffer
	if err := runCommand(ctx, root, "", args, &output); err != nil {
		t.Fatal("selected invocation failed", err, output.String())
	}
	body, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal("selected test did not publish its compiled-mode observation", err)
	}
	var observed invocationRaceObservation
	if err := json.Unmarshal(body, &observed); err != nil {
		t.Fatal(err)
	}
	wantOptions := ""
	if want {
		wantOptions = raceOptions
	}
	if observed.Race != want || observed.GORACE != wantOptions || observed.Test != "TestParent/child" {
		t.Errorf("actual selected execution differs: got %+v want race=%t GORACE=%q", observed, want, wantOptions)
	}

}

// full_only: false
func TestInvocationRaceDefaultsAndExplicitEnable(t *testing.T) {
	for _, row := range []struct {
		name, profile string
		enable, want  bool
	}{
		{"ordinary-small", "dev", false, false},
		{"ordinary-full", "full", false, false},

		{"ordinary-small-enabled", "dev", true, true},
		{"ordinary-full-enabled", "full", true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			checkInvocationRace(t, row.profile, row.enable, false, row.want)
		})
	}
}

// full_only: false
func TestInvocationRaceFocusKeepsOwningProfile(t *testing.T) {
	for _, row := range []struct {
		profile string
		want    bool
	}{{"dev", false}, {"full", false}} {
		t.Run(row.profile, func(t *testing.T) {
			checkInvocationRace(t, row.profile, false, true, row.want)
		})
	}
}

// full_only: false
func TestRaceOptionOnlyEnables(t *testing.T) {
	for _, option := range []string{"--race", "--race=true", "--race=false", "--no-race", "--evidence"} {
		t.Run(option, func(t *testing.T) {
			valid := option == "--race"
			_, planErr := parsePlanRunArguments([]string{"run", "--workflow", "matrix.json", option})
			_, _, bareErr := parseExecutionPositionals([]string{"runner-tests", option})
			_, cleanupErr := parseCleanupRequest([]string{"cleanup", strings.Repeat("a", 32), "--limits", "limits.json", option})
			if (planErr == nil) != valid || (bareErr == nil) != valid || (cleanupErr == nil) != valid {
				t.Errorf("race option admission differs: expected valid=%t plan=%v bare=%v cleanup=%v", valid, planErr, bareErr, cleanupErr)
			}
		})
	}
}

// full_only: false
func TestWorkflowRejectsPerStepRaceChoices(t *testing.T) {
	for _, kind := range []string{"component-tests", "run"} {
		for _, race := range []bool{false, true} {
			t.Run(kind+"/"+map[bool]string{false: "off", true: "on"}[race], func(t *testing.T) {
				root, suite, environment := savedSelectionFixture(t)
				step := map[string]any{"id": "selected", "kind": kind, "race": race}
				if kind == "component-tests" {
					step["profile"] = "full"
				} else {
					step["suites"], step["environment"], step["recovery_mode"] = []string{suite}, environment, "both"
				}
				path := filepath.Join(root, "workflow.json")
				saveSelection(t, path, map[string]any{"schema_version": 1, "name": "stale-race", "steps": []any{step}})
				if _, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path}); err == nil {
					t.Fatal("obsolete per-step race choice was accepted")
				}
			})
		}
	}
}

// full_only: false

// full_only: false
