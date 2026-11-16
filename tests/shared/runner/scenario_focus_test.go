package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
)

func scenarioFocusFixture(t *testing.T, selected []string, mode string, smoke catalog.SmokePolicy) (string, string) {
	t.Helper()
	root, suite, environment := savedSelectionFixture(t)
	saveSelection(t, suite, suiteFixture("focus", []string{
		"state.single-value-update-preserves-other-values/members_1",
		"state.single-value-update-preserves-other-values/members_32",
		"state.single-value-update-preserves-other-values/members_64",
		"genesis.empty-domain-reopens/empty_genesis",
	}))
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "scenario-focus", Steps: []workflowStep{
		{ID: "components", Kind: "component-tests", Profile: "full"},
		{ID: "state", Kind: "run", Suites: []string{suite}, Environment: environment, RecoveryMode: mode, Scenarios: selected, SmokePolicy: string(smoke)},
		{ID: "unselected", Kind: "run", Suites: []string{"absent-suite.json"}, Environment: "absent-environment.json", RecoveryMode: "both"},
	}})
	return root, path
}

// full_only: false
func TestWorkflowScenarioFocusUsesOneResolvedSelection(t *testing.T) {
	point := "state.single-value-update-preserves-other-values"
	p1, p32 := point+"/members_1", point+"/members_32"
	genesis := "genesis.empty-domain-reopens/empty_genesis"
	selectedPoint := []catalog.Entry{{Scenario: p32, Repetition: 1, Smoke: true}}
	selectedGenesis := []catalog.Entry{{Scenario: p32, Smoke: true}, {Scenario: genesis, Sequence: 1, Repetition: 1}}
	selectedDiagnostics := []catalog.Entry{{Scenario: p1, Repetition: 1, Smoke: true}, {Scenario: p32, Sequence: 1, Repetition: 1}}
	for _, test := range []struct {
		name, mode, savedMode string
		admitted, flags, want []string
		smoke                 catalog.SmokePolicy
		entries               []catalog.Entry
	}{
		{"leaf", "both", "both", []string{p32, genesis}, []string{"--scenario", p32}, []string{p32}, "", selectedPoint},
		{"single-child-group", "both", "both", []string{p32, genesis}, []string{"--scenario", "genesis.empty-domain-reopens"}, []string{genesis}, "", selectedGenesis},
		{"multi-child-group", "both", "both", []string{p1, p32}, []string{"--scenario", point}, []string{p1, p32}, catalog.SmokeFirstSelectedPoint, selectedDiagnostics},
		{"repeated-literals-keep-suite-order", "both", "both", []string{p1, p32}, []string{"--scenario", p32, "--scenario", p1}, []string{p1, p32}, catalog.SmokeFirstSelectedPoint, selectedDiagnostics},
		{"disabled", "disabled", "both", []string{p32}, []string{"--scenario", p32, "--recovery-mode", "disabled"}, []string{p32}, "", selectedPoint},
		{"enabled", "enabled", "both", []string{p32}, []string{"--recovery-mode", "enabled"}, []string{p32}, "", selectedPoint},
		{"already-disabled", "disabled", "disabled", []string{p32}, []string{"--scenario", p32, "--recovery-mode", "disabled"}, []string{p32}, "", selectedPoint},
		{"already-enabled", "enabled", "enabled", []string{p32}, []string{"--recovery-mode", "enabled"}, []string{p32}, "", selectedPoint},
		{"saved-enabled", "enabled", "enabled", []string{p32}, nil, []string{p32}, "", selectedPoint},
		{"saved-disabled", "disabled", "disabled", []string{p32}, nil, []string{p32}, "", selectedPoint},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, path := scenarioFocusFixture(t, test.admitted, test.savedMode, test.smoke)
			args := append([]string{"plan", "--workflow", path, "--step", "state"}, test.flags...)
			var prior workflowPlan
			for _, command := range []string{"plan", "run"} {
				args[0] = command
				request, err := workflowArguments(args)
				if err != nil {
					t.Fatal("literal scenario/recovery selection refused", err)
				}
				plan, err := resolveWorkflow(context.Background(), root, request)
				if err != nil || len(plan.Steps) != 3 {
					t.Fatal("focused workflow did not resolve", err)
				}
				step := plan.Steps[1]
				if plan.Steps[0].Selected || plan.Steps[2].Selected || !step.Selected || step.Run == nil || !slices.Equal(step.Run.Schedule.Selected, test.want) || step.Run.RecoveryMode != test.mode || step.Run.Schedule.FullCoverage {
					t.Fatal("focus widened scope or lost its recovery selection", plan)
				}
				if !reflect.DeepEqual(step.request.Schedule, step.Run.Schedule) {
					t.Fatal("coordinator request differs from the public plan")
				}
				if !reflect.DeepEqual(step.Run.Schedule.Entries, test.entries) {
					t.Fatal("focus changed smoke ownership, order or execution count", step.Run.Schedule.Entries)
				}
				if command == "run" {
					current, previous := plan, prior
					if !reflect.DeepEqual(current, previous) {
						t.Fatal("plan and execution resolve different selections")
					}
				}
				prior = plan
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("selection planning created execution state")
			}
		})
	}
}

// full_only: false
func TestWorkflowScenarioFocusPlansWithoutCredentials(t *testing.T) {
	const name = "access.normal-signer-k2-zero-material/plain1_no_current_secret"
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			root, _, _ := savedSelectionFixture(t)
			path, _ := recoveryModeWorkflowFixture(t, root, provider)
			if _, err := os.Stat(filepath.Join(root, "missing-operator.json")); !os.IsNotExist(err) {
				t.Fatal("fixture unexpectedly has credentials")
			}
			args := []string{"plan", "--workflow", path, "--step", provider, "--scenario", name, "--recovery-mode", "disabled"}
			request, err := workflowArguments(args)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := resolveWorkflow(context.Background(), root, request)
			if err != nil || len(plan.Steps) != 1 || plan.Steps[0].Run == nil {
				t.Fatal("focused planning required credentials", err)
			}
			step := plan.Steps[0]
			if !slices.Equal(step.Run.Schedule.Selected, []string{name}) || step.Run.RecoveryMode != "disabled" || !reflect.DeepEqual(step.request.Schedule, step.Run.Schedule) {
				t.Fatal("focused planning changed the selected case or recovery mode")
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("focused planning created execution state")
			}
		})
	}
}

// full_only: false
func TestWorkflowScenarioFocusRefusesWideningAndAmbiguity(t *testing.T) {
	point := "state.single-value-update-preserves-other-values"
	p32 := point + "/members_32"
	for _, test := range []struct {
		name, mode string
		flags      []string
	}{
		{"duplicate", "both", []string{"--scenario", p32, "--scenario", p32}},
		{"group-overlap", "both", []string{"--scenario", point, "--scenario", p32}},
		{"excluded-leaf", "both", []string{"--scenario", point + "/members_64"}},
		{"empty-group", "both", []string{"--scenario", "genesis.empty-domain-reopens"}},
		{"unknown-group", "both", []string{"--scenario", "unknown.case"}},
		{"pattern", "both", []string{"--scenario", point + "/members_.*"}},
		{"empty", "both", []string{"--scenario="}},
		{"test-combination", "both", []string{"--scenario", p32, "--test", "TestExample"}},
		{"package-combination", "both", []string{"--scenario", p32, "--package", "core"}},
		{"repeat-mode", "both", []string{"--recovery-mode", "enabled", "--recovery-mode", "enabled"}},
		{"empty-mode", "both", []string{"--recovery-mode="}},
		{"unknown-mode", "both", []string{"--recovery-mode", "automatic"}},
		{"widen-mode", "disabled", []string{"--recovery-mode", "both"}},
		{"replace-mode", "disabled", []string{"--recovery-mode", "enabled"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, path := scenarioFocusFixture(t, []string{p32}, test.mode, "")
			args := append([]string{"plan", "--workflow", path, "--step", "state"}, test.flags...)
			request, err := workflowArguments(args)
			if err == nil {
				_, err = resolveWorkflow(context.Background(), root, request)
			}
			if err == nil {
				t.Fatal("invalid focus admitted")
			}
		})
	}
	root, path := scenarioFocusFixture(t, []string{p32}, "both", "")
	for _, flags := range [][]string{
		{"--scenario", p32}, {"--recovery-mode", "enabled"},
		{"--step", "components", "--scenario", p32},
		{"--step", "components", "--recovery-mode", "enabled"},
		{"--resume", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--scenario", p32},
	} {
		request, err := workflowArguments(append([]string{"plan", "--workflow", path}, flags...))
		if err == nil {
			_, err = resolveWorkflow(context.Background(), root, request)
		}
		if err == nil {
			t.Fatal("scenario focus without one run step admitted", flags)
		}
	}
}
