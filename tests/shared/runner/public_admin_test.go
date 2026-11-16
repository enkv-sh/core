package main

import (
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestAdministrativeSavedWorkflowUsesEightIndependentSDKCells(t *testing.T) {
	path := savedWorkflowPath(t, "authority-operator-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var focused workflowFile
	if err := readSelectionFile(path, &focused); err != nil {
		t.Fatal(err)
	}
	var adminLimits limits
	if err := readSelectionFile(filepath.Join(filepath.Dir(path), focused.Steps[0].Limits), &adminLimits); err != nil {
		t.Fatal(err)
	}
	// The complete controlled setup and command sequence is checked by
	// TestPublicOperatorUsesInitializedIDsAndSharedCurrentValue. Each request
	// can reserve at most 5 MiB; this ceiling must not stop an admitted request.
	if adminLimits.Requests != 8192 || adminLimits.BodyBytes != 8192*(5<<20) ||
		adminLimits.Objects != 256 || adminLimits.ObjectBytes != 512<<20 ||
		adminLimits.CleanupRequests != 20*adminLimits.Objects+1024 ||
		adminLimits.CleanupBytes != (50*adminLimits.Objects+512)*(1<<20) {
		t.Fatal("administrative limits do not cover the complete reserved sequence")
	}
	var expected []workflowStep
	for _, recovery := range []string{"disabled", "enabled"} {
		for _, provider := range []string{"gcp", "aws"} {
			suffix := map[string]string{"aws": "assume-role", "gcp": "impersonated"}[provider]
			conditions := []struct{ name, scenario string }{
				{"abandon", "operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt"},
				{"replacement-refusal", "operator.disabled-recovery-refuses-authority-replacement-through-cli/disabled_recovery_preserves_selected_work"},
			}
			if recovery == "enabled" {
				conditions[1] = struct{ name, scenario string }{"replace-authority", "operator.replace-authority-then-abandon-through-cli/recovery_signing_replacement_then_stale_plan_apply_history"}
			}
			for _, condition := range conditions {
				expected = append(expected, workflowStep{ID: "admin-" + provider + "-" + condition.name + "-" + recovery, Kind: "run",
					Suites: []string{"../suites/authority-operator.json"}, Environment: "../environments/public-" + provider + "-" + suffix + ".example.json",
					Limits: "../live/limits/authority-operator.json", RecoveryMode: recovery, TelemetryConfig: "../telemetry/local.json", Scenarios: []string{condition.scenario}})
			}
		}
	}
	if !reflect.DeepEqual(focused.Steps, expected) {
		t.Fatal("administrative workflow does not preserve the eight exact cells")
	}
	for _, name := range []string{"canonical", "live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var found []workflowStep
		for _, step := range file.Steps {
			if strings.HasPrefix(step.ID, "admin-") {
				found = append(found, step)
			}
		}
		if !reflect.DeepEqual(found, expected) {
			t.Fatal("administrative cells differ from the supported inventory", name)
		}
	}
	for _, cell := range expected {
		t.Run(cell.ID, func(t *testing.T) {
			plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: cell.ID})
			if err != nil {
				t.Fatal("administrative plan required credentials or generated-provider inputs", err)
			}
			for _, step := range plan.Steps {
				if !step.Selected {
					continue
				}
				run := step.Run
				if run == nil || run.Race || len(run.Entries) != 1 || !run.Entries[0].Smoke ||
					run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration || !slices.Equal(run.Schedule.Selected, cell.Scenarios) ||
					run.Generator != nil || step.request.environment.Generator != nil {
					t.Fatal("administrative cell admitted an injected or extra fixture")
				}
				actors, identities, err := loadRunSettings(step.request)
				roles := []string{"authority", "reader", "cleanup", "recipient-consumer"}
				if strings.Contains(cell.ID, "-replace-authority-") {
					roles = append(roles, "successor")
				}
				if err != nil || identities != nil || len(actors) != len(roles) || len(run.RoleBindings) != len(roles) {
					t.Fatal("administrative SDK contexts differ", err)
				}
				for _, role := range roles {
					if !publicConfigurationSettingsValid(actors[role], run.Provider) || actors[role]["credentials_file"] != "" {
						t.Fatal("administrative role did not use its isolated SDK context", role)
					}
				}
			}
		})
	}
}

// full_only: false
func TestAdministrativeSelectionRequiresOnlyItsActualRolesBeforeLogin(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	for _, recovery := range []string{"disabled", "enabled"} {
		t.Run(recovery, func(t *testing.T) {
			var environment environmentFile
			if err := readSelectionFile(filepath.Join(root, "tests/environments/public-aws-assume-role.example.json"), &environment); err != nil {
				t.Fatal(err)
			}
			scenario := "operator.disabled-recovery-refuses-authority-replacement-through-cli/disabled_recovery_preserves_selected_work"
			roles := []string{"authority", "reader", "cleanup", "recipient-consumer"}
			if recovery == "enabled" {
				scenario = "operator.replace-authority-then-abandon-through-cli/recovery_signing_replacement_then_stale_plan_apply_history"
				roles = append(roles, "successor")
			}
			for role := range environment.RoleBindings {
				if !slices.Contains(roles, role) {
					delete(environment.Participants, environment.RoleBindings[role])
					delete(environment.RoleBindings, role)
				}
			}
			directory := t.TempDir()
			suite, path := filepath.Join(directory, "suite.json"), filepath.Join(directory, "environment.json")
			saveSelection(t, suite, suiteFixture("authority-operator", []string{scenario}))
			resolve := func() (runRequest, error) {
				saveSelection(t, path, environment)
				return resolveSavedRun([]string{suite}, path, "", "", recovery, "", "", "", 1, false)
			}
			request, err := resolve()
			if err != nil {
				t.Fatal("administrative plan required an unused Recovery or successor context", err)
			}
			actors, _, err := loadRunSettings(request)
			if err != nil || len(actors) != len(roles) {
				t.Fatal("exact administrative roles did not resolve", err)
			}
			for _, role := range roles {
				participant := environment.RoleBindings[role]
				delete(environment.RoleBindings, role)
				if _, err := resolve(); err == nil {
					t.Fatal("missing role reached login selection", role)
				}
				environment.RoleBindings[role] = participant
			}
			if recovery == "enabled" {
				delete(environment.Resource.Settings, "normal_successor_key_id")
				request, err := resolve()
				if err == nil {
					_, _, err = loadRunSettings(request)
				}
				if err == nil {
					t.Fatal("replacement selected a login without its successor selector")
				}
			}
		})
	}
}

// full_only: false
func TestAdministrativeCleanupRetainsExactSDKResourcesAndRoles(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, cell := range []struct{ recovery, scenario string }{
			{"disabled", "operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt"},
			{"enabled", "operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt"},
			{"disabled", "operator.disabled-recovery-refuses-authority-replacement-through-cli/disabled_recovery_preserves_selected_work"},
			{"enabled", "operator.replace-authority-then-abandon-through-cli/recovery_signing_replacement_then_stale_plan_apply_history"},
		} {
			t.Run(provider+"/"+cell.recovery+"/"+cell.scenario, func(t *testing.T) {
				_, _, entry := publicCleanupFixture(t, provider, cell.recovery)
				input := entry.Input
				input.Scenarios = []string{cell.scenario}
				roles := []string{"recipient-consumer"}
				if strings.HasPrefix(cell.scenario, "operator.replace-authority-then-abandon-through-cli/") {
					roles = append(roles, "successor")
				}
				for _, role := range roles {
					input.Participants[role] = role
					actor := maps.Clone(input.Settings)
					actor["sdk_home"] = filepath.Join(actor["sdk_home"], role)
					input.PublicConfiguration.Actors[role] = actor
				}
				if !publicCleanupInputValid(input, provider) {
					t.Fatal("administrative cleanup required the old operator fixture")
				}
				for _, role := range roles {
					actor := input.PublicConfiguration.Actors[role]
					delete(input.PublicConfiguration.Actors, role)
					if publicCleanupInputValid(input, provider) {
						t.Fatal("administrative cleanup lost an original role", role)
					}
					input.PublicConfiguration.Actors[role] = actor
				}
			})
		}
	}
}

// full_only: false
func TestAdministrativeWorkerEvidenceRequiresIndependentRecipientAfterWriter(t *testing.T) {
	for _, row := range []struct{ scenario, transition, verification string }{
		{"operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt", "stale-plan-refused-fresh-plan-selected-history-discovered", "later-list-and-original-receipt-after-ordinary-progress"},
		{"operator.replace-authority-then-abandon-through-cli/recovery_signing_replacement_then_stale_plan_apply_history", "recovery-signing-replacement-then-reviewed-abandonment", "later-list-and-original-receipt-after-ordinary-progress"},
		{"operator.disabled-recovery-refuses-authority-replacement-through-cli/disabled_recovery_preserves_selected_work", "disabled-recovery-replacement-refused-without-private-work", "disabled-recovery-preserves-selected-work"},
	} {
		t.Run(row.scenario, func(t *testing.T) {
			participants := map[string]string{"authority": "initializer", "reader": "auditor", "cleanup": "janitor", "recipient-consumer": "recipient", "successor": "successor"}
			writer := records.WorkerResult{Scenario: row.scenario, Role: "writer", Actor: "initializer", Outcome: "passed",
				Phases: []records.PhaseResult{
					{Sequence: 1, Name: "setup", Outcome: "passed", MeasurementsExpected: true, Actor: "initializer", Expected: "selected-generated-work-ready", Actual: "selected-generated-work-ready"},
					{Sequence: 2, Name: "transition", Outcome: "passed", MeasurementsExpected: true, Actor: "initializer", Expected: row.transition, Actual: row.transition},
					{Sequence: 3, Name: "verification", Outcome: "passed", MeasurementsExpected: true, Actor: "initializer", Expected: row.verification, Actual: row.verification},
				}, FreshChecks: []records.FreshCheck{{Facts: "after.json"}}}
			consumer := records.WorkerResult{Scenario: row.scenario, Role: "fresh_after", Actor: "recipient", Outcome: "passed",
				Phases: []records.PhaseResult{{Sequence: 1, Name: "reopen", Outcome: "passed", MeasurementsExpected: true, Actor: "recipient", Expected: "success", Actual: "success"}}}
			if !completeWorker(writer, "live", participants, "", nil) || !completeWorker(consumer, "live", participants, "", nil) {
				t.Fatal("complete public administrative phases were refused")
			}
			writer.FreshChecks = nil
			if completeWorker(writer, "live", participants, "", nil) {
				t.Fatal("writer omitted its independent after-exit check")
			}
			consumer.Actor, consumer.Phases[0].Actor = "auditor", "auditor"
			if completeWorker(consumer, "live", participants, "", nil) {
				t.Fatal("GET-only Reader replaced private Recipient consumption")
			}
		})
	}
}
