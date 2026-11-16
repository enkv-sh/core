package main

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
)

func publicConfigurationWorkflowCase(name string) bool {
	row, known := catalog.PublicConfiguration(name)
	if !known {
		return false
	}
	switch row.Condition {
	case "standard-discovery", "empty-initialization", "required-public-denied", "normal-signing-denied", "authority-private-denied", "recovery-signing-denied", "recovery-private-denied", "portable-validation", "fresh-secret-apply", "retained-input-access", "readonly-unknown-outcomes", "recipient-lifecycle":
		return true
	}
	return false
}

// full_only: false
func TestPublicConfigurationSavedWorkflowInventory(t *testing.T) {
	path := savedWorkflowPath(t, "public-configuration-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var expected []workflowStep
	for _, mode := range []string{"disabled", "enabled"} {
		for _, provider := range []string{"aws", "gcp"} {
			expected = append(expected, workflowStep{ID: "public-" + provider + "-" + mode, Kind: "run",
				Suites: []string{"../suites/public-configuration.json"}, Environment: "../environments/public-" + provider + ".example.json",
				TelemetryConfig: "../telemetry/local.json", Limits: "../live/limits/public-configuration.json", RecoveryMode: mode})
		}
	}
	for _, name := range []string{"public-configuration-live", "canonical", "live"} {
		var file workflowFile
		workflowPath := savedWorkflowPath(t, name)
		if err := readSelectionFile(workflowPath, &file); err != nil {
			t.Fatal(name, err)
		}
		var public []workflowStep
		for _, step := range file.Steps {
			if step.Kind != "run" {
				continue
			}
			_, names := savedWorkflowRunInputs(t, root, workflowPath, step)
			if slices.ContainsFunc(names, publicConfigurationWorkflowCase) && !strings.HasPrefix(step.ID, "public-functional-") && !strings.HasPrefix(step.ID, "public-operator-") {
				public = append(public, step)
			}
		}
		if !reflect.DeepEqual(public, expected) || name == "public-configuration-live" && !reflect.DeepEqual(file.Steps, expected) {
			t.Fatal("public provider cells differ from the exact focused inventory", name)
		}
	}
	conditions := []string{"standard-discovery", "empty-initialization", "required-public-denied", "normal-signing-denied", "authority-private-denied", "recovery-signing-denied", "recovery-private-denied", "portable-validation", "fresh-secret-apply", "retained-input-access", "readonly-unknown-outcomes", "recipient-lifecycle"}
	var all []string
	for _, condition := range conditions {
		all = append(all, "public-configuration."+condition+"/"+strings.ReplaceAll(condition, "-", "_"))
	}
	wantLimits := limits{Requests: 6144, BodyBytes: 1280 << 20, Objects: 256, ObjectBytes: 512 << 20,
		GeneratorCreates: 1, GeneratorRetires: 1, ElapsedSeconds: 1200, CleanupRequests: 4096,
		CleanupBytes: 8 << 30, CleanupSeconds: 600}
	for _, cell := range expected {
		t.Run(cell.ID, func(t *testing.T) {
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: cell.ID})
			if err != nil {
				t.Fatal(err)
			}
			var selected *resolvedWorkflowStep
			for i := range plan.Steps {
				if plan.Steps[i].Selected {
					if selected != nil {
						t.Fatal("public cell focus selected another activity")
					}
					selected = &plan.Steps[i]
				}
			}
			if selected == nil || selected.Run == nil || selected.Limits == nil || *selected.Limits != wantLimits {
				t.Fatal("public cell lost its exact finite limits")
			}
			run := selected.Run
			provider := strings.Split(cell.ID, "-")[1]
			if run.Mode != "live" || run.Provider != provider || run.Race || run.RecoveryMode != cell.RecoveryMode || run.Generator != nil || len(run.Outputs) != 0 ||
				run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration || run.Schedule.Repetitions != 1 || !slices.Equal(run.Suites, []string{"public-configuration"}) {
				t.Fatal("public cell changed execution family, recovery mode or race policy")
			}
			var want, notApplicable []string
			for _, name := range all {
				if cell.RecoveryMode == "disabled" && (strings.Contains(name, ".recovery-signing-denied/") || strings.Contains(name, ".recovery-private-denied/")) {
					notApplicable = append(notApplicable, name)
				} else {
					want = append(want, name)
				}
			}
			var applicable []string
			for _, name := range catalog.Names() {
				definition, known := catalog.DefinitionFor(name)
				if known && publicConfigurationWorkflowCase(name) && !strings.Contains(name, ".credential-discovery/") && slices.Contains(definition.Providers, provider) && len(definition.RolesForRecovery(cell.RecoveryMode)) != 0 {
					applicable = append(applicable, name)
				}
			}
			actual := slices.Clone(run.Schedule.Selected)
			omitted := slices.Clone(run.Schedule.NotApplicable)
			slices.Sort(actual)
			slices.Sort(omitted)
			slices.Sort(want)
			slices.Sort(notApplicable)
			slices.Sort(applicable)
			if !slices.Equal(actual, want) || !slices.Equal(actual, applicable) || !slices.Equal(omitted, notApplicable) || len(run.Entries) != len(want) {
				t.Fatal("public cell does not cover every exact applicable public leaf")
			}
			smokes := 0
			for i, entry := range run.Entries {
				if !publicConfigurationWorkflowCase(entry.Scenario) || !slices.Contains(want, entry.Scenario) || entry.Smoke != (i == 0) {
					t.Fatal("private or additional smoke entered the public cell")
				}
				if entry.Smoke {
					smokes++
				}
			}
			if smokes != 1 {
				t.Fatal("public smoke must reuse the first public leaf exactly once")
			}
			environment, _ := savedWorkflowRunInputs(t, root, path, cell)
			if !environment.PublicConfiguration || environment.Name != "public-"+provider+"-example" {
				t.Fatal("public cell substituted a private environment")
			}
			actors, identities, err := loadRunSettings(selected.request)
			if err != nil || identities != nil || len(actors) != len(run.RoleBindings) {
				t.Fatal("public cell requires injected identities or credential files", err)
			}
			homes := map[string]bool{}
			for role, settings := range actors {
				if !publicConfigurationSettingsValid(settings, provider) || settings["credentials_file"] != "" || settings["public_key_pem"] != "" {
					t.Fatal("public role is not a standard SDK context", role)
				}
				sdk := environment.Participants[environment.RoleBindings[role]].Access.SDK
				if sdk == nil || standardContext(settings) != *sdk || homes[sdk.Home] {
					t.Fatal("public role substituted or shared its isolated example login", role)
				}
				homes[sdk.Home] = true
			}
		})
	}
}

// full_only: false
func TestPublicFunctionalSavedWorkflowInventory(t *testing.T) {
	path := savedWorkflowPath(t, "public-configuration-functional-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var focused workflowFile
	if err := readSelectionFile(path, &focused); err != nil {
		t.Fatal(err)
	}
	var expected []workflowStep
	for _, mode := range []string{"disabled", "enabled"} {
		for _, provider := range []string{"aws", "gcp"} {
			suffix := "assume-role"
			if provider == "gcp" {
				suffix = "impersonated"
			}
			expected = append(expected, workflowStep{ID: "public-functional-" + provider + "-" + mode, Kind: "run",
				Suites: []string{"../suites/public-configuration-functional.json"}, Environment: "../environments/public-" + provider + "-" + suffix + ".example.json",
				TelemetryConfig: "../telemetry/local.json", Limits: "../live/limits/public-configuration.json", RecoveryMode: mode})
		}
	}
	if !reflect.DeepEqual(focused.Steps, expected) {
		t.Fatal("functional provider cells differ")
	}
	for _, name := range []string{"canonical", "live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var found []workflowStep
		for _, step := range file.Steps {
			if strings.HasPrefix(step.ID, "public-functional-") {
				found = append(found, step)
			}
		}
		if !reflect.DeepEqual(found, expected) {
			t.Fatal("functional cells missing from supported inventory", name)
		}
	}
	for _, cell := range expected {
		t.Run(cell.ID, func(t *testing.T) {
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: cell.ID})
			if err != nil {
				t.Fatal(err)
			}
			var selected *resolvedWorkflowStep
			for i := range plan.Steps {
				if plan.Steps[i].Selected {
					if selected != nil {
						t.Fatal("functional focus selected another step")
					}
					selected = &plan.Steps[i]
				}
			}
			if selected == nil || selected.Run == nil || selected.Limits == nil {
				t.Fatal("functional finite selection absent")
			}
			run := selected.Run
			if run.Mode != "live" || run.Race || run.RecoveryMode != cell.RecoveryMode || run.Schedule.Repetitions != 1 || run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration || !slices.Equal(run.Suites, []string{"public-configuration-functional"}) {
				t.Fatal("functional execution scope changed")
			}
			var want, notApplicable []string
			for _, name := range catalog.Names() {
				row, _ := catalog.PublicConfiguration(name)
				if !publicConfigurationWorkflowCase(name) || row.Condition == "standard-discovery" {
					continue
				}
				if cell.RecoveryMode == "disabled" && row.EnabledOnly {
					notApplicable = append(notApplicable, name)
				} else {
					want = append(want, name)
				}
			}
			actual := slices.Clone(run.Schedule.Selected)
			omitted := slices.Clone(run.Schedule.NotApplicable)
			slices.Sort(actual)
			slices.Sort(omitted)
			slices.Sort(want)
			slices.Sort(notApplicable)
			if !slices.Equal(actual, want) || !slices.Equal(omitted, notApplicable) || len(run.Entries) != len(want) {
				t.Fatal("functional scope omitted a case or claimed standard discovery")
			}
			if len(run.Entries) == 0 || !run.Entries[0].Smoke {
				t.Fatal("functional smoke lost its first public case")
			}
			for i, entry := range run.Entries {
				if entry.Smoke != (i == 0) {
					t.Fatal("functional smoke repeated a case")
				}
			}
		})
	}
}
