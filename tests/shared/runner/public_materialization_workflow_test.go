package main

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestPublicMaterializationSavedWorkflowHasTwoRecoveryEnabledCells(t *testing.T) {
	path := savedWorkflowPath(t, "public-configuration-materialization-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var focused workflowFile
	if err := readSelectionFile(path, &focused); err != nil || focused.Name != "public-configuration-materialization-live" || len(focused.Steps) != 2 {
		t.Fatal("materialization workflow unavailable", err)
	}
	var suite suiteFile
	if err := readSelectionFile(filepath.Join(root, "tests/suites/public-configuration-materialization.json"), &suite); err != nil || suite.SchemaVersion != 2 || suite.Name != "public-configuration-materialization" ||
		!slices.Equal(suite.RequiredRoles, []string{"authority", "apply", "reader", "recipient-consumer", "cleanup"}) ||
		!slices.Equal(suite.Scenarios, []string{"public-configuration.materialization/atomic_recipient_file"}) {
		t.Fatal("materialization suite changed exact roles or case", err)
	}
	for i, step := range focused.Steps {
		provider := []string{"aws", "gcp"}[i]
		suffix := "assume-role"
		if provider == "gcp" {
			suffix = "impersonated"
		}
		environment, names := savedWorkflowRunInputs(t, root, path, step)
		if step.ID != "public-materialization-"+provider+"-enabled" || step.Kind != "run" || step.RecoveryMode != "enabled" ||
			step.Environment != "../environments/public-"+provider+"-"+suffix+".example.json" || !environment.PublicConfiguration || environment.Provider != provider || len(step.AdditionalProviders) != 0 ||
			!slices.Equal(step.Suites, []string{"../suites/public-configuration-materialization.json"}) || !slices.Equal(names, suite.Scenarios) || step.Limits != "../live/limits/public-configuration.json" || step.TelemetryConfig != "../telemetry/local.json" {
			t.Fatal("materialization provider cell changed", i)
		}
		plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: step.ID})
		if err != nil {
			t.Fatal(err)
		}
		selected := 0
		for _, resolved := range plan.Steps {
			if !resolved.Selected {
				continue
			}
			selected++
			if resolved.Run == nil || resolved.Limits == nil || !resolved.Limits.valid() || resolved.Run.Provider != provider || resolved.Run.RecoveryMode != "enabled" || resolved.Run.Race ||
				!slices.Equal(resolved.Run.Schedule.Selected, suite.Scenarios) || len(resolved.Run.Entries) != 1 || !resolved.Run.Entries[0].Smoke {
				t.Fatal("materialization focus changed finite execution selection")
			}
		}
		if selected != 1 {
			t.Fatal("materialization focus selected another activity")
		}
	}
	for _, name := range []string{"canonical", "live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var cells []workflowStep
		for _, step := range file.Steps {
			if strings.HasPrefix(step.ID, "public-materialization-") {
				cells = append(cells, step)
			}
		}
		if !reflect.DeepEqual(cells, focused.Steps) {
			t.Fatal("materialization cells differ from canonical live inventory", name)
		}
	}
}

// full_only: false
func TestPublicMaterializationKeepsExistingPublicWorkflowInventoriesSeparate(t *testing.T) {
	const materialization = "public-configuration.materialization/atomic_recipient_file"
	if publicConfigurationWorkflowCase(materialization) {
		t.Fatal("materialization entered broad public workflow classification")
	}
	for _, name := range []string{"public-configuration", "public-configuration-functional", "public-configuration-operator", "public-configuration-replacement"} {
		path := savedWorkflowPath(t, "public-configuration-materialization-live")
		var suite suiteFile
		if err := readSelectionFile(filepath.Join(filepath.Dir(filepath.Dir(path)), "suites", name+".json"), &suite); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(suite.Scenarios, materialization) {
			t.Fatal("materialization entered an existing public suite", name)
		}
	}
}
