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
func TestPublicPrepareSavedWorkflowHasFourProviderRecoveryCells(t *testing.T) {
	path := savedWorkflowPath(t, "public-configuration-prepare-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var focused workflowFile
	if err := readSelectionFile(path, &focused); err != nil || focused.Name != "public-configuration-prepare-live" || len(focused.Steps) != 4 {
		t.Fatal("preparation workflow unavailable", err)
	}
	var suite suiteFile
	if err := readSelectionFile(filepath.Join(root, "tests/suites/public-configuration-prepare.json"), &suite); err != nil || suite.SchemaVersion != 2 || suite.Name != "public-configuration-prepare" ||
		!slices.Equal(suite.RequiredRoles, []string{"authority", "apply", "reader", "consumer", "cleanup"}) ||
		!slices.Equal(suite.Scenarios, []string{"public-configuration.prepare-complete-loss/prepare_complete_loss"}) {
		t.Fatal("preparation suite changed exact roles or case", err)
	}
	for i, step := range focused.Steps {
		provider := []string{"aws", "gcp"}[i%2]
		mode := []string{"disabled", "enabled"}[i/2]
		environment, names := savedWorkflowRunInputs(t, root, path, step)
		if step.ID != "public-prepare-"+provider+"-"+mode || step.Kind != "run" || step.RecoveryMode != mode ||
			step.Environment != "../environments/public-"+provider+".example.json" || !environment.PublicConfiguration || environment.Provider != provider || len(step.AdditionalProviders) != 0 ||
			!slices.Equal(step.Suites, []string{"../suites/public-configuration-prepare.json"}) || !slices.Equal(names, suite.Scenarios) || step.Limits != "../live/limits/public-configuration.json" || step.TelemetryConfig != "../telemetry/local.json" {
			t.Fatal("preparation provider cell changed", i)
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
			if resolved.Run == nil || resolved.Limits == nil || !resolved.Limits.valid() || resolved.Run.Provider != provider || resolved.Run.RecoveryMode != mode || resolved.Run.Race || resolved.Run.Generator != nil || len(resolved.Run.Outputs) != 0 ||
				!slices.Equal(resolved.Run.Schedule.Selected, suite.Scenarios) || len(resolved.Run.Entries) != 1 || !resolved.Run.Entries[0].Smoke || len(resolved.Run.Schedule.NotApplicable) != 0 {
				t.Fatal("preparation focus changed finite execution selection or admitted an effect plugin")
			}
		}
		if selected != 1 {
			t.Fatal("preparation focus selected another activity")
		}
	}
	for _, name := range []string{"canonical", "live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var cells []workflowStep
		for _, step := range file.Steps {
			if strings.HasPrefix(step.ID, "public-prepare-") {
				cells = append(cells, step)
			}
		}
		if !reflect.DeepEqual(cells, focused.Steps) {
			t.Fatal("preparation cells differ from canonical live inventory", name)
		}
	}
}
