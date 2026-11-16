package main

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestCapacityGCPreparedWorkflowHasFourExactProviderModeCells(t *testing.T) {
	path := savedWorkflowPath(t, "capacity-gc-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var focused workflowFile
	if err := readSelectionFile(path, &focused); err != nil || focused.Name != "capacity-gc-live" || len(focused.Steps) != 4 {
		t.Fatal("prepared capacity/GC workflow unavailable", err)
	}
	var suite suiteFile
	if err := readSelectionFile(filepath.Join(root, "tests/suites/capacity-gc.json"), &suite); err != nil || suite.SchemaVersion != 2 || suite.Name != "capacity-gc" ||
		!slices.Equal(suite.RequiredRoles, []string{"authority", "apply", "reader", "cleanup"}) ||
		!slices.Equal(suite.Scenarios, []string{"public-configuration.capacity-gc/bounded_manual_gc"}) {
		t.Fatal("prepared capacity/GC suite changed its concrete case or roles", err)
	}
	for i, step := range focused.Steps {
		provider := []string{"aws", "gcp"}[i%2]
		mode := []string{"disabled", "enabled"}[i/2]
		wantEnvironment := "../environments/public-gcp-impersonated.example.json"
		if provider == "aws" {
			wantEnvironment = "../environments/public-aws-assume-role.example.json"
		}
		environment, names := savedWorkflowRunInputs(t, root, path, step)
		if step.ID != "capacity-gc-"+provider+"-"+mode || step.Kind != "run" || step.RecoveryMode != mode ||
			step.Environment != wantEnvironment || !environment.PublicConfiguration || environment.Provider != provider || len(step.AdditionalProviders) != 0 ||
			!slices.Equal(step.Suites, []string{"../suites/capacity-gc.json"}) || !slices.Equal(names, suite.Scenarios) ||
			step.Limits != "../live/limits/capacity-gc.json" || step.TelemetryConfig != "../telemetry/local.json" {
			t.Fatal("prepared capacity/GC provider/Recovery cell changed", i)
		}
		var bounds limits
		if err := readSelectionFile(filepath.Join(filepath.Dir(path), step.Limits), &bounds); err != nil || !bounds.valid() || bounds.Requests != 6144 || bounds.BodyBytes != 4<<30 || bounds.Objects != 256 || bounds.ObjectBytes != 512<<20 ||
			bounds.GeneratorCreates != 1 || bounds.GeneratorRetires != 1 || bounds.ElapsedSeconds != 1200 || bounds.CleanupRequests != 4096 || bounds.CleanupBytes != 8<<30 || bounds.CleanupSeconds != 600 {
			t.Fatal("prepared capacity/GC finite work/cleanup bounds changed", err)
		}
	}
	for _, name := range []string{"canonical", "live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var cells []workflowStep
		for _, step := range file.Steps {
			if strings.HasPrefix(step.ID, "capacity-gc-") {
				cells = append(cells, step)
			}
		}
		if !reflect.DeepEqual(cells, focused.Steps) {
			t.Fatal("prepared focused capacity/GC cells differ from canonical live inventory", name)
		}
	}
}
