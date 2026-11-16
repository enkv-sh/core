package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

// full_only: false
func TestDirectPlanAndRunKeepOneRacePolicy(t *testing.T) {
	for _, row := range []struct {
		name   string
		enable bool
	}{{"default-off", false}, {"explicit-on", true}} {
		t.Run(row.name, func(t *testing.T) {
			root, suite, environment := savedSelectionFixture(t)
			ctx := withRacePolicy(t.Context(), row.enable)
			args := []string{"plan", "--suite", suite, "--environment", environment}
			if row.enable {
				args = append(args, "--race")
			}
			var output bytes.Buffer
			if err := runCommand(ctx, root, "must-not-build", args, &output); err != nil {
				t.Fatal(err)
			}
			var public workflowPreview
			if err := json.Unmarshal(output.Bytes(), &public); err != nil {
				t.Fatal("invalid plan JSON", err)
			}
			if public.Kind != "selection_preview" || len(public.Steps) != 1 || !public.Steps[0].Selected ||
				public.Steps[0].Kind != "run" || !slices.Equal(public.Steps[0].Suites, []string{suite}) ||
				public.Steps[0].Environment != environment || public.Steps[0].RecoveryMode != "both" ||
				!slices.Contains(public.Unresolved, "compiled test and subtest existence") {
				t.Fatal("direct preview changed requested inputs or claimed compiled selection", public)
			}
			args[0] = "run"
			request, err := parseRunRequest(args)
			if err != nil {
				t.Fatal("matching run selection was refused", err)
			}
			if request.Resolved.Race != row.enable {
				t.Fatalf("run policy differs: got %t want %t", request.Resolved.Race, row.enable)
			}
			if public.Race != row.enable {
				t.Errorf("direct plan lost accepted policy: got %t want %t", public.Race, row.enable)
			}
			if public.Race != request.Resolved.Race {
				t.Error("direct preview and matching run accepted different race policies")
			}
		})
	}
}
