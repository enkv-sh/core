package main

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// full_only: false
func TestStockPluginAcceptanceWorkflowKeepsExactOptInCells(t *testing.T) {
	path := savedWorkflowPath(t, "stock-plugin-acceptance-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var expected []workflowStep
	for _, provider := range []string{"aws", "gcp"} {
		expected = append(expected, workflowStep{
			ID: "stock-plugin-" + provider + "-enabled", Kind: "run",
			Suites:              []string{"../suites/stock-plugin-acceptance.json"},
			Environment:         "../environments/stock-plugin-" + provider + ".example.json",
			AdditionalProviders: map[string]string{"cloudflare": "../environments/cloudflare-stock-plugin.example.json"},
			TelemetryConfig:     "../telemetry/local.json", Limits: "../live/limits/stock-plugin-acceptance.json", RecoveryMode: "enabled",
		})
	}
	for _, name := range []string{"stock-plugin-acceptance-live", "canonical", "live", "check", "dev"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var actual []workflowStep
		for _, step := range file.Steps {
			for _, suite := range step.Suites {
				if filepath.Base(suite) == "stock-plugin-acceptance.json" {
					actual = append(actual, step)
				}
			}
		}
		want := expected
		if name == "check" || name == "dev" {
			want = nil
		}
		if !reflect.DeepEqual(actual, want) || name == "stock-plugin-acceptance-live" && !reflect.DeepEqual(file.Steps, expected) {
			t.Fatal("stock acceptance workflow changed its opt-in provider matrix", name)
		}
	}
	var local workflowFile
	if err := readSelectionFile(savedWorkflowPath(t, "stock-plugin-acceptance-local"), &local); err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"TestStockSourceBasisAuthenticatesGenesisAndObservation":           "assembly-checks",
		"TestStockRecoveredMembershipIncludesAuthorityForEveryEntry":       "assembly-checks",
		"TestStockPublishedPreviewKeepsActivePlainAndUncheckedSecret":      "assembly-checks",
		"TestStockPublicationBindsStartingObservationAfterStateWrites":     "assembly-checks",
		"TestStockCommandReservationsCoverFixedLifecycle":                  "assembly-checks",
		"TestStockCommandReservationRefusesUnprovedShapes":                 "assembly-checks",
		"TestStockRecoveryReservationsKeepOriginalAllowance":               "assembly-checks",
		"TestGeneratedStockCapacityIncludesRetainedBacklog":                "unit",
		"TestStockGeneratedListRetainsKnownPendingCreateAndDeleteReleases": "assembly-checks",
		"TestStockGeneratedListRejectsUnboundPendingReleases":              "assembly-checks",
		"TestStockOutputDeclarationRoutesOnlySuppliedPair":                 "assembly-checks",
		"TestStockRecoveredRoutingRequiresExactSuppliedPair":               "assembly-checks",
	}
	for _, step := range local.Steps {
		for _, selected := range step.Tests {
			if kind, required := checks[selected]; required {
				if step.Kind != kind || kind == "assembly-checks" && step.Responsibility != "gcp" {
					t.Fatal("stock reservation proof moved to another execution owner", selected, step.Kind)
				}
				delete(checks, selected)
			}
		}
	}
	if len(checks) != 0 {
		t.Fatal("stock local workflow omits reservation proof", checks)
	}
	wantLimits := limits{Requests: 103828, BodyBytes: 311761309163, Objects: 4096, ObjectBytes: 1 << 30,
		GeneratorCreates: 9, GeneratorRetires: 24, ElapsedSeconds: 3600,
		CleanupRequests: 8192, CleanupBytes: 16 << 30, CleanupSeconds: 900}
	var generator generatorConfiguration
	if err := readSelectionFile(filepath.Join(root, "tests/environments/cloudflare-stock-plugin.example.json"), &generator); err != nil ||
		generator.SchemaVersion != 1 || generator.Provider != "cloudflare" || generator.Generator.Artifact != "" || generator.Generator.CredentialsFile != "" {
		t.Fatal("stock generator scope requires an old artifact or credential file", err)
	}
	for i, cell := range expected {
		provider := []string{"aws", "gcp"}[i]
		t.Run(provider, func(t *testing.T) {
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: cell.ID})
			if err != nil {
				t.Fatal(err)
			}
			selected := 0
			for _, step := range plan.Steps {
				if !step.Selected {
					continue
				}
				selected++
				run := step.Run
				if run == nil || run.Mode != "live" || run.Provider != provider || run.RecoveryMode != "enabled" || run.Race ||
					!slices.Equal(run.Schedule.Selected, []string{"public-configuration.plugin-contracts/plugin_contracts"}) ||
					len(run.Entries) != 1 || !run.Entries[0].Smoke || step.Limits == nil || *step.Limits != wantLimits ||
					run.Generator == nil || run.Generator.Provider != "cloudflare" {
					t.Fatal("stock acceptance lost its exact selection, finite allowance or ordinary credential route")
				}
			}
			if selected != 1 {
				t.Fatal("one stock cell focus selected another activity")
			}
			var environment environmentFile
			if err := readSelectionFile(filepath.Join(filepath.Dir(path), cell.Environment), &environment); err != nil {
				t.Fatal(err)
			}
			if environment.PluginAcceptance == nil || environment.PluginAcceptance.Validate() != nil ||
				environment.PluginAcceptance.Bucket != environment.Resource.Settings["bucket"] || len(environment.Participants) != 5 ||
				(provider == "aws") != (environment.PublicOutputs != nil) {
				t.Fatal("stock example lost its exact reusable fixture or output scopes")
			}
		})
	}
}
