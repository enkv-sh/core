package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestDailyRetirementSelectionRequiresDedicatedSuite(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	dailySuite := filepath.Join(root, "tests/suites/daily-retirement-browser-login.json")
	stockSuite := filepath.Join(root, "tests/suites/stock-plugin-acceptance.json")
	var daily, stock environmentFile
	if readSelectionFile(filepath.Join(root, "tests/environments/daily-retirement-browser-login.example.json"), &daily) != nil ||
		readSelectionFile(filepath.Join(root, "tests/environments/stock-plugin-aws.example.json"), &stock) != nil {
		t.Fatal("test environments unavailable")
	}
	for _, tc := range []struct {
		name        string
		suites      []string
		environment environmentFile
		accept      bool
	}{
		{"daily", []string{dailySuite}, daily, true},
		{"stock", []string{stockSuite}, stock, true},
		{"daily-with-stock-suite", []string{stockSuite}, daily, false},
		{"stock-with-daily-suite", []string{dailySuite}, stock, false},
		{"mixed-suites", []string{dailySuite, stockSuite}, daily, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			body, err := json.Marshal(tc.environment)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "environment.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			request, err := resolveSavedRun(tc.suites, path, filepath.Join(root, "tests/environments/cloudflare-stock-plugin.example.json"),
				"", "enabled", "", "", "", 1, false)
			if (err == nil) != tc.accept {
				t.Fatalf("suite and authentication fixture admission mismatch: %v", err)
			}
			if tc.accept && (!slices.Equal(request.Schedule.Selected, []string{records.StockPluginScenario}) || request.environment.PluginAcceptance.DailyRolePrefix != tc.environment.PluginAcceptance.DailyRolePrefix) {
				t.Fatal("admitted request changed scenario or authentication binding")
			}
		})
	}
	// Filtering another suite down to the stock scenario cannot grant daily access.
	if err := validateDailyRetirementSelection([]string{dailyRetirementSuite, "state"}, []string{records.StockPluginScenario}, daily); err == nil {
		t.Fatal("focused mixed suites admitted daily browser login")
	}
}

// full_only: false
func TestDailyRetirementWorkflowHasOneExplicitAWSCell(t *testing.T) {
	path := savedWorkflowPath(t, "daily-retirement-browser-login")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 1 {
		t.Fatal("daily workflow admits more than one cell")
	}
	step := plan.Steps[0]
	if !step.Selected || step.Run == nil || step.Run.Provider != "aws" || step.Run.Mode != "live" ||
		step.Run.Suite != dailyRetirementSuite || step.Run.RecoveryMode != "enabled" ||
		!slices.Equal(step.Run.Suites, []string{dailyRetirementSuite}) ||
		!slices.Equal(step.Run.Schedule.Selected, []string{records.StockPluginScenario}) || step.Limits == nil {
		t.Fatal("daily workflow lost its explicit suite, AWS cell or bounded stock proof")
	}
	for _, name := range []string{"stock-plugin-acceptance-live", "canonical", "live", "check", "dev"} {
		var workflow workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &workflow); err != nil {
			t.Fatal(err)
		}
		for _, step := range workflow.Steps {
			for _, suite := range step.Suites {
				if filepath.Base(suite) == "daily-retirement-browser-login.json" {
					t.Fatal("daily test entered another workflow", name)
				}
			}
		}
	}
}
