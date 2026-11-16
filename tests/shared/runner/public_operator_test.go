package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
)

// full_only: false
func TestPublicOperatorSavedWorkflowInventory(t *testing.T) {
	path := savedWorkflowPath(t, "public-configuration-operator-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var expected []workflowStep
	for _, recovery := range []string{"disabled", "enabled"} {
		for _, mode := range []string{"gcp-user-adc", "gcp-service-account-adc", "aws-shared-credentials", "aws-sso"} {
			expected = append(expected, workflowStep{ID: "public-operator-" + mode + "-" + recovery, Kind: "run", Suites: []string{"../suites/public-configuration-operator.json"}, Environment: "../environments/public-operator-" + mode + ".example.json", TelemetryConfig: "../telemetry/local.json", Limits: "../live/limits/public-configuration.json", RecoveryMode: recovery})
		}
	}
	for _, name := range []string{"public-configuration-operator-live", "canonical", "live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var actual []workflowStep
		for _, step := range file.Steps {
			if strings.HasPrefix(step.ID, "public-operator-") {
				actual = append(actual, step)
			}
		}
		if !reflect.DeepEqual(actual, expected) || name == "public-configuration-operator-live" && !reflect.DeepEqual(file.Steps, expected) {
			t.Fatal("operator workflow must retain exactly four sources and both Recovery modes", name)
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
						t.Fatal("operator focus selected another activity")
					}
					selected = &plan.Steps[i]
				}
			}
			if selected == nil || selected.Run == nil || selected.Limits == nil {
				t.Fatal("operator selection unavailable")
			}
			run := selected.Run
			want := []string{"public-configuration.credential-discovery/credential_discovery"}
			if run.Mode != "live" || run.Race || run.RecoveryMode != cell.RecoveryMode || run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration || run.Schedule.Repetitions != 1 || !slices.Equal(run.Schedule.Selected, want) || len(run.Schedule.NotApplicable) != 0 || len(run.Entries) != 1 || !run.Entries[0].Smoke || !slices.Equal(run.Suites, []string{"public-configuration-operator"}) {
				t.Fatal("operator cell changed the exact authentication-only scope")
			}
			if *selected.Limits != (limits{Requests: 6144, BodyBytes: 1280 << 20, Objects: 256, ObjectBytes: 512 << 20, GeneratorCreates: 1, GeneratorRetires: 1, ElapsedSeconds: 1200, CleanupRequests: 4096, CleanupBytes: 8 << 30, CleanupSeconds: 600}) {
				t.Fatal("operator cell lost finite budgets")
			}
			actors, identities, err := loadRunSettings(selected.request)
			if err != nil || identities != nil || len(actors) != 5 {
				t.Fatal("operator settings did not resolve", err)
			}
			participants, err := run.scenarioParticipants(want[0])
			if err != nil || len(participants) != 5 {
				t.Fatal("one selected operator was refused", err)
			}
			mode := strings.TrimSuffix(strings.TrimPrefix(cell.ID, "public-operator-"), "-"+cell.RecoveryMode)
			for role, settings := range actors {
				sdk := standardContext(settings)
				if !sdk.OperatorDiscovery(run.Provider) || sdk.Mode != mode || !publicConfigurationSettingsValid(settings, run.Provider) || participants[role] != "operator" || settings["credentials_file"] != "" {
					t.Fatal("operator source was substituted", role)
				}
				if mode == "gcp-service-account-adc" && (sdk.CredentialsFile != "/ABSOLUTE/EXISTING/service-account.json" || sdk.QuotaProject != settings["quota_project"]) {
					t.Fatal("service-account ADC selection or quota was lost")
				}
				label := strings.ReplaceAll(mode, "-", "_")
				if safeRunContext(settings).CredentialRoute != label {
					t.Fatal("run record changed source label")
				}
			}
			var output bytes.Buffer
			if err := json.NewEncoder(&output).Encode(runRecord{Resolved: selected.request.Resolved, Execution: recordExecutionPolicy(selected.request.execution), EffectiveTelemetry: selected.request.effectiveTelemetry}); err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{"/ABSOLUTE/", "sdk_home", "sdk_context", "sdk_credentials_file", "sdk_quota_project", "credentials_file", "enkv-operator", "arn:aws:", "projects/replace-project"} {
				if strings.Contains(output.String(), private) {
					t.Fatal("plan exposed private SDK context", private)
				}
			}
		})
	}
}

// full_only: false
func TestPublicOperatorDiscoveryRefusesOtherSourcesAndParticipants(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	suite := filepath.Join(root, "tests/suites/public-configuration-operator.json")
	for _, mode := range []string{"aws-assume-role", "gcp-impersonated-adc", "aws-sso", "gcp-service-account-adc"} {
		t.Run(mode, func(t *testing.T) {
			example := "public-operator-" + mode + ".example.json"
			if mode == "aws-assume-role" {
				example = "public-aws-assume-role.example.json"
			}
			if mode == "gcp-impersonated-adc" {
				example = "public-gcp-impersonated.example.json"
			}
			var env environmentFile
			if err := readSelectionFile(filepath.Join(root, "tests/environments", example), &env); err != nil {
				t.Fatal(err)
			}
			actor := env.Participants[env.RoleBindings["authority"]]
			env.Participants = map[string]participantReference{"operator": actor}
			for _, role := range []string{"authority", "apply", "reader", "consumer", "cleanup"} {
				env.RoleBindings[role] = "operator"
			}
			path := filepath.Join(t.TempDir(), "environment.json")
			if mode == "aws-sso" {
				env.Participants["second"] = actor
				env.RoleBindings["reader"] = "second"
			}
			if mode == "gcp-service-account-adc" {
				sdk := *actor.Access.SDK
				sdk.QuotaProject = "other-quota"
				actor.Access.SDK = &sdk
				env.Participants["operator"] = actor
			}
			saveSelection(t, path, env)
			request, err := resolveSavedRun([]string{suite}, path, "", "", "disabled", "", "", "", 1, false)
			if err == nil {
				_, _, err = loadRunSettings(request)
			}
			if err == nil {
				t.Fatal("operator route accepted an assumed source, another participant or mismatched quota")
			}
		})
	}
}
