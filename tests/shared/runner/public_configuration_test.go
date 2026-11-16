package main

import (
	"bytes"
	"encoding/json"
	catalog "enkv.sh/core/internal/testcatalog"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestPublicConfigurationPlanAndRolesNeedNoCredentialFiles(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	suite := filepath.Join(root, "tests", "suites", "public-configuration.json")
	limits := filepath.Join(root, "tests", "live", "limits", "public-configuration.json")
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				environment := filepath.Join(root, "tests", "environments", "public-"+provider+".example.json")
				request, err := resolveSavedRun([]string{suite}, environment, "", limits, mode, "", "", "", 1, false)
				if err != nil {
					t.Fatal("public plan required credentials or pasted keys", err)
				}
				actors, identities, err := loadRunSettings(request)
				if err != nil || identities != nil || len(actors) != len(request.Resolved.RoleBindings) {
					t.Fatal("public roles did not resolve from standard contexts only", err)
				}
				for _, settings := range actors {
					if settings["credentials_file"] != "" || settings["public_key_pem"] != "" || !publicConfigurationSettingsValid(settings, provider) {
						t.Fatal("public SDK role fell back to injected credentials")
					}
				}
				if len(request.Schedule.Entries) == 0 || !request.Schedule.Entries[0].Smoke || !strings.HasPrefix(request.Schedule.Entries[0].Scenario, "public-configuration.") {
					t.Fatal("private smoke fixture entered public process workflow")
				}
				var output bytes.Buffer
				if err := json.NewEncoder(&output).Encode(runRecord{Resolved: request.Resolved, Execution: recordExecutionPolicy(request.execution), EffectiveTelemetry: request.effectiveTelemetry}); err != nil {
					t.Fatal(err)
				}
				for _, private := range []string{"/ABSOLUTE/", "sdk_context", "sdk_home", "arn:aws:", "projects/replace-project", "public_key_pem", "credentials_file"} {
					if strings.Contains(output.String(), private) {
						t.Fatal("public plan exposed test context or source construction", private)
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicConfigurationMissingRoleRefusesBeforeLoginSelection(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	var environment environmentFile
	if err := readSelectionFile(filepath.Join(root, "tests", "environments", "public-aws.example.json"), &environment); err != nil {
		t.Fatal(err)
	}
	suite := filepath.Join(t.TempDir(), "public-configuration.json")
	saveSelection(t, suite, suiteFixture("public-configuration", []string{"public-configuration.empty-initialization/empty_initialization"}))
	path := filepath.Join(t.TempDir(), "environment.json")
	unused := environment.Participants["authority"]
	copyContext := *unused.Access.SDK
	copyContext.Home = "relative-unavailable-login"
	unused.Access.SDK = &copyContext
	environment.Participants["unused"] = unused
	environment.RoleBindings["unused"] = "unused"
	saveSelection(t, path, environment)
	request, err := resolveSavedRun([]string{suite}, path, "", "", "disabled", "", "", "", 1, false)
	if err != nil {
		t.Fatal("unused invalid login context became mandatory", err)
	}
	actors, _, err := loadRunSettings(request)
	if err != nil || actors["unused"] != nil {
		t.Fatal("unused role was selected", err)
	}
	delete(environment.RoleBindings, "reader")
	saveSelection(t, path, environment)
	if _, err := resolveSavedRun([]string{suite}, path, "", "", "disabled", "", "", "", 1, false); err == nil {
		t.Fatal("missing reader role reached credential discovery")
	}
}

// full_only: false
func TestPublicFunctionalContextsCannotClaimStandardDiscovery(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	for _, cell := range []struct{ provider, suffix, mode, label string }{
		{"aws", "assume-role", "aws-assume-role", "aws_assume_role"},
		{"gcp", "impersonated", "gcp-impersonated-adc", "gcp_impersonated_adc"},
	} {
		t.Run(cell.provider, func(t *testing.T) {
			environment := filepath.Join(root, "tests", "environments", "public-"+cell.provider+"-"+cell.suffix+".example.json")
			limits := filepath.Join(root, "tests", "live", "limits", "public-configuration.json")
			full := filepath.Join(root, "tests", "suites", "public-configuration.json")
			if _, err := resolveSavedRun([]string{full}, environment, "", limits, "enabled", "", "", "", 1, false); err == nil {
				t.Fatal("assumed identity claimed SSO or direct-user ADC discovery")
			}
			functional := filepath.Join(root, "tests", "suites", "public-configuration-functional.json")
			request, err := resolveSavedRun([]string{functional}, environment, "", limits, "enabled", "", "", "", 1, false)
			if err != nil {
				t.Fatal("functional plan required login or keys", err)
			}
			actors, identities, err := loadRunSettings(request)
			if err != nil || identities != nil || len(actors) != len(request.Resolved.RoleBindings) {
				t.Fatal("functional roles unavailable", err)
			}
			for role, settings := range actors {
				if standardContext(settings).Mode != cell.mode || standardContext(settings).StandardDiscovery(cell.provider) || safeRunContext(settings).CredentialRoute != cell.label {
					t.Fatal("functional source label claimed another login route", role)
				}
			}
		})
	}
}

// full_only: false
func TestPublicImpersonatedQuotaMustMatchResourceBeforeLogin(t *testing.T) {
	for _, cell := range []struct {
		name, quota, resource string
		valid                 bool
	}{
		{"matched", "replace-quota-project", "replace-quota-project", true},
		{"missing", "", "replace-quota-project", false},
		{"different", "another-project", "replace-quota-project", false},
		{"both-missing", "", "", false},
	} {
		t.Run(cell.name, func(t *testing.T) {
			var environment environmentFile
			if err := readSelectionFile(filepath.Join(maintainedCloudflareRoot(t), "tests/environments/public-gcp-impersonated.example.json"), &environment); err != nil {
				t.Fatal(err)
			}
			participant := environment.Participants["apply"]
			context := *participant.Access.SDK
			context.QuotaProject = cell.quota
			environment.Resource.Settings["quota_project"] = cell.resource
			participant.Access.SDK = &context
			environment.Participants["apply"] = participant
			settings, err := environment.publicConfigurationSettings("apply")
			if !cell.valid {
				if err == nil {
					t.Fatal("impersonated quota mismatch reached login selection")
				}
				return
			}
			if err != nil || settings["sdk_quota_project"] != "replace-quota-project" || settings["quota_project"] != "replace-quota-project" || settings["sdk_credentials_file"] != "" || standardContext(settings).Mode != "gcp-impersonated-adc" {
				t.Fatal("admitted impersonated quota or credential source changed", err)
			}
		})
	}
}

// full_only: false
func TestPublicGeneratedPlansUseEnvironmentRouteAndFiniteFourCellWorkflow(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	suite := filepath.Join(root, "tests", "suites", "public-generated.json")
	limitPath := filepath.Join(root, "tests", "live", "limits", "public-generated.json")
	generatorPath := filepath.Join(t.TempDir(), "cloudflare-public.json")
	generator := generatorConfiguration{SchemaVersion: 1, Provider: "cloudflare", Generator: generatorReference{Account: strings.Repeat("a", 32), PermissionGroup: strings.Repeat("b", 32), Artifact: filepath.Join(t.TempDir(), "installed-production-generator")}}
	saveSelection(t, generatorPath, generator)
	var workflow workflowFile
	if readSelectionFile(filepath.Join(root, "tests", "workflows", "public-generated-live.json"), &workflow) != nil || len(workflow.Steps) != 4 {
		t.Fatal("public generated four-cell workflow unavailable")
	}
	cells := map[string]bool{}
	for _, step := range workflow.Steps {
		if step.Kind != "run" || len(step.Suites) != 1 || step.Suites[0] != "../suites/public-generated.json" || step.Limits != "../live/limits/public-generated.json" || len(step.AdditionalProviders) != 1 || step.AdditionalProviders["cloudflare"] != "../environments/cloudflare-public-environment.json" {
			t.Fatal("public generated workflow changed its explicit finite capability")
		}
		provider := "aws"
		if strings.Contains(step.Environment, "gcp") {
			provider = "gcp"
		}
		key := provider + "/" + step.RecoveryMode
		if cells[key] || step.RecoveryMode != "enabled" && step.RecoveryMode != "disabled" {
			t.Fatal("public generated workflow duplicated or omitted recovery cell", key)
		}
		cells[key] = true
		request, err := resolveSavedRun([]string{suite}, filepath.Join(root, "tests", "workflows", step.Environment), generatorPath, limitPath, step.RecoveryMode, "", "", "", 1, false)
		if err != nil {
			t.Fatal("public generated planning demanded a credential file or live login", err)
		}
		if request.Resolved.Generator == nil || request.Resolved.Generator.CredentialContract != "environment:CLOUDFLARE_API_TOKEN" || len(request.Schedule.Selected) != 2 {
			t.Fatal("public generated plan selected the private file fixture")
		}
		for _, entry := range request.Schedule.Entries {
			if !catalog.HasFixtureCapability(entry.Scenario, catalog.FixturePublicConfiguration) || !catalog.HasFixtureCapability(entry.Scenario, catalog.FixtureGeneratedProcess) {
				t.Fatal("public generated selection admitted a private scenario")
			}
		}
		actors, _, err := loadRunSettings(request)
		if err != nil || len(actors) != 4 {
			t.Fatal("public generated exact roles unavailable", err)
		}
	}
	allowance, err := loadLimits(limitPath)
	if err != nil || allowance.GeneratorCreates != 12 || allowance.GeneratorRetires != 44 || allowance.Requests != 26224 || allowance.BodyBytes != 3244294144 || allowance.Objects != 3360 || allowance.ObjectBytes != 452984832 || allowance.ElapsedSeconds != 1200 || allowance.CleanupRequests != 78860 || allowance.CleanupBytes != 202463248384 || allowance.CleanupSeconds != 600 {
		t.Fatal("public generated finite allowances differ", err)
	}
	// Fresh generator selection refuses a credential file before credential discovery.
	generator.Generator.CredentialsFile = filepath.Join(t.TempDir(), "private-token-file")
	saveSelection(t, generatorPath, generator)
	if _, err := resolveSavedRun([]string{suite}, filepath.Join(root, "tests", "environments", "public-aws-assume-role.example.json"), generatorPath, limitPath, "disabled", "", "", "", 1, false); err == nil {
		t.Fatal("public generated plan admitted a file credential fallback")
	}
}
