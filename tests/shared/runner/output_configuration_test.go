package main

import (
	"bytes"
	"encoding/json"
	catalog "enkv.sh/core/internal/testcatalog"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mixedOutputInput(t *testing.T, provider string) (string, map[string]any) {
	t.Helper()
	path, input := outputEnvironmentInput(t, provider)
	github := map[string]any{}
	for _, scope := range []string{"repository", "organization", "environment"} {
		target := map[string]any{
			"owner": "example-owner", "secret_name_prefix": "ENKV_",
			"writer":  map[string]any{"credentials_file": "github-" + scope + "-writer"},
			"cleaner": map[string]any{"credentials_file": "github-" + scope + "-cleaner"},
		}
		if scope != "organization" {
			target["repository"] = "example-repository"
		} else {
			target["selected_repository_ids"] = []uint64{12, 34}
		}
		if scope == "environment" {
			target["environment"] = "production"
		}
		github[scope] = target
	}
	input["github_output_targets"] = github
	return path, input
}

// full_only: false
func TestOutputConfigurationParsesMixedScopesWithoutCredentials(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			path, input := mixedOutputInput(t, provider)
			env, err := loadOutputEnvironment(t, path, input)
			if err != nil {
				t.Fatal("valid cloud and GitHub public inputs refused", err)
			}
			if err := validateEnvironment(&env, filepath.Dir(path)); err != nil {
				t.Fatal("second validation changed normalized inputs", err)
			}
			if len(env.OutputTargets) != 2 {
				t.Fatal("original cloud namespaces changed")
			}
			github := env.GitHubOutputTargets
			if github == nil || github.Repository == nil || github.Organization == nil || github.Environment == nil ||
				github.Organization.SelectedRepositoryIDs[0] != 12 || github.Organization.SelectedRepositoryIDs[1] != 34 || github.Environment.Environment != "production" {
				t.Fatal("selected cloud and GitHub public facts changed")
			}
			if github.Repository.Writer.CredentialsFile != filepath.Join(filepath.Dir(path), "github-repository-writer") ||
				github.Repository.Cleaner.CredentialsFile != filepath.Join(filepath.Dir(path), "github-repository-cleaner") {
				t.Fatal("GitHub routes were not normalized independently")
			}
			settings, err := env.settingsFor("operator")
			if err != nil || len(env.Participants) != 1 || len(env.RoleBindings) != 1 ||
				strings.Contains(fmt.Sprint(settings), "github-") || strings.Contains(fmt.Sprint(settings), "output-") {
				t.Fatal("output actors entered state routes", err)
			}
			for _, role := range []string{"writer", "cleaner"} {
				for _, scope := range []string{"repository", "organization", "environment"} {
					if _, err := os.Stat(filepath.Join(filepath.Dir(path), "github-"+scope+"-"+role)); !os.IsNotExist(err) {
						t.Fatal("parse opened or created a credential route", err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestOutputConfigurationRefusesInvalidScopesAndSharedRoutes(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"github-state-route", func(g map[string]any) {
			g["repository"].(map[string]any)["writer"].(map[string]any)["credentials_file"] = "unused/../identity.json"
		}},
		{"github-cloud-route", func(g map[string]any) {
			g["repository"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"] = "output-positive-consumer_a"
		}},
		{"github-shared-route", func(g map[string]any) {
			g["environment"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"] = "github-repository-writer"
		}},
		{"github-empty-route", func(g map[string]any) {
			g["repository"].(map[string]any)["writer"].(map[string]any)["credentials_file"] = ""
		}},
		{"github-unknown-route-field", func(g map[string]any) {
			g["repository"].(map[string]any)["writer"].(map[string]any)["profile"] = "ambient"
		}},
		{"owner-alias", func(g map[string]any) { g["repository"].(map[string]any)["owner"] = "Example-owner" }},
		{"owner-overflow", func(g map[string]any) { g["repository"].(map[string]any)["owner"] = strings.Repeat("a", 40) }},
		{"repository-overflow", func(g map[string]any) { g["repository"].(map[string]any)["repository"] = strings.Repeat("a", 101) }},
		{"environment-overflow", func(g map[string]any) { g["environment"].(map[string]any)["environment"] = strings.Repeat("a", 256) }},
		{"github-own-cleaner-route", func(g map[string]any) {
			g["repository"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"] = "github-repository-writer"
		}},
		{"github-missing-cleaner", func(g map[string]any) { delete(g["repository"].(map[string]any), "cleaner") }},
		{"github-missing-owner", func(g map[string]any) { delete(g["repository"].(map[string]any), "owner") }},
		{"github-missing-repository", func(g map[string]any) { delete(g["repository"].(map[string]any), "repository") }},
		{"github-missing-environment", func(g map[string]any) { delete(g["environment"].(map[string]any), "environment") }},
		{"repository-alias", func(g map[string]any) { g["repository"].(map[string]any)["repository"] = "example.git" }},
		{"environment-alias", func(g map[string]any) { g["environment"].(map[string]any)["environment"] = "Production" }},
		{"reserved-prefix", func(g map[string]any) { g["repository"].(map[string]any)["secret_name_prefix"] = "GITHUB_ENKV_" }},
		{"prefix-overflow", func(g map[string]any) {
			g["repository"].(map[string]any)["secret_name_prefix"] = strings.Repeat("A", 67)
		}},
		{"prefix-alias", func(g map[string]any) { g["repository"].(map[string]any)["secret_name_prefix"] = "enkv_" }},
		{"repository-policy", func(g map[string]any) {
			g["repository"].(map[string]any)["selected_repository_ids"] = []uint64{12, 34}
		}},
		{"repository-empty-policy", func(g map[string]any) {
			g["repository"].(map[string]any)["selected_repository_ids"] = []uint64{}
		}},
		{"organization-repository", func(g map[string]any) { g["organization"].(map[string]any)["repository"] = "example" }},
		{"organization-empty-set", func(g map[string]any) { g["organization"].(map[string]any)["selected_repository_ids"] = []uint64{} }},
		{"organization-zero-id", func(g map[string]any) {
			g["organization"].(map[string]any)["selected_repository_ids"] = []uint64{0, 34}
		}},
		{"organization-duplicate-id", func(g map[string]any) {
			g["organization"].(map[string]any)["selected_repository_ids"] = []uint64{12, 12}
		}},
		{"organization-unsorted-id", func(g map[string]any) {
			g["organization"].(map[string]any)["selected_repository_ids"] = []uint64{34, 12}
		}},
		{"unknown-scope", func(g map[string]any) { g["other"] = g["repository"] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, input := mixedOutputInput(t, "aws")
			test.change(input["github_output_targets"].(map[string]any))
			if _, err := loadOutputEnvironment(t, path, input); err == nil {
				t.Fatal("invalid scope or shared route accepted")
			}
		})
	}
}

// full_only: false
func TestOutputConfigurationOptionalScopesAndExactBounds(t *testing.T) {
	for _, scope := range []string{"repository", "organization", "environment"} {
		t.Run(scope, func(t *testing.T) {
			path, input := mixedOutputInput(t, "aws")
			delete(input, "output_targets")
			target := input["github_output_targets"].(map[string]any)[scope].(map[string]any)
			target["secret_name_prefix"] = strings.Repeat("A", 66)
			target["owner"] = strings.Repeat("a", 39)
			if scope == "organization" {
				target["selected_repository_ids"] = []uint64{1, ^uint64(0)}
			} else {
				target["repository"] = strings.Repeat("a", 100)
			}
			if scope == "environment" {
				target["environment"] = strings.Repeat("a", 255)
			}
			input["github_output_targets"] = map[string]any{scope: target}
			if _, err := loadOutputEnvironment(t, path, input); err != nil {
				t.Fatal("independent optional scope or exact bound refused", err)
			}
		})
	}
	for _, field := range []string{"github_output_targets"} {
		t.Run(field+"-null", func(t *testing.T) {
			path, input := mixedOutputInput(t, "aws")
			input[field] = nil
			if _, err := loadOutputEnvironment(t, path, input); err == nil {
				t.Fatal("explicit null output input accepted")
			}
		})
	}
	t.Run("github-generator-route", func(t *testing.T) {
		path, input := mixedOutputInput(t, "aws")
		input["generator"] = map[string]any{"account": strings.Repeat("a", 32), "permission_group": strings.Repeat("b", 32), "credentials_file": "github-repository-cleaner", "artifact": "generator-bin"}
		if _, err := loadOutputEnvironment(t, path, input); err == nil {
			t.Fatal("GitHub route reused the generator capability")
		}
	})

	path, input := mixedOutputInput(t, "aws")
	input["mode"], input["provider"] = "hermetic", "memory"
	input["resource"].(map[string]any)["settings"] = map[string]any{}
	if _, err := loadOutputEnvironment(t, path, input); err == nil {
		t.Fatal("hermetic cloud output inputs accepted")
	}
}

// full_only: false
func TestOutputConfigurationRefusesSiblingCloudInput(t *testing.T) {
	path, input := mixedOutputInput(t, "aws")
	targets := map[string]any{}
	for _, name := range []string{"positive", "ambiguity"} {
		target := outputTargetInput("gcp", "secondary-"+name)
		target["secret_name_prefix"] = "projects/123456789012/secrets/enkv-output-" + name + "-"
		targets[name] = target
	}
	input["secondary_output_targets"] = map[string]any{
		"provider": "gcp", "project": "example-project", "project_number": "123456789012",
		"targets": targets,
	}
	if _, err := loadOutputEnvironment(t, path, input); err == nil || err.Error() != "selection file fields refused" {
		t.Fatal("sibling cloud input did not fail at the declared field boundary", err)
	}
}

// full_only: false
func TestOutputConfigurationPlanKeepsPrivateRoutesOutOfRecords(t *testing.T) {
	path, input := mixedOutputInput(t, "aws")
	if _, err := loadOutputEnvironment(t, path, input); err != nil {
		t.Fatal(err)
	}
	suite := filepath.Join(filepath.Dir(path), "suite.json")
	saveSelection(t, suite, suiteFixture("output-input", []string{"state.single-value-update-preserves-other-values/members_1"}))
	request, err := resolveSavedRun([]string{suite}, path, "", "", "disabled", "", "", catalog.SmokeFirstSelectedPoint, 1, false)
	if err != nil {
		t.Fatal("public plan required private output credentials", err)
	}
	var plan bytes.Buffer
	if err := json.NewEncoder(&plan).Encode(runRecord{Resolved: request.Resolved, Execution: recordExecutionPolicy(request.execution), EffectiveTelemetry: request.effectiveTelemetry}); err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{filepath.Dir(path), "credentials_file", "github-repository-writer", "github_output_targets", "selected_repository_ids"} {
		if strings.Contains(plan.String(), private) {
			t.Fatal("private fixture input entered public plan", private)
		}
	}
}
