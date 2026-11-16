package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func outputTargetInput(provider, label string) map[string]any {
	actors := map[string]any{}
	for _, role := range []string{"consumer_a", "consumer_b"} {
		actor := map[string]any{"credentials_file": "output-" + label + "-" + role}
		if provider == "aws" {
			actor["principal"] = "arn:aws:iam::123456789012:user/output-" + label + "-" + role
			actor["profile"] = "enkv-output-" + label + "-" + role
		} else {
			email := fmt.Sprintf("output-%s-%s@example-project.iam.gserviceaccount.com", label, role)
			actor["principal"] = "serviceAccount:" + email
			actor["service_account"] = email
		}
		actors[role] = actor
	}
	writer := map[string]any{"credentials_file": "output-" + label + "-writer"}
	cleaner := map[string]any{"credentials_file": "output-" + label + "-cleaner"}
	target := map[string]any{"consumers": actors}
	if provider == "aws" {
		writer["profile"] = "enkv-output-" + label + "-writer"
		cleaner["profile"] = "enkv-output-" + label + "-cleaner"
		target["region"], target["account"] = "example-region", "123456789012"
		target["secret_name_prefix"], target["version_stage"] = "enkv-output-"+label+"-", "AWSCURRENT"
	} else {
		writer["service_account"] = "output-" + label + "-writer@example-project.iam.gserviceaccount.com"
		cleaner["service_account"] = "output-" + label + "-cleaner@example-project.iam.gserviceaccount.com"
		target["project"], target["project_number"] = "example-project", "123456789012"
		target["secret_name_prefix"], target["version"] = "projects/123456789012/secrets/enkv-output-"+label+"-", "latest"
	}
	target["writer"] = writer
	target["cleaner"] = cleaner
	return target
}

func outputEnvironmentInput(t *testing.T, provider string) (string, map[string]any) {
	t.Helper()
	path, settings := configurationFixture(t, provider)
	body, err := json.Marshal(environmentFor(settings))
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(body, &input); err != nil {
		t.Fatal(err)
	}
	input["output_targets"] = map[string]any{
		"positive":  outputTargetInput(provider, "positive"),
		"ambiguity": outputTargetInput(provider, "ambiguity"),
	}
	return path, input
}

func loadOutputEnvironment(t *testing.T, path string, input map[string]any) (environmentFile, error) {
	t.Helper()
	if err := records.WriteJSON(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var env environmentFile
	if err := readSelectionFile(path, &env); err != nil {
		return env, err
	}
	return env, validateEnvironment(&env, filepath.Dir(path))
}

// full_only: false
func TestOutputTargetsAreOptionalAndStayOutsideStateWorkerRoutes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			path, input := outputEnvironmentInput(t, provider)
			delete(input, "output_targets")
			if _, err := loadOutputEnvironment(t, path, input); err != nil {
				t.Fatal("disabled output targets changed state fixture", err)
			}
			input["output_targets"] = map[string]any{"positive": outputTargetInput(provider, "positive"), "ambiguity": outputTargetInput(provider, "ambiguity")}
			env, err := loadOutputEnvironment(t, path, input)
			if err != nil {
				t.Fatal("complete output targets refused", err)
			}
			if err := validateEnvironment(&env, filepath.Dir(path)); err != nil {
				t.Fatal("resolved output targets changed on a second validation", err)
			}
			if len(env.OutputTargets) != 2 {
				t.Fatal("complete output fixture was not retained")
			}
			settings, err := env.settingsFor("operator")
			if err != nil || strings.Contains(fmt.Sprint(settings), "output-") || len(env.Participants) != 1 || len(env.RoleBindings) != 1 {
				t.Fatal("output-only actor entered state worker routes", err)
			}
			for _, name := range []string{"positive", "ambiguity"} {
				if !filepath.IsAbs(env.OutputTargets[name].Writer.CredentialsFile) ||
					env.OutputTargets[name].Writer.CredentialsFile == settings["credentials_file"] {
					t.Fatal("output writer did not retain a separate local route")
				}
				cleaner := env.OutputTargets[name].Cleaner
				if cleaner.CredentialsFile != filepath.Join(filepath.Dir(path), "output-"+name+"-cleaner") ||
					cleaner.Principal != "" || cleaner.CredentialsFile == settings["credentials_file"] {
					t.Fatal("output cleaner did not retain its separate nonconsumer route")
				}
				for _, role := range []string{"writer", "cleaner", "consumer_a", "consumer_b"} {
					path := filepath.Join(filepath.Dir(path), "output-"+name+"-"+role)
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("output credential was loaded or created during validation", path, err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestOutputTargetsRefuseWrongCloudPartialAndUnknownShape(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			for _, test := range []struct {
				name   string
				change func(map[string]any)
			}{
				{"wrong-cloud", func(targets map[string]any) {
					other := "aws"
					if provider == "aws" {
						other = "gcp"
					}
					targets["positive"] = outputTargetInput(other, "positive")
				}},
				{"missing-target", func(targets map[string]any) { delete(targets, "ambiguity") }},
				{"missing-consumer", func(targets map[string]any) {
					delete(targets["positive"].(map[string]any)["consumers"].(map[string]any), "consumer_b")
				}},
				{"missing-writer-route", func(targets map[string]any) {
					targets["positive"].(map[string]any)["writer"].(map[string]any)["credentials_file"] = ""
				}},
				{"missing-cleaner", func(targets map[string]any) { delete(targets["positive"].(map[string]any), "cleaner") }},
				{"null-cleaner", func(targets map[string]any) { targets["positive"].(map[string]any)["cleaner"] = nil }},
				{"missing-cleaner-route", func(targets map[string]any) {
					delete(targets["positive"].(map[string]any)["cleaner"].(map[string]any), "credentials_file")
				}},
				{"missing-cleaner-cloud-route", func(targets map[string]any) {
					cleaner := targets["positive"].(map[string]any)["cleaner"].(map[string]any)
					delete(cleaner, "profile")
					delete(cleaner, "service_account")
				}},
				{"wrong-cloud-cleaner", func(targets map[string]any) {
					other := "aws"
					if provider == "aws" {
						other = "gcp"
					}
					targets["positive"].(map[string]any)["cleaner"] = outputTargetInput(other, "positive")["cleaner"]
				}},
				{"unknown-cleaner-field", func(targets map[string]any) {
					targets["positive"].(map[string]any)["cleaner"].(map[string]any)["unexpected"] = true
				}},
				{"cleaner-principal", func(targets map[string]any) {
					positive := targets["positive"].(map[string]any)
					positive["cleaner"].(map[string]any)["principal"] = positive["consumers"].(map[string]any)["consumer_a"].(map[string]any)["principal"]
				}},
				{"cleaner-state-route", func(targets map[string]any) {
					targets["positive"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"] = "identity.json"
				}},
				{"cleaner-canonical-state-route", func(targets map[string]any) {
					targets["positive"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"] = "unused/../identity.json"
				}},
				{"cleaner-writer-route", func(targets map[string]any) {
					positive := targets["positive"].(map[string]any)
					positive["cleaner"].(map[string]any)["credentials_file"] = positive["writer"].(map[string]any)["credentials_file"]
				}},
				{"cleaner-consumer-route", func(targets map[string]any) {
					positive := targets["positive"].(map[string]any)
					positive["cleaner"].(map[string]any)["credentials_file"] = positive["consumers"].(map[string]any)["consumer_a"].(map[string]any)["credentials_file"]
				}},
				{"cleaner-other-output-writer-route", func(targets map[string]any) {
					targets["positive"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"] = targets["ambiguity"].(map[string]any)["writer"].(map[string]any)["credentials_file"]
				}},
				{"shared-output-cleaner-route", func(targets map[string]any) {
					targets["ambiguity"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"] = targets["positive"].(map[string]any)["cleaner"].(map[string]any)["credentials_file"]
				}},
				{"unknown-field", func(targets map[string]any) {
					targets["positive"].(map[string]any)["writer"].(map[string]any)["unexpected"] = true
				}},
				{"overlap", func(targets map[string]any) {
					targets["ambiguity"].(map[string]any)["secret_name_prefix"] = targets["positive"].(map[string]any)["secret_name_prefix"]
				}},
				{"state-route", func(targets map[string]any) {
					targets["positive"].(map[string]any)["writer"].(map[string]any)["credentials_file"] = "identity.json"
				}},
				{"consumer-state-route", func(targets map[string]any) {
					targets["positive"].(map[string]any)["consumers"].(map[string]any)["consumer_a"].(map[string]any)["credentials_file"] = "identity.json"
				}},
				{"shared-output-route", func(targets map[string]any) {
					positive := targets["positive"].(map[string]any)
					positive["consumers"].(map[string]any)["consumer_b"].(map[string]any)["credentials_file"] = positive["writer"].(map[string]any)["credentials_file"]
				}},
				{"wrong-owner", func(targets map[string]any) {
					positive := targets["positive"].(map[string]any)
					if provider == "aws" {
						positive["account"] = "999999999999"
					} else {
						positive["project_number"] = "999999999999"
					}
				}},
			} {
				t.Run(test.name, func(t *testing.T) {
					path, input := outputEnvironmentInput(t, provider)
					test.change(input["output_targets"].(map[string]any))
					if _, err := loadOutputEnvironment(t, path, input); err == nil {
						t.Fatal("invalid output target shape accepted")
					}
				})
			}
		})
	}
}

// full_only: false
func TestOutputTargetsRefuseNullAndOtherCapabilityRoutes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			for _, name := range []string{"explicit-null", "generator-route", "cleaner-generator-route"} {
				t.Run(name, func(t *testing.T) {
					path, input := outputEnvironmentInput(t, provider)
					switch name {
					case "explicit-null":
						input["output_targets"] = nil
					case "generator-route", "cleaner-generator-route":
						role := "writer"
						if name == "cleaner-generator-route" {
							role = "cleaner"
						}
						input["generator"] = map[string]any{"account": strings.Repeat("a", 32), "permission_group": strings.Repeat("b", 32), "credentials_file": "output-positive-" + role, "artifact": "generator-bin"}
					}
					if _, err := loadOutputEnvironment(t, path, input); err == nil {
						t.Fatal("malformed output targets or shared capability route accepted")
					}
				})
			}
		})
	}
}

// full_only: false
func TestOutputTargetsKeepDistinctOtherCapabilityRoutes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			path, input := outputEnvironmentInput(t, provider)
			input["generator"] = map[string]any{"account": strings.Repeat("a", 32), "permission_group": strings.Repeat("b", 32), "artifact": "generator-bin"}
			env, err := loadOutputEnvironment(t, path, input)
			if err != nil || env.Generator == nil {
				t.Fatal("separate optional capability routes refused or merged", err)
			}
			if env.Generator.Account != strings.Repeat("a", 32) || env.Generator.PermissionGroup != strings.Repeat("b", 32) || env.Generator.CredentialsFile != "" || env.Generator.Artifact != filepath.Join(filepath.Dir(path), "generator-bin") {
				t.Fatal("optional generator configuration changed", env.Generator)
			}
			if env.OutputTargets["positive"].Writer.CredentialsFile != filepath.Join(filepath.Dir(path), "output-positive-writer") || env.OutputTargets["positive"].Cleaner.CredentialsFile != filepath.Join(filepath.Dir(path), "output-positive-cleaner") {
				t.Fatal("separate output capability routes changed")
			}
			if err := validateEnvironment(&env, filepath.Dir(path)); err != nil {
				t.Fatal("separate capability routes changed on a second validation", err)
			}
		})
	}
}
