package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestPublicPublicationSelectionRequiresOnlySelectedScopes(t *testing.T) {
	valid := &records.PublicOutputScopes{
		Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repo"},
		Organization: records.PublicOutputScope{Owner: "org", Visibility: "selected", Repositories: []uint64{101}},
		Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repo", Environment: "prod"},
	}
	for _, provider := range []string{"aws", "gcp"} {
		for _, scenario := range []string{"public-configuration.manifest/atomic_public_file", "public-configuration.output-standalone/output_standalone", records.StockPluginScenario} {
			row, ok := catalog.PublicConfiguration(scenario)
			if !ok {
				t.Fatal("public output case unavailable")
			}
			scopes := row.OutputScopes(provider)
			for _, supplied := range []string{"missing", "valid", "malformed"} {
				t.Run(provider+"/"+row.Condition+"/"+supplied, func(t *testing.T) {
					environment := environmentFile{Mode: "live", Provider: provider}
					environment.Resource.Settings = liveSettings{"region": "region", "account": "123456789012", "project": "fixture-project", "project_number": "123456789012"}
					switch supplied {
					case "valid":
						environment.PublicOutputs = valid
					case "malformed":
						environment.PublicOutputs = &records.PublicOutputScopes{}
					}
					// A one-scope catalog case is cloud-only; all declared mixed
					// public cases select the complete three GitHub scopes.
					admitted := supplied == "valid" || supplied == "missing" && len(scopes) == 1
					schedule := catalog.Schedule{Entries: []catalog.Entry{{Scenario: scenario}}}
					selected, err := selectPublicationOutputs(schedule, environment)
					if (err == nil) != admitted {
						t.Fatal("publication scope inputs do not follow selected destinations", err)
					}
					if admitted {
						if len(selected) != len(scopes) || selected[0].Cloud == nil || selected[0].GitHub != nil || selected[0].Namespace != "public" {
							t.Fatal("cloud scope omitted or given an unrelated GitHub target")
						}
						for i, item := range selected {
							if item.Scope != scopes[i] || i > 0 && item.GitHub == nil {
								t.Fatal("selected output destination changed")
							}
						}
					}
				})
			}
		}
		t.Run(provider+"/mixed-schedule", func(t *testing.T) {
			environment := environmentFile{Mode: "live", Provider: provider, PublicOutputs: valid}
			entries := []catalog.Entry{{Scenario: "public-configuration.empty-initialization/empty_initialization"}, {Scenario: "public-configuration.output-standalone/output_standalone"}}
			for range 2 {
				selected, err := selectPublicationOutputs(catalog.Schedule{Entries: entries}, environment)
				if err != nil || len(selected) != 4 {
					t.Fatal("non-output row rejected shared selected output inputs", err)
				}
				slices.Reverse(entries)
			}
		})
		t.Run(provider+"/cleanup-input", func(t *testing.T) {
			_, _, entry := publicCleanupFixture(t, provider, "enabled")
			input := entry.Input
			if !publicCleanupInputValid(input, provider) {
				t.Fatal("non-output cleanup without output inputs refused")
			}
			input.PublicConfiguration.Outputs = valid
			if publicCleanupInputValid(input, provider) {
				t.Fatal("non-output cleanup carried unrelated output inputs")
			}
			input.Scenarios = []string{"public-configuration.manifest/atomic_public_file"}
			input.Participants["apply"] = "publisher"
			input.PublicConfiguration.Actors["apply"] = maps.Clone(input.Settings)
			input.PublicConfiguration.Outputs = nil
			if !publicCleanupInputValid(input, provider) {
				t.Fatal("cloud-only manifest cleanup required GitHub inputs")
			}
			input.PublicConfiguration.Outputs = &records.PublicOutputScopes{}
			if publicCleanupInputValid(input, provider) {
				t.Fatal("cloud-only manifest cleanup accepted malformed supplied inputs")
			}
			input.Scenarios = []string{"public-configuration.output-standalone/output_standalone"}
			input.PublicConfiguration.Outputs = nil
			if publicCleanupInputValid(input, provider) {
				t.Fatal("selected GitHub cleanup omitted its input scopes")
			}
			input.PublicConfiguration.Outputs = valid
			if !publicCleanupInputValid(input, provider) {
				t.Fatal("selected GitHub cleanup refused complete input scopes")
			}
		})
	}
}

// full_only: false
func TestPublicationSelectionRequiresExactScopesBeforeCredentials(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			path, raw := mixedOutputInput(t, provider)
			environment, err := loadOutputEnvironment(t, path, raw)
			if err != nil {
				t.Fatal(err)
			}
			schedule, err := catalog.Resolve(catalog.Request{Include: []string{"publication.mixed-destinations/plain1_secret1_initial_noop_delete_mixed4"}, Repetitions: 1})
			if err != nil {
				t.Fatal(err)
			}
			selected, err := selectPublicationOutputs(schedule, environment)
			cloud := "aws-secrets-manager"
			if provider == "gcp" {
				cloud = "gcp-secret-manager"
			}
			want := []string{cloud, "github-repository", "github-organization", "github-environment"}
			if err != nil || len(selected) != len(want) {
				t.Fatal("mixed scope omitted", err)
			}
			for i, item := range selected {
				if item.Scope != want[i] || item.Namespace != "positive" {
					t.Fatal("selected scope substituted")
				}
			}
			bindings, err := publicationAssemblyBindings(strings.Repeat("a", 32), selected)
			if err != nil || len(bindings) != 4 {
				t.Fatal("selected native artifacts omitted", err)
			}
			before, err := json.Marshal(selected)
			if err != nil {
				t.Fatal(err)
			}
			g := environment.GitHubOutputTargets
			g.Organization.SelectedRepositoryIDs[0] = 99
			c := environment.OutputTargets["positive"]
			c.Consumers["consumer_a"] = outputActorReference{}
			after, err := json.Marshal(selected)
			if err != nil || string(before) != string(after) {
				t.Fatal("selection retained mutable borrowed input")
			}
			for _, field := range []string{"credentials_file", "consumer_a", "secret_name_prefix"} {
				public, err := json.Marshal(selected[0].resolvedOutputScope)
				if err != nil || strings.Contains(string(public), field) {
					t.Fatal("private routing entered public plan")
				}
			}
			g.Environment = nil
			if _, err := selectPublicationOutputs(schedule, environment); err == nil {
				t.Fatal("missing required scope admitted")
			}
		})
	}
}

// full_only: false
func TestPublicationSelectionRefusesTwoNamespacesForOneArtifact(t *testing.T) {
	path, raw := mixedOutputInput(t, "aws")
	environment, err := loadOutputEnvironment(t, path, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"aws-secrets-manager", "github-repository", "github-organization", "github-environment"} {
		child := "plain1_secret1_create_value_delete"
		if scope == "github-organization" {
			child = "plain1_secret1_create_value_policy_delete"
		}
		if scope == "github-repository" || scope == "github-environment" {
			child = "plain1_secret1_create_value_inherited_policy_delete"
		}
		schedule, err := catalog.Resolve(catalog.Request{Include: []string{"publication." + scope + ".plain-secret-lifecycle/" + child, "publication." + scope + ".later-member-refusal/plain1_secret1_first_target_ack_later_not_sent"}, Repetitions: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := selectPublicationOutputs(schedule, environment); err == nil {
			t.Fatal("one artifact acquired alternate writer namespace", scope)
		}
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{"publication.gcp-secret-manager.plain-secret-lifecycle/plain1_secret1_create_value_delete"}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectPublicationOutputs(schedule, environment); err == nil {
		t.Fatal("sibling SDK scope admitted")
	}
}

// full_only: false
func TestPublicationArtifactBindingsKeepStablePublicRecipeFacts(t *testing.T) {
	path, raw := mixedOutputInput(t, "aws")
	environment, err := loadOutputEnvironment(t, path, raw)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{"publication.mixed-destinations/plain1_secret1_initial_noop_delete_mixed4"}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectPublicationOutputs(schedule, environment)
	if err != nil {
		t.Fatal(err)
	}
	first, err := publicationAssemblyBindings(strings.Repeat("a", 32), selected)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", first[0].DescriptorID) != "f1c462b07394555dd7a2d602b48c678bb2b2f8901310cff5713a972fbc43d6c0" || fmt.Sprintf("%x", first[0].CredentialRouteID) != "6a9e5b236a8b4fcd66b1149679e1d77cf791bda023676896859e2db8e0f83f90" || first[0].ConfigContractID != "ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1" || first[0].CredentialRouteContractID != "693c9548d6df16ead6cae7ad84b1363fa256413fc10bfe311090830ff18dc667" || fmt.Sprintf("%x", first[1].DescriptorID) != "6d408c7dd0ba3961f49eabe25646e5cd490655f328d22ea3bb8793af79b1b745" || fmt.Sprintf("%x", first[1].CredentialRouteID) != "87cfb42eb2de2607a1074fb863fdecbc2ee89d15da619b67fbedb274445695af" {
		t.Fatal("qualification descriptor/route identities differ", first)
	}
	selected[0].Cloud.Writer.CredentialsFile = "private-other-path"
	selected[0].Cloud.Consumers["consumer_a"] = outputActorReference{Principal: selected[0].Cloud.Consumers["consumer_a"].Principal, CredentialsFile: "other-consumer"}
	selected[1].GitHub.Writer.CredentialsFile = "other-github-writer"
	second, err := publicationAssemblyBindings(strings.Repeat("a", 32), selected)
	if err != nil || !slices.Equal(first, second) {
		t.Fatal("binding included credential file reference")
	}
	selected[1].GitHub.Repository = "different-repository"
	third, err := publicationAssemblyBindings(strings.Repeat("a", 32), selected)
	if err != nil || !slices.Equal(third, first) {
		t.Fatal("fixture target changed stable family recipe facts")
	}
	fourth, err := publicationAssemblyBindings(strings.Repeat("b", 32), selected)
	if err != nil || !slices.Equal(fourth, third) {
		t.Fatal("fixture run changed stable family recipe facts")
	}
}
