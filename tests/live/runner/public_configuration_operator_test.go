package core

import "testing"

// full_only: false
func TestPublicOperatorAdmissionKeepsOneSelectedContext(t *testing.T) {
	for _, mode := range []string{"gcp-user-adc", "gcp-service-account-adc", "aws-shared-credentials", "aws-sso"} {
		t.Run(mode, func(t *testing.T) {
			provider := "aws"
			if mode == "gcp-user-adc" || mode == "gcp-service-account-adc" {
				provider = "gcp"
			}
			settings := liveSettings{SDKMode: mode, SDKHome: "/isolated/operator", Provider: provider, RecoveryMode: "disabled"}
			if provider == "aws" {
				settings.SDKProfile = "operator"
			} else {
				settings.QuotaProject = "quota-project"
			}
			if mode == "gcp-service-account-adc" {
				settings.SDKCredentialsFile = "/existing/service-account.json"
				settings.SDKQuotaProject = "quota-project"
			}
			makeInput := func() liveRunInput {
				input := liveRunInput{Settings: settings, RecoveryMode: "disabled", Scenarios: []string{"public-configuration.credential-discovery/credential_discovery"}, Participants: map[string]string{}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{}}}
				for _, role := range []string{"authority", "apply", "reader", "consumer", "cleanup"} {
					input.Participants[role] = "operator"
					input.PublicConfiguration.Actors[role] = settings
				}
				return input
			}
			if !livePublicConfigurationAdmitted(makeInput()) {
				t.Fatal("one operator source was refused")
			}
			for _, damage := range []string{"participant", "home", "quota", "source"} {
				t.Run(damage, func(t *testing.T) {
					input := makeInput()
					actor := input.PublicConfiguration.Actors["reader"]
					switch damage {
					case "participant":
						input.Participants["reader"] = "another-operator"
					case "home":
						actor.SDKHome = "/another/operator"
					case "quota":
						actor.SDKQuotaProject = "other-quota"
					case "source":
						if provider == "aws" {
							actor.SDKMode = "aws-assume-role"
						} else {
							actor.SDKMode = "gcp-impersonated-adc"
						}
					}
					input.PublicConfiguration.Actors["reader"] = actor
					if livePublicConfigurationAdmitted(input) {
						t.Fatal("operator admission changed selected source or principal")
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicFunctionalAdmissionRequiresEveryImpersonatedQuota(t *testing.T) {
	for _, role := range []string{"authority", "reader", "cleanup"} {
		for _, quota := range []string{"selected-project", "", "another-project"} {
			t.Run(role+"/quota="+quota, func(t *testing.T) {
				settings := liveSettings{SDKMode: "gcp-impersonated-adc", SDKHome: "/isolated/functional", SDKQuotaProject: "selected-project", QuotaProject: "selected-project", Provider: "gcp", RecoveryMode: "disabled"}
				input := liveRunInput{Settings: settings, RecoveryMode: "disabled", Scenarios: []string{"public-configuration.empty-initialization/empty_initialization"}, Participants: map[string]string{}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{}}}
				for _, name := range []string{"authority", "reader", "cleanup"} {
					input.Participants[name] = name
					input.PublicConfiguration.Actors[name] = settings
				}
				actor := input.PublicConfiguration.Actors[role]
				actor.SDKQuotaProject = quota
				input.PublicConfiguration.Actors[role] = actor
				input.Settings = input.PublicConfiguration.Actors["authority"]
				if livePublicConfigurationAdmitted(input) != (quota == "selected-project") {
					t.Fatal("functional admission lost exact per-actor impersonated quota")
				}
			})
		}
	}
}

// full_only: false
func TestPublicAuthorityOperatorSDKAdmissionUsesDeclaredRoles(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, row := range []struct {
			name, scenario, mode string
			successor            bool
		}{
			{"end-disabled", "operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt", "disabled", false},
			{"end-enabled", "operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt", "enabled", false},
			{"restore", publicOperatorReplacementScenario, "enabled", true},
			{"restore-disabled", publicOperatorDisabledScenario, "disabled", false},
		} {
			t.Run(provider+"/"+row.name, func(t *testing.T) {
				makeInput := func() liveRunInput {
					settings := liveSettings{Provider: provider, RecoveryMode: row.mode, SDKMode: "aws-assume-role", SDKHome: "/isolated/administrative", SDKProfile: "selected"}
					if provider == "gcp" {
						settings.SDKMode, settings.SDKProfile, settings.SDKQuotaProject, settings.QuotaProject = "gcp-impersonated-adc", "", "selected-project", "selected-project"
					}
					if row.successor {
						settings.NormalSuccessorKeyID = "independent-successor"
					}
					input := liveRunInput{Settings: settings, RecoveryMode: row.mode, Scenarios: []string{row.scenario}, Participants: map[string]string{}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{}}}
					for _, role := range []string{"authority", "reader", "cleanup", "recipient-consumer"} {
						input.Participants[role], input.PublicConfiguration.Actors[role] = role, settings
					}
					if row.successor {
						input.Participants["successor"], input.PublicConfiguration.Actors["successor"] = "successor", settings
					}
					return input
				}
				if !livePublicConfigurationAdmitted(makeInput()) {
					t.Fatal("declared administrative SDK roles were refused")
				}
				for role := range makeInput().PublicConfiguration.Actors {
					input := makeInput()
					delete(input.PublicConfiguration.Actors, role)
					if livePublicConfigurationAdmitted(input) {
						t.Fatal("administrative admission accepted a missing declared role", role)
					}
				}
				if row.successor {
					input := makeInput()
					input.Settings.NormalSuccessorKeyID = ""
					for role, actor := range input.PublicConfiguration.Actors {
						actor.NormalSuccessorKeyID = ""
						input.PublicConfiguration.Actors[role] = actor
					}
					if livePublicConfigurationAdmitted(input) {
						t.Fatal("enabled restoration omitted the exact successor resource")
					}
				} else {
					input := makeInput()
					input.PublicConfiguration.Actors["successor"] = input.Settings
					input.Participants["successor"] = "unused"
					if livePublicConfigurationAdmitted(input) {
						t.Fatal("unused successor context entered administrative admission")
					}
				}
			})
		}
	}
}
