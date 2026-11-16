package main

import (
	"maps"
	"path/filepath"
	"testing"
)

const operatorReplacementCase = "public-configuration.keys-replace-operator-both/keys_replace_operator_both"
const operatorDiscoveryCase = "public-configuration.credential-discovery/credential_discovery"

func operatorReplacementEnvironment(t *testing.T, mode string) environmentFile {
	t.Helper()
	var env environmentFile
	if err := readSelectionFile(filepath.Join(maintainedCloudflareRoot(t), "tests/environments/public-operator-"+mode+".example.json"), &env); err != nil {
		t.Fatal(err)
	}
	return env
}
func operatorReplacementRequest(t *testing.T, env environmentFile, name string) (runRequest, error) {
	t.Helper()
	dir := t.TempDir()
	suite, path := filepath.Join(dir, "public-configuration-operator.json"), filepath.Join(dir, "environment.json")
	saveSelection(t, suite, suiteFixture("public-configuration-operator", []string{name}))
	saveSelection(t, path, env)
	return resolveSavedRun([]string{suite}, path, "", filepath.Join(maintainedCloudflareRoot(t), "tests/live/limits/authority-operator.json"), "disabled", "", "", "", 1, false)
}
func operatorReplacementCleanupInput(t *testing.T, request runRequest, name string) workerInput {
	t.Helper()
	actors, identities, err := loadRunSettings(request)
	if err != nil || identities != nil {
		t.Fatal("one operator settings unavailable", err)
	}
	participants, err := request.Resolved.scenarioParticipants(name)
	if err != nil || len(participants) != 5 || len(actors) != 5 {
		t.Fatal("one operator participant recheck refused", err)
	}
	for _, participant := range participants {
		if participant != participants["authority"] {
			t.Fatal("operator roles selected different principals")
		}
	}
	return workerInput{Settings: actors["authority"], RecoveryMode: "disabled", Scenarios: []string{name}, Participants: participants, PublicConfiguration: &publicConfigurationInput{Actors: actors}}
}

// full_only: false
func TestPublicOperatorSDKContextAdmitsDiscoveryAndReplacement(t *testing.T) {
	for _, mode := range []string{"aws-shared-credentials", "aws-sso", "gcp-user-adc", "gcp-service-account-adc"} {
		for _, name := range []string{operatorDiscoveryCase, operatorReplacementCase} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				env := operatorReplacementEnvironment(t, mode)
				request, err := operatorReplacementRequest(t, env, name)
				if err != nil {
					t.Fatal("declared one-operator SDK context refused before credential discovery", err)
				}
				input := operatorReplacementCleanupInput(t, request, name)
				if !publicCleanupInputValid(input, env.Provider) {
					t.Fatal("exact one-operator cleanup context refused")
				}
			})
		}
	}
}

// full_only: false
func TestPublicOperatorSDKContextKeepsStrictPrincipalAndCleanupChecks(t *testing.T) {
	for _, mode := range []string{"aws-shared-credentials", "aws-sso", "gcp-user-adc", "gcp-service-account-adc"} {
		t.Run(mode, func(t *testing.T) {
			t.Run("split-principal", func(t *testing.T) {
				env := operatorReplacementEnvironment(t, mode)
				env.Participants["second"] = env.Participants[env.RoleBindings["authority"]]
				env.RoleBindings["reader"] = "second"
				if _, err := operatorReplacementRequest(t, env, operatorReplacementCase); err == nil {
					t.Fatal("operator replacement admitted another principal")
				}
			})
			t.Run("assumed-or-impersonated", func(t *testing.T) {
				env := operatorReplacementEnvironment(t, mode)
				name := env.RoleBindings["authority"]
				actor := env.Participants[name]
				sdk := *actor.Access.SDK
				if env.Provider == "aws" {
					sdk.Mode = "aws-assume-role"
				} else {
					sdk.Mode = "gcp-impersonated-adc"
					sdk.CredentialsFile = ""
					sdk.QuotaProject = env.Resource.Settings["quota_project"]
				}
				actor.Access.SDK = &sdk
				env.Participants[name] = actor
				if _, err := operatorReplacementRequest(t, env, operatorReplacementCase); err == nil {
					t.Fatal("operator replacement admitted a restricted functional source")
				}
			})
			t.Run("ordinary-still-distinct", func(t *testing.T) {
				env := operatorReplacementEnvironment(t, mode)
				if _, err := operatorReplacementRequest(t, env, "public-configuration.keys-replace-authority-both-by-authority/keys_replace_authority_both_by_authority"); err == nil {
					t.Fatal("ordinary replacement lost its distinct-participant requirement")
				}
			})
			t.Run("cleanup-exact-role-context", func(t *testing.T) {
				env := operatorReplacementEnvironment(t, mode)
				request, err := operatorReplacementRequest(t, env, operatorReplacementCase)
				if err != nil {
					t.Fatal(err)
				}
				input := operatorReplacementCleanupInput(t, request, operatorReplacementCase)
				if !publicCleanupInputValid(input, env.Provider) {
					t.Fatal("valid cleanup refused")
				}
				actor := maps.Clone(input.PublicConfiguration.Actors["reader"])
				actor["sdk_home"] = "/ABSOLUTE/OTHER/OPERATOR"
				input.PublicConfiguration.Actors["reader"] = actor
				if publicCleanupInputValid(input, env.Provider) {
					t.Fatal("cleanup admitted another SDK context behind the same role principal")
				}
				input = operatorReplacementCleanupInput(t, request, operatorReplacementCase)
				input.Participants["reader"] = "second"
				if publicCleanupInputValid(input, env.Provider) {
					t.Fatal("cleanup admitted another role principal")
				}
			})
		})
	}
}
