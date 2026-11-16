package main

import (
	catalog "enkv.sh/core/internal/testcatalog"
	"os"
	"path/filepath"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestActorIdentityChecksContentAndOriginInsteadOfPaths(t *testing.T) {
	root, _, _ := savedSelectionFixture(t)
	writerPath, readerPath := filepath.Join(root, "writer.json"), filepath.Join(root, "reader.json")
	writer := serviceAccountIdentity{Type: "service_account", Project: "writer-project", ClientEmail: "writer@writer-project.iam.gserviceaccount.com", ClientID: "123456789012345678901"}
	if records.WriteJSON(writerPath, writer, 0600) != nil {
		t.Fatal("writer identity fixture failed")
	}
	for _, test := range []struct {
		name                   string
		reader                 serviceAccountIdentity
		wantValid, wantOrigins bool
	}{
		{"same identity in other file", writer, false, false},
		{"distinct identities and origins", serviceAccountIdentity{Type: "service_account", Project: "reader-project", ClientEmail: "reader@reader-project.iam.gserviceaccount.com", ClientID: "234567890123456789012"}, true, true},
		{"distinct identities same origin", serviceAccountIdentity{Type: "service_account", Project: "writer-project", ClientEmail: "reader@writer-project.iam.gserviceaccount.com", ClientID: "234567890123456789012"}, true, false},
		{"origin disagrees with email", serviceAccountIdentity{Type: "service_account", Project: "false-project", ClientEmail: "reader@reader-project.iam.gserviceaccount.com", ClientID: "234567890123456789012"}, false, false},
		{"same client ID", serviceAccountIdentity{Type: "service_account", Project: "reader-project", ClientEmail: "reader@reader-project.iam.gserviceaccount.com", ClientID: writer.ClientID}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if records.WriteJSON(readerPath, test.reader, 0600) != nil {
				t.Fatal("reader identity fixture failed")
			}
			evidence, err := verifyGCPActorIdentities(writerPath, readerPath)
			if (err == nil) != test.wantValid {
				t.Fatalf("identity admission differs: %v", err)
			}
			if err == nil && (!evidence.DistinctIdentities || evidence.DistinctOrigins != test.wantOrigins) {
				t.Fatal("identity/origin evidence differs")
			}
		})
	}
}

// full_only: false
func TestRunLoadsOnlyResolvedParticipantCredentials(t *testing.T) {
	for _, test := range []struct {
		name, scenario                       string
		reuse, sameIdentity, missingObserver bool
		accepted                             bool
	}{
		{name: "authority ignores unused recipient", scenario: "state.single-value-update-preserves-other-values/members_32", accepted: true},
		{name: "observer uses its own credentials", scenario: "access.observer-sees-selected-state/members_32_observer", accepted: true},
		{name: "roles reuse credentials", scenario: "access.observer-sees-selected-state/members_32_observer", reuse: true, accepted: true},
		{name: "same principal allowed", scenario: "access.observer-sees-selected-state/members_32_observer", sameIdentity: true, accepted: true},
		{name: "distinct principal required", scenario: "access.distinct-observer-sees-selected-state/members_32_distinct_observer", sameIdentity: true},
		{name: "distinct principals accepted", scenario: "access.distinct-observer-sees-selected-state/members_32_distinct_observer", accepted: true},
		{name: "missing observer has no fallback", scenario: "access.observer-sees-selected-state/members_32_observer", missingObserver: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, suite, path := savedSelectionFixture(t)
			_, settings := configurationFixture(t, "gcp")
			authorityPath, observerPath := filepath.Join(root, "operator.json"), filepath.Join(root, "auditor.json")
			authority := serviceAccountIdentity{Type: "service_account", Project: "example-project", ClientEmail: "operator@example-project.iam.gserviceaccount.com", ClientID: "123456789012345678901"}
			observer := authority
			if !test.sameIdentity {
				observer.ClientEmail = "auditor@example-project.iam.gserviceaccount.com"
				observer.ClientID = "234567890123456789012"
			}
			saveSelection(t, authorityPath, authority)
			if !test.missingObserver {
				saveSelection(t, observerPath, observer)
			}
			settings["credentials_file"] = authorityPath
			env := environmentFor(settings)
			env.Participants["auditor"] = participantReference{Access: accessReference{CredentialsFile: observerPath}}
			env.Participants["unused-recipient"] = participantReference{Access: accessReference{CredentialsFile: filepath.Join(root, "absent"), CredentialExpires: "2000-01-01T00:00:00Z"}}
			env.RoleBindings["observer"] = "auditor"
			if test.reuse {
				env.RoleBindings["observer"] = "operator"
			}
			saveSelection(t, path, env)
			saveSelection(t, suite, suiteFixture("routing", []string{test.scenario}))
			request, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", path})
			if err != nil {
				t.Fatal(err)
			}
			loaded, identities, err := loadRunSettings(request)
			writer, reader := loaded["authority"], loaded["observer"]
			if (err == nil) != test.accepted {
				t.Fatal("credential admission differs", err)
			}
			if test.accepted {
				if writer["credentials_file"] != authorityPath {
					t.Fatal("authority credential route changed")
				}
				if catalog.HasFixtureCapability(test.scenario, catalog.FixtureObserver) {
					want := observerPath
					if test.reuse {
						want = authorityPath
					}
					if reader["credentials_file"] != want {
						t.Fatal("wrong observer route")
					}
				} else if reader != nil {
					t.Fatal("unused participant was loaded")
				}
				definition, _ := catalog.DefinitionFor(test.scenario)
				if (identities != nil) != definition.DistinctParticipants {
					t.Fatal("unexpected identity proof requirement")
				}
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("credential admission caused fixture effects")
			}
		})
	}
}

// full_only: false
func TestFirstFlowLoadsOnlySelectedActorRoutes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				settings := firstFlowConfigurationFixture(t, provider, mode)
				env := environmentFor(settings)
				root, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				roles := []string{"authority", "reader", "denied-reader"}
				if mode == "enabled" {
					roles = append(roles, "recovery")
				}
				resolved := &resolvedRequest{RoleBindings: map[string]string{}}
				for _, role := range roles {
					name := role
					if role == "authority" {
						name = "operator"
					}
					path := filepath.Join(root, name+".json")
					if err := os.WriteFile(path, []byte("synthetic credential reference"), 0600); err != nil {
						t.Fatal(err)
					}
					access := accessReference{CredentialsFile: path}
					if provider == "aws" {
						access.Profile = "enkv-" + name
					}
					env.Participants[name] = participantReference{Access: access}
					env.RoleBindings[role], resolved.RoleBindings[role] = name, name
					resolved.Participants = append(resolved.Participants, name)
				}
				env.Participants["unused"] = participantReference{Access: accessReference{CredentialsFile: filepath.Join(root, "absent")}}
				request := runRequest{Provider: provider, environment: &env, Resolved: resolved}
				loaded, evidence, err := loadRunSettings(request)
				if err != nil || evidence != nil || len(loaded) != len(roles) {
					t.Fatalf("ordinary actor routes refused: %v", err)
				}
				for _, role := range roles {
					if loaded[role]["credentials_file"] != env.Participants[resolved.RoleBindings[role]].Access.CredentialsFile {
						t.Fatalf("actor route differs: %s", role)
					}
					if !sameResources(loaded["authority"], loaded[role]) {
						t.Fatal("actor resource binding differs")
					}
				}
				denied := env.RoleBindings["denied-reader"]
				original := env.Participants[denied]
				env.Participants[denied] = env.Participants["operator"]
				if _, _, err := loadRunSettings(request); err == nil {
					t.Fatal("denied reader fell back to authority route")
				}
				env.Participants[denied] = original
				if err := os.Remove(original.Access.CredentialsFile); err != nil {
					t.Fatal(err)
				}
				if _, _, err := loadRunSettings(request); err == nil {
					t.Fatal("denied reader admitted missing credentials")
				}
			})
		}
	}
}

// full_only: false
func TestObserverCasesUseSeparateAllowedAndDeniedCredentials(t *testing.T) {
	for _, condition := range []string{"separate", "missing-role", "missing-file", "authority-binding", "observer-binding", "authority-identity", "observer-identity", "mixed-origins"} {
		t.Run(condition, func(t *testing.T) {
			root, suite, path := savedSelectionFixture(t)
			_, settings := configurationFixture(t, "gcp")
			env := environmentFor(settings)
			identities := map[string]serviceAccountIdentity{}
			for index, role := range []string{"authority", "observer", "denied-observer"} {
				identity := serviceAccountIdentity{Type: "service_account", Project: "example-project", ClientEmail: role + "@example-project.iam.gserviceaccount.com", ClientID: []string{"123456789012345678901", "234567890123456789012", "345678901234567890123"}[index]}
				if condition == "mixed-origins" && role == "observer" {
					identity.Project, identity.ClientEmail = "observer-project", "observer@observer-project.iam.gserviceaccount.com"
				}
				identities[role] = identity
				credential := filepath.Join(root, role+".json")
				saveSelection(t, credential, identity)
				env.RoleBindings[role] = role
				env.Participants[role] = participantReference{Access: accessReference{CredentialsFile: credential}}
			}
			denied := env.Participants["denied-observer"].Access.CredentialsFile
			switch condition {
			case "missing-role":
				delete(env.RoleBindings, "denied-observer")
			case "missing-file":
				if err := os.Remove(denied); err != nil {
					t.Fatal(err)
				}
			case "authority-binding":
				env.RoleBindings["denied-observer"] = "authority"
			case "observer-binding":
				env.RoleBindings["denied-observer"] = "observer"
			case "authority-identity":
				saveSelection(t, denied, identities["authority"])
			case "observer-identity":
				saveSelection(t, denied, identities["observer"])
			}
			saveSelection(t, path, env)
			saveSelection(t, suite, suiteFixture("observers", []string{
				"access.observer-sees-selected-state/members_32_observer", "access.distinct-observer-sees-selected-state/members_32_distinct_observer", "access.provider-refuses-observer/members_32_denied_observer",
			}))
			request, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", path})
			var loaded map[string]liveSettings
			var evidence *actorIdentityEvidence
			if err == nil {
				loaded, evidence, err = loadRunSettings(request)
			}
			want := condition == "separate" || condition == "mixed-origins"
			if (err == nil) != want {
				t.Fatal("observer credential admission differs", err)
			}
			if want && (loaded["denied-observer"]["credentials_file"] != denied || loaded["observer"]["credentials_file"] == denied || evidence == nil || !evidence.DistinctIdentities || evidence.DistinctOrigins) {
				t.Fatal("observer roles or combined identity evidence differ")
			}
		})
	}
}

// full_only: false
func TestConfigurationRecoverySelectionLoadsProcessActorRoutes(t *testing.T) {
	canonical := savedWorkflowPath(t, "canonical")
	suite := filepath.Join(filepath.Dir(filepath.Dir(canonical)), "suites/configuration-recovery.json")
	for _, provider := range []string{"gcp", "aws"} {
		for _, mode := range []string{"disabled", "enabled"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				root, _, path := savedSelectionFixture(t)
				env, _ := replacementEnvironmentFixture(t, provider, mode)
				env.Resource.Settings["normal_successor_2_key_id"] = "second-normal-key"
				env.Resource.Settings["normal_successor_2_public_key_pem"] = "-----BEGIN PUBLIC KEY-----\nsynthetic-second-normal\n-----END PUBLIC KEY-----"
				for _, role := range []string{"normal-signer-2", "reader", "denied-observer", "denied-reader"} {
					env.RoleBindings[role] = role
					access := accessReference{}
					if provider == "aws" {
						access.Profile = "enkv-" + role
					}
					env.Participants[role] = participantReference{Access: access}
				}
				for name, participant := range env.Participants {
					participant.Access.CredentialsFile = filepath.Join(root, name+".json")
					if err := os.WriteFile(participant.Access.CredentialsFile, []byte("synthetic credential reference"), 0600); err != nil {
						t.Fatal(err)
					}
					env.Participants[name] = participant
				}
				env.Participants["unused"] = participantReference{Access: accessReference{CredentialsFile: filepath.Join(root, "absent")}}
				saveSelection(t, path, env)
				request, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", path, "--recovery-mode", mode})
				if err != nil {
					t.Fatal(err)
				}
				sawComplete, sawOther := false, false
				for _, entry := range request.Schedule.Entries {
					if _, recovery := catalog.ConfigurationRecovery(entry.Scenario); !recovery {
						continue
					}
					execution, known := catalog.ExecutionFor(entry.Scenario, request.Suite)
					if !known || execution.Family != catalog.FamilyConfigurationRecovery || len(execution.FreshAfter) != 0 || len(execution.Process) == 0 {
						t.Fatal("selection lacks the process-only recovery regression")
					}
					sawComplete = sawComplete || entry.Scenario == "reconstruction.complete/complete_loss_complete"
					sawOther = sawOther || entry.Scenario == "reconstruction.zero-secret-genesis/complete_loss_zero_secret_genesis"
				}
				if !sawComplete || !sawOther {
					t.Fatal("saved recovery suite did not select both required cases")
				}
				var loaded map[string]liveSettings
				var evidence *actorIdentityEvidence
				func() {
					defer func() {
						if value := recover(); value != nil {
							t.Errorf("valid process-only actor selection panicked: %T", value)
						}
					}()
					loaded, evidence, err = loadRunSettings(request)
				}()
				if err != nil || evidence != nil || len(loaded) != len(request.Resolved.RoleBindings) {
					t.Fatalf("process actor routes refused or identity proof added: %v", err)
				}
				for role, participant := range request.Resolved.RoleBindings {
					if loaded[role]["credentials_file"] != env.Participants[participant].Access.CredentialsFile {
						t.Fatalf("selected route changed: %s", role)
					}
				}
				if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
					t.Fatal("actor admission caused fixture effects")
				}
			})
		}
	}
}

// full_only: false
func TestObserverPairInitializesIdentityEvidence(t *testing.T) {
	root, _, _ := savedSelectionFixture(t)
	_, settings := configurationFixture(t, "gcp")
	env := environmentFor(settings)
	resolved := &resolvedRequest{RoleBindings: map[string]string{"authority": "operator"}, Participants: []string{"operator"}}
	for index, role := range []string{"authority", "observer", "denied-observer"} {
		name := role
		if role == "authority" {
			name = "operator"
		}
		path := filepath.Join(root, name+".json")
		saveSelection(t, path, serviceAccountIdentity{Type: "service_account", Project: "example-project", ClientEmail: role + "@example-project.iam.gserviceaccount.com", ClientID: []string{"123456789012345678901", "234567890123456789012", "345678901234567890123"}[index]})
		env.Participants[name] = participantReference{Access: accessReference{CredentialsFile: path}}
		env.RoleBindings[role], resolved.RoleBindings[role] = name, name
		if role != "authority" {
			resolved.Participants = append(resolved.Participants, name)
		}
	}
	loaded, evidence, err := loadRunSettings(runRequest{Provider: "gcp", environment: &env, Resolved: resolved})
	if err != nil || len(loaded) != 3 || evidence == nil || !evidence.DistinctIdentities || evidence.DistinctOrigins {
		t.Fatal("observer-only identity evidence was not initialized", err)
	}
}
