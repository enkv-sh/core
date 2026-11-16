package main

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestReplacementCleanupInputClearsEveryRestrictedRoute(t *testing.T) {
	s, roles := replacementConfigurationFixture(t, "aws", "enabled")
	input := workerInput{Settings: s, Participants: map[string]string{"authority": "operator"}, ReplacementSettings: map[string]liveSettings{}}
	for _, role := range roles {
		input.Participants[role] = role
		input.ReplacementSettings[role] = s
	}
	clean := input.authorityOnly()
	body, err := json.Marshal(clean)
	if err != nil || len(clean.Participants) != 1 || clean.ReplacementSettings != nil || strings.Contains(string(body), "replacement_settings") {
		t.Fatal("cleanup retained restricted actor routes")
	}
	if len(input.ReplacementSettings) != len(roles) || len(input.Participants) != len(roles)+1 {
		t.Fatal("cleanup changed writer input")
	}
}

// This fixture records the public fields and role names in the prepared Tofu
// outputs. It does not open any provisioned configuration or credential file.
func replacementConfigurationFixture(t *testing.T, provider, mode string) (liveSettings, []string) {
	t.Helper()
	s := firstFlowConfigurationFixture(t, provider, mode)
	pairs := [][2]string{{"normal_successor_key_id", "normal_successor_public_key_pem"}, {"reader_successor_kek_id", "reader_successor_kek_public_key_pem"}, {"authority_successor_1_kek_id", "authority_successor_1_kek_public_key_pem"}, {"authority_successor_2_kek_id", "authority_successor_2_kek_public_key_pem"}}
	roles := []string{"normal-signer-0", "normal-signer-1", "authority-decrypter-0", "authority-decrypter-1", "authority-decrypter-2", "reader-successor", "replacement-store"}
	if mode == "enabled" {
		pairs = append(pairs, [2]string{"recovery_successor_key_id", "recovery_successor_public_key_pem"}, [2]string{"recovery_successor_1_kek_id", "recovery_successor_1_kek_public_key_pem"}, [2]string{"recovery_successor_2_kek_id", "recovery_successor_2_kek_public_key_pem"})
		roles = append(roles, "recovery-signer-0", "recovery-signer-1", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2")
	}
	for _, pair := range pairs {
		s[pair[0]] = "public-key-" + pair[0]
		s[pair[1]] = "-----BEGIN PUBLIC KEY-----\nsynthetic-" + pair[0] + "\n-----END PUBLIC KEY-----"
	}
	return s, roles
}

// full_only: false
func TestReplacementConfigurationPublicBundle(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				s, _ := replacementConfigurationFixture(t, provider, mode)
				if _, err := validateSettingsFields(s, provider, "/unused"); err != nil {
					t.Fatal("prepared successor output shape refused", err)
				}
				for field := range s {
					if !strings.Contains(field, "successor") {
						continue
					}
					for _, change := range []string{"missing", "malformed"} {
						bad := maps.Clone(s)
						if change == "missing" {
							delete(bad, field)
						} else {
							bad[field] = "bad value"
						}
						if _, err := validateSettingsFields(bad, provider, ""); err == nil {
							t.Fatalf("%s %s accepted", change, field)
						}
					}
					changed := maps.Clone(s)
					changed[field] += "-changed"
					if sameResources(s, changed) || safeRunContext(s).ResourceHashes[field] == safeRunContext(changed).ResourceHashes[field] {
						t.Fatalf("public field %s escaped resource binding", field)
					}
				}
				if mode == "disabled" {
					s["recovery_successor_key_id"] = "public-recovery"
					if _, err := validateSettingsFields(s, provider, ""); err == nil {
						t.Fatal("disabled recovery successor accepted")
					}
				}
			})
		}
	}
}

func replacementEnvironmentFixture(t *testing.T, provider, mode string) (environmentFile, []string) {
	t.Helper()
	s, roles := replacementConfigurationFixture(t, provider, mode)
	e := environmentFor(s)
	if mode == "enabled" {
		roles = append(roles, "recovery")
	}
	for _, role := range roles {
		access := accessReference{CredentialsFile: role + ".json"}
		if provider == "aws" {
			access.Profile = "enkv-" + role
		}
		e.Participants[role] = participantReference{Access: access}
		e.RoleBindings[role] = role
	}
	return e, roles
}

// full_only: false
func TestReplacementEnvironmentRequiresModeApplicableRoutes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			e, roles := replacementEnvironmentFixture(t, provider, mode)
			if err := validateEnvironment(&e, "/absent-credentials"); err != nil {
				t.Fatal(err)
			}
			for _, role := range roles {
				bad := e
				bad.RoleBindings = maps.Clone(e.RoleBindings)
				delete(bad.RoleBindings, role)
				if err := validateEnvironment(&bad, ""); err == nil {
					t.Fatalf("missing %s accepted", role)
				}
			}
			if mode == "disabled" {
				e.RoleBindings["recovery-signer-0"] = "operator"
				if err := validateEnvironment(&e, ""); err == nil {
					t.Fatal("disabled recovery actor accepted")
				}
			}
		}
	}
}

// full_only: false
func TestReplacementLoadsOnlySelectedSeparateRoutes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		e, roles := replacementEnvironmentFixture(t, provider, "enabled")
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		resolved := &resolvedRequest{RoleBindings: map[string]string{"authority": "operator"}, Participants: []string{"operator"}}
		roles = append(roles, "authority")
		for _, role := range roles {
			name := e.RoleBindings[role]
			p := e.Participants[name]
			p.Access.CredentialsFile = filepath.Join(root, name+".json")
			if err := os.WriteFile(p.Access.CredentialsFile, []byte("synthetic credential reference"), 0600); err != nil {
				t.Fatal(err)
			}
			e.Participants[name] = p
			if role != "authority" {
				resolved.Participants = append(resolved.Participants, name)
				resolved.RoleBindings[role] = name
			}
		}
		e.Participants["unused"] = participantReference{Access: accessReference{CredentialsFile: filepath.Join(root, "absent")}}
		request := runRequest{Provider: provider, environment: &e, Resolved: resolved}
		loaded, _, err := loadRunSettings(request)
		if err != nil || len(loaded) != len(roles) {
			t.Fatal("restricted routes refused", err)
		}
		for _, role := range roles {
			if role == "authority" || role == "recovery" {
				continue
			}
			original := e.Participants[role]
			e.Participants[role] = e.Participants["operator"]
			if _, _, err := loadRunSettings(request); err == nil {
				t.Fatalf("%s reused authority credentials", role)
			}
			e.Participants[role] = original
		}
	}
}

// full_only: false
func TestSecondNormalSignerConfigurationIsOptionalAndIndependent(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			original, _ := replacementConfigurationFixture(t, provider, "disabled")
			if _, err := validateSettingsFields(original, provider, ""); err != nil {
				t.Fatal("one successor refused", err)
			}
			next := maps.Clone(original)
			next["normal_successor_2_key_id"] = "second-normal-key"
			next["normal_successor_2_public_key_pem"] = "-----BEGIN PUBLIC KEY-----\nsecond-independent-key\n-----END PUBLIC KEY-----"
			if _, err := validateSettingsFields(next, provider, ""); err != nil {
				t.Fatal("second successor refused", err)
			}
			for _, change := range []string{"missing-id", "missing-public", "alias-id", "alias-public"} {
				t.Run(change, func(t *testing.T) {
					bad := maps.Clone(next)
					switch change {
					case "missing-id":
						delete(bad, "normal_successor_2_key_id")
					case "missing-public":
						delete(bad, "normal_successor_2_public_key_pem")
					case "alias-id":
						bad["normal_successor_2_key_id"] = bad["normal_successor_key_id"]
					case "alias-public":
						bad["normal_successor_2_public_key_pem"] = bad["normal_successor_public_key_pem"]
					}
					if _, err := validateSettingsFields(bad, provider, ""); err == nil {
						t.Fatal("non-independent second signer accepted")
					}
				})
			}
			environment, _ := replacementEnvironmentFixture(t, provider, "disabled")
			environment.Resource.Settings = next
			if validateEnvironment(&environment, "") == nil {
				t.Fatal("second signer accepted without participant")
			}
			access := accessReference{CredentialsFile: "normal-signer-2.json"}
			if provider == "aws" {
				access.Profile = "normal-signer-2"
			}
			environment.Participants["normal-signer-2"] = participantReference{Access: access}
			environment.RoleBindings["normal-signer-2"] = "normal-signer-2"
			if err := validateEnvironment(&environment, ""); err != nil {
				t.Fatal("independent second role refused", err)
			}
		})
	}
}
