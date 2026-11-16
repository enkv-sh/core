package main

import (
	"fmt"
	"path/filepath"
	"testing"
)

func publicReplacementEnvironment(t *testing.T, provider string) environmentFile {
	t.Helper()
	var env environmentFile
	if err := readSelectionFile(filepath.Join(maintainedCloudflareRoot(t), "tests/environments/public-"+provider+".example.json"), &env); err != nil {
		t.Fatal(err)
	}
	for i, field := range []string{"normal_successor_key_id", "recovery_successor_key_id", "authority_successor_1_kek_id", "recovery_successor_1_kek_id", "reader_successor_kek_id"} {
		s := env.Resource.Settings
		if provider == "aws" {
			s[field] = fmt.Sprintf("arn:aws:kms:%s:%s:key/00000000-0000-0000-0000-%012d", s["region"], s["account"], 50+i)
		} else {
			s[field] = fmt.Sprintf("projects/%s/locations/%s/keyRings/preexisting/cryptoKeys/next-%d/cryptoKeyVersions/1", s["project"], s["region"], 50+i)
		}
	}
	return env
}

// full_only: false
func TestPublicReplacementHostAdmitsFiveExactSelectors(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			env := publicReplacementEnvironment(t, provider)
			if err := validatePublicConfigurationEnvironment(&env); err != nil {
				t.Fatal("five existing first-successor selectors refused before any login", err)
			}
			for _, field := range []string{"recovery_successor_key_id", "authority_successor_1_kek_id", "recovery_successor_1_kek_id", "reader_successor_kek_id"} {
				delete(env.Resource.Settings, field)
			}
			if err := validatePublicConfigurationEnvironment(&env); err != nil {
				t.Fatal("old functional N1-only input changed", err)
			}
		})
	}
}

// full_only: false
func TestPublicReplacementHostRefusesInvalidSelectorFacts(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, field := range []string{"normal_successor_key_id", "recovery_successor_key_id", "authority_successor_1_kek_id", "recovery_successor_1_kek_id", "reader_successor_kek_id"} {
			for _, damage := range []string{"alias", "malformed", "other-location"} {
				t.Run(provider+"/"+field+"/"+damage, func(t *testing.T) {
					env := publicReplacementEnvironment(t, provider)
					s := env.Resource.Settings
					switch damage {
					case "alias":
						s[field] = s["key_id"]
					case "malformed":
						s[field] = "unqualified-key"
					case "other-location":
						if provider == "aws" {
							s[field] = "arn:aws:kms:eu-west-1:999999999999:key/00000000-0000-0000-0000-000000000099"
						} else {
							s[field] = "projects/other-project/locations/europe-west1/keyRings/test/cryptoKeys/key/cryptoKeyVersions/1"
						}
					}
					if validatePublicConfigurationEnvironment(&env) == nil {
						t.Fatal("invalid selector accepted")
					}
				})
			}
		}
	}
	for _, field := range []string{"normal_successor_2_key_id", "authority_successor_1_kek_public_key_pem", "unknown_selector"} {
		t.Run(field, func(t *testing.T) {
			env := publicReplacementEnvironment(t, "aws")
			env.Resource.Settings[field] = "unselected-input"
			if validatePublicConfigurationEnvironment(&env) == nil {
				t.Fatal("legacy or unknown bundle field accepted")
			}
		})
	}
}

// full_only: false
func TestPublicReplacementHostDisabledProjectionDropsRecoverySuccessors(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			env := publicReplacementEnvironment(t, provider)
			if err := selectRecoveryMode(&env, "disabled"); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"recovery_key_id", "recovery_kek_id", "recovery_successor_key_id", "recovery_successor_1_kek_id"} {
				if _, present := env.Resource.Settings[field]; present {
					t.Fatal("disabled projection retained Recovery resource", field)
				}
			}
			if err := validatePublicConfigurationEnvironment(&env); err != nil {
				t.Fatal("disabled Authority/Recipient successors refused", err)
			}
			env.Resource.Settings["recovery_successor_key_id"] = env.Resource.Settings["normal_successor_key_id"]
			if validatePublicConfigurationEnvironment(&env) == nil {
				t.Fatal("disabled Recovery successor accepted")
			}
		})
	}
}
