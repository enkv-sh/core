package core

import (
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

func publicReplacementAdmitted(input liveRunInput, cell catalog.PublicReplacementCase) bool {
	if cell.Target != "authority" && cell.Target != "recovery" && cell.Target != "recipient" || cell.Change != "signing" && cell.Change != "encryption" && cell.Change != "both" || cell.Authorizer != "authority" && cell.Authorizer != "recovery" {
		return false
	}
	if cell.Change == "signing" && cell.MaterialSource != "" || cell.Change != "signing" && cell.MaterialSource != "authority" && cell.MaterialSource != "recovery" || cell.Target == "recipient" && (cell.Change != "encryption" || cell.Authorizer != "authority" || cell.MaterialSource != "authority") {
		return false
	}
	s := input.Settings
	if input.RecoveryMode == "disabled" && (cell.Target == "recovery" || cell.Authorizer == "recovery" || cell.MaterialSource == "recovery" || s.RecoverySuccessorKeyID != "" || s.RecoverySuccessor1KEKID != "") {
		return false
	}
	family := contract.AWS
	if s.Provider == "gcp" {
		family = contract.GCP
	}
	required := []struct {
		selector string
		signing  bool
	}{{s.NormalSuccessorKeyID, true}, {s.AuthoritySuccessor1KEKID, false}}
	if !cell.Operator {
		required = append(required, struct {
			selector string
			signing  bool
		}{s.ReaderSuccessorKEKID, false})
		if input.RecoveryMode == "enabled" {
			required = append(required, struct {
				selector string
				signing  bool
			}{s.RecoverySuccessorKeyID, true}, struct {
				selector string
				signing  bool
			}{s.RecoverySuccessor1KEKID, false})
		}
	}
	for _, key := range required {
		if !contract.PublicKeySelectorValid(family, key.selector, key.signing) {
			return false
		}
	}
	return true
}

// full_only: false
func TestPublicReplacementAdmissionBindsFiveSelectorsAndExactSDKRoles(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			name := "public-configuration.keys-replace-authority-both-by-authority/keys_replace_authority_both_by_authority"
			definition, known := catalog.DefinitionFor(name)
			if !known {
				t.Fatal("replacement case missing")
			}
			makeInput := func() liveRunInput {
				selector := func(n int) string {
					if provider == "aws" {
						return fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-%012d", n)
					}
					return fmt.Sprintf("projects/project-one/locations/us-central1/keyRings/ring/cryptoKeys/key%d/cryptoKeyVersions/1", n)
				}
				s := liveSettings{Provider: provider, RecoveryMode: mode, Region: "us-east-1", Bucket: "bucket", Account: "123456789012", KeyID: selector(1), AuthorityKEKID: selector(2), ReaderKEKID: selector(3), NormalSuccessorKeyID: selector(6), AuthoritySuccessor1KEKID: selector(7), ReaderSuccessorKEKID: selector(8), SDKMode: "aws-assume-role", SDKHome: "/isolated/authority", SDKProfile: "authority"}
				if provider == "gcp" {
					s.Region = "us-central1"
					s.Account = ""
					s.Project = "project-one"
					s.QuotaProject = "project-one"
					s.SDKMode = "gcp-impersonated-adc"
					s.SDKProfile = ""
					s.SDKQuotaProject = "project-one"
				}
				if mode == "enabled" {
					s.RecoveryKeyID = selector(4)
					s.RecoveryKEKID = selector(5)
					s.RecoverySuccessorKeyID = selector(9)
					s.RecoverySuccessor1KEKID = selector(10)
				}
				input := liveRunInput{Settings: s, RecoveryMode: mode, Scenarios: []string{name}, Participants: map[string]string{}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{}}}
				for _, role := range definition.RolesForRecovery(mode) {
					actor := s
					actor.SDKHome = "/isolated/" + role
					if provider == "aws" {
						actor.SDKProfile = role
					}
					input.Participants[role] = role
					input.PublicConfiguration.Actors[role] = actor
				}
				return input
			}
			input := makeInput()
			if !livePublicConfigurationAdmitted(input) {
				t.Fatal("complete replacement publicSDK input refused", provider, mode)
			}
			for _, field := range []string{"normal", "authority", "recipient", "recovery-signing", "recovery-encryption"} {
				if mode == "disabled" && (field == "recovery-signing" || field == "recovery-encryption") {
					continue
				}
				input := makeInput()
				actor := input.PublicConfiguration.Actors["reader"]
				switch field {
				case "normal":
					actor.NormalSuccessorKeyID = "different"
				case "authority":
					actor.AuthoritySuccessor1KEKID = "different"
				case "recipient":
					actor.ReaderSuccessorKEKID = "different"
				case "recovery-signing":
					actor.RecoverySuccessorKeyID = "different"
				case "recovery-encryption":
					actor.RecoverySuccessor1KEKID = "different"
				}
				input.PublicConfiguration.Actors["reader"] = actor
				if livePublicConfigurationAdmitted(input) {
					t.Fatal("one actor changed a nominated public resource", field)
				}
			}
			input = makeInput()
			input.PublicConfiguration.Actors["unused-private"] = input.Settings
			input.Participants["unused-private"] = "unused"
			if livePublicConfigurationAdmitted(input) {
				t.Fatal("unused private SDKcontext admitted")
			}
		}
	}
}
