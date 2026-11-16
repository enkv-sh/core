package records

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicOutputScopesRequireOnlySelectedGitHubInputs(t *testing.T) {
	valid := &PublicOutputScopes{
		Repository:   PublicOutputScope{Owner: "owner", Repository: "repo"},
		Organization: PublicOutputScope{Owner: "org", Visibility: "selected", Repositories: []uint64{101}},
		Environment:  PublicOutputScope{Owner: "owner", Repository: "repo", Environment: "prod"},
	}
	for _, row := range []struct {
		name    string
		scopes  []string
		nilOK   bool
		validOK bool
	}{
		{"empty", nil, true, false},
		{"aws", []string{"aws-secrets-manager"}, true, true},
		{"gcp", []string{"gcp-secret-manager"}, true, true},
		{"repository", []string{"github-repository"}, false, true},
		{"organization", []string{"github-organization"}, false, true},
		{"environment", []string{"github-environment"}, false, true},
		{"mixed", []string{"aws-secrets-manager", "github-repository", "github-organization", "github-environment"}, false, true},
		{"unknown", []string{"github-other"}, false, false},
		{"unknown after cloud", []string{"gcp-secret-manager", "other"}, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			var absent *PublicOutputScopes
			if absent.ValidForScopes(row.scopes) != row.nilOK || valid.ValidForScopes(row.scopes) != row.validOK {
				t.Fatal("runtime input requirement does not follow selected destinations")
			}
			if (&PublicOutputScopes{}).ValidForScopes(row.scopes) {
				t.Fatal("malformed supplied inputs accepted")
			}
			partial := *valid
			partial.Environment = PublicOutputScope{}
			if partial.ValidForScopes(row.scopes) {
				t.Fatal("partial supplied inputs accepted")
			}
		})
	}
}

func publicManifestOutputEvidenceFixture() PublicOutputEvidence {
	v := publicOutputEvidenceFixture()
	v.Version = 3
	for i, row := range v.Coordinates[2:] {
		domain, binding, entry, incarnation := contract.Hash([]byte("fixed public evidence domain")), contract.ID{byte(i/2 + 11)}, contract.ID{byte(i%2 + 21)}, contract.ID{byte(i + 31)}
		// Coordinate/v3 commits Domain, then two u32-length-prefixed strings.
		preimage := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), domain[:]...)
		for _, text := range []string{row.ServiceContractID, row.PhysicalTarget} {
			preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(text)))
			preimage = append(preimage, text...)
		}
		id := sha256.Sum256(preimage)
		row.CoordinateID, row.BindingID = hex.EncodeToString(id[:]), hex.EncodeToString(binding[:])
		before := contract.PublicationCoordinate{Schema: 5, DomainID: domain, CoordinateID: id, ServiceContractID: row.ServiceContractID, CanonicalTarget: row.PhysicalTarget, BindingState: contract.PublicationBindingActive, OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: binding, LastBindingIncarnationID: binding, LastEntryIncarnationID: entry, CurrentPublicationIncarnationID: incarnation}
		kind := "plain"
		basis, conditional := "unpublished", false
		if i%2 == 1 {
			kind, basis, conditional = "secret", "secret-unchecked", true
		}
		v.PassiveCoordinates = append(v.PassiveCoordinates, PublicOutputPassiveCoordinate{PublicOutputCoordinate: row, EntryKind: kind, EntryIncarnationID: hex.EncodeToString(entry[:]), Before: before, After: before})
		preview := &v.Preview.Entries[i+2]
		preview.Coordinate, preview.Binding = &row.CoordinateID, &row.BindingID
		preview.Origin, preview.Basis, preview.Conditional = "both", basis, &conditional
		negative := false
		preview.Remote, preview.Late = &negative, &negative
		preview.Actions = []string{"create-with-value"}
	}
	v.Coordinates, v.Deletes = v.Coordinates[:2], v.Deletes[:2]
	return v
}

// full_only: false
func TestPublicManifestOutputEvidenceKeepsPassiveCoordinates(t *testing.T) {
	for _, condition := range []string{"exact", "v2", "missing", "extra", "order", "class", "conditional", "remote", "action", "origin", "entry-alias", "binding-alias", "after-admission", "before-admission", "before-ack", "before-risk", "after-incarnation", "marker-fields", "preview-extra", "preview-missing"} {
		t.Run(condition, func(t *testing.T) {
			v := publicManifestOutputEvidenceFixture()
			switch condition {
			case "v2":
				v.Version = 2
			case "missing":
				v.PassiveCoordinates = v.PassiveCoordinates[:5]
			case "extra":
				v.PassiveCoordinates = append(v.PassiveCoordinates, v.PassiveCoordinates[0])
			case "order":
				v.PassiveCoordinates[0], v.PassiveCoordinates[1] = v.PassiveCoordinates[1], v.PassiveCoordinates[0]
			case "class":
				v.PassiveCoordinates[0].EntryKind = "secret"
			case "conditional":
				*v.Preview.Entries[2].Conditional = true
			case "remote":
				*v.Preview.Entries[2].Remote = true
			case "action":
				v.Preview.Entries[2].Actions = []string{"write-value"}
			case "origin":
				v.Preview.Entries[2].Origin = "current"
			case "entry-alias":
				for i := range v.PassiveCoordinates {
					p := &v.PassiveCoordinates[i]
					p.EntryIncarnationID = v.PassiveCoordinates[0].EntryIncarnationID
					p.Before.LastEntryIncarnationID = v.PassiveCoordinates[0].Before.LastEntryIncarnationID
					p.After = p.Before
				}
			case "binding-alias":
				for i := range v.PassiveCoordinates {
					p := &v.PassiveCoordinates[i]
					p.BindingID = v.PassiveCoordinates[0].BindingID
					p.Before.ActiveBindingIncarnationID = v.PassiveCoordinates[0].Before.ActiveBindingIncarnationID
					p.Before.LastBindingIncarnationID = p.Before.ActiveBindingIncarnationID
					p.After = p.Before
					v.Preview.Entries[i+2].Binding = &p.BindingID
				}
			case "after-admission":
				v.PassiveCoordinates[0].After.LastAdmissionOrdinal = 1
			case "before-admission":
				v.PassiveCoordinates[0].Before.LastAdmissionOrdinal = 1
			case "before-ack":
				v.PassiveCoordinates[0].Before.LastDeleteAckAttemptID = contract.ID{99}
			case "before-risk":
				v.PassiveCoordinates[0].Before.PossibleRemoteObject = 1
			case "after-incarnation":
				v.PassiveCoordinates[0].After.CurrentPublicationIncarnationID = contract.ID{99}
			case "marker-fields":
				v.PassiveCoordinates[0].Before.DeletionDestinationID = "foreign"
			case "preview-extra":
				v.Preview.Entries = append(v.Preview.Entries, v.Preview.Entries[2])
			case "preview-missing":
				v.Preview.Entries = v.Preview.Entries[:7]
			}
			if strings.HasPrefix(condition, "before-") || condition == "marker-fields" {
				v.PassiveCoordinates[0].After = v.PassiveCoordinates[0].Before
			}
			if (v.Validate(3, []string{"aws-secrets-manager"}) == nil) != (condition == "exact") {
				t.Fatal("manifest cleanup lost the complete passive coordinate proof")
			}
		})
	}
}

func publicOutputEvidenceFixture() PublicOutputEvidence {
	positive, negative, reason, actionReason := true, false, uint8(0), uint16(0)
	locator := ""
	row := PublicOutputEvidence{Verdict: "match", Version: 2, EditableSHA256: strings.Repeat("e", 64), GeneratedSHA256: strings.Repeat("f", 64), CleanupCaptureOrdinal: 1, ObservationCaptureOrdinal: 2, Preview: PublicOutputPreview{Schema: "PublicationPreview/v2", Complete: &positive, Reason: &reason, Warning: &negative}}
	for i, target := range []string{
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:PLAIN", "arn:aws:secretsmanager:us-east-1:123456789012:secret:SECRET",
		"orgs/organization/actions/secrets/PLAIN", "orgs/organization/actions/secrets/SECRET",
		"repos/owner/repo/actions/secrets/PLAIN", "repos/owner/repo/actions/secrets/SECRET",
		"repos/owner/repo/environments/prod/secrets/PLAIN", "repos/owner/repo/environments/prod/secrets/SECRET",
	} {
		id, binding, attempt, projection := fmt.Sprintf("%064x", i+1), fmt.Sprintf("%064x", i+11), fmt.Sprintf("%064x", i+21), fmt.Sprintf("%064x", i+31)
		service, targetContract := "github-actions/service/v1", "github-actions/target/v1"
		if i < 2 {
			service, targetContract = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1"
		}
		coordinate := PublicOutputCoordinate{ServiceContractID: service, TargetContractID: targetContract, PhysicalTarget: target, CoordinateID: id, BindingID: binding}
		row.Coordinates = append(row.Coordinates, coordinate)
		row.Preview.Entries = append(row.Preview.Entries, PublicOutputPreviewRow{ServiceContractID: service, TargetContractID: targetContract, PhysicalTarget: coordinate.PhysicalTarget, Coordinate: &id, Binding: &binding, Origin: "observed", Basis: "warning", Actions: []string{}, Blockers: []string{}, Conditional: &negative, Reason: &reason, Remote: &positive, Late: &negative})
		action := "delete-owned"
		row.Deletes = append(row.Deletes, PublicOutputActionResult{Coordinate: id, Actions: []PublicOutputAction{{Action: &action, Projection: &projection, Attempt: &attempt, Disposition: "acknowledged", Reason: &actionReason, Remote: &positive, Late: &negative, Blockers: []string{}, Evidence: &PublicOutputActionEvidence{Schema: "PublicationEvidence/v3", Entry: "may-have-entered", Class: "acknowledged", Response: strings.Repeat("d", 64), Status: 204, ConsumerLocator: &locator}}}})
	}
	return row
}

// full_only: false
func TestPublicOutputEvidenceRequiresOriginalDeletionAcknowledgement(t *testing.T) {
	baseline := publicOutputEvidenceFixture()
	for _, condition := range []string{"exact", "mismatched-declaration", "old-evidence-schema", "old-action-evidence-schema", "missing-consumer-locator", "nonempty-deletion-locator", "old-preview-schema", "different-service", "different-target-contract", "missing-ack", "failed-ack", "unknown-ack", "missing-capture", "unjoined-order", "different-coordinate", "different-binding", "missing-projection", "missing-attempt", "late-warning", "domain-warning", "later-action", "remote-absence-claim"} {
		t.Run(condition, func(t *testing.T) {
			body, err := json.Marshal(baseline)
			var changed PublicOutputEvidence
			if err != nil || json.Unmarshal(body, &changed) != nil {
				t.Fatal("output evidence fixture unavailable")
			}
			switch condition {
			case "mismatched-declaration":
				changed.Verdict = "mismatch"
			case "old-evidence-schema":
				changed.Version = 1
			case "old-action-evidence-schema":
				changed.Deletes[0].Actions[0].Evidence.Schema = "PublicationEvidence/v2"
			case "missing-consumer-locator":
				changed.Deletes[0].Actions[0].Evidence.ConsumerLocator = nil
			case "nonempty-deletion-locator":
				*changed.Deletes[0].Actions[0].Evidence.ConsumerLocator = "consumer/resource"
			case "old-preview-schema":
				changed.Preview.Schema = "PublicationPreview/v1"
			case "different-service":
				changed.Preview.Entries[0].ServiceContractID = "different/service/v1"
			case "different-target-contract":
				changed.Preview.Entries[0].TargetContractID = "different/target/v1"
			case "missing-ack":
				changed.Deletes = nil
			case "failed-ack":
				changed.Deletes[0].Actions[0].Disposition = "rejected"
			case "unknown-ack":
				changed.Deletes[0].Actions[0].Disposition = "unknown"
			case "missing-capture":
				changed.CleanupCaptureOrdinal = 3
			case "unjoined-order":
				changed.CleanupCaptureOrdinal = changed.ObservationCaptureOrdinal
			case "different-coordinate":
				changed.Preview.Entries[0].Coordinate = &changed.Coordinates[1].CoordinateID
			case "different-binding":
				changed.Preview.Entries[0].Binding = &changed.Coordinates[1].BindingID
			case "missing-projection":
				changed.Deletes[0].Actions[0].Projection = nil
			case "missing-attempt":
				changed.Deletes[0].Actions[0].Attempt = nil
			case "late-warning":
				*changed.Preview.Entries[0].Late = true
			case "domain-warning":
				*changed.Preview.Warning = true
			case "later-action":
				changed.Preview.Entries[0].Actions = []string{"delete-owned"}
			case "remote-absence-claim":
				*changed.Deletes[0].Actions[0].Remote = false
			}
			if (changed.Validate(3, []string{"aws-secrets-manager", "github-repository", "github-organization", "github-environment"}) == nil) != (condition == "exact") {
				t.Fatal("missing original deletion evidence was replaced by a later observation")
			}
		})
	}
	// The record remains ordinary JSON and retains the possibility flag.
	body, err := json.Marshal(baseline)
	if err != nil || !strings.Contains(string(body), `"remote_value_may_remain":true`) {
		t.Fatal("remote possibility was lost during retention")
	}
}

// full_only: false
func TestPublicOutputEvidenceBindsExactEffectScopes(t *testing.T) {
	for _, cloud := range []string{"aws-secrets-manager", "gcp-secret-manager"} {
		t.Run(cloud, func(t *testing.T) {
			for _, condition := range []string{"exact-cloud", "exact-mixed", "truncated-mixed", "extra-scope", "wrong-cloud", "mixed-cloud", "missing-coordinate", "missing-deletion", "service-mismatch", "unknown-target-contract", "duplicate-scope", "nil-scopes", "duplicate-scopes", "reordered-scopes"} {
				t.Run(condition, func(t *testing.T) {
					value := publicOutputEvidenceFixture()
					service := "ENKV/OUTPUT/" + strings.ToUpper(cloud) + "/v1"
					targetContract := "ENKV/OUTPUT/" + strings.ToUpper(cloud) + "/TARGET/v1"
					for i := 0; i < 2; i++ {
						value.Coordinates[i].ServiceContractID = service
						value.Coordinates[i].TargetContractID = targetContract
						if cloud == "gcp-secret-manager" {
							value.Coordinates[i].PhysicalTarget = "projects/123456789012/secrets/" + []string{"PLAIN", "SECRET"}[i]
						}
						value.Preview.Entries[i].ServiceContractID = service
						value.Preview.Entries[i].TargetContractID = targetContract
						value.Preview.Entries[i].PhysicalTarget = value.Coordinates[i].PhysicalTarget
					}
					scopes := []string{cloud}
					if condition != "exact-mixed" && condition != "extra-scope" && condition != "duplicate-scope" && condition != "reordered-scopes" {
						value.Coordinates = value.Coordinates[:2]
						value.Deletes = value.Deletes[:2]
						value.Preview.Entries = value.Preview.Entries[:2]
					}
					switch condition {
					case "exact-mixed", "truncated-mixed", "duplicate-scope", "reordered-scopes":
						scopes = []string{cloud, "github-repository", "github-organization", "github-environment"}
					}
					switch condition {
					case "wrong-cloud":
						other := "aws-secrets-manager"
						if cloud == other {
							other = "gcp-secret-manager"
						}
						scopes[0] = other
					case "mixed-cloud":
						other := "aws-secrets-manager"
						if cloud == other {
							other = "gcp-secret-manager"
						}
						value.Coordinates[1].ServiceContractID = "ENKV/OUTPUT/" + strings.ToUpper(other) + "/v1"
						value.Coordinates[1].TargetContractID = "ENKV/OUTPUT/" + strings.ToUpper(other) + "/TARGET/v1"
						value.Preview.Entries[1].ServiceContractID = value.Coordinates[1].ServiceContractID
						value.Preview.Entries[1].TargetContractID = value.Coordinates[1].TargetContractID
					case "missing-coordinate":
						value.Coordinates = value.Coordinates[:1]
					case "missing-deletion":
						value.Deletes = value.Deletes[:1]
					case "service-mismatch":
						value.Coordinates[0].ServiceContractID = "github-actions/service/v1"
						value.Preview.Entries[0].ServiceContractID = value.Coordinates[0].ServiceContractID
					case "unknown-target-contract":
						value.Coordinates[0].TargetContractID = "unknown/target/v1"
						value.Preview.Entries[0].TargetContractID = value.Coordinates[0].TargetContractID
					case "duplicate-scope":
						value.Coordinates[2].PhysicalTarget = "orgs/organization/actions/secrets/OTHER"
						value.Preview.Entries[2].PhysicalTarget = value.Coordinates[2].PhysicalTarget
						value.Coordinates[4].PhysicalTarget = "orgs/organization/actions/secrets/THIRD"
						value.Preview.Entries[4].PhysicalTarget = value.Coordinates[4].PhysicalTarget
					case "nil-scopes":
						scopes = nil
					case "duplicate-scopes":
						scopes = []string{cloud, cloud, cloud, cloud}
					case "reordered-scopes":
						scopes[1], scopes[2] = scopes[2], scopes[1]
					}
					if (value.Validate(3, scopes) == nil) != (condition == "exact-cloud" || condition == "exact-mixed") {
						t.Fatal("output evidence did not bind the whole selected effect scope")
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationEvidenceBindsOutputScopesToScenario(t *testing.T) {
	for _, test := range []struct {
		name, scenario string
		cloudOnly      bool
		valid          bool
	}{
		{"manifest-cloud", "public-configuration.manifest/atomic_public_file", true, true},
		{"output-mixed", "public-configuration.output-standalone/output_standalone", false, true},
		{"output-truncated", "public-configuration.output-standalone/output_standalone", true, false},
		{"manifest-extra-effects", "public-configuration.manifest/atomic_public_file", false, false},
		{"manifest-v3", "public-configuration.manifest/atomic_public_file", true, true},
		{"output-v3", "public-configuration.output-standalone/output_standalone", true, false},
		{"manifest-v3-foreign-domain", "public-configuration.manifest/atomic_public_file", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, binding := publicEvidenceFixture()
			value.Scenario, binding.Scenario = test.scenario, test.scenario
			output := publicOutputEvidenceFixture()
			if test.cloudOnly {
				output.Coordinates = output.Coordinates[:2]
				output.Deletes = output.Deletes[:2]
				output.Preview.Entries = output.Preview.Entries[:2]
			}
			if strings.Contains(test.name, "v3") {
				output = publicManifestOutputEvidenceFixture()
			}
			if strings.HasSuffix(test.name, "foreign-domain") {
				value.Domains = append(value.Domains, contract.ID{99})
				for i := range output.PassiveCoordinates {
					p := &output.PassiveCoordinates[i]
					p.Before.DomainID = contract.ID{99}
					p.Before.CoordinateID, _ = contract.PublicationCoordinateID(p.Before.DomainID, p.ServiceContractID, p.PhysicalTarget)
					p.After = p.Before
					p.CoordinateID = hex.EncodeToString(p.Before.CoordinateID[:])
					output.Preview.Entries[i+2].Coordinate = &p.CoordinateID
				}
			}
			value.Outputs = &output
			for ordinal := 1; ordinal <= 2; ordinal++ {
				capture := value.Captures[0]
				capture.Ordinal = uint16(ordinal)
				capture.ParentWorker = binding.Workers[2].Worker
				capture.ParentNonce = binding.Workers[2].Nonce
				capture.ParentRole = "cleanup"
				capture.SourceRelative = fmt.Sprintf("public-command-%d/capture.jsonl", ordinal)
				value.Captures = append(value.Captures, capture)
			}
			if (value.Validate(binding) == nil) != test.valid {
				t.Fatal("scenario admitted a different output effect vector")
			}
		})
	}
}
