package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"

	records "enkv.sh/core/internal/testrecords"
)

// These are local source-provenance inputs for the existing disposal fixture.
// They claim no native execution or provider result outside this fixture.
func attachPublicOutputDisposalEvidence(t *testing.T, state string, snapshot *records.PublicConfigurationEvidenceSnapshot, ownershipBody []byte, cleanup records.PublicConfigurationWorkerJoin) []byte {
	t.Helper()
	positive, negative, reason, actionReason := true, false, uint8(0), uint16(0)
	locator := ""
	proof := &records.PublicOutputEvidence{Version: 2, Verdict: "match", EditableSHA256: strings.Repeat("e", 64), GeneratedSHA256: strings.Repeat("f", 64), CleanupCaptureOrdinal: 1, ObservationCaptureOrdinal: 2,
		Preview: records.PublicOutputPreview{Schema: "PublicationPreview/v2", Complete: &positive, Reason: &reason, Warning: &negative}}
	for i, target := range []string{
		"projects/123456789012/secrets/PLAIN", "projects/123456789012/secrets/SECRET",
		"orgs/organization/actions/secrets/PLAIN", "orgs/organization/actions/secrets/SECRET",
		"repos/owner/repo/actions/secrets/PLAIN", "repos/owner/repo/actions/secrets/SECRET",
		"repos/owner/repo/environments/prod/secrets/PLAIN", "repos/owner/repo/environments/prod/secrets/SECRET",
	} {
		coordinate, binding, attempt, projection := fmt.Sprintf("%064x", i+1), fmt.Sprintf("%064x", i+11), fmt.Sprintf("%064x", i+21), fmt.Sprintf("%064x", i+31)
		service, targetContract := "github-actions/service/v1", "github-actions/target/v1"
		if i < 2 {
			service, targetContract = "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1"
		}
		row := records.PublicOutputCoordinate{ServiceContractID: service, TargetContractID: targetContract, PhysicalTarget: target, CoordinateID: coordinate, BindingID: binding}
		proof.Coordinates = append(proof.Coordinates, row)
		proof.Preview.Entries = append(proof.Preview.Entries, records.PublicOutputPreviewRow{ServiceContractID: service, TargetContractID: targetContract, PhysicalTarget: row.PhysicalTarget, Coordinate: &coordinate, Binding: &binding, Origin: "observed", Basis: "warning", Actions: []string{}, Blockers: []string{}, Conditional: &negative, Reason: &reason, Remote: &positive, Late: &negative})
		action := "delete-owned"
		proof.Deletes = append(proof.Deletes, records.PublicOutputActionResult{Coordinate: coordinate, Actions: []records.PublicOutputAction{{Action: &action, Projection: &projection, Attempt: &attempt, Disposition: "acknowledged", Reason: &actionReason, Remote: &positive, Late: &negative, Blockers: []string{}, Evidence: &records.PublicOutputActionEvidence{Schema: "PublicationEvidence/v3", Entry: "may-have-entered", Class: "acknowledged", Response: strings.Repeat("d", 64), Status: 200, ConsumerLocator: &locator}}}})
	}
	selected, _ := catalog.PublicConfiguration(snapshot.Scenario)
	if selected.Condition == "manifest" {
		proof.Version = 3
		for i, row := range proof.Coordinates[2:] {
			binding, entry := contract.ID{byte(11 + i/2)}, contract.ID{byte(21 + i%2)}
			coordinate, err := contract.PublicationCoordinateID(snapshot.Cleanup.Domain, row.ServiceContractID, row.PhysicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			row.CoordinateID, row.BindingID = hex.EncodeToString(coordinate[:]), hex.EncodeToString(binding[:])
			before := contract.PublicationCoordinate{Schema: 5, DomainID: snapshot.Cleanup.Domain, CoordinateID: coordinate, ServiceContractID: row.ServiceContractID, CanonicalTarget: row.PhysicalTarget, BindingState: contract.PublicationBindingActive, OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: binding, LastBindingIncarnationID: binding, LastEntryIncarnationID: entry, CurrentPublicationIncarnationID: contract.ID{byte(31 + i)}}
			kind, basis, conditional := "plain", "unpublished", false
			if i%2 == 1 {
				kind, basis, conditional = "secret", "secret-unchecked", true
			}
			proof.PassiveCoordinates = append(proof.PassiveCoordinates, records.PublicOutputPassiveCoordinate{PublicOutputCoordinate: row, EntryKind: kind, EntryIncarnationID: hex.EncodeToString(entry[:]), Before: before, After: before})
			preview := &proof.Preview.Entries[i+2]
			preview.Coordinate, preview.Binding, preview.Origin, preview.Basis, preview.Conditional, preview.Remote, preview.Late = &row.CoordinateID, &row.BindingID, "both", basis, &conditional, &negative, &negative
			preview.Actions = []string{"create-with-value"}
		}
		proof.Coordinates, proof.Deletes = proof.Coordinates[:2], proof.Deletes[:2]
	}
	var ownership records.PublicConfigurationOwnership
	if json.Unmarshal(ownershipBody, &ownership) != nil {
		t.Fatal("original ownership fixture unavailable")
	}
	for ordinal, actor := range []string{"apply", "reader"} {
		index := uint16(ordinal + 1)
		directory := filepath.Join(state, fmt.Sprintf("public-command-%d", index+1))
		if os.Mkdir(directory, 0700) != nil {
			t.Fatal("output capture fixture directory unavailable")
		}
		path := filepath.Join(directory, "capture.jsonl")
		body := []byte("{\"kind\":\"footer\"}\n")
		if os.WriteFile(path, body, 0600) != nil {
			t.Fatal("joined output capture fixture unavailable")
		}
		digest := publicEvidenceFixtureDigest(body)
		ownership.Captures = append(ownership.Captures, records.PublicConfigurationCaptureRegistration{Path: path, SHA256: digest, Complete: true, Ordinal: index, ParentWorker: cleanup.Worker, ParentNonce: cleanup.Nonce, ParentRole: cleanup.Role, Actor: actor, NativeKind: "cli", Bytes: uint64(len(body))})
		snapshot.Captures = append(snapshot.Captures, records.PublicConfigurationCaptureReceipt{Ordinal: index, ParentWorker: cleanup.Worker, ParentNonce: cleanup.Nonce, ParentRole: cleanup.Role, Actor: actor, NativeKind: "cli", SourceRelative: filepath.ToSlash(filepath.Join(filepath.Base(directory), "capture.jsonl")), Complete: true, SHA256: digest, Bytes: uint64(len(body))})
	}
	if proof.Validate(len(snapshot.Captures), selected.OutputScopes("gcp")) != nil {
		t.Fatal("complete output deletion fixture refused")
	}
	ownership.Outputs, snapshot.Outputs = proof, proof
	if records.WriteJSON(filepath.Join(state, "public-ownership.json"), ownership, 0600) != nil {
		t.Fatal("output original ownership fixture unavailable")
	}
	body, err := os.ReadFile(filepath.Join(state, "public-ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot.OriginalOwnershipSHA256 = publicEvidenceFixtureDigest(body)
	return body
}

// full_only: false
func TestPublicOutputEvidenceHandoffBindsOriginalOutputProof(t *testing.T) {
	const scenario = "public-configuration.output-standalone/output_standalone"
	for _, condition := range []string{"exact", "editable-image", "generated-image", "coordinate-and-deletion", "binding-and-preview", "projection", "original-ownership-image"} {
		t.Run(condition, func(t *testing.T) {
			fixture := publicEvidenceDisposalFixtureForScenario(t, 2, scenario)
			originalBody, err := os.ReadFile(filepath.Join(fixture.state, "public-ownership.json"))
			if err != nil || publicEvidenceFixtureDigest(originalBody) != fixture.expectedSnapshot.OriginalOwnershipSHA256 {
				t.Fatal("original output source image unavailable", err)
			}
			body, err := json.Marshal(fixture.expectedSnapshot)
			var snapshot records.PublicConfigurationEvidenceSnapshot
			if err != nil || json.Unmarshal(body, &snapshot) != nil {
				t.Fatal("independent output snapshot fixture unavailable")
			}
			expected, err := publicConfigurationEvidenceBinding(fixture.run.record, fixture.result)
			expected.Workers = fixture.expectedWorkers
			if err != nil || snapshot.Validate(expected) != nil || verifyOriginalPublicConfigurationEvidence(fixture.state, snapshot) != nil {
				t.Fatal("complete output handoff fixture is not valid", err)
			}
			switch condition {
			case "editable-image":
				snapshot.Outputs.EditableSHA256 = strings.Repeat("1", 64)
			case "generated-image":
				snapshot.Outputs.GeneratedSHA256 = strings.Repeat("2", 64)
			case "coordinate-and-deletion":
				id := strings.Repeat("9", 64)
				snapshot.Outputs.Coordinates[0].CoordinateID = id
				snapshot.Outputs.Preview.Entries[0].Coordinate = &id
				snapshot.Outputs.Deletes[0].Coordinate = id
				slices.SortFunc(snapshot.Outputs.Deletes, func(a, b records.PublicOutputActionResult) int { return strings.Compare(a.Coordinate, b.Coordinate) })
			case "binding-and-preview":
				id := strings.Repeat("8", 64)
				snapshot.Outputs.Coordinates[0].BindingID = id
				snapshot.Outputs.Preview.Entries[0].Binding = &id
			case "projection":
				id := strings.Repeat("7", 64)
				snapshot.Outputs.Deletes[0].Actions[0].Projection = &id
			case "original-ownership-image":
				if os.WriteFile(filepath.Join(fixture.state, "public-ownership.json"), append(bytes.Clone(originalBody), '\n'), 0600) != nil {
					t.Fatal("original source damage fixture unavailable")
				}
			}
			if snapshot.Validate(expected) != nil {
				t.Fatal("source-provenance regression was replaced by structural rejection")
			}
			if snapshot.OriginalOwnershipSHA256 != fixture.expectedSnapshot.OriginalOwnershipSHA256 || !reflect.DeepEqual(snapshot.Captures, fixture.expectedSnapshot.Captures) {
				t.Fatal("tampered projection changed its original source commitment or captures")
			}
			if condition != "original-ownership-image" {
				current, err := os.ReadFile(filepath.Join(fixture.state, "public-ownership.json"))
				if err != nil || !bytes.Equal(current, originalBody) {
					t.Fatal("projection tamper changed the pinned original ownership")
				}
			}
			if err := records.WriteJSON(fixture.snapshotPath, snapshot, 0600); err != nil {
				t.Fatal("validated output snapshot tamper fixture write failed", err)
			}
			if err := verifyOriginalPublicConfigurationEvidence(fixture.state, snapshot); (err == nil) != (condition == "exact") {
				t.Error("original output proof mismatch crossed its source boundary", condition, err)
			}
			err = fixture.run.retainPublicConfigurationEvidence(&fixture.result, fixture.participants)
			if condition == "exact" {
				if err != nil || fixture.result.PublicConfigurationEvidence == nil {
					t.Fatal("complete unchanged output proof failed retention", err)
				}
				sealPublicEvidenceFixture(t, &fixture)
				if err := fixture.run.verifyPublicConfigurationEvidence(); err != nil {
					t.Fatal("complete output proof failed disposal", err)
				}
				if err := readPublicConfigurationEvidence(fixture.run.directory, fixture.run.record, fixture.result); err != nil {
					t.Fatal("complete output proof did not reopen after disposal", err)
				}
				return
			}
			if err == nil || fixture.result.PublicConfigurationEvidence != nil {
				t.Error("changed output proof published a retained reference", condition)
				return
			}
			fixture.run.record.Scenarios = []scenarioResult{fixture.result}
			if fixture.run.writeCaseReceipt(fixture.result, fixture.identity) == nil {
				t.Fatal("mismatched output provenance sealed a successful case")
			}
			fixture.run.finish()
			if fixture.run.finishCurrentRun(io.Discard, nil) == nil {
				t.Fatal("mismatched output provenance permitted private disposal")
			}
			requirePublicEvidenceOriginalsPresent(t, fixture)
			if fixture.run.record.Scenarios[0].Outcome != "passed" || !fixture.run.record.Scenarios[0].CorrectnessPassed || fixture.run.record.Scenarios[0].Cleanup.Outcome != "passed" {
				t.Fatal("evidence refusal replaced original Product or cleanup facts")
			}
		})
	}
}

// full_only: false
func TestPublicManifestOutputEvidenceHandoffBindsPassiveProof(t *testing.T) {
	for _, condition := range []string{"exact", "before-only", "after-only", "coherent-incarnation"} {
		t.Run(condition, func(t *testing.T) {
			fixture := publicEvidenceDisposalFixtureForScenario(t, 2, "public-configuration.manifest/atomic_public_file")
			body, err := json.Marshal(fixture.expectedSnapshot)
			var snapshot records.PublicConfigurationEvidenceSnapshot
			if err != nil || json.Unmarshal(body, &snapshot) != nil || snapshot.Outputs == nil || snapshot.Outputs.Version != 3 {
				t.Fatal("manifest passive original fixture unavailable", err)
			}
			expected, err := publicConfigurationEvidenceBinding(fixture.run.record, fixture.result)
			expected.Workers = fixture.expectedWorkers
			if err != nil || snapshot.Validate(expected) != nil || verifyOriginalPublicConfigurationEvidence(fixture.state, snapshot) != nil {
				t.Fatal("manifest passive original proof refused", err)
			}
			switch condition {
			case "before-only":
				snapshot.Outputs.PassiveCoordinates[0].Before.CurrentPublicationIncarnationID = contract.ID{99}
			case "after-only":
				snapshot.Outputs.PassiveCoordinates[0].After.CurrentPublicationIncarnationID = contract.ID{99}
			case "coherent-incarnation":
				snapshot.Outputs.PassiveCoordinates[0].Before.CurrentPublicationIncarnationID = contract.ID{99}
				snapshot.Outputs.PassiveCoordinates[0].After = snapshot.Outputs.PassiveCoordinates[0].Before
			}
			if condition == "before-only" || condition == "after-only" {
				if snapshot.Validate(expected) == nil {
					t.Fatal("manifest passive before/after drift admitted")
				}
				return
			}
			if snapshot.Validate(expected) != nil {
				t.Fatal("source binding test was replaced by shape rejection")
			}
			if (verifyOriginalPublicConfigurationEvidence(fixture.state, snapshot) == nil) != (condition == "exact") {
				t.Fatal("manifest passive proof detached from original ownership")
			}
			if condition == "exact" {
				joins, output, joinErr := publicConfigurationWorkerJoins(fixture.participants.writer, fixture.result)
				if joinErr != nil || !reflect.DeepEqual(joins, fixture.expectedWorkers) {
					t.Fatal("manifest passive worker binding failed", joinErr)
				}
				savedBody, readErr := os.ReadFile(filepath.Join(output, "public-configuration-evidence.json"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				decoded, decodeErr := records.ReadPublicConfigurationEvidenceSnapshotBytes(savedBody, expected)
				if decodeErr != nil || verifyOriginalPublicConfigurationEvidence(fixture.state, decoded) != nil {
					t.Fatal("manifest passive saved snapshot failed", decodeErr)
				}
				if err := fixture.run.retainPublicConfigurationEvidence(&fixture.result, fixture.participants); err != nil {
					t.Fatal("manifest passive proof retention failed", err)
				}
				sealPublicEvidenceFixture(t, &fixture)
				if fixture.run.verifyPublicConfigurationEvidence() != nil || readPublicConfigurationEvidence(fixture.run.directory, fixture.run.record, fixture.result) != nil {
					t.Fatal("manifest passive proof did not survive disposal")
				}
			}
		})
	}
}
