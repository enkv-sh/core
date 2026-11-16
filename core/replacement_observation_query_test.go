package core

import (
	"encoding/hex"
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestReplacementQueryIdentityIndependentLiterals(t *testing.T) {
	// Digests were derived with Python hashlib.sha256 and struct.pack, independently
	// of the Go codec. IDs are 32 bytes with the stated first byte and 31 zero bytes.
	// The byte order is purpose, little-endian semantic/target/operation length,
	// operation, eight IDs, each three-ID/format/uint64-lengths/generated pin,
	// observation presence and three IDs if present, six correlation IDs,
	// kind/approval/material, and two uint16-length-prefixed selectors.
	for _, tc := range []struct {
		name     string
		target   ReplacementTarget
		observed bool
		digest   string
	}{
		{"authority-before", 1, false, "e2ad724f96dddfd94f9fbf6effe7ba51ae53325a3286d90ccee3b3598ef71f47"},
		{"authority-current", 1, true, "3e82ad19b7a187f45bc05fde905cffac08f59bdd6d6bfa7ec717e1f3e189a3b7"},
		{"recovery-current", 2, true, "23c6cc9f1c5aa2d50167731f6a6ea6105fbcf69068ce3020e7f28e8e8a0c32aa"},
		{"recipient-current", 3, true, "0490523e389660fac235560480d3345fff2a8a2b4da705a6b85d7cbaeb9f4c48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := ReplacementQueryIdentity{Schema: "QueryRequestIdentity/v1", Target: tc.target, ExpectedDomain: contract.ID{1}, StoreID: contract.ID{2}, CoordinateID: contract.ID{3}, NonBodyID: contract.ID{4}, StoreDescriptorDigest: contract.ID{5}, SourceBasisDigest: contract.ID{6}, SuccessorBasisDigest: contract.ID{7}, SourcePins: AdministrativeSourcePins{FileID: contract.ID{11}, Format: 1, EditableDigest: contract.ID{12}, GeneratedDigest: contract.ID{13}, EditableLength: 101, GeneratedLength: 202, HasGenerated: true}, OutputPins: AdministrativeSourcePins{FileID: contract.ID{11}, Format: 1, EditableDigest: contract.ID{14}, GeneratedDigest: contract.ID{15}, EditableLength: 303, GeneratedLength: 404, HasGenerated: true}, RequestNonce: contract.ID{16}, OriginalOperationID: contract.ID{17}, OriginalRequestIdentity: contract.ID{18}, CandidateDigest: contract.ID{19}, RequestedRevisionID: contract.ID{20}, Goal: RoleReplacementGoal{ApprovalRole: 1, SigningSelector: "sign-next"}}
			q.Operation, q.SemanticOperation, q.RequiredStoredKind, _ = replacementReadOperation(tc.target)
			switch tc.target {
			case ReplacementTargetAuthority:
				q.RequiredStoredKind = 0
			case ReplacementTargetRecovery:
				q.Goal.ApprovalRole = 2
				q.Goal.EncryptionSelector = "enc-next"
				q.Goal.MaterialSource = ReplacementMaterialRecovery
			case ReplacementTargetRecipient:
				q.RecipientID = contract.ID{21}
				q.Goal.SigningSelector = ""
				q.Goal.EncryptionSelector = "enc-next"
				q.Goal.MaterialSource = ReplacementMaterialAuthority
			}
			if tc.observed {
				q.AuthenticatedBasisDigest = contract.ID{8}
				q.Observation = &AdministrativeObservation{DomainID: contract.ID{1}, Revision: contract.ID{22}, Snapshot: contract.ID{23}}
			}
			literal, err := hex.DecodeString(tc.digest)
			if err != nil {
				t.Fatal(err)
			}
			copy(q.Digest[:], literal)
			if !q.Valid() {
				t.Fatal("independent query literal does not match", tc.digest)
			}
			for _, damage := range []struct {
				name string
				edit func(*ReplacementQueryIdentity)
			}{
				{"nonce", func(q *ReplacementQueryIdentity) { q.RequestNonce[1]++ }},
				{"store", func(q *ReplacementQueryIdentity) { q.StoreID[1]++ }},
				{"descriptor", func(q *ReplacementQueryIdentity) { q.StoreDescriptorDigest[1]++ }},
				{"source-basis", func(q *ReplacementQueryIdentity) { q.SourceBasisDigest[1]++ }},
				{"successor-basis", func(q *ReplacementQueryIdentity) { q.SuccessorBasisDigest[1]++ }},
				{"accepted-basis", func(q *ReplacementQueryIdentity) { q.AuthenticatedBasisDigest[1]++ }},
				{"source-pins", func(q *ReplacementQueryIdentity) { q.SourcePins.EditableLength++ }},
				{"output-pins", func(q *ReplacementQueryIdentity) { q.OutputPins.GeneratedDigest[1]++ }},
				{"original-operation", func(q *ReplacementQueryIdentity) { q.OriginalOperationID[1]++ }},
				{"original-graph", func(q *ReplacementQueryIdentity) { q.OriginalRequestIdentity[1]++ }},
				{"candidate", func(q *ReplacementQueryIdentity) { q.CandidateDigest[1]++ }},
				{"requested-revision", func(q *ReplacementQueryIdentity) { q.RequestedRevisionID[1]++ }},
				{"stored-kind", func(q *ReplacementQueryIdentity) { q.RequiredStoredKind++ }},
				{"target", func(q *ReplacementQueryIdentity) { q.Target++ }},
				{"selector", func(q *ReplacementQueryIdentity) { q.Goal.EncryptionSelector += "changed" }},
				{"approval", func(q *ReplacementQueryIdentity) { q.Goal.ApprovalRole++ }},
				{"material-route", func(q *ReplacementQueryIdentity) { q.Goal.MaterialSource++ }},
			} {
				t.Run(damage.name, func(t *testing.T) {
					changed := q
					damage.edit(&changed)
					if changed.Valid() {
						t.Fatal("changed query retained original identity")
					}
				})
			}
			if q.Observation != nil {
				changed := q
				observation := *q.Observation
				changed.Observation = &observation
				observation.Revision[1]++
				if changed.Valid() {
					t.Fatal("changed authenticated observation retained identity")
				}
			}
		})
	}
}

// full_only: false
func TestReplacementObservationPreservesClosedReadOutcomes(t *testing.T) {
	for _, tc := range []struct {
		result Result
		want   contract.ReaderStateResult
	}{
		{failure(RootLossUnsupported, MissingSelectedObject), ReplacementRootLossUnsupported},
		{refused(CapacityExceeded), contract.ReaderRefused},
		{failure(EvidenceUnavailable, MissingSelectedObject), contract.ReaderUnavailable},
		{failure(IntegrityFailure, MissingSelectedObject), contract.ReaderPositiveDefect},
		{refused(AdmissionInvalid), contract.ReaderRefused},
		{failure(Contention, DifferentSelection), contract.ReaderUnavailable},
		{failure(Contention, StalePrecondition), contract.ReaderUnavailable},
	} {
		if got := replacementReadState(tc.result); got != tc.want {
			t.Fatal("read outcome collapsed", tc.result, got, tc.want)
		}
	}
}

// full_only: false
func TestReplacementReadResultRetainsUnavailableCauseAndCorrelation(t *testing.T) {
	for _, reason := range []Reason{DifferentSelection, StalePrecondition} {
		before := Result{Outcome: Contention, Reason: reason, StoreReason: contract.ReasonLimit, RequestedRevision: contract.ID{1}, ObservedRevision: contract.ID{2}, ObservedSnapshotID: contract.ID{3}, Evidence: AuthenticatedClosure}
		got := replacementReadResult(before)
		want := before
		want.Outcome = EvidenceUnavailable
		if got != want || replacementReadState(got) != contract.ReaderUnavailable {
			t.Fatal("query owner lost unavailable cause or correlation", got)
		}
	}
	before := refused(CapacityExceeded)
	if got := replacementReadResult(before); got != before || replacementReadState(got) != contract.ReaderRefused {
		t.Fatal("query admission capacity cause changed", got)
	}
}
