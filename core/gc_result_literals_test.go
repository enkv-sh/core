package core

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"enkv.sh/core/contract"
)

func gcEmptyPlanLiteral(t testing.TB) contract.GCPlan {
	t.Helper()
	return contract.GCPlan{
		DomainID: contract.ID{1}, OperationID: contract.ID{2}, RequestNonce: contract.ID{3},
		StoreDescriptorDigest: contract.ID{4}, PublicBasisDigest: contract.ID{5}, SourcePinsDigest: contract.ID{6},
		HeadRevisionID: contract.ID{7}, FullHEADDigest: contract.ID{8}, SnapshotID: contract.ID{9}, RootDigest: contract.ID{10},
		MarkDigest: contract.ID{11}, EnumerationDigest: contract.ID{12},
		TargetsDigest:    gcResultLiteralDigest(t, "de2513225bfa3a375520461c2d7293042f206f8b8d639df2be6ba9292b8624dc"),
		PredecessorToken: contract.Token{Family: contract.GCP, Value: "17"}, InputProviderCursor: "before", NextProviderCursor: "next",
		Candidates: []contract.GCCandidate{
			{Classification: contract.GCCandidateUnverifiable, TargetIndex: 65535, Reason: contract.GCReasonForeign},
			{KeyDigest: contract.ID{14}, Classification: contract.GCCandidateProtected, TargetIndex: 65535, ListedLength: 42},
		},
	}
}

func gcEmptyResultLiteral(t testing.TB) PublicGCResult {
	t.Helper()
	plan := gcEmptyPlanLiteral(t)
	return PublicGCResult{
		Operation: GCApplyOperation, RequestID: contract.ID{13}, OperationID: plan.OperationID, DomainID: plan.DomainID,
		RequestIdentity: gcResultLiteralDigest(t, "e0406db5db851d953b809ecf1e6453b1cdc523b752aa7aa7a01b9d435d55ed78"),
		Result:          Result{Outcome: Unchanged, Evidence: AuthenticatedClosure, ObservedRevision: plan.HeadRevisionID, ObservedSnapshotID: plan.SnapshotID},
		StateResult:     "no-op", EffectSummary: contract.ReceiptEffectNoChange, OutputSummary: contract.ReceiptOutputNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical,
		Payload: &GCCleanupPayload{
			PlanDigest:      gcResultLiteralDigest(t, "4af009b37bc1030609da34e4ab4b9362ae794ad3c40d92d51309660b0f306f01"),
			RequestIdentity: gcResultLiteralDigest(t, "fd71d65af3ff3c9a9a5725794c1f5be5314d0a6361bd336d8d512426cd7d94b1"),
			MarkDigest:      plan.MarkDigest, EnumerationDigest: plan.EnumerationDigest,
			TargetsDescriptor: contract.GCDescriptor{Digest: plan.TargetsDigest, Length: 21, Count: 0},
			SiblingResults:    GCSiblingCommitment{Count: 0, RootDigest: gcResultLiteralDigest(t, "021d7e9f69f2a74856f7538789360a9dce73eb66444ef3279189f4e246a00672")},
			Observation:       PublicObservation{DomainID: plan.DomainID, HeadRevisionID: plan.HeadRevisionID, SnapshotID: plan.SnapshotID, RootDigest: plan.RootDigest},
			NoWork: &GCNoWorkObservation{
				FullHEADDigest: plan.FullHEADDigest,
				TokenDigest:    gcResultLiteralDigest(t, "3e99bbae266a6b3ebcf402527ac157d1fd347b556ee254ad53c2356bc1e7424f"),
				Snapshot:       contract.Ref{Kind: contract.RootKind, Format: 10, Domain: plan.DomainID, Object: plan.SnapshotID, Digest: plan.RootDigest, Length: 2048},
			},
			Candidates: plan.Candidates,
		},
	}
}

// The fixed hashes and field lengths came from independent field framing
// without Product code. The derivation limits are in tests/shared/testdata/README.md.
// full_only: false
func TestGCEmptySiblingResultCommitmentIndependentLiteral(t *testing.T) {
	out := gcEmptyResultLiteral(t)
	plan := gcEmptyPlanLiteral(t)
	encoded, err := contract.EncodeGCPlan(plan)
	if err != nil || len(encoded) != 553 || sha256.Sum256(encoded) != out.Payload.PlanDigest {
		t.Fatal("empty plan differs from independent canonical bytes", err, len(encoded))
	}
	request, err := contract.GCPlanRequestIdentity(plan)
	if err != nil || request != out.Payload.RequestIdentity {
		t.Fatal("original request core differs from independent plan commitment", err, request)
	}
	if contract.GCTargetsEmptyDescriptor() != out.Payload.TargetsDescriptor {
		t.Fatal("empty-work basis differs from independent 21-byte descriptor")
	}
	identity, err := gcNoWorkRequestIdentity(out)
	if err != nil || identity != out.RequestIdentity {
		t.Fatal("empty observation differs from independent 403-byte identity", err, identity)
	}
	sibling, err := GCSiblingResults(out)
	if err != nil || sibling != out.Payload.SiblingResults {
		t.Fatal("empty sibling differs from independent 661-byte result", err, sibling)
	}
	if err := out.Validate(); err != nil {
		t.Fatal("independent empty result rejected", err)
	}
}

func gcResultLiteralDigest(t testing.TB, text string) contract.ID {
	t.Helper()
	body, err := hex.DecodeString(text)
	if err != nil || len(body) != 32 {
		t.Fatal("invalid fixed digest", err)
	}
	return contract.ID(body)
}

func gcSiblingLiteral(t testing.TB, uncertain bool) PublicGCResult {
	t.Helper()
	absence := gcResultLiteralDigest(t, "0f034dfe4e0bda35720ff49c63b533aef1b9f26dc9965a56e27295731360da53")
	request := gcResultLiteralDigest(t, "eb4895e6799ad12453194ff137a000dbc4fd245754f68f902c25423272b6389f")
	result := Result{Outcome: ObservedCurrent, RequestedRevision: contract.ID{15}, ObservedRevision: contract.ID{15}, ObservedSnapshotID: contract.ID{16}, Evidence: AuthenticatedClosure}
	row := GCTargetResult{
		Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: contract.ID{6}},
		Length: 20, Digest: contract.ID{7},
		Selected: contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetAbsent, EvidenceDigest: absence},
		Observed: contract.GCTargetAbsent, ObservedEvidence: absence,
		DeleteAttempted: true, DeleteResult: contract.WriteResult{Status: contract.WriteAcknowledged}, PermissionOwned: true,
	}
	payload := &GCCleanupPayload{
		PlanDigest: contract.ID{11}, RequestIdentity: request, MarkDigest: contract.ID{12}, EnumerationDigest: contract.ID{13},
		TargetsDescriptor: contract.GCDescriptor{Digest: gcResultLiteralDigest(t, "f1020e163bb056c48c7bad4be3081b0c75c3b29749088250b6acc0b9c991d814"), Length: 100, Count: 1},
		Observation:       PublicObservation{DomainID: contract.ID{1}, HeadRevisionID: contract.ID{15}, SnapshotID: contract.ID{16}, RootDigest: contract.ID{17}},
		Closed:            true, ProgressOrdinal: 0x01020305, Targets: []GCTargetResult{row},
		Candidates: []contract.GCCandidate{{KeyDigest: gcResultLiteralDigest(t, "0487bf3cb412495ac322dfbaaf2e787b1901c26897ed632b3506716fa4625f74"), Classification: contract.GCCandidateEligible, TargetIndex: 0, ListedLength: 20}},
	}
	out := PublicGCResult{
		Operation: GCApplyOperation, DomainID: contract.ID{1}, OperationID: contract.ID{5}, RequestIdentity: request, RequestID: contract.ID{10},
		Result: result, StateResult: "success", EffectSummary: contract.ReceiptEffectComplete, OutputSummary: contract.ReceiptOutputNotApplicable,
		EvidenceCeiling: contract.ReceiptEvidenceProviderFacts, SummaryCounts: [4]uint32{1, 0, 0, 0}, Payload: payload,
	}
	if uncertain {
		out.Result = Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: contract.ID{14}, ObservedRevision: contract.ID{15}, ObservedSnapshotID: contract.ID{16}, Evidence: AuthenticatedClosure, CommitMayHaveOccurred: true, StoreReason: contract.ReasonTransport}
		out.StateResult, out.EffectSummary, out.SummaryCounts = "effect-unknown", contract.ReceiptEffectUnknown, [4]uint32{0, 0, 0, 1}
		payload.Active, payload.Closed, payload.SelectionUncertain = true, false, true
		payload.RemainingCount, payload.ProgressOrdinal = 1, 0x01020304
		payload.Targets[0].Selected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetUnknown}
		payload.Targets[0].Observed, payload.Targets[0].ObservationReason = contract.GCTargetUnknown, contract.ReasonTransport
		payload.Targets[0].ObservedEvidence = contract.ID{}
		payload.Targets[0].DeleteResult = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
		payload.Failures = []GCPhaseFailure{{Phase: contract.GCClose, Result: out.Result, Write: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}}}
	}
	return out
}

// full_only: false
func TestGCSiblingResultCommitmentIndependentLiterals(t *testing.T) {
	// The retained Python derivation uses explicit fields and struct/hashlib,
	// without calling the Product codec. These public facts are not a Store read.
	for _, test := range []struct {
		name      string
		uncertain bool
		digest    string
	}{
		{"confirmed-absence-close", false, "c68600b510d9896e0729b4304fc1cd6f6c92acc5b50fbe20494074b17b22f1cc"},
		{"unknown-progress-uncertain-close", true, "662acfb9f148c13ba80fc3787498889648e6b5c3e712360f863ed4040d69dfd7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			out := gcSiblingLiteral(t, test.uncertain)
			got, err := GCSiblingResults(out)
			want := GCSiblingCommitment{Count: 1, RootDigest: gcResultLiteralDigest(t, test.digest)}
			if err != nil || got != want {
				t.Fatalf("sibling commitment: got %+v, want %+v: %v", got, want, err)
			}
			out.Payload.SiblingResults = got
			if err := out.Validate(); err != nil {
				t.Fatal("fixed result rejected", err)
			}
		})
	}
}

// full_only: false
func TestGCRecoveryEvidenceIndependentLiterals(t *testing.T) {
	store := contract.Descriptor{Family: contract.GCP, Prefix: "fixture", HeadKey: "fixture/HEAD", Identity: contract.ID{2}, Coordinate: contract.ID{3}, NonBody: contract.ID{4}}
	plan := contract.GCPlan{DomainID: contract.ID{1}, OperationID: contract.ID{5}}
	target := contract.GCTarget{
		Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: contract.ID{6}},
		Length: 20, Digest: contract.ID{7}, Token: contract.Token{Family: contract.GCP, Value: "17"},
	}
	const ordinal = uint32(0x01020304)
	wantAbsence := gcResultLiteralDigest(t, "0f034dfe4e0bda35720ff49c63b533aef1b9f26dc9965a56e27295731360da53")
	if got := gcAbsenceEvidence(store, plan, target, ordinal); got != wantAbsence {
		t.Fatalf("absence evidence: got %x, want %x", got, wantAbsence)
	}
	permission := &gcDeletePermission{target: target, consumed: 2, used: true, joined: true, result: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}}
	wantNotSent := gcResultLiteralDigest(t, "8f0188296e1aa05f55069dbc041ae233c5f31ebe56b7b99d13c0b7bbded176b5")
	if got := gcNotSentEvidence(store, plan, permission, contract.GCTargetPending, ordinal); got != wantNotSent {
		t.Fatalf("not-sent evidence: got %x, want %x", got, wantNotSent)
	}
}
