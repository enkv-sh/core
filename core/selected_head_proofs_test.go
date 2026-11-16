package core

import (
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestSelectedHeadAuthorizationUsesExactOrdinaryFamily(t *testing.T) {
	id := generatedVectorID
	ordinary, _, _ := observationSelectedPredecessor(t)
	generated := generatedEmptyPredecessor(t)
	reservation, err := generated.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, generated))
	if err != nil {
		t.Fatal(err)
	}
	reserve := contract.OutputReserveSubject{Schema: 5, PublicationIncarnationID: id(23), AdmissionOrdinal: 1, Action: contract.PublicationWriteValue,
		DomainID: id(1), OperationID: id(2), AttemptID: id(3), PredecessorRevisionID: id(6), PredecessorFullHEADDigest: id(7),
		PredecessorToken: contract.Token{Family: contract.GCP, Value: "1"}, CurrentAccessRoot: id(8), ConfigurationDigest: id(9), CoordinateID: id(10),
		BindingIncarnationID: id(11), EntryIncarnationID: id(12), TargetRowDigest: id(13), BirthTargetRowDigest: id(22),
		OwnedBirthAttemptID: id(14), ValueBasisDigest: id(15), PolicyDigest: id(16), RequestContractDigest: id(17), DispatchContextDigest: id(18),
		BlockerCount: 1, BlockerDigest: id(19), HeadCoreDigest: id(20), HeadCoreLength: contract.SuccessorHeadCoreMinLength, ConditionalPlanDigest: id(21)}
	close := contract.OutputCloseSubject{Schema: 4, Action: contract.PublicationWriteValue,
		DomainID: id(1), OperationID: id(2), AttemptID: id(3), ReservationAdmissionDigest: id(6), PredecessorRevisionID: id(7), PredecessorFullHEADDigest: id(8),
		PredecessorToken: contract.Token{Family: contract.GCP, Value: "1"}, CurrentAccessRoot: id(9), ConfigurationDigest: id(10), CoordinateID: id(11),
		BindingIncarnationID: id(12), EntryIncarnationID: id(13), TargetRowDigest: id(14), OwnedBirthAttemptID: id(15), ActionProjectionCommitment: id(16),
		EntryClass: contract.PublicationMayHaveEnteredEntry, ResultClass: contract.PublicationRequestAcknowledged, LateRisk: 1,
		ResultEvidenceDigest: id(17), HeadCoreDigest: id(18), HeadCoreLength: contract.SuccessorHeadCoreMinLength, ConditionalPlanDigest: id(19)}
	end := contract.EndWorkSubject{Schema: contract.CanonicalSchema, DomainID: id(1), OperationID: id(2), AdmissionID: id(4),
		PredecessorRevisionID: id(6), PredecessorFullHEADDigest: id(7), PredecessorToken: contract.Token{Family: contract.AWS, Value: `"old-etag"`},
		TargetGroupID: id(8), TargetOwnerID: id(9), TargetID: id(10), TargetKind: 2, DutyKind: contract.GeneratedDutyCreate,
		SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
		DependentGroups:         contract.GeneratorDescriptor{Digest: id(11), Length: 42, Count: 1}, RemovedSupport: contract.GeneratorDescriptor{Digest: id(12), Length: 42, Count: 1},
		PreservedCurrent: contract.DigestLength{Digest: id(13), Length: 1200}, BeforeAccessRoot: id(17), AfterAccessRoot: id(18),
		BeforeAccessIncarnationID: id(19), AfterAccessIncarnationID: id(19), BeforeAccessGeneration: 2, AfterAccessGeneration: 3,
		BeforeWarningBits: 1, AfterWarningBits: 3, BeforeChildCount: 32, AfterChildCount: 31, BeforeChildBytes: 140000, AfterChildBytes: 139000,
		ReceiptDeltaDigest: id(14), HeadCoreDigest: id(15), HeadCoreLength: contract.SuccessorHeadCoreMinLength, ConditionalPlanDigest: id(16)}
	end.RequestCoreDigest, err = contract.EndWorkRequestCoreDigest(end)
	if err != nil {
		t.Fatal(err)
	}
	gc, _ := gcStateFixture(t, false)
	tests := []struct {
		name    string
		head    format.Head
		request func(format.Head) (contract.SignRequest, error)
	}{
		{"lifecycle", ordinary.head, func(h format.Head) (contract.SignRequest, error) { return contract.NewLifecycleRequest(h.Subject) }},
		{"generator", reservation.candidate.head, func(h format.Head) (contract.SignRequest, error) { return contract.NewGeneratorRequest(*h.Generator) }},
		{"administrative", format.Head{AuthKind: format.AdministrativeAuth, EndWork: &end}, func(h format.Head) (contract.SignRequest, error) { return contract.NewEndWorkRequest(*h.EndWork) }},
		{"output-reserve", format.Head{AuthKind: format.OutputReserveAuth, OutputReserve: &reserve}, func(h format.Head) (contract.SignRequest, error) {
			return contract.NewOutputReserveRequest(*h.OutputReserve)
		}},
		{"output-close", format.Head{AuthKind: format.OutputCloseAuth, OutputClose: &close}, func(h format.Head) (contract.SignRequest, error) {
			return contract.NewOutputCloseRequest(*h.OutputClose)
		}},
		{"gc", gc.head, func(h format.Head) (contract.SignRequest, error) { return contract.NewGCRequest(*h.GC) }},
	}
	signer := testtrust.New(t, contract.GCP, id(244))
	control := contract.ControlCore{CurrentControl: contract.CurrentControl{NormalSigning: contract.PublicSigningBinding{SPKI: signer.PublicKey()}}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := test.request(test.head)
			if err != nil {
				t.Fatal("invalid test subject", err)
			}
			head := test.head
			proof := signer.Sign(t.Context(), request)
			if proof.Reason != contract.ReasonNone || len(proof.Signature) == 0 {
				t.Fatal("test signer refused", proof.Reason)
			}
			head.AuthorizationSignature = proof.Signature
			if !selectedHeadAuthorizationProofs(head, control, nil) {
				t.Fatal("exact family proof refused")
			}
			head.AuthKind = 255
			if selectedHeadAuthorizationProofs(head, control, nil) {
				t.Fatal("unknown family inherited another authorization")
			}
			head = test.head
			head.AuthorizationSignature = proof.Signature
			head.Generator, head.EndWork, head.OutputReserve, head.OutputClose, head.GC = nil, nil, nil, nil, nil
			if head.AuthKind == format.LifecycleAuth {
				head.Subject.Request[0] ^= 1
			}
			if selectedHeadAuthorizationProofs(head, control, nil) {
				t.Fatal("missing subject or changed lifecycle commitment accepted")
			}
		})
	}
}
