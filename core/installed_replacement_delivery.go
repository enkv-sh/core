package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (e *installedReplacement) deliver(ctx context.Context, s *StateSession, candidate *Candidate, i ReplacementInstallation, guard *installedMutationGuard) Result {
	next := candidate.replacementState
	if next == nil || candidate.requestIdentity.IsZero() || len(candidate.body) == 0 || len(candidate.body) > contract.MaxHeadLength {
		return refused(AdmissionInvalid)
	}
	actual := currentControlOf(next)
	controlBytes, err := contract.EncodeControlCore(actual)
	if err != nil {
		return refused(InvalidRelation)
	}
	control, err := contract.DecodeControlCore(controlBytes)
	if err != nil {
		return refused(InvalidRelation)
	}
	recipients, err := ownReplacementRecipients(i.CapturedRecipients)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	if e.target == ReplacementTargetRecipient {
		if int(e.recipientRow) >= len(recipients) || recipients[e.recipientRow].RecipientID != e.recipient {
			return refused(AdmissionInvalid)
		}
		record := next.recipientRecord(e.recipient)
		if record == nil || record.Status != contract.CurrentRecipient || record.CurrentBinding == nil {
			return refused(InvalidRelation)
		}
		binding, err := contract.EncodeKMSBinding(*record.CurrentBinding)
		if err != nil {
			return refused(InvalidRelation)
		}
		recipients[e.recipientRow].Encryption, err = contract.DecodeKMSBinding(binding)
		if err != nil {
			return refused(InvalidRelation)
		}
	}
	basis := i.PublicBasis
	if e.target != ReplacementTargetRecipient {
		if candidate.succession == nil || candidate.succession.basis == nil || !candidate.successionBasisReady(s, candidate.succession.request) {
			return refused(AdmissionInvalid)
		}
		admission := s.admission
		admission.current = candidate.succession.basis.clone()
		admission.observation = nil
		admission.descriptor = nil
		basis = admission.publicBasis()
	}
	expectedBasis := basis
	basis, err = basis.own()
	if err != nil {
		return refused(InvalidRelation)
	}
	head, err := format.DecodeHead(candidate.body)
	if err != nil || head.Core != candidate.head.Core || !selectedHeadProofs(head, actual, nil) {
		return refused(InvalidProof)
	}
	if e.target == ReplacementTargetRecipient {
		actor := s.installedReplacement
		if head.AuthKind != format.LifecycleAuth || actor == nil || head.Subject.Operation != actor.operation || head.Subject.Recipient != s.admission.recipient || !actor.matchesRecipient(s, actor.intent) {
			return refused(InvalidProof)
		}
		if head.Subject.Request != actor.requestDigest || actor.requestDigest.IsZero() {
			return refused(InvalidProof)
		}
	} else {
		actor := s.installedReplacement
		if actor == nil || head.AuthKind != format.SuccessionAuth || head.Succession == nil || head.Succession.Subject.RequestIdentityDigest != candidate.requestIdentity || head.Succession.Subject.MaterialSourceRole != replacementMaterialRole(actor.goal.MaterialSource) || head.Succession.Subject.OperationID != actor.operation || head.Succession.Subject.ChangeMask != actor.mask || head.Succession.Subject.ApprovalRole != actor.goal.ApprovalRole {
			return refused(InvalidProof)
		}
		authorizer := currentControlOf(s).NormalSigning
		if actor.goal.ApprovalRole == contract.RecoverySigningRole {
			authorizer = currentControlOf(s).Recovery.Signing
		}
		if !signingBindingEqual(head.Succession.Authorizer, authorizer) {
			return refused(InvalidProof)
		}
	}
	operation := s.installedReplacement.operation
	correlation := ReplacementCorrelation{Target: e.target, RecipientID: e.recipient, RequestIdentity: candidate.requestIdentity, SignedCandidate: bytes.Clone(candidate.body)}
	successor := ReplacementSuccessor{DomainID: s.root.Domain, OperationID: operation, RequestIdentity: candidate.requestIdentity, Control: control, Recipients: recipients, Basis: basis, Correlation: correlation}
	if guard.check(ctx) != contract.ReasonNone {
		return refused(AdmissionInvalid)
	}
	expectedRecipients, err := ownReplacementRecipients(recipients)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	readback, err := i.PublishSuccessor(ctx, successor)
	if err != nil || guard.check(ctx) != contract.ReasonNone {
		return refused(AdmissionInvalid)
	}
	if readback.FileIdentity != i.FileIdentity || readback.Correlation.Target != e.target || readback.Correlation.RecipientID != e.recipient || readback.Correlation.RequestIdentity != candidate.requestIdentity || len(readback.Correlation.SignedCandidate) > contract.MaxHeadLength || !bytes.Equal(readback.Correlation.SignedCandidate, candidate.body) {
		return refused(AdmissionInvalid)
	}
	readback.Basis, err = readback.Basis.own()
	if err != nil || !sameReplacementBasis(readback.Basis, expectedBasis) {
		return refused(AdmissionInvalid)
	}
	readback.Recipients, err = ownReplacementRecipients(readback.Recipients)
	if err != nil || !sameReplacementRecipients(readback.Recipients, expectedRecipients) {
		return refused(AdmissionInvalid)
	}
	if e.target == ReplacementTargetRecipient {
		if !CurrentControlMatches(actual, readback.Control) {
			return refused(AdmissionInvalid)
		}
	} else if !sameControl(actual, readback.Control) {
		return refused(AdmissionInvalid)
	}
	// The callback basis is admitted only after exact comparison with Core's
	// independently qualified successor or unchanged source basis.
	admission, result := admitBorrowedPublicNormal(ctx, i.ExpectedDomain, i.ExpectedStore, readback.Basis, i.Store, i.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		return result
	}
	if candidate.succession != nil {
		owned := *admission.admission
		candidate.succession.selectionAdmission = &owned
	}
	return Result{}
}

func sameReplacementBasis(a, b PublicBasis) bool {
	return bytes.Equal(a.Descriptor, b.Descriptor) && bytes.Equal(a.Control, b.Control) && bytes.Equal(a.Selection, b.Selection) && slices.Equal(a.Enrollment, b.Enrollment) && bytes.Equal(a.SigningAnchor, b.SigningAnchor) && bytes.Equal(a.StoreConfiguration, b.StoreConfiguration) && bytes.Equal(a.HEAD, b.HEAD) && bytes.Equal(a.Root, b.Root) && slices.EqualFunc(a.RecipientPages, b.RecipientPages, bytes.Equal)
}
func sameReplacementRecipients(a, b []ReplacementRecipientFact) bool {
	if len(a) != len(b) {
		return false
	}
	for i, row := range a {
		if row.RecipientID != b[i].RecipientID || !kmsBindingEqual(row.Encryption, b[i].Encryption) {
			return false
		}
	}
	return true
}
func replacementCandidateReceipt(ctx context.Context, s *StateSession, operation, identity contract.ID, target ReplacementTarget) ([]byte, error) {
	windows, err := s.receiptWindows(ctx)
	if err != nil {
		return nil, err
	}
	kind := uint16(contract.OperationRotateRecipientKeyBinding)
	if target == ReplacementTargetRecovery {
		kind = contract.OperationReplaceRecoveryKeysAndRoot
	}
	var found *contract.CompactMutationReceipt
	for _, row := range windows.Successes {
		if row.OperationID != operation {
			continue
		}
		if found != nil || row.OperationKind != kind || row.RequestIdentityDigest != identity || row.RequestedRevisionID != s.head.Core.Revision || row.ObservedRevisionID != s.head.Core.Revision {
			return nil, contract.ErrRecord
		}
		own := row
		found = &own
	}
	if found == nil {
		return nil, contract.ErrRecord
	}
	return contract.EncodeCompactMutationReceipt(*found)
}
func (s *StateSession) replacementWorkIDs() ([]contract.ID, []contract.ID, error) {
	duties, hazards := make([]contract.ID, 0, s.root.Generated.Duties), make([]contract.ID, 0, s.root.Generated.Hazards)
	for _, page := range s.adminIndex.Pages {
		for _, row := range page.Rows {
			switch row.Kind {
			case contract.GeneratedDutySupportKind:
				duties = append(duties, row.RecordID)
			case contract.GeneratedHazardSupportKind:
				hazards = append(hazards, row.RecordID)
			}
		}
	}
	order := func(rows []contract.ID) []contract.ID {
		slices.SortFunc(rows, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		return slices.Compact(rows)
	}
	duties, hazards = order(duties), order(hazards)
	if uint32(len(duties)) != s.root.Generated.Duties || uint32(len(hazards)) != s.root.Generated.Hazards {
		return nil, nil, contract.ErrRecord
	}
	return duties, hazards, nil
}
