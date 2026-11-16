package core

import (
	"context"
	"strings"
	"time"

	"enkv.sh/core/contract"
)

func captureInstalledGeneratedCleanupObservation(ctx context.Context, s *StateSession, work *generatedSelection, proposal *generatedReservation, checkpoint *generatedSelectionCheckpoint) (*generatedCleanupResultCapture, error) {
	if work.parent == nil || work.phase == nil || len(work.bundles) == 0 || !installedGeneratedCleanupGraph(work.bundles[0]) {
		return nil, contract.ErrRecord
	}
	a, present := work.attempts[work.phase.FrontierAttemptID]
	if !present {
		return nil, contract.ErrRecord
	}
	source, err := work.generatedDeleteSource(a.record.OwnerID)
	if err != nil {
		return nil, err
	}
	key := generatedRecordKey{contract.GeneratedAttemptSupportKind, a.record.AttemptID}
	scope := generatedInvocationResultScope{OperationKind: contract.OperationCleanOwnedFailureResidue, OperationID: a.record.OperationID,
		RequestIdentity: work.parent.RequestIdentityDigest, OriginalPredecessorRevisionID: work.bundles[0].Request.PredecessorRevisionID,
		Effects: []contract.SupportRecord{work.records[key]}, EffectClasses: map[contract.ID]int{a.record.AttemptID: installedGeneratedCleanupObservedClass(a.record)}}
	if source.Record.Kind == contract.GeneratedDutySupportKind {
		scope.RelatedDutyIDs = []contract.ID{source.SourceID}
	} else {
		scope.RelatedHazardIDs = []contract.ID{source.SourceID}
	}
	if proposal != nil {
		selected, err := proposal.state.selectedGeneratedWork(ctx)
		if err != nil {
			return nil, err
		}
		row, present := selected.records[key]
		if !present {
			return nil, contract.ErrRecord
		}
		record, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil {
			return nil, err
		}
		scope.observedEffects = scope.Effects
		scope.observedEffectClasses = scope.EffectClasses
		scope.Effects = []contract.SupportRecord{row}
		scope.EffectClasses = map[contract.ID]int{record.AttemptID: installedGeneratedCleanupObservedClass(record)}
		scope.receiptFree = true
		scope.receiptFreeState = "effect-pending"
		if record.State == contract.GeneratedEffectFailedTerminal {
			scope.receiptFreeState = "effect-terminal-failure"
		}
		if row, present := selected.records[generatedRecordKey{source.Record.Kind, source.SourceID}]; present {
			if source.Record.Kind == contract.GeneratedDutySupportKind {
				scope.Duties = []contract.SupportRecord{row}
			} else {
				scope.Hazards = []contract.SupportRecord{row}
			}
		}
	}
	if checkpoint != nil && checkpoint.valid {
		scope.borrowedObserved = checkpoint.ownedBefore(s, scope.OperationKind, scope.OperationID)
		if scope.borrowedObserved == nil {
			return nil, contract.ErrRecord
		}
	}
	common, err := captureGeneratedInvocationResult(ctx, s, work, scope, proposal)
	if err != nil {
		return nil, err
	}
	basis, err := generatedCleanupBasisForEffect(work, GeneratedCleanupOwnedTarget, generatedRecordKey{source.Record.Kind, source.SourceID}, common.observed.Effects[0], nil)
	if err != nil {
		return nil, err
	}
	return newGeneratedCleanupResultCapture(ctx, s, work, common, basis, scope.OriginalPredecessorRevisionID, proposal, checkpoint)
}

// The adoption boundary captures both exact public closures before its CAS.
// The later close step can fail without losing the adopted original result.
func (s *StateSession) recordInstalledGeneratedCleanupResult(ctx context.Context, i ApplyInstallation, work *generatedSelection, attempt contract.ID, body []byte, deadline time.Time, out PublicApplyResult, checkpoint *generatedSelectionCheckpoint) (*StateSession, PublicApplyResult) {
	if i.Generated == nil || i.Generated.AdmitAdoption == nil {
		return nil, checkpoint.preparationFailure(ctx, out, refused(AdmissionInvalid))
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	plan, err := s.generatedRecordRequest(ctx, attempt, body, c)
	if err != nil {
		return nil, cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	input, err := s.installedGeneratedAdoptionInput(ctx, work, plan)
	if err != nil {
		return nil, cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	owner, err := i.Generated.AdmitAdoption(ctx, plan.request, currentControlOf(s), input, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		return nil, cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	defer owner.Close()
	p, result := s.PrepareGeneratedRecord(ctx, &admittedGeneratedRecord{session: s, plan: plan, crypto: owner.Crypto, instance: owner.Crypto.InstanceID(), deadline: deadline})
	if p == nil {
		return nil, checkpoint.preparationFailure(ctx, out, result)
	}
	capture, err := captureInstalledGeneratedCleanupObservation(ctx, s, work, p.reservation, checkpoint)
	if err != nil {
		return nil, cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	if err := capture.prevalidate(out, i); err != nil {
		return nil, cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	candidateInput, err := s.installedGeneratedCandidate(ctx, p.reservation, nil)
	if err != nil {
		return nil, cleanupPreparationFailure(ctx, checkpoint, out, err)
	}
	if owner.BindCandidate(ctx, candidateInput) != contract.CryptoSuccess {
		return nil, checkpoint.preparationFailure(ctx, out, refused(AdmissionInvalid))
	}
	candidate, result := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, i.Trust)
	if candidate == nil {
		return nil, checkpoint.preparationFailure(ctx, out, result)
	}
	next, result := s.selectObserved(ctx, candidate)
	recordInstalledGeneratedCleanupSelection(ctx, &out, next, result, capture, checkpoint)
	if result.RequestedRevision.IsZero() {
		return nil, out
	}
	return next, out
}

func captureInstalledGeneratedCleanupReservation(ctx context.Context, s *StateSession, work *generatedSelection, reservation *generatedReservation, attemptID contract.ID, source generatedRecordKey, target contract.GeneratorTarget) (*generatedCleanupResultCapture, error) {
	selected, err := reservation.state.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	a, present := selected.attempts[attemptID]
	if !present || selected.parent == nil {
		return nil, contract.ErrRecord
	}
	scope := generatedInvocationResultScope{OperationKind: contract.OperationCleanOwnedFailureResidue, OperationID: a.record.OperationID, RequestIdentity: selected.parent.RequestIdentityDigest,
		OriginalPredecessorRevisionID: s.head.Core.Revision, EffectClasses: map[contract.ID]int{a.record.AttemptID: contract.ReceiptSummaryUnknownCount}}
	effects := []contract.SupportRecord{selected.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, a.record.AttemptID}]}
	if source.kind == contract.GeneratedDutySupportKind {
		scope.RelatedDutyIDs = []contract.ID{source.id}
	} else {
		scope.RelatedHazardIDs = []contract.ID{source.id}
	}
	duties, hazards, err := generatedObservedInvocationWork(selected, scope)
	if err != nil {
		return nil, err
	}
	common := &generatedInvocationResultCapture{observed: GeneratedInvocationResult{OperationKind: contract.OperationCleanOwnedFailureResidue, StateResult: "commit-outcome-unknown", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical}, hasCandidate: true}
	common.selected, err = generatedInvocationFacts(ctx, selected, scope, effects, duties, hazards)
	if err != nil {
		return nil, err
	}
	common.candidate.head.Core = reservation.candidate.head.Core
	common.candidate.head.Core.PreviousToken.Value = strings.Clone(common.candidate.head.Core.PreviousToken.Value)
	common.candidate.head.AuthKind, common.candidate.head.Subject = reservation.candidate.head.AuthKind, reservation.candidate.head.Subject
	if reservation.candidate.head.Generator != nil {
		subject := *reservation.candidate.head.Generator
		common.candidate.head.Generator = &subject
	}
	common.backingBytes, err = generatedInvocationCaptureBackingBytes(common)
	if err != nil {
		return nil, err
	}
	basis, err := generatedCleanupBasisForEffect(selected, GeneratedCleanupOwnedTarget, source, common.selected.Effects[0], nil)
	if err != nil {
		return nil, err
	}
	basis.Target = &target
	return newGeneratedCleanupResultCapture(ctx, s, work, common, basis, s.head.Core.Revision, reservation, nil)
}

func cleanupDeliveryDefect(out *PublicApplyResult) {
	out.Diagnostics = append(out.Diagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedRelationInvalid})
}

func cleanupPreparationFailure(ctx context.Context, checkpoint *generatedSelectionCheckpoint, out PublicApplyResult, err error) PublicApplyResult {
	return checkpoint.preparationFailure(ctx, out, installedApplyPreparationFailure(err))
}
func preserveInstalledGeneratedCleanupObserved(ctx context.Context, out PublicApplyResult, s *StateSession, work *generatedSelection, checkpoint *generatedSelectionCheckpoint) PublicApplyResult {
	if checkpoint.valid {
		return out
	}
	return installedGeneratedCleanupObserved(ctx, out, s, work)
}
