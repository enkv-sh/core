package core

import (
	"bytes"
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type installedGeneratedDeleteReturn struct {
	ambiguity   []byte
	persistence Result
}

func (p *generatedPreparation) bindInstalledDelete(owner *InstalledGeneratedProducerCustody, out *PublicApplyResult) *installedGeneratedDeleteReturn {
	handoff := new(installedGeneratedDeleteReturn)
	if !p.reservation.candidate.bindFirstSend(p, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		returned, persistence := p.invokeInstalledProducer(ctx, owner, authority)
		handoff.persistence = persistence
		if returned.ExecutableCleanupFailed {
			out.AddCleanupDiagnostic()
		}
		if returned.Code == contract.CryptoCustodyUnavailable && len(returned.RejectedRetirement) != 0 && len(returned.Record) == 0 && len(returned.RetirementAmbiguity) == 0 {
			facts, err := contract.InspectGeneratorAttemptFacts(returned.RejectedRetirement)
			if err != nil || !facts.RetirementRejected {
				return contract.CryptoInvalidInput
			}
			handoff.ambiguity = bytes.Clone(returned.RejectedRetirement)
		}
		if returned.Code == contract.CryptoSuccess && len(returned.Record) == 0 && returned.Facts.Disposition == contract.GeneratorDispositionUnknown {
			var err error
			handoff.ambiguity, err = contract.EncodeGeneratorSafeFacts(returned.Facts)
			if err != nil {
				return contract.CryptoInvalidInput
			}
		}
		return returned.Code
	}) {
		return nil
	}
	return handoff
}

func (s *StateSession) prepareInstalledGeneratedDelete(ctx context.Context, i ApplyInstallation, plan *generatedPlan, deadline time.Time, capture func(*generatedReservation, contract.ID) error) (*generatedPreparation, *InstalledGeneratedProducerCustody, Result) {
	if plan == nil || plan.phase == nil || i.Generated == nil || i.Generated.AdmitReservation == nil ||
		i.Generated.AdmitProducer == nil || i.Generated.AdmitAdoption == nil || i.Generated.RequestDigest == nil || len(plan.input.graph.Lineages) != 1 {
		return nil, nil, refused(AdmissionInvalid)
	}
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	selected, found, err := s.generatedDeleteReservationSelection(ctx, plan.input.graph, work)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	if !found || selected.phase != *plan.phase {
		return nil, nil, refused(InvalidRelation)
	}
	session, proposal, err := s.installedGeneratedSession(ctx, plan.input.graph, plan.input.declaration, plan.input.registryImage, nil)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	input := contract.GeneratedReservationInput{Session: session, Plan: proposal, Phase: plan.phase, Target: &selected.target}
	if selected.source.CompletionClass == contract.GeneratedCompletionConfirmed {
		input.ControlledPredecessor, err = s.installedGeneratedControlledPredecessor(ctx, work, selected.source)
		if err != nil {
			return nil, nil, installedApplyPreparationFailure(err)
		}
	}
	owner, err := i.Generated.AdmitReservation(ctx, plan.request, currentControlOf(s), input, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		return nil, nil, installedApplyPreparationFailure(err)
	}
	prior, result := s.PrepareGeneratedPlan(ctx, &admittedGeneratedPlan{session: s, plan: plan, crypto: owner.Crypto, instance: owner.Crypto.InstanceID(), deadline: deadline})
	if prior == nil {
		owner.Close()
		return nil, nil, result
	}
	if prior.reservation == nil || prior.reservation.state == nil || prior.reservation.candidate == nil ||
		prior.reservation.state.root.Domain != s.root.Domain || !candidateMatches(prior.reservation.state, prior.reservation.candidate) {
		owner.Close()
		return nil, nil, refused(InvalidRelation)
	}
	if capture != nil {
		if err := capture(prior.reservation, selected.template.AttemptID); err != nil {
			owner.Close()
			return nil, nil, installedApplyPreparationFailure(err)
		}
	}
	candidate, err := s.installedGeneratedCandidate(ctx, prior.reservation, nil)
	if err != nil {
		owner.Close()
		return nil, nil, installedApplyPreparationFailure(err)
	}
	if owner.BindCandidate(ctx, candidate) != contract.CryptoSuccess {
		owner.Close()
		return nil, nil, refused(AdmissionInvalid)
	}
	if _, result = s.ClaimGeneratedPreparation(ctx, prior.reservation.candidate, i.Trust); result.Outcome != ObservedCurrent {
		owner.Close()
		return nil, nil, result
	}
	owner.Close()
	return s.installedGeneratedPrepareProducer(ctx, i, prior, selected.template.AttemptID, false, deadline)
}

func (s *StateSession) recordInstalledGeneratedResult(ctx context.Context, i ApplyInstallation, work *generatedSelection, attempt contract.ID, body []byte, deadline time.Time, out *PublicApplyResult, checkpoint *generatedSelectionCheckpoint) (*StateSession, bool, Result) {
	if i.Generated == nil || i.Generated.AdmitAdoption == nil {
		return nil, false, refused(AdmissionInvalid)
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	plan, err := s.generatedRecordRequest(ctx, attempt, body, c)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	input, err := s.installedGeneratedAdoptionInput(ctx, work, plan)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	owner, err := i.Generated.AdmitAdoption(ctx, plan.request, currentControlOf(s), input, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		return nil, false, installedApplyPreparationFailure(err)
	}
	return s.recordInstalledGeneratedPlan(ctx, i, work, plan, owner, deadline, out, checkpoint)
}

func (s *StateSession) recordInstalledGeneratedLocalFailure(ctx context.Context, i ApplyInstallation, work *generatedSelection, attempt contract.ID, reason uint8,
	admit func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedLocalFailureInput, time.Time) (*InstalledGeneratedCustody, error),
	deadline time.Time, out *PublicApplyResult, checkpoint *generatedSelectionCheckpoint) (*StateSession, bool, Result) {
	if admit == nil {
		return nil, false, refused(AdmissionInvalid)
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	plan, err := s.generatedLocalFailureRequest(ctx, attempt, reason, c)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	input, err := s.installedGeneratedLocalFailureInput(ctx, work, plan)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	owner, err := admit(ctx, plan.request, currentControlOf(s), input, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		return nil, false, installedApplyPreparationFailure(err)
	}
	return s.recordInstalledGeneratedPlan(ctx, i, work, plan, owner, deadline, out, checkpoint)
}

func (s *StateSession) recordInstalledGeneratedPlan(ctx context.Context, i ApplyInstallation, work *generatedSelection, plan *generatedRecordPlan, owner *InstalledGeneratedCustody, deadline time.Time, out *PublicApplyResult, checkpoint *generatedSelectionCheckpoint) (*StateSession, bool, Result) {
	defer owner.Close()
	p, result := s.PrepareGeneratedRecord(ctx, &admittedGeneratedRecord{session: s, plan: plan, crypto: owner.Crypto, instance: owner.Crypto.InstanceID(), deadline: deadline})
	if p == nil {
		return nil, false, result
	}
	capture, err := captureGeneratedSelectionStep(ctx, s, work, p.reservation, checkpoint)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	candidateInput, err := s.installedGeneratedCandidate(ctx, p.reservation, nil)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	if owner.BindCandidate(ctx, candidateInput) != contract.CryptoSuccess {
		return nil, false, refused(AdmissionInvalid)
	}
	candidate, result := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, i.Trust)
	if candidate == nil {
		return nil, false, result
	}
	next, result := s.selectObserved(ctx, candidate)
	if result.RequestedRevision.IsZero() {
		return nil, false, result
	}
	recordGeneratedSelection(ctx, out, next, result, capture, checkpoint)
	return next, true, result
}

func (e *InstalledApply) driveInstalledGeneratedRetirement(ctx context.Context, out PublicApplyResult, s *StateSession, i ApplyInstallation, deadline time.Time, ambiguity []byte, call *telemetry.Call, checkpoint *generatedSelectionCheckpoint) PublicApplyResult {
	fail := func(result Result) PublicApplyResult { return checkpoint.preparationFailure(ctx, out, result) }
	// One exact delete can adopt its original result and close or park. This
	// driver never prepares another producer or restores a send entitlement.
	for stage := 0; stage < 2; stage++ {
		work, err := s.selectedGeneratedWork(ctx)
		if err != nil {
			return fail(installedApplyPreparationFailure(err))
		}
		if work.parent == nil || work.phase == nil || work.parent.OperationID != out.OperationID || len(work.bundles) == 0 ||
			work.bundles[0].Request.OperationKind != contract.OperationRetireGeneratedGeneration {
			return fail(refused(InvalidRelation))
		}
		a, found := work.attempts[work.phase.FrontierAttemptID]
		if !found || a.expected.Template.Action != contract.GeneratorActionDelete {
			return fail(refused(InvalidRelation))
		}
		out.RequestIdentity = work.parent.RequestIdentityDigest
		c, err := installedGeneratedContext(s, deadline)
		if err != nil {
			return fail(installedApplyPreparationFailure(err))
		}
		if !checkpoint.valid {
			scope, err := generatedActiveResultScope(work)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			facts, err := generatedInvocationFacts(ctx, work, scope, scope.Effects, scope.Duties, scope.Hazards)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			out.Generated = &facts
			out.Result = s.observed(ObservedCurrent)
			checkpoint.rememberObserved(s, out)
		}
		if a.record.State == contract.GeneratedEffectTransmitted {
			body, present, result := s.ReadGeneratedResult(ctx, a.record.AttemptID)
			if result.Outcome != 0 {
				return fail(result)
			}
			if present {
				call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
				next, selected, result := s.recordInstalledGeneratedResult(ctx, i, work, a.record.AttemptID, body, deadline, &out, checkpoint)
				if !selected {
					return fail(result)
				}
				if next == nil || result.Outcome != ObservedCurrent {
					return out
				}
				s = next
				continue
			}
			if len(ambiguity) == 0 {
				reader := retirementEvidenceReader{s.admission.store.Prefix, s.storeRead}
				ambiguity, err = reader.load(ctx, work, a)
				if err != nil {
					return fail(installedApplyPreparationFailure(err))
				}
				if len(ambiguity) == 0 {
					return out
				}
			}
			plan, err := s.generatedRetirementAmbiguityPlan(ctx, a.record.OwnerID, ambiguity, c, false)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			return selectInstalledGeneratedRetirementLifecycle(ctx, out, s, work, plan, i, call, checkpoint)
		}
		plan, err := s.generatedRetirementClosePlan(ctx, a.record.AttemptID, c)
		if err != nil {
			return fail(installedApplyPreparationFailure(err))
		}
		return selectInstalledGeneratedRetirementLifecycle(ctx, out, s, work, plan, i, call, checkpoint)
	}
	return fail(refused(CapacityExceeded))
}

func selectInstalledGeneratedRetirementLifecycle(ctx context.Context, out PublicApplyResult, s *StateSession, work *generatedSelection, plan *generatedLifecyclePlan, i ApplyInstallation, call *telemetry.Call, checkpoint *generatedSelectionCheckpoint) PublicApplyResult {
	fail := func(result Result) PublicApplyResult { return checkpoint.preparationFailure(ctx, out, result) }
	proposal, err := s.deriveGeneratedLifecycle(ctx, plan, nil)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	capture, err := captureGeneratedLifecycleInvocationResult(ctx, s, work, plan, proposal, checkpoint)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	selectedWork, err := proposal.state.selectedGeneratedWork(ctx)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	row, raw, found, err := proposal.state.retainedMutationReceipt(out.OperationID)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	var payload *TransitionPayload
	var receipt []byte
	if found {
		receipt = bytes.Clone(raw)
		payload = installedGeneratedRetirementPayload(proposal.state, selectedWork, row.PredecessorRevisionID)
		payload.RequestedRevisionID, payload.ObservedRevisionID = row.RequestedRevisionID, row.ObservedRevisionID
		payload.ChangedSubjects = ChangedSubjectCommitment{Count: row.ChangedSubjects.Count, IdentityRootDigest: row.ChangedSubjects.Digest}
	}
	permit, err := s.admitGeneratedLifecyclePlan(ctx, plan)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, i.Trust)
	if candidate == nil {
		return fail(result)
	}
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	next, result := s.selectObserved(ctx, candidate)
	if result.RequestedRevision.IsZero() {
		return fail(result)
	}
	recordGeneratedSelection(ctx, &out, next, result, capture, checkpoint)
	if next == nil || result.Outcome != ObservedCurrent {
		return out
	}
	if !candidateMatches(next, proposal.candidate) {
		return out
	}
	if found {
		out.Receipt = receipt
		out.Payload = payload
	}

	out.WarningBits = next.root.WarningBits
	checkpoint.recordSelected(out)
	releaseInstalledGeneratedInboxes(ctx, next, out.OperationID, i.Trust, time.Unix(0, int64(plan.context.Expiry)))
	return out
}

func installedGeneratedRetirementPayload(s *StateSession, work *generatedSelection, predecessor contract.ID) *TransitionPayload {
	payload := &TransitionPayload{PredecessorRevisionID: predecessor, ObservedRevisionID: s.head.Core.Revision}
	for key := range work.records {
		if key.kind == contract.GeneratedDutySupportKind {
			payload.LiveDutyIDs = append(payload.LiveDutyIDs, key.id)
		}
		if key.kind == contract.GeneratedHazardSupportKind {
			payload.LiveHazardIDs = append(payload.LiveHazardIDs, key.id)
		}
	}
	slices.SortFunc(payload.LiveDutyIDs, compareGeneratedIDs)
	slices.SortFunc(payload.LiveHazardIDs, compareGeneratedIDs)
	return payload
}
