package core

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
)

func (e *InstalledApply) installedGeneratedAutomaticStep(ctx context.Context, out *PublicApplyResult, s *StateSession, g *generatedSelection, i ApplyInstallation, deadline time.Time, checkpoint *generatedSelectionCheckpoint) (*StateSession, bool, Result) {
	x, use, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok || x.AttemptID != g.phase.FrontierAttemptID {
		return nil, false, refused(InvalidRelation)
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	var plan *generatedLifecyclePlan
	a, entered := g.attempts[x.AttemptID]
	if !entered {
		if g.phase.Stage != contract.GeneratedStageRetainedResult || i.Generated == nil || i.Generated.RequestDigest == nil {
			return nil, false, refused(InvalidRelation)
		}
		source, err := g.generatedDeleteSource(x.DutyID)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		target, err := g.retirementTarget(ctx, source.Duty)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		intent, err := g.readSelectedSlice(ctx, contract.GeneratorContentIntent, x.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		inputEncoding, err := contract.GeneratorResultInputEncoding(g.bundles[0], x)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		implementation, err := resolveGeneratedImplementation(i, GeneratedImplementationRequest{ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, LifecycleMode: x.LifecycleMode, Retained: &GeneratedImplementationIdentity{ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, Action: x.Action, InputEncoding: inputEncoding, CompletionClass: x.CompletionClass, MaxSecret: use.MaxSecret, MaxFacts: use.MaxFacts}})
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		digest, err := i.Generated.RequestDigest(ctx, implementation, x.Action, intent, &target)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		reservationPlan, err := s.generatedAutomaticReservationRequest(ctx, c, digest)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		prior, result := s.PrepareGeneratedSuccessorReservation(ctx, &admittedGeneratedSuccessorReservation{session: s, plan: reservationPlan})
		if prior == nil {
			return nil, false, result
		}
		var capture *generatedInvocationResultCapture
		p, owner, result := s.installedGeneratedPrepareProducer(ctx, i, prior, x.AttemptID, false, deadline, func(p *generatedPreparation) error {
			var err error
			capture, err = captureGeneratedSelectionStep(ctx, s, g, p.reservation, checkpoint)
			return err
		})
		if owner != nil {
			defer func() {
				if owner != nil {
					owner.Close()
				}
			}()
		}
		if p == nil {
			return nil, false, result
		}
		handoff := p.bindInstalledDelete(owner, out)
		if handoff == nil {
			return nil, false, refused(AdmissionInvalid)
		}
		next, result := s.selectObserved(ctx, p.reservation.candidate)
		if owner != nil {
			owner.Close()
			owner = nil
		}
		recordGeneratedSelection(ctx, out, next, result, capture, checkpoint)
		if out.stopForResultPersistence(ctx, handoff.persistence) {
			return nil, true, result
		}
		ambiguity := handoff.ambiguity
		if next == nil || result.Outcome != ObservedCurrent || len(ambiguity) == 0 {
			return next, true, result
		}
		if !candidateMatches(next, p.reservation.candidate) {
			return nil, false, refused(DifferentSelection)
		}
		// Qualified bodyless facts belong only to this uninterrupted send.
		// Park under a fresh context for the exact selected reservation.
		s = next
		g, err = s.selectedGeneratedWork(ctx)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		c, err = installedGeneratedContext(s, deadline)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		plan, err = s.generatedAutomaticParkPlan(ctx, c, ambiguity)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
	} else {
		if a.expected.Template.Action != contract.GeneratorActionDelete {
			return nil, false, refused(InvalidRelation)
		}
		if a.record.State == contract.GeneratedEffectTransmitted {
			body, found, result := s.ReadGeneratedResult(ctx, a.record.AttemptID)
			if result.Outcome != 0 {
				return nil, false, result
			}
			if !found {
				return nil, false, failure(EvidenceUnavailable, ReadUnavailable)
			}
			record, e := contract.InspectGeneratedResultRecord(body)
			if e != nil {
				return nil, false, installedApplyPreparationFailure(e)
			}
			if record.SafeFacts.Disposition != contract.GeneratorDispositionUnknown {
				return s.recordInstalledGeneratedResult(ctx, i, g, a.record.AttemptID, body, deadline, out, checkpoint)
			}
			facts, e := contract.EncodeGeneratorSafeFacts(record.SafeFacts.GeneratorSafeFacts)
			if e != nil {
				return nil, false, installedApplyPreparationFailure(e)
			}
			plan, err = s.generatedAutomaticParkPlan(ctx, c, facts)
		} else {
			plan, err = s.generatedAutomaticClosePlan(ctx, c)
		}
	}
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	proposal, err := s.deriveGeneratedLifecycle(ctx, plan, nil)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	row, raw, terminal, err := proposal.state.retainedMutationReceipt(g.parent.OperationID)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	var capture *generatedInvocationResultCapture
	if terminal {
		capture, err = captureGeneratedFinalInvocationResult(ctx, s, g, &generatedFinalPlan{}, proposal, checkpoint)
	} else {
		capture, err = captureGeneratedSelectionStep(ctx, s, g, proposal, checkpoint)
	}
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	var payload *TransitionPayload
	if terminal {
		selectedWork, err := proposal.state.selectedGeneratedWork(ctx)
		if err != nil {
			return nil, false, installedApplyPreparationFailure(err)
		}
		payload = installedGeneratedRetirementPayload(proposal.state, selectedWork, row.PredecessorRevisionID)
		payload.RequestedRevisionID, payload.ObservedRevisionID = row.RequestedRevisionID, row.ObservedRevisionID
		payload.ChangedSubjects = ChangedSubjectCommitment{Count: row.ChangedSubjects.Count, IdentityRootDigest: row.ChangedSubjects.Digest}
	}
	permit, err := s.admitGeneratedLifecyclePlan(ctx, plan)
	if err != nil {
		return nil, false, installedApplyPreparationFailure(err)
	}
	candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, i.Trust)
	if candidate == nil {
		return nil, false, result
	}
	next, result := s.selectObserved(ctx, candidate)
	recordGeneratedSelection(ctx, out, next, result, capture, checkpoint)
	if terminal && result.Outcome == ObservedCurrent && candidateMatches(next, candidate) {
		out.Receipt = bytes.Clone(raw)
		out.Payload = payload
		checkpoint.recordSelected(*out)
		e.captureApplyPublication(ctx, next, applyPublicationComplete(*out))
	}
	return next, true, result
}
