package core

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func (e *InstalledApply) applyGenerated(ctx context.Context, requestID contract.ID, s *StateSession, i ApplyInstallation, input []ApplyEntryInput, output *outputApplyInput, deadline time.Time) (returned PublicApplyResult) {
	defer func() { qualifyGeneratedInvocationResult(i, &returned) }()
	out := PublicApplyResult{RequestID: requestID, DomainID: i.ExpectedDomain, WarningBits: s.root.WarningBits, Result: refused(AdmissionInvalid)}
	if i.Generated == nil || i.Generated.AdmitReservation == nil || i.Generated.AdmitProducer == nil || i.Generated.AdmitAdoption == nil || i.Generated.AdmitFinal == nil {
		return out
	}
	plan, err := s.installedGeneratedPlan(ctx, i, input, output, deadline)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		var binding *sealedInputBindingError
		if errors.As(err, &binding) {
			out.Diagnostics = []contract.Diagnostic{staleSealedInputBindingDiagnostic(binding.name)}
		}
		return out
	}
	out.OperationID = plan.input.graph.Request.OperationID
	session, proposal, err := s.installedGeneratedSession(ctx, plan.input.graph, plan.input.declaration, plan.input.registryImage, plan.input.outputConfiguration)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	owner, err := i.Generated.AdmitReservation(ctx, plan.request, currentControlOf(s), contract.GeneratedReservationInput{Session: session, Plan: proposal, Phase: plan.phase}, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	prior, result := s.PrepareGeneratedPlan(ctx, &admittedGeneratedPlan{session: s, plan: plan, crypto: owner.Crypto, instance: owner.Crypto.InstanceID(), deadline: deadline})
	if prior == nil {
		owner.Close()
		out.Result = result
		return out
	}
	candidateInput, err := s.installedGeneratedCandidate(ctx, prior.reservation, nil)
	if err != nil {
		owner.Close()
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if owner.BindCandidate(ctx, candidateInput) != contract.CryptoSuccess {
		owner.Close()
		return out
	}
	if _, result = s.ClaimGeneratedPreparation(ctx, prior.reservation.candidate, i.Trust); result.Outcome != ObservedCurrent {
		owner.Close()
		out.Result = result
		return out
	}
	owner.Close()
	out.RequestIdentity = prior.reservation.identity.RequestIdentityDigest
	producers := make([]*generatedPreparation, 0, len(prior.reservation.originalAttempts))
	owners := make([]*InstalledGeneratedProducerCustody, 0, len(prior.reservation.originalAttempts))
	defer func() {
		for _, owner := range owners {
			owner.Close()
		}
	}()
	for _, attempt := range prior.reservation.originalAttempts {
		producer, custody, result := s.installedGeneratedPrepareProducer(ctx, i, prior, attempt, true, deadline)
		if custody != nil {
			owners = append(owners, custody)
		}
		if producer == nil {
			out.Result = result
			return out
		}
		producers = append(producers, producer)
	}
	candidate, result := s.ClaimGeneratedOriginalSet(ctx, producers, i.Trust)
	if candidate == nil {
		out.Result = result
		return out
	}
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	var checkpoint generatedSelectionCheckpoint
	capture, err := captureGeneratedSelectionStep(ctx, s, work, prior.reservation, &checkpoint)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	var persistence Result
	if !candidate.bindFirstSend(producers[0], func(callctx context.Context, authority contract.ID) contract.CryptoResultCode {
		// Every original has been independently prepared and claimed. All admitted
		// children join before custody can close or an outcome can be returned.
		returns := make([]struct {
			code          contract.CryptoResultCode
			cleanupFailed bool
			persistence   Result
		}, len(producers))
		var joined sync.WaitGroup
		for at, p := range producers {
			joined.Add(1)
			go func(at int, p *generatedPreparation) {
				defer joined.Done()
				returned, stored := p.invokeInstalledProducer(callctx, owners[at], authority)
				returns[at].code = returned.Code
				returns[at].cleanupFailed = returned.ExecutableCleanupFailed
				returns[at].persistence = stored
			}(at, p)
		}
		joined.Wait()
		cleanupFailed := false
		for _, returned := range returns {
			cleanupFailed = cleanupFailed || returned.cleanupFailed
			persistence = firstGeneratedPersistenceFailure(persistence, returned.persistence)
		}
		if cleanupFailed {
			out.AddCleanupDiagnostic()
		}
		for _, returned := range returns {
			if returned.code != contract.CryptoSuccess {
				return returned.code
			}
		}
		return contract.CryptoSuccess
	}) {
		return out
	}
	selected, result := s.selectObserved(ctx, candidate)
	recordGeneratedSelection(ctx, &out, selected, result, capture, &checkpoint)
	failures := make([]installedGeneratedLocalFailure, 0, len(owners))
	for at, owner := range owners {
		if owner.LocalFailureReason != nil && owner.AdmitLocalFailure != nil {
			failures = append(failures, installedGeneratedLocalFailure{producers[at].attempt, owner.LocalFailureReason, owner.AdmitLocalFailure})
		}
		owner.Close()
	}
	owners = nil
	if out.stopForResultPersistence(ctx, persistence) {
		return out
	}
	if selected == nil || result.Outcome != ObservedCurrent {
		return out
	}
	return e.driveGenerated(ctx, out, selected, i, deadline, &checkpoint, failures)
}

func (p *generatedPreparation) invokeInstalledProducer(ctx context.Context, owner *InstalledGeneratedProducerCustody, authority contract.ID) (contract.GeneratedProducerResult, Result) {
	returned := owner.InvokeProducer(ctx, p.producerLocator, authority)
	if returned.Code != contract.CryptoSuccess || len(returned.Record) == 0 {
		return returned, Result{}
	}
	stored := p.reservation.state.persistGeneratedResult(ctx, generatedResultWrite{attempt: p.attempt, body: returned.Record})
	return returned, stored
}

func (s *StateSession) installedGeneratedPrepareProducer(ctx context.Context, i ApplyInstallation, prior *generatedPreparation, attempt contract.ID, original bool, deadline time.Time, capture ...func(*generatedPreparation) error) (*generatedPreparation, *InstalledGeneratedProducerCustody, Result) {
	if i.Generated == nil || i.Generated.RequestDigest == nil || i.Generated.AdmitProducer == nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	c, err := installedGeneratedContext(s, deadline)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	var q contract.CryptoGeneratedCompareRequest
	var preparation contract.GeneratedProducerPreparation
	if original {
		q, preparation, err = s.generatedOriginalProducerRequest(ctx, prior, attempt, c)
	} else {
		q, preparation, err = s.generatedProducerRequestForAttempt(ctx, prior, attempt, c)
	}
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	g, err := prior.reservation.state.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	input, err := s.installedGeneratedProducerInput(ctx, g, attempt, prior.producerPhase, preparation)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	x, use := input.Expected.Template, input.Expected.Use
	implementation, err := resolveGeneratedImplementation(i, GeneratedImplementationRequest{ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, LifecycleMode: x.LifecycleMode, Retained: &GeneratedImplementationIdentity{ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, Action: x.Action, InputEncoding: input.Expected.InputEncoding, CompletionClass: x.CompletionClass, MaxSecret: use.MaxSecret, MaxFacts: use.MaxFacts}})
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	// The independently normalized request must match the admitted original
	// digest, also when this is a later automatic successor.
	digest, err := i.Generated.RequestDigest(ctx, implementation, x.Action, input.Intent, input.Target)
	if err != nil || digest != preparation.RequestDigest {
		return nil, nil, refused(InvalidIntent)
	}
	owner, err := i.Generated.AdmitProducer(ctx, q, currentControlOf(s), input, implementation, deadline)
	if err != nil || owner == nil || !validInstalledGeneratedCustody(&owner.InstalledGeneratedCustody) || owner.InvokeProducer == nil {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		return nil, nil, installedApplyPreparationFailure(err)
	}
	permit := &admittedGeneratedProducer{session: s, prior: prior, attempt: attempt, request: q, preparation: preparation, crypto: owner.Crypto, instance: owner.Crypto.InstanceID(), deadline: deadline}
	var p *generatedPreparation
	var result Result
	if original {
		p, result = s.PrepareGeneratedOriginalProducer(ctx, permit)
	} else {
		p, result = s.PrepareGeneratedProducer(ctx, permit)
	}
	if p == nil {
		return nil, owner, result
	}
	for _, own := range capture {
		if own == nil {
			return nil, owner, refused(AdmissionInvalid)
		}
		if err := own(p); err != nil {
			return nil, owner, installedApplyPreparationFailure(err)
		}
	}
	candidate, err := s.installedGeneratedCandidate(ctx, p.reservation, nil)
	if err != nil {
		return nil, owner, installedApplyPreparationFailure(err)
	}
	if owner.BindCandidate(ctx, candidate) != contract.CryptoSuccess {
		return nil, owner, refused(AdmissionInvalid)
	}
	if original {
		_, result = s.ClaimGeneratedOriginalProducer(ctx, p)
	} else {
		_, result = s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, i.Trust)
	}
	if result.Outcome != ObservedCurrent {
		return nil, owner, result
	}
	return p, owner, Result{}
}

// Continue selects one exact retained OperationID. Local declaration edits are
// irrelevant once the original complete proposal has been accepted.
func (e *InstalledApply) Continue(ctx context.Context, requestID, operationID contract.ID) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreApply)
	out := e.continueGenerated(telemetry.CallContext(ctx, call), requestID, operationID, nil)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return out
}
func (e *InstalledApply) continueGenerated(ctx context.Context, requestID, operationID contract.ID, capture *applyPublicationCapture) (returned PublicApplyResult) {
	out := PublicApplyResult{RequestID: requestID, OperationID: operationID, Result: refused(AdmissionInvalid)}
	if e == nil || ctx == nil || ctx.Err() != nil || requestID.IsZero() || operationID.IsZero() {
		return out
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) {
		return out
	}
	i, done, acquired := e.beginApplyInvocation(capture)
	if !acquired {
		return out
	}
	defer e.endApplyInvocation(done, capture)
	defer func() { qualifyGeneratedInvocationResult(i, &returned) }()
	out.DomainID = i.ExpectedDomain
	admitted, result := admitBorrowedPublicNormal(ctx, i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, i.Store, i.CompositionID, i.ConfigurationValidator.interpret)
	if result.Outcome != ObservedCurrent {
		out.Result = result
		return out
	}
	s, result := Open(ctx, admitted, i.Store)
	if s == nil {
		out.Result = result
		return out
	}
	out.WarningBits = s.root.WarningBits
	// A retained terminal receipt is a public observation. No old generated
	// artifact, caller nonce, private key, or credential is needed here.
	row, raw, found, err := s.retainedMutationReceipt(operationID)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if found {
		if row.OperationKind != contract.OperationApplyDeclaration && row.OperationKind != contract.OperationRotateValueEntryValue {
			return out
		}
		out = installedGeneratedReceiptObservation(out, s, row, raw)
		if s.head.Core.Revision == row.ObservedRevisionID {
			e.captureApplyPublication(ctx, s, applyPublicationComplete(out))
		}
		return out
	}
	if i.Generated == nil || i.Generated.AdmitProducer == nil || i.Generated.AdmitAdoption == nil || i.Generated.AdmitFinal == nil {
		return out
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if g.parent == nil || g.parent.OperationID != operationID {
		return out
	}
	if g.bundles[0].Request.OperationKind != contract.OperationApplyDeclaration && g.bundles[0].Request.OperationKind != contract.OperationRotateValueEntryValue {
		return out
	}
	out.RequestIdentity = g.parent.RequestIdentityDigest
	var checkpoint generatedSelectionCheckpoint
	return e.driveGenerated(ctx, out, s, i, deadline, &checkpoint, nil)
}

func installedGeneratedReceiptObservation(out PublicApplyResult, s *StateSession, row contract.CompactMutationReceipt, raw []byte) PublicApplyResult {
	inspected, err := contract.InspectCompactMutationReceipt(raw)
	if err != nil || inspected != row {
		out.Result = refused(InvalidRelation)
		return out
	}
	generated, err := generatedReceiptObservationResult(row)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.OperationID, out.DomainID = row.OperationID, row.DomainID
	out.RequestIdentity = row.RequestIdentityDigest
	out.Receipt = bytes.Clone(raw)
	out.Result = s.observed(ObservedCurrent)
	out.WarningBits = s.root.WarningBits
	out.Payload = &TransitionPayload{PredecessorRevisionID: row.PredecessorRevisionID, RequestedRevisionID: row.RequestedRevisionID, ObservedRevisionID: row.ObservedRevisionID, ChangedSubjects: ChangedSubjectCommitment{Count: row.ChangedSubjects.Count, IdentityRootDigest: row.ChangedSubjects.Digest}}
	out.Generated = generated
	return out
}
func installedGeneratedReceiptState(state uint16) string {
	switch state {
	case contract.ReceiptStateSuccess:
		return "success"
	case contract.ReceiptStateExactResume:
		return "exact-resume"
	case contract.ReceiptStatePossibleLiveResidueAccepted:
		return "possible-live-residue-accepted"
	case contract.ReceiptStateRetirementPending:
		return "retirement-pending"
	case contract.ReceiptStateEffectUnknown:
		return "effect-unknown"
	case contract.ReceiptStateEffectTerminalFailure:
		return "effect-terminal-failure"
	case contract.ReceiptStateWorkEnded:
		return "work-ended"
	}
	return ""
}

func (e *InstalledApply) driveGenerated(ctx context.Context, out PublicApplyResult, s *StateSession, i ApplyInstallation, deadline time.Time, checkpoint *generatedSelectionCheckpoint, failures []installedGeneratedLocalFailure) PublicApplyResult {
	fail := func(result Result) PublicApplyResult { return checkpoint.preparationFailure(ctx, out, result) }

	// Three entered Attempts per create are the complete graph allowance.
	// Each enters at most one result/fence and one successor reservation; the
	// two final passes are checkpoint and atomic Final. No unbounded retry runs.
	for step := 0; step < generatedInvocationStepLimit; step++ {
		if ctx.Err() != nil {
			return fail(failure(EvidenceUnavailable, ReadUnavailable))
		}
		g, err := s.selectedGeneratedWork(ctx)
		if err != nil {
			return fail(installedApplyPreparationFailure(err))
		}
		if g.parent == nil || g.parent.OperationID != out.OperationID {
			return out
		}
		out.RequestIdentity = g.parent.RequestIdentityDigest
		if !checkpoint.valid {
			scope, err := generatedCurrentResultScope(ctx, s, g)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			facts, err := generatedInvocationFacts(ctx, g, scope, scope.Effects, scope.Duties, scope.Hazards)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			out.Generated = &facts
			checkpoint.rememberObserved(s, out)
		}
		c, err := installedGeneratedContext(s, deadline)
		if err != nil {
			return fail(installedApplyPreparationFailure(err))
		}
		if generatedSelectionAnchored(g) {
			next, selected, result := e.installedGeneratedAutomaticStep(ctx, &out, s, g, i, deadline, checkpoint)
			if !selected {
				return fail(result)
			}
			if next == nil || result.Outcome != ObservedCurrent {
				return out
			}
			s = next
			continue
		}
		if g.phase.Stage == contract.GeneratedStageTerminal {
			final, err := s.generatedFinalRequest(ctx, c)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			next, completed, selected, result := e.installedGeneratedFinal(ctx, s, g, final, i, deadline, &out, checkpoint)
			final.clearOwnedInputs()
			if !selected {
				return fail(result)
			}
			if completed || next == nil || result.Outcome != ObservedCurrent {
				return out
			}
			s = next
			continue
		}
		if _, _, _, err := generatedPlannedSuccessor(g); err == nil {
			plan, err := s.generatedSuccessorReservationRequest(ctx, c)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			prior, result := s.PrepareGeneratedSuccessorReservation(ctx, &admittedGeneratedSuccessorReservation{session: s, plan: plan})
			if prior == nil {
				return fail(result)
			}
			p, owner, result := s.installedGeneratedPrepareProducer(ctx, i, prior, plan.attempt, false, deadline)
			if p == nil {
				if owner != nil {
					owner.Close()
				}
				return fail(result)
			}
			capture, err := captureGeneratedSelectionStep(ctx, s, g, p.reservation, checkpoint)
			if err != nil {
				owner.Close()
				return fail(installedApplyPreparationFailure(err))
			}
			var persistence Result
			if !p.reservation.candidate.bindFirstSend(p, func(callctx context.Context, authority contract.ID) contract.CryptoResultCode {
				returned, stored := p.invokeInstalledProducer(callctx, owner, authority)
				persistence = stored
				if returned.ExecutableCleanupFailed {
					out.AddCleanupDiagnostic()
				}
				return returned.Code
			}) {
				owner.Close()
				return fail(refused(AdmissionInvalid))
			}
			next, result := s.selectObserved(ctx, p.reservation.candidate)
			owner.Close()
			recordGeneratedSelection(ctx, &out, next, result, capture, checkpoint)
			if out.stopForResultPersistence(ctx, persistence) {
				return out
			}
			if next == nil || result.Outcome != ObservedCurrent {
				return out
			}
			s = next
			continue
		}
		attempt, ok := g.attempts[g.phase.FrontierAttemptID]
		if !ok || attempt.expected.Template.Action != contract.GeneratorActionCreate {
			return fail(refused(InvalidRelation))
		}
		body, found, result := s.ReadGeneratedResult(ctx, attempt.record.AttemptID)
		if result.Outcome != 0 {
			return fail(result)
		}
		if !found && attempt.expected.Template.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			var joinedFailure installedGeneratedLocalFailure
			for _, candidate := range failures {
				if candidate.attempt == attempt.record.AttemptID {
					if joinedFailure.reason != nil {
						return fail(refused(AdmissionInvalid))
					}
					joinedFailure = candidate
				}
			}
			if joinedFailure.reason == nil || joinedFailure.admit == nil {
				return fail(failure(EvidenceUnavailable, ReadUnavailable))
			}
			reason := joinedFailure.reason()
			if reason == 0 {
				return fail(failure(EvidenceUnavailable, ReadUnavailable))
			}
			next, selected, result := s.recordInstalledGeneratedLocalFailure(ctx, i, g, attempt.record.AttemptID, reason, joinedFailure.admit, deadline, &out, checkpoint)
			if !selected {
				return fail(result)
			}
			if next == nil || result.Outcome != ObservedCurrent {
				return out
			}
			s = next
			continue
		}
		unknown := !found
		if found {
			record, err := contract.DecodeGeneratedResultRecord(body)
			if err != nil {
				return fail(refused(InvalidRelation))
			}
			unknown = record.SafeFacts.Disposition == contract.GeneratorDispositionUnknown || record.SafeFacts.Disposition == contract.GeneratorDispositionRetirementAcknowledged
		}
		if unknown {
			// The native family has no terminal-observation, exact retry, or
			// confirmed-no-effect capability. Fence the original as possible-live.
			plan, err := s.generatedCreateResidueRequest(ctx, attempt.record.AttemptID, c)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			candidate, result := s.PrepareGeneratedCreateResidue(ctx, &admittedGeneratedCreateResidue{session: s, plan: plan}, i.Trust)
			if candidate == nil {
				return fail(result)
			}
			capture, err := captureGeneratedSelectionStep(ctx, s, g, candidate.generated.reservation, checkpoint)
			if err != nil {
				return fail(installedApplyPreparationFailure(err))
			}
			next, result := s.selectObserved(ctx, candidate)
			recordGeneratedSelection(ctx, &out, next, result, capture, checkpoint)
			if next == nil || result.Outcome != ObservedCurrent {
				return out
			}
			s = next
			continue
		}
		next, selected, result := s.recordInstalledGeneratedResult(ctx, i, g, attempt.record.AttemptID, body, deadline, &out, checkpoint)
		if !selected {
			return fail(result)
		}
		if next == nil || result.Outcome != ObservedCurrent {
			return out
		}
		s = next
	}
	return fail(refused(CapacityExceeded))
}

func (e *InstalledApply) installedGeneratedFinal(ctx context.Context, s *StateSession, g *generatedSelection, plan *generatedFinalPlan, i ApplyInstallation, deadline time.Time, out *PublicApplyResult, checkpoint *generatedSelectionCheckpoint) (*StateSession, bool, bool, Result) {
	input, err := s.installedGeneratedFinalInput(ctx, g, plan)
	if err != nil {
		return nil, false, false, installedApplyPreparationFailure(err)
	}
	owner, err := i.Generated.AdmitFinal(ctx, plan.request, currentControlOf(s), input, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		if owner != nil && owner.Close != nil {
			owner.Close()
		}
		return nil, false, false, installedApplyPreparationFailure(err)
	}
	defer owner.Close()
	p, result := s.PrepareGeneratedFinal(ctx, &admittedGeneratedFinal{session: s, plan: plan, crypto: owner.Crypto, instance: owner.Crypto.InstanceID(), deadline: deadline})
	if p == nil {
		return nil, false, false, result
	}
	candidateInput, err := s.installedGeneratedCandidate(ctx, p.reservation, plan)
	if err != nil {
		return nil, false, false, installedApplyPreparationFailure(err)
	}
	row, raw, terminal, err := p.reservation.state.retainedMutationReceipt(out.OperationID)
	if err != nil {
		return nil, false, false, installedApplyPreparationFailure(err)
	}
	var capture *generatedInvocationResultCapture
	var payload *TransitionPayload
	var receipt []byte
	if terminal {
		capture, err = captureGeneratedFinalInvocationResult(ctx, s, g, plan, p.reservation, checkpoint)
		if err == nil {
			selected, readErr := p.reservation.state.selectedGeneratedWork(ctx)
			if readErr != nil {
				err = readErr
			} else {
				payload = installedGeneratedRetirementPayload(p.reservation.state, selected, row.PredecessorRevisionID)
				payload.RequestedRevisionID, payload.ObservedRevisionID = row.RequestedRevisionID, row.ObservedRevisionID
				payload.ChangedSubjects = ChangedSubjectCommitment{Count: row.ChangedSubjects.Count, IdentityRootDigest: row.ChangedSubjects.Digest}
				receipt = bytes.Clone(raw)
			}
		}
	} else {
		capture, err = captureGeneratedSelectionStep(ctx, s, g, p.reservation, checkpoint)
	}
	if err != nil {
		return nil, terminal, false, installedApplyPreparationFailure(err)
	}
	if owner.BindCandidate(ctx, candidateInput) != contract.CryptoSuccess {
		return nil, false, false, refused(AdmissionInvalid)
	}
	candidate, result := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, i.Trust)
	if candidate == nil {
		return nil, terminal, false, result
	}
	next, result := s.selectObserved(ctx, candidate)
	if result.RequestedRevision.IsZero() {
		return nil, terminal, false, result
	}
	recordGeneratedSelection(ctx, out, next, result, capture, checkpoint)
	if terminal && result.Outcome == ObservedCurrent && candidateMatches(next, p.reservation.candidate) {
		out.Payload, out.Receipt = payload, receipt
		checkpoint.recordSelected(*out)
		e.captureApplyPublication(ctx, next, applyPublicationComplete(*out))
	}
	return next, terminal, true, result
}

func compareGeneratedIDs(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) }
