package core

import (
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
)

type admittedGeneratedProducer struct {
	observation *operationObservation
	session     *StateSession
	prior       *generatedPreparation
	attempt     contract.ID
	request     contract.CryptoGeneratedCompareRequest
	preparation contract.GeneratedProducerPreparation
	crypto      contract.Crypto
	instance    contract.ID
	deadline    time.Time
	used        bool
}

// Only a live claimed preparation can request its reserved first send. For the
// initial reservation the fixed phase is implicit. A later reservation carries
// the exact phase that first made its successor or delete dispatchable.
// Reopening an observed reservation cannot reconstruct either permit.
func (s *StateSession) generatedProducerRequest(ctx context.Context, prior *generatedPreparation, admitted contract.ApplyContext) (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error) {
	return s.generatedProducerRequestForAttempt(ctx, prior, contract.ID{}, admitted)
}

func (s *StateSession) generatedProducerRequestForAttempt(ctx context.Context, prior *generatedPreparation, attempt contract.ID, admitted contract.ApplyContext) (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error) {
	if s == nil || prior == nil || prior.reservation == nil || prior.reservation.state == nil || prior.reservation.candidate == nil {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, contract.ErrRecord
	}
	candidate := prior.reservation.candidate
	ready := prior.claimed && !prior.plannedSuccessor && prior.operation != nil && candidate.producer == prior && candidate.generatedReady()
	if prior.plannedSuccessor {
		selected := prior.reservation.state.head
		ready = !prior.claimed && prior.operation == nil && s.generatedContextValid(prior.producerBaseContext) &&
			candidate.producer == prior && len(candidate.body) == 0 &&
			candidate.head.Core == selected.Core && candidate.head.Generator != nil && selected.Generator != nil &&
			*candidate.head.Generator == *selected.Generator
	}
	if !ready {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, contract.ErrRecord
	}
	if err := prior.reservation.state.validateGeneratedSelection(ctx, nil); err != nil {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, err
	}
	q, preparation, err := s.generatedProducerRequestChecked(ctx, prior, attempt, admitted)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, err
	}
	if !candidate.generated.reserveProducerMode(generatedSingleProducerMode) {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, contract.ErrRecord
	}
	return q, preparation, nil
}

func (s *StateSession) generatedOriginalProducerRequest(ctx context.Context, prior *generatedPreparation, attempt contract.ID, admitted contract.ApplyContext) (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error) {
	if s == nil || prior == nil || prior.reservation == nil || prior.reservation.state == nil || prior.reservation.candidate == nil {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, contract.ErrRecord
	}
	candidate := prior.reservation.candidate
	if !prior.claimed || prior.plannedSuccessor || prior.operation == nil || candidate.producer != prior ||
		candidate.generated == nil || !candidate.generated.claimed || candidate.generated.originalsComplete ||
		len(prior.reservation.originalAttempts) == 0 || !slices.Contains(prior.reservation.originalAttempts, attempt) ||
		!prior.reservation.state.cachedGeneratedSelectionValid() {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, contract.ErrRecord
	}
	q, preparation, err := s.generatedProducerRequestChecked(ctx, prior, attempt, admitted)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, err
	}
	if !candidate.generated.reserveProducerMode(generatedOriginalSetMode) {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, contract.ErrRecord
	}
	return q, preparation, nil
}

func (s *StateSession) generatedProducerRequestChecked(ctx context.Context, prior *generatedPreparation, attempt contract.ID, admitted contract.ApplyContext) (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error) {
	fail := func() (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error) {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, contract.ErrRecord
	}
	if s == nil || prior == nil || prior.reservation == nil || prior.reservation.candidate == nil ||
		prior.reservation.candidate.session != s || prior.reservation.candidate.used ||
		!prior.producerLocator.IsZero() || admitted.IntentDescriptor != (contract.DescriptorVector{}) ||
		admitted.Expiry > uint64(1<<63-1) || !validPrivateDeadline(time.Unix(0, int64(admitted.Expiry))) {
		return fail()
	}
	base := prior.producerBaseContext
	if !prior.plannedSuccessor {
		base = prior.operation.context
	}
	if base.AdmissionID == admitted.AdmissionID || base.SessionID == admitted.SessionID {
		return fail()
	}
	base.AdmissionID, base.SessionID, base.Expiry, base.IntentDescriptor = admitted.AdmissionID, admitted.SessionID, admitted.Expiry, contract.DescriptorVector{}
	if base != admitted {
		return fail()
	}
	g, err := prior.reservation.state.selectedGeneratedWork(ctx)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, contract.GeneratedProducerPreparation{}, err
	}
	if g.parent == nil || g.phase == nil {
		return fail()
	}
	if attempt.IsZero() {
		attempt = g.phase.FrontierAttemptID
	}
	a, ok := g.attempts[attempt]
	if !ok || generatedSelectionAnchored(g) && a.expected.Template.Action != contract.GeneratorActionDelete || len(a.result) != 0 || a.record.State != contract.GeneratedEffectTransmitted {
		return fail()
	}
	if g.phase.Phase == 1 {
		if prior.producerPhase != nil || a.expected.Template.Action != contract.GeneratorActionCreate || a.expected.Template.Branch != contract.GeneratorBranchInitial {
			return fail()
		}
		if !slices.Contains(prior.reservation.originalAttempts, attempt) {
			return fail()
		}
	} else {
		if attempt != g.phase.FrontierAttemptID {
			return fail()
		}
		var scheduled contract.ID
		if prior.producerPhase != nil {
			scheduled, err = contract.GeneratorPhaseID(*prior.producerPhase)
		}
		if prior.producerPhase == nil ||
			err != nil || prior.producerPhase.AfterPhase != g.phase.Phase || scheduled != g.phase.PhaseID {
			return fail()
		}
		if !generatedProducerPhaseMatches(g, a, prior.producerPhase.TransitionKind) {
			return fail()
		}
	}
	p := *g.parent
	q := contract.CryptoGeneratedCompareRequest{Context: admitted, Purpose: contract.CryptoGeneratedProducerPreparationPurpose, Parent: p, PlanGraph: p.Graph,
		UsePlanDigest: p.UsePlanDigest, MaterialID: p.MaterialID, AcceptedSources: p.SourceUses, IntendedEntryPlans: p.IntendedEntryPlans}
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		return fail()
	}
	if _, err := contract.EncodeCryptoGeneratedCompareRequest(q); err != nil {
		return fail()
	}
	c, err := generatedProducerPreparation(p, a)
	if err != nil {
		return fail()
	}
	if _, err := contract.EncodeGeneratedProducerPreparation(c); err != nil {
		return fail()
	}
	return q, c, nil
}

func generatedProducerPhaseMatches(g *generatedSelection, a generatedAttempt, purpose contract.GeneratorAuthorityPurpose) bool {
	if g == nil {
		return false
	}
	switch a.expected.Template.Action {
	case contract.GeneratorActionCreate:
		return a.expected.Template.Branch >= contract.GeneratorBranchNoEffect && a.expected.Template.Branch <= contract.GeneratorBranchResidueThenNoEffect && purpose == contract.GeneratorAuthorityReservation
	case contract.GeneratorActionDelete:
		if purpose == contract.GeneratorAuthorityCleanupReserve {
			source, err := g.generatedDeleteSource(a.record.OwnerID)
			return err == nil && (source.Record.Kind == contract.GeneratedHazardSupportKind || source.Duty.Kind == contract.GeneratedDutyUnselectedCleanup)
		}
		dutyRow, present := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: a.record.OwnerID}]
		if !present {
			return false
		}
		duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
		return err == nil && (duty.Kind == contract.GeneratedDutyRetirement && purpose == contract.GeneratorAuthorityRetireReserve ||
			duty.Kind == contract.GeneratedDutyUnselectedCleanup && purpose == contract.GeneratorAuthorityCleanupReserve)
	default:
		return false
	}
}

func generatedProducerPreparation(p contract.GeneratedParentRecord, a generatedAttempt) (contract.GeneratedProducerPreparation, error) {
	x := a.expected.Template
	c := contract.GeneratedProducerPreparation{Schema: contract.GeneratedProducerPreparationSchema, LifecycleMode: x.SemanticLifecycleMode(), DomainID: p.DomainID, OperationID: p.OperationID, RequestIdentityDigest: p.RequestIdentityDigest,
		PlanGraphID: p.PlanGraphID, LineageID: x.LineageID, AttemptID: x.AttemptID, TransmissionID: x.TransmissionID, ResultID: x.ResultID,
		ResultContractID: x.ResultContractID, DescriptorID: x.DescriptorID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		Action: x.Action, RequestDigest: a.record.RequestDigest, IntentDigest: x.IntentDigest, ResourceDigest: x.ResourceDigest}
	if x.Action == contract.GeneratorActionDelete {
		if a.expected.TargetResourceDigest.IsZero() {
			return contract.GeneratedProducerPreparation{}, contract.ErrRecord
		}
		c.ResourceDigest = a.expected.TargetResourceDigest
	}
	if _, err := contract.EncodeGeneratedProducerPreparation(c); err != nil {
		return contract.GeneratedProducerPreparation{}, err
	}
	return c, nil
}

// PrepareGeneratedProducer uses an opaque private admission for one selected
// generated Attempt.
func (s *StateSession) prepareGeneratedProducer(ctx context.Context, permit *admittedGeneratedProducer) (*generatedPreparation, Result) {
	p, result := s.prepareGeneratedProducerExchange(ctx, permit, s.generatedProducerRequestForAttempt)
	if result.Outcome != ObservedCurrent {
		return nil, result
	}
	p.reservation.candidate.body = nil
	p.reservation.candidate.producer = p
	return p, result
}

func (s *StateSession) prepareGeneratedOriginalProducer(ctx context.Context, permit *admittedGeneratedProducer) (*generatedPreparation, Result) {
	return s.prepareGeneratedProducerExchange(ctx, permit, s.generatedOriginalProducerRequest)
}

type generatedProducerRequestFunction func(context.Context, *generatedPreparation, contract.ID, contract.ApplyContext) (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error)

func (s *StateSession) prepareGeneratedProducerExchange(ctx context.Context, permit *admittedGeneratedProducer, request generatedProducerRequestFunction) (*generatedPreparation, Result) {
	if s == nil || ctx == nil || !s.admission.valid(s.store) || permit == nil || permit.used || permit.session != s || permit.crypto == nil ||
		permit.instance.IsZero() || permit.crypto.InstanceID() != permit.instance || !validPrivateDeadline(permit.deadline) ||
		permit.request.Context.Expiry != uint64(permit.deadline.UnixNano()) {
		return nil, refused(AdmissionInvalid)
	}
	permit.used = true
	if ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	admitted := permit.request.Context
	admitted.IntentDescriptor = contract.DescriptorVector{}
	q, preparation, err := request(ctx, permit.prior, permit.attempt, admitted)
	if err != nil || q != permit.request || preparation != permit.preparation {
		if readFailure, ok := selectedReadResult(err); ok {
			return nil, readFailure
		}
		return nil, refused(AdmissionInvalid)
	}
	g, err := permit.prior.reservation.state.selectedGeneratedWork(ctx)
	if err != nil {
		if readFailure, ok := selectedReadResult(err); ok {
			return nil, readFailure
		}
		return nil, refused(InvalidRelation)
	}
	attempt := permit.attempt
	if attempt.IsZero() {
		attempt = g.phase.FrontierAttemptID
	}
	a := g.attempts[attempt]
	selectedPreparation, err := generatedProducerPreparation(*g.parent, a)
	if err != nil || selectedPreparation != preparation {
		return nil, refused(AdmissionInvalid)
	}
	access, ok := permit.prior.reservation.state.materialAccess(contract.OperationSeedMaterialKind, q.MaterialID)
	if !ok {
		return nil, refused(InvalidRelation)
	}
	seed, err := contract.EncodeAccessRecord(access)
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	intent, err := g.content.read(contract.GeneratorContentIntent, a.expected.Template.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	bindings, err := s.generatedBindings(g)
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	body, err := contract.EncodeCryptoGeneratedCompareRequest(q)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	source := generatedExchangeSource(q)
	source.PhaseID, source.AttemptID = g.phase.PhaseID, a.record.AttemptID
	currentOpens, err := g.continuationCurrentOpens(ctx)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	p := &generatedPreparation{reservation: permit.prior.reservation, operation: &cryptoOperation{observation: permit.observation, source: source, adapter: permit.crypto, instance: permit.instance,
		authority: s.admission.recipient, context: q.Context, deadline: permit.deadline, bindings: bindings, sourceCount: 1 + currentOpens}}
	p.attempt = a.record.AttemptID
	if a.record.CompletionClass == contract.GeneratedCompletionConfirmed && a.expected.Template.Action == contract.GeneratorActionDelete {
		source, err := g.generatedDeleteSource(a.record.OwnerID)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		progress, err := g.controlledDeleteSourceProgress(source, nil, true)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		if len(progress.rows) > 0 {
			p.operation.sourceCount++
		}
	}
	p.operation.qualificationCounts = s.generatedQualificationCounts(bindings)
	reply, res := p.exchange(ctx, contract.CryptoCompare, body)
	if res.Outcome != 0 {
		return nil, res
	}
	compared, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	p.operation.operationRef, p.operation.sourceCount = compared.OperationRef, 0
	body, err = contract.EncodeCryptoGeneratedProducerRequest(contract.CryptoGeneratedProducerRequest{OperationRef: compared.OperationRef, Context: q.Context,
		Template: a.expected.Template, Material: a.material, SeedAccess: seed, Preparation: preparation,
		Intent: contract.GeneratorDescriptor{Digest: a.expected.Template.IntentDigest, Length: uint64(len(intent)), Count: 1}})
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	reply, res = p.exchange(ctx, contract.CryptoPrepare, body)
	if res.Outcome != 0 {
		return nil, res
	}
	result, err := contract.InspectCryptoGeneratedProducerResult(reply.Body)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	p.reservation.candidate.bindObservation(permit.observation, source)
	p.producerLocator = result.ProducerLocatorID
	return p, s.observed(ObservedCurrent)
}

// bindFirstSend installs one local handoff for a complete claimed candidate.
func (c *Candidate) bindFirstSend(p *generatedPreparation, handoff func(context.Context, contract.ID) contract.CryptoResultCode) bool {
	if c == nil || p == nil || !p.claimed || p.producerLocator.IsZero() || p.reservation == nil ||
		p.reservation.candidate != c || c.used || !c.generatedReady() || c.firstSend != nil || handoff == nil {
		return false
	}
	if c.producer != p && (!c.generated.originalsComplete || c.originalProducers[p.attempt] != p ||
		c.generated.originalClaims[p.attempt] != c.generated.authority) {
		return false
	}
	c.firstSend = &candidateFirstSend{handoff: handoff}
	return true
}
