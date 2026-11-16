package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

type generatedStream struct {
	length uint64
	digest contract.ID
	parts  []contract.ID
	next   uint16
	hash   hash.Hash
}

// The graph and declaration are immutable across continuation admissions for
// one accepted generated plan. The cache retains only validated public plan
// facts and content identities; every admission still validates its changing
// request, control, bindings, state, phase, result and candidate.
type validatedGeneratedPlan struct {
	graphDigest, declarationDigest contract.ID
	graphLength, declarationLength int
	graph                          contract.GeneratorPlanBundle
	descriptor                     contract.GeneratorDescriptor
	usePlan                        contract.ID
	intendedEntryPlans             contract.GeneratorDescriptor
}

type generatedSource struct {
	offset, length uint32
	core           contract.SealedInputCore
	envelope       contract.ID
	buffer, keys   []byte
	verified       bool
}

type generatedAdmission struct {
	*session
	request             contract.CryptoGeneratedCompareRequest
	requestDigest       contract.ID
	requestLength       int
	control             contract.ControlCore
	bindings            []contract.BindingTableRow
	bindingDigests      []contract.ID
	routeID             contract.ID
	graph               contract.GeneratorPlanBundle
	stage               contract.CryptoKind
	busy                bool
	operation           contract.ID
	seed                []byte
	material            contract.OperationMaterialRecord
	access              contract.AccessRecord
	keyUses             []contract.KeyUseRow
	before              contract.PublicState
	candidate           *generatedCandidateFacts
	frozen              contract.CryptoGeneratedFreezeRequest
	purpose             generatedPurposeState
	registry            *generatedRegistryAdmission
	selectionPhase      *contract.GeneratedPhaseRecord
	accessPins          map[generatedAccessIdentity]contract.ID
	beforeAccessRecords []contract.AccessRecord
	inputOwner          *generatedInputOwner
	graphBody           contract.DigestLength
}

func newGeneratedStream(body []byte, parts bool) generatedStream {
	v := generatedStream{length: uint64(len(body)), digest: contract.Hash(body), hash: sha256.New()}
	if !parts {
		return v
	}
	for offset := 0; offset < len(body); offset += contract.GeneratedFragmentMaxPayload {
		v.parts = append(v.parts, contract.Hash(body[offset:min(offset+contract.GeneratedFragmentMaxPayload, len(body))]))
	}
	return v
}

func (r *Runtime) validateGeneratedPlan(graphBody, declarationBody []byte, parts bool) (*validatedGeneratedPlan, [2]generatedStream, error) {
	streams := [2]generatedStream{newGeneratedStream(declarationBody, parts), newGeneratedStream(graphBody, parts)}
	owner, err := r.generatedInputOwner()
	if err != nil {
		return nil, [2]generatedStream{}, err
	}
	validated, err := owner.validatePlan(graphBody, declarationBody, streams)
	if err != nil {
		return nil, [2]generatedStream{}, err
	}
	r.mu.Lock()
	if !r.closed {
		r.generatedPlan = validated
	}
	r.mu.Unlock()
	return validated, streams, nil
}

func (r *Runtime) admitGeneratedReservation(q contract.CryptoGeneratedCompareRequest, input generatedReservationAdmissionInput, deadline time.Time) error {
	_, err := r.admitGeneratedReservationOwned(q, input, deadline)
	return err
}

func (r *Runtime) admitGeneratedReservationOwned(q contract.CryptoGeneratedCompareRequest, input generatedReservationAdmissionInput, deadline time.Time) (*generatedAdmission, error) {
	if q.Purpose != contract.CryptoGeneratedReservationPurpose {
		return nil, ErrAdmission
	}
	body, err := generatedAdmissionBody(r, q, input.Session, deadline)
	if err != nil {
		return nil, err
	}
	target, ok := ownGeneratedTarget(input.Target)
	if !ok {
		return nil, ErrAdmission
	}
	state := &generatedReservationState{target: target}
	a, err := r.prepareGeneratedPlan(q, input.Session, input.Plan, generatedPurposeState{reservation: state}, input.Accepted, body, deadline)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			a.clear()
		}
	}()
	if input.Phase != nil {
		if input.Phase.RequestIdentityDigest.IsZero() || input.Phase.ObservedHEADDigest != q.Context.PredecessorHEADDigest ||
			input.Phase.ConditionDigest != q.Context.OriginalConditionDigest ||
			input.Phase.TransitionKind != contract.GeneratorAuthorityRetireReserve && input.Phase.TransitionKind != contract.GeneratorAuthorityCleanupReserve ||
			len(a.graph.Lineages) != 1 || a.graph.Header.LineageCount != 0 || a.graph.Header.TemplateCount != 1 ||
			!a.deleteTargetTemplateMatches(a.graph.Lineages[0].Templates[0]) ||
			input.Phase.TransitionKind == contract.GeneratorAuthorityRetireReserve && a.graph.Lineages[0].Purpose != contract.GeneratorLineageRetirement ||
			input.Phase.TransitionKind == contract.GeneratorAuthorityCleanupReserve && a.graph.Lineages[0].Purpose != contract.GeneratorLineageCleanup {
			return nil, ErrAdmission
		}
		phase, err := contract.GeneratorPhaseID(*input.Phase)
		if err != nil {
			return nil, ErrAdmission
		}
		state.phaseID, state.phase = phase, new(contract.GeneratorPhaseIdentity)
		*state.phase = *input.Phase
	}
	if !a.admitControlledPredecessor(input.ControlledPredecessor) {
		return nil, ErrAdmission
	}
	transferred = true
	if err := r.installGeneratedAdmission(a, deadline); err != nil {
		return nil, err
	}
	return a, nil
}

func (r *Runtime) admitGeneratedAdoption(q contract.CryptoGeneratedCompareRequest, input generatedAdoptionAdmissionInput, deadline time.Time) error {
	_, err := r.admitGeneratedAdoptionOwned(q, input, deadline)
	return err
}

func (r *Runtime) admitGeneratedAdoptionOwned(q contract.CryptoGeneratedCompareRequest, input generatedAdoptionAdmissionInput, deadline time.Time) (*generatedAdmission, error) {
	return r.admitGeneratedAdoptionState(q, input, nil, nil, deadline)
}

func (r *Runtime) admitGeneratedAdoptionState(q contract.CryptoGeneratedCompareRequest, input generatedAdoptionAdmissionInput, failure *generatedLocalFailureAdmission, binding *generatedLocalFailureBinding, deadline time.Time) (*generatedAdmission, error) {
	if q.Purpose != contract.CryptoGeneratedAdoptionPurpose {
		return nil, ErrAdmission
	}
	body, err := generatedAdmissionBody(r, q, input.Session, deadline)
	if err != nil {
		return nil, err
	}
	target, ok := ownGeneratedTarget(input.Target)
	if !ok {
		return nil, ErrAdmission
	}
	phase, err := contract.GeneratorPhaseID(input.Phase)
	if err != nil || input.Phase.RequestIdentityDigest != q.Parent.RequestIdentityDigest || input.Phase.ObservedHEADDigest != q.Context.PredecessorHEADDigest ||
		input.Phase.ConditionDigest != q.Context.OriginalConditionDigest ||
		failure == nil && input.Phase.TransitionKind != contract.GeneratorAuthorityRecord && input.Phase.TransitionKind != contract.GeneratorAuthorityNoEffectBranch ||
		failure != nil && input.Phase.TransitionKind != contract.GeneratorAuthorityFailedTerminal {
		return nil, ErrAdmission
	}
	state := &generatedAdoptionState{phase: input.Phase, phaseID: phase, target: target, localFailure: failure}
	a, err := r.prepareGeneratedPlan(q, input.Session, input.Plan, generatedPurposeState{adoption: state}, nil, body, deadline)
	if err != nil || !a.admitContinuationCustody(input.Material, input.SeedAccess, input.SourceProtections, input.ControlledPredecessor) ||
		failure == nil && !a.resultsValid([]generatedResultAdmission{input.Result}) ||
		failure != nil && (binding == nil || input.Result != (generatedResultAdmission{}) || !binding.matches(q, input, failure.attempt) || !failure.matchesAdmission(a, *binding)) {
		if a != nil {
			a.clear()
		}
		return nil, ErrAdmission
	}
	if failure == nil {
		state.results = []generatedResultAdmission{input.Result}
	}
	if err := r.installGeneratedAdmission(a, deadline); err != nil {
		return nil, err
	}
	return a, nil
}

func (r *Runtime) admitGeneratedFinal(q contract.CryptoGeneratedCompareRequest, input generatedFinalAdmissionInput, deadline time.Time) error {
	_, err := r.admitGeneratedFinalOwned(q, input, deadline)
	return err
}

func (r *Runtime) admitGeneratedFinalOwned(q contract.CryptoGeneratedCompareRequest, input generatedFinalAdmissionInput, deadline time.Time) (*generatedAdmission, error) {
	if q.Purpose != contract.CryptoGeneratedFinalPreparationPurpose {
		return nil, ErrAdmission
	}
	if len(input.ResultBodies) != len(input.Results) {
		return nil, ErrAdmission
	}
	body, err := generatedAdmissionBody(r, q, input.Session, deadline)
	if err != nil {
		return nil, err
	}
	target, ok := ownGeneratedTarget(input.Target)
	if !ok {
		return nil, ErrAdmission
	}
	phase, err := contract.GeneratorPhaseID(input.Phase)
	if err != nil || input.Phase.RequestIdentityDigest != q.Parent.RequestIdentityDigest || input.Phase.ObservedHEADDigest != q.Context.PredecessorHEADDigest ||
		input.Phase.ConditionDigest != q.Context.OriginalConditionDigest || input.Phase.TransitionKind != contract.GeneratorAuthorityFinal {
		return nil, ErrAdmission
	}
	state := &generatedFinalPreparationState{phase: input.Phase, phaseID: phase, materializationPhaseID: phase, target: target}
	a, err := r.prepareGeneratedPlan(q, input.Session, input.Plan, generatedPurposeState{final: state}, nil, body, deadline)
	if err != nil {
		return nil, ErrAdmission
	}
	transferred := false
	defer func() {
		if !transferred {
			a.clear()
		}
	}()
	if !a.admitContinuationCustody(input.Material, input.SeedAccess, input.SourceProtections, input.ControlledPredecessor) || !a.resultsValid(input.Results) {
		return nil, ErrAdmission
	}
	for i, resultBody := range input.ResultBodies {
		selected := input.Results[i]
		if len(resultBody) != int(selected.Reference.ResultLength) || contract.Hash(resultBody) != selected.Reference.ResultBodyDigest {
			return nil, ErrAdmission
		}
		result, err := contract.DecodeGeneratedResultRecord(resultBody)
		if err != nil || contract.ValidateGeneratedResult(selected.Expected, input.Material, result) != nil {
			return nil, ErrAdmission
		}
		state.resultBodies = append(state.resultBodies, bytes.Clone(resultBody))
	}
	state.nonselecting = len(input.EntryAdmissions) == 0
	if generatedCurrentOnlyDeletePlan(a.graph) && !state.nonselecting {
		return nil, ErrAdmission
	}
	state.results = slices.Clone(input.Results)
	if !state.nonselecting {
		for _, entryPlan := range a.graph.ValueEntryPlans {
			if entryPlan.ValueSource == contract.Supplied && entryPlan.ChangeMask&(contract.GeneratorValueChangeContent|contract.GeneratorValueChangeMembership) != 0 || generatedMembershipOnly(entryPlan) {
				state.suppliedCount++
			}
		}
	}
	if !a.admitMembership(input.Membership, input.Plan.CurrentIntents) || !a.admitFinalCanonicalAccess(input.CanonicalAccess) {
		return nil, ErrAdmission
	}
	state.suppliedFinal = state.suppliedCount == 0
	if !a.admitEntries(input.EntryAdmissions) || !a.admitFinalPreparation(input) {
		return nil, ErrAdmission
	}
	transferred = true
	if err := r.installGeneratedAdmission(a, deadline); err != nil {
		return nil, err
	}
	return a, nil
}

func (r *Runtime) admitGeneratedProducer(q contract.CryptoGeneratedCompareRequest, input generatedProducerPreparationAdmissionInput, deadline time.Time) error {
	_, err := r.admitGeneratedProducerOwned(q, input, deadline)
	return err
}

func (r *Runtime) admitGeneratedProducerOwned(q contract.CryptoGeneratedCompareRequest, input generatedProducerPreparationAdmissionInput, deadline time.Time) (*generatedAdmission, error) {
	if q.Purpose != contract.CryptoGeneratedProducerPreparationPurpose {
		return nil, ErrAdmission
	}
	body, err := generatedAdmissionBody(r, q, input.Session, deadline)
	if err != nil {
		return nil, err
	}
	target, ok := ownGeneratedTarget(input.Target)
	if !ok {
		return nil, ErrAdmission
	}
	state := &generatedProducerPreparationState{target: target}
	if input.Phase == nil {
		p, c := q.Parent, q.Context
		if p.InitialPredecessorDigest != c.PredecessorHEADDigest || p.ConditionDigest != c.OriginalConditionDigest {
			return nil, ErrAdmission
		}
		state.phaseID, err = contract.GeneratorInitialPhaseID(p.RequestCoreDigest)
	} else {
		if input.Phase.RequestIdentityDigest != q.Parent.RequestIdentityDigest || input.Phase.ObservedHEADDigest != q.Context.PredecessorHEADDigest ||
			input.Phase.ConditionDigest != q.Context.OriginalConditionDigest ||
			input.Phase.TransitionKind != contract.GeneratorAuthorityReservation && input.Phase.TransitionKind != contract.GeneratorAuthorityRecord &&
				input.Phase.TransitionKind != contract.GeneratorAuthorityNoEffectBranch && input.Phase.TransitionKind != contract.GeneratorAuthorityRetireReserve &&
				input.Phase.TransitionKind != contract.GeneratorAuthorityCleanupReserve {
			return nil, ErrAdmission
		}
		state.phaseID, err = contract.GeneratorPhaseID(*input.Phase)
		state.phase = new(contract.GeneratorPhaseIdentity)
		*state.phase = *input.Phase
	}
	if err != nil {
		return nil, ErrAdmission
	}
	a, err := r.prepareGeneratedPlan(q, input.Session, input.Plan, generatedPurposeState{producer: state}, nil, body, deadline)
	if err != nil {
		return nil, ErrAdmission
	}
	transferred := false
	defer func() {
		if !transferred {
			a.clear()
		}
	}()
	if !a.admitContinuationCustody(input.Material, input.SeedAccess, input.SourceProtections, input.ControlledPredecessor) || !a.admitProducer(&input.Producer) {
		return nil, ErrAdmission
	}
	transferred = true
	if err := r.installGeneratedAdmission(a, deadline); err != nil {
		return nil, err
	}
	return a, nil
}

func (r *Runtime) admitGeneratedOriginalVerification(q contract.CryptoGeneratedCompareRequest, input generatedOriginalVerificationAdmissionInput, deadline time.Time) error {
	if q.Purpose != contract.CryptoGeneratedOriginalVerificationPurpose {
		return ErrAdmission
	}
	body, err := generatedAdmissionBody(r, q, input.Session, deadline)
	if err != nil {
		return err
	}
	return r.admitGeneratedVerification(q, input, body, deadline)
}

func generatedBindingsValid(control contract.ControlCore, bindings []contract.BindingTableRow) bool {
	if len(bindings) > contract.CryptoMaxRecipients+1 {
		return false
	}
	ordinary := 0
	for i, row := range bindings {
		if i > 0 && row.SubjectKind == bindings[i-1].SubjectKind && row.SubjectID == bindings[i-1].SubjectID {
			return false
		}
		if row.SubjectKind == contract.OrdinaryWrapSubject {
			ordinary++
		}
	}
	return ordinary <= contract.CryptoMaxRecipients && controlBindingsValid(control, bindings)
}

func generatedParentMatches(p contract.GeneratedParentRecord, plan *validatedGeneratedPlan) bool {
	g := plan.graph
	return p.DomainID == g.Header.DomainID && p.OperationID == g.Header.OperationID &&
		p.RequestCoreDigest == g.Header.RequestCoreDigest && p.PlanGraphID == g.UsePlan.PlanGraphID && p.UsePlanDigest == plan.usePlan &&
		p.MaterialID == g.Header.MaterialID && p.RecoveryPolicyID == g.Request.RecoveryPolicyID && p.ValueEntryPlanCount == g.Header.ValueEntryPlanCount &&
		p.LineageCount == g.Header.LineageCount && p.TemplateCount == g.Header.TemplateCount && p.Declaration == g.Request.Declaration &&
		p.Registry == g.Request.Registry && p.Graph == plan.descriptor && p.SourceUses == g.UsePlan.SourceUses && p.IntendedEntryPlans == plan.intendedEntryPlans &&
		p.InitialPredecessorDigest == g.Request.PredecessorHEADDigest && p.ConditionDigest == g.Request.ConditionDigest
}

func (a *generatedAdmission) clear() {
	clear(a.seed[:cap(a.seed)])
	clear(a.control.NormalSigning.SPKI[:cap(a.control.NormalSigning.SPKI)])
	clear(a.control.AuthorityKMSBinding.SPKI[:cap(a.control.AuthorityKMSBinding.SPKI)])
	if a.control.Recovery != nil {
		clear(a.control.Recovery.Signing.SPKI[:cap(a.control.Recovery.Signing.SPKI)])
		clear(a.control.Recovery.KMS.SPKI[:cap(a.control.Recovery.KMS.SPKI)])
	}
	for i := range a.bindings {
		clear(a.bindings[i].Binding.SPKI[:cap(a.bindings[i].Binding.SPKI)])
	}
	for i := range a.access.Wraps {
		clear(a.access.Wraps[i].RSACiphertext[:cap(a.access.Wraps[i].RSACiphertext)])
	}
	a.purpose.clear()
	a.seed, a.bindings, a.bindingDigests = nil, nil, nil
	a.graph = contract.GeneratorPlanBundle{}
	a.control = contract.ControlCore{}
	a.access = contract.AccessRecord{}
	a.before, a.candidate, a.keyUses = contract.PublicState{}, nil, nil
	a.frozen = contract.CryptoGeneratedFreezeRequest{}
	a.purpose = generatedPurposeState{}
	a.registry = nil
	a.beforeAccessRecords, a.accessPins, a.selectionPhase, a.inputOwner = nil, nil, nil, nil
	a.graphBody = contract.DigestLength{}
}

func (r *Runtime) generatedExchange(ctx context.Context, q contract.CryptoRequest, out contract.CryptoResponse) (reply contract.CryptoResponse) {
	return r.generatedExchangeOwned(ctx, q, out, nil)
}

func (r *Runtime) generatedExchangeOwned(ctx context.Context, q contract.CryptoRequest, out contract.CryptoResponse, expected *generatedAdmission) (reply contract.CryptoResponse) {
	reply = out
	callerDone := ctx.Done()
	r.mu.Lock()
	a := r.generated
	if r.closed || a == nil || expected != nil && a != expected {
		r.mu.Unlock()
		return reply
	}
	if a.terminal {
		r.mu.Unlock()
		reply.ResultCode = contract.CryptoAlreadyUsed
		return reply
	}
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		reply.ResultCode = code
		return reply
	}
	if a.busy || q.Kind != a.stage && (q.Kind != contract.CryptoDiscard || a.stage == contract.CryptoCompare) {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		reply.ResultCode = contract.CryptoAlreadyUsed
		return reply
	}
	a.busy = true
	a.work.Add(1)
	route := r.routes[a.routeID]
	r.mu.Unlock()
	defer a.work.Done()
	defer func() { r.finishGeneratedStage(callerDone, a, q.Kind, &reply) }()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	var prepare contract.CryptoGeneratedPrepareRequest
	if q.Kind == contract.CryptoPrepare {
		var err error
		prepare, err = contract.InspectCryptoGeneratedPrepareRequest(q)
		if err != nil {
			reply.ResultCode = contract.CryptoInvalidInput
			return reply
		}
		allowed := false
		switch {
		case a.purpose.reservation != nil:
			allowed = prepare.Variant == contract.CryptoGeneratedPreparePlanPart || prepare.Variant == contract.CryptoGeneratedPrepareFinishPlan
		case a.purpose.adoption != nil:
			allowed = a.purpose.adoption.localFailure == nil && prepare.Variant == contract.CryptoGeneratedPrepareAdopt ||
				a.purpose.adoption.localFailure != nil && prepare.Variant == contract.CryptoGeneratedPrepareLocalFailure
		case a.purpose.final != nil:
			allowed = prepare.Variant == contract.CryptoGeneratedPrepareValueEntries || prepare.Variant == contract.CryptoGeneratedPrepareSupplied
		case a.purpose.producer != nil:
			allowed = prepare.Variant == contract.CryptoGeneratedPrepareProducer
		case a.purpose.verification != nil:
			allowed = prepare.Variant == contract.CryptoGeneratedPrepareVerifyOriginal
		}
		if !allowed {
			reply.ResultCode = contract.CryptoInvalidInput
			return reply
		}
	} else if err := contract.ValidateCryptoGeneratedRequest(q); err != nil {
		reply.ResultCode = contract.CryptoInvalidInput
		return reply
	}
	private := telemetry.PrivateContext(a.ctx, ctx)
	switch q.Kind {
	case contract.CryptoCompare:
		if len(q.Body) != a.requestLength || contract.Hash(q.Body) != a.requestDigest {
			return reply
		}
		if code := a.qualifyGeneratedRecipients(private, &reply); code != contract.CryptoSuccess {
			reply.ResultCode = code
			return reply
		}
		if code := a.openControlledPredecessor(private, route, &reply); code != contract.CryptoSuccess {
			reply.ResultCode = code
			return reply
		}
		if a.purpose.reservation == nil {
			if code := a.openContinuation(private, route, &reply); code != contract.CryptoSuccess {
				reply.ResultCode = code
				return reply
			}
		}
		if _, err := rand.Read(a.operation[:]); err != nil || a.operation.IsZero() {
			reply.ResultCode = contract.CryptoCustodyUnavailable
			return reply
		}
		var err error
		reply.Body, err = contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: a.operation})
		if err != nil {
			reply.ResultCode = contract.CryptoCustodyUnavailable
			return reply
		}
		a.stage = contract.CryptoPrepare
		if final := a.purpose.final; final != nil && final.preparedImage != nil {
			a.stage = contract.CryptoFreeze
		}
		reply.ResultCode = contract.CryptoSuccess
	case contract.CryptoPrepare:
		switch prepare.Variant {
		case contract.CryptoGeneratedPrepareLocalFailure:
			failure := prepare.LocalFailure
			if failure.OperationRef != a.operation || failure.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.prepareLocalFailure(failure, &reply)
			return reply
		case contract.CryptoGeneratedPrepareVerifyOriginal:
			verify := prepare.VerifyOriginal
			if verify.OperationRef != a.operation || verify.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.verifyOriginalResult(verify, &reply)
			return reply
		case contract.CryptoGeneratedPrepareSupplied:
			supplied := prepare.Supplied
			if supplied.OperationRef != a.operation || supplied.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.prepareSupplied(private, route, supplied, &reply)
			return reply
		case contract.CryptoGeneratedPrepareValueEntries:
			entryRequest := prepare.ValueEntries
			if entryRequest.OperationRef != a.operation || entryRequest.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.prepareEntries(entryRequest, &reply)
			return reply
		case contract.CryptoGeneratedPrepareProducer:
			producer := prepare.Producer
			if producer.OperationRef != a.operation || producer.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.prepareProducer(producer, &reply)
			return reply
		case contract.CryptoGeneratedPrepareAdopt:
			adopt := prepare.Adopt
			if adopt.OperationRef != a.operation || adopt.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.adoptResult(adopt, &reply)
			return reply
		case contract.CryptoGeneratedPreparePlanPart:
			part := prepare.PlanPart
			if part.OperationRef != a.operation || part.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.planPart(private, route, part, &reply)
		case contract.CryptoGeneratedPrepareFinishPlan:
			finish := prepare.FinishPlan
			if finish.OperationRef != a.operation || finish.Context != a.request.Context {
				return reply
			}
			reply.ResultCode = a.finishPlan(finish, &reply)
		}
	case contract.CryptoDiscard:
		v, err := contract.InspectCryptoGeneratedDiscardRequest(q.Body)
		if err != nil {
			reply.ResultCode = contract.CryptoInvalidInput
			return reply
		}
		if v.Context != a.request.Context || v.OperationRef != a.operation {
			return reply
		}
		reply.ResultCode = contract.CryptoSuccess
	case contract.CryptoFreeze:
		v, err := contract.InspectCryptoGeneratedFreezeRequest(q.Body)
		if err != nil || a.candidate == nil || v != a.candidate.facts {
			return reply
		}
		digest, err := contract.CryptoGeneratedFactDigest(r.id, v)
		if err != nil {
			return reply
		}
		reply.Body, err = contract.EncodeCryptoFreezeResult(contract.CryptoFreezeResult{FactDigest: digest})
		if err != nil {
			reply.ResultCode = contract.CryptoCustodyUnavailable
			return reply
		}
		a.frozen, a.stage = v, contract.CryptoClaim
		reply.ResultCode = contract.CryptoSuccess
	case contract.CryptoClaim:
		v, err := contract.InspectCryptoGeneratedClaimRequest(q.Body)
		if err != nil || a.candidate == nil || contract.CryptoGeneratedFreezeRequest(v) != a.frozen {
			return reply
		}
		reply.ResultCode = contract.CryptoSuccess
	}
	return reply
}

func (r *Runtime) finishGeneratedStage(callerDone <-chan struct{}, a *generatedAdmission, kind contract.CryptoKind, reply *contract.CryptoResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		reply.ResultCode = code
	}
	if !a.accumulateKeyUses(reply.KeyUseRows) {
		reply.ResultCode = contract.CryptoResponseUnknown
	}
	a.busy = false
	if reply.ResultCode != contract.CryptoSuccess || kind == contract.CryptoClaim || kind == contract.CryptoDiscard ||
		a.purpose.verification != nil && kind == contract.CryptoPrepare {
		if reply.ResultCode != contract.CryptoSuccess {
			reply.Body = nil
		}
		a.terminal = true
		if reply.ResultCode == contract.CryptoSuccess && kind == contract.CryptoClaim && a.purpose.producer != nil && a.purpose.producer.producer != nil {
			a.purpose.producer.producer.claimed = true
			return
		}
		a.cancel()
	}
}

func (a *generatedAdmission) planPart(ctx context.Context, route KeyAccess, q contract.CryptoGeneratedPlanPartRequestView, out *contract.CryptoResponse) contract.CryptoResultCode {
	reservation := a.purpose.reservation
	if reservation == nil {
		return contract.CryptoInvalidAdmission
	}
	i := int(q.BlobKind) - int(contract.GeneratorContentDeclaration)
	v := &reservation.streams[i]
	if q.Total != v.length || q.WholeDigest != v.digest || int(q.Count) != len(v.parts) || q.Index != v.next ||
		int(q.Index) >= len(v.parts) || contract.Hash(q.Payload) != v.parts[q.Index] || i == 1 && int(reservation.streams[0].next) != len(reservation.streams[0].parts) {
		return contract.CryptoInvalidAdmission
	}
	if i == 0 {
		for j := range reservation.plan.sources {
			source := &reservation.plan.sources[j]
			start, end := max(source.offset, q.Offset), min(source.offset+source.length, q.Offset+uint32(len(q.Payload)))
			if start >= end {
				continue
			}
			if source.buffer == nil {
				source.buffer = make([]byte, 0, source.length)
			}
			if uint32(len(source.buffer)) != start-source.offset {
				return contract.CryptoInvalidAdmission
			}
			source.buffer = append(source.buffer, q.Payload[start-q.Offset:end-q.Offset]...)
			if uint32(len(source.buffer)) == source.length {
				if code := a.openSource(ctx, route, source, out); code != contract.CryptoSuccess {
					return code
				}
				clear(source.buffer[:cap(source.buffer)])
				source.buffer = nil
			}
		}
		if !generatedCurrentOnlyDeletePlan(a.graph) {
			for j := range reservation.plan.canonicals {
				source := &reservation.plan.canonicals[j]
				start, end := max(source.offset, q.Offset), min(source.offset+source.length, q.Offset+uint32(len(q.Payload)))
				if start >= end {
					continue
				}
				if source.buffer == nil {
					source.buffer = make([]byte, 0, source.length)
				}
				if uint32(len(source.buffer)) != start-source.offset {
					return contract.CryptoInvalidAdmission
				}
				source.buffer = append(source.buffer, q.Payload[start-q.Offset:end-q.Offset]...)
				if uint32(len(source.buffer)) == source.length {
					if code := a.openCanonical(ctx, route, source, out); code != contract.CryptoSuccess {
						return code
					}
					clear(source.buffer[:cap(source.buffer)])
					source.buffer = nil
				}
			}
		}
	}
	_, err := v.hash.Write(q.Payload)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	v.next++
	if int(v.next) == len(v.parts) && !bytes.Equal(v.hash.Sum(nil), v.digest[:]) {
		return contract.CryptoInvalidAdmission
	}
	out.Body, err = contract.EncodeCryptoGeneratedPartResult(contract.CryptoGeneratedPartResult{})
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) openSource(ctx context.Context, route KeyAccess, source *generatedSource, out *contract.CryptoResponse) contract.CryptoResultCode {
	envelope, err := contract.DecodeSealedInputEnvelope(source.buffer)
	if err != nil || envelope.Core != source.core || contract.Hash(source.buffer) != source.envelope {
		return contract.CryptoSourceAuthenticationFailed
	}
	index := applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)
	if index < 0 {
		return contract.CryptoInvalidAdmission
	}
	binding := a.bindings[index]
	wrap, err := custody.SealedInputWrapCore(source.core, binding)
	if err != nil {
		return contract.CryptoSourceAuthenticationFailed
	}
	keys, code := openMaterialPacket(ctx, route, binding, wrap, envelope.AuthorityWrap, contract.CryptoSourceAuthenticationFailed, out)
	if code != contract.CryptoSuccess {
		return code
	}
	plain, err := custody.OpenSealedInput(source.core, envelope, keys)
	if err != nil {
		clear(keys[:cap(keys)])
		return contract.CryptoSourceAuthenticationFailed
	}
	if code := a.compareSuppliedCurrent(ctx, route, source.core.Name, plain, out); code != contract.CryptoSuccess {
		clear(plain[:cap(plain)])
		clear(keys[:cap(keys)])
		return code
	}
	clear(plain[:cap(plain)])
	source.keys = keys
	return contract.CryptoSuccess
}

func (a *generatedAdmission) finishPlan(q contract.CryptoGeneratedFinishPlanRequest, out *contract.CryptoResponse) contract.CryptoResultCode {
	reservation := a.purpose.reservation
	if reservation == nil {
		return contract.CryptoInvalidAdmission
	}
	if q.Declaration != a.request.ParentPlan.Declaration || q.Graph != a.request.PlanGraph || q.SourceUses != a.request.AcceptedSources {
		return contract.CryptoInvalidAdmission
	}
	for _, stream := range reservation.streams {
		if int(stream.next) != len(stream.parts) {
			return contract.CryptoInvalidAdmission
		}
	}
	currentOnly := generatedCurrentOnlyDeletePlan(a.graph)
	for _, source := range reservation.plan.canonicals {
		if !source.opened && !currentOnly {
			return contract.CryptoInvalidAdmission
		}
	}
	a.material.Core = contract.OperationMaterialCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: a.request.Context.DomainID,
		CompatibilityID: a.request.Context.CompatibilityID, CryptoSupportID: a.control.CryptoSupportID, OperationID: a.graph.Header.OperationID,
		OperationMaterialID: a.request.MaterialID, UsePlanDigest: a.request.UsePlanDigest, SeedEpoch: 1}
	a.seed = make([]byte, 32)
	if _, err := rand.Read(a.seed); err != nil {
		return contract.CryptoCustodyUnavailable
	}
	var err error
	a.material.SeedCheck, err = custody.SeedCheck(a.material.Core, a.seed)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	materialContext, err := contract.OperationMaterialContextDigest(a.material.Core)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	a.access = contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.OperationSeedMaterialKind, MaterialID: a.request.MaterialID, MaterialContextDigest: materialContext, PackageCheck: a.material.SeedCheck}
	for _, binding := range a.bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && binding.SubjectID != a.control.AuthorityRecipientID {
			continue
		}
		wrapCore, err := custody.SeedWrapCore(a.material.Core, binding)
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		wrap, err := custody.Wrap(wrapCore, binding.Binding, a.seed)
		uses := KeyUses{Completed: 1}
		if err != nil {
			uses = KeyUses{Failed: 1}
		}
		if !appendKeyUses(out, binding, contract.KeyUseMaterialWrap, uses, 1) {
			return contract.CryptoResponseUnknown
		}
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		a.access.Wraps = append(a.access.Wraps, wrap)
	}
	result := contract.CryptoGeneratedFinishPlanResult{Material: a.material}
	result.SeedAccess, err = contract.EncodeAccessRecord(a.access)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	for i := range reservation.plan.sources {
		source := &reservation.plan.sources[i]
		if len(source.keys) != 32 {
			return contract.CryptoInvalidAdmission
		}
		coreDigest, err := contract.SealedInputCoreDigest(source.core)
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		transfer := contract.TransferCore{Schema: 2, Profile: 2, DomainID: a.material.Core.DomainID, CompatibilityID: a.material.Core.CompatibilityID,
			CryptoSupportID: a.material.Core.CryptoSupportID, OperationID: a.material.Core.OperationID, OperationMaterialID: a.material.Core.OperationMaterialID,
			UsePlanDigest: a.material.Core.UsePlanDigest, UseKind: 1, SourceID: source.core.SourceID, SealedInputCoreDigest: coreDigest, PacketKind: 5, PacketLength: contract.SourceTransferPacketLength}
		envelope, err := custody.SealTransfer(transfer, a.seed, source.keys)
		clear(source.keys[:cap(source.keys)])
		source.keys = nil
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		result.SourceProtections = append(result.SourceProtections, contract.CryptoGeneratedSourceProtection{SourceID: source.core.SourceID,
			OriginalSourceCoreDigest: coreDigest, OriginalEnvelopeDigest: source.envelope, Transfer: envelope})
	}
	slices.SortFunc(result.SourceProtections, func(x, y contract.CryptoGeneratedSourceProtection) int {
		return bytes.Compare(x.SourceID[:], y.SourceID[:])
	})
	if len(result.SourceProtections) > 0 {
		body, err := contract.EncodeGeneratedSourceProtections(a.material, result.SourceProtections)
		if err != nil {
			return contract.CryptoCustodyUnavailable
		}
		reservation.plan.protection = contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}
	}
	out.Body, err = contract.EncodeCryptoGeneratedFinishPlanResult(result)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	a.stage = contract.CryptoFreeze
	return contract.CryptoSuccess
}

func (a *generatedAdmission) accumulateKeyUses(rows []contract.KeyUseRow) bool {
	if _, err := contract.KeyUseRowsLength(rows); err != nil {
		return false
	}
	out := contract.CryptoResponse{KeyUseRows: a.keyUses}
	for _, row := range rows {
		index := slices.IndexFunc(a.bindings, func(binding contract.BindingTableRow) bool {
			return binding.SubjectKind == row.SubjectKind && binding.SubjectID == row.SubjectID && binding.Binding.BindingID == row.BindingID
		})
		if index < 0 {
			return false
		}
		var uses KeyUses
		switch row.Outcome {
		case contract.KeyUseCompleted:
			uses.Completed = row.Count
		case contract.KeyUseDenied:
			uses.Denied = row.Count
		case contract.KeyUseFailed:
			uses.Failed = row.Count
		case contract.KeyUseUnknown:
			uses.Unknown = row.Count
		}
		if !appendKeyUses(&out, a.bindings[index], row.Purpose, uses, uint64(row.Count)) {
			return false
		}
	}
	a.keyUses = out.KeyUseRows
	return true
}
