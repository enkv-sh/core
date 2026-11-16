package core

import (
	"bytes"
	"cmp"
	"context"
	"math"
	"slices"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
)

// The private parent pins an installed Crypto owner to this exact public plan.
// There is no public constructor and encoded inputs cannot supply this permit.
type admittedGeneratedPlan struct {
	observation *operationObservation
	session     *StateSession
	plan        *generatedPlan
	crypto      contract.Crypto
	instance    contract.ID
	deadline    time.Time
	used        bool
}

type generatedPreparation struct {
	reservation         *generatedReservation
	operation           *cryptoOperation
	keyUses             []contract.KeyUseRow
	plannedSuccessor    bool
	claimed             bool
	authority           contract.ID
	attempt             contract.ID
	producerLocator     contract.ID
	producerPhase       *contract.GeneratorPhaseIdentity
	producerBaseContext contract.ApplyContext
	results             []contract.GeneratorResultReference
	resultWrites        []generatedResultWrite
}

type generatedProducerMode uint32

const (
	generatedSingleProducerMode generatedProducerMode = iota + 1
	generatedOriginalSetMode
)

type generatedCandidateFacts struct {
	reservation       *generatedReservation
	authority         contract.ID
	claimed           bool
	producerMode      atomic.Uint32
	originalsComplete bool
	originalClaims    map[contract.ID]contract.ID
}

// PrepareGeneratedPlan uses an opaque private admission. Only Core can create
// the permit, so this surface does not grant generator authority by itself.
func (s *StateSession) prepareGeneratedPlan(ctx context.Context, permit *admittedGeneratedPlan) (*generatedPreparation, Result) {
	if s == nil || ctx == nil || s.prepared || !s.admission.valid(s.store) || permit == nil || permit.used || permit.session != s || permit.plan == nil ||
		permit.crypto == nil || permit.instance.IsZero() || permit.crypto.InstanceID() != permit.instance || !validPrivateDeadline(permit.deadline) ||
		permit.plan.request.Context.Expiry != uint64(permit.deadline.UnixNano()) {
		return nil, refused(AdmissionInvalid)
	}
	permit.used = true
	if ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	plan, err := s.generatedPlanRequest(ctx, permit.plan.input)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	if plan.request != permit.plan.request || plan.capacity != permit.plan.capacity || !plan.intents.equal(permit.plan.intents) ||
		!slices.Equal(plan.bindings, permit.plan.bindings) {
		return nil, refused(AdmissionInvalid)
	}
	if plan.phase != nil && plan.phase.TransitionKind == contract.GeneratorAuthorityCleanupReserve {
		effectContext, cancel := context.WithDeadline(ctx, permit.deadline)
		defer cancel()
		selection, ok, err := s.readGeneratedCleanup(effectContext)
		if result, matched := selectedReadResult(err); matched {
			return nil, result
		}
		if err != nil || !ok || selection.kind != generatedCleanupDuty && selection.kind != generatedCleanupHazard || len(plan.input.graph.Lineages) != 1 {
			return nil, refused(InvalidRelation)
		}
		owner := selection.duty.OwnerID
		if selection.kind == generatedCleanupHazard {
			owner = selection.hazard.OwnerID
		}
		if owner != plan.input.graph.Lineages[0].Templates[0].DutyID {
			return nil, refused(InvalidRelation)
		}
	}
	body, err := contract.EncodeCryptoGeneratedCompareRequest(plan.request)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	bindings, err := s.generatedPlanBindings(plan)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	s.prepared = true
	source := generatedExchangeSource(plan.request)
	if plan.phase != nil {
		source.PhaseID = mustGeneratedPhaseID(*plan.phase)
	}
	op := &cryptoOperation{observation: permit.observation, source: source, adapter: permit.crypto, instance: permit.instance, authority: s.admission.recipient,
		context: plan.request.Context, deadline: permit.deadline, bindings: bindings}
	p := &generatedPreparation{operation: op}
	if plan.phase != nil {
		g, err := s.selectedGeneratedWork(ctx)
		if err != nil {
			if result, matched := selectedReadResult(err); matched {
				return nil, result
			}
			return nil, refused(AdmissionInvalid)
		}
		deletion, ok, err := s.generatedDeleteReservationSelection(ctx, plan.input.graph, g)
		if result, matched := selectedReadResult(err); matched {
			return nil, result
		}
		if err != nil {
			return nil, refused(InvalidRelation)
		}
		if !ok {
			return nil, refused(AdmissionInvalid)
		}
		if deletion.source.CompletionClass == contract.GeneratedCompletionConfirmed {
			progress, err := g.controlledDeleteSourceProgress(deletion.source, nil, true)
			if err != nil {
				return nil, refused(AdmissionInvalid)
			}
			if len(progress.rows) != 0 {
				op.sourceCount = 1
			}
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
	op.operationRef = compared.OperationRef
	graph, err := contract.EncodeGeneratorPlanBundle(plan.input.graph)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	declaration, err := contract.InspectGeneratorDeclaration(plan.input.declaration)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	for _, content := range []struct {
		kind uint8
		body []byte
	}{{contract.GeneratorContentDeclaration, plan.input.declaration}, {contract.GeneratorContentGraph, graph}} {
		kind, blob := content.kind, content.body
		count := (len(blob) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
		digest := contract.Hash(blob)
		for index := 0; index < count; index++ {
			start := index * contract.GeneratedFragmentMaxPayload
			end := min(start+contract.GeneratedFragmentMaxPayload, len(blob))
			op.sourceCount = 0
			if kind == contract.GeneratorContentDeclaration {
				for entryIndex := 0; entryIndex < declaration.EntryCount(); entryIndex++ {
					entry, offset, err := declaration.Entry(entryIndex)
					if err != nil {
						return nil, refused(AdmissionInvalid)
					}
					if entry.Kind != contract.GeneratorDeclarationSealed && entry.Kind != contract.GeneratorDeclarationRetained {
						continue
					}
					if plan.phase != nil && entry.Kind == contract.GeneratorDeclarationRetained {
						// The validated delete phase carries current membership metadata.
						continue
					}
					entryLength, _, err := declaration.EntrySpan(entryIndex)
					if err != nil {
						return nil, refused(AdmissionInvalid)
					}
					entryEnd := int(offset) + int(entryLength)
					if entryEnd > start && entryEnd <= end {
						op.sourceCount++
						entryPlan := plan.input.graph.ValueEntryPlans[entryIndex]
						if entry.Kind == contract.GeneratorDeclarationSealed && entryPlan.ValueSource == contract.Supplied && entryPlan.ChangeMask&contract.GeneratorValueChangeContent == 0 {
							op.sourceCount++
						}
					}
				}
			}
			body, err = contract.EncodeCryptoGeneratedPlanPartRequest(contract.CryptoGeneratedPlanPartRequest{OperationRef: op.operationRef, Context: op.context,
				BlobKind: kind, Index: uint16(index), Count: uint16(count), Total: uint64(len(blob)), WholeDigest: digest, Offset: uint32(start), Payload: blob[start:end]})
			if err != nil {
				return nil, refused(AdmissionInvalid)
			}
			if _, res = p.exchange(ctx, contract.CryptoPrepare, body); res.Outcome != 0 {
				return nil, res
			}
		}
	}
	op.sourceCount, op.wrapCounts = 0, make(map[contract.ID]uint32)
	for _, binding := range bindings {
		if binding.SubjectKind == contract.RecoveryWrapSubject || binding.SubjectID == s.admission.recipient {
			op.wrapCounts[binding.Binding.BindingID] = 1
		}
	}
	q := plan.request
	body, err = contract.EncodeCryptoGeneratedFinishPlanRequest(contract.CryptoGeneratedFinishPlanRequest{OperationRef: op.operationRef, Context: op.context,
		Declaration: q.ParentPlan.Declaration, Graph: q.PlanGraph, SourceUses: q.AcceptedSources})
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	reply, res = p.exchange(ctx, contract.CryptoPrepare, body)
	if res.Outcome != 0 {
		return nil, res
	}
	view, err := contract.InspectCryptoGeneratedFinishPlanResult(reply.Body)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	finished, err := view.Own()
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	p.reservation, err = s.deriveGeneratedReservation(ctx, generatedReservationInput{graph: plan.input.graph, declaration: plan.input.declaration,
		registryImage: plan.input.registryImage, outputConfiguration: plan.input.outputConfiguration, parent: q.ParentPlan, finished: finished, requestBindings: plan.input.requestBindings, intents: plan.intents})
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	if plan.phase != nil {
		p.producerPhase = new(contract.GeneratorPhaseIdentity)
		*p.producerPhase = *plan.phase
	}
	source.PhaseID = p.reservation.candidate.head.Generator.PhaseID
	p.reservation.candidate.bindObservation(permit.observation, source)
	p.reservation.candidate.generated = &generatedCandidateFacts{reservation: p.reservation}
	p.reservation.candidate.producer = p
	return p, s.observed(ObservedCurrent)
}

func (p *generatedPreparation) exchange(ctx context.Context, kind contract.CryptoKind, body []byte) (contract.CryptoResponse, Result) {
	reply, res := p.operation.exchange(ctx, kind, body)
	if res.Outcome == 0 && !p.accumulateKeyUses(reply.KeyUseRows) {
		p.operation.terminal = true
		return contract.CryptoResponse{}, refused(AdmissionInvalid)
	}
	return reply, res
}

func (p *generatedPreparation) accumulateKeyUses(rows []contract.KeyUseRow) bool {
	if _, err := contract.KeyUseRowsLength(rows); err != nil {
		return false
	}
	counts := make(map[contract.KeyUseRow]uint32, len(p.keyUses)+len(rows))
	for _, batch := range [][]contract.KeyUseRow{p.keyUses, rows} {
		for _, row := range batch {
			count := row.Count
			row.Count = 0
			if count > math.MaxUint32-counts[row] {
				return false
			}
			counts[row] += count
		}
	}
	if len(counts) > contract.KeyUseRowsMaxCount {
		return false
	}
	out := make([]contract.KeyUseRow, 0, len(counts))
	for row, count := range counts {
		row.Count = count
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b contract.KeyUseRow) int {
		return cmp.Or(bytes.Compare(a.BindingID[:], b.BindingID[:]), bytes.Compare(a.PublicBindingDigest[:], b.PublicBindingDigest[:]),
			cmp.Compare(a.SubjectKind, b.SubjectKind), bytes.Compare(a.SubjectID[:], b.SubjectID[:]), cmp.Compare(a.Provider, b.Provider),
			cmp.Compare(a.Purpose, b.Purpose), cmp.Compare(a.Outcome, b.Outcome))
	})
	p.keyUses = out
	return true
}

// The private parent binds this prepared candidate inside Crypto before claim.
// A missing or changed private binding fails Freeze and never reaches signing.
// ClaimGeneratedPreparation binds a privately prepared generated candidate to
// the current authenticated session before persistence.
func (s *StateSession) claimGeneratedPreparationAttached(ctx context.Context, candidate *Candidate, trust contract.Trust) (*Candidate, Result) {
	if s == nil || ctx == nil || candidate == nil || candidate.generated == nil || candidate.producer == nil ||
		candidate.producer.reservation == nil || candidate.producer.reservation.state == nil ||
		candidate.producer.reservation.candidate != candidate ||
		trust == nil || trust.Identity() != s.admission.trust || trust.Family() != s.admission.store.Family {
		return nil, refused(AdmissionInvalid)
	}
	if err := candidate.producer.reservation.state.validateGeneratedSelection(ctx, nil); err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	p := candidate.producer
	authority, res := s.freezeAndClaimGeneratedPreparation(ctx, p)
	if res.Outcome != 0 {
		return nil, res
	}
	candidate.generated.authority = authority
	candidate.generated.claimed = true
	for _, result := range p.resultWrites {
		if res := s.persistGeneratedResult(ctx, result); res.Outcome != 0 {
			return nil, res
		}
	}
	return s.persistCandidate(ctx, candidate, trust)
}

// ClaimGeneratedOriginalProducer freezes one independent original producer.
// The complete producer set is collected on the same candidate before it is
// persisted. An individual claim cannot select or send on its own.
func (s *StateSession) claimGeneratedOriginalProducer(ctx context.Context, p *generatedPreparation) (*Candidate, Result) {
	if s == nil || ctx == nil || p == nil || p.reservation == nil || p.reservation.state == nil || p.reservation.candidate == nil ||
		p.reservation.candidate.generated == nil || !p.reservation.candidate.generated.claimed ||
		p.reservation.candidate.generated.producerMode.Load() != uint32(generatedOriginalSetMode) || p.reservation.candidate.generated.originalsComplete ||
		p.reservation.candidate.producer == p ||
		!slices.Contains(p.reservation.originalAttempts, p.attempt) ||
		!p.reservation.state.cachedGeneratedSelectionValid() {
		return nil, refused(AdmissionInvalid)
	}
	authority, res := s.freezeAndClaimGeneratedPreparation(ctx, p)
	if res.Outcome != 0 {
		return nil, res
	}
	if authority != p.reservation.candidate.generated.authority {
		return nil, refused(InvalidRelation)
	}
	return p.reservation.candidate, s.observed(ObservedCurrent)
}

func (s *StateSession) freezeAndClaimGeneratedPreparation(ctx context.Context, p *generatedPreparation) (contract.ID, Result) {
	if s == nil || ctx == nil || p == nil || p.claimed || p.reservation == nil || p.reservation.state == nil || p.operation == nil ||
		p.reservation.candidate == nil || p.reservation.candidate.session != s || !s.admission.valid(s.store) {
		return contract.ID{}, refused(AdmissionInvalid)
	}
	next, candidate, op := p.reservation.state, p.reservation.candidate, p.operation
	if candidate.head.Core != next.head.Core || candidate.head.Generator == nil ||
		*candidate.head.Generator != *next.head.Generator || candidate.generated == nil ||
		candidate.generated.reservation != p.reservation {
		return contract.ID{}, refused(InvalidRelation)
	}
	subject := *candidate.head.Generator
	public, err := next.publicProjection()
	if err != nil {
		return contract.ID{}, refused(InvalidRelation)
	}
	frozen := contract.CryptoGeneratedFreezeRequest{OperationRef: op.operationRef, Context: op.context, PhaseID: subject.PhaseID,
		RequestIdentityDigest: subject.RequestIdentityDigest, HeadCoreDigest: subject.HeadCoreDigest, ConditionDigest: subject.ConditionDigest}
	frozen.CandidatePublicStateDescriptor, err = contract.PublicStateDescriptor(public)
	if err != nil {
		return contract.ID{}, refused(InvalidRelation)
	}
	frozen.CandidateAccess, err = contract.AccessRecordsDescriptor(next.root.Domain, next.accessRecords())
	if err != nil {
		return contract.ID{}, refused(InvalidRelation)
	}
	frozen.CandidateSupport, err = next.supportDescriptor()
	if err != nil {
		return contract.ID{}, refused(InvalidRelation)
	}
	frozen.ActualResults, err = contract.GeneratorResultReferencesDescriptor(p.results)
	if err != nil {
		return contract.ID{}, refused(InvalidRelation)
	}
	frozen.KeyUses, err = contract.CryptoGeneratedKeyUseDescriptor(p.keyUses)
	if err != nil {
		return contract.ID{}, refused(AdmissionInvalid)
	}
	digest, err := contract.CryptoGeneratedFactDigest(op.instance, frozen)
	if err != nil {
		return contract.ID{}, refused(AdmissionInvalid)
	}
	body, err := contract.EncodeCryptoGeneratedFreezeRequest(frozen)
	if err != nil {
		return contract.ID{}, refused(AdmissionInvalid)
	}
	reply, res := p.exchange(ctx, contract.CryptoFreeze, body)
	if res.Outcome != 0 {
		return contract.ID{}, res
	}
	fact, err := contract.DecodeCryptoFreezeResult(reply.Body)
	if err != nil || fact.FactDigest != digest {
		return contract.ID{}, refused(AdmissionInvalid)
	}
	body, err = contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(frozen))
	if err != nil {
		return contract.ID{}, refused(AdmissionInvalid)
	}
	if _, res = p.exchange(ctx, contract.CryptoClaim, body); res.Outcome != 0 {
		return contract.ID{}, res
	}
	authority, err := contract.GeneratorAuthorityDigest(subject)
	if err != nil {
		return contract.ID{}, refused(InvalidProof)
	}
	p.authority, p.claimed = authority, true
	return authority, Result{}
}

// ClaimGeneratedOriginalSet makes one durable candidate from all independently
// claimed original producers. Every fixed original must be present exactly once.
func (s *StateSession) claimGeneratedOriginalSet(ctx context.Context, producers []*generatedPreparation, trust contract.Trust) (*Candidate, Result) {
	if s == nil || ctx == nil || len(producers) == 0 || producers[0] == nil || trust == nil ||
		trust.Identity() != s.admission.trust || trust.Family() != s.admission.store.Family {
		return nil, refused(AdmissionInvalid)
	}
	reservation := producers[0].reservation
	if reservation == nil || reservation.state == nil || reservation.candidate == nil || reservation.candidate.session != s ||
		reservation.candidate.generated == nil || reservation.candidate.generated.reservation != reservation ||
		!reservation.candidate.generated.claimed || reservation.candidate.generated.producerMode.Load() != uint32(generatedOriginalSetMode) ||
		reservation.candidate.generated.originalsComplete {
		return nil, refused(InvalidRelation)
	}
	expected := make(map[contract.ID]bool, len(reservation.originalAttempts))
	for _, attempt := range reservation.originalAttempts {
		expected[attempt] = true
	}
	if len(expected) == 0 || len(expected) != len(reservation.originalAttempts) || len(producers) != len(expected) {
		return nil, refused(InvalidRelation)
	}
	claims := make(map[contract.ID]contract.ID, len(expected))
	owned := make(map[contract.ID]*generatedPreparation, len(expected))
	for _, p := range producers {
		if p == nil || !p.claimed || p.reservation != reservation || p.producerLocator.IsZero() ||
			reservation.candidate.producer == p || !expected[p.attempt] ||
			p.authority != reservation.candidate.generated.authority {
			return nil, refused(InvalidRelation)
		}
		claims[p.attempt] = p.authority
		owned[p.attempt] = p
		delete(expected, p.attempt)
	}
	if len(expected) != 0 {
		return nil, refused(InvalidRelation)
	}
	if (len(reservation.candidate.originalProducers) != 0 || len(reservation.candidate.generated.originalClaims) != 0) &&
		(len(reservation.candidate.originalProducers) != len(owned) || len(reservation.candidate.generated.originalClaims) != len(claims)) {
		return nil, refused(InvalidRelation)
	}
	for attempt, producer := range reservation.candidate.originalProducers {
		if owned[attempt] != producer || reservation.candidate.generated.originalClaims[attempt] != claims[attempt] {
			return nil, refused(InvalidRelation)
		}
	}
	reservation.candidate.generated.originalClaims = claims
	reservation.candidate.originalProducers = owned
	reservation.candidate.generated.originalsComplete = true
	candidate, result := s.persistCandidate(ctx, reservation.candidate, trust)
	if result.Outcome != ObservedCurrent {
		reservation.candidate.generated.originalsComplete = false
	}
	return candidate, result
}

func (c *Candidate) generatedReady() bool {
	if c == nil || c.generated == nil || !c.generated.claimed || c.generated.reservation == nil ||
		c.generated.reservation.candidate != c || c.head.Generator == nil ||
		c.generated.producerMode.Load() == uint32(generatedOriginalSetMode) && !c.generated.originalsComplete {
		return false
	}
	digest, err := contract.GeneratorAuthorityDigest(*c.head.Generator)
	return err == nil && digest == c.generated.authority
}

// Producer requests reserve one local preparation mode before the caller can
// admit a private owner. Complete-set siblings share that reservation.
func (f *generatedCandidateFacts) reserveProducerMode(mode generatedProducerMode) bool {
	if f == nil {
		return false
	}
	return f.producerMode.CompareAndSwap(0, uint32(mode)) || f.producerMode.Load() == uint32(mode)
}
