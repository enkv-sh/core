package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedLifecycleKind uint8

const (
	generatedLifecycleRetirementResidue generatedLifecycleKind = iota + 1
	generatedLifecycleReflection
	generatedLifecycleCleanupClose
	generatedLifecycleInboxRelease
	generatedLifecycleRetirementClose
	generatedLifecycleInboxReleaseUnknown
	generatedLifecycleRetirementUnknown
	generatedLifecycleOrdinaryCleanupClose
	generatedLifecycleOrdinaryCleanupUnknown
	generatedLifecycleAutomaticClose
	generatedLifecycleAutomaticPark
)

// generatedLifecyclePlan is a closed, effect-free K2 transition plan. The
// caller cannot choose its owner, target or evidence: Core derives all three
// from the authenticated predecessor and verifies them again before signing.
type generatedLifecyclePlan struct {
	source                                   observationSource
	kind                                     generatedLifecycleKind
	context                                  contract.ApplyContext
	owner, target, evidence, requestIdentity contract.ID
	predecessorDigest, predecessorRevision   contract.ID
	predecessorToken                         contract.Token
	identity                                 transitionPlan
	result                                   []byte
}

// admittedGeneratedLifecycle is issued only by the private admission parent.
// It is bound to one session, current K2 route and one finite use.
type admittedGeneratedLifecycle struct {
	observation  *operationObservation
	session      *StateSession
	plan         *generatedLifecyclePlan
	trust        contract.ID
	family       contract.Family
	deadline     time.Time
	used         bool
	crypto       contract.Crypto
	instance     contract.ID
	verification contract.CryptoGeneratedCompareRequest
}

func (s *StateSession) freshGeneratedLifecyclePlan(ctx context.Context, supportPages, accessPages int) (transitionPlan, contract.ID, error) {
	if s == nil || supportPages < 0 || supportPages > contract.MaxChildPages || accessPages < 0 || accessPages > contract.MaxChildPages {
		return transitionPlan{}, contract.ID{}, contract.ErrRecord
	}
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return transitionPlan{}, contract.ID{}, err
	}
	entropy := s.admission.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	next := func() (contract.ID, bool) {
		var id contract.ID
		if _, err := io.ReadFull(entropy, id[:]); err != nil || id.IsZero() || used[id] {
			return contract.ID{}, false
		}
		used[id] = true
		return id, true
	}
	var p transitionPlan
	var ok bool
	for _, id := range []*contract.ID{&p.operation, &p.transition, &p.snapshot, &p.revision} {
		*id, ok = next()
		if !ok {
			return transitionPlan{}, contract.ID{}, contract.ErrRecord
		}
	}
	request, ok := next()
	if !ok {
		return transitionPlan{}, contract.ID{}, contract.ErrRecord
	}
	for i := range supportPages {
		p.supportPages[i], ok = next()
		if !ok {
			return transitionPlan{}, contract.ID{}, contract.ErrRecord
		}
	}
	for i := range accessPages {
		p.accessPages[i], ok = next()
		if !ok {
			return transitionPlan{}, contract.ID{}, contract.ErrRecord
		}
	}
	return p, request, nil
}

func (s *StateSession) generatedRetirementAmbiguityPlan(ctx context.Context, dutyID contract.ID, ambiguity []byte, admitted contract.ApplyContext, residue bool) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, fmt.Errorf("select lifecycle work: %w", err)
	}
	change, err := g.generatedRetirementAmbiguity(ctx, dutyID, ambiguity, residue)
	if err != nil {
		return nil, fmt.Errorf("derive lifecycle residue: %w", err)
	}
	target, err := g.retirementTarget(ctx, change.duty)
	if err != nil {
		return nil, err
	}
	evidence, err := generatedRetirementAmbiguityEvidence(s.root.Domain, change, residue)
	if err != nil {
		return nil, err
	}
	locations := change.locations
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, contract.MaxChildPages, 0)
	if err != nil {
		return nil, err
	}
	plan := &generatedLifecyclePlan{kind: generatedLifecycleRetirementResidue, context: admitted, owner: change.duty.DutyID,
		target: target.ResourceDigest, evidence: evidence.Digest, requestIdentity: request,
		predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision,
		predecessorToken: s.token, identity: identity, result: bytes.Clone(ambiguity), source: observationSource{ParentID: change.attempt.record.OperationID, AttemptID: change.attempt.record.AttemptID}}
	if !residue {
		plan.kind = generatedLifecycleRetirementUnknown
	}
	change.rows, _, _, _, err = s.generatedAmbiguityReceiptSupport(ctx, g, change, plan, change.rows, identity.revision, nil)
	if err != nil {
		return nil, fmt.Errorf("plan residue receipt: %w", err)
	}
	groups, err := generatedReservationGroupsForState(s, change.rows, locations, g.bundles)
	if err != nil {
		return nil, fmt.Errorf("group lifecycle residue: %w", err)
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(s.root, len(s.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return nil, fmt.Errorf("pack lifecycle residue: %w", err)
	}
	// Only selected pages are part of the identity and authority projection.
	for i := len(packed); i < len(plan.identity.supportPages); i++ {
		plan.identity.supportPages[i] = contract.ID{}
	}
	return plan, nil
}

func (s *StateSession) generatedLifecyclePlanValid(ctx context.Context, plan *generatedLifecyclePlan, supportPages, accessPages int) error {
	if s == nil || !s.root.ActiveGC.IsZero() || plan == nil || plan.predecessorDigest != contract.Hash(s.body) || plan.predecessorRevision != s.head.Core.Revision ||
		plan.predecessorToken != s.token || !s.generatedContextValid(plan.context) || plan.context.Expiry == 0 ||
		plan.owner.IsZero() || plan.evidence.IsZero() || plan.requestIdentity.IsZero() ||
		plan.identity.operation.IsZero() || plan.identity.transition.IsZero() || plan.identity.snapshot.IsZero() || plan.identity.revision.IsZero() ||
		supportPages < 0 || supportPages > contract.MaxChildPages || accessPages < 0 || accessPages > contract.MaxChildPages {
		return contract.ErrRecord
	}
	if plan.target.IsZero() {
		result, err := contract.InspectGeneratedResultRecord(plan.result)
		if plan.kind != generatedLifecycleCleanupClose || err != nil || contract.Hash(plan.result) != plan.evidence || result.Core.DomainID != s.root.Domain ||
			result.SafeFacts.Action != contract.GeneratorActionCreate || result.SafeFacts.LifecycleMode != contract.GeneratorLifecycleManaged ||
			result.SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect {
			return contract.ErrRecord
		}
	}
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return err
	}
	for _, id := range []contract.ID{plan.requestIdentity, plan.identity.operation, plan.identity.transition, plan.identity.snapshot, plan.identity.revision} {
		if used[id] {
			return contract.ErrRecord
		}
		used[id] = true
	}
	for i := range supportPages {
		id := plan.identity.supportPages[i]
		if id.IsZero() || used[id] {
			return contract.ErrRecord
		}
		used[id] = true
	}
	for i := supportPages; i < len(plan.identity.supportPages); i++ {
		if !plan.identity.supportPages[i].IsZero() {
			return contract.ErrRecord
		}
	}
	for i := range accessPages {
		id := plan.identity.accessPages[i]
		if id.IsZero() || used[id] {
			return contract.ErrRecord
		}
		used[id] = true
	}
	for i := accessPages; i < len(plan.identity.accessPages); i++ {
		if !plan.identity.accessPages[i].IsZero() {
			return contract.ErrRecord
		}
	}
	return nil
}

func (s *StateSession) deriveGeneratedRetirementResidue(ctx context.Context, plan *generatedLifecyclePlan, detail *changeObservation) (*generatedReservation, error) {
	if plan == nil || plan.kind != generatedLifecycleRetirementResidue && plan.kind != generatedLifecycleRetirementUnknown {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	residue := plan.kind == generatedLifecycleRetirementResidue
	change, err := g.generatedRetirementAmbiguity(ctx, plan.owner, plan.result, residue)
	if err != nil {
		return nil, err
	}
	target, err := g.retirementTarget(ctx, change.duty)
	if err != nil {
		return nil, err
	}
	if target.ResourceDigest != plan.target {
		return nil, contract.ErrRecord
	}
	evidence, err := generatedRetirementAmbiguityEvidence(s.root.Domain, change, residue)
	if err != nil || evidence.Digest != plan.evidence {
		return nil, contract.ErrRecord
	}
	locations := change.locations
	rows, successes, failures, order, err := s.generatedAmbiguityReceiptSupport(ctx, g, change, plan, change.rows, plan.identity.revision, detail)
	if err != nil {
		return nil, fmt.Errorf("derive residue receipt: %w", err)
	}
	rows, err = rebindSnapshotSliceRecords(rows, s.root.Domain, s.adminIndex.SliceSnapshot, plan.identity.snapshot)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsForState(s, rows, locations, g.bundles)
	if err != nil {
		return nil, fmt.Errorf("group derived lifecycle residue: %w", err)
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(s.root, len(s.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return nil, fmt.Errorf("validate derived lifecycle residue: %w", err)
	}
	if err := s.generatedLifecyclePlanValid(ctx, plan, len(packed), 0); err != nil {
		return nil, fmt.Errorf("validate derived lifecycle residue: %w", err)
	}

	next, candidate, identity := s.beginGeneratedSuccessor(plan.identity)
	next.root.Generated.ActiveOwner, next.root.Generated.ActivePhase, next.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	next.root.Generated.SuccessWindow, next.root.Generated.FailureWindow, next.root.Generated.ReceiptOrder = successes, failures, order
	next.root.Generated.Slices = change.slices
	next.root.RequiredSupport, next.support = nil, nil
	next.recountChildren()
	if residue {
		if err := next.clearGeneratedRetiringPointer(ctx, change.duty.DutyID, plan, candidate, &identity); err != nil {
			return nil, err
		}
	}
	generatedRefreshClosureCounts(&next.root.Generated, rows)
	supportPageCount := min(len(packed), len(plan.identity.supportPages))
	if err := s.installGeneratedSuccessorSupport(ctx, &next, packed, plan.identity.supportPages[:supportPageCount], candidate, &identity); err != nil {
		return nil, err
	}
	next.recountChildren()
	if !next.indexSelectedMaterials() {
		return nil, fmt.Errorf("index lifecycle residue successor: %w", contract.ErrRecord)
	}
	if !validAggregate(next.root) {
		return nil, fmt.Errorf("aggregate lifecycle residue successor: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("relate lifecycle residue successor: %w", err)
	}
	head, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
	if err != nil {
		return nil, err
	}
	subject, err := s.generatedRetirementResidueSubject(ctx, &next, g, plan, change, evidence, identity, head)
	if err != nil {
		return nil, fmt.Errorf("construct lifecycle residue authority: %w", err)
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, fmt.Errorf("validate lifecycle residue authority: %w", err)
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedRetirementResidueSubject(ctx context.Context, next *StateSession, before *generatedSelection, plan *generatedLifecyclePlan,
	change generatedResidueClosure, evidence contract.GeneratorDescriptor, identity contract.IdentityPlan, head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	bundle, err := before.retainedGraph(change.attempt.record.OperationID)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	purpose := contract.GeneratorAuthorityResidue
	if plan.kind == generatedLifecycleRetirementUnknown {
		purpose = contract.GeneratorAuthorityRecord
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: plan.requestIdentity, ObservedHEADDigest: plan.predecessorDigest,
		ConditionDigest: plan.context.OriginalConditionDigest, TransitionKind: purpose,
		BeforePhase: 1, AfterPhase: 2, Evidence: evidence}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	x := change.attempt.expected.Template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: purpose,
		DomainID: s.root.Domain, OperationID: plan.identity.operation, RequestIdentityDigest: plan.requestIdentity,
		PlanGraphID: bundle.UsePlan.PlanGraphID, UsePlanDigest: usePlan, PhaseID: phaseID,
		PreviousHEADDigest: plan.predecessorDigest, PreviousRevisionID: plan.predecessorRevision,
		ConditionDigest: plan.context.OriginalConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: change.duty.DutyID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: x.ResultID, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
		Intent: bundle.Request.Declaration, CapacityReservation: change.duty.CapacityReservation, BeforePhase: 1, AfterPhase: 2}
	if plan.kind == generatedLifecycleRetirementUnknown {
		subject.ResultDigest = contract.Hash(plan.result)
	}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		return subject, err
	}
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, generatedEntryUnion(s, next))
	if err != nil {
		return subject, err
	}
	membership := s.generatedUnchangedEntryUnion()
	for i := range membership {
		membership[i].After.EntryDigest = contract.ID{}
	}
	subject.RequiredAuthoritySet = generatedMembershipAuthority(membership)
	subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membership)
	if err != nil {
		return subject, err
	}
	beforeWork, err := s.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	afterWork, err := next.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	subject.BeforeWork, err = s.workSupportDescriptor(beforeWork)
	if err != nil {
		return subject, err
	}
	subject.AfterWork, err = next.workSupportDescriptor(afterWork)
	if err != nil {
		return subject, err
	}
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		return subject, err
	}
	subject.ResultVector = contract.GeneratorDescriptor(empty)
	headBody, err := format.EncodeHeadCore(head)
	if err != nil {
		return subject, err
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head, headBody))
	if err != nil {
		return subject, err
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(headBody), uint32(len(headBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(conditionalBody), uint32(len(conditionalBody))
	_, err = contract.NewGeneratorRequest(subject)
	return subject, err
}

func (s *selectedGeneratedProof) validGeneratedRetirementResidueSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	return s.validGeneratedRetirementAmbiguitySelection(g, subject, true)
}

func (s *selectedGeneratedProof) validGeneratedRetirementAmbiguitySelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject, residue bool) bool {
	purpose, state := contract.GeneratorAuthorityResidue, contract.GeneratedEffectClosedWithResidue
	if !residue {
		purpose, state = contract.GeneratorAuthorityRecord, contract.GeneratedEffectUnknown
	}
	if g == nil || g.parent != nil || g.phase != nil || subject.Purpose != purpose ||
		residue && !subject.ResultDigest.IsZero() || subject.BeforePhase != 1 || subject.AfterPhase != 2 ||
		subject.BeforeAccessDigest != subject.AfterAccessDigest || subject.AfterAccessDigest != s.root.CurrentAccess.AccessRoot {
		return false
	}
	var hazard contract.GeneratedHazardRecord
	found := false
	for key, row := range g.records {
		if key.kind != contract.GeneratedHazardSupportKind {
			continue
		}
		candidate, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil || candidate.OwnerID != subject.OwnerID || candidate.OriginalAttemptID != subject.AttemptID {
			continue
		}
		if found {
			return false
		}
		hazard, found = candidate, true
	}
	if residue && (!found || hazard.Exposure != contract.GeneratedExposurePossibleLive || hazard.Fenced != 1 ||
		hazard.CapacityReservation != subject.CapacityReservation) {
		return false
	}
	row, ok := g.records[generatedRecordKey{kind: contract.GeneratedAttemptSupportKind, id: subject.AttemptID}]
	if !ok {
		return false
	}
	attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
	if err != nil || attempt.State != state || attempt.OwnerID != subject.OwnerID ||
		attempt.LineageID != subject.LineageID || attempt.PredecessorAttemptID != subject.PredecessorAttemptID || attempt.ResultID != subject.ResultID ||
		attempt.ConfigContractID != subject.ConfigContractID || attempt.DescriptorID != subject.DescriptorID || attempt.ResultContractID != subject.ResultContractID {
		return false
	}
	bundle, err := g.retainedGraph(attempt.OperationID)
	if err != nil || bundle.Request.Declaration != subject.Intent || bundle.UsePlan.PlanGraphID != subject.PlanGraphID {
		return false
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil || usePlan != subject.UsePlanDigest {
		return false
	}
	change := generatedResidueClosure{hazard: hazard}
	if !residue {
		row, present := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, subject.OwnerID}]
		if !present {
			return false
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.Status != contract.GeneratedEffectUnknown || duty.CapacityReservation != subject.CapacityReservation {
			return false
		}
		change.duty = duty
		facts, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, attempt.AttemptID, contract.GeneratorVectorFacts, attempt.Facts)
		if err != nil || len(facts) != 1 {
			return false
		}
		fact, err := contract.InspectGeneratorFactsRow(facts[0])
		if err != nil || subject.ResultDigest != contract.Hash(fact.Facts) {
			return false
		}
	}
	evidence, err := generatedRetirementAmbiguityEvidence(s.root.Domain, change, residue)
	if err != nil {
		return false
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest,
		TransitionKind: subject.Purpose, BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: evidence})
	if err != nil || phase != subject.PhaseID {
		return false
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: s.root.Snapshot,
		Transition: s.root.Transition, Revision: s.head.Core.Revision}
	changes, membershipRows := s.generatedUnchangedEntryUnion(), s.generatedUnchangedEntryUnion()
	if residue {
		before, membership, valueEntryPages, ok := s.generatedReleasedRetirementEntryProjections(bundle, subject)
		if !ok {
			return false
		}
		changes, membershipRows = before, membership
		identity.Pages = append(identity.Pages, valueEntryPages...)
	}
	for _, ref := range s.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil || descriptor != subject.IdentityPlan {
		return false
	}
	entryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, changes)
	if err != nil || entryUnion != subject.ValueEntryUnion {
		return false
	}
	for i := range membershipRows {
		membershipRows[i].After.EntryDigest = contract.ID{}
	}
	planned, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membershipRows)
	if err != nil || planned != subject.MembershipChanges || generatedMembershipAuthority(membershipRows) != subject.RequiredAuthoritySet {
		return false
	}
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	return err == nil && subject.ResultVector == contract.GeneratorDescriptor(empty)
}

func (s *StateSession) deriveGeneratedLifecycle(ctx context.Context, plan *generatedLifecyclePlan,
	detail *changeObservation) (*generatedReservation, error) {
	switch plan.kind {
	case generatedLifecycleAutomaticClose, generatedLifecycleAutomaticPark:
		return s.deriveGeneratedAutomaticClose(ctx, plan)
	case generatedLifecycleRetirementResidue, generatedLifecycleRetirementUnknown:
		return s.deriveGeneratedRetirementResidue(ctx, plan, detail)
	case generatedLifecycleOrdinaryCleanupUnknown:
		return s.deriveGeneratedOrdinaryCleanupAmbiguity(ctx, plan)
	case generatedLifecycleReflection:
		return s.deriveGeneratedReflection(ctx, plan)
	case generatedLifecycleCleanupClose, generatedLifecycleOrdinaryCleanupClose:
		return s.deriveGeneratedCleanupClose(ctx, plan)
	case generatedLifecycleInboxRelease:
		return s.deriveGeneratedInboxRelease(ctx, plan)
	case generatedLifecycleRetirementClose:
		return s.deriveGeneratedRetirementClose(ctx, plan, detail)
	case generatedLifecycleInboxReleaseUnknown:
		return s.deriveGeneratedInboxReleaseUnknown(ctx, plan)
	default:
		return nil, contract.ErrRecord
	}
}

// PrepareGeneratedLifecycle signs one exact effect-free lifecycle candidate
// under the current K2 route. It does not create a producer or first-send
// permit and cannot call a provider.
func (s *StateSession) prepareGeneratedLifecycle(ctx context.Context, permit *admittedGeneratedLifecycle,
	trust contract.Trust) (*Candidate, Result) {
	if s == nil || s.prepared || ctx == nil || !s.admission.valid(s.store) || permit == nil || permit.used || permit.session != s ||
		permit.plan == nil || permit.trust != s.admission.trust || permit.family != s.admission.store.Family ||
		!validPrivateDeadline(permit.deadline) || permit.plan.context.Expiry != uint64(permit.deadline.UnixNano()) ||
		trust == nil || trust.Identity() != permit.trust || trust.Family() != permit.family {
		return nil, refused(AdmissionInvalid)
	}
	permit.used, s.prepared = true, true
	if permit.plan.kind == generatedLifecycleReflection || permit.plan.kind == generatedLifecycleCleanupClose {
		effectContext, cancel := context.WithDeadline(ctx, permit.deadline)
		defer cancel()
		first, err := s.generatedReflectionIsFirst(effectContext, permit.plan)
		if err != nil {
			if result, ok := selectedReadResult(err); ok {
				return nil, result
			}
			return nil, refused(InvalidRelation)
		}
		if !first {
			return nil, refused(InvalidRelation)
		}
		if permit.crypto == nil || permit.instance.IsZero() || permit.crypto.InstanceID() != permit.instance {
			return nil, refused(AdmissionInvalid)
		}
	}
	var detail *changeObservation
	if permit.observation.enabled() {
		detail = &changeObservation{}
	}
	reservation, err := s.deriveGeneratedLifecycle(ctx, permit.plan, detail)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	source := exchangeSource(permit.plan.context)
	source.OperationID, source.PhaseID = permit.plan.identity.operation, reservation.candidate.head.Generator.PhaseID
	source.ParentID, source.AttemptID = permit.plan.source.ParentID, permit.plan.source.AttemptID

	if detail != nil && detail.HasChangedSubjects {
		source.Stage, source.OperationID, source.PhaseID = observationCandidate, permit.plan.identity.operation, reservation.candidate.head.Generator.PhaseID

		source.ParentID, source.AttemptID = detail.Source.ParentID, detail.Source.AttemptID
		detail.Source = source
		detail.Candidate = candidateObservationIdentity(reservation.candidate)
		permit.observation.offerChange(ctx, *detail)
		detail = nil
	}
	p := &generatedPreparation{reservation: reservation}
	if permit.plan.kind == generatedLifecycleReflection || permit.plan.kind == generatedLifecycleCleanupClose {
		q, verifiedSource, err := s.generatedOriginalVerificationRequest(ctx, permit.plan)
		if err != nil || q != permit.verification {
			return nil, refused(InvalidRelation)
		}
		bindings, err := s.currentBindings()
		if err != nil {
			return nil, refused(InvalidRelation)
		}
		source = verifiedSource
		source.OperationID = permit.plan.identity.operation
		source.PhaseID = reservation.candidate.head.Generator.PhaseID
		p.operation = &cryptoOperation{observation: permit.observation, source: source, adapter: permit.crypto, instance: permit.instance, authority: s.admission.recipient,
			context: q.Context, deadline: permit.deadline, bindings: bindings, sourceCount: 1}
		body, err := contract.EncodeCryptoGeneratedCompareRequest(q)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		reply, res := p.exchange(ctx, contract.CryptoCompare, body)
		if res.Outcome != 0 {
			return nil, res
		}
		compared, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		p.operation.operationRef, p.operation.sourceCount = compared.OperationRef, 0
		body, err = contract.EncodeCryptoGeneratedVerifyRequest(contract.CryptoGeneratedVerifyRequest{OperationRef: compared.OperationRef,
			Context: q.Context, Result: permit.plan.result, ExpectedResult: contract.GeneratorDescriptor{
				Digest: q.OriginalResult.ResultBodyDigest, Length: uint64(q.OriginalResult.ResultLength), Count: 1}})
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		reply, res = p.exchange(ctx, contract.CryptoPrepare, body)
		if res.Outcome != 0 {
			return nil, res
		}
		verified, err := contract.InspectGeneratorResultReference(reply.Body)
		if err != nil || verified != q.OriginalResult {
			return nil, refused(InvalidProof)
		}
		p.operation.terminal = true
		p.results = []contract.GeneratorResultReference{verified}
	}
	authority, err := contract.GeneratorAuthorityDigest(*reservation.candidate.head.Generator)
	if err != nil {
		return nil, refused(InvalidProof)
	}
	reservation.candidate.bindObservation(permit.observation, source)
	reservation.candidate.generated = &generatedCandidateFacts{reservation: reservation, authority: authority, claimed: true}
	return s.persistCandidate(ctx, reservation.candidate, trust)
}
