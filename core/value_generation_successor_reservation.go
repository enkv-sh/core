package core

import (
	"bytes"
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedSuccessorReservationPlan struct {
	context       contract.ApplyContext
	source        observationSource
	phase         contract.GeneratorPhaseIdentity
	attempt       contract.ID
	requestDigest contract.ID
}

type admittedGeneratedSuccessorReservation struct {
	observation *operationObservation
	session     *StateSession
	plan        *generatedSuccessorReservationPlan
	used        bool
}

func generatedSuccessorReservationEvidence(x contract.GeneratorAttemptTemplate) (contract.GeneratorDescriptor, error) {
	body, err := contract.EncodeGeneratorAttemptTemplate(x)
	if err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	return contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: uint64(len(body)), Count: 1}, nil
}

func generatedPlannedSuccessor(g *generatedSelection) (contract.GeneratorAttemptTemplate, contract.GeneratorResultUse, contract.GeneratedAttemptRecord, error) {
	if g == nil || g.parent == nil || g.phase == nil || len(g.bundles) == 0 ||
		g.bundles[0].Header.OperationID != g.parent.OperationID || g.bundles[0].UsePlan.PlanGraphID != g.parent.PlanGraphID ||
		int(g.phase.LineageIndex) >= len(g.bundles[0].Lineages) {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	lineage := g.bundles[0].Lineages[g.phase.LineageIndex]
	if lineage.Purpose != contract.GeneratorLineageCreate || g.phase.Branch >= lineage.TemplateCount ||
		g.phase.Stage != contract.GeneratedStageRetainedResult || !g.phase.AcceptedResultID.IsZero() || !g.phase.ResultDigest.IsZero() {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	row, ok := g.records[generatedRecordKey{kind: contract.GeneratedLineageSupportKind, id: lineage.LineageID}]
	if !ok {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	installed, err := contract.InspectGeneratedLineageRecord(row.Body)
	if err != nil || installed.Branch != g.phase.Branch || installed.Branch == installed.Frontier || installed.NoEffectUsed != g.phase.NoEffectUsed ||
		installed.ResidueUsed != g.phase.ResidueUsed {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	x := lineage.Templates[installed.Branch]
	predecessor := lineage.Templates[installed.Frontier]
	if x.Action != contract.GeneratorActionCreate || x.AttemptID != g.phase.FrontierAttemptID || x.PredecessorAttemptID != predecessor.AttemptID {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	if _, ok := g.attempts[x.AttemptID]; ok {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	if _, ok := g.releases[x.AttemptID]; ok {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	guard, outcome := uint8(contract.GeneratorGuardResidue), uint8(contract.GeneratedEffectClosedWithResidue)
	if x.Branch == contract.GeneratorBranchNoEffect || x.Branch == contract.GeneratorBranchResidueThenNoEffect {
		guard, outcome = contract.GeneratorGuardQualifiedNoEffect, contract.GeneratedEffectConfirmedNoEffect
	}
	next, present, err := predecessor.SuccessorBranch(guard)
	if err != nil || !present || next != x.Branch {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	prior, ok := g.attempts[predecessor.AttemptID]
	if !ok {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	a := prior.record
	if a.State != outcome || a.Stage != contract.GeneratedStageTerminal || a.OperationID != g.parent.OperationID || a.LineageID != x.LineageID || a.RequestDigest.IsZero() {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	if guard == contract.GeneratorGuardResidue {
		hazardRow, present := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: predecessor.HazardID}]
		if !present {
			return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
		}
		hazard, e := contract.InspectGeneratedHazardRecord(hazardRow.Body)
		if e != nil || hazard.Fenced != 1 || hazard.OriginalOperationID != a.OperationID || hazard.OriginalAttemptID != a.AttemptID {
			return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
		}
	}
	_, use, ok := generatedTemplate(g.bundles[0], x.AttemptID)
	if !ok {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, contract.GeneratedAttemptRecord{}, contract.ErrRecord
	}
	return x, use, a, nil
}

func (s *StateSession) generatedSuccessorReservationRequest(ctx context.Context, admitted contract.ApplyContext) (*generatedSuccessorReservationPlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if g.phase == nil || g.phase.Phase == ^uint32(0) {
		return nil, contract.ErrRecord
	}
	x, _, _, err := generatedPlannedSuccessor(g)
	if err != nil {
		return nil, err
	}
	evidence, err := generatedSuccessorReservationEvidence(x)
	if err != nil {
		return nil, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: g.parent.RequestIdentityDigest,
		ObservedHEADDigest: admitted.PredecessorHEADDigest, ConditionDigest: admitted.OriginalConditionDigest,
		TransitionKind: contract.GeneratorAuthorityReservation, BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1, Evidence: evidence}
	if _, err := contract.GeneratorPhaseID(phase); err != nil {
		return nil, err
	}
	return &generatedSuccessorReservationPlan{context: admitted, phase: phase, attempt: x.AttemptID, source: observationSource{ParentID: g.parent.OperationID}}, nil
}

func (s *StateSession) deriveGeneratedSuccessorReservation(ctx context.Context, plan *generatedSuccessorReservationPlan) (*generatedReservation, error) {
	if plan == nil {
		return nil, contract.ErrRecord
	}
	checked, err := s.generatedSuccessorReservationRequest(ctx, plan.context)
	if plan.phase.TransitionKind == contract.GeneratorAuthorityRetireReserve {
		checked, err = s.generatedAutomaticReservationRequest(ctx, plan.context, plan.requestDigest)
	}
	if err != nil {
		return nil, err
	}
	if checked.context != plan.context || checked.phase != plan.phase || checked.attempt != plan.attempt {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if plan.phase.TransitionKind == contract.GeneratorAuthorityRetireReserve {
		return s.deriveGeneratedAutomaticReservation(ctx, g, plan)
	}
	x, use, predecessor, err := generatedPlannedSuccessor(g)
	if err != nil || x.AttemptID != plan.attempt {
		return nil, contract.ErrRecord
	}
	phaseID, err := contract.GeneratorPhaseID(plan.phase)
	if err != nil {
		return nil, err
	}
	entered, err := generatedScheduledCreateRowsWithHistory(g, *g.parent, x, use, predecessor.RequestDigest, contract.GeneratedAttemptRecord{}, contract.ID{})
	if err != nil {
		return nil, err
	}
	rows := append(slices.Clone(s.supportRecords()), entered...)
	lineageRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedLineageSupportKind, id: x.LineageID}]
	if !ok {
		return nil, contract.ErrRecord
	}
	lineage, err := contract.DecodeGeneratedLineageRecord(lineageRow.Body)
	if err != nil || lineage.Branch != x.Branch || lineage.Frontier == x.Branch {
		return nil, contract.ErrRecord
	}
	lineage.Frontier = x.Branch
	lineageBody, err := contract.EncodeGeneratedLineageRecord(lineage)
	if err != nil {
		return nil, err
	}
	phase := *g.phase
	phase.PhaseID, phase.Phase = phaseID, plan.phase.AfterPhase
	for i := range rows {
		if rows[i].Kind == contract.GeneratedLineageSupportKind && rows[i].RecordID == x.LineageID {
			rows[i].Body = lineageBody
		}
	}
	for _, set := range []struct {
		kind       uint8
		family     contract.GeneratorRecordSetKind
		descriptor *contract.GeneratorDescriptor
	}{
		{contract.GeneratedAttemptSupportKind, contract.GeneratorPhaseAttempts, &phase.Attempts},
		{contract.GeneratedDutySupportKind, contract.GeneratorPhaseDuties, &phase.Duties},
	} {
		var selected []contract.SupportRecord
		for _, row := range rows {
			if row.Kind == set.kind && (g.activePhaseOwns(row) || row.RecordID == x.AttemptID || row.RecordID == x.DutyID) {
				selected = append(selected, row)
			}
		}
		slices.SortFunc(selected, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
		*set.descriptor, err = contract.GeneratorRecordSetDescriptor(set.family, g.parent.DomainID, selected)
		if err != nil {
			return nil, err
		}
	}
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == contract.GeneratedPhaseSupportKind && rows[i].RecordID == phase.OperationID {
			rows[i].Body = phaseBody
		}
	}
	return s.deriveGeneratedSuccessorCandidate(ctx, g, plan, x, phaseID, rows)
}

func (s *StateSession) deriveGeneratedSuccessorCandidate(ctx context.Context, g *generatedSelection, plan *generatedSuccessorReservationPlan,
	x contract.GeneratorAttemptTemplate, phaseID contract.ID, rows []contract.SupportRecord) (*generatedReservation, error) {
	locations, err := s.resolveSelectedGeneratedSlices()
	if err != nil {
		return nil, err
	}
	return s.deriveGeneratedPhaseCandidate(ctx, g, plan, x, phaseID, rows, locations, s.root.Generated.Slices)
}

func (s *StateSession) deriveGeneratedPhaseCandidate(ctx context.Context, g *generatedSelection, plan *generatedSuccessorReservationPlan,
	x contract.GeneratorAttemptTemplate, phaseID contract.ID, rows []contract.SupportRecord, locations []contract.GeneratorSliceLocation,
	sliceDescriptor contract.GeneratorDescriptor) (*generatedReservation, error) {
	next := s.successorState()
	next.cache, next.accessLocations, next.valueReaders = nil, nil, nil
	var err error
	next.root.Snapshot, err = contract.GeneratorPhaseSnapshotID(phaseID)
	if err != nil {
		return nil, err
	}
	next.root.Transition, err = contract.GeneratorPhaseTransitionID(phaseID)
	if err != nil {
		return nil, err
	}
	revision, err := contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		return nil, err
	}
	rows, err = rebindSnapshotSliceRecords(rows, s.root.Domain, s.adminIndex.SliceSnapshot, next.root.Snapshot)
	if err != nil {
		return nil, err
	}
	next.root.Generated.Slices = sliceDescriptor
	groups, err := generatedReservationGroupsWithSource(&next, s, rows, locations, g.bundles)
	if err != nil {
		return nil, err
	}
	next.root.RequiredSupport, next.support = nil, nil
	next.root.Generated.ActivePhase = phaseID
	generatedRefreshClosureCounts(&next.root.Generated, rows)
	next.recountChildren()
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, next.root.ChildCount, fragments)
	if err != nil {
		return nil, err
	}
	candidate := &Candidate{session: s}
	identity := contract.IdentityPlan{Operation: g.parent.OperationID, Snapshot: next.root.Snapshot, Transition: next.root.Transition, Revision: revision}
	pageIDs := make([]contract.ID, len(packed))
	physicalIndexes, err := s.generatedSupportPhysicalIndexes(packed)
	if err != nil {
		return nil, err
	}

	for i := range pageIDs {
		id, err := contract.GeneratorPhasePageID(phaseID, contract.RequiredSupportKind, physicalIndexes[i])
		if err != nil {
			return nil, err
		}
		pageIDs[i] = id
	}
	var materialized generatedRequiredSupportMaterialization
	if len(s.fragmentFacts) != 0 || s.root.OutputConfiguration.SliceCount != 0 {
		materialized, err = s.materializeGeneratedSupportPages(ctx, packed, pageIDs)
	} else {
		materialized, err = materializeGeneratedRequiredSupport(s.root.Domain, packed, pageIDs)
	}
	if err != nil {
		return nil, err
	}
	next.root.RequiredSupport, next.support = materialized.references, materialized.views
	next.root.RequiredSupportRecordCount, next.root.Generated.Fragments = materialized.recordCount, materialized.fragments
	next.clearSelectedSupportFacts()
	candidate.objects = append(candidate.objects, materialized.objects...)
	identity.Pages = append(identity.Pages, materialized.identityPages...)
	if err := s.installAdministrativeIndexWithBundles(ctx, &next, candidate, g.bundles); err != nil {
		return nil, err
	}
	if !next.indexSelectedMaterials() || !validAggregate(next.root) {
		return nil, contract.ErrRecord
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, err
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, err
	}
	rootRef, err := format.Reference(format.RootKind, s.root.Domain, next.root.Snapshot, 0, rootBody)
	if err != nil {
		return nil, err
	}
	candidate.objects = append(candidate.objects, objectImage{ref: rootRef, body: rootBody})
	head := s.successorCore(transitionPlan{revision: revision})
	head.Root = rootRef
	subject, err := s.generatedSuccessorReservationSubject(ctx, &next, g, plan, x, identity, head)
	if err != nil {
		return nil, err
	}
	candidate.head = format.Head{Core: head, AuthKind: format.GeneratorAuth, Generator: &subject,
		K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = candidate.head
	if err := s.generatedAutomaticCandidatePreserved(&next); err != nil {
		return nil, err
	}
	if err := next.validateGeneratedSelection(ctx, nil); err != nil {
		return nil, err
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedSuccessorReservationSubject(ctx context.Context, next *StateSession, g *generatedSelection,
	plan *generatedSuccessorReservationPlan, x contract.GeneratorAttemptTemplate, identity contract.IdentityPlan,
	head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	p := *g.parent
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityReservation,
		DomainID: p.DomainID, OperationID: p.OperationID, RequestIdentityDigest: p.RequestIdentityDigest,
		PlanGraphID: p.PlanGraphID, UsePlanDigest: p.UsePlanDigest, PhaseID: next.root.Generated.ActivePhase,
		PreviousHEADDigest: contract.Hash(s.body), PreviousRevisionID: s.head.Core.Revision, ConditionDigest: plan.phase.ConditionDigest,
		BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: p.OperationID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: x.ResultID, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
		Intent: p.Declaration, CapacityReservation: p.Capacity, BeforePhase: plan.phase.BeforePhase, AfterPhase: plan.phase.AfterPhase}
	if plan.phase.TransitionKind == contract.GeneratorAuthorityRetireReserve {
		subject.Purpose = contract.GeneratorAuthorityRetireReserve
		subject.OwnerID = x.DutyID
	}
	if plan.phase.TransitionKind == contract.GeneratorAuthorityFinalPreparation {
		subject.Purpose = contract.GeneratorAuthorityFinalPreparation
	}
	var err error
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		return subject, err
	}
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(p.DomainID, s.generatedUnchangedEntryUnion())
	if err != nil {
		return subject, err
	}
	declaration, err := g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, p.OperationID, contract.GeneratorDeclarationMaxLength)
	if err != nil {
		return subject, err
	}
	planned, err := s.generatedMembershipPlan(g.bundles[0], declaration)
	if err != nil {
		return subject, err
	}
	subject.RequiredAuthoritySet = generatedMembershipAuthority(planned)
	subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(p.DomainID, planned)
	if err != nil {
		return subject, err
	}
	before, err := s.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	after, err := next.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	subject.BeforeWork, err = s.workSupportDescriptor(before)
	if err != nil {
		return subject, err
	}
	subject.AfterWork, err = next.workSupportDescriptor(after)
	if err != nil {
		return subject, err
	}
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		return subject, err
	}
	subject.ResultVector = contract.GeneratorDescriptor(empty)
	if plan.phase.TransitionKind == contract.GeneratorAuthorityFinalPreparation || plan.phase.TransitionKind == contract.GeneratorAuthorityRetireReserve {
		subject.ResultVector = plan.phase.Evidence
	}
	headBody, err := format.EncodeHeadCore(head)
	if err != nil {
		return subject, err
	}
	condition, err := format.EncodeConditionalPlan(conditional(head, headBody))
	if err != nil {
		return subject, err
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(headBody), uint32(len(headBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(condition), uint32(len(condition))
	_, err = contract.NewGeneratorRequest(subject)
	return subject, err
}

// PrepareGeneratedSuccessorReservation fixes a planned successor to the
// current authenticated state. It grants no dispatch right. Producer custody,
// normal authority claim, accepted CAS, and exact readback are still required.
func (s *StateSession) prepareGeneratedSuccessorReservation(ctx context.Context, permit *admittedGeneratedSuccessorReservation) (*generatedPreparation, Result) {
	if s == nil || ctx == nil || s.prepared || !s.admission.valid(s.store) || permit == nil || permit.used || permit.session != s || permit.plan == nil ||
		!validPrivateDeadline(time.Unix(0, int64(permit.plan.context.Expiry))) {
		return nil, refused(AdmissionInvalid)
	}
	permit.used = true
	if ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	checked, err := s.generatedSuccessorReservationRequest(ctx, permit.plan.context)
	if permit.plan.phase.TransitionKind == contract.GeneratorAuthorityRetireReserve {
		checked, err = s.generatedAutomaticReservationRequest(ctx, permit.plan.context, permit.plan.requestDigest)
	}
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(AdmissionInvalid)
	}
	if checked.context != permit.plan.context || checked.phase != permit.plan.phase || checked.attempt != permit.plan.attempt {
		return nil, refused(AdmissionInvalid)
	}
	reservation, err := s.deriveGeneratedSuccessorReservation(ctx, permit.plan)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	source := exchangeSource(permit.plan.context)
	source.OperationID, source.PhaseID, source.AttemptID = reservation.candidate.head.Generator.OperationID, reservation.candidate.head.Generator.PhaseID, permit.plan.attempt
	source.ParentID = checked.source.ParentID

	reservation.candidate.bindObservation(permit.observation, source)
	p := &generatedPreparation{plannedSuccessor: true, reservation: reservation, producerPhase: &permit.plan.phase,
		producerBaseContext: permit.plan.context}
	authority, err := contract.GeneratorAuthorityDigest(*reservation.candidate.head.Generator)
	if err != nil {
		return nil, refused(InvalidProof)
	}
	reservation.candidate.generated = &generatedCandidateFacts{reservation: reservation, authority: authority}
	reservation.candidate.producer = p
	s.prepared = true
	return p, s.observed(ObservedCurrent)
}

func (s *selectedGeneratedProof) validGeneratedSuccessorReservationSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	if g == nil || g.parent == nil || g.phase == nil || subject.BeforePhase == 0 ||
		subject.BeforeAccessDigest != subject.AfterAccessDigest || !subject.ResultDigest.IsZero() ||
		g.phase.Stage != contract.GeneratedStageRetainedResult || !g.phase.AcceptedResultID.IsZero() || !g.phase.ResultDigest.IsZero() ||
		int(g.phase.LineageIndex) >= len(g.bundles[0].Lineages) {
		return false
	}
	lineage := g.bundles[0].Lineages[g.phase.LineageIndex]
	if lineage.Purpose != contract.GeneratorLineageCreate || g.phase.Branch >= lineage.TemplateCount {
		return false
	}
	x := lineage.Templates[g.phase.Branch]
	a, ok := g.attempts[x.AttemptID]
	if !ok || x.Action != contract.GeneratorActionCreate || x.Branch == contract.GeneratorBranchInitial || a.record.State != contract.GeneratedEffectTransmitted ||
		a.record.Stage != contract.GeneratedStageRetainedResult || len(a.result) != 0 || g.phase.FrontierAttemptID != x.AttemptID ||
		subject.LineageID != x.LineageID || subject.AttemptID != x.AttemptID || subject.PredecessorAttemptID != x.PredecessorAttemptID ||
		subject.ResultID != x.ResultID || subject.ConfigContractID != x.ConfigContractID || subject.DescriptorID != x.DescriptorID ||
		subject.ResultContractID != x.ResultContractID {
		return false
	}
	row, ok := g.records[generatedRecordKey{kind: contract.GeneratedLineageSupportKind, id: x.LineageID}]
	if !ok {
		return false
	}
	installed, err := contract.InspectGeneratedLineageRecord(row.Body)
	if err != nil || installed.Branch != x.Branch || installed.Frontier != x.Branch {
		return false
	}
	var predecessor contract.GeneratorAttemptTemplate
	for _, candidate := range lineage.Templates[:lineage.TemplateCount] {
		if candidate.AttemptID == x.PredecessorAttemptID {
			predecessor = candidate
			break
		}
	}
	if predecessor.AttemptID.IsZero() {
		return false
	}
	guard, outcome := uint8(contract.GeneratorGuardResidue), uint8(contract.GeneratedEffectClosedWithResidue)
	if x.Branch == contract.GeneratorBranchNoEffect || x.Branch == contract.GeneratorBranchResidueThenNoEffect {
		guard, outcome = contract.GeneratorGuardQualifiedNoEffect, contract.GeneratedEffectConfirmedNoEffect
	}
	next, present, err := predecessor.SuccessorBranch(guard)
	if err != nil || !present || next != x.Branch {
		return false
	}
	prior, ok := g.attempts[predecessor.AttemptID]
	if !ok {
		return false
	}
	p := prior.record
	if p.State != outcome || p.Stage != contract.GeneratedStageTerminal || p.OperationID != a.record.OperationID ||
		p.LineageID != x.LineageID || p.RequestDigest != a.record.RequestDigest {
		return false
	}
	if guard == contract.GeneratorGuardResidue {
		hazardRow, present := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: predecessor.HazardID}]
		if !present {
			return false
		}
		hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
		if err != nil || hazard.Fenced != 1 || hazard.OriginalOperationID != p.OperationID || hazard.OriginalAttemptID != p.AttemptID {
			return false
		}
	}
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil || subject.ResultVector != contract.GeneratorDescriptor(empty) {
		return false
	}
	evidence, err := generatedSuccessorReservationEvidence(x)
	if err != nil {
		return false
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest, TransitionKind: subject.Purpose,
		BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: evidence})
	if err != nil || phase != subject.PhaseID {
		return false
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil || snapshot != s.root.Snapshot {
		return false
	}
	transition, err := contract.GeneratorPhaseTransitionID(phase)
	if err != nil || transition != s.root.Transition {
		return false
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil || revision != s.head.Core.Revision {
		return false
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: snapshot, Transition: transition, Revision: revision}
	for _, ref := range s.root.RequiredSupport {
		position := slices.Index(s.root.RequiredSupport, ref)
		if position >= 0 && position < len(s.support) {
			rows := make([]contract.SupportRecord, len(s.support[position].Records))
			for i, row := range s.support[position].Records {
				rows[i] = contract.SupportRecord(row)
			}
			if retained, ok := s.retainedOutputPage(rows); ok && retained.ref == ref {
				identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				continue
			}
		}
		id, err := contract.GeneratorPhasePageID(phase, contract.RequiredSupportKind, ref.Index)
		if err != nil || id != ref.Object {
			return false
		}
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	return err == nil && descriptor == subject.IdentityPlan
}
