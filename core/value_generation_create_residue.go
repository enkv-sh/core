package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedCreateResiduePlan struct {
	context contract.ApplyContext
	source  observationSource
	phase   contract.GeneratorPhaseIdentity
	attempt contract.ID
}

type admittedGeneratedCreateResidue struct {
	observation *operationObservation
	session     *StateSession
	plan        *generatedCreateResiduePlan
	used        bool
}

type generatedCreateResidueChange struct {
	attempt      contract.GeneratedAttemptRecord
	hazard       contract.GeneratedHazardRecord
	hazardBody   []byte
	replacement  []contract.SupportRecord
	next         contract.GeneratorAttemptTemplate
	hasSuccessor bool
	noEffectUsed uint8
	residueUsed  uint8
}

// generatedCreateResidueRequest fixes one fresh automatic residue fence. The
// transition preserves the exact original coordinate and can install only the
// graph's next residue successor. It grants no provider dispatch permission.
func (s *StateSession) generatedCreateResidueRequest(ctx context.Context, attempt contract.ID, admitted contract.ApplyContext) (*generatedCreateResiduePlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if g.parent == nil || g.phase == nil || g.phase.FrontierAttemptID != attempt {
		return nil, contract.ErrRecord
	}
	change, err := generatedCreateResidueRows(g)
	if err != nil {
		return nil, err
	}
	evidence, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseHazards, g.parent.DomainID,
		[]contract.SupportRecord{{Kind: contract.GeneratedHazardSupportKind, RecordID: change.hazard.HazardID, Body: change.hazardBody}})
	if err != nil {
		return nil, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: g.parent.RequestIdentityDigest,
		ObservedHEADDigest: admitted.PredecessorHEADDigest, ConditionDigest: admitted.OriginalConditionDigest,
		TransitionKind: contract.GeneratorAuthorityResidue, BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1,
		Evidence: evidence}
	if _, err := contract.GeneratorPhaseID(phase); err != nil {
		return nil, err
	}
	return &generatedCreateResiduePlan{context: admitted, phase: phase, attempt: attempt, source: observationSource{ParentID: g.parent.OperationID}}, nil
}

func generatedCreateResidueRows(g *generatedSelection) (generatedCreateResidueChange, error) {
	var out generatedCreateResidueChange
	if g == nil || g.parent == nil || g.phase == nil || int(g.phase.LineageIndex) >= len(g.bundles[0].Lineages) {
		return out, contract.ErrRecord
	}
	selected, ok := g.attempts[g.phase.FrontierAttemptID]
	if !ok || selected.expected.Template.Action != contract.GeneratorActionCreate || !selected.awaitingResult() {
		return out, contract.ErrRecord
	}
	dutyRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: selected.record.OwnerID}]
	if !ok {
		return out, contract.ErrRecord
	}
	duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
	if err != nil || duty.Kind != contract.GeneratedDutyCreate || duty.Status != contract.GeneratedEffectTransmitted {
		return out, contract.ErrRecord
	}
	historyBodies, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, selected.record.AttemptID, contract.GeneratorVectorHistory, selected.record.History)
	if err != nil {
		return out, err
	}
	if len(historyBodies) == 0 {
		historyBodies = [][]byte{nil}
	} else {
		historyBodies = slices.Clone(historyBodies)
	}
	history := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: selected.record.AttemptID,
		OwnerID: selected.record.OwnerID, Outcome: contract.GeneratedEffectClosedWithResidue}
	if historyBodies[len(historyBodies)-1] != nil {
		history, err = contract.InspectGeneratorHistory(historyBodies[len(historyBodies)-1])
		if err != nil || history.PredecessorAttemptID != selected.record.AttemptID || !history.NextAttemptID.IsZero() ||
			history.OwnerID != selected.record.OwnerID || !history.ResultID.IsZero() || !history.ResultDigest.IsZero() {
			return out, contract.ErrRecord
		}
		history.Outcome = contract.GeneratedEffectClosedWithResidue
	}
	historyBodies[len(historyBodies)-1], err = contract.EncodeGeneratorHistory(history)
	if err != nil {
		return out, err
	}
	attemptHistory, attemptCarriers, err := generatedCarrierRows(g.parent.DomainID, contract.GeneratedAttemptSupportKind, selected.record.AttemptID,
		contract.GeneratorVectorHistory, historyBodies)
	if err != nil {
		return out, err
	}
	consumers, err := g.vectors.resolve(contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorConsumers, duty.Consumers)
	if err != nil {
		return out, err
	}
	var late [][]byte
	lateCount := 0
	for _, body := range consumers {
		consumer, err := contract.InspectGeneratorConsumer(body)
		if err != nil {
			return out, err
		}
		if consumer.Purpose == contract.GeneratorConsumerDeriveSelectedResult {
			continue
		}
		if consumer.Purpose != contract.GeneratorConsumerAdoptLateOriginalResult && consumer.Purpose != contract.GeneratorConsumerUseRetainedCanonical {
			return out, contract.ErrRecord
		}
		if consumer.Purpose == contract.GeneratorConsumerAdoptLateOriginalResult {
			lateCount++
		}
		consumer.OwnerID = selected.expected.Template.HazardID
		body, err = contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			return out, err
		}
		late = append(late, body)
	}
	if lateCount != 1 {
		return out, contract.ErrRecord
	}
	slices.SortFunc(late, bytes.Compare)
	hazardConsumers, consumerCarriers, err := generatedCarrierRows(g.parent.DomainID, contract.GeneratedHazardSupportKind, selected.expected.Template.HazardID,
		contract.GeneratorVectorConsumers, late)
	if err != nil {
		return out, err
	}
	hazardHistory, hazardHistoryCarriers, err := generatedCarrierRows(g.parent.DomainID, contract.GeneratedHazardSupportKind, selected.expected.Template.HazardID,
		contract.GeneratorVectorHistory, historyBodies)
	if err != nil {
		return out, err
	}
	selected.record.State, selected.record.Stage = contract.GeneratedEffectClosedWithResidue, contract.GeneratedStageTerminal
	selected.record.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
	selected.record.History = attemptHistory
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(selected.record)
	if err != nil {
		return out, err
	}
	empty := contract.EmptyGeneratorVector
	hazard := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: duty.DomainID, HazardID: selected.expected.Template.HazardID,
		OriginalOperationID: duty.OriginalOperationID, OriginalAttemptID: duty.OriginalAttemptID, OwnerID: duty.OwnerID,
		ResourceID: duty.ResourceID, ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID, ExecutorID: duty.ExecutorID,
		CredentialRouteID: duty.CredentialRouteID, DescriptorID: duty.DescriptorID, ResultContractID: duty.ResultContractID,
		Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: duty.CompletionClass, Fenced: 1,
		CapacityReservation: duty.CapacityReservation,
		OriginalResults:     contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults), Target: empty(contract.GeneratorVectorTargets),
		History: hazardHistory, Support: duty.Support, Consumers: hazardConsumers}
	hazardBody, err := contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		return out, err
	}
	replacement := []contract.SupportRecord{{Kind: contract.GeneratedAttemptSupportKind, RecordID: selected.record.AttemptID, Body: attemptBody},
		{Kind: contract.GeneratedHazardSupportKind, RecordID: hazard.HazardID, Body: hazardBody}}
	replacement = append(replacement, attemptCarriers...)
	replacement = append(replacement, consumerCarriers...)
	replacement = append(replacement, hazardHistoryCarriers...)

	x := selected.expected.Template
	nextBranch, present, err := x.SuccessorBranch(contract.GeneratorGuardResidue)
	if err != nil {
		return out, err
	}
	lineage := g.bundles[0].Lineages[g.phase.LineageIndex]
	if lineage.LineageID != x.LineageID {
		return out, contract.ErrRecord
	}
	if present {
		if int(nextBranch) >= int(lineage.TemplateCount) {
			return out, contract.ErrRecord
		}
		next := lineage.Templates[nextBranch]
		_, _, ok := generatedTemplate(g.bundles[0], next.AttemptID)
		if !ok || next.PredecessorAttemptID != x.AttemptID {
			return out, contract.ErrRecord
		}
		out.next, out.hasSuccessor = next, true
	}
	out.attempt, out.hazard, out.hazardBody, out.replacement = selected.record, hazard, hazardBody, replacement
	out.noEffectUsed, out.residueUsed = g.phase.NoEffectUsed, g.phase.ResidueUsed
	if out.hasSuccessor {
		out.residueUsed = 1
	}
	if x.Branch == contract.GeneratorBranchNoEffect || x.Branch >= contract.GeneratorBranchNoEffectThenResidue {
		out.noEffectUsed = 1
	}
	return out, nil
}

func (s *StateSession) deriveGeneratedCreateResidue(ctx context.Context, plan *generatedCreateResiduePlan) (*generatedReservation, error) {
	if plan == nil {
		return nil, contract.ErrRecord
	}
	checked, err := s.generatedCreateResidueRequest(ctx, plan.attempt, plan.context)
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
	phaseID, err := contract.GeneratorPhaseID(plan.phase)
	if err != nil {
		return nil, err
	}
	change, err := generatedCreateResidueRows(g)
	if err != nil {
		return nil, err
	}
	removeDuty := change.attempt.OwnerID
	rows := make([]contract.SupportRecord, 0, len(g.records)+len(change.replacement))
	for _, row := range s.supportRecords() {
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == change.attempt.AttemptID || row.Kind == contract.GeneratedDutySupportKind && row.RecordID == removeDuty {
			continue
		}
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			if carrier.OwnerKind == contract.GeneratedDutySupportKind && carrier.OwnerID == removeDuty ||
				carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == change.attempt.AttemptID && carrier.VectorKind == contract.GeneratorVectorHistory {
				continue
			}
		}
		rows = append(rows, row)
	}
	rows = append(rows, change.replacement...)
	lineageRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedLineageSupportKind, id: change.attempt.LineageID}]
	if !ok {
		return nil, contract.ErrRecord
	}
	lineage, err := contract.DecodeGeneratedLineageRecord(lineageRow.Body)
	if err != nil || lineage.Branch != g.phase.Branch || lineage.Frontier != g.phase.Branch {
		return nil, contract.ErrRecord
	}
	phase := *g.phase
	phase.PhaseID, phase.Phase, phase.AcceptedResultID, phase.ResultDigest = phaseID, plan.phase.AfterPhase, contract.ID{}, contract.ID{}
	phase.Hazards = contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards)
	if change.hasSuccessor {
		lineage.Branch = change.next.Branch
		phase.FrontierAttemptID, phase.Branch, phase.Stage = change.next.AttemptID, change.next.Branch, contract.GeneratedStageRetainedResult
	} else {
		lineage.Branch, lineage.Frontier = g.phase.Branch, g.phase.Branch
		phase.Stage = contract.GeneratedStageTerminal
		if index, next, present := generatedNextOriginalAfter(g, change.attempt.LineageID); present {
			pending, entered := g.attempts[next.AttemptID]
			if !entered || !pending.awaitingResult() {
				return nil, contract.ErrRecord
			}
			phase.LineageIndex, phase.FrontierAttemptID, phase.Branch, phase.Stage = index, next.AttemptID, contract.GeneratorBranchInitial, contract.GeneratedStageRetainedResult
		}
	}
	lineage.NoEffectUsed, lineage.ResidueUsed = change.noEffectUsed, change.residueUsed
	phase.NoEffectUsed, phase.ResidueUsed = change.noEffectUsed, change.residueUsed
	if phase.LineageIndex != g.phase.LineageIndex {
		phase.NoEffectUsed, phase.ResidueUsed = 0, 0
	}
	lineageBody, err := contract.EncodeGeneratedLineageRecord(lineage)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == contract.GeneratedLineageSupportKind && rows[i].RecordID == lineage.LineageID {
			rows[i].Body = lineageBody
		}
	}
	for _, set := range []struct {
		kind       uint8
		family     contract.GeneratorRecordSetKind
		descriptor *contract.GeneratorDescriptor
	}{
		{contract.GeneratedResultSupportKind, contract.GeneratorPhaseResults, &phase.AcceptedResults},
		{contract.GeneratedAttemptSupportKind, contract.GeneratorPhaseAttempts, &phase.Attempts},
		{contract.GeneratedDutySupportKind, contract.GeneratorPhaseDuties, &phase.Duties},
		{contract.GeneratedHazardSupportKind, contract.GeneratorPhaseHazards, &phase.Hazards},
	} {
		var selected []contract.SupportRecord
		for _, row := range rows {
			if row.Kind == set.kind && g.activePhaseOwns(row) {
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
	reservation, err := s.deriveGeneratedCreateRecoveryCandidate(ctx, g, plan, change, phaseID, rows)
	if reservation != nil {
		reservation.candidate.observationSource = checked.source
	}
	return reservation, err
}

func (s *StateSession) deriveGeneratedCreateRecoveryCandidate(ctx context.Context, g *generatedSelection, plan *generatedCreateResiduePlan,
	change generatedCreateResidueChange, phaseID contract.ID, rows []contract.SupportRecord) (*generatedReservation, error) {
	snapshot, err := contract.GeneratorPhaseSnapshotID(phaseID)
	if err != nil {
		return nil, err
	}
	transition, err := contract.GeneratorPhaseTransitionID(phaseID)
	if err != nil {
		return nil, err
	}
	revision, err := contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		return nil, err
	}
	next, candidate, identity := s.beginGeneratedSuccessor(transitionPlan{operation: g.parent.OperationID,
		transition: transition, snapshot: snapshot, revision: revision})
	rows, err = rebindSnapshotSliceRecords(rows, s.root.Domain, s.adminIndex.SliceSnapshot, next.root.Snapshot)
	if err != nil {
		return nil, err
	}
	locations, err := s.resolveSelectedGeneratedSlices()
	if err != nil {
		return nil, err
	}
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
	if err := s.installGeneratedSuccessorSupport(ctx, &next, packed, pageIDs, candidate, &identity); err != nil {
		return nil, err
	}
	next.recountChildren()
	if !next.indexSelectedMaterials() {
		return nil, fmt.Errorf("index residue materials: %w", contract.ErrRecord)
	}
	if !validAggregate(next.root) {
		return nil, fmt.Errorf("residue aggregate: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("relate residue successor: %w", err)
	}
	head, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
	if err != nil {
		return nil, err
	}
	subject, err := s.generatedCreateResidueSubject(ctx, &next, g, plan, change, identity, head)
	if err != nil {
		return nil, err
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, fmt.Errorf("authenticate residue successor: %w", err)
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedCreateResidueSubject(ctx context.Context, next *StateSession, g *generatedSelection, plan *generatedCreateResiduePlan,
	change generatedCreateResidueChange, identity contract.IdentityPlan, head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	p, x := *g.parent, change.attempt
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityResidue,
		DomainID: p.DomainID, OperationID: p.OperationID, RequestIdentityDigest: p.RequestIdentityDigest,
		PlanGraphID: p.PlanGraphID, UsePlanDigest: p.UsePlanDigest, PhaseID: next.root.Generated.ActivePhase,
		PreviousHEADDigest: contract.Hash(s.body), PreviousRevisionID: s.head.Core.Revision, ConditionDigest: plan.phase.ConditionDigest,
		BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: p.OperationID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: x.ResultID, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
		Intent: p.Declaration, CapacityReservation: p.Capacity, BeforePhase: plan.phase.BeforePhase, AfterPhase: plan.phase.AfterPhase}
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

// PrepareGeneratedCreateResidue binds the exact automatic fence to fresh K2
// authority. It has no Crypto or provider action and cannot grant first send.
func (s *StateSession) prepareGeneratedCreateResidue(ctx context.Context, permit *admittedGeneratedCreateResidue,
	trust contract.Trust) (*Candidate, Result) {
	if s == nil || ctx == nil || s.prepared || !s.admission.valid(s.store) || permit == nil || permit.used || permit.session != s || permit.plan == nil || trust == nil ||
		!validPrivateDeadline(time.Unix(0, int64(permit.plan.context.Expiry))) {
		return nil, refused(AdmissionInvalid)
	}
	permit.used = true
	if ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	reservation, err := s.deriveGeneratedCreateResidue(ctx, permit.plan)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, refused(InvalidRelation)
	}
	authority, err := contract.GeneratorAuthorityDigest(*reservation.candidate.head.Generator)
	if err != nil {
		return nil, refused(InvalidProof)
	}
	source := exchangeSource(permit.plan.context)
	source.OperationID, source.PhaseID, source.AttemptID = reservation.candidate.head.Generator.OperationID, reservation.candidate.head.Generator.PhaseID, permit.plan.attempt
	source.ParentID = reservation.candidate.observationSource.ParentID

	reservation.candidate.bindObservation(permit.observation, source)
	reservation.candidate.generated = &generatedCandidateFacts{reservation: reservation, authority: authority, claimed: true}
	s.prepared = true
	return s.persistCandidate(ctx, reservation.candidate, trust)
}
