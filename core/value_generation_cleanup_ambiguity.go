package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedCleanupAmbiguity struct {
	attempt   generatedAttempt
	source    contract.GeneratedDeleteSource
	target    contract.GeneratorTarget
	rows      []contract.SupportRecord
	locations []contract.GeneratorSliceLocation
	slices    contract.GeneratorDescriptor
}

func (g *generatedSelection) generatedOrdinaryCleanupAmbiguityOwner(owner contract.ID) bool {
	if g == nil || owner.IsZero() {
		return false
	}
	if row, ok := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: owner}]; ok {
		d, err := contract.InspectGeneratedDutyRecord(row.Body)
		return err == nil && d.Kind == contract.GeneratedDutyUnselectedCleanup
	}
	_, ok := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: owner}]
	return ok
}

func generatedOrdinaryCleanupSourceEligible(source contract.GeneratedDeleteSource) bool {
	return source.Record.Kind == contract.GeneratedDutySupportKind && source.Duty.Kind == contract.GeneratedDutyUnselectedCleanup &&
		source.Duty.Status == contract.GeneratedEffectSucceeded ||
		source.Record.Kind == contract.GeneratedHazardSupportKind && source.Hazard.Fenced == 1 && source.Hazard.Eligibility != 0 &&
			source.Hazard.Eligibility == source.Hazard.Exposure
}

func (g *generatedSelection) generatedOrdinaryCleanupAmbiguity(ctx context.Context, attemptID contract.ID, ambiguity []byte) (generatedCleanupAmbiguity, error) {
	var out generatedCleanupAmbiguity
	if g == nil || g.parent == nil || g.phase == nil || g.phase.FrontierAttemptID != attemptID ||
		len(g.bundles) == 0 || len(g.bundles[0].Lineages) != 1 || g.bundles[0].Lineages[0].Purpose != contract.GeneratorLineageCleanup {
		return out, contract.ErrRecord
	}
	a, ok := g.attempts[attemptID]
	if !ok || a.expected.Template.Action != contract.GeneratorActionDelete || !a.awaitingResult() || a.record.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) {
		return out, contract.ErrRecord
	}
	target, source, err := g.generatedDeleteAttemptTargetAndSource(ctx, g.bundles[0], a.record)
	if err != nil {
		return out, err
	}
	if !generatedOrdinaryCleanupSourceEligible(source) || source.CompletionClass != a.record.CompletionClass {
		return out, contract.ErrRecord
	}
	wantDuties, wantHazards := uint32(1), uint32(0)
	if source.Record.Kind == contract.GeneratedHazardSupportKind {
		wantDuties, wantHazards = 0, 1
	}
	if g.phase.Attempts.Count != 1 || g.phase.Duties.Count != wantDuties || g.phase.Hazards.Count != wantHazards {
		return out, contract.ErrRecord
	}
	facts, err := contract.InspectGeneratorSafeFacts(ambiguity)
	if err != nil || facts.Disposition != contract.GeneratorDispositionUnknown || facts.Reason == contract.GeneratorReasonIdentityConflict || !generatedFactsMatchTemplate(facts.GeneratorSafeFacts, a.expected.Template) ||
		facts.RequestDigest != a.record.RequestDigest || facts.IntentDigest != a.expected.Template.IntentDigest ||
		!generatedResourceFactsMatch(facts.GeneratorSafeFacts, target.ResourceDigest) || uint32(len(ambiguity)) > a.expected.Use.MaxFacts {
		return out, contract.ErrRecord
	}
	historyBodies, err := g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorHistory, source.History)
	if err != nil || len(historyBodies) == 0 {
		return out, contract.ErrRecord
	}
	prefix := 0
	if original, present := g.attempts[source.OriginalAttemptID]; present && original.expected.Template.Action == contract.GeneratorActionCreate {
		prefix = int(original.record.History.Count)
		if prefix >= len(historyBodies) {
			return out, contract.ErrRecord
		}
	}
	for i, body := range historyBodies {
		if i < prefix {
			continue
		}
		h, err := contract.InspectGeneratorHistory(body)
		prior, present := g.attempts[h.PredecessorAttemptID]
		if err != nil || !present || h.OwnerID != source.OwnerID || prior.expected.Template.Action != contract.GeneratorActionDelete {
			return out, contract.ErrRecord
		}
		if i == len(historyBodies)-1 {
			if h.PredecessorAttemptID != attemptID || h.Outcome != contract.GeneratedEffectTransmitted ||
				!h.ResultID.IsZero() || !h.ResultDigest.IsZero() || h.Edge != 0 || !h.NextAttemptID.IsZero() {
				return out, contract.ErrRecord
			}
			continue
		}
		contradiction, err := g.validateDeleteFacts(prior)
		if err != nil || contradiction || prior.record.Stage != contract.GeneratedStageTerminal {
			return out, contract.ErrRecord
		}
	}

	factBody, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: ambiguity})
	if err != nil {
		return out, err
	}
	var factRows []contract.SupportRecord
	a.record.Facts, factRows, err = generatedCarrierRows(a.record.DomainID, contract.GeneratedAttemptSupportKind, a.record.AttemptID,
		contract.GeneratorVectorFacts, [][]byte{factBody})
	if err != nil {
		return out, err
	}
	a.record.State, a.record.Stage = contract.GeneratedEffectUnknown, contract.GeneratedStageTerminal
	attemptHistoryBodies, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorHistory, a.record.History)
	if err != nil || len(attemptHistoryBodies) != 1 {
		return out, contract.ErrRecord
	}
	attemptHistory, err := contract.InspectGeneratorHistory(attemptHistoryBodies[0])
	if err != nil || attemptHistory.PredecessorAttemptID != a.record.AttemptID || attemptHistory.OwnerID != a.record.OwnerID ||
		attemptHistory.Outcome != contract.GeneratedEffectTransmitted || !attemptHistory.ResultID.IsZero() ||
		!attemptHistory.ResultDigest.IsZero() || attemptHistory.Edge != 0 || !attemptHistory.NextAttemptID.IsZero() {
		return out, contract.ErrRecord
	}
	attemptHistory.Outcome = contract.GeneratedEffectUnknown
	attemptHistoryBodies[0], err = contract.EncodeGeneratorHistory(attemptHistory)
	if err != nil {
		return out, err
	}
	var attemptHistoryRows []contract.SupportRecord
	a.record.History, attemptHistoryRows, err = generatedCarrierRows(a.record.DomainID, contract.GeneratedAttemptSupportKind, a.record.AttemptID,
		contract.GeneratorVectorHistory, attemptHistoryBodies)
	if err != nil {
		return out, err
	}
	history := attemptHistory
	historyBodies = slices.Clone(historyBodies)
	historyBodies[len(historyBodies)-1], err = contract.EncodeGeneratorHistory(history)
	if err != nil {
		return out, err
	}
	var sourceHistoryRows []contract.SupportRecord
	source.History, sourceHistoryRows, err = generatedCarrierRows(a.record.DomainID, source.Record.Kind, source.SourceID,
		contract.GeneratorVectorHistory, historyBodies)
	if err != nil {
		return out, err
	}
	if source.Record.Kind == contract.GeneratedDutySupportKind {
		source.Duty.History = source.History
		source.Record.Body, err = contract.EncodeGeneratedDutyRecord(source.Duty)
	} else {
		source.Hazard.History = source.History
		source.Record.Body, err = contract.EncodeGeneratedHazardRecord(source.Hazard)
	}
	if err != nil {
		return out, err
	}
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		return out, err
	}
	rows := make([]contract.SupportRecord, 0, len(g.records)+len(factRows)+len(attemptHistoryRows)+len(sourceHistoryRows))
	for _, row := range g.image.supportRecords() {
		if (row.Kind == contract.GeneratedParentSupportKind || row.Kind == contract.GeneratedPhaseSupportKind) && row.RecordID == g.parent.OperationID ||
			row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == a.record.AttemptID ||
			row.Kind == source.Record.Kind && row.RecordID == source.SourceID {
			continue
		}
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return out, err
			}
			if v.VectorKind == contract.GeneratorVectorSlices ||
				v.OwnerKind == contract.GeneratedParentSupportKind && v.OwnerID == g.parent.OperationID && v.VectorKind != contract.GeneratorVectorSupport ||
				v.OwnerKind == contract.GeneratedAttemptSupportKind && v.OwnerID == a.record.AttemptID && (v.VectorKind == contract.GeneratorVectorFacts || v.VectorKind == contract.GeneratorVectorHistory) ||
				v.OwnerKind == source.Record.Kind && v.OwnerID == source.SourceID && v.VectorKind == contract.GeneratorVectorHistory {
				continue
			}
		}
		rows = append(rows, row)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: a.record.AttemptID, Body: attemptBody}, source.Record)
	rows = append(rows, factRows...)
	rows = append(rows, attemptHistoryRows...)
	rows = append(rows, sourceHistoryRows...)
	rows, out.locations, out.slices, err = g.generatedCloseContent(rows)
	if err != nil {
		return out, err
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	a.result = nil
	out.attempt, out.source, out.target, out.rows = a, source, target, rows
	return out, nil
}

func generatedOrdinaryCleanupAmbiguityEvidence(domain contract.ID, change generatedCleanupAmbiguity) (contract.GeneratorDescriptor, error) {
	family := contract.GeneratorPhaseDuties
	if change.source.Record.Kind == contract.GeneratedHazardSupportKind {
		family = contract.GeneratorPhaseHazards
	}
	return contract.GeneratorRecordSetDescriptor(family, domain, []contract.SupportRecord{change.source.Record})
}

func (s *StateSession) generatedOrdinaryCleanupAmbiguityPlan(ctx context.Context, attemptID contract.ID, ambiguity []byte,
	admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	change, err := g.generatedOrdinaryCleanupAmbiguity(ctx, attemptID, ambiguity)
	if err != nil {
		return nil, err
	}
	evidence, err := generatedOrdinaryCleanupAmbiguityEvidence(s.root.Domain, change)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsForState(s, change.rows, change.locations, g.bundles)
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(s.root, len(s.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return nil, err
	}
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, len(packed), 0)
	if err != nil {
		return nil, err
	}
	return &generatedLifecyclePlan{kind: generatedLifecycleOrdinaryCleanupUnknown, context: admitted,
		owner: change.source.SourceID, target: change.target.ResourceDigest, evidence: evidence.Digest, requestIdentity: request,
		predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token,
		identity: identity, result: bytes.Clone(ambiguity), source: observationSource{ParentID: change.attempt.record.OperationID, AttemptID: change.attempt.record.AttemptID}}, nil
}

func (s *StateSession) deriveGeneratedOrdinaryCleanupAmbiguity(ctx context.Context, plan *generatedLifecyclePlan) (*generatedReservation, error) {
	if plan == nil || plan.kind != generatedLifecycleOrdinaryCleanupUnknown || len(plan.result) == 0 || contract.Hash(plan.result).IsZero() {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	change, err := g.generatedOrdinaryCleanupAmbiguity(ctx, g.phase.FrontierAttemptID, plan.result)
	if err != nil {
		return nil, err
	}
	if change.source.SourceID != plan.owner || change.target.ResourceDigest != plan.target {
		return nil, contract.ErrRecord
	}
	evidence, err := generatedOrdinaryCleanupAmbiguityEvidence(s.root.Domain, change)
	if err != nil || evidence.Digest != plan.evidence {
		return nil, contract.ErrRecord
	}
	groups, err := generatedReservationGroupsForState(s, change.rows, change.locations, g.bundles)
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(s.root, len(s.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return nil, err
	}
	if err := s.generatedLifecyclePlanValid(ctx, plan, len(packed), 0); err != nil {
		return nil, err
	}
	next, candidate, identity := s.beginGeneratedSuccessor(plan.identity)
	next.root.Generated.ActiveOwner, next.root.Generated.ActivePhase, next.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	next.root.Generated.Slices = change.slices
	if err := s.installGeneratedLifecycleSupport(ctx, &next, change.rows, change.locations, g.bundles, plan, candidate, &identity); err != nil {
		return nil, err
	}
	next.recountChildren()
	if !next.indexSelectedMaterials() || !validAggregate(next.root) {
		return nil, fmt.Errorf("validate ordinary-cleanup ambiguity successor: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("validate ordinary-cleanup ambiguity successor: %w", err)
	}
	head, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
	if err != nil {
		return nil, err
	}
	subject, err := s.generatedOrdinaryCleanupAmbiguitySubject(ctx, &next, g, plan, change, identity, head)
	if err != nil {
		return nil, err
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, fmt.Errorf("validate ordinary-cleanup ambiguity authority: %w", err)
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedOrdinaryCleanupAmbiguitySubject(ctx context.Context, next *StateSession, before *generatedSelection,
	plan *generatedLifecyclePlan, change generatedCleanupAmbiguity, identity contract.IdentityPlan,
	head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	bundle, err := before.retainedGraph(change.attempt.record.OperationID)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	evidence, err := generatedOrdinaryCleanupAmbiguityEvidence(s.root.Domain, change)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: plan.requestIdentity, ObservedHEADDigest: plan.predecessorDigest,
		ConditionDigest: plan.context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityRecord,
		BeforePhase: 1, AfterPhase: 2, Evidence: evidence}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	x := change.attempt.expected.Template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityRecord,
		DomainID: s.root.Domain, OperationID: plan.identity.operation, RequestIdentityDigest: plan.requestIdentity,
		PlanGraphID: bundle.UsePlan.PlanGraphID, UsePlanDigest: usePlan, PhaseID: phaseID,
		PreviousHEADDigest: plan.predecessorDigest, PreviousRevisionID: plan.predecessorRevision,
		ConditionDigest: plan.context.OriginalConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: change.source.SourceID, LineageID: x.LineageID, AttemptID: x.AttemptID,
		PredecessorAttemptID: x.PredecessorAttemptID, ResultID: x.ResultID, ResultDigest: contract.Hash(plan.result),
		ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
		Intent: bundle.Request.Declaration, CapacityReservation: change.source.CapacityReservation, BeforePhase: 1, AfterPhase: 2}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		return subject, err
	}
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, s.generatedUnchangedEntryUnion())
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

func (s *selectedGeneratedProof) validateGeneratedOrdinaryCleanupAmbiguitySelection(ctx context.Context, g *generatedSelection,
	subject contract.GeneratorAuthoritySubject) error {
	if g == nil || g.parent != nil || g.phase != nil || subject.Purpose != contract.GeneratorAuthorityRecord ||
		subject.BeforePhase != 1 || subject.AfterPhase != 2 || subject.ResultDigest.IsZero() ||
		subject.BeforeAccessDigest != subject.AfterAccessDigest || subject.AfterAccessDigest != s.root.CurrentAccess.AccessRoot {
		return contract.ErrRecord
	}
	row, present := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: subject.OwnerID}]
	if !present {
		row, present = g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: subject.OwnerID}]
	}
	if !present {
		return contract.ErrRecord
	}
	source, err := contract.InspectGeneratedDeleteSource(row)
	if err != nil || source.SourceID != subject.OwnerID || !generatedOrdinaryCleanupSourceEligible(source) ||
		source.CapacityReservation != subject.CapacityReservation {
		return contract.ErrRecord
	}
	a, ok := g.attempts[subject.AttemptID]
	if !ok || a.record.State != contract.GeneratedEffectUnknown || a.record.Stage != contract.GeneratedStageTerminal || len(a.result) != 0 ||
		a.record.OwnerID != source.OwnerID || a.record.LineageID != subject.LineageID ||
		a.record.PredecessorAttemptID != subject.PredecessorAttemptID || a.record.ResultID != subject.ResultID ||
		a.record.ConfigContractID != subject.ConfigContractID || a.record.DescriptorID != subject.DescriptorID ||
		a.record.ResultContractID != subject.ResultContractID || a.record.CompletionClass != source.CompletionClass {
		return contract.ErrRecord
	}
	bundle, err := g.retainedGraph(a.record.OperationID)
	if err != nil {
		return contract.ErrRecord
	}
	target, exact, err := g.generatedDeleteAttemptTargetAndSource(ctx, bundle, a.record)
	if err != nil {
		return err
	}
	if exact.SourceID != source.SourceID || target.ResourceDigest.IsZero() {
		return contract.ErrRecord
	}
	factRows, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, a.record.Facts)
	if err != nil || len(factRows) != 1 {
		return contract.ErrRecord
	}
	fact, err := contract.InspectGeneratorFactsRow(factRows[0])
	if err != nil || fact.ResultID != a.record.ResultID || contract.Hash(fact.Facts) != subject.ResultDigest {
		return contract.ErrRecord
	}
	facts, err := contract.InspectGeneratorSafeFacts(fact.Facts)
	if err != nil || facts.Disposition != contract.GeneratorDispositionUnknown || facts.Reason == contract.GeneratorReasonIdentityConflict || !generatedFactsMatchTemplate(facts.GeneratorSafeFacts, a.expected.Template) ||
		facts.RequestDigest != a.record.RequestDigest || facts.IntentDigest != a.expected.Template.IntentDigest ||
		!generatedResourceFactsMatch(facts.GeneratorSafeFacts, target.ResourceDigest) {
		return contract.ErrRecord
	}
	history, err := g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorHistory, source.History)
	if err != nil || len(history) == 0 {
		return contract.ErrRecord
	}
	prefix := 0
	if original, present := g.attempts[source.OriginalAttemptID]; present && original.expected.Template.Action == contract.GeneratorActionCreate {
		prefix = int(original.record.History.Count)
		if prefix >= len(history) {
			return contract.ErrRecord
		}
	}
	for i, body := range history {
		if i < prefix {
			continue
		}
		h, err := contract.InspectGeneratorHistory(body)
		attempt, present := g.attempts[h.PredecessorAttemptID]
		if err != nil || !present || h.OwnerID != source.OwnerID || attempt.expected.Template.Action != contract.GeneratorActionDelete {
			return contract.ErrRecord
		}
		contradiction, err := g.validateDeleteFacts(attempt)
		if err != nil || contradiction {
			return contract.ErrRecord
		}
	}
	if bundle.Request.Declaration != subject.Intent || bundle.UsePlan.PlanGraphID != subject.PlanGraphID {
		return contract.ErrRecord
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil || usePlan != subject.UsePlanDigest {
		return contract.ErrRecord
	}
	evidence, err := contract.GeneratorRecordSetDescriptor(map[uint8]contract.GeneratorRecordSetKind{
		contract.GeneratedDutySupportKind:   contract.GeneratorPhaseDuties,
		contract.GeneratedHazardSupportKind: contract.GeneratorPhaseHazards,
	}[source.Record.Kind], s.root.Domain, []contract.SupportRecord{source.Record})
	if err != nil {
		return contract.ErrRecord
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest,
		TransitionKind: subject.Purpose, BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: evidence})
	if err != nil || phase != subject.PhaseID {
		return contract.ErrRecord
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: s.root.Snapshot,
		Transition: s.root.Transition, Revision: s.head.Core.Revision}
	for _, ref := range s.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil || descriptor != subject.IdentityPlan {
		return contract.ErrRecord
	}
	entryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, s.generatedUnchangedEntryUnion())
	if err != nil || entryUnion != subject.ValueEntryUnion {
		return contract.ErrRecord
	}
	membership := s.generatedUnchangedEntryUnion()
	for i := range membership {
		membership[i].After.EntryDigest = contract.ID{}
	}
	planned, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membership)
	if err != nil || planned != subject.MembershipChanges || generatedMembershipAuthority(membership) != subject.RequiredAuthoritySet {
		return contract.ErrRecord
	}
	empty, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil || subject.ResultVector != contract.GeneratorDescriptor(empty) {
		return contract.ErrRecord
	}
	return nil
}
