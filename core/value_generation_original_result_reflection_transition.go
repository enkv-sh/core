package core

import (
	"bytes"
	"context"
	"fmt"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) generatedReflectionPlan(ctx context.Context, resultID contract.ID, result []byte, admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || resultID.IsZero() || len(result) == 0 || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, fmt.Errorf("select reflection work: %w", err)
	}
	selection, ok, err := g.selectGeneratedCleanup(ctx, map[contract.ID][]byte{resultID: result})
	if err != nil {
		return nil, err
	}
	if !ok || selection.kind != generatedCleanupReflection {
		return nil, contract.ErrRecord
	}
	var rows []contract.SupportRecord
	var target contract.ID
	var closeLocations []contract.GeneratorSliceLocation
	kind := generatedLifecycleReflection
	accessPages := 0
	if selection.closeOwner {
		change, err := g.generatedReflectOriginalClosure(ctx, selection, s.head.Core.Revision)
		if err != nil {
			return nil, fmt.Errorf("reflect original closure: %w", err)
		}
		rows, target, kind = change.rows, change.target.ResourceDigest, generatedLifecycleCleanupClose
		closeLocations = change.locations
		accessRows, err := s.generatedDeleteLifecycleAccess(change)
		if err != nil {
			return nil, err
		}
		accessPages, err = generatedLifecycleAccessPageCount(accessRows)
		if err != nil {
			return nil, err
		}
	} else {
		var change generatedReflection
		if selection.attempt.expected.Template.Action == contract.GeneratorActionDelete {
			change, err = g.generatedReflectLateNonfinalDelete(ctx, selection)
		} else {
			change, err = g.generatedReflectLateCreate(selection)
		}
		if err != nil {
			return nil, err
		}
		rows, target = change.rows, change.target.ResourceDigest
	}
	locations, err := s.resolveSelectedGeneratedSlices()
	if err != nil {
		return nil, err
	}
	if selection.closeOwner {
		locations = closeLocations
	}
	groups, err := generatedReservationGroupsForState(s, rows, locations, g.bundles)
	if err != nil {
		return nil, err
	}
	otherAccessPages := len(s.root.CurrentAccess.Core.AccessPageRefs)
	if selection.closeOwner {
		otherAccessPages = accessPages
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, generatedNonSupportChildCount(s.root, otherAccessPages), fragments)
	if err != nil {
		return nil, err
	}
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, len(packed), accessPages)
	if err != nil {
		return nil, err
	}
	return &generatedLifecyclePlan{kind: kind, context: admitted, owner: selection.sourceKey().id,
		target: target, evidence: contract.Hash(result), requestIdentity: request,
		predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision,
		predecessorToken: s.token, identity: identity, result: bytes.Clone(result)}, nil
}

func (s *StateSession) deriveGeneratedReflection(ctx context.Context, plan *generatedLifecyclePlan) (*generatedReservation, error) {
	if plan == nil || plan.kind != generatedLifecycleReflection || len(plan.result) == 0 || contract.Hash(plan.result) != plan.evidence {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	result, err := contract.InspectGeneratedResultRecord(plan.result)
	if err != nil {
		return nil, err
	}
	selection, ok, err := g.selectGeneratedCleanup(ctx, map[contract.ID][]byte{result.Core.ResultID: plan.result})
	if err != nil {
		return nil, err
	}
	if !ok || selection.kind != generatedCleanupReflection || selection.closeOwner || selection.sourceKey().id != plan.owner {
		return nil, contract.ErrRecord
	}
	var change generatedReflection
	if selection.attempt.expected.Template.Action == contract.GeneratorActionDelete {
		change, err = g.generatedReflectLateNonfinalDelete(ctx, selection)
	} else {
		change, err = g.generatedReflectLateCreate(selection)
	}
	if err != nil || change.target.ResourceDigest != plan.target {
		return nil, contract.ErrRecord
	}
	locations, err := s.resolveSelectedGeneratedSlices()
	if err != nil {
		return nil, err
	}
	rows, err := rebindSnapshotSliceRecords(change.rows, s.root.Domain, s.adminIndex.SliceSnapshot, plan.identity.snapshot)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsForState(s, rows, locations, g.bundles)
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
	next.root.RequiredSupport, next.support = nil, nil
	next.recountChildren()
	generatedRefreshClosureCounts(&next.root.Generated, rows)
	supportPageCount := min(len(packed), len(plan.identity.supportPages))
	if err := s.installGeneratedSuccessorSupport(ctx, &next, packed, plan.identity.supportPages[:supportPageCount], candidate, &identity); err != nil {
		return nil, err
	}
	next.recountChildren()
	if !next.indexSelectedMaterials() || !validAggregate(next.root) {
		return nil, contract.ErrRecord
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, err
	}
	head, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
	if err != nil {
		return nil, err
	}
	subject, err := s.generatedReflectionSubject(ctx, &next, g, plan, change, identity, head)
	if err != nil {
		return nil, err
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, err
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedReflectionSubject(ctx context.Context, next *StateSession, before *generatedSelection, plan *generatedLifecyclePlan,
	change generatedReflection, identity contract.IdentityPlan, head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	bundle, err := before.retainedGraph(change.attempt.record.OperationID)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: change.attempt.record.ResultID,
		ResultBodyDigest: contract.Hash(plan.result), ResultLength: uint32(len(plan.result))}
	evidence, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{reference})
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: plan.requestIdentity, ObservedHEADDigest: plan.predecessorDigest,
		ConditionDigest: plan.context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityReflection,
		BeforePhase: 1, AfterPhase: 2, Evidence: contract.GeneratorDescriptor(evidence)}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	x := change.attempt.expected.Template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityReflection,
		DomainID: s.root.Domain, OperationID: plan.identity.operation, RequestIdentityDigest: plan.requestIdentity,
		PlanGraphID: bundle.UsePlan.PlanGraphID, UsePlanDigest: usePlan, PhaseID: phaseID,
		PreviousHEADDigest: plan.predecessorDigest, PreviousRevisionID: plan.predecessorRevision,
		ConditionDigest: plan.context.OriginalConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: change.source.SourceID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: x.ResultID, ResultDigest: contract.Hash(plan.result), ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID,
		ResultContractID: x.ResultContractID, Intent: bundle.Request.Declaration, CapacityReservation: change.source.CapacityReservation,
		BeforePhase: 1, AfterPhase: 2, ResultVector: contract.GeneratorDescriptor(evidence)}
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

func (s *selectedGeneratedProof) validGeneratedReflectionSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	if g == nil || g.parent != nil || g.phase != nil || subject.Purpose != contract.GeneratorAuthorityReflection ||
		subject.BeforePhase != 1 || subject.AfterPhase != 2 || subject.BeforeAccessDigest != subject.AfterAccessDigest ||
		subject.AfterAccessDigest != s.root.CurrentAccess.AccessRoot || subject.ResultDigest.IsZero() {
		return false
	}
	row, ok := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: subject.OwnerID}]
	if !ok {
		row, ok = g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: subject.OwnerID}]
	}
	if !ok {
		return false
	}
	owner, err := contract.InspectGeneratedDeleteSource(row)
	if err != nil || owner.CapacityReservation != subject.CapacityReservation ||
		owner.Record.Kind == contract.GeneratedHazardSupportKind && owner.Hazard.Fenced != 1 {
		return false
	}
	hazard := owner.Hazard
	a, ok := g.attempts[subject.AttemptID]
	if !ok || len(a.result) == 0 || contract.Hash(a.result) != subject.ResultDigest ||
		a.record.Stage != contract.GeneratedStageTerminal || a.record.ResultID != subject.ResultID {
		return false
	}
	x := a.expected.Template
	if subject.LineageID != x.LineageID || subject.PredecessorAttemptID != x.PredecessorAttemptID ||
		subject.ResultID != x.ResultID || subject.ConfigContractID != x.ConfigContractID || subject.DescriptorID != x.DescriptorID ||
		subject.ResultContractID != x.ResultContractID {
		return false
	}
	switch x.Action {
	case contract.GeneratorActionCreate:
		if owner.Record.Kind != contract.GeneratedHazardSupportKind || hazard.Exposure != contract.GeneratedExposureLateEffect || hazard.Eligibility != contract.GeneratedExposureLateEffect ||
			hazard.OriginalAttemptID != subject.AttemptID || a.record.State != contract.GeneratedEffectClosedWithResidue {
			return false
		}
	case contract.GeneratorActionDelete:
		if owner.CompletionClass != contract.GeneratedCompletionConfirmed {
			return false
		}
		if owner.Record.Kind == contract.GeneratedHazardSupportKind && hazard.Exposure == contract.GeneratedExposurePossibleLive {
			if hazard.Eligibility != contract.GeneratedExposurePossibleLive || g.deleteHazards[a.record.AttemptID] != hazard.HazardID ||
				a.record.State != contract.GeneratedEffectUnknown && a.record.State != contract.GeneratedEffectClosedWithResidue {
				return false
			}
		} else if owner.OwnerID != a.record.OwnerID || a.record.State != contract.GeneratedEffectSucceeded ||
			owner.Record.Kind == contract.GeneratedDutySupportKind && (owner.Duty.Kind != contract.GeneratedDutyUnselectedCleanup || owner.Duty.Status != contract.GeneratedEffectSucceeded) ||
			owner.Record.Kind == contract.GeneratedHazardSupportKind && (hazard.Exposure != contract.GeneratedExposureLateEffect || hazard.Eligibility != contract.GeneratedExposureLateEffect) {
			return false
		}
		result, err := contract.InspectGeneratedResultRecord(a.result)
		if err != nil || result.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged {
			return false
		}
	default:
		return false
	}
	bundle, err := g.retainedGraph(a.record.OperationID)
	if err != nil || bundle.Request.Declaration != subject.Intent || bundle.UsePlan.PlanGraphID != subject.PlanGraphID {
		return false
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil || usePlan != subject.UsePlanDigest {
		return false
	}
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID,
		ResultBodyDigest: contract.Hash(a.result), ResultLength: uint32(len(a.result))}
	evidence, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{reference})
	if err != nil || subject.ResultVector != contract.GeneratorDescriptor(evidence) {
		return false
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest,
		TransitionKind: subject.Purpose, BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase,
		Evidence: contract.GeneratorDescriptor(evidence)})
	if err != nil || phase != subject.PhaseID {
		return false
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: s.root.Snapshot,
		Transition: s.root.Transition, Revision: s.head.Core.Revision}
	for _, ref := range s.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil || descriptor != subject.IdentityPlan {
		return false
	}
	entryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, s.generatedUnchangedEntryUnion())
	if err != nil || entryUnion != subject.ValueEntryUnion {
		return false
	}
	membership := s.generatedUnchangedEntryUnion()
	for i := range membership {
		membership[i].After.EntryDigest = contract.ID{}
	}
	planned, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membership)
	return err == nil && planned == subject.MembershipChanges && generatedMembershipAuthority(membership) == subject.RequiredAuthoritySet
}
