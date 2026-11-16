package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedLifecycleAccessRows(rows []contract.AccessRecord, materials ...contract.ID) []contract.AccessRecord {
	out := make([]contract.AccessRecord, 0, len(rows))
	for _, row := range rows {
		if row.MaterialKind == contract.OperationSeedMaterialKind && slices.Contains(materials, row.MaterialID) {
			continue
		}
		out = append(out, row)
	}
	return out
}

func generatedDeleteLifecycleAccessRows(rows []contract.AccessRecord, change generatedDeleteReflection) []contract.AccessRecord {
	out := generatedLifecycleAccessRows(rows, change.materials...)
	return slices.DeleteFunc(out, func(row contract.AccessRecord) bool {
		return row.MaterialKind == contract.ValueMaterialKind && slices.Contains(change.values, row.MaterialID)
	})
}

func (s *StateSession) generatedDeleteLifecycleAccess(change generatedDeleteReflection) ([]contract.AccessRecord, error) {
	view := format.RequiredSupportPageView{Records: make([]contract.SupportRecordView, len(change.rows))}
	for i, row := range change.rows {
		view.Records[i] = contract.SupportRecordView(row)
	}
	facts, ok := indexSelectedMaterialFacts(s.root, &s.pages, &s.access, []format.RequiredSupportPageView{view})
	if !ok {
		return nil, contract.ErrRecord
	}
	access := generatedDeleteLifecycleAccessRows(s.accessRecords(), change)
	for i, row := range access {
		if row.MaterialKind != contract.ValueMaterialKind {
			continue
		}
		readers := facts.valueReaders[row.MaterialID]
		wraps := make([]contract.WrapRow, 0, len(readers)+boolInt(s.root.CurrentAccess.Core.Recovery != nil))
		for _, wrap := range row.Wraps {
			if wrap.SubjectKind == contract.OrdinaryWrapSubject && slices.Contains(readers, wrap.SubjectID) ||
				wrap.SubjectKind == contract.RecoveryWrapSubject && s.root.CurrentAccess.Core.Recovery != nil {
				wraps = append(wraps, wrap)
			}
		}
		row.Wraps = wraps
		if !s.validateMaterialWraps(row, readers) {
			return nil, contract.ErrRecord
		}
		access[i] = row
	}
	return access, nil
}

func generatedLifecycleAccessPageCount(rows []contract.AccessRecord) (int, error) {
	pages, length, count := 0, contract.AccessPageHeaderLength, 0
	for _, row := range rows {
		size, err := contract.AccessRecordLength(row)
		if err != nil {
			return 0, err
		}
		if length+size > contract.MaxAccessPageLength || count == contract.AccessPageRecordLimit {
			pages, length, count = pages+1, contract.AccessPageHeaderLength, 0
		}
		length, count = length+size, count+1
	}
	if count != 0 {
		pages++
	}
	if pages > contract.MaxChildPages {
		return 0, contract.ErrRecordCapacity
	}
	return pages, nil
}

// Support pages replace the predecessor's pages. Count only entry, recipient,
// and successor access pages before packing the new support.
func generatedNonSupportChildCount(root format.Root, accessPages int) uint32 {
	count := 1 + uint32(len(root.AdministrativeIndexShards)) + uint32(accessPages)
	for _, table := range [][]*format.Ref{root.ValueEntryPages[:], root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				count++
			}
		}
	}
	return count
}

func (s *StateSession) packGeneratedLifecycleAccess(rows []contract.AccessRecord, plan transitionPlan,
	candidate *Candidate, identity *contract.IdentityPlan) error {
	slices.SortFunc(rows, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	descriptor, err := contract.AccessRecordsDescriptor(s.root.Domain, rows)
	if err != nil {
		return err
	}
	var pages []format.AccessPage
	page, length := format.AccessPage{Domain: s.root.Domain}, contract.AccessPageHeaderLength
	flush := func() error {
		if len(page.Records) == 0 {
			return nil
		}
		if len(pages) == contract.MaxChildPages {
			return contract.ErrRecordCapacity
		}
		page.Index = uint16(len(pages))
		page.Object = plan.accessPages[len(pages)]
		if page.Object.IsZero() {
			return contract.ErrRecord
		}
		pages = append(pages, page)
		page, length = format.AccessPage{Domain: s.root.Domain}, contract.AccessPageHeaderLength
		return nil
	}
	for _, row := range rows {
		size, err := contract.AccessRecordLength(row)
		if err != nil {
			return err
		}
		if length+size > contract.MaxAccessPageLength || len(page.Records) == contract.AccessPageRecordLimit {
			if err := flush(); err != nil {
				return err
			}
		}
		page.Records, length = append(page.Records, row), length+size
	}
	if err := flush(); err != nil {
		return err
	}
	s.root.CurrentAccess.Core.AccessPageRefs, s.access = nil, [contract.MaxChildPages]*format.AccessPage{}
	for i := range pages {
		page := &pages[i]
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			return err
		}
		ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			return err
		}
		s.access[i] = page
		s.root.CurrentAccess.Core.AccessPageRefs = append(s.root.CurrentAccess.Core.AccessPageRefs, ref)
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: format.AccessKind, Index: page.Index, Object: page.Object})
	}
	s.root.AccessRecordCount = uint32(len(rows))
	s.root.CurrentAccess.Core.AccessRecordsDescriptor = descriptor
	if err := contract.AdvanceAccessGeneration(&s.root.CurrentAccess.Core, plan.transition); err != nil {
		return err
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	return err
}

func (s *StateSession) installGeneratedLifecycleSupport(ctx context.Context, next *StateSession, rows []contract.SupportRecord,
	locations []contract.GeneratorSliceLocation, bundles []contract.GeneratorPlanBundle, plan *generatedLifecyclePlan,
	candidate *Candidate, identity *contract.IdentityPlan) error {
	rows, err := rebindSnapshotSliceRecords(rows, s.root.Domain, s.adminIndex.SliceSnapshot, plan.identity.snapshot)
	if err != nil {
		return err
	}
	groups, err := generatedReservationGroupsWithSource(next, s, rows, locations, bundles)
	if err != nil {
		return err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups,
		generatedNonSupportChildCount(next.root, len(next.root.CurrentAccess.Core.AccessPageRefs)), fragments)
	if err != nil {
		return err
	}
	generatedRefreshClosureCounts(&next.root.Generated, rows)
	graphs := make([]contract.ID, 0, len(bundles))
	for _, location := range locations {
		if location.ContentKind == contract.GeneratorContentGraph {
			graphs = append(graphs, location.ContentID)
		}
	}
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	next.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, slices.Compact(graphs))
	if err != nil {
		return err
	}
	supportPageCount := min(len(packed), len(plan.identity.supportPages))
	if err := s.installGeneratedSuccessorSupportWithBundles(ctx, next, packed, plan.identity.supportPages[:supportPageCount], candidate, identity, bundles); err != nil {
		return err
	}
	return nil
}

func (s *StateSession) deriveGeneratedCleanupClose(ctx context.Context, plan *generatedLifecyclePlan) (*generatedReservation, error) {
	if plan == nil || plan.kind != generatedLifecycleCleanupClose && plan.kind != generatedLifecycleOrdinaryCleanupClose || len(plan.result) == 0 || contract.Hash(plan.result) != plan.evidence {
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
	var change generatedDeleteReflection
	if plan.kind == generatedLifecycleOrdinaryCleanupClose {
		change, err = g.generatedOrdinaryCleanupClosure(ctx, result.Core.AttemptID, plan.identity.revision)
		if err != nil {
			return nil, err
		}
		if change.source.SourceID != plan.owner || !bytes.Equal(g.attempts[result.Core.AttemptID].result, plan.result) {
			return nil, contract.ErrRecord
		}
	} else {
		selection, ok, selectErr := g.selectGeneratedCleanup(ctx, map[contract.ID][]byte{result.Core.ResultID: plan.result})
		if selectErr != nil {
			return nil, selectErr
		}
		if !ok || selection.kind != generatedCleanupReflection || !selection.closeOwner || selection.sourceKey().id != plan.owner {
			return nil, contract.ErrRecord
		}
		change, err = g.generatedReflectOriginalClosure(ctx, selection, plan.identity.revision)
	}
	if err != nil {
		return nil, err
	}
	if change.target.ResourceDigest != plan.target {
		return nil, contract.ErrRecord
	}
	access, err := s.generatedDeleteLifecycleAccess(change)
	if err != nil {
		return nil, err
	}
	accessPages, err := generatedLifecycleAccessPageCount(access)
	if err != nil {
		return nil, err
	}
	rows, err := rebindSnapshotSliceRecords(change.rows, s.root.Domain, s.adminIndex.SliceSnapshot, plan.identity.snapshot)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsForState(s, rows, change.locations, g.bundles)
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, generatedNonSupportChildCount(s.root, accessPages), fragments)
	if err != nil {
		return nil, err
	}
	if err := s.generatedLifecyclePlanValid(ctx, plan, len(packed), accessPages); err != nil {
		return nil, err
	}

	next, candidate, identity := s.beginGeneratedSuccessor(plan.identity)
	next.root.Generated.Slices = change.slices
	next.root.Generated.ActiveOwner, next.root.Generated.ActivePhase, next.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	if err := next.packGeneratedLifecycleAccess(access, plan.identity, candidate, &identity); err != nil {
		return nil, err
	}
	if err := s.installGeneratedLifecycleSupport(ctx, &next, change.rows, change.locations, g.bundles, plan, candidate, &identity); err != nil {
		return nil, err
	}
	next.recountChildren()
	if !next.indexSelectedMaterials() {
		return nil, fmt.Errorf("index cleanup-close successor materials: %w", contract.ErrRecord)
	}
	if !validAggregate(next.root) {
		return nil, fmt.Errorf("validate cleanup-close successor aggregate: %w", contract.ErrRecord)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("validate cleanup-close successor: %w", err)
	}
	head, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
	if err != nil {
		return nil, err
	}
	subject, err := s.generatedCleanupCloseSubject(ctx, &next, g, plan, change, identity, head)
	if err != nil {
		return nil, err
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, fmt.Errorf("validate cleanup-close authority: %w", err)
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func (s *StateSession) generatedCleanupCloseSubject(ctx context.Context, next *StateSession, before *generatedSelection, plan *generatedLifecyclePlan,
	change generatedDeleteReflection, identity contract.IdentityPlan, head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	bundle, err := before.retainedGraph(change.attempt.record.OperationID)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: change.release.OriginalResultID,
		ResultBodyDigest: plan.evidence, ResultLength: change.release.ObjectLength}
	evidence, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{reference})
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: plan.requestIdentity, ObservedHEADDigest: plan.predecessorDigest,
		ConditionDigest: plan.context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityCleanupClose,
		BeforePhase: 1, AfterPhase: 2, Evidence: contract.GeneratorDescriptor(evidence)}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		return contract.GeneratorAuthoritySubject{}, err
	}
	x := change.attempt.expected.Template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityCleanupClose,
		DomainID: s.root.Domain, OperationID: plan.identity.operation, RequestIdentityDigest: plan.requestIdentity,
		PlanGraphID: bundle.UsePlan.PlanGraphID, UsePlanDigest: usePlan, PhaseID: phaseID,
		PreviousHEADDigest: plan.predecessorDigest, PreviousRevisionID: plan.predecessorRevision,
		ConditionDigest: plan.context.OriginalConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: change.source.SourceID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: x.ResultID, ResultDigest: plan.evidence, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID,
		ResultContractID: x.ResultContractID, Intent: bundle.Request.Declaration, CapacityReservation: change.source.CapacityReservation,
		BeforePhase: 1, AfterPhase: 2, ResultVector: contract.GeneratorDescriptor(evidence)}
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

func (s *selectedGeneratedProof) validGeneratedCleanupCloseSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	kind := uint8(contract.GeneratedHazardSupportKind)
	if row, present := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, subject.OwnerID}]; present {
		d, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || d.Kind != contract.GeneratedDutyUnselectedCleanup {
			return false
		}
		kind = contract.GeneratedDutySupportKind
	}
	return s.validGeneratedDeleteCloseSelection(g, subject, contract.GeneratorAuthorityCleanupClose, kind)
}

func (g *generatedSelection) generatedOrdinaryCleanupClosure(ctx context.Context, attemptID, revision contract.ID) (generatedDeleteReflection, error) {
	var out generatedDeleteReflection
	if g == nil || g.parent == nil || g.phase == nil || g.phase.FrontierAttemptID != attemptID || len(g.bundles[0].Lineages) != 1 || g.bundles[0].Lineages[0].Purpose != contract.GeneratorLineageCleanup {
		return out, contract.ErrRecord
	}
	a, ok := g.attempts[attemptID]
	if !ok || a.record.State != contract.GeneratedEffectSucceeded && (a.record.CompletionClass != contract.GeneratedCompletionConfirmed || a.record.State != contract.GeneratedEffectFailedTerminal) || a.record.Stage != contract.GeneratedStageTerminal || len(a.result) == 0 {
		return out, contract.ErrRecord
	}
	r, err := contract.InspectGeneratedResultRecord(a.result)
	if err != nil || !generatedResourceFactsMatch(r.SafeFacts.GeneratorSafeFacts, a.expected.TargetResourceDigest) {
		return out, contract.ErrRecord
	}
	target, source, err := g.generatedDeleteAttemptTargetAndSource(ctx, g.bundles[0], a.record)
	if err != nil {
		return out, err
	}
	if a.record.CompletionClass == contract.GeneratedCompletionConfirmed {
		progress, err := g.controlledDeleteSourceProgress(source, nil, true)
		if err != nil {
			return out, err
		}
		if len(progress.rows) != 2 || progress.contradiction {
			return g.generatedOrdinaryCleanupParking(a, source, target, revision)
		}
		if r.SafeFacts.Disposition != contract.GeneratorDispositionScopedUnusability || a.record.State != contract.GeneratedEffectSucceeded {
			return out, contract.ErrRecord
		}
	} else if a.record.CompletionClass != contract.GeneratedCompletionAcknowledged || r.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged {
		return out, contract.ErrRecord
	}
	return g.generatedDeleteSourceClosure(a, source, target, a.result, revision)
}

func (g *generatedSelection) generatedOrdinaryCleanupParking(a generatedAttempt, source contract.GeneratedDeleteSource, target contract.GeneratorTarget, revision contract.ID) (generatedDeleteReflection, error) {
	out := generatedDeleteReflection{attempt: a, source: source, hazard: source.Hazard, target: target,
		release: contract.PendingInboxReleaseRecord{Schema: 1, DomainID: a.record.DomainID, InboxID: a.record.InboxID,
			OriginalResultID: a.record.ResultID, SelectedHandoffDigest: contract.Hash(a.result), HandoffRevisionID: revision,
			CapacityReservation: source.CapacityReservation, ObjectLength: uint32(len(a.result)), State: contract.GeneratedReleasePending}}
	for _, row := range g.image.supportRecords() {
		if (row.Kind == contract.GeneratedParentSupportKind || row.Kind == contract.GeneratedPhaseSupportKind) && row.RecordID == g.parent.OperationID {
			continue
		}
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return out, err
			}
			if v.VectorKind == contract.GeneratorVectorSlices || v.OwnerKind == contract.GeneratedParentSupportKind && v.OwnerID == g.parent.OperationID && v.VectorKind != contract.GeneratorVectorSupport {
				continue
			}
		}
		out.rows = append(out.rows, row)
	}
	var err error
	out.rows, out.locations, out.slices, err = g.generatedCloseContent(out.rows)
	return out, err
}

func (s *StateSession) generatedOrdinaryCleanupClosePlan(ctx context.Context, attemptID contract.ID, admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	change, err := g.generatedOrdinaryCleanupClosure(ctx, attemptID, s.head.Core.Revision)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsForState(s, change.rows, change.locations, g.bundles)
	if err != nil {
		return nil, err
	}
	access, err := s.generatedDeleteLifecycleAccess(change)
	if err != nil {
		return nil, err
	}
	accessPages, err := generatedLifecycleAccessPageCount(access)
	if err != nil {
		return nil, err
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, generatedNonSupportChildCount(s.root, accessPages), fragments)
	if err != nil {
		return nil, err
	}
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, len(packed), accessPages)
	if err != nil {
		return nil, err
	}
	return &generatedLifecyclePlan{kind: generatedLifecycleOrdinaryCleanupClose, context: admitted, owner: change.source.SourceID,
		target: change.target.ResourceDigest, evidence: contract.Hash(g.attempts[attemptID].result), requestIdentity: request,
		predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token,
		identity: identity, result: bytes.Clone(g.attempts[attemptID].result), source: observationSource{ParentID: change.attempt.record.OperationID, AttemptID: change.attempt.record.AttemptID}}, nil
}

func (s *selectedGeneratedProof) validGeneratedRetirementCloseSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	return s.validGeneratedDeleteCloseSelection(g, subject, contract.GeneratorAuthorityRetireClose, 10)
}

func (s *selectedGeneratedProof) validGeneratedDeleteCloseSelection(g *generatedSelection, subject contract.GeneratorAuthoritySubject,
	purpose contract.GeneratorAuthorityPurpose, ownerKind uint8) bool {
	if g == nil || g.parent != nil || g.phase != nil || subject.Purpose != purpose ||
		subject.BeforePhase != 1 || subject.AfterPhase != 2 || subject.ResultDigest.IsZero() ||
		subject.AfterAccessDigest != s.root.CurrentAccess.AccessRoot {
		return false
	}
	released, ok := g.releases[subject.AttemptID]
	nonfinal := false
	if !ok {
		a, present := g.attempts[subject.AttemptID]
		source, err := contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{ownerKind, subject.OwnerID}])
		if !present || err != nil || source.CompletionClass != contract.GeneratedCompletionConfirmed || a.record.OwnerID != source.OwnerID || len(a.result) == 0 ||
			purpose == contract.GeneratorAuthorityRetireClose && (ownerKind != contract.GeneratedDutySupportKind || source.Duty.Kind != contract.GeneratedDutyRetirement) ||
			purpose == contract.GeneratorAuthorityCleanupClose && ownerKind == contract.GeneratedDutySupportKind && source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup {
			return false
		}
		progress, err := g.controlledDeleteSourceProgress(source, nil, true)
		if err != nil || len(progress.rows) == 2 && !progress.contradiction {
			return false
		}
		released = generatedReleasedAttempt{attempt: a.record, template: a.expected.Template, release: contract.PendingInboxReleaseRecord{InboxID: a.record.InboxID, OriginalResultID: a.record.ResultID,
			SelectedHandoffDigest: contract.Hash(a.result), HandoffRevisionID: s.head.Core.Revision, CapacityReservation: source.CapacityReservation, ObjectLength: uint32(len(a.result)), State: contract.GeneratedReleasePending}}
		ok, nonfinal = true, true
	}
	reflectedFinal := false
	if !nonfinal && released.attempt.CompletionClass == contract.GeneratedCompletionConfirmed &&
		(released.attempt.State == contract.GeneratedEffectUnknown || released.attempt.State == contract.GeneratedEffectClosedWithResidue) {
		rows, err := g.controlledReleasedProgress(released)
		reflectedFinal = err == nil && len(rows) == 2
	}
	createNoEffect := purpose == contract.GeneratorAuthorityCleanupClose && ownerKind == contract.GeneratedHazardSupportKind &&
		released.template.Action == contract.GeneratorActionCreate && released.template.HazardID == subject.OwnerID &&
		released.attempt.State == contract.GeneratedEffectConfirmedNoEffect && !nonfinal
	if !ok || released.release.InboxID.IsZero() || released.release.OriginalResultID != subject.ResultID ||
		released.release.SelectedHandoffDigest != subject.ResultDigest || released.release.HandoffRevisionID != s.head.Core.Revision ||
		released.release.CapacityReservation != subject.CapacityReservation || released.release.State != contract.GeneratedReleasePending ||
		released.template.Action != contract.GeneratorActionDelete && !createNoEffect || released.attempt.State != contract.GeneratedEffectSucceeded &&
		!reflectedFinal && !createNoEffect && (!nonfinal || released.attempt.State != contract.GeneratedEffectFailedTerminal) ||
		released.template.LineageID != subject.LineageID || released.template.PredecessorAttemptID != subject.PredecessorAttemptID ||
		released.template.ConfigContractID != subject.ConfigContractID || released.template.DescriptorID != subject.DescriptorID ||
		released.template.ResultContractID != subject.ResultContractID {
		return false
	}
	if _, present := g.records[generatedRecordKey{kind: ownerKind, id: subject.OwnerID}]; present && !nonfinal {
		return false
	}
	bundle, err := g.retainedGraph(released.attempt.OperationID)
	if err != nil || bundle.Request.Declaration != subject.Intent || bundle.UsePlan.PlanGraphID != subject.PlanGraphID {
		return false
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil || usePlan != subject.UsePlanDigest {
		return false
	}
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: subject.ResultID,
		ResultBodyDigest: subject.ResultDigest, ResultLength: released.release.ObjectLength}
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
	entryUnionRows, membershipRows := s.generatedUnchangedEntryUnion(), s.generatedUnchangedEntryUnion()
	if purpose == contract.GeneratorAuthorityRetireClose && !nonfinal {
		var pages []contract.IdentityPage
		var ok bool
		entryUnionRows, membershipRows, pages, ok = s.generatedReleasedRetirementEntryProjections(bundle, subject)
		if !ok {
			return false
		}
		identity.Pages = append(identity.Pages, pages...)
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	for _, ref := range s.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil || descriptor != subject.IdentityPlan {
		return false
	}
	entryUnion, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, entryUnionRows)
	if err != nil || entryUnion != subject.ValueEntryUnion {
		return false
	}
	for i := range membershipRows {
		membershipRows[i].After.EntryDigest = contract.ID{}
	}
	planned, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membershipRows)
	return err == nil && planned == subject.MembershipChanges && generatedMembershipAuthority(membershipRows) == subject.RequiredAuthoritySet
}
