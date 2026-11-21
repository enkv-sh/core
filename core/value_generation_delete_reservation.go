package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedDeleteReservationSelection struct {
	purpose      contract.GeneratorAuthorityPurpose
	lineageIndex uint16
	template     contract.GeneratorAttemptTemplate
	use          contract.GeneratorResultUse
	duty         contract.GeneratedDutyRecord
	dutyRow      contract.SupportRecord
	source       contract.GeneratedDeleteSource
	target       contract.GeneratorTarget
	phase        contract.GeneratorPhaseIdentity
}

func (s *StateSession) generatedDeleteReservationSelection(ctx context.Context, graph contract.GeneratorPlanBundle,
	selected *generatedSelection) (generatedDeleteReservationSelection, bool, error) {
	var out generatedDeleteReservationSelection
	if s == nil || selected == nil || selected.parent != nil || len(graph.Lineages) != 1 || graph.Header.LineageCount != 0 ||
		graph.Header.TemplateCount != 1 {
		return out, false, nil
	}
	lineage := graph.Lineages[0]
	if lineage.TemplateCount != 1 || lineage.Purpose != contract.GeneratorLineageRetirement && lineage.Purpose != contract.GeneratorLineageCleanup {
		return out, false, nil
	}
	x := lineage.Templates[0]
	if x.Action != contract.GeneratorActionDelete || x.Branch != contract.GeneratorBranchInitial || !x.PredecessorAttemptID.IsZero() {
		return out, false, nil
	}
	_, use, ok := generatedTemplate(graph, x.AttemptID)
	if !ok {
		return out, false, nil
	}
	source, err := selected.generatedDeleteSource(x.DutyID)
	if err != nil {
		return out, false, nil
	}
	row, duty := source.Record, source.Duty
	purpose := contract.GeneratorAuthorityRetireReserve
	if lineage.Purpose == contract.GeneratorLineageRetirement {
		if row.Kind != contract.GeneratedDutySupportKind || duty.Kind != contract.GeneratedDutyRetirement ||
			duty.Status != contract.GeneratedEffectNotStarted && duty.Status != contract.GeneratedEffectUnknown &&
				(duty.CompletionClass != contract.GeneratedCompletionConfirmed || duty.Status != contract.GeneratedEffectSucceeded && duty.Status != contract.GeneratedEffectFailedTerminal) {
			return out, false, nil
		}
		if duty.CompletionClass == contract.GeneratedCompletionConfirmed {
			progress, err := selected.controlledRetirementProgress(duty, nil, true)
			if err != nil || progress.contradiction || len(progress.rows) > 1 {
				return out, false, nil
			}
		} else {
			for _, attempt := range selected.attempts {
				if attempt.record.OwnerID != duty.OwnerID || attempt.expected.Template.Action != contract.GeneratorActionDelete {
					continue
				}
				contradiction, err := selected.validateDeleteFacts(attempt)
				if err != nil || contradiction {
					return out, false, nil
				}
			}
		}
	} else {
		purpose = contract.GeneratorAuthorityCleanupReserve
		if !generatedOrdinaryCleanupSourceEligible(source) || selected.cleanupConflicts[source.SourceID] {
			return out, false, nil
		}
	}
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		return out, false, nil
	}
	a := contract.GeneratedAttemptRecord{Schema: contract.GeneratedAttemptRecordSchema, DomainID: graph.Header.DomainID, OperationID: graph.Header.OperationID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TemplateDigest: template, OwnerID: x.DutyID,
		ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, InboxID: x.InboxID,
		ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, CompletionClass: x.CompletionClass}
	target, exactSource, err := selected.generatedDeleteAttemptTargetAndSource(ctx, graph, a)
	if err != nil {
		return out, false, err
	}
	if exactSource.SourceID != source.SourceID || target.ResourceDigest.IsZero() {
		return out, false, nil
	}
	requestIdentity, err := contract.GeneratorDeleteReservationRequestID(graph.Header.RequestCoreDigest)
	if err != nil {
		return out, false, nil
	}
	kind := contract.GeneratorPhaseDuties
	if row.Kind == contract.GeneratedHazardSupportKind {
		kind = contract.GeneratorPhaseHazards
	}
	evidence, err := contract.GeneratorRecordSetDescriptor(kind, s.root.Domain, []contract.SupportRecord{row})
	if err != nil {
		return out, false, nil
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: requestIdentity,
		ObservedHEADDigest: graph.Request.PredecessorHEADDigest, ConditionDigest: graph.Request.ConditionDigest,
		TransitionKind: purpose, BeforePhase: 1, AfterPhase: 2, Evidence: evidence}
	if _, err := contract.GeneratorPhaseID(phase); err != nil {
		return out, false, nil
	}
	return generatedDeleteReservationSelection{purpose: purpose, lineageIndex: 0, template: x, use: use,
		duty: duty, dutyRow: row, source: source, target: target, phase: phase}, true, nil
}

func generatedDeleteReservationReplaces(row contract.SupportRecord, selected generatedDeleteReservationSelection) bool {
	if row.Kind == selected.source.Record.Kind && row.RecordID == selected.source.SourceID {
		return true
	}
	if row.Kind != contract.GeneratorVectorSupportKind {
		return false
	}
	carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
	if err != nil || carrier.OwnerKind != selected.source.Record.Kind || carrier.OwnerID != selected.source.SourceID {
		return false
	}
	return carrier.VectorKind == contract.GeneratorVectorConsumers || carrier.VectorKind == contract.GeneratorVectorHistory
}

func generatedInitialDeleteRows(input generatedReservationInput, phaseID contract.ID, selected generatedDeleteReservationSelection,
	before *generatedSelection) ([]contract.SupportRecord, error) {
	parent, x, duty, source := input.parent, selected.template, selected.duty, selected.source
	kind, owner := source.Record.Kind, source.SourceID
	consumers, historyVector := source.Consumers, source.History
	empty := contract.EmptyGeneratorVector
	context, err := contract.GeneratorResultUseDigest(selected.use)
	if err != nil {
		return nil, err
	}
	consumerBodies, err := before.vectors.resolve(kind, owner, contract.GeneratorVectorConsumers, consumers)
	if err != nil {
		return nil, err
	}
	consumer, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: owner,
		MaterialID: parent.MaterialID, ContextDigest: context, SubjectKind: contract.GeneratorConsumerOriginalResult, SubjectID: x.ResultID, Purpose: contract.GeneratorConsumerAdoptLateOriginalResult})
	if err != nil {
		return nil, err
	}
	consumerBodies = append(consumerBodies, consumer)
	slices.SortFunc(consumerBodies, bytes.Compare)
	for i := 1; i < len(consumerBodies); i++ {
		if bytes.Equal(consumerBodies[i-1], consumerBodies[i]) {
			return nil, contract.ErrRecord
		}
	}
	var rows []contract.SupportRecord
	supportOwner := source.OriginalOperationID
	if kind == contract.GeneratedHazardSupportKind {
		supportOwner, err = generatedHazardSupportOwner(source.Hazard, before.bundles, before.vectors)
		if err != nil {
			return nil, err
		}
	}
	supportBodies, err := before.vectors.resolve(contract.GeneratedParentSupportKind, supportOwner, contract.GeneratorVectorSupport, source.Support)
	if err != nil {
		return nil, err
	}
	support, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratedParentSupportKind, parent.OperationID, contract.GeneratorVectorSupport, supportBodies)
	if err != nil {
		return nil, err
	}
	if support != source.Support {
		return nil, contract.ErrRecord
	}
	rows = append(rows, carriers...)
	consumers, carriers, err = generatedCarrierRows(parent.DomainID, kind, owner, contract.GeneratorVectorConsumers, consumerBodies)
	if err != nil {
		return nil, err
	}
	rows = append(rows, carriers...)
	for _, accepted := range input.graph.SourceUses {
		consumer, err := contract.GeneratorAcceptedSourceConsumer(parent.OperationID, parent.MaterialID, accepted)
		if err != nil {
			return nil, err
		}
		body, err := contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			return nil, err
		}
		descriptor, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratedParentSupportKind, parent.OperationID,
			contract.GeneratorVectorConsumers, [][]byte{body})
		if err != nil || descriptor != accepted.Consumers {
			return nil, contract.ErrRecord
		}
		rows = append(rows, carriers...)
	}
	history := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: x.AttemptID, OwnerID: source.OwnerID,
		Outcome: contract.GeneratedEffectTransmitted}
	historyBody, err := contract.EncodeGeneratorHistory(history)
	if err != nil {
		return nil, err
	}
	attemptHistory, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratedAttemptSupportKind, x.AttemptID, contract.GeneratorVectorHistory, [][]byte{historyBody})
	if err != nil {
		return nil, err
	}
	rows = append(rows, carriers...)
	{
		historyBodies, err := before.vectors.resolve(kind, owner, contract.GeneratorVectorHistory, historyVector)
		if err != nil {
			return nil, err
		}
		if len(historyBodies) != 0 {
			last, err := contract.InspectGeneratorHistory(historyBodies[len(historyBodies)-1])
			previous, deleting := before.attempts[last.PredecessorAttemptID]
			if err != nil {
				return nil, contract.ErrRecord
			}
			reflectedCreate := deleting && source.Record.Kind == contract.GeneratedHazardSupportKind &&
				source.Hazard.Exposure == contract.GeneratedExposureLateEffect && source.Hazard.Eligibility == contract.GeneratedExposureLateEffect &&
				source.Hazard.Fenced == 1 && source.Hazard.OriginalAttemptID == previous.record.AttemptID &&
				previous.record.State == contract.GeneratedEffectClosedWithResidue && len(previous.result) != 0
			if deleting && previous.expected.Template.Action == contract.GeneratorActionDelete {
				if (last.Outcome != contract.GeneratedEffectUnknown && last.Outcome != contract.GeneratedEffectClosedWithResidue &&
					(source.CompletionClass != contract.GeneratedCompletionConfirmed || last.Outcome != contract.GeneratedEffectSucceeded && last.Outcome != contract.GeneratedEffectFailedTerminal)) ||
					last.Edge != 0 || !last.NextAttemptID.IsZero() {
					return nil, contract.ErrRecord
				}
			} else if !deleting || previous.expected.Template.Action != contract.GeneratorActionCreate || previous.record.Stage != contract.GeneratedStageTerminal ||
				previous.record.State != contract.GeneratedEffectSucceeded && previous.record.State != contract.GeneratedEffectFailedTerminal && !reflectedCreate || last.Edge != 0 || !last.NextAttemptID.IsZero() {
				return nil, contract.ErrRecord
			}
			last.NextAttemptID, last.Edge = x.AttemptID, 4
			historyBodies[len(historyBodies)-1], err = contract.EncodeGeneratorHistory(last)
			if err != nil {
				return nil, err
			}
		}
		historyBodies = append(historyBodies, historyBody)
		if duty.Kind == contract.GeneratedDutyRetirement {
			duty.Status = contract.GeneratedEffectTransmitted
		}
		historyVector, carriers, err = generatedCarrierRows(parent.DomainID, kind, owner, contract.GeneratorVectorHistory, historyBodies)
		if err != nil {
			return nil, err
		}
		rows = append(rows, carriers...)
	}
	templateID, err := contract.GeneratorTemplateID(x)
	if err != nil {
		return nil, err
	}
	attempt := contract.GeneratedAttemptRecord{Schema: contract.GeneratedAttemptRecordSchema, DomainID: parent.DomainID, OperationID: parent.OperationID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TemplateDigest: templateID, OwnerID: source.OwnerID,
		ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, InboxID: x.InboxID,
		ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, RequestDigest: input.requestBindings[0].Digest,
		State: contract.GeneratedEffectTransmitted, Stage: contract.GeneratedStageRetainedResult, CompletionClass: x.CompletionClass,
		Facts: empty(contract.GeneratorVectorFacts), Progress: empty(contract.GeneratorVectorProgress), Support: source.Support, History: attemptHistory}
	attempt.LifecycleMode = x.LifecycleMode
	if source.CompletionClass == contract.GeneratedCompletionConfirmed {
		progress, err := before.controlledDeleteSourceProgress(source, nil, true)
		if err != nil {
			return nil, err
		}
		var carriers []contract.SupportRecord
		attempt.Progress, carriers, err = generatedCarrierRows(parent.DomainID, contract.GeneratedAttemptSupportKind, attempt.AttemptID, contract.GeneratorVectorProgress, progress.rows)
		if err != nil {
			return nil, err
		}
		rows = append(rows, carriers...)
	}
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		return nil, err
	}
	var sourceBody []byte
	if kind == contract.GeneratedDutySupportKind {
		duty.Consumers, duty.History = consumers, historyVector
		sourceBody, err = contract.EncodeGeneratedDutyRecord(duty)
	} else {
		h := source.Hazard
		h.Consumers, h.History = consumers, historyVector
		sourceBody, err = contract.EncodeGeneratedHazardRecord(h)
	}
	if err != nil {
		return nil, err
	}
	aRow := contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: x.AttemptID, Body: attemptBody}
	dRow := contract.SupportRecord{Kind: kind, RecordID: owner, Body: sourceBody}
	attemptSet, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseAttempts, parent.DomainID, []contract.SupportRecord{aRow})
	if err != nil {
		return nil, err
	}
	dutySet, hazardSet := contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseDuties), contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards)
	if kind == contract.GeneratedDutySupportKind {
		dutySet, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, parent.DomainID, []contract.SupportRecord{dRow})
	} else {
		hazardSet, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseHazards, parent.DomainID, []contract.SupportRecord{dRow})
	}
	if err != nil {
		return nil, err
	}
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: parent.DomainID, OperationID: parent.OperationID,
		OwnerID: parent.OperationID, PlanGraphID: parent.PlanGraphID, UsePlanDigest: parent.UsePlanDigest, PhaseID: phaseID,
		Phase: selected.phase.AfterPhase, LineageIndex: selected.lineageIndex, FrontierAttemptID: x.AttemptID,
		Stage: contract.GeneratedStageRetainedResult, AcceptedResults: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseResults),
		Attempts: attemptSet, Duties: dutySet, Hazards: hazardSet,
		PendingReleases: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases), Proofs: empty(contract.GeneratorVectorProofs)}
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		return nil, err
	}
	material, err := contract.EncodeOperationMaterialRecord(input.finished.Material)
	if err != nil {
		return nil, err
	}
	parentPlan, err := contract.AppendGeneratedParentSupportPlan(nil, parent)
	if !parent.RequestIdentityDigest.IsZero() {
		var body []byte
		body, err = contract.EncodeGeneratedParentRecord(contract.GeneratedParentRecord(parent))
		parentPlan = append(make([]byte, contract.SupportRecordOverhead), body...)
	}
	if err != nil {
		return nil, err
	}
	return append(rows, aRow, dRow, contract.SupportRecord{Kind: contract.OperationMaterialSupportKind, RecordID: parent.MaterialID, Body: material},
		contract.SupportRecord{Kind: contract.GeneratedParentSupportKind, RecordID: parent.OperationID, Body: parentPlan[contract.SupportRecordOverhead:]},
		contract.SupportRecord{Kind: contract.GeneratedPhaseSupportKind, RecordID: parent.OperationID, Body: phaseBody}), nil
}

func (s *StateSession) fillGeneratedDeleteReservation(plan format.GeneratorInitialReservationPlan,
	phase contract.GeneratorPhaseIdentity) (format.GeneratorInitialReservation, error) {
	parent := contract.GeneratedParentRecord(plan.Parent)
	parent.RequestIdentityDigest = phase.RequestIdentityDigest
	parentBody, err := contract.EncodeGeneratedParentRecord(parent)
	if err != nil {
		return format.GeneratorInitialReservation{}, err
	}
	parentPage := -1
	pages := slices.Clone(plan.SupportPages)
	for i := range pages {
		pages[i].Records = slices.Clone(pages[i].Records)
		for j := range pages[i].Records {
			row := &pages[i].Records[j]
			if row.Kind == contract.GeneratedParentSupportKind && row.RecordID == parent.OperationID {
				if parentPage >= 0 {
					return format.GeneratorInitialReservation{}, contract.ErrRecord
				}
				parentPage, row.Body = i, parentBody
			}
		}
	}
	if parentPage < 0 {
		return format.GeneratorInitialReservation{}, contract.ErrRecord
	}
	pageBody, err := format.EncodeRequiredSupportPage(pages[parentPage])
	if err != nil {
		return format.GeneratorInitialReservation{}, err
	}
	root := plan.Snapshot
	root.RequiredSupport = slices.Clone(root.RequiredSupport)
	position := slices.IndexFunc(root.RequiredSupport, func(ref format.Ref) bool {
		return ref.Index == pages[parentPage].Index
	})
	if position < 0 || root.RequiredSupport[position].Domain != pages[parentPage].Domain ||
		root.RequiredSupport[position].Object != pages[parentPage].Object ||
		position >= len(plan.Administrative.Pages) || plan.Administrative.Pages[position].Ref != root.RequiredSupport[position] {
		return format.GeneratorInitialReservation{}, contract.ErrRecord
	}
	root.RequiredSupport[position].Digest = contract.Hash(pageBody)
	administrative := plan.Administrative
	administrative.Pages = slices.Clone(administrative.Pages)
	administrative.Pages[position].Ref = root.RequiredSupport[position]
	administrativePages, err := format.EncodeAdministrativeIndexPages(administrative)
	if err != nil || len(administrativePages) != 1+len(root.AdministrativeIndexShards) {
		return format.GeneratorInitialReservation{}, contract.ErrRecord
	}
	root.AdministrativeIndex = administrativePages[0].Ref
	root.AdministrativeIndexShards = nil
	for _, shard := range administrativePages[1:] {
		root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, shard.Ref)
	}
	root.ChildEncodedBytes = plan.Snapshot.ChildEncodedBytes - uint64(plan.Snapshot.AdministrativeIndex.Length) + uint64(root.AdministrativeIndex.Length)
	for i, shard := range root.AdministrativeIndexShards {
		root.ChildEncodedBytes += uint64(shard.Length) - uint64(plan.Snapshot.AdministrativeIndexShards[i].Length)
	}
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		return format.GeneratorInitialReservation{}, err
	}
	head := format.HeadCore(plan.Head)
	head.Root.Digest = contract.Hash(rootBody)
	headBody, err := format.EncodeHeadCore(head)
	if err != nil {
		return format.GeneratorInitialReservation{}, err
	}
	conditional := format.ConditionalPlan(plan.Conditional)
	conditional.HeadCore = contract.Hash(headBody)
	if _, err := format.EncodeConditionalPlan(conditional); err != nil {
		return format.GeneratorInitialReservation{}, err
	}
	identityPlan := contract.IdentityPlan{Operation: parent.OperationID, Snapshot: root.Snapshot,
		Transition: root.Transition, Revision: head.Revision}
	for _, ref := range root.CurrentAccess.Core.AccessPageRefs {
		identityPlan.Pages = append(identityPlan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	for _, ref := range root.RequiredSupport {
		identityPlan.Pages = append(identityPlan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	identity, err := contract.GeneratorAuthorityIdentityDescriptor(identityPlan)
	if err != nil {
		return format.GeneratorInitialReservation{}, err
	}
	material, err := contract.OperationImmutableBodyDigest(plan.Material.Core, plan.Material.SeedCheck)
	if err != nil {
		return format.GeneratorInitialReservation{}, err
	}
	return format.GeneratorInitialReservation{Identity: format.GeneratorInitialIdentity{RequestIdentityDigest: phase.RequestIdentityDigest,
		MaterialDigest: material, Plan: identity}, ParentPage: pages[parentPage], Snapshot: root, Head: head, Conditional: conditional,
		AdministrativePages: administrativePages}, nil
}

func (s *StateSession) generatedDeleteReservationSubject(ctx context.Context, next *StateSession, input generatedReservationInput,
	filled format.GeneratorInitialReservation, selected generatedDeleteReservationSelection) (contract.GeneratorAuthoritySubject, error) {
	parent, q, x := input.parent, input.graph.Request, selected.template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: selected.purpose, DomainID: q.DomainID,
		OperationID: q.OperationID, RequestIdentityDigest: selected.phase.RequestIdentityDigest,
		PlanGraphID: parent.PlanGraphID, UsePlanDigest: parent.UsePlanDigest, PhaseID: next.root.Generated.ActivePhase,
		PreviousHEADDigest: q.PredecessorHEADDigest, PreviousRevisionID: q.PredecessorRevisionID,
		ConditionDigest: q.ConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: filled.Head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: selected.source.SourceID, LineageID: x.LineageID, AttemptID: x.AttemptID,
		ResultID: x.ResultID, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
		Intent: q.Declaration, IdentityPlan: filled.Identity.Plan, CapacityReservation: selected.source.CapacityReservation,
		BeforePhase: selected.phase.BeforePhase, AfterPhase: selected.phase.AfterPhase, ResultVector: selected.phase.Evidence}
	var err error
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(q.DomainID, s.generatedUnchangedEntryUnion())
	if err != nil {
		return subject, err
	}
	planned, err := s.generatedMembershipPlan(input.graph, input.declaration)
	if err != nil {
		return subject, err
	}
	subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(q.DomainID, planned)
	if err != nil {
		return subject, err
	}
	subject.RequiredAuthoritySet = generatedMembershipAuthority(planned)
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
	headBody, err := format.EncodeHeadCore(filled.Head)
	if err != nil {
		return subject, err
	}
	conditionalBody, err := format.EncodeConditionalPlan(filled.Conditional)
	if err != nil {
		return subject, err
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(headBody), uint32(len(headBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(conditionalBody), uint32(len(conditionalBody))
	_, err = contract.NewGeneratorRequest(subject)
	return subject, err
}

func (s *selectedGeneratedProof) validateGeneratedDeleteReservationSelection(ctx context.Context, g *generatedSelection,
	subject contract.GeneratorAuthoritySubject) error {
	enclosed := generatedSelectionAnchored(g)
	if g == nil || g.parent == nil || g.phase == nil || (!enclosed && (g.phase.Phase != 2 || subject.BeforePhase != 1 || subject.AfterPhase != 2)) ||
		enclosed && (subject.BeforePhase == 0 || subject.AfterPhase != subject.BeforePhase+1 || g.phase.Phase != subject.AfterPhase) ||
		subject.OperationID != g.parent.OperationID || subject.RequestIdentityDigest != g.parent.RequestIdentityDigest ||
		subject.PlanGraphID != g.parent.PlanGraphID || subject.UsePlanDigest != g.parent.UsePlanDigest ||
		subject.PhaseID != g.phase.PhaseID || subject.Intent != g.parent.Declaration || !subject.ResultDigest.IsZero() ||
		!subject.PredecessorAttemptID.IsZero() || (!enclosed && subject.BeforeAccessDigest == subject.AfterAccessDigest) || enclosed && subject.BeforeAccessDigest != subject.AfterAccessDigest {
		return contract.ErrRecord
	}
	a, ok := g.attempts[subject.AttemptID]
	if !ok || len(a.result) != 0 || a.record.State != contract.GeneratedEffectTransmitted ||
		a.record.Stage != contract.GeneratedStageRetainedResult {
		return contract.ErrRecord
	}
	x := a.expected.Template
	if enclosed {
		exact, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
		if !ok || exact != x {
			return contract.ErrRecord
		}
	}
	if x.Action != contract.GeneratorActionDelete || x.Branch != contract.GeneratorBranchInitial || subject.LineageID != x.LineageID || subject.ResultID != x.ResultID ||
		subject.ConfigContractID != x.ConfigContractID || subject.DescriptorID != x.DescriptorID || subject.ResultContractID != x.ResultContractID {
		return contract.ErrRecord
	}
	source, err := g.generatedDeleteSource(a.record.OwnerID)
	if err != nil || source.SourceID != subject.OwnerID || source.CapacityReservation != subject.CapacityReservation {
		return contract.ErrRecord
	}
	duty := source.Duty
	if source.Record.Kind == contract.GeneratedHazardSupportKind && (subject.Purpose != contract.GeneratorAuthorityCleanupReserve ||
		source.Hazard.Eligibility == 0 || source.Hazard.Eligibility != source.Hazard.Exposure) ||
		duty.Kind == contract.GeneratedDutyRetirement && subject.Purpose != contract.GeneratorAuthorityRetireReserve ||
		duty.Kind == contract.GeneratedDutyUnselectedCleanup && subject.Purpose != contract.GeneratorAuthorityCleanupReserve {
		return contract.ErrRecord
	}
	if _, err := g.generatedDeleteAttemptTarget(ctx, g.bundles[0], a.record); err != nil {
		return err
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest,
		TransitionKind: subject.Purpose, BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: subject.ResultVector})
	if err != nil || phase != subject.PhaseID {
		return contract.ErrRecord
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil || snapshot != s.root.Snapshot {
		return contract.ErrRecord
	}
	transition, err := contract.GeneratorPhaseTransitionID(phase)
	if err != nil || transition != s.root.Transition {
		return contract.ErrRecord
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil || revision != s.head.Core.Revision {
		return contract.ErrRecord
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: snapshot, Transition: transition, Revision: revision}
	if !enclosed {
		for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
			identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
		}
	}
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
	var declaration []byte
	if g.image.fragmentFacts != nil {
		declaration, err = g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	} else {
		declaration, err = g.content.read(contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	}
	if err != nil {
		return err
	}
	planned, err := s.generatedMembershipPlan(g.bundles[0], declaration)
	if err != nil || generatedMembershipAuthority(planned) != subject.RequiredAuthoritySet {
		return contract.ErrRecord
	}
	membership, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, planned)
	if err != nil || membership != subject.MembershipChanges {
		return contract.ErrRecord
	}
	return nil
}
