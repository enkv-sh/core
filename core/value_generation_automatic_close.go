package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

// One effect-free close releases the current delete and advances the finite
// original graph cursor. Only the last close appends the original apply receipt.
func (s *StateSession) generatedAutomaticClosePlan(ctx context.Context, admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if !generatedSelectionAnchored(g) || g.phase.Phase == ^uint32(0) {
		return nil, contract.ErrRecord
	}
	x, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok || x.AttemptID != g.phase.FrontierAttemptID {
		return nil, contract.ErrRecord
	}
	a, ok := g.attempts[x.AttemptID]
	if !ok || len(a.result) == 0 || a.record.Stage != contract.GeneratedStageTerminal {
		return nil, contract.ErrRecord
	}
	target, err := g.retirementAttemptTarget(ctx, g.bundles[0], a.record)
	if err != nil {
		return nil, err
	}
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, contract.MaxChildPages, contract.MaxChildPages)
	if err != nil {
		return nil, err
	}
	plan := &generatedLifecyclePlan{kind: generatedLifecycleAutomaticClose, context: admitted, owner: x.DutyID, target: target.ResourceDigest, evidence: contract.Hash(a.result), requestIdentity: request, predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token, identity: identity, result: bytes.Clone(a.result), source: observationSource{ParentID: g.parent.OperationID, AttemptID: x.AttemptID}}
	return plan, nil
}

func generatedAutomaticTerminalRows(g *generatedSelection, rows []contract.SupportRecord) ([]contract.SupportRecord, error) {
	hazardAttempts := make(map[contract.ID]bool)
	for _, row := range rows {
		if row.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return nil, err
		}
		if hazard.OriginalOperationID == g.parent.OperationID {
			hazardAttempts[hazard.OriginalAttemptID] = true
		}
	}
	creates := make(map[contract.ID]bool)
	owners := make(map[contract.ID]bool)
	results := make(map[contract.ID]bool)
	lineages := make(map[contract.ID]bool)
	for _, a := range g.attempts {
		if a.record.OperationID == g.parent.OperationID && a.expected.Template.Action == contract.GeneratorActionCreate {
			lineages[a.record.LineageID] = true
			if hazardAttempts[a.record.AttemptID] {
				continue
			}
			creates[a.record.AttemptID] = true
			owners[a.record.OwnerID] = true
			results[a.record.ResultID] = true
		}
	}
	var out []contract.SupportRecord
	for _, row := range rows {
		remove := false
		switch row.Kind {
		case contract.GeneratedParentSupportKind, contract.GeneratedPhaseSupportKind, contract.GeneratedFinalPreparationSupportKind:
			remove = row.RecordID == g.parent.OperationID
		case contract.GeneratedAttemptSupportKind:
			remove = creates[row.RecordID]
		case contract.GeneratedDutySupportKind:
			remove = owners[row.RecordID]
		case contract.GeneratedResultSupportKind:
			remove = results[row.RecordID]
		case contract.GeneratedLineageSupportKind:
			remove = lineages[row.RecordID]
		case contract.GeneratorVectorSupportKind:
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			remove = creates[v.OwnerID] || owners[v.OwnerID] || lineages[v.OwnerID] || v.OwnerKind == contract.GeneratedParentSupportKind && v.OwnerID == g.parent.OperationID && v.VectorKind != contract.GeneratorVectorSupport
		}
		if !remove {
			out = append(out, row)
		}
	}
	// The shared seed ends only when no surviving independent result consumer
	// owns it. The remaining close projection decides this once for the parent.
	needed := false
	for _, row := range out {
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			if v.VectorKind == contract.GeneratorVectorConsumers {
				c, err := contract.InspectGeneratorConsumer(v.Row)
				if err != nil {
					return nil, err
				}
				needed = needed || c.MaterialID == g.parent.MaterialID
			}
		}
	}
	if !needed {
		out = slices.DeleteFunc(out, func(row contract.SupportRecord) bool {
			return row.Kind == contract.OperationMaterialSupportKind && row.RecordID == g.parent.MaterialID
		})
	}
	return g.pruneClosedCreateEvidence(out)
}

func (s *StateSession) deriveGeneratedAutomaticClose(ctx context.Context, plan *generatedLifecyclePlan) (*generatedReservation, error) {
	if plan == nil || (plan.kind != generatedLifecycleAutomaticClose && plan.kind != generatedLifecycleAutomaticPark) || plan.predecessorDigest != contract.Hash(s.body) || plan.predecessorRevision != s.head.Core.Revision || plan.predecessorToken != s.token || !s.generatedContextValid(plan.context) {
		return nil, contract.ErrRecord
	}
	if err := s.generatedLifecyclePlanValid(ctx, plan, contract.MaxChildPages, contract.MaxChildPages); err != nil {
		return nil, err
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if !generatedSelectionAnchored(g) || g.phase.Phase == ^uint32(0) {
		return nil, contract.ErrRecord
	}
	x, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok || x.AttemptID != g.phase.FrontierAttemptID || x.DutyID != plan.owner {
		return nil, contract.ErrRecord
	}
	a, ok := g.attempts[x.AttemptID]
	park := plan.kind == generatedLifecycleAutomaticPark
	if !ok || contract.Hash(plan.result) != plan.evidence || !park && !bytes.Equal(a.result, plan.result) {
		return nil, contract.ErrRecord
	}
	var closure generatedRetirementClose
	var parking generatedResidueClosure
	if park {
		parking, err = g.generatedRetirementAmbiguity(ctx, x.DutyID, plan.result, false)
		closure = generatedRetirementClose{duty: parking.duty, attempt: parking.attempt, rows: parking.rows, locations: parking.locations, slices: parking.slices}
	} else {
		closure, err = g.generatedRetirementAcknowledgement(ctx, x.AttemptID, plan.identity.revision)
	}
	if err != nil {
		return nil, err
	}
	target, err := g.retirementAttemptTarget(ctx, g.bundles[0], a.record)
	if err != nil || target.ResourceDigest != plan.target {
		return nil, contract.ErrRecord
	}
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: x.ResultID, ResultBodyDigest: plan.evidence, ResultLength: uint32(len(plan.result))}
	evidence, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{reference})
	if err != nil {
		return nil, err
	}
	phaseIdentity := contract.GeneratorPhaseIdentity{RequestIdentityDigest: g.parent.RequestIdentityDigest, ObservedHEADDigest: plan.predecessorDigest, ConditionDigest: plan.context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityRetireClose, BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1, Evidence: contract.GeneratorDescriptor(evidence)}
	if park {
		phaseIdentity.TransitionKind = contract.GeneratorAuthorityRecord
		phaseIdentity.Evidence, err = generatedRetirementAmbiguityEvidence(s.root.Domain, parking, false)
		if err != nil {
			return nil, err
		}
	}
	phaseID, err := contract.GeneratorPhaseID(phaseIdentity)
	if err != nil {
		return nil, err
	}
	rows := closure.rows
	index, nextTemplate, hasNext := generatedAutomaticNext(g, int(g.phase.LineageIndex))
	terminal := !hasNext
	if hasNext {
		phase := *g.phase
		phase.PhaseID, phase.Phase = phaseID, phaseIdentity.AfterPhase
		phase.LineageIndex, phase.FrontierAttemptID = index, nextTemplate.AttemptID
		phase.Stage = contract.GeneratedStageRetainedResult
		phase.AcceptedResultID, phase.ResultDigest = contract.ID{}, contract.ID{}
		rows, err = generatedAutomaticPhaseRows(g, phase, rows)
	} else {
		rows, err = generatedAutomaticTerminalRows(g, rows)
	}
	if err != nil {
		return nil, err
	}
	// Recompute content roots after releasing the original CREATE consumers.
	rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		v, e := contract.InspectGeneratorVectorCarrier(row.Body)
		return e == nil && v.VectorKind == contract.GeneratorVectorSlices
	})
	rows, locations, sliceDescriptor, err := g.generatedCloseContent(rows)
	if err != nil {
		return nil, err
	}
	next, candidate, identity := s.beginGeneratedSuccessor(plan.identity)
	identity.Operation = g.parent.OperationID
	pointerPlan := *plan
	pointerPlan.requestIdentity = phaseID
	if !park && !closure.nonfinal {
		if err := next.clearGeneratedRetiringPointer(ctx, x.DutyID, &pointerPlan, candidate, &identity); err != nil {
			return nil, err
		}
	}
	next.root.Generated.Slices = sliceDescriptor
	if terminal {
		next.root.Generated.ActiveOwner, next.root.Generated.ActivePhase, next.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	} else {
		next.root.Generated.ActivePhase = phaseID
	}
	access := s.accessRecords()
	if !generatedRowsContainMaterial(rows, g.parent.MaterialID) {
		access = generatedLifecycleAccessRows(access, g.parent.MaterialID)
	}
	if err := generatedAutomaticAccessPreserved(s.accessRecords(), access); err != nil {
		return nil, err
	}
	if len(access) != len(s.accessRecords()) {
		if err := next.packGeneratedLifecycleAccess(access, plan.identity, candidate, &identity); err != nil {
			return nil, err
		}
	}
	if terminal {
		scope, err := generatedAutomaticInvocationScope(ctx, s, g)
		if err != nil {
			return nil, err
		}
		if park {
			for j, row := range scope.Effects {
				if row.RecordID == x.AttemptID {
					scope.Effects[j] = contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: x.AttemptID}
					scope.Effects[j].Body, err = contract.EncodeGeneratedAttemptRecord(parking.attempt.record)
					if err != nil {
						return nil, err
					}
					scope.EffectClasses[x.AttemptID] = contract.ReceiptSummaryUnknownCount
				}
			}
		}
		var duties, hazards []contract.SupportRecord
		relatedDuties, relatedHazards := make(map[contract.ID]bool), make(map[contract.ID]bool)
		for _, row := range rows {
			if row.Kind == contract.GeneratedDutySupportKind && slices.Contains(scope.RelatedDutyIDs, row.RecordID) {
				duties = append(duties, row)
				relatedDuties[row.RecordID] = true
			}
			if row.Kind == contract.GeneratedHazardSupportKind && slices.Contains(scope.RelatedHazardIDs, row.RecordID) {
				hazards = append(hazards, row)
				relatedHazards[row.RecordID] = true
			}
		}
		delta, retained, err := s.generatedTerminalMutation(ctx, generatedMutationTerminalInput{Parent: *g.parent, OperationKind: scope.OperationKind, OriginalPredecessorRevisionID: scope.OriginalPredecessorRevisionID, RequestedRevisionID: plan.identity.revision, ObservedRevisionID: plan.identity.revision, ChangedSubjects: scope.ChangedSubjects, ChangedAccess: scope.ChangedAccess, Effects: scope.Effects, Duties: duties, Hazards: hazards, EffectClasses: scope.EffectClasses, CompletionClasses: scope.CompletionClasses, RelatedDutyIDs: relatedDuties, RelatedHazardIDs: relatedHazards, Selected: true})
		if err != nil || !retained {
			return nil, contract.ErrRecord
		}
		rows, next.root.Generated.SuccessWindow, next.root.Generated.FailureWindow, next.root.Generated.ReceiptOrder, err = s.generatedReceiptSupport(rows, delta, g.parent.RequestIdentityDigest)
		if err != nil {
			return nil, err
		}
	}
	if err := s.installGeneratedLifecycleSupport(ctx, &next, rows, locations, g.bundles, plan, candidate, &identity); err != nil {
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
	var subject contract.GeneratorAuthoritySubject
	if park {
		p := *plan
		p.kind = generatedLifecycleRetirementUnknown
		subject, err = s.generatedRetirementResidueSubject(ctx, &next, g, &p, parking, phaseIdentity.Evidence, identity, head)
	} else {
		subject, err = s.generatedRetirementCloseSubject(ctx, &next, g, plan, closure, identity, head)
	}
	if err != nil {
		return nil, err
	}
	subject.OperationID, subject.RequestIdentityDigest, subject.PhaseID = g.parent.OperationID, g.parent.RequestIdentityDigest, phaseID
	subject.BeforePhase, subject.AfterPhase = phaseIdentity.BeforePhase, phaseIdentity.AfterPhase
	if park {
		subject.Purpose = contract.GeneratorAuthorityRecord
		subject.ResultDigest = plan.evidence
	}
	if err := s.finalizeGeneratedSuccessor(ctx, &next, candidate, head, subject); err != nil {
		return nil, err
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

// Cold proof checks one exact original delete close, not a new retirement
// operation. It never reconstructs a producer preparation or first-send right.
func (s *selectedGeneratedProof) validGeneratedAutomaticCloseSelection(ctx context.Context, g *generatedSelection, subject contract.GeneratorAuthoritySubject) bool {
	park := subject.Purpose == contract.GeneratorAuthorityRecord
	if g == nil || (subject.Purpose != contract.GeneratorAuthorityRetireClose && !park) || subject.BeforePhase == 0 || subject.AfterPhase != subject.BeforePhase+1 || subject.ResultDigest.IsZero() {
		return false
	}
	bundle, err := g.retainedGraph(subject.OperationID)
	if err != nil || bundle.Request.OperationKind != contract.OperationApplyDeclaration && bundle.Request.OperationKind != contract.OperationRotateValueEntryValue {
		return false
	}
	var exact contract.GeneratorAttemptTemplate
	for _, index := range contract.GeneratedAutomaticRetirementIndices(bundle) {
		x := bundle.Lineages[index].Templates[0]
		if x.AttemptID == subject.AttemptID {
			exact = x
		}
	}
	if exact.AttemptID.IsZero() || subject.OwnerID != exact.DutyID || subject.LineageID != exact.LineageID || subject.ResultID != exact.ResultID || subject.ConfigContractID != exact.ConfigContractID || subject.DescriptorID != exact.DescriptorID || subject.ResultContractID != exact.ResultContractID {
		return false
	}
	var phaseEvidence contract.GeneratorDescriptor
	nonfinal := false
	if park {
		a, ok := g.attempts[exact.AttemptID]
		drow, present := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, exact.DutyID}]
		d, e := contract.InspectGeneratedDutyRecord(drow.Body)
		if !ok || !present || e != nil || a.record.State != contract.GeneratedEffectUnknown || a.record.Stage != contract.GeneratedStageTerminal || len(a.result) != 0 || d.Status != contract.GeneratedEffectUnknown {
			return false
		}
		facts, e := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, a.record.Facts)
		if e != nil || len(facts) != 1 {
			return false
		}
		fact, e := contract.InspectGeneratorFactsRow(facts[0])
		if e != nil || contract.Hash(fact.Facts) != subject.ResultDigest {
			return false
		}
		phaseEvidence, e = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, s.root.Domain, []contract.SupportRecord{drow})
		if e != nil {
			return false
		}
		empty, e := contract.GeneratorResultReferencesDescriptor(nil)
		if e != nil || subject.ResultVector != contract.GeneratorDescriptor(empty) {
			return false
		}
	} else {
		released, ok := g.releases[exact.AttemptID]
		length := released.release.ObjectLength
		if ok {
			if released.attempt.State != contract.GeneratedEffectSucceeded || released.release.SelectedHandoffDigest != subject.ResultDigest || released.release.HandoffRevisionID != s.head.Core.Revision {
				return false
			}
		} else {
			a, present := g.attempts[exact.AttemptID]
			row, dutyPresent := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, exact.DutyID}]
			d, e := contract.InspectGeneratedDutyRecord(row.Body)
			if !present || !dutyPresent || e != nil || a.record.CompletionClass != contract.GeneratedCompletionConfirmed || a.record.State != contract.GeneratedEffectSucceeded || len(a.result) == 0 || contract.Hash(a.result) != subject.ResultDigest {
				return false
			}
			progress, e := g.controlledRetirementProgress(d, nil, true)
			if e != nil || progress.contradiction || len(progress.rows) != 1 {
				return false
			}
			nonfinal = true
			length = uint32(len(a.result))
		}
		evidence, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{{Schema: 1, ResultID: exact.ResultID, ResultBodyDigest: subject.ResultDigest, ResultLength: length}})
		if err != nil || subject.ResultVector != contract.GeneratorDescriptor(evidence) {
			return false
		}
		phaseEvidence = contract.GeneratorDescriptor(evidence)
	}
	phase, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest, ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest, TransitionKind: subject.Purpose, BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: phaseEvidence})
	if err != nil || phase != subject.PhaseID {
		return false
	}
	if generatedSelectionAnchored(g) {
		if g.phase.PhaseID != phase || g.phase.Phase != subject.AfterPhase || g.parent.RequestIdentityDigest != subject.RequestIdentityDigest {
			return false
		}
	} else {
		windows, err := s.receiptWindows(ctx)
		if err != nil {
			return false
		}
		found := false
		for _, list := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
			for _, row := range list {
				if row.OperationID == subject.OperationID {
					if found || row.RequestIdentityDigest != subject.RequestIdentityDigest || row.RequestedRevisionID != s.head.Core.Revision || row.OperationKind != bundle.Request.OperationKind || row.CanonicalOutcome != contract.ReceiptCanonicalSelected {
						return false
					}
					found = true
				}
			}
		}
		if !found {
			return false
		}
	}
	use, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil || use != subject.UsePlanDigest || bundle.UsePlan.PlanGraphID != subject.PlanGraphID || bundle.Request.Declaration != subject.Intent {
		return false
	}
	changes, membershipRows := s.generatedUnchangedEntryUnion(), s.generatedUnchangedEntryUnion()
	var changedPages []contract.IdentityPage
	if !park && !nonfinal {
		pointerSubject := subject
		pointerSubject.RequestIdentityDigest = phase
		var ok bool
		changes, membershipRows, changedPages, ok = s.generatedReleasedRetirementEntryProjections(bundle, pointerSubject)
		if !ok {
			return false
		}
	}
	union, err := contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, changes)
	if err != nil || union != subject.ValueEntryUnion {
		return false
	}
	for i := range membershipRows {
		membershipRows[i].After.EntryDigest = contract.ID{}
	}
	membership, err := contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membershipRows)
	if err != nil || membership != subject.MembershipChanges || generatedMembershipAuthority(membershipRows) != subject.RequiredAuthoritySet {
		return false
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: s.root.Snapshot, Transition: s.root.Transition, Revision: s.head.Core.Revision, Pages: changedPages}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		if subject.BeforeAccessDigest != subject.AfterAccessDigest {
			identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
		}
	}
	for _, ref := range s.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(identity)
	return err == nil && descriptor == subject.IdentityPlan
}

func (s *StateSession) generatedAutomaticParkPlan(ctx context.Context, admitted contract.ApplyContext, facts []byte) (*generatedLifecyclePlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if !generatedSelectionAnchored(g) {
		return nil, contract.ErrRecord
	}
	x, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok || x.AttemptID != g.phase.FrontierAttemptID {
		return nil, contract.ErrRecord
	}
	change, err := g.generatedRetirementAmbiguity(ctx, x.DutyID, facts, false)
	if err != nil {
		return nil, err
	}
	target, err := g.retirementTarget(ctx, change.duty)
	if err != nil {
		return nil, err
	}
	identity, request, err := s.freshGeneratedLifecyclePlan(ctx, contract.MaxChildPages, contract.MaxChildPages)
	if err != nil {
		return nil, err
	}
	return &generatedLifecyclePlan{kind: generatedLifecycleAutomaticPark, context: admitted, owner: x.DutyID, target: target.ResourceDigest, evidence: contract.Hash(facts), requestIdentity: request, predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token, identity: identity, result: bytes.Clone(facts), source: observationSource{ParentID: g.parent.OperationID, AttemptID: x.AttemptID}}, nil
}
