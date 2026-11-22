package core

import (
	"context"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedRetirementAmbiguityEvidence(domain contract.ID, change generatedResidueClosure, residue bool) (contract.GeneratorDescriptor, error) {
	kind, set, id := uint8(contract.GeneratedDutySupportKind), contract.GeneratorPhaseDuties, change.duty.DutyID
	body, err := contract.EncodeGeneratedDutyRecord(change.duty)
	if residue {
		kind, set, id = contract.GeneratedHazardSupportKind, contract.GeneratorPhaseHazards, change.hazard.HazardID
		body, err = contract.EncodeGeneratedHazardRecord(change.hazard)
	}
	if err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	return contract.GeneratorRecordSetDescriptor(set, domain, []contract.SupportRecord{{Kind: kind, RecordID: id, Body: body}})
}

func (s *StateSession) generatedAmbiguityReceiptSupport(ctx context.Context, g *generatedSelection, change generatedResidueClosure,
	plan *generatedLifecyclePlan, rows []contract.SupportRecord, revision contract.ID, detail *changeObservation) ([]contract.SupportRecord, contract.GeneratorDescriptor, contract.GeneratorDescriptor, contract.GeneratorDescriptor, error) {
	if plan.kind == generatedLifecycleRetirementResidue {
		return s.generatedResidueReceiptSupport(ctx, g, change, plan, rows, revision, detail)
	}
	var zero contract.GeneratorDescriptor
	if plan.kind != generatedLifecycleRetirementUnknown || g.parent == nil || g.bundles[0].Request.OperationKind != contract.OperationRetireGeneratedGeneration {
		return nil, zero, zero, zero, contract.ErrRecord
	}
	changed, err := generatedChangedSubjects(ctx, s, s, detail)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	if projection := detail; projection != nil {
		generatedObservationOriginal(projection, g.bundles[0].Request, change.attempt.record)
	}
	access, err := contract.AccessChangeDescriptor(s.root.Domain, nil)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	var effects, duties []contract.SupportRecord
	for _, row := range rows {
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == change.attempt.record.AttemptID {
			effects = append(effects, row)
		}
		if row.Kind == contract.GeneratedDutySupportKind && row.RecordID == change.duty.DutyID {
			duties = append(duties, row)
		}
	}
	observation, err := inspectRetirementAttemptFacts(plan.result, g.attempts[change.attempt.record.AttemptID])
	if err != nil {
		return nil, zero, zero, zero, err
	}
	delta, retained, err := s.generatedTerminalMutation(ctx, generatedMutationTerminalInput{Parent: *g.parent, OperationKind: contract.OperationRetireGeneratedGeneration,
		RetirementResourceRejected:    observation.RetirementRejected,
		OriginalPredecessorRevisionID: g.bundles[0].Request.PredecessorRevisionID, RequestedRevisionID: revision, ObservedRevisionID: s.head.Core.Revision,
		ChangedSubjects: changed, ChangedAccess: access, Effects: effects, Duties: duties,
		EffectClasses:  map[contract.ID]int{change.attempt.record.AttemptID: contract.ReceiptSummaryUnknownCount},
		RelatedDutyIDs: map[contract.ID]bool{change.duty.DutyID: true}, Selected: false})
	if err != nil {
		return nil, zero, zero, zero, err
	}
	if !retained {
		return nil, zero, zero, zero, contract.ErrRecord
	}
	return s.generatedReceiptSupport(rows, delta, g.parent.RequestIdentityDigest)
}

func (s *StateSession) generatedRetirementReceiptSupport(ctx context.Context, g *generatedSelection, attemptID contract.ID,
	rows []contract.SupportRecord, revision contract.ID, detail *changeObservation) ([]contract.SupportRecord, contract.GeneratorDescriptor, contract.GeneratorDescriptor, contract.GeneratorDescriptor, error) {
	var zero contract.GeneratorDescriptor
	if g == nil || g.parent == nil || g.bundles[0].Request.OperationKind != contract.OperationRetireGeneratedGeneration {
		return nil, zero, zero, zero, contract.ErrRecord
	}
	a, ok := g.attempts[attemptID]
	if !ok || a.expected.Template.Action != contract.GeneratorActionDelete || a.record.State != contract.GeneratedEffectSucceeded && a.record.State != contract.GeneratedEffectFailedTerminal {
		return nil, zero, zero, zero, contract.ErrRecord
	}
	if a.record.CompletionClass == contract.GeneratedCompletionConfirmed {
		d, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.record.OwnerID}].Body)
		if err != nil {
			return nil, zero, zero, zero, err
		}
		progress, err := g.controlledRetirementProgress(d, nil, true)
		if err != nil {
			return nil, zero, zero, zero, err
		}
		if len(progress.rows) != 2 || progress.contradiction {
			return rows, s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder, nil
		}
	}
	changed, err := s.generatedRetiringChangeObservation(ctx, a.record.OwnerID, detail)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	if projection := detail; projection != nil {
		generatedObservationOriginal(projection, g.bundles[0].Request, a.record)
	}
	access, err := contract.AccessChangeDescriptor(s.root.Domain, nil)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	delta, retained, err := s.generatedTerminalMutation(ctx, generatedMutationTerminalInput{Parent: *g.parent, OperationKind: contract.OperationRetireGeneratedGeneration,
		OriginalPredecessorRevisionID: g.bundles[0].Request.PredecessorRevisionID, RequestedRevisionID: revision,
		ObservedRevisionID: revision, ChangedSubjects: changed, ChangedAccess: access,
		Effects:           []contract.SupportRecord{g.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, attemptID}]},
		EffectClasses:     map[contract.ID]int{attemptID: contract.ReceiptSummarySuccessCount},
		CompletionClasses: map[contract.ID]uint8{attemptID: a.record.CompletionClass}, Selected: true})
	if err != nil {
		return nil, zero, zero, zero, err
	}
	if !retained {
		return nil, zero, zero, zero, contract.ErrRecord
	}
	return s.generatedReceiptSupport(rows, delta, g.parent.RequestIdentityDigest)
}

func (s *StateSession) generatedResidueReceiptSupport(ctx context.Context, g *generatedSelection, change generatedResidueClosure,
	plan *generatedLifecyclePlan, rows []contract.SupportRecord, revision contract.ID, detail *changeObservation) ([]contract.SupportRecord, contract.GeneratorDescriptor, contract.GeneratorDescriptor, contract.GeneratorDescriptor, error) {
	var zero contract.GeneratorDescriptor
	bundle, err := g.retainedGraph(change.attempt.record.OperationID)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	request := generatedRetirementResidueRequest(s, bundle.Request, plan)
	core, err := contract.GeneratorRequestCoreDigest(request)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	material, err := contract.GeneratorMaterialID(s.root.Domain, request.OperationID)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	graph, err := contract.GeneratorPlanBundleDescriptor(bundle)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	use, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	entryUnion, err := contract.GeneratorValueEntryPlansDescriptor(bundle.ValueEntryPlans)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	parent := contract.GeneratedParentRecord{Schema: contract.GeneratedParentSchema, DomainID: s.root.Domain, OperationID: request.OperationID,
		RequestIdentityDigest: plan.requestIdentity, RequestCoreDigest: core, PlanGraphID: bundle.UsePlan.PlanGraphID,
		UsePlanDigest: use, MaterialID: material,
		RecoveryPolicyID: request.RecoveryPolicyID, ValueEntryPlanCount: bundle.Header.ValueEntryPlanCount,
		LineageCount: bundle.Header.LineageCount, TemplateCount: bundle.Header.TemplateCount, Declaration: request.Declaration,
		Registry: request.Registry, Graph: graph, SourceUses: bundle.UsePlan.SourceUses, IntendedEntryPlans: entryUnion,
		Capacity: change.duty.CapacityReservation, InitialPredecessorDigest: request.PredecessorHEADDigest, ConditionDigest: request.ConditionDigest}
	changed, err := s.generatedRetiringChangeObservation(ctx, change.duty.DutyID, detail)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	if projection := detail; projection != nil {
		generatedObservationOriginal(projection, bundle.Request, change.attempt.record)
	}
	access, err := contract.AccessChangeDescriptor(s.root.Domain, nil)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	var hazardRows []contract.SupportRecord
	for _, row := range rows {
		if row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == change.hazard.HazardID {
			hazardRows = append(hazardRows, row)
		}
	}
	delta, retained, err := s.generatedTerminalMutation(ctx, generatedMutationTerminalInput{Parent: parent, OperationKind: contract.OperationAcceptGeneratedRetirementResidue,
		OriginalPredecessorRevisionID: s.head.Core.Revision, RequestedRevisionID: revision, ObservedRevisionID: revision,
		ChangedSubjects: changed, ChangedAccess: access, Hazards: hazardRows,
		RelatedHazardIDs: map[contract.ID]bool{change.hazard.HazardID: true}, Selected: true})
	if err != nil {
		return nil, zero, zero, zero, err
	}
	if !retained {
		return nil, zero, zero, zero, contract.ErrRecord
	}
	return s.generatedReceiptSupport(rows, delta, plan.requestIdentity)
}

func (s *StateSession) generatedRetiringChangedSubjects(ctx context.Context, duty contract.ID) (contract.GeneratorDescriptor, error) {
	return s.generatedRetiringChangeObservation(ctx, duty, nil)
}

func (s *StateSession) generatedRetiringChangeObservation(ctx context.Context, duty contract.ID, detail *changeObservation) (contract.GeneratorDescriptor, error) {
	next := *s
	for i, page := range s.pages {
		if page == nil {
			continue
		}
		pageCopy := *page
		for j, entry := range page.Slots {
			if entry != nil && entry.ValueSource == contract.Generated && entry.Generated.RetiringDutyPresent == 1 && entry.Generated.RetiringDutyID == duty {
				value := *entry
				value.Generated.RetiringDutyPresent, value.Generated.RetiringDutyID = 0, contract.ID{}
				pageCopy.Slots[j] = &value
			}
		}
		next.pages[i] = &pageCopy
	}
	return generatedChangedSubjects(ctx, s, &next, detail)
}

// Cold authentication reconstructs the lifecycle-only before entry. Both
// acknowledged retirement and residue release the same per-name slot pointer.
func (s *selectedGeneratedProof) generatedReleasedRetirementEntryProjections(bundle contract.GeneratorPlanBundle,
	subject contract.GeneratorAuthoritySubject) ([]contract.UnionRow, []contract.UnionRow, []contract.IdentityPage, bool) {
	changes, membershipRows := s.generatedUnchangedEntryUnion(), s.generatedUnchangedEntryUnion()
	var name string
	found := false
	for _, lineage := range bundle.Lineages {
		if lineage.LineageID == subject.LineageID && lineage.Purpose == contract.GeneratorLineageRetirement {
			name = lineage.Name
			found = true
		}
	}
	if !found {
		return nil, nil, nil, false
	}
	var pages []contract.IdentityPage
	for i, entry := range s.root.Names {
		if entry.Name != name {
			continue
		}
		current := s.valueEntry(entry.Slot)
		if current == nil {
			return nil, nil, nil, false
		}
		if current.ValueSource != contract.Generated {
			continue
		}
		if current.Generated.RetiringDutyPresent != 0 || !current.Generated.RetiringDutyID.IsZero() {
			return nil, nil, nil, false
		}
		old := *current
		old.Generated.RetiringDutyPresent, old.Generated.RetiringDutyID = 1, subject.OwnerID
		prior := membership(s.root.Domain, entry.Slot, &old).Side()
		changes[i].Before = prior
		membershipRows[i].Before, membershipRows[i].After = prior, prior
		ref := s.root.ValueEntryPages[entry.Slot/format.PageSlots]
		if ref == nil {
			return nil, nil, nil, false
		}
		page, err := contract.GeneratorPhasePageID(subject.RequestIdentityDigest, format.ValueEntryPageKind, ref.Index)
		if err != nil || page != ref.Object {
			return nil, nil, nil, false
		}
		pages = append(pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	return changes, membershipRows, pages, true
}

// Clearing this pointer changes lifecycle metadata only. It preserves the new
// selected value, incarnation, epoch, membership and every ciphertext byte.
func (s *StateSession) clearGeneratedRetiringPointer(ctx context.Context, duty contract.ID, plan *generatedLifecyclePlan,
	candidate *Candidate, identity *contract.IdentityPlan) error {
	used, err := candidate.session.closureIDsMode(ctx, false)
	if err != nil {
		return err
	}
	for i, current := range s.pages {
		if current == nil {
			continue
		}
		var page *format.ValueEntryPage
		for j, entry := range current.Slots {
			if entry == nil || entry.ValueSource != contract.Generated || entry.Generated.RetiringDutyPresent != 1 || entry.Generated.RetiringDutyID != duty {
				continue
			}
			if page == nil {
				pageCopy := *current
				page = &pageCopy
				var err error
				page.Object, err = contract.GeneratorPhasePageID(plan.requestIdentity, format.ValueEntryPageKind, uint16(i))
				if err != nil || used[page.Object] {
					return contract.ErrRecord
				}
			}
			entryCopy := *entry
			entryCopy.Generated.RetiringDutyPresent, entryCopy.Generated.RetiringDutyID = 0, contract.ID{}
			page.Slots[j] = &entryCopy
		}
		if page != nil {
			body, err := format.EncodeValueEntryPage(*page)
			if err != nil {
				return err
			}
			ref, err := format.Reference(format.ValueEntryPageKind, s.root.Domain, page.Object, uint16(i), body)
			if err != nil {
				return err
			}
			s.pages[i], s.root.ValueEntryPages[i] = page, &ref
			candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
			identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: format.ValueEntryPageKind, Index: uint16(i), Object: page.Object})
		}
	}
	return nil
}

// Residue acceptance has its own public v3 request. The retained apply graph
// continues to describe its original v4 output commitment without alteration.
func generatedRetirementResidueRequest(before *StateSession, original contract.GeneratorRequestCore, plan *generatedLifecyclePlan) contract.GeneratorRequestCore {
	return contract.GeneratorRequestCore{
		Schema: contract.GeneratorPublicRequestCoreSchema, OperationKind: contract.OperationAcceptGeneratedRetirementResidue,
		DomainID: before.root.Domain, OperationID: plan.identity.operation,
		PredecessorRevisionID: before.head.Core.Revision, PredecessorHEADDigest: contract.Hash(before.body),
		ConditionDigest: plan.context.OriginalConditionDigest, CallerNonce: plan.requestIdentity,
		Declaration: original.Declaration, Registry: original.Registry,
		CompatibilityID: original.CompatibilityID, RecoveryPolicyID: contract.GeneratorRecoveryPolicyID(),
	}
}
