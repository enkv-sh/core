package core

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedRecordPlan struct {
	failureReason uint8
	request       contract.CryptoGeneratedCompareRequest
	phase         contract.GeneratorPhaseIdentity
	expected      contract.GeneratorResultExpectation
	reference     contract.GeneratorResultReference
	result        []byte
}

func (s *StateSession) generatedContextValid(c contract.ApplyContext) bool {
	if s == nil || c.OperationClass != contract.CryptoGeneratedClass || c.AdmissionID.IsZero() || c.SessionID.IsZero() ||
		c.IntentDescriptor != (contract.DescriptorVector{}) || c.Expiry > uint64(math.MaxInt64) || !validPrivateDeadline(time.Unix(0, int64(c.Expiry))) ||
		c.DomainID != s.admission.domain ||
		c.CompatibilityID != s.root.CurrentAccess.Core.CompatibilityID || c.CurrentAccessRoot != s.root.CurrentAccess.AccessRoot || c.PredecessorHEADDigest != contract.Hash(s.body) {
		return false
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil || !bytes.Equal(root, c.PredecessorRootRef[:]) {
		return false
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	return err == nil && condition == c.OriginalConditionDigest
}

func (s *StateSession) generatedRecordRequest(ctx context.Context, attempt contract.ID, result []byte, admitted contract.ApplyContext) (*generatedRecordPlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if g.parent == nil || g.phase == nil || g.phase.Phase == math.MaxUint32 || g.phase.FrontierAttemptID != attempt {
		return nil, contract.ErrRecord
	}
	a, ok := g.attempts[attempt]
	if !ok || generatedSelectionAnchored(g) && a.expected.Template.Action != contract.GeneratorActionDelete || !a.awaitingResult() {
		return nil, contract.ErrRecord
	}
	r, err := contract.DecodeGeneratedResultRecord(result)
	if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, r) != nil {
		return nil, contract.ErrRecord
	}
	if a.expected.Template.Action == contract.GeneratorActionDelete && a.record.CompletionClass == contract.GeneratedCompletionConfirmed {
		source, err := g.generatedDeleteSource(a.record.OwnerID)
		pending := a
		pending.result = result
		if err != nil {
			return nil, err
		}
		if _, err := g.controlledDeleteSourceProgress(source, &pending, false); err != nil {
			return nil, err
		}
	}
	p := *g.parent
	q := contract.CryptoGeneratedCompareRequest{Context: admitted, Purpose: contract.CryptoGeneratedAdoptionPurpose, Parent: p, PlanGraph: p.Graph, UsePlanDigest: p.UsePlanDigest,
		MaterialID: p.MaterialID, AcceptedSources: p.SourceUses, IntendedEntryPlans: p.IntendedEntryPlans}
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		return nil, err
	}
	if _, err := contract.EncodeCryptoGeneratedCompareRequest(q); err != nil {
		return nil, err
	}
	kind := contract.GeneratorAuthorityRecord
	if r.SafeFacts.Disposition == contract.GeneratorDispositionConfirmedNoEffect && a.expected.Template.Action == contract.GeneratorActionCreate {
		kind = contract.GeneratorAuthorityNoEffectBranch
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: p.RequestIdentityDigest, ObservedHEADDigest: admitted.PredecessorHEADDigest,
		ConditionDigest: admitted.OriginalConditionDigest, TransitionKind: kind, BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1,
		Evidence: contract.GeneratorDescriptor{Digest: contract.Hash(result), Length: uint64(len(result)), Count: 1}}
	if _, err := contract.GeneratorPhaseID(phase); err != nil {
		return nil, err
	}
	return &generatedRecordPlan{request: q, phase: phase, expected: a.expected, result: bytes.Clone(result),
		reference: contract.GeneratorResultReference{Schema: 1, ResultID: r.Core.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}}, nil
}

// generatedLocalFailureRequest derives public transition facts only. The original
// joined receiver separately grants custody for this exact request.
func (s *StateSession) generatedLocalFailureRequest(ctx context.Context, attempt contract.ID, reason uint8, admitted contract.ApplyContext) (*generatedRecordPlan, error) {
	if s == nil || s.prepared || !s.generatedContextValid(admitted) || !contract.GeneratorLocalFailureReasonValid(reason) {
		return nil, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if g.parent == nil || g.phase == nil || generatedSelectionAnchored(g) || g.phase.Phase == math.MaxUint32 || g.phase.FrontierAttemptID != attempt {
		return nil, contract.ErrRecord
	}
	a, ok := g.attempts[attempt]
	if !ok || a.expected.Template.SemanticLifecycleMode() != contract.GeneratorLifecycleNone || a.expected.Template.Action != contract.GeneratorActionCreate ||
		a.expected.Template.Branch != contract.GeneratorBranchInitial || !a.expected.Template.PredecessorAttemptID.IsZero() ||
		a.record.State != contract.GeneratedEffectTransmitted || a.record.Stage != contract.GeneratedStageRetainedResult || a.record.RetryUsed != 0 || a.record.FailureReason != 0 ||
		len(a.result) != 0 || a.record.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) {
		return nil, contract.ErrRecord
	}
	terminal := a.record
	terminal.State, terminal.Stage, terminal.FailureReason = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal, reason
	body, err := contract.EncodeGeneratedAttemptRecord(terminal)
	if err != nil || len(body) != contract.GeneratedAttemptRecordFixedLength {
		return nil, contract.ErrRecord
	}
	p := *g.parent
	q := contract.CryptoGeneratedCompareRequest{Context: admitted, Purpose: contract.CryptoGeneratedAdoptionPurpose, Parent: p, PlanGraph: p.Graph, UsePlanDigest: p.UsePlanDigest,
		MaterialID: p.MaterialID, AcceptedSources: p.SourceUses, IntendedEntryPlans: p.IntendedEntryPlans}
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		return nil, err
	}
	if _, err := contract.EncodeCryptoGeneratedCompareRequest(q); err != nil {
		return nil, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: p.RequestIdentityDigest, ObservedHEADDigest: admitted.PredecessorHEADDigest,
		ConditionDigest: admitted.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityFailedTerminal, BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1,
		Evidence: contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: uint64(len(body)), Count: 1}}
	if _, err := contract.GeneratorPhaseID(phase); err != nil {
		return nil, err
	}
	return &generatedRecordPlan{request: q, phase: phase, expected: a.expected, failureReason: reason}, nil
}

func (s *StateSession) deriveGeneratedRecord(ctx context.Context, plan *generatedRecordPlan) (*generatedReservation, error) {
	if plan == nil {
		return nil, contract.ErrRecord
	}
	c := plan.request.Context
	c.IntentDescriptor = contract.DescriptorVector{}
	var checked *generatedRecordPlan
	var err error
	if plan.failureReason != 0 {
		if len(plan.result) != 0 || plan.reference != (contract.GeneratorResultReference{}) {
			return nil, contract.ErrRecord
		}
		checked, err = s.generatedLocalFailureRequest(ctx, plan.expected.Template.AttemptID, plan.failureReason, c)
	} else {
		checked, err = s.generatedRecordRequest(ctx, plan.expected.Template.AttemptID, plan.result, c)
	}
	if err != nil {
		return nil, fmt.Errorf("generated record request: %w", err)
	}
	if checked.request != plan.request || checked.phase != plan.phase || checked.expected != plan.expected || checked.reference != plan.reference || checked.failureReason != plan.failureReason {
		return nil, fmt.Errorf("generated record request: %w", contract.ErrRecord)
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, fmt.Errorf("generated record selected work: %w", err)
	}
	phaseID, err := contract.GeneratorPhaseID(plan.phase)
	if err != nil {
		return nil, err
	}
	rows, err := generatedRecordedRows(g, plan, phaseID)
	if err != nil {
		return nil, fmt.Errorf("generated record rows: %w", err)
	}
	next := *s
	next.cache, next.accessLocations, next.valueReaders = nil, nil, nil
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
		return nil, fmt.Errorf("generated record snapshot slices: %w", err)
	}
	locations, err := s.resolveSelectedGeneratedSlices()
	if err != nil {
		return nil, fmt.Errorf("generated record slices: %w", err)
	}
	groups, err := generatedReservationGroupsWithSource(&next, s, rows, locations, g.bundles)
	if err != nil {
		return nil, fmt.Errorf("generated record groups: %w", err)
	}
	next.root.RequiredSupport, next.support = nil, nil
	next.root.Generated.ActivePhase = phaseID
	generatedRefreshClosureCounts(&next.root.Generated, rows)
	next.recountChildren()
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, fmt.Errorf("generated record fragment facts: %w", err)
	}
	packed, err := generatedSupportPages(s.root.Domain, groups, next.root.ChildCount, fragments)
	if err != nil {
		return nil, fmt.Errorf("generated record pack: %w", err)
	}
	identity := contract.IdentityPlan{Operation: g.parent.OperationID, Snapshot: next.root.Snapshot, Transition: next.root.Transition, Revision: revision}
	candidate := &Candidate{session: s}
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
		return nil, fmt.Errorf("generated record materialize: %w", err)
	}
	next.root.RequiredSupport, next.support = materialized.references, materialized.views
	next.root.RequiredSupportRecordCount, next.root.Generated.Fragments = materialized.recordCount, materialized.fragments
	next.clearSelectedSupportFacts()
	candidate.objects = append(candidate.objects, materialized.objects...)
	identity.Pages = append(identity.Pages, materialized.identityPages...)
	if err := s.installAdministrativeIndexWithBundles(ctx, &next, candidate, g.bundles); err != nil {
		return nil, fmt.Errorf("generated record administrative index: %w", err)
	}
	if !next.indexSelectedMaterials() || !validAggregate(next.root) {
		return nil, contract.ErrRecord
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		return nil, fmt.Errorf("generated record selected relations: %w", err)
	}
	body, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, err
	}
	ref, err := format.Reference(format.RootKind, s.root.Domain, next.root.Snapshot, 0, body)
	if err != nil {
		return nil, err
	}
	candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	head := s.successorCore(transitionPlan{revision: revision})
	head.Root = ref
	subject, err := s.generatedRecordSubject(ctx, &next, g, plan, identity, head)
	if err != nil {
		return nil, fmt.Errorf("generated record subject: %w", err)
	}
	candidate.head = format.Head{Core: head, AuthKind: format.GeneratorAuth, Generator: &subject, K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = candidate.head
	if err := s.generatedAutomaticCandidatePreserved(&next); err != nil {
		return nil, err
	}
	return &generatedReservation{state: &next, candidate: candidate}, nil
}

func generatedRecordedRows(g *generatedSelection, plan *generatedRecordPlan, phaseID contract.ID) ([]contract.SupportRecord, error) {
	if plan.failureReason != 0 {
		return generatedLocalFailureRows(g, plan, phaseID)
	}
	a := g.attempts[plan.expected.Template.AttemptID].record
	var source contract.GeneratedDeleteSource
	var d contract.GeneratedDutyRecord
	var h contract.GeneratedHazardRecord
	var kind uint8
	var owner contract.ID
	var err error
	if a.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
		row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.OwnerID}]
		if !ok {
			return nil, contract.ErrRecord
		}
		d, err = contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || d.SemanticLifecycleMode() != contract.GeneratorLifecycleNone || d.Kind != contract.GeneratedDutyCreate {
			return nil, contract.ErrRecord
		}
		kind, owner = row.Kind, row.RecordID
	} else {
		source, err = g.generatedDeleteSource(a.OwnerID)
		if err != nil {
			return nil, err
		}
		d, h, kind, owner = source.Duty, source.Hazard, source.Record.Kind, source.SourceID
	}
	r, err := contract.DecodeGeneratedResultRecord(plan.result)
	if err != nil {
		return nil, err
	}
	a.State, a.Stage = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal
	switch r.Disposition() {
	case contract.GeneratorDispositionCompleteCreate:
	case contract.GeneratorDispositionOwnedUnusableCreate:
		a.State = contract.GeneratedEffectFailedTerminal
	case contract.GeneratorDispositionConfirmedNoEffect:
		a.State = contract.GeneratedEffectConfirmedNoEffect
	case contract.GeneratorDispositionRetirementAcknowledged:
	case contract.GeneratorDispositionScopedUnusability:
	case contract.GeneratorDispositionContinuedUsability, contract.GeneratorDispositionConflictingBinding:
		a.State = contract.GeneratedEffectFailedTerminal
	default:
		return nil, contract.ErrRecord
	}
	updateDutyHistory := true
	if kind == contract.GeneratedDutySupportKind && (plan.expected.Template.Action == contract.GeneratorActionCreate || d.Kind == contract.GeneratedDutyRetirement) {
		d.Status = a.State
	}
	facts, err := contract.EncodeGeneratorSafeFacts(r.SafeFacts)
	if err != nil {
		return nil, err
	}
	fact, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.ResultID, Facts: facts})
	if err != nil {
		return nil, err
	}
	var extra []contract.SupportRecord
	a.Facts, extra, err = generatedCarrierRows(g.parent.DomainID, contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorFacts, [][]byte{fact})
	if err != nil {
		return nil, err
	}
	var carriers []contract.SupportRecord
	if plan.expected.Template.Action == contract.GeneratorActionCreate && r.SafeFacts.LifecycleMode == contract.GeneratorLifecycleManaged && len(r.SafeFacts.Target) > 0 && len(r.SafeFacts.ResourceData) > 0 {
		lineage := g.bundles[0].Lineages[g.phase.LineageIndex]
		resourceDigest, err := contract.GeneratorResourceDigest(r.SafeFacts)
		if err != nil {
			return nil, err
		}
		target, err := contract.EncodeGeneratorTarget(contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: lineage.Name, IncarnationID: lineage.EntryIncarnationID,
			Epoch: lineage.Epoch, ResourceID: a.ResourceID, ResourceDigest: resourceDigest, ConfigContractID: a.ConfigContractID,
			ResourceContractID: a.ResourceContractID, OriginalOperationID: a.OperationID, OriginalAttemptID: a.AttemptID, ResultContractID: a.ResultContractID, CompletionClass: a.CompletionClass})
		if err != nil {
			return nil, err
		}
		d.Target, carriers, err = generatedCarrierRows(g.parent.DomainID, contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorTargets, [][]byte{target})
		if err != nil {
			return nil, err
		}
	}
	extras := append(extra, carriers...)
	if plan.expected.Template.Action == contract.GeneratorActionDelete && source.CompletionClass == contract.GeneratedCompletionConfirmed {
		pending := g.attempts[a.AttemptID]
		pending.record = a
		pending.result = plan.result
		progress, err := g.controlledDeleteSourceProgress(source, &pending, false)
		if err != nil {
			return nil, fmt.Errorf("record controlled progress: %w", err)
		}
		if kind == contract.GeneratedDutySupportKind && len(progress.rows) > 0 {
			d.Step = 2
		}
		if kind == contract.GeneratedHazardSupportKind && progress.contradiction {
			h.Eligibility = 0
		}
		attemptProgress := progress.rows
		if r.SafeFacts.Disposition == contract.GeneratorDispositionRetirementAcknowledged {
			ack, err := generatedControlledProgressRow(pending, contract.GeneratorProgressAcknowledged)
			if err != nil {
				return nil, err
			}
			attemptProgress = [][]byte{ack}
		}
		a.Progress, carriers, err = generatedCarrierRows(g.parent.DomainID, contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorProgress, attemptProgress)
		if err != nil {
			return nil, err
		}
		extras = append(extras, carriers...)
		if kind == contract.GeneratedDutySupportKind {
			d.Progress, carriers, err = generatedCarrierRows(g.parent.DomainID, contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorProgress, progress.rows)
			if err != nil {
				return nil, err
			}
			extras = append(extras, carriers...)
		}
	}
	extras = append(extras, contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: a.ResultID, Body: plan.result})
	a.History, carriers, err = generatedRecordedHistory(g, contract.GeneratedAttemptSupportKind, a.AttemptID, a.History, a, plan.reference.ResultBodyDigest)
	if err != nil {
		return nil, err
	}
	extras = append(extras, carriers...)
	if updateDutyHistory {
		history := source.History
		if a.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			history = d.History
		}
		history, carriers, err = generatedRecordedHistory(g, kind, owner, history, a, plan.reference.ResultBodyDigest)
		if err != nil {
			return nil, err
		}
		extras = append(extras, carriers...)
		if kind == contract.GeneratedDutySupportKind {
			d.History = history
		} else {
			h.History = history
			anchor, present := g.attempts[h.OriginalAttemptID]
			if present && anchor.expected.Template.Action == contract.GeneratorActionDelete {
				historyBodies, err := g.vectors.resolve(kind, owner, contract.GeneratorVectorHistory, source.History)
				if err != nil {
					return nil, err
				}
				var results []contract.SupportRecord
				for _, body := range historyBodies {
					entry, err := contract.InspectGeneratorHistory(body)
					if err != nil {
						return nil, err
					}
					attempt, present := g.attempts[entry.PredecessorAttemptID]
					if !present {
						return nil, contract.ErrRecord
					}
					if attempt.record.AttemptID == a.AttemptID {
						results = append(results, contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: a.ResultID, Body: plan.result})
					} else if result, present := g.records[generatedRecordKey{kind: contract.GeneratedResultSupportKind, id: attempt.record.ResultID}]; present {
						results = append(results, result)
					}
				}
				h.OriginalResults, err = generatedHazardResultsDescriptor(h.DomainID, results)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	attempt, err := contract.EncodeGeneratedAttemptRecord(a)
	if err != nil {
		return nil, err
	}
	var duty []byte
	if kind == contract.GeneratedDutySupportKind {
		duty, err = contract.EncodeGeneratedDutyRecord(d)
	} else {
		duty, err = contract.EncodeGeneratedHazardRecord(h)
	}
	if err != nil {
		return nil, err
	}
	var rows []contract.SupportRecord
	for _, row := range g.image.supportRecords() {
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			if v.VectorKind == contract.GeneratorVectorHistory && (v.OwnerKind == contract.GeneratedAttemptSupportKind && v.OwnerID == a.AttemptID || updateDutyHistory && v.OwnerKind == kind && v.OwnerID == owner) {
				continue
			}
			if v.VectorKind == contract.GeneratorVectorProgress && plan.expected.Template.Action == contract.GeneratorActionDelete && source.CompletionClass == contract.GeneratedCompletionConfirmed && (v.OwnerKind == contract.GeneratedAttemptSupportKind && v.OwnerID == a.AttemptID || kind == contract.GeneratedDutySupportKind && v.OwnerKind == contract.GeneratedDutySupportKind && v.OwnerID == d.DutyID) {
				continue
			}
		}
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == a.AttemptID {
			row.Body = attempt
		}
		if row.Kind == kind && row.RecordID == owner {
			row.Body = duty
		}
		rows = append(rows, row)
	}
	rows = append(rows, extras...)
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	phase := *g.phase
	phase.PhaseID, phase.Phase, phase.Stage = phaseID, plan.phase.AfterPhase, a.Stage
	phase.AcceptedResultID, phase.ResultDigest = a.ResultID, plan.reference.ResultBodyDigest
	next, _, recovery := contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
	if r.SafeFacts.Disposition == contract.GeneratorDispositionConfirmedNoEffect && plan.expected.Template.Action == contract.GeneratorActionCreate {
		next, _, recovery = generatedNextNoEffect(g, plan.expected.Template)
	}
	lineageIndex := g.phase.LineageIndex
	if !recovery && plan.expected.Template.Action == contract.GeneratorActionCreate {
		lineageIndex, next, _ = generatedNextOriginalAfter(g, plan.expected.Template.LineageID)
	}
	if !next.AttemptID.IsZero() {
		if !recovery {
			pending, present := g.attempts[next.AttemptID]
			if !present || len(pending.result) != 0 || pending.record.State != contract.GeneratedEffectTransmitted {
				return nil, contract.ErrRecord
			}
		}
		phase.LineageIndex, phase.Branch = lineageIndex, next.Branch
		phase.FrontierAttemptID, phase.Stage = next.AttemptID, contract.GeneratedStageRetainedResult
		phase.NoEffectUsed, phase.ResidueUsed = 0, 0
		if next.Branch == contract.GeneratorBranchNoEffect || next.Branch >= contract.GeneratorBranchNoEffectThenResidue {
			phase.NoEffectUsed = 1
		}
		if next.Branch >= contract.GeneratorBranchResidue {
			phase.ResidueUsed = 1
		}
		phase.AcceptedResultID, phase.ResultDigest = contract.ID{}, contract.ID{}
		if recovery {
			lineageRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedLineageSupportKind, id: next.LineageID}]
			if !ok {
				return nil, contract.ErrRecord
			}
			lineage, err := contract.DecodeGeneratedLineageRecord(lineageRow.Body)
			if err != nil || lineage.Branch != plan.expected.Template.Branch || lineage.Frontier != plan.expected.Template.Branch {
				return nil, contract.ErrRecord
			}
			lineage.Branch = next.Branch
			lineage.NoEffectUsed, lineage.ResidueUsed = phase.NoEffectUsed, phase.ResidueUsed
			body, err := contract.EncodeGeneratedLineageRecord(lineage)
			if err != nil {
				return nil, err
			}
			for i := range rows {
				if rows[i].Kind == contract.GeneratedLineageSupportKind && rows[i].RecordID == next.LineageID {
					rows[i].Body = body
				}
			}
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
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == contract.GeneratedPhaseSupportKind && rows[i].RecordID == phase.OperationID {
			rows[i].Body = body
		}
	}
	return rows, nil
}

func generatedLocalFailureRows(g *generatedSelection, plan *generatedRecordPlan, phaseID contract.ID) ([]contract.SupportRecord, error) {
	a := g.attempts[plan.expected.Template.AttemptID].record
	row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.OwnerID}]
	if !ok {
		return nil, contract.ErrRecord
	}
	d, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || d.Kind != contract.GeneratedDutyCreate || !generatedCreateDutyMatches(d, a) || d.SemanticLifecycleMode() != contract.GeneratorLifecycleNone {
		return nil, contract.ErrRecord
	}
	a.State, a.Stage, a.FailureReason = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal, plan.failureReason
	d.Status = a.State
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a)
	if err != nil || plan.phase.Evidence != (contract.GeneratorDescriptor{Digest: contract.Hash(attemptBody), Length: uint64(len(attemptBody)), Count: 1}) {
		return nil, contract.ErrRecord
	}
	dutyBody, err := contract.EncodeGeneratedDutyRecord(d)
	if err != nil {
		return nil, err
	}
	var rows []contract.SupportRecord
	for _, row := range g.image.supportRecords() {
		if row.Kind == contract.GeneratedResultSupportKind && row.RecordID == a.ResultID {
			return nil, contract.ErrRecord
		}
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == a.AttemptID {
			row.Body = attemptBody
		}
		if row.Kind == contract.GeneratedDutySupportKind && row.RecordID == d.DutyID {
			row.Body = dutyBody
		}
		rows = append(rows, row)
	}
	phase := *g.phase
	phase.PhaseID, phase.Phase, phase.Stage = phaseID, plan.phase.AfterPhase, contract.GeneratedStageTerminal
	phase.AcceptedResultID, phase.ResultDigest = contract.ID{}, contract.ID{}
	if index, next, ok := generatedNextOriginalAfter(g, a.LineageID); ok {
		pending, present := g.attempts[next.AttemptID]
		if !present || len(pending.result) != 0 || pending.record.State != contract.GeneratedEffectTransmitted {
			return nil, contract.ErrRecord
		}
		phase.LineageIndex, phase.Branch = index, contract.GeneratorBranchInitial
		phase.FrontierAttemptID, phase.Stage = next.AttemptID, contract.GeneratedStageRetainedResult
		phase.NoEffectUsed, phase.ResidueUsed = 0, 0
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
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == contract.GeneratedPhaseSupportKind && rows[i].RecordID == phase.OperationID {
			rows[i].Body = body
		}
	}
	return rows, nil
}

func generatedRecordedHistory(g *generatedSelection, ownerKind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor, a contract.GeneratedAttemptRecord, resultDigest contract.ID) (contract.GeneratorDescriptor, []contract.SupportRecord, error) {
	rows, err := g.vectors.resolve(ownerKind, owner, contract.GeneratorVectorHistory, descriptor)
	if err != nil || len(rows) == 0 {
		return descriptor, nil, err
	}
	last, err := contract.InspectGeneratorHistory(rows[len(rows)-1])
	if err != nil || last.PredecessorAttemptID != a.AttemptID || !last.NextAttemptID.IsZero() || last.OwnerID != a.OwnerID {
		return contract.GeneratorDescriptor{}, nil, contract.ErrRecord
	}
	last.ResultID, last.ResultDigest, last.Outcome = a.ResultID, resultDigest, a.State
	body, err := contract.EncodeGeneratorHistory(last)
	if err != nil {
		return contract.GeneratorDescriptor{}, nil, err
	}
	rows = slices.Clone(rows)
	rows[len(rows)-1] = body
	return generatedCarrierRows(a.DomainID, ownerKind, owner, contract.GeneratorVectorHistory, rows)
}

func (s *StateSession) generatedRecordSubject(ctx context.Context, next *StateSession, g *generatedSelection, plan *generatedRecordPlan, identity contract.IdentityPlan, head format.HeadCore) (contract.GeneratorAuthoritySubject, error) {
	p, x := *g.parent, plan.expected.Template
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: plan.phase.TransitionKind, DomainID: p.DomainID, OperationID: p.OperationID,
		RequestIdentityDigest: p.RequestIdentityDigest, PlanGraphID: p.PlanGraphID, UsePlanDigest: p.UsePlanDigest, PhaseID: next.root.Generated.ActivePhase,
		PreviousHEADDigest: contract.Hash(s.body), PreviousRevisionID: s.head.Core.Revision, ConditionDigest: plan.phase.ConditionDigest,
		BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest, BeforeAccessDigest: s.root.CurrentAccess.AccessRoot,
		AfterAccessDigest: next.root.CurrentAccess.AccessRoot, OwnerID: p.OperationID, LineageID: x.LineageID, AttemptID: x.AttemptID, PredecessorAttemptID: x.PredecessorAttemptID,
		ResultID: x.ResultID, ResultDigest: plan.reference.ResultBodyDigest, ConfigContractID: x.ConfigContractID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
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
	var declaration []byte
	if s.fragmentFacts != nil {
		declaration, err = g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, p.OperationID, contract.GeneratorDeclarationMaxLength)
	} else {
		declaration, err = g.content.read(contract.GeneratorContentDeclaration, p.OperationID, contract.GeneratorDeclarationMaxLength)
	}
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
	var references []contract.GeneratorResultReference
	if plan.failureReason == 0 {
		references = []contract.GeneratorResultReference{plan.reference}
	}
	results, err := contract.GeneratorResultReferencesDescriptor(references)
	if err != nil {
		return subject, err
	}
	subject.ResultVector = contract.GeneratorDescriptor(results)
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
