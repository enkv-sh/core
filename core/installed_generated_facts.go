package core

import (
	"context"
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

func generatedPublicFactContext(ctx context.Context, g *generatedSelection) error {
	if ctx == nil || g == nil || g.image == nil {
		return contract.ErrRecord
	}
	return ctx.Err()
}

func generatedPublicProgress(g *generatedSelection, kind uint8, id contract.ID, descriptor contract.GeneratorDescriptor) ([]contract.GeneratorProgress, error) {
	if uint64(descriptor.Count) > GeneratedResultProgressLimit {
		return nil, contract.ErrRecordCapacity
	}
	rows, err := g.vectors.resolve(kind, id, contract.GeneratorVectorProgress, descriptor)
	if err != nil {
		return nil, err
	}
	return generatedPublicProgressRows(rows)
}

func generatedPublicProgressRows(rows [][]byte) ([]contract.GeneratorProgress, error) {
	if uint64(len(rows)) > GeneratedResultProgressLimit {
		return nil, contract.ErrRecordCapacity
	}
	out := make([]contract.GeneratorProgress, len(rows))
	for i, body := range rows {
		row, err := contract.InspectGeneratorProgress(body)
		if err != nil {
			return nil, err
		}
		out[i] = row
	}
	slices.SortFunc(out, func(a, b contract.GeneratorProgress) int { return int(a.CompletedSteps) - int(b.CompletedSteps) })
	return out, nil
}

func generatedPublicTarget(g *generatedSelection, kind uint8, id contract.ID, descriptor contract.GeneratorDescriptor) (*contract.GeneratorTarget, error) {
	if descriptor.Count > 1 {
		return nil, contract.ErrRecord
	}
	rows, err := g.vectors.resolve(kind, id, contract.GeneratorVectorTargets, descriptor)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	target, err := contract.InspectGeneratorTarget(rows[0])
	if err != nil {
		return nil, err
	}
	target.Name = strings.Clone(target.Name)
	return &target, nil
}

func generatedPublicGeneration(g *generatedSelection, target *contract.GeneratorTarget) (contract.ID, uint8) {
	if target == nil {
		return contract.ID{}, 0
	}
	for _, named := range g.image.root.Names {
		entry := g.image.valueEntry(named.Slot)
		if entry == nil || entry.ValueSource != contract.Generated || entry.Incarnation != target.IncarnationID {
			continue
		}
		if generatedPublicTargetMatchesEntry(target, entry) {
			return entry.Generated.GenerationID, entry.Generated.RetirementMode
		}
	}
	for _, retained := range g.canonical {
		if generatedPublicTargetMatchesEntry(target, &retained.record.Entry) {
			return retained.record.Entry.Generated.GenerationID, retained.record.Entry.Generated.RetirementMode
		}
	}
	return contract.ID{}, 0
}

// A local result has no provider target. Only exact authenticated metadata can
// establish its selected generation; a planned slot or a later same-name value
// cannot establish that relation.
func generatedPublicEffectGeneration(g *generatedSelection, effect GeneratedEffectFact) contract.ID {
	if effect.Record.SemanticLifecycleMode() != contract.GeneratorLifecycleNone {
		generation, _ := generatedPublicGeneration(g, effect.Target)
		return generation
	}
	matches := func(entry *contract.ValueEntry) bool {
		if entry == nil || entry.ValueSource != contract.Generated || entry.Name != effect.Name || entry.Incarnation != effect.EntryIncarnationID {
			return false
		}
		m, r := entry.Generated, effect.Record
		return m.SemanticLifecycleMode() == contract.GeneratorLifecycleNone && m.Epoch == effect.Epoch &&
			m.OriginOperationID == r.OperationID && m.OriginAttemptID == r.AttemptID && m.CreateResultID == r.ResultID &&
			m.ConfigContractID == r.ConfigContractID && m.ResourceContractID == r.ResourceContractID && m.ResourceIncarnationID == r.ResourceID
	}
	for _, named := range g.image.root.Names {
		if entry := g.image.valueEntry(named.Slot); matches(entry) {
			return entry.Generated.GenerationID
		}
	}
	for _, retained := range g.canonical {
		if entry := &retained.record.Entry; matches(entry) {
			return entry.Generated.GenerationID
		}
	}
	return contract.ID{}
}

func generatedPublicTargetMatchesEntry(target *contract.GeneratorTarget, entry *contract.ValueEntry) bool {
	if entry == nil || entry.ValueSource != contract.Generated || entry.Incarnation != target.IncarnationID || entry.Name != target.Name {
		return false
	}
	m := entry.Generated
	return m.Epoch == target.Epoch && m.ResourceIncarnationID == target.ResourceID && m.ConfigContractID == target.ConfigContractID && m.ResourceContractID == target.ResourceContractID && m.LifecycleMode == target.LifecycleMode && m.ResourceDigest == target.ResourceDigest && m.OriginOperationID == target.OriginalOperationID && m.OriginAttemptID == target.OriginalAttemptID
}

func generatedProgressCeiling(rows []contract.GeneratorProgress) (uint16, GeneratedResultWarnings) {
	ceiling := uint16(contract.ReceiptEvidenceCanonical)
	for _, row := range rows {
		if row.CompletedSteps == contract.GeneratorProgressConfirmed {
			return contract.ReceiptEvidenceConfirmed, GeneratedResultWarnings{}
		}
		if row.CompletedSteps == contract.GeneratorProgressAcknowledged {
			ceiling = contract.ReceiptEvidenceAcknowledged
		}
	}
	return ceiling, GeneratedResultWarnings{InvalidationNotConfirmed: ceiling == contract.ReceiptEvidenceAcknowledged}
}

func generatedDutyFact(ctx context.Context, g *generatedSelection, id contract.ID) (GeneratedDutyFact, error) {
	var out GeneratedDutyFact
	if err := generatedPublicFactContext(ctx, g); err != nil {
		return out, err
	}
	row, present := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, id}]
	if !present {
		return out, contract.ErrRecord
	}
	var err error
	out.Record, err = contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || out.Record.DutyID != id || out.Record.DomainID != g.image.root.Domain {
		return GeneratedDutyFact{}, contract.ErrRecord
	}
	if out.Record.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
		if out.Record.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) || out.Record.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
			return GeneratedDutyFact{}, contract.ErrRecord
		}
		out.EvidenceCeiling = contract.ReceiptEvidenceCanonical
		return out, ctx.Err()
	}
	out.Target, err = generatedPublicTarget(g, row.Kind, id, out.Record.Target)
	if err != nil {
		return GeneratedDutyFact{}, err
	}
	out.Progress, err = generatedPublicProgress(g, row.Kind, id, out.Record.Progress)
	if err != nil {
		return GeneratedDutyFact{}, err
	}
	out.GenerationID, out.RetirementMode = generatedPublicGeneration(g, out.Target)
	out.EvidenceCeiling, out.Warnings = generatedProgressCeiling(out.Progress)
	return out, ctx.Err()
}

func generatedHazardFact(ctx context.Context, g *generatedSelection, id contract.ID) (GeneratedHazardFact, error) {
	var out GeneratedHazardFact
	if err := generatedPublicFactContext(ctx, g); err != nil {
		return out, err
	}
	row, present := g.records[generatedRecordKey{contract.GeneratedHazardSupportKind, id}]
	if !present {
		return out, contract.ErrRecord
	}
	var err error
	out.Record, err = contract.InspectGeneratedHazardRecord(row.Body)
	if err != nil || out.Record.HazardID != id || out.Record.DomainID != g.image.root.Domain {
		return GeneratedHazardFact{}, contract.ErrRecord
	}
	out.Target, err = generatedPublicTarget(g, row.Kind, id, out.Record.Target)
	if err != nil {
		return GeneratedHazardFact{}, err
	}
	out.GenerationID, out.RetirementMode = generatedPublicGeneration(g, out.Target)
	if out.Target != nil {
		source, err := contract.InspectGeneratedDeleteSource(row)
		if err != nil {
			return GeneratedHazardFact{}, err
		}
		out.CleanupResultContractID, err = generatedCleanupResultContract(g, source, *out.Target)
		if err != nil {
			return GeneratedHazardFact{}, err
		}
	}
	out.EvidenceCeiling = contract.ReceiptEvidenceCanonical
	out.Warnings.PossibleLiveResidue = out.Record.Exposure == contract.GeneratedExposurePossibleLive
	out.Warnings.LateEffect = out.Record.Exposure == contract.GeneratedExposureLateEffect
	return out, ctx.Err()
}

func generatedEffectFact(ctx context.Context, g *generatedSelection, id contract.ID) (GeneratedEffectFact, error) {
	if err := generatedPublicFactContext(ctx, g); err != nil {
		return GeneratedEffectFact{}, err
	}
	var operation, lineageID contract.ID
	if a, ok := g.attempts[id]; ok {
		operation, lineageID = a.record.OperationID, a.record.LineageID
	} else if a, ok := g.releases[id]; ok {
		operation, lineageID = a.attempt.OperationID, a.attempt.LineageID
	} else {
		return GeneratedEffectFact{}, contract.ErrRecord
	}
	for _, bundle := range g.bundles {
		if bundle.Header.OperationID != operation {
			continue
		}
		for _, lineage := range bundle.Lineages {
			if lineage.LineageID == lineageID {
				return generatedEffectFactForLineage(ctx, g, id, lineage)
			}
		}
	}
	return GeneratedEffectFact{}, contract.ErrRecord
}

func generatedEffectFactForLineage(ctx context.Context, g *generatedSelection, id contract.ID, lineage contract.GeneratorLineageTemplate) (GeneratedEffectFact, error) {
	var out GeneratedEffectFact
	if err := generatedPublicFactContext(ctx, g); err != nil {
		return out, err
	}
	a, live := g.attempts[id]
	released, ended := g.releases[id]
	if live == ended {
		return out, contract.ErrRecord
	}
	out.Record = a.record
	x := a.expected.Template
	if ended {
		out.Record, x = released.attempt, released.template
	}
	if lineage.LineageID != out.Record.LineageID || lineage.OperationID != out.Record.OperationID || !generatedAttemptMatches(out.Record, x) {
		return GeneratedEffectFact{}, contract.ErrRecord
	}
	out.Action, out.Name, out.EntryIncarnationID, out.Epoch = x.Action, strings.Clone(lineage.Name), lineage.EntryIncarnationID, lineage.Epoch
	out.PlannedValueSlotID, out.ResourceDigest = x.PlannedValueSlotID, x.ResourceDigest
	out.EvidenceCeiling = contract.ReceiptEvidenceCanonical
	var err error
	local := out.Record.SemanticLifecycleMode() == contract.GeneratorLifecycleNone
	if local {
		if out.Record.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
			return GeneratedEffectFact{}, contract.ErrRecord
		}
		out.Reason = out.Record.FailureReason
	} else if ended && x.Action == contract.GeneratorActionDelete && out.Record.CompletionClass == contract.GeneratedCompletionConfirmed && released.release.State != contract.GeneratedReleaseUnobserved {
		rows, err := g.controlledReleasedProgress(released)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
		out.Progress, err = generatedPublicProgressRows(rows)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
	} else {
		out.Progress, err = generatedPublicProgress(g, contract.GeneratedAttemptSupportKind, id, out.Record.Progress)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
	}
	rows, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, id, contract.GeneratorVectorFacts, out.Record.Facts)
	if err != nil || len(rows) > 1 {
		return GeneratedEffectFact{}, contract.ErrRecord
	}
	if len(rows) == 1 {
		row, err := contract.InspectGeneratorFactsRow(rows[0])
		if err != nil {
			return GeneratedEffectFact{}, err
		}
		facts, err := contract.InspectGeneratorSafeFacts(row.Facts)
		if err != nil || row.ResultID != out.Record.ResultID {
			return GeneratedEffectFact{}, contract.ErrRecord
		}
		out.Reason, out.EvidenceCeiling = facts.Reason, contract.ReceiptEvidenceProviderFacts
		if x.Action == contract.GeneratorActionCreate && len(facts.Target) > 0 && len(facts.ResourceData) > 0 &&
			(facts.Disposition == contract.GeneratorDispositionCompleteCreate || facts.Disposition == contract.GeneratorDispositionOwnedUnusableCreate) {
			resourceDigest, err := contract.GeneratorResourceDigest(facts.GeneratorSafeFacts)
			if err != nil {
				return GeneratedEffectFact{}, err
			}
			out.Target = &contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: out.Name, IncarnationID: out.EntryIncarnationID, Epoch: out.Epoch,
				ResourceID: out.Record.ResourceID, ResourceDigest: resourceDigest, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID,
				OriginalOperationID: out.Record.OperationID, OriginalAttemptID: id, ResultContractID: x.ResultContractID, CompletionClass: x.CompletionClass}
		}
		if x.Action == contract.GeneratorActionDelete && facts.Disposition == contract.GeneratorDispositionRetirementAcknowledged {
			out.EvidenceCeiling, out.Warnings.InvalidationNotConfirmed = contract.ReceiptEvidenceAcknowledged, true
		}
		if facts.Disposition == contract.GeneratorDispositionScopedUnusability {
			out.EvidenceCeiling = contract.ReceiptEvidenceConfirmed
		}
	}
	if row, present := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, x.DutyID}]; present {
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
		out.DutyID = duty.DutyID
		if out.Target == nil && !local {
			out.Target, err = generatedPublicTarget(g, row.Kind, row.RecordID, duty.Target)
			if err != nil {
				return GeneratedEffectFact{}, err
			}
		}
	}
	hazardID := x.HazardID
	if selected := g.deleteHazards[id]; !selected.IsZero() {
		hazardID = selected
	}
	if row, present := g.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazardID}]; present {
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
		out.HazardID = hazard.HazardID
		out.Warnings.PossibleLiveResidue = hazard.Exposure == contract.GeneratedExposurePossibleLive
		out.Warnings.LateEffect = hazard.Exposure == contract.GeneratedExposureLateEffect
		if out.Target == nil {
			out.Target, err = generatedPublicTarget(g, row.Kind, row.RecordID, hazard.Target)
			if err != nil {
				return GeneratedEffectFact{}, err
			}
		}
	}
	// Ordinary cleanup can consume an existing create-derived Hazard whose
	// identity differs from the new Delete template's possible Hazard.
	if live && out.Target == nil && x.Action == contract.GeneratorActionDelete {
		bundle, err := g.retainedGraph(out.Record.OperationID)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
		target, source, err := g.generatedDeleteAttemptTargetAndSource(ctx, bundle, out.Record)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
		target.Name = out.Name
		out.Target = &target
		if source.Record.Kind == contract.GeneratedHazardSupportKind {
			out.HazardID = source.SourceID
			out.Warnings.PossibleLiveResidue = source.Hazard.Exposure == contract.GeneratedExposurePossibleLive
			out.Warnings.LateEffect = source.Hazard.Exposure == contract.GeneratedExposureLateEffect
		} else {
			out.DutyID = source.SourceID
		}
	}
	// An active original apply can retain a completed Delete after its Duty
	// ends. Only its exact anchored graph and historical Create evidence can
	// supply that released Target on a cold observation.
	if ended && out.Target == nil && x.Action == contract.GeneratorActionDelete && generatedSelectionAnchored(g) && out.Record.OperationID == g.parent.OperationID {
		if len(g.bundles) == 0 || g.parent.DomainID != g.image.root.Domain || out.Record.DomainID != g.image.root.Domain ||
			g.phase.DomainID != g.image.root.Domain || g.phase.OperationID != g.parent.OperationID || g.phase.OwnerID != g.parent.OperationID ||
			g.phase.PlanGraphID != g.parent.PlanGraphID || g.phase.UsePlanDigest != g.parent.UsePlanDigest ||
			g.image.root.Generated.ActiveOwner != g.parent.OperationID || g.image.root.Generated.ActivePhase != g.phase.PhaseID || g.image.root.Generated.ActiveGraph != g.phase.PlanGraphID ||
			g.bundles[0].Header.OperationID != g.parent.OperationID || (g.bundles[0].Request.OperationKind != contract.OperationApplyDeclaration && g.bundles[0].Request.OperationKind != contract.OperationRotateValueEntryValue) {
			return GeneratedEffectFact{}, contract.ErrRecord
		}
		out.Target, err = generatedAutomaticReleasedTarget(ctx, g, x)
		if err != nil {
			return GeneratedEffectFact{}, err
		}
	}
	if ended && x.Action == contract.GeneratorActionDelete && released.release.State != contract.GeneratedReleaseUnobserved {
		out.EvidenceCeiling, out.Warnings.InvalidationNotConfirmed = contract.ReceiptEvidenceAcknowledged, true
		if ceiling, _ := generatedProgressCeiling(out.Progress); ceiling == contract.ReceiptEvidenceConfirmed {
			out.EvidenceCeiling, out.Warnings.InvalidationNotConfirmed = ceiling, false
		}
	}
	if out.Target != nil && out.Target.Name == out.Name {
		out.Target.Name = out.Name
	}
	out.GenerationID = generatedPublicEffectGeneration(g, out)
	if out.Target != nil {
		out.ResourceDigest = out.Target.ResourceDigest
	}

	return out, ctx.Err()
}
