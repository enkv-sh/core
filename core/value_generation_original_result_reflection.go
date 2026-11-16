package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
)

type generatedReflection struct {
	source  contract.GeneratedDeleteSource
	attempt generatedAttempt
	hazard  contract.GeneratedHazardRecord
	target  contract.GeneratorTarget
	rows    []contract.SupportRecord
}

type generatedDeleteReflection struct {
	attempt   generatedAttempt
	source    contract.GeneratedDeleteSource
	hazard    contract.GeneratedHazardRecord
	target    contract.GeneratorTarget
	release   contract.PendingInboxReleaseRecord
	materials []contract.ID
	values    []contract.ID
	slices    contract.GeneratorDescriptor
	locations []contract.GeneratorSliceLocation
	rows      []contract.SupportRecord
}

// generatedReflectLateCreate applies the effect-free original-result reflection.
// It changes only the selected possible-live Hazard, roots the exact original
// result, and creates no new Attempt or provider dispatch right.
func (g *generatedSelection) generatedReflectLateCreate(selection generatedCleanupSelection) (generatedReflection, error) {
	if g == nil || selection.kind != generatedCleanupReflection || selection.closeOwner ||
		selection.attempt.expected.Template.Action != contract.GeneratorActionCreate || len(selection.result) == 0 {
		return generatedReflection{}, contract.ErrRecord
	}
	a := selection.attempt
	h := selection.hazard
	currentRow, present := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: h.HazardID}]
	if !present {
		return generatedReflection{}, contract.ErrRecord
	}
	current, err := contract.InspectGeneratedHazardRecord(currentRow.Body)
	if err != nil || current != h {
		return generatedReflection{}, contract.ErrRecord
	}
	if h.Exposure != contract.GeneratedExposurePossibleLive || h.Fenced != 1 || h.OriginalAttemptID != a.record.AttemptID ||
		a.record.State != contract.GeneratedEffectClosedWithResidue || a.record.Stage != contract.GeneratedStageTerminal {
		return generatedReflection{}, contract.ErrRecord
	}
	result, err := contract.DecodeGeneratedResultRecord(selection.result)
	if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, result) != nil ||
		result.SafeFacts.Disposition != contract.GeneratorDispositionCompleteCreate && result.SafeFacts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate {
		return generatedReflection{}, contract.ErrRecord
	}
	factsBody, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
	if err != nil {
		return generatedReflection{}, err
	}
	factBody, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: factsBody})
	if err != nil {
		return generatedReflection{}, err
	}
	factsDescriptor, factsRows, err := generatedCarrierRows(a.record.DomainID, contract.GeneratedAttemptSupportKind, a.record.AttemptID,
		contract.GeneratorVectorFacts, [][]byte{factBody})
	if err != nil {
		return generatedReflection{}, err
	}
	a.record.Facts = factsDescriptor
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		return generatedReflection{}, err
	}
	bundle, err := g.retainedGraph(a.record.OperationID)
	if err != nil {
		return generatedReflection{}, err
	}
	lineageIndex := slices.IndexFunc(bundle.Lineages, func(v contract.GeneratorLineageTemplate) bool {
		return v.LineageID == a.record.LineageID && v.Purpose == contract.GeneratorLineageCreate
	})
	if lineageIndex < 0 {
		return generatedReflection{}, contract.ErrRecord
	}
	lineage := bundle.Lineages[lineageIndex]
	resourceDigest, err := contract.GeneratorResourceDigest(result.SafeFacts)
	if err != nil {
		return generatedReflection{}, err
	}
	target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: lineage.Name, IncarnationID: lineage.EntryIncarnationID, Epoch: lineage.Epoch,
		ResourceID: a.record.ResourceID, ResourceDigest: resourceDigest,
		ConfigContractID: a.record.ConfigContractID, ResourceContractID: a.record.ResourceContractID, OriginalOperationID: a.record.OperationID,
		OriginalAttemptID: a.record.AttemptID, ResultContractID: a.record.ResultContractID, CompletionClass: a.record.CompletionClass}
	targetBody, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		return generatedReflection{}, err
	}
	targetDescriptor, targetRows, err := generatedCarrierRows(a.record.DomainID, contract.GeneratedHazardSupportKind, h.HazardID,
		contract.GeneratorVectorTargets, [][]byte{targetBody})
	if err != nil {
		return generatedReflection{}, err
	}
	resultRow := contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: a.record.ResultID, Body: bytes.Clone(selection.result)}
	originalResults, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, a.record.DomainID, []contract.SupportRecord{resultRow})
	if err != nil {
		return generatedReflection{}, err
	}
	h.Exposure, h.Eligibility = contract.GeneratedExposureLateEffect, contract.GeneratedExposureLateEffect
	h.OriginalResults, h.Target = originalResults, targetDescriptor
	hazardBody, err := contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		return generatedReflection{}, err
	}
	rows := make([]contract.SupportRecord, 0, len(g.records)+len(factsRows)+len(targetRows)+3)
	for _, existing := range g.image.supportRecords() {
		if existing.Kind == contract.GeneratedResultSupportKind && existing.RecordID == a.record.ResultID ||
			existing.Kind == contract.GeneratedAttemptSupportKind && existing.RecordID == a.record.AttemptID ||
			existing.Kind == contract.GeneratedHazardSupportKind && existing.RecordID == h.HazardID {
			continue
		}
		if existing.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(existing.Body)
			if err != nil {
				return generatedReflection{}, err
			}
			if carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == a.record.AttemptID && carrier.VectorKind == contract.GeneratorVectorFacts ||
				carrier.OwnerKind == contract.GeneratedHazardSupportKind && carrier.OwnerID == h.HazardID && carrier.VectorKind == contract.GeneratorVectorTargets {
				continue
			}
		}
		rows = append(rows, existing)
	}
	rows = append(rows, resultRow,
		contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: a.record.AttemptID, Body: attemptBody},
		contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: h.HazardID, Body: hazardBody})
	rows = append(rows, factsRows...)
	rows = append(rows, targetRows...)
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	a.result = bytes.Clone(selection.result)
	source, err := contract.InspectGeneratedDeleteSource(currentRow)
	if err != nil {
		return generatedReflection{}, err
	}
	return generatedReflection{source: source, attempt: a, hazard: h, target: target, rows: rows}, nil
}

func (g *generatedSelection) generatedReflectLateNonfinalDelete(ctx context.Context, selection generatedCleanupSelection) (generatedReflection, error) {
	if g == nil || selection.kind != generatedCleanupReflection || selection.closeOwner || selection.reflected ||
		selection.attempt.expected.Template.Action != contract.GeneratorActionDelete || len(selection.result) == 0 {
		return generatedReflection{}, contract.ErrRecord
	}
	owner, err := contract.InspectGeneratedDeleteSource(g.records[selection.sourceKey()])
	if err != nil {
		return generatedReflection{}, err
	}
	if owner.Record.Kind == contract.GeneratedDutySupportKind || owner.Hazard.Exposure == contract.GeneratedExposureLateEffect {
		a := selection.attempt
		if owner.CompletionClass != contract.GeneratedCompletionConfirmed || owner.OwnerID != a.record.OwnerID ||
			owner.Record.Kind == contract.GeneratedDutySupportKind && (owner.Duty.Kind != contract.GeneratedDutyUnselectedCleanup || owner.Duty.Status != contract.GeneratedEffectSucceeded) ||
			owner.Record.Kind == contract.GeneratedHazardSupportKind && (owner.Hazard.Fenced != 1 || owner.Hazard.Eligibility != owner.Hazard.Exposure) ||
			a.record.State != contract.GeneratedEffectUnknown && a.record.State != contract.GeneratedEffectClosedWithResidue ||
			a.record.Stage != contract.GeneratedStageTerminal || len(a.result) != 0 {
			return generatedReflection{}, contract.ErrRecord
		}
		result, err := contract.DecodeGeneratedResultRecord(selection.result)
		if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, result) != nil ||
			result.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || !generatedResourceFactsMatch(result.SafeFacts, a.expected.TargetResourceDigest) {
			return generatedReflection{}, contract.ErrRecord
		}
		bundle, err := g.retainedGraph(a.record.OperationID)
		if err != nil {
			return generatedReflection{}, err
		}
		target, err := g.generatedCleanupTarget(owner.Record.Kind, owner.SourceID, owner.Target)
		if err != nil || g.validateDeleteTarget(ctx, bundle, a.record, target) != nil {
			return generatedReflection{}, contract.ErrRecord
		}
		a.record.State, a.record.Stage = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal
		a.result = bytes.Clone(selection.result)
		progress, err := g.controlledDeleteSourceProgress(owner, &a, false)
		if err != nil || progress.contradiction || len(progress.rows) != 1 {
			return generatedReflection{}, contract.ErrRecord
		}
		facts, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
		if err != nil {
			return generatedReflection{}, err
		}
		fact, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: facts})
		if err != nil {
			return generatedReflection{}, err
		}
		var extra, carriers []contract.SupportRecord
		a.record.Facts, carriers, err = generatedCarrierRows(a.record.DomainID, contract.GeneratedAttemptSupportKind, a.record.AttemptID,
			contract.GeneratorVectorFacts, [][]byte{fact})
		if err != nil {
			return generatedReflection{}, err
		}
		extra = append(extra, carriers...)
		ack, err := generatedControlledProgressRow(a, contract.GeneratorProgressAcknowledged)
		if err != nil {
			return generatedReflection{}, err
		}
		a.record.Progress, carriers, err = generatedCarrierRows(a.record.DomainID, contract.GeneratedAttemptSupportKind, a.record.AttemptID,
			contract.GeneratorVectorProgress, [][]byte{ack})
		if err != nil {
			return generatedReflection{}, err
		}
		extra = append(extra, carriers...)
		a.record.History, carriers, err = generatedRecordedHistory(g, contract.GeneratedAttemptSupportKind, a.record.AttemptID,
			a.record.History, a.record, contract.Hash(a.result))
		if err != nil {
			return generatedReflection{}, err
		}
		extra = append(extra, carriers...)
		history, err := g.vectors.resolve(owner.Record.Kind, owner.SourceID, contract.GeneratorVectorHistory, owner.History)
		if err != nil {
			return generatedReflection{}, err
		}
		history = slices.Clone(history)
		found := false
		for i, body := range history {
			row, err := contract.InspectGeneratorHistory(body)
			if err != nil {
				return generatedReflection{}, err
			}
			if row.PredecessorAttemptID != a.record.AttemptID {
				continue
			}
			if found || row.OwnerID != a.record.OwnerID {
				return generatedReflection{}, contract.ErrRecord
			}
			row.ResultID, row.ResultDigest, row.Outcome = a.record.ResultID, contract.Hash(a.result), a.record.State
			history[i], err = contract.EncodeGeneratorHistory(row)
			if err != nil {
				return generatedReflection{}, err
			}
			found = true
		}
		if !found {
			return generatedReflection{}, contract.ErrRecord
		}
		owner.History, carriers, err = generatedCarrierRows(a.record.DomainID, owner.Record.Kind, owner.SourceID, contract.GeneratorVectorHistory, history)
		if err != nil {
			return generatedReflection{}, err
		}
		extra = append(extra, carriers...)
		if owner.Record.Kind == contract.GeneratedDutySupportKind {
			owner.Duty.Step, owner.Duty.History = 2, owner.History
			owner.Duty.Progress, carriers, err = generatedCarrierRows(a.record.DomainID, owner.Record.Kind, owner.SourceID,
				contract.GeneratorVectorProgress, progress.rows)
			if err != nil {
				return generatedReflection{}, err
			}
			extra = append(extra, carriers...)
			owner.Record.Body, err = contract.EncodeGeneratedDutyRecord(owner.Duty)
		} else {
			owner.Hazard.History = owner.History
			owner.Record.Body, err = contract.EncodeGeneratedHazardRecord(owner.Hazard)
		}
		if err != nil {
			return generatedReflection{}, err
		}
		attemptBody, err := contract.EncodeGeneratedAttemptRecord(a.record)
		if err != nil {
			return generatedReflection{}, err
		}
		var rows []contract.SupportRecord
		for _, row := range g.image.supportRecords() {
			if row.Kind == owner.Record.Kind && row.RecordID == owner.SourceID ||
				row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == a.record.AttemptID ||
				row.Kind == contract.GeneratedResultSupportKind && row.RecordID == a.record.ResultID {
				continue
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				c, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					return generatedReflection{}, err
				}
				if c.OwnerKind == contract.GeneratedAttemptSupportKind && c.OwnerID == a.record.AttemptID &&
					(c.VectorKind == contract.GeneratorVectorFacts || c.VectorKind == contract.GeneratorVectorProgress || c.VectorKind == contract.GeneratorVectorHistory) ||
					c.OwnerKind == owner.Record.Kind && c.OwnerID == owner.SourceID &&
						(c.VectorKind == contract.GeneratorVectorHistory || owner.Record.Kind == contract.GeneratedDutySupportKind && c.VectorKind == contract.GeneratorVectorProgress) {
					continue
				}
			}
			rows = append(rows, row)
		}
		rows = append(rows, owner.Record, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: a.record.AttemptID, Body: attemptBody},
			contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: a.record.ResultID, Body: a.result})
		rows = append(rows, extra...)
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
			if a.Kind != b.Kind {
				return int(a.Kind) - int(b.Kind)
			}
			return bytes.Compare(a.RecordID[:], b.RecordID[:])
		})
		return generatedReflection{source: owner, attempt: a, hazard: owner.Hazard, target: target, rows: rows}, nil
	}
	a, h := selection.attempt, selection.hazard
	currentRow, present := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: h.HazardID}]
	if !present {
		return generatedReflection{}, contract.ErrRecord
	}
	current, err := contract.InspectGeneratedHazardRecord(currentRow.Body)
	if err != nil || current != h || h.Exposure != contract.GeneratedExposurePossibleLive || h.Fenced != 1 ||
		h.Eligibility != contract.GeneratedExposurePossibleLive || h.CompletionClass != contract.GeneratedCompletionConfirmed ||
		g.deleteHazards[a.record.AttemptID] != h.HazardID || a.record.CompletionClass != h.CompletionClass ||
		a.record.State != contract.GeneratedEffectUnknown && a.record.State != contract.GeneratedEffectClosedWithResidue ||
		a.record.Stage != contract.GeneratedStageTerminal || len(a.result) != 0 {
		return generatedReflection{}, contract.ErrRecord
	}
	result, err := contract.DecodeGeneratedResultRecord(selection.result)
	if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, result) != nil ||
		result.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || !generatedResourceFactsMatch(result.SafeFacts, a.expected.TargetResourceDigest) {
		return generatedReflection{}, contract.ErrRecord
	}
	bundle, err := g.retainedGraph(a.record.OperationID)
	if err != nil {
		return generatedReflection{}, err
	}
	target, err := g.generatedCleanupTarget(contract.GeneratedHazardSupportKind, h.HazardID, h.Target)
	if err != nil {
		return generatedReflection{}, contract.ErrRecord
	}
	if err := g.validateDeleteTarget(ctx, bundle, a.record, target); err != nil {
		return generatedReflection{}, err
	}
	resultRow := contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: a.record.ResultID, Body: bytes.Clone(selection.result)}
	var originals []contract.SupportRecord
	for id, owner := range g.deleteHazards {
		if owner != h.HazardID {
			continue
		}
		original, ok := g.attempts[id]
		if !ok || original.expected.Template.Action != contract.GeneratorActionDelete {
			return generatedReflection{}, contract.ErrRecord
		}
		if row, present := g.records[generatedRecordKey{kind: contract.GeneratedResultSupportKind, id: original.record.ResultID}]; present {
			if !bytes.Equal(row.Body, original.result) || len(original.result) == 0 {
				return generatedReflection{}, contract.ErrRecord
			}
			originals = append(originals, row)
		} else if len(original.result) != 0 {
			return generatedReflection{}, contract.ErrRecord
		}
	}
	before, err := generatedHazardResultsDescriptor(h.DomainID, originals)
	if err != nil || before != h.OriginalResults {
		return generatedReflection{}, contract.ErrRecord
	}
	originals = append(originals, resultRow)
	h.OriginalResults, err = generatedHazardResultsDescriptor(h.DomainID, originals)
	if err != nil {
		return generatedReflection{}, err
	}
	hazardBody, err := contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		return generatedReflection{}, err
	}
	rows := make([]contract.SupportRecord, 0, len(g.records)+2)
	for _, row := range g.image.supportRecords() {
		if row.Kind != contract.GeneratedHazardSupportKind || row.RecordID != h.HazardID {
			rows = append(rows, row)
		}
	}
	rows = append(rows, resultRow, contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: h.HazardID, Body: hazardBody})
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	a.result = bytes.Clone(selection.result)
	source, err := contract.InspectGeneratedDeleteSource(currentRow)
	if err != nil {
		return generatedReflection{}, err
	}
	return generatedReflection{source: source, attempt: a, hazard: h, target: target, rows: rows}, nil
}

func (g *generatedSelection) generatedReflectOriginalClosure(ctx context.Context, selection generatedCleanupSelection, handoffRevision contract.ID) (generatedDeleteReflection, error) {
	if selection.attempt.expected.Template.Action != contract.GeneratorActionCreate {
		return g.generatedReflectLateDelete(ctx, selection, handoffRevision)
	}
	if g == nil || g.parent != nil || g.phase != nil || selection.kind != generatedCleanupReflection || !selection.closeOwner ||
		len(selection.result) == 0 || handoffRevision.IsZero() {
		return generatedDeleteReflection{}, contract.ErrRecord
	}
	a := selection.attempt
	source, err := contract.InspectGeneratedDeleteSource(g.records[selection.sourceKey()])
	if err != nil || source.Record.Kind != contract.GeneratedHazardSupportKind || source.Hazard != selection.hazard ||
		source.OwnerID != a.record.OwnerID || source.OriginalOperationID != a.record.OperationID || source.OriginalAttemptID != a.record.AttemptID ||
		source.Hazard.Exposure != contract.GeneratedExposurePossibleLive || source.Hazard.Fenced != 1 || source.Hazard.Eligibility != 0 ||
		source.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) || source.Hazard.OriginalResults != contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults) ||
		a.record.State != contract.GeneratedEffectClosedWithResidue || a.record.Stage != contract.GeneratedStageTerminal || len(a.result) != 0 {
		return generatedDeleteReflection{}, contract.ErrRecord
	}
	result, err := contract.DecodeGeneratedResultRecord(selection.result)
	if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, result) != nil || result.SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect {
		return generatedDeleteReflection{}, contract.ErrRecord
	}
	return g.generatedDeleteSourceClosure(a, source, contract.GeneratorTarget{}, selection.result, handoffRevision)
}

// generatedReflectLateDelete consumes a qualified original delete
// acknowledgement without another provider call. It closes only the fixed
// acknowledgement class and retains the release-only result coordinate.
func (g *generatedSelection) generatedReflectLateDelete(ctx context.Context, selection generatedCleanupSelection, handoffRevision contract.ID) (generatedDeleteReflection, error) {
	if g == nil || g.parent != nil || g.phase != nil || selection.kind != generatedCleanupReflection || !selection.closeOwner ||
		selection.attempt.expected.Template.Action != contract.GeneratorActionDelete || len(selection.result) == 0 || handoffRevision.IsZero() {
		return generatedDeleteReflection{}, contract.ErrRecord
	}
	a := selection.attempt
	source, err := contract.InspectGeneratedDeleteSource(g.records[selection.sourceKey()])
	if err != nil || source.OwnerID != a.record.OwnerID ||
		(source.CompletionClass != contract.GeneratedCompletionAcknowledged && source.CompletionClass != contract.GeneratedCompletionConfirmed) ||
		source.Record.Kind == contract.GeneratedDutySupportKind && (source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup || source.Duty.Status != contract.GeneratedEffectSucceeded) ||
		source.Record.Kind == contract.GeneratedHazardSupportKind && (source.Hazard.Fenced != 1 || source.Hazard.Eligibility == 0 || source.Hazard.Eligibility != source.Hazard.Exposure) ||
		a.record.State != contract.GeneratedEffectUnknown && a.record.State != contract.GeneratedEffectClosedWithResidue || a.record.Stage != contract.GeneratedStageTerminal ||
		a.record.CompletionClass != source.CompletionClass {
		return generatedDeleteReflection{}, contract.ErrRecord
	}
	result, err := contract.DecodeGeneratedResultRecord(selection.result)
	if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, result) != nil ||
		!generatedResourceFactsMatch(result.SafeFacts, a.expected.TargetResourceDigest) ||
		source.CompletionClass == contract.GeneratedCompletionAcknowledged && result.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged ||
		source.CompletionClass == contract.GeneratedCompletionConfirmed && result.SafeFacts.Disposition != contract.GeneratorDispositionScopedUnusability {
		return generatedDeleteReflection{}, contract.ErrRecord
	}
	bundle, err := g.retainedGraph(a.record.OperationID)
	if err != nil {
		return generatedDeleteReflection{}, err
	}
	target, err := g.generatedCleanupTarget(source.Record.Kind, source.SourceID, source.Target)
	if err != nil {
		return generatedDeleteReflection{}, err
	}
	if err := g.validateDeleteTarget(ctx, bundle, a.record, target); err != nil {
		return generatedDeleteReflection{}, err
	}
	if source.CompletionClass == contract.GeneratedCompletionConfirmed {
		pending := a
		pending.result = selection.result
		progress, err := g.controlledDeleteSourceProgress(source, &pending, false)
		if err != nil || progress.contradiction || len(progress.rows) != 2 {
			return generatedDeleteReflection{}, contract.ErrRecord
		}
	}
	closed, err := g.generatedDeleteSourceClosure(a, source, target, selection.result, handoffRevision)
	if err != nil {
		return generatedDeleteReflection{}, fmt.Errorf("delete source closure: %w", err)
	}
	return closed, nil
}

// Closing exact ordinary ownership and reflecting exact original closure share
// release accounting, not provider authority or receipt production.
func (g *generatedSelection) generatedDeleteSourceClosure(a generatedAttempt, source contract.GeneratedDeleteSource, target contract.GeneratorTarget, evidence []byte, handoffRevision contract.ID) (generatedDeleteReflection, error) {
	h := source.Hazard

	originals := make(map[contract.ID]generatedAttempt)
	results := make(map[contract.ID]bool)
	observed := make(map[contract.ID]bool)
	reflected := make(map[contract.ID]bool)
	retainedProgress := make(map[contract.ID]bool)
	removeMaterials := make(map[contract.ID]bool)
	var releasedRows []contract.SupportRecord
	var release contract.PendingInboxReleaseRecord
	var releaseAttempt contract.GeneratedAttemptRecord
	consumers, err := g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorConsumers, source.Consumers)
	if err != nil {
		return generatedDeleteReflection{}, err
	}
	for _, body := range consumers {
		consumer, err := contract.InspectGeneratorConsumer(body)
		if err != nil {
			return generatedDeleteReflection{}, err
		}
		if consumer.SubjectKind != contract.GeneratorConsumerOriginalResult {
			continue
		}
		if consumer.Purpose != contract.GeneratorConsumerAdoptLateOriginalResult || consumer.OwnerID != source.SourceID {
			return generatedDeleteReflection{}, contract.ErrRecord
		}
		var original generatedAttempt
		for _, candidate := range g.attempts {
			if candidate.record.ResultID == consumer.SubjectID {
				original = candidate
				break
			}
		}
		if original.record.AttemptID.IsZero() || original.material.Core.OperationMaterialID != consumer.MaterialID {
			return generatedDeleteReflection{}, contract.ErrRecord
		}
		id := original.record.AttemptID
		if _, repeated := originals[id]; repeated {
			return generatedDeleteReflection{}, contract.ErrRecord
		}
		if original.expected.Template.Action == contract.GeneratorActionDelete {
			contradiction, err := g.validateDeleteFacts(original)
			if err != nil || contradiction {
				return generatedDeleteReflection{}, contract.ErrRecord
			}
		}
		originals[id], results[original.record.ResultID] = original, true
		body = original.result
		if id == a.record.AttemptID {
			body = evidence
		}
		r := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: original.record.DomainID, InboxID: original.record.InboxID,
			OriginalResultID: original.record.ResultID, SelectedHandoffDigest: contract.Hash(evidence), HandoffRevisionID: handoffRevision,
			CapacityReservation: source.CapacityReservation, State: contract.GeneratedReleaseUnobserved}
		mapping := original.record
		mapping.Progress = contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
		if len(body) != 0 {
			if original.expected.Template.Action == contract.GeneratorActionDelete && original.record.CompletionClass == contract.GeneratedCompletionConfirmed {
				result, err := contract.InspectGeneratedResultRecord(body)
				if err != nil {
					return generatedDeleteReflection{}, err
				}
				if result.SafeFacts.Disposition == contract.GeneratorDispositionScopedUnusability {
					progress, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, id, contract.GeneratorVectorProgress, original.record.Progress)
					if err != nil || len(progress) < 1 || len(progress) > 2 {
						return generatedDeleteReflection{}, contract.ErrRecord
					}
					var ack []byte
					for _, body := range progress {
						row, err := contract.InspectGeneratorProgress(body)
						if err != nil {
							return generatedDeleteReflection{}, err
						}
						if row.CompletedSteps == contract.GeneratorProgressAcknowledged {
							if ack != nil {
								return generatedDeleteReflection{}, contract.ErrRecord
							}
							ack = body
						}
					}
					if ack == nil {
						return generatedDeleteReflection{}, contract.ErrRecord
					}
					var carriers []contract.SupportRecord
					mapping.Progress, carriers, err = generatedCarrierRows(original.record.DomainID, contract.GeneratedAttemptSupportKind, id, contract.GeneratorVectorProgress, [][]byte{ack})
					if err != nil {
						return generatedDeleteReflection{}, err
					}
					releasedRows = append(releasedRows, carriers...)
					retainedProgress[id] = true
				}
			}
			r.SelectedHandoffDigest, r.ObjectLength, r.State = contract.Hash(body), uint32(len(body)), contract.GeneratedReleasePending
			if original.expected.Template.Action == contract.GeneratorActionDelete && original.record.CompletionClass == contract.GeneratedCompletionAcknowledged {
				mapping.State = contract.GeneratedEffectSucceeded
			}
			if a.expected.Template.Action == contract.GeneratorActionCreate && id == a.record.AttemptID {
				mapping.State = contract.GeneratedEffectConfirmedNoEffect
			}
			if original.expected.Template.Action != contract.GeneratorActionDelete || original.record.CompletionClass != contract.GeneratedCompletionConfirmed {
				mapping.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
			} else {
				recorded, err := g.deleteResultRecorded(original)
				if err != nil {
					return generatedDeleteReflection{}, err
				}
				if !recorded {
					result, err := contract.InspectGeneratedResultRecord(body)
					if err != nil || result.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged && result.SafeFacts.Disposition != contract.GeneratorDispositionScopedUnusability {
						return generatedDeleteReflection{}, contract.ErrRecord
					}
					facts, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts.GeneratorSafeFacts)
					if err != nil {
						return generatedDeleteReflection{}, err
					}
					fact, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: original.record.ResultID, Facts: facts})
					if err != nil {
						return generatedDeleteReflection{}, err
					}
					var carriers []contract.SupportRecord
					mapping.Facts, carriers, err = generatedCarrierRows(original.record.DomainID, contract.GeneratedAttemptSupportKind, id, contract.GeneratorVectorFacts, [][]byte{fact})
					if err != nil {
						return generatedDeleteReflection{}, err
					}
					releasedRows = append(releasedRows, carriers...)
					reflected[id] = true
				}
			}
			if !reflected[id] {
				mapping.History = contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
			}
			observed[id] = true
		}
		attemptBody, err := contract.EncodeGeneratedAttemptRecord(mapping)
		if err != nil {
			return generatedDeleteReflection{}, err
		}
		releaseBody, err := contract.EncodePendingInboxReleaseRecord(r)
		if err != nil {
			return generatedDeleteReflection{}, err
		}
		releasedRows = append(releasedRows, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: id, Body: attemptBody},
			contract.SupportRecord{Kind: contract.PendingInboxReleaseSupportKind, RecordID: r.InboxID, Body: releaseBody})
		if id == a.record.AttemptID {
			release, releaseAttempt = r, mapping
		}
		material := original.material.Core.OperationMaterialID
		shared := false
		for _, consumer := range g.consumers[materialIdentity{contract.OperationSeedMaterialKind, material}] {
			shared = shared || consumer.OwnerID != source.SourceID
		}
		if !shared {
			removeMaterials[material] = true
		}
	}
	if len(originals) == 0 || release.InboxID.IsZero() {
		return generatedDeleteReflection{}, contract.ErrRecord
	}
	createOperation, createAttempt := target.OriginalOperationID, target.OriginalAttemptID
	if a.expected.Template.Action == contract.GeneratorActionCreate {
		createOperation, createAttempt = a.record.OperationID, a.record.AttemptID
	}
	createResult, err := generatedCreateResultID(source.DomainID, createOperation, createAttempt)
	if err != nil {
		return generatedDeleteReflection{}, err
	}
	createNeeded := generatedSelectionAnchored(g) || g.generatedResultSelectedByEntry(createResult)
	for key, row := range g.records {
		if key.kind == source.Record.Kind && key.id == source.SourceID {
			continue
		}
		var kind uint8
		var descriptor contract.GeneratorDescriptor
		switch key.kind {
		case contract.GeneratedDutySupportKind:
			d, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return generatedDeleteReflection{}, err
			}
			kind, descriptor = 10, d.Target
		case contract.GeneratedHazardSupportKind:
			if key.id == h.HazardID {
				continue
			}
			sibling, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return generatedDeleteReflection{}, err
			}
			kind, descriptor = 11, sibling.Target
		default:
			continue
		}
		if descriptor.Count == 0 {
			continue
		}
		siblingTarget, err := g.generatedCleanupTarget(kind, key.id, descriptor)
		if err != nil {
			return generatedDeleteReflection{}, err
		}
		createNeeded = createNeeded || siblingTarget.OriginalOperationID == createOperation && siblingTarget.OriginalAttemptID == createAttempt
	}
	rows := make([]contract.SupportRecord, 0, len(g.records)+2)
	for _, existing := range g.image.supportRecords() {
		remove := false
		switch existing.Kind {
		case contract.OperationMaterialSupportKind:
			remove = removeMaterials[existing.RecordID]
		case contract.GeneratedResultSupportKind:
			remove = results[existing.RecordID]
		case contract.GeneratedAttemptSupportKind:
			_, remove = originals[existing.RecordID]
		case contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind:
			remove = existing.Kind == source.Record.Kind && existing.RecordID == source.SourceID
		case contract.GeneratedParentSupportKind, contract.GeneratedPhaseSupportKind:
			remove = g.parent != nil && existing.RecordID == g.parent.OperationID && !generatedSelectionAnchored(g)
		case contract.GeneratedCreateEvidenceSupportKind:
			remove = existing.RecordID == createResult && !createNeeded
		case contract.GeneratorVectorSupportKind:
			carrier, inspectErr := contract.InspectGeneratorVectorCarrier(existing.Body)
			if inspectErr != nil {
				return generatedDeleteReflection{}, inspectErr
			}
			_, released := originals[carrier.OwnerID]
			remove = carrier.VectorKind == contract.GeneratorVectorSlices || carrier.OwnerKind == contract.GeneratedAttemptSupportKind && released && carrier.VectorKind == contract.GeneratorVectorProgress || carrier.OwnerKind == contract.GeneratedAttemptSupportKind && reflected[carrier.OwnerID] && carrier.VectorKind == contract.GeneratorVectorFacts || carrier.OwnerKind == contract.GeneratedAttemptSupportKind && observed[carrier.OwnerID] &&
				(g.attempts[carrier.OwnerID].expected.Template.Action != contract.GeneratorActionDelete || g.attempts[carrier.OwnerID].record.CompletionClass != contract.GeneratedCompletionConfirmed ||
					carrier.VectorKind != contract.GeneratorVectorFacts && (!reflected[carrier.OwnerID] || carrier.VectorKind != contract.GeneratorVectorHistory) && (!retainedProgress[carrier.OwnerID] || carrier.VectorKind != contract.GeneratorVectorProgress)) ||
				carrier.OwnerKind == source.Record.Kind && carrier.OwnerID == source.SourceID
		}
		if !remove {
			rows = append(rows, existing)
		}
	}
	rows, values, err := g.generatedPruneRetainedCanonicals(rows)
	if err != nil {
		return generatedDeleteReflection{}, fmt.Errorf("prune retained canonicals: %w", err)
	}
	rows = append(rows, releasedRows...)
	rows, locations, sliceDescriptor, err := g.generatedCloseContent(rows)
	if err != nil {
		return generatedDeleteReflection{}, fmt.Errorf("close content: %w", err)
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	a.record, a.result = releaseAttempt, nil
	materials := make([]contract.ID, 0, len(removeMaterials))
	for id := range removeMaterials {
		materials = append(materials, id)
	}
	slices.SortFunc(materials, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(values, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return generatedDeleteReflection{attempt: a, hazard: h, source: source, target: target, release: release,
		materials: materials, values: values, slices: sliceDescriptor,
		locations: locations, rows: rows}, nil
}

func (g *generatedSelection) generatedPruneRetainedCanonicals(rows []contract.SupportRecord) ([]contract.SupportRecord, []contract.ID, error) {
	retainedConsumers, err := generatedRetainedCanonicalConsumers(rows)
	if err != nil {
		return nil, nil, err
	}
	kept := rows[:0]
	removed, surviving := make(map[contract.ID]bool), make(map[contract.ID]bool)
	for _, row := range rows {
		if row.Kind == contract.RetainedCanonicalSupportKind {
			source, err := contract.InspectRetainedCanonicalRecord(row.Body)
			if err != nil {
				return nil, nil, err
			}
			if !retainedConsumers[row.RecordID] {
				removed[source.Entry.ValueState] = true
				continue
			}
			surviving[source.Entry.ValueState] = true
		}
		kept = append(kept, row)
	}
	var values []contract.ID
	for value := range removed {
		if !surviving[value] && !g.generatedCurrentSecretValue(value) {
			values = append(values, value)
		}
	}
	slices.SortFunc(values, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return kept, values, nil
}

func (g *generatedSelection) generatedCurrentSecretValue(id contract.ID) bool {
	if g == nil || g.session == nil {
		return false
	}
	for _, entry := range g.image.root.Names {
		valueEntry := g.session.valueEntry(entry.Slot)
		if valueEntry != nil && valueEntry.ConfidentialityClass == contract.Secret && valueEntry.ValueState == id {
			return true
		}
	}
	return false
}

func generatedRetainedCanonicalConsumers(rows []contract.SupportRecord) (map[contract.ID]bool, error) {
	retainedConsumers := make(map[contract.ID]bool)
	for _, row := range rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return nil, err
		}
		if carrier.VectorKind != contract.GeneratorVectorConsumers {
			continue
		}
		consumer, err := contract.InspectGeneratorConsumer(carrier.Row)
		if err != nil {
			return nil, err
		}
		if consumer.SubjectKind == contract.GeneratorConsumerRetainedCanonicalValue {
			retainedConsumers[consumer.SubjectID] = true
		}
	}
	return retainedConsumers, nil
}
