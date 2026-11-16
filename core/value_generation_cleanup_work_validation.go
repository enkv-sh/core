package core

import (
	"fmt"

	"enkv.sh/core/contract"
)

func (b *generatedSelectionBuilder) resolveUnselectedCreates(rows []contract.SupportRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	for _, row := range rows {
		if row.Kind != contract.GeneratedDutySupportKind {
			continue
		}
		d, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return err
		}
		if d.Kind != contract.GeneratedDutyUnselectedCleanup {
			continue
		}
		if d.DomainID != g.image.root.Domain || d.Status != contract.GeneratedEffectSucceeded ||
			g.parent != nil && d.OriginalOperationID == g.parent.OperationID ||
			d.CompletionClass != contract.GeneratedCompletionConfirmed && d.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
			return contract.ErrRecord
		}
		selected, err := b.resolveDetachedCreate(d.OriginalOperationID, d.OriginalAttemptID)
		if err != nil || !generatedCreateDutyMatches(d, selected.record) || len(selected.result) == 0 {
			return contract.ErrRecord
		}
		b.claimRecord(contract.GeneratedDutySupportKind, d.DutyID)
	}
	return nil
}

func (b *generatedSelectionBuilder) resolveDetachedCreate(operation, attempt contract.ID) (generatedAttempt, error) {
	if b == nil || b.facts == nil {
		return generatedAttempt{}, contract.ErrRecord
	}
	g := b.facts
	bundle, err := b.retainedGraph(operation)
	if err != nil {
		return generatedAttempt{}, err
	}
	row, ok := b.claimRecord(contract.GeneratedAttemptSupportKind, attempt)
	if !ok {
		return generatedAttempt{}, contract.ErrRecord
	}
	a, err := contract.InspectGeneratedAttemptRecord(row.Body)
	if err != nil || a.Stage != contract.GeneratedStageTerminal || a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
		return generatedAttempt{}, contract.ErrRecord
	}
	material, err := b.operationMaterial(bundle)
	if err != nil {
		return generatedAttempt{}, err
	}
	if err := b.resolveAttempt(bundle, material, a, contract.ID{}); err != nil {
		return generatedAttempt{}, err
	}
	selected := g.attempts[a.AttemptID]
	intent, err := b.content.read(contract.GeneratorContentIntent, selected.expected.Template.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return generatedAttempt{}, err
	}
	digest, err := contract.GeneratorIntentDigest(intent)
	if err != nil || digest != selected.expected.Template.IntentDigest {
		return generatedAttempt{}, contract.ErrRecord
	}
	return selected, nil
}

func (g *generatedSelection) retainedGraph(operation contract.ID) (contract.GeneratorPlanBundle, error) {
	if g == nil {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	for _, bundle := range g.bundles {
		if bundle.Header.OperationID == operation {
			return cloneGeneratorPlanBundle(bundle), nil
		}
	}
	return contract.GeneratorPlanBundle{}, contract.ErrRecord
}

func (b *generatedSelectionBuilder) retainedGraph(operation contract.ID) (contract.GeneratorPlanBundle, error) {
	if b == nil || b.facts == nil {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	if bundle, err := b.facts.retainedGraph(operation); err == nil {
		return bundle, nil
	}
	bundle, err := b.content.graphForOperation(operation)
	if err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	if !generatedOperationGraphValid(bundle) {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	if _, err := b.content.graph(bundle.UsePlan.PlanGraphID); err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	b.facts.bundles = append(b.facts.bundles, bundle)
	return bundle, nil
}

func (b *generatedSelectionBuilder) resolveOrdinaryCleanupAttempts(rows []contract.SupportRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	for _, row := range rows {
		if row.Kind != contract.GeneratedDutySupportKind && row.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		source, err := contract.InspectGeneratedDeleteSource(row)
		if err != nil {
			return err
		}
		if row.Kind == contract.GeneratedDutySupportKind && source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup || row.Kind == contract.GeneratedHazardSupportKind && source.Hazard.Fenced != 1 {
			continue
		}
		history, err := b.vectors.resolve(row.Kind, row.RecordID, contract.GeneratorVectorHistory, source.History)
		if err != nil {
			return err
		}
		var createPrefix uint32
		if original, present := g.attempts[source.OriginalAttemptID]; present && original.expected.Template.Action == contract.GeneratorActionCreate {
			createPrefix = original.record.History.Count
			if createPrefix > uint32(len(history)) {
				return contract.ErrRecord
			}
		}
		for ordinal, body := range history {
			if uint32(ordinal) < createPrefix {
				// validateCreateHistories independently checks this complete immutable
				// prefix against the actual original graph and Attempt.History.
				continue
			}
			h, err := contract.InspectGeneratorHistory(body)
			if err != nil {
				return err
			}
			if _, present := g.attempts[h.PredecessorAttemptID]; present {
				continue
			}
			original, ok := g.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, h.PredecessorAttemptID}]
			if !ok {
				return contract.ErrRecord
			}
			a, err := contract.InspectGeneratedAttemptRecord(original.Body)
			if err != nil {
				return err
			}
			bundle, err := b.retainedGraph(a.OperationID)
			if err != nil {
				return fmt.Errorf("ordinary cleanup predecessor graph: %w", err)
			}
			x, _, ok := generatedTemplate(bundle, a.AttemptID)
			if !ok {
				return contract.ErrRecord
			}
			if x.Action != contract.GeneratorActionDelete {
				return contract.ErrRecord
			}
			target, actualSource, err := g.generatedDeleteAttemptTargetAndSource(b.content.ctx, bundle, a)
			if err != nil {
				return err
			}
			if actualSource.Record.Kind != row.Kind || actualSource.SourceID != row.RecordID {
				return contract.ErrRecord
			}
			if err := b.claimTargetEvidence(target); err != nil {
				return err
			}
			material, err := b.operationMaterial(bundle)
			if err != nil {
				return err
			}
			if err := b.resolveAttempt(bundle, material, a, target.ResourceDigest); err != nil {
				return err
			}
		}
	}
	return nil
}
