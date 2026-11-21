package core

import (
	"bytes"
	"context"
	"fmt"

	"enkv.sh/core/contract"
)

func (b *generatedSelectionBuilder) resolveRetirementAttempts(rows []contract.SupportRecord) error {
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
		if d.Kind != contract.GeneratedDutyRetirement || d.Status == contract.GeneratedEffectNotStarted {
			continue
		}
		history, err := b.vectors.resolve(contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorHistory, d.History)
		if err != nil || len(history) == 0 {
			return contract.ErrRecord
		}
		for _, body := range history {
			h, err := contract.InspectGeneratorHistory(body)
			if err != nil {
				return err
			}
			if _, resolved := g.attempts[h.PredecessorAttemptID]; resolved {
				continue
			}
			row, ok := g.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, h.PredecessorAttemptID}]
			if !ok {
				return contract.ErrRecord
			}
			a, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil || a.OwnerID != d.DutyID {
				return contract.ErrRecord
			}
			bundle, err := b.retainedGraph(a.OperationID)
			if err != nil {
				return err
			}
			target, err := g.generatedDeleteAttemptTarget(b.content.ctx, bundle, a)
			if err != nil {
				return fmt.Errorf("retained delete target: %w", err)
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

func (g *generatedSelection) retirementAttemptTarget(ctx context.Context, bundle contract.GeneratorPlanBundle, a contract.GeneratedAttemptRecord) (contract.GeneratorTarget, error) {
	target, duty, err := g.generatedDeleteAttemptTargetAndDuty(ctx, bundle, a)
	if err != nil {
		return contract.GeneratorTarget{}, err
	}
	if duty.Kind != contract.GeneratedDutyRetirement {
		return contract.GeneratorTarget{}, contract.ErrRecord
	}
	return target, nil
}

// generatedDeleteAttemptTarget binds an entered delete to its exact retained
// retirement or unselected-create cleanup owner. These owners share the delete
// result relation, but their target roots have different origins.

func (g *generatedSelection) generatedDeleteAttemptTarget(ctx context.Context, bundle contract.GeneratorPlanBundle, a contract.GeneratedAttemptRecord) (contract.GeneratorTarget, error) {
	target, _, err := g.generatedDeleteAttemptTargetAndSource(ctx, bundle, a)
	return target, err
}

func (g *generatedSelection) generatedDeleteSource(owner contract.ID) (contract.GeneratedDeleteSource, error) {
	if row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, owner}]; ok {
		return contract.InspectGeneratedDeleteSource(row)
	}
	var source contract.GeneratedDeleteSource
	found := false
	for _, row := range g.records {
		if row.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		h, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return source, err
		}
		if h.OwnerID != owner {
			continue
		}
		if found {
			return source, contract.ErrRecord
		}
		source, err = contract.InspectGeneratedDeleteSource(row)
		if err != nil {
			return source, err
		}
		found = true
	}
	if !found {
		return source, contract.ErrRecord
	}
	return source, nil
}

func (g *generatedSelection) generatedDeleteAttemptTargetAndSource(ctx context.Context, bundle contract.GeneratorPlanBundle, a contract.GeneratedAttemptRecord) (contract.GeneratorTarget, contract.GeneratedDeleteSource, error) {
	source, err := g.generatedDeleteSource(a.OwnerID)
	if err != nil {
		return contract.GeneratorTarget{}, source, err
	}
	if source.Record.Kind == contract.GeneratedDutySupportKind {
		target, _, err := g.generatedDeleteAttemptTargetAndDuty(ctx, bundle, a)
		return target, source, err
	}
	h := source.Hazard
	if h.DomainID != g.image.root.Domain || h.OwnerID != a.OwnerID || h.ResourceID != a.ResourceID || h.ConfigContractID != a.ConfigContractID ||
		h.ResourceContractID != a.ResourceContractID || h.ExecutorID != a.ExecutorID || h.CredentialRouteID != a.CredentialRouteID ||
		h.DescriptorID != a.DescriptorID || h.CompletionClass != a.CompletionClass || h.Fenced != 1 ||
		h.Eligibility != 0 && h.Eligibility != h.Exposure {
		return contract.GeneratorTarget{}, source, contract.ErrRecord
	}
	target, err := g.generatedCleanupTarget(contract.GeneratedHazardSupportKind, h.HazardID, h.Target)
	if err != nil {
		return contract.GeneratorTarget{}, source, err
	}
	if target.ResourceID != h.ResourceID || target.ConfigContractID != h.ConfigContractID || target.ResourceContractID != h.ResourceContractID ||
		target.CompletionClass != h.CompletionClass {
		return contract.GeneratorTarget{}, source, contract.ErrRecord
	}
	if err := g.validateDeleteTarget(ctx, bundle, a, target); err != nil {
		return contract.GeneratorTarget{}, source, err
	}
	for _, lineage := range bundle.Lineages {
		if lineage.LineageID == a.LineageID && lineage.Purpose == contract.GeneratorLineageCleanup {
			return target, source, nil
		}
	}
	return contract.GeneratorTarget{}, source, contract.ErrRecord
}

func (g *generatedSelection) generatedDeleteAttemptTargetAndDuty(ctx context.Context, bundle contract.GeneratorPlanBundle, a contract.GeneratedAttemptRecord) (contract.GeneratorTarget, contract.GeneratedDutyRecord, error) {
	row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.OwnerID}]
	if !ok {
		return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, contract.ErrRecord
	}
	d, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || d.ResourceID != a.ResourceID || d.ConfigContractID != a.ConfigContractID || d.ResourceContractID != a.ResourceContractID ||
		d.ExecutorID != a.ExecutorID || d.CredentialRouteID != a.CredentialRouteID || d.DescriptorID != a.DescriptorID ||
		d.CompletionClass != a.CompletionClass {
		return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, contract.ErrRecord
	}
	var target contract.GeneratorTarget
	switch d.Kind {
	case contract.GeneratedDutyRetirement:
		if d.ResultContractID != a.ResultContractID {
			return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, contract.ErrRecord
		}
		target, err = g.retirementTarget(ctx, d)
	case contract.GeneratedDutyUnselectedCleanup:
		if d.DomainID != g.image.root.Domain || d.OwnerID != d.DutyID || (d.Step != 1 && (d.CompletionClass != contract.GeneratedCompletionConfirmed || d.Step != 2)) ||
			d.Status != contract.GeneratedEffectSucceeded {
			return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, contract.ErrRecord
		}
		var rows [][]byte
		rows, err = g.vectors.resolve(contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorTargets, d.Target)
		if err == nil && len(rows) == 1 {
			target, err = contract.InspectGeneratorTarget(rows[0])
		} else if err == nil {
			err = contract.ErrRecord
		}
		if err == nil && (target.OriginalOperationID != d.OriginalOperationID || target.OriginalAttemptID != d.OriginalAttemptID ||
			target.ResourceID != d.ResourceID || target.ConfigContractID != d.ConfigContractID || target.ResourceContractID != d.ResourceContractID ||
			target.ResultContractID != d.ResultContractID || target.CompletionClass != d.CompletionClass) {
			err = contract.ErrRecord
		}
	default:
		err = contract.ErrRecord
	}
	if err != nil {
		return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, err
	}
	if err := g.validateDeleteTarget(ctx, bundle, a, target); err != nil {
		return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, err
	}
	for _, lineage := range bundle.Lineages {
		if lineage.LineageID != a.LineageID {
			continue
		}
		want := contract.GeneratorLineageRetirement
		if d.Kind == contract.GeneratedDutyUnselectedCleanup {
			want = contract.GeneratorLineageCleanup
		}
		if lineage.Purpose != want {
			return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, contract.ErrRecord
		}
		return target, d, nil
	}
	return contract.GeneratorTarget{}, contract.GeneratedDutyRecord{}, contract.ErrRecord
}

func (g *generatedSelection) validateDeleteTarget(ctx context.Context, bundle contract.GeneratorPlanBundle, a contract.GeneratedAttemptRecord, target contract.GeneratorTarget) error {
	facts, err := g.createTargetEvidence(ctx, target)
	if err != nil {
		return err
	}
	if target.ResourceID != a.ResourceID || target.ConfigContractID != a.ConfigContractID || target.ResourceContractID != a.ResourceContractID ||
		target.CompletionClass != a.CompletionClass {
		return contract.ErrRecord
	}
	for _, lineage := range bundle.Lineages {
		if lineage.LineageID != a.LineageID {
			continue
		}
		x := lineage.Templates[0]
		if lineage.Purpose != contract.GeneratorLineageRetirement && lineage.Purpose != contract.GeneratorLineageCleanup || lineage.Name != target.Name || lineage.EntryIncarnationID != target.IncarnationID ||
			lineage.Epoch != target.Epoch || lineage.ResourceIncarnationID != target.ResourceID ||
			x.IntentDigest != facts.IntentDigest {
			return contract.ErrRecord
		}
		if lineage.Purpose == contract.GeneratorLineageRetirement {
			duty, err := contract.GeneratorDutyID(a.DomainID, target.OriginalOperationID, target.OriginalAttemptID, contract.GeneratedDutyRetirement)
			if err != nil || a.OwnerID != duty || facts.Disposition != contract.GeneratorDispositionCompleteCreate || x.TargetKind != contract.GeneratorTargetOwnedResource {
				return contract.ErrRecord
			}
		}
		source := target.ResourceID
		switch x.TargetKind {
		case contract.GeneratorTargetOwnedResource:
			if x.ResourceDigest != target.ResourceDigest {
				return contract.ErrRecord
			}
		case contract.GeneratorTargetResultResourceSlot:
			if !x.ResourceDigest.IsZero() && x.ResourceDigest != target.ResourceDigest {
				return contract.ErrRecord
			}
			source, err = generatedCreateResultID(a.DomainID, target.OriginalOperationID, target.OriginalAttemptID)
			if err != nil {
				return err
			}
		default:
			return contract.ErrRecord
		}
		if x.Action != contract.GeneratorActionDelete || x.TargetSourceID != source {
			return contract.ErrRecord
		}
		return nil
	}
	return contract.ErrRecord
}

func (b *generatedSelectionBuilder) validateGeneratedDeleteAttempt(a generatedAttempt) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	source, err := g.generatedDeleteSource(a.record.OwnerID)
	if err != nil {
		return fmt.Errorf("delete source: %w", err)
	}
	b.claimRecord(source.Record.Kind, source.SourceID)
	d := source.Duty
	if source.Record.Kind == contract.GeneratedDutySupportKind && (d.Kind != contract.GeneratedDutyRetirement && d.Kind != contract.GeneratedDutyUnselectedCleanup ||
		d.CompletionClass != contract.GeneratedCompletionConfirmed && (a.record.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) ||
			d.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress))) ||
		source.Record.Kind == contract.GeneratedHazardSupportKind && source.CompletionClass != contract.GeneratedCompletionConfirmed && a.record.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
		return fmt.Errorf("delete duty shape: %w", contract.ErrRecord)
	}
	if len(a.result) == 0 {
		switch a.record.State {
		case contract.GeneratedEffectTransmitted:
			if a.record.Stage != contract.GeneratedStageRetainedResult || a.record.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) {
				return fmt.Errorf("delete transmitted: %w", contract.ErrRecord)
			}
		case contract.GeneratedEffectUnknown:
			if a.record.Stage != contract.GeneratedStageTerminal || a.record.Facts.Count != 1 {
				return fmt.Errorf("delete unknown: %w", contract.ErrRecord)
			}
			if _, err := g.validateDeleteFacts(a); err != nil {
				return fmt.Errorf("delete unknown facts: %w", err)
			}
		default:
			return fmt.Errorf("delete empty-result state: %w", contract.ErrRecord)
		}
	} else {
		if a.record.State != contract.GeneratedEffectSucceeded && (a.record.CompletionClass != contract.GeneratedCompletionConfirmed || a.record.State != contract.GeneratedEffectFailedTerminal) || a.record.Stage != contract.GeneratedStageTerminal {
			return fmt.Errorf("delete result state: %w", contract.ErrRecord)
		}
		if _, err := g.validateDeleteFacts(a); err != nil {
			return fmt.Errorf("delete result facts: %w", err)
		}
	}
	if err := b.validateDeleteHistory(a, contract.GeneratedAttemptSupportKind, a.record.AttemptID, a.record.History); err != nil {
		return fmt.Errorf("delete attempt history: %w", err)
	}
	return nil
}

func (b *generatedSelectionBuilder) validateRetirementHistory(d contract.GeneratedDutyRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	rows, err := b.vectors.resolve(contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorHistory, d.History)
	if err != nil || len(rows) == 0 {
		return contract.ErrRecord
	}
	wanted := make(map[contract.ID]contract.GeneratorConsumer, len(rows))
	operations := make(map[contract.ID]bool, len(rows))
	for i, body := range rows {
		h, err := contract.InspectGeneratorHistory(body)
		if err != nil {
			return err
		}
		a, ok := g.attempts[h.PredecessorAttemptID]
		if !ok || a.record.OwnerID != d.DutyID || a.expected.Template.Action != contract.GeneratorActionDelete || operations[a.record.OperationID] {
			return contract.ErrRecord
		}
		operations[a.record.OperationID] = true
		want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: d.DutyID, Outcome: a.record.State}
		if len(a.result) != 0 {
			want.ResultID, want.ResultDigest = a.record.ResultID, contract.Hash(a.result)
		}
		if i+1 < len(rows) {
			if (a.record.State != contract.GeneratedEffectUnknown && (d.CompletionClass != contract.GeneratedCompletionConfirmed || a.record.State != contract.GeneratedEffectSucceeded && a.record.State != contract.GeneratedEffectFailedTerminal)) || a.record.Stage != contract.GeneratedStageTerminal {
				return contract.ErrRecord
			}
			next, err := contract.InspectGeneratorHistory(rows[i+1])
			if err != nil {
				return err
			}
			want.NextAttemptID, want.Edge = next.PredecessorAttemptID, 4
		} else if d.Status != a.record.State {
			return contract.ErrRecord
		}
		if h != want {
			return contract.ErrRecord
		}
		context, err := contract.GeneratorResultUseDigest(a.expected.Use)
		if err != nil {
			return err
		}
		wanted[a.record.ResultID] = contract.GeneratorConsumer{Schema: 1, OwnerID: d.DutyID, MaterialID: a.material.Core.OperationMaterialID,
			ContextDigest: context, SubjectKind: contract.GeneratorConsumerOriginalResult, SubjectID: a.record.ResultID, Purpose: contract.GeneratorConsumerAdoptLateOriginalResult}
	}
	for _, a := range g.attempts {
		if a.record.OwnerID == d.DutyID && a.expected.Template.Action == contract.GeneratorActionDelete {
			if _, present := wanted[a.record.ResultID]; !present {
				return contract.ErrRecord
			}
		}
	}
	consumers, err := b.vectors.resolve(contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorConsumers, d.Consumers)
	if err != nil || len(consumers) != len(wanted) {
		return contract.ErrRecord
	}
	for _, body := range consumers {
		consumer, err := contract.InspectGeneratorConsumer(body)
		want, ok := wanted[consumer.SubjectID]
		if err != nil || !ok || consumer != want {
			return contract.ErrRecord
		}
		delete(wanted, consumer.SubjectID)
		key := materialIdentity{contract.OperationSeedMaterialKind, consumer.MaterialID}
		g.consumers[key] = append(g.consumers[key], consumer)
	}
	if d.CompletionClass == contract.GeneratedCompletionConfirmed {
		if _, err := g.controlledRetirementProgress(d, nil, true); err != nil {
			return err
		}
	}
	return nil
}

func (b *generatedSelectionBuilder) validateDeleteHistory(a generatedAttempt, kind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	rows, err := b.vectors.resolve(kind, owner, contract.GeneratorVectorHistory, descriptor)
	if err != nil || len(rows) != 1 {
		return contract.ErrRecord
	}
	history, err := contract.InspectGeneratorHistory(rows[0])
	want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: a.record.OwnerID, Outcome: a.record.State}
	if !history.ResultID.IsZero() && len(a.result) != 0 {
		want.ResultID, want.ResultDigest = a.record.ResultID, contract.Hash(a.result)
	}
	if err != nil || history != want {
		return contract.ErrRecord
	}
	return nil
}

func (g *generatedSelection) deleteResultRecorded(a generatedAttempt) (bool, error) {
	rows, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorHistory, a.record.History)
	if err != nil || len(rows) != 1 {
		return false, contract.ErrRecord
	}
	history, err := contract.InspectGeneratorHistory(rows[0])
	if err != nil || history.PredecessorAttemptID != a.record.AttemptID {
		return false, contract.ErrRecord
	}
	return !history.ResultID.IsZero(), nil
}

func (g *generatedSelection) validateDeleteFacts(a generatedAttempt) (contradiction bool, err error) {
	recorded, err := g.deleteResultRecorded(a)
	if err != nil || recorded && len(a.result) == 0 {
		return false, contract.ErrRecord
	}
	facts, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, a.record.Facts)
	if err != nil || len(facts) > 1 || recorded && len(facts) != 1 {
		return false, contract.ErrRecord
	}
	if len(facts) == 0 {
		return false, nil
	}
	fact, err := contract.InspectGeneratorFactsRow(facts[0])
	if err != nil || fact.ResultID != a.record.ResultID || uint32(len(fact.Facts)) > a.expected.Use.MaxFacts {
		return false, contract.ErrRecord
	}
	if recorded {
		result, err := contract.DecodeGeneratedResultRecord(a.result)
		if err != nil {
			return false, err
		}
		body, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
		if err != nil || !bytes.Equal(fact.Facts, body) {
			return false, contract.ErrRecord
		}
		return result.SafeFacts.Disposition == contract.GeneratorDispositionContinuedUsability || result.SafeFacts.Disposition == contract.GeneratorDispositionConflictingBinding, nil
	}
	unknown, err := contract.InspectGeneratorSafeFacts(fact.Facts)
	if err != nil || unknown.Disposition != contract.GeneratorDispositionUnknown || !generatedFactsMatchTemplate(unknown.GeneratorSafeFacts, a.expected.Template) ||
		unknown.RequestDigest != a.record.RequestDigest || unknown.IntentDigest != a.expected.Template.IntentDigest {
		return false, contract.ErrRecord
	}
	sameTarget := generatedResourceFactsMatch(unknown.GeneratorSafeFacts, a.expected.TargetResourceDigest)
	if a.expected.Template.TargetKind == contract.GeneratorTargetResultResourceSlot && !sameTarget {
		return false, contract.ErrRecord
	}
	return unknown.Reason == contract.GeneratorReasonIdentityConflict || !sameTarget, nil
}
