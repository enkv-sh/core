package core

import (
	"context"

	"enkv.sh/core/contract"
)

func (b *generatedSelectionBuilder) validateResourceCoordinates(rows []contract.SupportRecord, entries []contract.ValueEntry) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	type claim struct {
		resource, operation, attempt contract.ID
	}
	seen := make(map[[2]contract.ID]claim)
	add := func(resourceContract, resourceDigest contract.ID, current claim) error {
		if resourceContract.IsZero() || resourceDigest.IsZero() || current.resource.IsZero() || current.operation.IsZero() || current.attempt.IsZero() {
			return contract.ErrRecord
		}
		coordinate := [2]contract.ID{resourceContract, resourceDigest}
		if old, present := seen[coordinate]; present && old != current {
			return contract.ErrRecord
		}
		seen[coordinate] = current
		return nil
	}
	currentEntryCoordinates := make(map[[2]contract.ID]bool)
	for _, entry := range entries {
		if entry.ValueSource == contract.Generated {
			m := entry.Generated
			if m.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				continue
			}
			coordinate := [2]contract.ID{m.ResourceContractID, m.ResourceDigest}
			if currentEntryCoordinates[coordinate] {
				return contract.ErrRecord
			}
			currentEntryCoordinates[coordinate] = true
			if err := add(m.ResourceContractID, m.ResourceDigest, claim{m.ResourceIncarnationID, m.OriginOperationID, m.OriginAttemptID}); err != nil {
				return err
			}
		}
	}
	for _, row := range rows {
		var descriptor contract.GeneratorDescriptor
		switch row.Kind {
		case contract.GeneratedDutySupportKind:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return err
			}
			descriptor = duty.Target
		case contract.GeneratedHazardSupportKind:
			hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return err
			}
			descriptor = hazard.Target
		default:
			continue
		}
		if descriptor.Count == 0 {
			continue
		}
		targets, err := b.vectors.resolve(uint8(row.Kind), row.RecordID, contract.GeneratorVectorTargets, descriptor)
		if err != nil || len(targets) != 1 {
			return contract.ErrRecord
		}
		target, err := contract.InspectGeneratorTarget(targets[0])
		if err != nil {
			return err
		}
		if err := add(target.ResourceContractID, target.ResourceDigest, claim{target.ResourceID, target.OriginalOperationID, target.OriginalAttemptID}); err != nil {
			return err
		}
	}
	return nil
}

func generatedRetirementTemplate(bundle contract.GeneratorPlanBundle, old contract.ValueEntry) (contract.GeneratorAttemptTemplate, bool) {
	if old.ValueSource != contract.Generated || old.Generated.RetiringDutyPresent != 0 {
		return contract.GeneratorAttemptTemplate{}, false
	}
	wantDuty, err := contract.GeneratorDutyID(bundle.Header.DomainID, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
	if err != nil {
		return contract.GeneratorAttemptTemplate{}, false
	}
	var found contract.GeneratorAttemptTemplate
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageRetirement || lineage.Name != old.Name {
			continue
		}
		if !found.AttemptID.IsZero() || lineage.TemplateCount != 1 || lineage.DomainID != bundle.Header.DomainID ||
			lineage.OperationID != bundle.Header.OperationID || lineage.EntryIncarnationID != old.Incarnation ||
			lineage.Epoch != old.Generated.Epoch || lineage.IntentDigest != old.Generated.IntentDigest ||
			lineage.ResourceIncarnationID != old.Generated.ResourceIncarnationID {
			return contract.GeneratorAttemptTemplate{}, false
		}
		x := lineage.Templates[0]
		if x.Action != contract.GeneratorActionDelete || x.Branch != contract.GeneratorBranchInitial || x.DutyID != wantDuty || x.ResourceIncarnationID != old.Generated.ResourceIncarnationID ||
			x.ConfigContractID != old.Generated.ConfigContractID || x.ResourceContractID != old.Generated.ResourceContractID || x.IntentDigest != old.Generated.IntentDigest ||
			x.ResourceDigest != old.Generated.ResourceDigest || x.TargetKind != contract.GeneratorTargetOwnedResource || x.TargetSourceID != old.Generated.ResourceIncarnationID ||
			x.CompletionClass != old.Generated.CompletionClass {
			return contract.GeneratorAttemptTemplate{}, false
		}
		found = x
	}
	return found, !found.AttemptID.IsZero()
}

func generatedCreateResultID(domain, operation, attempt contract.ID) (contract.ID, error) {
	transmission, err := contract.GeneratorTransmissionID(attempt, contract.GeneratorActionCreate)
	if err != nil {
		return contract.ID{}, err
	}
	return contract.GeneratorResultID(domain, operation, attempt, transmission, contract.GeneratorActionCreate)
}

func (b *generatedSelectionBuilder) resolveRetirements(rows []contract.SupportRecord, entries []contract.ValueEntry) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	type retirement struct {
		duty   contract.ID
		target contract.GeneratorTarget
	}
	retiring := make(map[string]retirement)
	for _, row := range rows {
		if row.Kind != contract.GeneratedDutySupportKind {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return err
		}
		if duty.Kind != contract.GeneratedDutyRetirement {
			continue
		}
		target, err := g.retirementTarget(b.content.ctx, duty)
		if err != nil {
			return err
		}
		if err := b.claimTargetEvidence(target); err != nil {
			return err
		}
		if duty.Status == contract.GeneratedEffectNotStarted {
			if duty.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || duty.History != contract.EmptyGeneratorVector(contract.GeneratorVectorHistory) ||
				duty.Consumers != contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers) {
				return contract.ErrRecord
			}
		} else {
			if err := b.validateRetirementHistory(duty); err != nil {
				return err
			}
		}
		if _, duplicate := retiring[target.Name]; duplicate {
			return contract.ErrRecord
		}
		retiring[target.Name] = retirement{duty.DutyID, target}
		b.claimRecord(contract.GeneratedDutySupportKind, duty.DutyID)
	}
	if uint32(len(retiring)) != g.image.root.Generated.Retiring {
		return contract.ErrRecord
	}
	for _, entry := range entries {
		if entry.ValueSource != contract.Generated {
			continue
		}
		m := entry.Generated
		old, present := retiring[entry.Name]
		if !present {
			if m.RetiringDutyPresent != 0 || !m.RetiringDutyID.IsZero() {
				return contract.ErrRecord
			}
			continue
		}
		target := old.target
		if m.RetiringDutyPresent != 1 || m.RetiringDutyID != old.duty || m.ResourceIncarnationID == target.ResourceID ||
			m.ConfigContractID == target.ConfigContractID && m.ResourceDigest == target.ResourceDigest {
			return contract.ErrRecord
		}
	}
	return nil
}

func (g *generatedSelection) retirementTarget(ctx context.Context, d contract.GeneratedDutyRecord) (contract.GeneratorTarget, error) {
	if d.DomainID != g.image.root.Domain || d.OwnerID != d.DutyID || (d.Step != 1 && (d.CompletionClass != contract.GeneratedCompletionConfirmed || d.Step != 2)) || d.Kind != contract.GeneratedDutyRetirement {
		return contract.GeneratorTarget{}, contract.ErrRecord
	}
	id, err := contract.GeneratorDutyID(d.DomainID, d.OriginalOperationID, d.OriginalAttemptID, contract.GeneratedDutyRetirement)
	if err != nil || id != d.DutyID {
		return contract.GeneratorTarget{}, contract.ErrRecord
	}
	rows, err := g.vectors.resolve(contract.GeneratedDutySupportKind, d.DutyID, contract.GeneratorVectorTargets, d.Target)
	if err != nil || len(rows) != 1 {
		return contract.GeneratorTarget{}, contract.ErrRecord
	}
	target, err := contract.InspectGeneratorTarget(rows[0])
	if err != nil || target.OriginalOperationID != d.OriginalOperationID || target.OriginalAttemptID != d.OriginalAttemptID ||
		target.ResourceID != d.ResourceID || target.ConfigContractID != d.ConfigContractID || target.ResourceContractID != d.ResourceContractID || target.CompletionClass != d.CompletionClass {
		return contract.GeneratorTarget{}, contract.ErrRecord
	}
	facts, err := g.createTargetEvidence(ctx, target)
	if err != nil {
		return contract.GeneratorTarget{}, err
	}
	if facts.Disposition != contract.GeneratorDispositionCompleteCreate {
		return contract.GeneratorTarget{}, contract.ErrRecord
	}
	return target, nil
}

func (g *generatedSelection) createTargetEvidence(ctx context.Context, target contract.GeneratorTarget) (contract.GeneratorSafeFactsView, error) {
	domain := g.image.root.Domain
	result, err := generatedCreateResultID(domain, target.OriginalOperationID, target.OriginalAttemptID)
	if err != nil {
		return contract.GeneratorSafeFactsView{}, err
	}
	row, ok := g.record(contract.GeneratedCreateEvidenceSupportKind, result)
	if !ok {
		return g.liveCreateTargetEvidence(ctx, target, result)
	}
	evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
	if err != nil {
		return contract.GeneratorSafeFactsView{}, err
	}
	facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
	if err != nil {
		return contract.GeneratorSafeFactsView{}, err
	}
	var intent []byte
	if g.image.fragmentFacts != nil {
		intent, err = g.readSelectedLogicalSlice(ctx, contract.GeneratorContentIntent, facts.IntentDigest, evidence.Intent, contract.GeneratorIntentMaxLength)
	} else {
		intent, err = g.content.readLogical(contract.GeneratorContentIntent, facts.IntentDigest, evidence.Intent, contract.GeneratorIntentMaxLength)
	}
	if err != nil {
		return contract.GeneratorSafeFactsView{}, err
	}
	if err := contract.ValidateGeneratedTargetEvidence(domain, target, contract.GeneratedCreateEvidence(evidence), intent); err != nil {
		return contract.GeneratorSafeFactsView{}, err
	}
	return facts, nil
}

// liveCreateTargetEvidence validates the pre-handoff form used by an exact
// unselected-create cleanup. A detached owner must use kind-13 evidence; a
// cleanup that still retains its qualified original Result may bind that same
// target without first inventing a canonical handoff.

func (g *generatedSelection) liveCreateTargetEvidence(ctx context.Context, target contract.GeneratorTarget, resultID contract.ID) (contract.GeneratorSafeFactsView, error) {
	a, ok := g.attempts[target.OriginalAttemptID]
	if !ok || len(a.result) == 0 || a.record.DomainID != g.image.root.Domain ||
		a.record.OperationID != target.OriginalOperationID || a.record.ResultID != resultID ||
		a.record.ResourceID != target.ResourceID || a.record.ConfigContractID != target.ConfigContractID ||
		a.record.ResourceContractID != target.ResourceContractID || a.record.ResultContractID != target.ResultContractID ||
		a.record.CompletionClass != target.CompletionClass {
		return contract.GeneratorSafeFactsView{}, contract.ErrRecord
	}
	result, err := contract.InspectGeneratedResultRecord(a.result)
	if err != nil || result.SafeFacts.Disposition != contract.GeneratorDispositionCompleteCreate && result.SafeFacts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate ||
		!generatedResourceFactsMatch(result.SafeFacts.GeneratorSafeFacts, target.ResourceDigest) || !generatedResourceFactsMatch(result.SafeFacts.GeneratorSafeFacts, target.ResourceDigest) ||
		result.SafeFacts.IntentDigest != a.expected.Template.IntentDigest {
		return contract.GeneratorSafeFactsView{}, contract.ErrRecord
	}
	if g.image.fragmentFacts != nil {
		_, err = g.readSelectedSlice(ctx, contract.GeneratorContentIntent, result.SafeFacts.IntentDigest, contract.GeneratorIntentMaxLength)
	} else {
		_, err = g.content.read(contract.GeneratorContentIntent, result.SafeFacts.IntentDigest, contract.GeneratorIntentMaxLength)
	}
	if err != nil {
		return contract.GeneratorSafeFactsView{}, err
	}
	return result.SafeFacts, nil
}

// The caller has validated this exact target through the shared fact readers.
// Account for its evidence without copying the intent bytes a second time.
func (b *generatedSelectionBuilder) claimTargetEvidence(target contract.GeneratorTarget) error {
	if b == nil || b.facts == nil || b.content == nil || b.content.facts != b.facts.content {
		return contract.ErrRecord
	}
	g := b.facts
	result, err := generatedCreateResultID(g.image.root.Domain, target.OriginalOperationID, target.OriginalAttemptID)
	if err != nil {
		return err
	}
	var intent contract.ID
	row, present := g.record(contract.GeneratedCreateEvidenceSupportKind, result)
	if present {
		evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
		if err != nil {
			return err
		}
		facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
		if err != nil {
			return err
		}
		intent = facts.IntentDigest
	} else {
		a, ok := g.attempts[target.OriginalAttemptID]
		if !ok || a.record.OperationID != target.OriginalOperationID || a.record.ResultID != result || len(a.result) == 0 {
			return contract.ErrRecord
		}
		intent = a.expected.Template.IntentDigest
	}
	key := generatedContentKey{contract.GeneratorContentIntent, intent}
	if _, ok := g.content.locations[key]; !ok {
		return contract.ErrRecord
	}
	if present {
		b.claimRecord(contract.GeneratedCreateEvidenceSupportKind, result)
	}
	b.content.claimed[key] = true
	return nil
}
