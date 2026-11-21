package core

import "enkv.sh/core/contract"

func (b *generatedSelectionBuilder) resolveHazards(rows []contract.SupportRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	for _, row := range rows {
		if row.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		if b.recordClaimed(generatedRecordKey{contract.GeneratedHazardSupportKind, row.RecordID}) {
			continue
		}
		h, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil || h.DomainID != g.image.root.Domain {
			return contract.ErrRecord
		}
		if original, ok := g.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, h.OriginalAttemptID}]; ok {
			a, err := contract.InspectGeneratedAttemptRecord(original.Body)
			if err != nil {
				return err
			}
			bundle, err := b.retainedGraph(h.OriginalOperationID)
			if err != nil {
				return err
			}
			x, _, ok := generatedTemplate(bundle, a.AttemptID)
			if !ok {
				return contract.ErrRecord
			}
			if x.Action == contract.GeneratorActionDelete {
				if err := b.resolveDeleteHazard(bundle, a, h); err != nil {
					return err
				}
				continue
			}
		}
		result, err := generatedCreateResultID(h.DomainID, h.OriginalOperationID, h.OriginalAttemptID)
		if err != nil {
			return err
		}
		if _, detached := g.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, result}]; detached {
			// Detached evidence is checked after the selected vector owners have
			// been resolved. Its presence does not restore an original reader.
			continue
		}
		selected, err := b.resolveDetachedCreate(h.OriginalOperationID, h.OriginalAttemptID)
		if err != nil {
			return err
		}
		a := selected.record
		if _, hasDuty := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.OwnerID}]; hasDuty ||
			h.HazardID != selected.expected.Template.HazardID || h.OwnerID != a.OwnerID || h.ResourceID != a.ResourceID ||
			h.ConfigContractID != a.ConfigContractID || h.ResourceContractID != a.ResourceContractID || h.ExecutorID != a.ExecutorID ||
			h.CredentialRouteID != a.CredentialRouteID || h.DescriptorID != a.DescriptorID ||
			h.ResultContractID != a.ResultContractID || h.CompletionClass != a.CompletionClass {
			return contract.ErrRecord
		}
		switch a.State {
		case contract.GeneratedEffectClosedWithResidue:
			if h.Fenced != 1 {
				return contract.ErrRecord
			}
		case contract.GeneratedEffectFailedTerminal:
			result, err := contract.InspectGeneratedResultRecord(selected.result)
			if err != nil || result.Disposition() != contract.GeneratorDispositionOwnedUnusableCreate ||
				h.Fenced == 1 && (g.parent != nil && g.parent.OperationID == h.OriginalOperationID || h.Exposure != contract.GeneratedExposureLateEffect) {
				return contract.ErrRecord
			}
		default:
			return contract.ErrRecord
		}
		var results []contract.SupportRecord
		if len(selected.result) != 0 {
			results = append(results, g.records[generatedRecordKey{contract.GeneratedResultSupportKind, a.ResultID}])
		}
		descriptor, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, h.DomainID, results)
		if err != nil || descriptor != h.OriginalResults {
			return contract.ErrRecord
		}
		if len(selected.result) == 0 {
			if h.Exposure != contract.GeneratedExposurePossibleLive || h.Eligibility != 0 ||
				h.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) {
				return contract.ErrRecord
			}
		} else if h.Exposure != contract.GeneratedExposureLateEffect {
			return contract.ErrRecord
		}
		b.claimRecord(contract.GeneratedHazardSupportKind, h.HazardID)
	}
	return nil
}

func (b *generatedSelectionBuilder) resolveDetachedCreateHazards(rows []contract.SupportRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	for _, row := range rows {
		if row.Kind != contract.GeneratedHazardSupportKind || b.recordClaimed(generatedRecordKey{contract.GeneratedHazardSupportKind, row.RecordID}) {
			continue
		}
		h, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil || h.Exposure != contract.GeneratedExposureLateEffect {
			return contract.ErrRecord
		}
		owner, err := contract.GeneratorDutyID(h.DomainID, h.OriginalOperationID, h.OriginalAttemptID, contract.GeneratedDutyCreate)
		if err != nil || h.OwnerID != owner {
			return contract.ErrRecord
		}
		hazard, err := contract.GeneratorHazardID(h.DomainID, h.OriginalAttemptID)
		if err != nil || h.HazardID != hazard {
			return contract.ErrRecord
		}
		if _, present := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, owner}]; present {
			return contract.ErrRecord
		}
		result, err := generatedCreateResultID(h.DomainID, h.OriginalOperationID, h.OriginalAttemptID)
		if err != nil {
			return err
		}
		if _, present := g.records[generatedRecordKey{contract.GeneratedResultSupportKind, result}]; present {
			return contract.ErrRecord
		}
		evidenceRow, ok := b.claimRecord(contract.GeneratedCreateEvidenceSupportKind, result)
		if !ok {
			return contract.ErrRecord
		}
		descriptor, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, h.DomainID, []contract.SupportRecord{evidenceRow})
		if err != nil || descriptor != h.OriginalResults {
			return contract.ErrRecord
		}
		evidence, err := contract.InspectGeneratedCreateEvidence(evidenceRow.Body)
		if err != nil {
			return err
		}
		core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
		if err != nil || core.ExecutorID != h.ExecutorID || core.DescriptorID != h.DescriptorID || evidence.CredentialRouteID != h.CredentialRouteID {
			return contract.ErrRecord
		}
		facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
		if err != nil || h.Fenced == 0 && core.Disposition(facts.Disposition) != contract.GeneratorDispositionOwnedUnusableCreate {
			return contract.ErrRecord
		}
		targets, err := b.vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorTargets, h.Target)
		if err != nil || len(targets) != 1 {
			return contract.ErrRecord
		}
		target, err := contract.InspectGeneratorTarget(targets[0])
		if err != nil || target.OriginalOperationID != h.OriginalOperationID || target.OriginalAttemptID != h.OriginalAttemptID ||
			target.ResourceID != h.ResourceID || target.ConfigContractID != h.ConfigContractID || target.ResourceContractID != h.ResourceContractID ||
			target.ResultContractID != h.ResultContractID || target.CompletionClass != h.CompletionClass {
			return contract.ErrRecord
		}
		intent, err := b.content.readLogical(contract.GeneratorContentIntent, facts.IntentDigest, evidence.Intent, contract.GeneratorIntentMaxLength)
		if err != nil {
			return err
		}
		if err := contract.ValidateGeneratedTargetEvidence(h.DomainID, target, contract.GeneratedCreateEvidence(evidence), intent); err != nil {
			return err
		}
		history, err := b.vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorHistory, h.History)
		if err != nil {
			return err
		}
		deleteConsumers := make(map[contract.ID]contract.GeneratorConsumer, len(history))
		historyAttempts := make(map[contract.ID]bool, len(history))
		operations := make(map[contract.ID]bool, len(history))
		for i, body := range history {
			entry, err := contract.InspectGeneratorHistory(body)
			deleting, present := g.attempts[entry.PredecessorAttemptID]
			if err != nil || !present || deleting.expected.Template.Action != contract.GeneratorActionDelete || deleting.record.OwnerID != h.OwnerID ||
				operations[deleting.record.OperationID] {
				return contract.ErrRecord
			}
			operations[deleting.record.OperationID] = true
			historyAttempts[deleting.record.AttemptID] = true
			var bundle contract.GeneratorPlanBundle
			for _, candidate := range g.bundles {
				if candidate.Header.OperationID == deleting.record.OperationID {
					bundle = candidate
					break
				}
			}
			selectedTarget, source, err := g.generatedDeleteAttemptTargetAndSource(b.content.ctx, bundle, deleting.record)
			if err != nil {
				return err
			}
			if source.Record.Kind != contract.GeneratedHazardSupportKind || source.SourceID != h.HazardID || selectedTarget != target {
				return contract.ErrRecord
			}
			want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: deleting.record.AttemptID,
				OwnerID: h.OwnerID, Outcome: deleting.record.State}
			if len(deleting.result) != 0 {
				want.ResultID, want.ResultDigest = deleting.record.ResultID, contract.Hash(deleting.result)
			}
			if i+1 < len(history) {
				next, err := contract.InspectGeneratorHistory(history[i+1])
				if err != nil || deleting.record.Stage != contract.GeneratedStageTerminal ||
					deleting.record.State != contract.GeneratedEffectUnknown && (h.CompletionClass != contract.GeneratedCompletionConfirmed ||
						deleting.record.State != contract.GeneratedEffectSucceeded && deleting.record.State != contract.GeneratedEffectFailedTerminal) {
					return contract.ErrRecord
				}
				want.NextAttemptID, want.Edge = next.PredecessorAttemptID, 4
			}
			if entry != want || b.validateDeleteHistory(deleting, contract.GeneratedAttemptSupportKind, deleting.record.AttemptID, deleting.record.History) != nil {
				return contract.ErrRecord
			}
			context, err := contract.GeneratorResultUseDigest(deleting.expected.Use)
			if err != nil {
				return err
			}
			deleteConsumers[deleting.record.ResultID] = contract.GeneratorConsumer{Schema: 1, OwnerID: h.HazardID,
				MaterialID: deleting.material.Core.OperationMaterialID, ContextDigest: context, SubjectKind: contract.GeneratorConsumerOriginalResult,
				SubjectID: deleting.record.ResultID, Purpose: contract.GeneratorConsumerAdoptLateOriginalResult}
		}
		for id, deleting := range g.attempts {
			if deleting.expected.Template.Action == contract.GeneratorActionDelete && deleting.record.OwnerID == h.OwnerID && !historyAttempts[id] {
				return contract.ErrRecord
			}
		}
		consumers, err := b.vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorConsumers, h.Consumers)
		if err != nil {
			return err
		}
		for _, body := range consumers {
			consumer, err := contract.InspectGeneratorConsumer(body)
			if err != nil {
				return contract.ErrRecord
			}
			if consumer.SubjectKind == contract.GeneratorConsumerRetainedCanonicalValue {
				if b.claimCanonicalConsumer(contract.GeneratedHazardSupportKind, h.HazardID, false, consumer) != nil {
					return contract.ErrRecord
				}
				continue
			}
			want, present := deleteConsumers[consumer.SubjectID]
			if !present || consumer != want {
				return contract.ErrRecord
			}
			delete(deleteConsumers, consumer.SubjectID)
			g.consumers[materialIdentity{contract.OperationSeedMaterialKind, consumer.MaterialID}] = append(g.consumers[materialIdentity{contract.OperationSeedMaterialKind, consumer.MaterialID}], consumer)
		}
		if len(deleteConsumers) != 0 {
			return contract.ErrRecord
		}
		b.claimRecord(contract.GeneratedHazardSupportKind, h.HazardID)
	}
	return nil
}

func (b *generatedSelectionBuilder) validateCreateHazardVectors(a generatedAttempt, h contract.GeneratedHazardRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	if err := b.resolveResultConsumers(a, contract.GeneratedHazardSupportKind, h.HazardID, h.Consumers, false); err != nil {
		return err
	}
	if len(a.result) != 0 {
		return b.validateCreateFactsAndTarget(a, contract.GeneratedHazardSupportKind, h.HazardID, h.Target)
	}
	rows, err := b.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, a.record.Facts)
	if err != nil || len(rows) > 1 {
		return contract.ErrRecord
	}
	for _, row := range rows {
		fact, err := contract.InspectGeneratorFactsRow(row)
		if err != nil || fact.ResultID != a.record.ResultID || uint32(len(fact.Facts)) > a.expected.Use.MaxFacts {
			return contract.ErrRecord
		}
		facts, err := contract.InspectGeneratorSafeFacts(fact.Facts)
		if err != nil || facts.Disposition != contract.GeneratorDispositionUnknown || facts.RequestDigest != a.record.RequestDigest ||
			!generatedFactsMatchTemplate(facts.GeneratorSafeFacts, a.expected.Template) || facts.IntentDigest != a.expected.Template.IntentDigest {
			return contract.ErrRecord
		}
	}
	return nil
}
