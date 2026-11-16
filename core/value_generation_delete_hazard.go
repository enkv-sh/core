package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

func generatedHazardResultsDescriptor(domain contract.ID, results []contract.SupportRecord) (contract.GeneratorDescriptor, error) {
	slices.SortFunc(results, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	return contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, domain, results)
}

func (b *generatedSelectionBuilder) resolveDeleteHazard(bundle contract.GeneratorPlanBundle, a contract.GeneratedAttemptRecord, h contract.GeneratedHazardRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	x, _, ok := generatedTemplate(bundle, a.AttemptID)
	if !ok || x.Action != contract.GeneratorActionDelete || h.OriginalOperationID != a.OperationID || h.OriginalAttemptID != a.AttemptID ||
		h.HazardID != x.HazardID || h.OwnerID != a.OwnerID || h.ResourceID != a.ResourceID || h.ConfigContractID != a.ConfigContractID ||
		h.ResourceContractID != a.ResourceContractID || h.ExecutorID != a.ExecutorID || h.CredentialRouteID != a.CredentialRouteID ||
		h.DescriptorID != a.DescriptorID || h.ResultContractID != a.ResultContractID || h.CompletionClass != a.CompletionClass ||
		h.Exposure != contract.GeneratedExposurePossibleLive || h.Fenced != 1 ||
		a.State != contract.GeneratedEffectClosedWithResidue || a.Stage != contract.GeneratedStageTerminal {
		return contract.ErrRecord
	}
	if _, hasDuty := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.OwnerID}]; hasDuty {
		return contract.ErrRecord
	}
	targets, err := b.vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorTargets, h.Target)
	if err != nil || len(targets) != 1 {
		return contract.ErrRecord
	}
	target, err := contract.InspectGeneratorTarget(targets[0])
	if err != nil || g.validateDeleteTarget(b.content.ctx, bundle, a, target) != nil {
		return contract.ErrRecord
	}
	if err := b.claimTargetEvidence(target); err != nil {
		return err
	}
	history, err := b.vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorHistory, h.History)
	if err != nil || len(history) == 0 {
		return contract.ErrRecord
	}
	var results []contract.SupportRecord
	operations := make(map[contract.ID]bool, len(history))
	anchorSeen := false
	for i, body := range history {
		entry, err := contract.InspectGeneratorHistory(body)
		row, ok := b.claimRecord(contract.GeneratedAttemptSupportKind, entry.PredecessorAttemptID)
		if err != nil || !ok {
			return contract.ErrRecord
		}
		original, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || original.OwnerID != h.OwnerID || original.ResourceID != h.ResourceID || original.ConfigContractID != h.ConfigContractID ||
			original.ResourceContractID != h.ResourceContractID || original.ExecutorID != h.ExecutorID || original.CredentialRouteID != h.CredentialRouteID ||
			original.DescriptorID != h.DescriptorID || original.ResultContractID != h.ResultContractID ||
			original.CompletionClass != h.CompletionClass || operations[original.OperationID] ||
			!g.deleteHazards[original.AttemptID].IsZero() {
			return contract.ErrRecord
		}
		if original == a {
			if anchorSeen {
				return contract.ErrRecord
			}
			anchorSeen = true
		}
		if i+1 < len(history) {
			continuable := original.State == contract.GeneratedEffectUnknown ||
				original == a && original.State == contract.GeneratedEffectClosedWithResidue ||
				original.CompletionClass == contract.GeneratedCompletionConfirmed &&
					(original.State == contract.GeneratedEffectSucceeded || original.State == contract.GeneratedEffectFailedTerminal)
			if original.Stage != contract.GeneratedStageTerminal || !continuable {
				return contract.ErrRecord
			}
		} else if original != a {
			terminal := original.Stage == contract.GeneratedStageTerminal &&
				(original.State == contract.GeneratedEffectUnknown || original.State == contract.GeneratedEffectSucceeded ||
					original.State == contract.GeneratedEffectFailedTerminal)
			if !terminal && (original.Stage != contract.GeneratedStageRetainedResult || original.State != contract.GeneratedEffectTransmitted) {
				return contract.ErrRecord
			}
		}
		operations[original.OperationID] = true
		originalBundle, err := b.retainedGraph(original.OperationID)
		if err != nil || g.validateDeleteTarget(b.content.ctx, originalBundle, original, target) != nil {
			return contract.ErrRecord
		}
		if err := b.claimTargetEvidence(target); err != nil {
			return err
		}
		material, err := b.operationMaterial(originalBundle)
		if err != nil {
			return err
		}
		if err := b.resolveAttempt(originalBundle, material, original, target.ResourceDigest); err != nil {
			return err
		}
		g.deleteHazards[original.AttemptID] = h.HazardID
		if row, present := g.records[generatedRecordKey{contract.GeneratedResultSupportKind, original.ResultID}]; present {
			results = append(results, row)
		}
	}
	if !anchorSeen {
		return contract.ErrRecord
	}
	descriptor, err := generatedHazardResultsDescriptor(h.DomainID, results)
	if err != nil || descriptor != h.OriginalResults {
		return contract.ErrRecord
	}
	b.claimRecord(contract.GeneratedHazardSupportKind, h.HazardID)
	return nil
}

func (b *generatedSelectionBuilder) validateDeleteHazardVectors(a generatedAttempt, h contract.GeneratedHazardRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	history, err := b.vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorHistory, h.History)
	if err != nil || len(history) == 0 || h.Consumers.Count != uint32(len(history)) {
		return contract.ErrRecord
	}
	wanted := make(map[contract.ID]contract.GeneratorConsumer, len(history))
	anchorSeen := false
	for i, body := range history {
		entry, err := contract.InspectGeneratorHistory(body)
		original, ok := g.attempts[entry.PredecessorAttemptID]
		if err != nil || !ok || g.deleteHazards[original.record.AttemptID] != h.HazardID {
			return contract.ErrRecord
		}
		want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: original.record.AttemptID, OwnerID: h.OwnerID, Outcome: original.record.State}
		if !entry.ResultID.IsZero() && len(original.result) != 0 {
			want.ResultID, want.ResultDigest = original.record.ResultID, contract.Hash(original.result)
		}
		if original.record.AttemptID == a.record.AttemptID {
			if anchorSeen {
				return contract.ErrRecord
			}
			anchorSeen = true
		}
		if i+1 < len(history) {
			next, err := contract.InspectGeneratorHistory(history[i+1])
			if err != nil {
				return err
			}
			want.NextAttemptID, want.Edge = next.PredecessorAttemptID, 4
		}
		if entry != want || b.validateDeleteHistory(original, contract.GeneratedAttemptSupportKind, original.record.AttemptID, original.record.History) != nil {
			return contract.ErrRecord
		}
		contradiction, err := g.validateDeleteFacts(original)
		if err != nil || contradiction && h.Eligibility != 0 || original.record.State == contract.GeneratedEffectUnknown && original.record.Facts.Count != 1 {
			return contract.ErrRecord
		}
		context, err := contract.GeneratorResultUseDigest(original.expected.Use)
		if err != nil {
			return err
		}
		wanted[original.record.ResultID] = contract.GeneratorConsumer{Schema: 1, OwnerID: h.HazardID,
			MaterialID: original.material.Core.OperationMaterialID, ContextDigest: context, SubjectKind: contract.GeneratorConsumerOriginalResult,
			SubjectID: original.record.ResultID, Purpose: contract.GeneratorConsumerAdoptLateOriginalResult}
	}
	if !anchorSeen {
		return contract.ErrRecord
	}
	consumers, err := b.vectors.resolve(contract.GeneratedHazardSupportKind, h.HazardID, contract.GeneratorVectorConsumers, h.Consumers)
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
	return nil
}
