package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

type generatedResidueClosure struct {
	duty      contract.GeneratedDutyRecord
	attempt   generatedAttempt
	hazard    contract.GeneratedHazardRecord
	rows      []contract.SupportRecord
	locations []contract.GeneratorSliceLocation
	slices    contract.GeneratorDescriptor
}

// generatedRetirementAmbiguity closes an exact unknown retirement into its
// possible-live Hazard. Active ambiguity is recorded in that same transition.
// Neither path claims deletion, invalidation, revocation, or absence.

func (g *generatedSelection) generatedRetirementAmbiguity(ctx context.Context, dutyID contract.ID, ambiguity []byte, residue bool) (generatedResidueClosure, error) {
	if g == nil || (g.parent == nil) != (g.phase == nil) {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	active := g.parent != nil
	if !residue && !active {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	row, ok := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: dutyID}]
	if !ok {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	duty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || duty.Kind != contract.GeneratedDutyRetirement ||
		!active && (duty.Status != contract.GeneratedEffectUnknown || len(ambiguity) != 0) ||
		active && (duty.Status != contract.GeneratedEffectTransmitted || len(ambiguity) == 0) {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	historyBodies, err := g.vectors.resolve(contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorHistory, duty.History)
	if err != nil || len(historyBodies) == 0 {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	history, err := contract.InspectGeneratorHistory(historyBodies[len(historyBodies)-1])
	if err != nil || history.OwnerID != duty.DutyID || history.Outcome != duty.Status ||
		!history.ResultID.IsZero() || !history.ResultDigest.IsZero() || history.Edge != 0 || !history.NextAttemptID.IsZero() {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	a, ok := g.attempts[history.PredecessorAttemptID]
	if !ok || a.record.OwnerID != duty.DutyID || a.record.State != duty.Status || len(a.result) != 0 ||
		!active && a.record.Stage != contract.GeneratedStageTerminal ||
		active && (a.record.Stage != contract.GeneratedStageRetainedResult || g.phase.FrontierAttemptID != a.record.AttemptID ||
			g.parent.OperationID != a.record.OperationID || !generatedSelectionAnchored(g) && (g.phase.Attempts.Count != 1 || g.phase.Duties.Count != 1)) {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	var ambiguityRows []contract.SupportRecord
	if active {
		facts, err := contract.InspectGeneratorSafeFacts(ambiguity)
		if err != nil || facts.Disposition != contract.GeneratorDispositionUnknown || !generatedFactsMatchTemplate(facts.GeneratorSafeFacts, a.expected.Template) ||
			facts.RequestDigest != a.record.RequestDigest || facts.IntentDigest != a.expected.Template.IntentDigest ||
			residue && (facts.Reason == contract.GeneratorReasonIdentityConflict || !generatedResourceFactsMatch(facts.GeneratorSafeFacts, a.expected.TargetResourceDigest)) || uint32(len(ambiguity)) > a.expected.Use.MaxFacts {
			return generatedResidueClosure{}, contract.ErrRecord
		}
		body, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: a.record.ResultID, Facts: ambiguity})
		if err != nil {
			return generatedResidueClosure{}, err
		}
		a.record.Facts, ambiguityRows, err = generatedCarrierRows(a.record.DomainID, contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, [][]byte{body})
		if err != nil {
			return generatedResidueClosure{}, err
		}
	}
	contradiction, err := g.validateDeleteFacts(g.attempts[a.record.AttemptID])
	if err != nil || residue && contradiction {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	if residue {
		for _, body := range historyBodies {
			h, err := contract.InspectGeneratorHistory(body)
			prior, ok := g.attempts[h.PredecessorAttemptID]
			if err != nil || !ok {
				return generatedResidueClosure{}, contract.ErrRecord
			}
			contradiction, err := g.validateDeleteFacts(prior)
			if err != nil || contradiction {
				return generatedResidueClosure{}, contract.ErrRecord
			}
		}
	}
	target, err := g.retirementTarget(ctx, duty)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	consumers, err := g.vectors.resolve(contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorConsumers, duty.Consumers)
	if err != nil || len(consumers) != len(historyBodies) {
		return generatedResidueClosure{}, contract.ErrRecord
	}
	var consumer contract.GeneratorConsumer
	for _, body := range consumers {
		c, err := contract.InspectGeneratorConsumer(body)
		if err != nil || c.OwnerID != duty.DutyID || c.Purpose != contract.GeneratorConsumerAdoptLateOriginalResult {
			return generatedResidueClosure{}, contract.ErrRecord
		}
		if c.SubjectID == a.record.ResultID {
			if !consumer.SubjectID.IsZero() {
				return generatedResidueClosure{}, contract.ErrRecord
			}
			consumer = c
		}
	}
	if consumer.SubjectID.IsZero() {
		return generatedResidueClosure{}, contract.ErrRecord
	}

	a.record.State, a.record.Stage = contract.GeneratedEffectClosedWithResidue, contract.GeneratedStageTerminal
	if !residue {
		a.record.State = contract.GeneratedEffectUnknown
	}
	history.Outcome = a.record.State
	historyBody, err := contract.EncodeGeneratorHistory(history)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	attemptHistoryDescriptor, attemptHistory, err := generatedCarrierRows(a.record.DomainID, contract.GeneratedAttemptSupportKind, a.record.AttemptID,
		contract.GeneratorVectorHistory, [][]byte{historyBody})
	if err != nil {
		return generatedResidueClosure{}, err
	}
	a.record.History = attemptHistoryDescriptor
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	targetBody, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	hazardID := a.expected.Template.HazardID
	targetDescriptor, targetRows, err := generatedCarrierRows(a.record.DomainID, contract.GeneratedHazardSupportKind, hazardID,
		contract.GeneratorVectorTargets, [][]byte{targetBody})
	if err != nil {
		return generatedResidueClosure{}, err
	}
	hazardConsumers := make([][]byte, len(consumers))
	for i, body := range consumers {
		c, err := contract.InspectGeneratorConsumer(body)
		if err != nil {
			return generatedResidueClosure{}, err
		}
		c.OwnerID = hazardID
		hazardConsumers[i], err = contract.EncodeGeneratorConsumer(c)
		if err != nil {
			return generatedResidueClosure{}, err
		}
	}
	slices.SortFunc(hazardConsumers, bytes.Compare)
	consumerDescriptor, consumerRows, err := generatedCarrierRows(a.record.DomainID, contract.GeneratedHazardSupportKind, hazardID,
		contract.GeneratorVectorConsumers, hazardConsumers)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	historyBodies = slices.Clone(historyBodies)
	historyBodies[len(historyBodies)-1] = historyBody
	historyDescriptor, hazardHistory, err := generatedCarrierRows(a.record.DomainID, contract.GeneratedHazardSupportKind, hazardID,
		contract.GeneratorVectorHistory, historyBodies)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	var originalResults []contract.SupportRecord
	for _, body := range historyBodies {
		entry, err := contract.InspectGeneratorHistory(body)
		if err != nil {
			return generatedResidueClosure{}, err
		}
		original, ok := g.attempts[entry.PredecessorAttemptID]
		if !ok {
			return generatedResidueClosure{}, contract.ErrRecord
		}
		if len(original.result) == 0 {
			continue
		}
		row, ok := g.records[generatedRecordKey{kind: contract.GeneratedResultSupportKind, id: original.record.ResultID}]
		if !ok || !bytes.Equal(row.Body, original.result) {
			return generatedResidueClosure{}, contract.ErrRecord
		}
		originalResults = append(originalResults, row)
	}
	resultDescriptor, err := generatedHazardResultsDescriptor(duty.DomainID, originalResults)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	hazard := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: duty.DomainID, HazardID: hazardID,
		OriginalOperationID: a.record.OperationID, OriginalAttemptID: a.record.AttemptID, OwnerID: duty.DutyID,
		ResourceID: duty.ResourceID, ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID, ExecutorID: duty.ExecutorID,
		CredentialRouteID: duty.CredentialRouteID, DescriptorID: duty.DescriptorID,
		ResultContractID: duty.ResultContractID, Exposure: contract.GeneratedExposurePossibleLive, CapacityReservation: duty.CapacityReservation,
		CompletionClass: duty.CompletionClass, Fenced: 1, Eligibility: contract.GeneratedExposurePossibleLive,
		OriginalResults: resultDescriptor, Target: targetDescriptor,
		History: historyDescriptor, Support: duty.Support, Consumers: consumerDescriptor}
	hazardBody, err := contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		return generatedResidueClosure{}, err
	}

	rows := make([]contract.SupportRecord, 0, len(g.records)+len(attemptHistory)+len(targetRows)+len(consumerRows)+len(hazardHistory))
	for _, existing := range g.image.supportRecords() {
		if active && !generatedSelectionAnchored(g) && (existing.Kind == contract.GeneratedParentSupportKind || existing.Kind == contract.GeneratedPhaseSupportKind) && existing.RecordID == g.parent.OperationID {
			continue
		}
		if existing.Kind == contract.GeneratedDutySupportKind && existing.RecordID == duty.DutyID {
			continue
		}
		if existing.Kind == contract.GeneratedAttemptSupportKind && existing.RecordID == a.record.AttemptID {
			continue
		}
		if existing.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(existing.Body)
			if err != nil {
				return generatedResidueClosure{}, err
			}
			if carrier.OwnerKind == contract.GeneratedDutySupportKind && carrier.OwnerID == duty.DutyID ||
				carrier.VectorKind == contract.GeneratorVectorSlices ||
				active && !generatedSelectionAnchored(g) && carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == g.parent.OperationID && carrier.VectorKind != contract.GeneratorVectorSupport ||
				carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == a.record.AttemptID && (carrier.VectorKind == contract.GeneratorVectorHistory || active && carrier.VectorKind == contract.GeneratorVectorFacts) {
				continue
			}
		}
		rows = append(rows, existing)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: a.record.AttemptID, Body: attemptBody})
	rows = append(rows, attemptHistory...)
	if residue {
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: hazard.HazardID, Body: hazardBody})
		rows = append(rows, targetRows...)
		rows = append(rows, consumerRows...)
		rows = append(rows, hazardHistory...)
	} else {
		duty.Status = contract.GeneratedEffectUnknown
		var carriers []contract.SupportRecord
		// Parking changes only this invocation's frontier. Earlier invocations
		// keep their exact uncertainty, fresh-invocation edges and result uses.
		historyBodies = slices.Clone(historyBodies)
		historyBodies[len(historyBodies)-1] = historyBody
		duty.History, carriers, err = generatedCarrierRows(a.record.DomainID, contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorHistory, historyBodies)
		if err != nil {
			return generatedResidueClosure{}, err
		}
		rows = append(rows, carriers...)
		body, err := contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			return generatedResidueClosure{}, err
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: duty.DutyID, Body: body})
		// The immutable target, consumer and support carriers remain owned by
		// this Duty. Only its status and history change.
		for _, row := range g.image.supportRecords() {
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return generatedResidueClosure{}, err
			}
			if v.OwnerKind == contract.GeneratedDutySupportKind && v.OwnerID == duty.DutyID && v.VectorKind != contract.GeneratorVectorHistory {
				rows = append(rows, row)
			}
		}
	}
	rows = append(rows, ambiguityRows...)
	rows, locations, sliceDescriptor, err := g.generatedCloseContent(rows)
	if err != nil {
		return generatedResidueClosure{}, err
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	a.result = nil
	return generatedResidueClosure{duty: duty, attempt: a, hazard: hazard, rows: rows, locations: locations, slices: sliceDescriptor}, nil
}
