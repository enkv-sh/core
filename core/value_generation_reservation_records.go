package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

func generatedInitialRows(input generatedReservationInput, declaration contract.GeneratorDeclarationView, phaseID contract.ID, lineageIndex uint16, x contract.GeneratorAttemptTemplate, use contract.GeneratorResultUse) ([]contract.SupportRecord, error) {
	parent := input.parent
	requestDigest, ok := generatedRequestDigest(input.requestBindings, x)
	if !ok {
		return nil, contract.ErrRecord
	}
	empty := contract.EmptyGeneratorVector
	rows, err := generatedInitialLineageRows(input.graph, declaration)
	if err != nil {
		return nil, err
	}
	var consumers [][]byte
	context, err := contract.GeneratorResultUseDigest(use)
	if err != nil {
		return nil, err
	}
	for _, purpose := range []uint8{contract.GeneratorConsumerDeriveSelectedResult, contract.GeneratorConsumerAdoptLateOriginalResult} {
		body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: x.DutyID, MaterialID: parent.MaterialID,
			ContextDigest: context, SubjectKind: contract.GeneratorConsumerOriginalResult, SubjectID: x.ResultID, Purpose: purpose})
		if err != nil {
			return nil, err
		}
		consumers = append(consumers, body)
	}
	for i := 0; i < declaration.EntryCount(); i++ {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			return nil, err
		}
		if entry.Kind != contract.GeneratorDeclarationRetained {
			continue
		}
		canonical, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
		if err != nil {
			return nil, err
		}
		core, err := contract.ValueCoreForEntry(parent.DomainID, input.finished.Material.Core.CompatibilityID, canonical.Entry)
		if err != nil {
			return nil, err
		}
		context, err := contract.ValueMaterialContextDigest(core)
		if err != nil {
			return nil, err
		}
		sourceID, err := contract.AdmissionEntryDigest(canonical)
		if err != nil {
			return nil, err
		}
		body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: x.DutyID, MaterialID: canonical.Entry.ValueState,
			ContextDigest: context, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue, SubjectID: sourceID, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
		if err != nil {
			return nil, err
		}
		consumers = append(consumers, body)
		rows = append(rows, contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: sourceID, Body: entry.Payload})
	}
	slices.SortFunc(consumers, bytes.Compare)
	consumerDescriptor, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratedDutySupportKind, x.DutyID, contract.GeneratorVectorConsumers, consumers)
	if err != nil {
		return nil, err
	}
	rows = append(rows, carriers...)
	for _, source := range input.graph.SourceUses {
		consumer, err := contract.GeneratorAcceptedSourceConsumer(parent.OperationID, parent.MaterialID, source)
		if err != nil {
			return nil, err
		}
		body, err := contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			return nil, err
		}
		descriptor, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratedParentSupportKind, parent.OperationID, contract.GeneratorVectorConsumers, [][]byte{body})
		if err != nil || descriptor != source.Consumers {
			return nil, contract.ErrRecord
		}
		rows = append(rows, carriers...)
	}
	attempt, duty, err := generatedCreateRecords(contract.GeneratedParentRecord(parent), x, requestDigest, consumerDescriptor)
	if err != nil {
		return nil, err
	}
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		return nil, err
	}
	dutyBody, err := contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		return nil, err
	}
	aRow := contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: x.AttemptID, Body: attemptBody}
	dRow := contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: x.DutyID, Body: dutyBody}
	attemptRows := []contract.SupportRecord{aRow}
	dutyRows := []contract.SupportRecord{dRow}
	for _, lineage := range input.graph.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate || lineage.Templates[0].AttemptID == x.AttemptID {
			continue
		}
		original := lineage.Templates[0]
		_, originalUse, ok := generatedTemplate(input.graph, original.AttemptID)
		if !ok {
			return nil, contract.ErrRecord
		}
		originalDigest, ok := generatedRequestDigest(input.requestBindings, original)
		if !ok {
			return nil, contract.ErrRecord
		}
		entered, err := generatedScheduledCreateRows(contract.GeneratedParentRecord(parent), original, originalUse, originalDigest)
		if err != nil {
			return nil, err
		}
		for _, row := range entered {
			switch row.Kind {
			case contract.GeneratedAttemptSupportKind:
				attemptRows = append(attemptRows, row)
			case contract.GeneratedDutySupportKind:
				dutyRows = append(dutyRows, row)
			}
		}
		rows = append(rows, entered...)
	}
	slices.SortFunc(attemptRows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	slices.SortFunc(dutyRows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	attemptSet, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseAttempts, parent.DomainID, attemptRows)
	if err != nil {
		return nil, err
	}
	dutySet, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, parent.DomainID, dutyRows)
	if err != nil {
		return nil, err
	}
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: parent.DomainID, OperationID: parent.OperationID, OwnerID: parent.OperationID, PlanGraphID: parent.PlanGraphID,
		UsePlanDigest: parent.UsePlanDigest, PhaseID: phaseID, Phase: 1, LineageIndex: lineageIndex, FrontierAttemptID: x.AttemptID, Stage: contract.GeneratedStageRetainedResult,
		AcceptedResults: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseResults), Attempts: attemptSet, Duties: dutySet,
		Hazards: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards), PendingReleases: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases), Proofs: empty(contract.GeneratorVectorProofs)}
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		return nil, err
	}
	material, err := contract.EncodeOperationMaterialRecord(input.finished.Material)
	if err != nil {
		return nil, err
	}
	parentPlan, err := contract.AppendGeneratedParentSupportPlan(nil, parent)
	if err != nil {
		return nil, err
	}
	return append(rows, aRow, dRow, contract.SupportRecord{Kind: contract.OperationMaterialSupportKind, RecordID: parent.MaterialID, Body: material},
		contract.SupportRecord{Kind: contract.GeneratedParentSupportKind, RecordID: parent.OperationID, Body: parentPlan[contract.SupportRecordOverhead:]}, contract.SupportRecord{Kind: contract.GeneratedPhaseSupportKind, RecordID: parent.OperationID, Body: phaseBody}), nil
}

func generatedCarrierRows(domain contract.ID, ownerKind uint8, owner contract.ID, kind contract.GeneratorVectorKind, bodies [][]byte) (contract.GeneratorDescriptor, []contract.SupportRecord, error) {
	descriptor, err := contract.GeneratorVectorDescriptor(kind, bodies)
	if err != nil {
		return descriptor, nil, err
	}
	rows := make([]contract.SupportRecord, len(bodies))
	for i, body := range bodies {
		carrier := contract.GeneratorVectorCarrier{Schema: 1, DomainID: domain, OwnerKind: ownerKind, OwnerID: owner, VectorKind: kind,
			Ordinal: uint32(i), Vector: descriptor, Row: body}
		encoded, err := contract.EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			return descriptor, nil, err
		}
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil {
			return descriptor, nil, err
		}
		rows[i] = contract.SupportRecord{Kind: contract.GeneratorVectorSupportKind, RecordID: id, Body: encoded}
	}
	return descriptor, rows, nil
}

func generatedFragmentRows(id contract.ID, body []byte) ([]contract.SupportRecord, error) {
	if id.IsZero() || len(body) == 0 || len(body) > contract.GeneratedFragmentMaxPayload*contract.MaxChildPages*2 {
		return nil, contract.ErrRecordCapacity
	}
	count := (len(body) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
	rows := make([]contract.SupportRecord, count)
	whole := contract.Hash(body)
	for i := range rows {
		offset := i * contract.GeneratedFragmentMaxPayload
		fragment := contract.GeneratedFragment{Schema: 1, BlobID: id, Index: uint16(i), Count: uint16(count), TotalLength: uint64(len(body)), WholeDigest: whole,
			Offset: uint32(offset), Payload: body[offset:min(offset+contract.GeneratedFragmentMaxPayload, len(body))]}
		encoded, err := contract.EncodeGeneratedFragment(fragment)
		if err != nil {
			return nil, err
		}
		id, err := contract.GeneratorFragmentID(id, uint16(i))
		if err != nil {
			return nil, err
		}
		rows[i] = contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: encoded}
	}
	return rows, nil
}
