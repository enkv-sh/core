package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// generatedNextOriginal returns the first create lineage that has not entered.
// Generator graphs are canonical, so this is also the stable dispatch order.
func generatedNextOriginal(g *generatedSelection) (uint16, contract.GeneratorAttemptTemplate, contract.GeneratorResultUse, bool) {
	if g == nil || g.parent == nil || len(g.bundles) == 0 {
		return 0, contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
	}
	bundle := g.bundles[0]
	for i, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate || lineage.TemplateCount == 0 {
			continue
		}
		x := lineage.Templates[0]
		if _, entered := g.attempts[x.AttemptID]; entered {
			continue
		}
		if _, entered := g.releases[x.AttemptID]; entered {
			continue
		}
		_, use, ok := generatedTemplate(bundle, x.AttemptID)
		return uint16(i), x, use, ok
	}
	return 0, contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
}

func generatedNextOriginalAfter(g *generatedSelection, lineageID contract.ID) (uint16, contract.GeneratorAttemptTemplate, bool) {
	if g == nil || len(g.bundles) == 0 {
		return 0, contract.GeneratorAttemptTemplate{}, false
	}
	reached := false
	for i, lineage := range g.bundles[0].Lineages {
		if lineage.LineageID == lineageID {
			reached = true
			continue
		}
		if reached && lineage.Purpose == contract.GeneratorLineageCreate {
			return uint16(i), lineage.Templates[0], true
		}
	}
	return 0, contract.GeneratorAttemptTemplate{}, false
}

// generatedNextNoEffect returns the fixed same-lineage successor reached by a
// qualified no-effect result. The graph has already fixed the branch and its
// result-use contract; this lookup does not grant a dispatch right by itself.
func generatedNextNoEffect(g *generatedSelection, current contract.GeneratorAttemptTemplate) (contract.GeneratorAttemptTemplate, contract.GeneratorResultUse, bool) {
	if g == nil || len(g.bundles) == 0 || current.Action != contract.GeneratorActionCreate {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
	}
	nextBranch, present, err := contract.GeneratorSuccessorBranch(current.Branch, contract.GeneratorGuardQualifiedNoEffect)
	if err != nil || !present {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
	}
	bundle := g.bundles[0]
	for _, lineage := range bundle.Lineages {
		if lineage.LineageID != current.LineageID || int(nextBranch) >= int(lineage.TemplateCount) {
			continue
		}
		next := lineage.Templates[nextBranch]
		if next.PredecessorAttemptID != current.AttemptID {
			return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
		}
		_, use, ok := generatedTemplate(bundle, next.AttemptID)
		return next, use, ok
	}
	return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
}

func generatedScheduledCreateRows(parent contract.GeneratedParentRecord, x contract.GeneratorAttemptTemplate,
	use contract.GeneratorResultUse, requestDigest contract.ID) ([]contract.SupportRecord, error) {
	context, err := contract.GeneratorResultUseDigest(use)
	if err != nil {
		return nil, err
	}
	var consumerBodies [][]byte
	for _, purpose := range []uint8{contract.GeneratorConsumerDeriveSelectedResult, contract.GeneratorConsumerAdoptLateOriginalResult} {
		body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: x.DutyID,
			MaterialID: parent.MaterialID, ContextDigest: context, SubjectKind: contract.GeneratorConsumerOriginalResult, SubjectID: x.ResultID, Purpose: purpose})
		if err != nil {
			return nil, err
		}
		consumerBodies = append(consumerBodies, body)
	}
	slices.SortFunc(consumerBodies, bytes.Compare)
	consumers, carriers, err := generatedCarrierRows(parent.DomainID, contract.GeneratedDutySupportKind, x.DutyID, contract.GeneratorVectorConsumers, consumerBodies)
	if err != nil {
		return nil, err
	}
	attempt, duty, err := generatedCreateRecords(parent, x, requestDigest, consumers)
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
	return append(carriers,
		contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: x.AttemptID, Body: attemptBody},
		contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: x.DutyID, Body: dutyBody}), nil
}

func generatedScheduledCreateRowsWithHistory(g *generatedSelection, parent contract.GeneratedParentRecord, x contract.GeneratorAttemptTemplate,
	use contract.GeneratorResultUse, requestDigest contract.ID, recorded contract.GeneratedAttemptRecord, resultDigest contract.ID) ([]contract.SupportRecord, error) {
	rows, err := generatedScheduledCreateRows(parent, x, use, requestDigest)
	if err != nil {
		return nil, err
	}
	var reverse []contract.GeneratorAttemptTemplate
	for current := x; ; {
		reverse = append(reverse, current)
		if current.PredecessorAttemptID.IsZero() {
			break
		}
		var ok bool
		current, _, ok = generatedTemplate(g.bundles[0], current.PredecessorAttemptID)
		if !ok || current.Action != contract.GeneratorActionCreate || current.LineageID != x.LineageID {
			return nil, contract.ErrRecord
		}
	}
	history := make([]contract.GeneratorHistory, 0, len(reverse))
	for i := len(reverse) - 1; i >= 0; i-- {
		template := reverse[i]
		h := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: template.AttemptID, OwnerID: template.DutyID}
		if template.AttemptID == x.AttemptID {
			h.Outcome = contract.GeneratedEffectTransmitted
		} else {
			a, ok := g.attempts[template.AttemptID]
			if !ok {
				return nil, contract.ErrRecord
			}
			record, result := a.record, a.result
			if record.AttemptID == recorded.AttemptID {
				record = recorded
			}
			h.Outcome = record.State
			if len(result) != 0 {
				h.ResultID, h.ResultDigest = record.ResultID, contract.Hash(result)
			}
			if record.AttemptID == recorded.AttemptID {
				if !resultDigest.IsZero() {
					h.ResultID, h.ResultDigest = record.ResultID, resultDigest
				}
			}
			next := reverse[i-1]
			h.NextAttemptID = next.AttemptID
			if next.Branch == contract.GeneratorBranchNoEffect || next.Branch == contract.GeneratorBranchResidueThenNoEffect {
				h.Edge = 1
			} else {
				h.Edge = 2
			}
		}
		history = append(history, h)
	}
	bodies := make([][]byte, len(history))
	for i := range history {
		bodies[i], err = contract.EncodeGeneratorHistory(history[i])
		if err != nil {
			return nil, err
		}
	}
	for _, owner := range []struct {
		kind uint8
		id   contract.ID
	}{
		{contract.GeneratedAttemptSupportKind, x.AttemptID},
		{contract.GeneratedDutySupportKind, x.DutyID},
	} {
		descriptor, carriers, err := generatedCarrierRows(parent.DomainID, owner.kind, owner.id, contract.GeneratorVectorHistory, bodies)
		if err != nil {
			return nil, err
		}
		for i := range rows {
			if rows[i].Kind != owner.kind || rows[i].RecordID != owner.id {
				continue
			}
			switch owner.kind {
			case contract.GeneratedAttemptSupportKind:
				a, err := contract.InspectGeneratedAttemptRecord(rows[i].Body)
				if err != nil {
					return nil, err
				}
				a.History = descriptor
				rows[i].Body, err = contract.EncodeGeneratedAttemptRecord(a)
				if err != nil {
					return nil, err
				}
			case contract.GeneratedDutySupportKind:
				d, err := contract.InspectGeneratedDutyRecord(rows[i].Body)
				if err != nil {
					return nil, err
				}
				d.History = descriptor
				rows[i].Body, err = contract.EncodeGeneratedDutyRecord(d)
				if err != nil {
					return nil, err
				}
			}
		}
		rows = append(rows, carriers...)
	}
	return rows, nil
}

func generatedRefreshClosureCounts(closure *format.GeneratedClosure, rows []contract.SupportRecord) {
	closure.Results, closure.Attempts, closure.Duties, closure.Retiring, closure.Hazards, closure.Materials, closure.PendingReleases = 0, 0, 0, 0, 0, 0, 0
	var owners []contract.ID
	if !closure.ActiveOwner.IsZero() {
		owners = append(owners, closure.ActiveOwner)
	}
	for _, row := range rows {
		switch row.Kind {
		case contract.OperationMaterialSupportKind:
			closure.Materials++
		case contract.GeneratedResultSupportKind:
			closure.Results++
		case contract.GeneratedAttemptSupportKind:
			closure.Attempts++
		case contract.GeneratedDutySupportKind:
			closure.Duties++
			if duty, err := contract.InspectGeneratedDutyRecord(row.Body); err == nil && duty.Kind == contract.GeneratedDutyRetirement {
				closure.Retiring++
			}
			owners = append(owners, row.RecordID)
		case contract.GeneratedHazardSupportKind:
			closure.Hazards++
			owners = append(owners, row.RecordID)
		case contract.PendingInboxReleaseSupportKind:
			closure.PendingReleases++
			owners = append(owners, row.RecordID)
		}
	}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	closure.LiveOwners, _ = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, slices.Compact(owners))
}

// Both the first original and later originals use the same template-owned
// record shape. Their callers retain their distinct consumer construction.
func generatedCreateRecords(parent contract.GeneratedParentRecord, x contract.GeneratorAttemptTemplate, requestDigest contract.ID, consumers contract.GeneratorDescriptor) (contract.GeneratedAttemptRecord, contract.GeneratedDutyRecord, error) {
	empty := contract.EmptyGeneratorVector
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		return contract.GeneratedAttemptRecord{}, contract.GeneratedDutyRecord{}, err
	}
	attempt := contract.GeneratedAttemptRecord{Schema: contract.GeneratedAttemptRecordSchema, DomainID: parent.DomainID, OperationID: parent.OperationID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TemplateDigest: template, PredecessorAttemptID: x.PredecessorAttemptID, OwnerID: x.DutyID,
		ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, InboxID: x.InboxID,
		ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, RequestDigest: requestDigest,
		State: contract.GeneratedEffectTransmitted, Stage: contract.GeneratedStageRetainedResult, CompletionClass: x.CompletionClass,
		Facts: empty(contract.GeneratorVectorFacts), Progress: empty(contract.GeneratorVectorProgress),
		Support: empty(contract.GeneratorVectorSupport), History: empty(contract.GeneratorVectorHistory)}
	duty := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, DomainID: parent.DomainID, DutyID: x.DutyID,
		OriginalOperationID: parent.OperationID, OriginalAttemptID: x.AttemptID, OwnerID: x.DutyID,
		ResourceID: x.ResourceIncarnationID, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID,
		CredentialRouteID: x.CredentialRouteID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID,
		Kind: contract.GeneratedDutyCreate, CompletionClass: x.CompletionClass, Step: 1, Status: contract.GeneratedEffectTransmitted, CapacityReservation: parent.Capacity,
		Target: empty(contract.GeneratorVectorTargets), Progress: empty(contract.GeneratorVectorProgress),
		History: empty(contract.GeneratorVectorHistory), Support: empty(contract.GeneratorVectorSupport), Consumers: consumers}
	attempt.LifecycleMode, duty.LifecycleMode = x.LifecycleMode, x.LifecycleMode
	return attempt, duty, nil
}
