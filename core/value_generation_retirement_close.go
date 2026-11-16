package core

import (
	"context"

	"enkv.sh/core/contract"
)

type generatedRetirementClose struct {
	duty      contract.GeneratedDutyRecord
	attempt   generatedAttempt
	release   contract.PendingInboxReleaseRecord
	material  contract.ID
	slices    contract.GeneratorDescriptor
	locations []contract.GeneratorSliceLocation
	rows      []contract.SupportRecord
	nonfinal  bool
	materials []contract.ID
}

// generatedRetirementAcknowledgement builds the detached selected closure for
// one exact acknowledged retirement. Acknowledgement cannot close the stronger
// invalidation-confirmed class. The pending release is rooted only after the
// complete result body and the selected handoff revision are fixed.

func (g *generatedSelection) generatedRetirementAcknowledgement(ctx context.Context, attemptID, handoffRevision contract.ID) (generatedRetirementClose, error) {
	if g == nil || g.parent == nil || g.phase == nil || handoffRevision.IsZero() {
		return generatedRetirementClose{}, contract.ErrRecord
	}
	a, ok := g.attempts[attemptID]
	if ok && a.record.CompletionClass == contract.GeneratedCompletionConfirmed {
		return g.generatedControlledRetirementClose(ctx, a, handoffRevision)
	}
	if !ok || len(a.result) == 0 || a.record.State != contract.GeneratedEffectSucceeded ||
		a.record.Stage != contract.GeneratedStageTerminal || a.record.CompletionClass != contract.GeneratedCompletionAcknowledged {
		return generatedRetirementClose{}, contract.ErrRecord
	}
	row, ok := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: a.record.OwnerID}]
	if !ok {
		return generatedRetirementClose{}, contract.ErrRecord
	}
	duty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.Status != contract.GeneratedEffectSucceeded ||
		duty.CompletionClass != contract.GeneratedCompletionAcknowledged {
		return generatedRetirementClose{}, contract.ErrRecord
	}
	result, err := contract.InspectGeneratedResultRecord(a.result)
	if err != nil || result.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || !generatedResourceFactsMatch(result.SafeFacts.GeneratorSafeFacts, a.expected.TargetResourceDigest) {
		return generatedRetirementClose{}, contract.ErrRecord
	}
	contradiction, err := g.validateDeleteFacts(a)
	if err != nil || contradiction {
		return generatedRetirementClose{}, contract.ErrRecord
	}
	bundle, err := g.retainedGraph(a.record.OperationID)
	if err != nil {
		return generatedRetirementClose{}, err
	}
	if _, err := g.retirementAttemptTarget(ctx, bundle, a.record); err != nil {
		return generatedRetirementClose{}, err
	}

	source, err := contract.InspectGeneratedDeleteSource(row)
	if err != nil {
		return generatedRetirementClose{}, err
	}
	target, err := g.retirementAttemptTarget(ctx, bundle, a.record)
	if err != nil {
		return generatedRetirementClose{}, err
	}
	closed, err := g.generatedDeleteSourceClosure(a, source, target, a.result, handoffRevision)
	if err != nil {
		return generatedRetirementClose{}, err
	}
	return generatedRetirementClose{duty: duty, attempt: closed.attempt, release: closed.release,
		material: a.material.Core.OperationMaterialID, materials: closed.materials, slices: closed.slices,
		locations: closed.locations, rows: closed.rows}, nil
}

func (g *generatedSelection) generatedResultSelectedByEntry(result contract.ID) bool {
	for _, entry := range g.image.root.Names {
		valueEntry := g.session.valueEntry(entry.Slot)
		if valueEntry != nil && valueEntry.ValueSource == contract.Generated && valueEntry.Generated.CreateResultID == result {
			return true
		}
	}
	return false
}
