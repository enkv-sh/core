package core

import (
	"context"
	"slices"

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

// Resource closure can end a canonical consumer whose secret belongs to a
// different CREATE. Rebuild the evidence set from the surviving owners.
func (g *generatedSelection) pruneClosedCreateEvidence(rows []contract.SupportRecord) ([]contract.SupportRecord, error) {
	needed := make(map[contract.ID]bool)
	for _, name := range g.image.root.Names {
		entry := g.image.valueEntry(name.Slot)
		if entry != nil && entry.ValueSource == contract.Generated {
			needed[entry.Generated.CreateResultID] = true
		}
	}
	for _, row := range rows {
		switch row.Kind {
		case contract.RetainedCanonicalSupportKind:
			canonical, err := contract.InspectRetainedCanonicalRecord(row.Body)
			if err != nil {
				return nil, err
			}
			if canonical.Entry.ValueSource == contract.Generated {
				needed[canonical.Entry.Generated.CreateResultID] = true
			}
		case contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind:
			source, err := contract.InspectGeneratedDeleteSource(row)
			if err != nil {
				return nil, err
			}
			if source.Target.Count == 0 {
				continue
			}
			target, err := g.generatedCleanupTarget(row.Kind, row.RecordID, source.Target)
			if err != nil {
				return nil, err
			}
			result, err := generatedCreateResultID(source.DomainID, target.OriginalOperationID, target.OriginalAttemptID)
			if err != nil {
				return nil, err
			}
			needed[result] = true
		}
	}
	return slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
		return row.Kind == contract.GeneratedCreateEvidenceSupportKind && !needed[row.RecordID]
	}), nil
}
