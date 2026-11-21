package core

import (
	"bytes"

	"enkv.sh/core/contract"
)

func (b *generatedSelectionBuilder) validateCreateHistories() error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	for _, a := range g.attempts {
		if a.expected.Template.Action != contract.GeneratorActionCreate {
			continue
		}
		if a.record.History.Count == 0 && !a.record.PredecessorAttemptID.IsZero() {
			return contract.ErrRecord
		}
		if err := b.validateCreateHistory(a, contract.GeneratedAttemptSupportKind, a.record.AttemptID, a.record.History); err != nil {
			return err
		}
		if row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.record.OwnerID}]; ok {
			d, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil || (d.Kind == contract.GeneratedDutyCreate && b.validateCreateHistory(a, contract.GeneratedDutySupportKind, d.DutyID, d.History) != nil) ||
				d.Kind == contract.GeneratedDutyUnselectedCleanup && b.validateCleanupHistory(a, contract.GeneratedDutySupportKind, d.DutyID, d.History) != nil {
				return contract.ErrRecord
			}
		}
		if row, ok := g.records[generatedRecordKey{contract.GeneratedHazardSupportKind, a.expected.Template.HazardID}]; ok {
			h, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return err
			}
			if a.record.State == contract.GeneratedEffectFailedTerminal && h.Fenced == 1 &&
				h.Eligibility == 0 && !g.cleanupConflicts[h.HazardID] {
				return contract.ErrRecord
			}
			hasCleanup := false
			for _, entered := range g.attempts {
				if entered.expected.Template.Action == contract.GeneratorActionDelete && entered.record.OwnerID == h.OwnerID {
					hasCleanup = true
					break
				}
			}
			if h.Fenced != 0 && hasCleanup {
				err = b.validateCleanupHistory(a, contract.GeneratedHazardSupportKind, h.HazardID, h.History)
			} else {
				err = b.validateCreateHistory(a, contract.GeneratedHazardSupportKind, h.HazardID, h.History)
			}
			if err != nil {
				return contract.ErrRecord
			}
		}
	}
	return nil
}

func (b *generatedSelectionBuilder) validateCleanupHistory(original generatedAttempt, kind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	rows, err := b.vectors.resolve(kind, owner, contract.GeneratorVectorHistory, descriptor)
	if err != nil {
		return err
	}
	ancestry, err := b.vectors.resolve(contract.GeneratedAttemptSupportKind, original.record.AttemptID, contract.GeneratorVectorHistory, original.record.History)
	if err != nil || len(rows) < len(ancestry) {
		return contract.ErrRecord
	}
	for i := range ancestry {
		actual := rows[i]
		if i+1 == len(ancestry) && len(rows) > len(ancestry) {
			h, err := contract.InspectGeneratorHistory(actual)
			original, originalErr := contract.InspectGeneratorHistory(ancestry[i])
			next, nextErr := contract.InspectGeneratorHistory(rows[i+1])
			if err != nil || originalErr != nil || nextErr != nil || h.Edge != 4 || h.NextAttemptID != next.PredecessorAttemptID || original.Edge != 0 || !original.NextAttemptID.IsZero() {
				return contract.ErrRecord
			}
			h.NextAttemptID, h.Edge = contract.ID{}, 0
			actual, err = contract.EncodeGeneratorHistory(h)
			if err != nil {
				return err
			}
		}
		if !bytes.Equal(actual, ancestry[i]) {
			return contract.ErrRecord
		}
	}
	deletes := rows[len(ancestry):]
	operations := make(map[contract.ID]bool, len(deletes))
	for i, body := range deletes {
		h, err := contract.InspectGeneratorHistory(body)
		a, ok := g.attempts[h.PredecessorAttemptID]
		if err != nil || !ok || a.expected.Template.Action != contract.GeneratorActionDelete || a.record.OwnerID != original.record.OwnerID || operations[a.record.OperationID] {
			return contract.ErrRecord
		}
		operations[a.record.OperationID] = true
		want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.record.AttemptID, OwnerID: a.record.OwnerID, Outcome: a.record.State}
		if len(a.result) != 0 {
			want.ResultID, want.ResultDigest = a.record.ResultID, contract.Hash(a.result)
		}
		if i+1 < len(deletes) {
			if a.record.Stage != contract.GeneratedStageTerminal || a.record.State != contract.GeneratedEffectUnknown && (a.record.CompletionClass != contract.GeneratedCompletionConfirmed || a.record.State != contract.GeneratedEffectSucceeded && a.record.State != contract.GeneratedEffectFailedTerminal) {
				return contract.ErrRecord
			}
			next, err := contract.InspectGeneratorHistory(deletes[i+1])
			if err != nil {
				return err
			}
			want.NextAttemptID, want.Edge = next.PredecessorAttemptID, 4
		}
		if h != want || b.validateDeleteHistory(a, contract.GeneratedAttemptSupportKind, a.record.AttemptID, a.record.History) != nil {
			return contract.ErrRecord
		}
	}
	for _, a := range g.attempts {
		if a.expected.Template.Action == contract.GeneratorActionDelete && a.record.OwnerID == original.record.OwnerID && !operations[a.record.OperationID] {
			return contract.ErrRecord
		}
	}
	return nil
}

func (b *generatedSelectionBuilder) validateCreateHistory(a generatedAttempt, ownerKind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	rows, err := b.vectors.resolve(ownerKind, owner, contract.GeneratorVectorHistory, descriptor)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if a.record.PredecessorAttemptID.IsZero() {
			return nil
		}
		return contract.ErrRecord
	}
	var bundle contract.GeneratorPlanBundle
	for _, candidate := range g.bundles {
		if candidate.Header.OperationID == a.record.OperationID {
			bundle = candidate
			break
		}
	}
	var path [contract.GeneratorMaxEnteredCreateAttempts]contract.GeneratorAttemptTemplate
	n := 0
	for x := a.expected.Template; ; {
		if n == len(path) {
			return contract.ErrRecord
		}
		path[n] = x
		n++
		if x.PredecessorAttemptID.IsZero() {
			break
		}
		var ok bool
		x, _, ok = generatedTemplate(bundle, x.PredecessorAttemptID)
		if !ok || x.Action != contract.GeneratorActionCreate || x.LineageID != a.record.LineageID {
			return contract.ErrRecord
		}
	}
	if len(rows) != n {
		return contract.ErrRecord
	}
	for i, body := range rows {
		h, err := contract.InspectGeneratorHistory(body)
		x := path[n-i-1]
		if err != nil || h.PredecessorAttemptID != x.AttemptID || h.OwnerID != x.DutyID ||
			!h.ResultID.IsZero() && h.ResultID != x.ResultID {
			return contract.ErrRecord
		}
		if i+1 < n {
			next := path[n-i-2]
			edge, outcome := uint8(contract.GeneratorGuardResidue), uint8(contract.GeneratedEffectClosedWithResidue)
			if next.Branch == contract.GeneratorBranchNoEffect || next.Branch == contract.GeneratorBranchResidueThenNoEffect {
				edge, outcome = contract.GeneratorGuardQualifiedNoEffect, contract.GeneratedEffectConfirmedNoEffect
				if h.ResultID.IsZero() {
					return contract.ErrRecord
				}
			}
			if h.NextAttemptID != next.AttemptID || h.Edge != edge || h.Outcome != outcome {
				return contract.ErrRecord
			}
		}
		known, retained := g.attempts[x.AttemptID]
		original, digest := known.record, contract.ID{}
		lateNoEffect := false
		if len(known.result) != 0 {
			digest = contract.Hash(known.result)
			if original.State == contract.GeneratedEffectClosedWithResidue && h.Outcome == contract.GeneratedEffectClosedWithResidue && h.ResultID.IsZero() && h.ResultDigest.IsZero() {
				row, present := g.records[generatedRecordKey{contract.GeneratedHazardSupportKind, known.expected.Template.HazardID}]
				hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
				result, resultPresent := g.records[generatedRecordKey{contract.GeneratedResultSupportKind, original.ResultID}]
				if !present || err != nil || !resultPresent || !bytes.Equal(result.Body, known.result) ||
					hazard.Fenced != 1 || hazard.Exposure != contract.GeneratedExposureLateEffect || hazard.OriginalOperationID != original.OperationID ||
					hazard.OriginalAttemptID != original.AttemptID || hazard.OwnerID != original.OwnerID || hazard.ResourceID != original.ResourceID {
					return contract.ErrRecord
				}
				reflected, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, original.DomainID, []contract.SupportRecord{result})
				if err != nil || reflected != hazard.OriginalResults {
					return contract.ErrRecord
				}
				digest = contract.ID{}
			}
		}
		if released, ok := g.releases[x.AttemptID]; ok {
			original, digest, retained = released.attempt, released.release.SelectedHandoffDigest, true
			lateNoEffect = contract.GeneratedReleasedCreatePreservesResidueHistory(original, x, h, released.release)
			if original.State == contract.GeneratedEffectClosedWithResidue && h.Outcome == contract.GeneratedEffectClosedWithResidue && h.ResultID.IsZero() && h.ResultDigest.IsZero() {
				digest = contract.ID{}
			}
			if lateNoEffect {
				digest = contract.ID{}
			}
		}
		if retained {
			if !lateNoEffect && h.Outcome != original.State || h.ResultDigest != digest || h.ResultID.IsZero() != digest.IsZero() {
				return contract.ErrRecord
			}
		} else if h.Outcome == contract.GeneratedEffectClosedWithResidue && h.ResultID.IsZero() {
			// An ancestry row cannot replace a still-possible original result
			// consumer or make its unresolved exposure disappear.
			return contract.ErrRecord
		}
	}
	return nil
}
