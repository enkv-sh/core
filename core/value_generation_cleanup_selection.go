package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

// readGeneratedCleanup derives the first work item from authenticated owners
// and their exact inbox coordinates. Missing is not an effect fact; unavailable
// or unqualified bytes cannot be skipped to obtain a later cleanup grant.
func (s *StateSession) readGeneratedCleanup(ctx context.Context) (generatedCleanupSelection, bool, error) {
	if s == nil || ctx == nil || !s.admission.valid(s.store) {
		return generatedCleanupSelection{}, false, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return generatedCleanupSelection{}, false, err
	}
	if g.parent != nil || g.phase != nil {
		return generatedCleanupSelection{}, false, contract.ErrRecord
	}
	hazards, err := g.generatedCleanupHazards()
	if err != nil {
		return generatedCleanupSelection{}, false, err
	}
	originals, err := g.generatedCleanupOriginals(hazards)
	if err != nil {
		return generatedCleanupSelection{}, false, err
	}
	for _, original := range originals {
		a := original.attempt
		body, present, read := s.ReadGeneratedResult(ctx, a.record.AttemptID)
		if read.Outcome != 0 {
			return generatedCleanupSelection{}, false, selectedReadFailure(read)
		}
		if !present {
			// A selected original result remains authoritative after inbox loss.
			body = a.result
		}
		if original.reflected {
			if present && !bytes.Equal(body, a.result) {
				return generatedCleanupSelection{}, false, contract.ErrRecord
			}
			continue
		}
		if len(body) != 0 {
			return g.selectGeneratedCleanup(ctx, map[contract.ID][]byte{a.record.ResultID: body})
		}
	}
	return g.selectGeneratedCleanup(ctx, nil)
}

func (s *StateSession) generatedReflectionIsFirst(ctx context.Context, plan *generatedLifecyclePlan) (bool, error) {
	if plan == nil {
		return false, contract.ErrRecord
	}
	selection, ok, err := s.readGeneratedCleanup(ctx)
	if err != nil {
		return false, err
	}
	return ok && selection.kind == generatedCleanupReflection &&
		selection.sourceKey().id == plan.owner && bytes.Equal(selection.result, plan.result), nil
}

type generatedCleanupSelectionKind uint8

const (
	generatedCleanupReflection generatedCleanupSelectionKind = iota + 1
	generatedCleanupDuty
	generatedCleanupHazard
)

// generatedCleanupSelection is the Core-selected cleanup owner. Callers do not
// supply an owner or a target. Reflection is selected before either ordinary
// cleanup source and therefore cannot be skipped in favor of a provider call.
type generatedCleanupSelection struct {
	kind       generatedCleanupSelectionKind
	attempt    generatedAttempt
	duty       contract.GeneratedDutyRecord
	hazard     contract.GeneratedHazardRecord
	target     contract.GeneratorTarget
	result     []byte
	closeOwner bool
	reflected  bool
}

func (s generatedCleanupSelection) sourceKey() generatedRecordKey {
	if !s.duty.DutyID.IsZero() {
		return generatedRecordKey{contract.GeneratedDutySupportKind, s.duty.DutyID}
	}
	return generatedRecordKey{contract.GeneratedHazardSupportKind, s.hazard.HazardID}
}

func (g *generatedSelection) selectGeneratedCleanup(ctx context.Context, returned map[contract.ID][]byte) (generatedCleanupSelection, bool, error) {
	if g == nil || g.parent != nil || g.phase != nil {
		return generatedCleanupSelection{}, false, contract.ErrRecord
	}
	hazards, err := g.generatedCleanupHazards()
	if err != nil {
		return generatedCleanupSelection{}, false, err
	}
	originals, err := g.generatedCleanupOriginals(hazards)
	if err != nil {
		return generatedCleanupSelection{}, false, err
	}
	for _, original := range originals {
		a := original.attempt
		if original.reflected {
			if supplied, present := returned[a.record.ResultID]; present && !bytes.Equal(supplied, a.result) {
				return generatedCleanupSelection{}, false, contract.ErrRecord
			}
			continue
		}
		body := a.result
		if supplied, present := returned[a.record.ResultID]; present {
			if len(body) != 0 && !bytes.Equal(body, supplied) {
				return generatedCleanupSelection{}, false, contract.ErrRecord
			}
			body = supplied
		}
		if len(body) == 0 {
			continue
		}
		if g.cleanupConflicts[original.sourceKey().id] {
			return generatedCleanupSelection{}, false, selectedReadFailure(failure(IntegrityFailure, InvalidRelation))
		}
		result, err := contract.DecodeGeneratedResultRecord(body)
		if err != nil || contract.ValidateGeneratedResult(a.expected, a.material, result) != nil {
			return generatedCleanupSelection{}, false, contract.ErrRecord
		}
		selection := original
		selection.result = bytes.Clone(body)
		switch a.expected.Template.Action {
		case contract.GeneratorActionCreate:
			switch result.SafeFacts.Disposition {
			case contract.GeneratorDispositionCompleteCreate, contract.GeneratorDispositionOwnedUnusableCreate:
				selection.closeOwner = false
			case contract.GeneratorDispositionConfirmedNoEffect:
				selection.closeOwner = true
			default:
				return generatedCleanupSelection{}, false, contract.ErrRecord
			}
		case contract.GeneratorActionDelete:
			if a.record.CompletionClass != contract.GeneratedCompletionAcknowledged && a.record.CompletionClass != contract.GeneratedCompletionConfirmed {
				return generatedCleanupSelection{}, false, contract.ErrRecord
			}
			switch result.SafeFacts.Disposition {
			case contract.GeneratorDispositionRetirementAcknowledged:
				selection.closeOwner = a.record.CompletionClass == contract.GeneratedCompletionAcknowledged
			case contract.GeneratorDispositionScopedUnusability:
				if a.record.CompletionClass != contract.GeneratedCompletionConfirmed {
					return generatedCleanupSelection{}, false, contract.ErrRecord
				}
				selection.closeOwner = true
				source, err := contract.InspectGeneratedDeleteSource(g.records[selection.sourceKey()])
				if err != nil {
					return generatedCleanupSelection{}, false, err
				}
				pending := a
				pending.result = selection.result
				progress, err := g.controlledDeleteSourceProgress(source, &pending, false)
				if err != nil || progress.contradiction || len(progress.rows) != 2 {
					return generatedCleanupSelection{}, false, contract.ErrRecord
				}
			default:
				return generatedCleanupSelection{}, false, contract.ErrRecord
			}
		default:
			return generatedCleanupSelection{}, false, contract.ErrRecord
		}
		return selection, true, nil
	}

	duties, err := g.generatedCleanupDuties()
	if err != nil {
		return generatedCleanupSelection{}, false, err
	}
	for _, d := range duties {
		if g.cleanupConflicts[d.DutyID] {
			continue
		}
		if err := g.generatedOrdinaryCleanupClass(contract.GeneratedDutySupportKind, d.DutyID, d.CompletionClass); err != nil {
			return generatedCleanupSelection{}, false, err
		}
		a, ok := g.attempts[d.OriginalAttemptID]
		if !ok {
			return generatedCleanupSelection{}, false, contract.ErrRecord
		}
		target, err := g.generatedCleanupTarget(contract.GeneratedDutySupportKind, d.DutyID, d.Target)
		if err != nil {
			return generatedCleanupSelection{}, false, err
		}
		return generatedCleanupSelection{kind: generatedCleanupDuty, attempt: a, duty: d, target: target}, true, nil
	}
	for _, h := range hazards {
		if h.Fenced != 1 || h.Eligibility == 0 || h.Eligibility != h.Exposure {
			continue
		}
		if err := g.generatedOrdinaryCleanupClass(contract.GeneratedHazardSupportKind, h.HazardID, h.CompletionClass); err != nil {
			return generatedCleanupSelection{}, false, err
		}
		target, err := g.generatedCleanupTarget(contract.GeneratedHazardSupportKind, h.HazardID, h.Target)
		if err != nil {
			return generatedCleanupSelection{}, false, err
		}
		a, liveOriginal := g.attempts[h.OriginalAttemptID]
		if !liveOriginal {
			if err := g.validateDetachedCleanupHazard(ctx, h, target); err != nil {
				return generatedCleanupSelection{}, false, err
			}
			return generatedCleanupSelection{kind: generatedCleanupHazard, hazard: h, target: target}, true, nil
		}
		return generatedCleanupSelection{kind: generatedCleanupHazard, attempt: a, hazard: h, target: target}, true, nil
	}
	if len(g.cleanupConflicts) != 0 {
		return generatedCleanupSelection{}, false, selectedReadFailure(failure(IntegrityFailure, InvalidRelation))
	}
	return generatedCleanupSelection{}, false, nil
}

// A detached create Hazard retains its exact kind-13 result context but no
// live original Attempt or succeeded Duty. The selected graph has already
// validated the Hazard. Recheck the evidence-to-target relation here so an
// ordinary cleanup selection cannot treat a merely missing Attempt as a grant.
func (g *generatedSelection) validateDetachedCleanupHazard(ctx context.Context, h contract.GeneratedHazardRecord, target contract.GeneratorTarget) error {
	if _, present := g.records[generatedRecordKey{kind: contract.GeneratedAttemptSupportKind, id: h.OriginalAttemptID}]; present {
		return contract.ErrRecord
	}
	if _, present := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: h.OwnerID}]; present {
		return contract.ErrRecord
	}
	result, err := generatedCreateResultID(h.DomainID, h.OriginalOperationID, h.OriginalAttemptID)
	if err != nil {
		return err
	}
	evidence, present := g.records[generatedRecordKey{kind: contract.GeneratedCreateEvidenceSupportKind, id: result}]
	if !present {
		return contract.ErrRecord
	}
	descriptor, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, h.DomainID, []contract.SupportRecord{evidence})
	if err != nil || descriptor != h.OriginalResults || target.OriginalOperationID != h.OriginalOperationID ||
		target.OriginalAttemptID != h.OriginalAttemptID || target.ResourceID != h.ResourceID || target.ConfigContractID != h.ConfigContractID ||
		target.ResourceContractID != h.ResourceContractID || target.ResultContractID != h.ResultContractID || target.CompletionClass != h.CompletionClass {
		return contract.ErrRecord
	}
	_, err = g.createTargetEvidence(ctx, target)
	return err
}

func (g *generatedSelection) generatedOrdinaryCleanupClass(kind uint8, id contract.ID, class uint8) error {
	if class == contract.GeneratedCompletionAcknowledged {
		return nil
	}
	if class != contract.GeneratedCompletionConfirmed {
		return contract.ErrRecord
	}
	source, err := contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{kind, id}])
	if err != nil {
		return err
	}
	progress, err := g.controlledDeleteSourceProgress(source, nil, true)
	if err != nil || progress.contradiction || len(progress.rows) > 1 {
		return contract.ErrRecord
	}
	return nil
}

// A repeated delete Hazard has one resource anchor and several original reply
// coordinates. Product ordering applies to each actual invocation, not to the
// anchor or to chronological History order.
func (g *generatedSelection) generatedCleanupOriginals(hazards []contract.GeneratedHazardRecord) ([]generatedCleanupSelection, error) {
	var out []generatedCleanupSelection
	for _, h := range hazards {
		if h.Exposure != contract.GeneratedExposurePossibleLive || h.Fenced != 1 {
			continue
		}
		anchor, ok := g.attempts[h.OriginalAttemptID]
		if !ok {
			return nil, contract.ErrRecord
		}
		if anchor.expected.Template.Action == contract.GeneratorActionCreate {
			out = append(out, generatedCleanupSelection{kind: generatedCleanupReflection, hazard: h, attempt: anchor})
			continue
		}
		count := 0
		var selectedResults []contract.SupportRecord
		for id, owner := range g.deleteHazards {
			if owner != h.HazardID {
				continue
			}
			a, ok := g.attempts[id]
			if !ok || a.expected.Template.Action != contract.GeneratorActionDelete {
				return nil, contract.ErrRecord
			}
			if len(a.result) != 0 {
				row, present := g.records[generatedRecordKey{kind: contract.GeneratedResultSupportKind, id: a.record.ResultID}]
				if !present || !bytes.Equal(row.Body, a.result) {
					return nil, contract.ErrRecord
				}
				selectedResults = append(selectedResults, row)
			}
			out = append(out, generatedCleanupSelection{kind: generatedCleanupReflection, hazard: h, attempt: a})
			count++
		}
		if count == 0 || uint32(count) != h.History.Count {
			return nil, contract.ErrRecord
		}
		descriptor, err := generatedHazardResultsDescriptor(h.DomainID, selectedResults)
		if err != nil || descriptor != h.OriginalResults {
			return nil, contract.ErrRecord
		}
		for i := range out {
			selection := &out[i]
			if selection.hazard.HazardID != h.HazardID || len(selection.attempt.result) == 0 ||
				selection.attempt.record.CompletionClass != contract.GeneratedCompletionConfirmed {
				continue
			}
			result, err := contract.InspectGeneratedResultRecord(selection.attempt.result)
			if err != nil {
				return nil, err
			}
			selection.reflected = result.SafeFacts.Disposition == contract.GeneratorDispositionRetirementAcknowledged
		}
	}
	// Ordinary cleanup also keeps original Delete replies under its actual
	// Duty or fenced create Hazard after the standalone parent leaves selection.
	// These coordinates have the same reflection priority as a parked Delete
	// Hazard; the create anchor is not the deleting invocation's reply key.
	seen := make(map[contract.ID]bool, len(out))
	for _, selection := range out {
		seen[selection.attempt.record.AttemptID] = true
	}
	for id, a := range g.attempts {
		if seen[id] || a.expected.Template.Action != contract.GeneratorActionDelete {
			continue
		}
		source, err := g.generatedDeleteSource(a.record.OwnerID)
		if err != nil {
			return nil, err
		}
		if source.Record.Kind == contract.GeneratedDutySupportKind && source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup ||
			source.Record.Kind == contract.GeneratedHazardSupportKind && source.Hazard.Fenced != 1 {
			continue
		}
		selection := generatedCleanupSelection{kind: generatedCleanupReflection, attempt: a, duty: source.Duty, hazard: source.Hazard}
		if len(a.result) != 0 && a.record.CompletionClass == contract.GeneratedCompletionConfirmed {
			result, err := contract.InspectGeneratedResultRecord(a.result)
			if err != nil {
				return nil, err
			}
			selection.reflected = result.SafeFacts.Disposition == contract.GeneratorDispositionRetirementAcknowledged
		}
		out = append(out, selection)
	}
	slices.SortFunc(out, func(a, b generatedCleanupSelection) int {
		return compareGeneratedOwnerOrder(a.attempt.record.OperationID, a.attempt.record.AttemptID, a.sourceKey().id,
			b.attempt.record.OperationID, b.attempt.record.AttemptID, b.sourceKey().id)
	})
	return out, nil
}

func (g *generatedSelection) generatedCleanupHazards() ([]contract.GeneratedHazardRecord, error) {
	var out []contract.GeneratedHazardRecord
	for key, row := range g.records {
		if key.kind != contract.GeneratedHazardSupportKind {
			continue
		}
		h, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	slices.SortFunc(out, func(a, b contract.GeneratedHazardRecord) int {
		return compareGeneratedOwnerOrder(a.OriginalOperationID, a.OriginalAttemptID, a.HazardID,
			b.OriginalOperationID, b.OriginalAttemptID, b.HazardID)
	})
	return out, nil
}

func (g *generatedSelection) generatedCleanupDuties() ([]contract.GeneratedDutyRecord, error) {
	var out []contract.GeneratedDutyRecord
	for key, row := range g.records {
		if key.kind != contract.GeneratedDutySupportKind {
			continue
		}
		d, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return nil, err
		}
		if d.Kind == contract.GeneratedDutyUnselectedCleanup && d.Status == contract.GeneratedEffectSucceeded {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b contract.GeneratedDutyRecord) int {
		return compareGeneratedOwnerOrder(a.OriginalOperationID, a.OriginalAttemptID, a.DutyID,
			b.OriginalOperationID, b.OriginalAttemptID, b.DutyID)
	})
	return out, nil
}

func compareGeneratedOwnerOrder(aOperation, aAttempt, aOwner, bOperation, bAttempt, bOwner contract.ID) int {
	if n := bytes.Compare(aOperation[:], bOperation[:]); n != 0 {
		return n
	}
	if n := bytes.Compare(aAttempt[:], bAttempt[:]); n != 0 {
		return n
	}
	return bytes.Compare(aOwner[:], bOwner[:])
}

func (g *generatedSelection) generatedCleanupTarget(kind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor) (contract.GeneratorTarget, error) {
	rows, err := g.vectors.resolve(kind, owner, contract.GeneratorVectorTargets, descriptor)
	if err != nil || len(rows) != 1 {
		return contract.GeneratorTarget{}, contract.ErrRecord
	}
	return contract.InspectGeneratorTarget(rows[0])
}
