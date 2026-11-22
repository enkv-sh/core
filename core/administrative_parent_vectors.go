package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A Parent vector's OwnerID names its storage namespace. The exact descriptor
// references on the selected records determine which groups can dispose of it.
func (c administrativeConsumers) bindParentVectorOwners(root format.Root, pages []format.RequiredSupportPage) error {
	if len(c.parentVectors) == 0 {
		return nil
	}
	claim := func(operation contract.ID, kind contract.GeneratorVectorKind, d contract.GeneratorDescriptor, groups ...contract.ID) {
		key := generatedVectorKey{contract.GeneratedParentSupportKind, operation, kind, d}
		if _, present := c.parentVectors[key]; present {
			c.parentVectors[key] = append(c.parentVectors[key], groups...)
		}
	}
	progressOwners := make(map[generatedVectorKey][]contract.ID)
	for _, attempt := range c.attempts {
		owners := c.attemptOwners(attempt.AttemptID, attempt.OperationID)
		claim(attempt.OperationID, contract.GeneratorVectorSupport, attempt.Support, owners...)
		if attempt.Progress.Count != 0 {
			progressOwners[generatedVectorKey{contract.GeneratedAttemptSupportKind, attempt.AttemptID, contract.GeneratorVectorProgress, attempt.Progress}] = owners
		}
	}
	var hazards []contract.GeneratedHazardRecord
	var targets []contract.SupportRecord
	var progresses []contract.GeneratorVectorCarrier
	anchored := false
	for _, page := range pages {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.GeneratedDutySupportKind:
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil {
					return err
				}
				claim(duty.OriginalOperationID, contract.GeneratorVectorSupport, duty.Support, duty.DutyID)
				if duty.Progress.Count != 0 {
					progressOwners[generatedVectorKey{contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorProgress, duty.Progress}] = []contract.ID{duty.DutyID}
				}
			case contract.GeneratedHazardSupportKind:
				hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
				if err != nil {
					return err
				}
				if hazard.Support.Count != 0 {
					hazards = append(hazards, hazard)
				}
			case contract.RetainedCanonicalSupportKind:
				canonical, err := contract.InspectRetainedCanonicalRecord(row.Body)
				if err != nil {
					return err
				}
				if canonical.Entry.ValueSource == contract.Generated {
					m := canonical.Entry.Generated
					claim(m.OriginOperationID, contract.GeneratorVectorSupport, m.RequiredSupport, c.canonical[row.RecordID]...)
				}
			case contract.GeneratedPhaseSupportKind:
				phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
				if err != nil {
					return err
				}
				claim(phase.OperationID, contract.GeneratorVectorProofs, phase.Proofs, phase.OperationID)
				if phase.OperationID == root.Generated.ActiveOwner {
					anchored = !phase.SelectionPhaseID.IsZero()
				}
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					return err
				}
				if carrier.OwnerKind == contract.GeneratedHazardSupportKind && carrier.VectorKind == contract.GeneratorVectorTargets {
					targets = append(targets, row)
				}
				if carrier.VectorKind == contract.GeneratorVectorProgress {
					progresses = append(progresses, carrier)
				}
			}
		}
	}
	if len(hazards) != 0 {
		vectors, err := newGeneratedVectorSet(root.Domain, targets)
		if err != nil {
			return err
		}
		for _, hazard := range hazards {
			op := hazard.OriginalOperationID
			_, hasGraph := c.graphSourceUses[op]
			if hasGraph && c.attemptIntent[hazard.OriginalAttemptID].operation == op && c.actions[hazard.OriginalAttemptID] == contract.GeneratorActionDelete {
				op, err = generatedDeleteHazardSupportOwner(hazard, vectors)
				if err != nil {
					return err
				}
			}
			claim(op, contract.GeneratorVectorSupport, hazard.Support, hazard.HazardID)
		}
	}
	for _, carrier := range progresses {
		groups := progressOwners[generatedVectorKey{carrier.OwnerKind, carrier.OwnerID, carrier.VectorKind, carrier.Vector}]
		if len(groups) == 0 {
			continue
		}
		progress, err := contract.InspectGeneratorProgress(carrier.Row)
		if err != nil {
			return err
		}
		if progress.CompletionClass != contract.GeneratedCompletionConfirmed && progress.Evidence.Count != 0 {
			attempt, ok := c.attempts[progress.AttemptID]
			if !ok {
				return contract.ErrRecord
			}
			claim(attempt.OperationID, contract.GeneratorVectorProofs, progress.Evidence, groups...)
		}
	}
	if !anchored {
		for _, source := range c.graphSourceUses[root.Generated.ActiveOwner] {
			claim(root.Generated.ActiveOwner, contract.GeneratorVectorConsumers, source.Consumers, root.Generated.ActiveOwner)
		}
	}
	for key, ids := range c.parentVectors {
		slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		c.parentVectors[key] = slices.Compact(ids)
	}
	return nil
}
