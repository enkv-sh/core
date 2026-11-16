package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

func compareRecipientRetirementBlockers(a, b RecipientRetirementBlocker) int {
	if order := bytes.Compare(a.MaterialID[:], b.MaterialID[:]); order != 0 {
		return order
	}
	if a.OwnerKind != b.OwnerKind {
		return int(a.OwnerKind) - int(b.OwnerKind)
	}
	return bytes.Compare(a.OwnerID[:], b.OwnerID[:])
}

// Owners were retained with their kind at authenticated canonical validation.
// Scan the complete closure even after the bounded public prefix is full.
func (g *generatedSelection) recipientRetirementBlockers(recipient contract.ID) (*RecipientRetirementBlockers, error) {
	if g == nil || recipient.IsZero() {
		return nil, contract.ErrRecord
	}
	result := &RecipientRetirementBlockers{Rows: make([]RecipientRetirementBlocker, 0, RecipientRetirementBlockerLimit)}
	seen := make(map[RecipientRetirementBlocker]bool)
	for id, canonical := range g.canonical {
		if !slices.Contains(canonical.record.Entry.Recipients, recipient) {
			continue
		}
		owners := g.retainedOwners[id]
		if len(owners) == 0 {
			return nil, contract.ErrRecord
		}
		for _, owner := range owners {
			switch owner.kind {
			case contract.GeneratedParentSupportKind:
				if g.parent == nil || owner.id != g.parent.OperationID {
					return nil, contract.ErrRecord
				}
			case contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind:
				if _, present := g.records[owner]; !present {
					return nil, contract.ErrRecord
				}
			default:
				return nil, contract.ErrRecord
			}
			row := RecipientRetirementBlocker{MaterialID: canonical.record.Entry.ValueState, OwnerKind: owner.kind, OwnerID: owner.id}
			if row.MaterialID.IsZero() || row.OwnerID.IsZero() {
				return nil, contract.ErrRecord
			}
			if seen[row] {
				continue
			}
			seen[row] = true
			if result.Total == ^uint32(0) {
				return nil, contract.ErrRecordCapacity
			}
			result.Total++
			at, _ := slices.BinarySearchFunc(result.Rows, row, compareRecipientRetirementBlockers)
			if at == RecipientRetirementBlockerLimit {
				continue
			}
			if len(result.Rows) < RecipientRetirementBlockerLimit {
				result.Rows = append(result.Rows, RecipientRetirementBlocker{})
			}
			copy(result.Rows[at+1:], result.Rows[at:len(result.Rows)-1])
			result.Rows[at] = row
		}
	}
	if result.Total == 0 {
		return nil, nil
	}
	result.Rows = slices.Clip(result.Rows)
	return result, nil
}
