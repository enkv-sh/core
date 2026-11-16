package records

import "enkv.sh/core/contract"

// OutputFixtureCleanupState describes retained fixture evidence. It grants no
// Product retry, and a completed cleanup does not settle an earlier unknown
// action or prove that its late effect cannot occur.
type OutputFixtureCleanupState struct {
	Eligible, Remaining, Unknown, Scheduled bool
}

// CleanupState validates the complete inventory before interpreting one row.
// Scheduled AWS deletion is a completed operation with possible physical
// residue; it is never evidence that the resource has been erased.
func (inventory OutputFixtureInventory) CleanupState(index uint32) (OutputFixtureCleanupState, error) {
	var state OutputFixtureCleanupState
	if inventory.validate(inventory.Scope) != nil || uint64(index) >= uint64(len(inventory.Rows)) {
		return state, errOutputInventory
	}
	row := inventory.Rows[index]
	possibleCreate := false
	for _, attempt := range row.Attempts {
		if (attempt.Action == contract.PublicationCreateEmpty || attempt.Action == contract.PublicationCreateWithValue) &&
			(attempt.Outcome == "acknowledged" || attempt.Outcome == "pending" || attempt.Outcome == "unknown") {
			possibleCreate = true
		}
		if attempt.Outcome == "pending" || attempt.Outcome == "unknown" {
			state.Unknown = true
		}
	}
	if !possibleCreate {
		return OutputFixtureCleanupState{}, nil
	}
	aws := row.ProfileID == "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3"
	last := row.Attempts[len(row.Attempts)-1]
	terminalDelete := last.Outcome == "acknowledged" &&
		(last.Action == contract.PublicationDeleteOwned || last.Action == contract.PublicationDeleteReservedSlot)
	state.Remaining = true
	if terminalDelete {
		state.Remaining = state.Unknown || aws
		state.Scheduled = aws
	}
	if cleanup := row.Cleanup; cleanup != nil {
		switch cleanup.Outcome {
		case "pending", "unknown":
			state.Remaining, state.Unknown = true, true
		case "absent":
			state.Remaining, state.Scheduled = state.Unknown, false
		case "acknowledged":
			state.Remaining, state.Scheduled = state.Unknown || aws, aws
		case "scheduled":
			state.Remaining, state.Scheduled = true, true
		}
	} else {
		state.Eligible = !terminalDelete
	}
	return state, nil
}
