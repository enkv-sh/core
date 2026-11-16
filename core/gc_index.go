package core

import (
	"context"

	"enkv.sh/core/contract"
)

type gcIndexChange struct {
	operation contract.ID
	progress  *contract.GCProgress
}

func (s *StateSession) installGCAdministrativeIndex(ctx context.Context, next *StateSession, candidate *Candidate, operation contract.ID, progress *contract.GCProgress) error {
	if operation.IsZero() || progress != nil && !progress.Valid() {
		return contract.ErrRecord
	}
	return s.installAdministrativeIndexInput(ctx, next, candidate, nil, nil, nil, &gcIndexChange{operation: operation, progress: progress})
}
