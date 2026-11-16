package core

import (
	"context"

	"enkv.sh/core/contract"
)

// The enclosing Authority admission must supply a current private session and
// normal K2 signing route. This path calls no effect provider.
func (s *StateSession) prepareEndSelectedWork(ctx context.Context, groupID contract.ID, trust contract.Trust) (*Candidate, Result) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.prepared || !s.admission.valid(s.store) || trust == nil ||
		s.admission.recipient != s.root.CurrentAccess.Core.AuthorityRecipientID || s.authority() == nil ||
		trust.Identity() != s.admission.trust || trust.Family() != s.admission.store.Family {
		return nil, refused(AdmissionInvalid)
	}
	ids, err := s.freshEndWorkIDs()
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	candidate, next, err := s.deriveEndWorkCandidate(ctx, groupID, ids)
	if err != nil {
		if readFailure, ok := selectedReadResult(err); ok {
			return nil, readFailure
		}
		return nil, refused(InvalidRelation)
	}
	if _, err := next.validateRelationsMode(ctx, true); err != nil {
		if readFailure, ok := selectedReadResult(err); ok {
			return nil, readFailure
		}
		return nil, refused(InvalidRelation)
	}
	s.prepared = true
	return s.persistCandidate(ctx, candidate, trust)
}
