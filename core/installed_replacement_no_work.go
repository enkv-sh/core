package core

import (
	"context"
	"crypto/rand"

	"enkv.sh/core/contract"
)

type AuthorityReplacementNoWorkObservation struct {
	OperationID, RequestIdentity, RequestCoreDigest contract.ID
}

func (s *StateSession) authorityReplacementNoWork(ctx context.Context, goal *admittedAuthorityGoal, source ReplacementMaterialSource) (*AuthorityReplacementNoWorkObservation, error) {
	changed, result := s.compareAuthorityGoal(ctx, goal)
	if changed != 0 || result.Outcome != Unchanged {
		return nil, contract.ErrRecord
	}
	var operation, nonce contract.ID
	if _, err := rand.Read(operation[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	if operation.IsZero() || nonce.IsZero() || operation == nonce {
		return nil, contract.ErrRecord
	}
	bindings, err := contract.AuthorityNoWorkBindings(currentControlOf(s), goal.goal.Roles)
	if err != nil {
		return nil, err
	}
	material := uint8(0)
	if goal.goal.Roles&contract.SuccessionChangeAuthorityKEK != 0 {
		material = contract.OrdinaryWrapSubject
		if source == ReplacementMaterialRecovery {
			material = contract.RecoveryWrapSubject
		}
	}
	h := s.head.Core
	request, err := contract.AuthorityNoWorkRequestDigest(contract.AuthorityNoWorkRequestCore{Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation,
		Epoch: h.Epoch, PreviousRevision: h.Revision, PreviousDigest: contract.Hash(s.body), PreviousToken: s.token, ApprovalRole: goal.goal.ApprovalRole, Roles: goal.goal.Roles, MaterialSubjectKind: material, Bindings: bindings})
	if err != nil {
		return nil, err
	}
	token, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		return nil, err
	}
	identity, err := contract.AuthorityNoWorkObservationIdentity(contract.AuthorityNoWorkObservation{OperationID: operation, DomainID: s.root.Domain, RequestCoreDigest: request, HEADRevisionID: h.Revision, HEADDigest: contract.Hash(s.body), TokenDigest: token, Snapshot: h.Root, Bindings: bindings, Nonce: nonce})
	if err != nil {
		return nil, err
	}
	return &AuthorityReplacementNoWorkObservation{OperationID: operation, RequestIdentity: identity, RequestCoreDigest: request}, nil
}
