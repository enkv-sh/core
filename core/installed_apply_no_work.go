package core

import (
	"context"
	"crypto/rand"

	"enkv.sh/core/contract"
)

func (s *StateSession) installedApplyNoWorkIdentity(ctx context.Context, parent *AdmittedParentComparison) (contract.ID, contract.ID, error) {
	if ctx == nil || parent == nil || parent.session != s || !parent.used || !parent.trackNoWork || parent.noWorkBasis.Digest.IsZero() || parent.noWorkIntent.Digest.IsZero() {
		return contract.ID{}, contract.ID{}, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	var operation, nonce contract.ID
	if _, err := rand.Read(operation[:]); err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	if operation.IsZero() || nonce.IsZero() || operation == nonce {
		return contract.ID{}, contract.ID{}, contract.ErrRecord
	}
	h := s.head.Core
	request, err := contract.SuppliedApplyNoWorkRequestDigest(contract.SuppliedApplyNoWorkRequestCore{Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation,
		Epoch: h.Epoch, PreviousRevision: h.Revision, PreviousDigest: contract.Hash(s.body), PreviousToken: s.token, Intent: parent.noWorkIntent})
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	token, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	identity, err := contract.SuppliedApplyNoWorkObservationIdentity(contract.SuppliedApplyNoWorkObservation{OperationID: operation, DomainID: s.admission.domain, RequestCoreDigest: request,
		HEADRevisionID: h.Revision, HEADDigest: contract.Hash(s.body), TokenDigest: token, Snapshot: h.Root, Comparison: parent.noWorkBasis, Nonce: nonce})
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	return operation, identity, nil
}
