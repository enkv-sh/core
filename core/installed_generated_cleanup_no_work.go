package core

import (
	"context"
	"crypto/rand"

	"enkv.sh/core/contract"
)

func (s *StateSession) installedGeneratedCleanupNoWorkIdentity(ctx context.Context) (contract.ID, contract.ID, error) {
	if ctx == nil || ctx.Err() != nil || s == nil {
		return contract.ID{}, contract.ID{}, contract.ErrRecord
	}
	rows, err := s.workSupportRecords(ctx)
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	allWork, err := s.workSupportDescriptor(rows)
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	basis, err := contract.CleanupNoWorkBasis(s.root.Domain, contract.DescriptorVector(allWork))
	if err != nil {
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
	request, err := contract.CleanupNoWorkRequestDigest(contract.CleanupNoWorkRequestCore{
		Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation,
		Epoch: h.Epoch, PreviousRevision: h.Revision, PreviousDigest: contract.Hash(s.body), PreviousToken: s.token, WorkBasis: basis})
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	token, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	identity, err := contract.CleanupNoWorkObservationIdentity(contract.CleanupNoWorkObservation{
		OperationID: operation, DomainID: s.root.Domain, RequestCoreDigest: request,
		HEADRevisionID: h.Revision, HEADDigest: contract.Hash(s.body), TokenDigest: token, Snapshot: h.Root, WorkBasis: basis, Nonce: nonce})
	if err != nil {
		return contract.ID{}, contract.ID{}, err
	}
	return operation, identity, ctx.Err()
}
