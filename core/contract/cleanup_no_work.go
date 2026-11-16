package contract

// CleanupNoWorkBasis commits all authenticated retained work and an empty
// eligible selection. The owning Core scan establishes eligibility; retained
// armed or unfenced work need not be empty. This descriptor grants no replay.
func CleanupNoWorkBasis(domain ID, allWork DescriptorVector) (DescriptorVector, error) {
	if !publicIDsValid(domain, allWork.Digest) || allWork.Length == 0 {
		return DescriptorVector{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/CLEANUP-NO-WORK-BASIS/v1\x00")
	w.id(domain)
	w.descriptor(allWork)
	w.u32(0)
	return w.result(0), nil
}

type CleanupNoWorkRequestCore struct {
	Domain, Store, Trust, Coordinate, NonBody, Interpretation ID
	Epoch                                                     uint64
	PreviousRevision, PreviousDigest                          ID
	PreviousToken                                             Token
	WorkBasis                                                 DescriptorVector
}

func CleanupNoWorkRequestDigest(v CleanupNoWorkRequestCore) (ID, error) {
	if !publicIDsValid(v.Domain, v.Store, v.Trust, v.Coordinate, v.NonBody, v.Interpretation, v.PreviousRevision, v.PreviousDigest, v.WorkBasis.Digest) ||
		v.Epoch == 0 || !v.PreviousToken.Valid() || v.WorkBasis.Length == 0 || v.WorkBasis.Count != 0 {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/CLEANUP-NO-WORK-REQUEST/v1\x00")
	writeRequestScope(&w, RequestCoreFields{Domain: v.Domain, Store: v.Store, Trust: v.Trust, Coordinate: v.Coordinate, NonBody: v.NonBody, Interpretation: v.Interpretation,
		Epoch: v.Epoch, PreviousRevision: v.PreviousRevision, PreviousDigest: v.PreviousDigest}, v.PreviousToken)
	w.descriptor(v.WorkBasis)
	return w.result(1).Digest, nil
}

type CleanupNoWorkObservation struct {
	OperationID, DomainID, RequestCoreDigest ID
	HEADRevisionID, HEADDigest, TokenDigest  ID
	Snapshot                                 Ref
	WorkBasis                                DescriptorVector
	Nonce                                    ID
}

func CleanupNoWorkObservationIdentity(v CleanupNoWorkObservation) (ID, error) {
	if v.WorkBasis.Count != 0 {
		return ID{}, ErrRecord
	}
	return noWorkObservationIdentity(OperationCleanOwnedFailureResidue, SuppliedApplyNoWorkObservation{
		OperationID: v.OperationID, DomainID: v.DomainID, RequestCoreDigest: v.RequestCoreDigest,
		HEADRevisionID: v.HEADRevisionID, HEADDigest: v.HEADDigest, TokenDigest: v.TokenDigest,
		Snapshot: v.Snapshot, Comparison: v.WorkBasis, Nonce: v.Nonce})
}
