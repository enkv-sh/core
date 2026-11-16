package contract

// GCNoWorkObservation binds the complete original plan request and its exact
// empty target vector to a fresh authenticated current-state observation.
type GCNoWorkObservation struct {
	OperationID, DomainID, RequestCoreDigest ID
	HEADRevisionID, HEADDigest, TokenDigest  ID
	Snapshot                                 Ref
	WorkBasis                                DescriptorVector
	Nonce                                    ID
}

func GCNoWorkObservationIdentity(v GCNoWorkObservation) (ID, error) {
	empty := GCTargetsEmptyDescriptor()
	if v.WorkBasis != DescriptorVector(empty) {
		return ID{}, ErrRecord
	}
	return noWorkObservationIdentityBounded(40, SuppliedApplyNoWorkObservation{
		OperationID: v.OperationID, DomainID: v.DomainID, RequestCoreDigest: v.RequestCoreDigest,
		HEADRevisionID: v.HEADRevisionID, HEADDigest: v.HEADDigest, TokenDigest: v.TokenDigest,
		Snapshot: v.Snapshot, Comparison: v.WorkBasis, Nonce: v.Nonce,
	}, 0)
}
