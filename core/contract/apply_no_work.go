package contract

// SuppliedApplyNoWorkBasis commits the complete admitted comparison. Core checks
// plain equality and exact membership; Crypto supplies every secret relation.
// A descriptor is a commitment, never an admission or a replay right.
func SuppliedApplyNoWorkBasis(domain ID, intent, current DescriptorVector, secrets []CryptoComparisonRow) (DescriptorVector, error) {
	if completeApplyIntentDescriptorError(domain, intent) != nil || current.Digest.IsZero() || current.Length == 0 || current.Count != intent.Count {
		return DescriptorVector{}, ErrRecord
	}
	for _, row := range secrets {
		if row.Relation != CryptoEqual || !row.BeforePresent || !row.AfterPresent || !row.ExclusionPathDigest.IsZero() {
			return DescriptorVector{}, ErrRecord
		}
	}
	comparison, err := CryptoComparisonDescriptor(secrets)
	if err != nil || comparison.Count > intent.Count {
		return DescriptorVector{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/SUPPLIED-APPLY-NO-WORK-BASIS/v1\x00")
	w.id(domain)
	for _, descriptor := range []DescriptorVector{intent, current, comparison} {
		w.descriptor(descriptor)
	}
	return w.result(int(intent.Count)), nil
}

// SuppliedApplyNoWorkRequestCore has no successor or identity plan. Its common
// scope uses the ordinary request writer; only the complete intent follows it.
type SuppliedApplyNoWorkRequestCore struct {
	Domain, Store, Trust, Coordinate, NonBody, Interpretation ID
	Epoch                                                     uint64
	PreviousRevision, PreviousDigest                          ID
	PreviousToken                                             Token
	Intent                                                    DescriptorVector
}

func SuppliedApplyNoWorkRequestDigest(v SuppliedApplyNoWorkRequestCore) (ID, error) {
	if completeApplyIntentDescriptorError(v.Domain, v.Intent) != nil || !publicIDsValid(v.Domain, v.Store, v.Trust, v.Coordinate, v.NonBody, v.Interpretation, v.PreviousRevision, v.PreviousDigest, v.Intent.Digest) || v.Epoch == 0 || !v.PreviousToken.Valid() || v.Intent.Length == 0 || v.Intent.Count > CryptoMaxValueEntries {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/SUPPLIED-APPLY-NO-WORK-REQUEST/v1\x00")
	writeRequestScope(&w, RequestCoreFields{Domain: v.Domain, Store: v.Store, Trust: v.Trust, Coordinate: v.Coordinate, NonBody: v.NonBody, Interpretation: v.Interpretation,
		Epoch: v.Epoch, PreviousRevision: v.PreviousRevision, PreviousDigest: v.PreviousDigest}, v.PreviousToken)
	w.descriptor(v.Intent)
	return w.result(1).Digest, nil
}

// SuppliedApplyNoWorkObservation is the supplied Apply specialization of
// NoWorkObservationIdentity/v1. Every field comes from the installed Core owner.
// It grants no mutation, historical replay or receipt append right.
type SuppliedApplyNoWorkObservation struct {
	OperationID, DomainID, RequestCoreDigest ID
	HEADRevisionID, HEADDigest, TokenDigest  ID
	Snapshot                                 Ref
	Comparison                               DescriptorVector
	Nonce                                    ID
}

func SuppliedApplyNoWorkObservationIdentity(v SuppliedApplyNoWorkObservation) (ID, error) {
	return noWorkObservationIdentity(OperationApplyDeclaration, v)
}

func noWorkObservationIdentity(operation uint16, v SuppliedApplyNoWorkObservation) (ID, error) {
	return noWorkObservationIdentityBounded(operation, v, CryptoMaxValueEntries)
}

func noWorkObservationIdentityBounded(operation uint16, v SuppliedApplyNoWorkObservation, maximum uint32) (ID, error) {
	if !publicIDsValid(v.OperationID, v.DomainID, v.RequestCoreDigest, v.HEADRevisionID, v.HEADDigest, v.TokenDigest, v.Nonce, v.Comparison.Digest) || v.Comparison.Length == 0 || v.Comparison.Count > maximum || v.Snapshot.Kind != RootKind || v.Snapshot.Domain != v.DomainID {
		return ID{}, ErrRecord
	}
	ref, err := AppendRef(nil, v.Snapshot, CanonicalSchema)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("ENKV/NO-WORK-OBSERVATION/v1\x00")
	w.u16(operation)
	for _, id := range []ID{v.OperationID, v.DomainID, v.RequestCoreDigest, v.HEADRevisionID, v.HEADDigest, v.TokenDigest} {
		w.id(id)
	}
	w.raw(ref)
	w.descriptor(v.Comparison)
	w.id(v.Nonce)
	return w.result(1).Digest, nil
}
