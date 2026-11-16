package contract

// AuthorityNoWorkBindings commits only the complete requested role bindings.
// The enclosing Core owner must first establish their equality to current state.
func AuthorityNoWorkBindings(control ControlCore, roles uint8) (DescriptorVector, error) {
	if roles == 0 || roles & ^uint8(SuccessionChangeAuthorityMask) != 0 {
		return DescriptorVector{}, ErrRecord
	}
	if _, err := EncodeControlCore(control); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("ENKV/AUTHORITY-NO-WORK-BINDINGS/v1\x00")
	w.id(control.DomainID)
	w.u8(roles)
	count := 0
	if roles&SuccessionChangeNormalSigner != 0 {
		body, err := EncodePublicSigningBinding(control.NormalSigning)
		if err != nil {
			return DescriptorVector{}, err
		}
		w.blob(body)
		count++
	}
	if roles&SuccessionChangeAuthorityKEK != 0 {
		body, err := EncodeKMSBinding(control.AuthorityKMSBinding)
		if err != nil {
			return DescriptorVector{}, err
		}
		w.blob(body)
		count++
	}
	return w.result(count), nil
}

type AuthorityNoWorkRequestCore struct {
	Domain, Store, Trust, Coordinate, NonBody, Interpretation ID
	Epoch                                                     uint64
	PreviousRevision, PreviousDigest                          ID
	PreviousToken                                             Token
	ApprovalRole, Roles, MaterialSubjectKind                  uint8
	Bindings                                                  DescriptorVector
}

func AuthorityNoWorkRequestDigest(v AuthorityNoWorkRequestCore) (ID, error) {
	count := uint32(0)
	if v.Roles&SuccessionChangeNormalSigner != 0 {
		count++
	}
	if v.Roles&SuccessionChangeAuthorityKEK != 0 {
		count++
	}
	if v.Bindings.Count != count {
		return ID{}, ErrRecord
	}
	if !publicIDsValid(v.Domain, v.Store, v.Trust, v.Coordinate, v.NonBody, v.Interpretation, v.PreviousRevision, v.PreviousDigest, v.Bindings.Digest) || v.Epoch == 0 || !v.PreviousToken.Valid() ||
		v.ApprovalRole != NormalSigningRole && v.ApprovalRole != RecoverySigningRole || v.Roles == 0 || v.Roles & ^uint8(SuccessionChangeAuthorityMask) != 0 || v.Bindings.Length == 0 || v.Bindings.Count == 0 || v.Bindings.Count > 2 ||
		v.Roles&SuccessionChangeAuthorityKEK == 0 && v.MaterialSubjectKind != 0 || v.Roles&SuccessionChangeAuthorityKEK != 0 && v.MaterialSubjectKind != OrdinaryWrapSubject && v.MaterialSubjectKind != RecoveryWrapSubject {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/AUTHORITY-NO-WORK-REQUEST/v1\x00")
	writeRequestScope(&w, RequestCoreFields{Domain: v.Domain, Store: v.Store, Trust: v.Trust, Coordinate: v.Coordinate, NonBody: v.NonBody, Interpretation: v.Interpretation, Epoch: v.Epoch, PreviousRevision: v.PreviousRevision, PreviousDigest: v.PreviousDigest}, v.PreviousToken)
	w.u8(v.ApprovalRole)
	w.u8(v.Roles)
	w.u8(v.MaterialSubjectKind)
	w.descriptor(v.Bindings)
	return w.result(1).Digest, nil
}

type AuthorityNoWorkObservation struct {
	OperationID, DomainID, RequestCoreDigest ID
	HEADRevisionID, HEADDigest, TokenDigest  ID
	Snapshot                                 Ref
	Bindings                                 DescriptorVector
	Nonce                                    ID
}

func AuthorityNoWorkObservationIdentity(v AuthorityNoWorkObservation) (ID, error) {
	if v.Bindings.Count == 0 || v.Bindings.Count > 2 {
		return ID{}, ErrRecord
	}
	return noWorkObservationIdentity(OperationReplaceAuthorityKeys, SuppliedApplyNoWorkObservation{OperationID: v.OperationID, DomainID: v.DomainID, RequestCoreDigest: v.RequestCoreDigest,
		HEADRevisionID: v.HEADRevisionID, HEADDigest: v.HEADDigest, TokenDigest: v.TokenDigest, Snapshot: v.Snapshot, Comparison: v.Bindings, Nonce: v.Nonce})
}
