package contract

func cryptoIdentityProjection(b []byte) (DescriptorVector, error) {
	v, err := InspectIdentityPlan(b)
	return v.Descriptor, err
}
func cryptoPublicProjection(b []byte, domain ID) (DescriptorVector, error) {
	v, err := InspectPublicState(b, domain)
	return v.Descriptor, err
}
func cryptoExclusionProjection(b []byte, domain ID) (DescriptorVector, error) {
	v, err := InspectExclusions(b, domain)
	return v.Descriptor, err
}

func cryptoIdentityDescriptorError(d DescriptorVector) error {
	if d.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	base := uint64(identityBaseLength) + identityRowFixedLength*uint64(d.Count)
	maximum := base + CryptoMaxName*uint64(d.Count) + identityPageLength*MaxChildPages
	if d.Length > maximum {
		return ErrCryptoCapacity
	}
	if d.Length < base+cryptoMinimumNameBytes(d.Count) || d.Count == 0 && (d.Length-base)%identityPageLength != 0 {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoPublicDescriptorError(d DescriptorVector) error {
	if d.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	n := uint64(d.Count)
	if d.Length > uint64(publicStateBaseLength)+(publicStateRowFixedLength+CryptoMaxName)*n {
		return ErrCryptoCapacity
	}
	if d.Length < uint64(publicStateBaseLength)+publicStateRowFixedLength*n+cryptoMinimumNameBytes(d.Count) {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoPreparedDescriptorError(d DescriptorVector) error {
	if d.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	count := uint64(d.Count)
	base := uint64(len(cryptoPreparedPrefix) + 4)
	minimum := base + cryptoPreparedRowFixedLength*count + 2*cryptoMinimumNameBytes(d.Count)
	memberships := min(uint64(CryptoMaxMemberships), uint64(CryptoMaxValueEntryRecipients)*count)
	maximum := base + (cryptoPreparedRowOverhead+2*CryptoMaxName+WrapRowWireLength)*count +
		(32+WrapRowWireLength)*memberships + min(uint64(CryptoMaxRetainedSet), uint64(CryptoMaxRetainedValue)*count) + min(count, GeneratedCurrentEntryLimit)*uint64(GeneratedEntryMetadataMaxLength)
	if d.Length > maximum {
		return ErrCryptoCapacity
	}
	if d.Length < minimum {
		return ErrCryptoMessage
	}
	if d.Count == 0 {
		header := cryptoPreparedHeader(0)
		if d.Digest != Hash(header[:]) {
			return ErrCryptoMessage
		}
	}
	return nil
}

func cryptoExclusionDescriptorError(domain ID, d DescriptorVector) error {
	if d.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	n := uint64(d.Count)
	minimum := uint64(exclusionBaseLength) + (exclusionRowFixedLength+32)*n + cryptoMinimumNameBytes(d.Count)
	maximum := uint64(exclusionBaseLength) + (exclusionRowFixedLength+CryptoMaxName)*n + 32*min(uint64(CryptoMaxMemberships), CryptoMaxValueEntryRecipients*n)
	if d.Length > maximum {
		return ErrCryptoCapacity
	}
	if domain.IsZero() || d.Length < minimum {
		return ErrCryptoMessage
	}
	if d.Count == 0 {
		var b [exclusionBaseLength]byte
		n := copy(b[:], cryptoExclusionPrefix)
		header := membershipProjectionHeader(domain, 0)
		copy(b[n:], header[:])
		if d.Digest != Hash(b[:]) {
			return ErrCryptoMessage
		}
	}
	return nil
}

func cryptoLifecycleDescriptorsError(c ApplyContext, identity, candidate, prepared, exclusion DescriptorVector) error {
	if c.OperationClass != CryptoOrdinaryLifecycle {
		return ErrCryptoMessage
	}
	if err := cryptoIdentityDescriptorError(identity); err != nil {
		return err
	}
	if err := cryptoPublicDescriptorError(candidate); err != nil {
		return err
	}
	if err := cryptoPreparedDescriptorError(prepared); err != nil {
		return err
	}
	if err := cryptoExclusionDescriptorError(c.DomainID, exclusion); err != nil {
		return err
	}
	if c.IntentDescriptor.Count != candidate.Count || identity.Count > candidate.Count || prepared.Count > candidate.Count {
		return ErrCryptoMessage
	}
	return nil
}

type cryptoRecordFacts struct {
	name, recipients []byte
	raw              uint32
	valueSource      uint8
}

func cryptoValueEntryFacts(b []byte) (cryptoRecordFacts, error) {
	v, err := InspectValueEntry(b)
	if err != nil {
		return cryptoRecordFacts{}, err
	}
	if v.ConfidentialityClass != Secret {
		return cryptoRecordFacts{}, ErrCryptoMessage
	}
	return cryptoRecordFacts{name: v.Name, raw: v.ContentLength, recipients: v.RecipientIDs, valueSource: v.ValueSource}, nil
}
func cryptoSealedInputDigest(b []byte) ID {
	w := cryptoHashWriter("ENKV/SEALED-INPUT/v1\x00")
	w.blob(b)
	return w.result(0).Digest
}

func SealedInputDigest(b []byte) (ID, error) {
	if _, err := InspectSealedInputEnvelope(b); err != nil {
		return ID{}, err
	}
	return cryptoSealedInputDigest(b), nil
}

// InspectCryptoSealedInput validates bounded public framing and copies its metadata.
// It does not authenticate the source or admit its use.
func InspectCryptoSealedInput(b []byte) (CryptoSealedInputMetadata, error) {
	v, err := InspectSealedInputEnvelope(b)
	if err != nil {
		return CryptoSealedInputMetadata{}, err
	}
	return CryptoSealedInputMetadata{SealedInputCore: v.Core.own(), AuthorityRecipientID: v.AuthorityWrap.SubjectID,
		AuthorityBindingID: v.AuthorityWrap.BindingID, AuthorityBindingSerial: v.AuthorityWrap.BindingSerial,
		AuthorityBindingDigest: v.AuthorityWrap.PublicBindingDigest}, nil
}
