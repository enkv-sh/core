package contract

// GeneratedBindingDigest excludes mutable retirement policy and its selected
// duty. Those fields cannot change the immutable value encryption context.
func GeneratedBindingDigest(v GeneratedEntryMetadata) (ID, error) {
	if _, err := GeneratedEntryMetadataLength(v); err != nil {
		return ID{}, err
	}
	var w cryptoWriter
	for _, id := range [...]ID{v.ConfigContractID, v.IntentDigest, v.ResourceContractID, v.ResourceDigest, v.ResourceIncarnationID} {
		w.id(id)
	}
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.CompletionClass)
	return generatorDigest("member-binding-v4", w.b), nil
}

// ValueCoreForEntry binds an authenticated entry's source metadata to its
// encrypted payload. The caller supplies the owning domain and compatibility.
func ValueCoreForEntry(domain, compatibility ID, m ValueEntry) (ValueCore, error) {
	if _, err := ValueEntryLength(m); err != nil || m.ConfidentialityClass != Secret {
		return ValueCore{}, ErrRecord
	}
	p, err := InspectCanonicalPayload(m.ValueBytes)
	if err != nil {
		return ValueCore{}, err
	}
	v := ValueCore{Schema: CanonicalSchema, Profile: p.Profile, CompatibilityID: compatibility,
		CryptoSupportID: p.CryptoSupportID, DomainID: domain, Name: m.Name, EntryIncarnationID: m.Incarnation,
		ValueStateID: m.ValueState, OriginSnapshotID: m.OriginSnapshot, OriginTransitionID: m.OriginTransition,
		DataKeyID: p.DataKeyID, DataKeyEpoch: p.DataKeyEpoch, CommitmentKeyID: p.CommitmentKeyID,
		CommitmentKeyEpoch: p.CommitmentKeyEpoch, ContentLength: p.ContentLength, InputEncoding: p.InputEncoding, RetainedLength: p.RetainedLength, ValueSource: m.ValueSource}
	if m.ValueSource == Generated {
		v.GeneratedBindingDigest, err = GeneratedBindingDigest(m.Generated)
		if err != nil {
			return ValueCore{}, err
		}
	}
	if _, err := ValueCoreLength(v); err != nil {
		return ValueCore{}, err
	}
	return v, nil
}
