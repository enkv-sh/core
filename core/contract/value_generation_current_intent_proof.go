package contract

// GeneratedSupportCurrentProof records semantic checks made while the private
// Core parent lends one authenticated current Intent. It contains no Intent
// bytes, Store reader, or authority to admit a different selected state.
type GeneratedSupportCurrentProof struct {
	binding ID
}

func generatedSupportCurrentBinding(domain, sliceSnapshot, root ID, row GeneratedSupportCurrent,
	evidence, carrier SupportRecord) (ID, error) {
	location, err := EncodeGeneratorSliceLocation(row.Intent)
	if err != nil {
		return ID{}, err
	}
	entry, err := InspectValueEntry(row.EntryBytes)
	if err != nil || entry.ValueSource != Generated {
		return ID{}, ErrRecord
	}
	var target []byte
	if entry.Generated.SemanticLifecycleMode() == GeneratorLifecycleNone {
		if row.Target != (GeneratorTarget{}) {
			return ID{}, ErrRecord
		}
	} else {
		target, err = EncodeGeneratorTarget(row.Target)
		if err != nil {
			return ID{}, err
		}
	}
	w := cryptoHashWriter("ENKV/GENERATED-SUPPORT-CURRENT-PROOF/v1\x00")
	w.id(domain)
	w.id(sliceSnapshot)
	w.id(root)
	w.u16(row.Slot)
	w.blob(row.EntryBytes)
	w.u32(row.EvidenceRecord)
	w.u8(uint8(evidence.Kind))
	w.id(evidence.RecordID)
	w.blob(evidence.Body)
	w.u32(row.CarrierRecord)
	w.u8(uint8(carrier.Kind))
	w.id(carrier.RecordID)
	w.blob(carrier.Body)
	w.blob(location)
	w.blob(target)
	return w.result(1).Digest, nil
}

func (p GeneratedSupportCurrentProof) matches(domain, sliceSnapshot, root ID, row GeneratedSupportCurrent,
	evidence, carrier SupportRecord) bool {
	if p.binding.IsZero() {
		return false
	}
	actual, err := generatedSupportCurrentBinding(domain, sliceSnapshot, root, row, evidence, carrier)
	return err == nil && actual == p.binding
}

// ProveGeneratedSupportCurrent checks the exact selected entry, evidence,
// Slice carrier and target while the bounded current Intent is present. Core
// must first read that Intent through its authenticated selected Ref path.
// The returned proof binds these facts to the selected Root without retaining
// the Intent or taking a Store callback into Crypto.
func ProveGeneratedSupportCurrent(domain, sliceSnapshot, root ID, row GeneratedSupportCurrent,
	evidence, carrier SupportRecord, intent []byte) (GeneratedSupportCurrent, error) {
	if !publicIDsValid(domain, sliceSnapshot, root) || row.Slot >= CryptoMaxValueEntries ||
		row.Intent.ContentKind != GeneratorContentIntent || row.Intent.Length > GeneratorIntentMaxLength ||
		uint32(len(intent)) != row.Intent.Length || Hash(intent) != row.Intent.Digest ||
		evidence.Kind != GeneratedCreateEvidenceSupportKind || carrier.Kind != GeneratorVectorSupportKind {
		return GeneratedSupportCurrent{}, ErrRecord
	}
	m, err := InspectValueEntry(row.EntryBytes)
	if err != nil || m.ValueSource != Generated || m.ConfidentialityClass != Secret ||
		row.Intent.ContentID != m.Generated.IntentDigest || evidence.RecordID != m.Generated.CreateResultID {
		return GeneratedSupportCurrent{}, ErrRecord
	}
	e, err := InspectGeneratedCreateEvidence(evidence.Body)
	if err != nil {
		return GeneratedSupportCurrent{}, err
	}
	c, err := InspectGeneratorVectorCarrier(carrier.Body)
	if err != nil {
		return GeneratedSupportCurrent{}, err
	}
	id, err := GeneratorVectorCarrierID(c)
	if err != nil || id != carrier.RecordID || c.DomainID != domain ||
		c.OwnerKind != GeneratorSnapshotOwner || c.OwnerID != sliceSnapshot || c.VectorKind != GeneratorVectorSlices {
		return GeneratedSupportCurrent{}, ErrRecord
	}
	selected, err := InspectGeneratorSliceLocation(c.Row)
	logical, logicalErr := GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{row.Intent.Logical()})
	if err != nil || selected != row.Intent || logicalErr != nil || logical != e.Intent {
		return GeneratedSupportCurrent{}, ErrRecord
	}
	entry := ValueEntry{Name: string(m.Name), Incarnation: m.Incarnation, ValueState: m.ValueState,
		OriginSnapshot: m.OriginSnapshot, OriginTransition: m.OriginTransition, ValueSource: m.ValueSource,
		ConfidentialityClass: m.ConfidentialityClass, InputEncoding: m.InputEncoding, OutputEncoding: m.OutputEncoding, ContentLength: m.ContentLength, RetainedLength: m.RetainedLength, ValueBytes: m.ValueBytes, Generated: m.Generated}
	for i := 0; i < m.RecipientCount(); i++ {
		id, _ := m.RecipientID(i)
		entry.Recipients = append(entry.Recipients, id)
	}
	if ValidateGeneratedValueEntryEvidence(domain, entry, GeneratedCreateEvidence(e), intent) != nil {
		return GeneratedSupportCurrent{}, ErrRecord
	}
	if entry.Generated.SemanticLifecycleMode() == GeneratorLifecycleNone {
		if row.Target != (GeneratorTarget{}) {
			return GeneratedSupportCurrent{}, ErrRecord
		}
	} else if ValidateGeneratedTargetEvidence(domain, row.Target, GeneratedCreateEvidence(e), intent) != nil || row.Target.Name != entry.Name || row.Target.IncarnationID != entry.Incarnation || row.Target.Epoch != entry.Generated.Epoch || row.Target.ResourceID != entry.Generated.ResourceIncarnationID {
		return GeneratedSupportCurrent{}, ErrRecord
	}
	binding, err := generatedSupportCurrentBinding(domain, sliceSnapshot, root, row, evidence, carrier)
	if err != nil {
		return GeneratedSupportCurrent{}, err
	}
	row.Proof = GeneratedSupportCurrentProof{binding: binding}
	return row, nil
}
