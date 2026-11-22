package contract

const (
	GeneratedFinalPreparationRecordLength = 318
	GeneratedGrantPreparationSchema       = 2
	// Bound the complete image before reading or allocating it. Prepared rows
	// obey the existing 8 MiB raw set and 4,096 current memberships. Every
	// secret has structural room for historical retained sources covering
	// every registered reader and one recovery wrap. Corrected grant-only
	// histories have at most 64 ordinary readers for one material.
	// The 1,024-byte generated metadata/core terms exceed
	// their canonical bounds; this does not introduce a new Product quota.
	GeneratedFinalPreparationMaxLength = 138 + MaxSelectedGrantRows*GeneratedGrantSealLength + CryptoMaxRetainedSet + 32*CryptoMaxMemberships +
		CryptoMaxValueEntries*(ValueEntryFixedLength+CryptoMaxName+CanonicalPayloadOverhead+AccessRecordFixedLength+CryptoMaxName+64) +
		GeneratedCurrentEntryLimit*2*1024 + WrapRowWireLength*CryptoMaxValueEntries*(CryptoMaxRecipients+1)
)

type GeneratedFinalPreparationRecord struct {
	Schema                uint16
	DomainID, OperationID ID
	MaterializationPhase  GeneratorPhaseIdentity
	Image                 GeneratorLogicalSlice
	ControlBindingDigest  ID
}

func (v GeneratedFinalPreparationRecord) valid() bool {
	_, err := GeneratorPhaseID(v.MaterializationPhase)
	return v.Schema == GeneratorRecordSchema && publicIDsValid(v.DomainID, v.OperationID, v.ControlBindingDigest) && err == nil &&
		v.MaterializationPhase.TransitionKind == GeneratorAuthorityFinal && v.Image.valid() && v.Image.ContentKind == GeneratorContentFinalPreparation &&
		v.Image.ContentID == v.Image.Digest && v.Image.Length <= GeneratedFinalPreparationMaxLength
}

func EncodeGeneratedFinalPreparationRecord(v GeneratedFinalPreparationRecord) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratedFinalPreparationRecordLength)}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	p := v.MaterializationPhase
	w.id(p.RequestIdentityDigest)
	w.id(p.ObservedHEADDigest)
	w.id(p.ConditionDigest)
	w.u8(uint8(p.TransitionKind))
	w.u32(p.BeforePhase)
	w.u32(p.AfterPhase)
	writeGeneratorDescriptor(&w, p.Evidence)
	image, _ := EncodeGeneratorLogicalSlice(v.Image)
	w.raw(image)
	w.id(v.ControlBindingDigest)
	return w.b, nil
}

func InspectGeneratedFinalPreparationRecord(body []byte) (GeneratedFinalPreparationRecord, error) {
	if len(body) != GeneratedFinalPreparationRecordLength {
		return GeneratedFinalPreparationRecord{}, ErrRecord
	}
	r := newRecordReader(body)
	v := GeneratedFinalPreparationRecord{Schema: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID()}
	v.MaterializationPhase = GeneratorPhaseIdentity{RequestIdentityDigest: r.requiredID(), ObservedHEADDigest: r.requiredID(), ConditionDigest: r.requiredID(),
		TransitionKind: GeneratorAuthorityPurpose(r.u8()), BeforePhase: r.u32(), AfterPhase: r.u32(), Evidence: readGeneratorDescriptor(&r)}
	v.Image = GeneratorLogicalSlice{Schema: r.u16(), ContentKind: r.u8(), ContentID: r.requiredID(), Length: r.u32(), Digest: r.requiredID()}
	v.ControlBindingDigest = r.requiredID()
	if err := r.end(); err != nil {
		return v, err
	}
	if !v.valid() {
		return v, ErrRecord
	}
	return v, nil
}

func GeneratedFinalPreparationBindingDigest(control ControlCore, bindings []BindingTableRow) (ID, error) {
	core, err := EncodeControlCore(control)
	if err != nil {
		return ID{}, err
	}
	rows, err := EncodeBindingTable(bindings)
	if err != nil {
		return ID{}, err
	}
	w := cryptoWriter{b: make([]byte, 0, 8+len(core)+len(rows))}
	w.blob(core)
	w.blob(rows)
	return generatorDigest("final-preparation-bindings", w.b), nil
}

// GeneratedFinalPreparationImage contains encrypted prepared rows only. The
// ordinary reader requires its phase association. Administrative disposal can
// discard missing backing through the authenticated parent ownership index.
type GeneratedFinalPreparationImage struct {
	Schema                                                              uint16
	DomainID, OperationID, MaterializationPhaseID, ControlBindingDigest ID
	Generated                                                           []CryptoGeneratedValueEntryResult
	Supplied                                                            []CryptoPreparedSecret
	GrantSeals                                                          []GeneratedGrantSeal
}

func EncodeGeneratedFinalPreparationImage(v GeneratedFinalPreparationImage) ([]byte, error) {
	if v.Schema != GeneratorRecordSchema && v.Schema != GeneratedGrantPreparationSchema || (v.Schema == GeneratedGrantPreparationSchema) != (len(v.GrantSeals) != 0) || !publicIDsValid(v.DomainID, v.OperationID, v.MaterializationPhaseID, v.ControlBindingDigest) ||
		len(v.Generated) == 0 || len(v.Generated) > GeneratedCurrentEntryLimit || len(v.Generated)+len(v.Supplied) > CryptoMaxValueEntries {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 138)}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.MaterializationPhaseID)
	w.id(v.ControlBindingDigest)
	w.u32(uint32(len(v.Generated)))
	var slots [CryptoMaxValueEntries]bool
	names := make(map[string]bool, CryptoMaxValueEntries)
	var raw, memberships uint64
	for i, row := range v.Generated {
		if names[row.ValueCore.Name] || row.Slot >= CryptoMaxValueEntries || slots[row.Slot] || i > 0 && v.Generated[i-1].Slot >= row.Slot {
			return nil, ErrRecord
		}
		slots[row.Slot], names[row.ValueCore.Name] = true, true
		raw += uint64(row.ValueCore.ContentLength)
		memberships += uint64(len(row.Entry.Recipients))
		if raw > CryptoMaxRawSet || memberships > CryptoMaxMemberships {
			return nil, ErrRecordCapacity
		}
		body, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{row}})
		if err != nil {
			return nil, err
		}
		w.blob(body)
		if len(w.b) > GeneratedFinalPreparationMaxLength {
			return nil, ErrRecordCapacity
		}
	}
	w.u32(uint32(len(v.Supplied)))
	for i, row := range v.Supplied {
		if names[row.Name] || row.Slot >= CryptoMaxValueEntries || slots[row.Slot] || i > 0 && v.Supplied[i-1].Name >= row.Name {
			return nil, ErrRecord
		}
		slots[row.Slot], names[row.Name] = true, true
		facts, err := cryptoValueEntryFacts(row.EntryBytes)
		if err != nil {
			return nil, err
		}
		memberships += uint64(len(facts.recipients) / 32)
		raw += uint64(facts.raw)
		if raw > CryptoMaxRawSet || memberships > CryptoMaxMemberships {
			return nil, ErrRecordCapacity
		}
		body, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: 1, Rows: []CryptoPreparedSecret{row}})
		if err != nil {
			return nil, err
		}
		w.blob(body)
		if len(w.b) > GeneratedFinalPreparationMaxLength {
			return nil, ErrRecordCapacity
		}
	}
	if err := v.VisitGrantWraps(nil); err != nil {
		return nil, err
	}
	if len(w.b)+len(v.GrantSeals)*GeneratedGrantSealLength > GeneratedFinalPreparationMaxLength {
		return nil, ErrRecordCapacity
	}
	return appendGeneratedGrantSeals(w.b, v.GrantSeals)
}

func DecodeGeneratedFinalPreparationImage(body []byte) (v GeneratedFinalPreparationImage, err error) {
	defer func() {
		if err != nil {
			v.Clear()
		}
	}()
	if len(body) > GeneratedFinalPreparationMaxLength {
		return GeneratedFinalPreparationImage{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v = GeneratedFinalPreparationImage{Schema: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID(), MaterializationPhaseID: r.requiredID(), ControlBindingDigest: r.requiredID()}
	if v.Schema != GeneratorRecordSchema && v.Schema != GeneratedGrantPreparationSchema {
		return v, ErrRecord
	}
	count := r.u32()
	if count == 0 || count > GeneratedCurrentEntryLimit {
		return v, ErrRecordCapacity
	}
	var slots [CryptoMaxValueEntries]bool
	names := make(map[string]bool, CryptoMaxValueEntries)
	var raw, memberships uint64
	for range count {
		view, err := InspectCryptoGeneratedValueEntriesResult(r.blob(CryptoGeneratedResponseLimit))
		if err != nil {
			return v, err
		}
		if view.BatchIndex != 0 || view.Final != 1 || view.RowCount() != 1 || len(view.GrantSeals) != 0 {
			return v, ErrRecord
		}
		borrowed, err := view.Row(0)
		if err != nil {
			return v, err
		}
		name := string(borrowed.ValueCore.Name)
		if names[name] {
			return v, ErrRecord
		}
		raw += uint64(borrowed.ValueCore.fields().ContentLength)
		memberships += uint64(borrowed.Entry.RecipientCount())
		if raw > CryptoMaxRawSet || memberships > CryptoMaxMemberships {
			return v, ErrRecordCapacity
		}
		names[name] = true
		rows, err := view.Own()
		if err != nil || rows.BatchIndex != 0 || rows.Final != 1 || len(rows.Rows) != 1 {
			partial := GeneratedFinalPreparationImage{Generated: rows.Rows}
			partial.Clear()
			return v, ErrRecord
		}
		row := rows.Rows[0]
		v.Generated = append(v.Generated, row)
		if row.Slot >= CryptoMaxValueEntries || slots[row.Slot] || len(v.Generated) > 1 && v.Generated[len(v.Generated)-2].Slot >= row.Slot {
			return v, ErrRecord
		}
		slots[row.Slot] = true
	}
	count = r.u32()
	if count > CryptoMaxValueEntries-uint32(len(v.Generated)) {
		return v, ErrRecordCapacity
	}
	for range count {
		view, err := InspectCryptoGeneratedSuppliedResult(r.blob(CryptoGeneratedResponseLimit))
		if err != nil {
			return v, err
		}
		if view.BatchIndex != 0 || view.Final != 1 || view.Descriptor.Count != 1 {
			return v, ErrRecord
		}
		traversal := view.forwardRows()
		borrowed, present, err := traversal.next()
		if err != nil || !present {
			return v, ErrRecord
		}
		name := string(borrowed.name)
		if names[name] {
			return v, ErrRecord
		}
		facts, err := cryptoValueEntryFacts(borrowed.current.entryBytes)
		if err != nil {
			return v, err
		}
		memberships += uint64(len(facts.recipients) / 32)
		raw += uint64(facts.raw)
		if raw > CryptoMaxRawSet || memberships > CryptoMaxMemberships {
			return v, ErrRecordCapacity
		}
		names[name] = true
		rows, err := view.Own()
		if err != nil || view.BatchIndex != 0 || view.Final != 1 || len(rows) != 1 {
			partial := GeneratedFinalPreparationImage{Supplied: rows}
			partial.Clear()
			return v, ErrRecord
		}
		row := rows[0]
		v.Supplied = append(v.Supplied, row)
		if row.Slot >= CryptoMaxValueEntries || slots[row.Slot] || len(v.Supplied) > 1 && v.Supplied[len(v.Supplied)-2].Name >= row.Name {
			return v, ErrRecord
		}
		slots[row.Slot] = true
	}
	if v.Schema == GeneratedGrantPreparationSchema {
		v.GrantSeals, err = readGeneratedGrantSeals(body[r.i:])
		if err != nil || len(v.GrantSeals) == 0 || v.VisitGrantWraps(nil) != nil {
			return v, ErrRecord
		}
		r.i = len(body)
	}
	if err := r.end(); err != nil {
		return v, err
	}
	return v, nil
}

func (v *GeneratedFinalPreparationImage) Clear() {
	if v == nil {
		return
	}
	for _, row := range v.Generated {
		clear(row.Entry.ValueBytes[:cap(row.Entry.ValueBytes)])
		for _, wrap := range row.Access.Wraps {
			clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
		}
	}
	for _, row := range v.Supplied {
		clear(row.EntryBytes[:cap(row.EntryBytes)])
		clear(row.AccessRecord[:cap(row.AccessRecord)])
	}
	*v = GeneratedFinalPreparationImage{}
}

func ReadGeneratedFinalPreparationImage(domain, snapshot ID, records []SupportRecord, preparation GeneratedFinalPreparationRecord) (GeneratedFinalPreparationImage, error) {
	if !preparation.valid() || preparation.DomainID != domain {
		return GeneratedFinalPreparationImage{}, ErrRecord
	}
	var location GeneratorSliceLocation
	for _, row := range records {
		if row.Kind != GeneratorVectorSupportKind {
			continue
		}
		carrier, err := InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return GeneratedFinalPreparationImage{}, err
		}
		if carrier.VectorKind != GeneratorVectorSlices {
			continue
		}
		slice, err := InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			return GeneratedFinalPreparationImage{}, err
		}
		if slice.ContentKind == GeneratorContentFinalPreparation && slice.ContentID == preparation.Image.ContentID {
			if !location.ContentID.IsZero() || slice.Logical() != preparation.Image {
				return GeneratedFinalPreparationImage{}, ErrRecord
			}
			location = slice
		}
	}
	if location.ContentID.IsZero() {
		return GeneratedFinalPreparationImage{}, ErrRecord
	}
	backing, err := inspectGeneratedImmutableSlice(domain, snapshot, records, location)
	if err != nil {
		return GeneratedFinalPreparationImage{}, err
	}
	defer func() { clear(backing.scratch[:cap(backing.scratch)]) }()
	body, err := backing.span(0, location.Length)
	if err != nil {
		return GeneratedFinalPreparationImage{}, err
	}
	image, err := DecodeGeneratedFinalPreparationImage(body)
	phase, phaseErr := GeneratorPhaseID(preparation.MaterializationPhase)
	if err != nil || phaseErr != nil || image.DomainID != domain || image.OperationID != preparation.OperationID ||
		image.MaterializationPhaseID != phase || image.ControlBindingDigest != preparation.ControlBindingDigest {
		image.Clear()
		return GeneratedFinalPreparationImage{}, ErrRecord
	}
	return image, nil
}
