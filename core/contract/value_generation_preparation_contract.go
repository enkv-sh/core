package contract

import "bytes"

// GeneratedSourceProtectionsView borrows the same counted vector returned by
// finish-plan. Its validity does not depend on the original seed wraps.
type GeneratedSourceProtectionsView struct {
	Material OperationMaterialRecord
	Rows     []byte
}

func generatedSourceProtectionsLength(material OperationMaterialRecord, rows []CryptoGeneratedSourceProtection) (int, error) {
	if _, err := OperationMaterialRecordLength(material); err != nil {
		return 0, err
	}
	if len(rows) > CryptoMaxValueEntries {
		return 0, ErrCryptoCapacity
	}
	n := 4
	for i, row := range rows {
		length, err := cryptoGeneratedSourceProtectionLength(row, material)
		if err != nil {
			return 0, err
		}
		if i > 0 && bytes.Compare(rows[i-1].SourceID[:], row.SourceID[:]) >= 0 {
			return 0, ErrCryptoMessage
		}
		n += 4 + length
		if n > 1<<20 {
			return 0, ErrCryptoCapacity
		}
	}
	return n, nil
}

func EncodeGeneratedSourceProtections(material OperationMaterialRecord, rows []CryptoGeneratedSourceProtection) ([]byte, error) {
	n, err := generatedSourceProtectionsLength(material, rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedSourceProtections(&w, material, rows)
	return w.b, nil
}

func writeGeneratedSourceProtections(w *cryptoWriter, material OperationMaterialRecord, rows []CryptoGeneratedSourceProtection) {
	w.u32(uint32(len(rows)))
	for _, row := range rows {
		length, _ := cryptoGeneratedSourceProtectionLength(row, material)
		w.u32(uint32(length))
		writeCryptoGeneratedSourceProtection(w, row)
	}
}

func InspectGeneratedSourceProtections(material OperationMaterialRecord, body []byte) (GeneratedSourceProtectionsView, error) {
	if len(body) > 1<<20 {
		return GeneratedSourceProtectionsView{}, ErrCryptoCapacity
	}
	if _, err := OperationMaterialRecordLength(material); err != nil {
		return GeneratedSourceProtectionsView{}, err
	}
	r := cryptoReader{b: body}
	count := r.count(CryptoMaxValueEntries, 4)
	var previous ID
	for i := 0; i < count && r.err == nil; i++ {
		row, err := inspectCryptoGeneratedSourceProtection(r.blob(100+transferEnvelopeMaxLength), material)
		if r.err != nil {
			return GeneratedSourceProtectionsView{}, r.failure()
		}
		if err != nil {
			return GeneratedSourceProtectionsView{}, err
		}
		if i > 0 && bytes.Compare(previous[:], row.SourceID[:]) >= 0 {
			return GeneratedSourceProtectionsView{}, ErrCryptoMessage
		}
		previous = row.SourceID
	}
	if err := r.end(); err != nil {
		return GeneratedSourceProtectionsView{}, err
	}
	return GeneratedSourceProtectionsView{Material: material, Rows: body}, nil
}

func (v GeneratedSourceProtectionsView) Count() int {
	r := cryptoReader{b: v.Rows}
	return r.count(CryptoMaxValueEntries, 4)
}

func (v GeneratedSourceProtectionsView) Row(index int) (CryptoGeneratedSourceProtectionView, error) {
	r := cryptoReader{b: v.Rows}
	count := r.count(CryptoMaxValueEntries, 4)
	if index < 0 || index >= count {
		return CryptoGeneratedSourceProtectionView{}, ErrCryptoMessage
	}
	for i := 0; i < index; i++ {
		_ = r.blob(100 + transferEnvelopeMaxLength)
	}
	row := r.blob(100 + transferEnvelopeMaxLength)
	if r.err != nil {
		return CryptoGeneratedSourceProtectionView{}, r.failure()
	}
	return inspectCryptoGeneratedSourceProtection(row, v.Material)
}

// CryptoGeneratedValueEntriesResultBound checks the complete input and predicts the
// exact counted output region before any private operation or output allocation.
func CryptoGeneratedValueEntriesResultBound(v CryptoGeneratedValueEntriesRequestView, recovery bool) (int, error) {
	if err := cryptoGeneratedValueEntryPlansSpanError(v); err != nil {
		return 0, err
	}
	r := cryptoReader{b: v.Rows}
	count := r.count(CryptoMaxValueEntries, 4)
	n := 4
	for i := 0; i < count; i++ {
		row, err := inspectCryptoGeneratedValueEntryPlan(r.blob(CryptoGeneratedMaterialLimit))
		if err != nil {
			return 0, err
		}
		meta, err := GeneratedEntryMetadataLength(row.Generated)
		if err != nil {
			return 0, err
		}
		recipients := len(row.RecipientIDs) / 32
		wraps := recipients
		if recovery {
			wraps++
		}
		core := valueCoreFixedLength + len(row.ValueCore.Name) + 32
		entryLength := ValueEntryFixedLength + len(row.ValueCore.Name) + 32*recipients + meta + CanonicalPayloadOverhead + int(row.ValueCore.RetainedLength)
		access := AccessRecordFixedLength + wraps*WrapRowWireLength
		n += 4 + 2 + 64 + 12 + core + entryLength + access
		if n > CryptoGeneratedMaterialLimit {
			return 0, ErrCryptoCapacity
		}
	}
	return n, nil
}

// CryptoGeneratedSuppliedResultBound reserves the complete generated response
// envelope before any supplied source is opened or sealed. The bound uses the
// maximum admitted raw value, recipient set and key-use rows for each whole
// identity; it may choose a smaller batch than the eventual encoded output.
func CryptoGeneratedSuppliedResultBound(v CryptoGeneratedSuppliedRequestView) (int, error) {
	if err := cryptoGeneratedSuppliedRequestViewError(v); err != nil {
		return 0, err
	}
	identity, err := InspectIdentityPlan(v.IdentityPlan)
	if err != nil {
		return 0, err
	}
	count := int(identity.Descriptor.Count)
	// The shared prepared-result grammar bounds ordinary wraps per response.
	// Supported historical same-material sources can cover the full registry;
	// corrected grant-only producers stay within the per-value membership limit.
	if count > CryptoMaxMemberships/CryptoMaxRecipients {
		return 0, ErrCryptoCapacity
	}
	const row = 14 + 2*CryptoMaxName + ValueEntryFixedLength + 32*CryptoMaxValueEntryRecipients +
		CanonicalPayloadOverhead + CryptoMaxRetainedValue + GeneratedEntryMetadataMaxLength + AccessRecordFixedLength +
		(CryptoMaxRecipients+1)*WrapRowWireLength
	body := 10 + count*row
	if cryptoResponseHeader+KeyUseRowsMaxLength-2+body > CryptoGeneratedResponseLimit {
		return 0, ErrCryptoCapacity
	}
	return body, nil
}
