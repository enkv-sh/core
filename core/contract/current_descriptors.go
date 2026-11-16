package contract

import "bytes"

func requiredSupportDescriptorValid(v DescriptorVector) bool {
	return v.Count <= requiredSupportMaxRecords && v.Length == uint64(requiredSupportBaseLength)+requiredSupportRowLength*uint64(v.Count)
}

func PublicValueEntryDigest(domain ID, slot uint16, m ValueEntry) (ID, error) {
	if domain.IsZero() || slot >= CryptoMaxValueEntries {
		return ID{}, ErrRecord
	}
	if _, err := ValueEntryLength(m); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "public-member-v6\x00")
	w.id(domain)
	w.u16(slot)
	writeValueEntry(&w, m)
	return w.result(1).Digest, nil
}
func PlainInputDigest(value []byte) (ID, error) {
	if len(value) > CryptoMaxRetainedValue {
		return ID{}, ErrRecordCapacity
	}
	w := cryptoHashWriter("ENKV/PLAIN-INPUT/v1\x00")
	w.blob(value)
	return w.result(0).Digest, nil
}

// EmptyRequiredSupportDescriptor is the canonical absent-support projection.
func EmptyRequiredSupportDescriptor(domain ID) (DescriptorVector, error) {
	return RequiredSupportDescriptor(domain, nil)
}
func AccessRecordsDescriptor(domain ID, records []AccessRecord) (DescriptorVector, error) {
	if domain.IsZero() {
		return DescriptorVector{}, ErrRecord
	}
	if len(records) > MaxChildPages*AccessPageRecordLimit {
		return DescriptorVector{}, ErrRecordCapacity
	}
	var encoded uint64
	for i, row := range records {
		n, err := AccessRecordLength(row)
		if err != nil {
			return DescriptorVector{}, err
		}
		if i > 0 && (row.MaterialKind < records[i-1].MaterialKind || row.MaterialKind == records[i-1].MaterialKind && bytes.Compare(row.MaterialID[:], records[i-1].MaterialID[:]) <= 0) {
			return DescriptorVector{}, ErrRecord
		}
		encoded += uint64(n)
	}
	if encoded > uint64(MaxChildPages)*(MaxAccessPageLength-AccessPageHeaderLength) {
		return DescriptorVector{}, ErrRecordCapacity
	}
	w := cryptoHashWriter(accessRecordsPrefix)
	w.id(domain)
	w.u32(uint32(len(records)))
	for _, row := range records {
		writeAccessRecordBlob(&w, row)
	}
	return w.result(len(records)), nil
}
