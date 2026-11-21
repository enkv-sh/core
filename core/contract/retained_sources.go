package contract

const (
	retainedCanonicalHeaderLength    = 2 + 2 + 4
	retainedCanonicalRecordMinLength = retainedCanonicalHeaderLength + ValueEntryFixedLength + 32 + CanonicalPayloadOverhead
	RetainedCanonicalRecordMaxLength = retainedCanonicalHeaderLength + CryptoMaxValueEntryLength
	retainedEntryAdmissionPrefix     = cryptoPurposePrefix + "retained-member-admission-v1\x00"
)

// RetainedCanonicalRecord keeps the exact earlier secret entry and slot.
// Current access and admitting the source owner remain separate state checks.
type RetainedCanonicalRecord struct {
	OriginalSlot uint16
	Entry        ValueEntry
}

// RetainedCanonicalRecordView borrows the shared ValueEntry's name, recipient
// span and payload. Own validates the complete current view before retention.
type RetainedCanonicalRecordView struct {
	OriginalSlot uint16
	Entry        ValueEntryView
}

func (v RetainedCanonicalRecordView) Own() (RetainedCanonicalRecord, error) {
	if v.OriginalSlot >= CryptoMaxValueEntries || v.Entry.ConfidentialityClass != Secret {
		return RetainedCanonicalRecord{}, ErrRecord
	}
	entry, err := v.Entry.Own()
	if err != nil {
		return RetainedCanonicalRecord{}, err
	}
	return RetainedCanonicalRecord{OriginalSlot: v.OriginalSlot, Entry: entry}, nil
}

func RetainedCanonicalRecordLength(v RetainedCanonicalRecord) (int, error) {
	if v.OriginalSlot >= CryptoMaxValueEntries || v.Entry.ConfidentialityClass != Secret {
		return 0, ErrRecord
	}
	n, err := ValueEntryLength(v.Entry)
	if err != nil {
		return 0, err
	}
	return retainedCanonicalHeaderLength + n, nil
}

func writeRetainedCanonicalRecord(w *cryptoWriter, v RetainedCanonicalRecord, entryLength int) {
	w.u16(GeneratorRecordSchema)
	w.u16(v.OriginalSlot)
	w.u32(uint32(entryLength))
	writeValueEntry(w, v.Entry)
}

func readRetainedCanonicalRecord(r *cryptoReader) RetainedCanonicalRecordView {
	if r.u16() != GeneratorRecordSchema {
		r.err = ErrRecord
	}
	v := RetainedCanonicalRecordView{OriginalSlot: r.u16()}
	if r.err != nil {
		return v
	}
	if v.OriginalSlot >= CryptoMaxValueEntries {
		r.err = ErrRecord
		return v
	}
	body := r.blob(CryptoMaxValueEntryLength)
	if r.err != nil {
		return v
	}
	v.Entry, r.err = InspectValueEntry(body)
	if r.err == nil && v.Entry.ConfidentialityClass != Secret {
		r.err = ErrRecord
	}
	return v
}

func AppendRetainedCanonicalRecord(dst []byte, v RetainedCanonicalRecord) ([]byte, error) {
	n, err := RetainedCanonicalRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeRetainedCanonicalRecord(&w, v, n-retainedCanonicalHeaderLength)
	return w.b, nil
}

func EncodeRetainedCanonicalRecord(v RetainedCanonicalRecord) ([]byte, error) {
	n, err := RetainedCanonicalRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeRetainedCanonicalRecord(&w, v, n-retainedCanonicalHeaderLength)
	return w.b, nil
}

func ParseRetainedCanonicalRecord(b []byte) (RetainedCanonicalRecordView, int, error) {
	r := newRecordReader(b)
	v := readRetainedCanonicalRecord(&r)
	if r.err != nil {
		return RetainedCanonicalRecordView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectRetainedCanonicalRecord(b []byte) (RetainedCanonicalRecordView, error) {
	if len(b) > RetainedCanonicalRecordMaxLength {
		return RetainedCanonicalRecordView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readRetainedCanonicalRecord(&r)
	if err := r.end(); err != nil {
		return RetainedCanonicalRecordView{}, err
	}
	return v, nil
}

func DecodeRetainedCanonicalRecord(b []byte) (RetainedCanonicalRecord, error) {
	v, err := InspectRetainedCanonicalRecord(b)
	if err != nil {
		return RetainedCanonicalRecord{}, err
	}
	return v.Own()
}

func AdmissionEntryDigest(v RetainedCanonicalRecord) (ID, error) {
	n, err := RetainedCanonicalRecordLength(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(retainedEntryAdmissionPrefix)
	writeRetainedCanonicalRecord(&w, v, n-retainedCanonicalHeaderLength)
	return w.result(0).Digest, nil
}
