package contract

const (
	qualifiedBindingFieldsLength = 1 + 32 + 32 + 32 + 1 + 1
	qualifiedSuccessorRowLength  = 32 + qualifiedBindingFieldsLength
)

// Qualification fields carry a public result. Its provenance and relation to
// the admitted key remain checks of the component that accepts the result.
type QualifiedBindingFields struct {
	SubjectKind          uint8
	SubjectID, BindingID ID
	PublicBindingDigest  ID
	Provider             Family
	Qualified            uint8
}

type QualifiedSuccessorRow struct {
	ProbeID ID
	QualifiedBindingFields
}

func qualifiedBindingFieldsValid(v QualifiedBindingFields) bool {
	return (v.SubjectKind == OrdinaryWrapSubject || v.SubjectKind == RecoveryWrapSubject) &&
		!v.SubjectID.IsZero() && !v.BindingID.IsZero() && v.Provider.Valid() && v.Qualified == 1
}

func writeQualifiedBindingFields(w *cryptoWriter, v QualifiedBindingFields) {
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.id(v.BindingID)
	w.id(v.PublicBindingDigest)
	w.u8(uint8(v.Provider))
	w.u8(v.Qualified)
}

func readQualifiedBindingFields(r *cryptoReader) QualifiedBindingFields {
	v := QualifiedBindingFields{SubjectKind: r.u8(), SubjectID: r.requiredID(), BindingID: r.requiredID(),
		PublicBindingDigest: r.id(), Provider: Family(r.u8()), Qualified: r.u8()}
	if r.err == nil && !qualifiedBindingFieldsValid(v) {
		r.err = ErrRecord
	}
	return v
}

func QualifiedSuccessorRowLength(v QualifiedSuccessorRow) (int, error) {
	if v.ProbeID.IsZero() || !qualifiedBindingFieldsValid(v.QualifiedBindingFields) {
		return 0, ErrRecord
	}
	return qualifiedSuccessorRowLength, nil
}

func writeQualifiedSuccessorRow(w *cryptoWriter, v QualifiedSuccessorRow) {
	w.id(v.ProbeID)
	writeQualifiedBindingFields(w, v.QualifiedBindingFields)
}

func readQualifiedSuccessorRow(r *cryptoReader) QualifiedSuccessorRow {
	return QualifiedSuccessorRow{ProbeID: r.requiredID(), QualifiedBindingFields: readQualifiedBindingFields(r)}
}

func AppendQualifiedSuccessorRow(dst []byte, v QualifiedSuccessorRow) ([]byte, error) {
	if _, err := QualifiedSuccessorRowLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeQualifiedSuccessorRow(&w, v)
	return w.b, nil
}

func EncodeQualifiedSuccessorRow(v QualifiedSuccessorRow) ([]byte, error) {
	n, err := QualifiedSuccessorRowLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeQualifiedSuccessorRow(&w, v)
	return w.b, nil
}

func parseQualifiedSuccessorRow(b []byte, complete bool) (QualifiedSuccessorRow, int, error) {
	if complete && len(b) > qualifiedSuccessorRowLength {
		return QualifiedSuccessorRow{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b[:min(len(b), qualifiedSuccessorRowLength)])
	v := readQualifiedSuccessorRow(&r)
	if complete {
		r.err = r.end()
	}
	if r.err != nil {
		return QualifiedSuccessorRow{}, 0, r.failure()
	}
	return v, r.i, nil
}

func ParseQualifiedSuccessorRow(b []byte) (QualifiedSuccessorRow, int, error) {
	return parseQualifiedSuccessorRow(b, false)
}

func InspectQualifiedSuccessorRow(b []byte) (QualifiedSuccessorRow, error) {
	v, _, err := parseQualifiedSuccessorRow(b, true)
	return v, err
}

func DecodeQualifiedSuccessorRow(b []byte) (QualifiedSuccessorRow, error) {
	return InspectQualifiedSuccessorRow(b)
}
