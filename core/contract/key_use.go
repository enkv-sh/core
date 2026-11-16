package contract

import (
	"bytes"
	"cmp"
)

const (
	KeyUseRowLength     = 104
	KeyUseRowsMaxCount  = BindingTableMaxRows * 4 * 4
	KeyUseRowsMaxLength = 2 + KeyUseRowsMaxCount*KeyUseRowLength
)

const (
	KeyUsePublicKeyRead    uint8 = 1
	KeyUseMaterialWrap     uint8 = 2
	KeyUseMaterialOpen     uint8 = 3
	KeyUsePrivateRoleProbe uint8 = 4
)

const (
	KeyUseCompleted uint8 = 1
	KeyUseDenied    uint8 = 2
	KeyUseFailed    uint8 = 3
	KeyUseUnknown   uint8 = 4
)

// KeyUseRow reports an attempted operation on an admitted public binding. The
// enclosing request supplies correlation; Core checks the admitted use relation.
type KeyUseRow struct {
	BindingID, PublicBindingDigest ID
	SubjectKind                    uint8
	SubjectID                      ID
	Provider                       Family
	Purpose, Outcome               uint8
	Count                          uint32
}

func keyUseRowValid(v KeyUseRow) bool {
	return !v.BindingID.IsZero() && !v.SubjectID.IsZero() &&
		(v.SubjectKind == OrdinaryWrapSubject || v.SubjectKind == RecoveryWrapSubject) && v.Provider.Valid() &&
		v.Purpose >= KeyUsePublicKeyRead && v.Purpose <= KeyUsePrivateRoleProbe &&
		v.Outcome >= KeyUseCompleted && v.Outcome <= KeyUseUnknown && v.Count > 0
}

func compareKeyUseRows(a, b KeyUseRow) int {
	return cmp.Or(bytes.Compare(a.BindingID[:], b.BindingID[:]),
		bytes.Compare(a.PublicBindingDigest[:], b.PublicBindingDigest[:]),
		cmp.Compare(a.SubjectKind, b.SubjectKind), bytes.Compare(a.SubjectID[:], b.SubjectID[:]),
		cmp.Compare(a.Provider, b.Provider), cmp.Compare(a.Purpose, b.Purpose), cmp.Compare(a.Outcome, b.Outcome))
}

func writeKeyUseRow(w *cryptoWriter, v KeyUseRow) {
	w.id(v.BindingID)
	w.id(v.PublicBindingDigest)
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.u8(uint8(v.Provider))
	w.u8(v.Purpose)
	w.u8(v.Outcome)
	w.u32(v.Count)
}

func readKeyUseRow(r *cryptoReader) KeyUseRow {
	v := KeyUseRow{BindingID: r.requiredID(), PublicBindingDigest: r.id(), SubjectKind: r.u8(),
		SubjectID: r.requiredID(), Provider: Family(r.u8()), Purpose: r.u8(), Outcome: r.u8(), Count: r.u32()}
	if r.err == nil && !keyUseRowValid(v) {
		r.err = ErrRecord
	}
	return v
}

func AppendKeyUseRow(dst []byte, v KeyUseRow) ([]byte, error) {
	if !keyUseRowValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeKeyUseRow(&w, v)
	return w.b, nil
}

func EncodeKeyUseRow(v KeyUseRow) ([]byte, error) {
	if !keyUseRowValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, KeyUseRowLength)}
	writeKeyUseRow(&w, v)
	return w.b, nil
}

func ParseKeyUseRow(b []byte) (KeyUseRow, int, error) {
	r := newRecordReader(b)
	v := readKeyUseRow(&r)
	if r.err != nil {
		return KeyUseRow{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectKeyUseRow(b []byte) (KeyUseRow, error) {
	if len(b) > KeyUseRowLength {
		return KeyUseRow{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readKeyUseRow(&r)
	if err := r.end(); err != nil {
		return KeyUseRow{}, err
	}
	return v, nil
}

func DecodeKeyUseRow(b []byte) (KeyUseRow, error) { return InspectKeyUseRow(b) }

func KeyUseRowsLength(rows []KeyUseRow) (int, error) {
	if len(rows) > KeyUseRowsMaxCount {
		return 0, ErrRecordCapacity
	}
	for i, row := range rows {
		if !keyUseRowValid(row) || i > 0 && compareKeyUseRows(rows[i-1], row) >= 0 {
			return 0, ErrRecord
		}
	}
	return 2 + len(rows)*KeyUseRowLength, nil
}

func writeKeyUseRows(w *cryptoWriter, rows []KeyUseRow) {
	w.u16(uint16(len(rows)))
	for _, row := range rows {
		writeKeyUseRow(w, row)
	}
}

func keyUseSpanError(span []byte) error {
	if len(span) > KeyUseRowsMaxLength-2 {
		return ErrRecordCapacity
	}
	if len(span)%KeyUseRowLength != 0 {
		return ErrRecord
	}
	r := newRecordReader(span)
	var previous KeyUseRow
	for i := 0; r.i < len(span) && r.err == nil; i++ {
		row := readKeyUseRow(&r)
		if r.err == nil && i > 0 && compareKeyUseRows(previous, row) >= 0 {
			r.err = ErrRecord
		}
		previous = row
	}
	return r.end()
}

// KeyUseRowsView borrows an ordered row span from unchanged input. Own creates
// independent scalar records after checking the complete span.
type KeyUseRowsView struct{ Rows []byte }

func (v KeyUseRowsView) RowCount() int { return len(v.Rows) / KeyUseRowLength }

func (v KeyUseRowsView) Row(index int) (KeyUseRow, bool) {
	if index < 0 || index >= v.RowCount() {
		return KeyUseRow{}, false
	}
	row, err := InspectKeyUseRow(v.Rows[index*KeyUseRowLength : (index+1)*KeyUseRowLength])
	return row, err == nil
}

func (v KeyUseRowsView) Own() ([]KeyUseRow, error) {
	if err := keyUseSpanError(v.Rows); err != nil {
		return nil, err
	}
	rows := make([]KeyUseRow, v.RowCount())
	r := newRecordReader(v.Rows)
	for i := range rows {
		rows[i] = readKeyUseRow(&r)
	}
	return rows, nil
}

func readKeyUseRows(r *cryptoReader) KeyUseRowsView {
	count := int(r.u16())
	if r.err != nil {
		return KeyUseRowsView{}
	}
	if count > KeyUseRowsMaxCount {
		r.err = ErrRecordCapacity
		return KeyUseRowsView{}
	}
	rows := r.take(count * KeyUseRowLength)
	if r.err == nil {
		r.err = keyUseSpanError(rows)
	}
	return KeyUseRowsView{Rows: rows[:len(rows):len(rows)]}
}

func AppendKeyUseRows(dst []byte, rows []KeyUseRow) ([]byte, error) {
	if _, err := KeyUseRowsLength(rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeKeyUseRows(&w, rows)
	return w.b, nil
}

func EncodeKeyUseRows(rows []KeyUseRow) ([]byte, error) {
	n, err := KeyUseRowsLength(rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeKeyUseRows(&w, rows)
	return w.b, nil
}

func ParseKeyUseRows(b []byte) (KeyUseRowsView, int, error) {
	r := newRecordReader(b)
	v := readKeyUseRows(&r)
	if r.err != nil {
		return KeyUseRowsView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectKeyUseRows(b []byte) (KeyUseRowsView, error) {
	if len(b) > KeyUseRowsMaxLength {
		return KeyUseRowsView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readKeyUseRows(&r)
	if err := r.end(); err != nil {
		return KeyUseRowsView{}, err
	}
	return v, nil
}

func DecodeKeyUseRows(b []byte) ([]KeyUseRow, error) {
	v, err := InspectKeyUseRows(b)
	if err != nil {
		return nil, err
	}
	return v.Own()
}
