package contract

import (
	"bytes"
	"cmp"
)

const (
	BindingTableMaxRows      = 2 * (CryptoMaxRecipients + 1)
	bindingTableRowOverhead  = 1 + 32 + 4
	bindingTableRowMinLength = bindingTableRowOverhead + kmsBindingFixedLength + 1
	BindingTableMaxLength    = 2 + BindingTableMaxRows*(bindingTableRowOverhead+KMSBindingMaxLength)
)

// BindingTableRow identifies one public key generation in a bounded operation.
// Core authenticates the exact current/successor set and its subject relation.
type BindingTableRow struct {
	SubjectKind uint8
	SubjectID   ID
	Binding     KMSBinding
}

type BindingTableRowView struct {
	SubjectKind uint8
	SubjectID   ID
	Binding     KMSBindingView
}

func (v BindingTableRowView) own() BindingTableRow {
	return BindingTableRow{SubjectKind: v.SubjectKind, SubjectID: v.SubjectID, Binding: v.Binding.own()}
}

func (v BindingTableRowView) Own() (BindingTableRow, error) {
	if !wrapSubjectValid(v.SubjectKind, v.SubjectID, v.Binding.BindingID, v.Binding.BindingSerial) {
		return BindingTableRow{}, ErrRecord
	}
	binding, err := v.Binding.Own()
	if err != nil {
		return BindingTableRow{}, err
	}
	return BindingTableRow{SubjectKind: v.SubjectKind, SubjectID: v.SubjectID, Binding: binding}, nil
}

type bindingTableOrder struct {
	kind    uint8
	subject ID
	serial  uint64
	binding ID
}

func (a bindingTableOrder) compare(b bindingTableOrder) int {
	return cmp.Or(cmp.Compare(a.kind, b.kind), bytes.Compare(a.subject[:], b.subject[:]),
		cmp.Compare(a.serial, b.serial), bytes.Compare(a.binding[:], b.binding[:]))
}

func (v BindingTableRowView) order() bindingTableOrder {
	return bindingTableOrder{v.SubjectKind, v.SubjectID, v.Binding.BindingSerial, v.Binding.BindingID}
}

func bindingTableShapeLength(rows []BindingTableRow) (int, error) {
	if len(rows) > BindingTableMaxRows {
		return 0, ErrRecordCapacity
	}
	n := 2
	var previous bindingTableOrder
	for i, row := range rows {
		if !wrapSubjectValid(row.SubjectKind, row.SubjectID, row.Binding.BindingID, row.Binding.BindingSerial) {
			return 0, ErrRecord
		}
		length, err := kmsBindingShapeLength(row.Binding)
		if err != nil {
			return 0, err
		}
		order := bindingTableOrder{row.SubjectKind, row.SubjectID, row.Binding.BindingSerial, row.Binding.BindingID}
		if i > 0 && previous.compare(order) >= 0 {
			return 0, ErrRecord
		}
		previous = order
		n += bindingTableRowOverhead + length
	}
	return n, nil
}

func bindingTableKeysError(rows []BindingTableRow) error {
	for _, row := range rows {
		if err := ValidatePublicEncryptionKey(row.Binding.SPKI, row.Binding.Fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func BindingTableLength(rows []BindingTableRow) (int, error) {
	n, err := bindingTableShapeLength(rows)
	if err != nil {
		return 0, err
	}
	// All nested sizes and table ordering pass before public-key parsing allocates.
	if err := bindingTableKeysError(rows); err != nil {
		return 0, err
	}
	return n, nil
}

func writeBindingTableCount(w *cryptoWriter, count uint16) {
	w.u16(count)
}

func writeBindingTable(w *cryptoWriter, rows []BindingTableRow) {
	writeBindingTableCount(w, uint16(len(rows)))
	for _, row := range rows {
		w.u8(row.SubjectKind)
		w.id(row.SubjectID)
		writeKMSBindingBlob(w, row.Binding)
	}
}

func readBindingTableRow(r *cryptoReader) BindingTableRowView {
	v := BindingTableRowView{SubjectKind: r.u8(), SubjectID: r.requiredID()}
	v.Binding = readKMSBindingBlob(r)
	if r.err != nil {
		return v
	}
	if !wrapSubjectValid(v.SubjectKind, v.SubjectID, v.Binding.BindingID, v.Binding.BindingSerial) {
		r.err = ErrRecord
	}
	return v
}

// BindingTableView borrows the complete row span. Keep its input unchanged
// through inspection and Own; retained rows copy each selector and public key.
type BindingTableView struct {
	Count uint16
	Rows  []byte
}

func (v BindingTableView) RowCount() int { return int(v.Count) }

func (v BindingTableView) Row(index int) (BindingTableRowView, bool) {
	if index < 0 || index >= v.RowCount() || v.RowCount() > BindingTableMaxRows {
		return BindingTableRowView{}, false
	}
	r := newRecordReader(v.Rows)
	var row BindingTableRowView
	for i := 0; i <= index && r.err == nil; i++ {
		row = readBindingTableRow(&r)
	}
	if r.err != nil || ValidatePublicEncryptionKey(row.Binding.SPKI, row.Binding.Fingerprint) != nil {
		return BindingTableRowView{}, false
	}
	return row, true
}

func readBindingTableRows(r *cryptoReader, count int) []byte {
	if r.err != nil {
		return nil
	}
	if count > BindingTableMaxRows {
		r.err = ErrRecordCapacity
		return nil
	}
	if count > (len(r.b)-r.i)/bindingTableRowMinLength {
		r.err = ErrRecord
		return nil
	}
	start := r.i
	var previous bindingTableOrder
	for i := 0; i < count && r.err == nil; i++ {
		row := readBindingTableRow(r)
		order := row.order()
		if r.err == nil && i > 0 && previous.compare(order) >= 0 {
			r.err = ErrRecord
		}
		previous = order
	}
	return r.b[start:r.i:r.i]
}

func readBindingTable(r *cryptoReader) BindingTableView {
	count := r.u16()
	return BindingTableView{Count: count, Rows: readBindingTableRows(r, int(count))}
}

func (v BindingTableView) keysError() error {
	r := newRecordReader(v.Rows)
	for i := 0; i < v.RowCount(); i++ {
		row := readBindingTableRow(&r)
		if r.err != nil {
			return r.failure()
		}
		if err := ValidatePublicEncryptionKey(row.Binding.SPKI, row.Binding.Fingerprint); err != nil {
			return err
		}
	}
	return r.end()
}

func (v BindingTableView) own() []BindingTableRow {
	rows := make([]BindingTableRow, v.RowCount())
	r := newRecordReader(v.Rows)
	for i := range rows {
		rows[i] = readBindingTableRow(&r).own()
	}
	return rows
}

func (v BindingTableView) Own() ([]BindingTableRow, error) {
	if len(v.Rows) > BindingTableMaxLength-2 {
		return nil, ErrRecordCapacity
	}
	r := newRecordReader(v.Rows)
	readBindingTableRows(&r, v.RowCount())
	if err := r.end(); err != nil {
		return nil, err
	}
	if err := v.keysError(); err != nil {
		return nil, err
	}
	return v.own(), nil
}

func AppendBindingTable(dst []byte, rows []BindingTableRow) ([]byte, error) {
	if _, err := BindingTableLength(rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeBindingTable(&w, rows)
	return w.b, nil
}

func EncodeBindingTable(rows []BindingTableRow) ([]byte, error) {
	n, err := BindingTableLength(rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeBindingTable(&w, rows)
	return w.b, nil
}

func ParseBindingTable(b []byte) (BindingTableView, int, error) {
	r := newRecordReader(b)
	v := readBindingTable(&r)
	if r.err != nil {
		return BindingTableView{}, 0, r.failure()
	}
	if err := v.keysError(); err != nil {
		return BindingTableView{}, 0, err
	}
	return v, r.i, nil
}

func InspectBindingTable(b []byte) (BindingTableView, error) {
	if len(b) > BindingTableMaxLength {
		return BindingTableView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readBindingTable(&r)
	if err := r.end(); err != nil {
		return BindingTableView{}, err
	}
	if err := v.keysError(); err != nil {
		return BindingTableView{}, err
	}
	return v, nil
}

func DecodeBindingTable(b []byte) ([]BindingTableRow, error) {
	v, err := InspectBindingTable(b)
	if err != nil {
		return nil, err
	}
	return v.own(), nil
}
