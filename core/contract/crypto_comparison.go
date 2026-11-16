package contract

import "bytes"

const (
	cryptoComparisonPrefix         = cryptoPurposePrefix + "secret-comparison-v2\x00"
	cryptoComparisonRowFixedLength = 4 + 3 + 3*32 + 4
	cryptoComparisonBaseLength     = len(cryptoComparisonPrefix) + 4
	cryptoComparisonMaxLength      = cryptoComparisonBaseLength + (cryptoComparisonRowFixedLength+CryptoMaxName)*CryptoMaxUnion
	cryptoCompareResultMaxLength   = 64 + cryptoComparisonMaxLength - len(cryptoComparisonPrefix)
)

func cryptoComparisonFieldsError(row CryptoComparisonRow) error {
	if row.AfterRawLength > CryptoMaxRawValue {
		return ErrCryptoCapacity
	}
	if !row.BeforePresent && !row.BeforePublicEntryDigest.IsZero() ||
		!row.AfterPresent && (!row.SourceDigest.IsZero() || row.AfterRawLength != 0) {
		return ErrCryptoMessage
	}
	switch row.Relation {
	case CryptoEqual, CryptoChanged:
		if !row.BeforePresent || !row.AfterPresent {
			return ErrCryptoMessage
		}
	case CryptoAdded:
		if row.BeforePresent || !row.AfterPresent || !row.ExclusionPathDigest.IsZero() {
			return ErrCryptoMessage
		}
	case CryptoRemoved:
		if !row.BeforePresent || row.AfterPresent || row.ExclusionPathDigest.IsZero() {
			return ErrCryptoMessage
		}
	default:
		return ErrCryptoMessage
	}
	return nil
}

func cryptoComparisonRowValid(row CryptoComparisonRow) error {
	if len(row.Name) > CryptoMaxName {
		return ErrCryptoCapacity
	}
	if !cryptoNamesValid(nil, []byte(row.Name), true) {
		return ErrCryptoMessage
	}
	return cryptoComparisonFieldsError(row)
}

type cryptoComparisonTotals struct {
	before, after int
	raw           uint64
}

func (s *cryptoComparisonTotals) add(row CryptoComparisonRow) error {
	if row.BeforePresent {
		s.before++
	}
	if row.AfterPresent {
		s.after++
	}
	s.raw += uint64(row.AfterRawLength)
	if s.before > CryptoMaxValueEntries || s.after > CryptoMaxValueEntries || s.raw > CryptoMaxRawSet {
		return ErrCryptoCapacity
	}
	return nil
}

func cryptoComparisonSize(rows []CryptoComparisonRow) (int, error) {
	if len(rows) > CryptoMaxUnion {
		return 0, ErrCryptoCapacity
	}
	n := cryptoComparisonBaseLength + cryptoComparisonRowFixedLength*len(rows)
	var totals cryptoComparisonTotals
	for i, row := range rows {
		if err := cryptoComparisonRowValid(row); err != nil {
			return 0, err
		}
		if i > 0 && rows[i-1].Name >= row.Name {
			return 0, ErrCryptoMessage
		}
		if err := totals.add(row); err != nil {
			return 0, err
		}
		n += len(row.Name)
	}
	return n, nil
}

func cryptoWriteComparisonRowData(w *cryptoWriter, name []byte, row CryptoComparisonRow) {
	w.blob(name)
	before, after := uint8(0), uint8(0)
	if row.BeforePresent {
		before = 1
	}
	if row.AfterPresent {
		after = 1
	}
	w.u8(before)
	w.u8(after)
	w.u8(uint8(row.Relation))
	w.id(row.BeforePublicEntryDigest)
	w.id(row.SourceDigest)
	w.u32(row.AfterRawLength)
	w.id(row.ExclusionPathDigest)
}

func cryptoWriteComparisonRow(w *cryptoWriter, row CryptoComparisonRow) {
	cryptoWriteComparisonRowData(w, []byte(row.Name), row)
}

func cryptoWriteComparisonRows(w *cryptoWriter, rows []CryptoComparisonRow) {
	w.u32(uint32(len(rows)))
	for _, row := range rows {
		cryptoWriteComparisonRow(w, row)
	}
}

func cryptoReadComparisonRow(r *cryptoReader) ([]byte, CryptoComparisonRow) {
	name := r.name()
	before, after := r.u8(), r.u8()
	if (before > 1 || after > 1) && r.err == nil {
		r.err = ErrCryptoMessage
	}
	row := CryptoComparisonRow{BeforePresent: before == 1, AfterPresent: after == 1, Relation: CryptoRelation(r.u8()),
		BeforePublicEntryDigest: r.id(), SourceDigest: r.id(), AfterRawLength: r.u32(), ExclusionPathDigest: r.id()}
	if r.err == nil {
		r.err = cryptoComparisonFieldsError(row)
	}
	return name, row
}

func cryptoReadComparisonRows(r *cryptoReader, count uint32) []byte {
	if r.err != nil {
		return nil
	}
	if count > CryptoMaxUnion {
		r.err = ErrCryptoCapacity
		return nil
	}
	if int(count) > (len(r.b)-r.i)/cryptoComparisonRowFixedLength {
		r.err = ErrCryptoMessage
		return nil
	}
	start := r.i
	var previous []byte
	var totals cryptoComparisonTotals
	for i := uint32(0); i < count && r.err == nil; i++ {
		name, row := cryptoReadComparisonRow(r)
		if r.err != nil {
			break
		}
		if !cryptoNamesValid(previous, name, i == 0) {
			r.err = ErrCryptoMessage
			break
		}
		previous = name
		r.err = totals.add(row)
	}
	return r.b[start:r.i:r.i]
}

// The named projection is written from parsed fields, independently of the
// message header, operation reference and other carrier bytes.
func cryptoComparisonRowsDescriptor(rows []byte, count uint32) DescriptorVector {
	w := cryptoHashWriter(cryptoComparisonPrefix)
	w.u32(count)
	r := cryptoReader{b: rows}
	for i := uint32(0); i < count; i++ {
		name, row := cryptoReadComparisonRow(&r)
		cryptoWriteComparisonRowData(&w, name, row)
	}
	return w.result(int(count))
}

func CryptoComparisonDescriptor(rows []CryptoComparisonRow) (DescriptorVector, error) {
	if _, err := cryptoComparisonSize(rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter(cryptoComparisonPrefix)
	cryptoWriteComparisonRows(&w, rows)
	return w.result(len(rows)), nil
}

func AppendCryptoComparison(dst []byte, rows []CryptoComparisonRow) ([]byte, error) {
	if _, err := cryptoComparisonSize(rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	w.raw([]byte(cryptoComparisonPrefix))
	cryptoWriteComparisonRows(&w, rows)
	return w.b, nil
}

func EncodeCryptoComparison(rows []CryptoComparisonRow) ([]byte, error) {
	n, err := cryptoComparisonSize(rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	w.raw([]byte(cryptoComparisonPrefix))
	cryptoWriteComparisonRows(&w, rows)
	return w.b, nil
}

// CryptoComparisonView borrows the complete ordered row span. Own validates
// the full descriptor and copies names before retaining rows.
type CryptoComparisonView struct {
	Rows       []byte
	Descriptor DescriptorVector
}

func (v CryptoComparisonView) own() []CryptoComparisonRow {
	rows := make([]CryptoComparisonRow, v.Descriptor.Count)
	r := cryptoReader{b: v.Rows}
	for i := range rows {
		name, row := cryptoReadComparisonRow(&r)
		row.Name = string(name)
		rows[i] = row
	}
	return rows
}

func (v CryptoComparisonView) validate() error {
	if len(v.Rows) > cryptoComparisonMaxLength-cryptoComparisonBaseLength {
		return ErrCryptoCapacity
	}
	r := cryptoReader{b: v.Rows}
	cryptoReadComparisonRows(&r, v.Descriptor.Count)
	if err := r.end(); err != nil {
		return err
	}
	if cryptoComparisonRowsDescriptor(v.Rows, v.Descriptor.Count) != v.Descriptor {
		return ErrCryptoMessage
	}
	return nil
}

func (v CryptoComparisonView) Own() ([]CryptoComparisonRow, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	return v.own(), nil
}

func readCryptoComparison(r *cryptoReader) ([]byte, uint32) {
	if !bytes.Equal(r.take(len(cryptoComparisonPrefix)), []byte(cryptoComparisonPrefix)) && r.err == nil {
		r.err = ErrCryptoMessage
	}
	count := r.u32()
	return cryptoReadComparisonRows(r, count), count
}

func ParseCryptoComparison(b []byte) (CryptoComparisonView, int, error) {
	r := cryptoReader{b: b}
	rows, count := readCryptoComparison(&r)
	if r.err != nil {
		return CryptoComparisonView{}, 0, r.failure()
	}
	return CryptoComparisonView{Rows: rows, Descriptor: cryptoComparisonRowsDescriptor(rows, count)}, r.i, nil
}

func InspectCryptoComparison(b []byte) (CryptoComparisonView, error) {
	if len(b) > cryptoComparisonMaxLength {
		return CryptoComparisonView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	rows, count := readCryptoComparison(&r)
	if err := r.end(); err != nil {
		return CryptoComparisonView{}, err
	}
	return CryptoComparisonView{Rows: rows, Descriptor: cryptoComparisonRowsDescriptor(rows, count)}, nil
}

func DecodeCryptoComparison(b []byte) ([]CryptoComparisonRow, error) {
	v, err := InspectCryptoComparison(b)
	if err != nil {
		return nil, err
	}
	return v.own(), nil
}

type CryptoCompareResultView struct {
	OperationRef     ID
	Comparison       CryptoComparisonView
	ComparisonDigest ID
}

func (v CryptoCompareResultView) Own() (CryptoCompareResult, error) {
	if v.OperationRef.IsZero() || v.ComparisonDigest != v.Comparison.Descriptor.Digest {
		return CryptoCompareResult{}, ErrCryptoMessage
	}
	rows, err := v.Comparison.Own()
	if err != nil {
		return CryptoCompareResult{}, err
	}
	return CryptoCompareResult{OperationRef: v.OperationRef, Rows: rows, ComparisonDigest: v.ComparisonDigest}, nil
}

func readCryptoCompareResult(r *cryptoReader) (CryptoCompareResultView, []byte, uint32) {
	v := CryptoCompareResultView{OperationRef: r.requiredID()}
	count := r.u32()
	rows := cryptoReadComparisonRows(r, count)
	v.ComparisonDigest = r.id()
	return v, rows, count
}

func completeCryptoCompareResult(v CryptoCompareResultView, rows []byte, count uint32) (CryptoCompareResultView, error) {
	v.Comparison = CryptoComparisonView{Rows: rows, Descriptor: cryptoComparisonRowsDescriptor(rows, count)}
	if v.ComparisonDigest != v.Comparison.Descriptor.Digest {
		return CryptoCompareResultView{}, ErrCryptoMessage
	}
	return v, nil
}

func ParseCryptoCompareResult(b []byte) (CryptoCompareResultView, int, error) {
	r := cryptoReader{b: b}
	v, rows, count := readCryptoCompareResult(&r)
	if r.err != nil {
		return CryptoCompareResultView{}, 0, r.failure()
	}
	v, err := completeCryptoCompareResult(v, rows, count)
	if err != nil {
		return CryptoCompareResultView{}, 0, err
	}
	return v, r.i, nil
}

func InspectCryptoCompareResult(b []byte) (CryptoCompareResultView, error) {
	if len(b) > cryptoCompareResultMaxLength {
		return CryptoCompareResultView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v, rows, count := readCryptoCompareResult(&r)
	if err := r.end(); err != nil {
		return CryptoCompareResultView{}, err
	}
	return completeCryptoCompareResult(v, rows, count)
}

func cryptoScanCompareResult(b []byte) (int, error) {
	v, err := InspectCryptoCompareResult(b)
	return int(v.Comparison.Descriptor.Count), err
}

func cryptoCompareResultSize(q CryptoCompareResult) (int, error) {
	if q.OperationRef.IsZero() {
		return 0, ErrCryptoMessage
	}
	d, err := CryptoComparisonDescriptor(q.Rows)
	if err != nil {
		return 0, err
	}
	if d.Digest != q.ComparisonDigest {
		return 0, ErrCryptoMessage
	}
	return 64 + int(d.Length) - len(cryptoComparisonPrefix), nil
}

func writeCryptoCompareResult(w *cryptoWriter, q CryptoCompareResult) {
	w.id(q.OperationRef)
	cryptoWriteComparisonRows(w, q.Rows)
	w.id(q.ComparisonDigest)
}

func AppendCryptoCompareResult(dst []byte, q CryptoCompareResult) ([]byte, error) {
	if _, err := cryptoCompareResultSize(q); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeCryptoCompareResult(&w, q)
	return w.b, nil
}

func EncodeCryptoCompareResult(q CryptoCompareResult) ([]byte, error) {
	n, err := cryptoCompareResultSize(q)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeCryptoCompareResult(&w, q)
	return w.b, nil
}

func DecodeCryptoCompareResult(b []byte) (CryptoCompareResult, error) {
	v, err := InspectCryptoCompareResult(b)
	if err != nil {
		return CryptoCompareResult{}, err
	}
	return CryptoCompareResult{OperationRef: v.OperationRef, Rows: v.Comparison.own(), ComparisonDigest: v.ComparisonDigest}, nil
}
