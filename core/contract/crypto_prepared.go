package contract

import (
	"bytes"
	"encoding/binary"
)

const (
	cryptoPreparedPrefix          = cryptoPurposePrefix + "prepared-secret-rows-v2\x00"
	cryptoPreparedRowOverhead     = 14 + ValueEntryFixedLength + CanonicalPayloadOverhead + AccessRecordFixedLength
	cryptoPreparedRowFixedLength  = 4 + cryptoCurrentRowFixedLength
	cryptoPreparedRowsLimit       = 4 + (cryptoPreparedRowOverhead+2*CryptoMaxName+WrapRowWireLength)*CryptoMaxValueEntries + (32+WrapRowWireLength)*CryptoMaxMemberships + CryptoMaxRetainedSet + GeneratedCurrentEntryLimit*GeneratedEntryMetadataMaxLength
	cryptoPreparedDescriptorLimit = len(cryptoPreparedPrefix) + cryptoPreparedRowsLimit
)

type cryptoPreparedRowView struct {
	name    []byte
	current cryptoCurrentRowView
}

type cryptoPreparedRowTraversal struct {
	reader    cryptoReader
	remaining uint32
}

func (v CryptoPreparedRowsView) forwardRows() cryptoPreparedRowTraversal {
	return cryptoPreparedRowTraversal{reader: cryptoReader{b: v.Rows}, remaining: v.Descriptor.Count}
}

func (t *cryptoPreparedRowTraversal) next() (cryptoPreparedRowView, bool, error) {
	if t.remaining == 0 {
		return cryptoPreparedRowView{}, false, t.reader.end()
	}
	row := cryptoReadPreparedRow(&t.reader)
	if t.reader.err != nil {
		return cryptoPreparedRowView{}, false, t.reader.failure()
	}
	t.remaining--
	return row, true, nil
}

func cryptoReadPreparedRow(r *cryptoReader) cryptoPreparedRowView {
	return cryptoPreparedRowView{name: r.name(), current: cryptoReadCurrentRow(r)}
}

func cryptoWritePreparedRowData(w *cryptoWriter, name []byte, row cryptoCurrentRowView) {
	w.blob(name)
	cryptoWriteCurrentRow(w, CryptoCurrentSecret{Slot: row.slot, EntryBytes: row.entryBytes, AccessRecord: row.access})
}

func cryptoWritePreparedRow(w *cryptoWriter, row CryptoPreparedSecret) {
	cryptoWritePreparedRowData(w, []byte(row.Name), cryptoCurrentRowView{slot: row.Slot, entryBytes: row.EntryBytes, access: row.AccessRecord})
}

func cryptoWritePreparedRows(w *cryptoWriter, rows []CryptoPreparedSecret) {
	w.u32(uint32(len(rows)))
	cryptoWritePreparedRowSpan(w, rows)
}

func cryptoWritePreparedRowSpan(w *cryptoWriter, rows []CryptoPreparedSecret) {
	for _, row := range rows {
		cryptoWritePreparedRow(w, row)
	}
}

func cryptoPreparedHeader(count uint32) (b [len(cryptoPreparedPrefix) + 4]byte) {
	n := copy(b[:], cryptoPreparedPrefix)
	binary.BigEndian.PutUint32(b[n:], count)
	return b
}

func cryptoWritePreparedCore(w *cryptoWriter, rows []CryptoPreparedSecret) {
	header := cryptoPreparedHeader(uint32(len(rows)))
	w.raw(header[:])
	cryptoWritePreparedRowSpan(w, rows)
}

func cryptoPreparedRowsSize(rows []CryptoPreparedSecret) (int, error) {
	if len(rows) > CryptoMaxValueEntries {
		return 0, ErrCryptoCapacity
	}
	size := 4
	var totals cryptoCurrentTotals
	for i, row := range rows {
		if len(row.Name) > CryptoMaxName {
			return 0, ErrCryptoCapacity
		}
		if err := totals.add(cryptoCurrentRowView{slot: row.Slot, entryBytes: row.EntryBytes, access: row.AccessRecord}, i == 0); err != nil {
			return 0, err
		}
		if row.Name != string(totals.previous) {
			return 0, ErrCryptoMessage
		}
		size += 14 + len(row.Name) + len(row.EntryBytes) + len(row.AccessRecord)
		if size > cryptoPreparedRowsLimit {
			return 0, ErrCryptoCapacity
		}
	}
	return size, nil
}

func cryptoReadPreparedRowSpan(r *cryptoReader, count uint32) []byte {
	if r.err != nil {
		return nil
	}
	if count > CryptoMaxValueEntries {
		r.err = ErrCryptoCapacity
		return nil
	}
	if int(count) > (len(r.b)-r.i)/cryptoPreparedRowFixedLength {
		r.err = ErrCryptoMessage
		return nil
	}
	start := r.i
	var totals cryptoCurrentTotals
	for i := uint32(0); i < count && r.err == nil; i++ {
		row := cryptoReadPreparedRow(r)
		if r.err != nil {
			break
		}
		if err := totals.add(row.current, i == 0); err != nil {
			r.err = err
			break
		}
		if !bytes.Equal(row.name, totals.previous) {
			r.err = ErrCryptoMessage
		}
	}
	return r.b[start:r.i:r.i]
}

func cryptoPreparedRowsDescriptor(rows []byte, count uint32) DescriptorVector {
	w := cryptoHashWriter("")
	header := cryptoPreparedHeader(count)
	w.raw(header[:])
	r := cryptoReader{b: rows}
	for i := uint32(0); i < count; i++ {
		row := cryptoReadPreparedRow(&r)
		cryptoWritePreparedRowData(&w, row.name, row.current)
	}
	return w.result(int(count))
}

func CryptoPreparedRowsDescriptor(rows []CryptoPreparedSecret) (DescriptorVector, error) {
	if _, err := cryptoPreparedRowsSize(rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	cryptoWritePreparedCore(&w, rows)
	return w.result(len(rows)), nil
}

// CryptoPreparedRowsView borrows complete public ValueEntry and AccessRecord
// bodies. Their authenticated correspondence remains an owning Core check.
type CryptoPreparedRowsView struct {
	Rows       []byte
	Descriptor DescriptorVector
}

func (v CryptoPreparedRowsView) own() []CryptoPreparedSecret {
	rows := make([]CryptoPreparedSecret, v.Descriptor.Count)
	r := cryptoReader{b: v.Rows}
	for i := range rows {
		row := cryptoReadPreparedRow(&r)
		rows[i] = CryptoPreparedSecret{Name: string(row.name), Slot: row.current.slot,
			EntryBytes: ownedBytes(row.current.entryBytes), AccessRecord: ownedBytes(row.current.access)}
	}
	return rows
}

func (v CryptoPreparedRowsView) Own() ([]CryptoPreparedSecret, error) {
	if len(v.Rows) > cryptoPreparedRowsLimit-4 || v.Descriptor.Length > uint64(cryptoPreparedDescriptorLimit) || v.Descriptor.Count > CryptoMaxValueEntries {
		return nil, ErrCryptoCapacity
	}
	r := cryptoReader{b: v.Rows}
	cryptoReadPreparedRowSpan(&r, v.Descriptor.Count)
	if err := r.end(); err != nil {
		return nil, err
	}
	if cryptoPreparedRowsDescriptor(v.Rows, v.Descriptor.Count) != v.Descriptor {
		return nil, ErrCryptoMessage
	}
	return v.own(), nil
}

func cryptoReadPrepareResult(r *cryptoReader) ([]byte, uint32) {
	count := r.u32()
	return cryptoReadPreparedRowSpan(r, count), count
}

func ParseCryptoPrepareResult(b []byte) (CryptoPreparedRowsView, int, error) {
	r := cryptoReader{b: b[:min(len(b), cryptoPreparedRowsLimit)]}
	rows, count := cryptoReadPrepareResult(&r)
	if r.err != nil {
		return CryptoPreparedRowsView{}, 0, r.failure()
	}
	return CryptoPreparedRowsView{Rows: rows, Descriptor: cryptoPreparedRowsDescriptor(rows, count)}, r.i, nil
}

func InspectCryptoPrepareResult(b []byte) (CryptoPreparedRowsView, error) {
	if len(b) > cryptoPreparedRowsLimit {
		return CryptoPreparedRowsView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	rows, count := cryptoReadPrepareResult(&r)
	if err := r.end(); err != nil {
		return CryptoPreparedRowsView{}, err
	}
	return CryptoPreparedRowsView{Rows: rows, Descriptor: cryptoPreparedRowsDescriptor(rows, count)}, nil
}

func cryptoScanPrepareResult(b []byte) (int, error) {
	v, err := InspectCryptoPrepareResult(b)
	return int(v.Descriptor.Count), err
}

func DecodeCryptoPrepareResult(b []byte) (CryptoPrepareResult, error) {
	v, err := InspectCryptoPrepareResult(b)
	if err != nil {
		return CryptoPrepareResult{}, err
	}
	return CryptoPrepareResult{Rows: v.own()}, nil
}

func EncodeCryptoPrepareResult(q CryptoPrepareResult) ([]byte, error) {
	size, err := cryptoPreparedRowsSize(q.Rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, size)}
	cryptoWritePreparedRows(&w, q.Rows)
	return w.b, nil
}

func AppendCryptoPrepareResult(dst []byte, q CryptoPrepareResult) ([]byte, error) {
	if _, err := cryptoPreparedRowsSize(q.Rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	cryptoWritePreparedRows(&w, q.Rows)
	return w.b, nil
}

func EncodeCryptoPreparedRows(rows []CryptoPreparedSecret) ([]byte, error) {
	size, err := cryptoPreparedRowsSize(rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, len(cryptoPreparedPrefix)+size)}
	cryptoWritePreparedCore(&w, rows)
	return w.b, nil
}

func AppendCryptoPreparedRows(dst []byte, rows []CryptoPreparedSecret) ([]byte, error) {
	if _, err := cryptoPreparedRowsSize(rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	cryptoWritePreparedCore(&w, rows)
	return w.b, nil
}

func cryptoReadPreparedRows(r *cryptoReader) ([]byte, uint32) {
	if !bytes.Equal(r.take(len(cryptoPreparedPrefix)), []byte(cryptoPreparedPrefix)) {
		r.err = ErrCryptoMessage
	}
	return cryptoReadPrepareResult(r)
}

func ParseCryptoPreparedRows(b []byte) (CryptoPreparedRowsView, int, error) {
	r := cryptoReader{b: b[:min(len(b), cryptoPreparedDescriptorLimit)]}
	rows, count := cryptoReadPreparedRows(&r)
	if r.err != nil {
		return CryptoPreparedRowsView{}, 0, r.failure()
	}
	return CryptoPreparedRowsView{Rows: rows, Descriptor: cryptoPreparedRowsDescriptor(rows, count)}, r.i, nil
}

func InspectCryptoPreparedRows(b []byte) (CryptoPreparedRowsView, error) {
	if len(b) > cryptoPreparedDescriptorLimit {
		return CryptoPreparedRowsView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	rows, count := cryptoReadPreparedRows(&r)
	if err := r.end(); err != nil {
		return CryptoPreparedRowsView{}, err
	}
	return CryptoPreparedRowsView{Rows: rows, Descriptor: cryptoPreparedRowsDescriptor(rows, count)}, nil
}

func DecodeCryptoPreparedRows(b []byte) ([]CryptoPreparedSecret, error) {
	v, err := InspectCryptoPreparedRows(b)
	if err != nil {
		return nil, err
	}
	return v.own(), nil
}
