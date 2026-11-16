package contract

import (
	"bytes"
	"encoding/binary"
)

const (
	cryptoIntentPrefix   = cryptoPurposePrefix + "supplied-intent-v8\x00"
	intentBaseLength     = len(cryptoIntentPrefix) + 32 + 4
	intentRowFixedLength = 4 + 2 + 1 + 1 + 4 + 1 + 4 + 1 + 32 + 4 + 1 + 2*32
	cryptoIntentLimit    = intentBaseLength + (intentRowFixedLength+CryptoMaxName)*CryptoMaxValueEntries + 32*CryptoMaxMemberships
)

// An Intent commits the complete desired entry set. Required membership and
// current binding admission are checked by the component that owns the input.
// Payload digests are opaque here; input correspondence is a separate check.
func cryptoIntentFieldsValid(v CryptoIntentRow, nameLength int) error {
	if v.ContentLength > CryptoMaxRawValue || v.RetainedLength > CryptoMaxRetainedValue {
		return ErrCryptoCapacity
	}
	if InputLengths(v.InputEncoding, v.ContentLength, v.RetainedLength) != nil || (v.OutputEncoding != OutputEncodingRaw && v.OutputEncoding != OutputEncodingBase64) || !ValidatePublicEntryTags(v.ValueSource, v.ConfidentialityClass) {
		return ErrCryptoMessage
	}
	retained := v.Retained != (RetainedSecretInput{})
	if retained && (v.ValueSource != Supplied || v.ConfidentialityClass != Secret || v.Retained.Incarnation.IsZero() || v.Retained.Material.IsZero()) {
		return ErrCryptoMessage
	}
	switch v.ConfidentialityClass {
	case Plain:
		if v.PayloadLength != v.RetainedLength {
			return ErrCryptoMessage
		}
	case Secret:
		overhead := uint64(SealedInputEnvelopeFixedLength) + uint64(nameLength)
		if v.ValueSource == Generated || retained {
			overhead = CanonicalPayloadOverhead
		}
		if uint64(v.PayloadLength) != overhead+uint64(v.RetainedLength) {
			return ErrCryptoMessage
		}
	}
	return nil
}

func cryptoIntentRowValid(v CryptoIntentRow) error {
	if len(v.Name) > CryptoMaxName {
		return ErrCryptoCapacity
	}
	if !cryptoNamesValid(nil, []byte(v.Name), true) {
		return ErrCryptoMessage
	}
	if _, err := recipientIDsLength(v.Recipients); err != nil {
		return err
	}
	return cryptoIntentFieldsValid(v, len(v.Name))
}

// Fixed scratch permits the complete aggregate scan before any row, name or
// recipient vector is retained. It is independent of caller-declared counts.
type cryptoIntentTotals struct {
	raw         uint64
	memberships int
	generated   int
	cryptoRecipientSet
}

func (s *cryptoIntentTotals) addValueSource(valueSource uint8) error {
	if valueSource == Generated {
		s.generated++
		if s.generated > GeneratedCurrentEntryLimit {
			return ErrCryptoCapacity
		}
	}
	return nil
}

type cryptoRecipientSet struct {
	count      int
	recipients [CryptoMaxRecipients]ID
}

func (s *cryptoIntentTotals) addRow(raw uint32, count int) error {
	s.raw += uint64(raw)
	s.memberships += count
	if s.raw > CryptoMaxRawSet || s.memberships > CryptoMaxMemberships {
		return ErrCryptoCapacity
	}
	return nil
}

func (s *cryptoRecipientSet) addRecipient(id ID) error {
	for _, known := range s.recipients[:s.count] {
		if id == known {
			return nil
		}
	}
	if s.count == len(s.recipients) {
		return ErrCryptoCapacity
	}
	s.recipients[s.count] = id
	s.count++
	return nil
}

func cryptoIntentSize(domain ID, rows []CryptoIntentRow) (int, error) {
	if domain.IsZero() {
		return 0, ErrCryptoMessage
	}
	if len(rows) > CryptoMaxValueEntries {
		return 0, ErrCryptoCapacity
	}
	n := intentBaseLength + intentRowFixedLength*len(rows)
	var totals cryptoIntentTotals
	for i, row := range rows {
		if err := cryptoIntentRowValid(row); err != nil {
			return 0, err
		}
		if i > 0 && rows[i-1].Name >= row.Name {
			return 0, ErrCryptoMessage
		}
		if err := totals.addRow(row.ContentLength, len(row.Recipients)); err != nil {
			return 0, err
		}
		if err := totals.addValueSource(row.ValueSource); err != nil {
			return 0, err
		}
		for _, id := range row.Recipients {
			if err := totals.addRecipient(id); err != nil {
				return 0, err
			}
		}
		n += len(row.Name) + 32*len(row.Recipients)
	}
	return n, nil
}

func cryptoWriteIntentRowData(w *cryptoWriter, name []byte, v CryptoIntentRow) {
	w.blob(name)
	writeRecipientIDs(w, v.Recipients)
	w.u8(v.ValueSource)
	w.u8(v.ConfidentialityClass)
	w.u32(v.ContentLength)
	w.u8(v.InputEncoding)
	w.u32(v.RetainedLength)
	w.u8(v.OutputEncoding)
	w.id(v.PayloadDigest)
	w.u32(v.PayloadLength)
	if v.Retained == (RetainedSecretInput{}) {
		w.u8(0)
	} else {
		w.u8(1)
	}
	w.id(v.Retained.Incarnation)
	w.id(v.Retained.Material)
}

func cryptoWriteIntentRow(w *cryptoWriter, v CryptoIntentRow) {
	cryptoWriteIntentRowData(w, []byte(v.Name), v)
}

func cryptoIntentHeader(domain ID, count uint32) [intentBaseLength]byte {
	var header [intentBaseLength]byte
	n := copy(header[:], cryptoIntentPrefix)
	n += copy(header[n:], domain[:])
	binary.BigEndian.PutUint32(header[n:], count)
	return header
}

func cryptoWriteIntent(w *cryptoWriter, domain ID, rows []CryptoIntentRow) {
	header := cryptoIntentHeader(domain, uint32(len(rows)))
	w.raw(header[:])
	for _, row := range rows {
		cryptoWriteIntentRow(w, row)
	}
}

type cryptoIntentRowView struct {
	name, recipients []byte
	fields           CryptoIntentRow
}

func cryptoReadIntentRow(r *cryptoReader) cryptoIntentRowView {
	v := cryptoIntentRowView{name: r.name(), recipients: readRecipientIDs(r)}
	v.fields = CryptoIntentRow{ValueSource: r.u8(), ConfidentialityClass: r.u8(), ContentLength: r.u32(), InputEncoding: r.u8(), RetainedLength: r.u32(), OutputEncoding: r.u8(), PayloadDigest: r.id(), PayloadLength: r.u32()}
	kind := r.u8()
	v.fields.Retained = RetainedSecretInput{Incarnation: r.id(), Material: r.id()}
	if r.err == nil && (kind > 1 || (kind == 0) != (v.fields.Retained == (RetainedSecretInput{}))) {
		r.err = ErrCryptoMessage
	}
	if r.err == nil {
		r.err = cryptoIntentFieldsValid(v.fields, len(v.name))
	}
	return v
}

func (v cryptoIntentRowView) own() CryptoIntentRow {
	out := v.fields
	out.Name = string(v.name)
	out.Recipients = make([]ID, len(v.recipients)/32)
	for i := range out.Recipients {
		out.Recipients[i] = ID(v.recipients[32*i : 32*(i+1)])
	}
	return out
}

func cryptoReadIntentRows(r *cryptoReader) (rows []byte, count int) {
	count = r.count(CryptoMaxValueEntries, intentRowFixedLength+32)
	return cryptoReadIntentRowSpan(r, count), count
}

func cryptoReadIntentRowSpan(r *cryptoReader, count int) []byte {
	if r.err != nil {
		return nil
	}
	if count < 0 || count > CryptoMaxValueEntries {
		r.err = ErrCryptoCapacity
		return nil
	}
	if count > (len(r.b)-r.i)/(intentRowFixedLength+32) {
		r.err = ErrCryptoMessage
		return nil
	}
	start := r.i
	var totals cryptoIntentTotals
	var previous []byte
	for i := 0; i < count && r.err == nil; i++ {
		row := cryptoReadIntentRow(r)
		if r.err != nil {
			break
		}
		if !cryptoNamesValid(previous, row.name, i == 0) {
			r.err = ErrCryptoMessage
			break
		}
		previous = row.name
		if r.err = totals.addRow(row.fields.ContentLength, len(row.recipients)/32); r.err != nil {
			break
		}
		if r.err = totals.addValueSource(row.fields.ValueSource); r.err != nil {
			break
		}
		for j := 0; j < len(row.recipients) && r.err == nil; j += 32 {
			r.err = totals.addRecipient(ID(row.recipients[j : j+32]))
		}
	}
	return r.b[start:r.i:r.i]
}

// This projection deliberately uses the shared row writer. A message carrier
// or a future transport cannot select different cryptographic input bytes.
func cryptoWriteIntentRowsView(w *cryptoWriter, rows []byte, count int) {
	r := cryptoReader{b: rows}
	var recipients [CryptoMaxValueEntryRecipients]ID
	for i := 0; i < count; i++ {
		row := cryptoReadIntentRow(&r)
		row.fields.Recipients = recipients[:len(row.recipients)/32]
		for j := range row.fields.Recipients {
			row.fields.Recipients[j] = ID(row.recipients[j*32 : (j+1)*32])
		}
		cryptoWriteIntentRowData(w, row.name, row.fields)
	}
}

func cryptoIntentRowsDescriptor(domain ID, rows []byte, count int) DescriptorVector {
	w := cryptoHashWriter("")
	header := cryptoIntentHeader(domain, uint32(count))
	w.raw(header[:])
	cryptoWriteIntentRowsView(&w, rows, count)
	return w.result(count)
}

func CryptoIntentDescriptor(domain ID, rows []CryptoIntentRow) (DescriptorVector, error) {
	if _, err := cryptoIntentSize(domain, rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	cryptoWriteIntent(&w, domain, rows)
	return w.result(len(rows)), nil
}

func EncodeCryptoIntent(domain ID, rows []CryptoIntentRow) ([]byte, error) {
	n, err := cryptoIntentSize(domain, rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	cryptoWriteIntent(&w, domain, rows)
	return w.b, nil
}

func AppendCryptoIntent(dst []byte, domain ID, rows []CryptoIntentRow) ([]byte, error) {
	if _, err := cryptoIntentSize(domain, rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	cryptoWriteIntent(&w, domain, rows)
	return w.b, nil
}

// CryptoIntentView borrows the canonical row span from unchanged input. Own
// copies every retained name and recipient set after complete preflight.
type CryptoIntentView struct {
	Domain     ID
	Rows       []byte
	Descriptor DescriptorVector
}

func cryptoOwnIntentRows(rows []byte, count int) []CryptoIntentRow {
	out := make([]CryptoIntentRow, count)
	r := cryptoReader{b: rows}
	for i := range out {
		out[i] = cryptoReadIntentRow(&r).own()
	}
	return out
}

func (v CryptoIntentView) Own() ([]CryptoIntentRow, error) {
	if v.Descriptor.Count > CryptoMaxValueEntries || v.Descriptor.Length > uint64(cryptoIntentLimit) ||
		len(v.Rows) > cryptoIntentLimit-intentBaseLength {
		return nil, ErrCryptoCapacity
	}
	if err := cryptoIntentDescriptorError(v.Domain, v.Descriptor); err != nil {
		return nil, err
	}
	r := cryptoReader{b: v.Rows}
	rows := cryptoReadIntentRowSpan(&r, int(v.Descriptor.Count))
	if err := r.end(); err != nil {
		return nil, err
	}
	if cryptoIntentRowsDescriptor(v.Domain, rows, int(v.Descriptor.Count)) != v.Descriptor {
		return nil, ErrCryptoMessage
	}
	return cryptoOwnIntentRows(rows, int(v.Descriptor.Count)), nil
}

func ParseCryptoIntent(b []byte, domain ID) (CryptoIntentView, int, error) {
	r := cryptoReader{b: b}
	if !bytes.Equal(r.take(len(cryptoIntentPrefix)), []byte(cryptoIntentPrefix)) || r.requiredID() != domain {
		return CryptoIntentView{}, 0, ErrCryptoMessage
	}
	rows, count := cryptoReadIntentRows(&r)
	if r.err != nil {
		return CryptoIntentView{}, 0, r.failure()
	}
	return CryptoIntentView{Domain: domain, Rows: rows, Descriptor: cryptoIntentRowsDescriptor(domain, rows, count)}, r.i, nil
}

func InspectCryptoIntent(b []byte, domain ID) (CryptoIntentView, error) {
	if len(b) > cryptoIntentLimit {
		return CryptoIntentView{}, ErrCryptoCapacity
	}
	v, consumed, err := ParseCryptoIntent(b, domain)
	if err != nil {
		return CryptoIntentView{}, err
	}
	if consumed != len(b) {
		return CryptoIntentView{}, ErrCryptoMessage
	}
	return v, nil
}

func DecodeCryptoIntent(b []byte, domain ID) ([]CryptoIntentRow, error) {
	v, err := InspectCryptoIntent(b, domain)
	if err != nil {
		return nil, err
	}
	return cryptoOwnIntentRows(v.Rows, int(v.Descriptor.Count)), nil
}
