package contract

import (
	"bytes"
	"encoding/binary"
)

const (
	cryptoGrantPrefix        = cryptoPurposePrefix + "grants-v6\x00"
	cryptoExclusionPrefix    = cryptoPurposePrefix + "exclusions-v6\x00"
	cryptoRetirementPrefix   = cryptoPurposePrefix + "retirements-v6\x00"
	membershipSideLength     = 2 + 2*32 + 2
	membershipRowFixedLength = 4 + membershipSideLength
	exclusionRowFixedLength  = membershipRowFixedLength + 32
	grantBaseLength          = len(cryptoGrantPrefix) + 32 + 4
	exclusionBaseLength      = len(cryptoExclusionPrefix) + 32 + 4
	retirementLength         = len(cryptoRetirementPrefix) + 32 + 4
	cryptoGrantLimit         = grantBaseLength + (membershipRowFixedLength+CryptoMaxName)*CryptoMaxValueEntries + 32*CryptoMaxMemberships
	cryptoExclusionLimit     = exclusionBaseLength + (exclusionRowFixedLength+CryptoMaxName)*CryptoMaxValueEntries + 32*CryptoMaxMemberships
)

type MembershipSide struct {
	Slot                     uint16
	Incarnation, EntryDigest ID
	Recipients               []ID
}

type MembershipSideView struct {
	Slot                     uint16
	Incarnation, EntryDigest ID
	Recipients               []byte
}

type MembershipRow struct {
	Name                     string
	Slot                     uint16
	Incarnation, EntryDigest ID
	Recipients               []ID
}

type ExclusionRow struct {
	MembershipRow
	Path ID
}

type MembershipProjectionView struct {
	Domain     ID
	Rows       []byte
	Descriptor DescriptorVector
}

func (v MembershipRow) Side() MembershipSide {
	return MembershipSide{Slot: v.Slot, Incarnation: v.Incarnation, EntryDigest: v.EntryDigest, Recipients: v.Recipients}
}

func membershipSideSize(v MembershipSide) (int, error) {
	if v.Slot >= CryptoMaxValueEntries || v.Incarnation.IsZero() {
		return 0, ErrRecord
	}
	n, err := recipientIDsLength(v.Recipients)
	return membershipSideLength - 2 + n, err
}

func writeMembershipSide(w *cryptoWriter, v MembershipSide) {
	w.u16(v.Slot)
	w.id(v.Incarnation)
	w.id(v.EntryDigest)
	writeRecipientIDs(w, v.Recipients)
}

func readMembershipSide(r *cryptoReader) MembershipSideView {
	v := MembershipSideView{Slot: r.u16(), Incarnation: r.requiredID(), EntryDigest: r.id(), Recipients: readRecipientIDs(r)}
	if r.err == nil && v.Slot >= CryptoMaxValueEntries {
		r.err = ErrRecord
	}
	return v
}

func (v MembershipSideView) own() MembershipSide {
	ids := make([]ID, len(v.Recipients)/32)
	for i := range ids {
		ids[i] = ID(v.Recipients[32*i : 32*(i+1)])
	}
	return MembershipSide{Slot: v.Slot, Incarnation: v.Incarnation, EntryDigest: v.EntryDigest, Recipients: ids}
}

func (v MembershipSideView) Own() (MembershipSide, error) {
	if v.Slot >= CryptoMaxValueEntries || v.Incarnation.IsZero() {
		return MembershipSide{}, ErrRecord
	}
	if err := recipientIDSpanError(v.Recipients); err != nil {
		return MembershipSide{}, err
	}
	return v.own(), nil
}

func writeMembershipSideView(w *cryptoWriter, v MembershipSideView) {
	var ids [CryptoMaxValueEntryRecipients]ID
	for i := 0; i < len(v.Recipients)/32; i++ {
		ids[i] = ID(v.Recipients[i*32 : (i+1)*32])
	}
	writeMembershipSide(w, MembershipSide{Slot: v.Slot, Incarnation: v.Incarnation, EntryDigest: v.EntryDigest, Recipients: ids[:len(v.Recipients)/32]})
}

func EncodeMembershipSide(v MembershipSide) ([]byte, error) {
	n, err := membershipSideSize(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeMembershipSide(&w, v)
	return w.b, nil
}

func AppendMembershipSide(dst []byte, v MembershipSide) ([]byte, error) {
	if _, err := membershipSideSize(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeMembershipSide(&w, v)
	return w.b, nil
}

func ParseMembershipSide(b []byte) (MembershipSideView, int, error) {
	r := newRecordReader(b)
	v := readMembershipSide(&r)
	if r.err != nil {
		return MembershipSideView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectMembershipSide(b []byte) (MembershipSideView, error) {
	if len(b) > membershipSideLength+32*CryptoMaxValueEntryRecipients {
		return MembershipSideView{}, ErrRecordCapacity
	}
	v, n, err := ParseMembershipSide(b)
	if err != nil {
		return MembershipSideView{}, err
	}
	if n != len(b) {
		return MembershipSideView{}, ErrRecord
	}
	return v, nil
}

func DecodeMembershipSide(b []byte) (MembershipSide, error) {
	v, err := InspectMembershipSide(b)
	if err != nil {
		return MembershipSide{}, err
	}
	return v.own(), nil
}

type membershipTotals struct {
	slots     [CryptoMaxValueEntries]bool
	rows      int
	relations int
	cryptoRecipientSet
}

func (t *membershipTotals) add(slot uint16, count int) error {
	if slot >= CryptoMaxValueEntries || t.slots[slot] {
		return ErrRecord
	}
	t.slots[slot] = true
	t.rows++
	t.relations += count
	if t.rows > CryptoMaxValueEntries || t.relations > CryptoMaxMemberships {
		return ErrRecordCapacity
	}
	return nil
}

func (t *membershipTotals) addOwned(v MembershipSide) error {
	if _, err := membershipSideSize(v); err != nil {
		return err
	}
	if err := t.add(v.Slot, len(v.Recipients)); err != nil {
		return err
	}
	for _, id := range v.Recipients {
		if err := t.addRecipient(id); err != nil {
			return err
		}
	}
	return nil
}

func (t *membershipTotals) addView(v MembershipSideView) error {
	if err := t.add(v.Slot, len(v.Recipients)/32); err != nil {
		return err
	}
	for i := 0; i < len(v.Recipients); i += 32 {
		if err := t.addRecipient(ID(v.Recipients[i : i+32])); err != nil {
			return err
		}
	}
	return nil
}

func membershipProjectionHeader(domain ID, count uint32) (b [32 + 4]byte) {
	n := copy(b[:], domain[:])
	binary.BigEndian.PutUint32(b[n:], count)
	return b
}

func writeProjectionStart(w *cryptoWriter, prefix string, domain ID, n int) {
	header := membershipProjectionHeader(domain, uint32(n))
	w.raw([]byte(prefix))
	w.raw(header[:])
}

func writeMembershipRow(w *cryptoWriter, v MembershipRow) {
	w.blob([]byte(v.Name))
	writeMembershipSide(w, v.Side())
}

func readMembershipRow(r *cryptoReader) ([]byte, MembershipSideView) {
	name := r.name()
	return name, readMembershipSide(r)
}

func membershipRowsSize(domain ID, rows []MembershipRow) (int, error) {
	if domain.IsZero() {
		return 0, ErrRecord
	}
	if len(rows) > CryptoMaxValueEntries {
		return 0, ErrRecordCapacity
	}
	n := grantBaseLength + membershipRowFixedLength*len(rows)
	var totals membershipTotals
	for i, row := range rows {
		if len(row.Name) > CryptoMaxName {
			return 0, ErrRecordCapacity
		}
		if !cryptoNamesValid(nil, []byte(row.Name), true) || i > 0 && rows[i-1].Name >= row.Name {
			return 0, ErrRecord
		}
		if err := totals.addOwned(row.Side()); err != nil {
			return 0, err
		}
		n += len(row.Name) + 32*len(row.Recipients)
	}
	return n, nil
}

func writeGrants(w *cryptoWriter, domain ID, rows []MembershipRow) {
	writeProjectionStart(w, cryptoGrantPrefix, domain, len(rows))
	for _, row := range rows {
		writeMembershipRow(w, row)
	}
}

func EncodeGrants(domain ID, rows []MembershipRow) ([]byte, error) {
	n, err := membershipRowsSize(domain, rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGrants(&w, domain, rows)
	return w.b, nil
}

func AppendGrants(dst []byte, domain ID, rows []MembershipRow) ([]byte, error) {
	if _, err := membershipRowsSize(domain, rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGrants(&w, domain, rows)
	return w.b, nil
}

func GrantDescriptor(domain ID, rows []MembershipRow) (DescriptorVector, error) {
	if _, err := membershipRowsSize(domain, rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeGrants(&w, domain, rows)
	return w.result(len(rows)), nil
}

func exclusionRowsSize(domain ID, rows []ExclusionRow) (int, error) {
	if domain.IsZero() {
		return 0, ErrRecord
	}
	if len(rows) > CryptoMaxValueEntries {
		return 0, ErrRecordCapacity
	}
	n := exclusionBaseLength + exclusionRowFixedLength*len(rows)
	var totals membershipTotals
	for i, row := range rows {
		if len(row.Name) > CryptoMaxName {
			return 0, ErrRecordCapacity
		}
		if !cryptoNamesValid(nil, []byte(row.Name), true) || i > 0 && rows[i-1].Name >= row.Name {
			return 0, ErrRecord
		}
		if err := totals.addOwned(row.Side()); err != nil {
			return 0, err
		}
		n += len(row.Name) + 32*len(row.Recipients)
	}
	return n, nil
}

func writeExclusionRow(w *cryptoWriter, v ExclusionRow) {
	writeMembershipRow(w, v.MembershipRow)
	w.id(v.Path)
}

func readExclusionRow(r *cryptoReader) ([]byte, MembershipSideView, ID) {
	name, side := readMembershipRow(r)
	return name, side, r.id()
}

func writeExclusions(w *cryptoWriter, domain ID, rows []ExclusionRow) {
	writeProjectionStart(w, cryptoExclusionPrefix, domain, len(rows))
	for _, row := range rows {
		writeExclusionRow(w, row)
	}
}

func EncodeExclusions(domain ID, rows []ExclusionRow) ([]byte, error) {
	n, err := exclusionRowsSize(domain, rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeExclusions(&w, domain, rows)
	return w.b, nil
}

func AppendExclusions(dst []byte, domain ID, rows []ExclusionRow) ([]byte, error) {
	if _, err := exclusionRowsSize(domain, rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeExclusions(&w, domain, rows)
	return w.b, nil
}

func ExclusionDescriptor(domain ID, rows []ExclusionRow) (DescriptorVector, error) {
	if _, err := exclusionRowsSize(domain, rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeExclusions(&w, domain, rows)
	return w.result(len(rows)), nil
}

func readMembershipRows(r *cryptoReader, n uint32, exclusion bool) []byte {
	rowMinimum := membershipRowFixedLength + 32
	if exclusion {
		rowMinimum += 32
	}
	if r.err != nil {
		return nil
	}
	if n > CryptoMaxValueEntries {
		r.err = ErrRecordCapacity
		return nil
	}
	if int(n) > (len(r.b)-r.i)/rowMinimum {
		r.err = ErrRecord
		return nil
	}
	start := r.i
	var previous []byte
	var totals membershipTotals
	for i := uint32(0); i < n && r.err == nil; i++ {
		name, side := readMembershipRow(r)
		if exclusion {
			r.id()
		}
		if r.err != nil {
			break
		}
		if !cryptoNamesValid(previous, name, i == 0) {
			r.err = ErrRecord
			break
		}
		previous = name
		r.err = totals.addView(side)
	}
	return r.b[start:r.i:r.i]
}

func membershipProjectionShape(exclusion bool) (prefix string, base, limit int) {
	if exclusion {
		return cryptoExclusionPrefix, exclusionBaseLength, cryptoExclusionLimit
	}
	return cryptoGrantPrefix, grantBaseLength, cryptoGrantLimit
}

func membershipRowsDescriptor(domain ID, span []byte, n uint32, exclusion bool) DescriptorVector {
	prefix, _, _ := membershipProjectionShape(exclusion)
	w := cryptoHashWriter("")
	writeProjectionStart(&w, prefix, domain, int(n))
	r := newRecordReader(span)
	for i := uint32(0); i < n; i++ {
		name, side := readMembershipRow(&r)
		w.blob(name)
		writeMembershipSideView(&w, side)
		if exclusion {
			w.id(r.id())
		}
	}
	return w.result(int(n))
}

func parseMembershipProjection(b []byte, domain ID, exclusion, complete bool) (MembershipProjectionView, int, error) {
	prefix, _, limit := membershipProjectionShape(exclusion)
	if complete && len(b) > limit {
		return MembershipProjectionView{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b[:min(len(b), limit)])
	if domain.IsZero() || !bytes.Equal(r.take(len(prefix)), []byte(prefix)) || r.requiredID() != domain {
		return MembershipProjectionView{}, 0, ErrRecord
	}
	n := r.u32()
	span := readMembershipRows(&r, n, exclusion)
	if complete {
		r.err = r.end()
	}
	if r.err != nil {
		return MembershipProjectionView{}, 0, r.failure()
	}
	v := MembershipProjectionView{Domain: domain, Rows: span, Descriptor: membershipRowsDescriptor(domain, span, n, exclusion)}
	return v, r.i, nil
}

func ParseGrants(b []byte, domain ID) (MembershipProjectionView, int, error) {
	return parseMembershipProjection(b, domain, false, false)
}

func ParseExclusions(b []byte, domain ID) (MembershipProjectionView, int, error) {
	return parseMembershipProjection(b, domain, true, false)
}

func InspectGrants(b []byte, domain ID) (MembershipProjectionView, error) {
	v, _, err := parseMembershipProjection(b, domain, false, true)
	return v, err
}

func InspectExclusions(b []byte, domain ID) (MembershipProjectionView, error) {
	v, _, err := parseMembershipProjection(b, domain, true, true)
	return v, err
}

func (v MembershipProjectionView) validateMembership(exclusion bool) error {
	_, base, limit := membershipProjectionShape(exclusion)
	if v.Descriptor.Count > CryptoMaxValueEntries || len(v.Rows) > limit-base || v.Descriptor.Length > uint64(limit) {
		return ErrRecordCapacity
	}
	if v.Domain.IsZero() || v.Descriptor.Length != uint64(base+len(v.Rows)) {
		return ErrRecord
	}
	r := newRecordReader(v.Rows)
	readMembershipRows(&r, v.Descriptor.Count, exclusion)
	if err := r.end(); err != nil {
		return err
	}
	if membershipRowsDescriptor(v.Domain, v.Rows, v.Descriptor.Count, exclusion) != v.Descriptor {
		return ErrRecord
	}
	return nil
}

func ownedMembershipRow(name []byte, side MembershipSideView) MembershipRow {
	v := side.own()
	return MembershipRow{Name: string(name), Slot: v.Slot, Incarnation: v.Incarnation, EntryDigest: v.EntryDigest, Recipients: v.Recipients}
}

func (v MembershipProjectionView) OwnGrants() ([]MembershipRow, error) {
	if err := v.validateMembership(false); err != nil {
		return nil, err
	}
	rows := make([]MembershipRow, v.Descriptor.Count)
	r := newRecordReader(v.Rows)
	for i := range rows {
		name, side := readMembershipRow(&r)
		rows[i] = ownedMembershipRow(name, side)
	}
	return rows, nil
}

func (v MembershipProjectionView) OwnExclusions() ([]ExclusionRow, error) {
	if err := v.validateMembership(true); err != nil {
		return nil, err
	}
	rows := make([]ExclusionRow, v.Descriptor.Count)
	r := newRecordReader(v.Rows)
	for i := range rows {
		name, side, path := readExclusionRow(&r)
		rows[i] = ExclusionRow{MembershipRow: ownedMembershipRow(name, side), Path: path}
	}
	return rows, nil
}

func DecodeGrants(b []byte, domain ID) ([]MembershipRow, error) {
	v, err := InspectGrants(b, domain)
	if err != nil {
		return nil, err
	}
	return v.OwnGrants()
}

func DecodeExclusions(b []byte, domain ID) ([]ExclusionRow, error) {
	v, err := InspectExclusions(b, domain)
	if err != nil {
		return nil, err
	}
	return v.OwnExclusions()
}

func RetirementDescriptor(domain ID, rows []RecipientRetirementRow) (DescriptorVector, error) {
	if err := retirementRowsError(domain, rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeRetirements(&w, domain, rows)
	return w.result(len(rows)), nil
}

func AppendRetirements(dst []byte, domain ID, rows []RecipientRetirementRow) ([]byte, error) {
	if err := retirementRowsError(domain, rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeRetirements(&w, domain, rows)
	return w.b, nil
}

func EncodeRetirements(domain ID, rows []RecipientRetirementRow) ([]byte, error) {
	if err := retirementRowsError(domain, rows); err != nil {
		return nil, err
	}
	return AppendRetirements(make([]byte, 0, retirementLength+RecipientRetirementRowLength*len(rows)), domain, rows)
}

func ParseRetirements(b []byte, domain ID) (DescriptorVector, int, error) {
	r := newRecordReader(b)
	if domain.IsZero() || !bytes.Equal(r.take(len(cryptoRetirementPrefix)), []byte(cryptoRetirementPrefix)) || r.requiredID() != domain {
		return DescriptorVector{}, 0, ErrRecord
	}
	count := r.u32()
	if count > 1 {
		return DescriptorVector{}, 0, ErrRecordCapacity
	}
	if count != 0 {
		readRecipientRetirementRow(&r)
	}
	if r.err != nil {
		return DescriptorVector{}, 0, r.failure()
	}
	return DescriptorVector{Digest: Hash(b[:r.i]), Length: uint64(r.i), Count: count}, r.i, nil
}

func InspectRetirements(b []byte, domain ID) (DescriptorVector, error) {
	if len(b) != retirementLength && len(b) != retirementLength+RecipientRetirementRowLength {
		return DescriptorVector{}, ErrRecord
	}
	d, n, err := ParseRetirements(b, domain)
	if err == nil && n != len(b) {
		return DescriptorVector{}, ErrRecord
	}
	return d, err
}
