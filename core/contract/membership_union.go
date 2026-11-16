package contract

import "bytes"

const (
	cryptoUnionPrefix   = cryptoPurposePrefix + "lifecycle-union-v6\x00"
	unionBaseLength     = len(cryptoUnionPrefix) + 32 + 4
	unionRowFixedLength = 4 + 2
	cryptoUnionLimit    = unionBaseLength + (unionRowFixedLength+CryptoMaxName)*CryptoMaxUnion + 2*membershipSideLength*CryptoMaxValueEntries + 2*32*CryptoMaxMemberships
)

type UnionRow struct {
	Name                        string
	BeforePresent, AfterPresent bool
	Before, After               MembershipSide
}

type unionRowView struct {
	name                        []byte
	beforePresent, afterPresent bool
	before, after               MembershipSideView
}

func absentMembershipSide(v MembershipSide) bool {
	return v.Slot == 0 && v.Incarnation.IsZero() && v.EntryDigest.IsZero() && len(v.Recipients) == 0
}

func unionSize(domain ID, rows []UnionRow) (int, error) {
	if domain.IsZero() {
		return 0, ErrRecord
	}
	if len(rows) > CryptoMaxUnion {
		return 0, ErrRecordCapacity
	}
	n := unionBaseLength + unionRowFixedLength*len(rows)
	var before, after membershipTotals
	for i, row := range rows {
		if len(row.Name) > CryptoMaxName {
			return 0, ErrRecordCapacity
		}
		if !cryptoNamesValid(nil, []byte(row.Name), true) || i > 0 && rows[i-1].Name >= row.Name ||
			!row.BeforePresent && !row.AfterPresent || !row.BeforePresent && !absentMembershipSide(row.Before) || !row.AfterPresent && !absentMembershipSide(row.After) {
			return 0, ErrRecord
		}
		n += len(row.Name)
		if row.BeforePresent {
			if err := before.addOwned(row.Before); err != nil {
				return 0, err
			}
			n += membershipSideLength + 32*len(row.Before.Recipients)
		}
		if row.AfterPresent {
			if err := after.addOwned(row.After); err != nil {
				return 0, err
			}
			n += membershipSideLength + 32*len(row.After.Recipients)
		}
	}
	return n, nil
}

func writeUnionPresence(w *cryptoWriter, name []byte, before, after bool) {
	w.blob(name)
	b, a := uint8(0), uint8(0)
	if before {
		b = 1
	}
	if after {
		a = 1
	}
	w.u8(b)
	w.u8(a)
}

func writeUnionRow(w *cryptoWriter, v UnionRow) {
	writeUnionPresence(w, []byte(v.Name), v.BeforePresent, v.AfterPresent)
	if v.BeforePresent {
		writeMembershipSide(w, v.Before)
	}
	if v.AfterPresent {
		writeMembershipSide(w, v.After)
	}
}

func readUnionRow(r *cryptoReader) unionRowView {
	v := unionRowView{name: r.name()}
	before, after := r.u8(), r.u8()
	if r.err == nil && (before > 1 || after > 1 || before == 0 && after == 0) {
		r.err = ErrRecord
	}
	v.beforePresent, v.afterPresent = before == 1, after == 1
	if v.beforePresent {
		v.before = readMembershipSide(r)
	}
	if v.afterPresent {
		v.after = readMembershipSide(r)
	}
	return v
}

func writeUnion(w *cryptoWriter, domain ID, rows []UnionRow) {
	writeProjectionStart(w, cryptoUnionPrefix, domain, len(rows))
	for _, row := range rows {
		writeUnionRow(w, row)
	}
}

func UnionDescriptor(domain ID, rows []UnionRow) (DescriptorVector, error) {
	if _, err := unionSize(domain, rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeUnion(&w, domain, rows)
	return w.result(len(rows)), nil
}

func EncodeUnion(domain ID, rows []UnionRow) ([]byte, error) {
	n, err := unionSize(domain, rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeUnion(&w, domain, rows)
	return w.b, nil
}

func AppendUnion(dst []byte, domain ID, rows []UnionRow) ([]byte, error) {
	if _, err := unionSize(domain, rows); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeUnion(&w, domain, rows)
	return w.b, nil
}

func readUnionRows(r *cryptoReader, n uint32) []byte {
	if r.err != nil {
		return nil
	}
	if n > CryptoMaxUnion {
		r.err = ErrRecordCapacity
		return nil
	}
	if int(n) > (len(r.b)-r.i)/(unionRowFixedLength+membershipSideLength+32) {
		r.err = ErrRecord
		return nil
	}
	start := r.i
	var previous []byte
	var before, after membershipTotals
	for i := uint32(0); i < n && r.err == nil; i++ {
		row := readUnionRow(r)
		if r.err != nil {
			break
		}
		if !cryptoNamesValid(previous, row.name, i == 0) {
			r.err = ErrRecord
			break
		}
		previous = row.name
		if row.beforePresent {
			r.err = before.addView(row.before)
		}
		if r.err == nil && row.afterPresent {
			r.err = after.addView(row.after)
		}
	}
	return r.b[start:r.i:r.i]
}

func unionRowsDescriptor(domain ID, span []byte, n uint32) DescriptorVector {
	w := cryptoHashWriter("")
	writeProjectionStart(&w, cryptoUnionPrefix, domain, int(n))
	r := newRecordReader(span)
	for i := uint32(0); i < n; i++ {
		row := readUnionRow(&r)
		writeUnionPresence(&w, row.name, row.beforePresent, row.afterPresent)
		if row.beforePresent {
			writeMembershipSideView(&w, row.before)
		}
		if row.afterPresent {
			writeMembershipSideView(&w, row.after)
		}
	}
	return w.result(int(n))
}

func parseUnion(b []byte, domain ID, complete bool) (MembershipProjectionView, int, error) {
	if complete && len(b) > cryptoUnionLimit {
		return MembershipProjectionView{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b[:min(len(b), cryptoUnionLimit)])
	if domain.IsZero() || !bytes.Equal(r.take(len(cryptoUnionPrefix)), []byte(cryptoUnionPrefix)) || r.requiredID() != domain {
		return MembershipProjectionView{}, 0, ErrRecord
	}
	n := r.u32()
	span := readUnionRows(&r, n)
	if complete {
		r.err = r.end()
	}
	if r.err != nil {
		return MembershipProjectionView{}, 0, r.failure()
	}
	v := MembershipProjectionView{Domain: domain, Rows: span, Descriptor: unionRowsDescriptor(domain, span, n)}
	return v, r.i, nil
}

func ParseUnion(b []byte, domain ID) (MembershipProjectionView, int, error) {
	return parseUnion(b, domain, false)
}

func InspectUnion(b []byte, domain ID) (MembershipProjectionView, error) {
	v, _, err := parseUnion(b, domain, true)
	return v, err
}

func (v MembershipProjectionView) OwnUnion() ([]UnionRow, error) {
	if v.Descriptor.Count > CryptoMaxUnion || len(v.Rows) > cryptoUnionLimit-unionBaseLength || v.Descriptor.Length > uint64(cryptoUnionLimit) {
		return nil, ErrRecordCapacity
	}
	if v.Domain.IsZero() || v.Descriptor.Length != uint64(unionBaseLength+len(v.Rows)) {
		return nil, ErrRecord
	}
	r := newRecordReader(v.Rows)
	readUnionRows(&r, v.Descriptor.Count)
	if err := r.end(); err != nil {
		return nil, err
	}
	if unionRowsDescriptor(v.Domain, v.Rows, v.Descriptor.Count) != v.Descriptor {
		return nil, ErrRecord
	}
	rows := make([]UnionRow, v.Descriptor.Count)
	r = newRecordReader(v.Rows)
	for i := range rows {
		row := readUnionRow(&r)
		rows[i] = UnionRow{Name: string(row.name), BeforePresent: row.beforePresent, AfterPresent: row.afterPresent}
		if row.beforePresent {
			rows[i].Before = row.before.own()
		}
		if row.afterPresent {
			rows[i].After = row.after.own()
		}
	}
	return rows, nil
}

func DecodeUnion(b []byte, domain ID) ([]UnionRow, error) {
	v, err := InspectUnion(b, domain)
	if err != nil {
		return nil, err
	}
	return v.OwnUnion()
}
