package contract

import "bytes"

const (
	cryptoPublicPrefix        = cryptoPurposePrefix + "public-state-v6\x00"
	publicStateBaseLength     = len(cryptoPublicPrefix) + 2*32 + descriptorSize + 4
	publicStateRowFixedLength = 4 + 2 + 32
	cryptoPublicLimit         = publicStateBaseLength + (publicStateRowFixedLength+CryptoMaxName)*CryptoMaxValueEntries
)

type PublicStateRow struct {
	Name        string
	Slot        uint16
	EntryDigest ID
}

type PublicState struct {
	Domain          ID
	AccessRoot      ID
	RequiredSupport DescriptorVector
	Rows            []PublicStateRow
}

// PublicStateView borrows Rows from unchanged input. Access, support and entry
// hashes remain opaque until Core checks their complete authenticated bodies.
type PublicStateView struct {
	Domain          ID
	AccessRoot      ID
	RequiredSupport DescriptorVector
	Rows            []byte
	Descriptor      DescriptorVector
	encoded         []byte
}

type publicStateRowView struct {
	name        []byte
	slot        uint16
	entryDigest ID
}

func readPublicStateRow(r *cryptoReader) publicStateRowView {
	return publicStateRowView{name: r.name(), slot: r.u16(), entryDigest: r.id()}
}

func writePublicStateRow(w *cryptoWriter, v PublicStateRow) {
	w.blob([]byte(v.Name))
	w.u16(v.Slot)
	w.id(v.EntryDigest)
}

func publicStateSize(v PublicState) (int, error) {
	if len(v.Rows) > CryptoMaxValueEntries {
		return 0, ErrRecordCapacity
	}
	if v.Domain.IsZero() || !requiredSupportDescriptorValid(v.RequiredSupport) {
		return 0, ErrRecord
	}
	size := publicStateBaseLength + publicStateRowFixedLength*len(v.Rows)
	var slots [CryptoMaxValueEntries]bool
	for i, row := range v.Rows {
		if len(row.Name) > CryptoMaxName {
			return 0, ErrRecordCapacity
		}
		if !cryptoNamesValid(nil, []byte(row.Name), true) || (i > 0 && v.Rows[i-1].Name >= row.Name) || row.Slot >= CryptoMaxValueEntries || slots[row.Slot] {
			return 0, ErrRecord
		}
		slots[row.Slot] = true
		size += len(row.Name)
	}
	return size, nil
}

func writePublicState(w *cryptoWriter, v PublicState) {
	w.raw([]byte(cryptoPublicPrefix))
	w.id(v.Domain)
	w.id(v.AccessRoot)
	w.descriptor(v.RequiredSupport)
	w.u32(uint32(len(v.Rows)))
	for _, row := range v.Rows {
		writePublicStateRow(w, row)
	}
}

func PublicStateDescriptor(v PublicState) (DescriptorVector, error) {
	if _, err := publicStateSize(v); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writePublicState(&w, v)
	return w.result(len(v.Rows)), nil
}

func EncodePublicState(v PublicState) ([]byte, error) {
	size, err := publicStateSize(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, size)}
	writePublicState(&w, v)
	return w.b, nil
}

func AppendPublicState(dst []byte, v PublicState) ([]byte, error) {
	if _, err := publicStateSize(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writePublicState(&w, v)
	return w.b, nil
}

func ParsePublicState(b []byte, domain ID) (PublicStateView, int, error) {
	r := newRecordReader(b[:min(len(b), cryptoPublicLimit)])
	if !bytes.Equal(r.take(len(cryptoPublicPrefix)), []byte(cryptoPublicPrefix)) {
		return PublicStateView{}, 0, ErrRecord
	}
	v := PublicStateView{Domain: r.requiredID(), AccessRoot: r.id(), RequiredSupport: r.descriptor()}
	if r.err != nil {
		return PublicStateView{}, 0, r.failure()
	}
	if v.Domain != domain || !requiredSupportDescriptorValid(v.RequiredSupport) {
		return PublicStateView{}, 0, ErrRecord
	}
	n := r.count(CryptoMaxValueEntries, publicStateRowFixedLength)
	start := r.i
	var previous []byte
	var slots [CryptoMaxValueEntries]bool
	for i := 0; i < n && r.err == nil; i++ {
		row := readPublicStateRow(&r)
		if r.err != nil {
			break
		}
		if !cryptoNamesValid(previous, row.name, i == 0) || row.slot >= CryptoMaxValueEntries || slots[row.slot] {
			return PublicStateView{}, 0, ErrRecord
		}
		previous = row.name
		slots[row.slot] = true
	}
	if r.err != nil {
		return PublicStateView{}, 0, r.failure()
	}
	v.Rows = b[start:r.i:r.i]
	v.encoded = b[:r.i:r.i]
	v.Descriptor = DescriptorVector{Digest: Hash(v.encoded), Length: uint64(r.i), Count: uint32(n)}
	return v, r.i, nil
}

func InspectPublicState(b []byte, domain ID) (PublicStateView, error) {
	if len(b) > cryptoPublicLimit {
		return PublicStateView{}, ErrRecordCapacity
	}
	v, n, err := ParsePublicState(b, domain)
	if err != nil {
		return PublicStateView{}, err
	}
	if n != len(b) {
		return PublicStateView{}, ErrRecord
	}
	return v, nil
}

func ownPublicState(v PublicStateView) PublicState {
	out := PublicState{Domain: v.Domain, AccessRoot: v.AccessRoot, RequiredSupport: v.RequiredSupport,
		Rows: make([]PublicStateRow, v.Descriptor.Count)}
	r := newRecordReader(v.Rows)
	for i := range out.Rows {
		row := readPublicStateRow(&r)
		out.Rows[i] = PublicStateRow{Name: string(row.name), Slot: row.slot, EntryDigest: row.entryDigest}
	}
	return out
}

func (v PublicStateView) Own() (PublicState, error) {
	if v.Descriptor.Count > CryptoMaxValueEntries || v.Descriptor.Length > uint64(cryptoPublicLimit) || len(v.Rows) > cryptoPublicLimit-publicStateBaseLength {
		return PublicState{}, ErrRecordCapacity
	}
	checked, err := InspectPublicState(v.encoded, v.Domain)
	if err != nil {
		return PublicState{}, err
	}
	if v.AccessRoot != checked.AccessRoot || v.RequiredSupport != checked.RequiredSupport || v.Descriptor != checked.Descriptor || !bytes.Equal(v.Rows, checked.Rows) {
		return PublicState{}, ErrRecord
	}
	return ownPublicState(checked), nil
}

func DecodePublicState(b []byte, domain ID) (PublicState, error) {
	v, err := InspectPublicState(b, domain)
	if err != nil {
		return PublicState{}, err
	}
	return ownPublicState(v), nil
}
