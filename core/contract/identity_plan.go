package contract

import "bytes"

const (
	cryptoIdentityPrefix   = "ENKV/LIFECYCLE-ID-PLAN/v7\x00"
	identityBaseLength     = len(cryptoIdentityPrefix) + 4*32 + 2*4
	identityRowFixedLength = 4 + 2 + 4*32
	identityPageLength     = 1 + 2 + 32
	cryptoIdentityLimit    = identityBaseLength + (identityRowFixedLength+CryptoMaxName)*CryptoMaxValueEntries + identityPageLength*MaxChildPages
)

type IdentityRow struct {
	Name                                                      string
	Slot                                                      uint16
	Incarnation, ValueState, OriginSnapshot, OriginTransition ID
}

type IdentityPage struct {
	Kind   Kind
	Index  uint16
	Object ID
}

type IdentityPlan struct {
	Operation, Transition, Snapshot, Revision ID
	Rows                                      []IdentityRow
	Pages                                     []IdentityPage
}

// IdentityPlanView borrows complete row spans from unchanged input. Identity
// allocation and correspondence with the selected state remain Core checks.
type IdentityPlanView struct {
	Operation, Transition, Snapshot, Revision ID
	Rows, Pages                               []byte
	PageCount                                 uint32
	Descriptor                                DescriptorVector
	encoded                                   []byte
}

type identityRowView struct {
	name []byte
	row  IdentityRow
}

type identityRowTraversal struct {
	reader    cryptoReader
	remaining uint32
}

func (v IdentityPlanView) forwardRows() identityRowTraversal {
	return identityRowTraversal{reader: newRecordReader(v.Rows), remaining: v.Descriptor.Count}
}

func (t *identityRowTraversal) next() (identityRowView, bool, error) {
	if t.remaining == 0 {
		return identityRowView{}, false, t.reader.end()
	}
	row := readIdentityRow(&t.reader)
	if t.reader.err != nil {
		return identityRowView{}, false, t.reader.failure()
	}
	t.remaining--
	return row, true, nil
}

func readIdentityRow(r *cryptoReader) identityRowView {
	return identityRowView{name: r.name(), row: IdentityRow{Slot: r.u16(), Incarnation: r.requiredID(), ValueState: r.requiredID(), OriginSnapshot: r.requiredID(), OriginTransition: r.requiredID()}}
}

func readIdentityPage(r *cryptoReader) IdentityPage {
	return IdentityPage{Kind: Kind(r.u8()), Index: r.u16(), Object: r.requiredID()}
}

func writeIdentityRow(w *cryptoWriter, v IdentityRow) {
	w.blob([]byte(v.Name))
	w.u16(v.Slot)
	w.id(v.Incarnation)
	w.id(v.ValueState)
	w.id(v.OriginSnapshot)
	w.id(v.OriginTransition)
}

func writeIdentityPage(w *cryptoWriter, v IdentityPage) {
	w.u8(uint8(v.Kind))
	w.u16(v.Index)
	w.id(v.Object)
}

func identityPageValid(v, previous IdentityPage, first bool) bool {
	return v.Index < childPageIndexCount(v.Kind) && !v.Object.IsZero() &&
		(first || previous.Kind < v.Kind || previous.Kind == v.Kind && previous.Index < v.Index)
}

func identityPlanSize(v IdentityPlan) (int, error) {
	if len(v.Rows) > CryptoMaxValueEntries || len(v.Pages) > MaxChildPages {
		return 0, ErrRecordCapacity
	}
	if !publicIDsValid(v.Operation, v.Transition, v.Snapshot, v.Revision) {
		return 0, ErrRecord
	}
	size := identityBaseLength + identityRowFixedLength*len(v.Rows) + identityPageLength*len(v.Pages)
	var slots [CryptoMaxValueEntries]bool
	for i, row := range v.Rows {
		if len(row.Name) > CryptoMaxName {
			return 0, ErrRecordCapacity
		}
		if !cryptoNamesValid(nil, []byte(row.Name), true) || (i > 0 && v.Rows[i-1].Name >= row.Name) ||
			row.Slot >= CryptoMaxValueEntries || slots[row.Slot] || !publicIDsValid(row.Incarnation, row.ValueState, row.OriginSnapshot, row.OriginTransition) {
			return 0, ErrRecord
		}
		slots[row.Slot] = true
		size += len(row.Name)
	}
	var previous IdentityPage
	for i, page := range v.Pages {
		if !identityPageValid(page, previous, i == 0) {
			return 0, ErrRecord
		}
		previous = page
	}
	return size, nil
}

func writeIdentityPlan(w *cryptoWriter, v IdentityPlan) {
	w.raw([]byte(cryptoIdentityPrefix))
	w.id(v.Operation)
	w.id(v.Transition)
	w.id(v.Snapshot)
	w.id(v.Revision)
	w.u32(uint32(len(v.Rows)))
	for _, row := range v.Rows {
		writeIdentityRow(w, row)
	}
	w.u32(uint32(len(v.Pages)))
	for _, page := range v.Pages {
		writeIdentityPage(w, page)
	}
}

func IdentityPlanDescriptor(v IdentityPlan) (DescriptorVector, error) {
	if _, err := identityPlanSize(v); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeIdentityPlan(&w, v)
	return w.result(len(v.Rows)), nil
}

func EncodeIdentityPlan(v IdentityPlan) ([]byte, error) {
	size, err := identityPlanSize(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, size)}
	writeIdentityPlan(&w, v)
	return w.b, nil
}

func AppendIdentityPlan(dst []byte, v IdentityPlan) ([]byte, error) {
	if _, err := identityPlanSize(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeIdentityPlan(&w, v)
	return w.b, nil
}

func ParseIdentityPlan(b []byte) (IdentityPlanView, int, error) {
	r := newRecordReader(b[:min(len(b), cryptoIdentityLimit)])
	if !bytes.Equal(r.take(len(cryptoIdentityPrefix)), []byte(cryptoIdentityPrefix)) {
		return IdentityPlanView{}, 0, ErrRecord
	}
	v := IdentityPlanView{Operation: r.requiredID(), Transition: r.requiredID(), Snapshot: r.requiredID(), Revision: r.requiredID()}
	n := r.count(CryptoMaxValueEntries, identityRowFixedLength)
	start := r.i
	var previousName []byte
	var slots [CryptoMaxValueEntries]bool
	for i := 0; i < n && r.err == nil; i++ {
		row := readIdentityRow(&r)
		if r.err != nil {
			break
		}
		if !cryptoNamesValid(previousName, row.name, i == 0) || row.row.Slot >= CryptoMaxValueEntries || slots[row.row.Slot] {
			return IdentityPlanView{}, 0, ErrRecord
		}
		previousName = row.name
		slots[row.row.Slot] = true
	}
	v.Rows = b[start:r.i:r.i]
	pages := r.count(MaxChildPages, identityPageLength)
	start = r.i
	var previousPage IdentityPage
	for i := 0; i < pages && r.err == nil; i++ {
		page := readIdentityPage(&r)
		if !identityPageValid(page, previousPage, i == 0) {
			return IdentityPlanView{}, 0, ErrRecord
		}
		previousPage = page
	}
	if r.err != nil {
		return IdentityPlanView{}, 0, r.failure()
	}
	v.Pages = b[start:r.i:r.i]
	v.PageCount = uint32(pages)
	v.encoded = b[:r.i:r.i]
	v.Descriptor = DescriptorVector{Digest: Hash(v.encoded), Length: uint64(r.i), Count: uint32(n)}
	return v, r.i, nil
}

func InspectIdentityPlan(b []byte) (IdentityPlanView, error) {
	if len(b) > cryptoIdentityLimit {
		return IdentityPlanView{}, ErrRecordCapacity
	}
	v, n, err := ParseIdentityPlan(b)
	if err != nil {
		return IdentityPlanView{}, err
	}
	if n != len(b) {
		return IdentityPlanView{}, ErrRecord
	}
	return v, nil
}

func ownIdentityPlan(v IdentityPlanView) IdentityPlan {
	out := IdentityPlan{Operation: v.Operation, Transition: v.Transition, Snapshot: v.Snapshot, Revision: v.Revision,
		Rows: make([]IdentityRow, v.Descriptor.Count), Pages: make([]IdentityPage, v.PageCount)}
	r := newRecordReader(v.Rows)
	for i := range out.Rows {
		row := readIdentityRow(&r)
		row.row.Name = string(row.name)
		out.Rows[i] = row.row
	}
	r = newRecordReader(v.Pages)
	for i := range out.Pages {
		out.Pages[i] = readIdentityPage(&r)
	}
	return out
}

func (v IdentityPlanView) checked() (IdentityPlanView, error) {
	if v.Descriptor.Count > CryptoMaxValueEntries || v.PageCount > MaxChildPages || v.Descriptor.Length > uint64(cryptoIdentityLimit) ||
		len(v.Rows) > cryptoIdentityLimit-identityBaseLength || len(v.Pages) > identityPageLength*MaxChildPages {
		return IdentityPlanView{}, ErrRecordCapacity
	}
	checked, err := InspectIdentityPlan(v.encoded)
	if err != nil {
		return IdentityPlanView{}, err
	}
	if v.Operation != checked.Operation || v.Transition != checked.Transition || v.Snapshot != checked.Snapshot || v.Revision != checked.Revision ||
		v.Descriptor != checked.Descriptor || v.PageCount != checked.PageCount || !bytes.Equal(v.Rows, checked.Rows) || !bytes.Equal(v.Pages, checked.Pages) {
		return IdentityPlanView{}, ErrRecord
	}
	return checked, nil
}

func (v IdentityPlanView) Own() (IdentityPlan, error) {
	checked, err := v.checked()
	if err != nil {
		return IdentityPlan{}, err
	}
	return ownIdentityPlan(checked), nil
}

func DecodeIdentityPlan(b []byte) (IdentityPlan, error) {
	v, err := InspectIdentityPlan(b)
	if err != nil {
		return IdentityPlan{}, err
	}
	return ownIdentityPlan(v), nil
}
