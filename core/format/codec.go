package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

var ErrFormat = errors.New("invalid canonical state encoding")

const (
	coreTag = 5
	planTag = 6
)

type writer struct {
	b   []byte
	err error
}

// Every HEAD uses the selected-grant revision, including genesis and successors
// with no grants. The published beta admits only revision 11.
const grantFormatVersion uint16 = 12

func startVersion(tag byte, version uint16) writer {
	return writer{b: []byte{'E', 'N', 'K', 'V', tag, byte(version >> 8), byte(version)}}
}
func start(tag byte) writer {
	if tag == byte(HeadKind) {
		return startVersion(tag, grantFormatVersion)
	}
	return startVersion(tag, Version)
}
func (w *writer) u8(n byte)     { w.b = append(w.b, n) }
func (w *writer) u16(n uint16)  { w.b = binary.BigEndian.AppendUint16(w.b, n) }
func (w *writer) u32(n uint32)  { w.b = binary.BigEndian.AppendUint32(w.b, n) }
func (w *writer) u64(n uint64)  { w.b = binary.BigEndian.AppendUint64(w.b, n) }
func (w *writer) id(n ID)       { w.b = append(w.b, n[:]...) }
func (w *writer) blob(b []byte) { w.u32(uint32(len(b))); w.b = append(w.b, b...) }
func (w *writer) token(t contract.Token) {
	if w.err == nil {
		w.b, w.err = contract.AppendToken(w.b, t)
	}
}
func (w *writer) ref(v Ref) {
	if w.err == nil {
		w.b, w.err = contract.AppendRef(w.b, v, Version)
	}
}
func (w *writer) result() ([]byte, error) {
	if w.err != nil {
		return nil, ErrFormat
	}
	return w.b, nil
}

type reader struct {
	b   []byte
	off int
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b)-r.off {
		r.bad = true
		return nil
	}
	b := r.b[r.off : r.off+n : r.off+n]
	r.off += n
	return b
}
func (r *reader) u8() byte {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *reader) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *reader) u64() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *reader) id() ID { var id ID; copy(id[:], r.take(32)); return id }
func (r *reader) blob(limit uint32) []byte {
	n := r.u32()
	if n > limit || uint64(n) > uint64(len(r.b)-r.off) {
		r.bad = true
		return nil
	}
	return r.take(int(n))
}
func (r *reader) token() contract.Token {
	v, n, err := contract.ParseToken(r.b[r.off:])
	if err != nil {
		r.bad = true
		return contract.Token{}
	}
	r.off += n
	return v
}
func (r *reader) ref() Ref {
	v, n, err := contract.ParseRef(r.b[r.off:], Version)
	if err != nil {
		r.bad = true
		return Ref{}
	}
	r.off += n
	return v
}
func (r *reader) end() bool      { return !r.bad && r.off == len(r.b) }
func (r *reader) remaining() int { return len(r.b) - r.off }
func (r *reader) badFormat()     { r.bad = true }
func begin(b []byte, tag byte, max int) *reader {
	r := &reader{b: b}
	if len(b) > max || !bytes.Equal(r.take(7), start(tag).b) {
		r.bad = true
	}
	return r
}

// Only grant-bearing roots and signed cores have a second layout.
func beginGrantFrame(b []byte, tag byte, max int) (*reader, bool) {
	if len(b) >= 7 && bytes.Equal(b[:7], startVersion(tag, grantFormatVersion).b) {
		return &reader{b: b, off: 7, bad: len(b) > max}, true
	}
	return begin(b, tag, max), false
}
func idsValid(ids ...ID) bool {
	for _, id := range ids {
		if id.IsZero() {
			return false
		}
	}
	return true
}
func nameValid(s string) bool { return len(s) <= contract.CryptoMaxName && utf8.ValidString(s) }
func valueEntryValid(m *ValueEntry) bool {
	if m == nil {
		return false
	}
	_, err := contract.ValueEntryLength(*m)
	return err == nil
}
func valueEntryPageValid(p ValueEntryPage) bool {
	if !idsValid(p.Domain, p.Object) || p.Index >= contract.MaxValueEntryPages {
		return false
	}
	var names [PageSlots]string
	var incarnations, states [PageSlots]ID
	count := 0
	for _, m := range p.Slots {
		if m == nil {
			continue
		}
		if !valueEntryValid(m) {
			return false
		}
		for i := 0; i < count; i++ {
			if names[i] == m.Name || incarnations[i] == m.Incarnation || states[i] == m.ValueState {
				return false
			}
		}
		names[count] = m.Name
		incarnations[count] = m.Incarnation
		states[count] = m.ValueState
		count++
	}
	return count > 0
}
func EncodeValueEntryPage(p ValueEntryPage) ([]byte, error) {
	if !valueEntryPageValid(p) {
		return nil, ErrFormat
	}
	var mask uint16
	length := contract.ValueEntryPageFixedLength
	for i, m := range p.Slots {
		if m != nil {
			mask |= 1 << i
			n, err := contract.ValueEntryLength(*m)
			if err != nil {
				return nil, ErrFormat
			}
			length += n
		}
	}
	if length > MaxValueEntryPage {
		return nil, ErrFormat
	}
	w := start(byte(ValueEntryPageKind))
	w.id(p.Domain)
	w.id(p.Object)
	w.u16(p.Index)
	w.u16(mask)
	for _, m := range p.Slots {
		if m != nil {
			var err error
			w.b, err = contract.AppendValueEntry(w.b, *m)
			if err != nil {
				return nil, ErrFormat
			}
		}
	}
	return w.result()
}
func DecodeValueEntryPage(b []byte) (ValueEntryPage, error) {
	r := begin(b, byte(ValueEntryPageKind), MaxValueEntryPage)
	p := ValueEntryPage{Domain: r.id(), Object: r.id(), Index: r.u16()}
	mask := r.u16()
	var views [PageSlots]contract.ValueEntryView
	if r.bad || mask == 0 || !idsValid(p.Domain, p.Object) || p.Index >= contract.MaxValueEntryPages {
		return ValueEntryPage{}, ErrFormat
	}
	for i := range views {
		if mask&(1<<i) == 0 {
			continue
		}
		v, n, err := contract.ParseValueEntry(r.b[r.off:])
		if err != nil {
			return ValueEntryPage{}, ErrFormat
		}
		r.off += n
		views[i] = v
		for j := 0; j < i; j++ {
			if mask&(1<<j) != 0 && (bytes.Equal(views[j].Name, v.Name) || views[j].Incarnation == v.Incarnation || views[j].ValueState == v.ValueState) {
				return ValueEntryPage{}, ErrFormat
			}
		}
	}
	if !r.end() {
		return ValueEntryPage{}, ErrFormat
	}
	for i, v := range views {
		if mask&(1<<i) != 0 {
			owned, err := v.Own()
			if err != nil {
				return ValueEntryPage{}, ErrFormat
			}
			p.Slots[i] = &owned
		}
	}
	return p, nil
}
func EncodeRecipientPage(p RecipientPage) ([]byte, error) {
	if !idsValid(p.Domain, p.Object) || p.Index >= contract.MaxRecipientPages {
		return nil, ErrFormat
	}
	var mask uint8
	length := contract.RecipientPageHeaderLength
	var previous ID
	for i, row := range p.Slots {
		if row == nil {
			continue
		}
		n, err := contract.RecipientRecordLength(*row)
		if err != nil || mask != 0 && bytes.Compare(previous[:], row.RecipientID[:]) >= 0 {
			return nil, ErrFormat
		}
		previous = row.RecipientID
		mask |= 1 << i
		length += n
	}
	if mask == 0 || length > MaxRecipientPage {
		return nil, ErrFormat
	}
	w := start(byte(RecipientKind))
	w.id(p.Domain)
	w.id(p.Object)
	w.u16(p.Index)
	w.u8(mask)
	for _, row := range p.Slots {
		if row != nil {
			var err error
			w.b, err = contract.AppendRecipientRecord(w.b, *row)
			if err != nil {
				return nil, ErrFormat
			}
		}
	}
	return w.result()
}
func DecodeRecipientPage(b []byte) (RecipientPage, error) {
	r := begin(b, byte(RecipientKind), MaxRecipientPage)
	p := RecipientPage{Domain: r.id(), Object: r.id(), Index: r.u16()}
	mask := r.u8()
	if r.bad || mask == 0 || !idsValid(p.Domain, p.Object) || p.Index >= contract.MaxRecipientPages {
		return RecipientPage{}, ErrFormat
	}
	var views [RecipientSlots]contract.RecipientRecordView
	var previous ID
	first := true
	for i := range views {
		if mask&(1<<i) == 0 {
			continue
		}
		v, n, err := contract.ParseRecipientRecord(r.b[r.off:])
		if err != nil || !first && bytes.Compare(previous[:], v.RecipientID[:]) >= 0 {
			return RecipientPage{}, ErrFormat
		}
		r.off += n
		views[i] = v
		previous = v.RecipientID
		first = false
	}
	if !r.end() {
		return RecipientPage{}, ErrFormat
	}
	for i, v := range views {
		if mask&(1<<i) != 0 {
			owned, err := v.Own()
			if err != nil {
				return RecipientPage{}, ErrFormat
			}
			p.Slots[i] = &owned
		}
	}
	return p, nil
}
func EncodeAccessPage(p AccessPage) ([]byte, error) {
	if !idsValid(p.Domain, p.Object) || p.Index >= contract.MaxChildPages || len(p.Records) == 0 || len(p.Records) > contract.AccessPageRecordLimit {
		return nil, ErrFormat
	}
	length := contract.AccessPageHeaderLength
	for i, row := range p.Records {
		n, err := contract.AccessRecordLength(row)
		if err != nil || i > 0 && !contract.AccessRecordBefore(p.Records[i-1], row) {
			return nil, ErrFormat
		}
		length += n
	}
	if length > contract.MaxAccessPageLength {
		return nil, ErrFormat
	}
	w := start(byte(AccessKind))
	w.id(p.Domain)
	w.id(p.Object)
	w.u16(p.Index)
	w.u16(uint16(len(p.Records)))
	header := w.b
	w.b = make([]byte, len(header), length)
	copy(w.b, header)
	for _, row := range p.Records {
		var err error
		w.b, err = contract.AppendAccessRecord(w.b, row)
		if err != nil {
			return nil, ErrFormat
		}
	}
	return w.result()
}
func DecodeAccessPage(b []byte) (AccessPage, error) {
	r := begin(b, byte(AccessKind), contract.MaxAccessPageLength)
	p := AccessPage{Domain: r.id(), Object: r.id(), Index: r.u16()}
	count := int(r.u16())
	if r.bad || !idsValid(p.Domain, p.Object) || p.Index >= contract.MaxChildPages || count < 1 || count > contract.AccessPageRecordLimit {
		return AccessPage{}, ErrFormat
	}
	var views [contract.AccessPageRecordLimit]contract.AccessRecordView
	for i := 0; i < count; i++ {
		v, n, err := contract.ParseAccessRecord(r.b[r.off:])
		if err != nil || i > 0 && (views[i-1].MaterialKind > v.MaterialKind || views[i-1].MaterialKind == v.MaterialKind && bytes.Compare(views[i-1].MaterialID[:], v.MaterialID[:]) >= 0) {
			return AccessPage{}, ErrFormat
		}
		r.off += n
		views[i] = v
	}
	if !r.end() {
		return AccessPage{}, ErrFormat
	}
	p.Records = make([]contract.AccessRecord, count)
	for i := range p.Records {
		v, err := views[i].Own()
		if err != nil {
			return AccessPage{}, ErrFormat
		}
		p.Records[i] = v
	}
	return p, nil
}
func maxForKind(k Kind) uint32 {
	switch k {
	case ValueEntryPageKind:
		return MaxValueEntryPage
	case RecipientKind:
		return MaxRecipientPage
	case RootKind:
		return MaxRoot
	case AccessKind:
		return contract.MaxAccessPageLength
	case contract.RequiredSupportKind:
		return MaxRequiredSupportPage
	case contract.AdministrativeIndexKind:
		return MaxRequiredSupportPage
	}
	return 0
}
func refValid(r Ref) bool { return maxForKind(r.Kind) != 0 && r.ValidFor(Version) }
func CheckChildCount(n uint32) error {
	if n > contract.MaxChildPages {
		return ErrFormat
	}
	return nil
}
func rootValid(p Root) bool {
	if !generatedRootValid(p) || !p.GCPlans.ValidOwners() || !p.ActiveGC.IsZero() && (!p.Generated.ActiveOwner.IsZero() || p.GCPlans.Count == 0) {
		return false
	}
	if _, err := contract.EncodeOutputConfigurationDescriptor(p.OutputConfiguration); err != nil ||
		len(p.RequiredSupport) == 0 || p.RequiredSupportRecordCount < uint32(p.OutputConfiguration.SliceCount) {
		return false
	}
	if !idsValid(p.Domain, p.Snapshot, p.Transition) || p.Unsupported != 0 || p.ValueEntryCount > contract.CryptoMaxValueEntries || p.SecretCount > p.ValueEntryCount || p.RawBytes > contract.CryptoMaxRawSet || p.RawBytes > uint64(p.ValueEntryCount)*contract.CryptoMaxRawValue || len(p.Names) != int(p.ValueEntryCount) || p.ChildCount > contract.MaxChildPages || p.MembershipCount < p.ValueEntryCount || p.MembershipCount > contract.CryptoMaxMemberships || p.MembershipCount > contract.CryptoMaxValueEntryRecipients*p.ValueEntryCount || p.RecipientCount < 1 || p.RecipientCount > contract.CryptoMaxRecipients || p.AccessRecordCount < p.SecretCount || p.AccessRecordCount > contract.MaxChildPages*contract.AccessPageRecordLimit || p.SecretOrdinaryWrapCount < p.SecretCount || p.SecretOrdinaryWrapCount > contract.CryptoMaxValueEntryRecipients*p.SecretCount || p.SecretOrdinaryWrapCount > contract.CryptoMaxMemberships || len(p.RequiredSupport) > contract.MaxChildPages || p.RequiredSupportRecordCount < uint32(len(p.RequiredSupport)) || uint64(p.RequiredSupportRecordCount) > uint64(len(p.RequiredSupport))*(contract.MaxRequiredSupportPageLength-contract.RequiredSupportPageHeaderLength)/contract.SupportRecordMinLength {
		return false
	}
	if p.CurrentAccess.Core.Recovery != nil && len(p.RequiredSupport) == 0 && p.ChildCount == contract.MaxChildPages {
		return false
	}
	var objects [contract.MaxChildPages]ID
	var count uint32
	var size uint64
	var recipients []Ref
	add := func(ref Ref) bool {
		if !refValid(ref) || ref.Domain != p.Domain || ref.Object == p.Snapshot || count >= contract.MaxChildPages {
			return false
		}
		for _, id := range objects[:count] {
			if id == ref.Object {
				return false
			}
		}
		objects[count] = ref.Object
		count++
		size += uint64(ref.Length)
		return true
	}
	for _, table := range []struct {
		refs []*Ref
		kind Kind
	}{{p.ValueEntryPages[:], ValueEntryPageKind}, {p.Recipients[:], RecipientKind}} {
		for i, ref := range table.refs {
			if ref == nil {
				continue
			}
			if ref.Kind != table.kind || ref.Index != uint16(i) || !add(*ref) {
				return false
			}
			if table.kind == RecipientKind {
				recipients = append(recipients, *ref)
			}
		}
	}
	for _, ref := range p.CurrentAccess.Core.AccessPageRefs {
		if ref.Kind != AccessKind || !add(ref) {
			return false
		}
	}
	if p.AdministrativeIndex.Kind != contract.AdministrativeIndexKind || p.AdministrativeIndex.Index != 0 ||
		len(p.AdministrativeIndexShards) >= contract.MaxChildPages || !add(p.AdministrativeIndex) || p.WarningBits & ^uint8(0x1f) != 0 {
		return false
	}
	for i, ref := range p.AdministrativeIndexShards {
		if ref.Kind != contract.AdministrativeIndexKind || ref.Index != uint16(i+1) || !add(ref) {
			return false
		}
	}
	for i, ref := range p.RequiredSupport {
		if ref.Kind != contract.RequiredSupportKind || ref.Length < contract.RequiredSupportPageHeaderLength+contract.SupportRecordMinLength || ref.Length > MaxRequiredSupportPage || i > 0 && p.RequiredSupport[i-1].Index >= ref.Index || !add(ref) {
			return false
		}
	}
	if len(recipients) == 0 || count != p.ChildCount || size != p.ChildEncodedBytes || p.CurrentAccess.Core.DomainID != p.Domain || p.CurrentAccess.Core.AccessRecordsDescriptor.Count != p.AccessRecordCount {
		return false
	}
	if len(p.GrantPages) > MaxGrantPages {
		return false
	}
	lastPage := -1
	for _, ref := range p.GrantPages {
		if !refValid(ref) || ref.Kind != AccessKind || ref.Domain != p.Domain || int(ref.Index) <= lastPage || ref.Object == p.Snapshot {
			return false
		}
		logical, ok := slices.BinarySearchFunc(p.CurrentAccess.Core.AccessPageRefs, ref.Index, func(r Ref, index uint16) int {
			return int(r.Index) - int(index)
		})
		if !ok || ref.Object != grantBaseObject(p.Domain, p.CurrentAccess.Core.AccessPageRefs[logical].Object) ||
			slices.Contains(objects[:count], ref.Object) || ref.Length != p.CurrentAccess.Core.AccessPageRefs[logical].Length {
			return false
		}
		lastPage = int(ref.Index)
	}
	rd, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: p.Domain, Refs: recipients})
	if err != nil || rd != p.CurrentAccess.Core.RecipientRefsDescriptor {
		return false
	}
	if _, err := contract.CurrentAccessSectionLength(p.CurrentAccess); err != nil {
		return false
	}
	var slots [contract.CryptoMaxValueEntries]bool
	var pages [contract.MaxValueEntryPages]bool
	for i, row := range p.Names {
		if !nameValid(row.Name) || row.Slot >= contract.CryptoMaxValueEntries || slots[row.Slot] || p.ValueEntryPages[row.Slot/PageSlots] == nil || i > 0 && p.Names[i-1].Name >= row.Name {
			return false
		}
		slots[row.Slot] = true
		pages[row.Slot/PageSlots] = true
	}
	for i, ref := range p.ValueEntryPages {
		if (ref != nil) != pages[i] {
			return false
		}
	}
	return true
}
func EncodeRoot(p Root) ([]byte, error) {
	if !rootValid(p) {
		return nil, ErrFormat
	}
	w := start(byte(RootKind))
	if len(p.GrantPages) != 0 {
		w = startVersion(byte(RootKind), grantFormatVersion)
	}
	w.id(p.Domain)
	w.id(p.Snapshot)
	w.id(p.Transition)
	for _, table := range [][]*Ref{p.ValueEntryPages[:], p.Recipients[:]} {
		for _, ref := range table {
			if ref == nil {
				w.u8(0)
			} else {
				w.u8(1)
				w.ref(*ref)
			}
		}
	}
	var err error
	w.b, err = contract.AppendCurrentAccessSection(w.b, p.CurrentAccess)
	if err != nil {
		return nil, ErrFormat
	}
	w.ref(p.AdministrativeIndex)
	w.u16(uint16(len(p.AdministrativeIndexShards)))
	for _, ref := range p.AdministrativeIndexShards {
		w.ref(ref)
	}
	w.u8(p.WarningBits)
	w.u16(uint16(len(p.RequiredSupport)))
	for _, ref := range p.RequiredSupport {
		w.ref(ref)
	}
	descriptor, err := contract.EncodeOutputConfigurationDescriptor(p.OutputConfiguration)
	if err != nil {
		return nil, ErrFormat
	}
	w.b = append(w.b, descriptor...)
	w.u32(uint32(len(p.Names)))
	for _, row := range p.Names {
		w.blob([]byte(row.Name))
		w.u16(row.Slot)
	}
	w.u32(p.ValueEntryCount)
	w.u32(p.SecretCount)
	w.u64(p.RawBytes)
	w.u32(p.MembershipCount)
	w.u32(p.SecretOrdinaryWrapCount)
	w.u16(p.RecipientCount)
	w.u32(p.AccessRecordCount)
	w.u32(p.RequiredSupportRecordCount)
	w.u16(uint16(p.ChildCount))
	w.u64(p.ChildEncodedBytes)
	w.u32(p.Unsupported)
	if err := writeGeneratedClosure(&w, p.Generated); err != nil {
		return nil, err
	}
	w.id(p.ActiveGC)
	w.b, err = contract.AppendGCDescriptor(w.b, p.GCPlans)
	if err != nil {
		return nil, ErrFormat
	}
	if len(p.GrantPages) != 0 {
		w.u16(uint16(len(p.GrantPages)))
		for _, ref := range p.GrantPages {
			w.ref(ref)
		}
	}
	if len(w.b) > MaxRoot {
		return nil, ErrFormat
	}
	return w.result()
}
func DecodeRoot(b []byte) (Root, error) {
	r, grants := beginGrantFrame(b, byte(RootKind), MaxRoot)
	p := Root{Domain: r.id(), Snapshot: r.id(), Transition: r.id()}
	for _, table := range [][]*Ref{p.ValueEntryPages[:], p.Recipients[:]} {
		for i := range table {
			switch r.u8() {
			case 0:
			case 1:
				ref := r.ref()
				table[i] = &ref
			default:
				r.bad = true
			}
		}
	}
	if r.bad {
		return Root{}, ErrFormat
	}
	view, n, err := contract.ParseCurrentAccessSection(r.b[r.off:])
	if err != nil {
		return Root{}, ErrFormat
	}
	r.off += n
	p.AdministrativeIndex = r.ref()
	shards := int(r.u16())
	if shards >= contract.MaxChildPages {
		return Root{}, ErrFormat
	}
	p.AdministrativeIndexShards = make([]Ref, shards)
	for i := range p.AdministrativeIndexShards {
		p.AdministrativeIndexShards[i] = r.ref()
	}
	p.WarningBits = r.u8()
	supportCount := r.u16()
	if supportCount > contract.MaxChildPages {
		return Root{}, ErrFormat
	}
	if supportCount != 0 {
		p.RequiredSupport = make([]Ref, supportCount)
		for i := range p.RequiredSupport {
			p.RequiredSupport[i] = r.ref()
		}
	}
	p.OutputConfiguration, err = contract.InspectOutputConfigurationDescriptor(r.take(46))
	if err != nil {
		return Root{}, ErrFormat
	}
	count := int(r.u32())
	if count > contract.CryptoMaxValueEntries || count > (len(r.b)-r.off)/6 {
		return Root{}, ErrFormat
	}
	var names [contract.CryptoMaxValueEntries][]byte
	var slots [contract.CryptoMaxValueEntries]uint16
	for i := 0; i < count; i++ {
		names[i] = r.blob(contract.CryptoMaxName)
		slots[i] = r.u16()
		if !utf8.Valid(names[i]) || i > 0 && bytes.Compare(names[i-1], names[i]) >= 0 {
			return Root{}, ErrFormat
		}
	}
	p.ValueEntryCount = r.u32()
	p.SecretCount = r.u32()
	p.RawBytes = r.u64()
	p.MembershipCount = r.u32()
	p.SecretOrdinaryWrapCount = r.u32()
	p.RecipientCount = r.u16()
	p.AccessRecordCount = r.u32()
	p.RequiredSupportRecordCount = r.u32()
	p.ChildCount = uint32(r.u16())
	p.ChildEncodedBytes = r.u64()
	p.Unsupported = r.u32()
	p.Generated = readGeneratedClosure(r)
	p.ActiveGC = r.id()
	p.GCPlans, err = contract.DecodeGCDescriptor(r.take(44))
	if err != nil {
		return Root{}, ErrFormat
	}
	if grants {
		n := int(r.u16())
		if n == 0 || n > MaxGrantPages || r.remaining() != n*contract.RefLength {
			return Root{}, ErrFormat
		}
		p.GrantPages = make([]Ref, n)
		for i := range p.GrantPages {
			p.GrantPages[i] = r.ref()
		}
	}
	if !r.end() {
		return Root{}, ErrFormat
	}
	p.CurrentAccess, err = view.Own()
	if err != nil {
		return Root{}, ErrFormat
	}
	p.Names = make([]NameEntry, count)
	for i := range p.Names {
		p.Names[i] = NameEntry{Name: string(names[i]), Slot: slots[i]}
	}
	if !rootValid(p) {
		return Root{}, ErrFormat
	}
	return p, nil
}
func headCoreFieldsValid(p HeadCore) bool {
	if !idsValid(p.Domain, p.Revision, p.Store, p.Trust, p.Coordinate, p.NonBody, p.Interpretation) || p.Epoch == 0 || p.Unsupported != 0 || p.Root.Kind != RootKind || p.Root.Domain != p.Domain {
		return false
	}
	switch p.Form {
	case SuccessorHead:
		return idsValid(p.PreviousRevision, p.PreviousDigest) && p.PreviousToken.Valid()
	case GenesisHead:
		return p.Epoch == 1 && p.PreviousRevision.IsZero() && p.PreviousDigest.IsZero() && p.PreviousToken == (contract.Token{}) && p.GrantDigest.IsZero()
	default:
		return false
	}
}
func headCoreValid(p HeadCore) bool { return headCoreFieldsValid(p) && refValid(p.Root) }
func EncodeHeadCore(p HeadCore) ([]byte, error) {
	if !headCoreValid(p) {
		return nil, ErrFormat
	}
	root, err := contract.AppendRef(nil, p.Root, Version)
	if err != nil {
		return nil, ErrFormat
	}
	return encodeHeadCoreFields(p, root)
}

// root is already encoded by the owning actual or typed digest-plan writer.
func encodeHeadCoreFields(p HeadCore, root []byte) ([]byte, error) {
	w := start(coreTag)
	if !p.GrantDigest.IsZero() {
		w = startVersion(coreTag, grantFormatVersion)
	}
	w.u8(p.Form)
	w.id(p.Domain)
	w.id(p.Revision)
	if p.Form == SuccessorHead {
		w.id(p.PreviousRevision)
		w.id(p.PreviousDigest)
		w.token(p.PreviousToken)
	}
	w.b = append(w.b, root...)
	w.id(p.Store)
	w.id(p.Trust)
	w.id(p.Coordinate)
	w.id(p.NonBody)
	w.id(p.Interpretation)
	w.u64(p.Epoch)
	w.u32(p.Unsupported)
	if !p.GrantDigest.IsZero() {
		w.id(p.GrantDigest)
	}
	return w.result()
}
func DecodeHeadCore(b []byte) (HeadCore, error) {
	r, grants := beginGrantFrame(b, coreTag, contract.GrantHeadCoreMaxLength)
	p := HeadCore{Form: r.u8(), Domain: r.id(), Revision: r.id()}
	switch p.Form {
	case SuccessorHead:
		p.PreviousRevision = r.id()
		p.PreviousDigest = r.id()
		p.PreviousToken = r.token()
	case GenesisHead:
	default:
		return HeadCore{}, ErrFormat
	}
	p.Root = r.ref()
	p.Store = r.id()
	p.Trust = r.id()
	p.Coordinate = r.id()
	p.NonBody = r.id()
	p.Interpretation = r.id()
	p.Epoch = r.u64()
	p.Unsupported = r.u32()
	if grants {
		p.GrantDigest = r.id()
		if p.GrantDigest.IsZero() {
			return HeadCore{}, ErrFormat
		}
	}
	if !r.end() || !headCoreValid(p) {
		return HeadCore{}, ErrFormat
	}
	return p, nil
}
func conditionalPlanFieldsValid(p ConditionalPlan) bool {
	if !p.Family.Valid() || !idsValid(p.Store, p.Coordinate, p.NonBody) {
		return false
	}
	if p.Condition.IsAbsent() {
		return p.HeadCoreLength == 349
	}
	token, ok := p.Condition.Token()
	return ok && token.Family == p.Family && (p.HeadCoreLength >= contract.SuccessorHeadCoreMinLength && p.HeadCoreLength <= contract.SuccessorHeadCoreMaxLength ||
		p.HeadCoreLength == uint32(contract.SuccessorHeadCoreMinLength-1+len(token.Value)+len(ID{})))
}
func conditionalPlanValid(p ConditionalPlan) bool {
	return !p.HeadCore.IsZero() && conditionalPlanFieldsValid(p)
}
func EncodeConditionalPlan(p ConditionalPlan) ([]byte, error) {
	if !conditionalPlanValid(p) {
		return nil, ErrFormat
	}
	return encodeConditionalPlanFields(p)
}
func encodeConditionalPlanFields(p ConditionalPlan) ([]byte, error) {
	w := start(planTag)
	w.u8(byte(p.Family))
	method := "PUT"
	if p.Family == contract.GCP {
		method = "POST"
	}
	w.blob([]byte(method))
	w.id(p.Store)
	w.id(p.Coordinate)
	w.id(p.NonBody)
	var err error
	w.b, err = contract.AppendHeadCondition(w.b, p.Condition)
	if err != nil {
		return nil, ErrFormat
	}
	w.id(p.HeadCore)
	w.u32(p.HeadCoreLength)
	return w.result()
}
func DecodeConditionalPlan(b []byte) (ConditionalPlan, error) {
	r := begin(b, planTag, 410)
	p := ConditionalPlan{Family: contract.Family(r.u8())}
	method := r.blob(4)
	want := "PUT"
	if p.Family == contract.GCP {
		want = "POST"
	}
	if !bytes.Equal(method, []byte(want)) {
		return ConditionalPlan{}, ErrFormat
	}
	p.Store = r.id()
	p.Coordinate = r.id()
	p.NonBody = r.id()
	if r.bad {
		return ConditionalPlan{}, ErrFormat
	}
	condition, n, err := contract.ParseHeadCondition(r.b[r.off:])
	if err != nil {
		return ConditionalPlan{}, ErrFormat
	}
	r.off += n
	p.Condition = condition
	p.HeadCore = r.id()
	p.HeadCoreLength = r.u32()
	if !r.end() || !conditionalPlanValid(p) {
		return ConditionalPlan{}, ErrFormat
	}
	return p, nil
}
func DecodeLifecycleSubject(b []byte) (contract.LifecycleSubject, error) {
	v, err := contract.DecodeLifecycleSubject(b)
	if err != nil {
		return contract.LifecycleSubject{}, ErrFormat
	}
	return v, nil
}
func signatureValid(b []byte) bool { return contract.P256SignatureEncodingValid(b) }

func Reference(kind Kind, domain, object ID, index uint16, body []byte) (Ref, error) {
	if uint64(len(body)) > uint64(maxForKind(kind)) {
		return Ref{}, ErrFormat
	}
	r := Ref{Kind: kind, Domain: domain, Object: object, Digest: contract.Hash(body), Format: Version, Length: uint32(len(body)), Index: index}
	if err := CheckReference(r, body); err != nil {
		return Ref{}, err
	}
	return r, nil
}
func CheckReference(ref Ref, body []byte) error {
	if !refValid(ref) || uint64(len(body)) != uint64(ref.Length) || contract.Hash(body) != ref.Digest {
		return ErrFormat
	}
	var domain, object ID
	var index uint16
	var err error
	switch ref.Kind {
	case ValueEntryPageKind:
		var p ValueEntryPage
		p, err = DecodeValueEntryPage(body)
		domain, object, index = p.Domain, p.Object, p.Index
	case RecipientKind:
		var p RecipientPage
		p, err = DecodeRecipientPage(body)
		domain, object, index = p.Domain, p.Object, p.Index
	case RootKind:
		var p Root
		p, err = DecodeRoot(body)
		domain, object = p.Domain, p.Snapshot
	case AccessKind:
		var p AccessPage
		p, err = DecodeAccessPage(body)
		domain, object, index = p.Domain, p.Object, p.Index
	case contract.RequiredSupportKind:
		var p RequiredSupportPageView
		p, err = InspectRequiredSupportPage(body)
		domain, object, index = p.Domain, p.Object, p.Index
	case contract.AdministrativeIndexKind:
		var p administrativeShard
		p, err = decodeAdministrativeShard(body)
		domain, object, index = p.Domain, p.Object, p.Index
	default:
		return ErrFormat
	}
	if err != nil || domain != ref.Domain || object != ref.Object || index != ref.Index {
		return ErrFormat
	}
	return nil
}
func Key(prefix string, ref Ref) (string, error) {
	if !refValid(ref) {
		return "", ErrFormat
	}
	key, err := contract.StoreObjectKey(prefix, ref.Domain, contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: ref.Kind, Index: ref.Index, ObjectID: ref.Object})
	if err != nil {
		return "", ErrFormat
	}
	return key, nil
}

func GeneratedResultKey(prefix string, domain, coordinate ID) (string, error) {
	key, err := contract.StoreObjectKey(prefix, domain, contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: coordinate})
	if err != nil {
		return "", ErrFormat
	}
	return key, nil
}
