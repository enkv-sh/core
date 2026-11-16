package contract

import "bytes"

const (
	recipientRefsPrefix       = cryptoPurposePrefix + "recipient-refs\x00"
	recipientRefsFixedLength  = len(recipientRefsPrefix) + 32 + 2
	recipientRefsMaxLength    = recipientRefsFixedLength + MaxRecipientPages*RefLength
	RecipientPageHeaderLength = 74
	recipientPageMinLength    = RecipientPageHeaderLength + recipientRecordFixedLength
	recipientPageMaxLength    = RecipientPageHeaderLength + 8*RecipientRecordMaxLength
)

type pageRefs struct {
	values []Ref
	span   []byte
}

func (v pageRefs) count() int {
	if v.span != nil {
		return len(v.span) / RefLength
	}
	return len(v.values)
}

func (v pageRefs) walk(visit func(int, Ref) error) error {
	if v.span == nil {
		for i, row := range v.values {
			if err := visit(i, row); err != nil {
				return err
			}
		}
		return nil
	}
	r := newRecordReader(v.span)
	for i := 0; r.i < len(v.span); i++ {
		row := readRef(&r, CanonicalSchema)
		if r.err != nil {
			return r.failure()
		}
		if err := visit(i, row); err != nil {
			return err
		}
	}
	return r.end()
}

func (v pageRefs) shapeError(kind Kind, domain ID, maximum int) error {
	if len(v.values) > maximum || len(v.span) > maximum*RefLength {
		return ErrRecordCapacity
	}
	if domain.IsZero() || v.values != nil && v.span != nil || len(v.span)%RefLength != 0 {
		return ErrRecord
	}
	var objects [MaxChildPages]ID
	var previous uint16
	return v.walk(func(i int, row Ref) error {
		if !row.ValidFor(CanonicalSchema) || row.Kind != kind || row.Domain != domain || i > 0 && row.Index <= previous {
			return ErrRecord
		}
		for j := 0; j < i; j++ {
			if objects[j] == row.Object {
				return ErrRecord
			}
		}
		objects[i], previous = row.Object, row.Index
		return nil
	})
}

func (v pageRefs) write(w *cryptoWriter) error {
	return v.walk(func(_ int, row Ref) error { writeRef(w, row); return nil })
}

func (v pageRefs) own() ([]Ref, error) {
	out := make([]Ref, v.count())
	if err := v.walk(func(i int, row Ref) error { out[i] = row; return nil }); err != nil {
		return nil, err
	}
	return out, nil
}

func pageRefAt(span []byte, index int) (Ref, bool) {
	if index < 0 || index >= len(span)/RefLength {
		return Ref{}, false
	}
	v, err := DecodeRef(span[index*RefLength:(index+1)*RefLength], CanonicalSchema)
	return v, err == nil
}

type RecipientRefsProjection struct {
	DomainID ID
	Refs     []Ref
}

// RecipientRefsProjectionView borrows complete Ref rows. Its descriptor binds
// this projection; it does not authenticate the referenced recipient pages.
type RecipientRefsProjectionView struct {
	DomainID   ID
	Refs       []byte
	Descriptor DescriptorVector
}

func (v RecipientRefsProjectionView) RefCount() int             { return len(v.Refs) / RefLength }
func (v RecipientRefsProjectionView) Ref(index int) (Ref, bool) { return pageRefAt(v.Refs, index) }

func recipientRefsShapeError(domain ID, refs pageRefs) error {
	if err := refs.shapeError(RecipientKind, domain, MaxRecipientPages); err != nil {
		return err
	}
	return refs.walk(func(_ int, row Ref) error {
		// A nonempty page has its 74-byte header and one through eight rows.
		// Full page contents and the current authority row remain owner checks.
		if row.Length < recipientPageMinLength || row.Length > recipientPageMaxLength {
			return ErrRecord
		}
		return nil
	})
}

func RecipientRefsProjectionLength(v RecipientRefsProjection) (int, error) {
	if err := recipientRefsShapeError(v.DomainID, pageRefs{values: v.Refs}); err != nil {
		return 0, err
	}
	return recipientRefsFixedLength + len(v.Refs)*RefLength, nil
}
func writeRecipientRefsProjection(w *cryptoWriter, domain ID, refs pageRefs) error {
	w.raw([]byte(recipientRefsPrefix))
	w.id(domain)
	w.u16(uint16(refs.count()))
	return refs.write(w)
}
func recipientRefsDescriptor(domain ID, refs pageRefs) (DescriptorVector, error) {
	w := cryptoHashWriter("")
	if err := writeRecipientRefsProjection(&w, domain, refs); err != nil {
		return DescriptorVector{}, err
	}
	return w.result(refs.count()), nil
}
func RecipientRefsDescriptor(v RecipientRefsProjection) (DescriptorVector, error) {
	if _, err := RecipientRefsProjectionLength(v); err != nil {
		return DescriptorVector{}, err
	}
	return recipientRefsDescriptor(v.DomainID, pageRefs{values: v.Refs})
}
func AppendRecipientRefsProjection(dst []byte, v RecipientRefsProjection) ([]byte, error) {
	if _, err := RecipientRefsProjectionLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	if err := writeRecipientRefsProjection(&w, v.DomainID, pageRefs{values: v.Refs}); err != nil {
		return nil, err
	}
	return w.b, nil
}
func EncodeRecipientRefsProjection(v RecipientRefsProjection) ([]byte, error) {
	n, err := RecipientRefsProjectionLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	if err := writeRecipientRefsProjection(&w, v.DomainID, pageRefs{values: v.Refs}); err != nil {
		return nil, err
	}
	return w.b, nil
}
func ParseRecipientRefsProjection(b []byte) (RecipientRefsProjectionView, int, error) {
	r := newRecordReader(b[:min(len(b), recipientRefsMaxLength)])
	if !bytes.Equal(r.take(len(recipientRefsPrefix)), []byte(recipientRefsPrefix)) {
		return RecipientRefsProjectionView{}, 0, ErrRecord
	}
	v := RecipientRefsProjectionView{DomainID: r.requiredID()}
	n := int(r.u16())
	if r.err != nil {
		return RecipientRefsProjectionView{}, 0, r.failure()
	}
	if n > MaxRecipientPages {
		return RecipientRefsProjectionView{}, 0, ErrRecordCapacity
	}
	v.Refs = r.take(n * RefLength)
	if r.err != nil {
		return RecipientRefsProjectionView{}, 0, r.failure()
	}
	if err := recipientRefsShapeError(v.DomainID, pageRefs{span: v.Refs}); err != nil {
		return RecipientRefsProjectionView{}, 0, err
	}
	v.Descriptor = DescriptorVector{Digest: Hash(b[:r.i]), Length: uint64(r.i), Count: uint32(n)}
	return v, r.i, nil
}
func InspectRecipientRefsProjection(b []byte) (RecipientRefsProjectionView, error) {
	if len(b) > recipientRefsMaxLength {
		return RecipientRefsProjectionView{}, ErrRecordCapacity
	}
	v, n, err := ParseRecipientRefsProjection(b)
	if err != nil {
		return RecipientRefsProjectionView{}, err
	}
	if n != len(b) {
		return RecipientRefsProjectionView{}, ErrRecord
	}
	return v, nil
}
func (v RecipientRefsProjectionView) Own() (RecipientRefsProjection, error) {
	refs := pageRefs{span: v.Refs}
	if err := recipientRefsShapeError(v.DomainID, refs); err != nil {
		return RecipientRefsProjection{}, err
	}
	d, err := recipientRefsDescriptor(v.DomainID, refs)
	if err != nil {
		return RecipientRefsProjection{}, err
	}
	if v.Descriptor != d {
		return RecipientRefsProjection{}, ErrRecord
	}
	rows, err := refs.own()
	if err != nil {
		return RecipientRefsProjection{}, err
	}
	return RecipientRefsProjection{DomainID: v.DomainID, Refs: rows}, nil
}
func DecodeRecipientRefsProjection(b []byte) (RecipientRefsProjection, error) {
	v, err := InspectRecipientRefsProjection(b)
	if err != nil {
		return RecipientRefsProjection{}, err
	}
	rows, err := (pageRefs{span: v.Refs}).own()
	if err != nil {
		return RecipientRefsProjection{}, err
	}
	return RecipientRefsProjection{DomainID: v.DomainID, Refs: rows}, nil
}
