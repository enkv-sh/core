package contract

import "errors"

const MaxHeadLength = 64 << 10

const (
	MaxValueEntryPages              = 32
	ValueEntryPageFixedLength       = 75
	RequiredSupportPageHeaderLength = 75
)

const (
	RefLength                           = 105
	MaxChildPages                       = 256
	MaxRecipientPages                   = 32
	MaxValueEntryPageLength             = 2 << 20
	MaxRecipientPageLength              = 96 << 10
	MaxRootLength                       = 256 << 10
	MaxAccessPageLength                 = 2 << 20
	AccessPageRecordLimit               = (MaxAccessPageLength - AccessPageHeaderLength) / (AccessRecordFixedLength + WrapRowWireLength)
	MaxRequiredSupportPageLength        = 2 << 20
	CanonicalSchema              uint16 = 11
)

var (
	ErrRecord         = errors.New("invalid record")
	ErrRecordCapacity = errors.New("record capacity exceeded")
)

type Kind uint8

const (
	ValueEntryPageKind      Kind = 1
	RecipientKind           Kind = 2
	RootKind                Kind = 3
	HeadKind                Kind = 4
	AccessKind              Kind = 7
	RequiredSupportKind     Kind = 8
	AdministrativeIndexKind Kind = 9
)

type Ref struct {
	Kind                   Kind
	Domain, Object, Digest ID
	Format                 uint16
	Length                 uint32
	Index                  uint16
}

func childPageIndexCount(kind Kind) uint16 {
	switch kind {
	case ValueEntryPageKind:
		return MaxValueEntryPages
	case RecipientKind:
		return MaxRecipientPages
	case AccessKind, RequiredSupportKind, AdministrativeIndexKind:
		return MaxChildPages
	default:
		return 0
	}
}

// ValidFor requires the owning container's expected version. Format identifies
// that container's bytes; it is not a version of the Ref field layout.
func (r Ref) ValidFor(version uint16) bool {
	return !r.Digest.IsZero() && r.shapeValidFor(version)
}

func (r Ref) shapeValidFor(version uint16) bool {
	limit, indexCount := uint32(0), childPageIndexCount(r.Kind)
	switch r.Kind {
	case ValueEntryPageKind:
		limit = MaxValueEntryPageLength
	case RecipientKind:
		limit = MaxRecipientPageLength
	case RootKind:
		limit, indexCount = MaxRootLength, 1
	case AccessKind:
		limit = MaxAccessPageLength
	case RequiredSupportKind:
		limit = MaxRequiredSupportPageLength
	case AdministrativeIndexKind:
		limit = MaxRequiredSupportPageLength
	default:
		return false
	}
	return version != 0 && r.Format == version && publicIDsValid(r.Domain, r.Object) &&
		r.Length > 0 && r.Length <= limit && r.Index < indexCount
}

// RootRefDigestPlan is the request-identity projection of one root reference.
// Its digest must be zero; every other field obeys the stored reference bounds.
type RootRefDigestPlan Ref

func AppendRootRefDigestPlan(dst []byte, plan RootRefDigestPlan, version uint16) ([]byte, error) {
	v := Ref(plan)
	if v.Kind != RootKind || !v.Digest.IsZero() || !v.shapeValidFor(version) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeRef(&w, v)
	return w.b, nil
}

func writeRef(w *cryptoWriter, v Ref) {
	w.u8(uint8(v.Kind))
	w.u16(v.Format)
	w.id(v.Domain)
	w.id(v.Object)
	w.id(v.Digest)
	w.u32(v.Length)
	w.u16(v.Index)
}
func readRef(r *cryptoReader, version uint16) Ref {
	v := Ref{Kind: Kind(r.u8()), Format: r.u16(), Domain: r.requiredID(), Object: r.requiredID(), Digest: r.requiredID(), Length: r.u32(), Index: r.u16()}
	if r.err == nil && !v.ValidFor(version) {
		r.err = ErrRecord
	}
	return v
}
func AppendRef(dst []byte, v Ref, version uint16) ([]byte, error) {
	if !v.ValidFor(version) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeRef(&w, v)
	return w.b, nil
}
func ParseRef(b []byte, version uint16) (Ref, int, error) {
	if len(b) < RefLength {
		return Ref{}, 0, ErrRecord
	}
	r := newRecordReader(b)
	v := readRef(&r, version)
	if r.err != nil {
		return Ref{}, 0, r.failure()
	}
	return v, r.i, nil
}
func DecodeRef(b []byte, version uint16) (Ref, error) {
	v, n, err := ParseRef(b, version)
	if err != nil {
		return Ref{}, err
	}
	if n != len(b) {
		return Ref{}, ErrRecord
	}
	return v, nil
}

func publicIDsValid(ids ...ID) bool {
	for _, id := range ids {
		if id.IsZero() {
			return false
		}
	}
	return true
}
func ownedBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
