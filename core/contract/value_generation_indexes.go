package contract

import "bytes"

// This conservative index charge is independent of operation-material encoding.
const generatorIndexMinimumCharge = 204

type GeneratorIndexKind uint8

const (
	GeneratorGraphSet GeneratorIndexKind = iota + 1
	GeneratorLiveOwnerSet
	GeneratorSuccessWindow
	GeneratorFailureWindow
	GeneratorReceiptOrder
)

func (v GeneratorIndexKind) label() string {
	switch v {
	case GeneratorGraphSet:
		return "graph-set"
	case GeneratorLiveOwnerSet:
		return "live-owner-set"
	case GeneratorSuccessWindow:
		return "success-window"
	case GeneratorFailureWindow:
		return "failure-window"
	case GeneratorReceiptOrder:
		return "receipt-order"
	default:
		return ""
	}
}

func GeneratorIndexDescriptor(kind GeneratorIndexKind, ids []ID) (GeneratorDescriptor, error) {
	label := kind.label()
	limit := MaxChildPages * (MaxRequiredSupportPageLength - RequiredSupportPageHeaderLength) / generatorIndexMinimumCharge
	if kind == GeneratorSuccessWindow || kind == GeneratorFailureWindow {
		limit = MutationReceiptWindowLimit
	}
	if kind == GeneratorReceiptOrder {
		limit = 2 * MutationReceiptWindowLimit
	}
	if len(ids) > limit {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	if label == "" {
		return GeneratorDescriptor{}, ErrRecord
	}
	seen := make(map[ID]struct{}, len(ids))
	for i, id := range ids {
		if id.IsZero() {
			return GeneratorDescriptor{}, ErrRecord
		}
		if _, exists := seen[id]; exists {
			return GeneratorDescriptor{}, ErrRecord
		}
		if kind <= GeneratorLiveOwnerSet && i > 0 && bytes.Compare(ids[i-1][:], id[:]) >= 0 {
			return GeneratorDescriptor{}, ErrRecord
		}
		seen[id] = struct{}{}
	}
	w := cryptoWriter{b: make([]byte, 0, 4+(4+len(ID{}))*len(ids))}
	w.u32(uint32(len(ids)))
	for _, id := range ids {
		w.blob(id[:])
	}
	return GeneratorDescriptor{Digest: generatorDigest(label, w.b), Length: uint64(len(w.b)), Count: uint32(len(ids))}, nil
}

// EmptyGeneratorIndexes is the five present empty vectors, not zero44 holes.
func EmptyGeneratorIndexes() [5]GeneratorDescriptor {
	var out [5]GeneratorDescriptor
	for i := range out {
		out[i] = GeneratorDescriptor{Digest: generatorDigest(GeneratorIndexKind(i+1).label(), []byte{0, 0, 0, 0}), Length: 4}
	}
	return out
}

func GeneratorIndexShapeValid(kind GeneratorIndexKind, v GeneratorDescriptor) bool {
	if kind.label() == "" || !v.Valid() || v.Length != 4+uint64(4+len(ID{}))*uint64(v.Count) {
		return false
	}
	if (kind == GeneratorSuccessWindow || kind == GeneratorFailureWindow) && v.Count > MutationReceiptWindowLimit {
		return false
	}
	if kind == GeneratorReceiptOrder && v.Count > 2*MutationReceiptWindowLimit {
		return false
	}
	if v.Count == 0 {
		return v == EmptyGeneratorIndexes()[kind-1]
	}
	return v.Count <= MaxChildPages*(MaxRequiredSupportPageLength-RequiredSupportPageHeaderLength)/generatorIndexMinimumCharge
}
