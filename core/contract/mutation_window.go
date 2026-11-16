package contract

import (
	"bytes"
	"slices"
)

const (
	MutationReceiptIndexesSchema    uint16 = 2
	MutationReceiptIndexesMaxLength        = 26 + 144*MutationReceiptWindowLimit
)

// MutationReceiptIndexes records terminal selection order, oldest first.
// Physical support-row order is independent of the retained order.
type MutationReceiptIndexes struct {
	Successes, Failures, Order []ID
}

func (v MutationReceiptIndexes) Descriptors() (GeneratorDescriptor, GeneratorDescriptor, GeneratorDescriptor, error) {
	successes, err := GeneratorIndexDescriptor(GeneratorSuccessWindow, v.Successes)
	if err != nil {
		return GeneratorDescriptor{}, GeneratorDescriptor{}, GeneratorDescriptor{}, err
	}
	failures, err := GeneratorIndexDescriptor(GeneratorFailureWindow, v.Failures)
	if err != nil {
		return GeneratorDescriptor{}, GeneratorDescriptor{}, GeneratorDescriptor{}, err
	}
	order, err := GeneratorIndexDescriptor(GeneratorReceiptOrder, v.Order)
	if err != nil {
		return GeneratorDescriptor{}, GeneratorDescriptor{}, GeneratorDescriptor{}, err
	}
	classes := make(map[ID]int, len(v.Successes)+len(v.Failures))
	for _, id := range v.Successes {
		classes[id] = 0
	}
	for _, id := range v.Failures {
		if _, exists := classes[id]; exists {
			return GeneratorDescriptor{}, GeneratorDescriptor{}, GeneratorDescriptor{}, ErrRecord
		}
		classes[id] = 1
	}
	if len(v.Order) != len(classes) {
		return GeneratorDescriptor{}, GeneratorDescriptor{}, GeneratorDescriptor{}, ErrRecord
	}
	windows := [2][]ID{v.Successes, v.Failures}
	var next [2]int
	for _, id := range v.Order {
		class, exists := classes[id]
		if !exists || next[class] >= len(windows[class]) || windows[class][next[class]] != id {
			return GeneratorDescriptor{}, GeneratorDescriptor{}, GeneratorDescriptor{}, ErrRecord
		}
		next[class]++
	}
	return successes, failures, order, nil
}

func EncodeMutationReceiptIndexes(v MutationReceiptIndexes) ([]byte, error) {
	if _, _, _, err := v.Descriptors(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 26+(4+len(ID{}))*(len(v.Successes)+len(v.Failures)+len(v.Order)))}
	w.u16(MutationReceiptIndexesSchema)
	for _, ids := range [][]ID{v.Successes, v.Failures, v.Order} {
		w.u32(uint32(4 + (4+len(ID{}))*len(ids)))
		w.u32(uint32(len(ids)))
		for _, id := range ids {
			w.blob(id[:])
		}
	}
	return w.b, nil
}

func InspectMutationReceiptIndexes(b []byte) (MutationReceiptIndexes, error) {
	if len(b) > MutationReceiptIndexesMaxLength {
		return MutationReceiptIndexes{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if r.u16() != MutationReceiptIndexesSchema {
		return MutationReceiptIndexes{}, ErrRecord
	}
	var out MutationReceiptIndexes
	for i, target := range []*[]ID{&out.Successes, &out.Failures, &out.Order} {
		limit := MutationReceiptWindowLimit
		if i == 2 {
			limit *= 2
		}
		body := r.blob(4 + (4+len(ID{}))*limit)
		if r.err != nil {
			return MutationReceiptIndexes{}, r.failure()
		}
		rows := newRecordReader(body)
		count := rows.count(limit, 4+len(ID{}))
		if rows.err != nil {
			return MutationReceiptIndexes{}, rows.failure()
		}
		*target = make([]ID, 0, count)
		for i := 0; i < count; i++ {
			if rows.u32() != 32 {
				return MutationReceiptIndexes{}, ErrRecord
			}
			*target = append(*target, rows.requiredID())
		}
		if err := rows.end(); err != nil {
			return MutationReceiptIndexes{}, err
		}
	}
	if err := r.end(); err != nil {
		return MutationReceiptIndexes{}, err
	}
	if _, _, _, err := out.Descriptors(); err != nil {
		return MutationReceiptIndexes{}, err
	}
	return out, nil
}

func MutationReceiptIndexBlobID(domain ID, successes, failures, order GeneratorDescriptor) (ID, error) {
	if domain.IsZero() || !GeneratorIndexShapeValid(GeneratorSuccessWindow, successes) || !GeneratorIndexShapeValid(GeneratorFailureWindow, failures) || !GeneratorIndexShapeValid(GeneratorReceiptOrder, order) || order.Count != successes.Count+failures.Count {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 32+3*GeneratorDescriptorLength)}
	w.id(domain)
	writeGeneratorDescriptor(&w, successes)
	writeGeneratorDescriptor(&w, failures)
	writeGeneratorDescriptor(&w, order)
	return generatorDigest("receipt-index", w.b), nil
}

type MutationReceiptWindows struct {
	DomainID            ID
	Successes, Failures []CompactMutationReceipt
	Order               []ID
}

type MutationReceiptDescriptors struct {
	Successes, Failures, Receipts, Order GeneratorDescriptor
}

func (v MutationReceiptWindows) validate() error {
	if v.DomainID.IsZero() {
		return ErrRecord
	}
	if len(v.Successes) > MutationReceiptWindowLimit || len(v.Failures) > MutationReceiptWindowLimit {
		return ErrRecordCapacity
	}
	seen := make(map[ID]bool, len(v.Successes)+len(v.Failures))
	for class, rows := range [][]CompactMutationReceipt{v.Successes, v.Failures} {
		for _, row := range rows {
			if !CompactMutationReceiptValid(row) || row.DomainID != v.DomainID || row.CanonicalOutcome != uint8(class+1) || seen[row.OperationID] {
				return ErrRecord
			}
			seen[row.OperationID] = true
		}
	}
	_, _, _, err := v.indexes().Descriptors()
	return err
}

func (v MutationReceiptWindows) indexes() MutationReceiptIndexes {
	out := MutationReceiptIndexes{Successes: make([]ID, len(v.Successes)), Failures: make([]ID, len(v.Failures)), Order: slices.Clone(v.Order)}
	for i, row := range v.Successes {
		out.Successes[i] = row.OperationID
	}
	for i, row := range v.Failures {
		out.Failures[i] = row.OperationID
	}
	return out
}

func (v MutationReceiptWindows) Indexes() (MutationReceiptIndexes, error) {
	if err := v.validate(); err != nil {
		return MutationReceiptIndexes{}, err
	}
	return v.indexes(), nil
}

func mutationReceiptSetDescriptor(successes, failures []CompactMutationReceipt) GeneratorDescriptor {
	rows := make([]CompactMutationReceipt, 0, len(successes)+len(failures))
	rows = append(rows, successes...)
	rows = append(rows, failures...)
	slices.SortFunc(rows, func(a, b CompactMutationReceipt) int { return bytes.Compare(a.OperationID[:], b.OperationID[:]) })
	w := cryptoWriter{b: make([]byte, 0, 4+(4+CompactMutationReceiptLength)*len(rows))}
	w.u32(uint32(len(rows)))
	for _, row := range rows {
		w.u32(CompactMutationReceiptLength)
		writeCompactMutationReceipt(&w, row)
	}
	return GeneratorDescriptor{Digest: generatorDigest("mutation-receipts", w.b), Length: uint64(len(w.b)), Count: uint32(len(rows))}
}

func (v MutationReceiptWindows) Descriptors() (MutationReceiptDescriptors, error) {
	indexes, err := v.Indexes()
	if err != nil {
		return MutationReceiptDescriptors{}, err
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		return MutationReceiptDescriptors{}, err
	}
	return MutationReceiptDescriptors{Successes: successes, Failures: failures, Receipts: mutationReceiptSetDescriptor(v.Successes, v.Failures), Order: order}, nil
}

func mutationReceiptFresh(v MutationReceiptWindows, operation ID) bool {
	for _, rows := range [][]CompactMutationReceipt{v.Successes, v.Failures} {
		for _, row := range rows {
			if row.OperationID == operation {
				return false
			}
		}
	}
	return true
}

func appendMutationReceipt(v MutationReceiptWindows, row CompactMutationReceipt) MutationReceiptWindows {
	var evicted ID
	appendRow := func(rows []CompactMutationReceipt) []CompactMutationReceipt {
		if len(rows) == MutationReceiptWindowLimit {
			evicted = rows[0].OperationID
			rows = rows[1:]
		}
		out := make([]CompactMutationReceipt, len(rows)+1)
		copy(out, rows)
		out[len(rows)] = row
		return out
	}
	if row.CanonicalOutcome == ReceiptCanonicalSelected {
		v.Successes = appendRow(v.Successes)
		v.Failures = slices.Clone(v.Failures)
	} else {
		v.Successes = slices.Clone(v.Successes)
		v.Failures = appendRow(v.Failures)
	}
	orderCount := len(v.Order) + 1
	if !evicted.IsZero() {
		orderCount--
	}
	order := make([]ID, 0, orderCount)
	for _, id := range v.Order {
		if id != evicted {
			order = append(order, id)
		}
	}
	v.Order = append(order, row.OperationID)
	return v
}

func AppendMutationReceipt(before MutationReceiptWindows, row CompactMutationReceipt) (MutationReceiptWindows, error) {
	if err := before.validate(); err != nil {
		return MutationReceiptWindows{}, err
	}
	if !CompactMutationReceiptValid(row) || row.DomainID != before.DomainID || !mutationReceiptFresh(before, row.OperationID) {
		return MutationReceiptWindows{}, ErrRecord
	}
	return appendMutationReceipt(before, row), nil
}
