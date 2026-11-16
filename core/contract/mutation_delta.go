package contract

import (
	"bytes"
	"slices"
)

type MutationReceiptDelta struct {
	DomainID      ID
	OperationKind uint16
	AddedCount    uint8
	Before, After MutationReceiptWindows
}

type MutationReceiptDeltaPlan struct {
	DomainID      ID
	OperationKind uint16
	AddedCount    uint8
	Before        MutationReceiptWindows
	NewReceipt    CompactMutationReceiptPlan
}

func mutationReceiptDeltaHeaderValid(domain ID, kind uint16, added uint8) bool {
	return !domain.IsZero() && (kind == OperationReplaceAuthorityKeys && added == 0 || compactMutationOperationValid(kind) && added == 1)
}

func mutationReceiptWindowsEqual(a, b MutationReceiptWindows) bool {
	return a.DomainID == b.DomainID && slices.Equal(a.Successes, b.Successes) && slices.Equal(a.Failures, b.Failures) && slices.Equal(a.Order, b.Order)
}

func mutationReceiptWindowDescriptors(v MutationReceiptWindows) (MutationReceiptDescriptors, error) {
	successes, failures, order, err := v.indexes().Descriptors()
	if err != nil {
		return MutationReceiptDescriptors{}, err
	}
	return MutationReceiptDescriptors{Successes: successes, Failures: failures, Receipts: mutationReceiptSetDescriptor(v.Successes, v.Failures), Order: order}, nil
}

func mutationReceiptDeltaDigest(domain ID, kind uint16, added uint8, before, after MutationReceiptWindows) (ID, error) {
	b, err := mutationReceiptWindowDescriptors(before)
	if err != nil {
		return ID{}, err
	}
	a, err := mutationReceiptWindowDescriptors(after)
	if err != nil {
		return ID{}, err
	}
	w := cryptoWriter{b: make([]byte, 0, 389)}
	w.u16(GeneratorRecordSchema)
	w.id(domain)
	w.u16(kind)
	w.u8(added)
	for _, descriptor := range []GeneratorDescriptor{b.Successes, b.Failures, b.Receipts, b.Order, a.Successes, a.Failures, a.Receipts, a.Order} {
		writeGeneratorDescriptor(&w, descriptor)
	}
	return generatorDigest("receipt-delta", w.b), nil
}

func MutationReceiptDeltaDigest(v MutationReceiptDelta) (ID, error) {
	if !mutationReceiptDeltaHeaderValid(v.DomainID, v.OperationKind, v.AddedCount) || v.Before.DomainID != v.DomainID || v.After.DomainID != v.DomainID {
		return ID{}, ErrRecord
	}
	if err := v.Before.validate(); err != nil {
		return ID{}, err
	}
	if err := v.After.validate(); err != nil {
		return ID{}, err
	}
	valid := v.AddedCount == 0 && mutationReceiptWindowsEqual(v.Before, v.After)
	if v.AddedCount == 1 {
		for _, rows := range [][]CompactMutationReceipt{v.After.Successes, v.After.Failures} {
			if len(rows) == 0 {
				continue
			}
			row := rows[len(rows)-1]
			if row.OperationKind != v.OperationKind {
				continue
			}
			want, err := AppendMutationReceipt(v.Before, row)
			if err == nil && mutationReceiptWindowsEqual(want, v.After) {
				valid = true
			}
		}
	}
	if !valid {
		return ID{}, ErrRecord
	}
	return mutationReceiptDeltaDigest(v.DomainID, v.OperationKind, v.AddedCount, v.Before, v.After)
}

func (v MutationReceiptDeltaPlan) after() (MutationReceiptWindows, error) {
	if !mutationReceiptDeltaHeaderValid(v.DomainID, v.OperationKind, v.AddedCount) || v.Before.DomainID != v.DomainID {
		return MutationReceiptWindows{}, ErrRecord
	}
	if err := v.Before.validate(); err != nil {
		return MutationReceiptWindows{}, err
	}
	if v.AddedCount == 0 {
		if v.NewReceipt != (CompactMutationReceiptPlan{}) {
			return MutationReceiptWindows{}, ErrRecord
		}
		return v.Before, nil
	}
	if _, err := AppendCompactMutationReceiptPlan(nil, v.NewReceipt); err != nil {
		return MutationReceiptWindows{}, err
	}
	if v.NewReceipt.DomainID != v.DomainID || v.NewReceipt.OperationKind != v.OperationKind || !mutationReceiptFresh(v.Before, v.NewReceipt.OperationID) {
		return MutationReceiptWindows{}, ErrRecord
	}
	return appendMutationReceipt(v.Before, CompactMutationReceipt(v.NewReceipt)), nil
}

func MutationReceiptDeltaPlanDigest(v MutationReceiptDeltaPlan) (ID, error) {
	after, err := v.after()
	if err != nil {
		return ID{}, err
	}
	return mutationReceiptDeltaDigest(v.DomainID, v.OperationKind, v.AddedCount, v.Before, after)
}

func (v MutationReceiptDeltaPlan) AfterIndexes() (MutationReceiptIndexes, error) {
	after, err := v.after()
	if err != nil {
		return MutationReceiptIndexes{}, err
	}
	return after.indexes(), nil
}

// AfterSupportRecords is an explicit hash projection. Only the newly appended
// body contains the named request-identity hole; actual support readers reject it.
func (v MutationReceiptDeltaPlan) AfterSupportRecords() ([]SupportRecord, error) {
	after, err := v.after()
	if err != nil {
		return nil, err
	}
	return mutationReceiptSupportRecords(after), nil
}

func mutationReceiptSupportRecords(v MutationReceiptWindows) []SupportRecord {
	rows := make([]SupportRecord, 0, len(v.Successes)+len(v.Failures))
	for _, window := range [][]CompactMutationReceipt{v.Successes, v.Failures} {
		for _, row := range window {
			w := cryptoWriter{b: make([]byte, 0, CompactMutationReceiptLength)}
			writeCompactMutationReceipt(&w, row)
			rows = append(rows, SupportRecord{Kind: MutationReceiptSupportKind, RecordID: row.OperationID, Body: w.b})
		}
	}
	slices.SortFunc(rows, func(a, b SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	return rows
}

func (v MutationReceiptWindows) SupportRecords() ([]SupportRecord, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	return mutationReceiptSupportRecords(v), nil
}
