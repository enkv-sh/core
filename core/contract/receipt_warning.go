package contract

const (
	receiptOperationWarningMask = ReceiptWarningPossibleLive | ReceiptWarningInvalidationNotConfirmed
	receiptDomainWarningShift   = 2
	receiptDomainWarningMask    = uint64(31) << receiptDomainWarningShift
)

// EncodeReceiptWarningBits keeps permanent domain warnings distinct from the
// ordinary operation's warning flags. Administrative receipts retain their
// complete domain byte in the operation-specific representation.
func EncodeReceiptWarningBits(operation uint16, domain uint8, effects uint64) (uint64, error) {
	if !compactMutationOperationValid(operation) || domain&^uint8(31) != 0 || effects&^receiptOperationWarningMask != 0 {
		return 0, ErrRecord
	}
	if operation == OperationInitializeDomain && (domain != 0 || effects != 0) {
		return 0, ErrRecord
	}
	if operation == OperationEndSelectedWork {
		if effects != 0 {
			return 0, ErrRecord
		}
		return uint64(domain), nil
	}
	return uint64(domain)<<receiptDomainWarningShift | effects, nil
}

// DecodeReceiptWarningBits interprets the closed warning vocabulary of the
// exact operation; administrative domain bits are never effect-warning flags.
func DecodeReceiptWarningBits(operation uint16, bits uint64) (domain uint8, effects uint64, err error) {
	if !compactMutationOperationValid(operation) {
		return 0, 0, ErrRecord
	}
	if operation == OperationInitializeDomain && bits != 0 {
		return 0, 0, ErrRecord
	}
	if operation == OperationEndSelectedWork {
		if bits&^uint64(31) != 0 {
			return 0, 0, ErrRecord
		}
		return uint8(bits), 0, nil
	}
	if bits & ^(receiptOperationWarningMask|receiptDomainWarningMask) != 0 {
		return 0, 0, ErrRecord
	}
	return uint8((bits & receiptDomainWarningMask) >> receiptDomainWarningShift), bits & receiptOperationWarningMask, nil
}
