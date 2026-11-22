package contract

// CompactMutationReceiptSummaryValid validates only the terminal fields carried
// by a retained-list row. It does not invent missing receipt descriptors or counts.
func CompactMutationReceiptSummaryValid(operation, state, evidence uint16, canonical uint8, bits uint64) bool {
	_, effects, err := DecodeReceiptWarningBits(operation, bits)
	if err != nil || evidence < ReceiptEvidenceCanonical || evidence > ReceiptEvidenceMixedCompletion {
		return false
	}
	if operation == OperationEndSelectedWork {
		return canonical == ReceiptCanonicalSelected && state == ReceiptStateWorkEnded && evidence == ReceiptEvidenceCanonical
	}
	acknowledged := evidence == ReceiptEvidenceAcknowledged || evidence == ReceiptEvidenceMixedCompletion
	if acknowledged != (effects&ReceiptWarningInvalidationNotConfirmed != 0) {
		return false
	}
	switch canonical {
	case ReceiptCanonicalSelected:
		switch state {
		case ReceiptStateSuccess, ReceiptStateExactResume:
			return true
		case ReceiptStatePossibleLiveResidueAccepted:
			return operation == OperationAcceptGeneratedRetirementResidue && effects&ReceiptWarningPossibleLive != 0
		case ReceiptStateRetirementPending:
			return operation == OperationApplyDeclaration || operation == OperationRotateValueEntryValue
		}
	case ReceiptCanonicalNotSelected:
		if evidence == ReceiptEvidenceCanonical {
			return operation == OperationRetireGeneratedGeneration && state == ReceiptStateEffectUnknown
		}
		return state == ReceiptStateEffectUnknown || state == ReceiptStateEffectTerminalFailure
	}
	return false
}
