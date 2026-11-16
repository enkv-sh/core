package contract

import "testing"

// full_only: false
func TestRetainedReceiptSummaryKeepsOperationStateWarningAndEvidenceMeanings(t *testing.T) {
	for _, row := range []struct {
		operation, state, evidence uint16
		canonical                  uint8
		bits                       uint64
		valid                      bool
	}{
		{OperationApplyDeclaration, ReceiptStateSuccess, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, 0, true},
		{OperationApplyDeclaration, ReceiptStateEffectUnknown, ReceiptEvidenceProviderFacts, ReceiptCanonicalNotSelected, ReceiptWarningPossibleLive, true},
		{OperationApplyDeclaration, ReceiptStateSuccess, ReceiptEvidenceAcknowledged, ReceiptCanonicalSelected, ReceiptWarningInvalidationNotConfirmed, true},
		{OperationEndSelectedWork, ReceiptStateWorkEnded, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, 8, true},
		{OperationInitializeDomain, ReceiptStateSuccess, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, 0, true},
		{OperationEndSelectedWork, ReceiptStateSuccess, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, 0, false},
		{OperationApplyDeclaration, ReceiptStateWorkEnded, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, 0, false},
		{OperationApplyDeclaration, ReceiptStateEffectUnknown, ReceiptEvidenceCanonical, ReceiptCanonicalNotSelected, 0, false},
		{OperationApplyDeclaration, ReceiptStateEffectUnknown, ReceiptEvidenceProviderFacts, ReceiptCanonicalSelected, 0, false},
		{OperationApplyDeclaration, ReceiptStateSuccess, ReceiptEvidenceAcknowledged, ReceiptCanonicalSelected, 0, false},
		{OperationApplyDeclaration, ReceiptStateSuccess, ReceiptEvidenceConfirmed, ReceiptCanonicalSelected, ReceiptWarningInvalidationNotConfirmed, false},
		{OperationApplyDeclaration, ReceiptStatePossibleLiveResidueAccepted, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, ReceiptWarningPossibleLive, false},
		{OperationAcceptGeneratedRetirementResidue, ReceiptStatePossibleLiveResidueAccepted, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, 0, false},
		{OperationInitializeDomain, ReceiptStateSuccess, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, ReceiptWarningPossibleLive, false},
		{65535, ReceiptStateSuccess, ReceiptEvidenceCanonical, ReceiptCanonicalSelected, 0, false},
	} {
		if got := CompactMutationReceiptSummaryValid(row.operation, row.state, row.evidence, row.canonical, row.bits); got != row.valid {
			t.Fatal("retained summary changed terminal meaning", row, got)
		}
	}
}
