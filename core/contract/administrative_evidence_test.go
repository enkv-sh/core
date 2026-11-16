package contract

import "testing"

// full_only: false
func TestAdministrativeEvidenceSummaryPreservesMixedSelectedFacts(t *testing.T) {
	row := administrativeReceiptFixture()
	row.AdministrativeOriginalEvidence = AdministrativeEvidenceTerminalFailure |
		AdministrativeEvidenceContradiction | AdministrativeEvidenceReleaseUnknown
	if _, err := EncodeCompactMutationReceipt(row); err != nil {
		t.Fatal("selected mixed evidence refused", err)
	}
	row.AdministrativeOriginalEvidence = 1 << 15
	if _, err := EncodeCompactMutationReceipt(row); err == nil {
		t.Fatal("unknown selected evidence bit accepted")
	}
}
