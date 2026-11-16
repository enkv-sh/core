package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestReplacementReceiptObservationUsesExactOwnedSameImageBytes(t *testing.T) {
	state, row, _ := receiptStateFixture(t)
	p := &ReplacementObserver{input: ReplacementObservationInstallation{ExpectedDomain: row.DomainID, Correlation: ReplacementCorrelation{RequestIdentity: row.RequestIdentityDigest}}, candidate: format.Head{Core: format.HeadCore{PreviousRevision: row.PredecessorRevisionID, Revision: row.RequestedRevisionID}}}
	q := &ReplacementQueryIdentity{OriginalOperationID: row.OperationID, RequiredStoredKind: contract.OperationReplaceRecoveryKeysAndRoot}
	receipt, result := p.receipt(state, q, false)
	if result.Outcome != ObservedCurrent || receipt == nil || receipt.Receipt != row || receipt.CandidateSelected || len(receipt.ReceiptBytes) != contract.CompactMutationReceiptLength {
		t.Fatal("exact retained result missing", result)
	}
	original := bytes.Clone(receipt.ReceiptBytes)
	receipt.ReceiptBytes[0] ^= 0xff
	got, raw, found, err := state.retainedMutationReceipt(row.OperationID)
	if err != nil || !found || got != row || !bytes.Equal(raw, original) {
		t.Fatal("returned raw receipt borrowed selected bytes", err)
	}
	for _, condition := range []string{"wrong-kind", "request", "revision", "missing-historical", "missing-current", "mandatory-row"} {
		t.Run(condition, func(t *testing.T) {
			state, row, _ := receiptStateFixture(t)
			parent := ReplacementObserver{input: ReplacementObservationInstallation{ExpectedDomain: row.DomainID, Correlation: ReplacementCorrelation{RequestIdentity: row.RequestIdentityDigest}}}
			parent.candidate = format.Head{Core: format.HeadCore{PreviousRevision: row.PredecessorRevisionID, Revision: row.RequestedRevisionID}}
			query := *q
			current := false
			want := IntegrityFailure
			switch condition {
			case "wrong-kind":
				query.RequiredStoredKind = contract.OperationRotateRecipientKeyBinding
				want = AdmissionRefused
			case "request":
				parent.input.Correlation.RequestIdentity = contract.ID{77}
			case "revision":
				parent.candidate.Core.Revision = contract.ID{78}
			case "missing-historical":
				query.OriginalOperationID = contract.ID{79}
				want = EvidenceUnavailable
			case "missing-current":
				query.OriginalOperationID = contract.ID{79}
				current = true
			case "mandatory-row":
				state.support[0].Records = nil
			}
			payload, result := parent.receipt(state, &query, current)
			if payload != nil || result.Outcome != want || result.CommitMayHaveOccurred {
				t.Fatal("typed receipt refusal changed", result)
			}
		})
	}
}
