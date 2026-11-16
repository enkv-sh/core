package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRetainedMutationReceiptKeepsOriginalBytesAndStoredKind(t *testing.T) {
	state, receipt, _ := receiptStateFixture(t)
	row, body, found, err := state.retainedMutationReceipt(receipt.OperationID)
	if err != nil || !found || row != receipt || row.OperationKind != contract.OperationReplaceRecoveryKeysAndRoot || len(body) != contract.CompactMutationReceiptLength {
		t.Fatal("retained typed original missing", err)
	}
	original := bytes.Clone(body)
	body[0] ^= 0xff
	again, retained, found, err := state.retainedMutationReceipt(receipt.OperationID)
	if err != nil || !found || again != receipt || !bytes.Equal(retained, original) {
		t.Fatal("raw receipt borrowed mutable state", err)
	}
	missing, raw, found, err := state.retainedMutationReceipt(contract.ID{99})
	if err != nil || found || missing != (contract.CompactMutationReceipt{}) || raw != nil {
		t.Fatal("genuinely absent operation gained a row", err)
	}
	abandonments, err := state.retainedAdministrativeAbandonments()
	if err != nil || len(abandonments) != 0 {
		t.Fatal("nonadministrative receipt entered abandonment view", err)
	}
}

// full_only: false
func TestRetainedMutationReceiptRefusesIncompleteMandatoryEvidence(t *testing.T) {
	for _, damage := range []string{"missing-row", "optional-row", "missing-index", "missing-order", "changed-order"} {
		t.Run(damage, func(t *testing.T) {
			state, receipt, _ := receiptStateFixture(t)
			switch damage {
			case "missing-row":
				state.support[0].Records = nil
			case "optional-row":
				state.adminIndex.Pages[0].Spans[0].Mandatory = false
			case "missing-order":
				state.root.Generated.ReceiptOrder = contract.GeneratorDescriptor{}
			case "changed-order":
				state.root.Generated.ReceiptOrder.Digest[0] ^= 1
			case "missing-index":
				state.support[1].Records = nil
			}
			if _, raw, found, err := state.retainedMutationReceipt(receipt.OperationID); err == nil || raw != nil || found {
				t.Fatal("damaged mandatory evidence was returned or called absent")
			}
			if _, raw, found, err := state.retainedMutationReceipt(contract.ID{99}); err == nil || raw != nil || found {
				t.Fatal("absent lookup bypassed complete mandatory validation")
			}
		})
	}
}
