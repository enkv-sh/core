package compositionfull

import (
	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestReplacementObservationRefusalRetainsProtectedTarget(t *testing.T) {
	nonce := contract.ID{1}
	for _, tc := range []struct {
		target    core.ReplacementTarget
		operation core.ReplacementReadOperation
		kind      uint16
	}{
		{core.ReplacementTargetAuthority, core.ReplacementObserve, contract.OperationReplaceAuthorityKeys},
		{core.ReplacementTargetRecovery, core.ReplacementReceipt, contract.OperationReplaceRecoveryKeysAndRoot},
		{core.ReplacementTargetRecipient, core.ReplacementReceipt, contract.OperationRotateRecipientKeyBinding},
	} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			result, err := NewReplacementObservationRefusal(tc.target, nonce, format)
			if err != nil || result.Target != tc.target || result.Operation != tc.operation || result.UnderlyingOperation != tc.kind || result.RequestID != nonce || result.StateResult != contract.ReaderRefused || result.PreAdmission == nil || result.PreAdmission.Code != string(contract.ReasonInvalidInput) || result.PreAdmission.RequestNonce != nonce || result.OperationID.IsZero() || result.Query != nil || result.Selection != nil || result.Receipt != nil || result.Result.CommitMayHaveOccurred {
				t.Fatal("recognized local refusal changed read meaning", tc.target, format, err, result)
			}
			repeated, err := NewReplacementObservationRefusal(tc.target, nonce, format)
			if err != nil || repeated.OperationID != result.OperationID {
				t.Fatal("fixed refusal facts changed operation", err)
			}
			next, err := NewReplacementObservationRefusal(tc.target, contract.ID{2}, format)
			if err != nil || next.OperationID == result.OperationID {
				t.Fatal("new query nonce borrowed refusal identity", err)
			}
		}
	}
	for _, tc := range []struct {
		target core.ReplacementTarget
		nonce  contract.ID
		format configuration.Format
	}{{0, nonce, configuration.JSON}, {core.ReplacementTargetAuthority, contract.ID{}, configuration.JSON}, {core.ReplacementTargetAuthority, nonce, 0}} {
		if _, err := NewReplacementObservationRefusal(tc.target, tc.nonce, tc.format); err == nil {
			t.Fatal("unknown or unbound refusal admitted")
		}
	}
}
