package core

import "testing"

// full_only: false
func TestGCNilPayloadCannotCarryBoundRequestIdentity(t *testing.T) {
	out := PublicGCResult{Operation: GCApplyOperation, RequestID: gcTestID("unbound-nonzero-nonce"), Result: refused(AdmissionInvalid), StateResult: "refused"}
	if err := out.Validate(); err != nil {
		t.Fatal("valid unbound refusal rejected", err)
	}
	out.RequestIdentity = gcTestID("bound-identity-without-payload")
	if err := gcValidateResult(out); err == nil {
		t.Error("bound request identity passed structural validation without a payload")
	}
	if err := out.Validate(); err == nil {
		t.Error("bound request identity passed public validation without a payload")
	}
}
