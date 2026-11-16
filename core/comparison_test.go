package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestComparisonNeedsPrivateParentBeforeCrypto(t *testing.T) {
	boundary := refusalBoundary{t: t}
	s := &StateSession{store: boundary}
	for _, parent := range []*AdmittedParentComparison{nil, {}, {crypto: boundary}} {
		c, result := s.Compare(context.Background(), nil, parent)
		if c != nil || result != refused(AdmissionInvalid) {
			t.Fatalf("public comparison admission: %+v", result)
		}
	}
}

// full_only: false
func TestGeneratedNormalHandoffRejectsUnboundComparisonBeforeEffects(t *testing.T) {
	boundary := refusalBoundary{t: t}
	s := &StateSession{store: boundary}
	for _, c := range []*Comparison{nil, {session: &StateSession{}}} {
		if witness, err := s.generatedSupportTransition(context.Background(), c, nil); err == nil || witness != nil {
			t.Fatal("unbound comparison prepared generated support")
		}
	}
	if witness, err := s.generatedSupportTransition(context.Background(), &Comparison{session: s}, nil); err != nil || witness != nil {
		t.Fatal("empty selected support allocated a generated handoff", err)
	}
}

// full_only: false
func TestPrivatePreparationRequiresAnAdmittedComparison(t *testing.T) {
	boundary := refusalBoundary{t: t}
	s := &StateSession{store: boundary}
	for _, c := range []*Comparison{nil, {session: s}, {session: &StateSession{}, operation: &cryptoOperation{adapter: boundary}}} {
		if result := s.prepareCompared(context.Background(), c, transitionPlan{}); result != refused(AdmissionInvalid) {
			t.Fatalf("private preparation without comparison admission: %+v", result)
		}
	}
}

// full_only: false
func TestCustodyFailureMapping(t *testing.T) {
	cases := []struct {
		code    contract.CryptoResultCode
		outcome Outcome
		reason  Reason
	}{
		{contract.CryptoInvalidInput, AdmissionRefused, InvalidIntent},
		{contract.CryptoInvalidAdmission, AdmissionRefused, AdmissionInvalid},
		{contract.CryptoExpired, AdmissionRefused, AdmissionInvalid},
		{contract.CryptoCancelled, AdmissionRefused, AdmissionInvalid},
		{contract.CryptoAlreadyUsed, AdmissionRefused, AlreadyUsed},
		{contract.CryptoSourceAuthenticationFailed, AdmissionRefused, InvalidIntent},
		{contract.CryptoPrivateRouteUnavailable, AdmissionRefused, AdmissionInvalid},
		{contract.CryptoCustodyUnavailable, EvidenceUnavailable, CustodyUnavailable},
		{contract.CryptoResponseUnknown, EvidenceUnavailable, CustodyUnavailable},
		{contract.CryptoCapacityExceeded, AdmissionRefused, CapacityExceeded},
		{contract.CryptoStoredAuthenticationFailed, IntegrityFailure, InvalidProof},
		{0, AdmissionRefused, AdmissionInvalid},
		{13, AdmissionRefused, AdmissionInvalid},
	}
	for _, tc := range cases {
		result := custodyFailure(tc.code)
		if result.Outcome != tc.outcome || result.Reason != tc.reason || result.CommitMayHaveOccurred || result.RequestedRevision != (contract.ID{}) {
			t.Fatalf("custody code %d: %+v", tc.code, result)
		}
	}
}
