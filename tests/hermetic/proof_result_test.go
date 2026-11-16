package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// signResultTrust supplies the normalized results returned by provider adapters
// without adding a provider dependency or production admission constructor.
type signResultTrust struct {
	contract.Trust
	result  contract.SignResult
	request contract.SignRequest
	calls   int
}

func (t *signResultTrust) Sign(_ context.Context, request contract.SignRequest) contract.SignResult {
	t.request = request
	t.calls++
	return t.result
}

// full_only: false
func TestPrepareRejectedSignResults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		proof   contract.SignResult
		outcome Outcome
		reason  Reason
	}{
		{"provider-proof-failure", contract.SignResult{Reason: contract.ReasonProof}, IntegrityFailure, InvalidProof},
		{"provider-access-failure", contract.SignResult{Reason: contract.ReasonAccess}, EvidenceUnavailable, SigningUnavailable},
		{"provider-transport-failure", contract.SignResult{Reason: contract.ReasonTransport}, EvidenceUnavailable, SigningUnavailable},
		{"empty-success", contract.SignResult{}, EvidenceUnavailable, SigningUnavailable},
		{"corrupt-signature", contract.SignResult{Signature: []byte("invalid signature")}, IntegrityFailure, InvalidProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			trust := &signResultTrust{Trust: f.trust, result: tc.proof}
			before := f.store.objects[f.store.desc.HeadKey]
			c := changed(t, f.session, 0)
			candidate, result := f.session.Prepare(context.Background(), c, admit(t, f.session, c), trust)
			if trust.calls != 1 || !trust.request.Valid() || trust.request.Purpose() != contract.LifecyclePurpose {
				t.Fatalf("sign calls = %d, request = %+v; want one valid lifecycle request", trust.calls, trust.request)
			}
			if candidate != nil {
				t.Fatal("rejected signing result produced a candidate")
			}
			if want := (Result{Outcome: tc.outcome, Reason: tc.reason}); result != want {
				t.Errorf("Prepare result = %+v, want %+v", result, want)
			}
			if result := f.session.Select(context.Background(), candidate); result.Outcome != AdmissionRefused {
				t.Errorf("Select without a candidate = %+v, want AdmissionRefused", result)
			}
			if f.store.cas != 0 {
				t.Errorf("HEAD CAS calls = %d, want 0", f.store.cas)
			}
			after := f.store.objects[f.store.desc.HeadKey]
			if after.Token != before.Token || !bytes.Equal(after.Body, before.Body) {
				t.Error("rejected signing result changed HEAD")
			}
		})
	}
}
