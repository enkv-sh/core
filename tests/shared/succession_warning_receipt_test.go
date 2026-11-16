package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestRecoverySuccessionReceiptPreservesInheritedDomainWarnings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	input := []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("warning history fixture")}}
	baseline := f.engine(t, f.selected, input, nil)
	result := baseline.Apply(ctx, fixtureID(f.env.Domain, "recovery warning baseline"), input)
	baseline.Close()
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("real warning history baseline refused", result.Result)
	}
	selected := seedInstalledApplyDomainWarnings(t, f, f.open(t, ctx), 31)
	body, err := contract.EncodeControlCore(currentControlOf(selected))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(body)
	if err != nil {
		t.Fatal(err)
	}
	successor, binding := f.env.Recovery.(*testtrust.Signer).Successor(t, after.Recovery.Signing)
	after.Recovery.Signing, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, selected, f.keys, after, contract.SuccessionReplaceRecoveryBasis, contract.NormalSigningRole, contract.SuccessionChangeRecoverySigner, contract.BindingTableRow{})
	candidate, prepared := selected.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: f.env.Trust, RecoverySuccessor: successor})
	if candidate == nil {
		t.Fatal("real Recovery succession preparation refused", prepared)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if outcome := selected.Select(ctx, candidate); outcome.Outcome != ObservedCurrent {
		t.Fatal("real Recovery succession did not select", outcome)
	}
	fresh, opened := Open(ctx, admission, f.env.Store)
	if fresh == nil || fresh.root.WarningBits != 31 {
		t.Fatal("cold selected root lost permanent warnings", opened)
	}
	receipt, err := contract.InspectCompactMutationReceipt(checkSuccessionReceipt(t, ctx, fresh, permit))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.WarningBits != 124 {
		t.Fatalf("Recovery receipt lost inherited domain summary: got %d, want 124", receipt.WarningBits)
	}
}
