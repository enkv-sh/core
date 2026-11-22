package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledRecipientRetirementUsesAuthenticatedSparsePredecessorSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	input := []ApplyEntryInput{{Name: "plain", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("ordinary predecessor")}}
	setup := f.engine(t, f.selected, input, nil)
	if result := setup.Apply(ctx, fixtureID(f.env.Domain, "sparse ordinary predecessor"), input); result.Result.Outcome != ObservedCurrent {
		t.Fatal(result.Result)
	}
	setup.Close()
	readerChangedRegistryFixture(t, ctx, f.env, f.open(t, ctx), f.env.Trust, false, true)
	selected := f.open(t, ctx)
	reader := fixtureID(f.env.Domain, "reader")
	slot, old := selected.selectedRecipientSlot(reader)
	if old == nil || slot < 5 {
		t.Fatal("cold authenticated sparse recipient setup absent")
	}
	called := false
	result := installedRetirementTestRun(t, ctx, f, selected, installedSecretAccessTestRef(t, selected, reader), "sparse recipient retirement", func(q contract.CryptoCompareRequest, independent uint16) {
		called = true
		body, err := contract.EncodeRecipientRecord(*old)
		if err != nil || q.Retirement == nil || q.Retirement.Slot != slot || independent != slot || q.Retirement.BeforeRecordDigest != contract.Hash(body) || q.Retirement.BeforeRecordLength != uint32(len(body)) {
			t.Fatal("physical predecessor slot/row changed at custody")
		}
	})
	closed := f.open(t, ctx)
	remainingSlot, remaining := closed.selectedRecipientSlot(selected.admission.recipient)
	if result.Result.Outcome != ObservedCurrent || !called || closed.recipientRecord(reader) != nil ||
		closed.root.RecipientCount != 1 || remaining == nil || remainingSlot != 0 {
		t.Fatal("actual sparse retirement did not select", result.Result)
	}
}
