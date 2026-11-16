package core

import (
	"context"
	"fmt"
	"math"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestReaderReplacementRollsBindingIncarnationAtMaximumSerial(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, family, false)
			base := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: base.admission, session: base.session}
			reader := fixtureID(env.Domain, "reader")
			state := fixtureStateImage(t, f)
			for _, row := range state.Recipient.Slots {
				if row != nil && row.RecipientID == reader {
					row.CurrentBinding.BindingSerial = math.MaxUint64
				}
			}
			storeContractClosure(t, f, state)
			keys.SetCurrentBindingSerial(t, reader, math.MaxUint64)
			selected, result := Open(ctx, f.admission, f.store)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("signed maximum-serial state did not open", result)
			}
			before := *selected.recipientRecord(reader).CurrentBinding
			successor := keys.RecipientSuccessor(t, reader)
			if successor.BindingIncarnationID == before.BindingIncarnationID || successor.BindingSerial != 1 {
				t.Fatal("successor did not start a fresh binding incarnation")
			}
			permit := admitReaderReplacement(t, selected, keys, reader, successor)
			candidate, result := selected.PrepareRecipientReplacement(ctx, permit, env.Trust)
			if candidate == nil {
				t.Fatal("maximum-serial replacement preparation", result)
			}
			if result := selected.Select(ctx, candidate); result.Outcome != ObservedCurrent {
				t.Fatal("maximum-serial replacement selection", result)
			}
			keys.RetireAccess()
			next, result := Open(ctx, f.admission, f.store)
			if next == nil || result.Outcome != ObservedCurrent {
				t.Fatal("rolled binding did not reopen", result)
			}
			got := next.recipientRecord(reader).CurrentBinding
			if got == nil || got.BindingIncarnationID != successor.BindingIncarnationID || got.BindingSerial != 1 {
				t.Fatal("selected binding did not roll over")
			}
		})
	}
}
