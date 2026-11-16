package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRecipientReplacementPreservesFullWindowsAndInheritedWarnings(t *testing.T) {
	for _, condition := range []string{"both-full-windows", "inherited-warnings"} {
		t.Run(condition, func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			if condition == "both-full-windows" {
				seedBothFullReceiptWindows(t, env, f)
			} else {
				fixture := installedApplyTestFixture{env: env, keys: keys, admitted: f.admission, selected: f.session}
				f.session = seedInstalledApplyDomainWarnings(t, fixture, f.session, 31)
			}
			before, err := f.session.receiptWindows(ctx)
			if err != nil || condition == "both-full-windows" && (len(before.Successes) != 256 || len(before.Failures) != 256) {
				t.Fatal("complete prior windows did not authenticate", err)
			}
			reader := fixtureID(env.Domain, "reader")
			successor := keys.RecipientSuccessor(t, reader)
			permit := admitReaderReplacement(t, f.session, keys, reader, successor)
			defer keys.RetireAccess()
			candidate, result := f.session.PrepareRecipientReplacement(ctx, permit, env.Trust)
			if candidate == nil {
				t.Fatal("receipt-bearing Recipient preparation", result)
			}
			if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
				t.Fatal("receipt-bearing Recipient selection", result)
			}
			keys.RetireAccess()
			if err := keys.ActivateRecipientSuccessor(reader); err != nil {
				t.Fatal(err)
			}
			selected, result := Open(ctx, f.admission, env.Store)
			if selected == nil {
				t.Fatal("cold receipt-bearing Recipient selection", result)
			}
			body, result := selected.MutationReceipt(ctx, permit.plan.operation)
			if result.Outcome != ObservedCurrent {
				t.Fatal("new Recipient receipt missing", result)
			}
			row, err := contract.InspectCompactMutationReceipt(body)
			if err != nil || row.OperationKind != contract.OperationRotateRecipientKeyBinding {
				t.Fatal("new Recipient receipt operation", err)
			}
			want := append(slices.Clone(before.Successes), row)
			if len(want) > 256 {
				want = want[1:]
			}
			after, err := selected.receiptWindows(ctx)
			if err != nil || !slices.Equal(after.Successes, want) || !slices.Equal(after.Failures, before.Failures) {
				t.Fatal("Recipient replacement changed ordered window policy", err)
			}
			assertSuccessReceiptOrder(t, before, after, row.OperationID)
			for _, old := range append(slices.Clone(want[:len(want)-1]), before.Failures...) {
				wire, err := contract.EncodeCompactMutationReceipt(old)
				got, read := selected.MutationReceipt(ctx, old.OperationID)
				if err != nil || read.Outcome != ObservedCurrent || !bytes.Equal(got, wire) {
					t.Fatal("Recipient replacement changed retained old result bytes", err, read)
				}
			}
			if condition == "both-full-windows" {
				if got, read := selected.MutationReceipt(ctx, before.Successes[0].OperationID); got != nil || read.Outcome != AdmissionRefused {
					t.Fatal("Recipient replacement retained its own evicted oldest success", read)
				}
				found := false
				for _, page := range selected.support {
					if len(page.Records) != 512 || page.Records[0].Kind != contract.MutationReceiptSupportKind {
						continue
					}
					for _, ref := range selected.root.RequiredSupport {
						if ref.Index == page.Index && ref.Length == 260171 {
							found = true
						}
					}
				}
				if !found {
					t.Fatal("actual both-full receipt page lost its exact encoded bound")
				}
			} else if selected.root.WarningBits != 31 || row.WarningBits != 124 {
				t.Fatal("Recipient receipt lost inherited warnings")
			}
		})
	}
}
