package crypto

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// full_only: false
func TestGeneratedSuppliedCurrentAuthenticatesBeforeEquality(t *testing.T) {
	for _, name := range []string{"equal", "unequal", "bad-data-key", "bad-commitment-key", "bad-package-check", "bad-ciphertext", "bad-semantic-commitment", "bad-payload-context", "bad-packet-context", "cancelled", "unavailable", "unknown"} {
		t.Run(name, func(t *testing.T) {
			a, carriers, declaration, route := generatedSuppliedCollectionFixture(t, 1)
			t.Cleanup(a.clear)
			input := carriers[0].Selection
			switch name {
			case "bad-package-check":
				input.Payload.PackageCheck[0] ^= 1
			case "bad-ciphertext":
				input.Payload.Ciphertext[0] ^= 1
			case "bad-semantic-commitment":
				input.Payload.SemanticCommitment[0] ^= 1
			case "bad-payload-context":
				private := route.testKeyAccess.Decrypt(t.Context(), input.Binding.Binding, input.Access.Wraps[0].RSACiphertext, contract.ValueMaterialPacketLength)
				if private.Status != KeyOK {
					t.Fatal("fixture original packet did not open")
				}
				keys := bytes.Clone(private.Packet[len(private.Packet)-64:])
				clear(private.Packet[:cap(private.Packet)])
				defer clear(keys[:cap(keys)])
				input.Payload.DataKeyID[0] ^= 1
				input.Core.DataKeyID = input.Payload.DataKeyID
				var err error
				input.Payload.PackageCheck, err = custody.PackageCheck(input.Core, keys)
				if err != nil {
					t.Fatal(err)
				}
				input.Access.Wraps = slices.Clone(input.Access.Wraps)
				for i, wrap := range input.Access.Wraps {
					binding := a.bindings[slices.IndexFunc(a.bindings, func(binding contract.BindingTableRow) bool { return binding.Binding.BindingID == wrap.BindingID })]
					core, err := custody.ValueWrapCore(input.Core, binding)
					if err != nil {
						t.Fatal(err)
					}
					input.Access.MaterialContextDigest = core.MaterialContextDigest
					input.Access.Wraps[i], err = custody.Wrap(core, binding.Binding, keys)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			input.Access.PackageCheck = input.Payload.PackageCheck
			refreshConsumerSelection(t, &input)
			index := slices.IndexFunc(a.before.Rows, func(row contract.PublicStateRow) bool { return row.Slot == input.Slot })
			a.before.Rows[index].EntryDigest = input.EntryDigest
			a.purpose.output.EntriesBefore[index].EntryDigest = input.EntryDigest
			body, err := contract.EncodeValueEntry(input.Entry)
			if err != nil {
				t.Fatal(err)
			}
			a.purpose.output.EntryBodies[index] = body
			if err := a.purpose.output.Inspect(a.before); err != nil {
				t.Fatal("altered stored payload lost exact public witness", err)
			}
			if !a.admitCurrentValues([]contract.ConsumerSelection{input}, declaration) {
				t.Fatal("exact current selection refused")
			}
			selected := &a.purpose.final.plan.currentValues[0]
			privateCalls := route.privateCalls
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
				private := route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
				if private.Status != KeyOK {
					t.Fatal("fixture current packet did not open")
				}
				switch name {
				case "bad-data-key":
					private.Packet[len(private.Packet)-64] ^= 1
				case "bad-commitment-key":
					private.Packet[len(private.Packet)-32] ^= 1
				case "bad-packet-context":
					private.Packet[4] ^= 1
				case "cancelled":
					cancel()
				case "unavailable":
					private.Status, private.Uses = KeyUnavailable, KeyUses{Unknown: 1}
				case "unknown":
					private.Status, private.Uses = KeyUnknown, KeyUses{Unknown: 1}
				}
				return private
			}
			before := len(a.purpose.final.plan.currentValues)
			graph := a.graph.UsePlan
			plain := []byte("old")
			want := contract.CryptoStoredAuthenticationFailed
			switch name {
			case "equal":
				want = contract.CryptoSuccess
			case "unequal":
				plain, want = []byte("new"), contract.CryptoInvalidAdmission
			case "cancelled":
				want = contract.CryptoCancelled
			case "unavailable":
				want = contract.CryptoCustodyUnavailable
			case "unknown":
				want = contract.CryptoResponseUnknown
			}
			var reply contract.CryptoResponse
			if got := a.compareSuppliedCurrent(ctx, route, selected.Entry.Name, plain, &reply); got != want {
				t.Errorf("comparison result=%v want=%v", got, want)
			}
			if reply.Body != nil || len(a.purpose.final.plan.currentValues) != before || !reflect.DeepEqual(a.graph.UsePlan, graph) {
				t.Error("comparison changed admitted work or returned output")
			}
			binding := selected.Binding
			digest, err := contract.PublicBindingDigest(binding.Binding)
			if err != nil {
				t.Fatal(err)
			}
			outcome := uint8(contract.KeyUseCompleted)
			if name == "unknown" || name == "unavailable" {
				outcome = contract.KeyUseUnknown
			}
			wantUses := []contract.KeyUseRow{{BindingID: binding.Binding.BindingID, PublicBindingDigest: digest, SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, Provider: binding.Binding.Provider, Purpose: contract.KeyUseMaterialOpen, Outcome: outcome, Count: 1}}
			if !reflect.DeepEqual(reply.KeyUseRows, wantUses) {
				t.Error("comparison lost exact private-open evidence", reply.KeyUseRows)
			}
			if route.privateCalls != privateCalls+1 || len(route.returned) <= int(contract.ValueMaterialPacketLength) || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Error("comparison did not open once and dispose complete private packet capacity")
			}
		})
	}
}

// full_only: false
func TestGeneratedSuppliedCurrentRejectsChangedSelectedBindingBeforePrivateWork(t *testing.T) {
	a, carriers, declaration, route := generatedSuppliedCollectionFixture(t, 1)
	t.Cleanup(a.clear)
	selected := carriers[0].Selection
	selected.Binding.Binding.BindingSerial++
	if a.admitCurrentValues([]contract.ConsumerSelection{selected}, declaration) {
		t.Fatal("changed selected current binding admitted")
	}
	if route.privateCalls != 0 || route.publicCalls != 0 || len(a.purpose.final.plan.currentValues) != 0 {
		t.Fatal("changed binding reached private work or changed admitted values")
	}
}
