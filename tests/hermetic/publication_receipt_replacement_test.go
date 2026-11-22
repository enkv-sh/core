package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestKeyReplacementKeepsSelectedPublicationAndSecret(t *testing.T) {
	for _, target := range []ReplacementTarget{ReplacementTargetRecipient, ReplacementTargetRecovery} {
		t.Run(map[ReplacementTarget]string{ReplacementTargetRecipient: "recipient", ReplacementTargetRecovery: "recovery"}[target], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env := memoryScenarioEnvironmentMode(t, true)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			reader := fixtureID(env.Domain, "reader")
			recipients := []contract.ID{f.session.admission.recipient, reader}
			slices.SortFunc(recipients, compareGeneratedIDs)
			entries := []ApplyEntryInput{sharingSecret(t, env, "shared for key replacement", recipients)}
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{outputConfigurationTarget(entries[0].Name, "selected-slot")}}}}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
			before, err := selectedPublicationRelation(f.session.selectedImage())
			if err != nil || len(before.coordinates) != 1 {
				t.Fatal("expected one selected output coordinate", err)
			}
			checkPages := func(s *StateSession) {
				t.Helper()
				var coordinates, receipts int
				for _, page := range s.support {
					hasCoordinate, hasReceipt := false, false
					for _, row := range page.Records {
						if row.Kind == contract.PublicationCoordinateSupportKind {
							coordinates++
							hasCoordinate = true
						}
						if row.Kind == contract.MutationReceiptSupportKind {
							receipts++
							hasReceipt = true
						}
					}
					if hasCoordinate && hasReceipt {
						t.Fatal("stock writer combined a receipt with a coordinate")
					}
				}
				if coordinates != 1 || receipts == 0 {
					t.Fatal("fixture lacks the selected coordinate or receipt")
				}
			}
			checkPages(f.session)
			original := sessionConsumerSelection(t, f.session, reader, entries[0].Name)
			if check := env.Custody.Consume(ctx, original, custody.StandardValue); !check.ValueMatched || check.Code != contract.CryptoSuccess {
				t.Fatal("fixture reader could not read the original secret")
			}
			var mask uint8
			if target == ReplacementTargetRecovery {
				mask = contract.SuccessionChangeRecoveryKEK
			}
			h := installedReplacementForCurrent(t, env, f, target, mask, contract.NormalSigningRole, ReplacementMaterialAuthority)
			if target == ReplacementTargetRecipient {
				env.Custody.LoseRecipientPredecessor(reader)
				if check := env.Custody.Consume(ctx, original, custody.StandardValue); check.Code == contract.CryptoSuccess || check.ValueMatched {
					t.Fatal("lost reader key remained usable")
				}
			}
			e := h.engine(t)
			out := e.Replace(ctx, fixtureID(env.Domain, "replace encryption key"))
			e.Close()
			if out.Result.Outcome != ObservedCurrent || h.delivered != 1 || len(out.Receipt) == 0 {
				t.Fatal("replacement did not deliver its successor and receipt", out.Result.Outcome, out.Result.Reason,
					"resolvers", h.publicCalls, "signers", h.signerFactories, "custody", h.custodyFactories, "deliveries", h.delivered)
			}
			admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), h.output.Basis, env.Store,
				h.installation.CompositionID, f.session.admission.outputInterpreter)
			if result.Outcome != ObservedCurrent {
				t.Fatal(result)
			}
			after, result := Open(ctx, admitted, env.Store)
			if after == nil || result.Outcome != ObservedCurrent {
				t.Fatal("cold replacement open", result)
			}
			checkPages(after)
			receipt, result := after.MutationReceipt(ctx, out.OperationID)
			if result.Outcome != ObservedCurrent || !bytes.Equal(receipt, out.Receipt) {
				t.Fatal("cold open lost the replacement receipt", result)
			}
			current, err := selectedPublicationRelation(after.selectedImage())
			if err != nil || !reflect.DeepEqual(current, before) {
				t.Fatal("replacement changed the selected publication", err)
			}
			next := sessionConsumerSelection(t, after, reader, entries[0].Name)
			if !reflect.DeepEqual(next.Entry, original.Entry) {
				t.Fatal("replacement changed the selected value")
			}
			if target == ReplacementTargetRecipient {
				if next.Binding.Binding.BindingID == original.Binding.Binding.BindingID ||
					next.Binding.Binding.KeySelector != h.goal.EncryptionSelector {
					t.Fatal("cold open lost the expected recipient binding")
				}
				if err := env.Custody.ActivateRecipientSuccessor(reader); err != nil {
					t.Fatal(err)
				}
			}
			if check := env.Custody.Consume(ctx, next, custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched {
				t.Fatal("cold reader could not read the same secret")
			}
		})
	}
}
