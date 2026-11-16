package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func installedApplyPreparedRecipient(t testing.TB, selected *StateSession, label string) []contract.ApplyRecipientInput {
	t.Helper()
	rows := currentApplyRecipients(selected.registry())
	reader := slices.IndexFunc(rows, func(row contract.ApplyRecipientInput) bool {
		return row.Recipient.RecipientID != selected.admission.recipient
	})
	if reader < 0 {
		t.Fatal("recipient creation requires an existing reusable public resource")
	}
	nonce := fixtureID(selected.root.Domain, label)
	recipient, err := contract.RecipientCreationID(selected.root.Domain, selected.root.Snapshot, nonce)
	if err != nil {
		t.Fatal(err)
	}
	binding, incarnation, err := contract.RecipientInitialBindingIDs(selected.root.Domain, recipient)
	if err != nil {
		t.Fatal(err)
	}
	key := *rows[reader].Recipient.CurrentBinding
	key.BindingID, key.BindingIncarnationID, key.BindingSerial = binding, incarnation, 1
	rows = append(rows, contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: recipient, Status: contract.CurrentRecipient, DisplayName: "created unassigned", CurrentBinding: &key}, Creation: &contract.RecipientCreationProof{Snapshot: selected.root.Snapshot, Nonce: nonce}})
	slices.SortFunc(rows, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	return rows
}

func installedApplyPriorRecoverySuccession(t *testing.T, ctx context.Context, f installedApplyTestFixture) installedApplyTestFixture {
	t.Helper()
	selected := f.selected
	encoded, err := contract.EncodeControlCore(currentControlOf(selected))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(encoded)
	if err != nil {
		t.Fatal(err)
	}
	successor, binding := f.env.Recovery.(*testtrust.Signer).Successor(t, after.Recovery.Signing)
	after.Recovery.Signing, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, selected, f.keys, after, contract.SuccessionReplaceRecoveryBasis, contract.NormalSigningRole, contract.SuccessionChangeRecoverySigner, contract.BindingTableRow{})
	candidate, result := selected.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: f.env.Trust, RecoverySuccessor: successor})
	if candidate == nil {
		t.Fatal("prior actual succession", result)
	}
	admitted := deliverSuccessionBasis(t, candidate)
	if result := selected.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("prior succession selection", result)
	}
	f.admitted = admitted
	f.basis = admitted.admission.publicBasis()
	f.selected = f.open(t, ctx)
	return f
}

// full_only: false
func TestInstalledApplyUnassignedCreationDisplayAndRepeatSurviveColdOpen(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, prior := range []string{"genesis", "recovery", "signer", "recipient"} {
			t.Run(fmt.Sprintf("%d/prior-%s", family, prior), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f := newInstalledApplyTestFixture(t, ctx, family, true)
				switch prior {
				case "recovery":
					f = installedApplyPriorRecoverySuccession(t, ctx, f)
				case "signer":
					f = installedApplyPriorSignerSuccession(t, ctx, f)
				case "recipient":
					f = installedApplyPriorRecipientReplacement(t, ctx, f)
				}
				desired := installedApplyPreparedRecipient(t, f.selected, "fresh recipient nonce")
				var stages []contract.CryptoKind
				engine := f.engineWithRecipients(t, f.selected, nil, desired, func(kind contract.CryptoKind) { stages = append(stages, kind) })
				result := engine.Apply(ctx, fixtureID(f.env.Domain, "create unassigned recipient"), nil)
				engine.Close()
				if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 1 || !slices.Contains(stages, contract.CryptoCompare) {
					t.Fatal("unassigned creation did not select one complete qualified recipient", result.Result, stages)
				}
				selected := f.open(t, ctx)
				expected := make([]contract.RecipientRecord, len(desired))
				for i, row := range desired {
					expected[i] = row.Recipient
				}
				if !reflect.DeepEqual(selected.registry(), expected) || selected.root.ValueEntryCount != 0 || selected.root.SecretCount != 0 {
					t.Fatal("cold creation registry differs")
				}
				run := func(label string, rows []contract.ApplyRecipientInput) PublicApplyResult {
					engine := f.engineWithRecipients(t, selected, nil, rows, nil)
					result := engine.Apply(ctx, fixtureID(f.env.Domain, label), nil)
					engine.Close()
					return result
				}
				repeat := run("repeat original creation", desired)
				if repeat.Result.Outcome != Unchanged {
					t.Fatal("current creation proof did not resolve exact current row", repeat.Result)
				}
				changed := slices.Clone(desired)
				index := slices.IndexFunc(changed, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
				changed[index].Recipient.DisplayName = "changed unassigned display"
				metadata := run("unassigned display change", changed)
				if metadata.Result.Outcome != ObservedCurrent || metadata.Payload == nil || metadata.Payload.ChangedSubjects.Count != 1 {
					t.Fatal("display-only apply did not select one recipient", metadata.Result)
				}
				selected = f.open(t, ctx)
				expected[index].DisplayName = "changed unassigned display"
				if !reflect.DeepEqual(selected.registry(), expected) {
					t.Fatal("cold metadata registry differs")
				}
				if repeat := run("repeat unassigned display", changed); repeat.Result.Outcome != Unchanged {
					t.Fatal("display repeat selected work", repeat.Result)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledApplyDisplayPreservesEncryptedRecordsAndValidatesUnchangedSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	input := []ApplyEntryInput{suppliedSecret(t, f.env, "secret", "metadata private validation", custody.StandardValue, f.selected.admission.recipient)}
	first := f.engine(t, f.selected, input, nil)
	baseline := first.Apply(ctx, fixtureID(f.env.Domain, "metadata secret baseline"), input)
	first.Close()
	if baseline.Result.Outcome != ObservedCurrent {
		t.Fatal("secret metadata baseline", baseline.Result)
	}
	selected := f.open(t, ctx)
	before := sessionConsumerSelection(t, selected, selected.admission.recipient, "secret")
	beforeEntry, err := contract.EncodeValueEntry(before.Entry)
	if err != nil {
		t.Fatal(err)
	}
	beforeAccess, err := contract.EncodeAccessRecord(before.Access)
	if err != nil {
		t.Fatal(err)
	}
	desired := currentApplyRecipients(selected.registry())
	desired[0].Recipient.DisplayName = "display after unchanged sealed source"
	source := bytes.Clone(input[0].InputBytes)
	engine := f.engineWithRecipients(t, selected, input, desired, nil)
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "metadata with unchanged secret"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 1 {
		t.Fatal("secret metadata change did not select", result.Result)
	}
	fresh := f.open(t, ctx)
	after := sessionConsumerSelection(t, fresh, fresh.admission.recipient, "secret")
	afterEntry, err := contract.EncodeValueEntry(after.Entry)
	if err != nil {
		t.Fatal(err)
	}
	afterAccess, err := contract.EncodeAccessRecord(after.Access)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeEntry, afterEntry) || !bytes.Equal(beforeAccess, afterAccess) || !bytes.Equal(source, input[0].InputBytes) {
		t.Fatal("metadata changed encrypted entry, access or source")
	}
	store := f.env.Store.(*memoryStore)
	creates, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
	desired[0].Recipient.DisplayName = "must fail private validation"
	f.keys.SetDenied(fresh.admission.recipient, true)
	engine = f.engineWithRecipients(t, fresh, input, desired, nil)
	refused := engine.Apply(ctx, fixtureID(f.env.Domain, "metadata private source failure"), input)
	engine.Close()
	if refused.Result.Outcome == ObservedCurrent || refused.Result.Outcome == Unchanged || store.creates != creates || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs {
		t.Fatal("display-only path bypassed unchanged secret private validation", refused.Result)
	}
}

func installedApplyPriorSignerSuccession(t *testing.T, ctx context.Context, f installedApplyTestFixture) installedApplyTestFixture {
	t.Helper()
	selected := f.selected
	body, err := contract.EncodeControlCore(currentControlOf(selected))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(body)
	if err != nil {
		t.Fatal(err)
	}
	successor, binding := f.env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
	after.NormalSigning, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, selected, f.keys, after, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
	candidate, result := selected.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: f.env.Trust, NormalSuccessor: successor})
	if candidate == nil {
		t.Fatal("prior signer succession", result)
	}
	admitted := deliverSuccessionBasis(t, candidate)
	if result := selected.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("prior signer selection", result)
	}
	f.env.Trust = successor
	f.admitted, f.basis = admitted, admitted.admission.publicBasis()
	f.selected = f.open(t, ctx)
	return f
}

func installedApplyPriorRecipientReplacement(t *testing.T, ctx context.Context, f installedApplyTestFixture) installedApplyTestFixture {
	t.Helper()
	selected := f.selected
	recipient := fixtureID(f.env.Domain, "reader")
	binding := f.keys.RecipientSuccessor(t, recipient)
	permit := admitReaderReplacement(t, selected, f.keys, recipient, binding)
	candidate, result := selected.PrepareRecipientReplacement(ctx, permit, f.env.Trust)
	if candidate == nil {
		t.Fatal("prior recipient replacement", result)
	}
	if result := selected.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("prior recipient selection", result)
	}
	f.keys.RestoreRecipientSuccessor(t, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: recipient, Binding: binding})
	f.keys.RetireAccess()
	f.selected = f.open(t, ctx)
	return f
}
