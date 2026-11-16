package core

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func retirementExpectedRegistry(expected map[contract.ID]contract.RecipientRecord) []contract.RecipientRecord {
	rows := make([]contract.RecipientRecord, 0, len(expected))
	for _, row := range expected {
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	return rows
}

func retirementTurnoverOpen(t testing.TB, ctx context.Context, f installedApplyTestFixture, expected map[contract.ID]contract.RecipientRecord, retired map[contract.ID]bool) *StateSession {
	t.Helper()
	if ctx.Err() != nil {
		t.Fatal("recipient turnover cumulative budget expired")
	}
	admission, result := admitPublicNormal(ctx, f.env.Domain, f.env.Store.Descriptor(), f.basis, f.env.Store, f.composition, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal("recipient turnover fresh public admission", result)
	}
	selected, result := Open(ctx, admission, f.env.Store)
	if selected == nil {
		t.Fatal("recipient turnover cold selection", result)
	}
	want := retirementExpectedRegistry(expected)
	if selected.root.RecipientCount != uint16(len(want)) || !reflect.DeepEqual(selected.registry(), want) || selected.root.ChildCount > ordinaryChildPageLimit {
		t.Fatal("recipient turnover selected image differs from complete independent registry/capacity")
	}
	refs := 0
	for _, ref := range selected.root.Recipients {
		if ref != nil {
			refs++
		}
	}
	if refs != (len(want)+format.RecipientSlots-1)/format.RecipientSlots {
		t.Fatal("recipient turnover did not reclaim bounded registry pages")
	}
	for _, row := range selected.registry() {
		if retired[row.RecipientID] || row.Status != contract.CurrentRecipient || row.CurrentBinding == nil {
			t.Fatal("recipient turnover revived retired identity or kept a tombstone")
		}
	}
	return selected
}

// full_only: true
func TestRecipientTurnoverReusesFullRegistryFor1025ActualRetireEnrollCycles(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
	defer cancel()
	started := time.Now()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	store := f.env.Store.(*memoryStore)
	if err := store.useFileBodies(filepath.Join(t.TempDir(), "recipient-turnover-bodies")); err != nil {
		t.Fatal(err)
	}
	reader := fixtureID(f.env.Domain, "reader")
	resource := *f.selected.recipientRecord(reader)
	desired := currentApplyRecipients(f.selected.registry())
	// Every initial additional row is admitted in one real complete Apply.
	for i := len(desired); i < contract.CryptoMaxRecipients; i++ {
		prepared := installedRetirementReenrollment(t, f.selected, resource, fmt.Sprintf("initial full registry recipient %03d", i))
		at := slices.IndexFunc(prepared, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
		desired = append(desired, prepared[at])
	}
	slices.SortFunc(desired, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	initial := f.engineWithRecipients(t, f.selected, nil, desired, nil)
	operation, done := context.WithTimeout(ctx, 2*time.Minute)
	initialResult := initial.Apply(operation, fixtureID(f.env.Domain, "fill full recipient registry"), nil)
	done()
	initial.Close()
	if initialResult.Result.Outcome != ObservedCurrent {
		t.Fatal("actual initial full registry selection", initialResult.Result)
	}
	expected := make(map[contract.ID]contract.RecipientRecord, contract.CryptoMaxRecipients)
	for _, row := range desired {
		expected[row.Recipient.RecipientID] = row.Recipient
	}
	retired := make(map[contract.ID]bool, 1025)
	selected := retirementTurnoverOpen(t, ctx, f, expected, retired)
	if len(expected) != 256 || selected.root.RecipientCount != 256 {
		t.Fatal("turnover did not start at Authority plus 255 ordinary recipients")
	}
	firstCAS := store.cas
	_, private := f.keys.Calls()
	rotating := reader
	for cycle := range 1025 {
		if ctx.Err() != nil {
			t.Fatal("recipient turnover cumulative deadline", cycle)
		}
		old := expected[rotating]
		operation, done := context.WithTimeout(ctx, 2*time.Minute)
		result := installedRetirementTestRun(t, operation, f, selected, installedSecretAccessTestRef(t, selected, rotating), fmt.Sprintf("turnover retire %04d", cycle), nil)
		done()
		if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 1 || store.cas != firstCAS+cycle*2+1 {
			t.Fatal("real full-registry retirement did not select exactly once", cycle, result.Result)
		}
		delete(expected, rotating)
		retired[rotating] = true
		selected = retirementTurnoverOpen(t, ctx, f, expected, retired)
		if selected.root.RecipientCount != 255 || selected.root.ValueEntryCount != 0 || selected.root.AccessRecordCount != 0 {
			t.Fatal("retirement did not release exactly one current row without private material", cycle)
		}
		prepared := installedRetirementReenrollment(t, selected, old, fmt.Sprintf("turnover fresh enrollment %04d", cycle))
		at := slices.IndexFunc(prepared, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
		fresh := prepared[at].Recipient
		if fresh.RecipientID == rotating || retired[fresh.RecipientID] || fresh.CurrentBinding.BindingID == old.CurrentBinding.BindingID || fresh.CurrentBinding.BindingIncarnationID == old.CurrentBinding.BindingIncarnationID || fresh.CurrentBinding.BindingSerial != 1 || fresh.DisplayName != old.DisplayName || fresh.CurrentBinding.KeySelector != old.CurrentBinding.KeySelector || !bytes.Equal(fresh.CurrentBinding.SPKI, old.CurrentBinding.SPKI) {
			t.Fatal("same-resource enrollment reused identity/binding or changed public resource", cycle)
		}
		engine := f.engineWithRecipients(t, selected, nil, prepared, nil)
		operation, done = context.WithTimeout(ctx, 2*time.Minute)
		result = engine.Apply(operation, fixtureID(f.env.Domain, fmt.Sprintf("turnover enroll %04d", cycle)), nil)
		done()
		engine.Close()
		if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 1 || store.cas != firstCAS+cycle*2+2 {
			t.Fatal("real full-registry enrollment did not select exactly once", cycle, result.Result)
		}
		expected[fresh.RecipientID] = fresh
		selected = retirementTurnoverOpen(t, ctx, f, expected, retired)
		rotating = fresh.RecipientID
	}
	_, privateAfter := f.keys.Calls()
	if store.cas-firstCAS != 2050 || len(retired) != 1025 || len(expected) != 256 || privateAfter != private {
		t.Fatal("actual turnover CAS/identity/private-use totals differ", store.cas-firstCAS, len(retired), privateAfter-private)
	}
	windows, err := selected.receiptWindows(ctx)
	if err != nil || len(windows.Successes) != contract.MutationReceiptWindowLimit || len(windows.Failures) != 0 {
		t.Fatal("turnover receipt windows did not remain bounded", err)
	}
	// The child receives independent expected rows and only authenticated source
	// basis, object facts and immutable file references, with no in-process state.
	input := selectedProcessFacts(t, OpenContext{admission: &selected.admission}, selected)
	input.ExpectedRecipients = retirementExpectedRegistry(expected)
	compactFreshProcessWork(&input)
	input.WriterObjects = make(map[string]generatedWriterObject, len(store.objects))
	for key, object := range store.objects {
		input.WriterObjects[key] = generatedWriterObjectFacts(object)
	}
	checkFreshProcessInputContext(ctx, t, input)
	t.Logf("recipient turnover completed: cycles=1025 canonical_selections=2050 current_rows=256 elapsed=%s immutable_objects=%d immutable_body_bytes=%d", time.Since(started), len(store.objects), store.fileBodies.used)
}
