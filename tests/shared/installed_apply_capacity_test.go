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
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// The history is a trusted signed prior-state fixture, not a claim that its
// 512 operations ran here. Init and every new public result use real owners.
func installedApplyFullWindows(t *testing.T, ctx context.Context) (installedApplyTestFixture, contract.MutationReceiptWindows) {
	t.Helper()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.Context = ctx
	input := []ApplyEntryInput{{Name: "alpha", Recipients: []contract.ID{f.selected.admission.recipient},
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("before")}}
	first := f.engine(t, f.selected, input, nil)
	result := first.Apply(ctx, fixtureID(f.env.Domain, "capacity first public apply"), input)
	first.Close()
	if result.Result.Outcome != ObservedCurrent || len(result.Receipt) == 0 {
		t.Fatal("real first public apply did not select receipt support", result.Result)
	}
	f.selected = f.open(t, ctx)
	selected := &environmentFixture{admission: f.admitted, session: f.selected}
	windows := seedBothFullReceiptWindows(t, f.env, selected)
	f.selected = f.open(t, ctx)
	actual, err := f.selected.receiptWindows(ctx)
	if err != nil || !reflect.DeepEqual(actual, windows) || len(f.selected.adminIndex.Groups) != 0 {
		t.Fatal("both full prior-state windows did not authenticate", err)
	}
	return f, windows
}

func assertInstalledApplyWindowAppend(t *testing.T, ctx context.Context, selected *StateSession, before contract.MutationReceiptWindows, result PublicApplyResult) {
	t.Helper()
	if result.Result.Outcome != ObservedCurrent || result.OperationID.IsZero() || result.RequestIdentity.IsZero() || result.Payload == nil {
		t.Fatal("real public apply did not select its complete result", result.Result)
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.OperationID != result.OperationID ||
		receipt.RequestIdentityDigest != result.RequestIdentity || receipt.StateResult != contract.ReceiptStateSuccess ||
		receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.EffectSummary != contract.ReceiptEffectNoChange ||
		receipt.RequestedRevisionID != selected.head.Core.Revision || receipt.ObservedRevisionID != selected.head.Core.Revision {
		t.Fatal("selected public apply receipt differs", err)
	}
	after, err := selected.receiptWindows(ctx)
	want := append(slices.Clone(before.Successes[1:]), receipt)
	if err != nil || len(after.Successes) != contract.MutationReceiptWindowLimit || len(after.Failures) != contract.MutationReceiptWindowLimit ||
		!reflect.DeepEqual(after.Successes, want) || !reflect.DeepEqual(after.Failures, before.Failures) {
		t.Fatal("public apply changed history beyond the exact success append and eviction", err)
	}
	assertSuccessReceiptOrder(t, before, after, result.OperationID)
	if got, read := selected.MutationReceipt(ctx, result.OperationID); read.Outcome != ObservedCurrent || !bytes.Equal(got, result.Receipt) {
		t.Fatal("fresh current receipt lookup changed actual public result", read)
	}
	if got, read := selected.MutationReceipt(ctx, before.Successes[0].OperationID); got != nil || read != refused(AdmissionInvalid) {
		t.Fatal("oldest success remained available after own-window eviction", read)
	}
	for _, row := range []contract.CompactMutationReceipt{before.Successes[1], before.Failures[0], before.Failures[len(before.Failures)-1]} {
		want, err := contract.EncodeCompactMutationReceipt(row)
		got, read := selected.MutationReceipt(ctx, row.OperationID)
		if err != nil || read.Outcome != ObservedCurrent || !bytes.Equal(got, want) {
			t.Fatal("retained prior result bytes changed", err, read)
		}
	}
	if _, read := selected.currentOutputConfigurationForApply(ctx); read.Outcome != 0 || selected.root.OutputConfiguration.BindingCount != 0 {
		t.Fatal("receipt append lost empty mandatory output configuration", read)
	}
	fragments, err := selected.selectedFragmentFactsByRecord()
	if err != nil || len(fragments) != len(selected.root.Generated.Fragments)+int(selected.root.OutputConfiguration.SliceCount) || !selected.adminIndex.Valid() {
		t.Fatal("receipt append lost authenticated fragment facts or administrative index", err)
	}
}

// full_only: false
func TestInstalledApplyBothFullReceiptWindowsAppendAndNoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, before := installedApplyFullWindows(t, ctx)
	store := requireAdmittedMemoryStore(t, f.env.Store)
	input := []ApplyEntryInput{{Name: "alpha", Recipients: []contract.ID{f.selected.admission.recipient},
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("before")}}
	creates, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
	root, token := f.selected.head.Core.Root, f.selected.token
	var stages []contract.CryptoKind
	noop := f.engine(t, f.selected, input, func(kind contract.CryptoKind) { stages = append(stages, kind) })
	result := noop.Apply(ctx, fixtureID(f.env.Domain, "full window public noop"), input)
	noop.Close()
	if result.Result.Outcome != Unchanged || result.Payload != nil || len(result.Receipt) != 0 || result.OperationID.IsZero() || result.RequestIdentity.IsZero() ||
		store.creates != creates || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs || len(stages) != 0 {
		t.Fatal("full-window no-op consumed history or mutation authority", result.Result)
	}
	selected := f.open(t, ctx)
	after, err := selected.receiptWindows(ctx)
	if err != nil || !reflect.DeepEqual(after, before) || selected.head.Core.Root != root || selected.token != token {
		t.Fatal("full-window no-op changed its selected predecessor", err)
	}
	input[0].InputBytes = []byte("after")
	changed := f.engine(t, selected, input, func(kind contract.CryptoKind) { stages = append(stages, kind) })
	result = changed.Apply(ctx, fixtureID(f.env.Domain, "full window public append"), input)
	changed.Close()
	if len(stages) != 0 {
		t.Fatal("plain receipt append entered private custody")
	}
	assertInstalledApplyWindowAppend(t, ctx, f.open(t, ctx), before, result)
}

// Sparse Access pages are legal selected input. This fixture keeps every genuine
// material, packet and digest from a real public Apply; only page partitioning
// changes. The existing signed prior-state owner authenticates the new refs.
func installedApplySparseAccess(t *testing.T, ctx context.Context, f installedApplyTestFixture, source *StateSession, count int, windows contract.MutationReceiptWindows) installedApplyTestFixture {
	t.Helper()
	records := source.accessRecords()
	if count < 1 || count > len(records) || count > contract.MaxChildPages || count+int(source.root.CurrentAccess.Core.RecipientRefsDescriptor.Count) > contract.MaxChildPages {
		t.Fatal("sparse access fixture exceeds existing ref or material bounds")
	}
	store := cloneCheckpointStore(requireAdmittedMemoryStore(t, f.env.Store))
	f.env.Store = store
	f.env.Put = func(_ context.Context, key string, body []byte) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.putSelected(key, body)
	}
	bad := *source
	bad.root.CurrentAccess.Core.AccessPageRefs = nil
	bad.access = [contract.MaxChildPages]*format.AccessPage{}
	remaining := records
	for i := 0; i < count; i++ {
		n := 1
		if len(remaining) > count-i {
			n++
		}
		page := format.AccessPage{Domain: source.root.Domain, Object: fixtureID(source.root.Domain, fmt.Sprintf("sparse actual access/%d/%d", count, i)), Index: uint16(i), Records: slices.Clone(remaining[:n])}
		remaining = remaining[n:]
		body, err := format.EncodeAccessPage(page)
		if err != nil {
			t.Fatal("genuine sparse access page", err)
		}
		ref, err := format.Reference(contract.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		bad.access[i] = &page
		bad.root.CurrentAccess.Core.AccessPageRefs = append(bad.root.CurrentAccess.Core.AccessPageRefs, ref)
		store.put(mustKey(t, store.desc.Prefix, ref), body)
	}
	if len(remaining) != 0 {
		t.Fatal("sparse access partition omitted genuine records")
	}
	bad.root.CurrentAccess.Core.AccessGeneration++
	var err error
	bad.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(bad.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("genuine sparse access refs exceed current-access grammar", err)
	}
	bad.head.Subject.AfterAccessRoot = bad.root.CurrentAccess.AccessRoot
	selected := &environmentFixture{admission: f.admitted, session: &bad}
	seedSignedReceiptWindows(t, f.env, selected, mutationReceiptFixtureStorage(t, windows))
	f.selected = f.open(t, ctx)
	if len(f.selected.root.CurrentAccess.Core.AccessPageRefs) != count || !reflect.DeepEqual(f.selected.accessRecords(), records) {
		t.Fatal("authenticated sparse baseline changed material facts")
	}
	return f
}

// full_only: false
func TestInstalledApplyReceiptReservationKeepsExactChildBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	f, _ := installedApplyFullWindows(t, ctx)
	const members = 240
	const valuePages = members / format.PageSlots
	other := int(f.selected.root.ChildCount) - 1 // replace the one plain page
	maximumAccessPages := int(ordinaryChildPageLimit) - other - valuePages
	if maximumAccessPages < 2 || maximumAccessPages > members || maximumAccessPages+int(f.selected.root.CurrentAccess.Core.RecipientRefsDescriptor.Count) > contract.MaxChildPages {
		t.Fatal("existing ref bounds do not permit the proposed sparse boundary")
	}
	input := make([]ApplyEntryInput, members)
	authority := f.selected.admission.recipient
	for i := range input {
		name := fmt.Sprintf("secret-%03d", i)
		input[i] = suppliedSecret(t, f.env, name, "sparse public "+name, custody.EmptyValue, authority)
	}
	initial := f.engine(t, f.selected, input, nil)
	result := initial.Apply(ctx, fixtureID(f.env.Domain, "sparse actual public material"), input)
	initial.Close()
	if result.Result.Outcome != ObservedCurrent || len(result.Receipt) == 0 {
		t.Fatal("real public material prerequisite", result.Result)
	}
	source := f.open(t, ctx)
	if source.root.SecretCount != members || len(source.root.Names) != members || int(source.root.ChildCount)-len(source.root.CurrentAccess.Core.AccessPageRefs)-valuePages != other {
		t.Fatal("real material prerequisite changed the derived nonaccess budget")
	}
	windows, err := source.receiptWindows(ctx)
	if err != nil || len(windows.Successes) != 256 || len(windows.Failures) != 256 {
		t.Fatal("real material prerequisite lost full history", err)
	}
	for _, fits := range []bool{true, false} {
		t.Run(fmt.Sprintf("fits=%t", fits), func(t *testing.T) {
			pages := maximumAccessPages
			if fits {
				pages--
			}
			current := installedApplySparseAccess(t, ctx, f, source, pages, windows)
			selected := current.selected
			wantChildren := uint32(ordinaryChildPageLimit)
			if fits {
				wantChildren--
			}
			if selected.root.ChildCount != wantChildren {
				t.Fatal("authenticated predecessor missed exact adjacent boundary", selected.root.ChildCount, wantChildren)
			}
			var desired []ApplyEntryInput
			for _, named := range selected.root.Names {
				entry := selected.valueEntry(named.Slot)
				desired = append(desired, ApplyEntryInput{Name: entry.Name, Recipients: slices.Clone(entry.Recipients), ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret,
					Retained: &contract.RetainedSecretInput{Incarnation: entry.Incarnation, Material: entry.ValueState}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			}
			desired = append(desired, ApplyEntryInput{Name: "zz-new-plain", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("next page"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			store := requireAdmittedMemoryStore(t, current.env.Store)
			creates, cas, signs := store.creates, store.cas, current.env.Trust.(*fixtureTrust).signs
			root, token := selected.head.Core.Root, selected.token
			var stages []contract.CryptoKind
			engine := current.engine(t, selected, desired, func(kind contract.CryptoKind) { stages = append(stages, kind) })
			result := engine.Apply(ctx, fixtureID(f.env.Domain, fmt.Sprintf("sparse boundary request/%t", fits)), desired)
			engine.Close()
			if !slices.Contains(stages, contract.CryptoCompare) {
				t.Fatal("sparse boundary did not authenticate exact retained input")
			}
			if fits {
				if !slices.Contains(stages, contract.CryptoPrepare) || !slices.Contains(stages, contract.CryptoFreeze) || !slices.Contains(stages, contract.CryptoClaim) {
					t.Fatal("adjacent fitting transition missed complete custody admission")
				}
				after := current.open(t, ctx)
				if after.root.ChildCount != ordinaryChildPageLimit || len(after.root.CurrentAccess.Core.AccessPageRefs) != pages {
					t.Fatal("fitting receipt successor changed exact unchanged-access packing")
				}
				assertInstalledApplyWindowAppend(t, ctx, after, windows, result)
				return
			}
			if result.Result != refused(CapacityExceeded) || result.Payload != nil || len(result.Receipt) != 0 || !result.RequestIdentity.IsZero() ||
				slices.Contains(stages, contract.CryptoPrepare) || slices.Contains(stages, contract.CryptoFreeze) || slices.Contains(stages, contract.CryptoClaim) ||
				store.creates != creates || store.cas != cas || current.env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("capacity reservation crossed private preparation or mutation boundary", result.Result)
			}
			after := current.open(t, ctx)
			got, err := after.receiptWindows(ctx)
			if err != nil || after.head.Core.Root != root || after.token != token || !reflect.DeepEqual(got, windows) {
				t.Fatal("capacity refusal changed the exact selected predecessor", err)
			}
		})
	}
}
