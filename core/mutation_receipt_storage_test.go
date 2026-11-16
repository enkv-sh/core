package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestMutationReceiptStoragePreservesWorkAndFillsOnlyNewIdentity(t *testing.T) {
	s, before, other := receiptStateFixture(t)
	s.recountChildren()
	row := before
	row.OperationID = contract.ID{70}
	row.RequestIdentityDigest = contract.ID{}
	delta := contract.MutationReceiptDeltaPlan{DomainID: row.DomainID, OperationKind: row.OperationKind, AddedCount: 1,
		Before:     contract.MutationReceiptWindows{DomainID: row.DomainID, Successes: []contract.CompactMutationReceipt{before}, Order: []contract.ID{before.OperationID}},
		NewReceipt: contract.CompactMutationReceiptPlan(row)}
	indexes, err := s.mutationReceiptPageIndexes(t.Context())
	if err != nil || len(indexes) != 3 {
		t.Fatalf("receipt/index plus shared fragment rewrite: %v, %v", indexes, err)
	}
	var p transitionPlan
	for _, index := range indexes {
		p.supportPages[index] = contract.ID{80, byte(index)}
	}
	projection, err := s.encodeMutationReceiptSupport(t.Context(), p, delta, contract.ID{})
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.ID{71}
	actual, err := s.encodeMutationReceiptSupport(t.Context(), p, delta, identity)
	if err != nil || len(actual.objects) != len(projection.objects) {
		t.Fatalf("actual storage: %v", err)
	}
	different := 0
	for i, object := range actual.objects {
		projected := projection.objects[i]
		if len(object.body) != len(projected.body) || object.ref.Object != projected.ref.Object {
			t.Fatal("filling identity changed allocation")
		}
		if !bytes.Equal(object.body, projected.body) {
			different++
			if _, err := format.InspectRequiredSupportPage(projected.body); err == nil {
				t.Fatal("actual reader accepted a hash projection")
			}
		}
	}
	if different != 1 {
		t.Fatalf("changed %d pages, want exactly one", different)
	}
	next := *s
	actual.install(&next)
	windows, err := next.receiptWindows(t.Context())
	if err != nil || len(windows.Successes) != 2 || windows.Successes[0] != before || windows.Successes[1].RequestIdentityDigest != identity || !slices.Equal(windows.Order, []contract.ID{before.OperationID, row.OperationID}) {
		t.Fatalf("frozen receipt preservation: %v", err)
	}
	work, err := next.workSupportRecords(t.Context())
	if err != nil || len(work) != 1 {
		t.Fatalf("live work: %v", err)
	}
	fragment, err := contract.InspectGeneratedFragment(work[0].Body)
	if err != nil || fragment.BlobID != other || string(fragment.Payload) != "retained source bytes" {
		t.Fatal("receipt storage changed live source")
	}
	for _, mutate := range []func(*transitionPlan){
		func(p *transitionPlan) { p.supportPages[indexes[0]] = contract.ID{} },
		func(p *transitionPlan) { p.supportPages[255] = contract.ID{90} },
	} {
		bad := p
		mutate(&bad)
		if _, err := s.encodeMutationReceiptSupport(t.Context(), bad, delta, identity); err == nil {
			t.Fatal("accepted an incomplete or surplus physical identity plan")
		}
	}
}

// full_only: false
func TestMutationReceiptStorageKeepsUnchangedFragmentSlots(t *testing.T) {
	s, before, _ := receiptStateFixture(t)
	fragment := func(blob contract.ID) contract.SupportRecord {
		payload := []byte("unchanged fragment")
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
			TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		return contract.SupportRecord{Kind: 3, RecordID: id, Body: body}
	}
	rows := []contract.SupportRecord{fragment(contract.ID{60}), fragment(contract.ID{61})}
	if bytes.Compare(rows[0].RecordID[:], rows[1].RecordID[:]) < 0 {
		rows[0], rows[1] = rows[1], rows[0]
	}
	const pageIndex = 2
	body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.admission.domain,
		Object: contract.ID{62}, Index: pageIndex, Records: rows})
	if err != nil {
		t.Fatal(err)
	}
	page, err := format.InspectRequiredSupportPage(body)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, s.admission.domain, page.Object, pageIndex, body)
	if err != nil {
		t.Fatal(err)
	}
	s.support = append(s.support, page)
	s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
	s.root.RequiredSupportRecordCount += uint32(len(rows))
	for slot, row := range rows {
		v, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.Generated.Fragments = append(s.root.Generated.Fragments, format.FragmentLocation{BlobID: v.BlobID,
			SupportPageIndex: pageIndex, RowSlot: uint8(slot)})
	}
	slices.SortFunc(s.root.Generated.Fragments, func(a, b format.FragmentLocation) int { return bytes.Compare(a.BlobID[:], b.BlobID[:]) })
	s.recountChildren()
	if err := format.ValidateFragmentDirectory(s.root.Generated.Fragments, s.support); err != nil {
		t.Fatal("unchanged fragment fixture", err)
	}
	receipt := before
	receipt.OperationID = contract.ID{70}
	receipt.RequestIdentityDigest = contract.ID{}
	delta := contract.MutationReceiptDeltaPlan{DomainID: receipt.DomainID, OperationKind: receipt.OperationKind, AddedCount: 1,
		Before:     contract.MutationReceiptWindows{DomainID: receipt.DomainID, Successes: []contract.CompactMutationReceipt{before}, Order: []contract.ID{before.OperationID}},
		NewReceipt: contract.CompactMutationReceiptPlan(receipt)}
	indexes, err := s.mutationReceiptPageIndexes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var plan transitionPlan
	for _, index := range indexes {
		if index == pageIndex {
			t.Fatal("unchanged fragment page was assigned a new identity")
		}
		plan.supportPages[index] = contract.ID{80, byte(index)}
	}
	storage, err := s.encodeMutationReceiptSupport(t.Context(), plan, delta, contract.ID{71})
	if err != nil {
		t.Fatal(err)
	}
	if storage.refs[pageIndex] != ref || !reflect.DeepEqual(storage.pages[pageIndex], page) ||
		format.ValidateFragmentDirectory(storage.generated.Fragments, storage.pages) != nil {
		t.Fatal("receipt append changed an unchanged fragment page or its row slots")
	}
}

// full_only: false
func TestMutationReceiptStorageChecksJointChildCapacityBeforeAllocation(t *testing.T) {
	s, _, _ := receiptStateFixture(t)
	s.recountChildren()
	// Three support pages replace two, so 253 other children fit exactly.
	s.root.ChildCount = 255
	if _, err := s.mutationReceiptPageIndexes(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.root.ChildCount++
	if _, err := s.mutationReceiptPageIndexes(t.Context()); err == nil {
		t.Fatal("accepted the 257th child")
	}
}
