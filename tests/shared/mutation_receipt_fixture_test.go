package core

import (
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This fixture installs authenticated terminal outcomes, not the operations
// that produced them. Transition tests execute the next real mutation.
func mutationReceiptFixtureStorage(t testing.TB, windows contract.MutationReceiptWindows) mutationReceiptStorage {
	t.Helper()
	rows, err := windows.SupportRecords()
	if err != nil || len(rows) == 0 {
		t.Fatal("nonempty receipt fixture", err)
	}
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	generated := format.EmptyGeneratedClosure()
	generated.SuccessWindow, generated.FailureWindow, generated.ReceiptOrder, err = indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := contract.MutationReceiptIndexBlobID(windows.DomainID, generated.SuccessWindow, generated.FailureWindow, generated.ReceiptOrder)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
		TotalLength: uint64(len(indexBody)), WholeDigest: contract.Hash(indexBody), Payload: indexBody})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	generated.Fragments = []format.FragmentLocation{{BlobID: blob, SupportPageIndex: 1}}
	storage := mutationReceiptStorage{generated: generated, count: uint32(len(rows) + 1)}
	for i, records := range [][]contract.SupportRecord{rows, {{Kind: 3, RecordID: fragmentID, Body: fragment}}} {
		object := fixtureID(windows.DomainID, fmt.Sprintf("receipt-fixture-page-%d", i))
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: windows.DomainID, Object: object, Index: uint16(i), Records: records})
		if err != nil {
			t.Fatal("receipt fixture support page", i, err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, windows.DomainID, object, uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		storage.objects = append(storage.objects, objectImage{ref: ref, body: body})
		storage.refs = append(storage.refs, ref)
		storage.pages = append(storage.pages, page)
	}
	return storage
}

// These fixture support rows are terminal evidence and the receipt index.
// They remain mandatory after the generated owner has ended.
func installReceiptFixtureAdministrativeIndex(t testing.TB, s *StateSession) []objectImage {
	t.Helper()
	index := format.AdministrativeIndex{Domain: s.root.Domain, Object: administrativeIndexObject(s.root.Domain, s.root.Snapshot), SliceSnapshot: s.root.Snapshot}
	for _, page := range s.support {
		if len(page.Records) == 0 {
			t.Fatal("empty receipt fixture page")
		}
		var ref format.Ref
		found := false
		for _, candidate := range s.root.RequiredSupport {
			if candidate.Index == page.Index {
				ref, found = candidate, true
				break
			}
		}
		if !found {
			t.Fatal("receipt fixture reference absent")
		}
		indexed := format.AdministrativePage{Ref: ref,
			Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(page.Records)), Mandatory: true}}}
		for _, row := range page.Records {
			indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: row.Kind,
				RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
		}
		index.Pages = append(index.Pages, indexed)
	}
	pages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(pages) == 0 {
		t.Fatal("receipt fixture index", err)
	}
	s.adminIndex = index
	s.root.AdministrativeIndex = pages[0].Ref
	s.root.AdministrativeIndexShards = nil
	objects := make([]objectImage, 0, len(pages))
	for i, page := range pages {
		if i != 0 {
			s.root.AdministrativeIndexShards = append(s.root.AdministrativeIndexShards, page.Ref)
		}
		objects = append(objects, objectImage{ref: page.Ref, body: page.Body})
	}
	s.recountChildren()
	return objects
}

func assertSuccessReceiptOrder(t testing.TB, before, after contract.MutationReceiptWindows, operation contract.ID) {
	t.Helper()
	want := make([]contract.ID, 0, len(before.Order)+1)
	for _, id := range before.Order {
		if len(before.Successes) == contract.MutationReceiptWindowLimit && id == before.Successes[0].OperationID {
			continue
		}
		want = append(want, id)
	}
	want = append(want, operation)
	if !slices.Equal(after.Order, want) {
		t.Fatal("success append changed retained common receipt order")
	}
}
