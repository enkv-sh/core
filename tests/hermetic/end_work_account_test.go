package core

import (
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func assertJointEndWorkPageAccount(t *testing.T, before, after *StateSession, target contract.ID, indexBytes uint64) {
	t.Helper()
	for _, group := range before.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativeGeneratedDuty && group.OwnerKind != format.AdministrativeGeneratedHazard || len(group.RelatedGroupIndexes) != 0 {
			t.Fatal("joint page oracle requires independent Duty/Hazard owners", group.OwnerKind, len(group.RelatedGroupIndexes))
		}
	}
	if len(after.adminIndex.Groups) != len(before.adminIndex.Groups)-1 {
		t.Fatal("joint exact account requires one removed owner")
	}
	for _, group := range after.adminIndex.Groups {
		position := slices.IndexFunc(before.adminIndex.Groups, func(old format.AdministrativeGroup) bool { return old.GroupID == group.GroupID })
		if position < 0 || group.GroupID == target {
			t.Fatal("joint exit selected another owner")
		}
		want := before.adminIndex.Groups[position]
		group.Disposable, want.Disposable = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
		group.ChargedPages, want.ChargedPages, group.ChargedBytes, want.ChargedBytes = 0, 0, 0, 0
		if !reflect.DeepEqual(group, want) {
			t.Fatal("joint exit changed a surviving owner's stable fields", group.OwnerKind)
		}
	}
	for _, named := range before.root.Names {
		if entry := before.valueEntry(named.Slot); entry == nil || entry.ValueSource != contract.Supplied {
			t.Fatal("joint page oracle requires supplied current entries", named.Slot)
		}
	}
	if len(before.adminIndex.PublicationOrder) != 0 || len(after.adminIndex.PublicationOrder) != 0 || before.root.Generated.PendingReleases != 0 || before.root.Generated.GeneratedCurrent != 0 || len(before.root.AdministrativeIndexShards) != 0 || len(after.root.AdministrativeIndexShards) != 0 {
		t.Fatal("joint page oracle requires no release normalization/current Intent emission and one index shard")
	}
	if !reflect.DeepEqual(before.root.ValueEntryPages, after.root.ValueEntryPages) || !reflect.DeepEqual(before.root.Recipients, after.root.Recipients) || !slices.Equal(before.root.CurrentAccess.Core.AccessPageRefs, after.root.CurrentAccess.Core.AccessPageRefs) {
		t.Fatal("joint exit changed fixed current/access page references")
	}
	type rowFact struct {
		row       format.AdministrativeRowSummary
		location  contract.GeneratorSliceLocation
		ordinal   uint16
		mandatory bool
		owners    []contract.ID
	}
	type pageFact struct {
		ref          contract.Ref
		readRequired bool
		rows         []rowFact
		spanBytes    uint64
	}
	owners := func(index format.AdministrativeIndex, span format.AdministrativeSpan, remove contract.ID) []contract.ID {
		var ids []contract.ID
		for _, owner := range span.GroupIndexes {
			if id := index.Groups[owner].GroupID; id != remove {
				ids = append(ids, id)
			}
		}
		return ids
	}
	readCarrier := func(s *StateSession, page, row int) contract.GeneratorSliceLocation {
		support := s.support[page].Records[row]
		carrier, err := contract.InspectGeneratorVectorCarrier(support.Body)
		if err != nil || support.Kind != contract.GeneratorVectorSupportKind || carrier.VectorKind != contract.GeneratorVectorSlices || carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.OwnerID != s.adminIndex.SliceSnapshot || carrier.DomainID != s.root.Domain || carrier.Vector != s.root.Generated.Slices {
			t.Fatal("joint selected Slice carrier", err)
		}
		location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			t.Fatal("joint selected Slice location", err)
		}
		return location
	}
	// Receipt rows/index are dedicated mandatory pages. Their independent
	// full-window frames are 75+512*(37+471), and 75+37+86+(26+72*512).
	receiptPages := func(s *StateSession) map[uint16]bool {
		blob, err := s.receiptIndexID()
		if err != nil {
			t.Fatal("joint receipt-index identity", err)
		}
		indexPage := -1
		for _, location := range s.root.Generated.Fragments {
			if location.BlobID == blob {
				if indexPage >= 0 || location.FragmentIndex != 0 || location.RowSlot != 0 {
					t.Fatal("joint receipt index is not one complete fragment")
				}
				indexPage = int(location.SupportPageIndex)
			}
		}
		found := make(map[uint16]bool)
		var rowsPages, indexPages int
		for _, page := range s.adminIndex.Pages {
			isRows := len(page.Rows) != 0 && page.Rows[0].Kind == contract.MutationReceiptSupportKind
			isIndex := int(page.Ref.Index) == indexPage
			if !isRows && !isIndex {
				continue
			}
			wantRows, wantLength, wantKind, wantBody := 512, uint32(260171), uint8(contract.MutationReceiptSupportKind), uint32(471)
			if isIndex {
				wantRows, wantLength, wantKind, wantBody = 1, 37088, contract.GeneratedFragmentSupportKind, 36976
				indexPages++
			} else {
				rowsPages++
			}
			if page.ReadRequired || len(page.Spans) != 1 || page.Spans[0].First != 0 || int(page.Spans[0].Count) != wantRows || !page.Spans[0].Mandatory || len(page.Spans[0].GroupIndexes) != 0 || len(page.Rows) != wantRows || page.Ref.Length != wantLength {
				t.Fatal("joint receipt replacement page has a different physical frame", page.Ref.Index, page.Ref.Length, len(page.Rows))
			}
			for _, row := range page.Rows {
				if row.Kind != wantKind || row.BodyLength != wantBody {
					t.Fatal("joint receipt replacement page contains another row kind/frame", row.Kind, row.BodyLength)
				}
			}
			found[page.Ref.Index] = true
		}
		if rowsPages != 1 || indexPages != 1 {
			t.Fatal("joint receipt replacement is not exactly two dedicated pages", rowsPages, indexPages)
		}
		return found
	}
	oldReceipts, newReceipts := receiptPages(before), receiptPages(after)
	expected := make(map[uint16]pageFact)
	var slicesRemoved bool
	for i, page := range before.adminIndex.Pages {
		if oldReceipts[page.Ref.Index] {
			continue
		}
		fact := pageFact{ref: page.Ref, readRequired: page.ReadRequired}
		logical := 0
		for _, span := range page.Spans {
			keepOwners := owners(before.adminIndex, span, target)
			if span.Mandatory || len(keepOwners) != 0 {
				fact.spanBytes += uint64(7 + 2*len(keepOwners))
			}
			for n := uint16(0); n < span.Count; n++ {
				row := rowFact{ordinal: span.First + n, mandatory: span.Mandatory, owners: keepOwners}
				if page.ReadRequired {
					row.location = readCarrier(before, i, logical)
				} else {
					row.row = page.Rows[logical]
					if row.row.Kind == contract.PendingInboxReleaseSupportKind || row.row.Kind == contract.PublicationCoordinateSupportKind || row.row.Kind == contract.PublicationMarkerSupportKind {
						t.Fatal("joint page oracle excludes release/publication rows", row.row.Kind)
					}
				}
				logical++
				if row.mandatory || len(row.owners) != 0 {
					fact.rows = append(fact.rows, row)
				} else if page.ReadRequired {
					slicesRemoved = true
				}
			}
		}
		if len(fact.rows) != 0 {
			expected[page.Ref.Index] = fact
		}
	}
	// No fresh content is emitted for this supplied-current fixture. Each
	// surviving Slice page keeps its physical index, with new carrier bindings
	// only when the complete Slice vector changes: 75+n*(37+120+111).
	if (before.root.Generated.Slices != after.root.Generated.Slices) != slicesRemoved {
		t.Fatal("joint exit changed a different selected Slice vector")
	}
	var supportBytes uint64 = 297259
	// Logical index: 115 base; 247 per independent Duty/Hazard; 108 per
	// page; 7+2*owners per span; 37 per optional-row summary. The receipt
	// pair contributes 2*(108+7)+513*37. Explicit canonical MaterialIDs add
	// 32 bytes to every surviving canonical summary when any is explicit.
	wantIndex := uint64(115 + 247*(len(before.adminIndex.Groups)-1) + 19211)
	explicitMaterials := false
	for _, page := range expected {
		for _, row := range page.rows {
			explicitMaterials = explicitMaterials || row.row.Kind == contract.RetainedCanonicalSupportKind && !row.row.MaterialID.IsZero()
		}
	}
	for index, page := range expected {
		length := uint64(page.ref.Length)
		if page.readRequired && slicesRemoved {
			length = 75 + 268*uint64(len(page.rows))
		}
		supportBytes += length
		actualPage := slices.IndexFunc(after.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref.Index == index })
		if actualPage < 0 || newReceipts[index] {
			t.Fatal("joint exit lost an independently retained support page", index)
		}
		actual := after.adminIndex.Pages[actualPage]
		if actual.ReadRequired != page.readRequired || uint64(actual.Ref.Length) != length || (!page.readRequired || !slicesRemoved) && actual.Ref != page.ref || page.readRequired && slicesRemoved && actual.Ref == page.ref {
			t.Fatal("joint retained support page changed its exact reference/frame", index, actual.Ref.Length, length)
		}
		seen := make([]bool, len(page.rows))
		logical := 0
		var previous *rowFact
		var reboundSpanBytes, actualSpanBytes uint64
		for _, span := range actual.Spans {
			gotOwners := owners(after.adminIndex, span, contract.ID{})
			actualSpanBytes += uint64(7 + 2*len(gotOwners))
			for n := uint16(0); n < span.Count; n++ {
				var location contract.GeneratorSliceLocation
				if page.readRequired {
					location = readCarrier(after, actualPage, logical)
				}
				match := slices.IndexFunc(page.rows, func(row rowFact) bool {
					return page.readRequired && row.location == location && (slicesRemoved || row.ordinal == span.First+n) || !page.readRequired && row.row == actual.Rows[logical] && row.ordinal == span.First+n
				})
				if match < 0 || seen[match] || page.rows[match].mandatory != span.Mandatory || !slices.Equal(page.rows[match].owners, gotOwners) {
					t.Fatal("joint exit changed selected support rows, physical ordinals or owners", index, logical)
				}
				if page.readRequired && slicesRemoved {
					if span.First+n != uint16(logical) {
						t.Fatal("joint rebound Slice page is not densely packed", index, logical)
					}
					row := &page.rows[match]
					if previous == nil || previous.mandatory != row.mandatory || !slices.Equal(previous.owners, row.owners) {
						reboundSpanBytes += uint64(7 + 2*len(row.owners))
					}
					previous = row
				}
				seen[match], logical = true, logical+1
			}
		}
		spanBytes := page.spanBytes
		if page.readRequired && slicesRemoved {
			spanBytes = reboundSpanBytes
		}
		if actualSpanBytes != spanBytes {
			t.Fatal("joint selected span framing changed", index, actualSpanBytes, spanBytes)
		}
		wantIndex += 108 + spanBytes
		if !page.readRequired {
			wantIndex += 37 * uint64(len(page.rows))
			for _, row := range page.rows {
				if explicitMaterials && row.row.Kind == contract.RetainedCanonicalSupportKind {
					wantIndex += 32
				}
			}
		}
		if logical != len(page.rows) {
			t.Fatal("joint exit omitted retained support rows", index, logical, len(page.rows))
		}
	}
	if len(after.adminIndex.Pages) != len(expected)+2 {
		t.Fatal("joint exit selected an extra support page", len(after.adminIndex.Pages), len(expected)+2)
	}
	fixed := slices.Clone(before.root.CurrentAccess.Core.AccessPageRefs)
	for _, table := range [][]*contract.Ref{before.root.ValueEntryPages[:], before.root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				fixed = append(fixed, *ref)
			}
		}
	}
	// The one physical index shard adds its independent 116-byte envelope to
	// the independently counted logical index. The selected reserve is
	// checked separately; no fresh RecordID/hash or carrier sort is reproduced here.
	wantCount := uint32(len(fixed) + len(expected) + 3)
	wantBytes := supportBytes + wantIndex + 116
	for _, ref := range fixed {
		wantBytes += uint64(ref.Length)
	}
	if indexBytes != wantIndex || after.root.ChildCount != wantCount || after.root.ChildEncodedBytes != wantBytes || uint64(after.root.AdministrativeIndex.Length) != wantIndex+116 {
		t.Fatalf("joint exact child account changed: children=%d expected=%d bytes=%d expected=%d index=%d expected-index=%d", after.root.ChildCount, wantCount, after.root.ChildEncodedBytes, wantBytes, after.root.AdministrativeIndex.Length, wantIndex+116)
	}
}
