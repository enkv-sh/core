package core

import (
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func administrativeSummaryBytes(row format.AdministrativeRowSummary) []byte {
	b := []byte{row.Kind}
	b = append(b, row.RecordID[:]...)
	return binary.BigEndian.AppendUint32(b, row.BodyLength)
}

// full_only: false
func TestAdministrativeProjectionKeepsSharedBlobForSecondDisposition(t *testing.T) {
	domain, first, second, snapshot := generatedVectorID(1), generatedVectorID(2), generatedVectorID(3), generatedVectorID(4)
	blob := []byte("AB")
	blobID := contract.Hash(blob)
	fragmentID, err := contract.GeneratorFragmentID(blobID, 0)
	if err != nil {
		t.Fatal(err)
	}
	locations := []contract.GeneratorSliceLocation{
		{Schema: 1, ContentKind: contract.GeneratorContentConfiguration, ContentID: first, BlobID: blobID, Length: 1, Digest: contract.Hash(blob[:1])},
		{Schema: 1, ContentKind: contract.GeneratorContentConfiguration, ContentID: second, BlobID: blobID, Offset: 1, Length: 1, Digest: contract.Hash(blob[1:])},
	}
	makeCarriers := func(selected []contract.GeneratorSliceLocation, object contract.ID) (contract.GeneratorDescriptor, format.RequiredSupportPageView, format.Ref) {
		t.Helper()
		bodies := make([][]byte, len(selected))
		for i, location := range selected {
			bodies[i], err = contract.EncodeGeneratorSliceLocation(location)
			if err != nil {
				t.Fatal(err)
			}
		}
		descriptor, carriers, err := generatedCarrierRows(domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, bodies)
		if err != nil {
			t.Fatal(err)
		}
		page := format.RequiredSupportPage{Domain: domain, Object: object, Index: 1, Records: carriers}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, domain, object, 1, body)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		return descriptor, view, ref
	}
	slicesDescriptor, sliceView, sliceRef := makeCarriers(locations, generatedVectorID(5))
	optionalRef := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
		Object: generatedVectorID(6), Digest: generatedVectorID(7), Length: 447}
	rows := []format.AdministrativeRowSummary{
		{Kind: contract.GeneratedHazardSupportKind, RecordID: first, BodyLength: 87},
		{Kind: contract.GeneratedHazardSupportKind, RecordID: second, BodyLength: 87},
		{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, BodyLength: 87},
	}
	index := format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(8), SliceSnapshot: snapshot,
		Pages: []format.AdministrativePage{
			{Ref: optionalRef, Rows: rows, Spans: []format.AdministrativeSpan{
				{First: 0, Count: 1, GroupIndexes: []uint16{0}},
				{First: 1, Count: 1, GroupIndexes: []uint16{1}},
				{First: 2, Count: 1, GroupIndexes: []uint16{0, 1}},
			}},
			{Ref: sliceRef, ReadRequired: true, Spans: []format.AdministrativeSpan{
				{First: 0, Count: 1, GroupIndexes: []uint16{0}},
				{First: 1, Count: 1, GroupIndexes: []uint16{1}},
			}},
		},
	}
	descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(9), Length: 4}
	for i, owner := range []contract.ID{first, second} {
		carrier := sliceView.Records[i]
		items := [][]byte{administrativeSummaryBytes(rows[i]), administrativeSummaryBytes(rows[2]),
			administrativeSummaryBytes(format.AdministrativeRowSummary{Kind: carrier.Kind, RecordID: carrier.RecordID, BodyLength: uint32(len(carrier.Body))})}
		index.Groups = append(index.Groups, format.AdministrativeGroup{GroupID: owner, OwnerID: owner, TargetID: owner,
			OwnerKind: format.AdministrativeGeneratedHazard, SelectedEvidenceSummary: contract.AdministrativeEvidencePossibleLive,
			Affected: descriptor, Dependencies: descriptor,
			Disposable: administrativeDescriptor("selected-disposable", items...), ChargedPages: 2,
			ChargedBytes: uint64(3*contract.SupportRecordOverhead + 87 + 87 + len(carrier.Body))})
	}
	if !index.Valid() {
		t.Fatal("synthetic selected index is invalid")
	}
	generated := format.EmptyGeneratedClosure()
	generated.Hazards = 2
	generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{first, second})
	if err != nil {
		t.Fatal(err)
	}
	generated.Slices = slicesDescriptor
	generated.Fragments = []format.FragmentLocation{{BlobID: blobID, SupportPageIndex: 0, RowSlot: 2}}
	s := &StateSession{admission: openAdmission{domain: domain}, root: format.Root{Domain: domain, Snapshot: snapshot,
		AdministrativeIndex: format.Ref{Object: index.Object}, RequiredSupport: []format.Ref{optionalRef, sliceRef}, Generated: generated},
		adminIndex: index, support: []format.RequiredSupportPageView{{}, sliceView}}
	afterFirst, err := s.administrativeWorkDisposition(first)
	if err != nil {
		t.Fatal("first disposition", err)
	}
	projected, selected, err := s.administrativeGeneratedProjection(afterFirst)
	if err != nil || selected != 3 || projected.Hazards != 1 || len(projected.Fragments) != 1 || projected.Fragments[0].RowSlot != 1 ||
		projected.GeneratedCurrent != 0 || projected.Retiring != 0 {
		t.Fatal("first exact projection", selected, projected, err)
	}
	bOnly, bView, bRef := makeCarriers(locations[1:], generatedVectorID(10))
	if projected.Slices != bOnly || afterFirst.Groups[0].ChargedPages != 2 || afterFirst.Groups[0].ChargedBytes != index.Groups[1].ChargedBytes ||
		len(afterFirst.Pages[0].Rows) != 2 || afterFirst.Pages[0].Rows[0].RecordID != second ||
		len(afterFirst.Pages[1].Spans) != 1 || afterFirst.Pages[1].Spans[0].First != 1 {
		t.Fatal("B lost its exact shared-page projection")
	}
	// Administrative successor construction writes a new readable B-only carrier
	// page. Reconstruct that selected successor here without using the unreadable
	// optional page.
	projectedIndex := afterFirst
	projectedIndex.Pages = slices.Clone(afterFirst.Pages)
	projectedIndex.Pages[1] = format.AdministrativePage{Ref: bRef, ReadRequired: true,
		Spans: []format.AdministrativeSpan{{First: 0, Count: 1, GroupIndexes: []uint16{0}}}}
	carrier := bView.Records[0]
	projectedIndex.Groups = slices.Clone(afterFirst.Groups)
	projectedIndex.Groups[0].Disposable = administrativeDescriptor("selected-disposable",
		administrativeSummaryBytes(rows[1]), administrativeSummaryBytes(rows[2]),
		administrativeSummaryBytes(format.AdministrativeRowSummary{Kind: carrier.Kind, RecordID: carrier.RecordID, BodyLength: uint32(len(carrier.Body))}))
	projectedIndex.Groups[0].ChargedBytes = uint64(3*contract.SupportRecordOverhead + 87 + 87 + len(carrier.Body))
	if !projectedIndex.Valid() {
		t.Fatal("B-only projected index invalid")
	}
	s.adminIndex, s.root.Generated = projectedIndex, projected
	s.root.RequiredSupport[1] = bRef
	s.support[1] = bView
	if _, err := format.ResolveGeneratedSliceLocations(domain, snapshot, projected.Slices, s.support); err != nil {
		t.Fatal("B-only readable carrier did not reopen", err)
	}
	afterSecond, err := s.administrativeWorkDisposition(second)
	if err != nil {
		t.Fatal("second disposition", err)
	}
	final, count, err := s.administrativeGeneratedProjection(afterSecond)
	if err != nil || count != 0 || len(afterSecond.Pages) != 0 || len(afterSecond.Groups) != 0 ||
		final.Hazards != 0 || len(final.Fragments) != 0 || final.Slices != contract.EmptyGeneratorVector(contract.GeneratorVectorSlices) ||
		final.LiveOwners != format.EmptyGeneratedClosure().LiveOwners {
		t.Fatal("second exact projection", count, final, err)
	}
}

// full_only: false
func TestAdministrativeSliceProjectionPacksAcrossNearFullPages(t *testing.T) {
	domain, snapshot, blob := generatedVectorID(31), generatedVectorID(32), generatedVectorID(33)
	location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentConfiguration,
		ContentID: generatedVectorID(34), BlobID: blob, Length: 1, Digest: generatedVectorID(35)}
	body, err := contract.EncodeGeneratorSliceLocation(location)
	if err != nil {
		t.Fatal(err)
	}
	_, example, err := generatedCarrierRows(domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	rowLength := contract.SupportRecordOverhead + len(example[0].Body)
	perPage := (contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength) / rowLength
	t.Logf("Slice carrier framed bytes=%d, carriers per full page=%d", rowLength, perPage)
	if perPage < 2 {
		t.Fatal("Slice carrier has no useful page capacity", rowLength)
	}
	bodies := make([][]byte, perPage+1)
	for i := range bodies {
		location.ContentID = contract.ID{}
		binary.BigEndian.PutUint32(location.ContentID[28:], uint32(i+1))
		bodies[i], err = contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
	}
	descriptor, carriers, err := generatedCarrierRows(domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, bodies)
	if err != nil {
		t.Fatal(err)
	}
	groups := []format.RequiredSupportGroup{
		{Class: format.GraphIndexSupport, Owner: generatedVectorID(36), Records: carriers[:perPage]},
		{Class: format.GraphIndexSupport, Owner: generatedVectorID(37), Records: carriers[perPage:]},
	}
	packed, err := format.PackRequiredSupportRows(domain, groups, 1)
	if err != nil || len(packed) != 2 || len(packed[0]) != perPage || len(packed[1]) != 1 {
		t.Fatal("near-full Slice vector lost multi-page packing", len(packed), err)
	}
	var views []format.RequiredSupportPageView
	for i, records := range packed {
		page := format.RequiredSupportPage{Domain: domain, Object: generatedVectorID(uint8(38 + i)), Index: uint16(i), Records: records}
		encoded, err := format.EncodeRequiredSupportPage(page)
		if err != nil || len(encoded) > contract.MaxRequiredSupportPageLength {
			t.Fatal("near-full Slice page exceeds wire limit", len(encoded), err)
		}
		t.Logf("Slice projection page %d encoded bytes=%d", i, len(encoded))
		view, err := format.InspectRequiredSupportPage(encoded)
		if err != nil {
			t.Fatal(err)
		}
		views = append(views, view)
	}
	resolved, err := format.ResolveGeneratedSliceLocations(domain, snapshot, descriptor, views)
	if err != nil || len(resolved) != perPage+1 {
		t.Fatal("multi-page readable Slice vector did not resolve", len(resolved), err)
	}
}

// full_only: false
func TestAdministrativeProjectionRecognizesExactPublicationOwners(t *testing.T) {
	for _, fault := range []string{"none", "coordinate wrong kind", "marker wrong kind", "coordinate missing owner", "marker missing owner", "charged bytes", "charged pages", "disposable"} {
		t.Run(fault, func(t *testing.T) {
			image := publicationSelectedImageFixture(t)
			index := image.adminIndex
			index.Groups = slices.Clone(index.Groups)
			index.Pages = slices.Clone(index.Pages)
			index.Pages[0].Rows = slices.Clone(index.Pages[0].Rows)
			if fault == "coordinate wrong kind" {
				index.Pages[0].Rows[0].Kind = contract.PublicationMarkerSupportKind
			}
			if fault == "marker wrong kind" {
				index.Pages[0].Rows[1].Kind = contract.PublicationCoordinateSupportKind
			}
			if fault == "coordinate missing owner" {
				index.Pages[0].Rows[0].RecordID = publicationRelationID(98)
			}
			if fault == "marker missing owner" {
				index.Pages[0].Rows[1].RecordID = publicationRelationID(99)
			}
			for _, span := range index.Pages[0].Spans {
				row := index.Pages[0].Rows[span.First]
				group := &index.Groups[span.GroupIndexes[0]]
				group.Disposable = administrativeDescriptor("selected-disposable", administrativeSummaryBytes(row))
				group.ChargedPages = 1
				group.ChargedBytes = uint64(contract.SupportRecordOverhead) + uint64(row.BodyLength)
			}
			if fault == "charged bytes" {
				index.Groups[0].ChargedBytes++
			}
			if fault == "charged pages" {
				index.Groups[0].ChargedPages++
			}
			if fault == "disposable" {
				index.Groups[0].Disposable.Digest = publicationRelationID(100)
			}
			state := &StateSession{root: image.root, adminIndex: index, support: image.support}
			state.root.Generated = format.EmptyGeneratedClosure()
			projected, count, err := state.administrativeGeneratedProjection(index)
			if fault != "none" {
				if err == nil {
					t.Fatal("projection accepted altered publication owner", projected, count)
				}
				return
			}
			if err != nil || count != 2 || !reflect.DeepEqual(projected, format.EmptyGeneratedClosure()) {
				t.Fatal("publication owner changed generated projection or was refused", projected, count, err)
			}
		})
	}
}
