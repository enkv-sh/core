package core

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestEndWorkHistoricalReleaseKeepsOnlyNeededSharedFragments(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint(shared), func(t *testing.T) {
			id := generatedVectorID
			domain, snapshot, hazard, release := id(1), id(2), id(3), id(4)
			intentBlob, graphBlob := id(5), id(6)
			if shared {
				graphBlob = intentBlob
			}
			locations := []contract.GeneratorSliceLocation{
				{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: id(9), BlobID: intentBlob, Offset: 1, Length: 1, Digest: id(10)},
				{Schema: 1, ContentKind: contract.GeneratorContentGraph, ContentID: id(7), BlobID: graphBlob, Length: 1, Digest: id(8)},
			}
			var bodies [][]byte
			for _, location := range locations {
				body, err := contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
			_, carriers := generatedVectorRowsForDomain(t, domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, bodies)
			page := format.RequiredSupportPage{Domain: domain, Object: id(11), Index: 1, Records: carriers}
			body, err := format.EncodeRequiredSupportPage(page)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(contract.RequiredSupportKind, domain, page.Object, page.Index, body)
			if err != nil {
				t.Fatal(err)
			}
			view, err := format.InspectRequiredSupportPage(body)
			if err != nil {
				t.Fatal(err)
			}
			optional := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain, Object: id(12), Digest: id(13), Length: 2048}
			intentFragment, err := contract.GeneratorFragmentID(intentBlob, 0)
			if err != nil {
				t.Fatal(err)
			}
			rows := []format.AdministrativeRowSummary{
				{Kind: contract.OperationMaterialSupportKind, RecordID: id(14), BodyLength: 87},
				{Kind: contract.GeneratedFragmentSupportKind, RecordID: intentFragment, BodyLength: 87},
				{Kind: contract.PendingInboxReleaseSupportKind, RecordID: release, BodyLength: 87},
			}
			fragments := []format.FragmentLocation{{BlobID: intentBlob, SupportPageIndex: 0, RowSlot: 1}}
			if !shared {
				graphFragment, err := contract.GeneratorFragmentID(graphBlob, 0)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, format.AdministrativeRowSummary{Kind: contract.GeneratedFragmentSupportKind, RecordID: graphFragment, BodyLength: 87})
				fragments = append(fragments, format.FragmentLocation{BlobID: graphBlob, SupportPageIndex: 0, RowSlot: 3})
			}
			descriptor := contract.GeneratorDescriptor{Digest: id(15), Length: 4}
			index := format.AdministrativeIndex{Domain: domain, Object: id(16), SliceSnapshot: snapshot, Groups: []format.AdministrativeGroup{
				{GroupID: hazard, OwnerID: hazard, TargetID: hazard, OwnerKind: format.AdministrativeGeneratedHazard, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: descriptor, Dependencies: descriptor, Disposable: descriptor},
				{GroupID: release, OwnerID: release, TargetID: release, OwnerKind: format.AdministrativeInboxRelease, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: descriptor, Dependencies: descriptor, Disposable: descriptor},
			}, Pages: []format.AdministrativePage{
				{Ref: optional, Rows: rows, Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(rows)), GroupIndexes: []uint16{0, 1}}}},
				{Ref: ref, ReadRequired: true, Spans: []format.AdministrativeSpan{{First: 0, Count: 1, GroupIndexes: []uint16{0, 1}}, {First: 1, Count: 1, GroupIndexes: []uint16{1}}}},
			}}
			if !index.Valid() {
				t.Fatal("historical index fixture")
			}
			original, _ := format.EncodeAdministrativeIndex(index)
			state := &StateSession{root: format.Root{Domain: domain, AdministrativeIndex: format.Ref{Object: index.Object}, RequiredSupport: []format.Ref{optional, ref}, Generated: format.GeneratedClosure{Fragments: fragments}}, adminIndex: index, support: []format.RequiredSupportPageView{{}, view}}
			after, err := state.administrativeWorkDisposition(hazard)
			if err != nil {
				t.Fatal(err)
			}
			want := []format.AdministrativeRowSummary{rows[2]}
			if shared {
				want = append([]format.AdministrativeRowSummary{rows[1]}, want...)
			} else {
				want = append(want, rows[3])
			}
			if len(after.Groups) != 1 || after.Groups[0].GroupID != release || len(after.Pages) != 2 || !reflect.DeepEqual(after.Pages[0].Rows, want) ||
				len(after.Pages[1].Spans) != 1 || after.Pages[1].Spans[0].First != 1 || after.Pages[1].Spans[0].Count != 1 || !slices.Equal(after.Pages[1].Spans[0].GroupIndexes, []uint16{0}) {
				t.Fatal("release kept seed/Intent or lost Graph/shared fragment")
			}
			unchanged, _ := format.EncodeAdministrativeIndex(state.adminIndex)
			if !slices.Equal(original, unchanged) {
				t.Fatal("projection changed authenticated predecessor")
			}
		})
	}
}
