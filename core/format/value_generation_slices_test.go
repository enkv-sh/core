package format

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedSlicesRequireExactMappingAndBytes(t *testing.T) {
	payload := bytes.Repeat([]byte{13}, contract.GeneratedFragmentMaxPayload+17)
	fragments := packedFragments(t, fid(2), len(payload))
	slice := contract.GeneratorSliceLocation{Schema: 1, ContentKind: 4, ContentID: fid(3), BlobID: fid(2),
		Offset: contract.GeneratedFragmentMaxPayload - 8, Length: 16, Digest: contract.Hash(payload[contract.GeneratedFragmentMaxPayload-8 : contract.GeneratedFragmentMaxPayload+8])}
	row, err := contract.EncodeGeneratorSliceLocation(slice)
	if err != nil {
		t.Fatal(err)
	}
	d, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, [][]byte{row})
	if err != nil {
		t.Fatal(err)
	}
	carrier := contract.GeneratorVectorCarrier{Schema: 1, DomainID: fid(1), OwnerKind: contract.GeneratorSnapshotOwner, OwnerID: fid(4), VectorKind: contract.GeneratorVectorSlices, Vector: d, Row: row}
	body, err := contract.EncodeGeneratorVectorCarrier(carrier)
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.GeneratorVectorCarrierID(carrier)
	if err != nil {
		t.Fatal(err)
	}
	pages := []RequiredSupportPageView{
		{Domain: fid(1), Object: fid(5), Index: 0, Records: []contract.SupportRecordView{contract.SupportRecordView(fragments[0]), contract.SupportRecordView(fragments[1])}},
		{Domain: fid(1), Object: fid(6), Index: 1, Records: []contract.SupportRecordView{{Kind: 14, RecordID: id, Body: body}}},
	}
	closure := EmptyGeneratedClosure()
	closure.Slices = d
	closure.Fragments = []FragmentLocation{{BlobID: fid(2), RowSlot: 0}, {BlobID: fid(2), FragmentIndex: 1, RowSlot: 1}}
	locations, err := ResolveGeneratedSlices(fid(1), fid(4), closure, pages)
	if err != nil || len(locations) != 1 || locations[0] != slice {
		t.Fatal("cross-fragment mapping", locations, err)
	}
	for name, edit := range map[string]func(*contract.GeneratorSliceLocation){
		"digest":       func(v *contract.GeneratorSliceLocation) { v.Digest = fid(8) },
		"outside blob": func(v *contract.GeneratorSliceLocation) { v.Offset = uint64(len(payload)) - 8 },
		"missing blob": func(v *contract.GeneratorSliceLocation) { v.BlobID = fid(8) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := slice
			edit(&bad)
			row, err := contract.EncodeGeneratorSliceLocation(bad)
			if err != nil {
				t.Fatal(err)
			}
			d, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, [][]byte{row})
			if err != nil {
				t.Fatal(err)
			}
			c := carrier
			c.Vector, c.Row = d, row
			b, err := contract.EncodeGeneratorVectorCarrier(c)
			if err != nil {
				t.Fatal(err)
			}
			id, err := contract.GeneratorVectorCarrierID(c)
			if err != nil {
				t.Fatal(err)
			}
			badPages := append([]RequiredSupportPageView(nil), pages...)
			badPages[1].Records = []contract.SupportRecordView{{Kind: 14, RecordID: id, Body: b}}
			badClosure := closure
			badClosure.Slices = d
			if _, err := ResolveGeneratedSlices(fid(1), fid(4), badClosure, badPages); err == nil {
				t.Fatal("invalid mapping accepted")
			}
		})
	}
	for _, selected := range [][]RequiredSupportPageView{pages[:1], append(append([]RequiredSupportPageView(nil), pages...), pages[1])} {
		if _, err := ResolveGeneratedSlices(fid(1), fid(4), closure, selected); err == nil {
			t.Fatal("missing or duplicate row accepted")
		}
	}
	if _, err := ResolveGeneratedSlices(fid(1), fid(7), closure, pages); err == nil {
		t.Fatal("wrong snapshot owner accepted")
	}
	closure.Slices = contract.EmptyGeneratorVector(contract.GeneratorVectorSlices)
	if _, err := ResolveGeneratedSlices(fid(1), fid(4), closure, pages); err == nil {
		t.Fatal("unreferenced location accepted")
	}
}
