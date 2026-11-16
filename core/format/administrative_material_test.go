package format

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestAdministrativeCanonicalMaterialAssociationPreservesHistoricalEncoding(t *testing.T) {
	index := AdministrativeIndex{Domain: fid(1), Object: fid(2), SliceSnapshot: fid(3), Groups: []AdministrativeGroup{}, Pages: []AdministrativePage{{
		Ref:   Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: fid(1), Object: fid(4), Digest: fid(5), Length: 2048},
		Spans: []AdministrativeSpan{{First: 0, Count: 3, Mandatory: true, GroupIndexes: []uint16{}}},
		Rows: []AdministrativeRowSummary{
			{Kind: contract.RetainedCanonicalSupportKind, RecordID: fid(6), BodyLength: 400},
			{Kind: contract.RetainedCanonicalSupportKind, RecordID: fid(7), BodyLength: 400},
			{Kind: contract.GeneratedFragmentSupportKind, RecordID: fid(8), BodyLength: 87},
		},
	}}}
	legacy, err := EncodeAdministrativeIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	const marker = 7 + 32*3 + 4
	const firstRow = 113 + 108 + 7
	if binary.BigEndian.Uint16(legacy[marker:]) != 3 || len(legacy) != firstRow+3*37+2 {
		t.Fatal("historical framing changed")
	}
	index.Pages[0].Rows[1].MaterialID = fid(6)
	body, err := EncodeAdministrativeIndex(index)
	if err != nil || len(body) != len(legacy)+64 || binary.BigEndian.Uint16(body[marker:]) != 4 {
		t.Fatal("explicit association framing", err)
	}
	// Independently insert the two effective material IDs into marker-3 bytes.
	want := append([]byte(nil), legacy[:firstRow]...)
	binary.BigEndian.PutUint16(want[marker:], 4)
	for i := range 3 {
		want = append(want, legacy[firstRow+i*37:firstRow+(i+1)*37]...)
		if i < 2 {
			id := fid(6)
			want = append(want, id[:]...)
		}
	}
	want = append(want, legacy[firstRow+3*37:]...)
	if !bytes.Equal(body, want) {
		t.Fatal("new field order differs from independent framing")
	}
	if length, err := AdministrativeIndexEncodedLength(index); err != nil || length != uint64(len(want)) {
		t.Fatal("association charge", length, err)
	}
	decoded, err := DecodeAdministrativeIndex(body)
	if err != nil || !reflect.DeepEqual(decoded, index) {
		t.Fatal("mixed source association roundtrip", err)
	}
	// Exercise a 32-byte material field split at each possible shard boundary.
	for cut := firstRow + 37 + 1; cut < firstRow+37+32; cut++ {
		reader := &administrativeShardReader{parts: [][]byte{body[:cut], body[cut:]}, total: len(body)}
		reader.take(7)
		got, err := decodeAdministrativeIndex(reader, len(body))
		if err != nil || !reflect.DeepEqual(got, index) {
			t.Fatal("split material field", cut, err)
		}
	}
	bad := append([]byte(nil), body...)
	clear(bad[firstRow+37 : firstRow+69])
	if _, err := DecodeAdministrativeIndex(bad); err == nil {
		t.Fatal("zero explicit material admitted")
	}
	bad = append([]byte(nil), body...)
	implicitSecond := fid(7)
	copy(bad[firstRow+69+37:firstRow+69+69], implicitSecond[:])
	if _, err := DecodeAdministrativeIndex(bad); err == nil {
		t.Fatal("marker four without a distinct material association admitted")
	}
	index.Pages[0].Rows[1].MaterialID = ID{}
	restored, err := EncodeAdministrativeIndex(index)
	if err != nil || !bytes.Equal(restored, legacy) {
		t.Fatal("implicit summaries did not recover exact historical bytes", err)
	}
	index.Pages[0].Rows[2].MaterialID = fid(6)
	if _, err := EncodeAdministrativeIndex(index); err == nil {
		t.Fatal("noncanonical row acquired a material association")
	}
}

// full_only: false
func TestAdministrativeCanonicalMaterialUpgradeCrossesFirstShard(t *testing.T) {
	const groups, extraMandatorySpans = 8189, 28
	domain := fid(1)
	descriptor := contract.GeneratorDescriptor{Digest: fid(6), Length: 4}
	index := AdministrativeIndex{Domain: domain, Object: fid(7), SliceSnapshot: fid(10)}
	var spans []AdministrativeSpan
	for i := range groups {
		var id ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		index.Groups = append(index.Groups, AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind: AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
			Affected: descriptor, Dependencies: descriptor, Disposable: descriptor,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing})
		spans = append(spans, AdministrativeSpan{First: uint16(i), Count: 1, GroupIndexes: []uint16{uint16(i)}})
	}
	for i := range extraMandatorySpans {
		spans = append(spans, AdministrativeSpan{First: uint16(groups + i), Count: 1, Mandatory: true})
	}
	index.Pages = []AdministrativePage{{Ref: Ref{Kind: contract.RequiredSupportKind, Format: Version,
		Domain: domain, Object: fid(8), Digest: fid(9),
		Length: contract.RequiredSupportPageHeaderLength + (groups+extraMandatorySpans)*contract.SupportRecordMinLength}, ReadRequired: true, Spans: spans},
		{Ref: Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: domain, Object: fid(11), Digest: fid(12), Index: 1, Length: 2048},
			Spans: []AdministrativeSpan{{First: 0, Count: 3, GroupIndexes: []uint16{0}}}, Rows: []AdministrativeRowSummary{
				{Kind: contract.RetainedCanonicalSupportKind, RecordID: fid(20), BodyLength: 400},
				{Kind: contract.RetainedCanonicalSupportKind, RecordID: fid(21), BodyLength: 400},
				{Kind: contract.RetainedCanonicalSupportKind, RecordID: fid(22), BodyLength: 400}}}}
	legacy, err := EncodeAdministrativeIndex(index)
	// 115 header/tail + 8189*(247+9) + 28*7 + 2*108 + 9 + 3*37.
	if err != nil || len(legacy) != 2097031 {
		t.Fatal("independent legacy length", len(legacy), err)
	}
	pages, err := EncodeAdministrativeIndexPages(index)
	if err != nil || len(pages) != 1 {
		t.Fatal("legacy first shard", len(pages), err)
	}
	index.Pages[1].Rows[2].RecordID, index.Pages[1].Rows[2].MaterialID = fid(23), fid(22)
	body, err := EncodeAdministrativeIndex(index)
	if err != nil || len(body) != 2097127 {
		t.Fatal("first upgrade must charge all three sources", len(body), err)
	}
	pages, err = EncodeAdministrativeIndexPages(index)
	if err != nil || len(pages) != 2 {
		t.Fatal("first upgrade shard count", len(pages), err)
	}
	// The second material field starts at 2097024. The 2097036-byte
	// shard payload splits this 32-byte ID after its first twelve bytes.
	decoded, err := DecodeAdministrativeIndexPages(pages)
	if err != nil {
		t.Fatal("split material identity", err)
	}
	encoded, err := EncodeAdministrativeIndex(decoded)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatal("mixed source shard roundtrip", err)
	}
	index.Pages[1].Rows[2].RecordID, index.Pages[1].Rows[2].MaterialID = fid(22), ID{}
	encoded, err = EncodeAdministrativeIndex(index)
	if err != nil || !bytes.Equal(encoded, legacy) {
		t.Fatal("historical source encoding changed after last distinct source removal", err)
	}
}
