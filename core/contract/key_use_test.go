package contract

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

// full_only: false
func TestKeyUseRowsIndependentWireAndClosedFields(t *testing.T) {
	var rows []KeyUseRow
	// Independent schema: u16(row count), then ID1, ID2, subject kind1,
	// ID3, provider1, purpose3, outcome1..4 and big-endian count1..4.
	want := []byte{0, 4}
	for i := uint8(1); i <= 4; i++ {
		rows = append(rows, KeyUseRow{BindingID: generatedRecordID(1), PublicBindingDigest: generatedRecordID(2),
			SubjectKind: 1, SubjectID: generatedRecordID(3), Provider: AWS, Purpose: KeyUseMaterialOpen, Outcome: i, Count: uint32(i)})
		want = append(want, bytes.Repeat([]byte{1}, 32)...)
		want = append(want, bytes.Repeat([]byte{2}, 32)...)
		want = append(want, 1)
		want = append(want, bytes.Repeat([]byte{3}, 32)...)
		want = append(want, 1, 3, i)
		want = binary.BigEndian.AppendUint32(want, uint32(i))
	}
	body, err := EncodeKeyUseRows(rows)
	if err != nil || len(body) != 418 || !bytes.Equal(body, want) {
		t.Fatalf("key-use wire differs: length=%d err=%v", len(body), err)
	}
	got, err := DecodeKeyUseRows(want)
	if err != nil || !slices.Equal(got, rows) {
		t.Fatal("independent rows did not decode exactly", err)
	}
	for _, field := range []string{"purpose", "outcome"} {
		for _, unknown := range []uint8{0, 5, 255} {
			bad := slices.Clone(rows)
			offset := 2 + 32 + 32 + 1 + 32 + 1
			if field == "purpose" {
				bad[0].Purpose = unknown
			} else {
				bad[0].Outcome = unknown
				offset++
			}
			if _, err := EncodeKeyUseRows(bad); err == nil {
				t.Fatalf("unknown %s %d encoded", field, unknown)
			}
			damaged := bytes.Clone(want)
			damaged[offset] = unknown
			if _, err := InspectKeyUseRows(damaged); err == nil {
				t.Fatalf("unknown %s %d inspected", field, unknown)
			}
		}
	}
	for _, bad := range [][]KeyUseRow{append(slices.Clone(rows), rows[3]), {rows[1], rows[0]}} {
		if _, err := EncodeKeyUseRows(bad); err == nil {
			t.Fatal("duplicate or out-of-order rows encoded")
		}
	}
}
