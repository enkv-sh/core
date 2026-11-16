package contract

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// full_only: false
func TestGeneratorLogicalSliceIgnoresPhysicalLocation(t *testing.T) {
	v := GeneratorSliceLocation{Schema: 1, ContentKind: GeneratorContentSource, ContentID: generatedRecordID(1),
		BlobID: generatedRecordID(2), Offset: 17, Length: 23, Digest: generatedRecordID(3)}
	logical, err := GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{v.Logical()})
	if err != nil || logical.Length != 79 || logical.Count != 1 {
		t.Fatal("logical slice", logical, err)
	}
	body, err := EncodeGeneratorSliceLocation(v)
	if err != nil || len(body) != 111 {
		t.Fatal("slice location", len(body), err)
	}
	before, err := GeneratorVectorDescriptor(GeneratorVectorSlices, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	v.BlobID, v.Offset = generatedRecordID(4), 99
	afterLogical, err := GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{v.Logical()})
	if err != nil || afterLogical != logical {
		t.Fatal("physical relocation changed logical identity", err)
	}
	body, err = EncodeGeneratorSliceLocation(v)
	if err != nil {
		t.Fatal(err)
	}
	after, err := GeneratorVectorDescriptor(GeneratorVectorSlices, [][]byte{body})
	if err != nil || before == after {
		t.Fatal("physical location not committed", err)
	}
	v.Length++
	damaged, err := GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{v.Logical()})
	if err != nil || damaged == logical {
		t.Fatal("logical length not committed", err)
	}
}

// full_only: false
func TestGeneratorVectorCarrierExactBytesAndOwnerFamily(t *testing.T) {
	id := generatedRecordID
	row, err := EncodeGeneratorProgress(GeneratorProgress{Schema: 1, AttemptID: id(1), ResultID: id(2),
		Evidence: EmptyGeneratorVector(GeneratorVectorProofs), RequiredSteps: 1, CompletionClass: 1})
	if err != nil {
		t.Fatal(err)
	}
	d, err := GeneratorVectorDescriptor(GeneratorVectorProgress, [][]byte{row})
	if err != nil {
		t.Fatal(err)
	}
	v := GeneratorVectorCarrier{Schema: 1, DomainID: id(3), OwnerKind: 9, OwnerID: id(1),
		VectorKind: GeneratorVectorProgress, Vector: d, Row: row}
	b, err := EncodeGeneratorVectorCarrier(v)
	if err != nil || len(b) != 233 {
		t.Fatal("carrier", len(b), err)
	}
	// Independent field concatenation; the descriptor is an opaque value in
	// this wire check. Descriptor hashing has a separate fixed literal test.
	want := []byte{0, 1}
	want = append(want, bytes.Repeat([]byte{3}, 32)...)
	want = append(want, 9)
	want = append(want, bytes.Repeat([]byte{1}, 32)...)
	want = append(want, 2, 0, 0, 0, 0)
	want = append(want, d.Digest[:]...)
	want = binary.BigEndian.AppendUint64(want, d.Length)
	want = binary.BigEndian.AppendUint32(want, d.Count)
	want = binary.BigEndian.AppendUint32(want, uint32(len(row)))
	want = append(want, row...)
	if !bytes.Equal(b, want) {
		t.Fatal("carrier field order differs")
	}
	parsed, err := InspectGeneratorVectorCarrier(b)
	if err != nil || parsed.DomainID != v.DomainID || parsed.OwnerID != v.OwnerID || !bytes.Equal(parsed.Row, row) {
		t.Fatal("carrier traversal", err)
	}
	for n := range b {
		if _, err := InspectGeneratorVectorCarrier(b[:n]); err == nil {
			t.Fatal("accepted truncation", n)
		}
	}
	for _, edit := range []func(*GeneratorVectorCarrier){
		func(v *GeneratorVectorCarrier) { v.Schema = 2 },
		func(v *GeneratorVectorCarrier) { v.DomainID = ID{} },
		func(v *GeneratorVectorCarrier) { v.OwnerID = ID{} },
		func(v *GeneratorVectorCarrier) { v.OwnerKind = 2 },
		func(v *GeneratorVectorCarrier) { v.VectorKind = GeneratorVectorFacts },
		func(v *GeneratorVectorCarrier) { v.Ordinal = 1 },
		func(v *GeneratorVectorCarrier) { v.Vector = EmptyGeneratorVector(GeneratorVectorProgress) },
		func(v *GeneratorVectorCarrier) { v.Row = append(bytes.Clone(v.Row), 0) },
	} {
		bad := v
		edit(&bad)
		if _, err := EncodeGeneratorVectorCarrier(bad); err == nil {
			t.Fatal("accepted invalid carrier")
		}
	}
	key, err := GeneratorVectorCarrierID(v)
	if err != nil {
		t.Fatal(err)
	}
	if domain, err := SupportRecordDomain(SupportRecord{Kind: 14, RecordID: key, Body: b}); err != nil || domain != id(3) {
		t.Fatal("support traversal", err)
	}
	if _, err := SupportRecordDomain(SupportRecord{Kind: 14, RecordID: id(4), Body: b}); err == nil {
		t.Fatal("wrong carrier identity accepted")
	}
}

// full_only: false
func TestGeneratorVectorEmptyAndOrderedRows(t *testing.T) {
	for kind := GeneratorVectorTargets; kind <= GeneratorVectorFacts; kind++ {
		d, err := GeneratorVectorDescriptor(kind, nil)
		if err != nil || d != EmptyGeneratorVector(kind) || d.Count != 0 || d.Length != 4 {
			t.Fatal("empty family", kind, d, err)
		}
		if kind > GeneratorVectorTargets && d == EmptyGeneratorVector(kind-1) {
			t.Fatal("families share a hash purpose")
		}
	}
	if _, err := GeneratorVectorDescriptor(0, nil); err == nil {
		t.Fatal("unknown family accepted")
	}
	row := func(n byte) []byte {
		b, err := EncodeGeneratorSliceLocation(GeneratorSliceLocation{Schema: 1, ContentKind: 1,
			ContentID: generatedRecordID(n), BlobID: generatedRecordID(3), Length: 1, Digest: generatedRecordID(4)})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, b := row(1), row(2)
	for _, rows := range [][][]byte{{b, a}, {a, a}} {
		if _, err := GeneratorVectorDescriptor(GeneratorVectorSlices, rows); err == nil {
			t.Fatal("noncanonical vector order accepted")
		}
	}
	if _, err := GeneratorVectorDescriptor(GeneratorVectorSlices, [][]byte{a, b}); err != nil {
		t.Fatal("ordered vector refused", err)
	}
}

// full_only: false
func TestGeneratorHistorySequencePreservesEachAttemptOwner(t *testing.T) {
	id := generatedRecordID
	first := GeneratorHistory{Schema: 1, PredecessorAttemptID: id(1), NextAttemptID: id(2), OwnerID: id(3),
		Outcome: GeneratedEffectClosedWithResidue, Edge: 2}
	last := GeneratorHistory{Schema: 1, PredecessorAttemptID: id(2), OwnerID: id(4), Outcome: GeneratedEffectTransmitted}
	encode := func(v GeneratorHistory) []byte {
		t.Helper()
		body, err := EncodeGeneratorHistory(v)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	if _, err := GeneratorVectorDescriptor(GeneratorVectorHistory, [][]byte{encode(first), encode(last)}); err != nil {
		t.Fatal("consecutive create Attempts cannot retain their distinct owners", err)
	}
	for name, rows := range map[string][]GeneratorHistory{
		"reversed":        {last, first},
		"duplicate":       {first, first, last},
		"absent frontier": {first},
	} {
		t.Run(name, func(t *testing.T) {
			var bodies [][]byte
			for _, row := range rows {
				bodies = append(bodies, encode(row))
			}
			if _, err := GeneratorVectorDescriptor(GeneratorVectorHistory, bodies); err == nil {
				t.Fatal("invalid history sequence accepted")
			}
		})
	}
}
