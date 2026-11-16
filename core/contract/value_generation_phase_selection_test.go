package contract

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// full_only: false
func TestGeneratedPhaseSelectionAnchorUsesVersionedWidth(t *testing.T) {
	body, err := EncodeGeneratedPhaseRecord(generatedRecordPhase())
	if err != nil {
		t.Fatal("encode unselected Phase", err)
	}
	if len(body) != 716 {
		t.Fatalf("Phase omitted its canonical-selection anchor: got %d bytes, want 716", len(body))
	}
	if !bytes.Equal(body[:2], []byte{0, 2}) || !bytes.Equal(body[596:], make([]byte, 120)) {
		t.Fatal("unselected Phase did not use schema 2 with a zero selection anchor")
	}
}

// full_only: false
func TestGeneratedPhaseSelectionAnchorAcceptsOnlyCompleteIndependentBodies(t *testing.T) {
	// Big-endian concatenation: schema 2; IDs 1..7; two absent result IDs;
	// phase/index/branch/stage/N/R; descriptors 8..12; typed empty proofs;
	// absent FinalPreparationID; then the 120-byte selection anchor.
	// The three fixed empty digests are Python hashlib.sha256 over
	// "ENKV/GENERATOR/v1/" + label + NUL + uint32be(4) + uint32be(0).
	idHex := func(n byte) string { return strings.Repeat(hex.EncodeToString([]byte{n}), 32) }
	descriptorTail := "000000000000000400000000"
	prefix := "0002"
	for n := byte(1); n <= 7; n++ {
		prefix += idHex(n)
	}
	prefix += strings.Repeat("00", 64) + "00000001000000010000"
	for n := byte(8); n <= 12; n++ {
		prefix += idHex(n) + descriptorTail
	}
	prefix += "a6659542c5ea7cff99112402d26aacc0f0ad99e22cdb2f6ecaff8e26d4847365" + descriptorTail + strings.Repeat("00", 32)
	anchor := idHex(13) + "3d240a9d5d0241648525855d4f6d251f87630ee51adab9414bbe8a429c186b6d" + descriptorTail +
		"48314ad098b2bfe3230c4ad29c7a4ed63f159b2c1684e27510ae65769156afcd" + descriptorTail
	for _, tc := range []struct {
		name, suffix string
	}{
		{name: "unselected", suffix: strings.Repeat("00", 120)},
		{name: "selected", suffix: anchor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(prefix + tc.suffix)
			if err != nil || len(want) != 716 {
				t.Fatal("independent Phase literal", len(want), err)
			}
			decoded, err := InspectGeneratedPhaseRecord(want)
			if err != nil {
				t.Fatal("complete independently encoded Phase refused", err)
			}
			encoded, err := EncodeGeneratedPhaseRecord(decoded)
			if err != nil || !bytes.Equal(encoded, want) {
				t.Fatal("Phase did not preserve exact independent anchor bytes", err)
			}
			for _, size := range []int{595, 596, 627, 628, 671, 672, 715} {
				if _, err := InspectGeneratedPhaseRecord(want[:size]); err == nil {
					t.Fatal("incomplete selection anchor accepted", size)
				}
			}
			bad := append(bytes.Clone(want), 0)
			if _, err := InspectGeneratedPhaseRecord(bad); err == nil {
				t.Fatal("trailing Phase byte accepted")
			}
			bad = bytes.Clone(want)
			bad[1] = 1
			if _, err := InspectGeneratedPhaseRecord(bad); err == nil {
				t.Fatal("old Phase schema accepted")
			}
			if tc.name == "selected" {
				for _, span := range [][2]int{{596, 628}, {628, 672}, {672, 716}} {
					bad := bytes.Clone(want)
					clear(bad[span[0]:span[1]])
					if _, err := InspectGeneratedPhaseRecord(bad); err == nil {
						t.Fatal("partial selection anchor accepted", span)
					}
				}
				bad := bytes.Clone(want)
				copy(bad[628:660], want[672:704])
				if _, err := InspectGeneratedPhaseRecord(bad); err == nil {
					t.Fatal("changed-access digest used as empty changed-subject commitment")
				}
			}
		})
	}
}
