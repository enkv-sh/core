package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func generatorCapacityFixture() GeneratorCapacityEvidence {
	v := GeneratorCapacityEvidence{Schema: 1, BeforeRootDigest: generatedRecordID(1), PlanGraphID: generatedRecordID(2),
		Declaration: GeneratorDescriptor{Digest: generatedRecordID(3), Length: 100, Count: 1}}
	for i := range v.Groups {
		v.Groups[i] = GeneratorCapacityGroup{MaxCount: uint64(i + 1), MaxFramedBytes: uint64(1000 * (i + 1)), MaxPages: 1}
	}
	return v
}

// Independent Node concatenation uses big-endian integers: u16(1), three
// repeated-byte IDs(1,2,3), u64(100), u32(1), u32(17), then seventeen rows
// u8(i),u64(i),u64(1000*i),u32(1) for i=1..17. Descriptor hashing adds
// ENKV/GENERATOR/v1/capacity-reservation\0,u32(479),u32(1),u32(471).
// full_only: false
func TestGeneratorCapacityEvidenceIndependentVector(t *testing.T) {
	v := generatorCapacityFixture()
	body, err := EncodeGeneratorCapacityEvidence(v)
	if err != nil || len(body) != 471 {
		t.Fatal("capacity evidence length", len(body), err)
	}
	d, err := GeneratorCapacityDescriptor(v)
	if err != nil || d.Count != 1 || d.Length != 479 {
		t.Fatal("capacity descriptor", d, err)
	}
	if got, err := InspectGeneratorCapacityEvidence(body); err != nil || got != v {
		t.Fatal("capacity evidence round trip", err)
	}
	for _, tc := range []struct {
		actual   ID
		expected string
	}{
		{Hash(body), "f45b04b7fe08e82cbca7db97d8a60b0a1af455732bf6633a4d3640266e38ce96"},
		{d.Digest, "b905adebfc587548cfb58d38511ab0cf8143100b1fb9f00f4a69d3815dfa6a7e"},
	} {
		if hex.EncodeToString(tc.actual[:]) != tc.expected {
			t.Fatal("independent capacity evidence hash", hex.EncodeToString(tc.actual[:]))
		}
	}
}

// full_only: false
func TestGeneratorCapacityEvidenceRejectsOpenShapeAndExcess(t *testing.T) {
	v := generatorCapacityFixture()
	body, err := EncodeGeneratorCapacityEvidence(v)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(body); n++ {
		if _, err := InspectGeneratorCapacityEvidence(body[:n]); err == nil {
			t.Fatal("truncated capacity evidence accepted", n)
		}
	}
	for _, offset := range []int{1, 113, 114, 135, 450} {
		bad := bytes.Clone(body)
		bad[offset]++
		if _, err := InspectGeneratorCapacityEvidence(bad); err == nil {
			t.Fatal("unknown schema, group count, or ordered tag accepted", offset)
		}
	}
	if _, err := InspectGeneratorCapacityEvidence(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("trailing capacity evidence accepted")
	}
	for name, change := range map[string]func(*GeneratorCapacityEvidence){
		"missing predecessor": func(v *GeneratorCapacityEvidence) { v.BeforeRootDigest = ID{} },
		"missing graph":       func(v *GeneratorCapacityEvidence) { v.PlanGraphID = ID{} },
		"missing declaration": func(v *GeneratorCapacityEvidence) { v.Declaration = GeneratorDescriptor{} },
		"no pages":            func(v *GeneratorCapacityEvidence) { v.Groups[0].MaxPages = 0 },
		"no count":            func(v *GeneratorCapacityEvidence) { v.Groups[0].MaxCount = 0 },
		"no bytes":            func(v *GeneratorCapacityEvidence) { v.Groups[0].MaxFramedBytes = 0 },
		"excess bytes":        func(v *GeneratorCapacityEvidence) { v.Groups[0].MaxFramedBytes = 1 << 63 },
		"excess count":        func(v *GeneratorCapacityEvidence) { v.Groups[0].MaxCount = 1 << 63 },
		"excess pages":        func(v *GeneratorCapacityEvidence) { v.Groups[0].MaxPages = 1 << 31 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			change(&bad)
			if _, err := EncodeGeneratorCapacityEvidence(bad); err == nil {
				t.Fatal("invalid capacity evidence encoded")
			}
			if _, err := GeneratorCapacityDescriptor(bad); err == nil {
				t.Fatal("invalid capacity evidence committed")
			}
		})
	}
	v.Groups = [GeneratorCapacityGroupCount]GeneratorCapacityGroup{}
	v.Groups[0] = GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: 256 * (2<<20 - 75), MaxPages: 256}
	if _, err := GeneratorCapacityDescriptor(v); err != nil {
		t.Fatal("exact child boundary refused", err)
	}
	v.Groups[1] = GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: 1, MaxPages: 1}
	if _, err := GeneratorCapacityDescriptor(v); err != ErrRecordCapacity {
		t.Fatal("excess child accepted", err)
	}
}
