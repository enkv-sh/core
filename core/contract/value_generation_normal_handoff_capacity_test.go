package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestNormalHandoffCapacityIndependentVector(t *testing.T) {
	id := func(n byte) ID { return ID(bytes.Repeat([]byte{n}, 32)) }
	v := GeneratedNormalCapacity{Schema: 1, BeforeRootDigest: id(1), TransitionID: id(2), Intent: DescriptorVector{Digest: id(3), Length: 100, Count: 1}}
	for i := range v.Groups {
		v.Groups[i] = GeneratorCapacityGroup{MaxCount: uint64(i + 1), MaxFramedBytes: uint64(1000 * (i + 1)), MaxPages: 1}
	}
	body, err := EncodeGeneratedNormalCapacity(v)
	if err != nil || len(body) != 471 {
		t.Fatal("normal capacity encoding", err, len(body))
	}
	want, _ := hex.DecodeString("f45b04b7fe08e82cbca7db97d8a60b0a1af455732bf6633a4d3640266e38ce96")
	if got := Hash(body); !bytes.Equal(got[:], want) {
		t.Fatal("normal row independent hash differs")
	}
	d, err := GeneratedNormalCapacityDescriptor(v)
	want, _ = hex.DecodeString("c1f4e566e83b7c80dff0d88905b169aa1b00cb46a9b18812c54a6809a8b86556")
	if err != nil || d.Length != 479 || d.Count != 1 || !bytes.Equal(d.Digest[:], want) {
		t.Fatal("normal purpose or framing differs", err, d)
	}
	parsed, err := InspectGeneratedNormalCapacity(body)
	if err != nil || parsed != v {
		t.Fatal("normal capacity round trip", err)
	}
	for i := range v.Groups {
		for _, fault := range []string{"count", "bytes", "pages", "oversized"} {
			bad := v
			switch fault {
			case "count":
				bad.Groups[i].MaxCount = 0
			case "bytes":
				bad.Groups[i].MaxFramedBytes = 0
			case "pages":
				bad.Groups[i].MaxPages = 0
			case "oversized":
				bad.Groups[i].MaxPages = 257
			}
			if _, err := GeneratedNormalCapacityDescriptor(bad); err == nil {
				t.Fatal("invalid normal capacity family admitted", i, fault)
			}
		}
	}
	for _, offset := range []int{0, 2, 34, 66, 137} {
		bad := bytes.Clone(body)
		bad[offset] ^= 0x80
		if _, err := InspectGeneratedNormalCapacity(bad); offset == 0 || offset == 137 {
			if err == nil {
				t.Fatal("invalid normal capacity frame admitted", offset)
			}
		}
	}
	v.Groups[0].MaxPages = 257
	if _, err := GeneratedNormalCapacityDescriptor(v); err != ErrRecordCapacity {
		t.Fatal("normal oversized capacity admitted", err)
	}
}
