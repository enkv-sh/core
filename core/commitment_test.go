package core

import (
	"encoding/hex"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestIntentCommitmentGolden(t *testing.T) {
	var one, two contract.ID
	for i := range one {
		one[i], two[i] = 1, 2
	}
	desiredEntries := []ApplyEntryInput{
		{Name: "a", Recipients: []contract.ID{two}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
		{Name: "b", Recipients: []contract.ID{two}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte{0, 255}},
	}
	// Independent Python hashlib/struct scalar assembly first reproduced the
	// prior supplied-intent-v7 length362 and hash11f60e13... exactly. The v8
	// rows encode content:u32, input:u8, retained:u32 and output:u8 before
	// each plain-input-v1 digest. Empty a is C0/R0; b is C2/R2
	// raw or C2/R4 Base64 AP8=. Both rows end in discriminator0 and two zero
	// 32-byte pin fields. Both complete preimages have length374.
	for _, test := range []struct {
		name   string
		base64 bool
		digest string
	}{
		{"raw", false, "b3b9f88700599f9a95068c9843e5237849de1041c39dd36142d158b228da0fb4"},
		{"Base64 retained", true, "b0464dbecce7f54c2aef02647beee054c29665b4908c1f8dd4338f90e75d494c"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := append([]ApplyEntryInput(nil), desiredEntries...)
			if test.base64 {
				input[1].InputEncoding = contract.InputEncodingBase64
				input[1].InputBytes = []byte("AP8=")
			}
			digest, length := entryInputCommitment(one, input)
			if length != 374 || hex.EncodeToString(digest[:]) != test.digest {
				t.Fatalf("commitment changed: %d %x", length, digest)
			}
		})
	}
}
