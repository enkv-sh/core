package format

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

func accessFixture() AccessPage {
	return AccessPage{Domain: fid(1), Object: fid(2), Index: 255, Records: []contract.AccessRecord{{
		Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: fid(3), MaterialContextDigest: fid(4), PackageCheck: fid(5),
		Wraps: []contract.WrapRow{{SubjectKind: 1, SubjectID: fid(6), BindingID: fid(7), BindingSerial: 1, PublicBindingDigest: fid(8), RSACiphertext: bytes.Repeat([]byte{0xa5}, 384)}},
	}}}
}

// full_only: false
func TestAccessPageCanonicalIndexAndOwnership(t *testing.T) {
	for _, index := range []uint16{0, 31, 32, 255, 256} {
		page := accessFixture()
		page.Index = index
		body, err := EncodeAccessPage(page)
		if index == 256 {
			if err == nil {
				t.Fatal("access index256 encoded")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeAccessPage(body)
		if err != nil || got.Index != index {
			t.Fatal("canonical access index refused", index, err)
		}
		encoded, err := EncodeAccessPage(got)
		if err != nil || !bytes.Equal(body, encoded) {
			t.Fatal("access record did not round trip")
		}
		body[len(body)-1] ^= 1
		if got.Records[0].Wraps[0].RSACiphertext[383] != 0xa5 {
			t.Fatal("decoded access retained borrowed ciphertext")
		}
		body[71], body[72] = 1, 0
		if _, err := DecodeAccessPage(body); err == nil {
			t.Fatal("access index256 decoded")
		}
	}
}
