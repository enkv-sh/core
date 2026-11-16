package custody

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func testID(n byte) (id contract.ID) {
	for i := range id {
		id[i] = n
	}
	return
}
func fixtureValueCore() contract.ValueCore {
	return contract.ValueCore{ValueSource: 1, Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: testID(1), CryptoSupportID: testID(2), DomainID: testID(3), Name: "n", EntryIncarnationID: testID(4), ValueStateID: testID(5), OriginSnapshotID: testID(6), OriginTransitionID: testID(7), DataKeyID: testID(8), DataKeyEpoch: 3, CommitmentKeyID: testID(9), CommitmentKeyEpoch: 4, ContentLength: 12, InputEncoding: contract.InputEncodingRaw, RetainedLength: 12}
}
func hexBytes(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func fixtureKeys() []byte {
	keys := make([]byte, 64)
	for i := range keys {
		keys[i] = byte(i)
	}
	return keys
}
func fixturePayload(t testing.TB) contract.CanonicalPayload {
	c := fixtureValueCore()
	p := contract.CanonicalPayload{Profile: c.Profile, CryptoSupportID: c.CryptoSupportID, DataKeyID: c.DataKeyID, DataKeyEpoch: c.DataKeyEpoch, CommitmentKeyID: c.CommitmentKeyID, CommitmentKeyEpoch: c.CommitmentKeyEpoch, ContentLength: c.ContentLength, Ciphertext: hexBytes(t, "3467b569a091ef6dec2de2eed61e538fa6af50eb45a405d49ecd3413"), InputEncoding: contract.InputEncodingRaw, RetainedLength: c.ContentLength}
	for i := range p.Nonce {
		p.Nonce[i] = byte(i)
	}
	copy(p.SemanticCommitment[:], hexBytes(t, "5c2e368f7b9ba6eb1d71d8a9d3ef147732fbd57b1a2c82c3cbdd8b435d8b13eb"))
	copy(p.PackageCheck[:], hexBytes(t, "4af6aa19449e1ce93737a4f23799e6d9253717b00038fddb70656c581ab2e89b"))
	return p
}

// full_only: false
func TestValueIndependentKnownAnswers(t *testing.T) {
	// Expected context is an independent scalar transcription. Expected HMAC,
	// HKDF and GCM bytes came from Node/OpenSSL with this literal context, not
	// from any production encoder or SealValue call.
	want := hexBytes(t, "000b0002"+strings.Repeat("01", 32)+strings.Repeat("02", 32)+strings.Repeat("03", 32)+"000000016e"+strings.Repeat("04", 32)+strings.Repeat("05", 32)+strings.Repeat("06", 32)+strings.Repeat("07", 32)+strings.Repeat("08", 32)+"0000000000000003"+strings.Repeat("09", 32)+"00000000000000040000000c010000000c01")
	core := fixtureValueCore()
	actual, err := contract.EncodeValueCore(core)
	if err != nil || !bytes.Equal(actual, want) {
		t.Fatal("context differs from independent bytes")
	}
	keys := fixtureKeys()
	defer clear(keys[:cap(keys)])
	check, err := PackageCheck(core, keys)
	if err != nil || check != fixturePayload(t).PackageCheck {
		t.Fatal("package check differs from independent HKDF/HMAC")
	}
	plaintext, err := OpenValue(core, fixturePayload(t), keys)
	if err != nil || !bytes.Equal(plaintext, []byte("secret-value")) || cap(plaintext) != 12 {
		t.Fatal("independent ciphertext did not open")
	}
	clear(plaintext[:cap(plaintext)])
}

// full_only: false
func TestValueRejectsDamageWithoutInputMutation(t *testing.T) {
	for _, mode := range []string{"data-key", "commitment-key", "package", "semantic", "nonce", "ciphertext", "tag", "context", "metadata", "short", "long", "key-length"} {
		t.Run(mode, func(t *testing.T) {
			core, p, keys := fixtureValueCore(), fixturePayload(t), fixtureKeys()
			defer clear(keys[:cap(keys)])
			switch mode {
			case "data-key":
				keys[0] ^= 1
			case "commitment-key":
				keys[32] ^= 1
			case "package":
				p.PackageCheck[0] ^= 1
			case "semantic":
				p.SemanticCommitment[0] ^= 1
			case "nonce":
				p.Nonce[0] ^= 1
			case "ciphertext":
				p.Ciphertext[0] ^= 1
			case "tag":
				p.Ciphertext[len(p.Ciphertext)-1] ^= 1
			case "context":
				core.DomainID[0] ^= 1
			case "metadata":
				p.DataKeyEpoch++
			case "short":
				p.Ciphertext = p.Ciphertext[:len(p.Ciphertext)-1]
			case "long":
				p.Ciphertext = append(p.Ciphertext, 0)
			case "key-length":
				keys = keys[:63]
			}
			before := bytes.Clone(p.Ciphertext)
			got, err := OpenValue(core, p, keys)
			if err == nil || got != nil {
				t.Fatal("damaged value released plaintext")
			}
			if !bytes.Equal(before, p.Ciphertext) {
				t.Fatal("Open modified borrowed ciphertext")
			}
		})
	}
}

// full_only: false
func TestValueSealBoundsAndIndependentKeys(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    uint8
		content  int
		retained []byte
	}{
		{"raw-empty", contract.InputEncodingRaw, 0, []byte{}},
		{"raw-one", contract.InputEncodingRaw, 1, []byte("d")},
		{"raw-maximum", contract.InputEncodingRaw, 65536, bytes.Repeat([]byte{'d'}, 65536)},
		{"base64-empty", contract.InputEncodingBase64, 0, []byte{}},
		{"base64-one", contract.InputEncodingBase64, 1, []byte("ZA==")},
		{"base64-maximum", contract.InputEncodingBase64, 65536, []byte(strings.Repeat("ZGRk", 21845) + "ZA==")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core := fixtureValueCore()
			core.InputEncoding, core.ContentLength, core.RetainedLength = tc.input, uint32(tc.content), uint32(len(tc.retained))
			p, keys, err := SealValue(core, tc.retained)
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 64 || cap(keys) != 64 || bytes.Equal(keys[:32], keys[32:]) || p.InputEncoding != tc.input || p.ContentLength != uint32(tc.content) || p.RetainedLength != uint32(len(tc.retained)) || len(p.Ciphertext) != len(tc.retained)+16 || cap(p.Ciphertext) != len(tc.retained)+16 {
				t.Fatal("wrong generated owners or representation metadata")
			}
			got, err := OpenValue(core, p, keys)
			if err != nil || !bytes.Equal(got, tc.retained) || cap(got) != len(tc.retained) {
				t.Fatal("sealed value did not open exact retained bytes", err)
			}
			if len(got) > 0 {
				original := tc.retained[0]
				got[0] ^= 1
				if tc.retained[0] != original {
					t.Fatal("output aliases retained input")
				}
			}
			clear(got[:cap(got)])
			clear(keys[:cap(keys)])
		})
	}
	core := fixtureValueCore()
	core.ContentLength, core.RetainedLength = contract.CryptoMaxRawValue+1, contract.CryptoMaxRawValue+1
	if _, keys, err := SealValue(core, make([]byte, contract.CryptoMaxRawValue+1)); err == nil || keys != nil {
		t.Fatal("oversized value accepted")
	}
	core = fixtureValueCore()
	if _, keys, err := SealValue(core, []byte("wrong")); err == nil || keys != nil {
		t.Fatal("length mismatch accepted")
	}
}
