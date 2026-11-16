package custody

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func fixtureSourceCore() contract.SealedInputCore {
	return contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: 4, Profile: 2, CompatibilityID: testID(1), DomainID: testID(3), FileIdentity: testID(10), FilePredecessorDigest: testID(11), SourceID: testID(12), CryptoSupportID: testID(2), DataKeyID: testID(15), DataKeyEpoch: 5, ContentLength: 12, IntendedRecipientBindingSetDigest: testID(16), InputEncoding: contract.InputEncodingRaw, RetainedLength: 12}, Name: "n"}
}
func fixtureSourceKeys() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(64 + i)
	}
	return k
}
func fixtureSource(t testing.TB) contract.SealedInputEnvelope {
	s := contract.SealedInputEnvelope{Core: fixtureSourceCore(), Ciphertext: hexBytes(t, "b6171da35df9de2908573b2befc00252964f0719a4a88bd907b8f65b"), AuthorityWrap: contract.WrapRow{SubjectKind: 1, SubjectID: testID(19), BindingID: testID(20), BindingSerial: 7, PublicBindingDigest: testID(21), RSACiphertext: make([]byte, 384)}}
	for i := range s.Nonce {
		s.Nonce[i] = byte(i + 12)
	}
	return s
}

// full_only: false
func TestSourceIndependentKnownAnswer(t *testing.T) {
	// Source AAD transcription and Node/OpenSSL ciphertext are independent of
	// production SealedInputCore writers and SealInput.
	want := hexBytes(t, "00040002"+strings.Repeat("01", 32)+strings.Repeat("03", 32)+strings.Repeat("0a", 32)+strings.Repeat("0b", 32)+strings.Repeat("0c", 32)+"000000016e"+strings.Repeat("02", 32)+strings.Repeat("0f", 32)+"00000000000000050000000c010000000c"+strings.Repeat("10", 32))
	core := fixtureSourceCore()
	actual, err := contract.EncodeSealedInputCore(core)
	if err != nil || !bytes.Equal(actual, want) {
		t.Fatal("source context differs from independent bytes")
	}
	keys := fixtureSourceKeys()
	defer clear(keys[:cap(keys)])
	got, err := OpenSealedInput(core, fixtureSource(t), keys)
	if err != nil || !bytes.Equal(got, []byte("secret-value")) || cap(got) != 12 {
		t.Fatal("independent source did not open")
	}
	clear(got[:cap(got)])
}

// full_only: false
func TestSourceSealAndRefusal(t *testing.T) {
	private, authority := wrappingKey(t)
	for _, n := range []int{0, 12, contract.CryptoMaxRawValue} {
		core := fixtureSourceCore()
		core.ContentLength = uint32(n)
		core.RetainedLength = uint32(n)
		plain := bytes.Repeat([]byte{0x73}, n)
		source, err := SealInput(core, authority, plain)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := SealedInputWrapCore(core, authority)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, source.AuthorityWrap.RSACiphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(packet) != 68 || packet[0] != 0 || packet[1] != 2 || packet[2] != 0 || packet[3] != 2 {
			t.Fatal("source used another packet kind")
		}
		digest := independentPacketContext(wrap)
		if !bytes.Equal(packet[4:36], digest[:]) {
			t.Fatal("source packet has another context")
		}
		got, err := OpenSealedInput(core, source, packet[36:])
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("sealed source did not open")
		}
		clear(got[:cap(got)])
		clear(packet[:cap(packet)])
	}
	for _, mode := range []string{"context", "nonce", "ciphertext", "tag", "key", "key-length", "short", "long", "recovery-wrap"} {
		t.Run(mode, func(t *testing.T) {
			core, s, keys := fixtureSourceCore(), fixtureSource(t), fixtureSourceKeys()
			defer clear(keys[:cap(keys)])
			switch mode {
			case "context":
				core.FileIdentity[0] ^= 1
			case "nonce":
				s.Nonce[0] ^= 1
			case "ciphertext":
				s.Ciphertext[0] ^= 1
			case "tag":
				s.Ciphertext[len(s.Ciphertext)-1] ^= 1
			case "key":
				keys[0] ^= 1
			case "key-length":
				keys = keys[:31]
			case "short":
				s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			case "long":
				s.Ciphertext = append(s.Ciphertext, 0)
			case "recovery-wrap":
				s.AuthorityWrap.SubjectKind = 2
			}
			before := bytes.Clone(s.Ciphertext)
			got, err := OpenSealedInput(core, s, keys)
			if err == nil || got != nil || !bytes.Equal(before, s.Ciphertext) {
				t.Fatal("invalid source released plaintext or changed input")
			}
		})
	}
	authority.SubjectKind = 2
	if _, err := SealInput(fixtureSourceCore(), authority, []byte("secret-value")); err == nil {
		t.Fatal("source accepted dedicated recovery as authority")
	}
	authority.SubjectKind = 1
	core := fixtureSourceCore()
	core.ContentLength, core.RetainedLength = contract.CryptoMaxRawValue+1, contract.CryptoMaxRawValue+1
	if _, err := SealInput(core, authority, make([]byte, contract.CryptoMaxRawValue+1)); err == nil {
		t.Fatal("oversized source accepted")
	}
}
