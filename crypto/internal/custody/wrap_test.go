package custody

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"

	"enkv.sh/core/contract"
)

func wrappingKey(t testing.TB) (*rsa.PrivateKey, contract.BindingTableRow) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, contract.BindingTableRow{SubjectKind: 1, SubjectID: testID(19), Binding: contract.KMSBinding{BindingID: testID(20), BindingIncarnationID: testID(21), BindingSerial: 7, Provider: contract.AWS, WrapProfile: 2, ProtectionClass: contract.HardwareProtection, KeySelector: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", SPKI: spki, Fingerprint: sha256.Sum256(spki)}}
}
func independentBindingDigest(b contract.KMSBinding) contract.ID {
	encoded := append([]byte{}, b.BindingID[:]...)
	encoded = append(encoded, b.BindingIncarnationID[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, b.BindingSerial)
	encoded = append(encoded, byte(b.Provider))
	encoded = binary.BigEndian.AppendUint16(encoded, b.WrapProfile)
	encoded = append(encoded, b.ProtectionClass)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(b.KeySelector)))
	encoded = append(encoded, b.KeySelector...)
	encoded = append(encoded, b.SPKI...)
	encoded = append(encoded, b.Fingerprint[:]...)
	preimage := []byte("ENKV/CRYPTO/v2/binding\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(encoded)))
	return sha256.Sum256(append(preimage, encoded...))
}
func independentPacketContext(c contract.WrapCore) contract.ID {
	b := binary.BigEndian.AppendUint16(nil, c.Schema)
	b = binary.BigEndian.AppendUint16(b, c.Profile)
	b = append(b, c.DomainID[:]...)
	b = append(b, c.CompatibilityID[:]...)
	b = append(b, c.CryptoSupportID[:]...)
	b = binary.BigEndian.AppendUint16(b, c.MaterialKind)
	b = append(b, c.MaterialID[:]...)
	b = append(b, c.MaterialContextDigest[:]...)
	b = append(b, c.SubjectKind)
	b = append(b, c.SubjectID[:]...)
	b = append(b, c.BindingID[:]...)
	b = binary.BigEndian.AppendUint64(b, c.BindingSerial)
	b = append(b, c.PublicBindingDigest[:]...)
	b = append(b, byte(c.Provider))
	b = binary.BigEndian.AppendUint16(b, c.WrapProfile)
	b = binary.BigEndian.AppendUint16(b, c.PacketKind)
	b = binary.BigEndian.AppendUint16(b, c.PacketLength)
	preimage := []byte("ENKV/CRYPTO/v2/rsa-packet\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(b)))
	return sha256.Sum256(append(preimage, b...))
}

// full_only: false
func TestValueWrapExactPacketAndBindings(t *testing.T) {
	private, recipient := wrappingKey(t)
	keys := fixtureKeys()
	defer clear(keys[:cap(keys)])
	for _, subjectKind := range []uint8{1, 2} {
		recipient.SubjectKind = subjectKind
		core, err := ValueWrapCore(fixtureValueCore(), recipient)
		if err != nil {
			t.Fatal(err)
		}
		if core.PublicBindingDigest != independentBindingDigest(recipient.Binding) || core.MaterialKind != 1 || core.PacketKind != 1 || core.PacketLength != 100 {
			t.Fatal("wrong public wrap context")
		}
		row, err := Wrap(core, recipient.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, row.RSACiphertext, nil)
		if err != nil {
			t.Fatal("RSA packet could not open")
		}
		defer clear(packet[:cap(packet)])
		digest := independentPacketContext(core)
		want := append([]byte{0, 2, 0, 1}, digest[:]...)
		want = append(want, keys...)
		defer clear(want[:cap(want)])
		if !bytes.Equal(packet, want) || len(row.RSACiphertext) != 384 || row.SubjectKind != subjectKind || row.SubjectID != recipient.SubjectID || row.BindingID != recipient.Binding.BindingID || row.BindingSerial != recipient.Binding.BindingSerial || row.PublicBindingDigest != core.PublicBindingDigest {
			t.Fatal("wrap differs from independent packet/binding")
		}
	}
}

// full_only: false
func TestWrapRejectsMismatchedBindingAndPurpose(t *testing.T) {
	_, recipient := wrappingKey(t)
	base, err := ValueWrapCore(fixtureValueCore(), recipient)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"binding", "serial", "digest", "provider", "profile", "packet-kind", "packet-length", "future-material", "key-length", "spki"} {
		t.Run(mode, func(t *testing.T) {
			core, binding, keys := base, recipient.Binding, fixtureKeys()
			defer clear(keys[:cap(keys)])
			switch mode {
			case "binding":
				core.BindingID[0] ^= 1
			case "serial":
				core.BindingSerial++
			case "digest":
				core.PublicBindingDigest[0] ^= 1
			case "provider":
				core.Provider = contract.GCP
			case "profile":
				core.WrapProfile++
			case "packet-kind":
				core.PacketKind = 2
			case "packet-length":
				core.PacketLength = 68
			case "future-material":
				core.MaterialKind = 3
			case "key-length":
				keys = keys[:63]
			case "spki":
				binding.SPKI = []byte("private-sentinel")
			}
			row, err := Wrap(core, binding, keys)
			if err == nil || row.RSACiphertext != nil {
				t.Fatal("mismatched wrap produced ciphertext")
			}
		})
	}
}
