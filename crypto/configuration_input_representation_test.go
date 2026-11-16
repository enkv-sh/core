package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// full_only: false
func TestConfigurationInputSealsExactBase64Representation(t *testing.T) {
	target, key := configurationInputFixture(t)
	// RFC 4648 vectors give C independently of the implementation decoder.
	for _, tc := range []struct {
		value   string
		content uint32
	}{{"", 0}, {"QQ==", 1}, {"QUI=", 2}, {"QUJD", 3}, {"UVVKRA==", 4}, {"AP8K", 3}} {
		t.Run(tc.value, func(t *testing.T) {
			value := tc.value
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			input := &sourceReader{Reader: bytes.NewReader([]byte(value))}
			body, err := SealConfigurationInput(ctx, target, input, ConfigurationInputOptions{Base64: true, MaximumRawLength: 65536})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := contract.DecodeSealedInputEnvelope(body)
			if err != nil {
				t.Fatal(err)
			}
			coreBytes, err := contract.EncodeSealedInputCore(envelope.Core)
			if err != nil {
				t.Fatal(err)
			}
			// The source-v4 layout has 240 fixed bytes before C, then C:u32,
			// input:u8, R:u32 and the 32-byte recipient-binding digest.
			lengthOffset := 240 + len(target.Name)
			if len(coreBytes) != 281+len(target.Name) || binary.BigEndian.Uint16(coreBytes[:2]) != 4 {
				t.Fatal("sealed input does not use the authenticated representation schema")
			}
			if binary.BigEndian.Uint32(coreBytes[lengthOffset:]) != tc.content || coreBytes[lengthOffset+4] != 2 || binary.BigEndian.Uint32(coreBytes[lengthOffset+5:]) != uint32(len(value)) {
				t.Fatal("sealed input did not bind its input tag and content/retained lengths")
			}
			if len(envelope.Ciphertext) != len(value)+16 {
				t.Fatal("ciphertext shape charges decoded bytes instead of retained bytes")
			}
			packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, envelope.AuthorityWrap.RSACiphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(packet[:cap(packet)])
			if len(packet) != 68 {
				t.Fatal("source key packet length differs")
			}
			retained, err := custody.OpenSealedInput(envelope.Core, envelope, packet[36:])
			if err != nil {
				t.Fatal(err)
			}
			defer clear(retained[:cap(retained)])
			if !bytes.Equal(retained, []byte(value)) || input.reads == 0 || input.closes != 1 {
				t.Fatal("sealing changed retained representation or input ownership")
			}
			if value == "QUJD" {
				for _, mutation := range []struct {
					name              string
					content, retained uint32
					input             byte
				}{{"input-tag", 4, 4, 1}, {"content-length", 2, 4, 2}, {"retained-length", 4, 8, 2}} {
					t.Run(mutation.name, func(t *testing.T) {
						changed := bytes.Clone(coreBytes)
						binary.BigEndian.PutUint32(changed[lengthOffset:], mutation.content)
						changed[lengthOffset+4] = mutation.input
						binary.BigEndian.PutUint32(changed[lengthOffset+5:], mutation.retained)
						core, err := contract.DecodeSealedInputCore(changed)
						if err != nil {
							t.Fatal("structurally valid metadata mutation was not admitted", err)
						}
						damaged := envelope
						damaged.Core = core
						damaged.Ciphertext = append(bytes.Clone(envelope.Ciphertext), make([]byte, int(mutation.retained)-len(value))...)
						if _, err := contract.SealedInputEnvelopeLength(damaged); err != nil {
							t.Fatal("mutation failed structural envelope validation", err)
						}
						opened, err := custody.OpenSealedInput(core, damaged, packet[36:])
						defer clear(opened[:cap(opened)])
						if err == nil || len(opened) != 0 {
							t.Fatal("changed input tag or C/R passed authenticated opening")
						}
					})
				}
			}
			if value == "QQ==" {
				for _, invalid := range []string{"YR==", "YQ=\n", "____", "=YQ=", "QUJD"} {
					t.Run("authenticated-invalid/"+invalid, func(t *testing.T) {
						if _, err := custody.SealInput(envelope.Core, target.Bindings[0], []byte(invalid)); err == nil {
							t.Fatal("custody sealed invalid or mismatched declared Base64")
						}
						// Independently seal invalid bytes under the valid AAD so this
						// exercises validation after successful AEAD authentication.
						aad, err := contract.EncodeSealedInputAAD(envelope.Core)
						if err != nil {
							t.Fatal(err)
						}
						block, err := aes.NewCipher(packet[36:])
						if err != nil {
							t.Fatal(err)
						}
						gcm, err := cipher.NewGCM(block)
						if err != nil {
							t.Fatal(err)
						}
						damaged := envelope
						damaged.Ciphertext = gcm.Seal(nil, damaged.Nonce[:], []byte(invalid), aad)
						opened, err := custody.OpenSealedInput(envelope.Core, damaged, packet[36:])
						defer clear(opened[:cap(opened)])
						if err == nil || len(opened) != 0 {
							t.Fatal("authenticated invalid or mismatched Base64 escaped custody")
						}
					})
				}
			}
		})
	}
}
