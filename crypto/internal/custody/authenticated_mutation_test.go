package custody

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

func encodedAuthenticatedSeed[T any](t *testing.T, value T, encode func(T) ([]byte, error)) []byte {
	t.Helper()
	wire, err := encode(value)
	if err != nil {
		t.Fatal("authenticated seed encoding", err)
	}
	return wire
}

// Each changed record remains a valid outer record. A refusal therefore has
// to come from the private authenticated input, not from the wire parser.
// full_only: false
func TestAuthenticatedCustodyBitMutationRefusesPlaintext(t *testing.T) {
	check := func(t *testing.T, original, changed, alternate []byte, inspect func([]byte) error,
		open func([]byte) ([]byte, error), originalPlain, alternatePlain []byte) {
		t.Helper()
		if bytes.Equal(original, changed) || bytes.Equal(original, alternate) || bytes.Equal(changed, alternate) {
			t.Fatal("authenticated seeds are not distinct")
		}
		for _, row := range []struct {
			name string
			wire []byte
			want []byte
		}{
			{name: "fixed", wire: original, want: originalPlain},
			{name: "one-bit", wire: changed},
			{name: "valid-alternative", wire: alternate, want: alternatePlain},
		} {
			t.Run(row.name, func(t *testing.T) {
				if err := inspect(row.wire); err != nil {
					t.Fatal("authenticated seed failed outer framing", err)
				}
				before := bytes.Clone(row.wire)
				plain, err := open(row.wire)
				if !bytes.Equal(row.wire, before) {
					t.Fatal("private open changed borrowed input")
				}
				if row.want == nil {
					if err == nil || plain != nil {
						if plain != nil {
							clear(plain[:cap(plain)])
						}
						t.Fatal("altered authenticated seed released plaintext")
					}
					return
				}
				if err != nil || !bytes.Equal(plain, row.want) || cap(plain) != len(row.want) {
					if plain != nil {
						clear(plain[:cap(plain)])
					}
					t.Fatal("valid authenticated seed did not open exactly", err)
				}
				clear(plain[:cap(plain)])
			})
		}
	}
	t.Run("value-ciphertext", func(t *testing.T) {
		core, fixed, keys := fixtureValueCore(), fixturePayload(t), fixtureKeys()
		defer clear(keys[:cap(keys)])
		original := encodedAuthenticatedSeed(t, fixed, contract.EncodeCanonicalPayload)
		changed := fixed
		changed.Ciphertext = bytes.Clone(fixed.Ciphertext)
		changed.Ciphertext[0] ^= 1
		damaged := encodedAuthenticatedSeed(t, changed, contract.EncodeCanonicalPayload)
		other, otherKeys, err := SealValue(core, []byte("other-secret"))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(otherKeys[:cap(otherKeys)])
		alternate := encodedAuthenticatedSeed(t, other, contract.EncodeCanonicalPayload)
		check(t, original, damaged, alternate,
			func(wire []byte) error { _, err := contract.InspectCanonicalPayload(wire); return err },
			func(wire []byte) ([]byte, error) {
				view, err := contract.InspectCanonicalPayload(wire)
				if err != nil {
					return nil, err
				}
				if bytes.Equal(wire, alternate) {
					return OpenValue(core, contract.CanonicalPayload(view), otherKeys)
				}
				return OpenValue(core, contract.CanonicalPayload(view), keys)
			}, []byte("secret-value"), []byte("other-secret"))
	})

	t.Run("sealed-input-tag", func(t *testing.T) {
		core, fixed, keys := fixtureSourceCore(), fixtureSource(t), fixtureSourceKeys()
		defer clear(keys[:cap(keys)])
		original := encodedAuthenticatedSeed(t, fixed, contract.EncodeSealedInputEnvelope)
		changed := fixed
		changed.Ciphertext = bytes.Clone(fixed.Ciphertext)
		changed.Ciphertext[len(changed.Ciphertext)-1] ^= 1
		damaged := encodedAuthenticatedSeed(t, changed, contract.EncodeSealedInputEnvelope)
		aad, err := contract.EncodeSealedInputAAD(core)
		if err != nil {
			t.Fatal(err)
		}
		other := fixed
		other.Nonce, other.Ciphertext, err = sealPayload(keys, []byte("other-secret"), aad)
		if err != nil {
			t.Fatal(err)
		}
		alternate := encodedAuthenticatedSeed(t, other, contract.EncodeSealedInputEnvelope)
		check(t, original, damaged, alternate,
			func(wire []byte) error { _, err := contract.InspectSealedInputEnvelope(wire); return err },
			func(wire []byte) ([]byte, error) {
				view, err := contract.InspectSealedInputEnvelope(wire)
				if err != nil {
					return nil, err
				}
				owned, err := view.Own()
				if err != nil {
					return nil, err
				}
				return OpenSealedInput(core, owned, keys)
			}, []byte("secret-value"), []byte("other-secret"))
	})

	t.Run("generated-result-ciphertext", func(t *testing.T) {
		expected, material, fixed, seed := generatedVectorFixture(t)
		defer clear(seed[:cap(seed)])
		original := encodedAuthenticatedSeed(t, fixed, contract.EncodeGeneratedResultRecord)
		changed := fixed
		changed.Payload.Ciphertext = bytes.Clone(fixed.Payload.Ciphertext)
		changed.Payload.Ciphertext[0] ^= 1
		damaged := encodedAuthenticatedSeed(t, changed, contract.EncodeGeneratedResultRecord)
		other, err := SealGeneratedResult(expected, material, fixed.SafeFacts, seed, []byte("other-secret"))
		if err != nil {
			t.Fatal(err)
		}
		alternate := encodedAuthenticatedSeed(t, other, contract.EncodeGeneratedResultRecord)
		check(t, original, damaged, alternate,
			func(wire []byte) error { _, err := contract.InspectGeneratedResultRecord(wire); return err },
			func(wire []byte) ([]byte, error) {
				view, err := contract.InspectGeneratedResultRecord(wire)
				if err != nil {
					return nil, err
				}
				owned, err := view.Own()
				if err != nil {
					return nil, err
				}
				return OpenGeneratedResult(expected, material, seed, owned)
			}, []byte("secret-value"), []byte("other-secret"))
	})

	t.Run("transfer-tag", func(t *testing.T) {
		_, _, fixedResult, seed := generatedVectorFixture(t)
		defer clear(seed[:cap(seed)])
		fixed, keys := fixedResult.Transfer, fixtureKeys()
		defer clear(keys[:cap(keys)])
		original := encodedAuthenticatedSeed(t, fixed, contract.EncodeTransferEnvelope)
		changed := fixed
		changed.Ciphertext = bytes.Clone(fixed.Ciphertext)
		changed.Ciphertext[len(changed.Ciphertext)-1] ^= 1
		damaged := encodedAuthenticatedSeed(t, changed, contract.EncodeTransferEnvelope)
		other, err := SealTransfer(fixed.Core, seed, keys)
		if err != nil {
			t.Fatal(err)
		}
		alternate := encodedAuthenticatedSeed(t, other, contract.EncodeTransferEnvelope)
		check(t, original, damaged, alternate,
			func(wire []byte) error { _, err := contract.InspectTransferEnvelope(wire); return err },
			func(wire []byte) ([]byte, error) {
				view, err := contract.InspectTransferEnvelope(wire)
				if err != nil {
					return nil, err
				}
				return OpenTransfer(fixed.Core, contract.TransferEnvelope(view), seed)
			}, keys, keys)
	})
}
