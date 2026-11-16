package custody

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// This campaign persists public/encrypted records only. Its fixed private
// keys and plaintext expectations remain inside this out-of-Core owner.
// full_only: false
func FuzzCustodyOpen(f *testing.F) {
	payload, err := contract.EncodeCanonicalPayload(fixturePayload(f))
	if err != nil {
		f.Fatal(err)
	}
	source, err := contract.EncodeSealedInputEnvelope(fixtureSource(f))
	if err != nil {
		f.Fatal(err)
	}
	expected, material, generated, seed := generatedVectorFixture(f)
	defer clear(seed[:cap(seed)])
	result, err := contract.EncodeGeneratedResultRecord(generated)
	if err != nil {
		f.Fatal(err)
	}
	transfer, err := contract.EncodeTransferEnvelope(generated.Transfer)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append([]byte{0}, payload...))
	f.Add(append([]byte{1}, source...))
	f.Add(append([]byte{2}, result...))
	f.Add(append([]byte{3}, transfer...))
	f.Add([]byte{0})
	f.Add([]byte{1})
	valueKeys, sourceKeys := fixtureKeys(), fixtureSourceKeys()
	defer clear(valueKeys[:cap(valueKeys)])
	defer clear(sourceKeys[:cap(sourceKeys)])
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 || len(input) > contract.CryptoMaxSealedInputLength+1 {
			return
		}
		before := bytes.Clone(input)
		var plaintext []byte
		var err error
		length := 12
		switch input[0] {
		case 0:
			p, e := contract.InspectCanonicalPayload(input[1:])
			if e != nil {
				return
			}
			plaintext, err = OpenValue(fixtureValueCore(), contract.CanonicalPayload(p), valueKeys)
		case 1:
			view, e := contract.InspectSealedInputEnvelope(input[1:])
			if e != nil {
				return
			}
			s, e := view.Own()
			if e != nil {
				t.Fatal("inspected source could not be owned")
			}
			plaintext, err = OpenSealedInput(fixtureSourceCore(), s, sourceKeys)
		case 2:
			view, e := contract.InspectGeneratedResultRecord(input[1:])
			if e != nil {
				return
			}
			r, e := view.Own()
			if e != nil {
				t.Fatal("inspected result could not be owned")
			}
			plaintext, err = OpenGeneratedResult(expected, material, seed, r)
		case 3:
			view, e := contract.InspectTransferEnvelope(input[1:])
			if e != nil {
				return
			}
			plaintext, err = OpenTransfer(generated.Transfer.Core, contract.TransferEnvelope(view), seed)
			length = 64
		default:
			return
		}
		if !bytes.Equal(before, input) {
			t.Fatal("private open changed borrowed input")
		}
		if err != nil {
			if plaintext != nil {
				t.Fatal("failed private open retained plaintext")
			}
			return
		}
		defer clear(plaintext[:cap(plaintext)])
		if len(plaintext) != length || cap(plaintext) != length {
			t.Fatal("private open exceeded admitted output")
		}
		if (input[0] == 0 && bytes.Equal(input[1:], payload) || input[0] == 1 && bytes.Equal(input[1:], source) || input[0] == 2 && bytes.Equal(input[1:], result)) && !bytes.Equal(plaintext, []byte("secret-value")) {
			t.Fatal("fixed oracle plaintext changed")
		}
		if input[0] == 3 && bytes.Equal(input[1:], transfer) && !bytes.Equal(plaintext, valueKeys) {
			t.Fatal("fixed oracle transfer keys changed")
		}
	})
}
