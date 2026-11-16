package contract

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

// full_only: false
func TestCryptoRetainedIntentIndependentBytes(t *testing.T) {
	id := func(b byte) ID { return ID(bytes.Repeat([]byte{b}, 32)) }
	row := CryptoIntentRow{Name: "secret", Recipients: []ID{id(2)}, ValueSource: Supplied, ConfidentialityClass: Secret,
		ContentLength: 3, PayloadDigest: id(4), PayloadLength: 218, Retained: RetainedSecretInput{Incarnation: id(5), Material: id(6)}, InputEncoding: InputEncodingRaw, RetainedLength: 3, OutputEncoding: OutputEncodingRaw}
	// Python struct big-endian integers and literal bytes: v8 prefix, domain01,
	// one secret row, recipient02, content3, raw input, retained3, raw output,
	// digest04, canonical length218,
	// retained discriminator1, incarnation05 and material06.
	want, err := hex.DecodeString("454e4b562f43525950544f2f76322f737570706c6965642d696e74656e742d76380001010101010101010101010101010101010101010101010101010101010101010000000100000006736563726574000102020202020202020202020202020202020202020202020202020202020202020102000000030100000003010404040404040404040404040404040404040404040404040404040404040404000000da0105050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606")
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeCryptoIntent(id(1), []CryptoIntentRow{row})
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("retained intent differs from independent bytes", err)
	}
	decoded, err := DecodeCryptoIntent(want, id(1))
	if err != nil || !reflect.DeepEqual(decoded, []CryptoIntentRow{row}) {
		t.Fatal("retained intent lost fields", err)
	}
	d, err := CryptoIntentDescriptor(id(1), []CryptoIntentRow{row})
	if err != nil || d.Length != 227 || d.Count != 1 || hex.EncodeToString(d.Digest[:]) != "62c9921adf550e3097bf3913d5283a755cccefbd2ab93a79401f1d2e965b3387" {
		t.Fatal("retained descriptor differs from independent SHA-256", err)
	}
	for _, name := range []string{"unknown-kind", "ordinary-with-pin", "retained-with-zero-pin", "half-pin"} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(want)
			at := len(bad) - 65
			switch name {
			case "unknown-kind":
				bad[at] = 2
			case "ordinary-with-pin":
				bad[at] = 0
			case "retained-with-zero-pin":
				clear(bad[at+1:])
			case "half-pin":
				clear(bad[at+1 : at+33])
			}
			if _, err := InspectCryptoIntent(bad, id(1)); err == nil {
				t.Fatal("invalid retained discriminator or pin accepted")
			}
		})
	}
}

// full_only: false
func TestCryptoRetainedIntentFixedWireBound(t *testing.T) {
	rows := make([]CryptoIntentRow, 512)
	for i := range rows {
		rows[i] = CryptoIntentRow{Name: fmt.Sprintf("value-%03d", i), Recipients: []ID{generatedRecordID(1)}, ValueSource: Supplied, ConfidentialityClass: Secret,
			PayloadDigest: generatedRecordID(2), PayloadLength: 215, Retained: RetainedSecretInput{Incarnation: generatedRecordID(3), Material: generatedRecordID(4)}, InputEncoding: InputEncodingRaw, RetainedLength: 0, OutputEncoding: OutputEncodingRaw}
	}
	domain := generatedRecordID(5)
	body, err := EncodeCryptoIntent(domain, rows)
	// 70-byte header + 512 * (119 fixed + 9 name + 32 recipient).
	if err != nil || len(body) != 81990 {
		t.Fatal("fixed retained pin fields exceed the declared intent bound", len(body), err)
	}
	view, err := InspectCryptoIntent(body, domain)
	if err != nil || view.Descriptor.Count != 512 || view.Descriptor.Length != 81990 {
		t.Fatal("maximum retained intent scanner lost fixed metadata charge", err)
	}
	rows = append(rows, rows[0])
	if _, err := EncodeCryptoIntent(domain, rows); err != ErrCryptoCapacity {
		t.Fatal("one-over retained row count admitted", err)
	}
}

func cryptoRetainedCompareFixture(t *testing.T) CryptoCompareRequest {
	t.Helper()
	keys := initKeysFixture(t)
	id := generatedRecordID
	domain := keys.Context.DomainID
	payload, err := EncodeCanonicalPayload(CanonicalPayload{Profile: 2, CryptoSupportID: CryptoSupportID(), DataKeyID: id(10), DataKeyEpoch: 1,
		CommitmentKeyID: id(11), CommitmentKeyEpoch: 1, ContentLength: 3, Ciphertext: make([]byte, 19), InputEncoding: InputEncodingRaw, RetainedLength: 3})
	if err != nil {
		t.Fatal(err)
	}
	entry := ValueEntry{Name: "secret", Incarnation: id(12), ValueState: id(13), OriginSnapshot: id(14), OriginTransition: id(15), ValueSource: Supplied,
		ConfidentialityClass: Secret, Recipients: []ID{keys.Bindings[0].SubjectID}, ValueBytes: payload, InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: uint32(len(payload) - CanonicalPayloadOverhead), RetainedLength: uint32(len(payload) - CanonicalPayloadOverhead)}
	body, err := EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	binding := keys.Bindings[0]
	digest, err := PublicBindingDigest(binding.Binding)
	if err != nil {
		t.Fatal(err)
	}
	access, err := EncodeAccessRecord(AccessRecord{Schema: CanonicalSchema, MaterialKind: ValueMaterialKind, MaterialID: entry.ValueState, MaterialContextDigest: id(16),
		Wraps: []WrapRow{{SubjectKind: OrdinaryWrapSubject, SubjectID: binding.SubjectID, BindingID: binding.Binding.BindingID, BindingSerial: binding.Binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: make([]byte, 384)}}})
	if err != nil {
		t.Fatal(err)
	}
	row := CryptoIntentRow{Name: entry.Name, Recipients: entry.Recipients, ValueSource: Supplied, ConfidentialityClass: Secret, ContentLength: 3,
		PayloadDigest: Hash(payload), PayloadLength: uint32(len(payload)), Retained: RetainedSecretInput{Incarnation: entry.Incarnation, Material: entry.ValueState}, InputEncoding: InputEncodingRaw, RetainedLength: 3, OutputEncoding: OutputEncodingRaw}
	recipients := []ApplyRecipientInput{{Recipient: RecipientRecord{RecipientID: keys.Bindings[0].SubjectID, Status: CurrentRecipient, CurrentBinding: &keys.Bindings[0].Binding}}}
	intent, err := CompleteApplyIntentDescriptor(domain, []CryptoIntentRow{row}, recipients)
	if err != nil {
		t.Fatal(err)
	}
	c := ApplyContext{OperationClass: CryptoOrdinaryLifecycle, AdmissionID: id(1), SessionID: id(2), DomainID: domain, CompatibilityID: CompatibilityID(), Expiry: 1,
		PredecessorHEADDigest: id(3), OriginalConditionDigest: id(4), IntentDescriptor: intent, CurrentAccessRoot: id(5)}
	ref, err := AppendRef(nil, Ref{Kind: RootKind, Format: CanonicalSchema, Domain: domain, Object: id(6), Digest: id(7), Length: 100}, CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], ref)
	return CryptoCompareRequest{Context: c, Intent: []CryptoIntentRow{row}, Recipients: recipients, Current: []CryptoCurrentSecret{{Slot: 0, EntryBytes: body, AccessRecord: access}}, Bindings: keys.Bindings}
}

// full_only: false
func TestCryptoRetainedCompareBindsExactCurrent(t *testing.T) {
	q := cryptoRetainedCompareFixture(t)
	body, err := EncodeCryptoCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectCryptoCompareRequest(body)
	if err != nil || view.SealedInputCount() != 0 || view.CurrentCount() != 1 || view.IntentCount() != 1 {
		t.Fatal("retained request requires a fabricated sealed source", err)
	}
	owned, err := view.Own()
	if err != nil || q.Context != owned.Context || !reflect.DeepEqual(q.Intent, owned.Intent) || !reflect.DeepEqual(q.Recipients, owned.Recipients) || !reflect.DeepEqual(q.Current, owned.Current) || !reflect.DeepEqual(q.Bindings, owned.Bindings) || len(owned.SealedInputs) != 0 {
		t.Fatal("retained request ownership lost fields", err)
	}
	want := bytes.Clone(body)
	clear(body)
	encoded, err := EncodeCryptoCompareRequest(owned)
	if err != nil || !bytes.Equal(encoded, want) {
		t.Fatal("owned retained request borrowed input bytes", err)
	}
	for _, name := range []string{"absent", "name", "incarnation", "material", "digest", "length", "raw", "extra-source", "plain", "generated"} {
		t.Run(name, func(t *testing.T) {
			bad := cryptoRetainedCompareFixture(t)
			switch name {
			case "absent":
				bad.Current = nil
			case "name":
				bad.Intent[0].Name = "other"
			case "incarnation":
				bad.Intent[0].Retained.Incarnation[0] ^= 1
			case "material":
				bad.Intent[0].Retained.Material[0] ^= 1
			case "digest":
				bad.Intent[0].PayloadDigest[0] ^= 1
			case "length":
				bad.Intent[0].PayloadLength++
			case "raw":
				bad.Intent[0].ContentLength++
				bad.Intent[0].RetainedLength++
				bad.Intent[0].PayloadLength++
			case "extra-source":
				bad.SealedInputs = []CryptoSealedInput{{Name: "secret"}}
			case "plain":
				bad.Intent[0].ConfidentialityClass = Plain
			case "generated":
				bad.Intent[0].ValueSource = Generated
			}
			if descriptor, err := CompleteApplyIntentDescriptor(bad.Context.DomainID, bad.Intent, bad.Recipients); err == nil {
				bad.Context.IntentDescriptor = descriptor
			} else if name != "length" && name != "plain" && name != "generated" {
				t.Fatal("valid negative-case intent refused before correspondence", err)
			}
			if _, err := EncodeCryptoCompareRequest(bad); err == nil {
				t.Fatal("retained mismatch accepted by writer")
			}
			w := cryptoWriter{}
			table, err := BindingTableLength(bad.Bindings)
			if err != nil {
				t.Fatal(err)
			}
			cryptoWriteCompare(&w, bad, table)
			if _, err := InspectCryptoCompareRequest(w.b); err == nil {
				t.Fatal("retained mismatch accepted by bounded scanner")
			}
		})
	}
}
