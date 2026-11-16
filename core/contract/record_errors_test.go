package contract

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// full_only: false
func TestGeneralRecordErrorsKeepTheirOwner(t *testing.T) {
	valid, err := EncodeGeneratorIntent(GeneratorIntent{Schema: 1, ConfigContractID: ID{1}, LifecycleMode: GeneratorLifecycleNone, Settings: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	missingID := bytes.Clone(valid)
	clear(missingID[2:34])
	oversizedField := bytes.Clone(valid)
	binary.BigEndian.PutUint32(oversizedField[67:71], uint32(GeneratorIntentMaxLength))
	for _, row := range []struct {
		name string
		body []byte
		want error
	}{
		{"truncated", valid[:2], ErrRecord},
		{"missing-required-id", missingID, ErrRecord},
		{"field-capacity", oversizedField, ErrRecordCapacity},
		{"whole-capacity", make([]byte, GeneratorIntentMaxLength+1), ErrRecordCapacity},
		{"trailing", append(bytes.Clone(valid), 0), ErrRecord},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := InspectGeneratorIntent(row.body)
			if err == nil || !errors.Is(fmt.Errorf("decode record: %w", err), row.want) {
				t.Fatalf("record lost its error family: %v", err)
			}
			if errors.Is(err, ErrCryptoMessage) || errors.Is(err, ErrCryptoCapacity) {
				t.Fatalf("general record returned a custody error: %v", err)
			}
		})
	}
	if _, err := InspectGeneratorIntent(valid); err != nil {
		t.Fatal("valid record refused", err)
	}
	valueBody, err := EncodeValueCore(accessStructuralRow(t, 0, 1, 1).ValueCore)
	if err != nil {
		t.Fatal(err)
	}
	invalidName := bytes.Clone(valueBody)
	invalidName[104] = 0xff
	for _, row := range []struct {
		name string
		body []byte
		want error
	}{
		{"value-truncated", valueBody[:2], ErrRecord},
		{"value-invalid-name", invalidName, ErrRecord},
		{"value-whole-capacity", make([]byte, valueCoreMaxLength+1), ErrRecordCapacity},
		{"value-trailing", append(bytes.Clone(valueBody), 0), ErrRecord},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := InspectValueCore(row.body)
			if !errors.Is(err, row.want) || errors.Is(err, ErrCryptoMessage) || errors.Is(err, ErrCryptoCapacity) {
				t.Fatal("nested value record lost its error owner", err)
			}
		})
	}
	// Frame one valid RecipientRecord leaf independently. A registry requires
	// at least one recipient; InitiallyAbsent may be empty. Key encoding is not
	// the count-error property checked here.
	domain, _, recipients := completeApplyFixture(t)
	recipient, err := EncodeRecipientRecord(recipients[0].Recipient)
	if err != nil {
		t.Fatal(err)
	}
	registry := binary.BigEndian.AppendUint16(nil, 1)
	for _, id := range []ID{domain, {2}, {3}} {
		registry = append(registry, id[:]...)
	}
	empty := binary.BigEndian.AppendUint32(bytes.Clone(registry), 0)
	empty = binary.BigEndian.AppendUint32(empty, 0)
	if _, err := DecodeGeneratedRecipientRegistryImage(empty); !errors.Is(err, ErrRecord) || errors.Is(err, ErrCryptoMessage) {
		t.Fatal("empty recipient registry lost its refusal or error owner", err)
	}
	registry = binary.BigEndian.AppendUint32(registry, 1)
	registry = append(registry, recipient...)
	registry = append(registry, 0) // No optional creation proof.
	registry = binary.BigEndian.AppendUint32(registry, 0)
	if got, err := DecodeGeneratedRecipientRegistryImage(registry); err != nil || got.DomainID != domain || len(got.Recipients) != 1 ||
		got.Recipients[0].Recipient.RecipientID != recipients[0].Recipient.RecipientID || len(got.InitiallyAbsent) != 0 {
		t.Fatal("valid one-recipient registry refused or changed", err)
	}
	for _, count := range []uint32{1, CryptoMaxRecipients + 1} {
		bad := bytes.Clone(registry)
		binary.BigEndian.PutUint32(bad[len(bad)-4:], count)
		want := ErrRecord
		if count > CryptoMaxRecipients {
			want = ErrRecordCapacity
		}
		if _, err := DecodeGeneratedRecipientRegistryImage(bad); !errors.Is(err, want) || errors.Is(err, ErrCryptoMessage) || errors.Is(err, ErrCryptoCapacity) {
			t.Fatal("registry count error lost its owner", count, err)
		}
	}
	for _, body := range [][]byte{nil, {0, 1}, make([]byte, cryptoRequestHeader)} {
		if _, err := InspectCryptoRequest(body); !errors.Is(err, ErrCryptoMessage) || errors.Is(err, ErrRecord) {
			t.Fatal("custody request lost its own error family", err)
		}
	}
}

// full_only: false
func TestRecordInspectionBorrowsAndOwnCopies(t *testing.T) {
	facts := GeneratorSafeFacts{Schema: GeneratorSafeFactsSchema, Action: GeneratorActionCreate, LifecycleMode: GeneratorLifecycleManaged,
		Disposition: GeneratorDispositionCompleteCreate, RequestDigest: ID{1}, IntentDigest: ID{2}, ResourceContractID: ID{3},
		Target: []byte("target"), ResourceData: []byte("resource"), ProviderFacts: []byte("facts")}
	body, err := EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectGeneratorSafeFacts(body)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	for _, span := range [][]byte{view.Target, view.ResourceData, view.ProviderFacts} {
		if cap(span) != len(span) {
			t.Fatal("borrowed span reaches adjacent fields")
		}
	}
	view.Target[0] = 'T'
	if !bytes.Contains(body, []byte("Target")) || string(owned.Target) != "target" {
		t.Fatal("inspection did not borrow or Own retained borrowed storage")
	}
	clear(body)
	if string(owned.Target) != "target" || string(owned.ResourceData) != "resource" || string(owned.ProviderFacts) != "facts" {
		t.Fatal("owned record changed with its former input")
	}
}
