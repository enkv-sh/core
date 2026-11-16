package contract

import (
	"bytes"
	"errors"
	"testing"
)

// full_only: false
func TestInspectedSupportFactsPreserveExactDescriptor(t *testing.T) {
	domain := successionTestID(7)
	blob := successionTestID(8)
	payload := []byte{1, 2, 3}
	body, err := EncodeGeneratedFragment(GeneratedFragment{Schema: GeneratorRecordSchema, BlobID: blob,
		Index: 0, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: Hash(payload), Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	recordID, err := GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	row := SupportRecord{Kind: GeneratedFragmentSupportKind, RecordID: recordID, Body: body}
	fact, err := InspectSupportRecordDigest(domain, row)
	if err != nil || fact.Kind() != row.Kind || fact.RecordID() != row.RecordID ||
		fact.BodyLength() != uint32(len(body)) || fact.BodyDigest() != Hash(body) {
		t.Fatal("typed fragment fact", err)
	}
	want, err := RequiredSupportDescriptor(domain, []SupportRecord{row})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := RequiredSupportDescriptorFromDigests(domain, []SupportRecordDigest{fact})
	if err != nil || actual != want {
		t.Fatal("inspected fact changed required support descriptor", err)
	}
	for _, altered := range []SupportRecordDigest{{}, {kind: fact.kind, recordID: fact.recordID,
		bodyDigest: fact.bodyDigest, bodyLength: fact.bodyLength, domain: domain},
		{kind: fact.kind, recordID: fact.recordID, bodyDigest: fact.bodyDigest,
			bodyLength: fact.bodyLength, domain: successionTestID(9), inspected: true}} {
		if _, err := RequiredSupportDescriptorFromDigests(domain, []SupportRecordDigest{altered}); err == nil {
			t.Fatal("uninspected or wrong-domain fact accepted")
		}
	}
	if _, err := RequiredSupportDescriptorFromDigests(domain, []SupportRecordDigest{fact, fact}); err == nil {
		t.Fatal("duplicate selected row fact accepted")
	}
}

// full_only: false
func TestInspectedSupportFactsPreserveCapacityAndMalformedMeaning(t *testing.T) {
	domain := Hash([]byte("support capacity domain"))
	blob := Hash([]byte("support capacity blob"))
	fragmentID, err := GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := EncodeGeneratedFragment(GeneratedFragment{Schema: GeneratorRecordSchema, BlobID: blob, Count: 1, TotalLength: GeneratedFragmentMaxPayload, WholeDigest: Hash([]byte("independent fragment payload identity")), Payload: make([]byte, GeneratedFragmentMaxPayload)})
	if err != nil {
		t.Fatal(err)
	}
	configuration := Hash([]byte("support capacity configuration"))
	sliceID, err := OutputConfigurationSliceID(domain, configuration, 0)
	if err != nil {
		t.Fatal(err)
	}
	slice, err := EncodeOutputConfigurationSlice(OutputConfigurationSlice{Schema: OutputConfigurationSchema, DomainID: domain, ConfigurationDigest: configuration, SliceCount: 1, TotalLength: MaxOutputConfigurationSliceBytes, SliceBytes: make([]byte, MaxOutputConfigurationSliceBytes)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		row    SupportRecord
		length int
	}{
		{"generated fragment", SupportRecord{Kind: GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragment}, GeneratedFragmentHeaderLength + GeneratedFragmentMaxPayload},
		{"output configuration", SupportRecord{Kind: OutputConfigurationSliceSupportKind, RecordID: sliceID, Body: slice}, OutputConfigurationSliceBodyOverhead + MaxOutputConfigurationSliceBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.row.Body) != tc.length {
				t.Fatal("independent scalar maximum differs")
			}
			fact, err := InspectSupportRecordDigest(domain, tc.row)
			if err != nil || fact.BodyLength() != uint32(tc.length) {
				t.Fatal("exact scalar maximum refused", err)
			}
			over := tc.row
			over.Body = append(bytes.Clone(tc.row.Body), 0)
			if _, err := InspectSupportRecordDigest(domain, over); !errors.Is(err, ErrRecordCapacity) {
				t.Fatalf("over-bound classification=%v", err)
			}
			malformed := tc.row
			malformed.Body = bytes.Clone(tc.row.Body)
			malformed.Body[0], malformed.Body[1] = 0, 0
			if _, err := InspectSupportRecordDigest(domain, malformed); !errors.Is(err, ErrRecord) || errors.Is(err, ErrRecordCapacity) {
				t.Fatalf("malformed classification=%v", err)
			}
			wrongID := tc.row
			wrongID.RecordID = Hash([]byte("wrong support record"))
			if _, err := InspectSupportRecordDigest(domain, wrongID); !errors.Is(err, ErrRecord) {
				t.Fatalf("wrong identity=%v", err)
			}
		})
	}
	if _, err := InspectSupportRecordDigest(Hash([]byte("wrong domain")), SupportRecord{Kind: OutputConfigurationSliceSupportKind, RecordID: sliceID, Body: slice}); !errors.Is(err, ErrRecord) {
		t.Fatalf("wrong domain=%v", err)
	}
}
