package contract

import (
	"bytes"
	"reflect"
	"testing"
)

// These are codec fixtures only. Repeated IDs and the structurally empty
// descriptor do not establish supported-profile or authenticated provenance.
func localRecordFixtures(t *testing.T) (GeneratedEntryMetadata, GeneratedAttemptRecord, GeneratedDutyRecord, GeneratedCreateEvidence) {
	t.Helper()
	e := GeneratorDescriptor{Digest: generatedRecordID(0xee), Length: 4}
	m := GeneratedEntryMetadata{
		Schema:                GeneratedEntryMetadataSchema,
		LifecycleMode:         GeneratorLifecycleNone,
		Epoch:                 7,
		ConfigContractID:      generatedRecordID(2),
		IntentDigest:          generatedRecordID(3),
		ResourceIncarnationID: generatedRecordID(4),
		OriginOperationID:     generatedRecordID(5),
		OriginAttemptID:       generatedRecordID(6),
		GenerationID:          generatedRecordID(7),
		CreateResultID:        generatedRecordID(8),
		CreateEvidence:        e,
		RequiredSupport:       e,
	}
	a := GeneratedAttemptRecord{
		Schema:            GeneratedAttemptRecordSchema,
		LifecycleMode:     GeneratorLifecycleNone,
		DomainID:          generatedRecordID(1),
		OperationID:       generatedRecordID(2),
		LineageID:         generatedRecordID(3),
		AttemptID:         generatedRecordID(4),
		TemplateDigest:    generatedRecordID(5),
		OwnerID:           generatedRecordID(7),
		ResourceID:        generatedRecordID(8),
		TransmissionID:    generatedRecordID(9),
		ResultID:          generatedRecordID(10),
		InboxID:           generatedRecordID(11),
		DescriptorID:      generatedRecordID(12),
		ConfigContractID:  generatedRecordID(13),
		ExecutorID:        generatedRecordID(14),
		ResultContractID:  generatedRecordID(15),
		RequestDigest:     generatedRecordID(16),
		State:             GeneratedEffectTransmitted,
		Stage:             GeneratedStageRetainedResult,
		CredentialRouteID: generatedRecordID(17),
		Facts:             e,
		Progress:          e,
		Support:           e,
		History:           e,
	}
	d := GeneratedDutyRecord{
		Schema:              GeneratedDutyRecordSchema,
		LifecycleMode:       GeneratorLifecycleNone,
		DomainID:            generatedRecordID(1),
		DutyID:              generatedRecordID(2),
		OriginalOperationID: generatedRecordID(3),
		OriginalAttemptID:   generatedRecordID(4),
		OwnerID:             generatedRecordID(5),
		ResourceID:          generatedRecordID(6),
		DescriptorID:        generatedRecordID(7),
		ConfigContractID:    generatedRecordID(8),
		ExecutorID:          generatedRecordID(9),
		ResultContractID:    generatedRecordID(10),
		Kind:                GeneratedDutyCreate,
		Step:                1,
		Status:              GeneratedEffectPrepared,
		CredentialRouteID:   generatedRecordID(11),
		CapacityReservation: e,
		Target:              e,
		Progress:            e,
		History:             e,
		Support:             e,
		Consumers:           e,
	}
	core, err := EncodeGeneratedResultCore(localResultCoreFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := EncodeGeneratorSafeFacts(localFactsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	intent := GeneratorDescriptor{Digest: profileLiteralID(t, "82641b6595d39324053c6ece4bed42bb8ab513795ee7b563aede7d85b8402826"), Length: 79, Count: 1}
	c := GeneratedCreateEvidence{
		Schema:            GeneratedCreateEvidenceSchema,
		LifecycleMode:     GeneratorLifecycleNone,
		OriginalResultID:  generatedRecordID(8),
		CredentialRouteID: generatedRecordID(17),
		ResultCore:        core,
		SafeFacts:         facts,
		Intent:            intent,
	}
	return m, a, d, c
}

// full_only: false
func TestLocalGeneratorStoredRecordsIndependentVectors(t *testing.T) {
	m, a, d, c := localRecordFixtures(t)
	// This pointer retains an older managed generation. It grants no retirement
	// authority over the current generation, which has no managed resource.
	pointer := m
	pointer.RetiringDutyPresent, pointer.RetiringDutyID = 1, generatedRecordID(9)
	// Python struct/hashlib: schema3 with the listed repeated-byte IDs,
	// zero resource contract/digest for None, fixed descriptors and lifecycle1.
	// Attempt has18 IDs+6tags; Duty has12 IDs+5tags. Evidence schema4 adds
	// the listed route ID17 after OriginalResultID and keeps the two blobs.
	for _, test := range []struct {
		name   string
		value  any
		encode func() ([]byte, error)
		decode func([]byte) (any, error)
		length int
		hash   string
	}{
		{"metadata", m, func() ([]byte, error) { return EncodeGeneratedEntryMetadata(m) }, func(b []byte) (any, error) { return InspectGeneratedEntryMetadata(b) }, 390, "040776a6b2347a716ef134b4b2eaebde3693d33af84e60f5b0ff7441414d7f68"},
		{"older retirement pointer", pointer, func() ([]byte, error) { return EncodeGeneratedEntryMetadata(pointer) }, func(b []byte) (any, error) { return InspectGeneratedEntryMetadata(b) }, 422, "951ec54eb9c9ac941210831544cec750d2c7f4dd7e02f3495fd1aae924ab3834"},
		{"attempt", a, func() ([]byte, error) { return EncodeGeneratedAttemptRecord(a) }, func(b []byte) (any, error) { return InspectGeneratedAttemptRecord(b) }, 760, "8e0d038f00c96bcd74c08872a2ed3bece8d92150f6f348a87cb6fbb221b360d3"},
		{"create duty", d, func() ([]byte, error) { return EncodeGeneratedDutyRecord(d) }, func(b []byte) (any, error) { return InspectGeneratedDutyRecord(b) }, 655, "7f5500efba0f989b913f191c4e050470ce215e5ec469a1603b32460c99fd4311"},
		{"create evidence", c, func() ([]byte, error) { return EncodeGeneratedCreateEvidence(c) }, func(b []byte) (any, error) { return DecodeGeneratedCreateEvidence(b) }, 687, "5b0eaf3006613f60a24da36db7a24f0c4018f20eb75de9bf8b182ef85a35f6d9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, err := test.encode()
			if err != nil || len(body) != test.length || Hash(body) != profileLiteralID(t, test.hash) {
				t.Fatal("stored record differs from independent bytes", len(body), err)
			}
			got, err := test.decode(body)
			if err != nil || !reflect.DeepEqual(got, test.value) {
				t.Fatal("record round trip", err)
			}
			for cut := range len(body) {
				if _, err := test.decode(body[:cut]); err == nil {
					t.Fatal("record truncation accepted", cut)
				}
			}
			if _, err := test.decode(append(bytes.Clone(body), 0)); err == nil {
				t.Fatal("record suffix accepted")
			}
			body[1] = 99
			if _, err := test.decode(body); err == nil {
				t.Fatal("unknown record schema accepted")
			}
		})
	}
}

// full_only: false
func TestLocalGeneratorRecordsForbidRemoteAuthority(t *testing.T) {
	m, a, d, c := localRecordFixtures(t)
	m.ResourceContractID = generatedRecordID(1)
	if _, err := EncodeGeneratedEntryMetadata(m); err == nil {
		t.Fatal("local resource contract accepted")
	}
	a.CredentialRouteID = ID{}
	if _, err := EncodeGeneratedAttemptRecord(a); err == nil {
		t.Fatal("local missing credential route accepted")
	}
	for _, test := range []struct {
		name     string
		progress GeneratorDescriptor
	}{
		{"nonempty progress", GeneratorDescriptor{Digest: generatedRecordID(0xee), Length: 8, Count: 1}},
		{"zero progress", GeneratorDescriptor{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, attempt, _, _ := localRecordFixtures(t)
			attempt.Progress = test.progress
			if _, err := EncodeGeneratedAttemptRecord(attempt); err == nil {
				t.Fatal("invalid local progress descriptor accepted")
			}
		})
	}
	_, a, _, _ = localRecordFixtures(t)
	a.State = GeneratedEffectPossibleLive
	if _, err := EncodeGeneratedAttemptRecord(a); err == nil {
		t.Fatal("local remote-residue state accepted")
	}
	d.Kind = GeneratedDutyRetirement
	if _, err := EncodeGeneratedDutyRecord(d); err == nil {
		t.Fatal("local retirement duty accepted")
	}
	c.CompletionClass = GeneratedCompletionAcknowledged
	if _, err := EncodeGeneratedCreateEvidence(c); err == nil {
		t.Fatal("local deletion class accepted")
	}
}

// full_only: false
func TestLocalFactsVectorAcceptsExactSmallestRow(t *testing.T) {
	facts, err := EncodeGeneratorSafeFacts(localFactsFixture(t))
	if err != nil || len(facts) != 115 {
		t.Fatal("local facts bound", err)
	}
	row, err := EncodeGeneratorFactsRow(GeneratorFactsRow{Schema: 1, ResultID: generatedRecordID(8), Facts: facts})
	if err != nil || len(row) != 153 {
		t.Fatal("local facts row bound", len(row), err)
	}
	descriptor, err := GeneratorVectorDescriptor(GeneratorVectorFacts, [][]byte{row})
	if err != nil || descriptor.Length != 161 || descriptor.Count != 1 {
		t.Fatal("exact local facts vector refused", err)
	}
	if !GeneratorVectorShapeValid(GeneratorVectorFacts, descriptor) {
		t.Fatal("exact local facts descriptor shape refused")
	}
	carrier := GeneratorVectorCarrier{Schema: 1, DomainID: generatedRecordID(1), OwnerKind: GeneratedAttemptSupportKind, OwnerID: generatedRecordID(4), VectorKind: GeneratorVectorFacts, Vector: descriptor, Row: row}
	encoded, err := EncodeGeneratorVectorCarrier(carrier)
	if err != nil || len(encoded) != 273 {
		t.Fatal("exact local facts carrier refused", err)
	}
	decoded, err := InspectGeneratorVectorCarrier(encoded)
	if err != nil || !bytes.Equal(decoded.Row, row) || decoded.Vector != descriptor {
		t.Fatal("local facts carrier changed", err)
	}
	if _, err := InspectGeneratorFactsRow(row[:152]); err == nil {
		t.Fatal("truncated local facts row admitted")
	}
	if _, err := GeneratorVectorDescriptor(GeneratorVectorFacts, [][]byte{row[:152]}); err == nil {
		t.Fatal("truncated local facts vector admitted")
	}
}
