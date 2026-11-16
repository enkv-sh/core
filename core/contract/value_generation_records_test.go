package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func generatedRecordID(n byte) ID { return ID(bytes.Repeat([]byte{n}, 32)) }

func generatorIntentFixture(t testing.TB, config, resource ID, mode GeneratorLifecycleMode, settings []byte) []byte {
	t.Helper()
	body, err := EncodeGeneratorIntent(GeneratorIntent{Schema: 1, ConfigContractID: config, LifecycleMode: mode, ResourceContractID: resource, Settings: settings})
	if err != nil {
		t.Fatal("canonical intent fixture", err)
	}
	return body
}
func generatorIntentLengthFixture(t testing.TB, config, resource ID, mode GeneratorLifecycleMode, length int) []byte {
	t.Helper()
	settings := append([]byte{'"'}, bytes.Repeat([]byte{'x'}, length-73)...)
	settings = append(settings, '"')
	return generatorIntentFixture(t, config, resource, mode, settings)
}

func generatorResourceFixtureDigest(t testing.TB, facts GeneratorSafeFacts) ID {
	t.Helper()
	id, err := GeneratorResourceDigest(facts)
	if err != nil {
		t.Fatal("resource fixture", err)
	}
	return id
}

func generatedRecordDescriptor(n byte) GeneratorDescriptor {
	return GeneratorDescriptor{Digest: generatedRecordID(n), Length: 4}
}

func generatedRecordParent() GeneratedParentRecord {
	return GeneratedParentRecord{
		Schema: GeneratedParentSchema, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		RequestIdentityDigest: generatedRecordID(3), RequestCoreDigest: generatedRecordID(4),
		PlanGraphID: generatedRecordID(5), UsePlanDigest: generatedRecordID(6), MaterialID: generatedRecordID(7),
		RecoveryPolicyID:    generatedRecordID(10),
		ValueEntryPlanCount: 1, LineageCount: 1, TemplateCount: 5,
		Declaration: generatedRecordDescriptor(11), Registry: generatedRecordDescriptor(12),
		Graph: generatedRecordDescriptor(13), SourceUses: generatedRecordDescriptor(14),
		IntendedEntryPlans: generatedRecordDescriptor(15), Capacity: generatedRecordDescriptor(16),
		InitialPredecessorDigest: generatedRecordID(17), ConditionDigest: generatedRecordID(18),
	}
}

// full_only: false
func TestGeneratedParentPlanHasOnlyNamedRequestIdentityHole(t *testing.T) {
	actual := generatedRecordParent()
	body, err := EncodeGeneratedParentRecord(actual)
	if err != nil {
		t.Fatal(err)
	}
	plan := GeneratedParentPlan(actual)
	plan.RequestIdentityDigest = ID{}
	wire, err := EncodeGeneratedParentPlan(plan)
	if err != nil || len(wire) != 592 {
		t.Fatal("parent plan", len(wire), err)
	}
	// Request identity follows schema and the domain/operation IDs.
	want := bytes.Clone(body)
	clear(want[66:98])
	if !bytes.Equal(wire, want) {
		t.Fatal("plan changed fields outside the request identity")
	}
	parsed, err := InspectGeneratedParentPlan(wire)
	if err != nil || parsed != plan {
		t.Fatal("plan traversal", err)
	}
	if _, err := InspectGeneratedParentRecord(wire); err == nil {
		t.Fatal("stored parent accepted pre-material plan")
	}
	if _, err := InspectGeneratedParentPlan(body); err == nil {
		t.Fatal("plan accepted an already filled identity")
	}
	for n := range wire {
		if _, err := InspectGeneratedParentPlan(wire[:n]); err == nil {
			t.Fatal("accepted incomplete parent plan", n)
		}
	}
	for _, offset := range []int{2, 34, 98, 130, 162, 194, 226, 528, 560} {
		bad := bytes.Clone(wire)
		clear(bad[offset : offset+32])
		if _, err := InspectGeneratedParentPlan(bad); err == nil {
			t.Fatal("accepted extra identity hole", offset)
		}
	}
}

func generatedRecordEntryMetadata() GeneratedEntryMetadata {
	return GeneratedEntryMetadata{
		Schema:                GeneratedEntryMetadataSchema,
		Epoch:                 0,
		ConfigContractID:      generatedRecordID(2),
		IntentDigest:          generatedRecordID(3),
		ResourceIncarnationID: generatedRecordID(4),
		OriginOperationID:     generatedRecordID(5),
		OriginAttemptID:       generatedRecordID(6),
		GenerationID:          generatedRecordID(7),
		CreateResultID:        generatedRecordID(10),
		CreateEvidence:        generatedRecordDescriptor(11),
		RequiredSupport:       generatedRecordDescriptor(12),
		CompletionClass:       1,
		RetirementMode:        1,
		RetiringDutyPresent:   1,
		RetiringDutyID:        generatedRecordID(13),
		ResourceContractID:    generatedRecordID(8),
		ResourceDigest:        generatedRecordID(9),
		LifecycleMode:         GeneratorLifecycleManaged,
	}
}

// full_only: false
func TestGeneratedRecordsIndependentFieldOrder(t *testing.T) {
	// The fixture is the documented big-endian field concatenation, with each
	// ID a repeated byte. No production encoder supplies expected bytes.
	idHex := func(n byte) string { return strings.Repeat(hex.EncodeToString([]byte{n}), 32) }
	descriptorHex := func(n byte) string { return idHex(n) + "000000000000000400000000" }
	parentHex := "0002"
	for n := byte(1); n <= 7; n++ {
		parentHex += idHex(n)
	}
	parentHex += idHex(10) + "000100010005"
	for n := byte(11); n <= 16; n++ {
		parentHex += descriptorHex(n)
	}
	parentHex += idHex(17) + idHex(18)
	entryMetadataHex := "00030000000000000000"
	for _, n := range []byte{2, 3, 8, 9, 4, 5, 6, 7, 10} {
		entryMetadataHex += idHex(n)
	}
	entryMetadataHex += descriptorHex(11) + descriptorHex(12) + "02010101" + idHex(13)
	for _, tc := range []struct {
		name    string
		hex     string
		digest  string
		length  int
		encode  func() ([]byte, error)
		inspect func([]byte) error
	}{
		{"parent", parentHex, "7c9c2528f10940274a7cc0511552c4166767cf4ec87d5d5ec8d04d4f23a30284", 592, func() ([]byte, error) { return EncodeGeneratedParentRecord(generatedRecordParent()) }, func(b []byte) error { _, err := InspectGeneratedParentRecord(b); return err }},
		{"member", entryMetadataHex, "f04c9f18e8e0a786785df4777253adda0d826e48713b7db516253ea97c8aa8ca", 422, func() ([]byte, error) { return EncodeGeneratedEntryMetadata(generatedRecordEntryMetadata()) }, func(b []byte) error { _, err := InspectGeneratedEntryMetadata(b); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.hex)
			if err != nil || len(want) != tc.length {
				t.Fatal("literal shape", len(want), err)
			}
			// Python hashlib.sha256 over the displayed hex supplied
			// these fixed digests, without importing the production package.
			digest := sha256.Sum256(want)
			if hex.EncodeToString(digest[:]) != tc.digest {
				t.Fatal("independent digest changed")
			}
			got, err := tc.encode()
			if err != nil || !bytes.Equal(want, got) {
				t.Fatal("field order", err)
			}
			if err := tc.inspect(want); err != nil {
				t.Fatal("literal refused", err)
			}
			for i := range want {
				if err := tc.inspect(want[:i]); err == nil {
					t.Fatalf("truncation %d accepted", i)
				}
			}
			if err := tc.inspect(append(bytes.Clone(want), 0)); err == nil {
				t.Fatal("trailing byte accepted")
			}
			bad := bytes.Clone(want)
			bad[1] = 0
			if err := tc.inspect(bad); !errors.Is(err, ErrRecord) {
				t.Fatal("wrong schema accepted", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedRecordsDescriptorBounds(t *testing.T) {
	v := generatedRecordDescriptor(1)
	wire, err := AppendGeneratorDescriptor(nil, v)
	if err != nil || len(wire) != 44 {
		t.Fatal("descriptor width", len(wire), err)
	}
	if got, err := DecodeGeneratorDescriptor(wire); err != nil || got != v {
		t.Fatal("descriptor round trip", err)
	}
	for _, bad := range []GeneratorDescriptor{
		{}, {Digest: v.Digest, Length: 0}, {Digest: v.Digest, Length: 5},
		{Digest: v.Digest, Length: 7, Count: 1}, {Digest: v.Digest, Length: 4, Count: ^uint32(0)},
	} {
		if bad.Valid() {
			t.Fatal("invalid descriptor", bad.Length, bad.Count)
		}
		if _, err := AppendGeneratorDescriptor(nil, bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid descriptor encoded", err)
		}
	}
	v.Length, v.Count = 8, 1
	if !v.Valid() {
		t.Fatal("minimum framed row refused")
	}
}

// full_only: false
func TestGeneratedRecordsMemberVariants(t *testing.T) {
	v := generatedRecordEntryMetadata()
	v.RetiringDutyPresent, v.RetiringDutyID = 0, ID{}
	if n, err := GeneratedEntryMetadataLength(v); err != nil || n != 390 {
		t.Fatal("unarmed width", n, err)
	}
	for _, mutate := range []func(*GeneratedEntryMetadata){
		func(v *GeneratedEntryMetadata) { v.ResourceContractID = ID{} },
		func(v *GeneratedEntryMetadata) { v.CompletionClass = 0 },
		func(v *GeneratedEntryMetadata) { v.CompletionClass = 3 },
		func(v *GeneratedEntryMetadata) { v.RetirementMode = 0 },
		func(v *GeneratedEntryMetadata) { v.RetirementMode = 3 },
		func(v *GeneratedEntryMetadata) { v.RetiringDutyPresent = 2 },
		func(v *GeneratedEntryMetadata) { v.RetiringDutyPresent = 1 },
		func(v *GeneratedEntryMetadata) { v.RetiringDutyID = generatedRecordID(13) },
		func(v *GeneratedEntryMetadata) { v.RequiredSupport = GeneratorDescriptor{} },
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeGeneratedEntryMetadata(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid member accepted", err)
		}
	}
	v.CompletionClass, v.RetirementMode = 2, 2
	if _, err := EncodeGeneratedEntryMetadata(v); err != nil {
		t.Fatal("stronger class and auto refused", err)
	}
}

// full_only: false
func TestGeneratedRecordsFragmentShapeAndOwnership(t *testing.T) {
	v := GeneratedFragment{Schema: 1, BlobID: generatedRecordID(1), Count: 2,
		TotalLength: GeneratedFragmentMaxPayload + 1, WholeDigest: generatedRecordID(2),
		Payload: bytes.Repeat([]byte{0xab}, GeneratedFragmentMaxPayload)}
	encoded, err := EncodeGeneratedFragment(v)
	if err != nil || len(encoded) != 86+GeneratedFragmentMaxPayload {
		t.Fatal("full fragment", len(encoded), err)
	}
	view, err := InspectGeneratedFragment(encoded)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	encoded[86] = 0xcd
	if view.Payload[0] != 0xcd || owned.Payload[0] != 0xab {
		t.Fatal("borrowed/owned contract")
	}
	v.Index, v.Offset, v.Payload = 1, GeneratedFragmentMaxPayload, []byte{0xab}
	if _, err := EncodeGeneratedFragment(v); err != nil {
		t.Fatal("final remainder", err)
	}
	for _, mutate := range []func(*GeneratedFragment){
		func(v *GeneratedFragment) { v.Count = 0 },
		func(v *GeneratedFragment) { v.Count = 3 },
		func(v *GeneratedFragment) { v.Index = 2 },
		func(v *GeneratedFragment) { v.Offset++ },
		func(v *GeneratedFragment) { v.TotalLength++ },
		func(v *GeneratedFragment) { v.Payload = nil },
		func(v *GeneratedFragment) { v.WholeDigest = ID{} },
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeGeneratedFragment(bad); err == nil {
			t.Fatal("invalid fragment accepted")
		}
	}
	v.Count = 513
	if _, err := EncodeGeneratedFragment(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("directory ceiling", err)
	}
	bad := bytes.Clone(encoded[:86])
	binary.BigEndian.PutUint32(bad[82:], ^uint32(0))
	if _, err := InspectGeneratedFragment(bad); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("oversized declared payload", err)
	}
}

func generatedRecordPhase() GeneratedPhaseRecord {
	return GeneratedPhaseRecord{Schema: GeneratedPhaseSchema, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		PlanGraphID: generatedRecordID(3), UsePlanDigest: generatedRecordID(4), OwnerID: generatedRecordID(5),
		PhaseID: generatedRecordID(6), FrontierAttemptID: generatedRecordID(7), Phase: 1, Stage: 1,
		AcceptedResults: generatedRecordDescriptor(8), Attempts: generatedRecordDescriptor(9),
		Duties: generatedRecordDescriptor(10), Hazards: generatedRecordDescriptor(11), PendingReleases: generatedRecordDescriptor(12), Proofs: EmptyGeneratorVector(GeneratorVectorProofs)}
}

func generatedRecordLineage() GeneratedLineageRecord {
	return GeneratedLineageRecord{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		LineageID: generatedRecordID(3), IncarnationID: generatedRecordID(4), Name: "n",
		Intent: generatedRecordDescriptor(5), Membership: generatedRecordDescriptor(6), Templates: generatedRecordDescriptor(7)}
}

func generatedRecordAttempt() GeneratedAttemptRecord {
	return GeneratedAttemptRecord{
		Schema:             GeneratedAttemptRecordSchema,
		DomainID:           generatedRecordID(1),
		OperationID:        generatedRecordID(2),
		LineageID:          generatedRecordID(3),
		AttemptID:          generatedRecordID(4),
		TemplateDigest:     generatedRecordID(5),
		OwnerID:            generatedRecordID(7),
		ResourceID:         generatedRecordID(8),
		TransmissionID:     generatedRecordID(9),
		ResultID:           generatedRecordID(10),
		InboxID:            generatedRecordID(11),
		DescriptorID:       generatedRecordID(12),
		ConfigContractID:   generatedRecordID(13),
		ExecutorID:         generatedRecordID(14),
		CredentialRouteID:  generatedRecordID(15),
		ResourceContractID: generatedRecordID(16),
		ResultContractID:   generatedRecordID(17),
		RequestDigest:      generatedRecordID(18),
		State:              3,
		Stage:              1,
		CompletionClass:    1,
		Facts:              generatedRecordDescriptor(19),
		Progress:           generatedRecordDescriptor(20),
		Support:            generatedRecordDescriptor(21),
		History:            generatedRecordDescriptor(22),
		LifecycleMode:      GeneratorLifecycleManaged,
	}
}

func generatedRecordDuty() GeneratedDutyRecord {
	return GeneratedDutyRecord{
		Schema:              GeneratedDutyRecordSchema,
		DomainID:            generatedRecordID(1),
		DutyID:              generatedRecordID(2),
		OriginalOperationID: generatedRecordID(3),
		OriginalAttemptID:   generatedRecordID(4),
		OwnerID:             generatedRecordID(5),
		ResourceID:          generatedRecordID(6),
		DescriptorID:        generatedRecordID(7),
		ConfigContractID:    generatedRecordID(8),
		ExecutorID:          generatedRecordID(9),
		CredentialRouteID:   generatedRecordID(10),
		ResourceContractID:  generatedRecordID(11),
		ResultContractID:    generatedRecordID(12),
		Kind:                1,
		CompletionClass:     1,
		Step:                1,
		Status:              3,
		CapacityReservation: generatedRecordDescriptor(13),
		Target:              generatedRecordDescriptor(14),
		Progress:            generatedRecordDescriptor(15),
		History:             generatedRecordDescriptor(16),
		Support:             generatedRecordDescriptor(17),
		Consumers:           generatedRecordDescriptor(18),
		LifecycleMode:       GeneratorLifecycleManaged,
	}
}

func generatedRecordHazard() GeneratedHazardRecord {
	return GeneratedHazardRecord{Schema: GeneratedHazardRecordSchema, DomainID: generatedRecordID(1), HazardID: generatedRecordID(2),
		OriginalOperationID: generatedRecordID(3), OriginalAttemptID: generatedRecordID(4), OwnerID: generatedRecordID(5),
		ResourceID: generatedRecordID(6), DescriptorID: generatedRecordID(7), ConfigContractID: generatedRecordID(8),
		ExecutorID: generatedRecordID(9), CredentialRouteID: generatedRecordID(10), ResourceContractID: generatedRecordID(11),
		ResultContractID: generatedRecordID(12), Exposure: 1, CompletionClass: 1, Fenced: 1, Eligibility: 1,
		CapacityReservation: generatedRecordDescriptor(13), OriginalResults: generatedRecordDescriptor(14), Target: generatedRecordDescriptor(15),
		History: generatedRecordDescriptor(16), Support: generatedRecordDescriptor(17), Consumers: generatedRecordDescriptor(18)}
}

func generatedRecordRelease() PendingInboxReleaseRecord {
	return PendingInboxReleaseRecord{Schema: 1, DomainID: generatedRecordID(1), InboxID: generatedRecordID(2),
		OriginalResultID: generatedRecordID(3), SelectedHandoffDigest: generatedRecordID(4), HandoffRevisionID: generatedRecordID(5),
		CapacityReservation: generatedRecordDescriptor(6), ObjectLength: 1024, State: 1}
}

// full_only: false
func TestGeneratedRecordsFixedBodiesAndDamage(t *testing.T) {
	// Independent Node Buffer concatenation and crypto.createHash("sha256"):
	// Parent/phase/lineage remain unchanged; Attempt/Duty schema3 and Hazard2.
	// IDs are their fixture byte repeated32; a descriptor is
	// its repeated ID followed by uint64be(4), uint32be(0). In displayed order:
	// phase IDs1..7, zero32 twice, 00000001000000010000, descriptors8..12,
	// then D("proofs", u32(0)), uint64(4), uint32(0), zero32, zero120;
	// lineage IDs1..4, 000000016e0000000000000000, descriptors5..7, 00000000;
	// attempt IDs1..5, zero32, IDs7..18, tags020301000100, descriptors19..22;
	// duty IDs1..12, tags0201010103, descriptors13..18;
	// hazard IDs1..12, 01010101, descriptors13..18;
	// release IDs1..5, descriptor6, 0000040001;
	// fragment ID1, 000000010000000000000003, ID2, 0000000000000003616263.
	for _, tc := range []struct {
		name, digest string
		length       int
		encode       func() ([]byte, error)
		inspect      func([]byte) error
	}{
		{"phase", "12b8aa81fd9f03736c39c420bb4e586f21e41c1a14265a4316d17d62ccd1fad5", 716,
			func() ([]byte, error) { return EncodeGeneratedPhaseRecord(generatedRecordPhase()) }, func(b []byte) error { _, err := InspectGeneratedPhaseRecord(b); return err }},
		{"lineage", "970d7bb269b870123d8aa01773644baf8cff25bfe946e5ec1a65f15679b589e3", 279,
			func() ([]byte, error) { return EncodeGeneratedLineageRecord(generatedRecordLineage()) }, func(b []byte) error { _, err := InspectGeneratedLineageRecord(b); return err }},
		{"attempt", "f0b14b0be1f3eedfd514659f933fc08afc0db18ede2a8ffb07f760ba04f992a2", 760,
			func() ([]byte, error) { return EncodeGeneratedAttemptRecord(generatedRecordAttempt()) }, func(b []byte) error { _, err := InspectGeneratedAttemptRecord(b); return err }},
		{"duty", "dd737e0fc186a416ebb4f391c37bb8c4f19d445ad8eec3cab064c99bed7be99b", 655,
			func() ([]byte, error) { return EncodeGeneratedDutyRecord(generatedRecordDuty()) }, func(b []byte) error { _, err := InspectGeneratedDutyRecord(b); return err }},
		{"hazard", "addd370d8d383a5bfe0f209d27a3a5110c3cbf1c8afd1a99c8a02ebc1d10d3d8", 654,
			func() ([]byte, error) { return EncodeGeneratedHazardRecord(generatedRecordHazard()) }, func(b []byte) error { _, err := InspectGeneratedHazardRecord(b); return err }},
		{"release", "fbcdb0001a586fb67182de772051ac508068d9574870a28dc378166717715ae3", 211,
			func() ([]byte, error) { return EncodePendingInboxReleaseRecord(generatedRecordRelease()) }, func(b []byte) error { _, err := InspectPendingInboxReleaseRecord(b); return err }},
		{"fragment", "2a343e9fed6b588449cb126f921519910d70a28565b4c4a844ce1452124e171e", 89,
			func() ([]byte, error) {
				return EncodeGeneratedFragment(GeneratedFragment{Schema: 1, BlobID: generatedRecordID(1), Count: 1, TotalLength: 3, WholeDigest: generatedRecordID(2), Payload: []byte("abc")})
			}, func(b []byte) error { _, err := InspectGeneratedFragment(b); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tc.encode()
			if err != nil || len(wire) != tc.length {
				t.Fatal("wire width", len(wire), err)
			}
			digest := sha256.Sum256(wire)
			if hex.EncodeToString(digest[:]) != tc.digest {
				t.Fatalf("independent field-order digest: got %x", digest)
			}
			if err := tc.inspect(wire); err != nil {
				t.Fatal("valid body", err)
			}
			for i := range wire {
				if err := tc.inspect(wire[:i]); err == nil {
					t.Fatalf("truncation %d accepted", i)
				}
			}
			if err := tc.inspect(append(bytes.Clone(wire), 0)); err == nil {
				t.Fatal("trailing byte")
			}
			bad := bytes.Clone(wire)
			bad[1] = 99
			if tc.name == "phase" {
				bad[1] = 1
			}
			if err := tc.inspect(bad); !errors.Is(err, ErrRecord) {
				t.Fatal("bad schema", err)
			}
			bad = bytes.Clone(wire)
			clear(bad[2:34])
			if err := tc.inspect(bad); !errors.Is(err, ErrRecord) {
				t.Fatal("zero required identity", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedRecordsParentCountBoundaries(t *testing.T) {
	v := generatedRecordParent()
	v.ValueEntryPlanCount, v.LineageCount, v.TemplateCount = 512, 128, 1408
	if _, err := EncodeGeneratedParentRecord(v); err != nil {
		t.Fatal("full supported counts", err)
	}
	for _, mutate := range []func(*GeneratedParentRecord){
		func(v *GeneratedParentRecord) { v.ValueEntryPlanCount++ },
		func(v *GeneratedParentRecord) { v.LineageCount++ },
		func(v *GeneratedParentRecord) { v.TemplateCount++ },
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeGeneratedParentRecord(bad); !errors.Is(err, ErrRecordCapacity) {
			t.Fatal("above count ceiling", err)
		}
	}
	v.TemplateCount = 127
	if _, err := EncodeGeneratedParentRecord(v); !errors.Is(err, ErrRecord) {
		t.Fatal("missing lineage template", err)
	}
}

// full_only: false
func TestGeneratedRecordsPhaseBranchesAndAggregate(t *testing.T) {
	for _, bits := range [][3]uint8{{0, 0, 0}, {1, 1, 0}, {2, 0, 1}, {3, 1, 1}, {4, 1, 1}} {
		v := generatedRecordPhase()
		v.Branch, v.NoEffectUsed, v.ResidueUsed = bits[0], bits[1], bits[2]
		if _, err := EncodeGeneratedPhaseRecord(v); err != nil {
			t.Fatal("valid branch", bits, err)
		}
		v.NoEffectUsed ^= 1
		if _, err := EncodeGeneratedPhaseRecord(v); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid branch budget", bits, err)
		}
	}
	for _, index := range []uint16{127, 128, 129, 895} {
		v := generatedRecordPhase()
		v.LineageIndex = index
		if _, err := EncodeGeneratedPhaseRecord(v); err != nil {
			t.Fatal("valid obligation container index", index, err)
		}
	}
	v := generatedRecordPhase()
	v.LineageIndex, v.Stage, v.FrontierAttemptID = 896, GeneratedStageTerminal, ID{}
	if _, err := EncodeGeneratedPhaseRecord(v); err != nil {
		t.Fatal("aggregate without terminal result", err)
	}
	for _, mutate := range []func(*GeneratedPhaseRecord){
		func(v *GeneratedPhaseRecord) { v.Stage = GeneratedStageResidue },
		func(v *GeneratedPhaseRecord) { v.FrontierAttemptID = generatedRecordID(7) },
		func(v *GeneratedPhaseRecord) { v.Branch = 1; v.NoEffectUsed = 1 },
		func(v *GeneratedPhaseRecord) { v.AcceptedResultID = generatedRecordID(8) },
		func(v *GeneratedPhaseRecord) { v.ResultDigest = generatedRecordID(9) },
		func(v *GeneratedPhaseRecord) { v.Phase = 0 },
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeGeneratedPhaseRecord(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid aggregate", err)
		}
	}
	v.AcceptedResultID, v.ResultDigest = generatedRecordID(8), generatedRecordID(9)
	if _, err := EncodeGeneratedPhaseRecord(v); err != nil {
		t.Fatal("paired result", err)
	}
	v.LineageIndex = 897
	if _, err := EncodeGeneratedPhaseRecord(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("above lineage bound", err)
	}
}

// full_only: false
func TestGeneratedRecordsLineageNameBoundsAndOwnership(t *testing.T) {
	v := generatedRecordLineage()
	for _, name := range []string{"", strings.Repeat("a", 256)} {
		v.Name = name
		wire, err := EncodeGeneratedLineageRecord(v)
		if err != nil || len(wire) != 278+len(name) {
			t.Fatal("valid name bound", len(name), err)
		}
		view, err := InspectGeneratedLineageRecord(wire)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil || owned != v {
			t.Fatal("lineage round trip", err)
		}
		if len(name) != 0 {
			wire[134] = 'b'
			if view.Name[0] != 'b' || owned.Name[0] != 'a' {
				t.Fatal("lineage ownership")
			}
		}
	}
	v.Name = strings.Repeat("a", 257)
	if _, err := EncodeGeneratedLineageRecord(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("oversized name", err)
	}
	v.Name = "\xff"
	if _, err := EncodeGeneratedLineageRecord(v); !errors.Is(err, ErrRecord) {
		t.Fatal("invalid UTF-8", err)
	}
}

// full_only: false
func TestGeneratedRecordsClosedStateTags(t *testing.T) {
	attempt := generatedRecordAttempt()
	for state := uint8(0); state <= 10; state++ {
		attempt.State = state
		_, err := EncodeGeneratedAttemptRecord(attempt)
		if (err == nil) != (state >= 3 && state <= 9) {
			t.Fatal("entered-state boundary", state, err)
		}
	}
	attempt.State = GeneratedEffectTransmitted
	for stage := uint8(0); stage <= 6; stage++ {
		attempt.Stage = stage
		_, err := EncodeGeneratedAttemptRecord(attempt)
		if (err == nil) != (stage >= 1 && stage <= 5) {
			t.Fatal("recovery-stage boundary", stage, err)
		}
	}
	attempt.Stage, attempt.RetryUsed = 1, 2
	if _, err := EncodeGeneratedAttemptRecord(attempt); !errors.Is(err, ErrRecord) {
		t.Fatal("retry boolean", err)
	}
	duty := generatedRecordDuty()
	duty.Kind = GeneratedDutyUnselectedCleanup
	if _, err := EncodeGeneratedDutyRecord(duty); !errors.Is(err, ErrRecord) {
		t.Fatal("transmitted converted duty", err)
	}
	duty.Status = GeneratedEffectSucceeded
	if _, err := EncodeGeneratedDutyRecord(duty); err != nil {
		t.Fatal("successful unselected duty", err)
	}
	for step := uint8(0); step <= 9; step++ {
		duty.Step = step
		_, err := EncodeGeneratedDutyRecord(duty)
		if (err == nil) != (step >= 1 && step <= 8) {
			t.Fatal("step-mask boundary", step, err)
		}
	}
	hazard := generatedRecordHazard()
	for _, mutate := range []func(*GeneratedHazardRecord){
		func(v *GeneratedHazardRecord) { v.Exposure = 0 },
		func(v *GeneratedHazardRecord) { v.Exposure = 3 },
		func(v *GeneratedHazardRecord) { v.Fenced = 2 },
		func(v *GeneratedHazardRecord) { v.Eligibility = 3 },
		func(v *GeneratedHazardRecord) { v.Eligibility = 2 },
	} {
		bad := hazard
		mutate(&bad)
		if _, err := EncodeGeneratedHazardRecord(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid hazard tags", err)
		}
	}
	hazard.Exposure, hazard.Eligibility = 2, 2
	if _, err := EncodeGeneratedHazardRecord(hazard); err != nil {
		t.Fatal("late-effect eligibility", err)
	}
	hazard.Eligibility = 0
	if _, err := EncodeGeneratedHazardRecord(hazard); err != nil {
		t.Fatal("unqualified hazard", err)
	}
}

// full_only: false
func TestGeneratedRecordsReleaseLimits(t *testing.T) {
	v := generatedRecordRelease()
	for _, state := range []uint8{1, 2} {
		v.State = state
		if _, err := EncodePendingInboxReleaseRecord(v); err != nil {
			t.Fatal("live release state", err)
		}
	}
	for _, state := range []uint8{0, 3, 4} {
		v.State = state
		if _, err := EncodePendingInboxReleaseRecord(v); !errors.Is(err, ErrRecord) {
			t.Fatal("release tag", err)
		}
	}
	v.State, v.ObjectLength = 1, 0
	if _, err := EncodePendingInboxReleaseRecord(v); !errors.Is(err, ErrRecord) {
		t.Fatal("empty release object", err)
	}
	v.ObjectLength = uint32(GeneratedResultRecordMaxLength)
	if _, err := EncodePendingInboxReleaseRecord(v); err != nil {
		t.Fatal("maximum release object", err)
	}
	v.ObjectLength++
	if _, err := EncodePendingInboxReleaseRecord(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("oversized release object", err)
	}
	v.State, v.ObjectLength = 3, 0
	body, err := EncodePendingInboxReleaseRecord(v)
	if err != nil || len(body) != 211 {
		t.Fatal("unobserved mapping changed its exact existing body bound", err)
	}
	decoded, err := InspectPendingInboxReleaseRecord(body)
	if err != nil || decoded != v {
		t.Fatal("unobserved mapping did not round trip", err)
	}
	for _, state := range []uint8{1, 2, 4} {
		v.State = state
		if _, err := EncodePendingInboxReleaseRecord(v); !errors.Is(err, ErrRecord) {
			t.Fatal("unobserved zero length was accepted as an observed release", err)
		}
	}
}

// full_only: false
func TestGeneratedRecordsCreateEvidenceFramingAndOwnership(t *testing.T) {
	facts := generatedSafeFactsFixture(1)
	factsBytes, err := EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	core := generatedResultCoreFixture()
	core.RequestDigest = facts.RequestDigest
	core.SafeFactsDigest, err = GeneratorSafeFactsDigest(facts)
	if err != nil {
		t.Fatal(err)
	}
	coreBytes, err := EncodeGeneratedResultCore(core)
	if err != nil {
		t.Fatal(err)
	}
	v := GeneratedCreateEvidence{
		Schema:            GeneratedCreateEvidenceSchema,
		OriginalResultID:  core.ResultID,
		CredentialRouteID: generatedRecordID(17),
		ResultCore:        coreBytes,
		SafeFacts:         factsBytes,
		Intent:            generatedRecordDescriptor(4),
		CompletionClass:   1,
		LifecycleMode:     GeneratorLifecycleManaged,
	}
	wire, err := EncodeGeneratedCreateEvidence(v)
	if err != nil || len(wire) != 120+452+len(factsBytes) {
		t.Fatal("evidence framing", len(wire), err)
	}
	// Independent Python struct/hashlib schema4 vector: route ID17 follows
	// result ID8; the existing core/facts fixtures and descriptor ID4 are unchanged.
	if Hash(wire) != generatedCryptoHexID(t, "b0e8d02165627af9a360a0bf7cf8084ba306191e2dd37f3da29bf0a6205e2ae9") {
		t.Fatal("create evidence differs from independent bytes")
	}
	legacy := append([]byte{0, 3}, wire[2:34]...)
	legacy = append(legacy, wire[66:]...)
	if _, err := InspectGeneratedCreateEvidence(legacy); err == nil {
		t.Fatal("old create evidence was silently accepted")
	}
	if _, err := InspectGeneratedCreateEvidence(append(bytes.Clone(wire), 0)); err == nil {
		t.Fatal("trailing create evidence bytes were accepted")
	}
	changed := v
	changed.CredentialRouteID = generatedRecordID(18)
	originalDescriptor, err := GeneratedCreateEvidenceDescriptor(v)
	if err != nil {
		t.Fatal(err)
	}
	changedDescriptor, err := GeneratedCreateEvidenceDescriptor(changed)
	if err != nil || changedDescriptor.Digest == originalDescriptor.Digest || changedDescriptor.Length != originalDescriptor.Length {
		t.Fatal("original credential route is not committed", err)
	}
	view, err := InspectGeneratedCreateEvidence(wire)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	wire[70], wire[526] = 4, 5
	if view.ResultCore[0] != 4 || view.SafeFacts[0] != 5 || owned.ResultCore[0] != 0 || owned.SafeFacts[0] != 0 {
		t.Fatal("evidence ownership")
	}
	if _, err := view.Own(); err == nil {
		t.Fatal("accepted damaged evidence after inspection")
	}
	for _, mutate := range []func(*GeneratedCreateEvidence){
		func(v *GeneratedCreateEvidence) { v.ResultCore = v.ResultCore[:451] },
		func(v *GeneratedCreateEvidence) { v.SafeFacts = v.SafeFacts[:1] },
		func(v *GeneratedCreateEvidence) { v.CompletionClass = 0 },
		func(v *GeneratedCreateEvidence) { v.OriginalResultID = ID{} },
		func(v *GeneratedCreateEvidence) { v.CredentialRouteID = ID{} },
		func(v *GeneratedCreateEvidence) { v.Schema = 3 },
		func(v *GeneratedCreateEvidence) { v.OriginalResultID = generatedRecordID(99) },
		func(v *GeneratedCreateEvidence) {
			v.SafeFacts = bytes.Clone(v.SafeFacts)
			v.SafeFacts[6] ^= 1
		},
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeGeneratedCreateEvidence(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid evidence framing", err)
		}
	}
	for _, disposition := range []uint8{3, 4} {
		bad := v
		facts := generatedSafeFactsFixture(disposition)
		bad.SafeFacts, err = EncodeGeneratorSafeFacts(facts)
		if err != nil {
			t.Fatal(err)
		}
		core.SafeFactsDigest, err = GeneratorSafeFactsDigest(facts)
		if err != nil {
			t.Fatal(err)
		}
		bad.ResultCore, err = EncodeGeneratedResultCore(core)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EncodeGeneratedCreateEvidence(bad); err == nil {
			t.Fatal("non-create evidence accepted", disposition)
		}
	}
	bad := bytes.Clone(wire[:70])
	binary.BigEndian.PutUint32(bad[66:], ^uint32(0))
	if _, err := InspectGeneratedCreateEvidence(bad); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("declared core bound", err)
	}
	bad = bytes.Clone(wire[:526])
	binary.BigEndian.PutUint32(bad[522:], ^uint32(0))
	if _, err := InspectGeneratedCreateEvidence(bad); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("declared facts bound", err)
	}
	for i := range wire {
		if _, err := InspectGeneratedCreateEvidence(wire[:i]); err == nil {
			t.Fatalf("truncation %d", i)
		}
	}
}
