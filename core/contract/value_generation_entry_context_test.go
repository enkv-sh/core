package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestGeneratedMemberIdentityChangesWithEveryInput(t *testing.T) {
	ids := [4]ID{generatedRecordID(1), generatedRecordID(2), generatedRecordID(3), generatedRecordID(4)}
	first, err := DeriveGeneratedValueIdentity(ids[0], ids[1], ids[2], ids[3])
	if err != nil {
		t.Fatal(err)
	}
	for i := range ids {
		changed := ids
		changed[i] = generatedRecordID(9)
		next, err := DeriveGeneratedValueIdentity(changed[0], changed[1], changed[2], changed[3])
		if err != nil || first.ValueStateID == next.ValueStateID || first.DataKeyID == next.DataKeyID || first.CommitmentKeyID == next.CommitmentKeyID {
			t.Fatal("identity input omitted", i, err)
		}
		if (i < 2) == (first.OriginSnapshotID == next.OriginSnapshotID || first.OriginTransitionID == next.OriginTransitionID) {
			t.Fatal("origin dependency differs", i)
		}
		changed[i] = ID{}
		if _, err := DeriveGeneratedValueIdentity(changed[0], changed[1], changed[2], changed[3]); err == nil {
			t.Fatal("absent derivation input accepted", i)
		}
	}
}

func generatedEntryEvidenceFixture(t *testing.T, branch uint8) (ValueEntry, GeneratedCreateEvidence, []byte) {
	t.Helper()
	id := generatedRecordID
	intent := generatorIntentFixture(t, id(6), id(9), GeneratorLifecycleManaged, []byte("{}"))
	intentID, err := GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	lineage := generatorGraphCreateIntentFixture(t, "generated", intentID)
	x := lineage.Templates[branch]
	facts := generatedSafeFactsFixture(GeneratorDispositionCompleteCreate)
	facts.ResourceContractID, facts.IntentDigest, facts.RequestDigest = x.ResourceContractID, intentID, id(25)
	fd, err := GeneratorSafeFactsDigest(facts)
	if err != nil {
		t.Fatal(err)
	}
	material, err := GeneratorMaterialID(lineage.DomainID, lineage.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	core := GeneratedResultCore{Schema: GeneratedResultCoreSchema, Profile: 2, DomainID: lineage.DomainID, OperationID: lineage.OperationID, MaterialID: material, UsePlanDigest: id(22), PlanGraphID: id(23),
		AttemptID: x.AttemptID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, ExecutorID: x.ExecutorID, DescriptorID: x.DescriptorID,
		ConfigContractID: x.ConfigContractID, ResultContractID: x.ResultContractID, RequestDigest: facts.RequestDigest, SafeFactsDigest: fd}
	cb, err := EncodeGeneratedResultCore(core)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	logical, err := GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{{Schema: 1, ContentKind: GeneratorContentIntent, ContentID: intentID, Length: uint32(len(intent)), Digest: Hash(intent)}})
	if err != nil {
		t.Fatal(err)
	}
	evidence := GeneratedCreateEvidence{
		Schema:            GeneratedCreateEvidenceSchema,
		OriginalResultID:  core.ResultID,
		CredentialRouteID: x.CredentialRouteID,
		ResultCore:        cb,
		SafeFacts:         fb,
		Intent:            logical,
		CompletionClass:   x.CompletionClass,
		LifecycleMode:     GeneratorLifecycleManaged,
	}
	ed, err := GeneratedCreateEvidenceDescriptor(evidence)
	if err != nil {
		t.Fatal(err)
	}
	meta := GeneratedEntryMetadata{
		Schema:                GeneratedEntryMetadataSchema,
		Epoch:                 lineage.Epoch,
		ConfigContractID:      x.ConfigContractID,
		IntentDigest:          intentID,
		ResourceIncarnationID: x.ResourceIncarnationID,
		OriginOperationID:     lineage.OperationID,
		OriginAttemptID:       x.AttemptID,
		GenerationID:          id(30),
		CreateResultID:        x.ResultID,
		CreateEvidence:        ed,
		RequiredSupport:       EmptyGeneratorVector(GeneratorVectorSupport),
		CompletionClass:       x.CompletionClass,
		RetirementMode:        GeneratedRetirementManual,
		ResourceContractID:    facts.ResourceContractID,
		ResourceDigest:        generatorResourceFixtureDigest(t, facts),
		LifecycleMode:         GeneratorLifecycleManaged,
	}
	binding, err := GeneratedBindingDigest(meta)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveGeneratedValueIdentity(x.PlannedValueSlotID, id(31), x.ResultID, binding)
	if err != nil {
		t.Fatal(err)
	}
	meta.GenerationID = identity.ValueStateID
	value, err := EncodeCanonicalPayload(CanonicalPayload{Profile: 2, CryptoSupportID: id(32), DataKeyID: identity.DataKeyID, DataKeyEpoch: 1,
		CommitmentKeyID: identity.CommitmentKeyID, CommitmentKeyEpoch: 1, ContentLength: 3, Ciphertext: bytes.Repeat([]byte{0xaa}, 19), InputEncoding: InputEncodingRaw, RetainedLength: 3})
	if err != nil {
		t.Fatal(err)
	}
	return ValueEntry{Name: lineage.Name, Incarnation: lineage.EntryIncarnationID, ValueState: identity.ValueStateID, OriginSnapshot: identity.OriginSnapshotID,
		OriginTransition: identity.OriginTransitionID, ValueSource: Generated, ConfidentialityClass: Secret, Recipients: []ID{id(33)}, ValueBytes: value, Generated: meta, InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: uint32(len(value) - CanonicalPayloadOverhead), RetainedLength: uint32(len(value) - CanonicalPayloadOverhead)}, evidence, intent
}

// full_only: false
func TestGeneratedMemberDetachedEvidenceRequiresUsableExactOrigin(t *testing.T) {
	for branch := uint8(0); branch < 5; branch++ {
		entry, evidence, intent := generatedEntryEvidenceFixture(t, branch)
		if err := ValidateGeneratedValueEntryEvidence(generatedRecordID(1), entry, evidence, intent); err != nil {
			t.Fatal("detached create evidence", branch, err)
		}
		entry.Generated.RetirementMode = GeneratedRetirementAuto
		entry.Generated.RetiringDutyPresent, entry.Generated.RetiringDutyID = 1, generatedRecordID(99)
		if err := ValidateGeneratedValueEntryEvidence(generatedRecordID(1), entry, evidence, intent); err != nil {
			t.Fatal("retirement is separate selected state", err)
		}
	}
	for name, change := range map[string]func(*ValueEntry){
		"name":             func(v *ValueEntry) { v.Name = "other" },
		"incarnation":      func(v *ValueEntry) { v.Incarnation = generatedRecordID(99) },
		"epoch":            func(v *ValueEntry) { v.Generated.Epoch++ },
		"operation":        func(v *ValueEntry) { v.Generated.OriginOperationID = generatedRecordID(99) },
		"attempt":          func(v *ValueEntry) { v.Generated.OriginAttemptID = generatedRecordID(99) },
		"resource":         func(v *ValueEntry) { v.Generated.ResourceIncarnationID = generatedRecordID(99) },
		"profile":          func(v *ValueEntry) { v.Generated.LifecycleMode = GeneratorLifecycleNone },
		"assumptions":      func(v *ValueEntry) { v.Generated.ConfigContractID = generatedRecordID(99) },
		"account":          func(v *ValueEntry) { v.Generated.ResourceContractID = generatedRecordID(99) },
		"token":            func(v *ValueEntry) { v.Generated.ResourceDigest = generatedRecordID(99) },
		"intent":           func(v *ValueEntry) { v.Generated.IntentDigest = generatedRecordID(99) },
		"create result":    func(v *ValueEntry) { v.Generated.CreateResultID = generatedRecordID(99) },
		"evidence":         func(v *ValueEntry) { v.Generated.CreateEvidence.Digest = generatedRecordID(99) },
		"completion class": func(v *ValueEntry) { v.Generated.CompletionClass = GeneratedCompletionConfirmed },
	} {
		t.Run(name, func(t *testing.T) {
			entry, evidence, intent := generatedEntryEvidenceFixture(t, 0)
			change(&entry)
			if err := ValidateGeneratedValueEntryEvidence(generatedRecordID(1), entry, evidence, intent); err == nil {
				t.Fatal("changed origin accepted")
			}
		})
	}
	for _, reason := range []string{"provider returned unusable", "host rejected encoding"} {
		t.Run(reason, func(t *testing.T) {
			entry, evidence, intent := generatedEntryEvidenceFixture(t, 0)
			facts, err := DecodeGeneratorSafeFacts(evidence.SafeFacts)
			if err != nil {
				t.Fatal(err)
			}
			core, err := InspectGeneratedResultCore(evidence.ResultCore)
			if err != nil {
				t.Fatal(err)
			}
			if reason == "host rejected encoding" {
				core.Schema = GeneratedResultEncodingFailureSchema
			} else {
				facts.Disposition, facts.Reason = GeneratorDispositionOwnedUnusableCreate, GeneratorReasonMissingValue
				evidence.SafeFacts, err = EncodeGeneratorSafeFacts(facts)
				if err != nil {
					t.Fatal(err)
				}
				core.SafeFactsDigest, err = GeneratorSafeFactsDigest(facts)
				if err != nil {
					t.Fatal(err)
				}
			}
			evidence.ResultCore, err = EncodeGeneratedResultCore(core)
			if err != nil {
				t.Fatal(err)
			}
			entry.Generated.CreateEvidence, err = GeneratedCreateEvidenceDescriptor(evidence)
			if err != nil {
				t.Fatal("detached cleanup evidence was refused", err)
			}
			m := entry.Generated
			target := GeneratorTarget{Schema: GeneratorTargetSchema, Name: entry.Name, IncarnationID: entry.Incarnation, Epoch: m.Epoch,
				ResourceID: m.ResourceIncarnationID, ResourceDigest: m.ResourceDigest, ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID,
				OriginalOperationID: m.OriginOperationID, OriginalAttemptID: m.OriginAttemptID, ResultContractID: core.ResultContractID, LifecycleMode: m.LifecycleMode, CompletionClass: m.CompletionClass}
			if err := ValidateGeneratedTargetEvidence(core.DomainID, target, evidence, intent); err != nil {
				t.Fatal("lost exact detached cleanup target", err)
			}
			if err := ValidateGeneratedValueEntryEvidence(core.DomainID, entry, evidence, intent); err == nil {
				t.Fatal("owned resource without usable return became canonical")
			}
		})
	}
}

// full_only: false
func TestGeneratedMemberEvidenceChecksOriginalKeyIDsAndIntentBytes(t *testing.T) {
	for _, field := range []string{"data", "commitment", "intent"} {
		entry, evidence, intent := generatedEntryEvidenceFixture(t, 0)
		payload, err := DecodeCanonicalPayload(entry.ValueBytes)
		if err != nil {
			t.Fatal(err)
		}
		switch field {
		case "data":
			payload.DataKeyID = generatedRecordID(99)
		case "commitment":
			payload.CommitmentKeyID = generatedRecordID(99)
		case "intent":
			intent = []byte("[]")
		}
		entry.ValueBytes, err = EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateGeneratedValueEntryEvidence(generatedRecordID(1), entry, evidence, intent); err == nil {
			t.Fatal("changed member context accepted", field)
		}
	}
}

// full_only: false
func TestGeneratedMemberEvidenceAllowsSelectedRekey(t *testing.T) {
	for _, field := range []string{"data", "commitment", "both"} {
		t.Run(field, func(t *testing.T) {
			entry, evidence, intent := generatedEntryEvidenceFixture(t, 0)
			payload, err := DecodeCanonicalPayload(entry.ValueBytes)
			if err != nil {
				t.Fatal(err)
			}
			if field != "commitment" {
				payload.DataKeyID, payload.DataKeyEpoch = generatedRecordID(98), 2
			}
			if field != "data" {
				payload.CommitmentKeyID, payload.CommitmentKeyEpoch = generatedRecordID(99), 3
			}
			entry.ValueBytes, err = EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateGeneratedValueEntryEvidence(generatedRecordID(1), entry, evidence, intent); err != nil {
				t.Fatal("selected re-key changed original create evidence", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedMemberIdentityIndependentHashes(t *testing.T) {
	got, err := DeriveGeneratedValueIdentity(generatedRecordID(1), generatedRecordID(2), generatedRecordID(3), generatedRecordID(4))
	if err != nil {
		t.Fatal(err)
	}
	// Independent Node.js SHA-256 over the specified labels and B framing.
	// Value uses four repeated-byte IDs1/2/3/4; origins use IDs1/2; both key
	// IDs use the derived ValueStateID. No production encoder was called.
	for _, row := range []struct {
		got  ID
		want string
	}{
		{got.ValueStateID, "ddad502bdf9e2de6d7f9a4d56bc353e37f125a9b59c718a7c42791c13123fadd"},
		{got.OriginSnapshotID, "2935401e753d03ad9375a5aab90658cfd326510ee9c4f640db486539e2a30bbf"},
		{got.OriginTransitionID, "47261da63de81c9bf26b534a6bf25a0b66be84007575c903a3de13b6e4075606"},
		{got.DataKeyID, "dab707e34bbdc41c3bfd6c8f0f0a46361f46f5ee5417d9b406e5bad7f7b41f90"},
		{got.CommitmentKeyID, "675fd862eba49c6949ed7b9fedea6d66f4c0a2aa0be885dc97b1b67865e04abc"},
	} {
		if hex.EncodeToString(row.got[:]) != row.want {
			t.Fatal("independent member identity differs")
		}
	}
}
