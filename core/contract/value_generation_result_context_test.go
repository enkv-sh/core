package contract

import (
	"bytes"
	"testing"
)

func generatedResultFixture(t testing.TB, disposition uint8) (GeneratorResultExpectation, OperationMaterialRecord, GeneratedResultRecord) {
	t.Helper()
	domain, operation := ID{31}, ID{32}
	template := generatorTemplateFixture(t, 0)
	facts := generatedSafeFactsFixture(disposition)
	facts.ResourceContractID, facts.IntentDigest = template.ResourceContractID, template.IntentDigest
	if disposition == GeneratorDispositionRetirementAcknowledged {
		template.ResourceDigest = generatorResourceFixtureDigest(t, facts)
		template.Action, template.TargetKind, template.NoEffectBudget, template.ResidueBudget = 2, 2, 0, 0
		template.TargetSourceID = template.ResourceIncarnationID
	}
	var err error
	must := func(id ID, err error) ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	template.RequestPlanDigest = must(GeneratorRequestPlanDigest(template))
	template.TransmissionID = must(GeneratorTransmissionID(template.AttemptID, template.Action))
	template.ResultID = must(GeneratorResultID(domain, operation, template.AttemptID, template.TransmissionID, template.Action))
	template.InboxID = must(GeneratorInboxID(domain, operation, template.AttemptID, template.ResultID))
	materialID := must(GeneratorMaterialID(domain, operation))
	use := GeneratorResultUse{Schema: 1, AttemptID: template.AttemptID, ResultID: template.ResultID, InboxID: template.InboxID,
		ExecutorID: template.ExecutorID, ResultContractID: template.ResultContractID, PlannedValueSlotID: template.PlannedValueSlotID,
		MaterialID: materialID, Purpose: 1, MaxSecret: CryptoMaxRawValue, MaxFacts: 4096}
	if disposition == GeneratorDispositionRetirementAcknowledged {
		use.MaxSecret = 0
	}
	uses, err := GeneratorResultUsesDescriptor([]GeneratorResultUse{use})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := GeneratorUsePlanCore{DomainID: domain, OperationID: operation, MaterialID: materialID, PlanGraphID: ID{33},
		ResultUses: uses, SourceUses: sources, ValueDerivationID: GeneratorValueDerivationID()}
	expected := GeneratorResultExpectation{InputEncoding: InputEncodingRaw, Plan: plan, Template: template, Use: use, RequestDigest: ID{34}}
	facts.RequestDigest = expected.RequestDigest
	if disposition == GeneratorDispositionRetirementAcknowledged {
		expected.TargetResourceDigest = template.ResourceDigest
	}
	material := OperationMaterialRecord{Core: OperationMaterialCore{Schema: CanonicalSchema, Profile: 2, CompatibilityID: ID{35}, CryptoSupportID: ID{36},
		DomainID: domain, OperationID: operation, OperationMaterialID: materialID, UsePlanDigest: must(GeneratorUsePlanDigest(plan)), SeedEpoch: 1}, SeedCheck: ID{37}}
	core, err := ExpectedGeneratedResultCore(expected, material, facts)
	if err != nil {
		t.Fatal(err)
	}
	data, commitment, err := GeneratorResultKeyIDs(template.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	raw := uint32(0)
	if disposition == 1 {
		raw = CryptoMaxRawValue
	}
	payload := CanonicalPayload{Profile: 2, CryptoSupportID: material.Core.CryptoSupportID, DataKeyID: data, DataKeyEpoch: 1,
		CommitmentKeyID: commitment, CommitmentKeyEpoch: 1, ContentLength: raw, Ciphertext: bytes.Repeat([]byte{42}, int(raw)+16),
		PackageCheck: ID{38}, SemanticCommitment: ID{39}, InputEncoding: InputEncodingRaw, RetainedLength: raw}
	transfer := TransferEnvelope{Core: TransferCore{Schema: 2, Profile: 2, CompatibilityID: material.Core.CompatibilityID, CryptoSupportID: material.Core.CryptoSupportID,
		DomainID: domain, OperationID: operation, OperationMaterialID: materialID, UsePlanDigest: material.Core.UsePlanDigest,
		UseKind: 2, PacketKind: 6, PacketLength: 100, AttemptID: template.AttemptID, ResultID: template.ResultID,
		ResultCoreDigest: must(GeneratedResultCoreDigest(core)), EnvelopeID: ID{40}}, Ciphertext: bytes.Repeat([]byte{43}, 116)}
	return expected, material, GeneratedResultRecord{Core: core, SafeFacts: facts, Payload: payload, Transfer: transfer}
}

// full_only: false
func TestGeneratedResultRecordBoundContextAndOwnership(t *testing.T) {
	for _, disposition := range []uint8{GeneratorDispositionCompleteCreate, GeneratorDispositionOwnedUnusableCreate, GeneratorDispositionConfirmedNoEffect, GeneratorDispositionRetirementAcknowledged} {
		expected, material, record := generatedResultFixture(t, disposition)
		if err := ValidateGeneratedResult(expected, material, record); err != nil {
			t.Fatal(err)
		}
		wire, err := EncodeGeneratedResultRecord(record)
		if err != nil || len(wire) != 16+452+115+len(record.SafeFacts.Target)+len(record.SafeFacts.ResourceData)+215+int(record.Payload.RetainedLength)+474 || len(wire) > 92637 {
			t.Fatal("result length", len(wire), err)
		}
		view, err := InspectGeneratedResultRecord(wire)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil {
			t.Fatal(err)
		}
		clear(wire)
		if !bytes.Equal(owned.Payload.Ciphertext, record.Payload.Ciphertext) || !bytes.Equal(owned.Transfer.Ciphertext, record.Transfer.Ciphertext) {
			t.Fatal("result retained borrowed ciphertext")
		}
		if _, err := view.Own(); err == nil {
			t.Fatal("result retained changed safe facts")
		}
	}
	expected, material, record := generatedResultFixture(t, 1)
	for name, mutate := range map[string]func(*GeneratedResultRecord){
		"graph":        func(v *GeneratedResultRecord) { v.Core.PlanGraphID[0] ^= 1 },
		"producer":     func(v *GeneratedResultRecord) { v.Core.ExecutorID[0] ^= 1 },
		"attempt":      func(v *GeneratedResultRecord) { v.Core.AttemptID[0] ^= 1 },
		"transmission": func(v *GeneratedResultRecord) { v.Core.TransmissionID[0] ^= 1 },
		"result":       func(v *GeneratedResultRecord) { v.Core.ResultID[0] ^= 1 },
		"request":      func(v *GeneratedResultRecord) { v.Core.RequestDigest[0] ^= 1 },
		"facts":        func(v *GeneratedResultRecord) { v.SafeFacts.ResourceData[0] ^= 1 },
		"key ID":       func(v *GeneratedResultRecord) { v.Payload.DataKeyID[0] ^= 1 },
		"key epoch":    func(v *GeneratedResultRecord) { v.Payload.CommitmentKeyEpoch++ },
		"empty create": func(v *GeneratedResultRecord) {
			v.Payload.ContentLength = 0
			v.Payload.Ciphertext = v.Payload.Ciphertext[:16]
		},
		"transfer":      func(v *GeneratedResultRecord) { v.Transfer.Core.OperationID[0] ^= 1 },
		"compatibility": func(v *GeneratedResultRecord) { v.Transfer.Core.CompatibilityID[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := record
			mutate(&bad)
			if err := ValidateGeneratedResult(expected, material, bad); err == nil {
				t.Fatal("accepted changed context")
			}
		})
	}
	expected.Use.MaxSecret--
	if err := ValidateGeneratedResult(expected, material, record); err == nil {
		t.Fatal("accepted value beyond admitted result use")
	}
}
