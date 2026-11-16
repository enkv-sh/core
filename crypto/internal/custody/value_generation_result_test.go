package custody

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

func generatedResultContext(t testing.TB, action uint8) (contract.GeneratorResultExpectation, contract.OperationMaterialRecord, contract.GeneratorSafeFacts, []byte) {
	t.Helper()
	mustID := func(v contract.ID, err error) contract.ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	domain, operation := testID(3), testID(17)
	template := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, LifecycleMode: contract.GeneratorLifecycleManaged, ResultReaderID: contract.GeneratorResultReaderID(), Action: action, LineageID: testID(4), DescriptorID: testID(5), ConfigContractID: testID(6),
		ExecutorID: testID(7), CredentialRouteID: testID(8), ResourceContractID: testID(9), ResultContractID: testID(10),
		IntentDigest: testID(11), TargetKind: 1, TargetSourceID: testID(11), CompletionClass: 1,
		NoEffectBudget: 1, ResidueBudget: 1, RequiredAuthoritySet: 1}
	template.AttemptID = mustID(contract.GeneratorAttemptID(template.LineageID, 0))
	template.TransmissionID = mustID(contract.GeneratorTransmissionID(template.AttemptID, action))
	template.ResultID = mustID(contract.GeneratorResultID(domain, operation, template.AttemptID, template.TransmissionID, action))
	template.InboxID = mustID(contract.GeneratorInboxID(domain, operation, template.AttemptID, template.ResultID))
	template.ResourceIncarnationID = mustID(contract.GeneratorResourceID(domain, operation, template.AttemptID))
	template.PlannedValueSlotID = mustID(contract.GeneratorValueSlotID(domain, operation, template.AttemptID))
	template.DutyID = mustID(contract.GeneratorDutyID(domain, operation, template.AttemptID, 1))
	template.HazardID = mustID(contract.GeneratorHazardID(domain, template.AttemptID))
	if action == 2 {
		template.TargetKind, template.TargetSourceID, template.NoEffectBudget, template.ResidueBudget = 2, template.ResourceIncarnationID, 0, 0
	}
	facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: action, LifecycleMode: contract.GeneratorLifecycleManaged, ResourceContractID: template.ResourceContractID,
		Disposition: contract.GeneratorDispositionCompleteCreate, RequestDigest: testID(14), IntentDigest: template.IntentDigest, Target: bytes.Repeat([]byte{12}, 32), ResourceData: bytes.Repeat([]byte{15}, 32), ProviderFacts: []byte{200, 1, 3}}
	var resourceDigest contract.ID
	if action == contract.GeneratorActionDelete {
		facts.Disposition = contract.GeneratorDispositionRetirementAcknowledged
		resourceDigest = mustID(contract.GeneratorResourceDigest(facts))
		template.ResourceDigest = resourceDigest
	}
	template.RequestPlanDigest = mustID(contract.GeneratorRequestPlanDigest(template))
	materialID := mustID(contract.GeneratorMaterialID(domain, operation))
	use := contract.GeneratorResultUse{Schema: 1, AttemptID: template.AttemptID, ResultID: template.ResultID, InboxID: template.InboxID, ExecutorID: template.ExecutorID,
		ResultContractID: template.ResultContractID, PlannedValueSlotID: template.PlannedValueSlotID, MaterialID: materialID, Purpose: 1, MaxSecret: 65536, MaxFacts: 4096}
	if action == 2 {
		use.MaxSecret = 0
	}
	uses, err := contract.GeneratorResultUsesDescriptor([]contract.GeneratorResultUse{use})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := contract.GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := contract.GeneratorUsePlanCore{DomainID: domain, OperationID: operation, MaterialID: materialID, PlanGraphID: testID(13),
		ResultUses: uses, SourceUses: sources, ValueDerivationID: contract.GeneratorValueDerivationID()}
	expected := contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Plan: plan, Template: template, Use: use, RequestDigest: testID(14)}
	material := contract.OperationMaterialRecord{Core: contract.OperationMaterialCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: testID(1), CryptoSupportID: testID(2),
		DomainID: domain, OperationID: operation, OperationMaterialID: materialID, UsePlanDigest: mustID(contract.GeneratorUsePlanDigest(plan)), SeedEpoch: 1}}
	seed := bytes.Repeat([]byte{128}, 32)
	material.SeedCheck = mustID(SeedCheck(material.Core, seed))
	expected.TargetResourceDigest = resourceDigest
	return expected, material, facts, seed
}

// full_only: false
func TestGeneratedResultSealOpenAndRefusals(t *testing.T) {
	for _, action := range []uint8{1, 2} {
		expected, material, facts, seed := generatedResultContext(t, action)
		defer clear(seed)
		plain := []byte("one exact private provider return")
		if action == 2 {
			plain = nil
		}
		first, err := SealGeneratedResult(expected, material, facts, seed, plain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenGeneratedResult(expected, material, seed, first)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("result did not open", err)
		}
		clear(got)
		second, err := SealGeneratedResult(expected, material, facts, seed, plain)
		if err != nil || second.Core != first.Core || second.Transfer.Core.EnvelopeID == first.Transfer.Core.EnvelopeID || bytes.Equal(second.Payload.Ciphertext, first.Payload.Ciphertext) {
			t.Fatal("physical encryption did not stay separate", err)
		}
		for name, mutate := range map[string]func(*contract.GeneratedResultRecord){
			"ciphertext": func(v *contract.GeneratedResultRecord) {
				v.Payload.Ciphertext = bytes.Clone(v.Payload.Ciphertext)
				v.Payload.Ciphertext[0] ^= 1
			},
			"transfer": func(v *contract.GeneratedResultRecord) {
				v.Transfer.Ciphertext = bytes.Clone(v.Transfer.Ciphertext)
				v.Transfer.Ciphertext[0] ^= 1
			},
			"package":  func(v *contract.GeneratedResultRecord) { v.Payload.PackageCheck[0] ^= 1 },
			"semantic": func(v *contract.GeneratedResultRecord) { v.Payload.SemanticCommitment[0] ^= 1 },
			"nonce":    func(v *contract.GeneratedResultRecord) { v.Payload.Nonce[0] ^= 1 },
			"facts":    func(v *contract.GeneratedResultRecord) { v.SafeFacts.ResourceData[0] ^= 1 },
			"producer": func(v *contract.GeneratedResultRecord) { v.Core.ExecutorID[0] ^= 1 },
			"key ID":   func(v *contract.GeneratedResultRecord) { v.Payload.CommitmentKeyID[0] ^= 1 },
			"length":   func(v *contract.GeneratedResultRecord) { v.Payload.ContentLength++ },
		} {
			t.Run(name, func(t *testing.T) {
				bad := first
				mutate(&bad)
				if got, err := OpenGeneratedResult(expected, material, seed, bad); err == nil || got != nil {
					t.Fatal("private refusal leaked plaintext")
				}
			})
		}
		seed[0] ^= 1
		if got, err := OpenGeneratedResult(expected, material, seed, first); err == nil || got != nil {
			t.Fatal("wrong seed opened result")
		}
		if _, err := SealGeneratedResult(expected, material, facts, seed, plain); err == nil {
			t.Fatal("wrong seed sealed result")
		}
	}
}
