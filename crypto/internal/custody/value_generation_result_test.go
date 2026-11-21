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

func managedResultEncodingFailure(t *testing.T) {
	expected, material, facts, seed := generatedResultContext(t, contract.GeneratorActionCreate)
	defer clear(seed)
	expected.InputEncoding = contract.InputEncodingBase64
	expected.Template.ResultReaderID = contract.GeneratorResultReaderFor(expected.Template.Action, expected.Template.CompletionClass, expected.InputEncoding)
	private := []byte("bad_")
	rejected, err := SealGeneratedResult(expected, material, facts, seed, private)
	if err != nil {
		t.Fatal(err)
	}
	original, err := contract.EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := contract.EncodeGeneratorSafeFacts(rejected.SafeFacts)
	if err != nil || !bytes.Equal(original, retained) || rejected.Core.Schema != contract.GeneratedResultEncodingFailureSchema ||
		rejected.Payload.RetainedLength != 0 || rejected.Payload.ContentLength != 0 {
		t.Fatal("rejection lost the provider facts or retained private bytes", err)
	}
	opened, err := OpenGeneratedResult(expected, material, seed, rejected)
	if err != nil || len(opened) != 0 {
		t.Fatal("rejected result failed original verification", err)
	}
	usable, err := SealGeneratedResult(expected, material, facts, seed, []byte("Zg=="))
	if err != nil || usable.Disposition() != contract.GeneratorDispositionCompleteCreate {
		t.Fatal("valid Base64", err)
	}
	opened, err = OpenGeneratedResult(expected, material, seed, usable)
	if err != nil || !bytes.Equal(opened, []byte("Zg==")) {
		t.Fatal("valid Base64 changed", err)
	}
	clear(opened)

	legacy := expected
	legacy.Template.ResultReaderID = contract.GeneratorResultReaderID()
	if _, err := OpenGeneratedResult(legacy, material, seed, rejected); err == nil {
		t.Fatal("earlier reader accepted the host rejection")
	}
	if _, err := SealGeneratedResult(legacy, material, facts, seed, private); err == nil {
		t.Fatal("earlier reader produced the host rejection")
	}
	previous, err := SealGeneratedResult(legacy, material, facts, seed, []byte("Zg=="))
	if err != nil || previous.Core.Schema != contract.GeneratedResultCoreSchema {
		t.Fatal("earlier reader lost its valid result", err)
	}

	other := expected
	other.Template.AttemptID[0] ^= 1
	if _, err := OpenGeneratedResult(other, material, seed, rejected); err == nil {
		t.Fatal("other attempt accepted the rejection")
	}
	for name, modify := range map[string]func(*contract.GeneratedResultRecord){
		"remove host rejection": func(r *contract.GeneratedResultRecord) { r.Core.Schema = contract.GeneratedResultCoreSchema },
		"replace transfer":      func(r *contract.GeneratedResultRecord) { r.Transfer = usable.Transfer },
		"replace ciphertext": func(r *contract.GeneratedResultRecord) {
			r.Payload.Ciphertext = bytes.Clone(r.Payload.Ciphertext)
			r.Payload.Ciphertext[0] ^= 1
		},
		"change target":        func(r *contract.GeneratedResultRecord) { r.SafeFacts.ResourceData = []byte("other target") },
		"attach private value": func(r *contract.GeneratedResultRecord) { r.Payload = usable.Payload },
	} {
		t.Run(name, func(t *testing.T) {
			changed := rejected
			modify(&changed)
			if p, err := OpenGeneratedResult(expected, material, seed, changed); err == nil || p != nil {
				t.Fatal("changed result verified")
			}
		})
	}
	for _, invalid := range [][]byte{nil, bytes.Repeat([]byte("_"), contract.CryptoMaxRetainedValue+1)} {
		if _, err := SealGeneratedResult(expected, material, facts, seed, invalid); err == nil {
			t.Fatal("missing or oversized bytes became host rejection")
		}
	}
	local, localMaterial, localFacts, localSeed := localGeneratedResultContext(t)
	defer clear(localSeed)
	local.InputEncoding = contract.InputEncodingBase64
	if _, err := SealGeneratedResult(local, localMaterial, localFacts, localSeed, private); err == nil {
		t.Fatal("local CREATE emitted managed encoding evidence")
	}
	for name, modify := range map[string]func(*contract.GeneratorResultExpectation){
		"raw encoding": func(v *contract.GeneratorResultExpectation) { v.InputEncoding = contract.InputEncodingRaw },
		"delete":       func(v *contract.GeneratorResultExpectation) { v.Template.Action = contract.GeneratorActionDelete },
		"resource-free": func(v *contract.GeneratorResultExpectation) {
			v.Template.LifecycleMode = contract.GeneratorLifecycleNone
		},
	} {
		t.Run(name, func(t *testing.T) {
			incompatible := expected
			modify(&incompatible)
			if _, err := OpenGeneratedResult(incompatible, material, seed, rejected); err == nil {
				t.Fatal("wrong result context accepted the host rejection")
			}
		})
	}
	seed[0] ^= 1
	if _, err := SealGeneratedResult(expected, material, facts, seed, private); err == nil {
		t.Fatal("seed failure became host rejection")
	}
}

// full_only: false
func TestGeneratedResultSealOpenAndRefusals(t *testing.T) {
	t.Run("managed value encoding failure", managedResultEncodingFailure)
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
