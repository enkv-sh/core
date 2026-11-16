package custody

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

func mustGeneratedResourceDigest(t testing.TB, facts contract.GeneratorSafeFacts) contract.ID {
	t.Helper()
	if facts.LifecycleMode == contract.GeneratorLifecycleNone {
		return contract.ID{}
	}
	digest, err := contract.GeneratorResourceDigest(facts)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func generatedValueEntryPlan(t testing.TB, expected contract.GeneratorResultExpectation, material contract.OperationMaterialRecord, result contract.GeneratedResultRecord, phase contract.ID) (contract.CryptoGeneratedValueEntryPlan, contract.GeneratorResultReference) {
	t.Helper()
	x, f := expected.Template, result.SafeFacts
	meta := contract.GeneratedEntryMetadata{Schema: contract.GeneratedEntryMetadataSchema, Epoch: 1, LifecycleMode: x.LifecycleMode, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, IntentDigest: x.IntentDigest,
		ResourceIncarnationID: x.ResourceIncarnationID, OriginOperationID: material.Core.OperationID, OriginAttemptID: x.AttemptID,
		GenerationID: testID(30), ResourceDigest: mustGeneratedResourceDigest(t, f), CreateResultID: x.ResultID,
		CreateEvidence:  contract.GeneratorDescriptor{Digest: testID(31), Length: 8, Count: 1},
		RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), CompletionClass: x.CompletionClass, RetirementMode: contract.GeneratedRetirementManual}
	binding, err := contract.GeneratedBindingDigest(meta)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contract.DeriveGeneratedValueIdentity(x.PlannedValueSlotID, phase, x.ResultID, binding)
	if err != nil {
		t.Fatal(err)
	}
	meta.GenerationID = identity.ValueStateID
	core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: material.Core.CompatibilityID, CryptoSupportID: material.Core.CryptoSupportID,
		DomainID: material.Core.DomainID, Name: "token", EntryIncarnationID: testID(21), ValueStateID: identity.ValueStateID,
		OriginSnapshotID: identity.OriginSnapshotID, OriginTransitionID: identity.OriginTransitionID, DataKeyID: identity.DataKeyID, DataKeyEpoch: 1,
		CommitmentKeyID: identity.CommitmentKeyID, CommitmentKeyEpoch: 1, ContentLength: result.Payload.ContentLength, ValueSource: contract.Generated, GeneratedBindingDigest: binding, InputEncoding: contract.InputEncodingRaw, RetainedLength: result.Payload.ContentLength}
	body, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	return contract.CryptoGeneratedValueEntryPlan{OutputEncoding: contract.OutputEncodingRaw, Result: body, ValueCore: core, Generated: meta, Recipients: []contract.ID{testID(22)}},
		contract.GeneratorResultReference{Schema: 1, ResultID: result.Core.ResultID, ResultBodyDigest: contract.Hash(body), ResultLength: uint32(len(body))}
}

// full_only: false
func TestGeneratedMemberReproducesExactSelectedResult(t *testing.T) {
	expected, material, result, seed := generatedVectorFixture(t)
	defer clear(seed)
	phase := testID(20)
	plan, selected := generatedValueEntryPlan(t, expected, material, result, phase)
	first, keys, err := SealGeneratedValuePayload(expected, material, phase, selected, plan, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	if len(keys) != 64 || cap(keys) != 64 {
		t.Fatal("member keys do not have one exact owned buffer")
	}
	plain, err := OpenValue(plan.ValueCore, first, keys)
	if err != nil || !bytes.Equal(plain, []byte("secret-value")) {
		t.Fatal("ordinary member reader did not open prepared value", err)
	}
	clear(plain[:cap(plain)])
	second, nextKeys, err := SealGeneratedValuePayload(expected, material, phase, selected, plan, seed)
	defer clear(nextKeys[:cap(nextKeys)])
	a, errA := contract.EncodeCanonicalPayload(first)
	b, errB := contract.EncodeCanonicalPayload(second)
	if err != nil || errA != nil || errB != nil || !bytes.Equal(a, b) || !bytes.Equal(keys, nextKeys) {
		t.Fatal("same immutable context did not reproduce exact member bytes")
	}
	plan.Generated.RetirementMode = contract.GeneratedRetirementAuto
	plan.Generated.RetiringDutyPresent, plan.Generated.RetiringDutyID = 1, testID(23)
	policyOnly, policyKeys, err := SealGeneratedValuePayload(expected, material, phase, selected, plan, seed)
	defer clear(policyKeys[:cap(policyKeys)])
	if err != nil || !bytes.Equal(policyOnly.Ciphertext, first.Ciphertext) || !bytes.Equal(policyKeys, keys) {
		t.Fatal("retirement policy changed immutable encryption", err)
	}
	newPhase := testID(24)
	changedPlan, _ := generatedValueEntryPlan(t, expected, material, result, newPhase)
	changed, changedKeys, err := SealGeneratedValuePayload(expected, material, newPhase, selected, changedPlan, seed)
	defer clear(changedKeys[:cap(changedKeys)])
	if err != nil || bytes.Equal(changedKeys, keys) || changed.Nonce == first.Nonce || bytes.Equal(changed.Ciphertext, first.Ciphertext) {
		t.Fatal("new materialization phase reused the old encryption context", err)
	}
	if bytes.Equal(keys, fixtureKeys()) || bytes.Equal(first.Ciphertext, result.Payload.Ciphertext) {
		t.Fatal("member reused result-only encryption")
	}
}

// full_only: false
func TestGeneratedMemberIndependentDerivation(t *testing.T) {
	// Node/OpenSSL independently framed ValueCore/v11 for name "token",
	// incarnation 0x15 repeated, phase 0x14 repeated and the result fixture's
	// fixed public fields. It computed D identities, then C = B(ValueCore) ||
	// ResultID || SHA256(B(ResultCore) || result semantic commitment).
	// HKDF used seed 0x80 repeated, the specified generated-member labels and
	// C without an extra B frame. AES-GCM/HMAC used plaintext "secret-value".
	// No production encoder, derivation or sealing routine supplied answers.
	expected, material, result, seed := generatedVectorFixture(t)
	defer clear(seed)
	phase := testID(20)
	plan, selected := generatedValueEntryPlan(t, expected, material, result, phase)
	payload, keys, err := SealGeneratedValuePayload(expected, material, phase, selected, plan, seed)
	defer clear(keys[:cap(keys)])
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name string
		got  []byte
		want string
	}{
		{"data key", keys[:32], "ba8e15744d4da85c627dc3982962dbbea0aa07d79d8b203c78d4749b77cfe2a5"},
		{"commitment key", keys[32:], "2603438b2865e6f9d0ef69cea2b0609d3d9e12b0783543fc2c600af9f730f1c8"},
		{"nonce", payload.Nonce[:], "0d9f6ecdc0f80de9604451eb"},
		{"ciphertext", payload.Ciphertext, "5e80ef286ce23e8b1bd259e1d9c08cc811318759a63102b2b53a8bf0"},
		{"semantic commitment", payload.SemanticCommitment[:], "7ddc6f2fd0146a026ca7abcddccc14c8120910a0b0daa85c211f713c906aa5c2"},
		{"package check", payload.PackageCheck[:], "b959b35819083b0892c34da2a553e667f003308f82e17199005a2f59c4e9c062"},
	} {
		if !bytes.Equal(row.got, hexBytes(t, row.want)) {
			t.Fatal("member differs from independent answer", row.name)
		}
	}
}

// full_only: false
func TestGeneratedMemberRefusesUnselectedOrChangedContext(t *testing.T) {
	for name, change := range map[string]func(*contract.CryptoGeneratedValueEntryPlan, *contract.GeneratorResultReference, *contract.ID, []byte){
		"result bytes": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.Result[len(p.Result)-1] ^= 1
		},
		"selected result": func(_ *contract.CryptoGeneratedValueEntryPlan, r *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			r.ResultID[0] ^= 1
		},
		"selected digest": func(_ *contract.CryptoGeneratedValueEntryPlan, r *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			r.ResultBodyDigest[0] ^= 1
		},
		"selected length": func(_ *contract.CryptoGeneratedValueEntryPlan, r *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			r.ResultLength++
		},
		"phase": func(_ *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, p *contract.ID, _ []byte) {
			p[0] ^= 1
		},
		"seed": func(_ *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, s []byte) {
			s[0] ^= 1
		},
		"domain": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.DomainID[0] ^= 1
		},
		"compatibility": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.CompatibilityID[0] ^= 1
		},
		"support": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.CryptoSupportID[0] ^= 1
		},
		"raw length": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.ContentLength++
		},
		"value": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.ValueStateID[0] ^= 1
		},
		"snapshot": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.OriginSnapshotID[0] ^= 1
		},
		"transition": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.OriginTransitionID[0] ^= 1
		},
		"data key": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.DataKeyID[0] ^= 1
		},
		"commitment key": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.CommitmentKeyID[0] ^= 1
		},
		"data epoch": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.DataKeyEpoch++
		},
		"commitment epoch": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.CommitmentKeyEpoch++
		},
		"binding": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.ValueCore.GeneratedBindingDigest[0] ^= 1
		},
		"resource contract": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.Generated.ResourceContractID[0] ^= 1
		},
		"resource digest": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.Generated.ResourceDigest[0] ^= 1
		},
		"operation": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.Generated.OriginOperationID[0] ^= 1
		},
		"attempt": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.Generated.OriginAttemptID[0] ^= 1
		},
		"create result": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.Generated.CreateResultID[0] ^= 1
		},
		"generation": func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.GeneratorResultReference, _ *contract.ID, _ []byte) {
			p.Generated.GenerationID[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			expected, material, result, seed := generatedVectorFixture(t)
			defer clear(seed)
			phase := testID(20)
			plan, selected := generatedValueEntryPlan(t, expected, material, result, phase)
			change(&plan, &selected, &phase, seed)
			got, keys, err := SealGeneratedValuePayload(expected, material, phase, selected, plan, seed)
			if err == nil || keys != nil || got.Ciphertext != nil {
				clear(keys)
				t.Fatal("changed context returned member material")
			}
		})
	}
	expected, material, first, seed := generatedVectorFixture(t)
	defer clear(seed)
	phase := testID(20)
	plan, selected := generatedValueEntryPlan(t, expected, material, first, phase)
	second, err := SealGeneratedResult(expected, material, first.SafeFacts, seed, []byte("other-secret"))
	if err != nil {
		t.Fatal(err)
	}
	plan.Result, err = contract.EncodeGeneratedResultRecord(second)
	if err != nil {
		t.Fatal(err)
	}
	got, keys, err := SealGeneratedValuePayload(expected, material, phase, selected, plan, seed)
	if err == nil || keys != nil || got.Ciphertext != nil {
		clear(keys)
		t.Fatal("another valid result at the same ResultID replaced selected bytes")
	}
}
