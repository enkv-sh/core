package custody

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

func localGeneratedResultContext(t testing.TB) (contract.GeneratorResultExpectation, contract.OperationMaterialRecord, contract.GeneratorSafeFacts, []byte) {
	t.Helper()
	expected, material, _, seed := generatedResultContext(t, contract.GeneratorActionCreate)
	x := &expected.Template
	x.Schema, x.LifecycleMode, x.ResultReaderID = contract.GeneratorAttemptTemplateSchema, contract.GeneratorLifecycleNone, contract.GeneratorResultReaderID()
	x.ResourceContractID, x.ResourceDigest, x.HazardID, x.TargetSourceID = contract.ID{}, contract.ID{}, contract.ID{}, contract.ID{}
	x.TargetKind, x.CompletionClass, x.NoEffectBudget, x.ResidueBudget = 0, 0, 0, 0
	var err error
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(*x)
	if err != nil {
		t.Fatal(err)
	}
	expected.Use.MaxSecret, expected.Use.MaxFacts = 65536, 4096
	expected.Plan.ResultUses, err = contract.GeneratorResultUsesDescriptor([]contract.GeneratorResultUse{expected.Use})
	if err != nil {
		t.Fatal(err)
	}
	expected.Plan.ValueDerivationID = contract.GeneratorValueDerivationID()
	material.Core.UsePlanDigest, err = contract.GeneratorUsePlanDigest(expected.Plan)
	if err != nil {
		t.Fatal(err)
	}
	material.SeedCheck, err = SeedCheck(material.Core, seed)
	if err != nil {
		t.Fatal(err)
	}
	facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate, LifecycleMode: contract.GeneratorLifecycleNone, Disposition: contract.GeneratorDispositionCompleteCreate, RequestDigest: expected.RequestDigest, IntentDigest: x.IntentDigest}
	return expected, material, facts, seed
}

// full_only: false
func TestLocalGeneratedResultSealingUsesFamilyValueBounds(t *testing.T) {
	expected, material, facts, seed := localGeneratedResultContext(t)
	defer clear(seed)
	for _, tc := range []struct {
		name  string
		value []byte
		valid bool
	}{
		{"one byte", []byte{0}, true}, {"arbitrary bytes", []byte{0, 255, '/', '+'}, true}, {"maximum", bytes.Repeat([]byte{255}, 65536), true},
		{"empty", []byte{}, false}, {"one over", bytes.Repeat([]byte{255}, 65537), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := SealGeneratedResult(expected, material, facts, seed, tc.value)
			if !tc.valid {
				if err == nil {
					t.Fatal("out-of-bound local value sealed")
				}
				return
			}
			if err != nil || result.Core.Schema != contract.GeneratedResultCoreSchema || result.Payload.ContentLength != uint32(len(tc.value)) {
				t.Fatal("family-valid value refused", err)
			}
			opened, err := OpenGeneratedResult(expected, material, seed, result)
			if err != nil || !bytes.Equal(opened, tc.value) {
				t.Fatal("local result did not reopen", err)
			}
			clear(opened[:cap(opened)])
		})
	}
}
