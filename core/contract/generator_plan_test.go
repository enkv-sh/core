package contract

import "testing"

func generatorTemplateFixture(t testing.TB, branch uint8) GeneratorAttemptTemplate {
	t.Helper()
	id := ID{1}
	v := GeneratorAttemptTemplate{Schema: GeneratorAttemptTemplateSchema, LifecycleMode: GeneratorLifecycleManaged, ResultReaderID: GeneratorResultReaderID(), Branch: branch, Action: 1,
		LineageID: id, ResourceIncarnationID: id, PlannedValueSlotID: id, DutyID: id, HazardID: id,
		ResultID: id, InboxID: id, DescriptorID: id, ConfigContractID: id, ExecutorID: id,
		CredentialRouteID: id, ResourceContractID: id, ResultContractID: id,
		RequestPlanDigest: id, IntentDigest: id, TargetKind: 1,
		TargetSourceID: id, CompletionClass: 1, RequiredAuthoritySet: 1}
	var err error
	v.AttemptID, err = GeneratorAttemptID(v.LineageID, branch)
	if err != nil {
		t.Fatal(err)
	}
	if branch != 0 {
		previous := uint8(0)
		if branch > 2 {
			previous = branch - 2
		}
		v.PredecessorAttemptID, err = GeneratorAttemptID(v.LineageID, previous)
		if err != nil {
			t.Fatal(err)
		}
	}
	v.TransmissionID, err = GeneratorTransmissionID(v.AttemptID, v.Action)
	if err != nil {
		t.Fatal(err)
	}
	if branch == 0 || branch == 2 {
		v.NoEffectBudget = 1
	}
	if branch == 0 || branch == 1 {
		v.ResidueBudget = 1
	}
	v.RequestPlanDigest, err = GeneratorRequestPlanDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// full_only: false
func TestGeneratorTemplateBranchesAndDamage(t *testing.T) {
	for branch := uint8(0); branch <= 4; branch++ {
		v := generatorTemplateFixture(t, branch)
		body, err := EncodeGeneratorAttemptTemplate(v)
		if err != nil || len(body) != 682 {
			t.Fatalf("branch %d: length %d, %v", branch, len(body), err)
		}
		got, err := InspectGeneratorAttemptTemplate(body)
		if err != nil || got != v {
			t.Fatalf("branch %d: %v", branch, err)
		}
		for n := range len(body) {
			if _, err := InspectGeneratorAttemptTemplate(body[:n]); err == nil {
				t.Fatalf("accepted prefix %d", n)
			}
		}
		for _, change := range []func(*GeneratorAttemptTemplate){
			func(v *GeneratorAttemptTemplate) { v.Schema++ },
			func(v *GeneratorAttemptTemplate) { v.AttemptID[0] ^= 1 },
			func(v *GeneratorAttemptTemplate) { v.PredecessorAttemptID[0] ^= 1 },
			func(v *GeneratorAttemptTemplate) { v.TransmissionID[0] ^= 1 },
			func(v *GeneratorAttemptTemplate) { v.NoEffectBudget ^= 1 },
			func(v *GeneratorAttemptTemplate) { v.ResidueBudget ^= 1 },
			func(v *GeneratorAttemptTemplate) { v.RequiredAuthoritySet = 0 },
			func(v *GeneratorAttemptTemplate) { v.TargetSourceID[0] ^= 1 },
			func(v *GeneratorAttemptTemplate) { v.TargetKind = 3 },
			func(v *GeneratorAttemptTemplate) { v.DescriptorID = ID{} },
		} {
			broken := v
			change(&broken)
			if _, err := EncodeGeneratorAttemptTemplate(broken); err == nil {
				t.Fatalf("accepted mutation for branch %d", branch)
			}
		}
		if _, err := InspectGeneratorAttemptTemplate(append(body, 0)); err == nil {
			t.Fatal("accepted trailing byte")
		}
	}
}
