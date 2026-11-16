package core

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedCleanupSelectsDetachedCreateHazardWithoutRestoringAttempt(t *testing.T) {
	s, h, target := generatedDetachedHazardState(t, "absent", 0, 1, 1)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.attempts) != 0 {
		t.Fatal("detached cleanup fixture restored an original live Attempt")
	}
	if _, present := g.records[generatedRecordKey{kind: 10, id: h.OwnerID}]; present {
		t.Fatal("detached cleanup fixture invented a Duty")
	}

	selected, ok, err := g.selectGeneratedCleanup(context.Background(), nil)
	if err != nil || !ok {
		t.Fatal("valid detached kind-13 Hazard was not selected", err)
	}
	if selected.kind != generatedCleanupHazard || selected.hazard != h || selected.target != target {
		t.Fatal("detached cleanup selection lost its exact Hazard or target")
	}
	if !selected.attempt.record.AttemptID.IsZero() || selected.duty != (contract.GeneratedDutyRecord{}) {
		t.Fatal("detached cleanup selection fabricated an Attempt or Duty")
	}
}

// full_only: false
func TestGeneratedCleanupDeleteBindsOriginalOwnedTarget(t *testing.T) {
	s, original := generatedUnselectedCleanupState(t, 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bundle := g.bundles[0]
	if _, ok := g.records[generatedRecordKey{kind: 13, id: original.record.ResultID}]; !ok {
		t.Log("cleanup fixture retains original result without a kind-13 handoff")
	}
	var x contract.GeneratorAttemptTemplate
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose == 3 && lineage.TemplateCount == 1 &&
			lineage.Templates[0].TargetSourceID == original.record.ResultID {
			x = lineage.Templates[0]
			break
		}
	}
	if x.AttemptID.IsZero() {
		t.Fatal("missing exact cleanup delete template")
	}
	templateDigest, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	a := contract.GeneratedAttemptRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedAttemptRecordSchema, DomainID: bundle.Header.DomainID, OperationID: bundle.Header.OperationID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TemplateDigest: templateDigest, OwnerID: x.DutyID,
		ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, InboxID: x.InboxID,
		ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, RequestDigest: original.record.RequestDigest,
		State: contract.GeneratedEffectTransmitted, Stage: contract.GeneratedStageRetainedResult, CompletionClass: x.CompletionClass,
		Facts: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts), Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress),
		Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)}
	target, err := g.generatedDeleteAttemptTarget(t.Context(), bundle, a)
	if err != nil {
		t.Fatal("exact unselected cleanup target refused", err)
	}
	if target.OriginalOperationID != original.record.OperationID || target.OriginalAttemptID != original.record.AttemptID ||
		target.ResourceID != original.record.ResourceID || target.ResourceDigest.IsZero() || target.CompletionClass != original.record.CompletionClass {
		t.Fatal("cleanup delete did not retain its original create target")
	}
	if target.ResultContractID == a.ResultContractID {
		t.Fatal("fixture does not prove separate create and delete result contracts")
	}
	if _, err := g.retirementAttemptTarget(t.Context(), bundle, a); err == nil {
		t.Fatal("cleanup Duty was accepted as an ordinary retirement")
	}
	for _, test := range []struct {
		name   string
		kind   uint8
		digest contract.ID
		valid  bool
	}{
		{"result slot resolves zero placeholder", contract.GeneratorTargetResultResourceSlot, contract.ID{}, true},
		{"result slot binds exact resource", contract.GeneratorTargetResultResourceSlot, target.ResourceDigest, true},
		{"result slot refuses changed resource", contract.GeneratorTargetResultResourceSlot, generatedVectorID(98), false},
		{"owned resource refuses zero digest", contract.GeneratorTargetOwnedResource, contract.ID{}, false},
		{"owned resource binds exact digest", contract.GeneratorTargetOwnedResource, target.ResourceDigest, true},
		{"owned resource refuses changed digest", contract.GeneratorTargetOwnedResource, generatedVectorID(98), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := bundle
			changed.Lineages = slices.Clone(bundle.Lineages)
			for i := range changed.Lineages {
				if changed.Lineages[i].LineageID != a.LineageID {
					continue
				}
				changed.Lineages[i].Templates[0].TargetKind = test.kind
				changed.Lineages[i].Templates[0].ResourceDigest = test.digest
				if test.kind == contract.GeneratorTargetOwnedResource {
					changed.Lineages[i].Templates[0].TargetSourceID = target.ResourceID
				}
			}
			if err := g.validateDeleteTarget(t.Context(), changed, a, target); (err == nil) != test.valid {
				t.Fatal("cleanup target resource relation", err)
			}
		})
	}

	changed := a
	changed.OwnerID = generatedVectorID(99)
	if _, err := g.generatedDeleteAttemptTarget(t.Context(), bundle, changed); err == nil {
		t.Fatal("cleanup delete accepted a substituted owner")
	}
	changed = a
	changed.CompletionClass = contract.GeneratedCompletionConfirmed
	if _, err := g.generatedDeleteAttemptTarget(t.Context(), bundle, changed); err == nil {
		t.Fatal("cleanup delete lowered or changed the retained completion class")
	}
}
