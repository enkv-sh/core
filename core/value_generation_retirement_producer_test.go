package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedRetirementProducerBindsReservePurposeAndExactTarget(t *testing.T) {
	s, original, _, target := generatedEnteredRetirementState(t, false)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	if !generatedProducerPhaseMatches(g, a, contract.GeneratorAuthorityRetireReserve) ||
		generatedProducerPhaseMatches(g, a, contract.GeneratorAuthorityRecord) ||
		generatedProducerPhaseMatches(g, a, contract.GeneratorAuthorityCleanupReserve) {
		t.Fatal("retirement delete accepted the wrong producer reservation purpose")
	}
	preparation, err := generatedProducerPreparation(*g.parent, a)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.Action != 2 || preparation.LifecycleMode != contract.GeneratorLifecycleManaged || preparation.ResourceContractID != target.ResourceContractID || preparation.ResourceDigest != target.ResourceDigest ||
		preparation.AttemptID != a.record.AttemptID || preparation.ResultID != a.record.ResultID ||
		preparation.RequestDigest != a.record.RequestDigest || preparation.IntentDigest != a.expected.Template.IntentDigest {
		t.Fatal("retirement producer did not bind the exact selected delete")
	}

	a.expected.TargetResourceDigest = contract.ID{}
	if _, err := generatedProducerPreparation(*g.parent, a); err == nil {
		t.Fatal("retirement producer accepted an absent exact target")
	}
}
