package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

func generatedFinalWithFreshToken(t *testing.T, before *StateSession, operation, token contract.ID, nonce byte) *StateSession {
	t.Helper()
	next, err := before.deriveGeneratedReservation(t.Context(), generatedReservationInputForOperation(t, before, operation))
	if err != nil {
		t.Fatal("fresh reservation with older retained work", err)
	}
	active := next.state
	work := mustSelectedGeneratedWork(t, active)
	frontier := work.attempts[work.phase.FrontierAttemptID]
	packet := generatedPublicResultFixtureWithRawToken(t, frontier, contract.GeneratorDispositionCompleteCreate, 1, token)
	record, err := active.generatedRecordRequest(t.Context(), frontier.record.AttemptID, packet,
		generatedContinuationContext(t, active, nonce, nonce+1))
	if err != nil {
		t.Fatal("fresh successful frontier result", err)
	}
	recorded, err := active.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("fresh successful frontier selection", err)
	}
	plan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, nonce+2, nonce+3))
	if err != nil || !plan.selecting || len(plan.entryPlans) != 1 {
		t.Fatal("fresh successful frontier must admit selecting Final", err)
	}
	prepared := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, recorded.state, plan.entryPlans[0])}
	final, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, prepared)
	if err != nil || final.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("selecting Final with older retained work", err)
	}
	entry := final.state.valueEntry(plan.entryPlans[0].Slot)
	if entry == nil || entry.Generated.OriginAttemptID != frontier.record.AttemptID {
		t.Fatal("Final selected the wrong frontier")
	}
	return final.state
}

// full_only: false
func TestGeneratedSelectingFinalPreservesPriorCleanup(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base,
		generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal("two-lineage reservation", err)
	}
	active := reservation.state
	work := mustSelectedGeneratedWork(t, active)
	original := work.attempts[work.phase.FrontierAttemptID]
	record, err := active.generatedRecordRequest(t.Context(), original.record.AttemptID,
		generatedPublicResultFixture(t, original, contract.GeneratorDispositionCompleteCreate), generatedContinuationContext(t, active, 170, 171))
	if err != nil {
		t.Fatal("first lineage success request", err)
	}
	recorded, err := active.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("first lineage success", err)
	}
	active = recorded.state
	work = mustSelectedGeneratedWork(t, active)
	second := work.attempts[work.phase.FrontierAttemptID]
	record, err = active.generatedRecordRequest(t.Context(), second.record.AttemptID,
		generatedPublicResultFixtureWithRawToken(t, second, contract.GeneratorDispositionOwnedUnusableCreate, 0, generatedVectorID(98)),
		generatedContinuationContext(t, active, 172, 173))
	if err != nil {
		t.Fatal("second lineage owned unusable result request", err)
	}
	recorded, err = active.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("second lineage owned unusable result", err)
	}
	failedPlan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 174, 175))
	if err != nil || failedPlan.selecting || len(failedPlan.results) != 2 {
		t.Fatal("mixed terminal aggregate must admit nonselecting Final", err)
	}
	failed, err := recorded.state.deriveGeneratedFinal(t.Context(), failedPlan, nil)
	if err != nil || failed.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("mixed terminal aggregate Final", err)
	}
	before := failed.state
	prior := mustSelectedGeneratedWork(t, before)
	cleanup, err := contract.InspectGeneratedDutyRecord(prior.records[generatedRecordKey{contract.GeneratedDutySupportKind, original.record.OwnerID}].Body)
	if err != nil || cleanup.Kind != contract.GeneratedDutyUnselectedCleanup || cleanup.Status != contract.GeneratedEffectSucceeded {
		t.Fatal("real failed Final did not convert its succeeded create into cleanup", err)
	}
	selected := generatedFinalWithFreshToken(t, before, generatedVectorID(98), generatedVectorID(99), 180)
	closed := mustSelectedGeneratedWork(t, selected)
	if closed.parent != nil || closed.phase != nil || selected.root.Generated.GeneratedCurrent != 1 ||
		selected.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("successful Final did not preserve a valid selected closure")
	}
	for _, key := range []generatedRecordKey{
		{contract.OperationMaterialSupportKind, original.material.Core.OperationMaterialID},
		{contract.GeneratedResultSupportKind, original.record.ResultID},
		{contract.GeneratedAttemptSupportKind, original.record.AttemptID},
		{contract.GeneratedDutySupportKind, original.record.OwnerID},
	} {
		if !closed.hasRecord(key) || !bytes.Equal(prior.records[key].Body, closed.records[key].Body) {
			t.Fatal("successful Final changed unrelated cleanup", key.kind)
		}
	}
	accessBefore, ok := before.materialAccess(contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID)
	if !ok {
		t.Fatal("cleanup predecessor lost its material access")
	}
	accessAfter, ok := selected.materialAccess(contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID)
	if !ok {
		t.Fatal("successful Final lost unrelated cleanup access")
	}
	beforeBody, err := contract.EncodeAccessRecord(accessBefore)
	if err != nil {
		t.Fatal(err)
	}
	afterBody, err := contract.EncodeAccessRecord(accessAfter)
	if err != nil || !bytes.Equal(beforeBody, afterBody) {
		t.Fatal("successful Final changed unrelated cleanup wraps", err)
	}
}

// full_only: false
func TestGeneratedFinalAfterOwnedUnusablePreservesResidue(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal(err)
	}
	active := reservation.state
	original := mustSelectedGeneratedWork(t, active).attempts[mustSelectedGeneratedWork(t, active).phase.FrontierAttemptID]
	packet := generatedPublicResultFixture(t, original, contract.GeneratorDispositionOwnedUnusableCreate)
	record, err := active.generatedRecordRequest(t.Context(), original.record.AttemptID, packet,
		generatedContinuationContext(t, active, 180, 181))
	if err != nil {
		t.Fatal("owned unusable result request", err)
	}
	recorded, err := active.deriveGeneratedRecord(t.Context(), record)
	if err != nil {
		t.Fatal("owned unusable result selection", err)
	}
	failedPlan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 182, 183))
	if err != nil || failedPlan.selecting {
		t.Fatal("owned unusable result must close without canonical selection", err)
	}
	failed, err := recorded.state.deriveGeneratedFinal(t.Context(), failedPlan, nil)
	if err != nil {
		t.Fatal("owned unusable Final", err)
	}
	before := failed.state
	prior := mustSelectedGeneratedWork(t, before)
	selected := generatedFinalWithFreshToken(t, before, generatedVectorID(98), generatedVectorID(99), 184)
	closed := mustSelectedGeneratedWork(t, selected)
	if closed.parent != nil || closed.phase != nil || selected.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("Final retained the active parent or selected no current value")
	}
	for _, key := range []generatedRecordKey{
		{contract.OperationMaterialSupportKind, original.material.Core.OperationMaterialID},
		{contract.GeneratedResultSupportKind, original.record.ResultID},
		{contract.GeneratedAttemptSupportKind, original.record.AttemptID},
		{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID},
	} {
		if !closed.hasRecord(key) || !bytes.Equal(prior.records[key].Body, closed.records[key].Body) {
			t.Fatal("successful frontier changed earlier owned unusable residue", key.kind)
		}
	}
	accessBefore, ok := before.materialAccess(contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID)
	if !ok {
		t.Fatal("owned unusable predecessor lost seed access")
	}
	accessAfter, ok := selected.materialAccess(contract.OperationSeedMaterialKind, original.material.Core.OperationMaterialID)
	if !ok {
		t.Fatal("successful frontier lost earlier owned unusable seed access")
	}
	beforeBody, err := contract.EncodeAccessRecord(accessBefore)
	if err != nil {
		t.Fatal(err)
	}
	afterBody, err := contract.EncodeAccessRecord(accessAfter)
	if err != nil || !bytes.Equal(beforeBody, afterBody) {
		t.Fatal("successful frontier changed earlier owned unusable wraps", err)
	}
}
