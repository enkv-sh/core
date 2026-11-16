package core

import (
	"context"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestEndWorkWarnsForRetainedDeletePermissionBeforeProviderEntry(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	env.Context = ctx
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	profile := defaultGeneratedFixtureProfile()
	selected := selectPrivateGeneratedOperation(t, env, f.session,
		generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"generated"}, profile), "initial retirement target")
	old := *selected.valueEntry(0)
	selected = selectPrivateGeneratedOperation(t, env, selected,
		generatedStatePlanInput(t, selected, generatedVectorID(231), []string{old.Name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "rotation before delete permission")
	work := mustSelectedGeneratedWork(t, selected)
	duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{
		contract.GeneratedDutySupportKind, selected.valueEntry(0).Generated.RetiringDutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	target, err := work.retirementTarget(ctx, duty)
	if err != nil {
		t.Fatal(err)
	}
	input, canonical := generatedDeletePlanInput(t, selected, generatedVectorID(233), duty, target, 2)
	reservation, _ := preparePrivateGeneratedReservation(t, env, selected, input, canonical)
	var calls atomic.Int32
	producer, expected := preparePrivateGeneratedProducer(t, env, selected, reservation, func() { calls.Add(1) })
	var accepted contract.ID
	if expected.Template.Action != contract.GeneratorActionDelete ||
		!producer.reservation.candidate.bindFirstSend(producer, func(_ context.Context, authority contract.ID) contract.CryptoResultCode {
			accepted = authority
			return contract.CryptoSuccess
		}) {
		t.Fatal("no retained original delete permission")
	}
	before, result := selected.selectCandidate(ctx, producer.reservation.candidate)
	if before == nil || result.Outcome != ObservedCurrent || accepted.IsZero() || calls.Load() != 0 {
		t.Fatal("delete reservation did not select without provider entry", result, calls.Load())
	}
	before = generatedLifecycleReopen(t, ctx, before, env.Store)
	work = mustSelectedGeneratedWork(t, before)
	attempt := work.attempts[expected.Template.AttemptID]
	if work.parent == nil || attempt.record.State != contract.GeneratedEffectTransmitted || len(attempt.result) != 0 {
		t.Fatal("selected permission lost its conservative effect state")
	}
	warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningPossibleStoreGarbage
	after := endGeneratedObligation(t, ctx, env, before, work.parent.OperationID,
		[]contract.ID{work.parent.OperationID}, before.currentEntryInputs(), warning)
	if calls.Load() != 0 || after.root.WarningBits&WarningLateDestructiveEffect == 0 {
		t.Fatal("local exit changed provider entry or omitted retained delete exposure", calls.Load())
	}
}
