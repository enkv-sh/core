package core

import (
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestGCRuntimePendingAllowanceSurvivesSigningSuccessionAndReconstruction(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newConsumerLoadingFixture(t, ctx, false)
	f.env = syntheticAuthorityScenarioEnvironment(t, f.env)
	before := f.f.session
	stale, _ := prepareConsumerLoadingSuccessor(t, ctx, f)
	key := gcInterleavingCandidateKey(t, f.store.desc, stale, contract.ValueEntryPageKind)
	store := newGCInterleavingStore(f.store)
	t.Cleanup(func() {
		t.Logf("runtime succession GC inventory: deletes=%d creates=%d cas=%d phases=%v", len(store.deleteCalls), store.creates, store.cas, store.phases)
	})
	plan, encoded := gcInterleavingPreview(t, ctx, before, store, []string{key}, "runtime succession")
	if len(plan.Targets) != 1 {
		t.Fatal("runtime succession did not prepare exactly one obsolete target")
	}
	store.delete = func(context.Context, string, contract.Token) *contract.WriteResult {
		return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	engine := gcInterleavingEngine(t, before, store, []string{key}, f.env.Trust)
	partial := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(f.env.Domain, "runtime succession apply"), EncodedPlan: encoded})
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if partial.Validate() != nil || partial.StateResult != "gc-partial-garbage" || partial.Payload == nil || !partial.Payload.Closed || len(store.deleteCalls) != 1 {
		t.Fatal("runtime succession did not retain a transmitted unknown", partial.Result)
	}
	current := gcInterleavingCurrent(t, ctx, f.f.admission, store)
	originalPlan, originalProgress, err := current.selectedGCPlan(plan.OperationID)
	if err != nil || !reflect.DeepEqual(originalPlan, plan) || originalProgress.Targets[0].Consumed != 1 || originalProgress.Targets[0].Disposition != contract.GCTargetUnknown {
		t.Fatal("runtime succession lost the original vector or consumed allowance", err)
	}
	actors := f.env.ReplacementActors(t, ctx, current, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
	permit := admitAuthorityReplacement(t, current, actors.Keys, actors.After, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, actors.Source)
	candidate, result := current.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil {
		t.Fatal("pending runtime GC signing replacement", result)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if result := current.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("pending runtime GC signing replacement selection", result)
	}
	changed := gcInterleavingCurrent(t, ctx, admission, store)
	actors.Activate(t, changed)
	f.env.Trust = &fixtureTrust{Signer: actors.Signers.NormalSuccessor.(*testtrust.Signer)}
	retainedPlan, retainedProgress, err := changed.selectedGCPlan(plan.OperationID)
	if err != nil || !reflect.DeepEqual(retainedPlan, originalPlan) || !contract.GCProgressEqual(retainedProgress, originalProgress) ||
		!reflect.DeepEqual(changed.pages, current.pages) || !reflect.DeepEqual(changed.root.Generated, current.root.Generated) || changed.root.ActiveGC != current.root.ActiveGC || len(store.deleteCalls) != 1 {
		t.Fatal("signing replacement changed pending GC authority or application bytes", err)
	}
	projection := reconstructProjectionFixture(t, f.env, changed, f.store)
	assertReconstructionProjectionExact(t, projection, changed, f.store)
	returned := reconstructionReturnedSession(t, projection, changed)
	projectedPlan, projectedProgress, err := returned.selectedGCPlan(plan.OperationID)
	if err != nil || !reflect.DeepEqual(projectedPlan, originalPlan) || !contract.GCProgressEqual(projectedProgress, originalProgress) || len(store.deleteCalls) != 1 {
		t.Fatal("reconstruction changed the original runtime GC obligation", err)
	}
	projection.Close()
	// A matching GET after a transmitted unknown cannot issue a new allowance.
	resumer := gcInterleavingEngine(t, changed, store, []string{key}, f.env.Trust)
	resumed := resumer.Continue(ctx, GCContinueRequest{RequestNonce: fixtureID(f.env.Domain, "runtime successor continuation"), OperationID: plan.OperationID})
	if err := resumer.Close(); err != nil {
		t.Fatal(err)
	}
	if resumed.Validate() != nil || resumed.StateResult != "gc-partial-garbage" || resumed.Payload == nil || resumed.Payload.Targets[0].Selected.Consumed != 1 || len(store.deleteCalls) != 1 ||
		contract.Hash(store.objects[key].Body) != plan.Targets[0].Digest {
		t.Fatal("successor continuation restored a consumed runtime allowance", resumed.Result)
	}
	t.Logf("runtime GC succession: original_delete_joined=1 successor_selected=1 projection_complete=1 continuation_deletes=0 consumed=1")
}
