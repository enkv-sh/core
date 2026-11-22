package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCDefersGeneratedLifecycleWritesUntilClose(t *testing.T) {
	t.Run("retirement-risk", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "unknown")
		duty := current.Generated.RetiringDutyID
		engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
		parked := engine.RetireGenerated(ctx, testID("park retirement before GC"), GeneratedRetirementRequest{DutyID: duty})
		engine.Close()
		if parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" {
			t.Fatal("expected a parked retirement", parked.Result)
		}
		cold := f.open(t, ctx)
		attempts := mustSelectedGeneratedWork(t, cold).attempts
		if len(attempts) != 1 {
			t.Fatal("expected one original attempt")
		}
		request := GeneratedRetirementRiskRequest{DutyID: duty}
		for id := range attempts {
			request.AttemptID = id
		}
		got := checkGCLifecycleAfterClose(t, ctx, f.env, cold, func(s *StateSession, id contract.ID) PublicApplyResult {
			e := installedGeneratedRetirementEngine(t, ctx, f, s, nil)
			defer e.Close()
			return e.AcceptGeneratedRetirementRisk(ctx, id, request)
		})
		creates, deletes := effects()
		if got.Generated == nil || got.Generated.StateResult != "possible-live-residue-accepted" || len(got.Receipt) == 0 ||
			!got.Generated.Warnings.PossibleLiveResidue || creates != 2 || len(deletes) != 1 {
			t.Fatal("risk acceptance lost uncertainty or repeated a provider effect")
		}
	})
	t.Run("late-original", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		env, selected, original, packet := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
		key, err := format.GeneratedResultKey(env.Store.Descriptor().Prefix, original.record.DomainID, original.record.InboxID)
		if err != nil {
			t.Fatal(err)
		}
		requireAdmittedMemoryStore(t, env.Store).put(key, bytes.Clone(packet))
		got := checkGCLifecycleAfterClose(t, ctx, env, selected, func(s *StateSession, id contract.ID) PublicApplyResult {
			e := installedGeneratedCleanupTestEngine(t, env, s, installedGeneratedVerificationTestCallbacks(t, env))
			defer e.Close()
			return e.CleanupGenerated(ctx, id)
		})
		if got.Generated == nil || got.Generated.AcknowledgedCount != 1 || len(got.Generated.Effects) != 1 ||
			got.Generated.Effects[0].Record.AttemptID != original.record.AttemptID || len(got.Receipt) != 0 {
			t.Fatal("late reflection lost the acknowledged original")
		}
	})
}

// full_only: false
func TestControlledRetirementCompletesAfterPreservingGC(t *testing.T) {
	checkControlledRetirementCompletion(t, func(t *testing.T, env fixtureEnvironment, parked *StateSession) *StateSession {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		store := newGCInterleavingStore(requireAdmittedMemoryStore(t, env.Store))
		old, err := format.DecodeHead(store.casBodies[0])
		if err != nil {
			t.Fatal(err)
		}
		keys := []string{mustKey(t, store.desc.Prefix, old.Core.Root)}
		plan, encoded := gcInterleavingPreview(t, ctx, parked, store, keys, "GC after retirement acknowledgement")
		if len(plan.Targets) != 1 || plan.Targets[0].Object.ObjectID != old.Core.Root.Object {
			t.Fatal("expected one obsolete root")
		}
		gc := gcInterleavingEngine(t, parked, store, keys, env.Trust)
		result := gc.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(env.Domain, "collect before confirmation"), EncodedPlan: encoded})
		if err := gc.Close(); err != nil {
			t.Fatal(err)
		}
		if result.StateResult != "success" || result.Payload == nil || !result.Payload.Closed || len(store.deleteCalls) != 1 {
			t.Fatal("GC did not close", result.Result)
		}
		selected := retainedReaderColdOpen(t, parked, env.Store)
		if selected.root.Snapshot == parked.root.Snapshot || selected.adminIndex.SliceSnapshot != parked.adminIndex.SliceSnapshot ||
			selected.adminIndex.SliceSnapshot == selected.root.Snapshot || selected.root.Generated.Slices != parked.root.Generated.Slices ||
			selected.valueEntry(0).Generated.RetiringDutyID != parked.valueEntry(0).Generated.RetiringDutyID {
			t.Fatal("GC changed the retained slice directory or retirement duty")
		}
		return selected
	})
}

func checkGCLifecycleAfterClose(t *testing.T, ctx context.Context, env fixtureEnvironment, selected *StateSession, run func(*StateSession, contract.ID) PublicApplyResult) PublicApplyResult {
	t.Helper()
	store := newGCInterleavingStore(requireAdmittedMemoryStore(t, env.Store))
	source := retainedReaderColdOpen(t, selected, store)
	if len(store.casBodies) == 0 {
		t.Fatal("expected a previous signed root")
	}
	old, err := format.DecodeHead(store.casBodies[0])
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{mustKey(t, store.desc.Prefix, old.Core.Root)}
	plan, _ := gcInterleavingPreview(t, ctx, source, store, keys, "release GC before generated transition")
	if len(plan.Targets) != 1 || plan.Targets[0].Object.ObjectID != old.Core.Root.Object {
		t.Fatal("expected one obsolete root")
	}
	active := gcSelectPlanAndReopen(t, ctx, source, store, env.Trust, plan)
	_, before, err := active.selectedGCPlan(plan.OperationID)
	if err != nil || len(before.Targets) != 1 || before.Targets[0].Consumed != 0 {
		t.Fatal("expected an unspent GC target", err)
	}
	trust := env.Trust.(*fixtureTrust)
	signs, creates, cas := trust.signs, store.creates, store.cas
	refused := run(active, testID("request while GC is active"))
	current := retainedReaderColdOpen(t, active, store)
	_, after, err := current.selectedGCPlan(plan.OperationID)
	if err != nil || refused.Result.Outcome != AdmissionRefused || refused.Result.CommitMayHaveOccurred || len(refused.Receipt) != 0 ||
		!bytes.Equal(active.body, current.body) || active.token != current.token || !reflect.DeepEqual(before, after) ||
		signs != trust.signs || creates != store.creates || cas != store.cas || len(store.deleteCalls) != 0 {
		t.Fatal("occupied GC lost its predecessor, progress or effect rights", refused.Result, err)
	}
	collector := gcInterleavingEngine(t, current, store, keys, env.Trust)
	closed := collector.Continue(ctx, GCContinueRequest{RequestNonce: testID("continue selected GC"), OperationID: plan.OperationID})
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}
	if closed.StateResult != "success" || closed.Payload == nil || !closed.Payload.Closed || len(store.deleteCalls) != 1 {
		t.Fatal("original GC could not finish", closed.Result)
	}
	available := retainedReaderColdOpen(t, current, store)
	if !available.root.ActiveGC.IsZero() {
		t.Fatal("GC slot remained occupied")
	}
	result := run(available, testID("fresh request after GC closes"))
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("eligible action after GC", result.Result)
	}
	// The reverse order uses the generated successor as the next GC basis.
	successor := retainedReaderColdOpen(t, available, store)
	keys = []string{mustKey(t, store.desc.Prefix, available.head.Core.Root)}
	next, encoded := gcInterleavingPreview(t, ctx, successor, store, keys, "GC after generated transition")
	if len(next.Targets) != 1 || next.Targets[0].Object.ObjectID != available.head.Core.Root.Object ||
		next.HeadRevisionID != successor.head.Core.Revision || next.PredecessorToken != successor.token {
		t.Fatal("new GC plan lost the generated successor")
	}
	later := gcInterleavingEngine(t, successor, store, keys, env.Trust)
	collected := later.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: testID("collect after generated lifecycle"), EncodedPlan: encoded})
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
	if collected.StateResult != "success" || collected.Payload == nil || !collected.Payload.Closed || len(store.deleteCalls) != 2 {
		t.Fatal("GC after completed generated work", collected.Result)
	}
	return result
}
