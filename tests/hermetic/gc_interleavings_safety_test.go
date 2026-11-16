package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func gcInterleavingCurrent(t *testing.T, ctx context.Context, admitted OpenContext, store contract.Store) *StateSession {
	t.Helper()
	current, result := Open(ctx, admitted, store)
	if current == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure {
		t.Fatal("GC interleaving current closure", result)
	}
	return current
}

func gcInterleavingCandidateKey(t *testing.T, store contract.Descriptor, candidate *Candidate, kind contract.Kind) string {
	t.Helper()
	for _, object := range candidate.objects {
		if object.ref.Kind == kind {
			return mustKey(t, store.Prefix, object.ref)
		}
	}
	t.Fatal("GC interleaving candidate has no requested physical page", kind)
	return ""
}

// full_only: false
func TestGCDeferredDeleteCannotAdoptOldCandidateAfterCloseOrAbandon(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		name := "partial_close"
		if abandon {
			name = "administrative_ending"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, contract.AWS, false)
			env.Context = ctx
			store := newGCInterleavingStore(env.Store.(*memoryStore))
			env.Store = store
			f := newEnvironmentFixture(t, ctx, env, []int{3}, false)
			original := f.session
			input := original.currentEntryInputs()
			input[0].InputBytes = []byte("old prepared candidate")
			comparison, result := original.Compare(ctx, input, admitSuppliedComparison(t, original, nil, input))
			if comparison == nil {
				t.Fatal("old GC-raced comparison", result)
			}
			stale, result := original.Prepare(ctx, comparison, admit(t, original, comparison), env.Trust)
			if stale == nil {
				t.Fatal("old GC-raced preparation", result)
			}
			targetKey := gcInterleavingCandidateKey(t, store.Descriptor(), stale, contract.ValueEntryPageKind)
			keys := []string{targetKey}
			plan, encoded := gcInterleavingPreview(t, ctx, original, store, keys, "old candidate "+name)
			if len(plan.Targets) != 1 {
				t.Fatal("old candidate page was not the exact eligible vector")
			}
			store.mu.Lock()
			object := store.objects[targetKey]
			body := bytes.Clone(object.Body)
			store.mu.Unlock()
			entered, completed := 0, 0
			var late func() contract.WriteResult
			store.delete = func(_ context.Context, key string, token contract.Token) *contract.WriteResult {
				entered++
				if entered != 1 || key != targetKey || token != object.Token {
					t.Fatal("deferred GC request changed its exact original condition")
				}
				late = func() contract.WriteResult {
					completed++
					return store.deleteExact(key, token)
				}
				return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			}
			engine := gcInterleavingEngine(t, original, store, keys, env.Trust)
			cleaned := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(env.Domain, name+" apply"), EncodedPlan: encoded})
			if err := engine.Close(); err != nil {
				t.Fatal("deferred GC invocation did not join", err)
			}
			if cleaned.Validate() != nil || cleaned.StateResult != "gc-partial-garbage" || cleaned.Payload == nil ||
				!cleaned.Payload.Closed || cleaned.Payload.Active || cleaned.Payload.RemainingCount != 1 ||
				cleaned.Payload.Targets[0].Selected.Consumed != 1 || cleaned.Payload.Targets[0].Selected.Disposition != contract.GCTargetUnknown || entered != 1 || completed != 0 {
				t.Fatal("deferred delete did not close with its exact unresolved obligation", cleaned.Result)
			}
			current := gcInterleavingCurrent(t, ctx, f.admission, store)
			_, progress, err := current.selectedGCPlan(plan.OperationID)
			if err != nil {
				t.Fatal("deferred GC lost selected progress", err)
			}
			// A fresh page cannot reset the retained obligation or its budget.
			fresh, empty := gcInterleavingPreview(t, ctx, current, store, keys, "pending exclusion "+name)
			if len(fresh.Targets) != 0 || len(fresh.Candidates) != 1 || fresh.Candidates[0].Classification != contract.GCCandidateAlreadyPending {
				t.Fatal("pending GC target became a new allowance")
			}
			beforeCAS, signs := store.cas, env.Trust.(*fixtureTrust).signs
			noopEngine := gcInterleavingEngine(t, current, store, keys, env.Trust)
			noop := noopEngine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(env.Domain, name+" pending noop"), EncodedPlan: empty})
			if err := noopEngine.Close(); err != nil {
				t.Fatal(err)
			}
			if noop.Validate() != nil || noop.StateResult != "no-op" || store.cas != beforeCAS || env.Trust.(*fixtureTrust).signs != signs || len(store.deleteCalls) != 1 {
				t.Fatal("pending exclusion created state or effect rights", noop.Result)
			}
			if abandon {
				ending, prepared := prepareTestEndSelectedWork(t, current, ctx, plan.OperationID, env.Trust)
				if ending == nil || prepared.Outcome != ObservedCurrent {
					t.Fatal("deferred GC exact ending", prepared)
				}
				current, result = current.selectObserved(ctx, ending)
				if current == nil || result.Outcome != ObservedCurrent || current.root.WarningBits&(WarningDiscardedExactEvidence|WarningPossibleStoreGarbage) != WarningDiscardedExactEvidence|WarningPossibleStoreGarbage {
					t.Fatal("deferred GC ending did not select its permanent warning", result)
				}
				current = gcInterleavingCurrent(t, ctx, f.admission, store)
			}
			staleResult := original.Select(ctx, stale)
			if staleResult.Outcome != Contention || staleResult.Reason != StalePrecondition || staleResult.CommitMayHaveOccurred {
				t.Fatal("old prepared candidate adopted after maintenance ended", staleResult)
			}
			input = current.currentEntryInputs()
			input[0].InputBytes = []byte("fresh selected value")
			comparison, result = current.Compare(ctx, input, admitSuppliedComparison(t, current, nil, input))
			if comparison == nil {
				t.Fatal("fresh post-GC comparison", result)
			}
			freshCandidate, result := current.Prepare(ctx, comparison, admit(t, current, comparison), env.Trust)
			if freshCandidate == nil {
				t.Fatal("fresh post-GC preparation", result)
			}
			if gcInterleavingCandidateKey(t, store.Descriptor(), freshCandidate, contract.ValueEntryPageKind) == targetKey {
				t.Fatal("fresh writer reused a permanently obsolete physical page")
			}
			current, result = current.selectObserved(ctx, freshCandidate)
			if current == nil || result.Outcome != ObservedCurrent {
				t.Fatal("fresh post-GC selection", result)
			}
			beforeLate := bytes.Clone(current.body)
			// S3 can recreate the same bytes with the same strong ETag. The
			// original condition is therefore not an incarnation fence.
			store.mu.Lock()
			delete(store.objects, targetKey)
			store.objects[targetKey] = stored{Body: bytes.Clone(body), Token: object.Token}
			store.mu.Unlock()
			if late == nil || late().Status != contract.WriteAcknowledged || completed != 1 {
				t.Fatal("deferred exact delete did not complete and join")
			}
			current = gcInterleavingCurrent(t, ctx, f.admission, store)
			if !bytes.Equal(current.body, beforeLate) || !bytes.Equal(current.valueEntry(0).ValueBytes, input[0].InputBytes) || len(store.deleteCalls) != 1 {
				t.Fatal("late GC delete reached a fresh selected object")
			}
			if !abandon {
				_, retained, err := current.selectedGCPlan(plan.OperationID)
				if err != nil || !contract.GCProgressEqual(progress, retained) {
					t.Fatal("late completion silently changed selected uncertainty", err)
				}
			}
			resumer := gcInterleavingEngine(t, current, store, keys, env.Trust)
			resumed := resumer.Continue(ctx, GCContinueRequest{RequestNonce: fixtureID(env.Domain, name+" resume"), OperationID: plan.OperationID})
			if err := resumer.Close(); err != nil {
				t.Fatal(err)
			}
			if len(store.deleteCalls) != 1 || !abandon && (resumed.StateResult != "success" || resumed.Validate() != nil) || abandon && resumed.StateResult == "success" {
				t.Fatal("continuation replayed a permission or invented historical success", resumed.Result)
			}
		})
	}
}

// full_only: false
func TestGCObsoleteGeneratedCandidateCannotInstallAfterClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	env.Context = ctx
	store := newGCInterleavingStore(env.Store.(*memoryStore))
	env.Store = store
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	input := generatedPlanInputForGenerations(t, f.session, fixtureID(env.Domain, "stale generated request"), []string{"generated"}, defaultGeneratedFixtureProfile())
	prepared, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
	defer keys.RetireGenerated()
	stale := prepared.reservation.candidate
	target := gcInterleavingCandidateKey(t, store.Descriptor(), stale, contract.RequiredSupportKind)
	plan, encoded := gcInterleavingPreview(t, ctx, f.session, store, []string{target}, "stale generated candidate")
	if len(plan.Targets) != 1 {
		t.Fatal("unselected generated support was not the exact GC vector")
	}
	engine := gcInterleavingEngine(t, f.session, store, []string{target}, env.Trust)
	cleaned := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(env.Domain, "generated GC apply"), EncodedPlan: encoded})
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if cleaned.Validate() != nil || cleaned.StateResult != "success" || len(store.deleteCalls) != 1 {
		t.Fatal("unselected generated page was not reclaimed exactly", cleaned.Result)
	}
	public, private := keys.Calls()
	result := f.session.Select(ctx, stale)
	if result.Outcome != Contention || result.Reason != StalePrecondition {
		t.Fatal("stale generated candidate regained selection", result)
	}
	if afterPublic, afterPrivate := keys.Calls(); afterPublic != public || afterPrivate != private {
		t.Fatal("stale generated selection entered private work")
	}
	current := gcInterleavingCurrent(t, ctx, f.admission, store)
	if !current.root.Generated.ActiveOwner.IsZero() || current.root.Generated.Attempts != 0 || !reflect.DeepEqual(current.currentEntryInputs(), f.session.currentEntryInputs()) {
		t.Fatal("stale generated selection changed current application or work")
	}
}
