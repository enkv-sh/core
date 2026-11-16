package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestThreeGenerationHistoryAndStaleCandidate(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 32, false, 1)
	original := fixtureStateImage(t, f)
	originalValues := original.entryInputs()
	originalToken := f.session.token

	// Retain a fully prepared candidate from the first A in a separate session.
	staleSession, r := Open(ctx, f.admission, f.store)
	initialResult := Result{Outcome: ObservedCurrent, ObservedRevision: original.Revision, ObservedSnapshotID: original.Root.Snapshot, Evidence: AuthenticatedClosure}
	if staleSession == nil || r != initialResult {
		t.Fatalf("open retained session: %+v", r)
	}
	staleInput := original.entryInputs()
	staleInput[0].InputBytes, staleInput[16].InputBytes = []byte("B"), []byte("B")
	staleComparison, r := staleSession.Compare(context.Background(), staleInput, admitSuppliedComparison(t, staleSession, nil, staleInput))
	if staleComparison == nil || r != initialResult {
		t.Fatalf("compare retained candidate: %+v", r)
	}
	stalePermit := admit(t, staleSession, staleComparison)
	staleCandidate, r := staleSession.Prepare(ctx, staleComparison, stalePermit, f.trust)
	stalePreparationResult := initialResult
	stalePreparationResult.RequestedRevision = stalePermit.plan.revision
	if staleCandidate == nil || r != stalePreparationResult {
		t.Fatalf("prepare retained candidate: %+v", r)
	}

	seen := historyIDs(original)
	assertFreshIDs := func(permit *AdmittedParentTransition) {
		assertFreshAllocatedIDs(t, seen, observeAllocatedTransitionInputs(permit))
	}
	assertFreshIDs(stalePermit)

	want := original
	for step := 0; step < 3; step++ {
		requested := want.entryInputs()
		switch step {
		case 0:
			requested[0].InputBytes, requested[16].InputBytes = []byte("B"), []byte("B")
		case 1:
			requested[1].InputBytes = []byte("second generation")
		case 2:
			requested[0].InputBytes, requested[16].InputBytes = originalValues[0].InputBytes, originalValues[16].InputBytes
		}
		// A complete desired image has no caller-selected ordering.
		slices.Reverse(requested)
		previous := want
		observed := Result{Outcome: ObservedCurrent, ObservedRevision: previous.Revision, ObservedSnapshotID: previous.Root.Snapshot, Evidence: AuthenticatedClosure}
		comparison, r := f.session.Compare(context.Background(), requested, admitSuppliedComparison(t, f.session, nil, requested))
		if comparison == nil || r != observed {
			t.Fatalf("step %d compare: %+v", step, r)
		}
		permit := admit(t, f.session, comparison)
		assertFreshIDs(permit)
		want = expectedSuccessorImage(t, previous, requested, observeAllocatedTransitionInputs(permit))
		candidate, r := f.session.Prepare(ctx, comparison, permit, f.trust)
		observed.RequestedRevision = want.Revision
		if candidate == nil || r != observed {
			t.Fatalf("step %d prepare: %+v", step, r)
		}
		observed.ObservedRevision, observed.ObservedSnapshotID = want.Revision, want.Root.Snapshot
		if r := f.session.Select(ctx, candidate); r != observed {
			t.Fatalf("step %d select: %+v", step, r)
		}

		// Fixture pruning tests independence from history; it is not Product GC.
		removeUnselectedFixtureObjects(t, f, previous, want)
		checkFreshProcess(t, f, want)
		f.session, r = Open(ctx, f.admission, f.store)
		observed.RequestedRevision = contract.ID{}
		if f.session == nil || r != observed {
			t.Fatalf("step %d fresh open: %+v", step, r)
		}
		assertStateImage(t, f.session, want)

		reads, creates, cas, signs := f.store.reads, f.store.creates, f.store.cas, f.trust.signs
		comparison, r = f.session.Compare(context.Background(), requested, admitSuppliedComparison(t, f.session, nil, requested))
		observed.Outcome = Unchanged
		if comparison != nil || r != observed {
			t.Fatalf("step %d no-op: %+v", step, r)
		}
		if f.store.reads-reads != 2*int(f.session.root.OutputConfiguration.SliceCount) || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || f.session.prepared {
			t.Fatalf("step %d no-op mutated state or read outside its configuration", step)
		}
		assertStateImage(t, f.session, want)
	}
	for _, slot := range []uint16{0, 16} {
		before := original.Pages[slot/format.PageSlots].Slots[slot%format.PageSlots]
		after := want.Pages[slot/format.PageSlots].Slots[slot%format.PageSlots]
		if !bytes.Equal(after.ValueBytes, before.ValueBytes) || after.ValueState == before.ValueState || after.OriginSnapshot == before.OriginSnapshot || after.OriginTransition == before.OriginTransition {
			t.Fatal("return to equal value bytes reused historical identity or origins")
		}
	}

	reads, creates, cas, signs := f.store.reads, f.store.creates, f.store.cas, f.trust.signs
	selectedHead := f.store.objects[f.store.desc.HeadKey]
	if staleSession.token != originalToken || staleCandidate.head.Core.PreviousToken != originalToken {
		t.Fatal("retained candidate lost its original predecessor token")
	}
	wantStaleResult := Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: stalePermit.plan.revision, ObservedRevision: original.Revision, ObservedSnapshotID: original.Root.Snapshot, Evidence: AuthenticatedClosure}
	if r := staleSession.Select(ctx, staleCandidate); r != wantStaleResult {
		t.Fatalf("select retained candidate: %+v", r)
	}
	if f.store.cas != cas+1 || f.store.reads != reads || f.store.creates != creates || f.trust.signs != signs || staleSession.token != originalToken {
		t.Fatal("stale selection refreshed its token, rebased, retried, or prepared again")
	}
	currentHead := f.store.objects[f.store.desc.HeadKey]
	if selectedHead.Token != currentHead.Token || !bytes.Equal(selectedHead.Body, currentHead.Body) {
		t.Fatal("stale candidate changed the selected HEAD")
	}
	checkFreshProcess(t, f, want)
}

// full_only: false
func TestSelectedRemovalReaddRejectsStaleAndDelayedCandidates(t *testing.T) {
	for _, mode := range []string{"prepared", "delayed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, 1, false, 1)
			before := fixtureStateImage(t, f)
			seen := historyIDs(before)
			oldToken := f.session.token
			staleStore := &recordingCASStore{Store: f.store}
			stale, result := Open(ctx, f.admission, staleStore)
			if stale == nil {
				t.Fatal(result)
			}
			staleInput := before.entryInputs()
			staleInput[0].InputBytes = []byte("stale update")
			comparison, result := stale.Compare(context.Background(), staleInput, admitSuppliedComparison(t, stale, nil, staleInput))
			if comparison == nil {
				t.Fatal(result)
			}
			permit := admit(t, stale, comparison)
			assertFreshAllocatedIDs(t, seen, observeAllocatedTransitionInputs(permit))
			candidate, result := stale.Prepare(ctx, comparison, permit, f.trust)
			if candidate == nil {
				t.Fatal(result)
			}
			frozen := bytes.Clone(candidate.body)
			if mode == "delayed" {
				priorCAS := len(f.store.casConditions)
				f.store.casMode = "delayed"
				want := Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: permit.plan.revision, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure, CommitMayHaveOccurred: true, StoreReason: contract.ReasonTransport}
				if result := stale.Select(ctx, candidate); result != want {
					t.Fatalf("delayed selection = %+v, want %+v", result, want)
				}
				if staleStore.calls != 3 || len(f.store.casConditions) != priorCAS+3 {
					t.Fatal("delayed selection exceeded its bounded retry count")
				}
				for send := priorCAS; send < priorCAS+3; send++ {
					if f.store.casConditions[send] != oldToken || !bytes.Equal(f.store.casBodies[send], frozen) {
						t.Fatal("delayed selection changed its original condition or body")
					}
				}
				f.store.casMode = ""
			}
			empty := selectHistoryUpdate(t, f, before, nil, seen)
			removeUnselectedFixtureObjects(t, f, before, empty)
			checkFreshProcess(t, f, empty)
			f.session, result = Open(ctx, f.admission, f.store)
			if f.session == nil {
				t.Fatal(result)
			}
			readded := selectHistoryUpdate(t, f, empty, before.entryInputs(), seen)
			removeUnselectedFixtureObjects(t, f, empty, readded)
			oldEntry, newEntry := before.Pages[0].Slots[0], readded.Pages[0].Slots[0]
			if oldEntry.Incarnation == newEntry.Incarnation || oldEntry.ValueState == newEntry.ValueState || !bytes.Equal(oldEntry.ValueBytes, newEntry.ValueBytes) {
				t.Fatal("re-add reused the removed incarnation or value identity")
			}
			selected := f.store.objects[f.store.desc.HeadKey]
			reads, creates, cas, signs := f.store.reads, f.store.creates, f.store.cas, f.trust.signs
			if mode == "delayed" {
				if err := f.store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
			} else {
				want := Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: permit.plan.revision, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure}
				if result := stale.Select(ctx, candidate); result != want {
					t.Fatalf("stale selection = %+v, want %+v", result, want)
				}
				cas++
			}
			if mode != "delayed" {
				assertExactSelectionRequest(t, staleStore, f.store.desc.HeadKey, oldToken, frozen)
			}
			after := f.store.objects[f.store.desc.HeadKey]
			if after.Token != selected.Token || !bytes.Equal(after.Body, selected.Body) || stale.token != oldToken || f.store.reads != reads || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
				t.Fatal("old candidate changed the re-added selection, refreshed its token, or resumed preparation")
			}
			checkFreshProcess(t, f, readded)
		})
	}
}
