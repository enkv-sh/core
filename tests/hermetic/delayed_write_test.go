package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestDelayedCASChecksConditionAtDelivery(t *testing.T) {
	for _, delayedFirst := range []bool{false, true} {
		name := "competitor-first"
		if delayedFirst {
			name = "delayed-first"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 32, true, 1)
			old := fixtureStateImage(t, f)
			other, r := Open(context.Background(), f.admission, f.store)
			if other == nil {
				t.Fatal(r)
			}
			firstInput := mixedLifecycleInput(old)
			c, r := f.session.Compare(context.Background(), firstInput, admitSuppliedComparison(t, f.session, nil, firstInput))
			if c == nil {
				t.Fatal(r)
			}
			permit := admit(t, f.session, c)
			firstWant := expectedSuccessorImage(t, old, firstInput, observeAllocatedTransitionInputs(permit))
			first, r := f.session.Prepare(context.Background(), c, permit, f.trust)
			if first == nil {
				t.Fatal(r)
			}
			secondInput := old.entryInputs()
			secondInput[1].InputBytes = []byte("second")
			secondInput = secondInput[:len(secondInput)-1]
			c, r = other.Compare(context.Background(), secondInput, admitSuppliedComparison(t, other, nil, secondInput))
			if c == nil {
				t.Fatal(r)
			}
			permit = admit(t, other, c)
			secondWant := expectedSuccessorImage(t, old, secondInput, observeAllocatedTransitionInputs(permit))
			second, r := other.Prepare(context.Background(), c, permit, f.trust)
			if second == nil {
				t.Fatal(r)
			}
			f.store.casMode = "delayed"
			unresolved := f.session.Select(context.Background(), first)
			if unresolved.Outcome != UnresolvedCommit || !unresolved.CommitMayHaveOccurred || unresolved.ObservedRevision != old.Revision || unresolved.RequestedRevision != firstWant.Revision || unresolved.Evidence != AuthenticatedClosure {
				t.Fatal(unresolved)
			}
			f.store.casMode = ""
			want, outcome := secondWant, ObservedCurrent
			if delayedFirst {
				if err := f.store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
				want, outcome = firstWant, Contention
			}
			if r := other.Select(context.Background(), second); r.Outcome != outcome || r.RequestedRevision != secondWant.Revision || r.CommitMayHaveOccurred {
				t.Fatal(r)
			}
			if !delayedFirst {
				if err := f.store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
			}
			s, r := Open(context.Background(), f.admission, f.store)
			if s == nil {
				t.Fatal(r)
			}
			assertStateImage(t, s, want)
			if f.store.cas != 4 || first.head.Core.PreviousToken != f.session.token || second.head.Core.PreviousToken != f.session.token {
				t.Fatal("delayed delivery changed the bounded send count or original precondition")
			}
			start := len(f.store.casConditions) - 4
			if start < 0 || len(f.store.casBodies) != len(f.store.casConditions) {
				t.Fatal("delayed Store call record incomplete")
			}
			for attempt := 0; attempt < 3; attempt++ {
				if f.store.casConditions[start+attempt] != f.session.token || !bytes.Equal(f.store.casBodies[start+attempt], first.body) {
					t.Fatalf("delayed retry %d changed original condition or frozen body", attempt)
				}
			}
			checkFreshProcess(t, f, want)
		})
	}
}

// full_only: false
func TestThreeWritersEveryDeliveryOrder(t *testing.T) {
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, mode := range []string{"disjoint-changes", "equal-desired-values"} {
		for _, order := range orders {
			t.Run(fmt.Sprintf("%s/%d-%d-%d", mode, order[0], order[1], order[2]), func(t *testing.T) {
				ctx := context.Background()
				f := newFixture(t, 32, true, 1)
				before := fixtureStateImage(t, f)
				oldHead := f.store.objects[f.store.desc.HeadKey]
				seen := historyIDs(before)
				var sessions [3]*StateSession
				var candidates [3]*Candidate
				var requests [3][]byte
				var stores [3]*recordingCASStore
				var expected [3]stateImage
				for writer := range sessions {
					store := &recordingCASStore{Store: f.store}
					session, result := Open(ctx, f.admission, store)
					if session == nil {
						t.Fatal(result)
					}
					input := mixedLifecycleInput(before)
					index, value := writer, fmt.Sprintf("writer %d", writer)
					if mode == "equal-desired-values" {
						index, value = 0, "same requested bytes"
					}
					input[index].InputBytes = []byte(value)
					if mode == "disjoint-changes" {
						input[len(input)-1].Name = fmt.Sprintf("writer-added-%d", writer)
					}
					comparison, result := session.Compare(context.Background(), input, admitSuppliedComparison(t, session, nil, input))
					if comparison == nil {
						t.Fatal(result)
					}
					permit := admit(t, session, comparison)
					inputs := observeAllocatedTransitionInputs(permit)
					assertFreshAllocatedIDs(t, seen, inputs)
					expected[writer] = expectedSuccessorImage(t, before, input, inputs)
					candidate, result := session.Prepare(ctx, comparison, permit, f.trust)
					if candidate == nil {
						t.Fatal(result)
					}
					sessions[writer], candidates[writer], stores[writer] = session, candidate, store
					requests[writer] = bytes.Clone(candidate.body)
					if session.token != oldHead.Token || candidate.head.Core.PreviousToken != oldHead.Token || candidate.head.Core.PreviousRevision != before.Revision || candidate.head.Core.PreviousDigest != contract.Hash(oldHead.Body) {
						t.Fatal("candidate did not freeze the exact common predecessor")
					}
				}
				selected := expected[order[0]]
				for delivery, writer := range order {
					reads, creates, signs := f.store.reads, f.store.creates, f.trust.signs
					want := Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: expected[writer].Revision, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure}
					if delivery == 0 {
						want.Outcome, want.Reason = ObservedCurrent, NoReason
						want.ObservedRevision, want.ObservedSnapshotID = selected.Revision, selected.Root.Snapshot
					}
					if result := sessions[writer].Select(ctx, candidates[writer]); result != want {
						t.Fatalf("delivery %d writer %d: %+v, want %+v", delivery, writer, result, want)
					}
					assertExactSelectionRequest(t, stores[writer], f.store.desc.HeadKey, oldHead.Token, requests[writer])
					if f.store.cas != delivery+1 || f.store.creates != creates || f.trust.signs != signs || sessions[writer].token != oldHead.Token || (delivery > 0 && f.store.reads != reads) {
						t.Fatal("writer retried, refreshed its predecessor, or prepared again")
					}
					reader, result := Open(ctx, f.admission, f.store)
					if reader == nil {
						t.Fatal(result)
					}
					assertStateImage(t, reader, selected)
				}
			})
		}
	}
}

// full_only: false
func TestDelayedCreateChecksAbsenceAtDelivery(t *testing.T) {
	for _, delayedFirst := range []bool{false, true} {
		name := "competitor-first"
		if delayedFirst {
			name = "delayed-first"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			ref := *f.session.root.ValueEntryPages[0]
			ref.Object = testID("delayed-create")
			key, err := format.Key(f.store.desc.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			f.store.createMode = "delayed"
			if r := f.store.Create(context.Background(), key, []byte("first")); r.Status != contract.WriteUnknown {
				t.Fatal(r)
			}
			f.store.createMode = ""
			want, status := []byte("second"), contract.WriteAcknowledged
			if delayedFirst {
				if err := f.store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
				want, status = []byte("first"), contract.WritePrecondition
			}
			if r := f.store.Create(context.Background(), key, []byte("second")); r.Status != status {
				t.Fatal(r)
			}
			if !delayedFirst {
				if err := f.store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
			}
			r := f.store.Read(context.Background(), key, 16)
			if r.Status != contract.ReadOK || !bytes.Equal(r.Body, want) || f.store.creates != 2 {
				t.Fatalf("delayed create replaced the first accepted bytes: %+v", r)
			}
		})
	}
}
