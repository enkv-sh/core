package core

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedStateHistories(t *testing.T) {
	seeds := []uint64{3, 11, 29, 47, 83, 131, 211, 347, 557, 907, 1451, 2333}
	for _, fragmented := range []bool{false, true} {
		placement := "compact"
		if fragmented {
			placement = "fragmented"
		}
		for _, seed := range seeds {
			t.Run(fmt.Sprintf("%s/seed-%d", placement, seed), func(t *testing.T) {
				ctx := context.Background()
				f := newFixture(t, 64, fragmented, 1)
				want := fixtureStateImage(t, f)
				history := []stateImage{want}
				seen := historyIDs(want)
				rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
				kinds := []string{"value-update", "no-op", "return-to-earlier-bytes", "stale-writer", "abandoned-preparation", "fresh-open", "add-member", "remove-member", "mixed-membership"}
				schedule := make([]string, 4*len(kinds))
				for i := range schedule {
					schedule[i] = kinds[i%len(kinds)]
				}
				// Start with a changed value before the seed-dependent action order.
				rng.Shuffle(len(schedule)-1, func(i, j int) { schedule[i+1], schedule[j+1] = schedule[j+1], schedule[i+1] })
				var trace []string
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("seed=%d placement=%s schedule=%v\nexecuted actions:\n%s", seed, placement, schedule, strings.Join(trace, "\n"))
					}
				})
				counts := make(map[string]int)
				for step, kind := range schedule {
					counts[kind]++
					before := want
					selectedHead := f.store.objects[f.store.desc.HeadKey]
					input := before.entryInputs()
					index := rng.IntN(len(input))
					trace = append(trace, fmt.Sprintf("%02d %s", step, kind))
					change := func(label string) {
						input[index].InputBytes = []byte(fmt.Sprintf("seed-%d/step-%d/%s", seed, step, label))
						trace[len(trace)-1] += fmt.Sprintf(" %s=%x", input[index].Name, input[index].InputBytes)
					}
					switch kind {
					case "add-member":
						added := input[0]
						added.Name, added.InputBytes = fmt.Sprintf("new-%d-%d", seed, step), []byte("added")
						input = append(input, added)
						want = selectHistoryUpdate(t, f, before, input, seen)
					case "remove-member":
						input = append(input[:index], input[index+1:]...)
						want = selectHistoryUpdate(t, f, before, input, seen)
					case "mixed-membership":
						change("retained-update")
						removed := (index + 1) % len(input)
						added := input[removed]
						added.Name, added.InputBytes = fmt.Sprintf("mixed-%d-%d", seed, step), nil
						input[removed] = added
						want = selectHistoryUpdate(t, f, before, input, seen)
					case "value-update":
						change("update")
						want = selectHistoryUpdate(t, f, before, input, seen)
					case "no-op":
						rng.Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
						reads, creates, cas, signs := f.store.reads, f.store.creates, f.store.cas, f.trust.signs
						comparison, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
						wantResult := Result{Outcome: Unchanged, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure}
						if comparison != nil || result != wantResult || f.session.prepared || f.store.reads-reads != 2*int(f.session.root.OutputConfiguration.SliceCount) || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
							t.Fatalf("no-op produced work or incorrect facts: %+v", result)
						}
					case "return-to-earlier-bytes":
						found := false
						for _, historyIndex := range rng.Perm(len(history)) {
							earlier := make(map[string][]byte)
							for _, value := range history[historyIndex].entryInputs() {
								earlier[value.Name] = value.InputBytes
							}
							for offset := range len(input) {
								slot := (index + offset) % len(input)
								prior, present := earlier[input[slot].Name]
								if !present || bytes.Equal(input[slot].InputBytes, prior) {
									continue
								}
								input[slot].InputBytes = bytes.Clone(prior)
								trace[len(trace)-1] += fmt.Sprintf(" prior-image=%d %s=%x", historyIndex, input[slot].Name, input[slot].InputBytes)
								found = true
								break
							}
							if found {
								break
							}
						}
						if !found {
							t.Fatal("generated return action has no distinct earlier bytes")
						}
						want = selectHistoryUpdate(t, f, before, input, seen)
					case "stale-writer":
						store := &recordingCASStore{Store: f.store}
						stale, result := Open(ctx, f.admission, store)
						if stale == nil {
							t.Fatal(result)
						}
						staleToken := stale.token
						change("stale")
						comparison, result := stale.Compare(context.Background(), input, admitSuppliedComparison(t, stale, nil, input))
						if comparison == nil {
							t.Fatal(result)
						}
						permit := admit(t, stale, comparison)
						assertFreshAllocatedIDs(t, seen, observeAllocatedTransitionInputs(permit))
						candidate, result := stale.Prepare(ctx, comparison, permit, f.trust)
						if candidate == nil {
							t.Fatal(result)
						}
						frozenBody := bytes.Clone(candidate.body)
						input = before.entryInputs()
						index = (index + 1) % len(input)
						change("winner")
						want = selectHistoryUpdate(t, f, before, input, seen)
						selectedHead = f.store.objects[f.store.desc.HeadKey]
						reads, creates, cas, signs := f.store.reads, f.store.creates, f.store.cas, f.trust.signs
						wantResult := Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: permit.plan.revision, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure}
						if result := stale.Select(ctx, candidate); result != wantResult {
							t.Fatalf("stale selection = %+v, want %+v", result, wantResult)
						}
						assertExactSelectionRequest(t, store, f.store.desc.HeadKey, staleToken, frozenBody)
						if f.store.reads != reads || f.store.creates != creates || f.store.cas != cas+1 || f.trust.signs != signs || stale.token != staleToken || candidate.head.Core.PreviousToken != staleToken {
							t.Fatal("stale writer retried, rebased, refreshed or prepared again")
						}
					case "abandoned-preparation":
						change("abandoned")
						input[(index+1)%len(input)].Name = fmt.Sprintf("abandoned-%d-%d", seed, step)
						comparison, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
						if comparison == nil {
							t.Fatal(result)
						}
						permit := admit(t, f.session, comparison)
						assertFreshAllocatedIDs(t, seen, observeAllocatedTransitionInputs(permit))
						cas := f.store.cas
						candidate, result := f.session.Prepare(ctx, comparison, permit, f.trust)
						wantResult := Result{Outcome: ObservedCurrent, RequestedRevision: permit.plan.revision, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure}
						if candidate == nil || result != wantResult || !permit.used || !f.session.prepared || f.store.cas != cas {
							t.Fatalf("abandoned preparation = %+v, want %+v", result, wantResult)
						}
					case "fresh-open":
						// The independent read and complete comparison below are the action.
					default:
						t.Fatalf("unknown generated action %q", kind)
					}
					if kind == "no-op" || kind == "stale-writer" || kind == "abandoned-preparation" || kind == "fresh-open" {
						after := f.store.objects[f.store.desc.HeadKey]
						if after.Token != selectedHead.Token || !bytes.Equal(after.Body, selectedHead.Body) {
							t.Fatal("non-selecting action changed HEAD from immediately before the attempt")
						}
					}
					creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
					reader, result := Open(ctx, f.admission, f.store)
					wantResult := Result{Outcome: ObservedCurrent, ObservedRevision: want.Revision, ObservedSnapshotID: want.Root.Snapshot, Evidence: AuthenticatedClosure}
					if reader == nil || result != wantResult || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
						t.Fatalf("fresh read = %+v, want %+v", result, wantResult)
					}
					assertStateImage(t, reader, want)
					f.session = reader
					history = append(history, want)
				}
				for _, kind := range kinds {
					if counts[kind] != 4 {
						t.Fatalf("action %s executed %d times, want 4", kind, counts[kind])
					}
				}
			})
		}
	}
}

func selectHistoryUpdate(t *testing.T, f *fixture, before stateImage, input []ApplyEntryInput, seen map[contract.ID]bool) stateImage {
	t.Helper()
	comparison, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
	if comparison == nil {
		t.Fatal(result)
	}
	permit := admit(t, f.session, comparison)
	inputs := observeAllocatedTransitionInputs(permit)
	assertFreshAllocatedIDs(t, seen, inputs)
	want := expectedSuccessorImage(t, before, input, inputs)
	candidate, result := f.session.Prepare(context.Background(), comparison, permit, f.trust)
	wantResult := Result{Outcome: ObservedCurrent, RequestedRevision: want.Revision, ObservedRevision: before.Revision, ObservedSnapshotID: before.Root.Snapshot, Evidence: AuthenticatedClosure}
	if candidate == nil || result != wantResult {
		t.Fatalf("Prepare = %+v, want %+v", result, wantResult)
	}
	wantResult.ObservedRevision, wantResult.ObservedSnapshotID = want.Revision, want.Root.Snapshot
	if result := f.session.Select(context.Background(), candidate); result != wantResult {
		t.Fatalf("Select = %+v, want %+v", result, wantResult)
	}
	return want
}
