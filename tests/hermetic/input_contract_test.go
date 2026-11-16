package core

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestCompleteInputRefusesInvalidIntent(t *testing.T) {
	for _, name := range []string{"duplicate-and-omitted", "recipient", "source", "encoding", "invalid-name", "over-limit-name"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 2, false, 1)
			before := fixtureStateImage(t, f)
			input := before.entryInputs()
			switch name {
			case "duplicate-and-omitted":
				input[1] = input[0]
			case "recipient":
				input[0].Recipients[0] = testID("changed recipient")
			case "source":
				input[0].ValueSource++
			case "encoding":
				input[0].ConfidentialityClass++
			case "invalid-name":
				input[0].Name = string([]byte{0xff})
			case "over-limit-name":
				input[0].Name = strings.Repeat("n", contract.CryptoMaxName+1)
			}
			reads := f.store.reads
			if c, r := f.session.Compare(context.Background(), input, nil); c != nil || r != (Result{Outcome: AdmissionRefused, Reason: InvalidIntent}) {
				t.Fatalf("invalid complete input: comparison=%v result=%+v", c, r)
			}
			if f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || f.session.prepared {
				t.Fatal("input refusal crossed a mutation boundary")
			}
			assertStateImage(t, f.session, before)
		})
	}
}

// full_only: false
func TestCompleteInputOrderAndByteSemantics(t *testing.T) {
	for _, name := range []string{"reordered-unchanged", "nil-is-empty", "empty-is-present", "binary-zero-and-non-utf8", "reordered-changed"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 2, false, 0)
			original := fixtureStateImage(t, f)
			input := original.entryInputs()
			changed := false
			switch name {
			case "reordered-unchanged":
				slices.Reverse(input)
			case "nil-is-empty":
				input[0].InputBytes = nil
				input[1].InputBytes = []byte{}
			case "empty-is-present":
				input[0].InputBytes = []byte{}
				input[1].InputBytes = []byte{1}
				changed = true
			case "binary-zero-and-non-utf8":
				input[0].InputBytes = []byte{0, 0xff, 0xfe, 0, 0x80}
				changed = true
			case "reordered-changed":
				input[0].InputBytes = []byte{1}
				slices.Reverse(input)
				changed = true
			}
			reads := f.store.reads
			c, r := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
			if !changed {
				want := Result{Outcome: Unchanged, ObservedRevision: original.Revision, ObservedSnapshotID: original.Root.Snapshot, Evidence: AuthenticatedClosure}
				if c != nil || r != want || f.session.prepared || f.store.reads-reads != 2*int(original.Root.OutputConfiguration.SliceCount) || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 {
					t.Fatalf("unchanged input created a mutation: comparison=%v result=%+v", c, r)
				}
				assertStateImage(t, f.session, original)
				return
			}
			if c == nil {
				t.Fatal(r)
			}
			ordered := slices.Clone(input)
			slices.SortFunc(ordered, func(a, b ApplyEntryInput) int { return strings.Compare(a.Name, b.Name) })
			other, r := f.session.Compare(context.Background(), ordered, admitSuppliedComparison(t, f.session, nil, ordered))
			if other == nil || c.desired != other.desired || c.desiredLength != other.desiredLength || !slices.Equal(c.changed, other.changed) {
				t.Fatalf("order changed complete-image meaning: %+v", r)
			}
			permit := admit(t, f.session, c)
			want := expectedSuccessorImage(t, original, input, observeAllocatedTransitionInputs(permit))
			candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust)
			if candidate == nil {
				t.Fatal(r)
			}
			if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
				t.Fatal(r)
			}
			s, r := Open(context.Background(), f.admission, f.store)
			if s == nil {
				t.Fatal(r)
			}
			assertStateImage(t, s, want)
		})
	}
}

// full_only: false
func TestCompleteInputKeepsDistinctUnicodeNames(t *testing.T) {
	f := newFixture(t, 2, false, 0)
	state := fixtureStateImage(t, f)
	for i, name := range []string{"e\u0301", "\u00e9"} {
		state.Pages[0].Slots[i].Name = name
		state.Root.Names[i].Name = name
	}
	storeContractClosure(t, f, state)
	s, r := Open(context.Background(), f.admission, f.store)
	if s == nil {
		t.Fatal(r)
	}
	f.session = s
	original := fixtureStateImage(t, f)
	input := original.entryInputs()
	input[0].InputBytes, input[1].InputBytes = []byte{0}, []byte{0xff}
	slices.Reverse(input)
	c, r := s.Compare(context.Background(), input, admitSuppliedComparison(t, s, nil, input))
	if c == nil || len(c.changed) != 2 || bytes.Equal([]byte(c.desiredEntries[0].Name), []byte(c.desiredEntries[1].Name)) {
		t.Fatalf("Unicode names lost byte identity: %+v", r)
	}
	permit := admit(t, s, c)
	want := expectedSuccessorImage(t, original, input, observeAllocatedTransitionInputs(permit))
	candidate, r := s.Prepare(context.Background(), c, permit, f.trust)
	if candidate == nil {
		t.Fatal(r)
	}
	if r := s.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
		t.Fatal(r)
	}
	s, r = Open(context.Background(), f.admission, f.store)
	if s == nil {
		t.Fatal(r)
	}
	assertStateImage(t, s, want)
}
