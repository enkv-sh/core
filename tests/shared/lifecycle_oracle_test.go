package core

import (
	"context"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestIndependentOracleRetainsIntersectionBeforeReusingSlots(t *testing.T) {
	f := newFixture(t, 3, false, 1)
	original := fixtureStateImage(t, f)
	retained := original.entryInputs()[2]
	requested := []ApplyEntryInput{
		{Name: "z", Recipients: []contract.ID{retained.Recipients[0]}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
		retained,
		{Name: "a", Recipients: []contract.ID{retained.Recipients[0]}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte("new")},
	}
	inputs := allocatedTransitionInputs{
		operation: testID("oracle-operation"), transition: testID("oracle-transition"), snapshot: testID("oracle-snapshot"), revision: testID("oracle-revision"),
		values:       map[uint16]contract.ID{0: testID("a-value"), 1: testID("z-value")},
		incarnations: map[uint16]contract.ID{0: testID("a-incarnation"), 1: testID("z-incarnation")},
	}
	inputs.valueEntryPages[0] = testID("oracle-page")
	next := expectedSuccessorImage(t, original, requested, inputs)
	if !reflect.DeepEqual(next.Root.Names, []format.NameEntry{{Name: "a", Slot: 0}, {Name: retained.Name, Slot: 2}, {Name: "z", Slot: 1}}) {
		t.Fatal("oracle did not keep the retained slot and assign sorted additions to successor-free slots")
	}
	if !entriesEqual(*next.Pages[0].Slots[2], *original.Pages[0].Slots[2]) || next.Pages[0].Slots[0].Incarnation != inputs.incarnations[0] || next.Pages[0].Slots[1].Incarnation != inputs.incarnations[1] {
		t.Fatal("oracle changed retained records or addition identities")
	}
	// Selected children: value page, recipient page, administrative index,
	// initialization receipt, receipt index and configuration.
	if next.Root.ValueEntryCount != 3 || next.Root.RawBytes != 4 || next.Root.ChildCount != 6 {
		t.Fatal("oracle successor totals differ")
	}
}

// full_only: false
func TestIndependentOracleDropsEveryPageOnLastRemoval(t *testing.T) {
	f := newFixture(t, 17, false, 1)
	original := fixtureStateImage(t, f)
	inputs := allocatedTransitionInputs{operation: testID("oracle-empty-operation"), transition: testID("oracle-empty-transition"), snapshot: testID("oracle-empty-snapshot"), revision: testID("oracle-empty-revision")}
	next := expectedSuccessorImage(t, original, nil, inputs)
	if next.Root.ValueEntryCount != 0 || next.Root.RawBytes != 0 || next.Root.ChildCount != 5 || len(next.Root.Names) != 0 {
		t.Fatal("oracle empty successor totals differ")
	}
	for i := range next.Pages {
		if next.Pages[i] != nil || next.Root.ValueEntryPages[i] != nil {
			t.Fatal("oracle retained an empty member page")
		}
	}
	if !reflect.DeepEqual(next.Recipient, original.Recipient) || !reflect.DeepEqual(next.Root.Recipients, original.Root.Recipients) {
		t.Fatal("oracle removed selected public support")
	}
	if created, obsolete := successorObjectCounts(original, next); created != 2 || obsolete != 4 {
		t.Fatalf("root-only removal object counts %d/%d", created, obsolete)
	}
}

// full_only: false
func TestStateImageReadsOperationFromSelectedAuthority(t *testing.T) {
	op := testID("oracle selected operation")
	for name, head := range map[string]format.Head{
		"lifecycle":      {AuthKind: format.LifecycleAuth, Subject: contract.LifecycleSubject{Operation: op}},
		"genesis":        {AuthKind: format.GenesisAuth, Genesis: &format.GenesisProof{Subject: contract.GenesisSubject{InitID: op}}},
		"succession":     {AuthKind: format.SuccessionAuth, Succession: &format.SuccessionProof{Subject: contract.SuccessionSubject{OperationID: op}}},
		"generated":      {AuthKind: format.GeneratorAuth, Generator: &contract.GeneratorAuthoritySubject{OperationID: op}},
		"output_reserve": {AuthKind: format.OutputReserveAuth, OutputReserve: &contract.OutputReserveSubject{OperationID: op}},
		"output_close":   {AuthKind: format.OutputCloseAuth, OutputClose: &contract.OutputCloseSubject{OperationID: op}},
	} {
		t.Run(name, func(t *testing.T) {
			s := generatedEmptyPredecessor(t)
			head.Core = s.head.Core
			s.head = head
			want := sessionStateImage(t, s)
			if want.Operation != op {
				t.Fatal("state image omitted the selected operation")
			}
			if err := stateImageDifference(s, want); err != nil {
				t.Fatal("exact operation differs", err)
			}
			want.Operation = testID("another oracle operation")
			if err := stateImageDifference(s, want); err == nil {
				t.Fatal("state image ignored a different operation")
			}
		})
	}
}

// full_only: false
func TestIndependentOracleRejectsDamagedSuccessorFacts(t *testing.T) {
	for name, count := range map[string]int{"genesis": 0, "ordinary": 1} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, count, false, 1)
			original := observeSelectedState(t, f.session)
			requested := original.entryInputs()
			if count == 0 {
				requested = []ApplyEntryInput{{Name: "first", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: format.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: format.Plain, InputBytes: []byte("changed")}}
			} else {
				requested[0].InputBytes = []byte("changed")
			}
			comparison, result := f.session.Compare(ctx, requested, admitSuppliedComparison(t, f.session, nil, requested))
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("oracle comparison", result)
			}
			permit, inputs := admitTransition(t, f.session, comparison)
			want := expectedSuccessorImage(t, original, requested, inputs)
			candidate, result := f.session.Prepare(ctx, comparison, permit, f.trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("oracle preparation", result)
			}
			if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
				t.Fatal("oracle selection", result)
			}
			selected, result := Open(ctx, f.admission, f.store)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("oracle observation", result)
			}
			assertStateImage(t, selected, want)

			for _, test := range []struct {
				name   string
				damage func(*StateSession)
			}{
				{"revision", func(s *StateSession) { s.head.Core.Revision = testID("damaged observed revision") }},
				{"operation", func(s *StateSession) { s.head.Subject.Operation = testID("damaged observed operation") }},
				{"root-reference", func(s *StateSession) { s.head.Core.Root.Object = testID("damaged observed root reference") }},
				{"snapshot", func(s *StateSession) { s.root.Snapshot = testID("damaged observed snapshot") }},
				{"transition", func(s *StateSession) { s.root.Transition = testID("damaged observed transition") }},
				{"member-reference", func(s *StateSession) {
					ref := *s.root.ValueEntryPages[0]
					ref.Object = testID("damaged observed member reference")
					s.root.ValueEntryPages[0] = &ref
				}},
				{"page-identity", func(s *StateSession) { s.pages[0].Object = testID("damaged observed page identity") }},
				{"member-incarnation", func(s *StateSession) { s.pages[0].Slots[0].Incarnation = testID("damaged observed incarnation") }},
				{"value-identity", func(s *StateSession) { s.pages[0].Slots[0].ValueState = testID("damaged observed value identity") }},
			} {
				t.Run(test.name, func(t *testing.T) {
					observed, result := Open(ctx, f.admission, f.store)
					if observed == nil || result.Outcome != ObservedCurrent {
						t.Fatal("fresh oracle observation", result)
					}
					test.damage(observed)
					if err := stateImageDifference(observed, want); err == nil {
						t.Fatal("independent oracle accepted a damaged successor")
					}
				})
			}
		})
	}
}
