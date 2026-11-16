package core

import "testing"

// full_only: false
func TestAdministrativePreservedCurrentBindsCurrentAndExcludesWork(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	before, err := administrativePreservedCurrent(s.root, s.pages, nil, nil)
	if err != nil || before.Length == 0 {
		t.Fatal("initial current projection", err)
	}
	work := s.root
	work.Snapshot = generatedVectorID(220)
	work.Transition = generatedVectorID(221)
	work.WarningBits = 0x1f
	work.Generated.ActiveOwner = generatedVectorID(222)
	work.ChildCount++
	work.ChildEncodedBytes++
	if same, err := administrativePreservedCurrent(work, s.pages, nil, nil); err != nil || same != before {
		t.Fatal("work and successor identifiers changed preserved current", err)
	}
	current := s.root
	ref := *current.Recipients[0]
	ref.Digest = generatedVectorID(223)
	current.Recipients[0] = &ref
	if changed, err := administrativePreservedCurrent(current, s.pages, nil, nil); err != nil || changed == before {
		t.Fatal("changed current child reference escaped projection", err)
	}
}
