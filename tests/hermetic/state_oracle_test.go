package core

import (
	"context"
	"testing"

	"enkv.sh/core/format"
)

// full_only: false
func TestStateOracleRejectsWrongExpectedImage(t *testing.T) {
	f := newFixture(t, 32, false, 1)
	original := fixtureStateImage(t, f)
	if err := stateImageDifference(f.session, original); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name  string
		apply func(*stateImage)
	}{
		{"head", func(s *stateImage) { s.Revision = testID("wrong-revision") }},
		{"root", func(s *stateImage) { s.Root.RawBytes++ }},
		{"page", func(s *stateImage) { s.Pages[1].Object = testID("wrong-page") }},
		{"value", func(s *stateImage) { s.Pages[1].Slots[0].ValueBytes[0]++ }},
		{"origin", func(s *stateImage) { s.Pages[1].Slots[0].OriginSnapshot = testID("wrong-origin") }},
		{"recipient", func(s *stateImage) { s.Recipient.Slots[0].CurrentBinding.SPKI[0]++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			wrong := copyStateImage(t, original)
			change.apply(&wrong)
			if err := stateImageDifference(f.session, wrong); err == nil {
				t.Fatal("wrong expected image passed the state oracle")
			}
		})
	}
}

// full_only: false
func TestSignedMultiPageInvalidRelations(t *testing.T) {
	for _, relation := range []string{"valid", "duplicate-value-state", "current-snapshot-other-transition", "other-snapshot-current-transition"} {
		t.Run(relation, func(t *testing.T) {
			f := newFixture(t, 32, false, 1)
			const configurationSlices = 1
			if f.session.root.OutputConfiguration.SliceCount != configurationSlices {
				t.Fatal("plain fixture does not retain one canonical configuration slice")
			}
			page := *f.session.pages[1]
			entry := *page.Slots[0]
			switch relation {
			case "duplicate-value-state":
				// A cross-page duplicate passes each page's canonical codec.
				entry.ValueState = f.session.pages[0].Slots[0].ValueState
			case "current-snapshot-other-transition":
				entry.OriginTransition = testID("other-origin-transition")
			case "other-snapshot-current-transition":
				entry.OriginSnapshot = testID("other-origin-snapshot")
			}
			page.Slots[0] = &entry
			body, err := format.EncodeValueEntryPage(page)
			if err != nil {
				t.Fatal(err)
			}
			pageRef, err := format.Reference(format.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
			if err != nil {
				t.Fatal(err)
			}
			key, err := format.Key(f.store.desc.Prefix, pageRef)
			if err != nil {
				t.Fatal(err)
			}
			f.store.put(key, body)
			root := f.session.root
			root.ValueEntryPages[1] = &pageRef
			body, err = format.EncodeRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			rootRef, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, body)
			if err != nil {
				t.Fatal(err)
			}
			key, err = format.Key(f.store.desc.Prefix, rootRef)
			if err != nil {
				t.Fatal(err)
			}
			f.store.put(key, body)
			head := f.session.head
			head.Core.Root = rootRef
			// Plain values did not change. Desired and Request stay correct; K2
			// must be signed again to authenticate the updated root reference.
			storeHead(t, f, head, true)
			f.trust.signs = 0
			f.trust.SetUnavailable(true)
			reads := f.store.reads
			s, r := Open(context.Background(), f.admission, f.store)
			if relation == "valid" {
				if s == nil || r.Outcome != ObservedCurrent {
					t.Fatalf("valid rebuilt closure: %+v", r)
				}
			} else if s != nil || r.Outcome != IntegrityFailure || r.Reason != InvalidRelation {
				t.Fatalf("expected closure relation rejection: %+v", r)
			}
			wantReads := int(root.ChildCount) + 2 + configurationSlices + len(root.Generated.Fragments)
			if relation == "valid" {
				wantReads = len(processPlainReadRequests(t, f.store.desc, fixtureStateImage(t, f)))
			}
			if f.store.reads-reads != wantReads {
				t.Fatal("fixture did not reach complete closure validation")
			}
			if f.trust.signs != 0 || f.store.creates != 0 || f.store.cas != 0 {
				t.Fatal("closure validation signed or wrote data")
			}
		})
	}
}
