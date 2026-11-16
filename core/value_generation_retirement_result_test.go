package core

import (
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestReleasedRetirementEntryProjectionsKeepsEmptyName(t *testing.T) {
	for _, name := range []string{"", "generated"} {
		label := name
		if name == "" {
			label = "empty"
		}
		t.Run(label, func(t *testing.T) {
			state := generatedSelectedEntryOriginNamed(t, generatedVectorID(10), generatedVectorID(11), 0, name,
				generatedVectorID(18), generatedVectorID(12), generatedVectorID(10))
			current := *state.valueEntry(0)
			current.Name = name
			current.Generated.RetiringDutyPresent, current.Generated.RetiringDutyID = 0, contract.ID{}
			sibling := contract.ValueEntry{Name: "healthy", Incarnation: generatedVectorID(90), ValueState: generatedVectorID(91),
				OriginSnapshot: generatedVectorID(92), OriginTransition: generatedVectorID(93),
				ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
				Recipients: current.Recipients, ValueBytes: []byte("healthy sibling"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("healthy sibling"))), RetainedLength: uint32(len([]byte("healthy sibling")))}
			subject := contract.GeneratorAuthoritySubject{LineageID: generatedVectorID(94), OwnerID: generatedVectorID(95), RequestIdentityDigest: generatedVectorID(96)}
			pageID, err := contract.GeneratorPhasePageID(subject.RequestIdentityDigest, format.ValueEntryPageKind, 0)
			if err != nil {
				t.Fatal(err)
			}
			page := &format.ValueEntryPage{Domain: state.root.Domain, Object: pageID}
			page.Slots[0], page.Slots[1] = &current, &sibling
			image := &selectedImage{root: format.Root{Domain: state.root.Domain, Names: []format.NameEntry{{Name: name, Slot: 0}, {Name: sibling.Name, Slot: 1}}}}
			image.pages[0] = page
			image.root.ValueEntryPages[0] = &format.Ref{Kind: format.ValueEntryPageKind, Object: pageID}
			proof := &selectedGeneratedProof{selectedImage: image}
			bundle := contract.GeneratorPlanBundle{Lineages: []contract.GeneratorLineageTemplate{{LineageID: subject.LineageID, Name: name, Purpose: contract.GeneratorLineageRetirement}}}
			side := func(slot uint16, value contract.ValueEntry) contract.MembershipSide {
				t.Helper()
				digest, err := contract.PublicValueEntryDigest(image.root.Domain, slot, value)
				if err != nil {
					t.Fatal("projection input", err)
				}
				return contract.MembershipSide{Slot: slot, Incarnation: value.Incarnation, EntryDigest: digest, Recipients: value.Recipients}
			}
			old := current
			old.Generated.RetiringDutyPresent, old.Generated.RetiringDutyID = 1, subject.OwnerID
			before, after, healthy := side(0, old), side(0, current), side(1, sibling)
			wantChanges := []contract.UnionRow{{Name: name, BeforePresent: true, AfterPresent: true, Before: before, After: after},
				{Name: sibling.Name, BeforePresent: true, AfterPresent: true, Before: healthy, After: healthy}}
			wantMembership := []contract.UnionRow{{Name: name, BeforePresent: true, AfterPresent: true, Before: before, After: before}, wantChanges[1]}
			changes, membership, pages, ok := proof.generatedReleasedRetirementEntryProjections(bundle, subject)
			if !ok || !reflect.DeepEqual(changes, wantChanges) || !reflect.DeepEqual(membership, wantMembership) ||
				!reflect.DeepEqual(pages, []contract.IdentityPage{{Kind: format.ValueEntryPageKind, Object: pageID}}) {
				t.Fatal("matched retirement lineage lost its exact name or sibling projections")
			}
			if !reflect.DeepEqual(*page.Slots[0], current) || !reflect.DeepEqual(*page.Slots[1], sibling) {
				t.Fatal("projection changed selected entries")
			}
			t.Run("absent lineage", func(t *testing.T) {
				wrong := subject
				wrong.LineageID = generatedVectorID(97)
				if _, _, _, ok := proof.generatedReleasedRetirementEntryProjections(bundle, wrong); ok {
					t.Fatal("missing retirement lineage accepted")
				}
			})
			t.Run("wrong purpose", func(t *testing.T) {
				wrong := bundle
				wrong.Lineages = []contract.GeneratorLineageTemplate{{LineageID: subject.LineageID, Name: name, Purpose: contract.GeneratorLineageCleanup}}
				if _, _, _, ok := proof.generatedReleasedRetirementEntryProjections(wrong, subject); ok {
					t.Fatal("cleanup lineage accepted as retirement")
				}
			})
			t.Run("removed entry", func(t *testing.T) {
				detached := *image
				detached.root.Names = []format.NameEntry{{Name: sibling.Name, Slot: 1}}
				proof := &selectedGeneratedProof{selectedImage: &detached}
				changes, membership, pages, ok := proof.generatedReleasedRetirementEntryProjections(bundle, subject)
				want := []contract.UnionRow{wantChanges[1]}
				if !ok || !reflect.DeepEqual(changes, want) || !reflect.DeepEqual(membership, want) || len(pages) != 0 {
					t.Fatal("detached retirement required a current name slot")
				}
			})
			t.Run("retiring pointer present", func(t *testing.T) {
				page.Slots[0] = &old
				defer func() { page.Slots[0] = &current }()
				if _, _, _, ok := proof.generatedReleasedRetirementEntryProjections(bundle, subject); ok {
					t.Fatal("uncleared retiring pointer accepted")
				}
			})
			t.Run("wrong phase page", func(t *testing.T) {
				image.root.ValueEntryPages[0].Object = generatedVectorID(98)
				defer func() { image.root.ValueEntryPages[0].Object = pageID }()
				if _, _, _, ok := proof.generatedReleasedRetirementEntryProjections(bundle, subject); ok {
					t.Fatal("page from a different lifecycle accepted")
				}
			})
		})
	}
}
