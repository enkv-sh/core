package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationProofRelationIsFreshAndKeepsMutationGuards(t *testing.T) {
	_, image := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
	if !publicationCompleteFixtureAccepted(t, &image) {
		t.Fatal("complete publication fixture refused")
	}
	proof := image.publicationProof
	selected, valid := proof.relationFor(&image)
	if !valid || len(selected.coordinates) != 1 || len(selected.markers) != 1 || selected.markers[publicationRelationID(4)].State != contract.PublicationUnknown {
		t.Fatal("proof did not return its complete freshly validated relation")
	}
	clear(selected.coordinates)
	clear(selected.markers)
	selected, valid = proof.relationFor(&image)
	if !valid || len(selected.coordinates) != 1 || len(selected.markers) != 1 || !proof.validFor(&image) {
		t.Fatal("returned mutable relation changed the proof or selected image")
	}
	for _, condition := range []string{"root", "selected-ref", "raw-row", "index-order"} {
		t.Run(condition, func(t *testing.T) {
			changed := image
			switch condition {
			case "root":
				changed.root.Transition = publicationRelationID(96)
			case "selected-ref":
				changed.root.RequiredSupport = slices.Clone(image.root.RequiredSupport)
				changed.root.RequiredSupport[0].Object = publicationRelationID(97)
			case "raw-row":
				changed.support = slices.Clone(image.support)
				found := false
				for i, page := range changed.support {
					for j, row := range page.Records {
						if row.Kind != contract.PublicationCoordinateSupportKind {
							continue
						}
						changed.support[i].Records = slices.Clone(page.Records)
						changed.support[i].Records[j].Body = bytes.Clone(row.Body)
						changed.support[i].Records[j].Body[0] ^= 0x80
						found = true
						break
					}
					if found {
						break
					}
				}
				if !found {
					t.Fatal("publication coordinate fixture missing")
				}
			case "index-order":
				changed.adminIndex.PublicationOrder = slices.Clone(image.adminIndex.PublicationOrder)
				changed.adminIndex.PublicationOrder[0].Incarnations = slices.Clone(image.adminIndex.PublicationOrder[0].Incarnations)
				changed.adminIndex.PublicationOrder[0].Incarnations[0] = publicationRelationID(98)
			}
			selected, valid := proof.relationFor(&changed)
			if valid || selected.coordinates != nil || selected.markers != nil || proof.validFor(&changed) {
				t.Fatal("changed publication input escaped proof validation")
			}
		})
	}
}

// full_only: false
func TestPublicationProofRoutesPreserveDefaultAndReplacements(t *testing.T) {
	inherited, suppressed, fixed := publicationRelationID(10), publicationRelationID(11), publicationRelationID(12)
	for _, tc := range []struct {
		name         string
		defaultRoute []string
		inherited    uint64
	}{
		{name: "original_default", defaultRoute: []string{"a"}, inherited: 1},
		{name: "changed_default", defaultRoute: []string{"b"}, inherited: 2},
		{name: "empty_default", defaultRoute: []string{}, inherited: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks := &selectedPublicationChecks{
				entries:      map[contract.ID]bool{inherited: true, suppressed: true, fixed: true},
				destinations: map[string]uint64{"a": 1, "b": 2},
				targets:      map[contract.ID]uint64{inherited: tc.inherited, fixed: 1},
				routes:       make(map[contract.ID]uint64),
			}
			visit := checks.visitor(nil)
			for _, route := range []struct {
				entry        contract.ID
				destinations []string
			}{{destinations: tc.defaultRoute}, {entry: suppressed, destinations: []string{}}, {entry: fixed, destinations: []string{"a"}}} {
				if err := visit.Route(route.entry, route.destinations); err != nil {
					t.Fatal(err)
				}
			}
			if err := checks.complete(); err != nil {
				t.Fatal("effective targets differ from shared entry routes", err)
			}
			checks.targets[suppressed] = 2
			if err := checks.complete(); err == nil {
				t.Fatal("explicit empty override accepted a publication target")
			}
			delete(checks.targets, suppressed)
			checks.targets[fixed] = 2
			if err := checks.complete(); err == nil {
				t.Fatal("entry override merged or inherited a changed default")
			}
		})
	}
}
