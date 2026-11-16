package core

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationCoordinateMarkerIndexKeepsProofAndIncarnationScope(t *testing.T) {
	domain, first, firstMarker, _ := publicationRelationFixture(t)
	first.LatestUnresolvedAttemptID = contract.ID{}
	first.CurrentPublicationIncarnationID = publicationRelationID(83)
	second, secondMarker := first, firstMarker
	second.CanonicalTarget = "account/other-slot"
	var err error
	second.CoordinateID, err = contract.PublicationCoordinateID(domain, second.ServiceContractID, second.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	second.CurrentPublicationIncarnationID = publicationRelationID(85)
	secondMarker.CoordinateID, secondMarker.Projection.CoordinateID = second.CoordinateID, second.CoordinateID
	secondMarker.AttemptID, secondMarker.OperationID = publicationRelationID(80), publicationRelationID(81)
	secondMarker.PublicationIncarnationID = publicationRelationID(84)
	secondMarker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(secondMarker.Projection)
	if err != nil {
		t.Fatal(err)
	}
	// Both open creates deliberately have the same binding/entry/target tuple.
	// Only their coordinate distinguishes which uncertain owner they prove.
	if firstMarker.Projection.BindingIncarnationID != secondMarker.Projection.BindingIncarnationID ||
		firstMarker.Projection.EntryIncarnationID != secondMarker.Projection.EntryIncarnationID ||
		firstMarker.Projection.TargetRowDigest != secondMarker.Projection.TargetRowDigest {
		t.Fatal("fixture does not isolate coordinate scope")
	}
	rows := append(publicationRelationRows(t, first, firstMarker), publicationRelationRows(t, second, secondMarker)...)
	for _, condition := range []string{"healthy", "foreign-create-cannot-prove-owner", "foreign-incarnation-is-extra", "missing-historical-incarnation", "duplicate-historical-incarnation"} {
		t.Run(condition, func(t *testing.T) {
			offered := slices.Clone(rows)
			if condition == "foreign-create-cannot-prove-owner" {
				// Preserve both coordinates and the exact other create. Neither
				// LatestUnresolvedAttemptID supplies an incidental missing edge.
				offered = append(offered[:1], offered[2:]...)
			}
			// The expected complete incarnation vectors are independent of the
			// production union builder and retain distinct historical entries.
			order := []format.PublicationCoordinateOrder{
				{CoordinateID: first.CoordinateID, Incarnations: []contract.ID{firstMarker.PublicationIncarnationID, first.CurrentPublicationIncarnationID}},
				{CoordinateID: second.CoordinateID, Incarnations: []contract.ID{secondMarker.PublicationIncarnationID, second.CurrentPublicationIncarnationID}},
			}
			slices.SortFunc(order, func(a, b format.PublicationCoordinateOrder) int {
				return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
			})
			for i := range order {
				if order[i].CoordinateID != first.CoordinateID {
					continue
				}
				switch condition {
				case "foreign-create-cannot-prove-owner":
					order[i].Incarnations = []contract.ID{first.CurrentPublicationIncarnationID}
				case "foreign-incarnation-is-extra":
					order[i].Incarnations = []contract.ID{firstMarker.PublicationIncarnationID, secondMarker.PublicationIncarnationID, first.CurrentPublicationIncarnationID}
				case "missing-historical-incarnation":
					order[i].Incarnations = []contract.ID{first.CurrentPublicationIncarnationID}
				case "duplicate-historical-incarnation":
					order[i].Incarnations = []contract.ID{firstMarker.PublicationIncarnationID, firstMarker.PublicationIncarnationID, first.CurrentPublicationIncarnationID}
				}
			}
			selected, err := publicationRowsRelation(domain, offered, order)
			if condition == "healthy" {
				if err != nil || len(selected.coordinates) != 2 || len(selected.markers) != 2 || !selected.coordinates[first.CoordinateID].Equal(first) || !selected.coordinates[second.CoordinateID].Equal(second) || selected.markers[firstMarker.AttemptID] != firstMarker || selected.markers[secondMarker.AttemptID] != secondMarker {
					t.Fatal("exact two-coordinate relation refused or changed", err)
				}
				return
			}
			if !errors.Is(err, contract.ErrRecord) {
				t.Fatal("coordinate-local proof or exact incarnation union escaped validation", err)
			}
		})
	}
}
