package core

import (
	"errors"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationCloseKeepsMarkerResultsWithinCoordinate(t *testing.T) {
	for _, condition := range []string{"matching_close_preserves_foreign_open_create", "foreign_result_cannot_change_unrelated_coordinate"} {
		t.Run(condition, func(t *testing.T) {
			state := publicationCapacityState(t)
			rows := publicationNoEffectRows(t, state)
			closedCoordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			closedMarker, err := contract.InspectPublicationMarker(rows[1].Body)
			if err != nil {
				t.Fatal(err)
			}
			_, other, open, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
			other.CanonicalTarget = "account/other-close"
			other.CoordinateID, err = contract.PublicationCoordinateID(other.DomainID, other.ServiceContractID, other.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			other.BindingState, other.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
			other.CurrentPublicationIncarnationID = publicationRelationID(112)
			open.CoordinateID, open.Projection.CoordinateID = other.CoordinateID, other.CoordinateID
			open.AttemptID, open.OperationID, open.PublicationIncarnationID = publicationRelationID(110), publicationRelationID(111), other.CurrentPublicationIncarnationID
			other.LatestUnresolvedAttemptID = open.AttemptID
			open.ProjectionCommitment, err = contract.PublicationProjectionCommitment(open.Projection)
			if err != nil {
				t.Fatal(err)
			}
			// The shared tuple leaves coordinate identity as the only distinction.
			if open.Projection.BindingIncarnationID != closedMarker.Projection.BindingIncarnationID || open.Projection.EntryIncarnationID != closedMarker.Projection.EntryIncarnationID || open.Projection.TargetRowDigest != closedMarker.Projection.TargetRowDigest {
				t.Fatal("fixture does not isolate coordinate scope")
			}
			otherRows := publicationRelationRows(t, other, open)
			state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(113), Index: generatedFixtureFreeSupportIndex(t, state),
				Records: []contract.SupportRecordView{contract.SupportRecordView(otherRows[0]), contract.SupportRecordView(otherRows[1])}})
			generatedRefreshSupport(t, state)
			if _, err := selectedPublicationRelation(state.selectedImage()); err != nil {
				t.Fatal("two-coordinate predecessor", err)
			}
			rows = append(rows, otherRows...)
			if condition == "foreign_result_cannot_change_unrelated_coordinate" {
				changed := other
				changed.OwnerState, changed.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
				rows[2].Body, err = contract.EncodePublicationCoordinate(changed)
				if err != nil {
					t.Fatal(err)
				}
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			initial := next
			initialStateFacts := publicationBoundsCaptureRefusalFacts(t, state)
			initialNextFacts := publicationBoundsCaptureRefusalFacts(t, &next)
			candidate := Candidate{session: state}
			construction, err := state.preparePublicationConstruction(t.Context(), rows)
			if err != nil {
				t.Fatal("two-coordinate construction", err)
			}
			pageIDs := make([]contract.ID, construction.pageCount())
			for i := range pageIDs {
				pageIDs[i] = publicationRelationID(byte(92 + i))
			}
			err = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, pageIDs)
			if condition == "foreign_result_cannot_change_unrelated_coordinate" {
				if !errors.Is(err, contract.ErrRecord) || len(candidate.objects) != 0 || !reflect.DeepEqual(next, initial) {
					t.Fatal("foreign result changed unrelated coordinate or refused state", err)
				}
				if !reflect.DeepEqual(publicationBoundsCaptureRefusalFacts(t, state), initialStateFacts) || !reflect.DeepEqual(publicationBoundsCaptureRefusalFacts(t, &next), initialNextFacts) {
					t.Fatal("foreign result mutated predecessor or successor storage")
				}
				return
			}
			if err != nil {
				t.Fatal("matching close with foreign open create", err)
			}
			selected, err := selectedPublicationRelation(next.selectedImage())
			if err != nil || len(selected.coordinates) != 2 || len(selected.markers) != 2 || !selected.coordinates[closedCoordinate.CoordinateID].Equal(closedCoordinate) || !selected.coordinates[other.CoordinateID].Equal(other) || selected.markers[closedMarker.AttemptID] != closedMarker || selected.markers[open.AttemptID] != open {
				t.Fatal("close changed complete coordinate or marker set", err)
			}
			if next.publicationProof == nil || !next.publicationProof.validFor(next.selectedImage()) {
				t.Fatal("two-coordinate successor lacks complete proof")
			}
		})
	}
}
