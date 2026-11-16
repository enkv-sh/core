package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeExposureMatchesSelectedDeletePermissions(t *testing.T) {
	for _, name := range []string{"retirement history", "delete hazard", "create hazard", "unentered retirement"} {
		t.Run(name, func(t *testing.T) {
			var state *StateSession
			var owner contract.ID
			var want uint8
			switch name {
			case "retirement history":
				var duty contract.GeneratedDutyRecord
				state, _, duty = generatedRepeatedRetirementState(t, 1)
				owner, want = duty.DutyID, 1
			case "delete hazard":
				var hazard contract.GeneratedHazardRecord
				state, _, hazard, _ = generatedDeleteHazardState(t, 2)
				owner, want = hazard.HazardID, 1
			case "create hazard":
				var hazard contract.GeneratedHazardRecord
				state, _, hazard = generatedCreateHazardState(t, 0, 1)
				owner = hazard.HazardID
			default:
				var duty contract.GeneratedDutyRecord
				state, duty, _ = generatedDetachedRetirementState(t, "absent", 0)
				owner = duty.DutyID
			}
			selected, err := state.selectedGeneratedWork(t.Context())
			if err != nil || validateAdministrativeExposure(state.adminIndex, state.support, selected) != nil {
				t.Fatal("complete selected exposure facts refused", err)
			}
			position := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
				return group.GroupID == owner
			})
			if position < 0 || state.adminIndex.Groups[position].DestructiveEffect != want {
				t.Fatal("selected owner has incorrect destructive exposure", name, position, want)
			}
			bad := state.adminIndex
			bad.Groups = slices.Clone(bad.Groups)
			bad.Groups[position].DestructiveEffect = 1 - want
			if !bad.Valid() || validateAdministrativeExposure(bad, state.support, selected) == nil {
				t.Fatal("full selected validation accepted an altered destructive exposure bit")
			}
		})
	}
}

// full_only: false
func TestAdministrativeExposureBindsUncertainCreateProof(t *testing.T) {
	state := publicationCapacityState(t)
	generatedInstallFixtureSupportReader(t, state)
	var coordinate contract.PublicationCoordinate
	var marker contract.PublicationMarker
	for _, page := range state.support {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.PublicationCoordinateSupportKind:
				var err error
				coordinate, err = contract.InspectPublicationCoordinate(row.Body)
				if err != nil {
					t.Fatal("selected coordinate fixture", err)
				}
			case contract.PublicationMarkerSupportKind:
				var err error
				marker, err = contract.InspectPublicationMarker(row.Body)
				if err != nil {
					t.Fatal("selected marker fixture", err)
				}
			}
		}
	}
	coordinates, err := state.publicationCoordinatesForDisposition()
	if err != nil || len(coordinates) != 1 || !coordinates[coordinate.CoordinateID].Equal(coordinate) {
		t.Fatal("complete selected publication facts refused", err)
	}
	if err := validateAdministrativeExposure(state.adminIndex, state.support, nil); err != nil {
		t.Fatal("complete publication exposure facts refused", err)
	}
	position := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
		return group.GroupID == marker.AttemptID
	})
	if position < 0 || state.adminIndex.Groups[position].UncertainCreateProof != 1 {
		t.Fatal("selected matching uncertain create was not qualified")
	}
	bad := state.adminIndex
	bad.Groups = slices.Clone(bad.Groups)
	bad.Groups[position].UncertainCreateProof = 0
	if !bad.Valid() || validateAdministrativeExposure(bad, state.support, nil) == nil {
		t.Fatal("full selected validation accepted removal of the uncertain-create proof bit")
	}
	for _, change := range []string{"coordinate", "binding", "entry", "target", "action", "state"} {
		t.Run(change, func(t *testing.T) {
			altered := marker
			switch change {
			case "coordinate":
				altered.CoordinateID = publicationRelationID(90)
			case "binding":
				altered.Projection.BindingIncarnationID = publicationRelationID(90)
			case "entry":
				altered.Projection.EntryIncarnationID = publicationRelationID(90)
			case "target":
				altered.Projection.TargetRowDigest = publicationRelationID(90)
			case "action":
				altered.Projection.Action = contract.PublicationDeleteOwned
			case "state":
				altered.State = contract.PublicationAcknowledged
			}
			if publicationMarkerProvesUncertainCreate(altered, coordinate) {
				t.Fatal("unrelated marker qualified uncertain ownership")
			}
		})
	}
}
