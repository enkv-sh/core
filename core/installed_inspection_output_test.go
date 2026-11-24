package core

import (
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func inspectionOutputFixture(t *testing.T) (format.Root, []format.PublicationCoordinateOrder, contract.OutputConfiguration, selectedPublication) {
	t.Helper()
	state, image := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
	source, err := state.outputConfigurationBodySource()
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := contract.InspectOutputConfigurationSource(state.root.Domain, state.root.OutputConfiguration, source)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := selectedPublicationRelation(&image)
	if err != nil {
		t.Fatal(err)
	}
	return state.root, state.adminIndex.PublicationOrder, configuration, facts
}

// full_only: false
func TestInspectionOutputTargetsUseExactSelectedConfiguration(t *testing.T) {
	root, orders, configuration, facts := inspectionOutputFixture(t)
	for _, condition := range []string{"current", "without-coordinate", "retired"} {
		t.Run(condition, func(t *testing.T) {
			selected := facts
			wantTargets, wantCoordinates := 1, 1
			config := configuration
			selectedRoot := root
			selectedOrders := orders
			switch condition {
			case "without-coordinate":
				selected = selectedPublication{coordinates: map[contract.ID]contract.PublicationCoordinate{}, markers: map[contract.ID]contract.PublicationMarker{}}
				wantCoordinates = 0
				selectedOrders = nil
			case "retired":
				selected.coordinates = make(map[contract.ID]contract.PublicationCoordinate, len(facts.coordinates))
				for id, coordinate := range facts.coordinates {
					coordinate.BindingState = contract.PublicationBindingRetired
					coordinate.ActiveBindingIncarnationID = contract.ID{}
					selected.coordinates[id] = coordinate
				}
				config = contract.OutputConfiguration{Schema: 5, DomainID: root.Domain}
				body, err := contract.EncodeOutputConfiguration(config)
				if err != nil {
					t.Fatal(err)
				}
				selectedRoot.OutputConfiguration, _, err = contract.SplitOutputConfiguration(root.Domain, body)
				if err != nil {
					t.Fatal(err)
				}
				wantTargets = 0
			}
			if _, err := publicationTypedRelation(root.Domain, selected, selectedOrders); err != nil {
				t.Fatal("projection fixture has invalid selected publication relation", err)
			}
			view, failed := projectInspectionOutputFacts(t.Context(), selectedRoot, selectedOrders, config, selected)
			if failed.Outcome != 0 || !reflect.DeepEqual(view.Configuration, config) || view.ConfigurationDescriptor != selectedRoot.OutputConfiguration || len(view.CurrentTargets) != wantTargets || len(view.Coordinates) != wantCoordinates {
				t.Fatal("selected output declaration or retained coordinate lost", failed, view)
			}
			if wantTargets != 0 {
				row := view.CurrentTargets[0]
				if row.BindingIndex != 0 || row.TargetIndex != 0 || row.LocatorBasis != InspectionConfiguredOnly || row.ResolvedConsumerLocator != nil || (row.CoordinateIndex != nil) != (wantCoordinates != 0) {
					t.Fatal("configured-only target gained resolved resource evidence", row)
				}
			}
			if err := view.validate(root.Domain, root.WarningBits, selectedOrders); err != nil {
				t.Fatal("complete projected output failed owner validation", err)
			}
		})
	}
}

// full_only: false
func TestInspectionOutputQualifiedLocatorUsesBirthEvidence(t *testing.T) {
	root, orders, configuration, facts := inspectionOutputFixture(t)
	var coordinate contract.PublicationCoordinate
	var birth contract.PublicationMarker
	for _, row := range facts.coordinates {
		coordinate = row
	}
	for _, row := range facts.markers {
		birth = row
	}
	birth.State, birth.Evidence.Class, birth.Evidence.NormalizedStatus, birth.Evidence.SafeResourceID = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201, "owned-resource"
	birth.Evidence.ConsumerLocator = coordinate.DeletionConsumerLocator
	coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, contract.ID{}, birth.AttemptID
	var err error
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(root.Domain, coordinate.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	facts, err = publicationRowsRelation(root.Domain, publicationRelationRows(t, coordinate, birth), orders)
	if err != nil {
		t.Fatal("qualified selected fixture", err)
	}
	configuration.Bindings[0].Targets[0].ConsumerLocator = "changed-current-locator"
	body, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	root.OutputConfiguration, _, err = contract.SplitOutputConfiguration(root.Domain, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"qualified", "empty", "oversized", "invalid-utf8", "changed-locator", "different-binding", "different-entry"} {
		t.Run(condition, func(t *testing.T) {
			config := configuration
			selectedRoot := root
			if condition == "different-binding" || condition == "different-entry" {
				config.Bindings = append([]contract.OutputBinding(nil), configuration.Bindings...)
				if condition == "different-binding" {
					config.Bindings[0].IncarnationID = publicationRelationID(88)
				} else {
					config.Bindings[0].Targets = append([]contract.OutputTarget(nil), config.Bindings[0].Targets...)
					config.Bindings[0].Targets[0].EntryIncarnationID = publicationRelationID(88)
				}
				body, err := contract.EncodeOutputConfiguration(config)
				if err != nil {
					t.Fatal(err)
				}
				selectedRoot.OutputConfiguration, _, err = contract.SplitOutputConfiguration(root.Domain, body)
				if err != nil {
					t.Fatal(err)
				}
			}
			view, failed := projectInspectionOutputFacts(t.Context(), selectedRoot, orders, config, facts)
			if failed.Outcome != 0 {
				t.Fatal(failed)
			}
			row := view.CurrentTargets[0]
			if condition == "different-binding" || condition == "different-entry" {
				if row.LocatorBasis != InspectionConfiguredOnly || row.ResolvedConsumerLocator != nil {
					t.Fatal("old binding supplied new binding ownership", row)
				}
				return
			}
			if row.LocatorBasis != InspectionQualifiedBirth || row.ResolvedConsumerLocator == nil || *row.ResolvedConsumerLocator != coordinate.DeletionConsumerLocator {
				t.Fatal("qualified stored locator missing", row)
			}
			if err := view.validate(root.Domain, root.WarningBits, orders); err != nil {
				t.Fatal("complete qualified output refused", err)
			}
			if condition == "qualified" {
				return
			}
			locator := "different-returned-consumer"
			switch condition {
			case "empty":
				locator = ""
			case "oversized":
				locator = strings.Repeat("x", 1025)
			case "invalid-utf8":
				locator = string([]byte{255})
			}
			view.CurrentTargets[0].ResolvedConsumerLocator = &locator
			if err := view.validate(root.Domain, root.WarningBits, orders); err == nil {
				t.Fatal("changed or unusable returned locator accepted")
			}
		})
	}
}

// full_only: false
func TestInspectionOutputCurrentBlockersDoNotExpandHistoricalCommitments(t *testing.T) {
	root, orders, configuration, facts := inspectionOutputFixture(t)
	for id, marker := range facts.markers {
		marker.BlockerCount = 1
		var err error
		marker.BlockerDigest, err = contract.PublicationBlockerDigest([]contract.ID{publicationRelationID(99)})
		if err != nil {
			t.Fatal(err)
		}
		facts.markers[id] = marker
	}
	view, failed := projectInspectionOutputFacts(t.Context(), root, orders, configuration, facts)
	if failed.Outcome != 0 || len(view.CurrentBlockers) != 1 || !reflect.DeepEqual(view.CurrentBlockers[0].MarkerIndexes, []uint16{0}) || view.Markers[0].BlockerCount != 1 || !view.Warnings.UnresolvedPublication {
		t.Fatal("current blocker set confused with historical commitment", failed, view)
	}
	if cap(view.CurrentBlockers[0].MarkerIndexes) != 1 || cap(view.CurrentTargets) != 1 {
		t.Fatal("returned relation retains excess backing capacity")
	}
	if err := view.validate(root.Domain, root.WarningBits, orders); err != nil {
		t.Fatal(err)
	}
	view.CurrentBlockers[0].MarkerIndexes[0] = 1
	if err := view.validate(root.Domain, root.WarningBits, orders); err == nil {
		t.Fatal("damaged current blocker index accepted")
	}
}
