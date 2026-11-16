package core

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type InspectionLocatorBasis string

const (
	InspectionConfiguredOnly InspectionLocatorBasis = "configured-only"
	InspectionQualifiedBirth InspectionLocatorBasis = "qualified-birth"
)

type InspectionCurrentTarget struct {
	BindingIndex, TargetIndex uint16
	CoordinateID              contract.ID
	CoordinateIndex           *uint16
	ResolvedConsumerLocator   *string
	LocatorBasis              InspectionLocatorBasis
}

type InspectionCurrentBlockers struct {
	CoordinateIndex uint16
	MarkerIndexes   []uint16
}

type InspectionOutputWarnings struct {
	DomainWideWarning, UnresolvedPublication, LateWriteRisk bool
}

type InspectionOutput struct {
	ConfigurationDescriptor contract.OutputConfigurationDescriptor
	Configuration           contract.OutputConfiguration
	CurrentTargets          []InspectionCurrentTarget
	Coordinates             []contract.PublicationCoordinate
	Markers                 []contract.PublicationMarker
	CurrentBlockers         []InspectionCurrentBlockers
	Warnings                InspectionOutputWarnings
}

func projectInspectionOutput(ctx context.Context, selected *publicSelection) (InspectionOutput, selectedPublication, readerFailure) {
	configuration, result := selectedOutputConfigurationWithReader(ctx, selected.image.root, selected.image.supportFacts, selected.basis.reader, true, nil)
	if result.Outcome != 0 {
		return InspectionOutput{}, selectedPublication{}, readerSelectionFailure(result)
	}
	facts, failed := readPublicationPreviewFacts(ctx, selected)
	if failed.Outcome != 0 {
		return InspectionOutput{}, selectedPublication{}, failed
	}
	out, failed := projectInspectionOutputFacts(ctx, selected.image.root, selected.image.adminIndex.PublicationOrder, configuration, facts)
	return out, facts, failed
}

func projectInspectionOutputFacts(ctx context.Context, root format.Root, orders []format.PublicationCoordinateOrder, configuration contract.OutputConfiguration, facts selectedPublication) (InspectionOutput, readerFailure) {
	if len(facts.coordinates) > contract.MaxPublicationCoordinates || len(facts.markers) > contract.MaxPublicationMarkers {
		return InspectionOutput{}, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
	}
	out := InspectionOutput{ConfigurationDescriptor: root.OutputConfiguration, Configuration: configuration,
		Coordinates: make([]contract.PublicationCoordinate, 0, len(facts.coordinates)), Markers: make([]contract.PublicationMarker, 0, len(facts.markers))}
	for _, row := range facts.coordinates {
		owned, err := row.Clone()
		if err != nil {
			return InspectionOutput{}, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
		}
		out.Coordinates = append(out.Coordinates, owned)
	}
	for _, row := range facts.markers {
		out.Markers = append(out.Markers, row)
	}
	slices.SortFunc(out.Coordinates, func(a, b contract.PublicationCoordinate) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	slices.SortFunc(out.Markers, func(a, b contract.PublicationMarker) int { return bytes.Compare(a.AttemptID[:], b.AttemptID[:]) })
	positions := make(map[contract.ID]uint16, len(out.Coordinates))
	for i, coordinate := range out.Coordinates {
		positions[coordinate.CoordinateID] = uint16(i)
	}
	targetCount := 0
	for _, binding := range configuration.Bindings {
		targetCount += len(binding.Targets)
	}
	out.CurrentTargets = make([]InspectionCurrentTarget, 0, targetCount)
	for bindingIndex, binding := range configuration.Bindings {
		for targetIndex, target := range binding.Targets {
			if ctx == nil || ctx.Err() != nil {
				return InspectionOutput{}, readerRefusal(contract.ReasonCancelled)
			}
			id, err := contract.PublicationCoordinateID(root.Domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				return InspectionOutput{}, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
			}
			row := InspectionCurrentTarget{BindingIndex: uint16(bindingIndex), TargetIndex: uint16(targetIndex), CoordinateID: id, LocatorBasis: InspectionConfiguredOnly}
			if position, present := positions[id]; present {
				row.CoordinateIndex = &position
				coordinate := out.Coordinates[position]
				if _, qualified := inspectionQualifiedBirth(root.Domain, orders, binding.IncarnationID, target.EntryIncarnationID, coordinate, facts); qualified {
					if !validInspectionLocator(coordinate.DeletionConsumerLocator) {
						return InspectionOutput{}, readerRefusal(contract.ReasonLocatorUnusable)
					}
					owned := strings.Clone(coordinate.DeletionConsumerLocator)
					row.ResolvedConsumerLocator, row.LocatorBasis = &owned, InspectionQualifiedBirth
				}
			}
			out.CurrentTargets = append(out.CurrentTargets, row)
		}
	}
	out.CurrentBlockers = inspectionCurrentBlockers(out.Coordinates, out.Markers)
	out.Warnings = inspectionOutputWarnings(root.WarningBits, out.Coordinates, out.Markers)
	return out, readerFailure{}
}

func inspectionQualifiedBirth(domain contract.ID, orders []format.PublicationCoordinateOrder, binding, entry contract.ID, coordinate contract.PublicationCoordinate, facts selectedPublication) (contract.PublicationMarker, bool) {
	if coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.LastBindingIncarnationID != binding || coordinate.LastEntryIncarnationID != entry {
		return contract.PublicationMarker{}, false
	}
	birth, present := facts.markers[coordinate.OwnedBirthAttemptID]
	if !present || !publicationQualifiedBirthValid(domain, coordinate, birth) {
		return contract.PublicationMarker{}, false
	}
	available, err := publicationBirthAfterDelete(coordinate, birth, facts, orders)
	return birth, err == nil && available
}

func validInspectionLocator(locator string) bool {
	return len(locator) >= 1 && len(locator) <= 1024 && utf8.ValidString(locator)
}

func inspectionCurrentBlockers(coordinates []contract.PublicationCoordinate, markers []contract.PublicationMarker) []InspectionCurrentBlockers {
	out := make([]InspectionCurrentBlockers, len(coordinates))
	positions := make(map[contract.ID]int, len(coordinates))
	for i, row := range coordinates {
		out[i].CoordinateIndex, positions[row.CoordinateID] = uint16(i), i
	}
	counts := make([]uint16, len(coordinates))
	for _, marker := range markers {
		if marker.State == contract.PublicationMayHaveEntered || marker.State == contract.PublicationUnknown {
			if at, present := positions[marker.CoordinateID]; present {
				counts[at]++
			}
		}
	}
	for i, count := range counts {
		out[i].MarkerIndexes = make([]uint16, 0, int(count))
	}
	for i, marker := range markers {
		if marker.State == contract.PublicationMayHaveEntered || marker.State == contract.PublicationUnknown {
			if at, present := positions[marker.CoordinateID]; present {
				out[at].MarkerIndexes = append(out[at].MarkerIndexes, uint16(i))
			}
		}
	}
	return out
}

func inspectionOutputWarnings(bits uint8, coordinates []contract.PublicationCoordinate, markers []contract.PublicationMarker) InspectionOutputWarnings {
	out := InspectionOutputWarnings{DomainWideWarning: bits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != 0}
	for _, row := range coordinates {
		out.LateWriteRisk = out.LateWriteRisk || row.LateEffectRisk != 0
	}
	for _, row := range markers {
		out.UnresolvedPublication = out.UnresolvedPublication || row.State == contract.PublicationMayHaveEntered || row.State == contract.PublicationUnknown
		out.LateWriteRisk = out.LateWriteRisk || row.LateEffectRisk != 0
	}
	return out
}

func (v InspectionOutput) validate(domain contract.ID, bits uint8, orders []format.PublicationCoordinateOrder) error {
	if v.Configuration.DomainID != domain || len(v.Coordinates) > contract.MaxPublicationCoordinates || len(v.Markers) > contract.MaxPublicationMarkers || len(v.CurrentTargets) > contract.MaxOutputTargets || len(v.CurrentBlockers) != len(v.Coordinates) {
		return contract.ErrRecord
	}
	if err := contract.ValidateOutputConfigurationAgainstDescriptor(v.Configuration, v.ConfigurationDescriptor); err != nil {
		return err
	}
	facts := selectedPublication{coordinates: make(map[contract.ID]contract.PublicationCoordinate, len(v.Coordinates)), markers: make(map[contract.ID]contract.PublicationMarker, len(v.Markers))}
	positions := make(map[contract.ID]uint16, len(v.Coordinates))
	for i, row := range v.Coordinates {
		if row.DomainID != domain || i > 0 && bytes.Compare(v.Coordinates[i-1].CoordinateID[:], row.CoordinateID[:]) >= 0 {
			return contract.ErrRecord
		}
		if _, err := contract.EncodePublicationCoordinate(row); err != nil {
			return err
		}
		facts.coordinates[row.CoordinateID], positions[row.CoordinateID] = row, uint16(i)
	}
	for i, row := range v.Markers {
		if row.DomainID != domain || i > 0 && bytes.Compare(v.Markers[i-1].AttemptID[:], row.AttemptID[:]) >= 0 {
			return contract.ErrRecord
		}
		if _, err := contract.EncodePublicationMarker(row); err != nil {
			return err
		}
		facts.markers[row.AttemptID] = row
	}
	if _, err := publicationTypedRelation(domain, facts, orders); err != nil {
		return err
	}
	at := 0
	for i, binding := range v.Configuration.Bindings {
		for j, target := range binding.Targets {
			if at >= len(v.CurrentTargets) {
				return contract.ErrRecord
			}
			row := v.CurrentTargets[at]
			at++
			id, err := contract.PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil || row.BindingIndex != uint16(i) || row.TargetIndex != uint16(j) || row.CoordinateID != id {
				return contract.ErrRecord
			}
			position, present := positions[id]
			if present != (row.CoordinateIndex != nil) || present && *row.CoordinateIndex != position {
				return contract.ErrRecord
			}
			qualified := false
			if present {
				_, qualified = inspectionQualifiedBirth(domain, orders, binding.IncarnationID, target.EntryIncarnationID, v.Coordinates[position], facts)
			}
			if qualified {
				if row.LocatorBasis != InspectionQualifiedBirth || row.ResolvedConsumerLocator == nil || !validInspectionLocator(*row.ResolvedConsumerLocator) || *row.ResolvedConsumerLocator != v.Coordinates[position].DeletionConsumerLocator {
					return contract.ErrRecord
				}
			} else if row.LocatorBasis != InspectionConfiguredOnly || row.ResolvedConsumerLocator != nil {
				return contract.ErrRecord
			}
		}
	}
	if at != len(v.CurrentTargets) || v.Warnings != inspectionOutputWarnings(bits, v.Coordinates, v.Markers) {
		return contract.ErrRecord
	}
	expected := inspectionCurrentBlockers(v.Coordinates, v.Markers)
	for i, row := range v.CurrentBlockers {
		if row.CoordinateIndex != uint16(i) || !slices.Equal(row.MarkerIndexes, expected[i].MarkerIndexes) {
			return contract.ErrRecord
		}
	}
	return nil
}
