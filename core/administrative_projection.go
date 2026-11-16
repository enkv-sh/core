package core

import (
	"bytes"
	"cmp"
	"hash"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// administrativeSelectedSummaries uses only readable core projection pages
// and authenticated summaries of optional rows. It never reads optional work
// detail to decide which group owns a retained row.
func (s *StateSession) administrativeSelectedSummaries(index format.AdministrativeIndex) ([][]format.AdministrativeRowSummary, []contract.GeneratorSliceLocation, error) {
	if s == nil || !s.adminIndex.Valid() || !index.Valid() || len(s.support) != len(s.adminIndex.Pages) {
		return nil, nil, contract.ErrRecord
	}
	rows := make([][]format.AdministrativeRowSummary, len(index.Pages))
	var locations []contract.GeneratorSliceLocation
	for i, page := range index.Pages {
		if !page.ReadRequired {
			rows[i] = page.Rows
			continue
		}
		oldPosition := slices.IndexFunc(s.adminIndex.Pages, func(old format.AdministrativePage) bool { return old.Ref == page.Ref })
		if oldPosition < 0 || !s.adminIndex.Pages[oldPosition].ReadRequired {
			return nil, nil, contract.ErrRecord
		}
		oldPage := s.adminIndex.Pages[oldPosition]
		physical := s.support[oldPosition]
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				oldLogical, ok := administrativeSelectedOrdinal(oldPage, uint16(ordinal))
				if !ok || int(oldLogical) >= len(physical.Records) {
					return nil, nil, contract.ErrRecord
				}
				row := physical.Records[oldLogical]
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil || row.Kind != contract.GeneratorVectorSupportKind || carrier.VectorKind != contract.GeneratorVectorSlices {
					return nil, nil, contract.ErrRecord
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					return nil, nil, err
				}
				locations = append(locations, location)
				rows[i] = append(rows[i], format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
			}
		}
	}
	return rows, locations, nil
}

// administrativeGeneratedProjection derives root-owned work fields for a
// disposition from selected index rows and readable Slice carriers. Administrative
// successor construction must separately update current-value retirement metadata
// when its exact target is removed, then rebuild the Slice carrier pages with
// this new descriptor.
func (s *StateSession) administrativeGeneratedProjection(index format.AdministrativeIndex) (format.GeneratedClosure, uint32, error) {
	entries, err := selectedGeneratedEntryMetadata(s)
	if err != nil {
		return format.GeneratedClosure{}, 0, err
	}
	return s.administrativeGeneratedProjectionForEntries(index, entries)
}

func (s *StateSession) administrativeGeneratedProjectionForEntries(index format.AdministrativeIndex, entries []contract.GeneratedEntryMetadata) (format.GeneratedClosure, uint32, error) {
	var empty format.GeneratedClosure
	rows, locations, err := s.administrativeSelectedSummaries(index)
	if err != nil {
		return empty, 0, err
	}
	projected := s.root.Generated
	if _, err := generatedIntentIDs(entries); err != nil {
		return empty, 0, err
	}
	projected.GeneratedCurrent, projected.Retiring = uint32(len(entries)), 0
	for _, group := range index.Groups {
		if group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind == contract.GeneratedDutyRetirement {
			projected.Retiring++
		}
	}
	var counts [contract.GCPlanSupportKind + 1]uint32
	var selected uint32
	ownedCount := make([]uint32, len(index.Groups))
	ownedDigest := make([]hash.Hash, len(index.Groups))
	for i, group := range index.Groups {
		ownedDigest[i] = selectedDisposableDigest(group.Disposable.Count)
	}
	chargedPages := make([]uint16, len(index.Groups))
	chargedBytes := make([]uint64, len(index.Groups))
	ownerRecord := make([]bool, len(index.Groups))
	lastPage := make([]int, len(index.Groups))
	for i := range lastPage {
		lastPage[i] = -1
	}
	for i, page := range index.Pages {
		if page.Ref.Domain != s.root.Domain || len(rows[i]) == 0 {
			return empty, 0, contract.ErrRecord
		}
		position := 0
		for _, span := range page.Spans {
			if position+int(span.Count) > len(rows[i]) {
				return empty, 0, contract.ErrRecord
			}
			for _, group := range span.GroupIndexes {
				if lastPage[group] != int(page.Ref.Index) {
					chargedPages[group]++
					lastPage[group] = int(page.Ref.Index)
				}
			}
			for j := 0; j < int(span.Count); j++ {
				row := rows[i][position+j]
				if row.Kind == 0 || int(row.Kind) >= len(counts) {
					return empty, 0, contract.ErrRecord
				}
				counts[row.Kind]++
				selected++
				for _, groupIndex := range span.GroupIndexes {
					ownedCount[groupIndex]++
					writeSelectedDisposableRow(ownedDigest[groupIndex], row.Kind, row.RecordID, row.BodyLength)
					chargedBytes[groupIndex] += uint64(contract.SupportRecordOverhead) + uint64(row.BodyLength)
					group := index.Groups[groupIndex]
					if row.RecordID == group.GroupID &&
						(group.OwnerKind == format.AdministrativeGeneratedParent && row.Kind == contract.GeneratedParentSupportKind ||
							group.OwnerKind == format.AdministrativeGeneratedDuty && row.Kind == contract.GeneratedDutySupportKind ||
							group.OwnerKind == format.AdministrativeGeneratedHazard && row.Kind == contract.GeneratedHazardSupportKind ||
							group.OwnerKind == format.AdministrativeInboxRelease && row.Kind == contract.PendingInboxReleaseSupportKind ||
							group.OwnerKind == format.AdministrativePublicationCoordinate && row.Kind == contract.PublicationCoordinateSupportKind ||
							group.OwnerKind == format.AdministrativePublicationMarker && row.Kind == contract.PublicationMarkerSupportKind ||
							group.OwnerKind == format.AdministrativeGC && row.Kind == contract.GCPlanSupportKind) {
						ownerRecord[groupIndex] = true
					}
				}
			}
			position += int(span.Count)
		}
		if position != len(rows[i]) {
			return empty, 0, contract.ErrRecord
		}
	}
	for i, group := range index.Groups {
		computed := selectedDisposableDescriptor(ownedDigest[i], ownedCount[i])
		if !ownerRecord[i] || group.ChargedPages != chargedPages[i] || group.ChargedBytes != chargedBytes[i] ||
			group.Disposable != computed {
			return empty, 0, contract.ErrRecord
		}
	}
	projected.Attempts, projected.Duties, projected.Hazards = counts[contract.GeneratedAttemptSupportKind], counts[contract.GeneratedDutySupportKind], counts[contract.GeneratedHazardSupportKind]
	projected.Results, projected.Materials, projected.PendingReleases = counts[contract.GeneratedResultSupportKind], counts[contract.OperationMaterialSupportKind], counts[contract.PendingInboxReleaseSupportKind]
	if !projected.ActiveOwner.IsZero() && !slices.ContainsFunc(index.Groups, func(group format.AdministrativeGroup) bool {
		return group.OwnerKind == format.AdministrativeGeneratedParent && group.GroupID == projected.ActiveOwner
	}) {
		projected.ActiveOwner, projected.ActivePhase, projected.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	}
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return cmp.Compare(a.ContentKind, b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	vectorRows := make([][]byte, len(locations))
	var graphIDs []contract.ID
	for i, location := range locations {
		if i > 0 && location.ContentKind == locations[i-1].ContentKind && location.ContentID == locations[i-1].ContentID {
			return empty, 0, contract.ErrRecord
		}
		vectorRows[i], err = contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			return empty, 0, err
		}
		if location.ContentKind == contract.GeneratorContentGraph {
			graphIDs = append(graphIDs, location.ContentID)
		}
	}
	projected.Slices, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, vectorRows)
	if err != nil {
		return empty, 0, err
	}
	slices.SortFunc(graphIDs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	projected.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphIDs)
	if err != nil {
		return empty, 0, err
	}
	var owners []contract.ID
	for _, group := range index.Groups {
		if group.OwnerKind == format.AdministrativeGeneratedParent && group.GroupID != projected.ActiveOwner {
			return empty, 0, contract.ErrRecord
		}
		if group.OwnerKind >= format.AdministrativeGeneratedParent && group.OwnerKind <= format.AdministrativeInboxRelease {
			owners = append(owners, group.GroupID)
		}
	}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	projected.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		return empty, 0, err
	}
	projected.Fragments, err = s.administrativeFragmentProjection(index, rows)
	if err != nil || uint32(len(projected.Fragments)) != counts[contract.GeneratedFragmentSupportKind] {
		return empty, 0, contract.ErrRecord
	}
	return projected, selected, nil
}

func (s *StateSession) administrativeFragmentProjection(index format.AdministrativeIndex, rows [][]format.AdministrativeRowSummary) ([]format.FragmentLocation, error) {
	var out []format.FragmentLocation
	for _, location := range s.root.Generated.Fragments {
		oldPosition := slices.IndexFunc(s.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref.Index == location.SupportPageIndex })
		if oldPosition < 0 {
			return nil, contract.ErrRecord
		}
		oldPage := s.adminIndex.Pages[oldPosition]
		physical, ok := administrativePhysicalRowSlot(oldPage, location.RowSlot)
		if !ok {
			return nil, contract.ErrRecord
		}
		newPosition := slices.IndexFunc(index.Pages, func(page format.AdministrativePage) bool { return page.Ref == oldPage.Ref })
		if newPosition < 0 {
			continue
		}
		newOrdinal, selected := administrativeSelectedOrdinal(index.Pages[newPosition], physical)
		if !selected {
			continue
		}
		if newOrdinal > 255 {
			return nil, contract.ErrRecord
		}
		newSlot := uint8(newOrdinal)
		id, err := contract.GeneratorFragmentID(location.BlobID, location.FragmentIndex)
		if err != nil || int(newSlot) >= len(rows[newPosition]) || rows[newPosition][newSlot].Kind != contract.GeneratedFragmentSupportKind ||
			rows[newPosition][newSlot].RecordID != id {
			return nil, contract.ErrRecord
		}
		location.RowSlot = newSlot
		out = append(out, location)
	}
	return out, nil
}

func administrativePhysicalRowSlot(page format.AdministrativePage, logical uint8) (uint16, bool) {
	selected := uint32(0)
	for _, span := range page.Spans {
		if uint32(logical) >= selected && uint32(logical) < selected+uint32(span.Count) {
			return span.First + uint16(uint32(logical)-selected), true
		}
		selected += uint32(span.Count)
	}
	return 0, false
}
