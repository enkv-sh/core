package core

import (
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A retained immutable page keeps physical record ordinals. Selected rows use
// compact logical ordinals after a disposition removes spans.
func administrativeSelectedOrdinal(page format.AdministrativePage, physical uint16) (uint16, bool) {
	selected := uint32(0)
	for _, span := range page.Spans {
		start, end := uint32(span.First), uint32(span.First)+uint32(span.Count)
		if uint32(physical) >= start && uint32(physical) < end {
			logical := selected + uint32(physical) - start
			if logical > 0xffff {
				return 0, false
			}
			return uint16(logical), true
		}
		selected += uint32(span.Count)
	}
	return 0, false
}

// Generated fragment locations encode an eight-bit row slot because a fragment
// support page contains at most two physical rows.
func administrativeSelectedRowSlot(page format.AdministrativePage, physical uint8) (uint8, bool) {
	logical, ok := administrativeSelectedOrdinal(page, uint16(physical))
	if !ok || logical > 255 {
		return 0, false
	}
	return uint8(logical), true
}

func appendAdministrativeOwnerSpan(spans []format.AdministrativeSpan, span format.AdministrativeSpan) []format.AdministrativeSpan {
	if n := len(spans); n != 0 {
		last := &spans[n-1]
		if last.Mandatory == span.Mandatory && slices.Equal(last.GroupIndexes, span.GroupIndexes) &&
			uint32(last.First)+uint32(last.Count) == uint32(span.First) &&
			uint32(last.Count)+uint32(span.Count) <= uint32(^uint16(0)) {
			last.Count += span.Count
			return spans
		}
	}
	return append(spans, span)
}

// administrativeWorkDisposition derives the retained logical work from a
// previously authenticated index. It does not read disposable page bodies.
func (s *StateSession) administrativeWorkDisposition(groupID contract.ID) (format.AdministrativeIndex, error) {
	next, _, err := s.administrativeWorkDispositionScope(groupID, false)
	return next, err
}

// A parent exit includes every selected group that depends on it, through the
// complete authenticated relation graph. A leaf exit remains exact to the
// named group. Neither path reads disposable payloads.
func (s *StateSession) administrativeWorkClosure(groupID contract.ID) (format.AdministrativeIndex, []format.AdministrativeGroup, error) {
	return s.administrativeWorkDispositionScope(groupID, true)
}

// A selected active child is not an independent exit. Its parent is the
// target that disposes the complete active operation, without a reverse edge.
func administrativeRequiredParentTarget(root format.Root, index format.AdministrativeIndex, group format.AdministrativeGroup) contract.ID {
	if root.Generated.ActiveOwner.IsZero() || group.OwnerKind == format.AdministrativeGeneratedParent {
		return contract.ID{}
	}
	for _, related := range group.RelatedGroupIndexes {
		if int(related) < len(index.Groups) {
			parent := index.Groups[related]
			if parent.OwnerKind == format.AdministrativeGeneratedParent && parent.GroupID == root.Generated.ActiveOwner {
				return parent.GroupID
			}
		}
	}
	return contract.ID{}
}

func administrativeTargetSelectable(root format.Root, index format.AdministrativeIndex, group format.AdministrativeGroup,
	coordinates map[contract.ID]contract.PublicationCoordinate) bool {
	if !administrativeRequiredParentTarget(root, index, group).IsZero() {
		return false
	}
	if group.OwnerKind == format.AdministrativePublicationCoordinate {
		coordinate, present := coordinates[group.GroupID]
		return present && coordinate.BindingState != contract.PublicationBindingActive
	}
	if group.OwnerKind == format.AdministrativePublicationMarker {
		coordinate, present := coordinates[group.OwnerID]
		return !present || coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedBirthAttemptID != group.GroupID
	}
	return true
}

func (s *StateSession) administrativeWorkDispositionScope(groupID contract.ID, includeDependents bool) (format.AdministrativeIndex, []format.AdministrativeGroup, error) {
	if s == nil || groupID.IsZero() || !s.adminIndex.Valid() ||
		s.root.Domain != s.adminIndex.Domain || s.root.AdministrativeIndex.Object != s.adminIndex.Object ||
		len(s.root.RequiredSupport) != len(s.adminIndex.Pages) {
		return format.AdministrativeIndex{}, nil, contract.ErrRecord
	}
	found := false
	for _, group := range s.adminIndex.Groups {
		found = found || group.GroupID == groupID
	}
	if !found {
		return format.AdministrativeIndex{}, nil, contract.ErrRecord
	}
	removed := slices.IndexFunc(s.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == groupID })
	publicationCoordinates, err := s.publicationCoordinatesForDisposition()
	if err != nil {
		return format.AdministrativeIndex{}, nil, err
	}
	if !administrativeTargetSelectable(s.root, s.adminIndex, s.adminIndex.Groups[removed], publicationCoordinates) {
		return format.AdministrativeIndex{}, nil, contract.ErrRecord
	}
	ended := make([]bool, len(s.adminIndex.Groups))
	ended[removed] = true
	for changed := true; changed; {
		changed = false
		for i, group := range s.adminIndex.Groups {
			if ended[i] {
				continue
			}
			for _, related := range group.RelatedGroupIndexes {
				if ended[related] {
					if !includeDependents {
						return format.AdministrativeIndex{}, nil, contract.ErrRecord
					}
					ended[i], changed = true, true
					break
				}
			}
		}
	}
	var scope []format.AdministrativeGroup
	for i, group := range s.adminIndex.Groups {
		if ended[i] {
			scope = append(scope, group)
		}
	}
	pages, ownershipChanged, err := s.administrativeDispositionPages()
	if err != nil {
		return format.AdministrativeIndex{}, nil, err
	}
	next, err := s.retainedAdministrativeIndex(pages, ownershipChanged, ended, publicationCoordinates)
	if err != nil {
		return format.AdministrativeIndex{}, nil, err
	}
	return next, scope, nil
}

// Build the logical projection from the authenticated physical ordinals.
// GC keeps every group when its own operation is absent on this side of a phase.
func (s *StateSession) retainedAdministrativeIndex(pages []format.AdministrativePage, ownershipChanged bool,
	ended []bool, publicationCoordinates map[contract.ID]contract.PublicationCoordinate) (format.AdministrativeIndex, error) {
	for i, page := range s.adminIndex.Pages {
		if page.Ref != s.root.RequiredSupport[i] {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
		mandatory := page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory })
		if !mandatory {
			continue
		}
		present := false
		for _, current := range s.support {
			if current.Index == page.Ref.Index && current.Object == page.Ref.Object && current.Domain == page.Ref.Domain {
				present = true
				break
			}
		}
		if !present {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
	}
	next := format.AdministrativeIndex{Domain: s.adminIndex.Domain, Object: s.adminIndex.Object, SliceSnapshot: s.adminIndex.SliceSnapshot}
	retainedGroups := make(map[uint16]uint16, len(s.adminIndex.Groups))
	for i, group := range s.adminIndex.Groups {
		if !ended[i] {
			retainedGroups[uint16(i)] = uint16(len(next.Groups))
			next.Groups = append(next.Groups, group)
		}
	}
	for i := range next.Groups {
		next.Groups[i] = next.Groups[i].Own()
		for j, related := range next.Groups[i].RelatedGroupIndexes {
			mapped, ok := retainedGroups[related]
			if !ok {
				return format.AdministrativeIndex{}, contract.ErrRecord
			}
			next.Groups[i].RelatedGroupIndexes[j] = mapped
		}
	}
	requiredBirths, err := publicationRequiredBirths(next.Groups, publicationCoordinates)
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	for _, page := range pages {
		kept := page
		kept.Spans = nil
		kept.Rows = nil
		rowOffset := 0
		for _, span := range page.Spans {
			retained := span
			retained.GroupIndexes = nil
			for _, index := range span.GroupIndexes {
				if mapped, ok := retainedGroups[index]; ok {
					retained.GroupIndexes = append(retained.GroupIndexes, mapped)
				}
			}
			if !page.ReadRequired && span.Count == 1 && len(span.GroupIndexes) == 1 {
				group := s.adminIndex.Groups[span.GroupIndexes[0]]
				row := page.Rows[rowOffset]
				switch row.Kind {
				case contract.PublicationCoordinateSupportKind:
					if group.OwnerKind != format.AdministrativePublicationCoordinate || row.RecordID != group.GroupID {
						return format.AdministrativeIndex{}, contract.ErrRecord
					}
					retained.Mandatory = len(retained.GroupIndexes) != 0
				case contract.PublicationMarkerSupportKind:
					if group.OwnerKind != format.AdministrativePublicationMarker || row.RecordID != group.GroupID {
						return format.AdministrativeIndex{}, contract.ErrRecord
					}
					retained.Mandatory = requiredBirths[group.GroupID]
				}
			}
			if retained.Mandatory || len(retained.GroupIndexes) != 0 {
				kept.Spans = appendAdministrativeOwnerSpan(kept.Spans, retained)
				if !page.ReadRequired {
					kept.Rows = append(kept.Rows, page.Rows[rowOffset:rowOffset+int(span.Count)]...)
				}
			}
			rowOffset += int(span.Count)
		}
		if len(kept.Spans) != 0 {
			next.Pages = append(next.Pages, kept)
		}
	}
	next.PublicationOrder = slices.Clone(s.adminIndex.PublicationOrder)
	next.PublicationOrder, err = publicationIncarnationOrder(next, publicationCoordinates, true)
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	if !next.Valid() {
		return format.AdministrativeIndex{}, contract.ErrRecord
	}
	if ownershipChanged {
		views := make(map[format.Ref]format.RequiredSupportPageView)
		for _, page := range next.Pages {
			if !page.ReadRequired {
				continue
			}
			view, err := s.administrativeSelectedSupportPage(page)
			if err != nil {
				return format.AdministrativeIndex{}, err
			}
			views[page.Ref] = view
		}
		if err := rechargeEndWorkGroups(&next, views); err != nil {
			return format.AdministrativeIndex{}, err
		}
	}
	return next, nil
}
