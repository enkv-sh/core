package core

import (
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Older indexes let inbox provenance own seeds and Intents. A release needs
// its Attempt and graph, but never those private-operation inputs. Correct
// the successor ownership using readable Slice carriers and fragment IDs;
// the authenticated predecessor remains the physical-row reference.
func (s *StateSession) administrativeDispositionPages() ([]format.AdministrativePage, bool, error) {
	releases := make([]bool, len(s.adminIndex.Groups))
	for i, group := range s.adminIndex.Groups {
		releases[i] = group.OwnerKind == format.AdministrativeInboxRelease
	}
	if !slices.Contains(releases, true) {
		return s.adminIndex.Pages, false, nil
	}
	intentRows := make(map[contract.ID]bool)
	blobOwners := make(map[contract.ID][]uint16)
	for _, page := range s.adminIndex.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil {
			return nil, false, err
		}
		logical := 0
		for _, span := range page.Spans {
			for n := uint16(0); n < span.Count; n++ {
				if logical >= len(view.Records) {
					return nil, false, contract.ErrRecord
				}
				row := view.Records[logical]
				logical++
				carrier, match, err := snapshotSliceRecord(contract.SupportRecord(row), s.root.Domain, s.adminIndex.SliceSnapshot)
				if err != nil || !match {
					return nil, false, contract.ErrRecord
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					return nil, false, err
				}
				if location.ContentKind == contract.GeneratorContentIntent {
					intentRows[row.RecordID] = true
					continue
				}
				for _, group := range span.GroupIndexes {
					if releases[group] && !slices.Contains(blobOwners[location.BlobID], group) {
						blobOwners[location.BlobID] = append(blobOwners[location.BlobID], group)
					}
				}
			}
		}
		if logical != len(view.Records) {
			return nil, false, contract.ErrRecord
		}
	}
	fragments := make(map[contract.ID]contract.ID, len(s.root.Generated.Fragments))
	for _, location := range s.root.Generated.Fragments {
		id, err := contract.GeneratorFragmentID(location.BlobID, location.FragmentIndex)
		if err != nil {
			return nil, false, err
		}
		fragments[id] = location.BlobID
	}
	pages := slices.Clone(s.adminIndex.Pages)
	changed := false
	for i, page := range pages {
		pages[i].Spans = nil
		logical := 0
		for _, span := range page.Spans {
			for n := uint16(0); n < span.Count; n++ {
				var kind contract.SupportRecordKind
				var id contract.ID
				if page.ReadRequired {
					row := s.support[i].Records[logical]
					kind, id = row.Kind, row.RecordID
				} else {
					row := page.Rows[logical]
					kind, id = row.Kind, row.RecordID
				}
				logical++
				one := span
				one.First, one.Count, one.GroupIndexes = span.First+n, 1, nil
				for _, group := range span.GroupIndexes {
					remove := releases[group] && (kind == contract.OperationMaterialSupportKind ||
						kind == contract.GeneratorVectorSupportKind && intentRows[id] ||
						kind == contract.GeneratedFragmentSupportKind && !slices.Contains(blobOwners[fragments[id]], group))
					if remove {
						changed = true
					} else {
						one.GroupIndexes = append(one.GroupIndexes, group)
					}
				}
				if last := len(pages[i].Spans) - 1; last >= 0 {
					previous := &pages[i].Spans[last]
					if previous.Mandatory == one.Mandatory && slices.Equal(previous.GroupIndexes, one.GroupIndexes) &&
						uint32(previous.First)+uint32(previous.Count) == uint32(one.First) && previous.Count < ^uint16(0) {
						previous.Count++
						continue
					}
				}
				pages[i].Spans = append(pages[i].Spans, one)
			}
		}
	}
	return pages, changed, nil
}
