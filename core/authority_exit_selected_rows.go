package core

import (
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Administrative exits use authenticated row lengths and fragment identities
// without retaining selected fragment payloads.
type administrativeSelectedRow struct {
	summary  format.AdministrativeRowSummary
	physical uint16
	blob     contract.ID
}

func (s *StateSession) administrativeSelectedFragmentFact(ref format.Ref, logical, physical uint16,
	id contract.ID) (selectedFragmentFact, error) {
	position, found := s.selectedSupportPosition(ref)
	if !found || position >= len(s.adminIndex.Pages) || s.adminIndex.Pages[position].Ref != ref ||
		logical > 255 || int(logical) >= len(s.supportFacts[position].rows) ||
		int(logical) >= len(s.supportFacts[position].ordinals) ||
		s.supportFacts[position].ordinals[logical] != physical {
		return selectedFragmentFact{}, contract.ErrRecord
	}
	want := s.supportFacts[position].rows[logical]
	if want.Kind() != contract.GeneratedFragmentSupportKind || want.RecordID() != id {
		return selectedFragmentFact{}, contract.ErrRecord
	}
	var match selectedFragmentFact
	seen := false
	for _, location := range s.root.Generated.Fragments {
		if location.SupportPageIndex != ref.Index || location.RowSlot != uint8(logical) {
			continue
		}
		fact, ok := s.fragmentFacts[location]
		fragmentID, err := contract.GeneratorFragmentID(location.BlobID, location.FragmentIndex)
		if seen || !ok || err != nil || fragmentID != id || fact.ref != ref || fact.row != want ||
			fact.physical != physical || fact.logical != uint8(logical) ||
			fact.blob != location.BlobID || fact.index != location.FragmentIndex {
			return selectedFragmentFact{}, contract.ErrRecord
		}
		match, seen = fact, true
	}
	if !seen {
		return selectedFragmentFact{}, contract.ErrRecord
	}
	return match, nil
}

// The predecessor index supplies optional summaries; the selected facts bind
// every summary to its exact page Ref and physical ordinal.
func (s *StateSession) administrativeSelectedRows(page format.AdministrativePage) ([]administrativeSelectedRow, error) {
	view, err := s.administrativeSelectedSupportPage(page)
	if err != nil {
		return nil, err
	}
	position := slices.IndexFunc(s.adminIndex.Pages, func(old format.AdministrativePage) bool { return old.Ref == page.Ref })
	if position < 0 {
		return nil, contract.ErrRecord
	}
	old := s.adminIndex.Pages[position]
	withFacts := len(s.supportFacts) != 0
	var facts selectedSupportPageFacts
	if withFacts {
		if position >= len(s.supportFacts) || s.supportFacts[position].ref != page.Ref {
			return nil, contract.ErrRecord
		}
		facts = s.supportFacts[position]
	}
	rows := make([]administrativeSelectedRow, 0, len(page.Rows))
	selected := 0
	for _, span := range page.Spans {
		for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
			oldLogical, ok := administrativeSelectedOrdinal(old, uint16(ordinal))
			if !ok {
				return nil, contract.ErrRecord
			}
			var fact contract.SupportRecordDigest
			if withFacts {
				if int(oldLogical) >= len(facts.rows) || int(oldLogical) >= len(facts.ordinals) ||
					facts.ordinals[oldLogical] != uint16(ordinal) {
					return nil, contract.ErrRecord
				}
				fact = facts.rows[oldLogical]
			}
			if selected >= len(view.Records) {
				return nil, contract.ErrRecord
			}
			row := view.Records[selected]
			summary := format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID,
				BodyLength: uint32(len(row.Body))}
			if !page.ReadRequired {
				if selected >= len(page.Rows) {
					return nil, contract.ErrRecord
				}
				summary = page.Rows[selected]
			}
			planned, err := facts.plannedReceipt.matches(s, row)
			if err != nil {
				return nil, err
			}
			if planned && (fact != (contract.SupportRecordDigest{}) || page.ReadRequired || !span.Mandatory || len(span.GroupIndexes) != 0) {
				return nil, contract.ErrRecord
			}
			if withFacts && !planned {
				if page.ReadRequired && row.Kind == contract.GeneratedFragmentSupportKind && row.Body == nil {
					summary.BodyLength = fact.BodyLength()
				}
				if summary.Kind != fact.Kind() || summary.RecordID != fact.RecordID() ||
					summary.BodyLength != fact.BodyLength() {
					return nil, contract.ErrRecord
				}
			}
			if row.Kind != summary.Kind || row.RecordID != summary.RecordID ||
				row.Body != nil && !summary.MatchesRecord(contract.SupportRecord(row)) {
				return nil, contract.ErrRecord
			}
			entry := administrativeSelectedRow{summary: summary, physical: uint16(ordinal)}
			if summary.Kind == contract.GeneratedFragmentSupportKind {
				if row.Body == nil {
					fragment, factErr := s.administrativeSelectedFragmentFact(page.Ref, oldLogical, uint16(ordinal), row.RecordID)
					if factErr != nil || fragment.row.BodyLength() != summary.BodyLength {
						return nil, contract.ErrRecord
					}
					entry.blob = fragment.blob
				} else {
					fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
					if inspectErr != nil {
						return nil, inspectErr
					}
					entry.blob = fragment.BlobID
				}
			} else if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body == nil {
				if !withFacts || !s.selectedOutputComplete() || !span.Mandatory || len(span.GroupIndexes) != 0 {
					return nil, contract.ErrRecord
				}
			} else if row.Body == nil && publicationSupportKind(row.Kind) {
				fact, err := s.publicationRecord(contract.SupportRecord(row))
				if err != nil || fact.digest.BodyLength() != summary.BodyLength {
					return nil, contract.ErrRecord
				}
			} else if row.Body == nil && summary.BodyLength != 0 {
				return nil, contract.ErrRecord
			}
			rows = append(rows, entry)
			selected++
		}
	}
	if selected != len(view.Records) || !page.ReadRequired && selected != len(page.Rows) {
		return nil, contract.ErrRecord
	}
	return rows, nil
}
