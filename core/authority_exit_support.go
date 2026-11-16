package core

import (
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Receipt rows and their ordered-index fragment are replaced as one set. A
// signed predecessor can place them beside other mandatory nonfragment rows,
// so unchanged rows keep their exact page reference and physical ordinal.
// Optional work pages need no read for this operation.
func (s *StateSession) administrativeWorkWithoutOldReceipts(index format.AdministrativeIndex) (format.AdministrativeIndex, error) {
	oldIndex, err := s.receiptIndexID()
	if err != nil || !index.Valid() {
		return format.AdministrativeIndex{}, contract.ErrRecord
	}
	kept := index
	kept.Pages = nil
	for _, page := range index.Pages {
		original := slices.IndexFunc(s.adminIndex.Pages, func(old format.AdministrativePage) bool { return old.Ref == page.Ref })
		if original < 0 {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
		if !slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
			kept.Pages = append(kept.Pages, page)
			continue
		}
		selected, err := s.administrativeSelectedRows(page)
		if err != nil {
			return format.AdministrativeIndex{}, err
		}
		if page.ReadRequired {
			if slices.ContainsFunc(selected, func(row administrativeSelectedRow) bool {
				return row.summary.Kind == contract.MutationReceiptSupportKind ||
					row.summary.Kind == contract.GeneratedFragmentSupportKind
			}) {
				return format.AdministrativeIndex{}, contract.ErrRecord
			}
			kept.Pages = append(kept.Pages, page)
			continue
		}
		projected := format.AdministrativePage{Ref: page.Ref}
		rowIndex, removed := 0, false
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				if rowIndex >= len(selected) {
					return format.AdministrativeIndex{}, contract.ErrRecord
				}
				row := selected[rowIndex]
				summary := row.summary
				rowIndex++
				drop := summary.Kind == contract.MutationReceiptSupportKind
				if summary.Kind == contract.GeneratedFragmentSupportKind && !oldIndex.IsZero() {
					drop = row.blob == oldIndex
				}
				if drop {
					if !span.Mandatory || len(span.GroupIndexes) != 0 {
						return format.AdministrativeIndex{}, contract.ErrRecord
					}
					removed = true
					continue
				}
				projected.Rows = append(projected.Rows, summary)
				if count := len(projected.Spans); count != 0 &&
					uint32(projected.Spans[count-1].First)+uint32(projected.Spans[count-1].Count) == ordinal &&
					projected.Spans[count-1].Mandatory == span.Mandatory &&
					slices.Equal(projected.Spans[count-1].GroupIndexes, span.GroupIndexes) {
					projected.Spans[count-1].Count++
				} else {
					projected.Spans = append(projected.Spans, format.AdministrativeSpan{First: uint16(ordinal), Count: 1,
						Mandatory: span.Mandatory, GroupIndexes: slices.Clone(span.GroupIndexes)})
				}
			}
		}
		if rowIndex != len(selected) {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
		if !removed {
			kept.Pages = append(kept.Pages, page)
		} else if len(projected.Spans) != 0 {
			kept.Pages = append(kept.Pages, projected)
		}
	}
	if !kept.Valid() {
		return format.AdministrativeIndex{}, contract.ErrRecord
	}
	return kept, nil
}

// A selected administrative page retains physical ordinals in its index. Its
// decoded view contains only selected logical rows; optional views are empty.
func (s *StateSession) administrativeSelectedSupportPage(page format.AdministrativePage) (format.RequiredSupportPageView, error) {
	position := slices.IndexFunc(s.adminIndex.Pages, func(old format.AdministrativePage) bool { return old.Ref == page.Ref })
	if position < 0 || position >= len(s.support) {
		return format.RequiredSupportPageView{}, contract.ErrRecord
	}
	old := s.adminIndex.Pages[position]
	view := s.support[position]
	out := format.RequiredSupportPageView{Domain: view.Domain, Object: view.Object, Index: view.Index}
	if view.Domain != page.Ref.Domain || view.Object != page.Ref.Object || view.Index != page.Ref.Index {
		return format.RequiredSupportPageView{}, contract.ErrRecord
	}
	if len(s.supportFacts) != 0 {
		if len(s.supportFacts) != len(s.support) || s.supportFacts[position].ref != page.Ref {
			return format.RequiredSupportPageView{}, contract.ErrRecord
		}
		facts := s.supportFacts[position]
		if facts.plannedReceipt != nil && facts.plannedReceipt.owner != s {
			return format.RequiredSupportPageView{}, contract.ErrRecord
		}
		if len(facts.rows) == 0 && len(facts.ordinals) == 0 && len(view.Records) == 0 {
			if old.ReadRequired || page.ReadRequired ||
				slices.ContainsFunc(old.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) ||
				slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
				return format.RequiredSupportPageView{}, contract.ErrRecord
			}
			return out, nil
		}
		if len(facts.rows) != len(facts.ordinals) || old.ReadRequired && len(view.Records) != len(facts.rows) {
			return format.RequiredSupportPageView{}, contract.ErrRecord
		}
		for i, fact := range facts.rows {
			if i >= len(view.Records) {
				return format.RequiredSupportPageView{}, contract.ErrRecord
			}
			planned, err := facts.plannedReceipt.matches(s, view.Records[i])
			if err != nil {
				return format.RequiredSupportPageView{}, err
			}
			if planned {
				mandatory := slices.ContainsFunc(old.Spans, func(span format.AdministrativeSpan) bool {
					return span.Mandatory && len(span.GroupIndexes) == 0 && uint32(i) >= uint32(span.First) && uint32(i) < uint32(span.First)+uint32(span.Count)
				})
				if old.ReadRequired || !mandatory || fact != (contract.SupportRecordDigest{}) || facts.ordinals[i] != uint16(i) {
					return format.RequiredSupportPageView{}, contract.ErrRecord
				}
				continue
			}
			if i >= len(view.Records) || view.Records[i].Kind != fact.Kind() ||
				view.Records[i].RecordID != fact.RecordID() {
				return format.RequiredSupportPageView{}, contract.ErrRecord
			}
			row := view.Records[i]
			if row.Kind == contract.GeneratedFragmentSupportKind && row.Body == nil {
				fragment, err := s.administrativeSelectedFragmentFact(page.Ref, uint16(i), facts.ordinals[i], row.RecordID)
				if err != nil || fragment.row != fact {
					return format.RequiredSupportPageView{}, contract.ErrRecord
				}
			} else if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body == nil {
				logical, selected := administrativeSelectedOrdinal(old, facts.ordinals[i])
				mandatory := slices.ContainsFunc(old.Spans, func(span format.AdministrativeSpan) bool {
					return span.Mandatory && len(span.GroupIndexes) == 0 &&
						uint32(facts.ordinals[i]) >= uint32(span.First) &&
						uint32(facts.ordinals[i]) < uint32(span.First)+uint32(span.Count)
				})
				if old.ReadRequired || !selected || int(logical) != i || !mandatory || !s.selectedOutputComplete() {
					return format.RequiredSupportPageView{}, contract.ErrRecord
				}
			} else if row.Body == nil && publicationSupportKind(row.Kind) {
				publication, err := s.publicationRecord(contract.SupportRecord(row))
				if err != nil || publication.digest != fact {
					return format.RequiredSupportPageView{}, contract.ErrRecord
				}
			} else if uint32(len(row.Body)) != fact.BodyLength() || contract.Hash(row.Body) != fact.BodyDigest() {
				return format.RequiredSupportPageView{}, contract.ErrRecord
			}
		}
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				logical := slices.Index(facts.ordinals, uint16(ordinal))
				if logical < 0 {
					return format.RequiredSupportPageView{}, contract.ErrRecord
				}
				row := view.Records[logical]
				if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body == nil &&
					(page.ReadRequired || !span.Mandatory || len(span.GroupIndexes) != 0) {
					return format.RequiredSupportPageView{}, contract.ErrRecord
				}
				out.Records = append(out.Records, row)
			}
		}
		return out, nil
	}
	if len(view.Records) == 0 {
		if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
			return format.RequiredSupportPageView{}, contract.ErrRecord
		}
		return out, nil
	}
	for _, span := range page.Spans {
		for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
			logical, ok := administrativeSelectedOrdinal(old, uint16(ordinal))
			if !ok || int(logical) >= len(view.Records) {
				return format.RequiredSupportPageView{}, contract.ErrRecord
			}
			out.Records = append(out.Records, view.Records[logical])
		}
	}
	return out, nil
}

// removedAdministrativeSupport is the exact old selected row set that no
// longer appears in the successor. The digest includes the immutable page and
// physical ordinal, so equal record IDs on different page references cannot
// stand in for each other.
func (s *StateSession) removedAdministrativeSupport(after format.AdministrativeIndex) (contract.GeneratorDescriptor, error) {
	if s == nil || !s.adminIndex.Valid() || !after.Valid() {
		return contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	var removed [][]byte
	for _, old := range s.adminIndex.Pages {
		var selected []administrativeSelectedRow
		if old.ReadRequired {
			var err error
			selected, err = s.administrativeSelectedRows(old)
			if err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		}
		now := slices.IndexFunc(after.Pages, func(page format.AdministrativePage) bool { return page.Ref == old.Ref })
		row := 0
		for _, span := range old.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				if now >= 0 {
					if _, selected := administrativeSelectedOrdinal(after.Pages[now], uint16(ordinal)); selected {
						row++
						continue
					}
				}
				var summary format.AdministrativeRowSummary
				if old.ReadRequired {
					if row >= len(selected) {
						return contract.GeneratorDescriptor{}, contract.ErrRecord
					}
					summary = selected[row].summary
				} else {
					if row >= len(old.Rows) {
						return contract.GeneratorDescriptor{}, contract.ErrRecord
					}
					summary = old.Rows[row]
				}
				item := make([]byte, 0, 32+2+2+1+32+4)
				item = append(item, old.Ref.Digest[:]...)
				item = binary.BigEndian.AppendUint16(item, old.Ref.Index)
				item = binary.BigEndian.AppendUint16(item, uint16(ordinal))
				item = append(item, summary.Kind)
				item = append(item, summary.RecordID[:]...)
				item = binary.BigEndian.AppendUint32(item, summary.BodyLength)
				removed = append(removed, item)
				row++
			}
		}
	}
	if len(removed) == 0 {
		return contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	return administrativeDescriptor("removed-selected-support", removed...), nil
}
