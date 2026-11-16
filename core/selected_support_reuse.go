package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Immutable index facts bind a complete ordered authenticated physical Ref set.
// A cached object fact alone does not establish current selection.
type selectedAdministrativeIndexFacts struct {
	refs  []format.Ref
	index format.AdministrativeIndex
}

func (facts *selectedAdministrativeIndexFacts) exact(refs []format.Ref) bool {
	return facts != nil && slices.Equal(facts.refs, refs)
}

// Reuse keeps the current index's selected subset of already authenticated
// physical ordinals. New ordinals require an ordinary page read; a conflicting
// summary for a known ordinal is an integrity failure.
func reuseSelectedSupportPage(previous *selectedImage, page format.AdministrativePage) (format.RequiredSupportPageView, selectedSupportPageFacts, bool, error) {
	var empty format.RequiredSupportPageView
	var noFacts selectedSupportPageFacts
	if previous == nil || len(previous.support) != len(previous.root.RequiredSupport) || len(previous.supportFacts) != len(previous.support) || len(previous.adminIndex.Pages) != len(previous.support) {
		return empty, noFacts, false, nil
	}
	position := slices.Index(previous.root.RequiredSupport, page.Ref)
	if position < 0 {
		return empty, noFacts, false, nil
	}
	prior := previous.adminIndex.Pages[position]
	view, facts := previous.support[position], previous.supportFacts[position]
	if prior.Ref != page.Ref || facts.ref != page.Ref || facts.plannedReceipt != nil || len(facts.rows) != len(facts.ordinals) || len(facts.rows) != len(view.Records) {
		return empty, noFacts, false, contract.ErrRecord
	}
	if len(view.Records) == 0 || prior.ReadRequired || slices.ContainsFunc(view.Records, func(row contract.SupportRecordView) bool { return row.Kind == contract.GeneratedFragmentSupportKind }) {
		return empty, noFacts, false, nil
	}
	if page.ReadRequired || len(prior.Rows) != len(facts.rows) {
		return empty, noFacts, false, contract.ErrRecord
	}
	projected := selectedSupportPageFacts{ref: page.Ref}
	logical := 0
	for _, span := range page.Spans {
		for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
			old, present := slices.BinarySearch(facts.ordinals, uint16(ordinal))
			if !present {
				return empty, noFacts, false, nil
			}
			if logical >= len(page.Rows) || page.Rows[logical] != prior.Rows[old] || facts.rows[old].Kind() != prior.Rows[old].Kind || facts.rows[old].RecordID() != prior.Rows[old].RecordID || facts.rows[old].BodyLength() != prior.Rows[old].BodyLength {
				return empty, noFacts, false, contract.ErrRecord
			}
			projected.rows = append(projected.rows, facts.rows[old])
			projected.ordinals = append(projected.ordinals, uint16(ordinal))
			logical++
		}
	}
	if logical != len(page.Rows) {
		return empty, noFacts, false, contract.ErrRecord
	}
	source := &StateSession{root: previous.root, support: previous.support, supportFacts: previous.supportFacts,
		adminIndex: previous.adminIndex, fragmentFacts: previous.fragmentFacts, publicationFacts: previous.publicationFacts,
		outputConfigurationRoot: previous.outputConfigurationRoot}
	retained, err := source.administrativeSelectedSupportPage(page)
	if err != nil {
		return empty, noFacts, false, err
	}
	if slices.ContainsFunc(retained.Records, func(row contract.SupportRecordView) bool { return publicationSupportKind(row.Kind) && row.Body != nil }) {
		for i, row := range retained.Records {
			if !publicationSupportKind(row.Kind) {
				retained.Records[i].Body = bytes.Clone(row.Body)
			}
		}
	}
	return retained, projected, true, nil
}

// cacheCandidateAdministrativeIndex replaces only a complete verified physical
// cache tuple. Current selection still requires an independently authenticated
// HEAD/Root and all ordinary selected-image relation checks.
func (s *StateSession) cacheCandidateAdministrativeIndex(candidate *Candidate) error {
	if !s.replacementRead {
		return nil
	}
	if candidate == nil || candidate.session != s {
		return contract.ErrRecord
	}
	rootRef := candidate.head.Core.Root
	body, present := s.cache[rootRef]
	if !present || format.CheckReference(rootRef, body) != nil {
		return contract.ErrRecord
	}
	root, err := format.DecodeRoot(body)
	if err != nil || root.Domain != s.admission.domain || root.Snapshot != rootRef.Object {
		return contract.ErrRecord
	}
	refs := append([]format.Ref{root.AdministrativeIndex}, root.AdministrativeIndexShards...)
	fact := s.administrativeIndexFacts
	if !fact.exact(refs) {
		pages := make([]format.AdministrativeIndexPage, len(refs))
		for i, ref := range refs {
			body, present := s.cache[ref]
			if !present {
				return contract.ErrRecord
			}
			pages[i] = format.AdministrativeIndexPage{Ref: ref, Body: body}
		}
		index, err := format.DecodeAdministrativeIndexPages(pages)
		if err != nil {
			return err
		}
		fact = &selectedAdministrativeIndexFacts{refs: slices.Clone(refs), index: index}
	}
	if fact.index.Domain != root.Domain || fact.index.Object != root.AdministrativeIndex.Object || len(fact.index.Pages) != len(root.RequiredSupport) {
		return contract.ErrRecord
	}
	for i, page := range fact.index.Pages {
		if page.Ref != root.RequiredSupport[i] {
			return contract.ErrRecord
		}
	}
	// Publish only after the whole tuple passes. A partial persist or corrupt
	// cached tuple leaves both the predecessor fact and verified bytes intact.
	s.cachedAdministrativeIndexFacts = fact
	for _, ref := range refs {
		delete(s.cache, ref)
	}
	return nil
}
