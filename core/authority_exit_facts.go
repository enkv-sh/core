package core

import (
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// An exit changes selected rows without rewriting every retained page. Bind
// its prospective facts to the final index before another exit is planned.
// Unchanged pages retain physical ordinals; new pages use their owned bytes.
// Optional unreadable pages retain only their exact Ref and index summaries.
func (s *StateSession) bindEndWorkSupportFacts(next *StateSession, images []objectImage) error {
	return s.bindEndWorkSupportFactsInput(next, images, nil)
}

func (s *StateSession) bindPublicationSupportFacts(next *StateSession, images []objectImage, construction *publicationConstruction) error {
	if construction == nil || !construction.consumed {
		return contract.ErrRecord
	}
	if err := s.bindEndWorkSupportFactsInput(next, images, construction); err != nil {
		return err
	}
	construction.emissionChecked = s.fragmentFacts != nil
	return nil
}

func (s *StateSession) bindEndWorkSupportFactsInput(next *StateSession, images []objectImage, construction *publicationConstruction) error {
	if s == nil || next == nil || s.root.Domain != next.root.Domain {
		return contract.ErrRecord
	}
	if s.fragmentFacts == nil {
		if len(s.supportFacts) != 0 {
			return contract.ErrRecord
		}
		next.generatedWork, next.generatedSliceLocations, next.generatedSlicesRoot = nil, nil, contract.ID{}
		return nil
	}
	if len(s.supportFacts) != len(s.root.RequiredSupport) || len(s.support) != len(s.supportFacts) ||
		len(s.adminIndex.Pages) != len(s.supportFacts) || !next.adminIndex.Valid() ||
		len(next.root.RequiredSupport) != len(next.support) || len(next.adminIndex.Pages) != len(next.support) {
		return contract.ErrRecord
	}
	prior := make(map[format.Ref]int, len(s.supportFacts))
	for i, facts := range s.supportFacts {
		if facts.ref != s.root.RequiredSupport[i] || facts.ref != s.adminIndex.Pages[i].Ref ||
			len(facts.rows) != len(facts.ordinals) || len(facts.rows) != len(s.support[i].Records) {
			return contract.ErrRecord
		}
		for logical, physical := range facts.ordinals {
			slot, selected := administrativeSelectedOrdinal(s.adminIndex.Pages[i], physical)
			if !selected || slot != uint16(logical) || logical > 0 && physical <= facts.ordinals[logical-1] {
				return contract.ErrRecord
			}
		}
		if _, duplicate := prior[facts.ref]; duplicate {
			return contract.ErrRecord
		}
		prior[facts.ref] = i
	}
	owned := make(map[format.Ref][]byte)
	for _, image := range images {
		if image.ref.Kind != contract.RequiredSupportKind {
			continue
		}
		if _, duplicate := owned[image.ref]; duplicate {
			return contract.ErrRecord
		}
		owned[image.ref] = image.body
	}
	facts := make([]selectedSupportPageFacts, len(next.support))
	byIndex := make(map[uint16]int, len(next.support))
	knownFragments := 0
	for i, page := range next.adminIndex.Pages {
		ref, view := next.root.RequiredSupport[i], next.support[i]
		if page.Ref != ref || view.Domain != ref.Domain || view.Object != ref.Object || view.Index != ref.Index {
			return contract.ErrRecord
		}
		if _, duplicate := byIndex[ref.Index]; duplicate {
			return contract.ErrRecord
		}
		byIndex[ref.Index] = i
		facts[i].ref = ref
		oldPosition, retained := prior[ref]
		if retained && len(view.Records) == 0 {
			if len(s.supportFacts[oldPosition].rows) != 0 || page.ReadRequired ||
				slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
				return contract.ErrRecord
			}
			continue
		}
		var physical []contract.SupportRecordView
		if !retained {
			body, present := owned[ref]
			if !present || uint64(len(body)) != uint64(ref.Length) || contract.Hash(body) != ref.Digest {
				return contract.ErrRecord
			}
			if construction == nil {
				decoded, err := format.InspectRequiredSupportPage(body)
				if err != nil || decoded.Domain != ref.Domain || decoded.Object != ref.Object || decoded.Index != ref.Index {
					return contract.ErrRecord
				}
				physical = decoded.Records
			} else {
				var err error
				physical, err = construction.physical(ref, body)
				if err != nil {
					return err
				}
			}
		}
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				logical := len(facts[i].rows)
				if logical >= len(view.Records) {
					return contract.ErrRecord
				}
				row := view.Records[logical]
				var fact contract.SupportRecordDigest
				if retained {
					old := s.supportFacts[oldPosition]
					slot := slices.Index(old.ordinals, uint16(ordinal))
					if slot < 0 {
						return contract.ErrRecord
					}
					fact = old.rows[slot]
				} else {
					if int(ordinal) >= len(physical) {
						return contract.ErrRecord
					}
					var err error
					fact, err = construction.rowFact(s.root.Domain, contract.SupportRecord(physical[ordinal]))
					if err != nil {
						return err
					}
				}
				if row.Kind != fact.Kind() || row.RecordID != fact.RecordID() {
					return contract.ErrRecord
				}
				if row.Body == nil {
					if !retained || !opaqueSupportKind(row.Kind) && !publicationSupportKind(row.Kind) {
						return contract.ErrRecord
					}
				} else if actual, err := construction.rowFact(s.root.Domain, contract.SupportRecord(row)); err != nil || actual != fact {
					return contract.ErrRecord
				}
				if !page.ReadRequired {
					summary := page.Rows[logical]
					if summary.Kind != fact.Kind() || summary.RecordID != fact.RecordID() || summary.BodyLength != fact.BodyLength() || row.Body != nil && !summary.MatchesRecord(contract.SupportRecord(row)) {
						return contract.ErrRecord
					}
				}
				facts[i].rows = append(facts[i].rows, fact)
				facts[i].ordinals = append(facts[i].ordinals, uint16(ordinal))
				if row.Kind == contract.GeneratedFragmentSupportKind {
					knownFragments++
				}
			}
		}
		if len(facts[i].rows) != len(view.Records) {
			return contract.ErrRecord
		}
	}
	fragments := make(map[format.FragmentLocation]selectedFragmentFact, knownFragments)
	for _, location := range next.root.Generated.Fragments {
		position, present := byIndex[location.SupportPageIndex]
		if !present {
			return contract.ErrRecord
		}
		page, pageFacts := next.adminIndex.Pages[position], facts[position]
		id, err := contract.GeneratorFragmentID(location.BlobID, location.FragmentIndex)
		if err != nil {
			return err
		}
		if len(pageFacts.rows) == 0 {
			if int(location.RowSlot) >= len(page.Rows) || page.Rows[location.RowSlot].Kind != contract.GeneratedFragmentSupportKind ||
				page.Rows[location.RowSlot].RecordID != id {
				return contract.ErrRecord
			}
			continue // This exact retained optional page remains opaque.
		}
		if int(location.RowSlot) >= len(pageFacts.rows) {
			return contract.ErrRecord
		}
		row, digest := next.support[position].Records[location.RowSlot], pageFacts.rows[location.RowSlot]
		if row.Kind != contract.GeneratedFragmentSupportKind || row.RecordID != id {
			return contract.ErrRecord
		}
		fact := selectedFragmentFact{ref: pageFacts.ref, row: digest, physical: pageFacts.ordinals[location.RowSlot],
			logical: uint16(location.RowSlot), blob: location.BlobID, index: location.FragmentIndex}
		if row.Body == nil {
			oldPosition, retained := prior[pageFacts.ref]
			if !retained {
				return contract.ErrRecord
			}
			oldLogical := slices.Index(s.supportFacts[oldPosition].ordinals, fact.physical)
			if oldLogical < 0 || oldLogical > 255 {
				return contract.ErrRecord
			}
			oldLocation := location
			oldLocation.RowSlot = uint8(oldLogical)
			old, found := s.fragmentFacts[oldLocation]
			if !found || old.ref != fact.ref || old.row != digest || old.physical != fact.physical ||
				int(old.logical) != oldLogical || old.blob != fact.blob || old.index != fact.index {
				return contract.ErrRecord
			}
			fact = old
			fact.logical = uint16(location.RowSlot)
		} else {
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil || fragment.BlobID != location.BlobID || fragment.Index != location.FragmentIndex {
				return contract.ErrRecord
			}
			fact.count, fact.total, fact.whole = fragment.Count, fragment.TotalLength, fragment.WholeDigest
			fact.offset, fact.payloadLength = fragment.Offset, uint32(len(fragment.Payload))
		}
		if _, duplicate := fragments[location]; duplicate {
			return contract.ErrRecord
		}
		fragments[location] = fact
	}
	if len(fragments) != knownFragments {
		return contract.ErrRecord
	}
	next.supportFacts, next.fragmentFacts = facts, fragments
	next.generatedWork, next.generatedSliceLocations, next.generatedSlicesRoot = nil, nil, contract.ID{}
	next.outputConfigurationRoot, next.publicationProof = contract.ID{}, nil
	return nil
}
