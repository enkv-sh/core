package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type selectedOutputLocation struct {
	page, ordinal int
	fact          contract.SupportRecordDigest
}

// validateSelectedOutputConfiguration rereads one authenticated physical page
// at a time. The selected row facts were made only after the complete ordinary
// page inspection. A missing slice can never mean an empty configuration.
func (s *StateSession) validateSelectedOutputConfiguration(ctx context.Context) Result {
	return s.validateSelectedOutputConfigurationRelations(ctx, nil)
}

func (s *StateSession) validateSelectedOutputConfigurationRelations(ctx context.Context, visit *contract.OutputConfigurationVisit) Result {
	if s == nil {
		return refused(AdmissionInvalid)
	}
	image := s.selectedImage()
	result := validateSelectedOutputConfiguration(ctx, image, s.selectedObjectReader(), visit)
	if result.Outcome == 0 {
		s.outputConfigurationRoot = image.outputConfigurationRoot
	}
	return result
}

type selectedOutputConfigurationReader struct {
	image  *selectedImage
	reader selectedObjectReader
}

func (r selectedOutputConfigurationReader) validateSelectedOutputConfigurationRelations(ctx context.Context, visit *contract.OutputConfigurationVisit) Result {
	return validateSelectedOutputConfiguration(ctx, r.image, r.reader, visit)
}
func validateSelectedOutputConfiguration(ctx context.Context, s *selectedImage, reader selectedObjectReader, visit *contract.OutputConfigurationVisit) Result {
	if s == nil {
		return refused(AdmissionInvalid)
	}
	_, result := selectedOutputConfigurationWithReader(ctx, s.root, s.supportFacts, reader, false, visit)
	if result.Outcome != 0 {
		return result
	}
	root, err := format.EncodeRoot(s.root)
	if err != nil {
		return failure(IntegrityFailure, InvalidRelation)
	}
	s.outputConfigurationRoot = contract.Hash(root)
	return Result{}
}

func selectedOutputConfigurationWithReader(ctx context.Context, root format.Root, facts []selectedSupportPageFacts, reader selectedObjectReader, materialize bool, visit *contract.OutputConfigurationVisit) (contract.OutputConfiguration, Result) {
	s := &selectedImage{root: root, supportFacts: facts}
	if ctx == nil || ctx.Err() != nil || root.Domain != reader.domain || len(s.supportFacts) != len(s.root.RequiredSupport) {
		return contract.OutputConfiguration{}, refused(AdmissionInvalid)
	}
	count := int(s.root.OutputConfiguration.SliceCount)
	if count < 1 || count > contract.MaxOutputConfigurationSlices {
		return contract.OutputConfiguration{}, failure(IntegrityFailure, InvalidRelation)
	}
	locations := make(map[contract.ID]selectedOutputLocation, count)
	selectedCount := 0
	for pageIndex, page := range s.supportFacts {
		if page.ref != s.root.RequiredSupport[pageIndex] || len(page.rows) != len(page.ordinals) {
			return contract.OutputConfiguration{}, failure(IntegrityFailure, InvalidRelation)
		}
		for rowIndex, fact := range page.rows {
			if fact.Kind() != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			if _, duplicate := locations[fact.RecordID()]; duplicate {
				return contract.OutputConfiguration{}, failure(IntegrityFailure, InvalidRelation)
			}
			locations[fact.RecordID()] = selectedOutputLocation{page: pageIndex, ordinal: int(page.ordinals[rowIndex]), fact: fact}
			selectedCount++
		}
	}
	if selectedCount != count {
		return contract.OutputConfiguration{}, failure(IntegrityFailure, InvalidRelation)
	}
	var readResult Result
	source := func(index uint16) (contract.OutputConfigurationSlice, error) {
		id, err := contract.OutputConfigurationSliceID(s.root.Domain, s.root.OutputConfiguration.ConfigurationDigest, index)
		if err != nil {
			return contract.OutputConfigurationSlice{}, err
		}
		location, present := locations[id]
		if !present {
			return contract.OutputConfigurationSlice{}, contract.ErrRecord
		}
		ref := s.root.RequiredSupport[location.page]
		uncached := reader
		uncached.cache = nil
		body, _, result := uncached.readBorrowed(ctx, ref)
		if result.Outcome != 0 {
			readResult = result
			return contract.OutputConfigurationSlice{}, contract.ErrRecord
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil || page.Domain != s.root.Domain || page.Object != ref.Object || page.Index != ref.Index || location.ordinal >= len(page.Records) {
			return contract.OutputConfigurationSlice{}, contract.ErrRecord
		}
		row := page.Records[location.ordinal]
		if row.Kind != location.fact.Kind() || row.RecordID != id || uint32(len(row.Body)) != location.fact.BodyLength() || contract.Hash(row.Body) != location.fact.BodyDigest() {
			return contract.OutputConfigurationSlice{}, contract.ErrRecord
		}
		return contract.InspectOutputConfigurationSlice(row.Body)
	}
	var configuration contract.OutputConfiguration
	var err error
	if visit != nil {
		err = contract.VisitOutputConfigurationSource(s.root.Domain, s.root.OutputConfiguration, source, *visit)
	} else if materialize {
		configuration, err = contract.InspectOutputConfigurationSource(s.root.Domain, s.root.OutputConfiguration, source)
	} else {
		err = contract.ValidateOutputConfigurationSource(s.root.Domain, s.root.OutputConfiguration, source)
	}
	if readResult.Outcome != 0 {
		return contract.OutputConfiguration{}, readResult
	}
	if err != nil {
		return contract.OutputConfiguration{}, failure(IntegrityFailure, InvalidRelation)
	}
	return configuration, Result{}
}

// selectedOutputComplete never joins the complete configuration image. A proof
// is bound to the exact encoded Root; body-backed construction uses the same
// streaming grammar as the ordinary reader.
func (s *StateSession) selectedOutputComplete() bool {
	return s.selectedImage().selectedOutputComplete()
}
func (s *selectedImage) selectedOutputComplete() bool {
	if s == nil || len(s.support) != len(s.root.RequiredSupport) {
		return false
	}
	root, err := format.EncodeRoot(s.root)
	if err != nil {
		return false
	}
	if s.outputConfigurationRoot == contract.Hash(root) {
		return true
	}
	source, err := selectedOutputConfigurationBodySource(s)
	return err == nil && contract.ValidateOutputConfigurationSource(s.root.Domain, s.root.OutputConfiguration, source) == nil
}

func (s *StateSession) outputConfigurationBodySource() (func(uint16) (contract.OutputConfigurationSlice, error), error) {
	return selectedOutputConfigurationBodySource(s.selectedImage())
}
func selectedOutputConfigurationBodySource(s *selectedImage) (func(uint16) (contract.OutputConfigurationSlice, error), error) {
	rows := make(map[contract.ID]contract.OutputConfigurationSlice)
	for _, page := range s.support {
		for _, row := range page.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			if _, duplicate := rows[row.RecordID]; duplicate {
				return nil, contract.ErrRecord
			}
			slice, err := contract.InspectOutputConfigurationSlice(row.Body)
			if err != nil {
				return nil, err
			}
			rows[row.RecordID] = slice
		}
	}
	if len(rows) != int(s.root.OutputConfiguration.SliceCount) {
		return nil, contract.ErrRecord
	}
	return func(index uint16) (contract.OutputConfigurationSlice, error) {
		id, err := contract.OutputConfigurationSliceID(s.root.Domain, s.root.OutputConfiguration.ConfigurationDigest, index)
		slice, ok := rows[id]
		if err != nil || !ok {
			return contract.OutputConfigurationSlice{}, contract.ErrRecord
		}
		return slice, nil
	}, nil
}

func (s *StateSession) onlyOutputConfigurationSupport() bool {
	if s == nil {
		return false
	}
	var count uint16
	if len(s.supportFacts) == len(s.root.RequiredSupport) {
		for i, page := range s.supportFacts {
			if page.ref != s.root.RequiredSupport[i] {
				return false
			}
			for _, row := range page.rows {
				if row.Kind() != contract.OutputConfigurationSliceSupportKind {
					return false
				}
				count++
			}
		}
		return count == s.root.OutputConfiguration.SliceCount
	}
	for _, page := range s.support {
		for _, row := range page.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				return false
			}
			count++
		}
	}
	return count == s.root.OutputConfiguration.SliceCount
}

func (s *StateSession) selectedOutputFactsByRecord() (map[contract.ID]selectedFragmentFact, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	image := &selectedImage{root: s.root, support: s.support, supportFacts: s.supportFacts,
		outputConfigurationRoot: s.outputConfigurationRoot}
	return image.selectedOutputFactsByRecord()
}

// selectedOutputFactsByRecord retains only authenticated identities. It never
// retains a borrowed slice body or treats an absent slice as empty.
func (s *selectedImage) selectedOutputFactsByRecord() (map[contract.ID]selectedFragmentFact, error) {
	out := make(map[contract.ID]selectedFragmentFact)
	if !s.selectedOutputComplete() {
		return nil, contract.ErrRecord
	}
	for position, page := range s.supportFacts {
		if position >= len(s.root.RequiredSupport) || page.ref != s.root.RequiredSupport[position] || len(page.rows) != len(page.ordinals) {
			return nil, contract.ErrRecord
		}
		for logical, row := range page.rows {
			if row.Kind() != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			if logical > 255 {
				return nil, contract.ErrRecord
			}
			if _, exists := out[row.RecordID()]; exists {
				return nil, contract.ErrRecord
			}
			out[row.RecordID()] = selectedFragmentFact{ref: page.ref, row: row, physical: page.ordinals[logical], logical: uint8(logical), blob: s.root.OutputConfiguration.ConfigurationDigest}
		}
	}
	return out, nil
}

func opaqueSupportKind(kind contract.SupportRecordKind) bool {
	return kind == contract.GeneratedFragmentSupportKind || kind == contract.OutputConfigurationSliceSupportKind
}

func (s *StateSession) retainedOutputPage(rows []contract.SupportRecord) (selectedSupportPageFacts, bool) {
	return s.selectedImage().retainedOutputPage(rows)
}
func (s *selectedImage) retainedOutputPage(rows []contract.SupportRecord) (selectedSupportPageFacts, bool) {
	if len(rows) == 0 || !s.selectedOutputComplete() {
		return selectedSupportPageFacts{}, false
	}
	for position, ref := range s.root.RequiredSupport {
		if position >= len(s.support) || len(s.support[position].Records) != len(rows) {
			continue
		}
		var facts selectedSupportPageFacts
		if position < len(s.supportFacts) {
			facts = s.supportFacts[position]
		} else {
			facts.ref = ref
		}
		matches := true
		for slot, row := range rows {
			old := s.support[position].Records[slot]
			if row.Kind != contract.OutputConfigurationSliceSupportKind || old.Kind != row.Kind || old.RecordID != row.RecordID {
				matches = false
				break
			}
			var fact contract.SupportRecordDigest
			if old.Body == nil {
				if facts.ref != ref || slot >= len(facts.rows) || slot >= len(facts.ordinals) || row.Body != nil {
					matches = false
					break
				}
				fact = facts.rows[slot]
			} else {
				var err error
				fact, err = contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(old))
				if err != nil || row.Body == nil || contract.Hash(row.Body) != fact.BodyDigest() {
					matches = false
					break
				}
				if len(s.supportFacts) == 0 {
					facts.rows = append(facts.rows, fact)
					facts.ordinals = append(facts.ordinals, uint16(slot))
				}
			}
			if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
				matches = false
				break
			}
		}
		if matches {
			return facts, true
		}
	}
	return selectedSupportPageFacts{}, false
}

// outputSupportOrdinalCursor follows ordered selected spans without retaining
// row bodies or searching the same spans for every compact logical slot.
type outputSupportOrdinalCursor struct {
	spans   []format.AdministrativeSpan
	span    int
	logical uint32
}

func newOutputSupportOrdinalCursor(page format.AdministrativePage, rows int) (outputSupportOrdinalCursor, error) {
	var selected, end uint32
	for i, span := range page.Spans {
		first, last := uint32(span.First), uint32(span.First)+uint32(span.Count)
		if span.Count == 0 || last > 0x10000 || i > 0 && first < end {
			return outputSupportOrdinalCursor{}, contract.ErrRecord
		}
		selected += uint32(span.Count)
		end = last
	}
	if selected != uint32(rows) {
		return outputSupportOrdinalCursor{}, contract.ErrRecord
	}
	return outputSupportOrdinalCursor{spans: page.Spans}, nil
}

func (c *outputSupportOrdinalCursor) physical(logical int) (uint16, bool) {
	if logical < 0 || uint32(logical) < c.logical {
		return 0, false
	}
	for c.span < len(c.spans) {
		span := c.spans[c.span]
		if uint32(logical) < c.logical+uint32(span.Count) {
			return uint16(uint32(span.First) + uint32(logical) - c.logical), true
		}
		c.logical += uint32(span.Count)
		c.span++
	}
	return 0, false
}

func (c *outputSupportOrdinalCursor) selected(physical uint16) (int, bool) {
	for c.span < len(c.spans) {
		span := c.spans[c.span]
		first, end := uint32(span.First), uint32(span.First)+uint32(span.Count)
		if uint32(physical) < first {
			return 0, false
		}
		if uint32(physical) < end {
			return int(c.logical + uint32(physical) - first), true
		}
		c.logical += uint32(span.Count)
		c.span++
	}
	return 0, false
}

func (s *StateSession) retainedOutputSelection(next *StateSession, position, prior int) (outputSupportOrdinalCursor, outputSupportOrdinalCursor, error) {
	if position >= len(next.support) || position >= len(next.root.RequiredSupport) || position >= len(next.adminIndex.Pages) ||
		prior < 0 || prior >= len(s.support) || prior >= len(s.root.RequiredSupport) || prior >= len(s.adminIndex.Pages) {
		return outputSupportOrdinalCursor{}, outputSupportOrdinalCursor{}, contract.ErrRecord
	}
	ref := next.root.RequiredSupport[position]
	page, oldPage := next.support[position], s.support[prior]
	if s.root.Domain != next.root.Domain || s.root.RequiredSupport[prior] != ref ||
		page.Domain != next.root.Domain || page.Object != ref.Object || page.Index != ref.Index ||
		oldPage.Domain != s.root.Domain || oldPage.Object != ref.Object || oldPage.Index != ref.Index ||
		s.adminIndex.Pages[prior].Ref != ref || next.adminIndex.Pages[position].Ref != ref {
		return outputSupportOrdinalCursor{}, outputSupportOrdinalCursor{}, contract.ErrRecord
	}
	current, err := newOutputSupportOrdinalCursor(next.adminIndex.Pages[position], len(page.Records))
	if err != nil {
		return outputSupportOrdinalCursor{}, outputSupportOrdinalCursor{}, err
	}
	old, err := newOutputSupportOrdinalCursor(s.adminIndex.Pages[prior], len(oldPage.Records))
	return current, old, err
}

// An unloaded optional page has authenticated summaries, not payload facts.
// Check retained physical selections against those summaries without loading it.
func (s *StateSession) validateUnloadedRetainedOutputSupport(next *StateSession, position, prior int) error {
	if position >= len(next.adminIndex.Pages) || prior < 0 || prior >= len(s.support) ||
		prior >= len(s.root.RequiredSupport) || prior >= len(s.adminIndex.Pages) || prior >= len(s.supportFacts) {
		return contract.ErrRecord
	}
	ref := next.root.RequiredSupport[position]
	page, oldPage := next.support[position], s.support[prior]
	index, oldIndex := next.adminIndex.Pages[position], s.adminIndex.Pages[prior]
	oldFacts := s.supportFacts[prior]
	if next.root.Domain != s.root.Domain || s.root.RequiredSupport[prior] != ref || index.Ref != ref || oldIndex.Ref != ref || oldFacts.ref != ref ||
		page.Domain != next.root.Domain || page.Object != ref.Object || page.Index != ref.Index ||
		oldPage.Domain != s.root.Domain || oldPage.Object != ref.Object || oldPage.Index != ref.Index ||
		len(page.Records) != 0 || len(oldPage.Records) != 0 || len(oldFacts.rows) != 0 || len(oldFacts.ordinals) != 0 ||
		index.ReadRequired || oldIndex.ReadRequired ||
		slices.ContainsFunc(index.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) ||
		slices.ContainsFunc(oldIndex.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
		return contract.ErrRecord
	}
	current, err := newOutputSupportOrdinalCursor(index, len(index.Rows))
	if err != nil {
		return err
	}
	old, err := newOutputSupportOrdinalCursor(oldIndex, len(oldIndex.Rows))
	if err != nil {
		return err
	}
	for logical, summary := range index.Rows {
		physical, selected := current.physical(logical)
		oldLogical, retained := old.selected(physical)
		if !selected || !retained || oldIndex.Rows[oldLogical] != summary {
			return contract.ErrRecord
		}
	}
	return nil
}

// validatePreservedOutputConfiguration checks exact slice identities without
// publishing facts for unrelated rows in a provisional selected image.
func (s *StateSession) validatePreservedOutputConfiguration(next *StateSession) error {
	if next == nil || next.root.Domain != s.root.Domain || next.root.OutputConfiguration != s.root.OutputConfiguration || !s.selectedOutputComplete() {
		return contract.ErrRecord
	}
	type preservedOutputFact struct {
		page, logical int
		fact          contract.SupportRecordDigest
	}
	old := make(map[contract.ID]preservedOutputFact)
	for i, page := range s.support {
		for j, row := range page.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			var fact contract.SupportRecordDigest
			if row.Body == nil {
				if i >= len(s.supportFacts) || j >= len(s.supportFacts[i].rows) {
					return contract.ErrRecord
				}
				fact = s.supportFacts[i].rows[j]
			} else {
				var err error
				fact, err = contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(row))
				if err != nil {
					return err
				}
			}
			if _, duplicate := old[row.RecordID]; duplicate {
				return contract.ErrRecord
			}
			old[row.RecordID] = preservedOutputFact{page: i, logical: j, fact: fact}
		}
	}
	if len(old) != int(next.root.OutputConfiguration.SliceCount) {
		return contract.ErrRecord
	}
	for i, page := range next.support {
		if i >= len(next.root.RequiredSupport) {
			return contract.ErrRecord
		}
		var current, prior outputSupportOrdinalCursor
		priorPosition := -1
		for j, row := range page.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			location, ok := old[row.RecordID]
			if !ok {
				return contract.ErrRecord
			}
			if row.Body != nil {
				actual, err := contract.InspectSupportRecordDigest(next.root.Domain, contract.SupportRecord(row))
				if err != nil || actual != location.fact {
					return contract.ErrRecord
				}
			} else {
				if priorPosition < 0 {
					var err error
					current, prior, err = s.retainedOutputSelection(next, i, location.page)
					if err != nil {
						return err
					}
					priorPosition = location.page
				}
				physical, selected := current.physical(j)
				logical, retained := prior.selected(physical)
				if !selected || !retained || location.page != priorPosition || location.logical != logical || priorPosition >= len(s.supportFacts) {
					return contract.ErrRecord
				}
				facts := s.supportFacts[priorPosition]
				if facts.ref != next.root.RequiredSupport[i] || logical >= len(facts.rows) || logical >= len(facts.ordinals) ||
					facts.rows[logical] != location.fact || facts.ordinals[logical] != physical ||
					location.fact.Kind() != row.Kind || location.fact.RecordID() != row.RecordID {
					return contract.ErrRecord
				}
			}
			delete(old, row.RecordID)
		}
	}
	if len(old) != 0 {
		return contract.ErrRecord
	}
	return nil
}

// bindPreservedOutputConfiguration publishes facts only for complete rows.
func (s *StateSession) bindPreservedOutputConfiguration(next *StateSession) error {
	if err := s.validatePreservedOutputConfiguration(next); err != nil {
		return err
	}
	return s.bindOutputSupportFacts(next)
}

func (s *StateSession) bindChangedOutputConfiguration(next *StateSession) error {
	if err := s.validateChangedOutputConfiguration(next); err != nil {
		return err
	}
	return s.bindOutputSupportFacts(next)
}

func (s *StateSession) validateSuccessorOutputConfiguration(next *StateSession) error {
	if next != nil && next.root.OutputConfiguration == s.root.OutputConfiguration {
		return s.validatePreservedOutputConfiguration(next)
	}
	return s.validateChangedOutputConfiguration(next)
}

func (s *StateSession) validateChangedOutputConfiguration(next *StateSession) error {
	if s == nil || next == nil || next.root.Domain != s.root.Domain || next.root.OutputConfiguration == s.root.OutputConfiguration || !s.selectedOutputComplete() {
		return contract.ErrRecord
	}
	source, err := next.outputConfigurationBodySource()
	if err != nil {
		return err
	}
	if err := contract.ValidateOutputConfigurationSource(next.root.Domain, next.root.OutputConfiguration, source); err != nil {
		return err
	}
	return nil
}

func (s *StateSession) bindOutputSupportFacts(next *StateSession) error {
	if next == nil || len(next.support) != len(next.root.RequiredSupport) {
		return contract.ErrRecord
	}
	// Fixture construction can bind a session to itself. Keep predecessor facts
	// available until the replacement facts have been fully built.
	oldFacts := s.supportFacts
	bound := make([]selectedSupportPageFacts, len(next.support))
	unloadedIndexesChecked := false
	for i, page := range next.support {
		ref := next.root.RequiredSupport[i]
		if page.Domain != next.root.Domain || page.Object != ref.Object || page.Index != ref.Index {
			return contract.ErrRecord
		}
		facts := selectedSupportPageFacts{ref: ref}
		priorPosition := -1
		for p, oldRef := range s.root.RequiredSupport {
			if oldRef == ref {
				priorPosition = p
			}
		}
		if len(page.Records) == 0 {
			if !unloadedIndexesChecked {
				if !s.adminIndex.Valid() || !next.adminIndex.Valid() {
					return contract.ErrRecord
				}
				unloadedIndexesChecked = true
			}
			if err := s.validateUnloadedRetainedOutputSupport(next, i, priorPosition); err != nil {
				return err
			}
			bound[i] = facts
			continue
		}
		var current, prior outputSupportOrdinalCursor
		if priorPosition >= 0 {
			var err error
			current, prior, err = s.retainedOutputSelection(next, i, priorPosition)
			if err != nil {
				return err
			}
		}
		for j, row := range page.Records {
			var fact contract.SupportRecordDigest
			ordinal := uint16(j)
			if row.Body != nil {
				var err error
				fact, err = contract.InspectSupportRecordDigest(next.root.Domain, contract.SupportRecord(row))
				if err != nil {
					return err
				}
			} else if priorPosition < 0 {
				return contract.ErrRecord
			}
			if priorPosition >= 0 {
				physical, selected := current.physical(j)
				logical, retained := prior.selected(physical)
				if !selected || !retained {
					return contract.ErrRecord
				}
				oldRow := s.support[priorPosition].Records[logical]
				if oldRow.Kind != row.Kind || oldRow.RecordID != row.RecordID {
					return contract.ErrRecord
				}
				var oldFact contract.SupportRecordDigest
				if row.Body != nil && oldRow.Body != nil {
					var err error
					oldFact, err = contract.InspectSupportRecordDigest(next.root.Domain, contract.SupportRecord(oldRow))
					if err != nil {
						return err
					}
				} else {
					if priorPosition >= len(oldFacts) || oldFacts[priorPosition].ref != ref || logical >= len(oldFacts[priorPosition].rows) ||
						logical >= len(oldFacts[priorPosition].ordinals) || oldFacts[priorPosition].ordinals[logical] != physical {
						return contract.ErrRecord
					}
					oldFact = oldFacts[priorPosition].rows[logical]
				}
				if oldFact.Kind() != row.Kind || oldFact.RecordID() != row.RecordID || row.Body != nil && oldFact != fact {
					return contract.ErrRecord
				}
				fact, ordinal = oldFact, physical
			}
			facts.rows = append(facts.rows, fact)
			facts.ordinals = append(facts.ordinals, ordinal)
		}
		bound[i] = facts
	}
	root, err := format.EncodeRoot(next.root)
	if err != nil {
		return err
	}
	next.supportFacts = bound
	next.outputConfigurationRoot = contract.Hash(root)
	next.publicationProof = nil
	return nil
}

// bindPlannedRetainedSupportFacts copies only complete predecessor facts under
// unchanged physical references. New planning rows receive no fact.
func (s *StateSession) bindPlannedRetainedSupportFacts(next *StateSession) error {
	if next == nil || next.root.Domain != s.root.Domain || len(next.support) != len(next.root.RequiredSupport) {
		return contract.ErrRecord
	}
	bound := make([]selectedSupportPageFacts, len(next.support))
	unloadedIndexesChecked := false
	for i, page := range next.support {
		ref := next.root.RequiredSupport[i]
		bound[i].ref = ref
		retained := false
		for p, old := range s.supportFacts {
			if old.ref != ref {
				continue
			}
			retained = true
			if p >= len(s.root.RequiredSupport) || s.root.RequiredSupport[p] != ref || len(old.rows) != len(page.Records) || len(old.ordinals) != len(old.rows) ||
				i >= len(next.adminIndex.Pages) || next.adminIndex.Pages[i].Ref != ref || page.Domain != next.root.Domain || page.Object != ref.Object || page.Index != ref.Index {
				return contract.ErrRecord
			}
			if len(page.Records) == 0 {
				if !unloadedIndexesChecked {
					if !s.adminIndex.Valid() || !next.adminIndex.Valid() {
						return contract.ErrRecord
					}
					unloadedIndexesChecked = true
				}
				if err := s.validateUnloadedRetainedOutputSupport(next, i, p); err != nil {
					return err
				}
				continue
			}
			cursor, err := newOutputSupportOrdinalCursor(next.adminIndex.Pages[i], len(page.Records))
			if err != nil {
				return err
			}
			for j, fact := range old.rows {
				if row := page.Records[j]; row.Body != nil {
					actual, err := contract.InspectSupportRecordDigest(next.root.Domain, contract.SupportRecord(row))
					if err != nil || actual != fact {
						return contract.ErrRecord
					}
				}
				physical, selected := cursor.physical(j)
				if !selected || physical != old.ordinals[j] || fact.Kind() != page.Records[j].Kind || fact.RecordID() != page.Records[j].RecordID {
					return contract.ErrRecord
				}
			}
			bound[i] = selectedSupportPageFacts{ref: ref, rows: slices.Clone(old.rows), ordinals: slices.Clone(old.ordinals)}
		}
		if len(page.Records) == 0 && !retained {
			return contract.ErrRecord
		}
	}
	next.supportFacts = bound
	return nil
}

// readSelectedOutputSupportRow owns one exact authenticated row for a changed
// physical page. Logical and physical ordinals stay bound to the selected Ref.
func (s *StateSession) readSelectedOutputSupportRow(ctx context.Context, id contract.ID) ([]byte, error) {
	facts, err := s.selectedOutputFactsByRecord()
	if err != nil {
		return nil, err
	}
	fact, ok := facts[id]
	position, selected := s.selectedSupportPosition(fact.ref)
	if !ok || !selected {
		return nil, contract.ErrRecord
	}
	var body []byte
	result, err := withAuthenticatedSupportRow(ctx, s.readObjectBorrowedUncached, s.root.Domain, s.supportFacts[position], uint16(fact.logical), func(view contract.SupportRecordView) error {
		if view.Kind != contract.OutputConfigurationSliceSupportKind || view.RecordID != id {
			return contract.ErrRecord
		}
		body = slices.Clone(view.Body)
		return nil
	})
	if result.Outcome != 0 {
		return nil, selectedReadFailure(result)
	}
	return body, err
}
