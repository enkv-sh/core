package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The administrative reader can inspect current intent fragments even when
// unrelated disposable work is unreadable. Slice carrier rows are ReadRequired
// and fragment rows for current intents are Mandatory in the signed index.
func (s *StateSession) administrativeCurrentIntentSelection(ctx context.Context) (*generatedSelection, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	entries, err := selectedGeneratedEntryMetadata(s)
	if err != nil {
		return nil, err
	}
	return s.administrativeCurrentIntentSelectionForEntries(ctx, entries)
}

func (s *StateSession) administrativeCurrentIntentSelectionForEntries(ctx context.Context, entries []contract.GeneratedEntryMetadata) (*generatedSelection, error) {
	if s == nil || ctx == nil || !s.adminIndex.Valid() {
		return nil, contract.ErrRecord
	}
	if ctx.Err() != nil {
		return nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	_, locations, err := s.administrativeSelectedSummaries(s.adminIndex)
	if err != nil {
		return nil, err
	}
	content := &generatedContent{domain: s.root.Domain, fragmentFacts: s.fragmentFacts,
		locations: make(map[generatedContentKey]contract.GeneratorSliceLocation, len(locations)),
		fragments: make(map[contract.ID][]contract.GeneratedFragmentView)}
	if s.fragmentFacts != nil {
		content.fragmentLocations = make(map[contract.ID][]format.FragmentLocation)
	}
	for _, location := range locations {
		key := generatedContentKey{kind: location.ContentKind, id: location.ContentID}
		if _, duplicate := content.locations[key]; duplicate {
			return nil, contract.ErrRecord
		}
		content.locations[key] = location
	}
	intents, err := generatedIntentIDs(entries)
	if err != nil {
		return nil, err
	}
	blobs := make(map[contract.ID]bool, len(intents))
	for _, id := range intents {
		location, ok := content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: id}]
		if !ok {
			return nil, contract.ErrRecord
		}
		blobs[location.BlobID] = true
	}
	for _, fragmentLocation := range s.root.Generated.Fragments {
		if !blobs[fragmentLocation.BlobID] {
			continue
		}
		if s.fragmentFacts != nil {
			fact, present := s.fragmentFacts[fragmentLocation]
			position, found := s.selectedSupportPosition(fact.ref)
			if !present || !found || position >= len(s.adminIndex.Pages) ||
				fact.ref.Domain != s.root.Domain || fact.ref.Index != fragmentLocation.SupportPageIndex ||
				fact.logical != fragmentLocation.RowSlot || fact.blob != fragmentLocation.BlobID ||
				fact.index != fragmentLocation.FragmentIndex || s.adminIndex.Pages[position].Ref != fact.ref {
				return nil, contract.ErrRecord
			}
			mandatory := false
			for _, span := range s.adminIndex.Pages[position].Spans {
				if uint32(fact.physical) >= uint32(span.First) &&
					uint32(fact.physical) < uint32(span.First)+uint32(span.Count) {
					mandatory = span.Mandatory
					break
				}
			}
			if !mandatory {
				return nil, contract.ErrRecord
			}
			content.fragmentLocations[fact.blob] = append(content.fragmentLocations[fact.blob], fragmentLocation)
			continue
		}
		position := slices.IndexFunc(s.adminIndex.Pages, func(page format.AdministrativePage) bool {
			return page.Ref.Index == fragmentLocation.SupportPageIndex
		})
		if position < 0 || position >= len(s.support) || int(fragmentLocation.RowSlot) >= len(s.support[position].Records) {
			return nil, contract.ErrRecord
		}
		page := s.adminIndex.Pages[position]
		physical, ok := administrativePhysicalRowSlot(page, fragmentLocation.RowSlot)
		if !ok {
			return nil, contract.ErrRecord
		}
		mandatory := false
		for _, span := range page.Spans {
			if uint32(physical) >= uint32(span.First) && uint32(physical) < uint32(span.First)+uint32(span.Count) {
				mandatory = span.Mandatory
				break
			}
		}
		if !mandatory {
			return nil, contract.ErrRecord
		}
		row := s.support[position].Records[fragmentLocation.RowSlot]
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		id, idErr := contract.GeneratorFragmentID(fragmentLocation.BlobID, fragmentLocation.FragmentIndex)
		if err != nil || idErr != nil || row.Kind != contract.GeneratedFragmentSupportKind || row.RecordID != id ||
			fragment.BlobID != fragmentLocation.BlobID || fragment.Index != fragmentLocation.FragmentIndex {
			return nil, contract.ErrRecord
		}
		content.fragments[fragment.BlobID] = append(content.fragments[fragment.BlobID], fragment)
	}
	for blob := range blobs {
		if s.fragmentFacts != nil {
			refs := content.fragmentLocations[blob]
			if len(refs) == 0 {
				return nil, contract.ErrRecord
			}
			first := s.fragmentFacts[refs[0]]
			if first.index != 0 || len(refs) != int(first.count) {
				return nil, contract.ErrRecord
			}
			whole := sha256.New()
			var total uint64
			for i, location := range refs {
				fact := s.fragmentFacts[location]
				if fact.index != uint16(i) || fact.blob != blob || fact.count != first.count ||
					fact.total != first.total || fact.whole != first.whole || uint64(fact.offset) != total {
					return nil, contract.ErrRecord
				}
				result, readErr := s.withSelectedFragmentForOpen(ctx, location, func(payload []byte) error {
					_, err := whole.Write(payload)
					total += uint64(len(payload))
					return err
				})
				if result.Outcome != 0 {
					return nil, selectedReadFailure(result)
				}
				if readErr != nil {
					return nil, readErr
				}
			}
			if total != first.total || !bytes.Equal(whole.Sum(nil), first.whole[:]) {
				return nil, contract.ErrRecord
			}
			continue
		}
		fragments := content.fragments[blob]
		if len(fragments) == 0 || fragments[0].Index != 0 || len(fragments) != int(fragments[0].Count) {
			return nil, contract.ErrRecord
		}
		whole := sha256.New()
		var total uint64
		for i, fragment := range fragments {
			if fragment.Index != uint16(i) || fragment.BlobID != blob || fragment.Count != fragments[0].Count ||
				fragment.TotalLength != fragments[0].TotalLength || fragment.WholeDigest != fragments[0].WholeDigest {
				return nil, contract.ErrRecord
			}
			_, _ = whole.Write(fragment.Payload)
			total += uint64(len(fragment.Payload))
		}
		if total != fragments[0].TotalLength || !bytes.Equal(whole.Sum(nil), fragments[0].WholeDigest[:]) {
			return nil, contract.ErrRecord
		}
	}
	return &generatedSelection{session: s, image: s.selectedImage(), content: content}, nil
}

// The selected Slice carriers identify the surviving groups that consume each
// relocated logical intent. Physical fragment ownership can move only for
// those groups; a group with another claim on the old blob keeps that blob.
func (s *StateSession) administrativeCurrentIntentOwners(index format.AdministrativeIndex,
	plan generatedCurrentIntentProjection) (map[contract.ID][]uint16, map[contract.ID][]uint16, []uint16, error) {
	before := make(map[generatedContentKey]contract.GeneratorSliceLocation, len(plan.before))
	after := make(map[generatedContentKey]contract.GeneratorSliceLocation, len(plan.after))
	current := make(map[contract.ID]bool, len(plan.intents))
	for _, id := range plan.intents {
		current[id] = true
	}
	for _, location := range plan.before {
		before[generatedContentKey{kind: location.ContentKind, id: location.ContentID}] = location
	}
	for _, location := range plan.after {
		after[generatedContentKey{kind: location.ContentKind, id: location.ContentID}] = location
	}
	if len(before) != len(plan.before) || len(after) != len(plan.after) || len(before) != len(after) {
		return nil, nil, nil, contract.ErrRecord
	}
	transferred := make(map[contract.ID][]uint16, len(plan.dropBlobs))
	retained := make(map[contract.ID][]uint16)
	var all []uint16
	seen := make(map[generatedContentKey]bool, len(before))
	for _, page := range index.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil {
			return nil, nil, nil, err
		}
		logical := 0
		for _, span := range page.Spans {
			for n := uint16(0); n < span.Count; n++ {
				if logical >= len(view.Records) {
					return nil, nil, nil, contract.ErrRecord
				}
				row := contract.SupportRecord(view.Records[logical])
				logical++
				carrier, match, err := snapshotSliceRecord(row, s.root.Domain, s.adminIndex.SliceSnapshot)
				if err != nil {
					return nil, nil, nil, err
				}
				if !match {
					return nil, nil, nil, contract.ErrRecord
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					return nil, nil, nil, err
				}
				key := generatedContentKey{kind: location.ContentKind, id: location.ContentID}
				prior, ok := before[key]
				projected, retainedKey := after[key]
				if !ok || !retainedKey || seen[key] || location != prior {
					return nil, nil, nil, contract.ErrRecord
				}
				seen[key] = true
				moved := location.ContentKind == contract.GeneratorContentIntent && current[location.ContentID]
				if moved {
					if !span.Mandatory || projected.BlobID != plan.blob || projected.Logical() != location.Logical() {
						return nil, nil, nil, contract.ErrRecord
					}
				} else if projected != location || span.Mandatory || len(span.GroupIndexes) == 0 {
					return nil, nil, nil, contract.ErrRecord
				}
				for _, group := range span.GroupIndexes {
					if moved {
						if !slices.Contains(transferred[location.BlobID], group) {
							transferred[location.BlobID] = append(transferred[location.BlobID], group)
						}
					} else if !slices.Contains(retained[location.BlobID], group) {
						retained[location.BlobID] = append(retained[location.BlobID], group)
					}
					if moved && !slices.Contains(all, group) {
						all = append(all, group)
					}
				}
			}
		}
		if logical != len(view.Records) {
			return nil, nil, nil, contract.ErrRecord
		}
	}
	if len(seen) != len(before) {
		return nil, nil, nil, contract.ErrRecord
	}
	for blob := range transferred {
		slices.Sort(transferred[blob])
	}
	for blob := range retained {
		slices.Sort(retained[blob])
	}
	slices.Sort(all)
	return transferred, retained, all, nil
}

func (s *StateSession) removeAdministrativeIntentBlobs(index *format.AdministrativeIndex,
	blobs, demoted map[contract.ID]bool, transferred, retained map[contract.ID][]uint16) error {
	if s == nil || index == nil || !index.Valid() {
		return contract.ErrRecord
	}
	if len(blobs) == 0 && len(demoted) == 0 {
		return nil
	}
	kept := make([]format.AdministrativePage, 0, len(index.Pages))
	for _, page := range index.Pages {
		if !slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
			kept = append(kept, page)
			continue
		}
		selected, err := s.administrativeSelectedRows(page)
		if err != nil {
			return err
		}
		out := format.AdministrativePage{Ref: page.Ref, ReadRequired: page.ReadRequired}
		logical, changed := 0, false
		for _, span := range page.Spans {
			for physical := uint32(span.First); physical < uint32(span.First)+uint32(span.Count); physical++ {
				if logical >= len(selected) {
					return contract.ErrRecord
				}
				row := selected[logical]
				summary := row.summary
				logical++
				blob := row.blob
				drop := summary.Kind == contract.GeneratedFragmentSupportKind && blobs[blob]
				if drop {
					if !span.Mandatory || page.ReadRequired {
						return contract.ErrRecord
					}
					for _, group := range span.GroupIndexes {
						if !slices.Contains(transferred[blob], group) {
							return contract.ErrRecord
						}
					}
					changed = true
					continue
				}
				mandatory, groups := span.Mandatory, span.GroupIndexes
				if demoted[blob] && summary.Kind == contract.GeneratedFragmentSupportKind {
					if !mandatory || page.ReadRequired || len(retained[blob]) == 0 {
						return contract.ErrRecord
					}
					previous := append(slices.Clone(transferred[blob]), retained[blob]...)
					slices.Sort(previous)
					if !slices.Equal(span.GroupIndexes, slices.Compact(previous)) {
						return contract.ErrRecord
					}
					mandatory, groups, changed = false, retained[blob], true
				}
				if !page.ReadRequired {
					out.Rows = append(out.Rows, summary)
				}
				n := len(out.Spans)
				if n != 0 && uint32(out.Spans[n-1].First)+uint32(out.Spans[n-1].Count) == physical &&
					out.Spans[n-1].Mandatory == mandatory && slices.Equal(out.Spans[n-1].GroupIndexes, groups) {
					out.Spans[n-1].Count++
				} else {
					out.Spans = append(out.Spans, format.AdministrativeSpan{First: uint16(physical), Count: 1,
						Mandatory: mandatory, GroupIndexes: slices.Clone(groups)})
				}
			}
		}
		if logical != len(selected) {
			return contract.ErrRecord
		}
		if !changed {
			kept = append(kept, page)
		} else if len(out.Spans) != 0 {
			kept = append(kept, out)
		}
	}
	index.Pages = kept
	if !index.Valid() {
		return contract.ErrRecord
	}
	return nil
}

// An exact compact blob may already be selected. Its immutable bytes and Ref
// stay fixed, but the authenticated owner spans must include consumers whose
// logical intents have moved onto it.
func (s *StateSession) addAdministrativeExistingIntentOwners(index *format.AdministrativeIndex,
	plan generatedCurrentIntentProjection, owners []uint16) error {
	if index == nil || !index.Valid() || !plan.changed || plan.emit {
		return contract.ErrRecord
	}
	pageIndexes := make(map[uint16]bool)
	for _, location := range s.root.Generated.Fragments {
		if location.BlobID == plan.blob {
			pageIndexes[location.SupportPageIndex] = true
		}
	}
	if len(pageIndexes) == 0 {
		return contract.ErrRecord
	}
	seen := 0
	for i := range index.Pages {
		page := &index.Pages[i]
		if !pageIndexes[page.Ref.Index] {
			continue
		}
		rows, err := s.administrativeSelectedRows(*page)
		if err != nil {
			return err
		}
		var spans []format.AdministrativeSpan
		logical := 0
		for _, old := range page.Spans {
			for physical := uint32(old.First); physical < uint32(old.First)+uint32(old.Count); physical++ {
				if logical >= len(rows) {
					return contract.ErrRecord
				}
				row := rows[logical]
				logical++
				groups := old.GroupIndexes
				if row.summary.Kind == contract.GeneratedFragmentSupportKind {
					if row.blob == plan.blob {
						if !old.Mandatory {
							return contract.ErrRecord
						}
						seen++
						groups = append(slices.Clone(groups), owners...)
						slices.Sort(groups)
						groups = slices.Compact(groups)
					}
				}
				n := len(spans)
				if n != 0 && uint32(spans[n-1].First)+uint32(spans[n-1].Count) == physical &&
					spans[n-1].Mandatory == old.Mandatory && slices.Equal(spans[n-1].GroupIndexes, groups) {
					spans[n-1].Count++
				} else {
					spans = append(spans, format.AdministrativeSpan{First: uint16(physical), Count: 1,
						Mandatory: old.Mandatory, GroupIndexes: slices.Clone(groups)})
				}
			}
		}
		if logical != len(rows) {
			return contract.ErrRecord
		}
		page.Spans = spans
	}
	if seen != int(plan.fragments) || !index.Valid() {
		return contract.ErrRecord
	}
	return nil
}

func (s *StateSession) prepareAdministrativeIntentRemoval(index *format.AdministrativeIndex,
	plan generatedCurrentIntentProjection) ([]uint16, error) {
	transferred, retained, owners, err := s.administrativeCurrentIntentOwners(*index, plan)
	if err != nil {
		return nil, err
	}
	receipt, err := s.receiptIndexID()
	if err != nil {
		return nil, err
	}
	current := make(map[contract.ID]bool, len(plan.intents))
	for _, id := range plan.intents {
		current[id] = true
	}
	demoted := make(map[contract.ID]bool)
	for _, location := range plan.before {
		if location.ContentKind != contract.GeneratorContentIntent || !current[location.ContentID] ||
			location.BlobID == plan.blob || plan.dropBlobs[location.BlobID] || location.BlobID == receipt {
			continue
		}
		if len(retained[location.BlobID]) == 0 {
			return nil, contract.ErrRecord
		}
		demoted[location.BlobID] = true
	}
	if err := s.removeAdministrativeIntentBlobs(index, plan.dropBlobs, demoted, transferred, retained); err != nil {
		return nil, err
	}
	if !plan.emit {
		if err := s.addAdministrativeExistingIntentOwners(index, plan, owners); err != nil {
			return nil, err
		}
	}
	// Both candidate construction and pre-effect capacity admission must use
	// the same exact surviving owner charges after physical relocation.
	readable := make(map[format.Ref]format.RequiredSupportPageView)
	for _, page := range index.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil {
			return nil, err
		}
		readable[page.Ref] = view
	}
	if err := rechargeEndWorkGroups(index, readable); err != nil {
		return nil, err
	}
	return owners, nil
}

func (s *StateSession) addAdministrativeCurrentIntentBlob(ctx context.Context, index *format.AdministrativeIndex, ids endWorkIDs,
	selected *generatedSelection, plan generatedCurrentIntentProjection, owners []uint16) (map[format.Ref]objectImage,
	map[format.Ref]format.RequiredSupportPageView, []format.FragmentLocation, uint32, error) {
	images := make(map[format.Ref]objectImage)
	views := make(map[format.Ref]format.RequiredSupportPageView)
	if !plan.changed || !plan.emit {
		return images, views, nil, 0, nil
	}
	fragments, err := emitGeneratedCurrentIntents(ctx, selected, plan)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	packed, err := format.PackRequiredSupportRows(s.root.Domain, []format.RequiredSupportGroup{{Class: format.IntentFragmentSupport,
		Owner: plan.blob, Mandatory: true, Records: fragments}}, 0)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	used := s.signerOnlyClosureIDs()
	if used == nil {
		return nil, nil, nil, 0, contract.ErrRecord
	}
	occupied := make(map[uint16]bool, len(index.Pages))
	for _, page := range index.Pages {
		occupied[page.Ref.Index] = true
	}
	var directory []format.FragmentLocation
	for ordinal, rows := range packed {
		var pageIndex uint16
		found := false
		for slot := uint16(0); slot < contract.MaxChildPages; slot++ {
			if !occupied[slot] {
				pageIndex, occupied[slot], found = slot, true, true
				break
			}
		}
		if !found {
			return nil, nil, nil, 0, contract.ErrRecordCapacity
		}
		preimage := make([]byte, 0, 32+32+32+2+32)
		preimage = append(preimage, "ENKV/end-work-intent-page/v1\x00"...)
		preimage = append(preimage, s.root.Domain[:]...)
		preimage = append(preimage, ids.operation[:]...)
		preimage = append(preimage, plan.blob[:]...)
		preimage = binary.BigEndian.AppendUint16(preimage, uint16(ordinal))
		object := contract.Hash(preimage)
		if used[object] {
			return nil, nil, nil, 0, contract.ErrRecord
		}
		used[object] = true
		ref, view, body, err := endWorkSupportPage(s.root.Domain, object, pageIndex, rows, nil)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		indexed := endWorkIndexPage(ref, rows)
		indexed.Spans[0].GroupIndexes = slices.Clone(owners)
		index.Pages = append(index.Pages, indexed)
		images[ref], views[ref] = objectImage{ref: ref, body: body}, view
		for slot, row := range rows {
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil || fragment.BlobID != plan.blob {
				return nil, nil, nil, 0, contract.ErrRecord
			}
			directory = append(directory, format.FragmentLocation{BlobID: plan.blob, FragmentIndex: fragment.Index,
				SupportPageIndex: pageIndex, RowSlot: uint8(slot)})
		}
	}
	slices.SortFunc(index.Pages, func(a, b format.AdministrativePage) int { return int(a.Ref.Index) - int(b.Ref.Index) })
	if !index.Valid() {
		return nil, nil, nil, 0, contract.ErrRecord
	}
	return images, views, directory, uint32(len(fragments)), nil
}

func (s *StateSession) planAdministrativeCurrentIntents(ctx context.Context, index format.AdministrativeIndex) (generatedCurrentIntentProjection, error) {
	if s == nil {
		return generatedCurrentIntentProjection{}, contract.ErrRecord
	}
	entries, err := selectedGeneratedEntryMetadata(s)
	if err != nil {
		return generatedCurrentIntentProjection{}, err
	}
	return s.planAdministrativeCurrentIntentsForEntries(ctx, index, entries)
}

func (s *StateSession) planAdministrativeCurrentIntentsForEntries(ctx context.Context, index format.AdministrativeIndex, entries []contract.GeneratedEntryMetadata) (generatedCurrentIntentProjection, error) {
	selected, err := s.administrativeCurrentIntentSelectionForEntries(ctx, entries)
	if err != nil {
		return generatedCurrentIntentProjection{}, err
	}
	_, retained, err := s.administrativeSelectedSummaries(index)
	if err != nil {
		return generatedCurrentIntentProjection{}, err
	}
	plan, err := planGeneratedCurrentIntentsForEntries(ctx, s, selected, retained, entries)
	if err != nil {
		return generatedCurrentIntentProjection{}, err
	}
	if plan.emit {
		// The optional body is not available for a byte-level reuse proof.
		// The selected fragment directory still reveals a colliding BlobID.
		if slices.ContainsFunc(s.root.Generated.Fragments, func(location format.FragmentLocation) bool {
			return location.BlobID == plan.blob
		}) {
			return generatedCurrentIntentProjection{}, contract.ErrRecord
		}
	}
	return plan, nil
}

func generatedProjectedSliceDescriptor(locations []contract.GeneratorSliceLocation) (contract.GeneratorDescriptor, error) {
	rows := make([][]byte, len(locations))
	for i, location := range locations {
		if i > 0 && compareGeneratedLocationKey(locations[i-1], location) >= 0 {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		rows[i] = body
	}
	return contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, rows)
}
