package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"hash"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) withSelectedFragmentForOpen(ctx context.Context, location format.FragmentLocation, consume func([]byte) error) (Result, error) {
	if s == nil {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	return withSelectedFragmentFromImage(ctx, s.selectedImage(), s.selectedObjectReader(), location, consume)
}
func verifySelectedGeneratedSlices(ctx context.Context, image *selectedImage, reader selectedObjectReader) Result {
	if ctx == nil || ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	if image == nil || len(image.supportFacts) != len(image.root.RequiredSupport) {
		return failure(IntegrityFailure, InvalidRelation)
	}
	if len(image.fragmentFacts) != len(image.root.Generated.Fragments) {
		return failure(IntegrityFailure, InvalidRelation)
	}
	var selectedFragments int
	for i, page := range image.supportFacts {
		if page.ref != image.root.RequiredSupport[i] || len(page.rows) != len(page.ordinals) {
			return failure(IntegrityFailure, InvalidRelation)
		}
		for _, row := range page.rows {
			if row.Kind() == contract.GeneratedFragmentSupportKind {
				selectedFragments++
			}
		}
	}
	if selectedFragments != len(image.root.Generated.Fragments) {
		return failure(IntegrityFailure, InvalidRelation)
	}
	locations, err := format.ResolveGeneratedSliceLocations(image.root.Domain, image.adminIndex.SliceSnapshot,
		image.root.Generated.Slices, image.support)
	if err != nil {
		return failure(IntegrityFailure, InvalidRelation)
	}
	type sliceVerification struct {
		location contract.GeneratorSliceLocation
		digest   hash.Hash
		written  uint64
	}
	checks := make([]sliceVerification, len(locations))
	byBlob := make(map[contract.ID][]int)
	keys := make(map[generatedContentKey]bool, len(locations))
	for i, location := range locations {
		key := generatedContentKey{location.ContentKind, location.ContentID}
		if keys[key] || location.Offset+uint64(location.Length) < location.Offset {
			return failure(IntegrityFailure, InvalidRelation)
		}
		keys[key] = true
		checks[i] = sliceVerification{location: location, digest: sha256.New()}
		byBlob[location.BlobID] = append(byBlob[location.BlobID], i)
	}
	blobLengths := make(map[contract.ID]uint64)
	var prior selectedFragmentFact
	var whole = sha256.New()
	var length uint64
	for i, location := range image.root.Generated.Fragments {
		fact, ok := image.fragmentFacts[location]
		if !ok || fact.blob != location.BlobID || fact.index != location.FragmentIndex ||
			fact.logical != uint16(location.RowSlot) || fact.ref.Index != location.SupportPageIndex ||
			fact.count == 0 || fact.index >= fact.count || fact.whole.IsZero() {
			return failure(IntegrityFailure, InvalidRelation)
		}
		if fact.index == 0 {
			if i != 0 && prior.index+1 != prior.count {
				return failure(IntegrityFailure, InvalidRelation)
			}
			if _, duplicate := blobLengths[fact.blob]; duplicate {
				return failure(IntegrityFailure, InvalidRelation)
			}
			blobLengths[fact.blob] = fact.total
			whole.Reset()
			length = 0
		} else if i == 0 || prior.blob != fact.blob || prior.index+1 != fact.index || prior.count != fact.count ||
			prior.total != fact.total || prior.whole != fact.whole {
			return failure(IntegrityFailure, InvalidRelation)
		}
		start := uint64(fact.offset)
		stop := start + uint64(fact.payloadLength)
		if start != length || stop < start || stop > fact.total {
			return failure(IntegrityFailure, InvalidRelation)
		}
		result, err := withSelectedFragmentFromImage(ctx, image, reader, location, func(payload []byte) error {
			if _, err := whole.Write(payload); err != nil {
				return err
			}
			length += uint64(len(payload))
			// Check logical slices while this authenticated borrow is live. A
			// separate slice pass would reread its whole containing page.
			for _, index := range byBlob[fact.blob] {
				check := &checks[index]
				first := max(start, check.location.Offset)
				last := min(stop, check.location.Offset+uint64(check.location.Length))
				if first >= last {
					continue
				}
				part := payload[first-start : last-start]
				if _, err := check.digest.Write(part); err != nil {
					return err
				}
				check.written += uint64(len(part))
			}
			return nil
		})
		if result.Outcome != 0 {
			return result
		}
		if err != nil {
			return failure(IntegrityFailure, InvalidRelation)
		}
		if fact.index+1 == fact.count {
			if length != fact.total || !bytes.Equal(whole.Sum(nil), fact.whole[:]) {
				return failure(IntegrityFailure, InvalidRelation)
			}
		}
		prior = fact
	}
	if len(image.root.Generated.Fragments) != 0 && prior.index+1 != prior.count {
		return failure(IntegrityFailure, InvalidRelation)
	}
	for _, check := range checks {
		total, found := blobLengths[check.location.BlobID]
		if !found || check.location.Offset+uint64(check.location.Length) > total ||
			check.written != uint64(check.location.Length) || !bytes.Equal(check.digest.Sum(nil), check.location.Digest[:]) {
			return failure(IntegrityFailure, InvalidRelation)
		}
	}
	if ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	image.generatedSliceLocations = slices.Clone(locations)
	return Result{}
}

// withSelectedFragmentFromImage lends only an exact authenticated fragment
// payload. The image stores no reader or borrowed page backing.
func withSelectedFragmentFromImage(ctx context.Context, image *selectedImage, reader selectedObjectReader,
	location format.FragmentLocation,
	consume func([]byte) error) (Result, error) {
	if image == nil || ctx == nil || ctx.Err() != nil || consume == nil {
		return failure(EvidenceUnavailable, ReadUnavailable), nil
	}
	fact, ok := image.fragmentFacts[location]
	if !ok || fact.ref.Domain != image.root.Domain || fact.ref.Index != location.SupportPageIndex ||
		fact.logical != uint16(location.RowSlot) || fact.blob != location.BlobID || fact.index != location.FragmentIndex ||
		!slices.Contains(image.root.Generated.Fragments, location) {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	for _, selected := range image.support {
		if selected.Index != location.SupportPageIndex {
			continue
		}
		// Released body backing has authenticated facts and uses the exact-ref
		// reread below. A present short page remains an integrity failure.
		if selected.Records == nil {
			break
		}
		if int(location.RowSlot) >= len(selected.Records) {
			return failure(IntegrityFailure, InvalidRelation), nil
		}
		row := selected.Records[location.RowSlot]
		if row.Body == nil {
			break
		}
		actual, err := contract.InspectSupportRecordDigest(image.root.Domain, contract.SupportRecord(row))
		if err != nil || actual != fact.row || row.Kind != contract.GeneratedFragmentSupportKind {
			return failure(IntegrityFailure, InvalidRelation), nil
		}
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil || !fact.matches(fragment) {
			return failure(IntegrityFailure, InvalidRelation), nil
		}
		return Result{}, consume(fragment.Payload)
	}
	position := -1
	for i, ref := range image.root.RequiredSupport {
		if ref == fact.ref {
			position = i
			break
		}
	}
	if position < 0 || position >= len(image.supportFacts) {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	page := image.supportFacts[position]
	if page.ref != fact.ref || int(fact.logical) >= len(page.rows) || int(fact.logical) >= len(page.ordinals) ||
		page.rows[fact.logical] != fact.row || page.ordinals[fact.logical] != fact.physical {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	return withAuthenticatedSupportRow(ctx, func(ctx context.Context, ref format.Ref) ([]byte, Result) {
		body, _, result := reader.readBorrowed(ctx, ref)
		return body, result
	}, image.root.Domain, page, fact.logical, func(row contract.SupportRecordView) error {
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil || row.Kind != contract.GeneratedFragmentSupportKind || !fact.matches(fragment) {
			return contract.ErrRecord
		}
		return consume(fragment.Payload)
	})
}

func (s *StateSession) resolveSelectedGeneratedSlices() ([]contract.GeneratorSliceLocation, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	rootDigest, ok := s.generatedSelectionRoot()
	if ok && !s.generatedSlicesRoot.IsZero() && s.generatedSlicesRoot == rootDigest {
		return slices.Clone(s.generatedSliceLocations), nil
	}
	return format.ResolveGeneratedSlices(s.root.Domain, s.adminIndex.SliceSnapshot, s.root.Generated, s.support)
}

// A snapshot rebind changes Slice carrier ownership, but not the verified
// logical locations or any fragment page. Bind those facts to the completed
// successor root before relation validation, which must not read bodyless
// fragments as a second physical image.
func (s *StateSession) bindReboundGeneratedSlices(next *StateSession) error {
	if s == nil || next == nil || s.fragmentFacts == nil || next.fragmentFacts == nil {
		return contract.ErrRecord
	}
	beforeRoot, beforeOK := s.generatedSelectionRoot()
	afterRoot, afterOK := next.generatedSelectionRoot()
	if !beforeOK || !afterOK || s.generatedSlicesRoot != beforeRoot ||
		s.root.Domain != next.root.Domain || s.root.Generated.Slices != next.root.Generated.Slices ||
		!slices.Equal(s.root.Generated.Fragments, next.root.Generated.Fragments) ||
		len(s.fragmentFacts) != len(next.fragmentFacts) || len(next.supportFacts) != len(next.root.RequiredSupport) {
		return contract.ErrRecord
	}
	locations, err := format.ResolveGeneratedSliceLocations(next.root.Domain, next.adminIndex.SliceSnapshot,
		next.root.Generated.Slices, next.support)
	if err != nil || !slices.Equal(locations, s.generatedSliceLocations) {
		return contract.ErrRecord
	}
	for _, location := range next.root.Generated.Fragments {
		prior, priorOK := s.fragmentFacts[location]
		fact, present := next.fragmentFacts[location]
		position, pageOK := next.selectedSupportPosition(fact.ref)
		if !priorOK || !present || fact != prior || !pageOK ||
			int(fact.logical) >= len(next.supportFacts[position].rows) ||
			int(fact.logical) >= len(next.supportFacts[position].ordinals) ||
			next.supportFacts[position].rows[fact.logical] != fact.row ||
			next.supportFacts[position].ordinals[fact.logical] != fact.physical {
			return contract.ErrRecord
		}
	}
	next.generatedSliceLocations = slices.Clone(locations)
	next.generatedSlicesRoot = afterRoot
	return nil
}

// A receipt successor may replace receipt-index fragments and their pages,
// while leaving every selected logical content slice byte-identical. Bind the
// previously validated slice locations only after its final page/index image
// carries the same fragment body facts for all content blobs they use.
func (s *StateSession) bindReceiptSuccessorSlices(next *StateSession) error {
	if next == nil {
		return contract.ErrRecord
	}
	root, ok := next.generatedSelectionRoot()
	if !ok {
		return contract.ErrRecord
	}
	locations, err := s.receiptSuccessorSlices(next)
	if err != nil {
		return err
	}
	next.generatedSliceLocations = slices.Clone(locations)
	next.generatedSlicesRoot = root
	return nil
}

// The private receipt reservation uses the same exact support checks without
// claiming that its partial application projection is a complete selected Root.
func (s *StateSession) receiptSuccessorSlices(next *StateSession) ([]contract.GeneratorSliceLocation, error) {
	if s == nil || next == nil || s.fragmentFacts == nil || next.fragmentFacts == nil ||
		len(next.supportFacts) != len(next.root.RequiredSupport) || s.root.Domain != next.root.Domain {
		return nil, contract.ErrRecord
	}
	expectedDescriptor, expectedLocations := s.root.Generated.Slices, s.generatedSliceLocations
	if expected := next.normalReceiptSlices; expected != nil {
		if expected.beforeRevision != s.head.Core.Revision || expected.beforeRoot != s.head.Core.Root.Digest || expected.domain != next.root.Domain || expected.snapshot != next.root.Snapshot || expected.transition != next.root.Transition {
			return nil, contract.ErrRecord
		}
		expectedDescriptor, expectedLocations = expected.descriptor, expected.locations
		if !generatedSlicesSurvive(s.generatedSliceLocations, expectedLocations) {
			return nil, contract.ErrRecord
		}
	}
	if next.root.Generated.Slices != expectedDescriptor {
		return nil, contract.ErrRecord
	}
	beforeRoot, beforeOK := s.generatedSelectionRoot()
	if !beforeOK || s.generatedSlicesRoot != beforeRoot {
		return nil, contract.ErrRecord
	}
	locations, err := format.ResolveGeneratedSliceLocations(next.root.Domain, next.adminIndex.SliceSnapshot,
		next.root.Generated.Slices, next.support)
	if err != nil || !slices.Equal(locations, expectedLocations) {
		return nil, contract.ErrRecord
	}
	contentBlobs := make(map[contract.ID]bool, len(locations))
	for _, location := range locations {
		contentBlobs[location.BlobID] = true
	}
	if len(next.fragmentFacts) != len(next.root.Generated.Fragments) {
		return nil, contract.ErrRecord
	}
	pageByIndex := make(map[uint16]int, len(next.supportFacts))
	for location, old := range s.fragmentFacts {
		if !contentBlobs[location.BlobID] {
			continue
		}
		found := false
		for nextLocation, fact := range next.fragmentFacts {
			if nextLocation.BlobID != location.BlobID || nextLocation.FragmentIndex != location.FragmentIndex {
				continue
			}
			if fact.blob != old.blob || fact.index != old.index || fact.count != old.count ||
				fact.total != old.total || fact.whole != old.whole || fact.offset != old.offset ||
				fact.payloadLength != old.payloadLength || fact.row != old.row {
				return nil, contract.ErrRecord
			}
			found = true
			break
		}
		if !found {
			return nil, contract.ErrRecord
		}
	}
	for i, page := range next.supportFacts {
		if page.ref != next.root.RequiredSupport[i] || len(page.rows) != len(next.support[i].Records) ||
			len(page.rows) != len(page.ordinals) {
			return nil, contract.ErrRecord
		}
		if _, duplicate := pageByIndex[page.ref.Index]; duplicate {
			return nil, contract.ErrRecord
		}
		pageByIndex[page.ref.Index] = i
	}
	oldContentCount, nextContentCount := 0, 0
	for location := range s.fragmentFacts {
		if contentBlobs[location.BlobID] {
			oldContentCount++
		}
	}
	for _, location := range next.root.Generated.Fragments {
		fact, ok := next.fragmentFacts[location]
		position, pageOK := pageByIndex[location.SupportPageIndex]
		if !ok || !pageOK || fact.ref != next.root.RequiredSupport[position] ||
			fact.blob != location.BlobID || fact.index != location.FragmentIndex || fact.logical != uint16(location.RowSlot) ||
			int(location.RowSlot) >= len(next.supportFacts[position].rows) ||
			fact.row != next.supportFacts[position].rows[location.RowSlot] ||
			fact.physical != next.supportFacts[position].ordinals[location.RowSlot] ||
			next.support[position].Records[location.RowSlot].RecordID != fact.row.RecordID() {
			return nil, contract.ErrRecord
		}
		if contentBlobs[location.BlobID] {
			nextContentCount++
		}
	}
	if oldContentCount != nextContentCount {
		return nil, contract.ErrRecord
	}
	return locations, nil
}
