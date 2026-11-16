package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// rows use compact selected slots. ordinals name the corresponding physical
// rows under ref; an unchanged page can have a selected slot zero at physical
// ordinal one after an administrative exit.
type selectedSupportPageFacts struct {
	// Only a private first-EndWork reservation copy can own this plan. It is
	// not an inspected row fact and cannot enter a physical selected reader.
	plannedReceipt *plannedReceiptSupport
	ref            format.Ref
	rows           []contract.SupportRecordDigest
	ordinals       []uint16
}

// A fragment fact contains no payload. It is useful only with its selected
// page Ref, row digest, and authenticated generated fragment directory entry.
type selectedFragmentFact struct {
	ref           format.Ref
	row           contract.SupportRecordDigest
	physical      uint16
	logical       uint8
	blob          contract.ID
	index, count  uint16
	total         uint64
	whole         contract.ID
	offset        uint32
	payloadLength uint32
}

// A support Ref.Index is a physical coordinate, not its position in the
// compact selected Root. EndWork can leave gaps in that physical sequence.
func (s *StateSession) selectedSupportPosition(ref format.Ref) (int, bool) {
	if s == nil || len(s.root.RequiredSupport) != len(s.supportFacts) {
		return 0, false
	}
	position := -1
	for i, candidate := range s.root.RequiredSupport {
		if candidate.Index != ref.Index {
			continue
		}
		if position >= 0 || candidate != ref || s.supportFacts[i].ref != ref {
			return 0, false
		}
		position = i
	}
	return position, position >= 0
}

func (s *StateSession) selectedFragmentFactsByRecord() (map[contract.ID]selectedFragmentFact, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	image := &selectedImage{root: s.root, support: s.support, supportFacts: s.supportFacts,
		fragmentFacts: s.fragmentFacts, outputConfigurationRoot: s.outputConfigurationRoot}
	return image.selectedFragmentFactsByRecord()
}

// selectedFragmentFactsByRecord keeps the selected directory's exact row
// identity while a phase writer plans rows without retained fragment bodies.
func (s *selectedImage) selectedFragmentFactsByRecord() (map[contract.ID]selectedFragmentFact, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	byRecord := make(map[contract.ID]selectedFragmentFact, len(s.fragmentFacts))
	for location, fact := range s.fragmentFacts {
		id, err := contract.GeneratorFragmentID(fact.blob, fact.index)
		if err != nil || fact.row.Kind() != contract.GeneratedFragmentSupportKind || fact.row.RecordID() != id ||
			location.BlobID != fact.blob || location.FragmentIndex != fact.index {
			return nil, contract.ErrRecord
		}
		if _, duplicate := byRecord[id]; duplicate {
			return nil, contract.ErrRecord
		}
		byRecord[id] = fact
	}
	if s.root.OutputConfiguration.SliceCount != 0 {
		output, err := s.selectedOutputFactsByRecord()
		if err != nil {
			return nil, err
		}
		for id, fact := range output {
			if _, duplicate := byRecord[id]; duplicate {
				return nil, contract.ErrRecord
			}
			byRecord[id] = fact
		}
	}
	return byRecord, nil
}

// A constructed successor has a new root. The predecessor's selected row
// facts and exact-ref source must not be reused as if they described it.
func (s *StateSession) clearSelectedSupportFacts() {
	s.supportFacts = nil
	s.fragmentFacts = nil
	s.generatedSliceLocations = nil
	s.generatedSlicesRoot = contract.ID{}
	s.outputConfigurationRoot = contract.ID{}
	s.publicationProof = nil
}

func (f selectedFragmentFact) matches(v contract.GeneratedFragmentView) bool {
	return v.BlobID == f.blob && v.Index == f.index && v.Count == f.count &&
		v.TotalLength == f.total && v.WholeDigest == f.whole && v.Offset == f.offset &&
		uint32(len(v.Payload)) == f.payloadLength
}

// withSelectedFragment lends one exact selected payload only during consume.
// Every call rechecks the immutable Ref and physical row; it never caches the
// page or returns a borrowed byte slice to a caller.
func (s *StateSession) withSelectedFragment(ctx context.Context, location format.FragmentLocation,
	consume func([]byte) error) (Result, error) {
	if s == nil || ctx == nil || consume == nil {
		return refused(AdmissionInvalid), nil
	}
	if ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable), nil
	}
	fact, ok := s.fragmentFacts[location]
	position, pageOK := s.selectedSupportPosition(fact.ref)
	if !ok || fact.ref.Domain != s.root.Domain || fact.ref.Index != location.SupportPageIndex ||
		fact.logical != location.RowSlot || fact.blob != location.BlobID || fact.index != location.FragmentIndex ||
		!pageOK || !slices.Contains(s.root.Generated.Fragments, location) {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	page := s.supportFacts[position]
	if page.ref != fact.ref || int(fact.logical) >= len(page.rows) || page.rows[fact.logical] != fact.row ||
		page.ordinals[fact.logical] != fact.physical {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	return withAuthenticatedSupportRow(ctx, s.readObjectBorrowedUncached, s.root.Domain, page, uint16(fact.logical),
		func(row contract.SupportRecordView) error {
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil || row.Kind != contract.GeneratedFragmentSupportKind || !fact.matches(fragment) {
				return contract.ErrRecord
			}
			return consume(fragment.Payload)
		})
}
