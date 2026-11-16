package core

import (
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) currentRetiringPointersSelected() bool {
	return s.selectedImage().currentRetiringPointersSelected()
}
func (s *selectedImage) currentRetiringPointersSelected() bool {
	if s == nil || !s.adminIndex.Valid() {
		return false
	}
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		if entry == nil || entry.Name != name.Name {
			return false
		}
		if entry.ValueSource != contract.Generated || entry.Generated.RetiringDutyPresent == 0 {
			continue
		}
		if !slices.ContainsFunc(s.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
			return group.GroupID == entry.Generated.RetiringDutyID && group.OwnerKind == format.AdministrativeGeneratedDuty &&
				group.DutyKind == contract.GeneratedDutyRetirement
		}) {
			return false
		}
	}
	return true
}

// Ending a retirement Duty clears only its exact pointer in the surviving
// current value. It does not change that value's generation or ciphertext.
func (s *StateSession) endWorkValueSuccessor(next *StateSession, ended []format.AdministrativeGroup,
	operation contract.ID) ([]objectImage, map[contract.ID]contract.ID, error) {
	if s == nil || next == nil || operation.IsZero() || !s.currentRetiringPointersSelected() {
		return nil, nil, contract.ErrRecord
	}
	retirements := make(map[contract.ID]bool)
	for _, group := range ended {
		if group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind == contract.GeneratedDutyRetirement {
			retirements[group.GroupID] = true
		}
	}
	next.pages = s.pages
	used := s.signerOnlyClosureIDs()
	if used == nil {
		return nil, nil, contract.ErrRecord
	}
	clearSlots := make(map[uint16]contract.ID)
	clears := make(map[contract.ID]contract.ID)
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		if entry != nil && entry.ValueSource == contract.Generated && entry.Generated.RetiringDutyPresent == 1 &&
			retirements[entry.Generated.RetiringDutyID] {
			clearSlots[name.Slot] = entry.Generated.RetiringDutyID
			if _, duplicate := clears[entry.ValueState]; duplicate {
				return nil, nil, contract.ErrRecord
			}
			clears[entry.ValueState] = entry.Generated.RetiringDutyID
		}
	}
	var images []objectImage
	for i, old := range s.pages {
		if old == nil {
			continue
		}
		var page *format.ValueEntryPage
		for j, entry := range old.Slots {
			duty, shouldClear := clearSlots[uint16(i*format.PageSlots+j)]
			if !shouldClear {
				continue
			}
			if entry == nil || entry.ValueSource != contract.Generated || entry.Generated.RetiringDutyPresent != 1 ||
				entry.Generated.RetiringDutyID != duty {
				return nil, nil, contract.ErrRecord
			}
			if page == nil {
				pageCopy := *old
				page = &pageCopy
			}
			entryCopy := *entry
			entryCopy.Generated.RetiringDutyPresent, entryCopy.Generated.RetiringDutyID = 0, contract.ID{}
			page.Slots[j] = &entryCopy
		}
		if page == nil {
			continue
		}
		oldRef := s.root.ValueEntryPages[i]
		if oldRef == nil {
			return nil, nil, contract.ErrRecord
		}
		preimage := append([]byte("ENKV/end-work-value-page/v1\x00"), operation[:]...)
		preimage = append(preimage, oldRef.Digest[:]...)
		preimage = binary.BigEndian.AppendUint16(preimage, uint16(i))
		page.Object = contract.Hash(preimage)
		if used[page.Object] {
			return nil, nil, contract.ErrRecord
		}
		used[page.Object] = true
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			return nil, nil, err
		}
		ref, err := format.Reference(format.ValueEntryPageKind, s.root.Domain, page.Object, uint16(i), body)
		if err != nil {
			return nil, nil, err
		}
		next.pages[i], next.root.ValueEntryPages[i] = page, &ref
		images = append(images, objectImage{ref: ref, body: body})
	}
	return images, clears, nil
}
