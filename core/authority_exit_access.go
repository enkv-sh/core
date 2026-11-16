package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The authenticated selected index says which operation materials and
// retained values still have live work consumers. Current secret values are
// also live. Ended-only access records have no remaining local consumer.
func (s *StateSession) endWorkRequiredMaterials(index format.AdministrativeIndex) (map[materialIdentity]bool, error) {
	if s == nil || !index.Valid() {
		return nil, contract.ErrRecord
	}
	keep := make(map[materialIdentity]bool)
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil || entry.Name != named.Name {
			return nil, contract.ErrRecord
		}
		if entry.ConfidentialityClass == format.Secret {
			keep[materialIdentity{contract.ValueMaterialKind, entry.ValueState}] = true
		}
	}
	for _, page := range index.Pages {
		for _, row := range page.Rows {
			switch row.Kind {
			case contract.RetainedCanonicalSupportKind:
				keep[materialIdentity{contract.ValueMaterialKind, row.RetainedMaterialID()}] = true
			case contract.OperationMaterialSupportKind:
				keep[materialIdentity{contract.OperationSeedMaterialKind, row.RecordID}] = true
			}
		}
	}
	return keep, nil
}

// EndWork derives reader obligations from the surviving authenticated rows.
// It never fetches a canonical page whose selected consumers all ended.
func (s *StateSession) endWorkAccessRows(ctx context.Context, index format.AdministrativeIndex) ([]contract.AccessRecord, error) {
	keep, err := s.endWorkRequiredMaterials(index)
	if err != nil || !s.adminIndex.Valid() {
		return nil, contract.ErrRecord
	}
	access := make(map[materialIdentity]contract.AccessRecord)
	for _, page := range s.access {
		if page == nil {
			continue
		}
		for _, row := range page.Records {
			key := materialIdentity{row.MaterialKind, row.MaterialID}
			if _, duplicate := access[key]; duplicate {
				return nil, contract.ErrRecord
			}
			access[key] = row
		}
	}
	readers := make(map[contract.ID][]contract.ID)
	canonicals := make(map[contract.ID]generatedCanonical)
	image := selectedImage{root: s.root, pages: s.pages}
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil || entry.Name != named.Name {
			return nil, contract.ErrRecord
		}
		if entry.ConfidentialityClass == format.Secret {
			readers[entry.ValueState] = append(readers[entry.ValueState], entry.Recipients...)
		}
	}
	for _, page := range index.Pages {
		// Authenticated ReadRequired pages contain only Slice carriers; the
		// selected reader rejects any other physical row on those pages.
		if !slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
			return row.Kind == contract.RetainedCanonicalSupportKind
		}) {
			continue
		}
		oldPosition := slices.IndexFunc(s.adminIndex.Pages, func(old format.AdministrativePage) bool { return old.Ref == page.Ref })
		if oldPosition < 0 || page.ReadRequired || s.adminIndex.Pages[oldPosition].ReadRequired {
			return nil, contract.ErrRecord
		}
		old := s.adminIndex.Pages[oldPosition]
		body, result := s.selectedObjectReader().readOwned(ctx, page.Ref)
		if result.Outcome != 0 {
			return nil, selectedReadFailure(result)
		}
		physical, err := format.InspectRequiredSupportPage(body)
		if err != nil || physical.Domain != s.root.Domain || physical.Object != page.Ref.Object || physical.Index != page.Ref.Index {
			return nil, selectedReadFailure(failure(IntegrityFailure, InvalidReference))
		}
		logical := 0
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				summary := page.Rows[logical]
				logical++
				if summary.Kind != contract.RetainedCanonicalSupportKind {
					continue
				}
				oldLogical, selected := administrativeSelectedOrdinal(old, uint16(ordinal))
				if !selected || int(oldLogical) >= len(old.Rows) || old.Rows[oldLogical] != summary || int(ordinal) >= len(physical.Records) {
					return nil, contract.ErrRecord
				}
				row := physical.Records[ordinal]
				if !summary.MatchesRecord(contract.SupportRecord(row)) {
					return nil, contract.ErrRecord
				}
				canonical, err := contract.DecodeRetainedCanonicalRecord(row.Body)
				if err != nil || canonical.Entry.ValueState != summary.RetainedMaterialID() || canonical.Entry.ValueSource != contract.Supplied {
					return nil, contract.ErrRecord
				}
				core, payload, err := image.canonicalValueMeaning(canonical, canonicals)
				if err != nil {
					return nil, err
				}
				context, contextErr := contract.ValueMaterialContextDigest(core)
				selectedAccess, exists := access[materialIdentity{contract.ValueMaterialKind, canonical.Entry.ValueState}]
				if contextErr != nil || !exists || selectedAccess.MaterialContextDigest != context || selectedAccess.PackageCheck != payload.PackageCheck {
					return nil, contract.ErrRecord
				}
				canonicals[row.RecordID] = generatedCanonical{record: canonical, core: core, payload: payload, access: selectedAccess}
				readers[canonical.Entry.ValueState] = append(readers[canonical.Entry.ValueState], canonical.Entry.Recipients...)
			}
		}
	}
	for id, union := range readers {
		slices.SortFunc(union, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		readers[id] = slices.Compact(union)
	}
	var rows []contract.AccessRecord
	for key := range keep {
		row, exists := access[key]
		if !exists {
			return nil, contract.ErrRecord
		}
		if key.kind == contract.ValueMaterialKind {
			needed := readers[key.id]
			accessCopy := row
			accessCopy.Wraps = nil
			for _, wrap := range row.Wraps {
				if wrap.SubjectKind == contract.OrdinaryWrapSubject && slices.Contains(needed, wrap.SubjectID) || wrap.SubjectKind == contract.RecoveryWrapSubject &&
					s.root.CurrentAccess.Core.Recovery != nil && wrap.SubjectID == s.root.CurrentAccess.Core.Recovery.RoleID {
					accessCopy.Wraps = append(accessCopy.Wraps, wrap)
				}
			}
			if !s.validateMaterialWraps(accessCopy, needed) {
				return nil, contract.ErrRecord
			}
			row = accessCopy
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	return rows, nil
}

// Reuse unchanged access pages. A page that contains an ended-only record is
// replaced at the same physical index with the exact retained rows.
func (s *StateSession) endWorkAccessSuccessor(next *StateSession, retained []contract.AccessRecord,
	operation, transition contract.ID) ([]objectImage, error) {
	if s == nil || next == nil || operation.IsZero() || transition.IsZero() {
		return nil, contract.ErrRecord
	}
	keep := make(map[materialIdentity]contract.AccessRecord, len(retained))
	for _, row := range retained {
		keep[materialIdentity{row.MaterialKind, row.MaterialID}] = row
	}
	next.access = s.access
	next.root.CurrentAccess.Core.AccessPageRefs = nil
	used := s.signerOnlyClosureIDs()
	if used == nil {
		return nil, contract.ErrRecord
	}
	var images []objectImage
	var count uint32
	accessChanged := false
	for _, oldRef := range s.root.CurrentAccess.Core.AccessPageRefs {
		if int(oldRef.Index) >= len(s.access) || s.access[oldRef.Index] == nil {
			return nil, contract.ErrRecord
		}
		old := s.access[oldRef.Index]
		page := *old
		page.Records = nil
		changed := false
		for _, row := range old.Records {
			if retainedRow, ok := keep[materialIdentity{row.MaterialKind, row.MaterialID}]; ok {
				before, err := contract.EncodeAccessRecord(row)
				if err != nil {
					return nil, err
				}
				after, err := contract.EncodeAccessRecord(retainedRow)
				if err != nil {
					return nil, err
				}
				changed = changed || !bytes.Equal(before, after)
				page.Records = append(page.Records, retainedRow)
			} else {
				changed = true
			}
		}
		count += uint32(len(page.Records))
		if !changed {
			next.root.CurrentAccess.Core.AccessPageRefs = append(next.root.CurrentAccess.Core.AccessPageRefs, oldRef)
			continue
		}
		accessChanged = true
		if len(page.Records) == 0 {
			next.access[oldRef.Index] = nil
			continue
		}
		preimage := append([]byte("ENKV/end-work-access-page/v1\x00"), operation[:]...)
		preimage = append(preimage, oldRef.Digest[:]...)
		preimage = binary.BigEndian.AppendUint16(preimage, oldRef.Index)
		page.Object = contract.Hash(preimage)
		if used[page.Object] {
			return nil, contract.ErrRecord
		}
		used[page.Object] = true
		body, err := format.EncodeAccessPage(page)
		if err != nil {
			return nil, err
		}
		ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			return nil, err
		}
		next.access[oldRef.Index] = &page
		next.root.CurrentAccess.Core.AccessPageRefs = append(next.root.CurrentAccess.Core.AccessPageRefs, ref)
		images = append(images, objectImage{ref: ref, body: body})
	}
	if count != uint32(len(retained)) {
		return nil, contract.ErrRecord
	}
	next.root.AccessRecordCount = count
	var err error
	next.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, retained)
	if err != nil {
		return nil, err
	}
	if accessChanged {
		if err := contract.AdvanceAccessGeneration(&next.root.CurrentAccess.Core, transition); err != nil {
			return nil, err
		}
	}
	next.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(next.root.CurrentAccess.Core)
	if err != nil {
		return nil, err
	}
	return images, nil
}
