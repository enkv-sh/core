package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Only K3 signer restoration may preserve unreadable work by its authenticated
// envelope. K2 succession has the complete work image and normalizes its bytes.

func (s *StateSession) preservedState(ctx context.Context, mask uint8, opaqueWork bool) (contract.DigestLength, error) {
	if opaqueWork && mask != contract.SuccessionChangeNormalSigner {
		return contract.DigestLength{}, contract.ErrRecord
	}
	control, ok := s.selectedControl()
	if !ok {
		return contract.DigestLength{}, contract.ErrRecord
	}
	var support []contract.SupportRecord
	if !opaqueWork {
		var err error
		support, err = s.workSupportRecords(ctx)
		if err != nil {
			return contract.DigestLength{}, err
		}
		support, err = rebindSnapshotSliceRecords(support, s.root.Domain, s.adminIndex.SliceSnapshot, s.root.Domain)
		if err != nil {
			return contract.DigestLength{}, err
		}
	}
	p, err := contract.NewPreservedStateProjection(control, mask, s.root.ValueEntryCount, uint32(s.root.RecipientCount), s.root.AccessRecordCount, uint32(len(support)))
	if err != nil {
		return contract.DigestLength{}, err
	}
	for i, page := range s.pages {
		if page != nil {
			for j, row := range page.Slots {
				if row != nil {
					if err := p.AddValueEntry(uint16(i*format.PageSlots+j), *row); err != nil {
						return contract.DigestLength{}, err
					}
				}
			}
		}
	}
	for i, page := range s.recipients {
		if page != nil {
			for j, row := range page.Slots {
				if row != nil {
					if err := p.AddRecipient(uint16(i*format.RecipientSlots+j), *row); err != nil {
						return contract.DigestLength{}, err
					}
				}
			}
		}
	}
	for _, row := range s.accessRecords() {
		if err := p.AddAccess(row); err != nil {
			return contract.DigestLength{}, err
		}
	}
	var opaque map[contract.ID]selectedFragmentFact
	if !opaqueWork {
		var err error
		opaque, err = s.selectedFragmentFactsByRecord()
		if err != nil {
			return contract.DigestLength{}, err
		}
	}
	for _, row := range support {
		if row.Body == nil && publicationSupportKind(row.Kind) {
			fact, err := s.publicationRecord(row)
			if err != nil {
				return contract.DigestLength{}, err
			}
			row.Body, err = fact.body()
			if err != nil {
				return contract.DigestLength{}, err
			}
		}
		if opaqueSupportKind(row.Kind) && row.Body == nil {
			fact, ok := opaque[row.RecordID]
			position, pageOK := s.selectedSupportPosition(fact.ref)
			if !ok || !pageOK || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID {
				return contract.DigestLength{}, contract.ErrRecord
			}
			page := s.supportFacts[position]
			if int(fact.logical) >= len(page.rows) || int(fact.logical) >= len(page.ordinals) ||
				page.rows[fact.logical] != fact.row || page.ordinals[fact.logical] != fact.physical {
				return contract.DigestLength{}, contract.ErrRecord
			}
			result, readErr := withAuthenticatedSupportRow(ctx, s.readObjectBorrowedUncached, s.root.Domain, page,
				uint16(fact.logical), func(view contract.SupportRecordView) error {
					inspected, err := contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(view))
					if err != nil || inspected != fact.row || view.Kind != row.Kind || view.RecordID != row.RecordID {
						return contract.ErrRecord
					}
					if row.Kind == contract.GeneratedFragmentSupportKind {
						fragment, err := contract.InspectGeneratedFragment(view.Body)
						if err != nil || !fact.matches(fragment) {
							return contract.ErrRecord
						}
					}
					return p.AddWorkSupport(contract.SupportRecord(view))
				})
			if result.Outcome != 0 {
				return contract.DigestLength{}, selectedReadFailure(result)
			}
			if readErr != nil {
				return contract.DigestLength{}, readErr
			}
			continue
		}
		if err := p.AddWorkSupport(row); err != nil {
			return contract.DigestLength{}, err
		}
	}
	base, err := p.Digest()
	if err != nil {
		return base, err
	}
	if !opaqueWork {
		return preservedGCState(base, s.root)
	}
	if !s.adminIndex.Valid() || s.adminIndex.Domain != s.root.Domain ||
		len(s.adminIndex.Pages) != len(s.root.RequiredSupport) {
		return contract.DigestLength{}, contract.ErrRecord
	}
	for i, page := range s.adminIndex.Pages {
		if page.Ref != s.root.RequiredSupport[i] {
			return contract.DigestLength{}, contract.ErrRecord
		}
	}
	// The physical index object is replaced on a successor. Its normalized
	// body retains exact logical ownership, page refs and disposable bytes.
	index := s.adminIndex
	index.Object = index.Domain
	indexBody, err := format.EncodeAdministrativeIndex(index)
	if err != nil {
		return contract.DigestLength{}, err
	}
	generated, err := format.EncodeGeneratedClosure(s.root.Generated)
	if err != nil {
		return contract.DigestLength{}, err
	}
	h := sha256.New()
	const purpose = "ENKV/signer-only-preserved-work/v1\x00"
	h.Write([]byte(purpose))
	h.Write(base.Digest[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], base.Length)
	h.Write(scalar[:])
	h.Write(indexBody)
	h.Write(generated)
	binary.BigEndian.PutUint32(scalar[:4], s.root.RequiredSupportRecordCount)
	h.Write(scalar[:4])
	h.Write([]byte{s.root.WarningBits})
	var digest contract.ID
	copy(digest[:], h.Sum(nil))
	return preservedGCState(contract.DigestLength{Digest: digest, Length: uint64(len(purpose)) + 32 + 8 + uint64(len(indexBody)+len(generated)) + 4 + 1}, s.root)
}

func (s *StateSession) accessRecords() []contract.AccessRecord {
	rows := make([]contract.AccessRecord, 0, s.root.AccessRecordCount)
	for _, page := range s.access {
		if page != nil {
			rows = append(rows, page.Records...)
		}
	}
	slices.SortFunc(rows, func(a, b contract.AccessRecord) int {
		return compareMaterial(a.MaterialKind, a.MaterialID, b.MaterialKind, b.MaterialID)
	})
	return rows
}

func (s *StateSession) deriveSuccession(ctx context.Context, request contract.SuccessionRequestCore, p transitionPlan, outputs map[materialIdentity]contract.AccessRecord) (*StateSession, []objectImage, error) {
	if err := s.successionRequestValid(ctx, request, p); err != nil {
		return nil, nil, err
	}
	next := *s
	next.head = format.Head{Core: s.successorCore(p), AuthKind: format.SuccessionAuth}
	next.head.Core.Epoch = request.ProposedAfterControl.NormalSigning.Binding.Epoch
	next.head.Core.Trust = request.ProposedAfterControl.NormalSigning.Binding.Trust
	next.root.Snapshot, next.root.Transition = p.snapshot, p.transition
	next.root.CurrentAccess.Core.CurrentControl = request.ProposedAfterControl.CurrentControl
	var objects []objectImage
	for i, id := range p.recipientPages {
		if id.IsZero() {
			continue
		}
		body, err := format.EncodeRecipientPage(*s.recipients[i])
		if err != nil {
			return nil, nil, contract.ErrRecord
		}
		page, err := format.DecodeRecipientPage(body)
		if err != nil {
			return nil, nil, contract.ErrRecord
		}
		page.Object = id
		for _, row := range page.Slots {
			if row != nil && row.RecipientID == request.BeforeControl.AuthorityRecipientID {
				binding := request.ProposedAfterControl.AuthorityKMSBinding
				row.CurrentBinding = &binding
			}
		}
		next.recipients[i] = &page
		next.recipient = page
		body, err = format.EncodeRecipientPage(page)
		if err != nil {
			return nil, nil, contract.ErrRecord
		}
		ref, err := format.Reference(format.RecipientKind, s.admission.domain, id, uint16(i), body)
		if err != nil {
			return nil, nil, contract.ErrRecord
		}
		next.root.Recipients[i] = &ref
		objects = append(objects, objectImage{ref: ref, body: body})
	}
	var recipientRefs []contract.Ref
	for _, ref := range next.root.Recipients {
		if ref != nil {
			recipientRefs = append(recipientRefs, *ref)
		}
	}
	descriptor, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: request.DomainID, Refs: recipientRefs})
	if err != nil {
		return nil, nil, contract.ErrRecord
	}
	next.root.CurrentAccess.Core.RecipientRefsDescriptor = descriptor
	next.root.CurrentAccess.Core.AccessPageRefs = nil
	changed := 0
	for i, page := range s.access {
		if page == nil {
			continue
		}
		if !p.accessPages[i].IsZero() {
			pageCopy := *page
			pageCopy.Object = p.accessPages[i]
			pageCopy.Records = slices.Clone(page.Records)
			for j, row := range pageCopy.Records {
				after, ok := outputs[materialIdentity{row.MaterialKind, row.MaterialID}]
				if !ok {
					return nil, nil, contract.ErrRecord
				}
				pageCopy.Records[j] = after
				changed++
			}
			page = &pageCopy
			next.access[i] = page
		}
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			return nil, nil, contract.ErrRecord
		}
		ref, err := format.Reference(format.AccessKind, request.DomainID, page.Object, page.Index, body)
		if err != nil {
			return nil, nil, contract.ErrRecord
		}
		next.root.CurrentAccess.Core.AccessPageRefs = append(next.root.CurrentAccess.Core.AccessPageRefs, ref)
		if !p.accessPages[i].IsZero() {
			objects = append(objects, objectImage{ref: ref, body: body})
		}
	}
	if changed != len(outputs) {
		return nil, nil, contract.ErrRecord
	}
	next.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(request.DomainID, next.accessRecords())
	if err != nil {
		return nil, nil, contract.ErrRecord
	}
	next.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(next.root.CurrentAccess.Core)
	if err != nil {
		return nil, nil, contract.ErrRecord
	}
	if signerOnlyRecovery(request) {
		// The exact support and index commitments are the preserved work.
		// Their optional bytes may be unavailable, so no carrier is rebound.
		next.support = s.support
		next.adminIndex = s.adminIndex
	} else {
		rebound, err := s.rebindGeneratedSnapshot(ctx, &next, p)
		if err != nil {
			return nil, nil, err
		}
		if request.OperationKind == contract.SuccessionReplaceAuthority {
			objects = append(objects, rebound...)
		}
		indexCandidate := &Candidate{session: s}
		if request.OperationKind == contract.SuccessionReplaceAuthority {
			err = s.installSuccessionSnapshotIndex(ctx, &next, indexCandidate)
		} else {
			err = s.installAdministrativeIndex(ctx, &next, indexCandidate)
		}
		if err != nil {
			return nil, nil, err
		}
		if request.OperationKind == contract.SuccessionReplaceAuthority {
			objects = append(objects, indexCandidate.objects...)
		}
		if s.fragmentFacts != nil {
			if err := s.bindReboundGeneratedSlices(&next); err != nil {
				return nil, nil, err
			}
		}
	}
	beforePreserved, err := s.preservedState(ctx, request.ChangeMask, signerOnlyRecovery(request))
	if err != nil {
		return nil, nil, err
	}
	afterPreserved, err := next.preservedState(ctx, request.ChangeMask, signerOnlyRecovery(request))
	if err != nil {
		return nil, nil, err
	}
	if beforePreserved != afterPreserved {
		return nil, nil, contract.ErrRecord
	}
	return &next, objects, nil
}

func (s *StateSession) recountChildren() {
	s.root.ChildCount, s.root.ChildEncodedBytes = 1, uint64(s.root.AdministrativeIndex.Length)
	for _, ref := range s.root.AdministrativeIndexShards {
		s.root.ChildCount++
		s.root.ChildEncodedBytes += uint64(ref.Length)
	}
	for _, table := range [][]*format.Ref{s.root.ValueEntryPages[:], s.root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				s.root.ChildCount++
				s.root.ChildEncodedBytes += uint64(ref.Length)
			}
		}
	}
	for _, refs := range [][]contract.Ref{s.root.CurrentAccess.Core.AccessPageRefs, s.root.RequiredSupport} {
		for _, ref := range refs {
			s.root.ChildCount++
			s.root.ChildEncodedBytes += uint64(ref.Length)
		}
	}
}
