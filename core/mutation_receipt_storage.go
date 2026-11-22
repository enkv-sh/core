package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type mutationReceiptLayout struct {
	rows            [contract.MaxChildPages][]contract.SupportRecord
	changed         [contract.MaxChildPages]bool
	receipts, index uint16
}

func (s *StateSession) mutationReceiptLayout(ctx context.Context) (mutationReceiptLayout, error) {
	var layout mutationReceiptLayout
	if _, err := s.receiptWindows(ctx); err != nil {
		return layout, err
	}
	index, err := s.receiptIndexID()
	if err != nil || s.root.ChildCount < uint32(len(s.support)) || s.root.ChildCount > contract.MaxChildPages {
		return layout, contract.ErrRecord
	}
	count := s.root.ChildCount - uint32(len(s.support))
	var selectedFragments map[contract.ID]selectedFragmentFact
	if s.fragmentFacts != nil {
		selectedFragments, err = s.selectedFragmentFactsByRecord()
		if err != nil {
			return layout, err
		}
	}
	for pagePosition, page := range s.support {
		rows := make([]contract.SupportRecord, 0, len(page.Records))
		for logical, row := range page.Records {
			if row.Kind == contract.MutationReceiptSupportKind {
				continue
			}
			if row.Kind == contract.GeneratedFragmentSupportKind {
				var blob contract.ID
				if row.Body == nil {
					fact, present := selectedFragments[row.RecordID]
					location, valid := fact.generatedLocation()
					if !present || !valid || pagePosition >= len(s.supportFacts) || pagePosition >= len(s.root.RequiredSupport) ||
						s.supportFacts[pagePosition].ref != fact.ref || s.root.RequiredSupport[pagePosition] != fact.ref ||
						logical >= len(s.supportFacts[pagePosition].rows) || logical >= len(s.supportFacts[pagePosition].ordinals) ||
						s.supportFacts[pagePosition].rows[logical] != fact.row ||
						s.supportFacts[pagePosition].ordinals[logical] != fact.physical || int(fact.logical) != logical ||
						!slices.Contains(s.root.Generated.Fragments, location) {
						return layout, contract.ErrRecord
					}
					blob = fact.blob
				} else {
					fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
					if inspectErr != nil {
						return layout, inspectErr
					}
					blob = fragment.BlobID
				}
				if blob == index {
					continue
				}
			}
			_, snapshotOwned, err := snapshotSliceRecord(contract.SupportRecord(row), s.admission.domain, s.adminIndex.SliceSnapshot)
			if err != nil {
				return layout, err
			}
			layout.changed[page.Index] = layout.changed[page.Index] || snapshotOwned
			rows = append(rows, contract.SupportRecord(row))
		}
		if len(rows) != 0 {
			layout.rows[page.Index] = rows
			layout.changed[page.Index] = layout.changed[page.Index] || len(rows) != len(page.Records)
			count++
		}
	}
	// Both full windows fit in one receipt page. Their bounded ordered index
	// fits in one fragment. No work row is evicted to make these pages fit.
	if count > contract.MaxChildPages-2 {
		return layout, contract.ErrRecordCapacity
	}
	found := 0
	for i, rows := range layout.rows {
		if len(rows) != 0 {
			continue
		}
		layout.changed[i] = true
		if found == 0 {
			layout.receipts = uint16(i)
		} else {
			layout.index = uint16(i)
			break
		}
		found++
	}
	return layout, nil
}

func (s *StateSession) mutationReceiptPageIndexes(ctx context.Context) ([]uint16, error) {
	layout, err := s.mutationReceiptLayout(ctx)
	if err != nil {
		return nil, err
	}
	var indexes []uint16
	for i, changed := range layout.changed {
		if changed {
			indexes = append(indexes, uint16(i))
		}
	}
	return indexes, nil
}

type mutationReceiptStorage struct {
	objects   []objectImage
	refs      []contract.Ref
	pages     []format.RequiredSupportPageView
	facts     []selectedSupportPageFacts
	fragments map[format.FragmentLocation]selectedFragmentFact
	generated format.GeneratedClosure
	count     uint32
	output    *contract.OutputConfigurationDescriptor
}

func (v mutationReceiptStorage) install(s *StateSession) {
	if v.output != nil {
		s.root.OutputConfiguration = *v.output
	}
	s.root.RequiredSupport = v.refs
	s.root.RequiredSupportRecordCount = v.count
	s.root.Generated = v.generated
	if v.pages != nil {
		s.support = v.pages
	}
	s.supportFacts = v.facts
	s.fragmentFacts = v.fragments
	s.generatedSliceLocations = nil
	s.generatedSlicesRoot = contract.ID{}
	s.adminIndex.SliceSnapshot = s.root.Snapshot
	s.recountChildren()
}

func (s *StateSession) encodeMutationReceiptSupport(ctx context.Context, p transitionPlan, delta contract.MutationReceiptDeltaPlan, identity contract.ID) (mutationReceiptStorage, error) {
	var out mutationReceiptStorage
	if delta.AddedCount != 1 || delta.DomainID != s.admission.domain {
		return out, contract.ErrRecord
	}
	layout, err := s.mutationReceiptLayout(ctx)
	if err != nil {
		return out, err
	}
	return s.encodeMutationReceiptLayout(ctx, p, delta, identity, layout)
}

func (s *StateSession) encodeMutationReceiptLayout(ctx context.Context, p transitionPlan, delta contract.MutationReceiptDeltaPlan, identity contract.ID, layout mutationReceiptLayout) (mutationReceiptStorage, error) {
	var out mutationReceiptStorage
	if delta.AddedCount != 1 || delta.DomainID != s.admission.domain {
		return out, contract.ErrRecord
	}
	selectedFragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return out, err
	}
	before, err := s.receiptWindows(ctx)
	if err != nil {
		return out, err
	}
	if before.DomainID != delta.Before.DomainID || !slices.Equal(before.Successes, delta.Before.Successes) || !slices.Equal(before.Failures, delta.Before.Failures) || !slices.Equal(before.Order, delta.Before.Order) {
		return out, contract.ErrRecord
	}
	for i, changed := range layout.changed {
		if changed == p.supportPages[i].IsZero() {
			return out, contract.ErrRecord
		}
	}
	rows, err := delta.AfterSupportRecords()
	if err != nil {
		return out, err
	}
	if !identity.IsZero() {
		row := contract.CompactMutationReceipt(delta.NewReceipt)
		row.RequestIdentityDigest = identity
		body, err := contract.EncodeCompactMutationReceipt(row)
		if err != nil {
			return out, err
		}
		for i := range rows {
			if rows[i].RecordID == row.OperationID {
				rows[i].Body = body
			}
		}
	}
	layout.rows[layout.receipts] = rows
	indexes, err := delta.AfterIndexes()
	if err != nil {
		return out, err
	}
	out.generated = s.root.Generated
	out.generated.SuccessWindow, out.generated.FailureWindow, out.generated.ReceiptOrder, err = indexes.Descriptors()
	if err != nil {
		return out, err
	}
	blob, err := contract.MutationReceiptIndexBlobID(s.admission.domain, out.generated.SuccessWindow, out.generated.FailureWindow, out.generated.ReceiptOrder)
	if err != nil {
		return out, err
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		return out, err
	}
	fragmentBody, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
		TotalLength: uint64(len(indexBody)), WholeDigest: contract.Hash(indexBody), Payload: indexBody})
	if err != nil {
		return out, err
	}
	fragmentID, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		return out, err
	}
	layout.rows[layout.index] = []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragmentBody}}
	out.generated.Fragments = nil
	for i, rows := range layout.rows {
		if len(rows) == 0 {
			continue
		}
		if layout.changed[i] {
			for slot, row := range rows {
				if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body == nil {
					rows[slot].Body, err = s.readSelectedOutputSupportRow(ctx, row.RecordID)
					if err != nil {
						return mutationReceiptStorage{}, err
					}
					continue
				}
				if row.Kind != contract.GeneratedFragmentSupportKind || row.Body != nil {
					continue
				}
				fact, ok := selectedFragments[row.RecordID]
				location, valid := fact.generatedLocation()
				if !ok || !valid || int(fact.ref.Index) != i {
					return mutationReceiptStorage{}, contract.ErrRecord
				}
				result, readErr := s.withSelectedFragment(ctx, location, func(payload []byte) error {
					body, encodeErr := contract.EncodeGeneratedFragment(contract.GeneratedFragment{
						Schema: contract.GeneratorRecordSchema, BlobID: fact.blob, Index: fact.index,
						Count: fact.count, TotalLength: fact.total, WholeDigest: fact.whole,
						Offset: fact.offset, Payload: payload})
					if encodeErr != nil || uint32(len(body)) != fact.row.BodyLength() ||
						contract.Hash(body) != fact.row.BodyDigest() {
						return contract.ErrRecord
					}
					rows[slot].Body = body
					return nil
				})
				if result.Outcome != 0 {
					return mutationReceiptStorage{}, selectedReadFailure(result)
				}
				if readErr != nil {
					return mutationReceiptStorage{}, readErr
				}
			}
			rows, err = rebindSnapshotSliceRecords(rows, s.admission.domain, s.adminIndex.SliceSnapshot, p.snapshot)
			if err != nil {
				return mutationReceiptStorage{}, err
			}
		}
		out.count += uint32(len(rows))
		for slot, row := range rows {
			if row.Kind == contract.GeneratedFragmentSupportKind {
				if row.Body == nil {
					fact, ok := selectedFragments[row.RecordID]
					if !ok || layout.changed[i] || int(fact.ref.Index) != i || int(fact.logical) != slot ||
						fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID {
						return mutationReceiptStorage{}, contract.ErrRecord
					}
					out.generated.Fragments = append(out.generated.Fragments, format.FragmentLocation{
						BlobID: fact.blob, FragmentIndex: fact.index, SupportPageIndex: uint16(i), RowSlot: uint8(slot)})
					continue
				}
				f, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					return mutationReceiptStorage{}, err
				}
				out.generated.Fragments = append(out.generated.Fragments, format.FragmentLocation{BlobID: f.BlobID,
					FragmentIndex: f.Index, SupportPageIndex: uint16(i), RowSlot: uint8(slot)})
			}
		}
		if !layout.changed[i] {
			for j, page := range s.support {
				if page.Index == uint16(i) {
					out.refs = append(out.refs, s.root.RequiredSupport[j])
					out.pages = append(out.pages, page)
					break
				}
			}
			continue
		}
		page := format.RequiredSupportPage{Domain: s.admission.domain, Object: p.supportPages[i], Index: uint16(i), Records: rows}
		var body []byte
		if identity.IsZero() && uint16(i) == layout.receipts {
			body, err = format.EncodeRequiredSupportReceiptPlan(page, delta.NewReceipt)
		} else {
			body, err = format.EncodeRequiredSupportPage(page)
		}
		if err != nil {
			return mutationReceiptStorage{}, err
		}
		ref := contract.Ref{Kind: contract.RequiredSupportKind, Format: contract.CanonicalSchema, Domain: page.Domain,
			Object: page.Object, Index: page.Index, Digest: contract.Hash(body), Length: uint32(len(body))}
		if !identity.IsZero() {
			ref, err = format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
			if err != nil {
				return mutationReceiptStorage{}, err
			}
		}
		out.refs = append(out.refs, ref)
		out.objects = append(out.objects, objectImage{ref: ref, body: body})
		if !identity.IsZero() {
			view, err := format.InspectRequiredSupportPage(body)
			if err != nil {
				return mutationReceiptStorage{}, err
			}
			out.pages = append(out.pages, view)
		} else {
			view := format.RequiredSupportPageView{Domain: page.Domain, Object: page.Object, Index: page.Index}
			for _, row := range rows {
				view.Records = append(view.Records, contract.SupportRecordView(row))
			}
			out.pages = append(out.pages, view)
		}
	}
	slices.SortFunc(out.generated.Fragments, func(a, b format.FragmentLocation) int {
		if c := bytes.Compare(a.BlobID[:], b.BlobID[:]); c != 0 {
			return c
		}
		return int(a.FragmentIndex) - int(b.FragmentIndex)
	})
	if !identity.IsZero() && s.fragmentFacts != nil {
		if err := out.bindSupportFacts(s, nil); err != nil {
			return mutationReceiptStorage{}, err
		}
	}
	return out, nil
}

// bindSupportFacts inspects complete new rows and retains exact predecessor
// facts for unchanged opaque rows. A typed receipt hole stays a zero fact.
func (out *mutationReceiptStorage) bindSupportFacts(s *StateSession, planned *plannedReceiptSupport) error {
	if out == nil || s == nil || len(out.pages) != len(out.refs) {
		return contract.ErrRecord
	}
	plannedRows := 0
	prior := make(map[format.Ref]selectedSupportPageFacts, len(s.supportFacts))
	for _, page := range s.supportFacts {
		if page.plannedReceipt != nil {
			return contract.ErrRecord
		}
		if _, duplicate := prior[page.ref]; duplicate {
			return contract.ErrRecord
		}
		prior[page.ref] = page
	}
	out.facts = make([]selectedSupportPageFacts, len(out.pages))
	byIndex := make(map[uint16]int, len(out.pages))
	for i, page := range out.pages {
		ref := out.refs[i]
		if old, ok := prior[ref]; ok {
			if len(old.rows) != len(page.Records) || len(old.ordinals) != len(page.Records) {
				return contract.ErrRecord
			}
			out.facts[i] = old
		} else {
			facts := selectedSupportPageFacts{ref: ref, rows: make([]contract.SupportRecordDigest, len(page.Records)),
				ordinals: make([]uint16, len(page.Records))}
			for j, row := range page.Records {
				matched, err := planned.matchesOwner(s.admission.domain, row)
				if err != nil {
					return err
				}
				if matched {
					if facts.plannedReceipt != nil {
						return contract.ErrRecord
					}
					facts.plannedReceipt = planned
					facts.ordinals[j] = uint16(j)
					plannedRows++
					continue
				}
				fact, factErr := contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(row))
				if factErr != nil {
					return factErr
				}
				facts.rows[j], facts.ordinals[j] = fact, uint16(j)
			}
			out.facts[i] = facts
		}
		if _, duplicate := byIndex[ref.Index]; duplicate {
			return contract.ErrRecord
		}
		byIndex[ref.Index] = i
	}
	out.fragments = make(map[format.FragmentLocation]selectedFragmentFact, len(out.generated.Fragments))
	for _, location := range out.generated.Fragments {
		position, ok := byIndex[location.SupportPageIndex]
		if !ok || int(location.RowSlot) >= len(out.pages[position].Records) {
			return contract.ErrRecord
		}
		page, factPage := out.pages[position], out.facts[position]
		row := page.Records[location.RowSlot]
		if row.Kind != contract.GeneratedFragmentSupportKind {
			return contract.ErrRecord
		}
		var fact selectedFragmentFact
		if row.Body == nil {
			priorFact, exists := s.fragmentFacts[location]
			if !exists || priorFact.ref != factPage.ref || priorFact.row != factPage.rows[location.RowSlot] ||
				priorFact.physical != factPage.ordinals[location.RowSlot] {
				return contract.ErrRecord
			}
			fact = priorFact
		} else {
			fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
			if inspectErr != nil || fragment.BlobID != location.BlobID || fragment.Index != location.FragmentIndex {
				return contract.ErrRecord
			}
			fact = selectedFragmentFact{ref: factPage.ref, row: factPage.rows[location.RowSlot],
				physical: factPage.ordinals[location.RowSlot], logical: uint16(location.RowSlot),
				blob: fragment.BlobID, index: fragment.Index, count: fragment.Count,
				total: fragment.TotalLength, whole: fragment.WholeDigest, offset: fragment.Offset,
				payloadLength: uint32(len(fragment.Payload))}
		}
		if _, duplicate := out.fragments[location]; duplicate {
			return contract.ErrRecord
		}
		out.fragments[location] = fact
	}
	if planned != nil && plannedRows != 1 {
		return contract.ErrRecord
	}
	return nil
}
