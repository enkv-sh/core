package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func snapshotSliceRecord(row contract.SupportRecord, domain, snapshot contract.ID) (contract.GeneratorVectorCarrier, bool, error) {
	if row.Kind != contract.GeneratorVectorSupportKind {
		return contract.GeneratorVectorCarrier{}, false, nil
	}
	v, err := contract.InspectGeneratorVectorCarrier(row.Body)
	if err != nil {
		return v, false, err
	}
	if v.VectorKind != contract.GeneratorVectorSlices {
		return v, false, nil
	}
	id, err := contract.GeneratorVectorCarrierID(v)
	if err != nil || id != row.RecordID || v.DomainID != domain || v.OwnerID != snapshot || v.OwnerKind != contract.GeneratorSnapshotOwner {
		return v, false, contract.ErrRecord
	}
	return v, true, nil
}

func rebindSnapshotSliceRecords(rows []contract.SupportRecord, domain, before, after contract.ID) ([]contract.SupportRecord, error) {
	out := slices.Clone(rows)
	for i, row := range out {
		v, match, err := snapshotSliceRecord(row, domain, before)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		v.OwnerID = after
		out[i].Body, err = contract.EncodeGeneratorVectorCarrier(v)
		if err != nil {
			return nil, err
		}
		out[i].RecordID, err = contract.GeneratorVectorCarrierID(v)
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	return out, nil
}

func (s *StateSession) generatedSnapshotPageIndexes() ([]uint16, error) {
	var indexes []uint16
	for _, page := range s.support {
		changed := false
		for _, row := range page.Records {
			_, match, err := snapshotSliceRecord(contract.SupportRecord(row), s.admission.domain, s.adminIndex.SliceSnapshot)
			if err != nil {
				return nil, err
			}
			changed = changed || match
		}
		if changed {
			indexes = append(indexes, page.Index)
		}
	}
	return indexes, nil
}

func (s *StateSession) rebindGeneratedSnapshot(ctx context.Context, next *StateSession, p transitionPlan) ([]objectImage, error) {
	if next == nil || p.snapshot.IsZero() || p.snapshot == s.root.Snapshot || next.root.Snapshot != p.snapshot || len(s.support) != len(s.root.RequiredSupport) {
		return nil, contract.ErrRecord
	}
	indexes, err := s.generatedSnapshotPageIndexes()
	if err != nil {
		return nil, err
	}
	next.support = slices.Clone(s.support)
	next.root.RequiredSupport = slices.Clone(s.root.RequiredSupport)
	if s.fragmentFacts != nil {
		next.supportFacts = slices.Clone(s.supportFacts)
		next.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact, len(s.fragmentFacts))
		for location, fact := range s.fragmentFacts {
			next.fragmentFacts[location] = fact
		}
		next.generatedSliceLocations = nil
		next.generatedSlicesRoot = contract.ID{}
	}
	next.adminIndex = s.adminIndex
	next.adminIndex.SliceSnapshot = p.snapshot
	var objects []objectImage
	for i, page := range s.support {
		if !slices.Contains(indexes, page.Index) {
			continue
		}
		id := p.supportPages[page.Index]
		if id.IsZero() || id == page.Object {
			return nil, contract.ErrRecord
		}
		rows := make([]contract.SupportRecord, 0, len(page.Records))
		if s.fragmentFacts != nil {
			if i >= len(s.supportFacts) || s.supportFacts[i].ref != s.root.RequiredSupport[i] {
				return nil, contract.ErrRecord
			}
			result, readErr := withAuthenticatedSupportRows(ctx, s.readObjectBorrowedUncached, s.root.Domain, s.supportFacts[i],
				func(_ uint16, _ uint16, row contract.SupportRecordView) error {
					rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
					return nil
				})
			if result.Outcome != 0 {
				return nil, selectedReadFailure(result)
			}
			if readErr != nil {
				return nil, readErr
			}
		} else {
			for _, row := range page.Records {
				rows = append(rows, contract.SupportRecord(row))
			}
		}
		rows, err = rebindSnapshotSliceRecords(rows, s.admission.domain, s.adminIndex.SliceSnapshot, p.snapshot)
		if err != nil {
			return nil, err
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: id, Index: page.Index, Records: rows})
		if err != nil {
			return nil, err
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, id, page.Index, body)
		if err != nil {
			return nil, err
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			return nil, err
		}
		next.support[i], next.root.RequiredSupport[i] = view, ref
		if s.fragmentFacts != nil {
			facts := selectedSupportPageFacts{ref: ref, rows: make([]contract.SupportRecordDigest, len(view.Records)),
				ordinals: make([]uint16, len(view.Records))}
			for slot, row := range view.Records {
				fact, factErr := contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(row))
				if factErr != nil {
					return nil, factErr
				}
				facts.rows[slot], facts.ordinals[slot] = fact, uint16(slot)
			}
			next.supportFacts[i] = facts
			for location, fact := range next.fragmentFacts {
				if location.SupportPageIndex == page.Index {
					if int(location.RowSlot) >= len(view.Records) || view.Records[location.RowSlot].RecordID != fact.row.RecordID() {
						return nil, contract.ErrRecord
					}
					fact.ref, fact.physical = ref, uint16(location.RowSlot)
					next.fragmentFacts[location] = fact
				}
			}
		}
		objects = append(objects, objectImage{ref: ref, body: body})
	}
	next.recountChildren()
	if len(s.fragmentFacts) != 0 {
		if err := s.bindReboundGeneratedSlices(next); err != nil {
			return nil, err
		}
	}
	return objects, nil
}

// Snapshot ownership is physical. The projection substitutes the stable domain
// only for that carrier owner and its derived ID; all location bytes remain.
