package core

import (
	"bytes"
	"encoding/binary"
	"hash"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type endWorkCarrier struct {
	page      int
	row       contract.SupportRecord
	location  contract.GeneratorSliceLocation
	mandatory bool
	groups    []uint16
}

// A snapshot Slice carrier binds the complete vector and its owner snapshot.
// When an exit drops even one location, every retained carrier needs a new
// immutable page. Unrelated support pages keep their predecessor references.
func (s *StateSession) rebindEndWorkSlices(index *format.AdministrativeIndex, snapshot, operation contract.ID,
	want contract.GeneratorDescriptor, projected ...[]contract.GeneratorSliceLocation) (map[format.Ref]objectImage, map[format.Ref]format.RequiredSupportPageView, error) {
	if s == nil || index == nil || !index.Valid() || snapshot.IsZero() || operation.IsZero() {
		return nil, nil, contract.ErrRecord
	}
	if len(projected) > 1 {
		return nil, nil, contract.ErrRecord
	}
	var relocated map[generatedContentKey]contract.GeneratorSliceLocation
	if len(projected) == 1 {
		relocated = make(map[generatedContentKey]contract.GeneratorSliceLocation, len(projected[0]))
		for _, location := range projected[0] {
			key := generatedContentKey{kind: location.ContentKind, id: location.ContentID}
			if _, duplicate := relocated[key]; duplicate {
				return nil, nil, contract.ErrRecord
			}
			relocated[key] = location
		}
	}
	var carriers []endWorkCarrier
	rows := make([][]int, len(index.Pages))
	for i, page := range index.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil {
			return nil, nil, err
		}
		position := 0
		for _, span := range page.Spans {
			for n := uint16(0); n < span.Count; n++ {
				if position >= len(view.Records) {
					return nil, nil, contract.ErrRecord
				}
				row := contract.SupportRecord(view.Records[position])
				carrier, match, err := snapshotSliceRecord(row, s.root.Domain, s.adminIndex.SliceSnapshot)
				if err != nil || !match {
					return nil, nil, contract.ErrRecord
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					return nil, nil, err
				}
				if relocated != nil {
					key := generatedContentKey{kind: location.ContentKind, id: location.ContentID}
					mapped, ok := relocated[key]
					if !ok || mapped.Logical() != location.Logical() {
						return nil, nil, contract.ErrRecord
					}
					location = mapped
				}
				rows[i] = append(rows[i], len(carriers))
				carriers = append(carriers, endWorkCarrier{page: i, row: row, location: location,
					mandatory: span.Mandatory, groups: span.GroupIndexes})
				position++
			}
		}
		if position != len(view.Records) {
			return nil, nil, contract.ErrRecord
		}
	}
	if relocated != nil && len(relocated) != len(carriers) {
		return nil, nil, contract.ErrRecord
	}
	order := make([]int, len(carriers))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		x, y := carriers[a].location, carriers[b].location
		if x.ContentKind != y.ContentKind {
			return int(x.ContentKind) - int(y.ContentKind)
		}
		return bytes.Compare(x.ContentID[:], y.ContentID[:])
	})
	vectorRows := make([][]byte, len(order))
	for i, ordinal := range order {
		if i > 0 {
			x, y := carriers[order[i-1]].location, carriers[ordinal].location
			if x.ContentKind == y.ContentKind && x.ContentID == y.ContentID {
				return nil, nil, contract.ErrRecord
			}
		}
		var err error
		vectorRows[i], err = contract.EncodeGeneratorSliceLocation(carriers[ordinal].location)
		if err != nil {
			return nil, nil, err
		}
	}
	descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, vectorRows)
	if err != nil || descriptor != want {
		return nil, nil, contract.ErrRecord
	}
	for ordinal, entry := range order {
		old, match, err := snapshotSliceRecord(carriers[entry].row, s.root.Domain, s.adminIndex.SliceSnapshot)
		if err != nil || !match {
			return nil, nil, contract.ErrRecord
		}
		old.OwnerID, old.Vector, old.Ordinal = snapshot, descriptor, uint32(ordinal)
		old.Row = vectorRows[ordinal]
		body, err := contract.EncodeGeneratorVectorCarrier(old)
		if err != nil {
			return nil, nil, err
		}
		id, err := contract.GeneratorVectorCarrierID(old)
		if err != nil {
			return nil, nil, err
		}
		carriers[entry].row.Body, carriers[entry].row.RecordID = body, id
	}
	used := s.signerOnlyClosureIDs()
	if used == nil {
		return nil, nil, contract.ErrRecord
	}
	images := make(map[format.Ref]objectImage)
	views := make(map[format.Ref]format.RequiredSupportPageView)
	for i := range index.Pages {
		if !index.Pages[i].ReadRequired {
			continue
		}
		old := index.Pages[i]
		var selected []endWorkCarrier
		for _, j := range rows[i] {
			selected = append(selected, carriers[j])
		}
		slices.SortFunc(selected, func(a, b endWorkCarrier) int {
			if a.location.ContentKind != b.location.ContentKind {
				return int(a.location.ContentKind) - int(b.location.ContentKind)
			}
			return bytes.Compare(a.location.ContentID[:], b.location.ContentID[:])
		})
		var idPreimage []byte
		idPreimage = append(idPreimage, "ENKV/end-work-slice-page/v1\x00"...)
		idPreimage = append(idPreimage, operation[:]...)
		idPreimage = append(idPreimage, old.Ref.Digest[:]...)
		idPreimage = binary.BigEndian.AppendUint16(idPreimage, old.Ref.Index)
		id := contract.Hash(idPreimage)
		if used[id] {
			return nil, nil, contract.ErrRecord
		}
		used[id] = true
		page := format.RequiredSupportPage{Domain: s.root.Domain, Object: id, Index: old.Ref.Index}
		replacement := format.AdministrativePage{ReadRequired: true}
		for ordinal, entry := range selected {
			page.Records = append(page.Records, entry.row)
			replacement.Spans = appendAdministrativeOwnerSpan(replacement.Spans, format.AdministrativeSpan{
				First: uint16(ordinal), Count: 1, Mandatory: entry.mandatory, GroupIndexes: entry.groups})
		}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			return nil, nil, err
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			return nil, nil, err
		}
		replacement.Ref = ref
		index.Pages[i] = replacement
		view := format.RequiredSupportPageView{Domain: page.Domain, Object: page.Object, Index: page.Index}
		for _, row := range page.Records {
			view.Records = append(view.Records, contract.SupportRecordView(row))
		}
		images[ref], views[ref] = objectImage{ref: ref, body: body}, view
	}
	index.SliceSnapshot = snapshot
	return images, views, nil
}

// Recompute only the per-owner charges whose record identities can change
// when selected Slice carriers are rebound. Optional payload bytes are not
// needed: their authenticated row summaries give the exact encoded lengths.
func rechargeEndWorkGroups(index *format.AdministrativeIndex, views map[format.Ref]format.RequiredSupportPageView) error {
	if index == nil || !index.Valid() {
		return contract.ErrRecord
	}
	// index is the owned closure copy. Rebinding keeps its immutable owner
	// backing; recharge streams each row instead of expanding row x owner IDs.
	ownedCount := make([]uint32, len(index.Groups))
	for _, page := range index.Pages {
		for _, span := range page.Spans {
			for _, group := range span.GroupIndexes {
				ownedCount[group] += uint32(span.Count)
			}
		}
	}
	ownedDigest := make([]hash.Hash, len(index.Groups))
	for i := range index.Groups {
		ownedDigest[i] = selectedDisposableDigest(ownedCount[i])
	}
	for i := range index.Groups {
		index.Groups[i].ChargedPages, index.Groups[i].ChargedBytes = 0, 0
	}
	for _, page := range index.Pages {
		var summaries []format.AdministrativeRowSummary
		if page.ReadRequired {
			view, ok := views[page.Ref]
			if !ok {
				return contract.ErrRecord
			}
			for _, row := range view.Records {
				summaries = append(summaries, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
			}
		} else {
			summaries = page.Rows
		}
		position := 0
		charged := make(map[uint16]bool)
		for _, span := range page.Spans {
			if position+int(span.Count) > len(summaries) {
				return contract.ErrRecord
			}
			for _, group := range span.GroupIndexes {
				if int(group) >= len(index.Groups) {
					return contract.ErrRecord
				}
				if !charged[group] {
					index.Groups[group].ChargedPages++
					charged[group] = true
				}
				for _, row := range summaries[position : position+int(span.Count)] {
					writeSelectedDisposableRow(ownedDigest[group], row.Kind, row.RecordID, row.BodyLength)
					index.Groups[group].ChargedBytes += uint64(contract.SupportRecordOverhead) + uint64(row.BodyLength)
				}
			}
			position += int(span.Count)
		}
		if position != len(summaries) {
			return contract.ErrRecord
		}
	}
	for i := range index.Groups {
		index.Groups[i].Disposable = selectedDisposableDescriptor(ownedDigest[i], ownedCount[i])
	}
	if !index.Valid() {
		return contract.ErrRecord
	}
	return nil
}
