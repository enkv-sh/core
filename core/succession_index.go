package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A normal authority succession changes the snapshot owner of Slice carriers,
// but does not change selected generated work. Rebuild its physical index from
// the authenticated predecessor ownership instead of reading every fragment
// body into the generic generated-work index writer.
func (s *StateSession) installSuccessionSnapshotIndex(ctx context.Context, next *StateSession, candidate *Candidate) error {
	if s == nil || next == nil || candidate == nil || len(s.adminIndex.Pages) != len(s.support) ||
		len(next.support) != len(s.support) || len(next.root.RequiredSupport) != len(s.support) ||
		next.root.Domain != s.root.Domain || next.root.Snapshot == s.root.Snapshot ||
		!s.adminIndex.Valid() {
		return contract.ErrRecord
	}
	index := s.adminIndex
	index.Object = administrativeIndexObject(s.root.Domain, next.root.Snapshot)
	index.SliceSnapshot = next.root.Snapshot
	index.Pages = slices.Clone(s.adminIndex.Pages)
	index.Groups = slices.Clone(s.adminIndex.Groups)
	for i := range index.Groups {
		index.Groups[i] = index.Groups[i].Own()
	}
	affected := make(map[uint16]bool)
	for i, old := range s.support {
		prior := s.adminIndex.Pages[i]
		current := next.support[i]
		if prior.Ref != s.root.RequiredSupport[i] || old.Domain != s.root.Domain ||
			old.Index != prior.Ref.Index || current.Index != old.Index || current.Domain != old.Domain ||
			len(current.Records) != len(old.Records) {
			return contract.ErrRecord
		}
		newRef := next.root.RequiredSupport[i]
		if newRef == prior.Ref {
			for j := range old.Records {
				if old.Records[j].Kind != current.Records[j].Kind || old.Records[j].RecordID != current.Records[j].RecordID ||
					!bytes.Equal(old.Records[j].Body, current.Records[j].Body) {
					return contract.ErrRecord
				}
			}
			continue
		}
		if !prior.ReadRequired || len(prior.Rows) != 0 || len(old.Records) == 0 {
			return contract.ErrRecord
		}
		type oldRow struct {
			body      []byte
			mandatory bool
			groups    []uint16
		}
		owners := make(map[generatedRecordKey]oldRow, len(old.Records))
		selected := 0
		for _, span := range prior.Spans {
			if selected+int(span.Count) > len(old.Records) {
				return contract.ErrRecord
			}
			for _, row := range old.Records[selected : selected+int(span.Count)] {
				key := generatedRecordKey{row.Kind, row.RecordID}
				if _, duplicate := owners[key]; duplicate {
					return contract.ErrRecord
				}
				owners[key] = oldRow{body: row.Body, mandatory: span.Mandatory, groups: span.GroupIndexes}
			}
			selected += int(span.Count)
		}
		if selected != len(old.Records) {
			return contract.ErrRecord
		}
		page := format.AdministrativePage{Ref: newRef, ReadRequired: true}
		for ordinal, row := range current.Records {
			if row.Kind != contract.GeneratorVectorSupportKind {
				return contract.ErrRecord
			}
			carrier, match, err := snapshotSliceRecord(contract.SupportRecord(row), s.root.Domain, next.root.Snapshot)
			if err != nil || !match {
				return contract.ErrRecord
			}
			carrier.OwnerID = s.adminIndex.SliceSnapshot
			beforeBody, err := contract.EncodeGeneratorVectorCarrier(carrier)
			if err != nil {
				return err
			}
			beforeID, err := contract.GeneratorVectorCarrierID(carrier)
			if err != nil {
				return err
			}
			oldRow, present := owners[generatedRecordKey{row.Kind, beforeID}]
			if !present || !bytes.Equal(beforeBody, oldRow.body) || len(row.Body) != len(beforeBody) {
				return contract.ErrRecord
			}
			delete(owners, generatedRecordKey{row.Kind, beforeID})
			span := format.AdministrativeSpan{First: uint16(ordinal), Count: 1,
				Mandatory: oldRow.mandatory, GroupIndexes: slices.Clone(oldRow.groups)}
			for _, group := range span.GroupIndexes {
				if int(group) >= len(index.Groups) {
					return contract.ErrRecord
				}
				affected[group] = true
			}
			if n := len(page.Spans); n != 0 {
				last := &page.Spans[n-1]
				if last.Mandatory == span.Mandatory && slices.Equal(last.GroupIndexes, span.GroupIndexes) &&
					uint32(last.First)+uint32(last.Count) == uint32(span.First) && last.Count < ^uint16(0) {
					last.Count++
					continue
				}
			}
			page.Spans = append(page.Spans, span)
		}
		if len(owners) != 0 {
			return contract.ErrRecord
		}
		index.Pages[i] = page
	}
	for group := range affected {
		var count uint32
		for _, page := range index.Pages {
			for _, span := range page.Spans {
				if slices.Contains(span.GroupIndexes, group) {
					count += uint32(span.Count)
				}
			}
		}
		digest := selectedDisposableDigest(count)
		var pages uint16
		var charge uint64
		for i, page := range index.Pages {
			selected, charged := 0, false
			for _, span := range page.Spans {
				end := selected + int(span.Count)
				if end > len(next.support[i].Records) {
					return contract.ErrRecord
				}
				if slices.Contains(span.GroupIndexes, group) {
					charged = true
					for j := selected; j < end; j++ {
						row := next.support[i].Records[j]
						length := uint32(len(row.Body))
						if row.Body == nil {
							if i >= len(next.supportFacts) || j >= len(next.supportFacts[i].rows) ||
								j >= len(next.supportFacts[i].ordinals) || next.supportFacts[i].ref != page.Ref ||
								next.supportFacts[i].rows[j].Kind() != row.Kind || next.supportFacts[i].rows[j].RecordID() != row.RecordID ||
								next.supportFacts[i].ordinals[j] != uint16(uint32(span.First)+uint32(j-selected)) ||
								next.supportFacts[i].rows[j].BodyDigest().IsZero() {
								return contract.ErrRecord
							}
							length = next.supportFacts[i].rows[j].BodyLength()
						}
						writeSelectedDisposableRow(digest, row.Kind, row.RecordID, length)
						charge += uint64(contract.SupportRecordOverhead) + uint64(length)
					}
				}
				selected = end
			}
			if selected != len(next.support[i].Records) {
				return contract.ErrRecord
			}
			if charged {
				pages++
			}
		}
		if pages != index.Groups[group].ChargedPages || charge != index.Groups[group].ChargedBytes {
			return contract.ErrRecord
		}
		index.Groups[group].Disposable = selectedDisposableDescriptor(digest, count)
	}
	if !index.Valid() {
		return contract.ErrRecord
	}
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		return err
	}
	next.adminIndex = index
	next.root.AdministrativeIndex = shards[0].Ref
	next.root.AdministrativeIndexShards = nil
	for _, shard := range shards[1:] {
		next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
	}
	for _, shard := range shards {
		candidate.objects = append(candidate.objects, objectImage{ref: shard.Ref, body: shard.Body})
	}
	next.recountChildren()
	if err := s.bindPreservedOutputConfiguration(next); err != nil {
		return err
	}
	if err := s.bindPreservedPublication(ctx, next); err != nil {
		return err
	}
	if err := next.reserveOrdinaryPublicationRewrite(ctx); err != nil {
		return err
	}
	if next.root.ChildCount > ordinaryChildPageLimit {
		return contract.ErrRecordCapacity
	}
	return next.reserveFirstEndWork(ctx)
}
