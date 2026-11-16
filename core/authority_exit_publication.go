package core

import (
	"context"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The selected index retains the exact qualified create proof even when its
// optional marker body is unavailable to an administrative reader.
func publicationRetainedUncertainCreate(index format.AdministrativeIndex, coordinate contract.PublicationCoordinate) bool {
	for _, group := range index.Groups {
		if group.OwnerKind == format.AdministrativePublicationMarker && group.OwnerID == coordinate.CoordinateID && group.UncertainCreateProof != 0 {
			return true
		}
	}
	return false
}

func publicationCoordinateAfterDisposition(index format.AdministrativeIndex, before contract.PublicationCoordinate,
	ended []format.AdministrativeGroup) contract.PublicationCoordinate {
	after := before
	markerEnded := false
	for _, group := range ended {
		if group.OwnerKind != format.AdministrativePublicationMarker || group.OwnerID != before.CoordinateID {
			continue
		}
		markerEnded = true
		if after.LatestUnresolvedAttemptID == group.GroupID {
			after.LatestUnresolvedAttemptID = contract.ID{}
		}
	}
	if markerEnded && after.OwnerState == contract.PublicationOwnerUncertainCreate &&
		!publicationRetainedUncertainCreate(index, after) {
		after.OwnerState = contract.PublicationOwnerNone
	}
	return after
}

type endWorkPublicationCoordinate struct {
	before, after contract.PublicationCoordinate
}

// Validate every retained coordinate before using the one-for-one page bound.
// Returned ordinals are physical, including gaps left by earlier dispositions.
func (s *StateSession) endWorkPublicationCoordinateChanges(index format.AdministrativeIndex, ended []format.AdministrativeGroup,
	coordinates map[contract.ID]contract.PublicationCoordinate) (map[format.Ref]map[uint16]endWorkPublicationCoordinate, error) {
	if s == nil || !index.Valid() || !s.adminIndex.Valid() {
		return nil, contract.ErrRecord
	}
	pending := make(map[uint16]endWorkPublicationCoordinate)
	for i, group := range index.Groups {
		if group.OwnerKind != format.AdministrativePublicationCoordinate {
			continue
		}
		before, present := coordinates[group.GroupID]
		if !present || before.CoordinateID != group.GroupID || len(group.RelatedGroupIndexes) != 0 {
			return nil, contract.ErrRecord
		}
		pending[uint16(i)] = endWorkPublicationCoordinate{before, publicationCoordinateAfterDisposition(index, before, ended)}
	}
	changed := make(map[format.Ref]map[uint16]endWorkPublicationCoordinate)
	for _, page := range index.Pages {
		logical := 0
		for _, span := range page.Spans {
			coordinateSpan := !page.ReadRequired && slices.ContainsFunc(page.Rows[logical:logical+int(span.Count)], func(row format.AdministrativeRowSummary) bool {
				return row.Kind == contract.PublicationCoordinateSupportKind
			})
			if !coordinateSpan {
				logical += int(span.Count)
				continue
			}
			if span.Count != 1 || len(span.GroupIndexes) != 1 || index.Groups[span.GroupIndexes[0]].OwnerKind != format.AdministrativePublicationCoordinate {
				return nil, contract.ErrRecord
			}
			for _, owner := range span.GroupIndexes {
				coordinate, present := pending[owner]
				if index.Groups[owner].OwnerKind != format.AdministrativePublicationCoordinate {
					continue
				}
				if !present || page.ReadRequired || !span.Mandatory || span.Count != 1 || len(span.GroupIndexes) != 1 || logical >= len(page.Rows) {
					return nil, contract.ErrRecord
				}
				before, err := contract.EncodePublicationCoordinate(coordinate.before)
				if err != nil {
					return nil, err
				}
				after, err := contract.EncodePublicationCoordinate(coordinate.after)
				row := contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinate.before.CoordinateID, Body: before}
				prior := slices.IndexFunc(s.adminIndex.Pages, func(old format.AdministrativePage) bool { return old.Ref == page.Ref })
				if err != nil || len(before) != len(after) || !page.Rows[logical].MatchesRecord(row) || prior < 0 {
					return nil, contract.ErrRecord
				}
				oldLogical, selected := administrativeSelectedOrdinal(s.adminIndex.Pages[prior], span.First)
				if !selected || int(oldLogical) >= len(s.adminIndex.Pages[prior].Rows) || s.adminIndex.Pages[prior].Rows[oldLogical] != page.Rows[logical] {
					return nil, contract.ErrRecord
				}
				fresh, present, err := administrativeGroupFromRow(row, nil)
				group := index.Groups[owner]
				if err != nil || !present || fresh.OwnerID != group.OwnerID || fresh.TargetID != group.TargetID ||
					fresh.Affected != group.Affected || fresh.Dependencies != group.Dependencies ||
					fresh.EffectEntryCeiling != group.EffectEntryCeiling || publicationCoordinateEvidence(coordinate.before) != group.SelectedEvidenceSummary {
					return nil, contract.ErrRecord
				}
				if !coordinate.before.Equal(coordinate.after) {
					if changed[page.Ref] == nil {
						changed[page.Ref] = make(map[uint16]endWorkPublicationCoordinate)
					}
					changed[page.Ref][span.First] = coordinate
				}
				delete(pending, owner)
			}
			logical += int(span.Count)
		}
	}
	if len(pending) != 0 {
		return nil, contract.ErrRecord
	}
	return changed, nil
}

// Replace a changed coordinate's entire physical page at the same Index.
// Unselected bytes and every retained peer keep their physical ordinals.
func (s *StateSession) rebindEndWorkPublication(ctx context.Context, index *format.AdministrativeIndex,
	ended []format.AdministrativeGroup, ids endWorkIDs) (map[format.Ref]objectImage,
	map[format.Ref]format.RequiredSupportPageView, error) {
	if s == nil || index == nil || ids.operation.IsZero() || ids.snapshot.IsZero() || ids.receipts.IsZero() || ids.receiptIndex.IsZero() {
		return nil, nil, contract.ErrRecord
	}
	coordinates, err := s.publicationCoordinatesForDisposition()
	if err != nil {
		return nil, nil, err
	}
	changed, err := s.endWorkPublicationCoordinateChanges(*index, ended, coordinates)
	if err != nil || len(changed) == 0 {
		return nil, nil, err
	}
	used := s.signerOnlyClosureIDs()
	if used == nil {
		return nil, nil, contract.ErrRecord
	}
	images := make(map[format.Ref]objectImage)
	views := make(map[format.Ref]format.RequiredSupportPageView)
	for i, page := range index.Pages {
		changes := changed[page.Ref]
		if len(changes) == 0 {
			continue
		}
		if ctx == nil || ctx.Err() != nil {
			return nil, nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
		}
		body, result := s.selectedObjectReader().readOwned(ctx, page.Ref)
		if result.Outcome != 0 {
			return nil, nil, selectedReadFailure(result)
		}
		if uint64(len(body)) != uint64(page.Ref.Length) || contract.Hash(body) != page.Ref.Digest {
			return nil, nil, selectedReadFailure(failure(IntegrityFailure, InvalidReference))
		}
		physical, err := format.InspectRequiredSupportPage(body)
		if err != nil || physical.Domain != s.root.Domain || physical.Object != page.Ref.Object || physical.Index != page.Ref.Index {
			return nil, nil, selectedReadFailure(failure(IntegrityFailure, InvalidReference))
		}
		for ordinal := range changes {
			if int(ordinal) >= len(physical.Records) {
				return nil, nil, contract.ErrRecord
			}
		}
		rows := make([]contract.SupportRecord, len(physical.Records))
		for ordinal, record := range physical.Records {
			if ctx.Err() != nil {
				return nil, nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
			}
			rows[ordinal] = contract.SupportRecord(record)
			if coordinate, present := changes[uint16(ordinal)]; present {
				before, err := contract.InspectPublicationCoordinate(record.Body)
				if err != nil || record.Kind != contract.PublicationCoordinateSupportKind || record.RecordID != coordinate.before.CoordinateID || !before.Equal(coordinate.before) {
					return nil, nil, contract.ErrRecord
				}
				encoded, err := contract.EncodePublicationCoordinate(coordinate.after)
				if err != nil || len(encoded) != len(record.Body) {
					return nil, nil, contract.ErrRecord
				}
				// Retain exact backing; the coordinate encoder may return spare capacity.
				rows[ordinal].Body = make([]byte, len(encoded))
				copy(rows[ordinal].Body, encoded)
			}
		}
		preimage := append([]byte("ENKV/end-work-publication-page/v1\x00"), s.root.Domain[:]...)
		preimage = append(preimage, ids.operation[:]...)
		preimage = append(preimage, page.Ref.Digest[:]...)
		preimage = binary.BigEndian.AppendUint16(preimage, page.Ref.Index)
		object := contract.Hash(preimage)
		if used[object] || object == ids.operation || object == ids.transition || object == ids.snapshot || object == ids.revision ||
			object == ids.receipts || object == ids.receiptIndex || object == administrativeIndexObject(s.root.Domain, ids.snapshot) {
			return nil, nil, contract.ErrRecord
		}
		used[object] = true
		ref, _, image, err := endWorkSupportPage(s.root.Domain, object, page.Ref.Index, rows, nil)
		if err != nil || ref.Length != page.Ref.Length {
			return nil, nil, contract.ErrRecord
		}
		owned, err := format.InspectRequiredSupportPage(image)
		if err != nil || len(owned.Records) != len(physical.Records) {
			return nil, nil, contract.ErrRecord
		}
		view := format.RequiredSupportPageView{Domain: owned.Domain, Object: owned.Object, Index: owned.Index}
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				if int(ordinal) >= len(owned.Records) || !page.Rows[len(view.Records)].MatchesRecord(contract.SupportRecord(owned.Records[ordinal])) {
					return nil, nil, contract.ErrRecord
				}
				view.Records = append(view.Records, owned.Records[ordinal])
			}
		}
		index.Pages[i].Ref = ref
		images[ref], views[ref] = objectImage{ref: ref, body: image}, view
		for ordinal, coordinate := range changes {
			row := contract.SupportRecord(owned.Records[ordinal])
			fresh, present, groupErr := administrativeGroupFromRow(row, nil)
			group := slices.IndexFunc(index.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == coordinate.after.CoordinateID })
			if groupErr != nil || !present || group < 0 {
				return nil, nil, contract.ErrRecord
			}
			index.Groups[group].Affected, index.Groups[group].Dependencies = fresh.Affected, fresh.Dependencies
			index.Groups[group].EffectEntryCeiling = fresh.EffectEntryCeiling
			index.Groups[group].SelectedEvidenceSummary = publicationCoordinateEvidence(coordinate.after)
		}
	}
	if ctx.Err() != nil {
		return nil, nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	if !index.Valid() {
		return nil, nil, contract.ErrRecord
	}
	return images, views, nil
}

// Fixed-width coordinate changes replace exact physical pages one for one.
func (s *StateSession) endWorkPublicationRewriteAllowance(index format.AdministrativeIndex, ended []format.AdministrativeGroup) (uint64, uint64, error) {
	coordinates, err := s.publicationCoordinatesForDisposition()
	if err != nil {
		return 0, 0, err
	}
	_, err = s.endWorkPublicationCoordinateChanges(index, ended, coordinates)
	return 0, 0, err
}
