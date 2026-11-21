package core

import (
	"bytes"
	"context"
	"math"
	"slices"

	"enkv.sh/core/contract"
)

// The enclosing private admission supplies fresh identities. Rollover resets
// only the new counter and does not remove any blocker, ownership or ACK stamp.
func (s *StateSession) publicationCoordinateForAdmission(id, freshIncarnation contract.ID) (contract.PublicationCoordinate, error) {
	if s == nil || !s.root.Generated.ActiveOwner.IsZero() {
		return contract.PublicationCoordinate{}, contract.ErrRecord
	}
	coordinates, err := s.publicationCoordinatesForDisposition()
	if err != nil {
		return contract.PublicationCoordinate{}, err
	}
	coordinate, present := coordinates[id]
	if !present {
		return contract.PublicationCoordinate{}, contract.ErrRecord
	}
	if coordinate.LastAdmissionOrdinal == math.MaxUint64 {
		used := s.signerOnlyClosureIDs()
		if used == nil || freshIncarnation.IsZero() || used[freshIncarnation] {
			return contract.PublicationCoordinate{}, contract.ErrRecord
		}
		for _, order := range s.adminIndex.PublicationOrder {
			if slices.Contains(order.Incarnations, freshIncarnation) {
				return contract.PublicationCoordinate{}, contract.ErrRecord
			}
		}
		coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal = freshIncarnation, 1
	} else {
		if !freshIncarnation.IsZero() {
			return contract.PublicationCoordinate{}, contract.ErrRecord
		}
		coordinate.LastAdmissionOrdinal++
	}
	return coordinate, nil
}

func (s *StateSession) publicationReservationRows(rows []contract.SupportRecord, p *publicationRewritePlan) error {
	if err := publicationRowBounds(rows, true); err != nil {
		return err
	}
	_, loaded, err := s.publicationLoadedRowsForDisposition()
	if err != nil {
		return err
	}
	seen := make(map[generatedRecordKey]bool, len(rows))
	coordinates := make(map[contract.ID]contract.PublicationCoordinate)
	fresh := make(map[contract.ID]contract.PublicationMarker)
	used := s.signerOnlyClosureIDs()
	if used == nil {
		return contract.ErrRecord
	}
	for _, row := range rows {
		key := generatedRecordKey{row.Kind, row.RecordID}
		if seen[key] {
			return contract.ErrRecord
		}
		seen[key] = true
		switch row.Kind {
		case contract.PublicationCoordinateSupportKind:
			coordinate, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil || coordinate.DomainID != s.root.Domain || coordinate.CoordinateID != row.RecordID || p.widths[key] == 0 {
				return contract.ErrRecord
			}
			coordinates[row.RecordID] = coordinate
		case contract.PublicationMarkerSupportKind:
			marker, err := contract.InspectPublicationMarker(row.Body)
			if err != nil || marker.DomainID != s.root.Domain || marker.AttemptID != row.RecordID {
				return contract.ErrRecord
			}
			if old, present := loaded[key]; present {
				if old.digest.BodyLength() != uint32(len(row.Body)) || old.digest.BodyDigest() != contract.Hash(row.Body) {
					return contract.ErrRecord
				}
			} else {
				if p.widths[key] != 0 || used[row.RecordID] || marker.State != contract.PublicationMayHaveEntered || !fresh[marker.CoordinateID].AttemptID.IsZero() {
					return contract.ErrRecord
				}
				fresh[marker.CoordinateID] = marker
			}
		default:
			return contract.ErrRecord
		}
	}
	for key := range p.widths {
		if !seen[key] {
			return contract.ErrRecord
		}
	}
	if len(fresh) == 0 {
		return contract.ErrRecord
	}
	for id, coordinate := range coordinates {
		marker, present := fresh[id]
		record, found := loaded[generatedRecordKey{contract.PublicationCoordinateSupportKind, id}]
		if !found || record.coordinate == nil {
			return contract.ErrRecord
		}
		old := *record.coordinate
		if !present {
			if !coordinate.Equal(old) {
				return contract.ErrRecord
			}
			continue
		}
		projection := marker.Projection
		if projection.Action == contract.PublicationDeleteOwned || projection.Action == contract.PublicationDeleteReservedSlot {
			if projection.BindingIncarnationID != old.LastBindingIncarnationID || projection.EntryIncarnationID != old.LastEntryIncarnationID || projection.TargetRowDigest != old.DeletionTargetRowDigest {
				return contract.ErrRecord
			}
		}
		switch projection.Action {
		case contract.PublicationDeleteReservedSlot:
			create := loaded[generatedRecordKey{contract.PublicationMarkerSupportKind, projection.UncertainCreateAttemptID}].marker
			if create == nil || !publicationReservedSlotEligible(old, *create) {
				return contract.ErrRecord
			}
		case contract.PublicationDeleteOwned:
			birth := loaded[generatedRecordKey{contract.PublicationMarkerSupportKind, projection.OwnedBirthAttemptID}].marker
			if old.BindingState != contract.PublicationBindingRetired || old.OwnerState != contract.PublicationOwnerQualified || birth == nil {
				return contract.ErrRecord
			}
			lastDelete := loaded[generatedRecordKey{contract.PublicationMarkerSupportKind, old.LastDeleteAckAttemptID}].marker
			available, err := publicationBirthAvailable(old, *birth, lastDelete, s.adminIndex.PublicationOrder)
			if err != nil {
				return err
			}
			if !available {
				return contract.ErrRecord
			}
		}
		var incarnation contract.ID
		if old.LastAdmissionOrdinal == math.MaxUint64 {
			incarnation = coordinate.CurrentPublicationIncarnationID
		}
		expected, err := s.publicationCoordinateForAdmission(id, incarnation)
		if err != nil || coordinate.CurrentPublicationIncarnationID != expected.CurrentPublicationIncarnationID || coordinate.LastAdmissionOrdinal != expected.LastAdmissionOrdinal ||
			marker.PublicationIncarnationID != coordinate.CurrentPublicationIncarnationID || marker.AdmissionOrdinal != coordinate.LastAdmissionOrdinal || coordinate.LatestUnresolvedAttemptID != marker.AttemptID {
			return contract.ErrRecord
		}
		// Admission preserves all historical equality witnesses and qualified
		// ownership. The close, rather than reservation, can change those facts.
		create := marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue
		old.CurrentPublicationIncarnationID, old.LastAdmissionOrdinal = coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal
		old.LatestUnresolvedAttemptID = coordinate.LatestUnresolvedAttemptID
		if create {
			if old.BindingState != contract.PublicationBindingActive || old.OwnerState == contract.PublicationOwnerQualified ||
				coordinate.OwnerState != contract.PublicationOwnerUncertainCreate || coordinate.PossibleRemoteObject != 1 ||
				marker.Projection.BindingIncarnationID != old.ActiveBindingIncarnationID ||
				coordinate.LastBindingIncarnationID != marker.Projection.BindingIncarnationID || coordinate.LastEntryIncarnationID != marker.Projection.EntryIncarnationID ||
				coordinate.DeletionTargetRowDigest != marker.Projection.TargetRowDigest || coordinate.ServiceContractID != marker.BirthServiceContractID ||
				coordinate.DeletionTargetContractID != marker.BirthTargetContractID {
				return contract.ErrRecord
			}
			if old.DeletionTargetRowDigest.IsZero() {
				if old.OwnerState != contract.PublicationOwnerNone || old.PossibleRemoteObject != 0 || old.LateEffectRisk != 0 {
					return contract.ErrRecord
				}
				old.LastBindingIncarnationID, old.LastEntryIncarnationID = coordinate.LastBindingIncarnationID, coordinate.LastEntryIncarnationID
				old.DeletionDestinationID, old.DeletionConsumerLocator = coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator
				old.DeletionTargetContractID, old.DeletionConfigContractID = coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID
				old.DeletionTargetData = bytes.Clone(coordinate.DeletionTargetData)
				old.DeletionCredentialRouteContractID = coordinate.DeletionCredentialRouteContractID
				old.LocatorRequiresCreation = coordinate.LocatorRequiresCreation
				old.DeletionPayloadEncoding = coordinate.DeletionPayloadEncoding
				old.DeletionTargetRowDigest = coordinate.DeletionTargetRowDigest
			}
			old.OwnerState, old.PossibleRemoteObject = contract.PublicationOwnerUncertainCreate, 1
		}
		if !old.Equal(coordinate) {
			return contract.ErrRecord
		}
	}
	for id := range fresh {
		if coordinates[id].CoordinateID.IsZero() {
			return contract.ErrRecord
		}
	}
	return nil
}

// This construction is also the payload preflight: it emits only public
// candidate bytes and proves the actual new envelope plus future growth before
// the parent prepares private payloads or arms a send permission.
func (s *StateSession) materializePublicationReservationConstruction(ctx context.Context, next *StateSession,
	candidate *Candidate, input *publicationConstruction, pageIDs []contract.ID) error {
	if s == nil || !s.admission.valid(s.store) {
		return contract.ErrRecord
	}
	if err := input.begin(ctx, s, next, candidate); err != nil {
		return err
	}
	p, rows := input.rewrite, input.rows
	if err := publicationRowBounds(rows, true); err != nil {
		return err
	}
	if err := s.publicationReservationRows(rows, p); err != nil {
		return err
	}
	staged := Candidate{session: s}
	successor := *next
	if err := s.writePublicationConstruction(ctx, input, &successor, &staged, pageIDs); err != nil {
		return err
	}
	*next = successor
	candidate.objects = append(candidate.objects, staged.objects...)
	return nil
}
