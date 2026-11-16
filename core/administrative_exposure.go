package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationMarkerProvesUncertainCreate(marker contract.PublicationMarker, coordinate contract.PublicationCoordinate) bool {
	return coordinate.OwnerState == contract.PublicationOwnerUncertainCreate &&
		marker.CoordinateID == coordinate.CoordinateID &&
		(marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue) &&
		(marker.State == contract.PublicationMayHaveEntered || marker.State == contract.PublicationUnknown) &&
		marker.Projection.BindingIncarnationID == coordinate.LastBindingIncarnationID &&
		marker.Projection.EntryIncarnationID == coordinate.LastEntryIncarnationID &&
		marker.Projection.TargetRowDigest == coordinate.DeletionTargetRowDigest
}

// Full writers derive these mandatory facts from the exact selected actions.
// An administrative disposition carries them without reading optional detail.
func administrativeExposure(index format.AdministrativeIndex, pages []format.RequiredSupportPageView,
	consumers administrativeConsumers, facts ...map[generatedRecordKey]selectedPublicationRecord) ([]uint8, []uint8, error) {
	var retained map[generatedRecordKey]selectedPublicationRecord
	if len(facts) > 1 {
		return nil, nil, contract.ErrRecord
	}
	if len(facts) == 1 {
		retained = facts[0]
	}
	destructive := make(map[contract.ID]bool)
	for id, attempt := range consumers.attempts {
		if attempt.State < contract.GeneratedEffectTransmitted || consumers.actions[id] != contract.GeneratorActionDelete {
			continue
		}
		destructive[attempt.OperationID] = true
		for _, owner := range consumers.attempt[id] {
			destructive[owner] = true
		}
	}
	coordinates := make(map[contract.ID]contract.PublicationCoordinate)
	markers := make(map[contract.ID]contract.PublicationMarker)
	for _, page := range pages {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.PublicationCoordinateSupportKind:
				fact, err := publicationRecordWithFacts(index.Domain, contract.SupportRecord(row), retained)
				if err != nil || fact.coordinate == nil || fact.coordinate.CoordinateID != row.RecordID {
					return nil, nil, contract.ErrRecord
				}
				coordinates[row.RecordID] = *fact.coordinate
			case contract.PublicationMarkerSupportKind:
				fact, err := publicationRecordWithFacts(index.Domain, contract.SupportRecord(row), retained)
				if err != nil || fact.marker == nil || fact.marker.AttemptID != row.RecordID {
					return nil, nil, contract.ErrRecord
				}
				markers[row.RecordID] = *fact.marker
			}
		}
	}
	deletes, creates := make([]uint8, len(index.Groups)), make([]uint8, len(index.Groups))
	for i, group := range index.Groups {
		if group.OwnerKind <= format.AdministrativeInboxRelease {
			deletes[i] = boolByte(destructive[group.GroupID])
		}
		if group.OwnerKind == format.AdministrativePublicationMarker {
			marker, present := markers[group.GroupID]
			coordinate, selected := coordinates[group.OwnerID]
			if !present || !selected {
				return nil, nil, contract.ErrRecord
			}
			creates[i] = boolByte(publicationMarkerProvesUncertainCreate(marker, coordinate))
		}
	}
	return deletes, creates, nil
}

func validateAdministrativeExposure(index format.AdministrativeIndex, views []format.RequiredSupportPageView, selected *generatedSelection, retained ...map[generatedRecordKey]selectedPublicationRecord) error {
	var publication map[generatedRecordKey]selectedPublicationRecord
	if len(retained) > 1 {
		return contract.ErrRecord
	}
	if len(retained) == 1 {
		publication = retained[0]
	}
	pages := make([]format.RequiredSupportPage, len(views))
	for i, view := range views {
		pages[i] = format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index,
			Records: make([]contract.SupportRecord, len(view.Records))}
		for j, row := range view.Records {
			pages[i].Records[j] = contract.SupportRecord(row)
		}
	}
	consumers, err := selectedAdministrativeConsumersWithValidated(pages, nil, nil, selected)
	if err != nil {
		return err
	}
	deletes, creates, err := administrativeExposure(index, views, consumers, publication)
	if err != nil {
		return err
	}
	for i, group := range index.Groups {
		if group.DestructiveEffect != deletes[i] || group.UncertainCreateProof != creates[i] {
			return contract.ErrRecord
		}
	}
	return nil
}
