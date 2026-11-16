package core

import (
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedPublication is derived from the complete selected support image. It
// contains public facts only and carries no permission to send an action.
type selectedPublication struct {
	coordinates map[contract.ID]contract.PublicationCoordinate
	markers     map[contract.ID]contract.PublicationMarker
}

func publicationQualifiedBirthValid(domain contract.ID, coordinate contract.PublicationCoordinate,
	birth contract.PublicationMarker) bool {
	if birth.CoordinateID != coordinate.CoordinateID || birth.AttemptID != coordinate.OwnedBirthAttemptID ||
		birth.State != contract.PublicationAcknowledged ||
		(birth.Projection.Action != contract.PublicationCreateEmpty && birth.Projection.Action != contract.PublicationCreateWithValue) ||
		birth.Projection.BindingIncarnationID != coordinate.LastBindingIncarnationID ||
		birth.Projection.EntryIncarnationID != coordinate.LastEntryIncarnationID ||
		birth.Projection.TargetRowDigest != coordinate.DeletionTargetRowDigest ||
		birth.BirthServiceContractID != coordinate.ServiceContractID ||
		birth.BirthTargetContractID != coordinate.DeletionTargetContractID ||
		birth.Evidence.ConsumerLocator == "" || birth.Evidence.ConsumerLocator != coordinate.DeletionConsumerLocator {
		return false
	}
	digest, err := contract.PublicationOwnedInstanceDigest(domain, coordinate.CoordinateID,
		birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID,
		birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	return err == nil && digest == coordinate.OwnedInstanceDigest
}

func inspectPublicationRows(domain contract.ID, rows []contract.SupportRecord) (selectedPublication, error) {
	if err := publicationRowBounds(rows, false); err != nil {
		return selectedPublication{}, err
	}
	selected := selectedPublication{coordinates: make(map[contract.ID]contract.PublicationCoordinate), markers: make(map[contract.ID]contract.PublicationMarker)}
	for _, row := range rows {
		switch row.Kind {
		case contract.PublicationCoordinateSupportKind:
			v, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil || v.DomainID != domain || v.CoordinateID != row.RecordID ||
				len(selected.coordinates) == contract.MaxPublicationCoordinates ||
				!selected.coordinates[v.CoordinateID].CoordinateID.IsZero() {
				return selectedPublication{}, contract.ErrRecord
			}
			selected.coordinates[v.CoordinateID] = v
		case contract.PublicationMarkerSupportKind:
			v, err := contract.InspectPublicationMarker(row.Body)
			if err != nil || v.DomainID != domain || v.Projection.DomainID != domain || v.AttemptID != row.RecordID ||
				len(selected.markers) == contract.MaxPublicationMarkers ||
				!selected.markers[v.AttemptID].AttemptID.IsZero() {
				return selectedPublication{}, contract.ErrRecord
			}
			selected.markers[v.AttemptID] = v
		}
	}
	return selected, nil
}

func publicationRowsRelation(domain contract.ID, rows []contract.SupportRecord, orders []format.PublicationCoordinateOrder) (selectedPublication, error) {
	if err := publicationRowBounds(rows, false); err != nil {
		return selectedPublication{}, err
	}
	if len(orders) > contract.MaxPublicationCoordinates {
		return selectedPublication{}, contract.ErrRecordCapacity
	}
	var incarnationCount int
	for _, order := range orders {
		incarnationCount += len(order.Incarnations)
		if incarnationCount > contract.MaxPublicationIncarnations {
			return selectedPublication{}, contract.ErrRecordCapacity
		}
	}
	selected, err := inspectPublicationRows(domain, rows)
	if err != nil {
		return selectedPublication{}, err
	}
	return publicationTypedRelation(domain, selected, orders)
}

func publicationTypedRelation(domain contract.ID, selected selectedPublication, orders []format.PublicationCoordinateOrder) (selectedPublication, error) {
	if len(selected.coordinates) > contract.MaxPublicationCoordinates || len(selected.markers) > contract.MaxPublicationMarkers || len(orders) > contract.MaxPublicationCoordinates {
		return selectedPublication{}, contract.ErrRecordCapacity
	}
	var incarnationCount int
	for _, order := range orders {
		incarnationCount += len(order.Incarnations)
		if incarnationCount > contract.MaxPublicationIncarnations {
			return selectedPublication{}, contract.ErrRecordCapacity
		}
	}
	type stamp struct {
		incarnation contract.ID
		ordinal     uint64
	}
	ordinals := make(map[stamp]bool)
	positions := make(map[contract.ID]map[contract.ID]int, len(orders))
	for _, order := range orders {
		if positions[order.CoordinateID] != nil {
			return selectedPublication{}, contract.ErrRecord
		}
		positions[order.CoordinateID] = make(map[contract.ID]int, len(order.Incarnations))
		for i, id := range order.Incarnations {
			positions[order.CoordinateID][id] = i + 1
		}
	}
	before := func(a, b contract.PublicationMarker) bool {
		first, last := positions[a.CoordinateID][a.PublicationIncarnationID], positions[b.CoordinateID][b.PublicationIncarnationID]
		return a.CoordinateID == b.CoordinateID && first != 0 && last != 0 && (first < last || first == last && a.AdmissionOrdinal < b.AdmissionOrdinal)
	}
	byCoordinate := make(map[contract.ID][]contract.ID, len(selected.coordinates))
	for id, marker := range selected.markers {
		coordinate, present := selected.coordinates[marker.CoordinateID]
		if !present || marker.Projection.CoordinateID != coordinate.CoordinateID ||
			marker.PublicationIncarnationID == coordinate.CurrentPublicationIncarnationID && marker.AdmissionOrdinal > coordinate.LastAdmissionOrdinal ||
			positions[marker.CoordinateID][marker.PublicationIncarnationID] == 0 ||
			!selected.coordinates[id].CoordinateID.IsZero() {
			return selectedPublication{}, contract.ErrRecord
		}
		// An exit can clear the cached pointer while another entered action
		// remains. Its selected marker still requires the frozen deletion inputs.
		if (marker.State == contract.PublicationMayHaveEntered || marker.State == contract.PublicationUnknown) &&
			coordinate.DeletionTargetRowDigest.IsZero() {
			return selectedPublication{}, contract.ErrRecord
		}
		key := stamp{marker.PublicationIncarnationID, marker.AdmissionOrdinal}
		if ordinals[key] {
			return selectedPublication{}, contract.ErrRecord
		}
		ordinals[key] = true
		if !marker.Projection.OwnedBirthAttemptID.IsZero() {
			birth, present := selected.markers[marker.Projection.OwnedBirthAttemptID]
			if !present || birth.State != contract.PublicationAcknowledged ||
				(birth.Projection.Action != contract.PublicationCreateEmpty && birth.Projection.Action != contract.PublicationCreateWithValue) ||
				birth.CoordinateID != marker.CoordinateID || !before(birth, marker) ||
				birth.Projection.BindingIncarnationID != marker.Projection.BindingIncarnationID ||
				birth.Projection.EntryIncarnationID != marker.Projection.EntryIncarnationID {
				return selectedPublication{}, contract.ErrRecord
			}
		}
		if marker.Projection.Action == contract.PublicationDeleteReservedSlot {
			uncertain, found := selected.markers[marker.Projection.UncertainCreateAttemptID]
			if !found || uncertain.CoordinateID != marker.CoordinateID ||
				(uncertain.Projection.Action != contract.PublicationCreateEmpty && uncertain.Projection.Action != contract.PublicationCreateWithValue) ||
				!before(uncertain, marker) ||
				uncertain.Projection.BindingIncarnationID != marker.Projection.BindingIncarnationID ||
				uncertain.Projection.EntryIncarnationID != marker.Projection.EntryIncarnationID {
				return selectedPublication{}, contract.ErrRecord
			}
		}
		byCoordinate[marker.CoordinateID] = append(byCoordinate[marker.CoordinateID], id)
	}
	for _, coordinate := range selected.coordinates {
		if !coordinate.LatestUnresolvedAttemptID.IsZero() {
			marker, present := selected.markers[coordinate.LatestUnresolvedAttemptID]
			if !present || marker.CoordinateID != coordinate.CoordinateID ||
				(marker.State != contract.PublicationMayHaveEntered && marker.State != contract.PublicationUnknown) {
				return selectedPublication{}, contract.ErrRecord
			}
		}
		// Terminal ACK summaries can outlive their selected markers. When a
		// marker remains, its exact acknowledged action must still explain the
		// signed summary. A missing marker is a compacted witness, not a new
		// permission or evidence of remote absence.
		if marker, present := selected.markers[coordinate.LastValueAckAttemptID]; present {
			if marker.PublicationIncarnationID != coordinate.LastValueAckIncarnationID || marker.AdmissionOrdinal != coordinate.LastValueAckOrdinal || marker.CoordinateID != coordinate.CoordinateID || marker.State != contract.PublicationAcknowledged ||
				(marker.Projection.Action != contract.PublicationCreateWithValue && marker.Projection.Action != contract.PublicationWriteValue) {
				return selectedPublication{}, contract.ErrRecord
			}
			birth := marker
			if marker.Projection.Action == contract.PublicationWriteValue {
				var found bool
				birth, found = selected.markers[marker.Projection.OwnedBirthAttemptID]
				if !found {
					return selectedPublication{}, contract.ErrRecord
				}
			}
			owner, err := contract.PublicationOwnedInstanceDigest(domain, marker.CoordinateID,
				birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID,
				birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
			if err != nil {
				return selectedPublication{}, contract.ErrRecord
			}
			value, err := contract.PublicationSelectedValueDigest(domain, marker.Projection.ValueBasisDigest, birth.AttemptID, owner)
			if err != nil || value != coordinate.LastValueDigest {
				return selectedPublication{}, contract.ErrRecord
			}
		}
		if marker, present := selected.markers[coordinate.LastPolicyAckAttemptID]; present &&
			(marker.PublicationIncarnationID != coordinate.LastPolicyAckIncarnationID || marker.AdmissionOrdinal != coordinate.LastPolicyAckOrdinal || marker.CoordinateID != coordinate.CoordinateID || marker.State != contract.PublicationAcknowledged ||
				(marker.Projection.Action != contract.PublicationCreateEmpty && marker.Projection.Action != contract.PublicationCreateWithValue &&
					marker.Projection.Action != contract.PublicationWriteValue && marker.Projection.Action != contract.PublicationUpdatePolicy) ||
				marker.Projection.PolicyDigest != coordinate.LastPolicyDigest) {
			return selectedPublication{}, contract.ErrRecord
		}
		if marker, present := selected.markers[coordinate.LastDeleteAckAttemptID]; present &&
			(marker.PublicationIncarnationID != coordinate.LastDeleteAckIncarnationID || marker.AdmissionOrdinal != coordinate.LastDeleteAckOrdinal || marker.CoordinateID != coordinate.CoordinateID || marker.State != contract.PublicationAcknowledged ||
				(marker.Projection.Action != contract.PublicationDeleteOwned && marker.Projection.Action != contract.PublicationDeleteReservedSlot)) {
			return selectedPublication{}, contract.ErrRecord
		}
		switch coordinate.OwnerState {
		case contract.PublicationOwnerQualified:
			birth, present := selected.markers[coordinate.OwnedBirthAttemptID]
			if !present || !publicationQualifiedBirthValid(domain, coordinate, birth) {
				return selectedPublication{}, contract.ErrRecord
			}
		case contract.PublicationOwnerUncertainCreate:
			found := false
			for _, id := range byCoordinate[coordinate.CoordinateID] {
				marker := selected.markers[id]
				if marker.CoordinateID == coordinate.CoordinateID &&
					(marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue) &&
					(marker.State == contract.PublicationMayHaveEntered || marker.State == contract.PublicationUnknown) &&
					marker.Projection.BindingIncarnationID == coordinate.LastBindingIncarnationID &&
					marker.Projection.EntryIncarnationID == coordinate.LastEntryIncarnationID &&
					marker.Projection.TargetRowDigest == coordinate.DeletionTargetRowDigest {
					found = true
					break
				}
			}
			if !found {
				return selectedPublication{}, contract.ErrRecord
			}
		}
	}
	if len(orders) != len(selected.coordinates) {
		return selectedPublication{}, contract.ErrRecord
	}
	for _, order := range orders {
		coordinate, ok := selected.coordinates[order.CoordinateID]
		if !ok || len(order.Incarnations) == 0 || order.Incarnations[len(order.Incarnations)-1] != coordinate.CurrentPublicationIncarnationID {
			return selectedPublication{}, contract.ErrRecord
		}
		union := map[contract.ID]bool{coordinate.CurrentPublicationIncarnationID: true}
		for _, id := range byCoordinate[coordinate.CoordinateID] {
			marker := selected.markers[id]
			if marker.CoordinateID == coordinate.CoordinateID {
				union[marker.PublicationIncarnationID] = true
			}
		}
		for _, id := range []contract.ID{coordinate.LastValueAckIncarnationID, coordinate.LastPolicyAckIncarnationID, coordinate.LastDeleteAckIncarnationID} {
			if !id.IsZero() {
				union[id] = true
			}
		}
		if len(union) != len(order.Incarnations) {
			return selectedPublication{}, contract.ErrRecord
		}
		for _, id := range order.Incarnations {
			if !union[id] {
				return selectedPublication{}, contract.ErrRecord
			}
			delete(union, id)
		}
	}
	return selected, nil
}

// selectedPublicationRelation adds exact index ownership to the typed row
// relation. Its caller has authenticated the signed Root and selected support.
func selectedPublicationRelation(image *selectedImage) (selectedPublication, error) {
	if image == nil || !image.adminIndex.Valid() || image.adminIndex.Domain != image.root.Domain ||
		image.adminIndex.Object != image.root.AdministrativeIndex.Object ||
		len(image.adminIndex.Pages) != len(image.support) || len(image.support) != len(image.root.RequiredSupport) {
		return selectedPublication{}, contract.ErrRecord
	}
	if err := publicationSupportBounds(image.support); err != nil {
		return selectedPublication{}, err
	}
	publicationCount := 0
	for _, page := range image.support {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				publicationCount++
			}
		}
	}
	rows := make([]contract.SupportRecord, 0, publicationCount)
	for _, page := range image.support {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				rows = append(rows, contract.SupportRecord(row))
			}
		}
	}
	selected, err := image.publicationRows(rows)
	if err == nil {
		selected, err = publicationTypedRelation(image.root.Domain, selected, image.adminIndex.PublicationOrder)
	}
	if err != nil {
		return selectedPublication{}, err
	}
	if err := validatePublicationIndexRelation(image, selected); err != nil {
		return selectedPublication{}, err
	}
	return selected, nil
}

func validatePublicationIndexRelation(image *selectedImage, selected selectedPublication) error {
	if image == nil || !image.adminIndex.Valid() || image.adminIndex.Domain != image.root.Domain ||
		image.adminIndex.Object != image.root.AdministrativeIndex.Object ||
		len(image.adminIndex.Pages) != len(image.support) || len(image.support) != len(image.root.RequiredSupport) {
		return contract.ErrRecord
	}
	if err := publicationSupportBounds(image.support); err != nil {
		return err
	}
	type owner struct {
		group     uint16
		mandatory bool
	}
	owned := make(map[contract.ID]owner, len(selected.coordinates)+len(selected.markers))
	for i, page := range image.adminIndex.Pages {
		if page.Ref != image.root.RequiredSupport[i] {
			return contract.ErrRecord
		}
		logical := 0
		for _, span := range page.Spans {
			for j := 0; j < int(span.Count); j++ {
				var kind uint8
				var id contract.ID
				if len(image.supportFacts) == len(image.support) && len(image.supportFacts[i].rows) != 0 {
					if logical >= len(image.supportFacts[i].rows) {
						return contract.ErrRecord
					}
					fact := image.supportFacts[i].rows[logical]
					kind, id = fact.Kind(), fact.RecordID()
				} else {
					if logical >= len(image.support[i].Records) {
						return contract.ErrRecord
					}
					row := image.support[i].Records[logical]
					kind, id = row.Kind, row.RecordID
				}
				logical++
				if kind != contract.PublicationCoordinateSupportKind && kind != contract.PublicationMarkerSupportKind {
					continue
				}
				if _, duplicate := owned[id]; duplicate || len(span.GroupIndexes) != 1 {
					return contract.ErrRecord
				}
				group := span.GroupIndexes[0]
				if int(group) >= len(image.adminIndex.Groups) || image.adminIndex.Groups[group].GroupID != id ||
					kind == contract.PublicationCoordinateSupportKind && image.adminIndex.Groups[group].OwnerKind != format.AdministrativePublicationCoordinate ||
					kind == contract.PublicationMarkerSupportKind && image.adminIndex.Groups[group].OwnerKind != format.AdministrativePublicationMarker {
					return contract.ErrRecord
				}
				owned[id] = owner{group: group, mandatory: span.Mandatory}
			}
		}
	}
	if len(owned) != len(selected.coordinates)+len(selected.markers) {
		return contract.ErrRecord
	}
	requiredBirths := make(map[contract.ID]bool)
	for _, coordinate := range selected.coordinates {
		if coordinate.OwnerState == contract.PublicationOwnerQualified {
			requiredBirths[coordinate.OwnedBirthAttemptID] = true
		}
	}
	for _, marker := range selected.markers {
		if !marker.Projection.OwnedBirthAttemptID.IsZero() {
			requiredBirths[marker.Projection.OwnedBirthAttemptID] = true
		}
	}
	for i, group := range image.adminIndex.Groups {
		switch group.OwnerKind {
		case format.AdministrativePublicationCoordinate:
			_, ok := selected.coordinates[group.GroupID]
			if !ok || group.OwnerID != group.GroupID || group.TargetID != group.GroupID ||
				len(group.RelatedGroupIndexes) != 0 || owned[group.GroupID].group != uint16(i) ||
				!owned[group.GroupID].mandatory {
				return contract.ErrRecord
			}
		case format.AdministrativePublicationMarker:
			marker, ok := selected.markers[group.GroupID]
			if !ok {
				return contract.ErrRecord
			}
			related := []uint16{owned[marker.CoordinateID].group}
			if !marker.Projection.OwnedBirthAttemptID.IsZero() {
				related = append(related, owned[marker.Projection.OwnedBirthAttemptID].group)
			}
			if marker.Projection.Action == contract.PublicationDeleteReservedSlot {
				related = append(related, owned[marker.Projection.UncertainCreateAttemptID].group)
			}
			slices.Sort(related)
			if group.PublicationIncarnationID != marker.PublicationIncarnationID || group.AdmissionOrdinal != marker.AdmissionOrdinal || group.OwnerID != marker.CoordinateID || group.TargetID != marker.CoordinateID ||
				!slices.Equal(group.RelatedGroupIndexes, related) ||
				owned[group.GroupID].group != uint16(i) {
				return contract.ErrRecord
			}
			if requiredBirths[marker.AttemptID] && !owned[group.GroupID].mandatory {
				return contract.ErrRecord
			}
		}
	}
	return nil
}

// An administrative exit can leave optional marker bodies unreadable. Its
// mandatory coordinate bodies still determine whether the named owner or birth
// may be disposed. The authenticated index supplies exact selected row IDs.
func (s *StateSession) publicationLoadedRowsForDisposition() (map[generatedRecordKey]administrativeRowOwnership,
	map[generatedRecordKey]selectedPublicationRecord, error) {
	if s == nil {
		return nil, nil, contract.ErrRecord
	}
	if err := publicationSupportBounds(s.support); err != nil {
		return nil, nil, err
	}
	positions, err := s.priorAdministrativeRows()
	if err != nil {
		return nil, nil, err
	}
	owners := make(map[generatedRecordKey]administrativeRowOwnership)
	for key, position := range positions {
		if key.kind != contract.PublicationCoordinateSupportKind && key.kind != contract.PublicationMarkerSupportKind {
			continue
		}
		if len(s.adminIndex.Pages[position.page].Spans[position.span].GroupIndexes) != 1 {
			return nil, nil, contract.ErrRecord
		}
		owners[key] = s.priorAdministrativeOwnership(position)
	}
	loaded := make(map[generatedRecordKey]selectedPublicationRecord)
	if len(s.supportFacts) != 0 && len(s.supportFacts) != len(s.support) {
		return nil, nil, contract.ErrRecord
	}
	for i, page := range s.support {
		selectedFacts := len(s.supportFacts) != 0
		if selectedFacts && (s.supportFacts[i].ref != s.adminIndex.Pages[i].Ref ||
			len(s.supportFacts[i].rows) != len(s.supportFacts[i].ordinals)) {
			return nil, nil, contract.ErrRecord
		}
		spanPosition, spanStart := 0, 0
		for logical, row := range page.Records {
			for spanPosition < len(s.adminIndex.Pages[i].Spans) &&
				logical >= spanStart+int(s.adminIndex.Pages[i].Spans[spanPosition].Count) {
				spanStart += int(s.adminIndex.Pages[i].Spans[spanPosition].Count)
				spanPosition++
			}
			if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
				continue
			}
			key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
			if _, selected := owners[key]; !selected {
				return nil, nil, contract.ErrRecord
			}
			if _, duplicate := loaded[key]; duplicate {
				return nil, nil, contract.ErrRecord
			}
			if selectedFacts {
				// Provisional receipt pages have no new facts. Only loaded
				// publication rows require a complete page fact vector here.
				if len(s.supportFacts[i].rows) != len(page.Records) {
					return nil, nil, contract.ErrRecord
				}
				fact := s.supportFacts[i].rows[logical]
				if spanPosition >= len(s.adminIndex.Pages[i].Spans) || fact.Kind() != row.Kind ||
					fact.RecordID() != row.RecordID || row.Body != nil && (fact.BodyLength() != uint32(len(row.Body)) ||
					fact.BodyDigest() != contract.Hash(row.Body)) ||
					uint32(s.supportFacts[i].ordinals[logical]) != uint32(s.adminIndex.Pages[i].Spans[spanPosition].First)+uint32(logical-spanStart) {
					return nil, nil, contract.ErrRecord
				}
			}
			decoded, err := s.publicationRecord(contract.SupportRecord(row))
			if err != nil {
				return nil, nil, err
			}
			loaded[key] = decoded
		}
	}
	for key, owner := range owners {
		if key.kind != contract.PublicationMarkerSupportKind || !owner.mandatory {
			continue
		}
		row, present := loaded[key]
		if !present {
			return nil, nil, contract.ErrRecord
		}
		marker := row.marker
		if marker == nil || marker.AttemptID != key.id || marker.State != contract.PublicationAcknowledged ||
			(marker.Projection.Action != contract.PublicationCreateEmpty && marker.Projection.Action != contract.PublicationCreateWithValue) {
			return nil, nil, contract.ErrRecord
		}
	}
	return owners, loaded, nil
}

func (s *StateSession) publicationCoordinatesForDisposition() (map[contract.ID]contract.PublicationCoordinate, error) {
	coordinates := make(map[contract.ID]contract.PublicationCoordinate)
	havePublication := false
	for _, group := range s.adminIndex.Groups {
		if group.OwnerKind == format.AdministrativePublicationCoordinate || group.OwnerKind == format.AdministrativePublicationMarker {
			havePublication = true
			break
		}
	}
	if !havePublication {
		return coordinates, nil
	}
	owners, loaded, err := s.publicationLoadedRowsForDisposition()
	if err != nil {
		return nil, err
	}
	for _, group := range s.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativePublicationCoordinate {
			continue
		}
		key := generatedRecordKey{kind: contract.PublicationCoordinateSupportKind, id: group.GroupID}
		owner, present := owners[key]
		if !present || len(owner.groups) != 1 || owner.groups[0] != group.GroupID ||
			group.OwnerID != group.GroupID || group.TargetID != group.GroupID {
			return nil, contract.ErrRecord
		}
		row, present := loaded[key]
		if !owner.mandatory || !present {
			return nil, contract.ErrRecord
		}
		if !present {
			continue
		}
		coordinate := row.coordinate
		if coordinate == nil || coordinate.DomainID != s.root.Domain || coordinate.CoordinateID != group.GroupID ||
			(coordinate.BindingState == contract.PublicationBindingActive || coordinate.OwnerState != contract.PublicationOwnerNone ||
				coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 ||
				!coordinate.LatestUnresolvedAttemptID.IsZero()) && !owner.mandatory {
			return nil, contract.ErrRecord
		}
		coordinates[group.GroupID] = *coordinate
	}
	uncertainProofs := make(map[contract.ID]bool)
	for _, group := range s.adminIndex.Groups {
		if group.UncertainCreateProof == 0 {
			continue
		}
		coordinate, present := coordinates[group.OwnerID]
		if !present || coordinate.OwnerState != contract.PublicationOwnerUncertainCreate {
			return nil, contract.ErrRecord
		}
		uncertainProofs[coordinate.CoordinateID] = true
	}
	for _, coordinate := range coordinates {
		if coordinate.OwnerState == contract.PublicationOwnerUncertainCreate && !uncertainProofs[coordinate.CoordinateID] {
			return nil, contract.ErrRecord
		}
		if coordinate.OwnerState != contract.PublicationOwnerQualified {
			continue
		}
		key := generatedRecordKey{kind: contract.PublicationMarkerSupportKind, id: coordinate.OwnedBirthAttemptID}
		owner, selected := owners[key]
		row, present := loaded[key]
		if !selected || !owner.mandatory || len(owner.groups) != 1 || owner.groups[0] != coordinate.OwnedBirthAttemptID || !present {
			return nil, contract.ErrRecord
		}
		birth := row.marker
		if birth == nil || !publicationQualifiedBirthValid(s.root.Domain, coordinate, *birth) {
			return nil, contract.ErrRecord
		}
	}
	if _, err := publicationIncarnationOrder(s.adminIndex, coordinates, false); err != nil {
		return nil, err
	}
	return coordinates, nil
}

// Partial readers use mandatory coordinates and authenticated marker stamps.
// Filtering drops only unreferenced IDs and preserves their previous order.
func publicationIncarnationOrder(index format.AdministrativeIndex, coordinates map[contract.ID]contract.PublicationCoordinate, filter bool) ([]format.PublicationCoordinateOrder, error) {
	unions := make(map[contract.ID]map[contract.ID]bool, len(coordinates))
	for _, group := range index.Groups {
		if group.OwnerKind != format.AdministrativePublicationCoordinate {
			continue
		}
		coordinate, present := coordinates[group.GroupID]
		if !present || group.OwnerID != coordinate.CoordinateID || group.TargetID != coordinate.CoordinateID {
			return nil, contract.ErrRecord
		}
		union := map[contract.ID]bool{coordinate.CurrentPublicationIncarnationID: true}
		for _, id := range []contract.ID{coordinate.LastValueAckIncarnationID, coordinate.LastPolicyAckIncarnationID, coordinate.LastDeleteAckIncarnationID} {
			if !id.IsZero() {
				union[id] = true
			}
		}
		unions[coordinate.CoordinateID] = union
	}
	type admissionStamp struct {
		coordinate, incarnation contract.ID
		ordinal                 uint64
	}
	stamps := make(map[admissionStamp]bool)
	for _, group := range index.Groups {
		if group.OwnerKind != format.AdministrativePublicationMarker {
			continue
		}
		stamp := admissionStamp{group.OwnerID, group.PublicationIncarnationID, group.AdmissionOrdinal}
		if stamps[stamp] {
			return nil, contract.ErrRecord
		}
		stamps[stamp] = true
		union, present := unions[group.OwnerID]
		if !present || group.PublicationIncarnationID.IsZero() || group.AdmissionOrdinal == 0 {
			return nil, contract.ErrRecord
		}
		coordinate := coordinates[group.OwnerID]
		if group.PublicationIncarnationID == coordinate.CurrentPublicationIncarnationID && group.AdmissionOrdinal > coordinate.LastAdmissionOrdinal {
			return nil, contract.ErrRecord
		}
		union[group.PublicationIncarnationID] = true
	}
	var out []format.PublicationCoordinateOrder
	for _, previous := range index.PublicationOrder {
		union, retained := unions[previous.CoordinateID]
		if !retained {
			if !filter {
				return nil, contract.ErrRecord
			}
			continue
		}
		row := format.PublicationCoordinateOrder{CoordinateID: previous.CoordinateID}
		for _, id := range previous.Incarnations {
			if union[id] {
				row.Incarnations = append(row.Incarnations, id)
				delete(union, id)
			} else if !filter {
				return nil, contract.ErrRecord
			}
		}
		coordinate := coordinates[previous.CoordinateID]
		if len(union) != 0 || len(row.Incarnations) == 0 || row.Incarnations[len(row.Incarnations)-1] != coordinate.CurrentPublicationIncarnationID {
			return nil, contract.ErrRecord
		}
		out = append(out, row)
		delete(unions, previous.CoordinateID)
	}
	if len(unions) != 0 {
		return nil, contract.ErrRecord
	}
	return out, nil
}
