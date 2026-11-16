package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// These selected rows must remain readable even when every work group ends.
// The same classification is used before packing and when writing the index.
type administrativeMandatorySupport struct {
	results     map[contract.ID]bool
	intents     map[contract.ID]bool
	proofs      map[contract.ID][]contract.GeneratorDescriptor
	blobs       map[contract.ID]bool
	known       map[contract.ID]bool
	publication map[contract.ID]bool
}

func (m *administrativeMandatorySupport) selectedPublication(domain contract.ID, rows []contract.SupportRecord, order []format.PublicationCoordinateOrder) (selectedPublication, error) {
	selected, err := publicationRowsRelation(domain, rows, order)
	if err != nil {
		return selectedPublication{}, err
	}
	m.bindPublicationRelation(selected)
	return selected, nil
}

func (m *administrativeMandatorySupport) bindPublicationRelation(selected selectedPublication) {
	m.publication = make(map[contract.ID]bool, len(selected.coordinates)+len(selected.markers))
	for id := range selected.coordinates {
		m.publication[id] = true
	}
	for id := range selected.markers {
		m.publication[id] = false
	}
	for _, coordinate := range selected.coordinates {
		if coordinate.OwnerState == contract.PublicationOwnerQualified {
			m.publication[coordinate.OwnedBirthAttemptID] = true
		}
	}
	for _, marker := range selected.markers {
		if !marker.Projection.OwnedBirthAttemptID.IsZero() {
			m.publication[marker.Projection.OwnedBirthAttemptID] = true
		}
	}
}

func newAdministrativeMandatorySupport(current *StateSession, locations []contract.GeneratorSliceLocation) (administrativeMandatorySupport, error) {
	entries, err := selectedGeneratedEntryMetadata(current)
	if err != nil {
		return administrativeMandatorySupport{}, err
	}
	return administrativeMandatorySupportForEntries(entries, locations), nil
}

func administrativeMandatorySupportForEntries(entries []contract.GeneratedEntryMetadata, locations []contract.GeneratorSliceLocation) administrativeMandatorySupport {
	m := administrativeMandatorySupport{results: make(map[contract.ID]bool),
		intents: make(map[contract.ID]bool), proofs: make(map[contract.ID][]contract.GeneratorDescriptor),
		blobs: make(map[contract.ID]bool), known: make(map[contract.ID]bool)}
	for _, entry := range entries {
		m.results[entry.CreateResultID] = true
		m.intents[entry.IntentDigest] = true
		m.proofs[entry.OriginOperationID] = append(m.proofs[entry.OriginOperationID], entry.RequiredSupport)
	}
	for _, location := range locations {
		m.known[location.BlobID] = true
		if location.ContentKind == contract.GeneratorContentIntent && m.intents[location.ContentID] {
			m.blobs[location.BlobID] = true
		}
	}
	return m
}

func (m administrativeMandatorySupport) row(row contract.SupportRecord) (bool, error) {
	switch row.Kind {
	case contract.PublicationCoordinateSupportKind, contract.PublicationMarkerSupportKind:
		mandatory, present := m.publication[row.RecordID]
		if !present {
			return false, contract.ErrRecord
		}
		return mandatory, nil
	case contract.OutputConfigurationSliceSupportKind:
		return true, nil
	case contract.GeneratedCreateEvidenceSupportKind:
		return m.results[row.RecordID], nil
	case contract.MutationReceiptSupportKind:
		return true, nil
	case contract.GeneratedFragmentSupportKind:
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil {
			return false, err
		}
		return m.blobs[fragment.BlobID] || !m.known[fragment.BlobID], nil
	case contract.GeneratorVectorSupportKind:
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return false, err
		}
		if carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices {
			location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
			if err != nil {
				return false, err
			}
			return location.ContentKind == contract.GeneratorContentIntent && m.intents[location.ContentID], nil
		}
		if carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.VectorKind == contract.GeneratorVectorSupport {
			for _, descriptor := range m.proofs[carrier.OwnerID] {
				if carrier.Vector == descriptor {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func partitionAdministrativeSupportGroups(groups []format.RequiredSupportGroup, m administrativeMandatorySupport) ([]format.RequiredSupportGroup, error) {
	out := make([]format.RequiredSupportGroup, 0, len(groups))
	for _, group := range groups {
		optional := format.RequiredSupportGroup{Class: group.Class, Owner: group.Owner}
		mandatory := format.RequiredSupportGroup{Class: group.Class, Owner: group.Owner, Mandatory: true}
		for _, row := range group.Records {
			keep, err := m.row(row)
			if err != nil {
				return nil, err
			}
			if keep {
				mandatory.Records = append(mandatory.Records, row)
			} else {
				optional.Records = append(optional.Records, row)
			}
		}
		if len(mandatory.Records) != 0 {
			out = append(out, mandatory)
		}
		if len(optional.Records) != 0 {
			out = append(out, optional)
		}
	}
	return out, nil
}

func generatedReservationGroupsForState(current *StateSession, rows []contract.SupportRecord,
	locations []contract.GeneratorSliceLocation, bundles []contract.GeneratorPlanBundle) ([]format.RequiredSupportGroup, error) {
	return generatedReservationGroupsWithSource(current, current, rows, locations, bundles)
}

func generatedReservationGroupsWithSource(current, source *StateSession, rows []contract.SupportRecord,
	locations []contract.GeneratorSliceLocation, bundles []contract.GeneratorPlanBundle) ([]format.RequiredSupportGroup, error) {
	groups, fragments, err := generatedReservationSourceGroups(source, rows, locations, bundles)
	if err != nil {
		return nil, err
	}
	mandatory, err := newAdministrativeMandatorySupport(current, locations)
	if err != nil {
		return nil, err
	}
	return partitionGeneratedReservationGroups(source, rows, groups, mandatory, fragments)
}

// Prospective entries determine mandatory generated work. The predecessor
// separately supplies authenticated opaque facts and publication domain/order.
func generatedReservationGroupsFromEntries(entries []contract.GeneratedEntryMetadata, source *StateSession, rows []contract.SupportRecord,
	locations []contract.GeneratorSliceLocation, bundles []contract.GeneratorPlanBundle) ([]format.RequiredSupportGroup, error) {
	groups, fragments, err := generatedReservationSourceGroups(source, rows, locations, bundles)
	if err != nil {
		return nil, err
	}
	mandatory := administrativeMandatorySupportForEntries(entries, locations)
	return partitionGeneratedReservationGroups(source, rows, groups, mandatory, fragments)
}

func generatedReservationSourceGroups(source *StateSession, rows []contract.SupportRecord,
	locations []contract.GeneratorSliceLocation, bundles []contract.GeneratorPlanBundle) ([]format.RequiredSupportGroup, map[contract.ID]selectedFragmentFact, error) {
	if err := publicationRowBounds(rows, false); err != nil {
		return nil, nil, err
	}
	var fragments map[contract.ID]selectedFragmentFact
	needsFacts := false
	for _, row := range rows {
		needsFacts = needsFacts || row.Body == nil && opaqueSupportKind(row.Kind)
	}
	if source != nil && needsFacts {
		var err error
		fragments, err = source.selectedFragmentFactsByRecord()
		if err != nil {
			return nil, nil, err
		}
	}
	// This existing generated request owns complete ordinary records. Complete
	// selected readers retain typed publication facts instead; materialize only
	// at this request boundary, never during idle key replacement.
	rows = slices.Clone(rows)
	for i, row := range rows {
		if row.Body != nil || !publicationSupportKind(row.Kind) {
			continue
		}
		if source == nil {
			return nil, nil, contract.ErrRecord
		}
		fact, err := source.publicationRecord(row)
		if err != nil {
			return nil, nil, err
		}
		rows[i].Body, err = fact.body()
		if err != nil {
			return nil, nil, err
		}
	}
	groups, err := generatedReservationGroupsWithFacts(rows, locations, bundles, fragments)
	return groups, fragments, err
}

func partitionGeneratedReservationGroups(source *StateSession, rows []contract.SupportRecord,
	groups []format.RequiredSupportGroup, mandatory administrativeMandatorySupport, fragments map[contract.ID]selectedFragmentFact) ([]format.RequiredSupportGroup, error) {
	if source == nil {
		for _, row := range rows {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				return nil, contract.ErrRecord
			}
		}
	} else {
		selected, err := source.selectedImage().publicationRows(rows)
		if err != nil {
			return nil, err
		}
		order, err := publicationOrderForRelation(selected, source.adminIndex.PublicationOrder)
		if err != nil {
			return nil, err
		}
		selected, err = publicationTypedRelation(source.root.Domain, selected, order)
		if err != nil {
			return nil, err
		}
		mandatory.bindPublicationRelation(selected)
	}
	return partitionAdministrativeSupportGroupsWithFacts(groups, mandatory, fragments)
}

func partitionAdministrativeSupportGroupsWithFacts(groups []format.RequiredSupportGroup,
	m administrativeMandatorySupport, fragments map[contract.ID]selectedFragmentFact) ([]format.RequiredSupportGroup, error) {
	out := make([]format.RequiredSupportGroup, 0, len(groups))
	for _, group := range groups {
		optional := format.RequiredSupportGroup{Class: group.Class, Owner: group.Owner}
		mandatory := format.RequiredSupportGroup{Class: group.Class, Owner: group.Owner, Mandatory: true}
		for _, row := range group.Records {
			var keep bool
			var err error
			if row.Kind == contract.GeneratedFragmentSupportKind && row.Body == nil {
				fact, ok := fragments[row.RecordID]
				if !ok || fact.blob != group.Owner || fact.row.BodyLength() == 0 {
					return nil, contract.ErrRecord
				}
				keep = m.blobs[fact.blob] || !m.known[fact.blob]
			} else {
				keep, err = m.row(row)
				if err != nil {
					return nil, err
				}
			}
			if keep {
				mandatory.Records = append(mandatory.Records, row)
			} else {
				optional.Records = append(optional.Records, row)
			}
		}
		if len(mandatory.Records) != 0 {
			out = append(out, mandatory)
		}
		if len(optional.Records) != 0 {
			out = append(out, optional)
		}
	}
	return out, nil
}

func publicationOrderForRows(domain contract.ID, rows []contract.SupportRecord, before []format.PublicationCoordinateOrder) ([]format.PublicationCoordinateOrder, error) {
	if err := publicationRowBounds(rows, false); err != nil {
		return nil, err
	}
	if len(before) > contract.MaxPublicationCoordinates {
		return nil, contract.ErrRecordCapacity
	}
	var incarnationCount int
	for _, order := range before {
		incarnationCount += len(order.Incarnations)
		if incarnationCount > contract.MaxPublicationIncarnations {
			return nil, contract.ErrRecordCapacity
		}
	}
	selected, err := inspectPublicationRows(domain, rows)
	if err != nil {
		return nil, err
	}
	return publicationOrderForRelation(selected, before)
}

func publicationOrderForRelation(selected selectedPublication, before []format.PublicationCoordinateOrder) ([]format.PublicationCoordinateOrder, error) {
	if len(selected.coordinates) > contract.MaxPublicationCoordinates || len(selected.markers) > contract.MaxPublicationMarkers || len(before) > contract.MaxPublicationCoordinates {
		return nil, contract.ErrRecordCapacity
	}
	incarnations := 0
	for _, order := range before {
		incarnations += len(order.Incarnations)
		if incarnations > contract.MaxPublicationIncarnations {
			return nil, contract.ErrRecordCapacity
		}
	}
	coordinates := selected.coordinates
	referenced := make(map[contract.ID]map[contract.ID]bool, len(coordinates))
	for id, coordinate := range coordinates {
		union := map[contract.ID]bool{coordinate.CurrentPublicationIncarnationID: true}
		for _, incarnation := range []contract.ID{coordinate.LastValueAckIncarnationID, coordinate.LastPolicyAckIncarnationID, coordinate.LastDeleteAckIncarnationID} {
			if !incarnation.IsZero() {
				union[incarnation] = true
			}
		}
		referenced[id] = union
	}
	for _, marker := range selected.markers {
		if referenced[marker.CoordinateID] == nil {
			return nil, contract.ErrRecord
		}
		referenced[marker.CoordinateID][marker.PublicationIncarnationID] = true
	}
	prior := make(map[contract.ID][]contract.ID, len(before))
	global := make(map[contract.ID]bool)
	for _, row := range before {
		if prior[row.CoordinateID] != nil {
			return nil, contract.ErrRecord
		}
		prior[row.CoordinateID] = row.Incarnations
		for _, id := range row.Incarnations {
			if global[id] {
				return nil, contract.ErrRecord
			}
			global[id] = true
		}
	}
	var order []format.PublicationCoordinateOrder
	for id, coordinate := range coordinates {
		union := referenced[id]
		row := format.PublicationCoordinateOrder{CoordinateID: id}
		for _, incarnation := range prior[id] {
			if union[incarnation] {
				row.Incarnations = append(row.Incarnations, incarnation)
				delete(union, incarnation)
			}
		}
		if union[coordinate.CurrentPublicationIncarnationID] {
			if global[coordinate.CurrentPublicationIncarnationID] {
				return nil, contract.ErrRecord
			}
			row.Incarnations = append(row.Incarnations, coordinate.CurrentPublicationIncarnationID)
			delete(union, coordinate.CurrentPublicationIncarnationID)
		}
		if len(union) != 0 || len(row.Incarnations) == 0 || row.Incarnations[len(row.Incarnations)-1] != coordinate.CurrentPublicationIncarnationID {
			return nil, contract.ErrRecord
		}
		order = append(order, row)
	}
	slices.SortFunc(order, func(a, b format.PublicationCoordinateOrder) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	return order, nil
}
