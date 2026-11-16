package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The complete Reader selection has released support bodies. Its proof still
// binds the fixed root, administrative index and exact immutable row facts.
// Each phase reads a packed page once and retains only decoded requested facts.
func manifestSelectedCreationLocators(ctx context.Context, selected publicSelection, requests []manifestLocatorRequest, assigned []int) ([]string, readerFailure) {
	image := &selected.image
	proof := image.publicationProof
	if !selected.complete || proof == nil || proof.indexRef != image.root.AdministrativeIndex {
		return nil, manifestInputFailure(contract.ReasonLocatorUnusable)
	}
	digest, err := publicationRootDigest(image.root)
	if err != nil || digest != proof.rootDigest {
		return nil, manifestInputFailure(contract.ReasonLocatorUnusable)
	}
	if len(assigned) > contract.MaxOutputTargets {
		return nil, manifestInputFailure(contract.ReasonLimitExceeded)
	}
	keys := make([]generatedRecordKey, len(assigned))
	coordinates := make([]contract.PublicationCoordinate, len(assigned))
	for index, requestIndex := range assigned {
		if failed := manifestContextFailure(ctx); failed.Outcome != 0 {
			return nil, failed
		}
		if requestIndex < 0 || requestIndex >= len(requests) {
			return nil, manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		target := requests[requestIndex].target
		id, err := contract.PublicationCoordinateID(image.root.Domain, target.ServiceContractID, target.CanonicalTarget)
		if err != nil {
			return nil, manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		keys[index] = generatedRecordKey{kind: contract.PublicationCoordinateSupportKind, id: id}
	}
	failed := manifestReadPublicationRows(ctx, selected, keys, func(index int, body []byte) readerFailure {
		coordinate, err := contract.InspectPublicationCoordinate(body)
		if err != nil {
			return readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
		}
		request := requests[assigned[index]]
		target := request.target
		if coordinate.DomainID != image.root.Domain || coordinate.CoordinateID != keys[index].id || coordinate.ServiceContractID != target.ServiceContractID || coordinate.CanonicalTarget != target.CanonicalTarget ||
			coordinate.BindingState != contract.PublicationBindingActive || coordinate.ActiveBindingIncarnationID != request.binding || coordinate.LastBindingIncarnationID != request.binding || coordinate.LastEntryIncarnationID != target.EntryIncarnationID ||
			coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.DeletionTargetContractID != target.TargetContractID || !bytes.Equal(coordinate.DeletionTargetData, target.TargetData) || coordinate.DeletionDestinationID != request.destination || !coordinate.LocatorRequiresCreation || !target.LocatorRequiresCreation || target.ConsumerLocator != "" || publicCoordinateReason(coordinate.DeletionConsumerLocator) != "" {
			return manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		coordinates[index] = coordinate
		return readerFailure{}
	})
	if failed.Outcome != 0 {
		return nil, failed
	}
	for index, coordinate := range coordinates {
		keys[index] = generatedRecordKey{kind: contract.PublicationMarkerSupportKind, id: coordinate.OwnedBirthAttemptID}
	}
	births := make([]contract.PublicationMarker, len(assigned))
	failed = manifestReadPublicationRows(ctx, selected, keys, func(index int, body []byte) readerFailure {
		birth, err := contract.InspectPublicationMarker(body)
		if err != nil {
			return readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
		}
		coordinate := coordinates[index]
		if !publicationQualifiedBirthValid(image.root.Domain, coordinate, birth) || birth.DomainID != image.root.Domain || birth.Evidence.Class != contract.PublicationRequestAcknowledged || birth.Evidence.SafeResourceID == "" || birth.Evidence.ConsumerLocator != coordinate.DeletionConsumerLocator {
			return manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		births[index] = birth
		return readerFailure{}
	})
	if failed.Outcome != 0 {
		return nil, failed
	}
	deletions := selectedPublication{markers: make(map[contract.ID]contract.PublicationMarker)}
	keys = keys[:0]
	for index, coordinate := range coordinates {
		available, err := publicationBirthAfterDelete(coordinate, births[index], deletions, image.adminIndex.PublicationOrder)
		if err == nil && available {
			continue
		}
		keys = append(keys, generatedRecordKey{kind: contract.PublicationMarkerSupportKind, id: coordinate.LastDeleteAckAttemptID})
	}
	failed = manifestReadPublicationRows(ctx, selected, keys, func(index int, body []byte) readerFailure {
		marker, err := contract.InspectPublicationMarker(body)
		if err != nil || marker.AttemptID != keys[index].id {
			return readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
		}
		deletions.markers[marker.AttemptID] = marker
		return readerFailure{}
	})
	if failed.Outcome != 0 {
		return nil, failed
	}
	resources := make([]string, len(assigned))
	for index, coordinate := range coordinates {
		available, err := publicationBirthAfterDelete(coordinate, births[index], deletions, image.adminIndex.PublicationOrder)
		if err != nil || !available {
			return nil, manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		resources[index] = births[index].Evidence.ConsumerLocator
	}
	return resources, readerFailure{}
}

func manifestReadPublicationRows(ctx context.Context, selected publicSelection, keys []generatedRecordKey, consume func(int, []byte) readerFailure) readerFailure {
	if selected.image.publicationProof == nil || consume == nil {
		return manifestInputFailure(contract.ReasonLocatorUnusable)
	}
	if len(keys) > contract.MaxOutputTargets {
		return manifestInputFailure(contract.ReasonLimitExceeded)
	}
	type rowRequest struct {
		index int
		key   generatedRecordKey
		proof selectedPublicationRowProof
	}
	type pageRequests struct {
		ref      format.Ref
		position int
		rows     []rowRequest
	}
	groups := make([]pageRequests, 0, min(len(keys), len(selected.image.root.RequiredSupport)))
	byRef := make(map[format.Ref]int, cap(groups))
	for index, key := range keys {
		if failed := manifestContextFailure(ctx); failed.Outcome != 0 {
			return failed
		}
		proof, present := selected.image.publicationProof.rows[key]
		if !present {
			return manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		group, present := byRef[proof.ref]
		if !present {
			position := slices.Index(selected.image.root.RequiredSupport, proof.ref)
			if position < 0 || position >= len(selected.image.supportFacts) || position >= len(selected.image.adminIndex.Pages) || selected.image.adminIndex.Pages[position].Ref != proof.ref {
				return manifestInputFailure(contract.ReasonLocatorUnusable)
			}
			facts := selected.image.supportFacts[position]
			if facts.ref != proof.ref || len(facts.rows) != len(facts.ordinals) {
				return manifestInputFailure(contract.ReasonLocatorUnusable)
			}
			group = len(groups)
			byRef[proof.ref] = group
			groups = append(groups, pageRequests{ref: proof.ref, position: position})
		}
		groups[group].rows = append(groups[group].rows, rowRequest{index: index, key: key, proof: proof})
	}
	for _, group := range groups {
		facts := selected.image.supportFacts[group.position]
		wanted := make(map[uint16][]int, len(group.rows))
		for index, row := range group.rows {
			wanted[row.proof.physical] = append(wanted[row.proof.physical], index)
		}
		for index, fact := range facts.rows {
			if failed := manifestContextFailure(ctx); failed.Outcome != 0 {
				return failed
			}
			physical := facts.ordinals[index]
			for _, rowIndex := range wanted[physical] {
				row := group.rows[rowIndex]
				if fact.Kind() != row.key.kind || fact.RecordID() != row.key.id || fact.BodyLength() != row.proof.length || fact.BodyDigest() != row.proof.bodyDigest {
					return manifestInputFailure(contract.ReasonLocatorUnusable)
				}
			}
			delete(wanted, physical)
		}
		if len(wanted) != 0 {
			return manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		body, _, result := selected.basis.reader.readBorrowed(ctx, group.ref)
		if failed := manifestContextFailure(ctx); failed.Outcome != 0 {
			return failed
		}
		if result.Outcome != 0 {
			return readerSelectionFailure(result)
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil || page.Domain != selected.image.root.Domain || page.Object != group.ref.Object || page.Index != group.ref.Index {
			return readerSelectionFailure(failure(IntegrityFailure, InvalidReference))
		}
		for _, request := range group.rows {
			if failed := manifestContextFailure(ctx); failed.Outcome != 0 {
				return failed
			}
			if int(request.proof.physical) >= len(page.Records) {
				return readerSelectionFailure(failure(IntegrityFailure, InvalidReference))
			}
			row := page.Records[request.proof.physical]
			if row.Kind != request.key.kind || row.RecordID != request.key.id || uint32(len(row.Body)) != request.proof.length || contract.Hash(row.Body) != request.proof.bodyDigest {
				return readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
			}
			consumed := consume(request.index, row.Body)
			if failed := manifestContextFailure(ctx); failed.Outcome != 0 {
				return failed
			}
			if consumed.Outcome != 0 {
				return consumed
			}
		}
	}
	return readerFailure{}
}
