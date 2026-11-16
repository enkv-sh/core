package core

import (
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type publicationPolicyActionInput struct {
	DestinationID, ConfigContractID string
	DomainID                        contract.ID
	Target                          contract.OutputTarget
	HasPreviousPolicyDigest         bool
	PreviousPolicyDigest            contract.ID
	Deadline                        time.Time
}

type publicationPolicyActionSelector func(context.Context, publicationPolicyActionInput) (uint8, error)

type publicationPolicyActionPin struct {
	coordinateDigest contract.ID
	birth            contract.PublicationMarker
	policyMarker     *contract.PublicationMarker
	order            []contract.ID
}

func publicationPreviousPolicy(coordinate contract.PublicationCoordinate, birth *contract.PublicationMarker, selected selectedPublication, order []contract.ID) (contract.ID, *contract.PublicationMarker, error) {
	if birth == nil || !publicationQualifiedBirthValid(coordinate.DomainID, coordinate, *birth) {
		return contract.ID{}, nil, contract.ErrRecord
	}
	if coordinate.LastPolicyDigest.IsZero() || coordinate.LastPolicyAckAttemptID.IsZero() ||
		!publicationStampAfter(order, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal) {
		return contract.ID{}, nil, nil
	}
	if coordinate.LastPolicyAckAttemptID == coordinate.LastValueAckAttemptID &&
		coordinate.LastPolicyAckIncarnationID == coordinate.LastValueAckIncarnationID &&
		coordinate.LastPolicyAckOrdinal == coordinate.LastValueAckOrdinal {
		return coordinate.LastPolicyDigest, nil, nil
	}
	marker, present := selected.markers[coordinate.LastPolicyAckAttemptID]
	if !present {
		return contract.ID{}, nil, nil
	}
	if marker.DomainID != coordinate.DomainID || marker.CoordinateID != coordinate.CoordinateID ||
		marker.AttemptID != coordinate.LastPolicyAckAttemptID || marker.PublicationIncarnationID != coordinate.LastPolicyAckIncarnationID ||
		marker.AdmissionOrdinal != coordinate.LastPolicyAckOrdinal || marker.Projection.PolicyDigest != coordinate.LastPolicyDigest ||
		marker.State != contract.PublicationAcknowledged || marker.Evidence.Class != contract.PublicationRequestAcknowledged ||
		marker.Projection.BindingIncarnationID != coordinate.LastBindingIncarnationID || marker.Projection.EntryIncarnationID != coordinate.LastEntryIncarnationID {
		return contract.ID{}, nil, contract.ErrRecord
	}
	create := marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue
	if create {
		if marker.AttemptID != birth.AttemptID {
			return contract.ID{}, nil, nil
		}
	} else if marker.Projection.Action != contract.PublicationWriteValue && marker.Projection.Action != contract.PublicationUpdatePolicy {
		return contract.ID{}, nil, contract.ErrRecord
	} else if marker.Projection.OwnedBirthAttemptID != birth.AttemptID {
		return contract.ID{}, nil, nil
	}
	if marker.AttemptID != birth.AttemptID && !publicationStampAfter(order, marker.PublicationIncarnationID, marker.AdmissionOrdinal, birth.PublicationIncarnationID, birth.AdmissionOrdinal) {
		return contract.ID{}, nil, contract.ErrRecord
	}
	return coordinate.LastPolicyDigest, &marker, nil
}

func publicationSelectActions(ctx context.Context, input publicationPolicyActionInput, coordinate contract.PublicationCoordinate, birth *contract.PublicationMarker,
	selected selectedPublication, order []contract.ID, owned, valueEqual, policyEqual, force bool, selectPolicy publicationPolicyActionSelector) ([]uint8, *publicationPolicyActionPin, error) {
	if !input.Target.Capabilities.Valid() {
		return nil, nil, contract.ErrRecord
	}
	if !owned || !valueEqual || policyEqual || force || input.Target.Policy.ContractID == "" {
		actions, err := publicationActionOrder(input.Target.Capabilities, owned, valueEqual, policyEqual, force, input.Target.Policy.ContractID != "")
		return actions, nil, err
	}
	if ctx == nil || selectPolicy == nil || birth == nil || input.DomainID != coordinate.DomainID ||
		input.Target.EntryIncarnationID != coordinate.LastEntryIncarnationID {
		return nil, nil, contract.ErrRecord
	}
	previous, marker, err := publicationPreviousPolicy(coordinate, birth, selected, order)
	if err != nil {
		return nil, nil, err
	}
	input.PreviousPolicyDigest, input.HasPreviousPolicyDigest = previous, !previous.IsZero()
	action, err := selectPolicy(ctx, input)
	if err != nil {
		return nil, nil, err
	}
	if action != contract.PublicationUpdatePolicy && action != contract.PublicationWriteValue || !input.Target.Capabilities.Has(action) ||
		action == contract.PublicationWriteValue && !input.Target.Capabilities.WriteSetsPolicy() {
		return nil, nil, contract.ErrRecord
	}
	body, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		return nil, nil, err
	}
	pin := &publicationPolicyActionPin{coordinateDigest: contract.Hash(body), birth: *birth, policyMarker: marker, order: slices.Clone(order)}
	return []uint8{action}, pin, nil
}

func publicationPolicyOrder(coordinate contract.ID, orders []format.PublicationCoordinateOrder) []contract.ID {
	for _, row := range orders {
		if row.CoordinateID == coordinate {
			return row.Incarnations
		}
	}
	return nil
}

func (p *publicationPolicyActionPin) matches(coordinate contract.PublicationCoordinate, selected selectedPublication, order []contract.ID, warning uint8) bool {
	if p == nil {
		return true
	}
	if warning != 0 || coordinate.LateEffectRisk != 0 || !slices.Equal(p.order, order) || selected.markers[p.birth.AttemptID] != p.birth {
		return false
	}
	body, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil || contract.Hash(body) != p.coordinateDigest {
		return false
	}
	return p.policyMarker == nil || selected.markers[p.policyMarker.AttemptID] == *p.policyMarker
}
