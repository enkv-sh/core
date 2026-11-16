package core

import (
	"context"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) publicationInvocationCapacity(ctx context.Context, targets []publicationTargetPlan, newMarkers int) error {
	if newMarkers == 0 {
		return nil
	}
	if newMarkers < 0 || newMarkers > contract.MaxPublicationMarkers {
		return contract.ErrRecordCapacity
	}
	p, err := s.planPublicationRewrite(ctx, s.adminIndex)
	if err != nil {
		return err
	}
	// Retained widths already include unresolved result growth. The selected
	// configuration owns every invocation coordinate, so only markers are new.
	var coordinates, markers uint64
	for key := range p.widths {
		if key.kind == contract.PublicationCoordinateSupportKind {
			coordinates++
		} else {
			markers++
		}
	}
	markers += uint64(newMarkers)
	if coordinates > contract.MaxPublicationCoordinates || markers > contract.MaxPublicationMarkers {
		return contract.ErrRecordCapacity
	}
	framed := p.framed + uint64(newMarkers)*contract.MaxPublicationMarkerRecordBytes
	width := max(p.maximumWidth, uint64(contract.MaxPublicationMarkerRecordBytes))
	for _, target := range targets {
		if len(target.actions) == 0 || target.refusal != 0 || !target.retained.DeletionTargetRowDigest.IsZero() {
			continue
		}
		future := target.retained
		future.DeletionTargetRowDigest = target.targetDigest
		future.DeletionDestinationID = target.destination
		future.DeletionConsumerLocator = target.target.ConsumerLocator
		future.DeletionTargetContractID = target.target.TargetContractID
		future.DeletionConfigContractID = target.configContractID
		future.DeletionTargetData = target.target.TargetData
		future.DeletionCredentialRouteContractID = target.facts.CredentialRouteContractID
		future.LocatorRequiresCreation = target.target.LocatorRequiresCreation
		future.DeletionPayloadEncoding = target.target.PayloadEncoding
		body, e := contract.EncodePublicationCoordinate(future)
		if e != nil {
			return e
		}
		old := p.widths[generatedRecordKey{kind: contract.PublicationCoordinateSupportKind, id: target.coordinate}]
		prospective := uint64(len(body) + contract.SupportRecordOverhead)
		if future.LocatorRequiresCreation {
			prospective += uint64(1024 - len(future.DeletionConsumerLocator))
		}
		if prospective > old {
			framed += prospective - old
		}
		width = max(width, prospective)
	}
	pages, err := publicationPageBound(coordinates+markers, framed, width)
	if err != nil {
		return err
	}
	growth, err := format.PublicationIndexPlanningGrowth(uint32(newMarkers), 0, pages)
	if err != nil {
		return err
	}
	// Existing pages and order rows stay charged. The helper additionally charges
	// all projected publication page headers, so this is a conservative refusal.
	beforeShards, err := format.AdministrativeIndexShardCount(p.indexBytes)
	if err != nil {
		return err
	}
	afterShards, err := format.AdministrativeIndexShardCount(p.indexBytes + growth)
	if err != nil {
		return contract.ErrRecordCapacity
	}
	dropped := 0
	for _, page := range p.work.Pages {
		retained := false
		for _, peer := range p.peers {
			if peer.Ref == page.Ref {
				retained = true
				break
			}
		}
		if !retained {
			dropped++
		}
	}
	children := int64(s.root.ChildCount) - int64(dropped) + int64(pages) + int64(afterShards) - int64(beforeShards)
	if children < 0 || children > ordinaryChildPageLimit {
		return contract.ErrRecordCapacity
	}
	return nil
}
