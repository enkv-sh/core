package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationStampAfter(order []contract.ID, incarnation contract.ID, ordinal uint64, prior contract.ID, priorOrdinal uint64) bool {
	if prior.IsZero() {
		return true
	}
	current, old := slices.Index(order, incarnation), slices.Index(order, prior)
	return current >= 0 && old >= 0 && (current > old || current == old && ordinal > priorOrdinal)
}

func publicationUnknownResult(original publicationOriginalResultOwner) contract.PublicationResult {
	digest := original.reserve.DispatchContextDigest
	return contract.PublicationResult{Schema: 2, DomainID: original.dispatch.DomainID, OperationID: original.dispatch.OperationID, AttemptID: original.dispatch.AttemptID, CoordinateID: original.dispatch.CoordinateID, ProjectionCommitment: original.dispatch.ProjectionCommitment, DispatchContextDigest: digest, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: original.dispatch.ResponseContractDigest}}
}

func (plan *publicationPlan) preparePublicationClose(ctx context.Context, s *StateSession, p *publicationPreparation, result contract.PublicationResult) (*Candidate, Result) {
	if !publicationNormalAdmission(ctx, s, plan.input.deadline) || !s.root.Generated.ActiveOwner.IsZero() || !s.root.ActiveGC.IsZero() || p == nil {
		return nil, refused(AdmissionInvalid)
	}
	p.mu.Lock()
	authorized := p.armed && p.consumed && !p.retired && p.resultReady && p.result == result
	p.mu.Unlock()
	if !authorized || contract.ValidatePublicationResult(p.original.dispatch, result) != nil {
		return nil, refused(InvalidProof)
	}
	selected, err := selectedPublicationRelation(s.selectedImage())
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	marker, present := selected.markers[p.original.marker.AttemptID]
	if !present || marker.State != contract.PublicationMayHaveEntered && marker.State != contract.PublicationUnknown || !publicationSameReservation(p.original.marker, marker) || marker.AuthoritySubjectDigest != p.original.reservationAdmissionDigest {
		return nil, refused(DifferentSelection)
	}
	coordinate, present := selected.coordinates[marker.CoordinateID]
	if !present {
		return nil, refused(InvalidRelation)
	}
	createResult := marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue
	if createResult && result.Evidence.Class == contract.PublicationRequestAcknowledged &&
		(result.Evidence.ConsumerLocator == "" || !p.original.locatorRequiresCreation && result.Evidence.ConsumerLocator != p.original.expectedConsumerLocator) {
		return nil, refused(InvalidProof)
	}
	marker.Evidence = result.Evidence
	switch result.Evidence.Class {
	case contract.PublicationRequestAcknowledged:
		marker.State = contract.PublicationAcknowledged
	case contract.PublicationQualifiedNoEffect:
		marker.State = contract.PublicationQualifiedNoEffectState
	default:
		marker.State = contract.PublicationUnknown
		marker.Evidence = publicationUnknownResult(p.original).Evidence
	}
	if marker.LateEffectRisk < coordinate.LateEffectRisk {
		marker.LateEffectRisk = coordinate.LateEffectRisk
	}
	if s.publicationDomainWideWarning() != 0 {
		marker.LateEffectRisk = 1
	}
	if marker.State == contract.PublicationUnknown {
		marker.LateEffectRisk = 1
	}
	selected.markers[marker.AttemptID] = marker
	var order []contract.ID
	for _, row := range s.adminIndex.PublicationOrder {
		if row.CoordinateID == coordinate.CoordinateID {
			order = row.Incarnations
			break
		}
	}
	if len(order) == 0 {
		return nil, refused(InvalidRelation)
	}
	if marker.State == contract.PublicationAcknowledged {
		create := marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue
		if create {
			prior := selected.markers[coordinate.OwnedBirthAttemptID]
			if coordinate.OwnerState != contract.PublicationOwnerQualified || publicationStampAfter(order, marker.PublicationIncarnationID, marker.AdmissionOrdinal, prior.PublicationIncarnationID, prior.AdmissionOrdinal) {
				// A late birth retains the current active/retired binding and its frozen
				// deletion inputs. A changed target cannot replace an older obligation.
				if marker.Projection.BindingIncarnationID != coordinate.LastBindingIncarnationID || marker.Projection.EntryIncarnationID != coordinate.LastEntryIncarnationID || marker.Projection.TargetRowDigest != coordinate.DeletionTargetRowDigest || marker.BirthServiceContractID != coordinate.ServiceContractID || marker.BirthTargetContractID != coordinate.DeletionTargetContractID {
					return nil, refused(InvalidRelation)
				}
				if coordinate.LocatorRequiresCreation {
					coordinate.DeletionConsumerLocator = marker.Evidence.ConsumerLocator
				}
				coordinate.OwnerState, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, marker.AttemptID
				coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(s.root.Domain, coordinate.CoordinateID, marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID, marker.Projection.TargetRowDigest, marker.AttemptID, marker.Evidence.SafeResourceID)
				if err != nil {
					return nil, refused(InvalidRelation)
				}
			}
		}
		birthID := marker.Projection.OwnedBirthAttemptID
		if create {
			birthID = marker.AttemptID
		}
		sameOwner := birthID == coordinate.OwnedBirthAttemptID && coordinate.OwnerState == contract.PublicationOwnerQualified
		if (marker.Projection.Action == contract.PublicationCreateWithValue || marker.Projection.Action == contract.PublicationWriteValue) && sameOwner && publicationStampAfter(order, marker.PublicationIncarnationID, marker.AdmissionOrdinal, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal) {
			coordinate.LastValueDigest, err = contract.PublicationSelectedValueDigest(s.root.Domain, marker.Projection.ValueBasisDigest, birthID, coordinate.OwnedInstanceDigest)
			if err != nil {
				return nil, refused(InvalidRelation)
			}
			coordinate.LastValueAckAttemptID, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = marker.AttemptID, marker.PublicationIncarnationID, marker.AdmissionOrdinal
		}
		if p.original.setsPolicy && !marker.Projection.PolicyDigest.IsZero() && sameOwner && publicationStampAfter(order, marker.PublicationIncarnationID, marker.AdmissionOrdinal, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal) {
			coordinate.LastPolicyDigest = marker.Projection.PolicyDigest
			coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = marker.AttemptID, marker.PublicationIncarnationID, marker.AdmissionOrdinal
		}
		if marker.Projection.Action >= contract.PublicationDeleteOwned && publicationStampAfter(order, marker.PublicationIncarnationID, marker.AdmissionOrdinal, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal) {
			coordinate.LastDeleteAckAttemptID, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal = marker.AttemptID, marker.PublicationIncarnationID, marker.AdmissionOrdinal
		}
	}
	if marker.State == contract.PublicationQualifiedNoEffectState && coordinate.OwnerState == contract.PublicationOwnerUncertainCreate && (marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue) && marker.Projection.BindingIncarnationID == coordinate.LastBindingIncarnationID && marker.Projection.EntryIncarnationID == coordinate.LastEntryIncarnationID && marker.Projection.TargetRowDigest == coordinate.DeletionTargetRowDigest {
		uncertain, possible, late := false, false, false
		for _, other := range selected.markers {
			if other.CoordinateID != coordinate.CoordinateID {
				continue
			}
			create := other.Projection.Action == contract.PublicationCreateEmpty || other.Projection.Action == contract.PublicationCreateWithValue
			open := other.State == contract.PublicationMayHaveEntered || other.State == contract.PublicationUnknown
			uncertain = uncertain || create && open && other.Projection.BindingIncarnationID == coordinate.LastBindingIncarnationID && other.Projection.EntryIncarnationID == coordinate.LastEntryIncarnationID && other.Projection.TargetRowDigest == coordinate.DeletionTargetRowDigest
			possible = possible || create && (open || other.State == contract.PublicationAcknowledged)
			late = late || other.LateEffectRisk != 0
		}
		if !uncertain {
			coordinate.OwnerState = contract.PublicationOwnerNone
			coordinate.OwnedBirthAttemptID, coordinate.OwnedInstanceDigest = contract.ID{}, contract.ID{}
			if !possible && !late && coordinate.LateEffectRisk == 0 && coordinate.LastValueAckAttemptID.IsZero() && coordinate.LastPolicyAckAttemptID.IsZero() && coordinate.LastDeleteAckAttemptID.IsZero() && s.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) == 0 {
				coordinate.PossibleRemoteObject = 0
			}
		}
	}
	if marker.State == contract.PublicationAcknowledged || marker.State == contract.PublicationUnknown || marker.Evidence.Entry == contract.PublicationMayHaveEnteredEntry && marker.State != contract.PublicationQualifiedNoEffectState {
		coordinate.PossibleRemoteObject = 1
	}
	if marker.LateEffectRisk > coordinate.LateEffectRisk {
		coordinate.LateEffectRisk = marker.LateEffectRisk
	}
	if coordinate.LatestUnresolvedAttemptID == marker.AttemptID && marker.State != contract.PublicationUnknown {
		coordinate.LatestUnresolvedAttemptID = contract.ID{}
		var best contract.PublicationMarker
		for _, other := range selected.markers {
			if other.CoordinateID == coordinate.CoordinateID && (other.State == contract.PublicationMayHaveEntered || other.State == contract.PublicationUnknown) && (best.AttemptID.IsZero() || publicationStampAfter(order, other.PublicationIncarnationID, other.AdmissionOrdinal, best.PublicationIncarnationID, best.AdmissionOrdinal)) {
				best = other
			}
		}
		coordinate.LatestUnresolvedAttemptID = best.AttemptID
	}
	selected.coordinates[coordinate.CoordinateID] = coordinate
	rows, err := publicationRows(selected)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	construction, err := s.preparePublicationConstruction(ctx, rows)
	if err != nil {
		return nil, refused(CapacityExceeded)
	}
	pages := construction.pageCount()
	identities, _, err := s.freshGeneratedLifecyclePlan(ctx, pages, 0)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	next := s.successorState()
	next.root.Snapshot, next.root.Transition = identities.snapshot, identities.transition
	c := &Candidate{session: s}
	if err := s.materializePublicationRewriteConstruction(ctx, &next, c, construction, identities.supportPages[:pages]); err != nil {
		return nil, refused(InvalidRelation)
	}
	evidence, err := contract.EncodePublicationEvidence(marker.Evidence)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	closeSubject := contract.OutputCloseSubject{Schema: 4, Action: marker.Projection.Action, DomainID: s.root.Domain, OperationID: marker.OperationID, AttemptID: marker.AttemptID, ReservationAdmissionDigest: p.original.reservationAdmissionDigest, PredecessorRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body), PredecessorToken: s.token, CurrentAccessRoot: s.root.CurrentAccess.AccessRoot, ConfigurationDigest: s.root.OutputConfiguration.ConfigurationDigest, CoordinateID: marker.CoordinateID, BindingIncarnationID: marker.Projection.BindingIncarnationID, EntryIncarnationID: marker.Projection.EntryIncarnationID, TargetRowDigest: marker.Projection.TargetRowDigest, OwnedBirthAttemptID: marker.Projection.OwnedBirthAttemptID, UncertainCreateAttemptID: marker.Projection.UncertainCreateAttemptID, ExclusiveNamespaceDigest: marker.Projection.ExclusiveNamespaceDigest, ActionProjectionCommitment: marker.ProjectionCommitment, EntryClass: marker.Evidence.Entry, ResultClass: marker.Evidence.Class, LateRisk: marker.LateEffectRisk, ResultEvidenceDigest: contract.Hash(evidence)}
	closeSubject.HeadCoreDigest, closeSubject.HeadCoreLength, closeSubject.ConditionalPlanDigest, err = s.encodePublicationCandidate(ctx, &next, c, identities)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	c.head.AuthKind, c.head.OutputClose = format.OutputCloseAuth, &closeSubject
	next.head = c.head
	if !construction.validOutputSelection(&next) {
		return nil, refused(InvalidProof)
	}
	request, err := contract.NewOutputCloseRequest(closeSubject)
	if err != nil {
		return nil, refused(InvalidProof)
	}
	c.publication = &publicationCandidateFacts{marker: marker, request: request.Digest(), close: true}
	return c, s.observed(ObservedCurrent)
}
