package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type publicationOriginalResultOwner struct {
	instanceID, admissionID                          contract.ID
	dispatch                                         contract.PublicationDispatch
	reserve                                          contract.OutputReserveSubject
	reservationAdmissionDigest, reserveRequestDigest contract.ID
	marker                                           contract.PublicationMarker
	setsPolicy                                       bool
	expectedConsumerLocator                          string
	locatorRequiresCreation                          bool
}

type publicationPreparation struct {
	mu                       sync.Mutex
	original                 publicationOriginalResultOwner
	owner                    publicationPrivateOwner
	armed, consumed, retired bool
	result                   contract.PublicationResult
	resultReady              bool
}

func (p *publicationPreparation) arm(ctx context.Context, digest contract.ID) contract.CryptoResultCode {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired || p.armed || p.consumed || digest != p.original.reserveRequestDigest || p.owner == nil || p.owner.InstanceID() != p.original.instanceID {
		return contract.CryptoInvalidAdmission
	}
	if err := p.owner.Arm(ctx, p.original.admissionID, p.original.dispatch); err != nil {
		return contract.CryptoInvalidAdmission
	}
	p.armed = true
	return contract.CryptoSuccess
}
func (p *publicationPreparation) send(ctx context.Context) (contract.PublicationResult, contract.CryptoResultCode) {
	p.mu.Lock()
	if !p.armed || p.consumed || p.retired {
		p.mu.Unlock()
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	p.consumed = true
	p.mu.Unlock()
	result, code := p.owner.Send(ctx, p.original.admissionID)
	if code != contract.CryptoSuccess || contract.ValidatePublicationResult(p.original.dispatch, result) != nil {
		result = publicationUnknownResult(p.original)
	}
	p.mu.Lock()
	p.result = result
	p.resultReady = true
	p.mu.Unlock()
	return result, code
}
func (p *publicationPreparation) retire(ctx context.Context) error {
	p.mu.Lock()
	p.retired = true
	p.mu.Unlock()
	return p.owner.Retire(ctx)
}

type publicationCandidateFacts struct {
	marker      contract.PublicationMarker
	request     contract.ID
	preparation *publicationPreparation
	close       bool
}

// A selected earlier action of this fixed invocation may install fresh birth
// facts on a never-entered readded coordinate. No other operation can update
// the original plan's retained binding pin.
func (plan *publicationPlan) publicationSelectedProgressMatches(selected selectedPublication, p publicationTargetPlan, action uint8) bool {
	position := slices.Index(p.actions, action)
	if position < 1 || len(p.attempts) <= position {
		return false
	}
	coordinate := selected.coordinates[p.coordinate]
	if coordinate.LastBindingIncarnationID != p.binding || coordinate.LastEntryIncarnationID != p.target.EntryIncarnationID || coordinate.DeletionTargetRowDigest != p.targetDigest || coordinate.OwnedBirthAttemptID != p.attempts[0] {
		return false
	}
	for i := 0; i < position; i++ {
		marker, present := selected.markers[p.attempts[i]]
		if !present || marker.OperationID != plan.operation || marker.State != contract.PublicationAcknowledged || marker.Projection.Action != p.actions[i] || marker.Projection.TargetRowDigest != p.targetDigest || marker.Projection.BindingIncarnationID != p.binding || marker.Projection.EntryIncarnationID != p.target.EntryIncarnationID || marker.CoordinateID != p.coordinate {
			return false
		}
		if i == position-1 && marker.AdmissionOrdinal != coordinate.LastAdmissionOrdinal {
			return false
		}
	}
	return true
}

func (c *Candidate) publicationReady() bool {
	if c == nil || c.publication == nil || c.session == nil {
		return false
	}
	f := c.publication
	if f.close {
		if c.head.AuthKind != format.OutputCloseAuth || c.head.OutputClose == nil || c.firstSend != nil || f.preparation != nil {
			return false
		}
		request, err := contract.NewOutputCloseRequest(*c.head.OutputClose)
		return err == nil && request.Digest() == f.request && c.head.OutputClose.AttemptID == f.marker.AttemptID && c.head.OutputClose.ReservationAdmissionDigest == f.marker.AuthoritySubjectDigest
	}
	if c.head.AuthKind != format.OutputReserveAuth || c.head.OutputReserve == nil || c.firstSend == nil || f.preparation == nil {
		return false
	}
	request, err := contract.NewOutputReserveRequest(*c.head.OutputReserve)
	return err == nil && request.Digest() == f.request && f.preparation.original.reserveRequestDigest == f.request && f.preparation.original.marker == f.marker && *c.head.OutputReserve == f.preparation.original.reserve
}

func publicationCandidateFamilyReady(c *Candidate) bool {
	if c.head.AuthKind == format.OutputReserveAuth || c.head.AuthKind == format.OutputCloseAuth {
		return c.publicationReady()
	}
	return c.publication == nil
}

func publicationRows(selected selectedPublication) ([]contract.SupportRecord, error) {
	rows := make([]contract.SupportRecord, 0, len(selected.coordinates)+len(selected.markers))
	for id, v := range selected.coordinates {
		body, err := contract.EncodePublicationCoordinate(v)
		if err != nil {
			return nil, err
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: id, Body: body})
	}
	for id, v := range selected.markers {
		body, err := contract.EncodePublicationMarker(v)
		if err != nil {
			return nil, err
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: id, Body: body})
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	return rows, nil
}

func (s *StateSession) encodePublicationCandidate(ctx context.Context, next *StateSession, c *Candidate, ids transitionPlan) (contract.ID, uint32, contract.ID, error) {
	next.recountChildren()
	root, err := format.EncodeRoot(next.root)
	if err != nil {
		return contract.ID{}, 0, contract.ID{}, err
	}
	ref, err := format.Reference(format.RootKind, s.root.Domain, ids.snapshot, 0, root)
	if err != nil {
		return contract.ID{}, 0, contract.ID{}, err
	}
	c.objects = append(c.objects, objectImage{ref: ref, body: root})
	c.head = format.Head{Core: s.successorCore(ids), K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	c.head.Core.Root = ref
	core, err := format.EncodeHeadCore(c.head.Core)
	if err != nil {
		return contract.ID{}, 0, contract.ID{}, err
	}
	condition, err := format.EncodeConditionalPlan(conditional(c.head.Core, core))
	if err != nil {
		return contract.ID{}, 0, contract.ID{}, err
	}
	return contract.Hash(core), uint32(len(core)), contract.Hash(condition), nil
}

func (plan *publicationPlan) preparePublicationReservation(ctx context.Context, s *StateSession, p publicationTargetPlan, action uint8, private publicationPrivate) (*Candidate, *publicationPreparation, Result) {
	if !publicationNormalAdmission(ctx, s, plan.input.deadline) || !s.root.Generated.ActiveOwner.IsZero() || !s.root.ActiveGC.IsZero() {
		return nil, nil, refused(AdmissionInvalid)
	}
	var configuration contract.OutputConfiguration
	if plan.input.captured != nil {
		var state Result
		configuration, state = plan.input.captured.checkCurrent(ctx, s, p)
		if state.Outcome != 0 {
			return nil, nil, state
		}
	}
	selected, err := selectedPublicationRelation(s.selectedImage())
	if err != nil {
		return nil, nil, refused(InvalidRelation)
	}
	coordinate, present := selected.coordinates[p.coordinate]
	if !present {
		return nil, nil, refused(InvalidRelation)
	}
	if coordinate.BindingState != p.retained.BindingState || coordinate.ActiveBindingIncarnationID != p.retained.ActiveBindingIncarnationID || (coordinate.LastBindingIncarnationID != p.retained.LastBindingIncarnationID || coordinate.LastEntryIncarnationID != p.retained.LastEntryIncarnationID) && !plan.publicationSelectedProgressMatches(selected, p, action) {
		return nil, nil, refused(DifferentSelection)
	}
	if !p.policyActionPin.matches(coordinate, selected, publicationPolicyOrder(p.coordinate, s.adminIndex.PublicationOrder), s.publicationDomainWideWarning()) {
		return nil, nil, refused(DifferentSelection)
	}
	blockers := publicationBlockers(selected, p.coordinate)
	if !slices.Equal(blockers, p.blockers) {
		return nil, nil, refused(DifferentSelection)
	}
	if action <= contract.PublicationUpdatePolicy {
		if plan.input.captured == nil {
			var result Result
			configuration, result = s.currentOutputConfigurationForApply(ctx)
			if result.Outcome != 0 {
				return nil, nil, result
			}
		}
		matched := false
		for _, binding := range configuration.Bindings {
			if binding.DestinationID == p.destination && binding.IncarnationID == p.binding {
				for _, target := range binding.Targets {
					digest, e := contract.PublicationTargetRowDigest(s.root.Domain, p.destination, p.binding, target)
					if e == nil && digest == p.targetDigest {
						matched = true
					}
				}
			}
		}
		if !matched {
			return nil, nil, refused(DifferentSelection)
		}
		admitted, result := s.admitConsumerSelection(ctx, []string{p.selection.Entry.Name}, plan.acting)
		if admitted == nil {
			return nil, nil, result
		}
		// Each later action rechecks current authority; its payload remains the fixed
		// original selection, rather than adopting a concurrently changed value.
	}
	if action == contract.PublicationCreateEmpty || action == contract.PublicationCreateWithValue {
		if _, ok := s.publicationNamespaceFor(p.target); !ok {
			return nil, nil, refused(AdmissionInvalid)
		}
	}
	if (action == contract.PublicationDeleteOwned || action == contract.PublicationDeleteReservedSlot) && !publicationDeletionWitnessMatches(coordinate, p.retained) {
		return nil, nil, refused(DifferentSelection)
	}
	var uncertain *contract.PublicationMarker
	if action == contract.PublicationDeleteReservedSlot {
		pin, ok := s.publicationNamespaceFor(p.target)
		if !ok || pin != p.exclusive || p.uncertain == nil {
			return nil, nil, refused(AdmissionInvalid)
		}
		retained, ok := selected.markers[p.uncertain.AttemptID]
		if !ok || retained != *p.uncertain || !publicationReservedSlotEligible(coordinate, retained) {
			return nil, nil, refused(InvalidRelation)
		}
		uncertain = &retained
	}
	var birth *contract.PublicationMarker
	if action == contract.PublicationWriteValue || action == contract.PublicationUpdatePolicy || action == contract.PublicationDeleteOwned {
		b, ok := selected.markers[coordinate.OwnedBirthAttemptID]
		available, err := publicationBirthAfterDelete(coordinate, b, selected, s.adminIndex.PublicationOrder)
		if result, read := selectedReadResult(err); read {
			return nil, nil, result
		}
		if !ok || err != nil || !available {
			return nil, nil, refused(InvalidRelation)
		}
		if action == contract.PublicationDeleteOwned && (p.birth == nil || b != *p.birth) {
			return nil, nil, refused(DifferentSelection)
		}
		birth = &b
	}
	facts, err := private.Check(ctx, publicationActionCheckInput{DestinationID: p.destination, ConfigContractID: p.configContractID, DomainID: s.root.Domain, Action: action, Target: p.target, Coordinate: coordinate, Birth: birth, UncertainCreate: uncertain, ExclusiveNamespaceDigest: p.exclusive, PayloadLength: publicationActionLength(action, p.payloadLength), Deadline: plan.input.deadline})
	if err != nil || !publicationFactsMatch(p, action, facts) {
		return nil, nil, refused(InvalidIntent)
	}
	if action == contract.PublicationCreateWithValue || action == contract.PublicationWriteValue {
		if p.payloadLength < facts.MinimumPayload || p.payloadLength > facts.MaximumPayload {
			return nil, nil, refused(InvalidIntent)
		}
	} else if facts.MinimumPayload != 0 || facts.MaximumPayload != 0 {
		return nil, nil, refused(InvalidIntent)
	}
	identities, _, err := s.freshGeneratedLifecyclePlan(ctx, contract.MaxChildPages, 0)
	if err != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	position := slices.Index(p.actions, action)
	if position < 0 || position >= len(p.attempts) {
		return nil, nil, refused(InvalidIntent)
	}
	attempt := p.attempts[position]
	var incarnation contract.ID
	if coordinate.LastAdmissionOrdinal == ^uint64(0) {
		incarnation = identities.operation
	}
	coordinate, err = s.publicationCoordinateForAdmission(p.coordinate, incarnation)
	if err != nil {
		return nil, nil, refused(InvalidRelation)
	}
	birthID := contract.ID{}
	if birth != nil {
		birthID = birth.AttemptID
	}
	projection, err := plan.projection(p, action, birthID)
	if err != nil {
		return nil, nil, refused(InvalidIntent)
	}
	projection.ConfigurationDigest = s.root.OutputConfiguration.ConfigurationDigest
	commitment, err := contract.PublicationProjectionCommitment(projection)
	if err != nil {
		return nil, nil, refused(InvalidIntent)
	}
	response, err := contract.PublicationResponseContractDigest(projection.RequestContractDigest, p.facts.ArtifactContractID)
	if err != nil {
		return nil, nil, refused(InvalidIntent)
	}
	marker := contract.PublicationMarker{Schema: 5, DomainID: s.root.Domain, OperationID: plan.operation, AttemptID: attempt, CoordinateID: p.coordinate, PublicationIncarnationID: coordinate.CurrentPublicationIncarnationID, AdmissionOrdinal: coordinate.LastAdmissionOrdinal, Projection: projection, ProjectionCommitment: commitment, ExecutorID: hex.EncodeToString(p.facts.ExecutorID[:]), CredentialRouteID: hex.EncodeToString(p.facts.CredentialRouteID[:]), BlockerCount: uint16(len(blockers)), State: contract.PublicationMayHaveEntered, LateEffectRisk: coordinate.LateEffectRisk, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: response}}
	if len(blockers) > 0 || s.publicationDomainWideWarning() != 0 {
		marker.LateEffectRisk = 1
	}
	marker.BlockerDigest, err = contract.PublicationBlockerDigest(blockers)
	if err != nil {
		return nil, nil, refused(InvalidIntent)
	}
	if action == contract.PublicationCreateEmpty || action == contract.PublicationCreateWithValue {
		marker.BirthServiceContractID, marker.BirthTargetContractID = p.target.ServiceContractID, p.target.TargetContractID
	}
	reserve := contract.OutputReserveSubject{Schema: 5, Action: action, DomainID: s.root.Domain, OperationID: plan.operation, AttemptID: attempt, PredecessorRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body), PredecessorToken: s.token, CurrentAccessRoot: s.root.CurrentAccess.AccessRoot, ConfigurationDigest: s.root.OutputConfiguration.ConfigurationDigest, CoordinateID: p.coordinate, PublicationIncarnationID: coordinate.CurrentPublicationIncarnationID, AdmissionOrdinal: coordinate.LastAdmissionOrdinal, BindingIncarnationID: projection.BindingIncarnationID, EntryIncarnationID: projection.EntryIncarnationID, TargetRowDigest: projection.TargetRowDigest, OwnedBirthAttemptID: projection.OwnedBirthAttemptID, UncertainCreateAttemptID: projection.UncertainCreateAttemptID, ExclusiveNamespaceDigest: projection.ExclusiveNamespaceDigest, ValueBasisDigest: projection.ValueBasisDigest, PolicyDigest: projection.PolicyDigest, RequestContractDigest: projection.RequestContractDigest, BlockerCount: marker.BlockerCount, BlockerDigest: marker.BlockerDigest}
	if birth != nil {
		reserve.BirthTargetRowDigest = birth.Projection.TargetRowDigest
	}
	marker.AuthoritySubjectDigest, err = contract.OutputReserveAdmissionDigest(reserve, marker)
	if err != nil {
		return nil, nil, refused(InvalidProof)
	}
	dispatch := contract.PublicationDispatch{Schema: 5, DomainID: s.root.Domain, OperationID: plan.operation, AttemptID: attempt, CoordinateID: p.coordinate, Projection: projection, ProjectionCommitment: commitment, AuthoritySubjectDigest: marker.AuthoritySubjectDigest, ExecutorID: marker.ExecutorID, CredentialRouteID: marker.CredentialRouteID, ResponseContractDigest: response}
	reserve.DispatchContextDigest, err = contract.PublicationDispatchContextDigest(dispatch)
	if err != nil {
		return nil, nil, refused(InvalidProof)
	}
	coordinate.LatestUnresolvedAttemptID = attempt
	if marker.BirthServiceContractID != "" {
		if coordinate.OwnerState == contract.PublicationOwnerQualified {
			return nil, nil, refused(InvalidRelation)
		}
		if coordinate.DeletionTargetRowDigest.IsZero() {
			if coordinate.OwnerState != contract.PublicationOwnerNone || coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 {
				return nil, nil, refused(InvalidRelation)
			}
			coordinate.LastBindingIncarnationID = p.binding
			coordinate.LastEntryIncarnationID = p.target.EntryIncarnationID
			coordinate.DeletionTargetRowDigest = p.targetDigest
			coordinate.DeletionDestinationID = p.destination
			coordinate.DeletionConsumerLocator = p.target.ConsumerLocator
			coordinate.DeletionTargetContractID = p.target.TargetContractID
			coordinate.DeletionConfigContractID = p.configContractID
			coordinate.DeletionTargetData = bytes.Clone(p.target.TargetData)
			coordinate.DeletionCredentialRouteContractID = p.facts.CredentialRouteContractID
			coordinate.LocatorRequiresCreation = p.target.LocatorRequiresCreation
			coordinate.DeletionPayloadEncoding = p.target.PayloadEncoding
		} else if coordinate.LastBindingIncarnationID != p.binding || coordinate.LastEntryIncarnationID != p.target.EntryIncarnationID ||
			coordinate.DeletionTargetRowDigest != p.targetDigest || coordinate.DeletionDestinationID != p.destination ||
			(!p.target.LocatorRequiresCreation && coordinate.DeletionConsumerLocator != p.target.ConsumerLocator) || coordinate.DeletionTargetContractID != p.target.TargetContractID ||
			coordinate.DeletionConfigContractID != p.configContractID || !bytes.Equal(coordinate.DeletionTargetData, p.target.TargetData) || coordinate.LocatorRequiresCreation != p.target.LocatorRequiresCreation || coordinate.DeletionPayloadEncoding != p.target.PayloadEncoding {
			return nil, nil, refused(InvalidRelation)
		}
		coordinate.OwnerState, coordinate.PossibleRemoteObject = contract.PublicationOwnerUncertainCreate, 1
	}
	selected.coordinates[p.coordinate], selected.markers[attempt] = coordinate, marker
	rows, err := publicationRows(selected)
	if err != nil {
		return nil, nil, refused(InvalidFormat)
	}
	construction, err := s.preparePublicationConstruction(ctx, rows)
	if err != nil {
		return nil, nil, refused(CapacityExceeded)
	}
	pages := construction.pageCount()
	next := *s
	next.root.Snapshot, next.root.Transition = identities.snapshot, identities.transition
	c := &Candidate{session: s}
	if err := s.materializePublicationReservationConstruction(ctx, &next, c, construction, identities.supportPages[:pages]); err != nil {
		return nil, nil, refused(CapacityExceeded)
	}
	reserve.HeadCoreDigest, reserve.HeadCoreLength, reserve.ConditionalPlanDigest, err = s.encodePublicationCandidate(ctx, &next, c, identities)
	if err != nil {
		return nil, nil, refused(InvalidFormat)
	}
	c.head.AuthKind, c.head.OutputReserve = format.OutputReserveAuth, &reserve
	next.head = c.head
	if !construction.validOutputSelection(&next) {
		return nil, nil, refused(InvalidProof)
	}
	request, err := contract.NewOutputReserveRequest(reserve)
	if err != nil {
		return nil, nil, refused(InvalidProof)
	}
	owner, err := private.NewOwner(ctx, publicationOwnerInput{Projection: projection, DestinationID: p.destination, ConfigContractID: p.configContractID, Target: p.target, Coordinate: selected.coordinates[p.coordinate], Birth: birth, UncertainCreate: uncertain, ActionCheck: facts, Deadline: plan.input.deadline})
	if owner == nil {
		return nil, nil, refused(CustodyUnavailable)
	}
	var instance contract.ID
	if err == nil {
		instance = owner.InstanceID()
	}
	if err != nil || instance.IsZero() {
		if retireErr := owner.Retire(ctx); retireErr != nil {
			return nil, nil, refused(CustodyUnavailable)
		}
		return nil, nil, refused(CustodyUnavailable)
	}
	preparation := &publicationPreparation{owner: owner, original: publicationOriginalResultOwner{instanceID: instance, admissionID: attempt, dispatch: dispatch, reserve: reserve, reservationAdmissionDigest: marker.AuthoritySubjectDigest, reserveRequestDigest: request.Digest(), marker: marker, expectedConsumerLocator: strings.Clone(p.target.ConsumerLocator), locatorRequiresCreation: p.target.LocatorRequiresCreation, setsPolicy: action == contract.PublicationUpdatePolicy || action == contract.PublicationCreateEmpty && p.target.Capabilities.CreateSetsPolicy() || action == contract.PublicationCreateWithValue && p.target.Capabilities.CreateSetsPolicy() || action == contract.PublicationWriteValue && p.target.Capabilities.WriteSetsPolicy()}}
	var selection *contract.ConsumerSelection
	if action == contract.PublicationCreateWithValue || action == contract.PublicationWriteValue {
		selection = p.selection
	}
	uses, code := owner.Prepare(ctx, attempt, selection)
	if owner.InstanceID() != instance || !publicationPrepareKeyUsesValid(selection, code, uses) {
		if err := preparation.retire(ctx); err != nil {
			return nil, nil, refused(CustodyUnavailable)
		}
		return nil, nil, refused(AdmissionInvalid)
	}
	plan.input.observation.offerExchange(ctx, exchangeObservation{Source: observationSource{Stage: observationExchange,
		DomainID: s.root.Domain, OperationID: plan.operation, AttemptID: attempt}, RequestID: attempt,
		CustodyInstanceID: instance, Kind: contract.CryptoPrepare, ResultCode: code, Rows: uses})
	if code != contract.CryptoSuccess || ctx.Err() != nil || !validPrivateDeadline(plan.input.deadline) {
		if err := preparation.retire(ctx); err != nil {
			return nil, nil, refused(CustodyUnavailable)
		}
		return nil, nil, refused(CustodyUnavailable)
	}
	c.publication = &publicationCandidateFacts{marker: marker, request: request.Digest(), preparation: preparation}
	c.firstSend = &candidateFirstSend{handoff: preparation.arm}
	return c, preparation, s.observed(ObservedCurrent)
}
