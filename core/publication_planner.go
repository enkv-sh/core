package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"slices"
	"time"
	"unicode/utf8"

	outputprotocol "enkv.sh/sdk/protocols/output"

	"enkv.sh/core/contract"
)

// The enclosing private parent supplies normal admission and a fresh current
// session for each action. Observation alone cannot issue this operation.
type publicationNamespace struct {
	domain            contract.ID
	service, physical string
	premise           contract.ID
}

func (s *StateSession) publicationNamespaceFor(target contract.OutputTarget) (contract.ID, bool) {
	if s == nil {
		return contract.ID{}, false
	}
	if s.admission.publicationPremise != nil {
		premise, err := s.admission.publicationPremise(s.root.Domain, target)
		return premise, err == nil && !premise.IsZero()
	}
	var selected contract.ID
	for _, pin := range s.admission.publicationNamespaces {
		if pin.domain == s.root.Domain && pin.service == target.ServiceContractID && pin.physical == target.CanonicalTarget && !pin.premise.IsZero() {
			if !selected.IsZero() {
				return contract.ID{}, false
			}
			selected = pin.premise
		}
	}
	return selected, !selected.IsZero()
}

type publicationInput struct {
	observation *operationObservation
	names       []string
	acting      contract.ID
	republish   map[contract.ID][]contract.ID
	deletes     []contract.ID
	deadline    time.Time
	captured    *applyPublicationHandoff
}

type publicationTargetPlan struct {
	destination, configContractID          string
	target                                 contract.OutputTarget
	binding, coordinate                    contract.ID
	slot                                   uint16
	selection                              *contract.ConsumerSelection
	valueBasis                             contract.PublicationValueBasis
	payloadLength                          uint32
	valueBasisDigest, policy, targetDigest contract.ID
	facts                                  publicationActionFacts
	actions                                []uint8
	attempts                               []contract.ID
	blockers                               []contract.ID
	refusal                                Reason
	uncertain                              *contract.PublicationMarker
	exclusive                              contract.ID
	birth                                  *contract.PublicationMarker
	retained                               contract.PublicationCoordinate
	policyActionPin                        *publicationPolicyActionPin
	deletion                               bool
}

type publicationPlan struct {
	session      *StateSession
	operation    contract.ID
	acting       contract.ID
	input        publicationInput
	targets      []publicationTargetPlan
	vector       contract.PublicationOutcomeVector
	descriptions []PublicationTargetDescription
}

func publicationNormalAdmission(ctx context.Context, s *StateSession, deadline time.Time) bool {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.admission.valid(s.store) || !time.Now().Before(deadline) || deadline.After(s.admission.expires) {
		return false
	}
	control, ok := s.admission.currentControl()
	return ok && s.admission.recipient == control.AuthorityRecipientID && s.root.CurrentAccess.Core.AuthorityRecipientID == control.AuthorityRecipientID && s.root.CurrentAccess.Core.NormalSigning.Binding == control.NormalSigning.Binding
}

func (s *StateSession) publicationConsumer(slot uint16, acting contract.ID) (*contract.ConsumerSelection, contract.PublicationValueBasis, error) {
	entry := s.valueEntry(slot)
	recipient := s.recipientRecord(acting)
	if entry == nil || recipient == nil || recipient.CurrentBinding == nil || !slices.Contains(entry.Recipients, acting) {
		return nil, contract.PublicationValueBasis{}, contract.ErrRecord
	}
	digest, err := contract.PublicValueEntryDigest(s.root.Domain, slot, *entry)
	if err != nil {
		return nil, contract.PublicationValueBasis{}, err
	}
	selected := &contract.ConsumerSelection{DomainID: s.root.Domain, SnapshotID: s.root.Snapshot, HEADDigest: contract.Hash(s.body), AccessRoot: s.root.CurrentAccess.AccessRoot, EntryDigest: digest, Root: s.head.Core.Root, HEADRevision: s.head.Core.Revision, HEADToken: s.token, Slot: slot, Entry: *entry, Binding: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: acting, Binding: *recipient.CurrentBinding}}
	selected.Entry.ValueBytes = bytes.Clone(entry.ValueBytes)
	selected.Entry.Recipients = slices.Clone(entry.Recipients)
	selected.Binding.Binding.SPKI = bytes.Clone(recipient.CurrentBinding.SPKI)
	valueBasis := contract.PublicationValueBasis{EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState, ConfidentialityClass: entry.ConfidentialityClass, ContentLength: entry.ContentLength, InputEncoding: entry.InputEncoding, RetainedLength: entry.RetainedLength, SemanticCommitment: digest}
	if entry.ConfidentialityClass == contract.Secret {
		var valid bool
		selected.Core, selected.Payload, selected.Access, valid = s.selectedValue(slot)
		if !valid {
			return nil, valueBasis, contract.ErrRecord
		}
		selected.Payload.Ciphertext = bytes.Clone(selected.Payload.Ciphertext)
		selected.Access.Wraps = slices.Clone(selected.Access.Wraps)
		for i := range selected.Access.Wraps {
			selected.Access.Wraps[i].RSACiphertext = bytes.Clone(selected.Access.Wraps[i].RSACiphertext)
		}
		valueBasis.ContentLength, valueBasis.SemanticCommitment = selected.Payload.ContentLength, selected.Payload.SemanticCommitment
	}
	return selected, valueBasis, nil
}

func publicationBlockers(selected selectedPublication, id contract.ID) []contract.ID {
	var ids []contract.ID
	for _, marker := range selected.markers {
		if marker.CoordinateID == id && (marker.State == contract.PublicationMayHaveEntered || marker.State == contract.PublicationUnknown) {
			ids = append(ids, marker.AttemptID)
		}
	}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

func (s *StateSession) publicationStampAfterDelete(coordinate contract.PublicationCoordinate, incarnation contract.ID, ordinal uint64) bool {
	for _, order := range s.adminIndex.PublicationOrder {
		if order.CoordinateID == coordinate.CoordinateID {
			return publicationStampAfter(order.Incarnations, incarnation, ordinal, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal)
		}
	}
	return false
}

func (s *StateSession) publicationDomainWideWarning() uint8 {
	if s.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != 0 {
		return 1
	}
	return 0
}

func publicationExecutionFactsValid(f publicationActionFacts, configContractID string) bool {
	config, err := contract.OutputConfigContractDigest(configContractID)
	return err == nil && f.ConfigContractDigest == config && f.ProtocolID == contract.ID(outputprotocol.ProtocolID()) &&
		!f.DescriptorID.IsZero() && !f.ArtifactContractID.IsZero() && !f.ExecutorID.IsZero() && !f.CredentialRouteID.IsZero() &&
		len(f.CredentialRouteContractID) > 0 && len(f.CredentialRouteContractID) <= 256 && utf8.ValidString(f.CredentialRouteContractID)
}

func (s *StateSession) preparePublicationPlan(ctx context.Context, input publicationInput, private publicationPrivate) (*publicationPlan, Result) {
	if !publicationNormalAdmission(ctx, s, input.deadline) || private.Actions == nil || private.Check == nil || private.NewOwner == nil || len(input.deletes) > contract.MaxPublicationCoordinates {
		return nil, refused(AdmissionInvalid)
	}
	var admitted *admittedConsumerSelection
	var result Result
	if input.captured == nil {
		admitted, result = s.admitConsumerSelection(ctx, input.names, input.acting)
		if admitted == nil {
			return nil, result
		}
	}
	configuration, result := s.currentOutputConfigurationForApply(ctx)
	if result.Outcome != 0 {
		return nil, result
	}
	if input.captured != nil {
		if state := input.captured.checkSelection(s, configuration); state.Outcome != 0 {
			return nil, state
		}
		admitted, result = s.admitConsumerSelection(ctx, input.names, input.acting)
		if admitted == nil {
			return nil, result
		}
	}
	selected, valid := s.publicationProof.relationFor(s.selectedImage())
	if !valid {
		return nil, refused(InvalidRelation)
	}
	selectedIDs, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	entropy := s.admission.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	allocated := make(map[contract.ID]bool)
	nextIdentity := func() (contract.ID, Reason) {
		if ctx.Err() != nil {
			return contract.ID{}, AdmissionInvalid
		}
		var id contract.ID
		if _, err := io.ReadFull(entropy, id[:]); err != nil || id.IsZero() || selectedIDs[id] {
			return contract.ID{}, AdmissionInvalid
		}
		if allocated[id] {
			return contract.ID{}, InvalidIntent
		}
		allocated[id] = true
		return id, 0
	}
	operation, reason := nextIdentity()
	if reason != 0 {
		return nil, refused(reason)
	}
	plan := &publicationPlan{session: s, operation: operation, acting: admitted.recipient, input: input}
	plan.vector = contract.PublicationOutcomeVector{Schema: 2, DomainID: s.root.Domain, OperationID: operation, SnapshotID: s.root.Snapshot, SelectionDigest: contract.Hash(s.body)}
	plan.vector.DomainWideWarning = s.publicationDomainWideWarning()
	chosen := make(map[contract.ID]uint16, len(admitted.slots))
	for _, slot := range admitted.slots {
		chosen[s.valueEntry(slot).Incarnation] = slot
	}
	for _, group := range configuration.Groups {
		requested := slices.ContainsFunc(group, func(entry contract.ID) bool { _, present := chosen[entry]; return present })
		if requested {
			for _, entry := range group {
				if _, present := chosen[entry]; !present {
					return nil, refused(AdmissionInvalid)
				}
			}
		}
	}
	destinations := make(map[string]bool)
	for entry := range chosen {
		for _, destination := range resolveOutputRoute(configuration, entry) {
			destinations[destination] = true
		}
	}
	seen := make(map[contract.ID]bool)
	consumers := make(map[uint16]*contract.ConsumerSelection, len(chosen))
	valueBases := make(map[uint16]contract.PublicationValueBasis, len(chosen))
	for _, binding := range configuration.Bindings {
		if !destinations[binding.DestinationID] {
			continue
		}
		for _, target := range binding.Targets {
			if _, present := chosen[target.EntryIncarnationID]; !present {
				continue
			}
			if !slices.Contains(resolveOutputRoute(configuration, target.EntryIncarnationID), binding.DestinationID) {
				continue
			}
			if input.captured != nil {
				pin, present := input.captured.target(binding.DestinationID, binding.IncarnationID, target)
				if !present {
					continue
				}
				target = pin.target
			}
			id, err := contract.PublicationCoordinateID(s.root.Domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil || seen[id] || len(seen) >= contract.MaxPublicationCoordinates {
				return nil, refused(InvalidIntent)
			}
			seen[id] = true
			coordinate, present := selected.coordinates[id]
			if !present || coordinate.BindingState != contract.PublicationBindingActive || coordinate.ActiveBindingIncarnationID != binding.IncarnationID {
				return nil, refused(InvalidRelation)
			}
			slot := chosen[target.EntryIncarnationID]
			selection, valueBasis := consumers[slot], valueBases[slot]
			if selection == nil {
				if input.captured == nil {
					selection, valueBasis, err = s.publicationConsumer(slot, admitted.recipient)
				} else {
					var present bool
					selection, valueBasis, present = input.captured.consumer(slot)
					if !present {
						err = contract.ErrRecord
					}
				}
				if err != nil {
					return nil, refused(AdmissionInvalid)
				}
				consumers[slot], valueBases[slot] = selection, valueBasis
			}
			p := publicationTargetPlan{destination: binding.DestinationID, configContractID: binding.Destination.ConfigContractID, target: target, binding: binding.IncarnationID, coordinate: id, slot: slot, selection: selection, valueBasis: valueBasis, retained: coordinate}
			p.targetDigest, err = contract.PublicationTargetRowDigest(s.root.Domain, p.destination, p.binding, p.target)
			if err != nil {
				return nil, refused(InvalidIntent)
			}
			p.valueBasisDigest, err = contract.PublicationValueBasisDigest(s.root.Domain, p.destination, p.binding, p.target, valueBasis)
			if err != nil {
				return nil, refused(InvalidIntent)
			}
			p.policy, err = contract.OutputPolicyDigest(s.root.Domain, p.target.Policy)
			if err != nil {
				return nil, refused(InvalidIntent)
			}
			p.blockers = publicationBlockers(selected, id)
			if coordinate.OwnerState == contract.PublicationOwnerQualified {
				birth := selected.markers[coordinate.OwnedBirthAttemptID]
				available, err := publicationBirthAfterDelete(coordinate, birth, selected, s.adminIndex.PublicationOrder)
				if err != nil {
					if result, read := selectedReadResult(err); read {
						return nil, result
					}
					return nil, refused(InvalidIntent)
				}
				if available {
					p.birth = &birth
				}
			}
			explicit, present := input.republish[id]
			if present {
				if len(p.blockers) == 0 || !slices.Equal(explicit, p.blockers) {
					return nil, refused(InvalidIntent)
				}
				for _, blocker := range p.blockers {
					m := selected.markers[blocker]
					if m.Projection.DomainID != s.root.Domain || m.Projection.EntryIncarnationID != target.EntryIncarnationID && coordinate.LastEntryIncarnationID != m.Projection.EntryIncarnationID || coordinate.DeletionDestinationID != binding.DestinationID || coordinate.DeletionTargetContractID != target.TargetContractID || coordinate.DeletionConfigContractID != binding.Destination.ConfigContractID || m.Projection.BindingIncarnationID != binding.IncarnationID && m.Projection.BindingIncarnationID != coordinate.LastBindingIncarnationID {
						return nil, refused(InvalidIntent)
					}
				}
			}
			if len(p.blockers) > 0 && !present {
				p.refusal = DifferentSelection
			}
			// Blockers are resolved before equality and before passive profile work.
			if p.refusal == 0 {
				valueEqual := false
				policyEqual := false
				owned := p.birth != nil && coordinate.LastBindingIncarnationID == binding.IncarnationID && coordinate.LastEntryIncarnationID == target.EntryIncarnationID
				if owned && plan.vector.DomainWideWarning == 0 && coordinate.LateEffectRisk == 0 {
					expected, e := contract.PublicationSelectedValueDigest(s.root.Domain, p.valueBasisDigest, coordinate.OwnedBirthAttemptID, coordinate.OwnedInstanceDigest)
					valueEqual = e == nil && coordinate.LastValueDigest == expected && !coordinate.LastValueAckAttemptID.IsZero() && s.publicationStampAfterDelete(coordinate, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal)
					policyEqual = p.policy.IsZero() || coordinate.LastPolicyDigest == p.policy && !coordinate.LastPolicyAckAttemptID.IsZero() && s.publicationStampAfterDelete(coordinate, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal)
				}
				if valueEqual && policyEqual && !present {
					plan.targets = append(plan.targets, p)
					continue
				}
				p.facts, err = private.Actions(ctx, p.executionInput())
				if err != nil {
					return nil, refused(InvalidIntent)
				}
				if !publicationExecutionFactsValid(p.facts, p.configContractID) {
					return nil, refused(InvalidIntent)
				}
				if coordinate.OwnerState == contract.PublicationOwnerQualified && !owned {
					return nil, refused(InvalidIntent)
				}
				if !owned {
					if _, qualified := s.publicationNamespaceFor(target); !qualified {
						return nil, refused(AdmissionInvalid)
					}
				}
				p.actions, p.policyActionPin, err = publicationSelectActions(ctx, publicationPolicyActionInput{DestinationID: p.destination, ConfigContractID: p.configContractID, DomainID: s.root.Domain, Target: p.target, Deadline: input.deadline}, coordinate, p.birth, selected, publicationPolicyOrder(p.coordinate, s.adminIndex.PublicationOrder), owned, valueEqual, policyEqual, present, private.SelectPolicyAction)
				if err != nil {
					return nil, refused(InvalidIntent)
				}
				p.payloadLength, err = publicationScheduledPayloadLength(p.target, p.actions, valueBasis.ContentLength)
				if err != nil {
					return nil, refused(CapacityExceeded)
				}
				if !owned && coordinate.OwnerState != contract.PublicationOwnerNone && !present {
					return nil, refused(InvalidIntent)
				}
				facts, e := private.Check(ctx, publicationActionCheckInput{DestinationID: p.destination, ConfigContractID: p.configContractID, DomainID: s.root.Domain, Action: p.actions[0], Target: p.target, Coordinate: coordinate, Birth: p.birth, PayloadLength: publicationActionLength(p.actions[0], p.payloadLength), Deadline: input.deadline})
				if e != nil || !publicationFactsMatch(p, p.actions[0], facts) {
					return nil, refused(InvalidIntent)
				}
			} else {
				p.actions = nil
			}
			plan.targets = append(plan.targets, p)
		}
	}
	for _, id := range input.deletes {
		coordinate, present := selected.coordinates[id]
		if !present || seen[id] || coordinate.BindingState != contract.PublicationBindingRetired || coordinate.DeletionTargetRowDigest.IsZero() {
			return nil, refused(InvalidIntent)
		}
		seen[id] = true
		target := publicationDeletionTarget(coordinate)
		p := publicationTargetPlan{coordinate: id, binding: coordinate.LastBindingIncarnationID, destination: coordinate.DeletionDestinationID,
			configContractID: coordinate.DeletionConfigContractID, deletion: true, retained: coordinate, targetDigest: coordinate.DeletionTargetRowDigest, target: target}
		p.blockers = publicationBlockers(selected, id)
		if coordinate.OwnerState == contract.PublicationOwnerQualified {
			birth := selected.markers[coordinate.OwnedBirthAttemptID]
			available, err := publicationBirthAfterDelete(coordinate, birth, selected, s.adminIndex.PublicationOrder)
			if err != nil {
				if result, read := selectedReadResult(err); read {
					return nil, result
				}
				return nil, refused(InvalidIntent)
			}
			if !available {
				return nil, refused(InvalidIntent)
			}
			p.birth = &birth
			p.actions = []uint8{contract.PublicationDeleteOwned}
		} else if coordinate.OwnerState == contract.PublicationOwnerUncertainCreate {
			premise, qualified := s.publicationNamespaceFor(p.target)
			if !qualified {
				return nil, refused(AdmissionInvalid)
			}
			p.exclusive = premise
			for _, id := range p.blockers {
				marker := selected.markers[id]
				if publicationReservedSlotEligible(coordinate, marker) {
					m := marker
					p.uncertain = &m
					break
				}
			}
			if p.uncertain == nil {
				return nil, refused(InvalidRelation)
			}
			p.actions = []uint8{contract.PublicationDeleteReservedSlot}
		} else {
			return nil, refused(InvalidIntent)
		}

		explicit, has := input.republish[id]
		if len(p.blockers) > 0 && (!has || !slices.Equal(explicit, p.blockers)) || has && len(p.blockers) == 0 {
			return nil, refused(InvalidIntent)
		}
		p.facts, err = private.Actions(ctx, p.executionInput())
		if err != nil || !publicationExecutionFactsValid(p.facts, p.configContractID) {
			return nil, refused(InvalidIntent)
		}
		facts, e := private.Check(ctx, publicationActionCheckInput{DestinationID: p.destination, ConfigContractID: p.configContractID, DomainID: s.root.Domain, Action: p.actions[0], Target: p.target, Coordinate: coordinate, Birth: p.birth, UncertainCreate: p.uncertain, ExclusiveNamespaceDigest: p.exclusive, Deadline: input.deadline})
		if e != nil || !publicationFactsMatch(p, p.actions[0], facts) {
			return nil, refused(InvalidIntent)
		}
		plan.targets = append(plan.targets, p)
	}
	for id := range input.republish {
		if !seen[id] {
			return nil, refused(InvalidIntent)
		}
	}
	slices.SortFunc(plan.targets, func(a, b publicationTargetPlan) int { return bytes.Compare(a.coordinate[:], b.coordinate[:]) })
	if len(plan.targets) > contract.MaxPublicationCoordinates {
		return nil, refused(CapacityExceeded)
	}
	// The full result's exact framing and worst evidence/marker growth are checked
	// before an owner or payload exists. Capacity is joint with the retained image.
	newMarkers := 0
	for _, target := range plan.targets {
		if target.refusal == 0 {
			newMarkers += len(target.actions)
		}
	}
	if len(selected.markers)+newMarkers > contract.MaxPublicationMarkers {
		return nil, refused(CapacityExceeded)
	}
	for i := range plan.targets {
		p := &plan.targets[i]
		entry := contract.PublicationTargetOutcome{CoordinateID: p.coordinate}
		if p.refusal != 0 {
			retained := selected.markers[p.blockers[0]]
			entry.Actions = []contract.PublicationOutcome{{Action: retained.Projection.Action, ProjectionCommitment: retained.ProjectionCommitment, AttemptID: retained.AttemptID, Disposition: contract.PublicationOutcomeUnknown, RemoteValueMayRemain: p.retained.PossibleRemoteObject, LateWriteRisk: p.retained.LateEffectRisk, BlockerIDs: slices.Clone(p.blockers), Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: retained.Evidence.ResponseContractDigest}}}
		} else if len(p.actions) == 0 {
			entry.Actions = []contract.PublicationOutcome{{Disposition: contract.PublicationNoOp}}
		} else {
			for range p.actions {
				id, reason := nextIdentity()
				if reason != 0 {
					return nil, refused(reason)
				}
				p.attempts = append(p.attempts, id)
			}
			var birth contract.ID
			if p.birth != nil {
				birth = p.birth.AttemptID
			} else {
				birth = p.attempts[0]
			}
			for _, action := range p.actions {
				projection, e := plan.projection(*p, action, birth)
				if e != nil {
					return nil, refused(InvalidIntent)
				}
				commitment, e := contract.PublicationProjectionCommitment(projection)
				if e != nil {
					return nil, refused(InvalidIntent)
				}
				entry.Actions = append(entry.Actions, contract.PublicationOutcome{Action: action, ProjectionCommitment: commitment, Disposition: contract.PublicationNotSent, CoreReason: uint16(AdmissionInvalid), BlockerIDs: slices.Clone(p.blockers), RemoteValueMayRemain: p.retained.PossibleRemoteObject, LateWriteRisk: p.retained.LateEffectRisk})
			}
			// Coordinate and action-count framing consume 33 bytes. Each
			// action consumes 76 bytes before its blockers and evidence body.
			targetBytes := 33 + len(entry.Actions)*(76+32*len(p.blockers))
			if !publicationOutcomeFutureFits(targetBytes, len(p.actions), contract.MaxPublicationOutcomeBytes) {
				return nil, refused(CapacityExceeded)
			}
		}
		plan.vector.Entries = append(plan.vector.Entries, entry)
	}
	body, e := contract.EncodePublicationOutcomeVector(plan.vector)
	if e != nil || !publicationOutcomeFutureFits(len(body), newMarkers, contract.MaxPublicationOutcomeVectorBytes) {
		return nil, refused(CapacityExceeded)
	}
	if err := s.publicationInvocationCapacity(ctx, plan.targets, newMarkers); err != nil {
		return nil, refused(CapacityExceeded)
	}
	if err := s.reserveOrdinaryPublicationRewrite(ctx); err != nil {
		return nil, refused(CapacityExceeded)
	}
	plan.descriptions, err = plan.captureDescriptions()
	if err != nil {
		return nil, refused(InvalidRelation)
	}
	return plan, s.observed(ObservedCurrent)
}

func publicationOutcomeFutureFits(currentBytes, futureActions, maximum int) bool {
	return currentBytes >= 0 && currentBytes <= maximum && futureActions >= 0 &&
		futureActions <= (maximum-currentBytes)/contract.MaxPublicationEvidenceBytes
}

func (p publicationTargetPlan) executionInput() publicationExecutionInput {
	input := publicationExecutionInput{DestinationID: p.destination, ConfigContractID: p.configContractID, Target: p.target}
	if p.deletion {
		input.DeleteCoordinate = p.coordinate
	}
	return input
}

func publicationActionLength(action uint8, length uint32) uint32 {
	if action == contract.PublicationCreateWithValue || action == contract.PublicationWriteValue {
		return length
	}
	return 0
}
func publicationActionBounds(target contract.OutputTarget, action uint8) contract.OutputPayloadBounds {
	switch action {
	case contract.PublicationCreateWithValue:
		return target.CreateValueBounds
	case contract.PublicationWriteValue:
		return target.WriteValueBounds
	default:
		return contract.OutputPayloadBounds{}
	}
}

func publicationScheduledPayloadLength(target contract.OutputTarget, actions []uint8, rawLength uint32) (uint32, error) {
	value := slices.Contains(actions, contract.PublicationCreateWithValue) || slices.Contains(actions, contract.PublicationWriteValue)
	if !value {
		return 0, nil
	}
	length, err := contract.PublicationPayloadLength(target.PayloadEncoding, rawLength)
	if err != nil {
		return 0, err
	}
	for _, action := range actions {
		if action != contract.PublicationCreateWithValue && action != contract.PublicationWriteValue {
			continue
		}
		bounds := publicationActionBounds(target, action)
		if bounds.Minimum > bounds.Maximum || bounds.Maximum > outputprotocol.MaximumPayloadBytes || length < bounds.Minimum || length > bounds.Maximum {
			return 0, contract.ErrRecordCapacity
		}
	}
	return length, nil
}

func publicationFactsMatch(p publicationTargetPlan, action uint8, f publicationActionCheckFacts) bool {
	bounds := publicationActionBounds(p.target, action)
	return f.MinimumPayload == bounds.Minimum && f.MaximumPayload == bounds.Maximum && f.MinimumPayload <= f.MaximumPayload && f.MaximumPayload <= outputprotocol.MaximumPayloadBytes &&
		f.ProtocolID == p.facts.ProtocolID && f.DescriptorID == p.facts.DescriptorID && f.ConfigContractDigest == p.facts.ConfigContractDigest &&
		f.ArtifactContractID == p.facts.ArtifactContractID && f.ExecutorID == p.facts.ExecutorID && f.CredentialRouteID == p.facts.CredentialRouteID && f.CredentialRouteContractID == p.facts.CredentialRouteContractID
}

// A reserved-slot delete is authorized by an unresolved create for this
// exact retired destination. A later qualified owner requires its own proof.
func publicationReservedSlotEligible(c contract.PublicationCoordinate, create contract.PublicationMarker) bool {
	return c.BindingState == contract.PublicationBindingRetired && c.OwnerState == contract.PublicationOwnerUncertainCreate &&
		create.CoordinateID == c.CoordinateID && (create.State == contract.PublicationMayHaveEntered || create.State == contract.PublicationUnknown) &&
		(create.Projection.Action == contract.PublicationCreateEmpty || create.Projection.Action == contract.PublicationCreateWithValue) &&
		create.Projection.BindingIncarnationID == c.LastBindingIncarnationID && create.Projection.EntryIncarnationID == c.LastEntryIncarnationID &&
		create.Projection.TargetRowDigest == c.DeletionTargetRowDigest && create.BirthServiceContractID == c.ServiceContractID && create.BirthTargetContractID == c.DeletionTargetContractID
}

func publicationDeletionTarget(coordinate contract.PublicationCoordinate) contract.OutputTarget {
	locator := coordinate.DeletionConsumerLocator
	if coordinate.LocatorRequiresCreation {
		locator = ""
	}
	var capabilities contract.OutputActionCapabilities
	switch coordinate.OwnerState {
	case contract.PublicationOwnerQualified:
		capabilities = contract.OutputCapabilityDeleteOwned
	case contract.PublicationOwnerUncertainCreate:
		capabilities = contract.OutputCapabilityDeleteReservedSlot
	}
	return contract.OutputTarget{EntryIncarnationID: coordinate.LastEntryIncarnationID, ServiceContractID: coordinate.ServiceContractID,
		TargetContractID: coordinate.DeletionTargetContractID, CanonicalTarget: coordinate.CanonicalTarget, ConsumerLocator: locator,
		TargetData: coordinate.DeletionTargetData, PayloadEncoding: coordinate.DeletionPayloadEncoding, LocatorRequiresCreation: coordinate.LocatorRequiresCreation,
		Capabilities: capabilities}
}

func (plan *publicationPlan) projection(p publicationTargetPlan, action uint8, birth contract.ID) (contract.PublicationProjection, error) {
	request, err := contract.PublicationRequestContractDigest(p.facts.ProtocolID, p.facts.ConfigContractDigest, p.target.ServiceContractID, p.target.TargetContractID, action)
	if err != nil {
		return contract.PublicationProjection{}, err
	}
	v := contract.PublicationProjection{Schema: 4, DomainID: plan.session.root.Domain, ConfigurationDigest: plan.session.root.OutputConfiguration.ConfigurationDigest, CoordinateID: p.coordinate, BindingIncarnationID: p.binding, EntryIncarnationID: p.target.EntryIncarnationID, TargetRowDigest: p.targetDigest, Action: action, RequestContractDigest: request, ActingRecipientID: plan.acting}
	if action == contract.PublicationWriteValue || action == contract.PublicationUpdatePolicy || action == contract.PublicationDeleteOwned {
		v.OwnedBirthAttemptID = birth
	}
	if action == contract.PublicationDeleteReservedSlot {
		if p.uncertain != nil {
			v.UncertainCreateAttemptID = p.uncertain.AttemptID
		}
		v.ExclusiveNamespaceDigest = p.exclusive
	}
	if action <= contract.PublicationUpdatePolicy {
		v.PolicyDigest = p.policy
	}
	if action == contract.PublicationCreateWithValue || action == contract.PublicationWriteValue {
		v.ValueBasisDigest = p.valueBasisDigest
	}
	return v, nil
}
