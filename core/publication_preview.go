package core

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func requestedPublicationPreview(payload *contract.ComparisonPayload, reason Reason) {
	payload.PublicationRequested = true
	if payload.Publication == nil {
		if reason == NoReason {
			reason = ReadUnavailable
		}
		payload.Publication = &contract.PublicationPreview{ReasonCode: uint8(reason)}
	}
}

type publicationPreviewRefinement struct {
	index       int
	name        string
	actions     []uint8
	basis       string
	equalReason Reason
	markerCount int
}

func refinePublicationPreview(preview *contract.PublicationPreview, refinements []publicationPreviewRefinement, relations []contract.PlanningRelation) {
	for _, refinement := range refinements {
		for _, relation := range relations {
			if relation.Name != refinement.name || relation.Code != contract.CryptoSuccess {
				continue
			}
			row := &preview.Entries[refinement.index]
			if row.ReasonCode != 0 || preview.DomainWideWarning || row.LateWriteRisk || len(row.BlockerIDs) != 0 || row.Basis == "warning" || row.Basis == "conflict" || row.Basis == "blocked" {
				if relation.Relation == contract.PlanningEqual || relation.Relation == contract.PlanningChanged || relation.Relation == contract.PlanningNew {
					row.Conditional = false
				}
				if relation.Relation == contract.PlanningEqual && row.ReasonCode == 0 {
					row.ReasonCode = uint8(refinement.equalReason)
				}
				continue
			}
			switch relation.Relation {
			case contract.PlanningEqual:
				row.Conditional, row.Actions, row.Basis = false, refinement.actions, refinement.basis
				row.ReasonCode = uint8(refinement.equalReason)
				if refinement.equalReason != NoReason {
					row.Basis = "capacity"
				}
			case contract.PlanningChanged, contract.PlanningNew:
				row.Conditional = false
				if row.Origin != "proposed" {
					row.Basis = "value-changed"
				} else {
					row.Basis = "unpublished"
				}
			}
		}
	}
	if len(refinements) != 0 {
		updatePublicationPreviewCapacity(preview, refinements[0].markerCount)
	}
}

// Only exact authenticated support pages from this fixed observation are read.
// The temporary encoded publication rows are released after relation validation.
func readPublicationPreviewFacts(ctx context.Context, selected *publicSelection) (selectedPublication, readerFailure) {
	if selected == nil || !selected.complete || !projectionSupportFactsBound(selected.image.root, selected.image.adminIndex, selected.image.supportFacts) {
		return selectedPublication{}, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
	}
	var rows []contract.SupportRecord
	read := func(ctx context.Context, ref format.Ref) ([]byte, Result) {
		body, _, result := selected.basis.reader.readBorrowed(ctx, ref)
		return body, result
	}
	for _, page := range selected.image.supportFacts {
		if !slices.ContainsFunc(page.rows, func(row contract.SupportRecordDigest) bool {
			return row.Kind() == contract.PublicationCoordinateSupportKind || row.Kind() == contract.PublicationMarkerSupportKind
		}) {
			continue
		}
		result, err := withAuthenticatedSupportRows(ctx, read, selected.image.root.Domain, page, func(_, _ uint16, row contract.SupportRecordView) error {
			if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
				return nil
			}
			if len(rows) >= contract.MaxPublicationCoordinates+contract.MaxPublicationMarkers {
				return contract.ErrRecordCapacity
			}
			rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
			return nil
		})
		if result.Outcome != 0 {
			return selectedPublication{}, readerSelectionFailure(result)
		}
		if err != nil {
			return selectedPublication{}, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
		}
	}
	facts, err := publicationRowsRelation(selected.image.root.Domain, rows, selected.image.adminIndex.PublicationOrder)
	if err != nil {
		return selectedPublication{}, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
	}
	return facts, readerFailure{}
}

func previewText(text string) *string { owned := strings.Clone(text); return &owned }

func previewTarget(target contract.PublicOutputTarget, incarnation contract.ID) contract.OutputTarget {
	return contract.OutputTarget{EntryIncarnationID: incarnation, ServiceContractID: target.ServiceContractID.Value, TargetContractID: target.TargetContractID.Value,
		CanonicalTarget: target.CanonicalTarget.Value, ConsumerLocator: target.ConsumerLocator.Value, TargetData: target.TargetData.Value,
		PayloadEncoding: target.PayloadEncoding.Value, LocatorRequiresCreation: target.LocatorRequiresCreation.Value, Capabilities: target.Capabilities.Value, CreateValueBounds: target.CreateValueBounds.Value, WriteValueBounds: target.WriteValueBounds.Value, Policy: target.ConsumerPolicy.Value}
}

func previewStampAfterDelete(selected *publicSelection, coordinate contract.PublicationCoordinate, incarnation contract.ID, ordinal uint64) bool {
	for _, order := range selected.image.adminIndex.PublicationOrder {
		if order.CoordinateID == coordinate.CoordinateID {
			return publicationStampAfter(order.Incarnations, incarnation, ordinal, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal)
		}
	}
	return false
}

func previewSelectedValueBasis(selected *publicSelection, name string) (contract.PublicationValueBasis, bool) {
	for _, named := range selected.image.root.Names {
		if named.Name != name {
			continue
		}
		entry := selected.image.valueEntry(named.Slot)
		if entry == nil {
			return contract.PublicationValueBasis{}, false
		}
		digest, err := contract.PublicValueEntryDigest(selected.image.root.Domain, named.Slot, *entry)
		if err != nil {
			return contract.PublicationValueBasis{}, false
		}
		basis := contract.PublicationValueBasis{EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState, ContentLength: entry.ContentLength, InputEncoding: entry.InputEncoding, RetainedLength: entry.RetainedLength, ConfidentialityClass: entry.ConfidentialityClass, SemanticCommitment: digest}
		if entry.ConfidentialityClass == contract.Secret {
			payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
			if err != nil {
				return contract.PublicationValueBasis{}, false
			}
			basis.ContentLength, basis.SemanticCommitment = payload.ContentLength, payload.SemanticCommitment
		}
		return basis, true
	}
	return contract.PublicationValueBasis{}, false
}

func publicationActionOrder(capabilities contract.OutputActionCapabilities, owned, valueEqual, policyEqual, force, hasPolicy bool) ([]uint8, error) {
	if !capabilities.Valid() {
		return nil, contract.ErrRecord
	}
	var actions []uint8
	if !owned {
		create := uint8(contract.PublicationCreateWithValue)
		if !capabilities.Has(create) || hasPolicy && !capabilities.CreateSetsPolicy() {
			create = contract.PublicationCreateEmpty
		}
		actions = append(actions, create)
		firstWrite := create == contract.PublicationCreateEmpty
		if hasPolicy && !capabilities.CreateSetsPolicy() && (!firstWrite || !capabilities.WriteSetsPolicy()) {
			actions = append(actions, contract.PublicationUpdatePolicy)
		}
		if firstWrite {
			actions = append(actions, contract.PublicationWriteValue)
		}
	} else {
		write := force || !valueEqual
		if hasPolicy && !policyEqual && (!write || !capabilities.WriteSetsPolicy()) {
			actions = append(actions, contract.PublicationUpdatePolicy)
		}
		if write {
			actions = append(actions, contract.PublicationWriteValue)
		}
	}
	for _, action := range actions {
		if !capabilities.Has(action) {
			return nil, contract.ErrRecord
		}
	}
	return actions, nil
}

func (e *ReaderEngine) projectPublicationPreview(ctx context.Context, selected *publicSelection, desired, actual PublicConfigurationValidation) (*contract.PublicationPreview, []publicationPreviewRefinement, readerFailure) {
	preview := &contract.PublicationPreview{DomainWideWarning: selected.image.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != 0}
	refuse := func(reason Reason) (*contract.PublicationPreview, []publicationPreviewRefinement, readerFailure) {
		preview.Complete, preview.ReasonCode = false, uint8(reason)
		return preview, nil, readerSelectionFailure(failure(EvidenceUnavailable, reason))
	}
	if !desired.Valid || !desired.Complete || !actual.Valid || !actual.Complete {
		return refuse(InvalidRelation)
	}
	facts, failed := readPublicationPreviewFacts(ctx, selected)
	if failed.Outcome != 0 {
		preview.ReasonCode = uint8(failed.Reason)
		return preview, nil, failed
	}
	bindings := make(map[string]contract.ID)
	visit := contract.OutputConfigurationVisit{Binding: func(id contract.ID, destination string, _ contract.OutputDestination) error {
		bindings[destination] = id
		return nil
	}}
	if _, result := selectedOutputConfigurationWithReader(ctx, selected.image.root, selected.image.supportFacts, selected.basis.reader, false, &visit); result.Outcome != 0 {
		preview.ReasonCode = uint8(result.Reason)
		return preview, nil, readerSelectionFailure(result)
	}
	type coordinateKey struct{ service, target string }
	seen := make(map[coordinateKey]int)
	observed := make(map[coordinateKey]contract.PublicationCoordinate, len(facts.coordinates))
	for _, coordinate := range facts.coordinates {
		observed[coordinateKey{coordinate.ServiceContractID, coordinate.CanonicalTarget}] = coordinate
	}
	routes := make(map[contract.PublicRoutingKey][]string, len(desired.Configuration.Routing.Value))
	for _, route := range desired.Configuration.Routing.Value {
		routes[route.Key] = route.Destinations.Value
	}
	routed := func(name, destination string) bool {
		for _, key := range [...]contract.PublicRoutingKey{
			{EntrySelector: contract.PublicNamedEntry, EntryName: name},
			{EntrySelector: contract.PublicDefaultRoute},
		} {
			if destinations, present := routes[key]; present {
				return slices.Contains(destinations, destination)
			}
		}
		return false
	}
	var refinements []publicationPreviewRefinement
	for _, binding := range desired.Configuration.OutputBindings.Value {
		for _, proposed := range binding.Targets.Value {
			if ctx.Err() != nil {
				return refuse(ReadUnavailable)
			}
			key := coordinateKey{proposed.ServiceContractID.Value, proposed.CanonicalTarget.Value}
			if at, duplicate := seen[key]; duplicate {
				if at < 0 {
					return refuse(InvalidIntent)
				}
				preview.Entries[at].Basis, preview.Entries[at].ReasonCode = "conflict", uint8(InvalidIntent)
				continue
			}
			seen[key] = -1
			want := publicEntryNamed(desired.Configuration.Entries.Value, proposed.EntryName)
			if want == nil {
				return refuse(InvalidRelation)
			}
			if !slices.Contains(want.Memberships.Value, selected.authorityID) || !routed(proposed.EntryName, binding.DestinationID) {
				continue
			}
			if len(preview.Entries) >= contract.MaxPublicationPreviewEntries {
				return refuse(CapacityExceeded)
			}
			row := contract.PublicationPreviewEntry{ServiceContractID: strings.Clone(proposed.ServiceContractID.Value), PhysicalTarget: strings.Clone(proposed.CanonicalTarget.Value), Origin: "proposed", EntryName: previewText(proposed.EntryName), DestinationID: previewText(binding.DestinationID), TargetContractID: strings.Clone(proposed.TargetContractID.Value), Basis: "unpublished"}
			coordinate, present := observed[key]
			if present {
				row.Origin, row.CoordinateID, row.BindingID = "both", coordinate.CoordinateID, coordinate.ActiveBindingIncarnationID
				if row.BindingID.IsZero() {
					row.BindingID = coordinate.LastBindingIncarnationID
				}
				row.BlockerIDs = publicationBlockers(facts, coordinate.CoordinateID)
				row.RemoteValueMayRemain, row.LateWriteRisk = coordinate.PossibleRemoteObject != 0, coordinate.LateEffectRisk != 0
			}
			current := selectedPlanningEntry(&selected.image, proposed.EntryName)
			before := publicEntryNamed(actual.Configuration.Entries.Value, proposed.EntryName)
			incarnation := contract.ID{}
			if current != nil {
				incarnation = current.Incarnation
			}
			target := previewTarget(proposed, incarnation)
			owned := present && coordinate.OwnerState == contract.PublicationOwnerQualified && coordinate.LastBindingIncarnationID == bindings[binding.DestinationID] && coordinate.LastEntryIncarnationID == incarnation
			if owned {
				birth := facts.markers[coordinate.OwnedBirthAttemptID]
				var err error
				owned, err = publicationBirthAfterDelete(coordinate, birth, facts, selected.image.adminIndex.PublicationOrder)
				if err != nil {
					return refuse(InvalidRelation)
				}
				if owned {
					locator := target.ConsumerLocator
					if target.LocatorRequiresCreation {
						locator = coordinate.DeletionConsumerLocator
					}
					if locator == "" {
						return refuse(InvalidRelation)
					}
					row.ConsumerLocator = previewText(locator)
				}
			}
			policy, err := contract.OutputPolicyDigest(selected.image.root.Domain, target.Policy)
			if err != nil {
				return refuse(InvalidIntent)
			}
			policyEqual := owned && (policy.IsZero() || coordinate.LastPolicyDigest == policy && !coordinate.LastPolicyAckAttemptID.IsZero() && previewStampAfterDelete(selected, coordinate, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal))
			valueEqual := false
			basis, basisAvailable := previewSelectedValueBasis(selected, proposed.EntryName)
			if owned && basisAvailable && !preview.DomainWideWarning && !row.LateWriteRisk {
				digest, err := contract.PublicationValueBasisDigest(selected.image.root.Domain, binding.DestinationID, bindings[binding.DestinationID], target, basis)
				if err != nil {
					return refuse(InvalidRelation)
				}
				digest, err = contract.PublicationSelectedValueDigest(selected.image.root.Domain, digest, coordinate.OwnedBirthAttemptID, coordinate.OwnedInstanceDigest)
				valueEqual = err == nil && digest == coordinate.LastValueDigest && !coordinate.LastValueAckAttemptID.IsZero() && previewStampAfterDelete(selected, coordinate, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal)
			}
			if preview.DomainWideWarning || row.LateWriteRisk {
				policyEqual, valueEqual = false, false
				row.Basis = "warning"
			}
			candidateEqual, secretUnchecked, future := false, false, false
			if current != nil && before != nil && want.Class.Value == before.Class.Value && want.Source.Value == before.Source.Value {
				switch {
				case want.Source.Value == contract.Generated:
					generated := classifyGeneratedPlanningEntry(want, before)
					valueFields := uint16(contract.GeneratedPlanningPresence | contract.GeneratedPlanningClass | contract.GeneratedPlanningSource | contract.GeneratedPlanningEpoch | contract.GeneratedPlanningConfigContract | contract.GeneratedPlanningResourceContract | contract.GeneratedPlanningLifecycle | contract.GeneratedPlanningContentIntent | contract.GeneratedPlanningCompletion)
					candidateEqual = generated.ChangedFields&valueFields == 0
					future = !candidateEqual
				case want.Class.Value == contract.Plain:
					candidateEqual = bytes.Equal(want.PlainValue.Value, current.ValueBytes)
				default:
					secretUnchecked = true
				}
			} else if want.Source.Value == contract.Generated {
				future = true
			} else if want.Class.Value == contract.Secret {
				secretUnchecked = true
			}
			var birth *contract.PublicationMarker
			if owned {
				b := facts.markers[coordinate.OwnedBirthAttemptID]
				birth = &b
			}
			deadline, _ := ctx.Deadline()
			actionInput := publicationPolicyActionInput{DestinationID: binding.DestinationID, ConfigContractID: binding.Destination.Value.ConfigContractID, DomainID: selected.image.root.Domain, Target: target, Deadline: deadline}
			choiceValueEqual := valueEqual && len(row.BlockerIDs) == 0 && selected.image.root.Generated.ActiveOwner.IsZero()
			equalActions, _, err := publicationSelectActions(ctx, actionInput, coordinate, birth, facts, publicationPolicyOrder(coordinate.CoordinateID, selected.image.adminIndex.PublicationOrder), owned, choiceValueEqual, policyEqual, false, e.selectPolicyAction)
			if err != nil {
				return refuse(InvalidIntent)
			}
			if candidateEqual {
				row.Actions = slices.Clone(equalActions)
			} else {
				row.Actions, _, err = publicationSelectActions(ctx, actionInput, coordinate, birth, facts, publicationPolicyOrder(coordinate.CoordinateID, selected.image.adminIndex.PublicationOrder), owned, false, policyEqual, false, e.selectPolicyAction)
			}
			if err != nil {
				return refuse(InvalidIntent)
			}
			if owned {
				row.Basis = "value-changed"
				if valueEqual && candidateEqual && policyEqual {
					row.Basis = "acknowledged-equal"
				} else if valueEqual && candidateEqual && !policyEqual {
					row.Basis = "policy-changed"
				}
			} else if present && coordinate.LastBindingIncarnationID != bindings[binding.DestinationID] {
				row.Basis = "binding-changed"
			}
			if future {
				row.Basis, row.Conditional = "generated-unavailable", true
			}
			equalReason := NoReason
			if basisAvailable && !future && (candidateEqual || secretUnchecked) {
				_, err := publicationScheduledPayloadLength(target, equalActions, basis.ContentLength)
				if err != nil {
					equalReason = CapacityExceeded
				}
			}
			if secretUnchecked {
				row.Basis, row.Conditional = "secret-unchecked", true
				equalBasis := "unpublished"
				if owned {
					equalBasis = "value-changed"
				}
				if owned && valueEqual && policyEqual {
					equalBasis = "acknowledged-equal"
				} else if owned && valueEqual {
					equalBasis = "policy-changed"
				}
				refinements = append(refinements, publicationPreviewRefinement{index: len(preview.Entries), name: proposed.EntryName, actions: equalActions, basis: equalBasis, equalReason: equalReason, markerCount: len(facts.markers)})
			}
			if candidateEqual && equalReason != NoReason {
				row.Basis, row.ReasonCode = "capacity", uint8(equalReason)
			} else if want.Class.Value == contract.Plain && !candidateEqual {
				_, err := publicationScheduledPayloadLength(target, row.Actions, uint32(len(want.PlainValue.Value)))
				if err != nil {
					row.Basis, row.ReasonCode = "capacity", uint8(CapacityExceeded)
				}
			}
			if preview.DomainWideWarning || row.LateWriteRisk {
				row.Basis = "warning"
			}
			if present && coordinate.OwnerState != contract.PublicationOwnerNone && !owned {
				row.Basis, row.ReasonCode, row.Actions = "conflict", uint8(InvalidIntent), nil
			}
			if len(row.BlockerIDs) != 0 {
				row.Basis, row.ReasonCode, row.Actions = "blocked", uint8(DifferentSelection), nil
			}
			if !selected.image.root.Generated.ActiveOwner.IsZero() {
				row.Basis, row.ReasonCode = "blocked", uint8(DifferentSelection)
			}
			seen[key] = len(preview.Entries)
			preview.Entries = append(preview.Entries, row)
		}
	}
	for key, coordinate := range observed {
		if _, present := seen[key]; present {
			continue
		}
		if len(preview.Entries) >= contract.MaxPublicationPreviewEntries {
			return refuse(CapacityExceeded)
		}
		row := contract.PublicationPreviewEntry{ServiceContractID: strings.Clone(coordinate.ServiceContractID), PhysicalTarget: strings.Clone(coordinate.CanonicalTarget), Origin: "observed", CoordinateID: coordinate.CoordinateID, BindingID: coordinate.LastBindingIncarnationID,
			TargetContractID: strings.Clone(coordinate.DeletionTargetContractID), Basis: "retained-deletion", BlockerIDs: publicationBlockers(facts, coordinate.CoordinateID), RemoteValueMayRemain: coordinate.PossibleRemoteObject != 0, LateWriteRisk: coordinate.LateEffectRisk != 0}
		if row.TargetContractID == "" {
			for _, binding := range actual.Configuration.OutputBindings.Value {
				for _, target := range binding.Targets.Value {
					if target.ServiceContractID.Value == coordinate.ServiceContractID && target.CanonicalTarget.Value == coordinate.CanonicalTarget {
						row.ServiceContractID, row.TargetContractID = target.ServiceContractID.Value, target.TargetContractID.Value
						row.DestinationID = previewText(binding.DestinationID)
						row.EntryName = previewText(target.EntryName)
					}
				}
			}
		}
		if row.ServiceContractID == "" || coordinate.OwnerState != contract.PublicationOwnerNone && row.TargetContractID == "" {
			row.Basis, row.ReasonCode = "evidence-unavailable", uint8(InvalidRelation)
			preview.Entries = append(preview.Entries, row)
			return refuse(InvalidRelation)
		}
		if coordinate.DeletionDestinationID != "" {
			row.DestinationID = previewText(coordinate.DeletionDestinationID)
		}
		for _, named := range selected.image.root.Names {
			if entry := selected.image.valueEntry(named.Slot); entry != nil && entry.Incarnation == coordinate.LastEntryIncarnationID {
				row.EntryName = previewText(named.Name)
			}
		}

		switch coordinate.OwnerState {
		case contract.PublicationOwnerQualified:
			birth := facts.markers[coordinate.OwnedBirthAttemptID]
			available, err := publicationBirthAfterDelete(coordinate, birth, facts, selected.image.adminIndex.PublicationOrder)
			if err != nil {
				row.Basis, row.ReasonCode = "evidence-unavailable", uint8(InvalidRelation)
				preview.Entries = append(preview.Entries, row)
				return refuse(InvalidRelation)
			}
			if !available {
				row.Basis = "acknowledged-equal"
				if row.RemoteValueMayRemain || row.LateWriteRisk {
					row.Basis = "warning"
				}
				break
			}
			row.Actions = []uint8{contract.PublicationDeleteOwned}
			if coordinate.DeletionConsumerLocator == "" {
				return refuse(InvalidRelation)
			}
			row.ConsumerLocator = previewText(coordinate.DeletionConsumerLocator)

		case contract.PublicationOwnerUncertainCreate:
			qualified := false
			for _, id := range row.BlockerIDs {
				marker := facts.markers[id]
				if publicationReservedSlotEligible(coordinate, marker) {
					qualified = true
				}
			}
			if !qualified {
				row.Basis, row.ReasonCode = "evidence-unavailable", uint8(InvalidRelation)
				preview.Entries = append(preview.Entries, row)
				return refuse(InvalidRelation)
			}
			row.Actions = []uint8{contract.PublicationDeleteReservedSlot}
		default:
			if row.RemoteValueMayRemain || row.LateWriteRisk {
				row.Basis = "warning"
			} else {
				row.Basis = "acknowledged-equal"
			}
		}
		if len(row.BlockerIDs) != 0 {
			row.Basis, row.ReasonCode = "blocked", uint8(DifferentSelection)
		}
		if preview.DomainWideWarning && row.Basis == "acknowledged-equal" {
			row.Basis = "warning"
		}
		if !selected.image.root.Generated.ActiveOwner.IsZero() {
			row.Basis, row.ReasonCode = "blocked", uint8(DifferentSelection)
		}
		preview.Entries = append(preview.Entries, row)
	}
	preview.Complete = true
	updatePublicationPreviewCapacity(preview, len(facts.markers))
	return preview, refinements, readerFailure{}
}

func sortPublicationPreview(preview *contract.PublicationPreview) {
	if preview == nil {
		return
	}
	slices.SortFunc(preview.Entries, func(a, b contract.PublicationPreviewEntry) int {
		if n := strings.Compare(a.ServiceContractID, b.ServiceContractID); n != 0 {
			return n
		}
		if n := strings.Compare(a.PhysicalTarget, b.PhysicalTarget); n != 0 {
			return n
		}
		return strings.Compare(a.Origin, b.Origin)
	})
}

func updatePublicationPreviewCapacity(preview *contract.PublicationPreview, markers int) {
	if preview == nil || !preview.Complete {
		return
	}
	actions := 0
	for _, row := range preview.Entries {
		actions += len(row.Actions)
	}
	if len(preview.Entries) > contract.MaxPublicationCoordinates || actions > contract.MaxPublicationInvocationActions || markers+actions > contract.MaxPublicationMarkers {
		preview.ReasonCode = uint8(CapacityExceeded)
	} else if preview.ReasonCode == uint8(CapacityExceeded) {
		preview.ReasonCode = 0
	}
}
