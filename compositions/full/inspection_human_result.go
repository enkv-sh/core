package compositionfull

import (
	"fmt"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func inspectionObservationHuman(w generatedFactWriter, v core.PublicObservation) {
	w.text("Observed revision: " + readerID(v.HeadRevisionID) + "\nSnapshot: " + readerID(v.SnapshotID) + "\n")
}

func inspectionActiveHuman(w generatedFactWriter, p *core.GeneratedActiveOperation) {
	if p == nil {
		w.text("Active operation: none\n")
		return
	}
	w.text(fmt.Sprintf("Active operation: %s; %s; phase %d; stage %s\n", readerID(p.OperationID), generatedOperationName(p.OperationKind), p.Phase, generatedStageHuman(p.Stage)))
	w.text("Phase identity: " + readerID(p.PhaseID) + "\n")
	if !p.FrontierAttemptID.IsZero() {
		w.text("Frontier attempt: " + readerID(p.FrontierAttemptID) + "\n")
	}
}

// A membership's optional label is drawn only from this validated observation.
// Its quoted 256-byte maximum and fixed text fit inside 60 times the existing
// 67-byte JSON membership allowance; the complete human limit is unchanged.
func inspectionDomainHuman(q *queryObject, v *core.DomainInspection) {
	w := q.w
	inspectionObservationHuman(w, v.Observation)
	inspectionActiveHuman(w, v.ActiveOperation)
	q.array("entries", len(v.Entries), func(i int) {
		p := v.Entries[i]
		w.text(fmt.Sprintf("Entry %q: %s; confidential %t\n", p.Name, inspectionSourceHuman(p.ValueSource), p.Confidential))
		w.text("  Incarnation: " + readerID(p.IncarnationID) + "; value state: " + readerID(p.ValueStateID) + "\n")
		w.text(fmt.Sprintf("  Recipients: %d\n", len(p.RecipientIDs)))
		for _, id := range p.RecipientIDs {
			w.text("  Recipient: " + readerID(id))
			for _, recipient := range v.Recipients {
				if recipient.RecipientID == id {
					w.text(fmt.Sprintf(" (%q)", recipient.DisplayName))
					break
				}
			}
			w.text("\n")
		}
		if p.ValueSource == contract.Generated {
			w.text(fmt.Sprintf("  Generation: %s; epoch %d; retirement %s\n", readerID(p.GenerationID), p.Epoch, inspectionRetirementHuman(p.RetirementMode)))
		}
	})
	q.array("recipients", len(v.Recipients), func(i int) {
		p := v.Recipients[i]
		w.text(fmt.Sprintf("Recipient %s: %s; display name %q\n", readerID(p.RecipientID), map[uint8]string{contract.CurrentRecipient: "current", contract.RetiredRecipient: "retired"}[p.Status], p.DisplayName))
		if p.Status == contract.CurrentRecipient {
			w.text(fmt.Sprintf("  Binding: %s; serial %d; fingerprint %s\n", readerID(p.BindingID), p.BindingSerial, readerID(p.BindingFingerprint)))
		}
	})
	writeGeneratedQueryRowsHuman(w, v.Generated, v.ActiveOperation == nil)
	inspectionWorkHuman(q, v.Work)
	inspectionOutputHuman(q, v)
	writeCurrentQueryWarnings(w, v.DomainWarningBits)
	if v.Warnings.Generated.PossibleLiveResidue {
		w.text("Warning for generated work: A generated effect can still be live.\n")
	}
	if v.Warnings.Generated.LateEffect {
		w.text("Warning for generated work: An earlier request can still act.\n")
	}
	if v.Warnings.Generated.InvalidationNotConfirmed {
		w.text("Warning for generated work: Deletion was acknowledged; invalidation is not confirmed.\n")
	}
	if v.Warnings.PossibleStoreGarbage {
		w.text("Warning: Immutable Store garbage may remain.\n")
	}
}

func inspectionSourceHuman(source uint8) string {
	return map[uint8]string{contract.Supplied: "supplied", contract.Generated: "generated"}[source]
}
func inspectionRetirementHuman(mode uint8) string {
	if mode == 0 {
		return "not-applicable"
	}
	return map[uint8]string{contract.GeneratedRetirementManual: "manual", contract.GeneratedRetirementAuto: "auto"}[mode]
}

func inspectionWorkHuman(q *queryObject, v core.InspectionWork) {
	w := q.w
	w.text(fmt.Sprintf("Selected work: %d groups\n", len(v.Groups)))
	for i, p := range v.Groups {
		selection := v.GroupSelections[i]
		w.text("Work " + readerID(p.GroupID) + ": " + abandonKind(p.OwnerKind))
		if p.DutyKind != 0 {
			w.text("; " + generatedDutyKindHuman(p.DutyKind))
		}
		w.text("\nOwner: " + readerID(p.OwnerID) + "\nTarget: " + readerID(p.TargetID) + "\n")
		w.text(fmt.Sprintf("Selectable: %t; destructive effect: %t; uncertain create proof: %t\n", selection.Selectable, p.DestructiveEffect != 0, p.UncertainCreateProof != 0))
		w.text(fmt.Sprintf("Effect entry ceiling: %d; evidence: ", p.EffectEntryCeiling))
		w.value(abandonEvidence(p.SelectedEvidenceSummary))
		w.text("\n")
		w.text(fmt.Sprintf("Affected subjects: %d; retained dependencies: %d; disposable records: %d\n", p.Affected.Count, p.Dependencies.Count, p.Disposable.Count))
		for _, related := range p.RelatedGroupIndexes {
			w.text("Related group: " + readerID(v.Groups[related].GroupID) + "\n")
		}
		if selection.RequiredParentIndex != nil {
			w.text("Required parent: " + readerID(v.Groups[*selection.RequiredParentIndex].GroupID) + "\n")
		}
		if !p.PublicationIncarnationID.IsZero() {
			w.text(fmt.Sprintf("Publication incarnation: %s; admission ordinal %d\n", readerID(p.PublicationIncarnationID), p.AdmissionOrdinal))
		}
		if p.GC != nil {
			progress, err := publicGCProgress(p.GC)
			if err != nil {
				w.err = err
				return
			}
			inspectionGCProgressHuman(q, progress)
		}
	}
	for _, order := range v.PublicationOrder {
		w.text("Publication order for " + readerID(order.CoordinateID) + ":\n")
		for _, id := range order.Incarnations {
			w.text("  Incarnation: " + readerID(id) + "\n")
		}
	}
}

func inspectionOutputHuman(q *queryObject, v *core.DomainInspection) {
	w := q.w
	output := v.Output
	blockers, blocked := 0, 0
	for _, row := range output.CurrentBlockers {
		blockers += len(row.MarkerIndexes)
		if len(row.MarkerIndexes) > 0 {
			blocked++
		}
	}
	w.text(fmt.Sprintf("Current publication blockers: %d across %d coordinates; blocked coordinates: %d\n", blockers, len(output.CurrentBlockers), blocked))
	for _, binding := range output.Configuration.Bindings {
		w.text(fmt.Sprintf("Destination %q: service %q; binding %s\n", binding.DestinationID, binding.Destination.ServiceContractID, readerID(binding.IncarnationID)))
		w.text(fmt.Sprintf("  Configuration contract %q; policy contract %q\n", binding.Destination.ConfigContractID, binding.Destination.Policy.ContractID))
		inspectionCapabilitiesHuman(w, binding.Destination.Capabilities)
		for _, target := range binding.Targets {
			w.text(fmt.Sprintf("  Target %q", target.CanonicalTarget))
			for _, entry := range v.Entries {
				if entry.IncarnationID == target.EntryIncarnationID {
					w.text(fmt.Sprintf("; entry %q", entry.Name))
					break
				}
			}
			w.text("; entry incarnation " + readerID(target.EntryIncarnationID) + "\n")
			w.text(fmt.Sprintf("  Consumer locator %q; target contract %q; locator requires creation %t\n", target.ConsumerLocator, target.TargetContractID, target.LocatorRequiresCreation))
			w.text(fmt.Sprintf("  Service contract %q; payload encoding %s; policy contract %q\n", target.ServiceContractID, map[uint8]string{contract.OutputEncodingRaw: "raw", contract.OutputEncodingBase64: "base64"}[target.PayloadEncoding], target.Policy.ContractID))
			w.text(fmt.Sprintf("  Create value bounds: %d..%d; write value bounds: %d..%d\n", target.CreateValueBounds.Minimum, target.CreateValueBounds.Maximum, target.WriteValueBounds.Minimum, target.WriteValueBounds.Maximum))
			inspectionCapabilitiesHuman(w, target.Capabilities)
		}
	}
	w.text("Default destinations:")
	for _, name := range output.Configuration.DefaultDestinations {
		w.text(fmt.Sprintf(" %q", name))
	}
	w.text("\n")
	for _, route := range output.Configuration.Routes {
		w.text("Route for entry " + readerID(route.EntryIncarnationID) + ":")
		for _, name := range route.Destinations {
			w.text(fmt.Sprintf(" %q", name))
		}
		w.text("\n")
	}
	for i, group := range output.Configuration.Groups {
		w.text(fmt.Sprintf("Output group %d:", i+1))
		for _, id := range group {
			w.text(" " + readerID(id))
		}
		w.text("\n")
	}
	for _, target := range output.CurrentTargets {
		w.text("Current target " + readerID(target.CoordinateID) + ": " + string(target.LocatorBasis))
		if target.ResolvedConsumerLocator != nil {
			w.text(fmt.Sprintf("; resolved consumer locator %q", *target.ResolvedConsumerLocator))
		}
		w.text("\n")
	}
	for _, p := range output.Coordinates {
		w.text(fmt.Sprintf("Publication target %q: %s; service %q; coordinate %s\n", p.CanonicalTarget, map[uint8]string{contract.PublicationBindingActive: "current", contract.PublicationBindingRetired: "retained"}[p.BindingState], p.ServiceContractID, readerID(p.CoordinateID)))
		w.text("  Ownership: " + map[uint8]string{contract.PublicationOwnerNone: "none", contract.PublicationOwnerUncertainCreate: "uncertain-create", contract.PublicationOwnerQualified: "qualified"}[p.OwnerState] + "\n")
		w.text("  Binding incarnation: " + readerID(p.LastBindingIncarnationID) + "; entry incarnation: " + readerID(p.LastEntryIncarnationID) + "\n")
		w.text(fmt.Sprintf("  Publication incarnation: %s; admission ordinal %d\n", readerID(p.CurrentPublicationIncarnationID), p.LastAdmissionOrdinal))
		for _, field := range []struct {
			label string
			id    contract.ID
		}{{"Active binding", p.ActiveBindingIncarnationID}, {"Owned birth attempt", p.OwnedBirthAttemptID}, {"Unresolved attempt", p.LatestUnresolvedAttemptID}} {
			if !field.id.IsZero() {
				w.text("  " + field.label + ": " + readerID(field.id) + "\n")
			}
		}
		for _, ack := range []struct {
			kind                 string
			attempt, incarnation contract.ID
			ordinal              uint64
		}{{"Value", p.LastValueAckAttemptID, p.LastValueAckIncarnationID, p.LastValueAckOrdinal}, {"Policy", p.LastPolicyAckAttemptID, p.LastPolicyAckIncarnationID, p.LastPolicyAckOrdinal}, {"Delete", p.LastDeleteAckAttemptID, p.LastDeleteAckIncarnationID, p.LastDeleteAckOrdinal}} {
			if !ack.attempt.IsZero() {
				w.text(fmt.Sprintf("  %s acknowledgement: attempt %s; incarnation %s; ordinal %d\n", ack.kind, readerID(ack.attempt), readerID(ack.incarnation), ack.ordinal))
			}
		}
		w.text(fmt.Sprintf("  Possible remote object: %t; late effect risk: %t\n", p.PossibleRemoteObject != 0, p.LateEffectRisk != 0))
		if p.DeletionDestinationID != "" {
			w.text(fmt.Sprintf("  Retained deletion destination %q; consumer locator %q; target contract %q\n", p.DeletionDestinationID, p.DeletionConsumerLocator, p.DeletionTargetContractID))
			w.text(fmt.Sprintf("  Retained configuration contract %q; credential route contract %q; payload encoding %s; locator requires creation %t\n", p.DeletionConfigContractID, p.DeletionCredentialRouteContractID, map[uint8]string{contract.OutputEncodingRaw: "raw", contract.OutputEncodingBase64: "base64"}[p.DeletionPayloadEncoding], p.LocatorRequiresCreation))
		}
	}
	for _, p := range output.Markers {
		w.text(fmt.Sprintf("Publication action %s: %s; coordinate %s\n", publicationActionName(p.Projection.Action), publicationMarkerStateHuman(p.State), readerID(p.CoordinateID)))
		w.text(fmt.Sprintf("  Operation: %s; attempt: %s; incarnation: %s; admission ordinal %d\n", readerID(p.OperationID), readerID(p.AttemptID), readerID(p.PublicationIncarnationID), p.AdmissionOrdinal))
		w.text(fmt.Sprintf("  Entry incarnation: %s; binding incarnation: %s; blocker count %d; late effect risk %t\n", readerID(p.Projection.EntryIncarnationID), readerID(p.Projection.BindingIncarnationID), p.BlockerCount, p.LateEffectRisk != 0))
		w.text("  Evidence: " + map[uint8]string{contract.PublicationUnproved: "unproved", contract.PublicationRequestAcknowledged: "request-acknowledged", contract.PublicationQualifiedNoEffect: "qualified-no-effect"}[p.Evidence.Class] + "; request entry " + map[uint8]string{contract.PublicationNotEntered: "not-entered", contract.PublicationMayHaveEnteredEntry: "may-have-entered"}[p.Evidence.Entry] + "\n")
		w.text(fmt.Sprintf("  Executor %q; credential route %q; birth service contract %q; birth target contract %q\n", p.ExecutorID, p.CredentialRouteID, p.BirthServiceContractID, p.BirthTargetContractID))
		if !p.Projection.ActingRecipientID.IsZero() {
			w.text("  Acting recipient: " + readerID(p.Projection.ActingRecipientID) + "\n")
		}
		if p.Evidence.SafeRequestID != "" || p.Evidence.SafeResourceID != "" || p.Evidence.ConsumerLocator != "" {
			w.text(fmt.Sprintf("  Request %q; resource %q; consumer locator %q\n", p.Evidence.SafeRequestID, p.Evidence.SafeResourceID, p.Evidence.ConsumerLocator))
		}
		if p.Evidence.NormalizedStatus != 0 {
			w.text(fmt.Sprintf("  normalized status %d\n", p.Evidence.NormalizedStatus))
		}
	}
	for _, row := range output.CurrentBlockers {
		for _, index := range row.MarkerIndexes {
			w.text("Blocker: coordinate " + readerID(output.Coordinates[row.CoordinateIndex].CoordinateID) + "; attempt " + readerID(output.Markers[index].AttemptID) + "\n")
		}
	}
	if output.Warnings.DomainWideWarning || output.Warnings.UnresolvedPublication || output.Warnings.LateWriteRisk {
		w.text("Warning for output: Publication acknowledgement does not prove current remote order or value. Deletion acknowledgement does not prove invalidation.\n")
	}
	if output.Warnings.DomainWideWarning {
		w.text("Domain-wide publication warning: The retained domain warning applies to every output coordinate, including new bindings.\n")
	}
	if output.Warnings.UnresolvedPublication {
		w.text("Unresolved publication attempts remain; their final effects are unproved. Retain their exact coordinate and attempt identities.\n")
	}
	if output.Warnings.LateWriteRisk {
		w.text("Retained publication late-write risk: A late write can still change the destination.\n")
	}
}

func publicationMarkerStateHuman(state uint8) string {
	return map[uint8]string{contract.PublicationMayHaveEntered: "may-have-entered", contract.PublicationAcknowledged: "acknowledged", contract.PublicationQualifiedNoEffectState: "qualified-no-effect", contract.PublicationUnknown: "unknown"}[state]
}

func inspectionCapabilitiesHuman(w generatedFactWriter, bits contract.OutputActionCapabilities) {
	w.text("  Supported plugin actions:")
	for _, flag := range []struct {
		bit  contract.OutputActionCapabilities
		name string
	}{{contract.OutputCapabilityCreateEmpty, "create-empty"}, {contract.OutputCapabilityCreateWithValue, "create-with-value"}, {contract.OutputCapabilityWriteValue, "write-value"}, {contract.OutputCapabilityUpdatePolicy, "update-policy"}, {contract.OutputCapabilityDeleteOwned, "delete-owned"}, {contract.OutputCapabilityDeleteReservedSlot, "delete-reserved-slot"}, {contract.OutputCapabilityCreateSetsPolicy, "create-sets-policy"}, {contract.OutputCapabilityWriteSetsPolicy, "write-sets-policy"}} {
		if bits&flag.bit != 0 {
			w.text(" " + flag.name)
		}
	}
	w.text(" (support grants no effect permission)\n")
}
