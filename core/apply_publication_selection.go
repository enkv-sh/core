package core

import (
	"bytes"
	"context"
	"math"
	"slices"
	"strings"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
)

type applyPublicationEntry struct {
	selection contract.ConsumerSelection
	basis     contract.PublicationValueBasis
}

type applyPublicationTarget struct {
	binding, coordinate, digest contract.ID
	destination                 string
	target                      contract.OutputTarget
}

type applyPublicationPolicy struct {
	binding     contract.ID
	destination string
	policy      contract.OutputPolicy
}

type applyPublicationDeletion struct {
	coordinate contract.PublicationCoordinate
	marker     contract.PublicationMarker
}

type applyPublicationHandoff struct {
	domain, acting contract.ID
	deadline       time.Time
	entries        []applyPublicationEntry
	targets        []applyPublicationTarget
	policies       []applyPublicationPolicy
	deletions      []applyPublicationDeletion
	groups         [][]contract.ID
	slots          [contract.CryptoMaxValueEntries]int16
	backingBytes   uint64
	consumed       bool
	closed         bool
}

func addApplyPublicationBytes(total *uint64, count, width uint64) bool {
	if width != 0 && count > (math.MaxUint64-*total)/width {
		return false
	}
	*total += count * width
	return true
}

func applyPublicationDynamicLimit() uint64 {
	wraps := uint64(contract.CryptoMaxValueEntries) * (contract.CryptoMaxRecipients + 1)
	return contract.CryptoMaxRetainedSet + contract.CanonicalPayloadOverhead*contract.CryptoMaxValueEntries +
		contract.CryptoMaxName*contract.CryptoMaxValueEntries + 32*contract.CryptoMaxMemberships +
		contract.MaxKeySelector + contract.KMSPublicKeyLength + 256 + wraps*(uint64(unsafe.Sizeof(contract.WrapRow{}))+contract.RSACiphertextLength) +
		4*contract.MaxOutputDeclarationBytes + contract.MaxPublicationCoordinates*(contract.MaxPublicationCoordinateRecordBytes+contract.MaxPublicationMarkerRecordBytes) + 32*contract.MaxPublicationMarkers
}

// This borrowed view avoids DecodeCanonicalPayload's ciphertext allocation.
// The complete selected session already authenticated its current reader union.
func (s *StateSession) borrowApplyPublicationEntry(slot uint16, acting contract.ID) (applyPublicationEntry, bool) {
	var out applyPublicationEntry
	entry := s.valueEntry(slot)
	recipient := s.recipientRecord(acting)
	if entry == nil || recipient == nil || recipient.CurrentBinding == nil || !slices.Contains(entry.Recipients, acting) {
		return out, false
	}
	digest, err := contract.PublicValueEntryDigest(s.root.Domain, slot, *entry)
	if err != nil {
		return out, false
	}
	out.selection = contract.ConsumerSelection{DomainID: s.root.Domain, SnapshotID: s.root.Snapshot, HEADDigest: contract.Hash(s.body), AccessRoot: s.root.CurrentAccess.AccessRoot,
		EntryDigest: digest, Root: s.head.Core.Root, HEADRevision: s.head.Core.Revision, HEADToken: s.token, Slot: slot, Entry: *entry,
		Binding: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: acting, Binding: *recipient.CurrentBinding}}
	out.basis = contract.PublicationValueBasis{EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState, ConfidentialityClass: entry.ConfidentialityClass, ContentLength: entry.ContentLength, InputEncoding: entry.InputEncoding, RetainedLength: entry.RetainedLength, SemanticCommitment: digest}
	if entry.ConfidentialityClass == contract.Secret {
		view, err := contract.InspectCanonicalPayload(entry.ValueBytes)
		if err != nil {
			return out, false
		}
		out.selection.Payload = contract.CanonicalPayload(view)
		out.selection.Core, err = contract.ValueCoreForEntry(s.root.Domain, contract.CompatibilityID(), *entry)
		access, present := selectedMaterialAccess(&s.access, s.accessLocations, contract.ValueMaterialKind, entry.ValueState)
		if err != nil || !present || !s.validateValueAccess(out.selection.Core, out.selection.Payload, access, s.valueReaders[entry.ValueState]) {
			return out, false
		}
		out.selection.Access = access
		out.basis.ContentLength, out.basis.SemanticCommitment = view.ContentLength, view.SemanticCommitment
	}
	return out, true
}

func applyPublicationEntryBytes(entry applyPublicationEntry) (uint64, error) {
	s := entry.selection
	n := uint64(len(s.Entry.Name))
	if !addApplyPublicationBytes(&n, uint64(len(s.Entry.ValueBytes)), 1) || !addApplyPublicationBytes(&n, uint64(len(s.Entry.Recipients)), 32) ||
		!addApplyPublicationBytes(&n, uint64(len(s.Access.Wraps)), uint64(unsafe.Sizeof(contract.WrapRow{}))+contract.RSACiphertextLength) {
		return 0, contract.ErrRecordCapacity
	}
	return n, nil
}

func ownApplyPublicationEntry(in applyPublicationEntry, binding contract.BindingTableRow, token contract.Token) (applyPublicationEntry, error) {
	out := in
	out.selection.Entry.Name = strings.Clone(in.selection.Entry.Name)
	out.selection.Entry.ValueBytes = make([]byte, len(in.selection.Entry.ValueBytes))
	copy(out.selection.Entry.ValueBytes, in.selection.Entry.ValueBytes)
	out.selection.Entry.Recipients = make([]contract.ID, len(in.selection.Entry.Recipients))
	copy(out.selection.Entry.Recipients, in.selection.Entry.Recipients)
	out.selection.Core.Name = out.selection.Entry.Name
	out.selection.Binding, out.selection.HEADToken = binding, token
	if in.selection.Entry.ConfidentialityClass == contract.Secret {
		payload, err := contract.InspectCanonicalPayload(out.selection.Entry.ValueBytes)
		if err != nil {
			return applyPublicationEntry{}, err
		}
		out.selection.Payload = contract.CanonicalPayload(payload)
		out.selection.Payload.Ciphertext = out.selection.Payload.Ciphertext[:len(payload.Ciphertext):len(payload.Ciphertext)]
		out.selection.Access.Wraps = make([]contract.WrapRow, len(in.selection.Access.Wraps))
		arena := make([]byte, len(in.selection.Access.Wraps)*contract.RSACiphertextLength)
		for i, wrap := range in.selection.Access.Wraps {
			start, end := i*contract.RSACiphertextLength, (i+1)*contract.RSACiphertextLength
			out.selection.Access.Wraps[i] = wrap
			out.selection.Access.Wraps[i].RSACiphertext = arena[start:end:end]
			copy(out.selection.Access.Wraps[i].RSACiphertext, wrap.RSACiphertext)
		}
	}
	return out, nil
}

func applyPublicationPolicyBytes(p contract.OutputPolicy) uint64 {
	return uint64(len(p.ContractID)) + uint64(len(p.Data))
}

func applyPublicationTargetBytes(t contract.OutputTarget) uint64 {
	return uint64(len(t.ServiceContractID)) + uint64(len(t.CanonicalTarget)) + uint64(len(t.ConsumerLocator)) + uint64(len(t.TargetContractID)) + uint64(len(t.TargetData))
}

func captureApplyPublicationSelection(ctx context.Context, s *StateSession) (_ *applyPublicationHandoff, err error) {
	if ctx == nil || ctx.Err() != nil || s == nil || !s.admission.valid(s.store) || len(s.root.Names) > contract.CryptoMaxValueEntries {
		return nil, contract.ErrRecord
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return nil, contract.ErrRecord
	}
	h := &applyPublicationHandoff{domain: s.root.Domain, acting: s.root.CurrentAccess.Core.AuthorityRecipientID, deadline: deadline}
	defer func() {
		if err != nil {
			h.close()
		}
	}()
	for i := range h.slots {
		h.slots[i] = -1
	}
	var borrowed [contract.CryptoMaxValueEntries]applyPublicationEntry
	var overridden [contract.CryptoMaxValueEntries]bool
	var routes [contract.CryptoMaxValueEntries][]string
	var dynamic, raw, memberships uint64
	for i, row := range s.root.Names {
		entry, valid := s.borrowApplyPublicationEntry(row.Slot, h.acting)
		if !valid || int(row.Slot) >= len(h.slots) || h.slots[row.Slot] != -1 {
			return nil, contract.ErrRecord
		}
		borrowed[i], h.slots[row.Slot] = entry, int16(i)
		n, err := applyPublicationEntryBytes(entry)
		if err != nil || !addApplyPublicationBytes(&dynamic, n, 1) || !addApplyPublicationBytes(&raw, uint64(entry.basis.ContentLength), 1) || !addApplyPublicationBytes(&memberships, uint64(len(entry.selection.Entry.Recipients)), 1) || raw > contract.CryptoMaxRawSet || memberships > contract.CryptoMaxMemberships {
			return nil, contract.ErrRecordCapacity
		}
	}
	r := s.recipientRecord(h.acting)
	if r == nil || r.CurrentBinding == nil || !s.token.Valid() {
		return nil, contract.ErrRecord
	}
	if !addApplyPublicationBytes(&dynamic, uint64(len(r.CurrentBinding.KeySelector)+len(r.CurrentBinding.SPKI)+len(s.token.Value)), 1) || dynamic > applyPublicationDynamicLimit() {
		return nil, contract.ErrRecordCapacity
	}
	// The descriptor reserves the decoder's bounded expansion before its visitors
	// own fields. Only selected target/policy/group facts survive this traversal.
	d := s.root.OutputConfiguration
	if _, descriptorErr := contract.EncodeOutputConfigurationDescriptor(d); descriptorErr != nil {
		return nil, contract.ErrRecord
	}
	declaration := uint64(d.TotalLength - d.RoutingLength - 4)
	if !addApplyPublicationBytes(&dynamic, 4*declaration, 1) || dynamic > applyPublicationDynamicLimit() {
		return nil, contract.ErrRecordCapacity
	}
	type targetKey struct {
		binding, entry, coordinate contract.ID
		destination                string
	}
	var keys [contract.MaxOutputTargets]targetKey
	keyCount, groupCount, groupMembers := 0, 0, 0
	var routeScratch uint64
	routeScratchLimit := uint64((contract.CryptoMaxValueEntries+1)*contract.MaxOutputRouteDestinations) * (uint64(unsafe.Sizeof("")) + 256)
	visit := contract.OutputConfigurationVisit{
		Target: func(binding, entry, coordinate contract.ID, destination string) error {
			if keyCount == len(keys) {
				return contract.ErrRecordCapacity
			}
			keys[keyCount] = targetKey{binding, entry, coordinate, destination}
			keyCount++
			return nil
		},
		Route: func(entry contract.ID, destinations []string) error {
			retained := false
			for i, row := range borrowed[:len(s.root.Names)] {
				if entry == row.basis.EntryIncarnationID || entry.IsZero() && !overridden[i] {
					routes[i] = destinations[:len(destinations):len(destinations)]
					overridden[i] = !entry.IsZero()
					retained = true
				}
			}
			if retained {
				n := uint64(len(destinations)) * uint64(unsafe.Sizeof(""))
				for _, destination := range destinations {
					n += uint64(len(destination))
				}
				if !addApplyPublicationBytes(&routeScratch, n, 1) || routeScratch > routeScratchLimit {
					return contract.ErrRecordCapacity
				}
			}
			return nil
		},
		Group: func(members []contract.ID) error {
			groupCount++
			groupMembers += len(members)
			if groupCount > contract.CryptoMaxValueEntries || groupMembers > contract.CryptoMaxValueEntries {
				return contract.ErrRecordCapacity
			}
			return nil
		},
	}
	if state := s.validateSelectedOutputConfigurationRelations(ctx, &visit); state.Outcome != 0 {
		return nil, contract.ErrRecord
	}
	wanted := func(entry contract.ID, destination string) bool {
		for i, row := range borrowed[:len(s.root.Names)] {
			if row.basis.EntryIncarnationID == entry {
				return slices.Contains(routes[i], destination)
			}
		}
		return false
	}
	selectedTargets := 0
	destinations := make(map[string]bool)
	for _, key := range keys[:keyCount] {
		if wanted(key.entry, key.destination) {
			selectedTargets++
			destinations[key.destination] = true
		}
	}
	selected, valid := s.publicationProof.relationFor(s.selectedImage())
	if !valid {
		return nil, contract.ErrRecord
	}
	var deletionRows [contract.MaxPublicationCoordinates]applyPublicationDeletion
	deleteCount := 0
	for _, coordinate := range selected.coordinates {
		if coordinate.BindingState != contract.PublicationBindingRetired || coordinate.OwnerState == contract.PublicationOwnerNone {
			continue
		}
		var marker contract.PublicationMarker
		if coordinate.OwnerState == contract.PublicationOwnerQualified {
			marker = selected.markers[coordinate.OwnedBirthAttemptID]
			available, err := publicationBirthAfterDelete(coordinate, marker, selected, s.adminIndex.PublicationOrder)
			if err != nil {
				return nil, err
			}
			if !available {
				continue
			}
		} else {
			for _, attempt := range publicationBlockers(selected, coordinate.CoordinateID) {
				candidate := selected.markers[attempt]
				if (candidate.Projection.Action == contract.PublicationCreateEmpty || candidate.Projection.Action == contract.PublicationCreateWithValue) && candidate.Projection.BindingIncarnationID == coordinate.LastBindingIncarnationID && candidate.Projection.EntryIncarnationID == coordinate.LastEntryIncarnationID && candidate.Projection.TargetRowDigest == coordinate.DeletionTargetRowDigest {
					marker = candidate
					break
				}
			}
		}
		if marker.AttemptID.IsZero() || deleteCount == len(deletionRows) {
			return nil, contract.ErrRecord
		}
		deletionRows[deleteCount] = applyPublicationDeletion{coordinate, marker}
		deleteCount++
	}
	if selectedTargets+deleteCount > contract.MaxPublicationCoordinates || !addApplyPublicationBytes(&dynamic, uint64(deleteCount), contract.MaxPublicationCoordinateRecordBytes+contract.MaxPublicationMarkerRecordBytes) || dynamic > applyPublicationDynamicLimit() {
		return nil, contract.ErrRecordCapacity
	}
	fixed := uint64(unsafe.Sizeof(*h))
	for _, part := range []struct{ count, width uint64 }{
		{uint64(len(s.root.Names)), uint64(unsafe.Sizeof(applyPublicationEntry{}))},
		{uint64(selectedTargets), uint64(unsafe.Sizeof(applyPublicationTarget{}))},
		{uint64(len(destinations)), uint64(unsafe.Sizeof(applyPublicationPolicy{}))},
		{uint64(deleteCount), uint64(unsafe.Sizeof(applyPublicationDeletion{}))},
		{uint64(groupCount), uint64(unsafe.Sizeof([]contract.ID{}))},
	} {
		if !addApplyPublicationBytes(&fixed, part.count, part.width) {
			return nil, contract.ErrRecordCapacity
		}
	}
	if !addApplyPublicationBytes(&fixed, dynamic, 1) {
		return nil, contract.ErrRecordCapacity
	}
	h.backingBytes = fixed
	binding := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: h.acting, Binding: *r.CurrentBinding}
	binding.Binding.KeySelector = strings.Clone(binding.Binding.KeySelector)
	binding.Binding.SPKI = make([]byte, len(r.CurrentBinding.SPKI))
	copy(binding.Binding.SPKI, r.CurrentBinding.SPKI)
	token := s.token
	token.Value = strings.Clone(token.Value)
	h.entries = make([]applyPublicationEntry, len(s.root.Names))
	for i, entry := range borrowed[:len(h.entries)] {
		h.entries[i], err = ownApplyPublicationEntry(entry, binding, token)
		if err != nil {
			return nil, err
		}
	}
	h.targets = make([]applyPublicationTarget, selectedTargets)
	h.policies = make([]applyPublicationPolicy, len(destinations))
	h.groups = make([][]contract.ID, groupCount)
	targetIndex, policyIndex, groupIndex := 0, 0, 0
	var currentPolicy contract.OutputPolicy
	var actualOutput uint64
	visit = contract.OutputConfigurationVisit{
		Binding: func(binding contract.ID, destination string, facts contract.OutputDestination) error {
			currentPolicy = contract.OutputPolicy{}
			if !destinations[destination] {
				return nil
			}
			currentPolicy = facts.Policy
			h.policies[policyIndex] = applyPublicationPolicy{binding, destination, currentPolicy}
			policyIndex++
			if !addApplyPublicationBytes(&actualOutput, uint64(len(destination))+applyPublicationPolicyBytes(currentPolicy), 1) || actualOutput > 4*declaration {
				return contract.ErrRecordCapacity
			}
			return nil
		},
		TargetFields: func(binding contract.ID, destination string, target contract.OutputTarget) error {
			if !wanted(target.EntryIncarnationID, destination) {
				return nil
			}
			coordinate, err := contract.PublicationCoordinateID(h.domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil || targetIndex >= len(h.targets) {
				return contract.ErrRecord
			}
			target.Policy = currentPolicy
			digest, err := contract.PublicationTargetRowDigest(h.domain, destination, binding, target)
			if err != nil {
				return err
			}
			// Destination backing comes from the binding owner, not each target.
			destination = h.policies[policyIndex-1].destination
			h.targets[targetIndex] = applyPublicationTarget{binding, coordinate, digest, destination, target}
			targetIndex++
			if !addApplyPublicationBytes(&actualOutput, applyPublicationTargetBytes(target), 1) || actualOutput > 4*declaration {
				return contract.ErrRecordCapacity
			}
			return nil
		},
		Group: func(members []contract.ID) error {
			h.groups[groupIndex] = members[:len(members):len(members)]
			groupIndex++
			if !addApplyPublicationBytes(&actualOutput, uint64(len(members)), 32) || actualOutput > 4*declaration {
				return contract.ErrRecordCapacity
			}
			return nil
		},
	}
	if state := s.validateSelectedOutputConfigurationRelations(ctx, &visit); state.Outcome != 0 || targetIndex != len(h.targets) || policyIndex != len(h.policies) || groupIndex != len(h.groups) {
		return nil, contract.ErrRecord
	}
	h.backingBytes -= 4*declaration - actualOutput
	h.deletions = make([]applyPublicationDeletion, deleteCount)
	var deletionBytes uint64
	for i, row := range deletionRows[:deleteCount] {
		c, m := row.coordinate, row.marker
		for _, field := range []string{c.ServiceContractID, c.CanonicalTarget, c.DeletionDestinationID, c.DeletionConsumerLocator, c.DeletionTargetContractID, c.DeletionConfigContractID, c.DeletionCredentialRouteContractID,
			m.ExecutorID, m.CredentialRouteID, m.BirthServiceContractID, m.BirthTargetContractID, m.Evidence.SafeRequestID, m.Evidence.SafeResourceID, m.Evidence.ConsumerLocator} {
			if !addApplyPublicationBytes(&deletionBytes, uint64(len(field)), 1) || deletionBytes > uint64(deleteCount)*(contract.MaxPublicationCoordinateRecordBytes+contract.MaxPublicationMarkerRecordBytes) {
				return nil, contract.ErrRecordCapacity
			}
		}
		if !addApplyPublicationBytes(&deletionBytes, uint64(len(c.DeletionTargetData)), 1) || deletionBytes > uint64(deleteCount)*(contract.MaxPublicationCoordinateRecordBytes+contract.MaxPublicationMarkerRecordBytes) {
			return nil, contract.ErrRecordCapacity
		}
		h.deletions[i], err = ownApplyPublicationDeletion(row)
		if err != nil {
			return nil, err
		}
	}
	h.backingBytes -= uint64(deleteCount)*(contract.MaxPublicationCoordinateRecordBytes+contract.MaxPublicationMarkerRecordBytes) - deletionBytes
	slices.SortFunc(h.targets, func(a, b applyPublicationTarget) int { return bytes.Compare(a.coordinate[:], b.coordinate[:]) })
	slices.SortFunc(h.deletions, func(a, b applyPublicationDeletion) int {
		return bytes.Compare(a.coordinate.CoordinateID[:], b.coordinate.CoordinateID[:])
	})
	return h, nil
}

func ownApplyPublicationDeletion(row applyPublicationDeletion) (applyPublicationDeletion, error) {
	coordinate, err := row.coordinate.Clone()
	if err != nil {
		return applyPublicationDeletion{}, err
	}
	if _, err := contract.EncodePublicationMarker(row.marker); err != nil {
		return applyPublicationDeletion{}, err
	}
	row.coordinate = coordinate
	m := &row.marker
	for _, field := range []*string{&m.ExecutorID, &m.CredentialRouteID, &m.BirthServiceContractID, &m.BirthTargetContractID, &m.Evidence.SafeRequestID, &m.Evidence.SafeResourceID, &m.Evidence.ConsumerLocator} {
		*field = strings.Clone(*field)
	}
	return row, nil
}

func (h *applyPublicationHandoff) close() {
	if h == nil || h.closed {
		return
	}
	h.closed = true
	clear(h.entries)
	clear(h.targets)
	clear(h.policies)
	clear(h.deletions)
	clear(h.groups)
	h.entries, h.targets, h.policies, h.deletions, h.groups = nil, nil, nil, nil, nil
}

func (h *applyPublicationHandoff) consumer(slot uint16) (*contract.ConsumerSelection, contract.PublicationValueBasis, bool) {
	if h == nil || h.closed || int(slot) >= len(h.slots) || h.slots[slot] < 0 {
		return nil, contract.PublicationValueBasis{}, false
	}
	entry := &h.entries[h.slots[slot]]
	return &entry.selection, entry.basis, true
}

func (h *applyPublicationHandoff) names() []string {
	var entries [contract.CryptoMaxValueEntries]contract.ID
	wanted := entries[:0]
	for _, pin := range h.targets {
		if !slices.Contains(wanted, pin.target.EntryIncarnationID) {
			wanted = append(wanted, pin.target.EntryIncarnationID)
		}
	}
	for _, group := range h.groups {
		if slices.ContainsFunc(group, func(entry contract.ID) bool { return slices.Contains(wanted, entry) }) {
			for _, entry := range group {
				if !slices.Contains(wanted, entry) {
					wanted = append(wanted, entry)
				}
			}
		}
	}
	names := make([]string, 0, len(wanted))
	for _, entry := range h.entries {
		if slices.Contains(wanted, entry.basis.EntryIncarnationID) {
			names = append(names, entry.selection.Entry.Name)
		}
	}
	return names
}

func (h *applyPublicationHandoff) deletes() []contract.ID {
	ids := make([]contract.ID, len(h.deletions))
	for i := range h.deletions {
		ids[i] = h.deletions[i].coordinate.CoordinateID
	}
	return ids
}

func (h *applyPublicationHandoff) target(destination string, binding contract.ID, target contract.OutputTarget) (*applyPublicationTarget, bool) {
	if h == nil || h.closed {
		return nil, false
	}
	digest, err := contract.PublicationTargetRowDigest(h.domain, destination, binding, target)
	if err != nil {
		return nil, false
	}
	for i := range h.targets {
		p := &h.targets[i]
		if p.binding == binding && p.destination == destination && p.digest == digest {
			return p, true
		}
	}
	return nil, false
}

func applyPublicationGroup(groups [][]contract.ID, entry contract.ID) []contract.ID {
	for _, group := range groups {
		if slices.Contains(group, entry) {
			return group
		}
	}
	return nil
}

func (h *applyPublicationHandoff) checkTarget(s *StateSession, configuration contract.OutputConfiguration, pin applyPublicationTarget) Result {
	var captured *applyPublicationEntry
	for i := range h.entries {
		if h.entries[i].basis.EntryIncarnationID == pin.target.EntryIncarnationID {
			captured = &h.entries[i]
			break
		}
	}
	if captured == nil {
		return refused(InvalidRelation)
	}
	current, valid := s.borrowApplyPublicationEntry(captured.selection.Slot, h.acting)
	if !valid || current.basis != captured.basis || current.selection.Entry.Name != captured.selection.Entry.Name ||
		!slices.Equal(applyPublicationGroup(h.groups, pin.target.EntryIncarnationID), applyPublicationGroup(configuration.Groups, pin.target.EntryIncarnationID)) ||
		!slices.Contains(resolveOutputRoute(configuration, pin.target.EntryIncarnationID), pin.destination) {
		return refused(DifferentSelection)
	}
	for _, binding := range configuration.Bindings {
		if binding.IncarnationID != pin.binding || binding.DestinationID != pin.destination {
			continue
		}
		for _, target := range binding.Targets {
			if target.EntryIncarnationID != pin.target.EntryIncarnationID || target.ServiceContractID != pin.target.ServiceContractID || target.CanonicalTarget != pin.target.CanonicalTarget {
				continue
			}
			digest, err := contract.PublicationTargetRowDigest(h.domain, binding.DestinationID, binding.IncarnationID, target)
			if err == nil && digest == pin.digest {
				return Result{}
			}
			return refused(DifferentSelection)
		}
	}
	return refused(DifferentSelection)
}

func publicationDeletionWitnessMatches(c, pin contract.PublicationCoordinate) bool {
	return c.BindingState == contract.PublicationBindingRetired && c.LastBindingIncarnationID == pin.LastBindingIncarnationID && c.LastEntryIncarnationID == pin.LastEntryIncarnationID &&
		c.OwnerState == pin.OwnerState && c.OwnedBirthAttemptID == pin.OwnedBirthAttemptID && c.OwnedInstanceDigest == pin.OwnedInstanceDigest &&
		c.LastDeleteAckAttemptID == pin.LastDeleteAckAttemptID && c.LastDeleteAckIncarnationID == pin.LastDeleteAckIncarnationID && c.LastDeleteAckOrdinal == pin.LastDeleteAckOrdinal &&
		c.DeletionTargetRowDigest == pin.DeletionTargetRowDigest && c.DeletionDestinationID == pin.DeletionDestinationID && c.DeletionConsumerLocator == pin.DeletionConsumerLocator &&
		c.DeletionTargetContractID == pin.DeletionTargetContractID && c.DeletionConfigContractID == pin.DeletionConfigContractID && c.DeletionCredentialRouteContractID == pin.DeletionCredentialRouteContractID &&
		c.LocatorRequiresCreation == pin.LocatorRequiresCreation && c.DeletionPayloadEncoding == pin.DeletionPayloadEncoding && bytes.Equal(c.DeletionTargetData, pin.DeletionTargetData)
}

func (h *applyPublicationHandoff) checkDeletion(s *StateSession, pin applyPublicationDeletion) Result {
	selected, err := selectedPublicationRelation(s.selectedImage())
	if err != nil {
		return refused(InvalidRelation)
	}
	c, present := selected.coordinates[pin.coordinate.CoordinateID]
	if !present || !publicationDeletionWitnessMatches(c, pin.coordinate) {
		return refused(DifferentSelection)
	}
	marker, present := selected.markers[pin.marker.AttemptID]
	if !present || marker != pin.marker {
		return refused(DifferentSelection)
	}
	if c.OwnerState == contract.PublicationOwnerQualified {
		available, err := publicationBirthAfterDelete(c, marker, selected, s.adminIndex.PublicationOrder)
		if err != nil || !available {
			return refused(DifferentSelection)
		}
	}
	return Result{}
}

func (h *applyPublicationHandoff) checkSelection(s *StateSession, configuration contract.OutputConfiguration) Result {
	if h == nil || h.closed || s == nil || s.root.Domain != h.domain || s.root.CurrentAccess.Core.AuthorityRecipientID != h.acting {
		return refused(AdmissionInvalid)
	}
	for _, pin := range h.targets {
		if state := h.checkTarget(s, configuration, pin); state.Outcome != 0 {
			return state
		}
	}
	for _, pin := range h.deletions {
		if state := h.checkDeletion(s, pin); state.Outcome != 0 {
			return state
		}
	}
	return Result{}
}

func (h *applyPublicationHandoff) checkCurrent(ctx context.Context, s *StateSession, p publicationTargetPlan) (contract.OutputConfiguration, Result) {
	if h == nil || h.closed || ctx == nil || ctx.Err() != nil || s == nil || s.root.Domain != h.domain || s.root.CurrentAccess.Core.AuthorityRecipientID != h.acting {
		return contract.OutputConfiguration{}, refused(AdmissionInvalid)
	}
	if p.selection == nil {
		for _, pin := range h.deletions {
			if pin.coordinate.CoordinateID == p.coordinate {
				return contract.OutputConfiguration{}, h.checkDeletion(s, pin)
			}
		}
		return contract.OutputConfiguration{}, refused(DifferentSelection)
	}
	configuration, state := s.currentOutputConfigurationForApply(ctx)
	if state.Outcome != 0 {
		return contract.OutputConfiguration{}, state
	}
	for _, pin := range h.targets {
		if pin.coordinate == p.coordinate {
			return configuration, h.checkTarget(s, configuration, pin)
		}
	}
	return contract.OutputConfiguration{}, refused(DifferentSelection)
}
