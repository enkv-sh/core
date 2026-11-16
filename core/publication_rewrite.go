package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A close preserves the admission body exactly except its result fields. In
// particular, a result cannot replace its original projection or ordinal.
func publicationSameReservation(before, after contract.PublicationMarker) bool {
	if after.LateEffectRisk < before.LateEffectRisk {
		return false
	}
	before.State, before.Evidence, before.LateEffectRisk = after.State, after.Evidence, after.LateEffectRisk
	return before == after
}

func (s *StateSession) publicationRewriteRows(rows []contract.SupportRecord, p *publicationRewritePlan) error {
	if err := publicationRowBounds(rows, true); err != nil {
		return err
	}
	_, loaded, err := s.publicationLoadedRowsForDisposition()
	if err != nil {
		return err
	}
	seen := make(map[generatedRecordKey]bool, len(rows))
	markers := make(map[contract.ID]contract.PublicationMarker)
	byCoordinate := make(map[contract.ID][]contract.ID, len(p.work.PublicationOrder))
	changedMarkers := make(map[contract.ID]contract.PublicationMarker)
	changedCoordinates := make(map[contract.ID]bool)
	type coordinatePair struct {
		before, after contract.PublicationCoordinate
	}
	var coordinates []coordinatePair
	for _, row := range rows {
		key := generatedRecordKey{row.Kind, row.RecordID}
		width, present := p.widths[key]
		if !present || seen[key] || uint64(contract.SupportRecordOverhead+len(row.Body)) > width {
			return contract.ErrRecord
		}
		seen[key] = true
		switch row.Kind {
		case contract.PublicationMarkerSupportKind:
			old, found := loaded[key]
			if !found {
				return contract.ErrRecord
			}
			if old.marker == nil {
				return contract.ErrRecord
			}
			before := *old.marker
			after, err := contract.InspectPublicationMarker(row.Body)
			if err != nil || !publicationSameReservation(before, after) {
				return contract.ErrRecord
			}
			markers[after.AttemptID] = after
			byCoordinate[after.CoordinateID] = append(byCoordinate[after.CoordinateID], after.AttemptID)
			if (before.State == contract.PublicationAcknowledged || before.State == contract.PublicationQualifiedNoEffectState) && (old.digest.BodyLength() != uint32(len(row.Body)) || old.digest.BodyDigest() != contract.Hash(row.Body)) {
				return contract.ErrRecord
			}
			if old.digest.BodyLength() != uint32(len(row.Body)) || old.digest.BodyDigest() != contract.Hash(row.Body) {
				changedMarkers[after.AttemptID] = after
				changedCoordinates[after.CoordinateID] = true
			}
		case contract.PublicationCoordinateSupportKind:
			old, present := loaded[key]
			if !present || old.coordinate == nil {
				return contract.ErrRecord
			}
			before := *old.coordinate
			after, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil || after.LateEffectRisk < before.LateEffectRisk {
				return contract.ErrRecord
			}
			coordinates = append(coordinates, coordinatePair{before, after})
			// A result can update ownership, cached result witnesses and risk.
			// It cannot replace the selected binding or frozen deletion target.
			before.OwnerState = after.OwnerState
			before.OwnedBirthAttemptID, before.OwnedInstanceDigest = after.OwnedBirthAttemptID, after.OwnedInstanceDigest
			before.LatestUnresolvedAttemptID = after.LatestUnresolvedAttemptID
			before.LastValueAckAttemptID, before.LastValueDigest = after.LastValueAckAttemptID, after.LastValueDigest
			before.LastPolicyAckAttemptID, before.LastPolicyDigest = after.LastPolicyAckAttemptID, after.LastPolicyDigest
			before.LastDeleteAckAttemptID = after.LastDeleteAckAttemptID
			before.LastValueAckIncarnationID, before.LastValueAckOrdinal = after.LastValueAckIncarnationID, after.LastValueAckOrdinal
			before.LastPolicyAckIncarnationID, before.LastPolicyAckOrdinal = after.LastPolicyAckIncarnationID, after.LastPolicyAckOrdinal
			before.LastDeleteAckIncarnationID, before.LastDeleteAckOrdinal = after.LastDeleteAckIncarnationID, after.LastDeleteAckOrdinal
			before.PossibleRemoteObject, before.LateEffectRisk = after.PossibleRemoteObject, after.LateEffectRisk
			if before.LocatorRequiresCreation {
				before.DeletionConsumerLocator = after.DeletionConsumerLocator
			}
			if !before.Equal(after) {
				return contract.ErrRecord
			}
		default:
			return contract.ErrRecord
		}
	}
	if len(seen) != len(p.widths) {
		return contract.ErrRecord
	}
	for _, pair := range coordinates {
		before, after := pair.before, pair.after
		if !before.Equal(after) && !changedCoordinates[after.CoordinateID] {
			return contract.ErrRecord
		}
		position, found := slices.BinarySearchFunc(p.work.PublicationOrder, after.CoordinateID, func(order format.PublicationCoordinateOrder, id contract.ID) int {
			return bytes.Compare(order.CoordinateID[:], id[:])
		})
		if !found {
			return contract.ErrRecord
		}
		order := p.work.PublicationOrder[position].Incarnations
		if !publicationCoordinateCloseValid(before, after, markers, changedMarkers, byCoordinate[after.CoordinateID], order, s.root.WarningBits) {
			return contract.ErrRecord
		}
		type ack struct {
			attempt, digest, incarnation contract.ID
			ordinal                      uint64
		}
		oldACKs := [3]ack{
			{before.LastValueAckAttemptID, before.LastValueDigest, before.LastValueAckIncarnationID, before.LastValueAckOrdinal},
			{before.LastPolicyAckAttemptID, before.LastPolicyDigest, before.LastPolicyAckIncarnationID, before.LastPolicyAckOrdinal},
			{before.LastDeleteAckAttemptID, contract.ID{}, before.LastDeleteAckIncarnationID, before.LastDeleteAckOrdinal},
		}
		newACKs := [3]ack{
			{after.LastValueAckAttemptID, after.LastValueDigest, after.LastValueAckIncarnationID, after.LastValueAckOrdinal},
			{after.LastPolicyAckAttemptID, after.LastPolicyDigest, after.LastPolicyAckIncarnationID, after.LastPolicyAckOrdinal},
			{after.LastDeleteAckAttemptID, contract.ID{}, after.LastDeleteAckIncarnationID, after.LastDeleteAckOrdinal},
		}

		for i, selected := range newACKs {
			prior := oldACKs[i]
			if selected == prior {
				continue
			}
			marker, present := changedMarkers[selected.attempt]
			if !present || marker.State != contract.PublicationAcknowledged || marker.CoordinateID != after.CoordinateID ||
				marker.PublicationIncarnationID != selected.incarnation || marker.AdmissionOrdinal != selected.ordinal {
				return contract.ErrRecord
			}
			oldPosition, newPosition := slices.Index(order, prior.incarnation), slices.Index(order, selected.incarnation)
			if newPosition < 0 || !prior.attempt.IsZero() && (oldPosition < 0 || newPosition < oldPosition || newPosition == oldPosition && selected.ordinal < prior.ordinal) {
				return contract.ErrRecord
			}
		}
	}
	return nil
}

func publicationCoordinateCloseValid(before, after contract.PublicationCoordinate,
	markers, changed map[contract.ID]contract.PublicationMarker, markerIDs, order []contract.ID, warnings uint8) bool {
	if before.DeletionConsumerLocator != after.DeletionConsumerLocator {
		birth, selected := changed[after.OwnedBirthAttemptID]
		if !before.LocatorRequiresCreation || before.OwnerState == contract.PublicationOwnerQualified && before.OwnedBirthAttemptID == after.OwnedBirthAttemptID ||
			!selected || !publicationQualifiedBirthValid(after.DomainID, after, birth) || birth.Evidence.ConsumerLocator != after.DeletionConsumerLocator {
			return false
		}
	}
	matchingNoEffect, remainingUncertain, otherPossibleCreate, enteredResult, lateResult, retainedLateRisk := false, false, false, false, false, false
	for _, id := range markerIDs {
		marker := markers[id]
		if marker.CoordinateID != before.CoordinateID {
			continue
		}
		create := marker.Projection.Action == contract.PublicationCreateEmpty || marker.Projection.Action == contract.PublicationCreateWithValue
		uncertain := marker.State == contract.PublicationMayHaveEntered || marker.State == contract.PublicationUnknown
		matching := create && marker.Projection.BindingIncarnationID == before.LastBindingIncarnationID &&
			marker.Projection.EntryIncarnationID == before.LastEntryIncarnationID && marker.Projection.TargetRowDigest == before.DeletionTargetRowDigest &&
			marker.BirthServiceContractID == before.ServiceContractID && marker.BirthTargetContractID == before.DeletionTargetContractID
		if matching && uncertain {
			remainingUncertain = true
		}
		if create && (uncertain || marker.State == contract.PublicationAcknowledged) {
			otherPossibleCreate = true
		}
		retainedLateRisk = retainedLateRisk || marker.LateEffectRisk != 0
		if _, selected := changed[marker.AttemptID]; selected {
			matchingNoEffect = matchingNoEffect || matching && marker.State == contract.PublicationQualifiedNoEffectState
			enteredResult = enteredResult || marker.State != contract.PublicationQualifiedNoEffectState && marker.Evidence.Entry == contract.PublicationMayHaveEnteredEntry
			lateResult = lateResult || marker.LateEffectRisk != 0
		}
	}
	if before.OwnerState != after.OwnerState || before.OwnedBirthAttemptID != after.OwnedBirthAttemptID || before.OwnedInstanceDigest != after.OwnedInstanceDigest {
		// Only a changed create ACK can establish a new exact birth. Policy,
		// value and delete results preserve the prior qualified owner tuple.
		switch after.OwnerState {
		case contract.PublicationOwnerQualified:
			birth, selected := changed[after.OwnedBirthAttemptID]
			if !selected || !publicationQualifiedBirthValid(after.DomainID, after, birth) {
				return false
			}
			if before.OwnerState == contract.PublicationOwnerQualified {
				prior, retained := markers[before.OwnedBirthAttemptID]
				if !retained || !publicationQualifiedBirthValid(before.DomainID, before, prior) {
					return false
				}
				oldPosition, newPosition := slices.Index(order, prior.PublicationIncarnationID), slices.Index(order, birth.PublicationIncarnationID)
				if oldPosition < 0 || newPosition < 0 || newPosition < oldPosition || newPosition == oldPosition && birth.AdmissionOrdinal <= prior.AdmissionOrdinal {
					return false
				}
			}
		case contract.PublicationOwnerNone:
			if before.OwnerState != contract.PublicationOwnerUncertainCreate || !matchingNoEffect || remainingUncertain {
				return false
			}
		default:
			return false
		}
	}
	latest := before.LatestUnresolvedAttemptID
	if closed, selected := changed[latest]; selected && (closed.State == contract.PublicationAcknowledged || closed.State == contract.PublicationQualifiedNoEffectState) {
		latest = contract.ID{}
		bestPosition, bestOrdinal := -1, uint64(0)
		for _, id := range markerIDs {
			marker := markers[id]
			if marker.CoordinateID != before.CoordinateID || marker.State != contract.PublicationMayHaveEntered && marker.State != contract.PublicationUnknown {
				continue
			}
			position := slices.Index(order, marker.PublicationIncarnationID)
			if position < 0 {
				return false
			}
			if position > bestPosition || position == bestPosition && marker.AdmissionOrdinal > bestOrdinal {
				latest, bestPosition, bestOrdinal = marker.AttemptID, position, marker.AdmissionOrdinal
			}
		}
	}
	if after.LatestUnresolvedAttemptID != latest {
		return false
	}
	if after.PossibleRemoteObject < before.PossibleRemoteObject {
		if before.OwnerState != contract.PublicationOwnerUncertainCreate || after.OwnerState != contract.PublicationOwnerNone ||
			!matchingNoEffect || otherPossibleCreate || retainedLateRisk || before.LateEffectRisk != 0 || after.LateEffectRisk != 0 ||
			!before.LastValueAckAttemptID.IsZero() || !before.LastPolicyAckAttemptID.IsZero() || !before.LastDeleteAckAttemptID.IsZero() ||
			warnings&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != 0 {
			return false
		}
	} else if after.PossibleRemoteObject > before.PossibleRemoteObject && !enteredResult {
		return false
	}
	if after.LateEffectRisk > before.LateEffectRisk && !lateResult {
		return false
	}
	return true
}

func (s *StateSession) materializePublicationRewriteConstruction(ctx context.Context, next *StateSession,
	candidate *Candidate, input *publicationConstruction, pageIDs []contract.ID) error {
	if err := input.begin(ctx, s, next, candidate); err != nil {
		return err
	}
	p, rows := input.rewrite, input.rows
	if err := publicationRowBounds(rows, true); err != nil {
		return err
	}
	if err := s.publicationRewriteRows(rows, p); err != nil {
		return err
	}
	capacity, err := p.capacity()
	if err != nil {
		return err
	}
	staged := Candidate{session: s}
	successor := *next
	if err := s.writePublicationConstruction(ctx, input, &successor, &staged, pageIDs); err != nil {
		return err
	}
	length, err := format.AdministrativeIndexEncodedLength(successor.adminIndex)
	if err != nil {
		return err
	}
	var physical uint64
	for _, ref := range successor.root.RequiredSupport {
		physical += uint64(ref.Length)
	}
	// No unresolved marker has no growth reserve and keeps the selected layout.
	// A terminal-only state cannot be rewritten to make new action authority.
	if !p.unresolved {
		return contract.ErrRecord
	}
	if length > capacity.indexBytes || physical > capacity.physicalBytes ||
		int64(len(successor.root.RequiredSupport)) > int64(len(s.root.RequiredSupport))+capacity.pageDelta {
		return contract.ErrRecordCapacity
	}
	for _, peer := range p.peers {
		selected := slices.IndexFunc(successor.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == peer.Ref })
		if selected < 0 || !samePublicationPage(peer, successor.adminIndex.Pages[selected]) {
			return contract.ErrRecord
		}
	}
	*next = successor
	candidate.objects = append(candidate.objects, staged.objects...)
	return nil
}

func samePublicationPage(a, b format.AdministrativePage) bool {
	if a.Ref != b.Ref || a.ReadRequired != b.ReadRequired || !slices.Equal(a.Rows, b.Rows) || len(a.Spans) != len(b.Spans) {
		return false
	}
	for i, span := range a.Spans {
		other := b.Spans[i]
		if span.First != other.First || span.Count != other.Count || span.Mandatory != other.Mandatory || !slices.Equal(span.GroupIndexes, other.GroupIndexes) {
			return false
		}
	}
	return true
}

func (s *StateSession) writePublicationConstruction(ctx context.Context, input *publicationConstruction,
	next *StateSession, candidate *Candidate, pageIDs []contract.ID) error {
	if input == nil || !input.consumed {
		return contract.ErrRecord
	}
	p, packed := input.rewrite, input.packed
	if len(pageIDs) != len(packed) {
		return contract.ErrRecord
	}
	used := s.signerOnlyClosureIDs()
	if used == nil || used[next.root.Snapshot] || used[next.root.Transition] {
		return contract.ErrRecord
	}
	used[next.root.Snapshot], used[next.root.Transition] = true, true
	support := make([]format.RequiredSupportPageView, 0, len(p.peers)+len(packed))
	refs := make([]format.Ref, 0, cap(support))
	indexes := make(map[uint16]bool, len(p.peers))
	for _, peer := range p.peers {
		prior := slices.Index(s.root.RequiredSupport, peer.Ref)
		if prior < 0 {
			return contract.ErrRecord
		}
		view := s.support[prior]
		retained := format.RequiredSupportPageView{Domain: view.Domain, Object: view.Object, Index: view.Index}
		logical := 0
		for _, span := range s.adminIndex.Pages[prior].Spans {
			for offset := uint32(0); offset < uint32(span.Count); offset++ {
				if logical >= len(view.Records) {
					return contract.ErrRecord
				}
				if _, present := administrativeSelectedOrdinal(peer, uint16(uint32(span.First)+offset)); present {
					retained.Records = append(retained.Records, view.Records[logical])
				}
				logical++
			}
		}
		refs = append(refs, peer.Ref)
		support = append(support, retained)
		indexes[peer.Ref.Index] = true
	}
	for i, rows := range packed {
		object := pageIDs[i]
		if object.IsZero() || used[object] {
			return contract.ErrRecord
		}
		used[object] = true
		var index uint16
		for indexes[index] {
			index++
			if uint32(index) >= contract.MaxChildPages {
				return contract.ErrRecordCapacity
			}
		}
		indexes[index] = true
		ref, view, body, err := endWorkSupportPage(s.root.Domain, object, index, rows, nil)
		if err != nil {
			return err
		}
		refs = append(refs, ref)
		support = append(support, view)
		input.emitted = append(input.emitted, ref)
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	positions := make([]int, len(refs))
	for i := range positions {
		positions[i] = i
	}
	slices.SortFunc(positions, func(a, b int) int { return int(refs[a].Index) - int(refs[b].Index) })
	next.root.RequiredSupport = nil
	next.support = nil
	next.root.RequiredSupportRecordCount = 0
	for _, i := range positions {
		next.root.RequiredSupport = append(next.root.RequiredSupport, refs[i])
		next.support = append(next.support, support[i])
		next.root.RequiredSupportRecordCount += uint32(len(support[i].Records))
	}
	next.clearSelectedSupportFacts()
	if err := s.installPublicationAdministrativeIndex(ctx, next, candidate, input); err != nil {
		return err
	}
	if err := s.bindPublicationSupportFacts(next, candidate.objects, input); err != nil {
		return err
	}
	if s.fragmentFacts != nil {
		prior := s
		if s.generatedSlicesRoot.IsZero() {
			locations, err := s.resolveSelectedGeneratedSlices()
			if err != nil {
				return err
			}
			validated := *s
			validated.generatedSliceLocations = locations
			var ok bool
			validated.generatedSlicesRoot, ok = s.generatedSelectionRoot()
			if !ok {
				return contract.ErrRecord
			}
			prior = &validated
		}
		if err := prior.bindReceiptSuccessorSlices(next); err != nil {
			return err
		}
	}
	if err := s.bindPreservedOutputConfiguration(next); err != nil {
		return err
	}
	if err := input.bindProof(ctx, s, next, candidate); err != nil {
		return err
	}
	publication, err := next.reservePublicationRewrite(ctx, next.adminIndex, ordinaryChildPageLimit)
	if err != nil {
		return err
	}
	if next.root.ChildCount > ordinaryChildPageLimit {
		return contract.ErrRecordCapacity
	}
	return next.reserveFirstEndWorkPublication(ctx, nil, nil, publication, nil)
}
