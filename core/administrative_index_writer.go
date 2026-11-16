package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type administrativeRowOwnership struct {
	mandatory bool
	groups    []contract.ID
}

func administrativeIndexObject(domain, snapshot contract.ID) contract.ID {
	b := make([]byte, 0, 28+64)
	b = append(b, "ENKV/admin-index/v1\x00"...)
	b = append(b, domain[:]...)
	b = append(b, snapshot[:]...)
	return contract.Hash(b)
}

// This fixed framing is independent of optional support payloads. It lets an
// administrative reader use the selected descriptor without fetching them.
func administrativeDescriptor(label string, items ...[]byte) contract.GeneratorDescriptor {
	body := make([]byte, 4, 4+len(items)*40)
	binary.BigEndian.PutUint32(body, uint32(len(items)))
	for _, item := range items {
		body = binary.BigEndian.AppendUint32(body, uint32(len(item)))
		body = append(body, item...)
	}
	preimage := make([]byte, 0, len(label)+len(body)+25)
	preimage = append(preimage, "ENKV/admin-descriptor/v1/"...)
	preimage = append(preimage, label...)
	preimage = append(preimage, 0)
	preimage = append(preimage, body...)
	return contract.GeneratorDescriptor{Digest: contract.Hash(preimage), Length: uint64(len(body)), Count: uint32(len(items))}
}

// selectedDisposableDigest uses the existing count-first descriptor framing.
// Callers count selected rows first and stream in physical page/span order.
func selectedDisposableDigest(count uint32) hash.Hash {
	digest := sha256.New()
	_, _ = digest.Write([]byte("ENKV/admin-descriptor/v1/selected-disposable\x00"))
	var framed [4]byte
	binary.BigEndian.PutUint32(framed[:], count)
	_, _ = digest.Write(framed[:])
	return digest
}

func writeSelectedDisposableRow(digest hash.Hash, kind uint8, id contract.ID, length uint32) {
	var item [41]byte
	binary.BigEndian.PutUint32(item[:4], 37)
	item[4] = kind
	copy(item[5:37], id[:])
	binary.BigEndian.PutUint32(item[37:], length)
	_, _ = digest.Write(item[:])
}

func selectedDisposableDescriptor(digest hash.Hash, count uint32) contract.GeneratorDescriptor {
	var id contract.ID
	copy(id[:], digest.Sum(nil))
	return contract.GeneratorDescriptor{Digest: id, Length: 4 + 41*uint64(count), Count: count}
}

func administrativeDescriptorPart(v contract.GeneratorDescriptor) []byte {
	b := make([]byte, 0, contract.GeneratorDescriptorLength)
	b = append(b, v.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, v.Length)
	b = binary.BigEndian.AppendUint32(b, v.Count)
	return b
}

type priorAdministrativeRow struct {
	page, span uint16
}

func (s *StateSession) priorAdministrativeOwnership(row priorAdministrativeRow) administrativeRowOwnership {
	span := s.adminIndex.Pages[row.page].Spans[row.span]
	owner := administrativeRowOwnership{mandatory: span.Mandatory, groups: make([]contract.ID, len(span.GroupIndexes))}
	for i, group := range span.GroupIndexes {
		owner.groups[i] = s.adminIndex.Groups[group].GroupID
	}
	return owner
}

func (s *StateSession) priorAdministrativeRows() (map[generatedRecordKey]priorAdministrativeRow, error) {
	rows := make(map[generatedRecordKey]priorAdministrativeRow)
	if len(s.support) > contract.MaxChildPages || len(s.support) != len(s.adminIndex.Pages) || len(s.support) != len(s.root.RequiredSupport) {
		return nil, contract.ErrRecord
	}
	for i, page := range s.support {
		indexed := s.adminIndex.Pages[i]
		if len(indexed.Spans) > 0xffff {
			return nil, contract.ErrRecord
		}
		if indexed.Ref != s.root.RequiredSupport[i] || page.Domain != indexed.Ref.Domain ||
			page.Object != indexed.Ref.Object || page.Index != indexed.Ref.Index {
			return nil, contract.ErrRecord
		}
		var keys []generatedRecordKey
		if len(page.Records) != 0 {
			for logical, row := range page.Records {
				if opaqueSupportKind(row.Kind) && row.Body == nil {
					if i >= len(s.supportFacts) || logical >= len(s.supportFacts[i].rows) ||
						s.supportFacts[i].ref != indexed.Ref || s.supportFacts[i].rows[logical].Kind() != row.Kind ||
						s.supportFacts[i].rows[logical].RecordID() != row.RecordID {
						return nil, contract.ErrRecord
					}
				}
				keys = append(keys, generatedRecordKey{row.Kind, row.RecordID})
			}
		} else if !indexed.ReadRequired {
			for _, row := range indexed.Rows {
				keys = append(keys, generatedRecordKey{row.Kind, row.RecordID})
			}
		}
		if len(keys) == 0 {
			return nil, contract.ErrRecord
		}
		selected := 0
		for position, span := range indexed.Spans {
			for _, group := range span.GroupIndexes {
				if int(group) >= len(s.adminIndex.Groups) {
					return nil, contract.ErrRecord
				}
			}
			if selected+int(span.Count) > len(keys) {
				return nil, contract.ErrRecord
			}
			for j := selected; j < selected+int(span.Count); j++ {
				key := keys[j]
				if _, duplicate := rows[key]; duplicate {
					return nil, contract.ErrRecord
				}
				rows[key] = priorAdministrativeRow{page: uint16(i), span: uint16(position)}
			}
			selected += int(span.Count)
		}
		if selected != len(keys) {
			return nil, contract.ErrRecord
		}
	}
	return rows, nil
}

func administrativeGroupFromRow(row contract.SupportRecord, parent *contract.GeneratedParentPlan) (format.AdministrativeGroup, bool, error) {
	switch row.Kind {
	case contract.GeneratedParentSupportKind:
		var v contract.GeneratedParentRecord
		if parent != nil && row.RecordID == parent.OperationID {
			v = contract.GeneratedParentRecord(*parent)
		} else {
			var err error
			v, err = contract.InspectGeneratedParentRecord(row.Body)
			if err != nil {
				return format.AdministrativeGroup{}, false, err
			}
		}
		return format.AdministrativeGroup{GroupID: v.OperationID, OwnerID: v.OperationID, TargetID: v.OperationID,
			OwnerKind: format.AdministrativeGeneratedParent, Affected: v.IntendedEntryPlans,
			Dependencies: administrativeDescriptor("parent-dependencies", administrativeDescriptorPart(v.Graph), administrativeDescriptorPart(v.SourceUses), administrativeDescriptorPart(v.Registry))}, true, nil
	case contract.GeneratedDutySupportKind:
		v, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return format.AdministrativeGroup{}, false, err
		}
		affected := v.Target
		if v.Schema == contract.GeneratedDutyRecordSchema && v.LifecycleMode == contract.GeneratorLifecycleNone {
			// The typed Duty has no Target field. Its generic administrative group
			// commits the canonical empty set of affected remote targets.
			affected = contract.EmptyGeneratorVector(contract.GeneratorVectorTargets)
		}
		return format.AdministrativeGroup{GroupID: v.DutyID, OwnerID: v.OwnerID, TargetID: v.ResourceID,
			OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: v.Kind, Affected: affected,
			Dependencies:       administrativeDescriptor("duty-dependencies", administrativeDescriptorPart(v.Support), administrativeDescriptorPart(v.Consumers), administrativeDescriptorPart(v.History)),
			EffectEntryCeiling: boolByte(v.Status >= contract.GeneratedEffectTransmitted)}, true, nil
	case contract.GeneratedHazardSupportKind:
		v, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return format.AdministrativeGroup{}, false, err
		}
		return format.AdministrativeGroup{GroupID: v.HazardID, OwnerID: v.OwnerID, TargetID: v.ResourceID,
			OwnerKind: format.AdministrativeGeneratedHazard, Affected: v.Target,
			Dependencies:       administrativeDescriptor("hazard-dependencies", administrativeDescriptorPart(v.Support), administrativeDescriptorPart(v.Consumers), administrativeDescriptorPart(v.History)),
			EffectEntryCeiling: 1}, true, nil
	case contract.PendingInboxReleaseSupportKind:
		v, err := contract.InspectPendingInboxReleaseRecord(row.Body)
		if err != nil {
			return format.AdministrativeGroup{}, false, err
		}
		return format.AdministrativeGroup{GroupID: row.RecordID, OwnerID: v.InboxID, TargetID: v.OriginalResultID,
			OwnerKind:          format.AdministrativeInboxRelease,
			Affected:           administrativeDescriptor("inbox-release-target", v.InboxID[:], v.OriginalResultID[:]),
			Dependencies:       administrativeDescriptor("inbox-release-dependencies", administrativeDescriptorPart(v.CapacityReservation)),
			EffectEntryCeiling: 1}, true, nil
	case contract.PublicationCoordinateSupportKind:
		v, err := contract.InspectPublicationCoordinate(row.Body)
		if err != nil || row.RecordID != v.CoordinateID {
			return format.AdministrativeGroup{}, false, contract.ErrRecord
		}
		return administrativePublicationCoordinateGroup(v), true, nil
	case contract.PublicationMarkerSupportKind:
		v, err := contract.InspectPublicationMarker(row.Body)
		if err != nil || row.RecordID != v.AttemptID {
			return format.AdministrativeGroup{}, false, contract.ErrRecord
		}
		return administrativePublicationMarkerGroup(v), true, nil
	}
	return format.AdministrativeGroup{}, false, nil
}

func administrativePublicationCoordinateGroup(v contract.PublicationCoordinate) format.AdministrativeGroup {
	return format.AdministrativeGroup{GroupID: v.CoordinateID, OwnerID: v.CoordinateID, TargetID: v.CoordinateID,
		OwnerKind:          format.AdministrativePublicationCoordinate,
		Affected:           administrativeDescriptor("publication-coordinate", v.CoordinateID[:], v.LastBindingIncarnationID[:], v.LastEntryIncarnationID[:]),
		Dependencies:       administrativeDescriptor("publication-coordinate-dependencies", v.OwnedBirthAttemptID[:], v.LatestUnresolvedAttemptID[:]),
		EffectEntryCeiling: boolByte(v.OwnerState != contract.PublicationOwnerNone || v.PossibleRemoteObject != 0 || v.LateEffectRisk != 0)}
}

func administrativePublicationMarkerGroup(v contract.PublicationMarker) format.AdministrativeGroup {
	return format.AdministrativeGroup{GroupID: v.AttemptID, OwnerID: v.CoordinateID, TargetID: v.CoordinateID,
		OwnerKind: format.AdministrativePublicationMarker, PublicationIncarnationID: v.PublicationIncarnationID, AdmissionOrdinal: v.AdmissionOrdinal,
		Affected:           administrativeDescriptor("publication-marker", v.CoordinateID[:], v.AttemptID[:], v.ProjectionCommitment[:]),
		Dependencies:       administrativeDescriptor("publication-marker-dependencies", v.BlockerDigest[:]),
		EffectEntryCeiling: boolByte(v.Evidence.Entry == contract.PublicationMayHaveEnteredEntry)}
}

func boolByte(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// buildAdministrativeReservationIndex binds one projected reservation image.
// Old row ownership is carried by authenticated predecessor ordinals. The
// new parent owns newly introduced detail; direct owner records also get an
// independent group, so shared pages never make removal all-or-nothing.
func (s *StateSession) buildAdministrativeIndex(ctx context.Context, root format.Root, pages []format.RequiredSupportPage, parent *contract.GeneratedParentPlan,
	receipt *contract.CompactMutationReceiptPlan, current *StateSession,
	bundles ...contract.GeneratorPlanBundle) (format.AdministrativeIndex, error) {
	return s.buildAdministrativeIndexInput(ctx, root, pages, parent, receipt, current, nil, nil, bundles...)
}

func (s *StateSession) buildAdministrativeIndexInput(ctx context.Context, root format.Root, pages []format.RequiredSupportPage, parent *contract.GeneratedParentPlan,
	receipt *contract.CompactMutationReceiptPlan, current *StateSession, construction *publicationConstruction, gc *gcIndexChange,
	bundles ...contract.GeneratorPlanBundle) (format.AdministrativeIndex, error) {
	entries, err := selectedGeneratedEntryMetadata(current)
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	return s.buildAdministrativeIndexInputForEntries(ctx, root, pages, parent, receipt, current, entries, construction, gc, bundles...)
}

func (s *StateSession) buildAdministrativeIndexInputForEntries(ctx context.Context, root format.Root, pages []format.RequiredSupportPage, parent *contract.GeneratedParentPlan,
	receipt *contract.CompactMutationReceiptPlan, current *StateSession, entries []contract.GeneratedEntryMetadata, construction *publicationConstruction, gc *gcIndexChange,
	bundles ...contract.GeneratorPlanBundle) (format.AdministrativeIndex, error) {
	if len(entries) > contract.GeneratedCurrentEntryLimit {
		return format.AdministrativeIndex{}, contract.ErrRecordCapacity
	}
	if construction != nil && (parent != nil || receipt != nil || len(bundles) != 0 || !construction.consumed) {
		return format.AdministrativeIndex{}, contract.ErrRecord
	}
	if len(root.RequiredSupport) != len(pages) || parent != nil && (root.Domain != parent.DomainID || root.Generated.ActiveOwner != parent.OperationID) {
		return format.AdministrativeIndex{}, contract.ErrRecord
	}
	if err := publicationOwnedPageBounds(pages); err != nil {
		return format.AdministrativeIndex{}, err
	}
	planned, err := s.administrativePagePlan(root, pages, parent, receipt)
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	prior, err := s.priorAdministrativeRows()
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	priorPages := make(map[format.Ref]int, len(s.root.RequiredSupport))
	for i, ref := range s.root.RequiredSupport {
		priorPages[ref] = i
	}
	groupsByID := make(map[contract.ID]format.AdministrativeGroup)
	parentsByID := make(map[contract.ID]contract.ID)
	for _, page := range pages {
		for _, row := range page.Records {
			var group format.AdministrativeGroup
			var present bool
			var err error
			if construction != nil && (row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind) {
				group, present, err = construction.group(row)
			} else {
				if row.Body == nil && publicationSupportKind(row.Kind) {
					fact, factErr := s.publicationRecord(row)
					err = factErr
					if err == nil {
						present = true
						if fact.coordinate != nil {
							group = administrativePublicationCoordinateGroup(*fact.coordinate)
						} else {
							group = administrativePublicationMarkerGroup(*fact.marker)
						}
					}
				} else {
					group, present, err = administrativeGroupFromRow(row, parent)
				}
			}
			if err != nil {
				return format.AdministrativeIndex{}, err
			}
			if row.Kind == contract.GCPlanSupportKind {
				plan, e := contract.DecodeGCPlan(row.Body)
				if e != nil {
					return format.AdministrativeIndex{}, e
				}
				var progress *contract.GCProgress
				if gc != nil && gc.operation == row.RecordID {
					progress = gc.progress
				} else {
					for _, old := range s.adminIndex.Groups {
						if old.OwnerKind == format.AdministrativeGC && old.GroupID == row.RecordID {
							progress = old.GC
							break
						}
					}
				}
				if progress == nil || contract.Hash(row.Body) != progress.PlanDigest {
					return format.AdministrativeIndex{}, contract.ErrRecord
				}
				owned := progress.Own()
				group = format.AdministrativeGroup{GroupID: row.RecordID, OwnerID: row.RecordID, TargetID: row.RecordID, OwnerKind: format.AdministrativeGC, GC: &owned, Affected: contract.GeneratorDescriptor{Digest: progress.TargetsDescriptor.Digest, Length: progress.TargetsDescriptor.Length, Count: progress.TargetsDescriptor.Count}, Dependencies: administrativeDescriptor("gc-dependencies", plan.MarkDigest[:], plan.EnumerationDigest[:]), EffectEntryCeiling: owned.EffectEntryCeiling()}
				present = true
			}
			if present {
				groupsByID[group.GroupID] = group
				switch row.Kind {
				case contract.GeneratedDutySupportKind:
					v, err := contract.InspectGeneratedDutyRecord(row.Body)
					if err != nil {
						return format.AdministrativeIndex{}, err
					}
					parentsByID[group.GroupID] = v.OriginalOperationID
				case contract.GeneratedHazardSupportKind:
					v, err := contract.InspectGeneratedHazardRecord(row.Body)
					if err != nil {
						return format.AdministrativeIndex{}, err
					}
					parentsByID[group.GroupID] = v.OriginalOperationID
				}
			}
		}
	}
	index := format.AdministrativeIndex{Domain: root.Domain, Object: administrativeIndexObject(root.Domain, root.Snapshot), SliceSnapshot: root.Snapshot}
	for _, group := range groupsByID {
		index.Groups = append(index.Groups, group)
	}
	slices.SortFunc(index.Groups, func(a, b format.AdministrativeGroup) int { return bytes.Compare(a.GroupID[:], b.GroupID[:]) })
	if len(index.Groups) > 0xffff {
		return format.AdministrativeIndex{}, contract.ErrRecordCapacity
	}
	groupIndex := make(map[contract.ID]uint16, len(index.Groups))
	for i, group := range index.Groups {
		groupIndex[group.GroupID] = uint16(i)
	}
	var selected *generatedSelection
	for _, page := range planned {
		for _, row := range page.rows {
			if row.row.Body != nil || row.row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			selected, err = s.selectedGeneratedWork(ctx)
			if err != nil {
				return format.AdministrativeIndex{}, err
			}
			break
		}
		if selected != nil {
			break
		}
	}
	consumers, err := selectedAdministrativeConsumersWithValidated(pages, parent, bundles, selected)
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	if err := s.bindAutomaticHistoricalConsumers(root, pages, bundles, prior, &consumers); err != nil {
		return format.AdministrativeIndex{}, err
	}
	locations := make([]contract.GeneratorSliceLocation, 0, len(consumers.slices))
	for _, location := range consumers.slices {
		locations = append(locations, location)
	}
	mandatory := administrativeMandatorySupportForEntries(entries, locations)
	completeCurrent := current != nil && current.root.Snapshot == root.Snapshot &&
		current.root.ValueEntryCount == uint32(len(current.root.Names)) &&
		current.root.ValueEntryCount == root.ValueEntryCount
	if current != nil && !completeCurrent {
		return format.AdministrativeIndex{}, contract.ErrRecord
	}
	publicationCount := 0
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				publicationCount++
			}
		}
	}
	publicationRows := make([]contract.SupportRecord, 0, publicationCount)
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				publicationRows = append(publicationRows, row)
			}
		}
	}
	var publication selectedPublication
	if construction == nil {
		publication, err = s.selectedImage().publicationRowsForDomain(root.Domain, publicationRows)
		if err != nil {
			return format.AdministrativeIndex{}, err
		}
		index.PublicationOrder, err = publicationOrderForRelation(publication, s.adminIndex.PublicationOrder)
		if err != nil {
			return format.AdministrativeIndex{}, err
		}
		publication, err = publicationTypedRelation(root.Domain, publication, index.PublicationOrder)
		mandatory.bindPublicationRelation(publication)
		if err != nil {
			return format.AdministrativeIndex{}, err
		}
	} else {
		if len(publicationRows) != len(construction.rows) {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
		for _, row := range publicationRows {
			if _, err := construction.fact(row); err != nil {
				return format.AdministrativeIndex{}, err
			}
		}
		index.PublicationOrder = clonePublicationOrder(construction.order)
		publication = construction.relation()
		mandatory.bindPublicationRelation(publication)
	}
	for i := range index.Groups {
		group := &index.Groups[i]
		marker, present := publication.markers[group.GroupID]
		if group.OwnerKind != format.AdministrativePublicationMarker {
			continue
		}
		if !present {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
		related := []contract.ID{marker.CoordinateID}
		if !marker.Projection.OwnedBirthAttemptID.IsZero() {
			related = append(related, marker.Projection.OwnedBirthAttemptID)
		}
		if marker.Projection.Action == contract.PublicationDeleteReservedSlot {
			related = append(related, marker.Projection.UncertainCreateAttemptID)
		}
		group.RelatedGroupIndexes = nil
		for _, id := range related {
			position, present := groupIndex[id]
			if !present {
				return format.AdministrativeIndex{}, contract.ErrRecord
			}
			group.RelatedGroupIndexes = append(group.RelatedGroupIndexes, position)
		}
	}
	automaticDuties := make(map[contract.ID]bool)
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == root.Generated.ActiveOwner {
				phase, e := contract.InspectGeneratedPhaseRecord(row.Body)
				if e != nil {
					return format.AdministrativeIndex{}, e
				}
				if !phase.SelectionPhaseID.IsZero() {
					for _, bundle := range bundles {
						if bundle.Header.OperationID == root.Generated.ActiveOwner {
							for _, index := range contract.GeneratedAutomaticRetirementIndices(bundle) {
								automaticDuties[bundle.Lineages[index].Templates[0].DutyID] = true
							}
						}
					}
				}
			}
		}
	}
	// Generic key succession preserves an authenticated dependency without
	// reopening the active graph's optional source detail. It must retain the
	// complete immutable Parent and selected Phase, including cursor/anchor.
	if s.sameAutomaticIndexAnchor(root, pages) {
		priorParent := -1
		for i, group := range s.adminIndex.Groups {
			if group.OwnerKind == format.AdministrativeGeneratedParent && group.GroupID == root.Generated.ActiveOwner {
				priorParent = i
				break
			}
		}
		if priorParent >= 0 {
			for _, group := range s.adminIndex.Groups {
				if group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind == contract.GeneratedDutyRetirement && slices.Contains(group.RelatedGroupIndexes, uint16(priorParent)) {
					automaticDuties[group.OwnerID] = true
				}
			}
		}
	}
	for i := range index.Groups {
		group := &index.Groups[i]
		if group.OwnerKind == format.AdministrativePublicationCoordinate || group.OwnerKind == format.AdministrativePublicationMarker {
			continue
		}
		parentID := parentsByID[group.GroupID]
		if group.OwnerKind == format.AdministrativeGeneratedDuty && automaticDuties[group.OwnerID] {
			parentID = root.Generated.ActiveOwner
		}
		if group.OwnerKind == format.AdministrativeInboxRelease {
			attempt := consumers.attempts[consumers.inbox[group.OwnerID]]
			parentID = attempt.OperationID
		}
		if parentID.IsZero() {
			parentID = group.OwnerID
		}
		if parent, ok := groupIndex[parentID]; ok && int(parent) != i {
			group.RelatedGroupIndexes = []uint16{parent}
		}
	}
	// Unresolved create ancestry needs its original selected consumer.
	// Qualified history, and shared graph/material alone, create no edge.
	// Related edges point from dependent to prerequisite; disposal follows
	// incoming edges, including the active-parent relation above.
	for attemptID, dependents := range consumers.historyDependencies {
		if _, retained := consumers.attempts[attemptID]; !retained {
			continue
		}
		for _, dependentID := range dependents {
			dependent, present := groupIndex[dependentID]
			if !present {
				continue
			}
			for _, ownerID := range consumers.historyOwners[attemptID] {
				owner, present := groupIndex[ownerID]
				if present && owner != dependent {
					group := &index.Groups[dependent]
					group.RelatedGroupIndexes = append(group.RelatedGroupIndexes, owner)
				}
			}
		}
	}
	// An active cleanup parent needs its exact detached Duty/Hazard source.
	// A source belonging to that same active parent is disposed with the
	// whole parent already; adding a reverse edge there would create a cycle.
	if active, present := groupIndex[root.Generated.ActiveOwner]; present {
		for _, attempt := range consumers.attempts {
			if attempt.OperationID != root.Generated.ActiveOwner || consumers.actions[attempt.AttemptID] != contract.GeneratorActionDelete || automaticDuties[attempt.OwnerID] {
				continue
			}
			for source, group := range index.Groups {
				if group.OwnerID != attempt.OwnerID || group.OwnerKind != format.AdministrativeGeneratedDuty && group.OwnerKind != format.AdministrativeGeneratedHazard ||
					parentsByID[group.GroupID] == root.Generated.ActiveOwner {
					continue
				}
				index.Groups[active].RelatedGroupIndexes = append(index.Groups[active].RelatedGroupIndexes, uint16(source))
			}
		}
	}
	for i := range index.Groups {
		slices.Sort(index.Groups[i].RelatedGroupIndexes)
		index.Groups[i].RelatedGroupIndexes = slices.Compact(index.Groups[i].RelatedGroupIndexes)
	}
	var sliceSnapshot contract.ID
	for i, page := range pages {
		if page.Index != root.RequiredSupport[i].Index || page.Object != root.RequiredSupport[i].Object || page.Domain != root.Domain {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
		indexed := format.AdministrativePage{Ref: root.RequiredSupport[i]}
		// An unchanged Ref still names the predecessor's physical page. Its
		// selected view may be sparse after an administrative exit, so compact
		// view positions cannot become physical span ordinals.
		type selectedPhysicalRow struct {
			ordinal uint16
			fact    contract.SupportRecordDigest
		}
		var physicalRows map[generatedRecordKey]selectedPhysicalRow
		if previous, reused := priorPages[indexed.Ref]; reused {
			oldPage, oldRows := s.adminIndex.Pages[previous], s.support[previous].Records
			if oldPage.Ref != indexed.Ref || len(oldRows) == 0 ||
				!oldPage.ReadRequired && len(oldPage.Rows) != len(oldRows) {
				return format.AdministrativeIndex{}, contract.ErrRecord
			}
			physicalRows = make(map[generatedRecordKey]selectedPhysicalRow, len(oldRows))
			selected := 0
			for _, span := range oldPage.Spans {
				for offset := uint32(0); offset < uint32(span.Count); offset++ {
					if selected >= len(oldRows) || uint32(span.First)+offset > uint32(^uint16(0)) {
						return format.AdministrativeIndex{}, contract.ErrRecord
					}
					row := oldRows[selected]
					var fact contract.SupportRecordDigest
					if len(s.supportFacts) == len(s.support) && len(s.supportFacts[previous].rows) == len(oldRows) &&
						len(s.supportFacts[previous].ordinals) == len(oldRows) {
						if s.supportFacts[previous].ref != indexed.Ref ||
							s.supportFacts[previous].ordinals[selected] != uint16(uint32(span.First)+offset) {
							return format.AdministrativeIndex{}, contract.ErrRecord
						}
						fact = s.supportFacts[previous].rows[selected]
					} else {
						var err error
						fact, err = contract.InspectSupportRecordDigest(root.Domain, contract.SupportRecord(row))
						if err != nil {
							return format.AdministrativeIndex{}, err
						}
					}
					if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
						return format.AdministrativeIndex{}, contract.ErrRecord
					}
					if !oldPage.ReadRequired {
						summary := oldPage.Rows[selected]
						if summary.Kind != row.Kind || summary.RecordID != row.RecordID || summary.BodyLength != fact.BodyLength() || row.Body != nil && !summary.MatchesRecord(contract.SupportRecord(row)) {
							return format.AdministrativeIndex{}, contract.ErrRecord
						}
					}
					key := generatedRecordKey{row.Kind, row.RecordID}
					if _, duplicate := physicalRows[key]; duplicate {
						return format.AdministrativeIndex{}, contract.ErrRecord
					}
					physicalRows[key] = selectedPhysicalRow{ordinal: uint16(uint32(span.First) + offset), fact: fact}
					selected++
				}
			}
			if selected != len(oldRows) {
				return format.AdministrativeIndex{}, contract.ErrRecord
			}
		}
		for _, row := range page.Records {
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return format.AdministrativeIndex{}, err
			}
			if carrier.VectorKind == contract.GeneratorVectorSlices {
				if carrier.OwnerKind != contract.GeneratorSnapshotOwner ||
					!sliceSnapshot.IsZero() && sliceSnapshot != carrier.OwnerID {
					return format.AdministrativeIndex{}, contract.ErrRecord
				}
				if carrier.OwnerID != root.Snapshot {
					old, retained := physicalRows[generatedRecordKey{row.Kind, row.RecordID}]
					fact, err := contract.InspectSupportRecordDigest(root.Domain, row)
					if carrier.OwnerID != s.adminIndex.SliceSnapshot || !retained || err != nil || old.fact != fact {
						return format.AdministrativeIndex{}, contract.ErrRecord
					}
				}
				sliceSnapshot, index.SliceSnapshot = carrier.OwnerID, carrier.OwnerID
				indexed.ReadRequired = true
			}
		}
		if indexed.ReadRequired {
			for _, row := range page.Records {
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if row.Kind != contract.GeneratorVectorSupportKind || err != nil || carrier.VectorKind != contract.GeneratorVectorSlices {
					return format.AdministrativeIndex{}, contract.ErrRecord
				}
			}
		}
		mandatoryPage, optionalPage := false, false
		for ordinal, row := range page.Records {
			plannedRow := planned[i].rows[ordinal]
			key := generatedRecordKey{row.Kind, row.RecordID}
			position, retained := prior[key]
			var ownership administrativeRowOwnership
			if retained {
				ownership = s.priorAdministrativeOwnership(position)
			}
			switch row.Kind {
			case contract.GCPlanSupportKind:
				ownership = administrativeRowOwnership{groups: []contract.ID{row.RecordID}}
				retained = true
			case contract.PublicationCoordinateSupportKind, contract.PublicationMarkerSupportKind:
				ownership = administrativeRowOwnership{groups: []contract.ID{row.RecordID}}
				retained = true
			case contract.OutputConfigurationSliceSupportKind:
				ownership = administrativeRowOwnership{mandatory: true}
				retained = true
			case contract.GeneratedFragmentSupportKind:
				if plannedRow.blob.IsZero() {
					return format.AdministrativeIndex{}, contract.ErrRecord
				}
				if groups := consumers.blobs[plannedRow.blob]; len(groups) != 0 {
					ownership = administrativeRowOwnership{groups: slices.Clone(groups)}
					retained = true
				}
			case contract.OperationMaterialSupportKind:
				material, err := contract.InspectOperationMaterialRecord(row.Body)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				ownership = administrativeRowOwnership{groups: consumers.materialOwners(material.Core.OperationMaterialID, material.Core.OperationID)}
				retained = true
			case contract.GeneratedAttemptSupportKind:
				attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				ownership = administrativeRowOwnership{groups: consumers.attemptOwners(attempt.AttemptID, attempt.OperationID)}
				retained = true
			case contract.GeneratedFinalPreparationSupportKind:
				preparation, err := contract.InspectGeneratedFinalPreparationRecord(row.Body)
				if err != nil || preparation.OperationID != row.RecordID {
					return format.AdministrativeIndex{}, contract.ErrRecord
				}
				// The prepared image is current active-parent evidence, not
				// detached attempt history or unowned configuration support.
				ownership = administrativeRowOwnership{groups: []contract.ID{preparation.OperationID}}
				retained = true
			case contract.GeneratedPhaseSupportKind:
				phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				// Phase is the active parent's frontier, not shared history.
				ownership = administrativeRowOwnership{groups: []contract.ID{phase.OperationID}}
				retained = true
			case contract.GeneratedLineageSupportKind:
				lineage, err := contract.InspectGeneratedLineageRecord(row.Body)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				// Lineage frontier rows also require their active parent.
				ownership = administrativeRowOwnership{groups: []contract.ID{lineage.OperationID}}
				retained = true
			case contract.GeneratedResultSupportKind:
				result, err := contract.InspectGeneratedResultRecord(row.Body)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				ownership = administrativeRowOwnership{groups: consumers.attemptOwners(result.Core.AttemptID, result.Core.OperationID)}
				retained = true
			case contract.GeneratedCreateEvidenceSupportKind:
				evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				ownership = administrativeRowOwnership{groups: consumers.attemptOwners(core.AttemptID, core.OperationID)}
				retained = true
			case contract.RetainedCanonicalSupportKind:
				// A current ValueState can outlive the selected work that copied it.
				// Its copy belongs to the exact Duty/Hazard consumers, not to the
				// current value by identity alone.
				ownership = administrativeRowOwnership{groups: slices.Clone(consumers.canonical[row.RecordID])}
				retained = true
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				switch carrier.OwnerKind {
				case contract.GeneratorSnapshotOwner:
					if carrier.VectorKind == contract.GeneratorVectorSlices {
						location, ok := consumers.slices[row.RecordID]
						if !ok {
							return format.AdministrativeIndex{}, contract.ErrRecord
						}
						ownership = administrativeRowOwnership{groups: consumers.sliceOwners(location, completeCurrent)}
						retained = true
					}
				case contract.GeneratedParentSupportKind:
					ownership = administrativeRowOwnership{groups: consumers.operationOwners(carrier.OwnerID)}
					retained = true
				case contract.GeneratedAttemptSupportKind:
					attempt := consumers.attempts[carrier.OwnerID]
					ownership = administrativeRowOwnership{groups: consumers.attemptOwners(carrier.OwnerID, attempt.OperationID)}
					retained = true
				case contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind:
					ownership = administrativeRowOwnership{groups: []contract.ID{carrier.OwnerID}}
					retained = true
				}
			}
			if !retained {
				switch row.Kind {
				case contract.MutationReceiptSupportKind:
					ownership.mandatory = true
				case contract.GeneratedParentSupportKind, contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind, contract.PendingInboxReleaseSupportKind:
					ownership.groups = []contract.ID{row.RecordID}
				default:
					if !root.Generated.ActiveOwner.IsZero() {
						ownership.groups = []contract.ID{root.Generated.ActiveOwner}
					}
				}
			}
			var must bool
			if row.Kind == contract.GeneratedFragmentSupportKind && row.Body == nil {
				must = mandatory.blobs[plannedRow.blob] || !mandatory.known[plannedRow.blob]
			} else {
				must, err = mandatory.row(row)
			}
			if err != nil {
				return format.AdministrativeIndex{}, err
			}
			if completeCurrent {
				// The old mandatory bit describes the predecessor's current values.
				// The complete successor determines current ownership anew.
				ownership.mandatory = must
			} else {
				ownership.mandatory = ownership.mandatory || must
			}
			physical := uint16(ordinal)
			if physicalRows != nil {
				old, present := physicalRows[key]
				if !present || old.fact != plannedRow.fact {
					return format.AdministrativeIndex{}, contract.ErrRecord
				}
				physical = old.ordinal
			}
			span := format.AdministrativeSpan{First: physical, Count: 1, Mandatory: ownership.mandatory}
			for _, id := range ownership.groups {
				group, ok := groupIndex[id]
				if ok {
					span.GroupIndexes = append(span.GroupIndexes, group)
				}
			}
			slices.Sort(span.GroupIndexes)
			span.GroupIndexes = slices.Compact(span.GroupIndexes)
			if len(span.GroupIndexes) == 0 && !span.Mandatory {
				return format.AdministrativeIndex{}, contract.ErrRecord
			}
			if !indexed.ReadRequired {
				summaryRow := row
				if row.Body == nil && publicationSupportKind(row.Kind) {
					fact, factErr := s.publicationRecord(row)
					if factErr != nil {
						return format.AdministrativeIndex{}, factErr
					}
					summaryRow.Body, err = fact.body()
					if err != nil {
						return format.AdministrativeIndex{}, err
					}
				}
				summary, err := format.AdministrativeSummary(summaryRow)
				if err != nil {
					return format.AdministrativeIndex{}, err
				}
				summary.BodyLength = plannedRow.bodyLength
				indexed.Rows = append(indexed.Rows, summary)
			}
			mandatoryPage = mandatoryPage || span.Mandatory
			optionalPage = optionalPage || !span.Mandatory
			if n := len(indexed.Spans); n != 0 {
				last := &indexed.Spans[n-1]
				if last.Mandatory == span.Mandatory && slices.Equal(last.GroupIndexes, span.GroupIndexes) &&
					uint32(last.First)+uint32(last.Count) == uint32(span.First) && last.Count < ^uint16(0) {
					last.Count++
					continue
				}
			}
			indexed.Spans = append(indexed.Spans, span)
		}
		if mandatoryPage && optionalPage {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
		index.Pages = append(index.Pages, indexed)
	}
	ownedCount := make([]uint32, len(index.Groups))
	for _, page := range index.Pages {
		for _, span := range page.Spans {
			for _, group := range span.GroupIndexes {
				ownedCount[group] += uint32(span.Count)
			}
		}
	}
	ownedDigest := make([]hash.Hash, len(index.Groups))
	for i := range index.Groups {
		ownedDigest[i] = selectedDisposableDigest(ownedCount[i])
	}
	lastPage := make([]int, len(index.Groups))
	for i := range lastPage {
		lastPage[i] = -1
	}
	for pagePosition, page := range index.Pages {
		selected := 0
		for _, span := range page.Spans {
			end := selected + int(span.Count)
			if end > len(pages[pagePosition].Records) {
				return format.AdministrativeIndex{}, contract.ErrRecord
			}
			for _, groupIndex := range span.GroupIndexes {
				group := &index.Groups[groupIndex]
				if lastPage[groupIndex] != int(page.Ref.Index) {
					group.ChargedPages++
					lastPage[groupIndex] = int(page.Ref.Index)
				}
				for _, row := range planned[pagePosition].rows[selected:end] {
					writeSelectedDisposableRow(ownedDigest[groupIndex], row.row.Kind, row.row.RecordID, row.bodyLength)
					group.ChargedBytes += uint64(contract.SupportRecordOverhead) + uint64(row.bodyLength)
				}
			}
			selected = end
		}
		if selected != len(pages[pagePosition].Records) {
			return format.AdministrativeIndex{}, contract.ErrRecord
		}
	}
	for i := range index.Groups {
		index.Groups[i].Disposable = selectedDisposableDescriptor(ownedDigest[i], ownedCount[i])
	}
	views := make([]format.RequiredSupportPageView, len(pages))
	for i, page := range pages {
		views[i] = format.RequiredSupportPageView{Domain: page.Domain, Object: page.Object, Index: page.Index,
			Records: make([]contract.SupportRecordView, len(page.Records))}
		for j, row := range page.Records {
			views[i].Records[j] = contract.SupportRecordView(row)
		}
	}
	evidence, err := administrativeSelectedEvidence(index, views, s.publicationFacts)
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	deletes, creates, err := administrativeExposure(index, views, consumers, s.publicationFacts)
	if err != nil {
		return format.AdministrativeIndex{}, err
	}
	for i := range index.Groups {
		index.Groups[i].SelectedEvidenceSummary = evidence[i]
		index.Groups[i].DestructiveEffect = deletes[i]
		index.Groups[i].UncertainCreateProof = creates[i]
	}
	if !index.Valid() {
		return format.AdministrativeIndex{}, contract.ErrRecord
	}
	return index, nil
}

// installAdministrativeIndex is called after ordinary support pages have their
// final identities and before Root or an authority subject is encoded.
func (s *StateSession) installAdministrativeIndex(ctx context.Context, next *StateSession, candidate *Candidate, receiptPlans ...*contract.CompactMutationReceiptPlan) error {
	return s.installAdministrativeIndexWithBundles(ctx, next, candidate, nil, receiptPlans...)
}

// Generated candidates already own the qualified graph. Passing that same
// graph establishes unentered auto dependencies before any delete exists.
func (s *StateSession) installAdministrativeIndexWithBundles(ctx context.Context, next *StateSession, candidate *Candidate, bundles []contract.GeneratorPlanBundle, receiptPlans ...*contract.CompactMutationReceiptPlan) error {
	return s.installAdministrativeIndexWithPublicationPlan(ctx, next, candidate, bundles, nil, receiptPlans...)
}

func (s *StateSession) installAdministrativeIndexWithPublicationPlan(ctx context.Context, next *StateSession, candidate *Candidate, bundles []contract.GeneratorPlanBundle, planned []plannedPublicationEntry, receiptPlans ...*contract.CompactMutationReceiptPlan) error {
	return s.installAdministrativeIndexInput(ctx, next, candidate, bundles, planned, nil, nil, receiptPlans...)
}

func (s *StateSession) installPublicationAdministrativeIndex(ctx context.Context, next *StateSession, candidate *Candidate, construction *publicationConstruction) error {
	if construction == nil || next.root.OutputConfiguration != s.root.OutputConfiguration {
		return contract.ErrRecord
	}
	return s.installAdministrativeIndexInput(ctx, next, candidate, nil, nil, construction, nil)
}

func (s *StateSession) installAdministrativeIndexInput(ctx context.Context, next *StateSession, candidate *Candidate, bundles []contract.GeneratorPlanBundle, planned []plannedPublicationEntry, construction *publicationConstruction, gc *gcIndexChange, receiptPlans ...*contract.CompactMutationReceiptPlan) error {
	return s.installAdministrativeIndexInputForApplication(ctx, next, candidate, bundles, planned, nil, construction, gc, receiptPlans...)
}

func (s *StateSession) installAdministrativeIndexInputForApplication(ctx context.Context, next *StateSession, candidate *Candidate, bundles []contract.GeneratorPlanBundle, planned []plannedPublicationEntry, application *receiptApplicationProjection, construction *publicationConstruction, gc *gcIndexChange, receiptPlans ...*contract.CompactMutationReceiptPlan) error {
	if construction != nil && (len(bundles) != 0 || len(planned) != 0 || len(receiptPlans) != 0 || !construction.consumed) {
		return contract.ErrRecord
	}
	if s == nil || next == nil || candidate == nil || len(next.support) != len(next.root.RequiredSupport) {
		return contract.ErrRecord
	}
	if len(receiptPlans) > 1 {
		return contract.ErrRecord
	}
	var receipt *contract.CompactMutationReceiptPlan
	if len(receiptPlans) == 1 {
		receipt = receiptPlans[0]
	}
	var entries []contract.GeneratedEntryMetadata
	var applicationPages uint32
	if application != nil {
		if receipt == nil || construction != nil || gc != nil {
			return contract.ErrRecord
		}
		entries, applicationPages = application.entries, application.pages
		if applicationPages > ordinaryChildPageLimit {
			return contract.ErrRecordCapacity
		}
	} else {
		var err error
		entries, err = selectedGeneratedEntryMetadata(next)
		if err != nil {
			return err
		}
	}
	if err := publicationSupportBounds(next.support); err != nil {
		return err
	}
	pages := make([]format.RequiredSupportPage, len(next.support))
	for i, view := range next.support {
		pages[i] = format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index,
			Records: make([]contract.SupportRecord, len(view.Records))}
		for j, row := range view.Records {
			pages[i].Records[j] = contract.SupportRecord(row)
		}
	}
	// The selected typed rows and declaration bytes supply the exact owner
	// relation. The authenticated predecessor index supplies retained ownership.
	// Revalidating a generated plan here would make an unrelated receipt or
	// signer succession depend on optional detail that it does not change.
	index, err := s.buildAdministrativeIndexInputForEntries(ctx, next.root, pages, nil, receipt, next, entries, construction, gc, bundles...)
	if err != nil {
		return fmt.Errorf("build successor administrative index: %w", err)
	}
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		return err
	}
	next.adminIndex = index
	next.root.GCPlans, err = format.GCPlansDescriptor(index)
	if err != nil {
		return err
	}
	next.root.AdministrativeIndex = shards[0].Ref
	next.root.AdministrativeIndexShards = nil
	for _, shard := range shards[1:] {
		next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
	}
	for _, shard := range shards {
		candidate.objects = append(candidate.objects, objectImage{ref: shard.Ref, body: shard.Body})
	}
	next.recountChildren()
	if construction != nil {
		// The publication writer binds emitted row facts, proof and exact
		// successor capacity after all new physical pages are installed.
		return nil
	}
	if receipt != nil {
		next.publicationProof = nil
		next.outputConfigurationRoot = contract.ID{}
		if err := s.bindPlannedRetainedSupportFacts(next); err != nil {
			return fmt.Errorf("retain planned predecessor facts: %w", err)
		}
		if err := s.bindPlannedPublicationFacts(next, *receipt); err != nil {
			return fmt.Errorf("bind planned publication facts: %w", err)
		}
		if err := s.validateSuccessorOutputConfiguration(next); err != nil {
			return fmt.Errorf("validate planned output configuration: %w", err)
		}
		if err := s.validatePreservedPublicationPlan(ctx, next, planned); err != nil {
			return fmt.Errorf("validate planned publication relation: %w", err)
		}
		if _, err := next.reservePublicationRewrite(ctx, next.adminIndex, ordinaryChildPageLimit-applicationPages); err != nil {
			return err
		}
		if next.root.ChildCount > ordinaryChildPageLimit-applicationPages {
			return contract.ErrRecordCapacity
		}
		if err := next.reservePlannedReceiptFirstEndWork(ctx, s, receipt, application); err != nil {
			return fmt.Errorf("reserve successor first EndWork: %w", err)
		}
		return nil
	}
	if next.root.OutputConfiguration == s.root.OutputConfiguration {
		if err := s.bindPreservedOutputConfiguration(next); err != nil {
			return fmt.Errorf("preserve successor output configuration: %w", err)
		}
		if err := s.bindPreservedPublication(ctx, next); err != nil {
			return fmt.Errorf("validate successor publication relation: %w", err)
		}
	} else {
		if err := s.bindChangedOutputConfiguration(next); err != nil {
			return fmt.Errorf("bind successor output configuration: %w", err)
		}
		proof, result, err := validateSelectedPublicationConfiguration(ctx, next.selectedImage(), nil)
		if result.Outcome != 0 {
			return selectedReadFailure(result)
		}
		if err != nil {
			return fmt.Errorf("validate changed publication relation: %w", err)
		}
		next.publicationProof = proof
	}
	if err := next.reserveOrdinaryPublicationRewrite(ctx); err != nil {
		return err
	}
	if next.root.ChildCount > ordinaryChildPageLimit {
		return contract.ErrRecordCapacity
	}
	if err := next.reserveFirstEndWork(ctx); err != nil {
		return fmt.Errorf("reserve successor first EndWork: %w", err)
	}
	return nil
}

// Both typed rows come from complete authenticated predecessor support and
// the caller's exact successor projection. No graph or source read occurs.
func (s *StateSession) sameAutomaticIndexAnchor(root format.Root, pages []format.RequiredSupportPage) bool {
	if s == nil || !s.adminIndex.Valid() || root.Generated.ActiveOwner.IsZero() || root.Generated.ActiveOwner != s.root.Generated.ActiveOwner || root.Generated.ActiveGraph != s.root.Generated.ActiveGraph || root.Generated.ActivePhase != s.root.Generated.ActivePhase {
		return false
	}
	var priorParent, priorPhase, nextParent, nextPhase []byte
	for _, row := range s.supportRecords() {
		if row.RecordID != root.Generated.ActiveOwner {
			continue
		}
		switch row.Kind {
		case contract.GeneratedParentSupportKind:
			priorParent = row.Body
		case contract.GeneratedPhaseSupportKind:
			priorPhase = row.Body
		}
	}
	for _, page := range pages {
		for _, row := range page.Records {
			if row.RecordID != root.Generated.ActiveOwner {
				continue
			}
			switch row.Kind {
			case contract.GeneratedParentSupportKind:
				nextParent = row.Body
			case contract.GeneratedPhaseSupportKind:
				nextPhase = row.Body
			}
		}
	}
	if len(priorParent) == 0 || len(priorPhase) == 0 || !bytes.Equal(priorParent, nextParent) || !bytes.Equal(priorPhase, nextPhase) {
		return false
	}
	p, err := contract.InspectGeneratedPhaseRecord(priorPhase)
	return err == nil && !p.SelectionPhaseID.IsZero() && p.DomainID == root.Domain && p.OperationID == root.Generated.ActiveOwner && p.OwnerID == p.OperationID && p.PlanGraphID == root.Generated.ActiveGraph && p.PhaseID == root.Generated.ActivePhase
}
