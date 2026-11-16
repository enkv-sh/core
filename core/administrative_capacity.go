package core

import (
	"context"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Two mandatory pages carry at most both full receipt windows and one
// ordered-index fragment: two page envelopes and spans, then 513 summaries.
const endWorkMaximumReceiptIndexBytes = 2*(108+7) + 37*(2*contract.MutationReceiptWindowLimit+1)

// A changed Slice vector re-encodes each retained carrier. A fresh RecordID
// order can separate every old coalesced span, including every owner index on
// each row. This bound is independent of the future fresh identities.
func endWorkSliceSpanExpansion(index format.AdministrativeIndex) uint64 {
	var added uint64
	for _, page := range index.Pages {
		if !page.ReadRequired {
			continue
		}
		for _, span := range page.Spans {
			added += uint64(span.Count-1) * uint64(7+2*len(span.GroupIndexes))
		}
	}
	return added
}

// Before a target is known, old-receipt filtering and intent relocation may
// split any selected span. This bound also covers a retained fragment page
// whose mandatory rows become disposable after its current intent moves.
func endWorkSelectedSpanExpansion(index format.AdministrativeIndex) uint64 {
	var added uint64
	for _, page := range index.Pages {
		for _, span := range page.Spans {
			added += uint64(span.Count-1) * uint64(7+2*len(span.GroupIndexes))
		}
	}
	return added
}

// The current index is already authenticated. Only future row/owner growth and
// possible span splitting are added; historical GC extensions stay in its
// measured logical length.
func selectedContinuationIndexLength(index format.AdministrativeIndex, futureRows, newGroups, supportPages uint64) (uint64, error) {
	length, err := format.AdministrativeIndexEncodedLength(index)
	if err != nil {
		return 0, err
	}
	var currentRows uint64
	for _, page := range index.Pages {
		for _, span := range page.Spans {
			currentRows += uint64(span.Count)
		}
	}
	addedRows := futureRows - min(futureRows, currentRows)
	oldGroups := uint64(len(index.Groups))
	newOwnerRows, err := capacityMultiply(newGroups, currentRows)
	if err != nil {
		return 0, err
	}
	sharedOwners, err := capacityAdd(oldGroups, newGroups)
	if err != nil {
		return 0, err
	}
	sharedOwners, err = capacityMultiply(sharedOwners, addedRows)
	if err != nil {
		return 0, err
	}
	owners, err := capacityAdd(newOwnerRows, sharedOwners)
	if err != nil {
		return 0, err
	}
	owners, err = capacityMultiply(owners, 2)
	if err != nil {
		return 0, err
	}
	groups, err := capacityMultiply(newGroups, 247)
	if err != nil {
		return 0, err
	}
	rows, err := capacityMultiply(addedRows, 37)
	if err != nil {
		return 0, err
	}
	spans, err := capacityMultiply(addedRows, 7)
	if err != nil {
		return 0, err
	}
	oldPages := uint64(len(index.Pages))
	if supportPages < oldPages {
		length -= 108 * (oldPages - supportPages)
	} else {
		pages, err := capacityMultiply(supportPages-oldPages, 108)
		if err != nil {
			return 0, err
		}
		length, err = capacityAdd(length, pages)
		if err != nil {
			return 0, err
		}
	}
	for _, term := range []uint64{endWorkSelectedSpanExpansion(index), groups, rows, spans, owners, 2 * (oldGroups + newGroups)} {
		length, err = capacityAdd(length, term)
		if err != nil {
			return 0, err
		}
	}
	return length, nil
}

// This is the existing absolute first-exit shortcut expressed as a numeric
// sufficient bound. It credits no future disposal. A refusal of this shortcut
// does not replace the mutation owner's target-specific fallback.
func selectedFirstExitCapacity(ctx context.Context, image *selectedImage, rootDigest contract.ID, rootBytes uint64, publication selectedPublicationCapacityBound) (selectedCapacityBound, error) {
	bound := selectedCapacityBound{Scope: firstAdministrativeExit, Status: capacityNotApplicable, BasisDigest: capacityBoundBasis(rootDigest, firstAdministrativeExit), ChildPageLimit: contract.MaxChildPages, RootByteLimit: contract.MaxRootLength, AdministrativePageByteLimit: contract.MaxRequiredSupportPageLength}
	if ctx == nil || image == nil {
		return bound, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return bound, err
	}
	if len(image.adminIndex.Groups) == 0 {
		return bound, nil
	}
	index, err := format.AdministrativeIndexEncodedLength(image.adminIndex)
	if err != nil {
		return bound, err
	}
	var currentIntent bool
	for _, name := range image.root.Names {
		entry := image.valueEntry(name.Slot)
		if entry == nil {
			return bound, contract.ErrRecord
		}
		currentIntent = currentIntent || entry.ValueSource == contract.Generated
	}
	var intentPages, intentBytes, intentIndex uint64
	if currentIntent {
		logical := uint64(contract.GeneratedCurrentEntryLimit) * contract.GeneratorIntentMaxLength
		fragments := capacityCeiling(logical, contract.GeneratedFragmentMaxPayload)
		intentPages = capacityCeiling(fragments, generatedFragmentsPerPage)
		intentBytes = logical + fragments*generatedFragmentCharge + intentPages*contract.RequiredSupportPageHeaderLength
		intentIndex = 115*intentPages + 37*fragments + 2*fragments*uint64(len(image.adminIndex.Groups))
	}
	publicationPages := uint64(max(publication.pageDelta, 0))
	index += endWorkMaximumReceiptIndexBytes + endWorkSelectedSpanExpansion(image.adminIndex) + 108*publicationPages + intentIndex
	shards := capacityCeiling(index, uint64(format.AdministrativeIndexShardPayloadLimit))
	beforeShards := uint64(1 + len(image.root.AdministrativeIndexShards))
	bound.AdministrativeIndexBytes, bound.AdministrativeIndexShards = index, shards
	bound.ChildPages = uint64(image.root.ChildCount) + publicationPages + 2 + intentPages + shards - min(shards, beforeShards)
	oldIndexBytes := uint64(image.root.AdministrativeIndex.Length)
	for _, ref := range image.root.AdministrativeIndexShards {
		oldIndexBytes += uint64(ref.Length)
	}
	indexBytes := index + shards*uint64(contract.MaxRequiredSupportPageLength-format.AdministrativeIndexShardPayloadLimit)
	bound.ChildEncodedBytes = image.root.ChildEncodedBytes - oldIndexBytes + indexBytes + intentBytes + 2*contract.MaxRequiredSupportPageLength + publication.framedBytes + publicationPages*contract.RequiredSupportPageHeaderLength
	bound.RootBytes = rootBytes + uint64(contract.RefLength)*(bound.ChildPages-min(bound.ChildPages, uint64(image.root.ChildCount)))
	bound.Status = capacitySufficient
	if bound.ChildPages > bound.ChildPageLimit || bound.RootBytes > bound.RootByteLimit {
		bound.Status = capacityNotEstablished
	}
	return bound, nil
}

// Reverse dependency closure stays within one coordinate when publication
// edges never cross coordinates or families. Exclusive publication row owners
// also prove that such an exit leaves generated intents and Slice rows intact.
func publicationExitsAreCoordinateLocal(index format.AdministrativeIndex, coordinates map[contract.ID]contract.PublicationCoordinate) bool {
	coordinateOf := func(group format.AdministrativeGroup) contract.ID {
		switch group.OwnerKind {
		case format.AdministrativePublicationCoordinate:
			return group.GroupID
		case format.AdministrativePublicationMarker:
			return group.OwnerID
		default:
			return contract.ID{}
		}
	}
	for _, group := range index.Groups {
		coordinate := coordinateOf(group)
		if !coordinate.IsZero() && coordinates[coordinate].CoordinateID != coordinate {
			return false
		}
		for _, related := range group.RelatedGroupIndexes {
			if int(related) >= len(index.Groups) || coordinateOf(index.Groups[related]) != coordinate {
				return false
			}
		}
	}
	for _, page := range index.Pages {
		logical := 0
		for _, span := range page.Spans {
			for _, owner := range span.GroupIndexes {
				if int(owner) >= len(index.Groups) {
					return false
				}
				group := index.Groups[owner]
				if coordinateOf(group).IsZero() {
					continue
				}
				if page.ReadRequired || span.Count != 1 || len(span.GroupIndexes) != 1 || logical >= len(page.Rows) {
					return false
				}
				row := page.Rows[logical]
				kind := contract.PublicationCoordinateSupportKind
				if group.OwnerKind == format.AdministrativePublicationMarker {
					kind = contract.PublicationMarkerSupportKind
				}
				if row.Kind != kind || row.RecordID != group.GroupID {
					return false
				}
			}
			logical += int(span.Count)
		}
	}
	return true
}

func (s *StateSession) publicationExitNeedsNoIntentCompaction(ctx context.Context) (bool, error) {
	if s == nil {
		return false, contract.ErrRecord
	}
	entries, err := selectedGeneratedEntryMetadata(s)
	if err != nil {
		return false, err
	}
	return s.publicationExitNeedsNoIntentCompactionForEntries(ctx, entries)
}

func (s *StateSession) publicationExitNeedsNoIntentCompactionForEntries(ctx context.Context, entries []contract.GeneratedEntryMetadata) (bool, error) {
	plan, err := s.planAdministrativeCurrentIntentsForEntries(ctx, s.adminIndex, entries)
	if err != nil {
		return false, err
	}
	// A publication exit also corrects historical release ownership. Use the
	// exact closure fallback when that correction can expose compaction.
	_, ownershipChanged, err := s.administrativeDispositionPages()
	if err != nil || ownershipChanged {
		return false, err
	}
	// Only the scalar proof outlives this plan, so its backing cannot overlap
	// a later exact closure.
	return !plan.changed || len(plan.dropBlobs) == 0, nil
}

// Each accepted ordinary state must leave enough room for its first exact
// selected EndWork. The estimate uses a one-row bound for changed Slice pages;
// dropping whole support/access pages is counted only after the target's
// authenticated closure and old-receipt filter are known.
func (s *StateSession) reserveFirstEndWork(ctx context.Context) error {
	return s.reserveFirstEndWorkReceipt(ctx, nil, nil, nil)
}

// The typed receipt plan is private to receipt construction. Only an Apply
// support projection adds separately counted future application pages.
func (s *StateSession) reservePlannedReceiptFirstEndWork(ctx context.Context, source *StateSession, receipt *contract.CompactMutationReceiptPlan, application *receiptApplicationProjection) error {
	if s == nil || source == nil || receipt == nil || source.root.Domain != s.root.Domain || receipt.DomainID != s.root.Domain {
		return contract.ErrRecord
	}
	return s.reserveFirstEndWorkReceipt(ctx, source, receipt, application)
}

func (s *StateSession) reserveFirstEndWorkReceipt(ctx context.Context, source *StateSession, receipt *contract.CompactMutationReceiptPlan, application *receiptApplicationProjection) error {
	if s == nil || !s.adminIndex.Valid() {
		return contract.ErrRecord
	}
	var applicationPages uint32
	if application != nil {
		if source == nil || receipt == nil {
			return contract.ErrRecord
		}
		applicationPages = application.pages
		if applicationPages > contract.MaxChildPages {
			return contract.ErrRecordCapacity
		}
	}
	publication, err := s.reservePublicationRewrite(ctx, s.adminIndex, contract.MaxChildPages-applicationPages)
	if err != nil {
		return err
	}
	return s.reserveFirstEndWorkPublication(ctx, source, receipt, publication, application)
}

func (s *StateSession) reserveFirstEndWorkPublication(ctx context.Context, source *StateSession, receipt *contract.CompactMutationReceiptPlan, publication publicationCapacity, application *receiptApplicationProjection) error {
	var entries []contract.GeneratedEntryMetadata
	var applicationPages uint32
	if application != nil {
		if source == nil || receipt == nil {
			return contract.ErrRecord
		}
		entries, applicationPages = application.entries, application.pages
		if applicationPages > contract.MaxChildPages {
			return contract.ErrRecordCapacity
		}
	} else {
		var err error
		entries, err = selectedGeneratedEntryMetadata(s)
		if err != nil {
			return err
		}
	}
	childrenBefore := int64(s.root.ChildCount) + int64(applicationPages)
	if len(s.adminIndex.Groups) == 0 {
		return nil
	}
	beforeLength, err := format.AdministrativeIndexEncodedLength(s.adminIndex)
	if err != nil {
		return contract.ErrRecord
	}
	beforeShards, err := format.AdministrativeIndexShardCount(beforeLength)
	if err != nil || beforeShards != uint32(1+len(s.root.AdministrativeIndexShards)) {
		return contract.ErrRecord
	}
	// A first exit may make an old current-intent blob exclusive and replace
	// its fragments with one compact mandatory blob. The fast path credits no
	// released page. A two-fragment page is guaranteed by the stored fragment
	// maximum, including the page and record framing.
	intents, err := generatedIntentIDs(entries)
	if err != nil {
		return err
	}
	var maximumIntentPages, maximumIntentIndexBytes uint64
	if len(intents) != 0 {
		fragments := (uint64(contract.GeneratedCurrentEntryLimit)*contract.GeneratorIntentMaxLength +
			contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
		maximumIntentPages = (fragments + 1) / 2
		maximumIntentIndexBytes = 115*maximumIntentPages + 37*fragments +
			2*fragments*uint64(len(s.adminIndex.Groups))
	}
	coordinates, err := s.publicationCoordinatesForDisposition()
	if err != nil {
		return err
	}
	// Every permitted coordinate update preserves its complete physical page.
	if _, err := s.endWorkPublicationCoordinateChanges(s.adminIndex, nil, coordinates); err != nil {
		return err
	}
	coordinateLocal := publicationExitsAreCoordinateLocal(s.adminIndex, coordinates)
	publicationPages := max(publication.pageDelta, 0)
	publicationIndexBytes := uint64(108 * publicationPages)
	// Most states have ample room. This is a page-space shortcut only. Ordinary
	// writers build groups from selected typed owner rows; an EndWork successor
	// retains and recharges those rows. Their semantic relation is validated by
	// the complete reader, not inferred from Index.Valid here.
	// The absolute bound avoids a scan of every group when no support or access
	// page needs to be credited as released.
	publicationExitLength := beforeLength + endWorkMaximumReceiptIndexBytes +
		endWorkSelectedSpanExpansion(s.adminIndex) + publicationIndexBytes
	allShards, err := format.AdministrativeIndexShardCount(publicationExitLength + maximumIntentIndexBytes)
	if err == nil && childrenBefore+publicationPages+2+int64(maximumIntentPages)+int64(allShards)-int64(beforeShards) <= contract.MaxChildPages {
		return nil
	}
	if receipt != nil {
		s, err = source.receiptReservationCopy(ctx, s, *receipt, application)
		if err != nil {
			return fmt.Errorf("bind planned receipt: %w", err)
		}
	}
	// With current Intents, the proof below must qualify unchanged ownership
	// and exclude compaction. Without them no canonical current image is emitted.
	// Removing a pure publication page lowers selected children and removes the
	// same rewrite-drop credit; mixed peer pages remain. The remaining row bound
	// cannot grow, so the combined child/index charge stays bounded.
	publicationShards, publicationErr := format.AdministrativeIndexShardCount(publicationExitLength)
	publicationExitFits := coordinateLocal && publicationErr == nil &&
		childrenBefore+publicationPages+2+int64(publicationShards)-int64(beforeShards) <= contract.MaxChildPages
	if publicationExitFits && len(intents) != 0 {
		publicationExitFits, err = s.publicationExitNeedsNoIntentCompactionForEntries(ctx, entries)
		if err != nil {
			return fmt.Errorf("check publication intent compaction: %w", err)
		}
	}
	for _, group := range s.adminIndex.Groups {
		if !administrativeTargetSelectable(s.root, s.adminIndex, group, coordinates) {
			continue
		}
		if publicationExitFits && (group.OwnerKind == format.AdministrativePublicationCoordinate || group.OwnerKind == format.AdministrativePublicationMarker) {
			continue
		}
		work, ended, err := s.administrativeWorkClosure(group.GroupID)
		if err != nil {
			return fmt.Errorf("derive administrative work closure: %w", err)
		}
		work, err = s.administrativeWorkWithoutOldReceipts(work)
		if err != nil {
			return fmt.Errorf("filter old receipts: %w", err)
		}
		remainingPublication, err := s.reservePublicationRewrite(ctx, work, contract.MaxChildPages-applicationPages)
		if err != nil {
			return fmt.Errorf("reserve retained publication: %w", err)
		}
		intentPlan, err := s.planAdministrativeCurrentIntentsForEntries(ctx, work, entries)
		if err != nil {
			return fmt.Errorf("plan current intents: %w", err)
		}
		compactIntents := intentPlan.changed && len(intentPlan.dropBlobs) != 0
		var addedIntentPages, addedIntentIndexBytes uint64
		if compactIntents {
			owners, err := s.prepareAdministrativeIntentRemoval(&work, intentPlan)
			if err != nil {
				return err
			}
			if intentPlan.emit {
				addedIntentPages = (uint64(intentPlan.fragments) + 1) / 2
				addedIntentIndexBytes = (115+2*uint64(len(owners)))*addedIntentPages + 37*uint64(intentPlan.fragments)
			}
		}
		projected, _, err := s.administrativeGeneratedProjectionForEntries(work, entries)
		if err != nil {
			return fmt.Errorf("project generated closure: %w", err)
		}
		if compactIntents {
			projected.Slices, err = generatedProjectedSliceDescriptor(intentPlan.after)
			if err != nil {
				return err
			}
		}
		if _, err := s.removedAdministrativeSupport(work); err != nil {
			return err
		}
		var keptMaterials map[materialIdentity]bool
		if len(s.root.CurrentAccess.Core.AccessPageRefs) != 0 {
			keptMaterials, err = s.endWorkRequiredMaterials(work)
			if err != nil {
				return fmt.Errorf("derive retained access materials: %w", err)
			}
		}
		var droppedAccess int64
		for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
			if int(ref.Index) >= len(s.access) || s.access[ref.Index] == nil {
				return contract.ErrRecord
			}
			if !slices.ContainsFunc(s.access[ref.Index].Records, func(row contract.AccessRecord) bool {
				return keptMaterials[materialIdentity{row.MaterialKind, row.MaterialID}]
			}) {
				droppedAccess++
			}
		}
		length, err := format.AdministrativeIndexEncodedLength(work)
		if err != nil {
			return contract.ErrRecord
		}
		coordinatePages, coordinateBytes, err := s.endWorkPublicationRewriteAllowance(work, ended)
		if err != nil {
			return fmt.Errorf("reserve publication exit: %w", err)
		}
		remainingPages := max(remainingPublication.pageDelta, 0)
		length += endWorkMaximumReceiptIndexBytes + addedIntentIndexBytes + coordinateBytes + uint64(108*remainingPages)
		if projected.Slices != s.root.Generated.Slices {
			length += endWorkSliceSpanExpansion(work)
		}
		afterShards, err := format.AdministrativeIndexShardCount(length)
		if err != nil {
			return contract.ErrRecordCapacity
		}
		droppedSupport := int64(len(s.adminIndex.Pages) - len(work.Pages))
		children := childrenBefore + remainingPages + 2 + int64(addedIntentPages) + int64(coordinatePages) - droppedSupport - droppedAccess + int64(afterShards) - int64(beforeShards)
		if children < 0 || children > contract.MaxChildPages {
			return contract.ErrRecordCapacity
		}
	}
	return nil
}

// The selected predecessor contributes its exact authenticated row and owner
// counts. The proposed operation contributes a closed row-kind envelope. A
// history or consumer vector replaces its prior carrier rows; its possible
// one-row growth is in the owner allowance below. A fresh delete retains both
// operation-owned support vectors. This is deliberately an upper bound on
// index bytes, since no private result exists at admission.
type generatedAdministrativeRowCounts [int(contract.GeneratedFinalPreparationSupportKind) + 1]uint64

func generatedAdministrativeRowEnvelope(v generatedCapacityShape) (generatedAdministrativeRowCounts, uint64, uint64, error) {
	clean := v
	clean.OldIntentBytes = 0 // Prior immutable blobs are already in the selected index.
	groups, err := generatedCleanCapacity(clean)
	if err != nil {
		return generatedAdministrativeRowCounts{}, 0, 0, err
	}
	creates := contract.GeneratorMaxEnteredCreateAttempts * v.Creates
	noncreate := v.Retirements + v.ControlledRetirements + v.Cleanups + v.ControlledCleanups
	attempts := creates + noncreate
	lineages := v.Creates + noncreate
	graphFragments := (groups[contract.GeneratorCapacityGraph].MaxFramedBytes + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
	// The fixed evidence categories cover each current SupportRecord kind.
	// Graph.MaxCount includes projected vector carriers and graph fragments, so
	// it overcharges kind 14. Owner.MaxCount additionally covers
	// one changed carrier row per selected owner when an existing vector grows.
	rows := generatedAdministrativeRowCounts{
		0,
		groups[contract.GeneratorCapacityMaterial].MaxCount, // OperationMaterial
		1, // GeneratedParent
		groups[contract.GeneratorCapacityIntents].MaxCount + graphFragments + groups[contract.GeneratorCapacityAuxiliary].MaxCount + v.ProjectedCurrentIntentFragments, // GeneratedFragment
		groups[contract.GeneratorCapacityCreateResults].MaxCount + noncreate,                                                                                           // GeneratedResult
		1,                 // GeneratedPhase
		v.RetainedSources, // RetainedCanonical; current generated evidence is kind 13 below.
		groups[contract.GeneratorCapacityReceipts].MaxCount, // MutationReceipt
		lineages, // GeneratedLineage
		attempts, // GeneratedAttempt
		groups[contract.GeneratorCapacityOwners].MaxCount, // GeneratedDuty or GeneratedHazard
		0,                        // Hazard shares the Owner allowance
		attempts,                 // PendingInboxRelease
		v.OldGenerated + creates, // GeneratedCreateEvidence
		groups[contract.GeneratorCapacityGraph].MaxCount + groups[contract.GeneratorCapacityOwners].MaxCount + uint64(v.deleteSupport.Count), // GeneratorVector, copied delete support and one-row owner growth
	}
	var outputOwners uint64
	if v.outputSupport != nil {
		outputOwners = v.outputSupport.coordinates.MaxCount
		rows[contract.PublicationCoordinateSupportKind] = outputOwners
		rows[contract.OutputConfigurationSliceSupportKind] = v.outputSupport.configuration.MaxCount
		rows[contract.GeneratedFragmentSupportKind] -= v.outputSupport.configuration.MaxCount
		rows[contract.GeneratedDutySupportKind] -= outputOwners
		rows[contract.GeneratorVectorSupportKind] -= outputOwners
	}
	// Apply/Rotate with an entered Create can select one encrypted Final
	// preparation. Delete-only work cannot create this active-parent row.
	if v.Creates != 0 {
		rows[contract.GeneratedFinalPreparationSupportKind] = 1
	}
	if len(rows) != int(contract.GeneratedFinalPreparationSupportKind)+1 {
		return generatedAdministrativeRowCounts{}, 0, 0, contract.ErrRecordCapacity
	}
	// One parent plus, conservatively, both a work owner and an inbox-release
	// owner for every entered Attempt. Independent old work stays in Gold.
	// The added carrier allowance is for one changed Duty/Hazard vector row
	// per owner. The index writer assigns that carrier to its exact OwnerID,
	// so it cannot acquire the operation-wide fanout of a slice or Parent row.
	return rows, groups[contract.GeneratorCapacityOwners].MaxCount, 1 + 2*attempts + outputOwners, nil
}

func (s *StateSession) generatedAdministrativeReservedLength(v generatedCapacityShape) (uint64, error) {
	if s == nil {
		return 0, contract.ErrRecord
	}
	oldLength, err := format.AdministrativeIndexEncodedLength(s.adminIndex)
	if err != nil {
		return 0, contract.ErrRecord
	}
	rowCounts, directOwnerRows, newGroups, err := generatedAdministrativeRowEnvelope(v)
	if err != nil {
		return 0, err
	}
	var newRows uint64
	for _, count := range rowCounts {
		newRows += count
	}
	oldGroups := uint64(len(s.adminIndex.Groups))
	var oldRows uint64
	var oldOwnerExpansion uint64
	for _, page := range s.adminIndex.Pages {
		for _, span := range page.Spans {
			oldRows += uint64(span.Count)
			oldOwnerExpansion += 2 * uint64(span.Count-1) * uint64(len(span.GroupIndexes))
		}
	}
	// Exact old length already includes every old group, page, span and owner
	// reference. New rows can each belong to every old/new group. Every old row
	// can gain each new group. A new page and row need 107 and 7 bytes; an owner
	// reference needs 2. Changed ownership may split any coalesced old span,
	// so charge one additional span for every old row. The writer has at most
	// one related index per group, including each newly admitted group.
	sharedRows := newRows - directOwnerRows
	length := oldLength + oldOwnerExpansion + 247*newGroups + 2*(oldGroups+newGroups) + 108*contract.MaxChildPages + 7*(oldRows+newRows) +
		37*newRows +
		2*(newGroups*oldRows+(oldGroups+newGroups)*sharedRows+directOwnerRows)
	canonicalRows := rowCounts[contract.RetainedCanonicalSupportKind]
	if canonicalRows != 0 && !s.adminIndex.HasRetainedMaterialIDs() {
		for _, page := range s.adminIndex.Pages {
			for _, row := range page.Rows {
				if row.Kind == contract.RetainedCanonicalSupportKind {
					canonicalRows++
				}
			}
		}
	}
	length += 32 * canonicalRows
	return length, nil
}

func (s *StateSession) generatedAdministrativeShardReserve(v generatedCapacityShape) (uint32, error) {
	length, err := s.generatedAdministrativeReservedLength(v)
	if err != nil {
		return 0, err
	}
	shards, err := format.AdministrativeIndexShardCount(length)
	if err != nil {
		return 0, contract.ErrRecordCapacity
	}
	return shards, nil
}

func (s *StateSession) generatedAdministrativeFirstExitShardReserve(v generatedCapacityShape) (uint32, error) {
	length, err := s.generatedAdministrativeReservedLength(v)
	if err != nil {
		return 0, err
	}
	shards, err := format.AdministrativeIndexShardCount(length + endWorkMaximumReceiptIndexBytes)
	if err != nil {
		return 0, contract.ErrRecordCapacity
	}
	return shards, nil
}
