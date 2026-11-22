package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

const (
	generatedEntryMetadataCharge     = 1024
	generatedValueEntryPlanCharge    = 1024
	generatedLineageHeaderCharge     = 1024
	generatedAttemptTemplateCharge   = 2048
	generatedEdgeCharge              = 256
	generatedEdgesPerTemplate        = 4
	generatedCarriersPerTemplate     = 4
	generatedParentPlanCharge        = 16 << 10
	generatedResultUseCharge         = 4 + contract.GeneratorResultUseLength
	generatedSourceUseCharge         = 4 + contract.GeneratorSourceUseLength
	generatedFragmentCharge          = contract.SupportRecordOverhead + contract.GeneratedFragmentHeaderLength
	generatedSliceCarrierCharge      = contract.SupportRecordOverhead + contract.GeneratorCarrierFixedLength + contract.GeneratorSliceLocationLength
	generatedFragmentsPerPage        = 2
	generatedSourceContextCharge     = 2 << 10
	generatedBindingCharge           = 2 << 10
	generatedExecutionSupportCharge  = 8 << 10
	generatedReleaseHandoffCharge    = 1 << 10
	generatedReceiptIndexEntryCharge = 128
	generatedControlSectionCount     = 4
	generatedControlSectionCharge    = 8 << 10
	generatedChildReferenceCharge    = 256
	generatedAuxiliaryIndexCharge    = 1 << 20
	generatedRetainedFixedCharge     = uint64(contract.SupportRecordOverhead + 8 + contract.ValueEntryFixedLength - 2 + 2 + contract.CanonicalPayloadOverhead)
	generatedRetainedMaximumCharge   = generatedRetainedFixedCharge + contract.CryptoMaxName + 32*contract.CryptoMaxValueEntryRecipients + contract.CryptoMaxRetainedValue
	generatedCurrentEvidenceCharge   = uint64(contract.SupportRecordOverhead + contract.GeneratedCreateEvidenceMaxLength)
	generatedMaterialFramedCharge    = uint64(contract.SupportRecordOverhead + 236)
	generatedParentFramedCharge      = uint64(contract.SupportRecordOverhead + contract.GeneratedParentRecordBodyLength)
	generatedOwnerGroupCharge        = uint64(2*contract.SupportRecordOverhead + contract.GeneratedDutyRecordBodyLength + contract.GeneratorCarrierFixedLength + contract.GeneratorTargetMaxLength)
)

// Counts describe the greatest current image and the new fixed operation.
// Existing pending work is separate actual backlog, never an unused allowance
// inside this clean-operation bound.
type generatedCapacityShape struct {
	ValueEntryCount, ValueEntryPageCount, Recipients, Secrets, Memberships, SecretMemberships    uint64
	Generated, OldGenerated, Creates, Retirements, ValueEntryPlanCount, Sources, RetainedSources uint64
	ControlledRetirements                                                                        uint64
	Cleanups, ControlledCleanups                                                                 uint64
	DeclarationBytes, RegistryBytes, OldIntentBytes                                              uint64
	DesiredOutputBytes                                                                           uint64
	outputSupport                                                                                *generatedOutputSupportCapacity
	publicRecovery                                                                               bool
	// A fresh delete copies this accepted vector into its new operation namespace.
	deleteSupport                   contract.GeneratorDescriptor
	ProjectedCurrentIntentFragments uint64
	Recovery                        bool
	// Only an identical selected kind-6 row is replaced by a retained
	// declaration. The count alone cannot establish that overlap.
	RetainedRows map[contract.ID][]byte
	// Only production admission sets this owned scalar, after qualifying the
	// declaration and selected current/canonical reader sets. A generic shape
	// without that proof keeps the full registry-product bound.
	finalImageReaders *uint64
	finalImageGrants  uint64
}

type generatedOutputSupportCapacity struct {
	configuration, coordinates contract.GeneratorCapacityGroup
}

func generatedFinalImageCapacity(values, access, historicalReaders, creates, entries, grants uint64) uint64 {
	return values + access + historicalReaders*contract.WrapRowWireLength + grants*contract.GeneratedGrantSealLength +
		creates*(512+contract.CryptoMaxName+generatedEntryMetadataCharge+128) + entries*(contract.CryptoMaxName+64) +
		138 + contract.SupportRecordOverhead + contract.GeneratedFinalPreparationRecordLength + generatedSliceCarrierCharge
}

func (s *StateSession) generatedOutputSupportCapacity(ctx context.Context, output *contract.GeneratedOutputTransition, graph contract.GeneratorPlanBundle) (*generatedOutputSupportCapacity, error) {
	after, _, err := output.Rebind(graph.Header.OperationID, graph.ValueEntryPlans)
	if err != nil {
		return nil, err
	}
	selected := make(map[generatedRecordKey]contract.SupportRecordDigest, len(output.Rows.Facts))
	for _, fact := range output.Rows.Facts {
		selected[generatedRecordKey{kind: fact.Kind(), id: fact.RecordID()}] = fact
	}
	var changed []contract.SupportRecord
	for _, row := range after.Records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fact, err := contract.InspectSupportRecordDigest(s.root.Domain, row)
		if err != nil {
			return nil, err
		}
		if selected[generatedRecordKey{kind: row.Kind, id: row.RecordID}] != fact {
			changed = append(changed, row)
		}
	}
	groups, err := generatedReservationGroups(changed, nil, nil)
	if err != nil {
		return nil, err
	}
	var configuration, coordinates []format.RequiredSupportGroup
	for _, group := range groups {
		switch group.Class {
		case format.OutputConfigurationSupport:
			configuration = append(configuration, group)
		case format.OwnerSupport:
			coordinates = append(coordinates, group)
		default:
			return nil, contract.ErrRecord
		}
	}
	charge := func(groups []format.RequiredSupportGroup) (contract.GeneratorCapacityGroup, error) {
		pages, err := format.PackRequiredSupportRows(s.root.Domain, groups, 0)
		if err != nil {
			return contract.GeneratorCapacityGroup{}, err
		}
		result := contract.GeneratorCapacityGroup{MaxPages: uint32(len(pages))}
		for _, group := range groups {
			for _, row := range group.Records {
				result.MaxCount++
				result.MaxFramedBytes += uint64(contract.SupportRecordOverhead + len(row.Body))
			}
		}
		return result, nil
	}
	out := &generatedOutputSupportCapacity{}
	out.configuration, err = charge(configuration)
	if err != nil {
		return nil, err
	}
	out.coordinates, err = charge(coordinates)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// The clean bound counts enterable attempts separately from graph templates.
// Each managed CREATE template also reserves its own exact cleanup template.
func (v generatedCapacityShape) createCapacity() (attempts, templates uint64) {
	if v.publicRecovery {
		attempts = contract.GeneratorPublicCreateLineageTemplates * v.Creates
		return attempts, 2 * attempts
	}
	return contract.GeneratorMaxEnteredCreateAttempts * v.Creates, 2 * contract.GeneratorCreateLineageTemplates * v.Creates
}

func (v generatedCapacityShape) valid() bool {
	if v.deleteSupport != (contract.GeneratorDescriptor{}) && !contract.GeneratorVectorShapeValid(contract.GeneratorVectorSupport, v.deleteSupport) {
		return false
	}
	// A delete-only retirement can belong to a detached duty after its old
	// generated entry leaves the current set. Admission matches that duty to
	// the selected graph; the count still has the fixed generated limit.
	if v.ValueEntryCount > contract.CryptoMaxValueEntries || v.ValueEntryPageCount > contract.MaxValueEntryPages || v.Recipients == 0 || v.Recipients > contract.CryptoMaxRecipients || v.Secrets > v.ValueEntryCount ||
		v.Memberships > contract.CryptoMaxMemberships || v.Memberships < v.ValueEntryCount || v.Memberships > v.ValueEntryCount*contract.CryptoMaxValueEntryRecipients ||
		v.SecretMemberships < v.Secrets || v.SecretMemberships > v.Memberships || v.SecretMemberships > v.Secrets*contract.CryptoMaxValueEntryRecipients ||
		v.Generated > contract.GeneratedCurrentEntryLimit || v.Generated > v.Secrets || v.OldGenerated > contract.GeneratedCurrentEntryLimit || v.OldGenerated > v.Generated ||
		v.Creates > contract.GeneratorMaxCreateLineages || v.Retirements > contract.GeneratedRetirementLimit || v.ControlledRetirements > v.Retirements || v.ValueEntryPlanCount > contract.CryptoMaxValueEntries || v.Sources > v.ValueEntryPlanCount || v.RetainedSources > v.ValueEntryPlanCount || v.Creates > v.ValueEntryPlanCount ||
		v.Cleanups > 1 || v.ControlledCleanups > v.Cleanups || v.Cleanups != 0 && (v.Creates != 0 || v.Retirements != 0 || v.Sources != 0) ||
		v.DesiredOutputBytes > contract.MaxOutputConfigurationBytes || v.RegistryBytes > contract.GeneratedRecipientRegistryMaxLength || v.DeclarationBytes == 0 || v.DeclarationBytes > contract.GeneratorDeclarationMaxFramedLength || v.OldIntentBytes > contract.GeneratedCurrentEntryLimit*contract.GeneratorIntentMaxLength ||
		v.ProjectedCurrentIntentFragments > contract.GeneratedCurrentEntryLimit*contract.GeneratorIntentMaxLength/contract.GeneratedFragmentMaxPayload+1 {
		return false
	}
	return v.Sources+v.RetainedSources+v.Creates <= v.ValueEntryPlanCount && v.OldIntentBytes <= v.OldGenerated*contract.GeneratorIntentMaxLength &&
		v.ValueEntryPageCount <= v.ValueEntryCount && v.ValueEntryCount <= v.ValueEntryPageCount*format.PageSlots
}

func generatedCleanCapacity(v generatedCapacityShape) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, error) {
	var groups [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	// Logical old intent lengths do not bound retained physical blobs: one
	// current 384 KiB slice can still require its complete 32 MiB declaration
	// blob. Production admission charges selected fragment rows in the backlog
	// path, which clears OldIntentBytes before calling this clean helper.
	if !v.valid() || v.OldIntentBytes != 0 {
		return groups, contract.ErrRecordCapacity
	}
	// Every input has passed its public bound before multiplication or addition.
	// Even 512 values with 256 ordinary wraps each add only 64,094,208
	// bytes; the bounded row, raw and fragment terms cannot approach u64 overflow.
	const (
		supportPayload = uint64(contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
		accessPayload  = uint64(contract.MaxAccessPageLength - contract.AccessPageHeaderLength)
	)
	ceil := func(n, d uint64) uint64 { return n/d + uint64(boolInt(n%d != 0)) }
	rows := func(group int, count, width, payload uint64) {
		if count == 0 {
			return
		}
		groups[group] = contract.GeneratorCapacityGroup{MaxCount: count, MaxFramedBytes: count * width, MaxPages: uint32(ceil(count, payload/width))}
	}
	support := func(group int, count uint64, class format.SupportStorageGroup) {
		rows(group, count, uint64(format.RequiredSupportGroupLimit(class)), supportPayload)
	}
	fragments := func(n uint64) uint64 { return ceil(n, contract.GeneratedFragmentMaxPayload) }
	fragmentGroup := func(group int, bytes, count uint64) {
		if count != 0 {
			groups[group] = contract.GeneratorCapacityGroup{MaxCount: count, MaxFramedBytes: bytes + generatedFragmentCharge*count, MaxPages: uint32(ceil(count, generatedFragmentsPerPage))}
		}
	}
	recovery := uint64(boolInt(v.Recovery))
	if v.ValueEntryCount != 0 {
		groups[contract.GeneratorCapacityCurrentValueEntries] = contract.GeneratorCapacityGroup{MaxCount: v.ValueEntryCount, MaxPages: uint32(v.ValueEntryPageCount),
			MaxFramedBytes: (contract.ValueEntryFixedLength+contract.CryptoMaxName)*v.ValueEntryCount + uint64(len(contract.ID{}))*v.Memberships + contract.CanonicalPayloadOverhead*v.Secrets + min(contract.CryptoMaxRetainedSet, v.ValueEntryCount*contract.CryptoMaxRetainedValue) + generatedEntryMetadataCharge*v.Generated}
	}
	groups[contract.GeneratorCapacityCurrentRecipients] = contract.GeneratorCapacityGroup{MaxCount: v.Recipients, MaxFramedBytes: contract.RecipientRecordMaxLength * v.Recipients,
		MaxPages: uint32(ceil(v.Recipients, format.RecipientSlots))}
	if v.Secrets != 0 {
		bytes := contract.AccessRecordFixedLength*v.Secrets + contract.WrapRowWireLength*(v.SecretMemberships+recovery*v.Secrets)
		maxRow := uint64(contract.AccessRecordFixedLength + contract.WrapRowWireLength*(contract.CryptoMaxValueEntryRecipients+recovery))
		// Every nonfinal greedy page contains at least this many bytes.
		nonfinal := accessPayload - maxRow + 1
		groups[contract.GeneratorCapacityCurrentAccess] = contract.GeneratorCapacityGroup{MaxCount: v.Secrets, MaxFramedBytes: bytes,
			MaxPages: uint32(1 + (bytes-1)/nonfinal)}
	}
	creates, createTemplates := v.createCapacity()
	deletes := v.Retirements + creates + v.ControlledRetirements + v.Cleanups + v.ControlledCleanups
	materials := creates + deletes
	fullAccess := uint64(contract.AccessRecordFixedLength + contract.WrapRowWireLength*(v.Recipients+recovery))
	// Only retained declarations create selected old-value rows. Sealed
	// SourceUses create graph and carrier work, but no retained canonical row.
	// Current generated provenance is a separate population.
	// A new retained declaration is byte-identical to a selected old supplied
	// ValueEntry. Its aggregate raw bytes and recipient slots obey the old
	// root's 8 MiB and 4,096 membership limits. Historical selected kind-6
	// generated entries are charged at their actual bytes in the backlog path.
	// Current generated evidence is a different kind with its own fixed core
	// plus at most 4,096 safe-fact bytes. The packer separates mandatory evidence
	// from optional retained declarations.
	retainedBytes := (generatedRetainedFixedCharge+contract.CryptoMaxName)*v.RetainedSources +
		32*min(contract.CryptoMaxMemberships, v.RetainedSources*contract.CryptoMaxValueEntryRecipients) +
		min(contract.CryptoMaxRetainedSet, v.RetainedSources*contract.CryptoMaxRetainedValue)
	evidenceBytes := generatedCurrentEvidenceCharge * v.OldGenerated
	oldValuePages := uint64(0)
	if retainedBytes != 0 {
		oldValuePages += 1 + (retainedBytes-1)/(supportPayload-generatedRetainedMaximumCharge+1)
	}
	if evidenceBytes != 0 {
		oldValuePages += 1 + (evidenceBytes-1)/(supportPayload-generatedCurrentEvidenceCharge+1)
	}
	if oldValuePages != 0 {
		groups[contract.GeneratorCapacityOldValues] = contract.GeneratorCapacityGroup{MaxCount: v.OldGenerated + v.RetainedSources,
			MaxFramedBytes: retainedBytes + evidenceBytes, MaxPages: uint32(oldValuePages)}
	}
	if v.OldGenerated != 0 {
		// Current and source5 producers admit retained canonical declarations
		// only for Supplied values. Old Generated materials therefore have no
		// accumulated canonical reader lists. This existing conservative charge
		// exceeds their current membership bound, including Recovery.
		currentWraps := min(v.SecretMemberships, v.OldGenerated*contract.CryptoMaxValueEntryRecipients)
		wraps := currentWraps + v.OldGenerated*(contract.CryptoMaxValueEntryRecipients+recovery)
		bytes := contract.AccessRecordFixedLength*v.OldGenerated + contract.WrapRowWireLength*wraps
		maxRow := uint64(contract.AccessRecordFixedLength + contract.WrapRowWireLength*(2*contract.CryptoMaxValueEntryRecipients+recovery))
		groups[contract.GeneratorCapacityOldAccess] = contract.GeneratorCapacityGroup{MaxCount: v.OldGenerated,
			MaxFramedBytes: bytes, MaxPages: uint32(1 + (bytes-1)/(accessPayload-maxRow+1))}
	}
	// No current writer emits CandidateValueSupport. The fixed evidence slot
	// remains zero; retained declaration sources are charged above as old values.
	rows(contract.GeneratorCapacityCandidateAccess, creates, fullAccess, accessPayload)
	support(contract.GeneratorCapacityCreateResults, creates, format.ResultSupport)
	rows(contract.GeneratorCapacitySeedAccess, materials, contract.AccessRecordFixedLength+contract.WrapRowWireLength*(1+recovery), accessPayload)
	// Each admitted operation owns one 236-byte OperationMaterial body and one
	// 592-byte Parent body. The attempt envelope `materials` is an upper bound
	// for operation materials; charge the Parent separately. Both rows are
	// optional and share MaterialSupport without a class boundary.
	if materials != 0 {
		materialBytes := generatedMaterialFramedCharge*materials + generatedParentFramedCharge
		groups[contract.GeneratorCapacityMaterial] = contract.GeneratorCapacityGroup{MaxCount: materials,
			MaxFramedBytes: materialBytes, MaxPages: uint32(1 + (materialBytes-1)/(supportPayload-generatedMaterialFramedCharge-generatedParentFramedCharge+1))}
	}
	support(contract.GeneratorCapacityCreates, creates, format.CreateContinuationSupport)
	support(contract.GeneratorCapacityDeletes, deletes, format.DeleteContinuationSupport)
	// An admitted Duty or Hazard owns its fixed record and at most one Target
	// carrier. The complete selected reader rejects a second Target. All owner
	// rows are disposable work, so no mandatory/optional class split is needed.
	rows(contract.GeneratorCapacityOwners, 2*deletes, generatedOwnerGroupCharge, supportPayload)
	support(contract.GeneratorCapacityReceipts, 2*contract.MutationReceiptWindowLimit, format.ReceiptSupport)
	newDeclarationFragments := fragments(v.DeclarationBytes)
	fragmentGroup(contract.GeneratorCapacityIntents, v.DeclarationBytes, newDeclarationFragments)
	templates := createTemplates + v.Retirements + v.ControlledRetirements + v.Cleanups + v.ControlledCleanups
	// Source rows produce two additional carrier streams in the initial
	// selected image. A retained source has Duty and Parent consumers; a
	// sealed source has a Parent consumer and a second declaration slice.
	// The sum is two per source for either kind. The entry count pays for
	// the first declaration slice for every planned value. A source-bearing
	// plan also has one configuration slice; this is needed even when its
	// only template is a delete that uses all four template carrier slots.
	sourceCount := v.Sources + v.RetainedSources
	carriers := uint64(boolInt(v.RegistryBytes != 0)) + uint64(boolInt(v.DesiredOutputBytes != 0)) + generatedCarriersPerTemplate*templates + v.ValueEntryPlanCount + 2*sourceCount + uint64(boolInt(sourceCount != 0))
	graph := v.ValueEntryPlanCount*generatedValueEntryPlanCharge + v.Creates*generatedLineageHeaderCharge + templates*(generatedAttemptTemplateCharge+generatedEdgesPerTemplate*generatedEdgeCharge+generatedResultUseCharge) + generatedParentPlanCharge + v.Sources*generatedSourceUseCharge
	graphFragments := fragments(graph)
	groups[contract.GeneratorCapacityGraph] = contract.GeneratorCapacityGroup{MaxCount: carriers + graphFragments,
		MaxFramedBytes: graph + generatedFragmentCharge*graphFragments + generatedSliceCarrierCharge*carriers, MaxPages: uint32(ceil(graphFragments, generatedFragmentsPerPage) + ceil(generatedSliceCarrierCharge*carriers, supportPayload))}
	auxiliary := sourceCount*generatedSourceContextCharge + (2*v.Recipients+2*recovery)*generatedBindingCharge + (v.OldGenerated+v.Creates)*generatedExecutionSupportCharge + materials*generatedReleaseHandoffCharge +
		2*contract.MutationReceiptWindowLimit*generatedReceiptIndexEntryCharge + generatedControlSectionCount*generatedControlSectionCharge + contract.MaxChildPages*generatedChildReferenceCharge + generatedAuxiliaryIndexCharge
	if v.Creates != 0 {
		// The Final preparation retains the complete encrypted output image
		// while all current values and entered obligations remain selected.
		// A no-removal prepared secret can preserve historical same-material
		// readers; exclusion prepares fresh current material. Keep the existing
		// conservative image allowance for supported historical unions;
		// live old-access pages remain a separate obligation above.
		// Fresh generated outputs cannot also be unchanged image rows.
		retainedImageReaders := (v.ValueEntryPlanCount - min(v.ValueEntryPlanCount, v.Creates)) * v.Recipients
		grantRows := min(v.SecretMemberships, uint64(contract.MaxSelectedGrantRows))
		if v.finalImageReaders != nil {
			if v.finalImageGrants > grantRows {
				return groups, contract.ErrRecordCapacity
			}
			grantRows = v.finalImageGrants
			if *v.finalImageReaders > retainedImageReaders {
				return groups, contract.ErrRecordCapacity
			}
			retainedImageReaders = *v.finalImageReaders
		}
		auxiliary += generatedFinalImageCapacity(groups[contract.GeneratorCapacityCurrentValueEntries].MaxFramedBytes,
			groups[contract.GeneratorCapacityCurrentAccess].MaxFramedBytes, retainedImageReaders, v.Creates, v.ValueEntryPlanCount, grantRows)
	}
	fragmentGroup(contract.GeneratorCapacityAuxiliary, auxiliary, fragments(auxiliary))
	for _, size := range []uint64{v.RegistryBytes, v.DesiredOutputBytes} {
		if size == 0 {
			continue
		}
		n := fragments(size)
		group := &groups[contract.GeneratorCapacityAuxiliary]
		group.MaxCount += n
		group.MaxFramedBytes += size + generatedFragmentCharge*n
		group.MaxPages += uint32(ceil(n, generatedFragmentsPerPage))
	}
	if v.outputSupport != nil {
		for _, charge := range []struct {
			tag   int
			value contract.GeneratorCapacityGroup
		}{{contract.GeneratorCapacityAuxiliary, v.outputSupport.configuration}, {contract.GeneratorCapacityOwners, v.outputSupport.coordinates}} {
			group := &groups[charge.tag]
			group.MaxCount += charge.value.MaxCount
			group.MaxFramedBytes += charge.value.MaxFramedBytes
			group.MaxPages += charge.value.MaxPages
		}
	}
	return groups, nil
}

// Nonempty whole groups pack greedily within one class and partition. Every
// nonfinal page either holds at least payload-maxWidth+1 bytes, or, counting
// groups instead, holds at least floor(payload/maxWidth) groups.
func supportGroupPages(count, framed, maxWidth uint64) uint64 {
	const payload = uint64(contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
	return min(capacityCeiling(framed, payload-maxWidth+1), capacityCeiling(count, payload/maxWidth))
}

func generatedCapacityWithBacklog(v generatedCapacityShape, selected *generatedSelection) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, error) {
	return generatedCapacityWithProjectedBacklog(v, selected, nil)
}

func generatedCapacityWithProjectedBacklog(v generatedCapacityShape, selected *generatedSelection,
	projection *generatedCurrentIntentProjection) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, error) {
	var empty [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	if selected == nil || selected.session == nil || selected.parent != nil {
		return empty, contract.ErrRecord
	}
	if projection != nil && projection.predecessor != contract.Hash(selected.session.body) {
		return empty, contract.ErrRecord
	}
	if !v.valid() {
		return empty, contract.ErrRecordCapacity
	}
	if v.RetainedSources != uint64(len(v.RetainedRows)) {
		return empty, contract.ErrRecordCapacity
	}
	// Preserve whole authenticated blobs, not just their live logical slices.
	// Their actual fragments below replace the clean old-intent estimate.
	v.OldIntentBytes = 0
	groups, err := generatedCleanCapacity(v)
	if err != nil {
		return empty, err
	}
	fragmentFacts, err := selected.session.selectedFragmentFactsByRecord()
	if err != nil {
		return empty, err
	}
	const (
		supportPayload = uint64(contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
		accessPayload  = uint64(contract.MaxAccessPageLength - contract.AccessPageHeaderLength)
	)
	ceil := func(n, d uint64) uint64 { return n/d + uint64(boolInt(n%d != 0)) }
	addRows := func(tag int, count, width, payload uint64) error {
		group := &groups[tag]
		// Selected records are bounded by the closure. Check again before any
		// multiplication so this arithmetic also refuses an excess reservation.
		if width == 0 || width > payload || group.MaxCount > contract.MaxChildPages*(payload/width) ||
			count > contract.MaxChildPages*(payload/width)-group.MaxCount {
			return contract.ErrRecordCapacity
		}
		group.MaxCount += count
		group.MaxFramedBytes += count * width
		group.MaxPages = max(group.MaxPages, uint32(ceil(group.MaxCount, payload/width)), uint32(ceil(group.MaxFramedBytes, payload)))
		return nil
	}
	currentValues, currentResults := make(map[contract.ID]bool), make(map[contract.ID]bool)
	for _, name := range selected.session.root.Names {
		entry := selected.session.valueEntry(name.Slot)
		if entry.ValueSource == contract.Generated {
			currentValues[entry.ValueState], currentResults[entry.Generated.CreateResultID] = true, true
		}
	}
	rows := make([]contract.SupportRecord, 0, len(selected.records))
	for key, row := range selected.records {
		if projection != nil && key.kind == contract.GeneratedFragmentSupportKind {
			var blob contract.ID
			if row.Body == nil {
				fact, ok := fragmentFacts[row.RecordID]
				if !ok || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID {
					return empty, contract.ErrRecord
				}
				blob = fact.blob
			} else {
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					return empty, err
				}
				blob = fragment.BlobID
			}
			if projection.dropBlobs[blob] {
				continue
			}
		}
		if key.kind == contract.RetainedCanonicalSupportKind {
			if newRow, exists := v.RetainedRows[key.id]; exists {
				if !bytes.Equal(row.Body, newRow) {
					return empty, contract.ErrRecord // The writer must reject this key collision.
				}
				continue // The writer keeps this one exact old/new row.
			}
		}
		if key.kind == contract.GeneratedCreateEvidenceSupportKind && currentResults[key.id] {
			continue // Current generated evidence is in the clean charge.
		}
		rows = append(rows, row)
	}
	locations := make([]contract.GeneratorSliceLocation, 0, len(selected.content.locations))
	for _, location := range selected.content.locations {
		locations = append(locations, location)
	}
	if projection != nil {
		locations = projection.after
	}
	backlog, err := generatedReservationGroupsForState(selected.session, rows, locations, selected.bundles)
	if err != nil {
		return empty, err
	}
	// A storage class can occupy one extra page when mandatory current
	// provenance and disposable work each use only part of a page. The
	// packer must flush at that boundary so an exit can read mandatory rows
	// without reading a damaged disposable row on the same physical page.
	var partition [format.OutputConfigurationSupport + 1]uint8
	for _, group := range backlog {
		if group.Mandatory {
			partition[group.Class] |= 1
		} else {
			partition[group.Class] |= 2
		}
	}
	if v.OldGenerated != 0 {
		partition[format.OldValueSupport] |= 1 // Current generated values are in the clean charge.
	}
	partition[format.IntentFragmentSupport] |= 2 // The new declaration is in the clean charge.
	var fragmentCounts, fragmentBytes [contract.GeneratorCapacityGroupCount]uint64
	var indexCounts, indexBytes, indexWidths [contract.GeneratorCapacityGroupCount]uint64
	if v.deleteSupport.Count != 0 {
		count := uint64(v.deleteSupport.Count)
		indexCounts[contract.GeneratorCapacityAuxiliary] = count
		// The vector descriptor includes a count and one blob length per row;
		// each emitted row instead has its carrier and support-record framing.
		indexBytes[contract.GeneratorCapacityAuxiliary] = v.deleteSupport.Length - 4 +
			count*(contract.SupportRecordOverhead+contract.GeneratorCarrierFixedLength-4)
		indexWidths[contract.GeneratorCapacityAuxiliary] = contract.SupportRecordOverhead + contract.GeneratorCarrierFixedLength + contract.GeneratorSupportBindingMaxLength
	}
	// Preserve the clean correlated charge when older selected groups join it.
	// A generic per-row limit would reset 6 old-value pages to 19, or one
	// owner/material page to 11/3, after even one historical row. Each selected
	// group has its actual framed size, and mandatory classes pack separately.
	type exactBacklog struct{ count, bytes, maxWidth uint64 }
	var exact [contract.GeneratorCapacityGroupCount][2]exactBacklog
	results := make(map[contract.ID]bool)
	for _, group := range backlog {
		tag := 0
		switch group.Class {
		case format.OldValueSupport:
			tag = contract.GeneratorCapacityOldValues
		case format.CandidateValueSupport:
			tag = contract.GeneratorCapacityCandidateValues
		case format.ResultSupport:
			tag = contract.GeneratorCapacityCreateResults
			results[group.Owner] = true
		case format.MaterialSupport:
			tag = contract.GeneratorCapacityMaterial
		case format.CreateContinuationSupport:
			tag = contract.GeneratorCapacityCreates
		case format.DeleteContinuationSupport:
			tag = contract.GeneratorCapacityDeletes
		case format.OwnerSupport:
			tag = contract.GeneratorCapacityOwners
		case format.ReceiptSupport:
			continue // Both complete receipt windows are in the clean charge.
		case format.GCPlanSupport:
			// Complete GC rows have their own whole-row storage class. They
			// cannot share a physical page with auxiliary fragments or indexes.
			tag = contract.GeneratorCapacityAuxiliary
		case format.IntentFragmentSupport, format.GraphFragmentSupport, format.AuxiliaryFragmentSupport, format.OutputConfigurationSupport:
			tag = contract.GeneratorCapacityIntents
			switch group.Class {
			case format.GraphFragmentSupport:
				tag = contract.GeneratorCapacityGraph
			case format.AuxiliaryFragmentSupport, format.OutputConfigurationSupport:
				tag = contract.GeneratorCapacityAuxiliary
			}
			for _, row := range group.Records {
				fragmentCounts[tag]++
				length := len(row.Body)
				if row.Body == nil {
					fact, ok := fragmentFacts[row.RecordID]
					if !ok || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID {
						return empty, contract.ErrRecord
					}
					length = int(fact.row.BodyLength())
				}
				fragmentBytes[tag] += uint64(contract.SupportRecordOverhead + length)
			}
			continue
		case format.GraphIndexSupport, format.AuxiliaryIndexSupport:
			tag = contract.GeneratorCapacityGraph
			if group.Class == format.AuxiliaryIndexSupport {
				tag = contract.GeneratorCapacityAuxiliary
			}
			width := uint64(0)
			for _, row := range group.Records {
				width += uint64(contract.SupportRecordOverhead + len(row.Body))
			}
			if width == 0 || width > supportPayload {
				return empty, contract.ErrRecordCapacity
			}
			indexCounts[tag]++
			indexBytes[tag] += width
			indexWidths[tag] = max(indexWidths[tag], width)
			continue
		default:
			return empty, contract.ErrRecord
		}
		if group.Class == format.OldValueSupport || group.Class == format.CandidateValueSupport || group.Class == format.ResultSupport ||
			group.Class == format.OwnerSupport || group.Class == format.MaterialSupport || group.Class == format.GCPlanSupport {
			width := uint64(0)
			for _, row := range group.Records {
				if row.Body == nil {
					return empty, contract.ErrRecord
				}
				width += uint64(contract.SupportRecordOverhead + len(row.Body))
			}
			if width == 0 || width > uint64(format.RequiredSupportGroupLimit(group.Class)) {
				return empty, contract.ErrRecordCapacity
			}
			part := 0
			if group.Mandatory {
				part = 1
			}
			x := &exact[tag][part]
			x.count++
			x.bytes += width
			x.maxWidth = max(x.maxWidth, width)
		} else if err := addRows(tag, 1, uint64(format.RequiredSupportGroupLimit(group.Class)), supportPayload); err != nil {
			return empty, err
		}
	}
	if projection != nil && projection.emit && projection.changed {
		// The compact current-intent blob is not materialized during public
		// admission. Its exact fragment lengths are fixed by the authenticated
		// selected logical bytes and the deterministic packing projection.
		fragmentCounts[contract.GeneratorCapacityIntents] += uint64(projection.fragments)
		fragmentBytes[contract.GeneratorCapacityIntents] += projection.total +
			uint64(projection.fragments)*(contract.SupportRecordOverhead+contract.GeneratedFragmentHeaderLength)
		partition[format.IntentFragmentSupport] |= 1
	}
	// Sealed result rows have exact widths. Missing CREATE results, including
	// new lineages, are disposable rows and still need their full envelope.
	maxResult := uint64(format.RequiredSupportGroupLimit(format.ResultSupport))
	pending := groups[contract.GeneratorCapacityCreateResults].MaxCount
	for _, attempt := range selected.attempts {
		if attempt.expected.Template.Action == contract.GeneratorActionCreate && !results[attempt.record.ResultID] {
			pending++
		}
	}
	if pending != 0 {
		part := &exact[contract.GeneratorCapacityCreateResults][0]
		part.count += pending
		part.bytes += pending * maxResult
		part.maxWidth = maxResult
	}
	groups[contract.GeneratorCapacityCreateResults] = contract.GeneratorCapacityGroup{}
	for _, tag := range []int{contract.GeneratorCapacityOldValues, contract.GeneratorCapacityCandidateValues, contract.GeneratorCapacityCreateResults, contract.GeneratorCapacityOwners, contract.GeneratorCapacityMaterial, contract.GeneratorCapacityAuxiliary} {
		for _, part := range exact[tag] {
			if part.count == 0 {
				continue
			}
			group := &groups[tag]
			pages := supportGroupPages(part.count, part.bytes, part.maxWidth)
			if group.MaxCount > contract.MaxChildPages*(supportPayload/contract.SupportRecordMinLength)-part.count ||
				pages > contract.MaxChildPages || uint64(group.MaxPages)+pages > contract.MaxChildPages {
				return empty, contract.ErrRecordCapacity
			}
			group.MaxCount += part.count
			group.MaxFramedBytes += part.bytes
			group.MaxPages += uint32(pages)
		}
	}
	recovery := uint64(boolInt(v.Recovery))
	for material := range selected.materials {
		if material.kind == contract.OperationSeedMaterialKind {
			if err := addRows(contract.GeneratorCapacitySeedAccess, 1, contract.AccessRecordFixedLength+contract.WrapRowWireLength*(1+recovery), accessPayload); err != nil {
				return empty, err
			}
		} else if len(selected.retainedReaders(material.id)) != 0 && !currentValues[material.id] {
			if err := addRows(contract.GeneratorCapacityOldAccess, 1, contract.AccessRecordFixedLength+contract.WrapRowWireLength*(v.Recipients+recovery), accessPayload); err != nil {
				return empty, err
			}
		}
	}
	for _, tag := range []int{contract.GeneratorCapacityIntents, contract.GeneratorCapacityGraph, contract.GeneratorCapacityAuxiliary} {
		group := &groups[tag]
		group.MaxCount += fragmentCounts[tag] + indexCounts[tag]
		group.MaxFramedBytes += fragmentBytes[tag] + indexBytes[tag]
		pages := ceil(fragmentCounts[tag], generatedFragmentsPerPage)
		if tag == contract.GeneratorCapacityIntents {
			// Both old and new intent fragments share this physical group.
			group.MaxPages = uint32(ceil(group.MaxCount, generatedFragmentsPerPage))
			continue
		}
		if indexCounts[tag] != 0 {
			pages += 1 + (indexBytes[tag]-1)/(supportPayload-indexWidths[tag]+1)
		}
		if pages > contract.MaxChildPages || uint64(group.MaxPages)+pages > contract.MaxChildPages {
			return empty, contract.ErrRecordCapacity
		}
		group.MaxPages += uint32(pages)
	}
	for class, tag := range map[format.SupportStorageGroup]int{
		format.GraphIndexSupport:        contract.GeneratorCapacityGraph,
		format.AuxiliaryIndexSupport:    contract.GeneratorCapacityAuxiliary,
		format.IntentFragmentSupport:    contract.GeneratorCapacityIntents,
		format.AuxiliaryFragmentSupport: contract.GeneratorCapacityAuxiliary,
	} {
		if partition[class] == 3 {
			if groups[tag].MaxPages == contract.MaxChildPages {
				return empty, contract.ErrRecordCapacity
			}
			groups[tag].MaxPages++
		}
	}
	// The clean operation is charged separately from selected backlog. Its
	// new graph can carry both a current intent and disposable graph detail.
	// Current proof/index support and the receipt index can likewise split
	// their own auxiliary classes. Each class has one flush boundary, so the
	// extra charge is at most one page for that class, independent of rows.
	if v.Creates != 0 {
		if groups[contract.GeneratorCapacityGraph].MaxPages == contract.MaxChildPages ||
			groups[contract.GeneratorCapacityAuxiliary].MaxPages == contract.MaxChildPages {
			return empty, contract.ErrRecordCapacity
		}
		groups[contract.GeneratorCapacityGraph].MaxPages++
		groups[contract.GeneratorCapacityAuxiliary].MaxPages++
	}
	if groups[contract.GeneratorCapacityAuxiliary].MaxPages == contract.MaxChildPages {
		return empty, contract.ErrRecordCapacity
	}
	groups[contract.GeneratorCapacityAuxiliary].MaxPages++
	return groups, nil
}
