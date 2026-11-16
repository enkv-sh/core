package core

import (
	"bytes"
	"context"
	"slices"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedNormalSupportRows aligns every old row with its authenticated
// selected fact. A cold fragment has no Body here; its fact still carries the
// exact inspected length and digest from the signed page Ref and ordinal.
func (s *StateSession) selectedNormalSupportRows() (contract.GeneratedSupportRows, error) {
	if s == nil || len(s.support) != len(s.root.RequiredSupport) ||
		len(s.supportFacts) != 0 && len(s.supportFacts) != len(s.support) {
		return contract.GeneratedSupportRows{}, contract.ErrRecord
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return contract.GeneratedSupportRows{}, err
	}
	return s.normalSupportRowsWithOpaqueFacts(fragments)
}

// Normal planning uses typed row facts before complete successor admission.
// The caller supplies their authenticated source; this does not publish a proof.
func (s *StateSession) normalSupportRowsWithOpaqueFacts(fragments map[contract.ID]selectedFragmentFact) (contract.GeneratedSupportRows, error) {
	if s == nil || len(s.support) != len(s.root.RequiredSupport) ||
		len(s.supportFacts) != 0 && len(s.supportFacts) != len(s.support) {
		return contract.GeneratedSupportRows{}, contract.ErrRecord
	}
	type pair struct {
		row  contract.SupportRecord
		fact contract.SupportRecordDigest
	}
	var ordered []pair
	for i, page := range s.support {
		ref := s.root.RequiredSupport[i]
		if page.Domain != s.root.Domain || page.Object != ref.Object || page.Index != ref.Index {
			return contract.GeneratedSupportRows{}, contract.ErrRecord
		}
		selected := len(s.supportFacts) != 0
		if selected && (s.supportFacts[i].ref != ref || len(s.supportFacts[i].rows) != len(page.Records) ||
			len(s.supportFacts[i].ordinals) != len(page.Records)) {
			return contract.GeneratedSupportRows{}, contract.ErrRecord
		}
		for j, view := range page.Records {
			row := contract.SupportRecord(view)
			var fact contract.SupportRecordDigest
			if selected {
				fact = s.supportFacts[i].rows[j]
				if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
					return contract.GeneratedSupportRows{}, contract.ErrRecord
				}
				if row.Body == nil && publicationSupportKind(row.Kind) {
					publication, err := s.publicationRecord(row)
					if err != nil || publication.digest != fact {
						return contract.GeneratedSupportRows{}, contract.ErrRecord
					}
					row.Body, err = publication.body()
					if err != nil {
						return contract.GeneratedSupportRows{}, err
					}
				} else if row.Body == nil {
					fragment, ok := fragments[row.RecordID]
					if !ok || !opaqueSupportKind(row.Kind) || fragment.ref != ref ||
						fragment.row != fact || int(fragment.logical) != j ||
						fragment.physical != s.supportFacts[i].ordinals[j] {
						return contract.GeneratedSupportRows{}, contract.ErrRecord
					}
				} else {
					inspected, err := contract.InspectSupportRecordDigest(s.root.Domain, row)
					if err != nil || inspected != fact {
						return contract.GeneratedSupportRows{}, contract.ErrRecord
					}
				}
			} else {
				if row.Body == nil {
					return contract.GeneratedSupportRows{}, contract.ErrRecord
				}
				var err error
				fact, err = contract.InspectSupportRecordDigest(s.root.Domain, row)
				if err != nil {
					return contract.GeneratedSupportRows{}, err
				}
			}
			ordered = append(ordered, pair{row: row, fact: fact})
		}
	}
	slices.SortFunc(ordered, func(a, b pair) int {
		if a.row.Kind != b.row.Kind {
			return int(a.row.Kind) - int(b.row.Kind)
		}
		return bytes.Compare(a.row.RecordID[:], b.row.RecordID[:])
	})
	out := contract.GeneratedSupportRows{Records: make([]contract.SupportRecord, len(ordered)),
		Facts: make([]contract.SupportRecordDigest, len(ordered))}
	for i, row := range ordered {
		out.Records[i], out.Facts[i] = row.row, row.fact
	}
	if _, err := contract.RequiredSupportDescriptorFromDigests(s.root.Domain, out.Facts); err != nil {
		return contract.GeneratedSupportRows{}, err
	}
	return out, nil
}

// generatedSupportTransition is private parent preparation from authenticated
// selected state and independently qualified static implementation rows.
// It allocates no mutation identity and grants no effect or selection authority.
func (s *StateSession) generatedSupportTransition(ctx context.Context, c *Comparison, registry map[string]contract.GeneratedSupportHandoff) (*contract.GeneratedSupportTransition, error) {
	if c == nil || c.session != s {
		return nil, contract.ErrRecord
	}
	if len(s.support) == 0 && s.root.Generated.GeneratedCurrent == 0 {
		return nil, nil
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	support, err := s.supportDescriptor()
	if err != nil {
		return nil, err
	}
	selected, err := s.selectedNormalSupportRows()
	if err != nil {
		return nil, err
	}
	w := &contract.GeneratedSupportTransition{Schema: 1, DomainID: s.root.Domain, BeforeSnapshot: s.root.Snapshot, BeforeSliceSnapshot: s.adminIndex.SliceSnapshot, BeforeRootDigest: s.head.Core.Root.Digest,
		BeforeSupport: support, Records: selected.Records, RecordFacts: selected.Facts,
		BeforeAccess: s.root.CurrentAccess.Core, AccessRecords: s.accessRecords()}
	if c.outputChanged {
		w.Output, err = s.normalOutputTransition(ctx, c)
		if err != nil {
			return nil, err
		}
	}
	carriers := make(map[contract.GeneratorSliceLocation]uint32)
	for i, row := range w.Records {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return nil, err
		}
		if carrier.VectorKind != contract.GeneratorVectorSlices {
			continue
		}
		location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
		if err != nil || carrier.DomainID != w.DomainID || carrier.OwnerKind != contract.GeneratorSnapshotOwner ||
			carrier.OwnerID != w.BeforeSliceSnapshot {
			return nil, contract.ErrRecord
		}
		if _, duplicate := carriers[location]; duplicate {
			return nil, contract.ErrRecord
		}
		carriers[location] = uint32(i)
	}
	for _, entry := range s.root.Names {
		m := s.valueEntry(entry.Slot)
		if m == nil {
			return nil, contract.ErrRecord
		}
		if m.ValueSource != contract.Generated {
			continue
		}
		index := slices.IndexFunc(w.Records, func(r contract.SupportRecord) bool {
			return r.Kind == contract.GeneratedCreateEvidenceSupportKind && r.RecordID == m.Generated.CreateResultID
		})
		if index < 0 {
			return nil, contract.ErrRecord
		}
		evidence, err := contract.InspectGeneratedCreateEvidence(w.Records[index].Body)
		if err != nil {
			return nil, err
		}
		created, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
		if err != nil {
			return nil, err
		}
		intent, ok := g.content.locations[generatedContentKey{contract.GeneratorContentIntent, m.Generated.IntentDigest}]
		if !ok {
			return nil, contract.ErrRecord
		}
		carrier, ok := carriers[intent]
		if !ok {
			return nil, contract.ErrRecord
		}
		body, err := contract.EncodeValueEntry(*m)
		if err != nil {
			return nil, err
		}
		target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: m.Name, IncarnationID: m.Incarnation, Epoch: m.Generated.Epoch, ResourceID: m.Generated.ResourceIncarnationID,
			ResourceDigest: m.Generated.ResourceDigest, ConfigContractID: m.Generated.ConfigContractID, ResourceContractID: m.Generated.ResourceContractID, OriginalOperationID: m.Generated.OriginOperationID,
			OriginalAttemptID: m.Generated.OriginAttemptID, ResultContractID: created.ResultContractID, CompletionClass: m.Generated.CompletionClass}
		if m.Generated.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			target = contract.GeneratorTarget{}
		}
		current := uint16(len(w.CurrentGenerated))
		currentRow := contract.GeneratedSupportCurrent{Slot: entry.Slot, EntryBytes: body,
			EvidenceRecord: uint32(index), CarrierRecord: carrier, Intent: intent, Target: target}
		intentBytes, err := g.readSelectedSlice(ctx, contract.GeneratorContentIntent,
			m.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil {
			return nil, err
		}
		currentRow, err = contract.ProveGeneratedSupportCurrent(w.DomainID, w.BeforeSliceSnapshot,
			w.BeforeRootDigest, currentRow, w.Records[index], w.Records[carrier], intentBytes)
		if err != nil {
			return nil, err
		}
		w.CurrentGenerated = append(w.CurrentGenerated, currentRow)
		after := slices.IndexFunc(c.intent, func(v contract.CryptoIntentRow) bool { return v.Name == m.Name })
		if after >= 0 && c.intent[after].ValueSource == contract.Generated {
			continue
		}
		if m.Generated.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			continue
		}
		if m.Generated.RetiringDutyPresent != 0 {
			return nil, contract.ErrRecord
		}
		for _, row := range w.Records {
			if row.Kind != contract.GeneratedDutySupportKind {
				continue
			}
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return nil, err
			}
			if duty.Kind == contract.GeneratedDutyRetirement {
				old, err := g.retirementTarget(ctx, duty)
				if err != nil {
					return nil, err
				}
				if old.Name == m.Name {
					return nil, contract.ErrRecord
				}
			}
		}
		handoff, present := registry[m.Name]
		if !present {
			return nil, contract.ErrRecord
		}
		handoff.Current = current
		w.Handoffs = append(w.Handoffs, handoff)
	}
	for i, access := range w.AccessRecords {
		r := contract.GeneratedSupportReaders{Access: uint32(i), Consumers: slices.Clone(g.consumers[materialIdentity{access.MaterialKind, access.MaterialID}])}
		for _, entry := range s.root.Names {
			m := s.valueEntry(entry.Slot)
			if m.ConfidentialityClass == contract.Secret && m.ValueState == access.MaterialID && access.MaterialKind == contract.ValueMaterialKind {
				r.Current = slices.Clone(m.Recipients)
			}
		}
		if access.MaterialKind == contract.ValueMaterialKind && len(r.Consumers) != 0 {
			r.Retained = g.retainedReaders(access.MaterialID)
		}
		if access.MaterialKind == contract.OperationSeedMaterialKind {
			for _, wrap := range access.Wraps {
				if wrap.SubjectKind == contract.OrdinaryWrapSubject {
					r.Retained = append(r.Retained, wrap.SubjectID)
				}
			}
		}
		for _, wrap := range access.Wraps {
			ref := contract.RecipientBindingReference{RecipientID: wrap.SubjectID, PublicBindingDigest: wrap.PublicBindingDigest}
			if wrap.SubjectKind == contract.OrdinaryWrapSubject {
				r.Bindings = append(r.Bindings, ref)
			} else {
				r.Recovery = &ref
			}
		}
		w.Readers = append(w.Readers, r)
	}
	w.Groups, err = s.generatedNormalGroups(ctx, c, g, w)
	if err != nil {
		return nil, err
	}
	if err := w.IntentError(c.intent); err != nil {
		return nil, err
	}
	return w, nil
}

// Groups use the existing typed physical census. Future delete charges are
// fixed codec envelopes, not a fabricated graph, Parent or Attempt.
func (s *StateSession) generatedNormalGroups(ctx context.Context, c *Comparison, g *generatedSelection, w *contract.GeneratedSupportTransition) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, error) {
	var groups [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	const (
		supportPayload = uint64(contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
		accessPayload  = uint64(contract.MaxAccessPageLength - contract.AccessPageHeaderLength)
	)
	add := func(tag int, count, size uint64, pages uint32) error {
		r := &groups[tag]
		if count > ^uint64(0)-r.MaxCount || size > ^uint64(0)-r.MaxFramedBytes || pages > ^uint32(0)-r.MaxPages {
			return contract.ErrRecordCapacity
		}
		r.MaxCount += count
		r.MaxFramedBytes += size
		r.MaxPages += pages
		return nil
	}
	// The page packer starts a new page when either Class or Mandatory
	// changes. Keep those physical streams separate. Future rows have their
	// own stream because their eventual mandatory partition is not yet known.
	type pageStream struct {
		tag       int
		class     format.SupportStorageGroup
		mandatory bool
	}
	type streamCharge struct {
		count, bytes, width, payload uint64
	}
	streams := make(map[pageStream]streamCharge)
	chargeRows := func(stream pageStream, count, width, payload uint64) error {
		if count == 0 {
			return nil
		}
		if width == 0 || width > payload || count > ^uint64(0)/width {
			return contract.ErrRecordCapacity
		}
		used := streams[stream]
		if used.count != 0 && used.payload != payload ||
			count > ^uint64(0)-used.count || count*width > ^uint64(0)-used.bytes {
			return contract.ErrRecordCapacity
		}
		used.count += count
		used.bytes += count * width
		used.width = max(used.width, width)
		used.payload = payload
		streams[stream] = used
		return add(stream.tag, count, count*width, 0)
	}
	rows := func(tag int, count, width, payload uint64) error {
		return chargeRows(pageStream{tag: tag}, count, width, payload)
	}
	var entryCount, secrets, relations, generated uint64
	var occupied [contract.MaxValueEntryPages]bool
	for i, row := range c.intent {
		entryCount++
		relations += uint64(len(row.Recipients))
		occupied[c.slots[i]/format.PageSlots] = true
		if row.ConfidentialityClass == contract.Secret {
			secrets++
		}
		if row.ValueSource == contract.Generated {
			generated++
		}
	}
	pages := uint32(0)
	for _, used := range occupied {
		if used {
			pages++
		}
	}
	if entryCount != 0 {
		groups[contract.GeneratorCapacityCurrentValueEntries] = contract.GeneratorCapacityGroup{MaxCount: entryCount, MaxPages: pages, MaxFramedBytes: (contract.ValueEntryFixedLength+contract.CryptoMaxName)*entryCount + uint64(len(contract.ID{}))*relations + contract.CanonicalPayloadOverhead*secrets + min(uint64(contract.CryptoMaxRetainedSet), entryCount*contract.CryptoMaxRetainedValue) + generated*uint64(contract.GeneratedEntryMetadataMaxLength)}
	}
	groups[contract.GeneratorCapacityCurrentRecipients] = contract.GeneratorCapacityGroup{MaxCount: uint64(len(c.recipients)), MaxFramedBytes: uint64(len(c.recipients)) * contract.RecipientRecordMaxLength, MaxPages: uint32((len(c.recipients) + format.RecipientSlots - 1) / format.RecipientSlots)}
	// Equal and changed values can both remain alongside real retained consumers.
	for _, access := range w.AccessRecords {
		n, err := contract.AccessRecordLength(access)
		if err != nil {
			return groups, err
		}
		tag := contract.GeneratorCapacityOldAccess
		if access.MaterialKind == contract.OperationSeedMaterialKind {
			tag = contract.GeneratorCapacitySeedAccess
		}
		if err := rows(tag, 1, uint64(n), accessPayload); err != nil {
			return groups, err
		}
	}
	for i, intended := range c.intent {
		if intended.ConfidentialityClass != contract.Secret {
			continue
		}
		ids := slices.Clone(intended.Recipients)
		old := s.valueEntry(c.slots[i])
		// A same-source equal value may keep its current material. Preserve the
		// exact retained reader union as well as the bounded current projection.
		// Exclusion and source-kind changes require new material instead.
		if old != nil && old.ValueSource == intended.ValueSource && slices.ContainsFunc(w.AccessRecords, func(a contract.AccessRecord) bool {
			return a.MaterialKind == contract.ValueMaterialKind && a.MaterialID == old.ValueState
		}) && !slices.ContainsFunc(old.Recipients, func(id contract.ID) bool { return !slices.Contains(intended.Recipients, id) }) {
			j := slices.IndexFunc(w.AccessRecords, func(a contract.AccessRecord) bool {
				return a.MaterialKind == contract.ValueMaterialKind && a.MaterialID == old.ValueState
			})
			ids = slices.Concat(ids, w.Readers[j].Retained)
			slices.SortFunc(ids, func(a, b contract.ID) int {
				return compareMaterial(contract.ValueMaterialKind, a, contract.ValueMaterialKind, b)
			})
			ids = slices.Compact(ids)
		}
		if len(ids) > contract.CryptoMaxRecipients {
			return groups, contract.ErrRecordCapacity
		}
		if err := rows(contract.GeneratorCapacityCurrentAccess, 1, uint64(contract.AccessRecordFixedLength+contract.WrapRowWireLength*(len(ids)+boolInt(s.root.CurrentAccess.Core.Recovery != nil))), accessPayload); err != nil {
			return groups, err
		}
	}
	entryMetadata, err := prospectiveNormalGeneratedEntryMetadata(c)
	if err != nil {
		return groups, err
	}
	// The capacity shape must omit the same dead local evidence as actual
	// SupportAfter. Otherwise it assigns removed local values no real owner.
	preview := contract.IdentityPlan{Operation: outputApplyPreviewID(3, "capacity")}
	fresh := c.freshIncarnationSlots()
	for i, intended := range c.intent {
		incarnation := outputApplyPreviewID(4, intended.Name)
		var valueState contract.ID
		if !slices.Contains(fresh, c.slots[i]) {
			current := s.valueEntry(c.slots[i])
			incarnation = current.Incarnation
			if intended.ValueSource == contract.Generated {
				valueState = current.ValueState
			}
		}
		preview.Rows = append(preview.Rows, contract.IdentityRow{Name: intended.Name, Slot: c.slots[i], Incarnation: incarnation, ValueState: valueState})
	}
	shape, err := w.LocalEvidenceAfter(c.intent)
	if err != nil {
		return groups, err
	}
	if w.Output != nil {
		shape, err = w.Output.SupportAfter(preview, shape)
		if err != nil {
			return groups, err
		}
	}
	_, locations, err := normalSupportSlices(w.DomainID, w.BeforeSliceSnapshot, shape.Records)
	if err != nil {
		return groups, err
	}
	physical, err := generatedReservationGroupsFromEntries(entryMetadata, s, shape.Records, locations, g.bundles)
	if err != nil {
		return groups, err
	}
	if len(shape.Facts) != len(shape.Records) {
		return groups, contract.ErrRecord
	}
	facts := make(map[generatedRecordKey]contract.SupportRecordDigest, len(shape.Facts))
	for i, row := range shape.Records {
		fact := shape.Facts[i]
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
			return groups, contract.ErrRecord
		}
		if _, duplicate := facts[key]; duplicate {
			return groups, contract.ErrRecord
		}
		facts[key] = fact
	}
	results := make(map[contract.ID]bool)
	for _, group := range physical {
		tag := generatedNormalSupportTag(group.Class)
		if group.Class == format.ResultSupport {
			results[group.Owner] = true
		}
		width := uint64(0)
		for _, row := range group.Records {
			fact, ok := facts[generatedRecordKey{kind: row.Kind, id: row.RecordID}]
			if !ok {
				return groups, contract.ErrRecord
			}
			if row.Body != nil {
				inspected, err := contract.InspectSupportRecordDigest(s.root.Domain, row)
				if err != nil || inspected != fact {
					return groups, contract.ErrRecord
				}
			} else if !opaqueSupportKind(row.Kind) {
				return groups, contract.ErrRecord
			}
			width += uint64(contract.SupportRecordOverhead) + uint64(fact.BodyLength())
		}
		if group.Class >= format.IntentFragmentSupport && group.Class <= format.OutputConfigurationSupport {
			if err := add(tag, uint64(len(group.Records)), width, uint32((uint64(len(group.Records))+generatedFragmentsPerPage-1)/generatedFragmentsPerPage)); err != nil {
				return groups, err
			}
		} else if group.Class == format.GraphIndexSupport || group.Class == format.AuxiliaryIndexSupport {
			if err := chargeRows(pageStream{tag, group.Class, group.Mandatory}, 1, width, supportPayload); err != nil {
				return groups, err
			}
		} else if group.Class == format.OwnerSupport || group.Class == format.MaterialSupport || group.Class == format.GCPlanSupport {
			// These selected optional groups have exact authenticated widths.
			// Replacing them with the generic class ceilings can
			// refuse a legal normal successor before its actual packing.
			if err := chargeRows(pageStream{tag, group.Class, group.Mandatory}, 1, width, supportPayload); err != nil {
				return groups, err
			}
		} else if err := chargeRows(pageStream{tag, group.Class, group.Mandatory}, 1,
			uint64(format.RequiredSupportGroupLimit(group.Class)), supportPayload); err != nil {
			return groups, err
		}
	}
	for _, attempt := range g.attempts {
		if attempt.expected.Template.Action == contract.GeneratorActionCreate && !results[attempt.record.ResultID] {
			if err := rows(contract.GeneratorCapacityCreateResults, 1, uint64(format.RequiredSupportGroupLimit(format.ResultSupport)), supportPayload); err != nil {
				return groups, err
			}
		}
	}
	var calls uint64
	for _, h := range w.Handoffs {
		m, _ := contract.InspectValueEntry(w.CurrentGenerated[h.Current].EntryBytes)
		calls++
		if m.Generated.CompletionClass == contract.GeneratedCompletionConfirmed {
			calls++
		}
	}
	if calls != 0 {
		windows, err := s.receiptWindows(ctx)
		if err != nil {
			return groups, err
		}
		before := uint64(len(windows.Successes) + len(windows.Failures))
		additional := min(uint64(len(w.Handoffs)), uint64(2*contract.MutationReceiptWindowLimit)-before)
		if err := rows(contract.GeneratorCapacityReceipts, additional, uint64(format.RequiredSupportGroupLimit(format.ReceiptSupport)), supportPayload); err != nil {
			return groups, err
		}
		// Append/eviction replaces the one bounded index fragment. Its maximum
		// joint count grows by at most one terminal outcome per initial handoff.
		// Charge the positive byte delta; the existing physical fragment is
		// already charged once above (an initially empty index needs one row).
		indexGrowth := uint64(4+len(contract.ID{})) * additional
		if before == 0 {
			indexGrowth += 18 + generatedFragmentCharge
			if err := add(contract.GeneratorCapacityAuxiliary, 1, indexGrowth, 1); err != nil {
				return groups, err
			}
		} else if indexGrowth != 0 {
			if err := add(contract.GeneratorCapacityAuxiliary, 0, indexGrowth, 0); err != nil {
				return groups, err
			}
		}
		for _, charge := range []struct {
			tag                   int
			count, width, payload uint64
		}{
			{contract.GeneratorCapacityDeletes, calls, uint64(format.RequiredSupportGroupLimit(format.DeleteContinuationSupport)), supportPayload},
			{contract.GeneratorCapacityMaterial, calls, uint64(2*contract.SupportRecordOverhead + 236 + contract.GeneratedParentRecordBodyLength), supportPayload},
			{contract.GeneratorCapacityOwners, 2 * calls, uint64(2*contract.SupportRecordOverhead + contract.GeneratedDutyRecordBodyLength + contract.GeneratorCarrierFixedLength + contract.GeneratorTargetMaxLength), supportPayload},
			{contract.GeneratorCapacitySeedAccess, calls, uint64(contract.AccessRecordFixedLength + contract.WrapRowWireLength*(1+boolInt(s.root.CurrentAccess.Core.Recovery != nil))), accessPayload},
		} {
			if err := rows(charge.tag, charge.count, charge.width, charge.payload); err != nil {
				return groups, err
			}
		}
		// These are the same closed template/carrier and configuration codec
		// envelopes used by generatedCleanCapacity, with no create lineage,
		// source or planned entry. They are charges, not emitted graphs.
		graph := calls*(generatedAttemptTemplateCharge+generatedEdgesPerTemplate*generatedEdgeCharge+generatedResultUseCharge) + generatedParentPlanCharge
		fragments := (graph + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
		carriers := generatedCarriersPerTemplate * calls
		if err := add(contract.GeneratorCapacityGraph, carriers+fragments, graph+generatedFragmentCharge*fragments+generatedSliceCarrierCharge*carriers, uint32((fragments+generatedFragmentsPerPage-1)/generatedFragmentsPerPage+(generatedSliceCarrierCharge*carriers+supportPayload-1)/supportPayload)); err != nil {
			return groups, err
		}
		auxiliary := uint64(len(w.Handoffs))*generatedExecutionSupportCharge + calls*generatedReleaseHandoffCharge + generatedControlSectionCount*generatedControlSectionCharge + contract.MaxChildPages*generatedChildReferenceCharge + generatedAuxiliaryIndexCharge
		fragments = (auxiliary + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
		if err := add(contract.GeneratorCapacityAuxiliary, fragments, auxiliary+generatedFragmentCharge*fragments, uint32((fragments+generatedFragmentsPerPage-1)/generatedFragmentsPerPage)); err != nil {
			return groups, err
		}
	}
	// Every nonfinal greedy page has at least payload-maxWholeRow+1 bytes.
	// Fixed-width owner streams use exact whole-row counts. Fragment pairs keep
	// their separate page charge. This also permits a full128 handoff census.
	for stream, used := range streams {
		pages := uint64(1) + (used.bytes-1)/(used.payload-used.width+1)
		if stream.tag == contract.GeneratorCapacityOldAccess || stream.tag == contract.GeneratorCapacitySeedAccess {
			pages = max(pages, (used.count+contract.AccessPageRecordLimit-1)/contract.AccessPageRecordLimit)
		}
		if pages > ^uint64(0)>>32 || uint64(groups[stream.tag].MaxPages)+pages > ^uint64(0)>>32 {
			return groups, contract.ErrRecordCapacity
		}
		groups[stream.tag].MaxPages += uint32(pages)
	}
	return groups, nil
}

func generatedNormalSupportRows(c *Comparison, p transitionPlan) (contract.GeneratedSupportRows, error) {
	if c == nil || c.session == nil || c.outputChanged != (c.outputAfter != nil) {
		return contract.GeneratedSupportRows{}, contract.ErrRecord
	}
	if !c.outputChanged && c.normalSupportSnapshot == p.snapshot && c.normalSupportTransition == p.transition && !p.snapshot.IsZero() && !p.transition.IsZero() {
		return c.normalSupportRows, nil
	}
	var selected contract.GeneratedSupportRows
	var err error
	if c.support != nil {
		selected, err = c.support.SupportAfter(identityPlan(c, p), c.intent)
	} else {
		selected, err = c.session.selectedNormalSupportRows()
	}
	if err != nil || !c.outputChanged {
		return selected, err
	}
	if c.outputAfter.transition == nil || !projectionSupportFactsBound(c.session.root, c.session.adminIndex, c.session.supportFacts) {
		return contract.GeneratedSupportRows{}, contract.ErrRecord
	}
	_, descriptor, rows, err := c.outputAfter.transition.ConfigurationAfter(identityPlan(c, p))
	if err != nil || descriptor != c.outputAfter.descriptor || !slices.EqualFunc(rows, c.outputAfter.records, func(a, b contract.SupportRecord) bool {
		return a.Kind == b.Kind && a.RecordID == b.RecordID && bytes.Equal(a.Body, b.Body)
	}) {
		return contract.GeneratedSupportRows{}, contract.ErrRecord
	}
	if c.support != nil {
		if c.support.Output == nil || !c.support.Output.Equal(c.outputAfter.transition) {
			return contract.GeneratedSupportRows{}, contract.ErrRecord
		}
		return selected, nil
	}
	return c.outputAfter.transition.SupportAfter(identityPlan(c, p), selected)
}

// plannedNormalSupportRows keeps unchanged configuration facts rooted in the
// predecessor while generated fragment facts describe the prospective pages.
// Complete configuration/publication proofs are installed by final assembly.
func (next *StateSession) plannedNormalSupportRows(c *Comparison) (contract.GeneratedSupportRows, error) {
	if next == nil || c == nil || c.session == nil || c.support == nil && !c.outputChanged ||
		next.root.Domain != c.session.root.Domain || next.root.OutputConfiguration != expectedNormalOutputDescriptor(c) ||
		next.root.Snapshot.IsZero() || next.root.Transition.IsZero() ||
		c.normalSupportSnapshot != next.root.Snapshot || c.normalSupportTransition != next.root.Transition ||
		!normalSupportPredecessorMatches(c) {
		return contract.GeneratedSupportRows{}, contract.ErrRecord
	}
	facts, err := c.session.selectedOutputFactsByRecord()
	if c.outputChanged {
		facts = make(map[contract.ID]selectedFragmentFact)
	}
	if err != nil {
		return contract.GeneratedSupportRows{}, err
	}
	for location, fact := range next.fragmentFacts {
		id, err := contract.GeneratorFragmentID(fact.blob, fact.index)
		if err != nil || fact.row.Kind() != contract.GeneratedFragmentSupportKind || fact.row.RecordID() != id ||
			location.BlobID != fact.blob || location.FragmentIndex != fact.index ||
			location.SupportPageIndex != fact.ref.Index || location.RowSlot != fact.logical ||
			!slices.Contains(next.root.Generated.Fragments, location) {
			return contract.GeneratedSupportRows{}, contract.ErrRecord
		}
		if _, duplicate := facts[id]; duplicate {
			return contract.GeneratedSupportRows{}, contract.ErrRecord
		}
		facts[id] = fact
	}
	actual, err := next.normalSupportRowsWithOpaqueFacts(facts)
	if err != nil || !slices.Equal(actual.Facts, c.normalSupportRows.Facts) ||
		len(actual.Records) != len(c.normalSupportRows.Records) {
		return contract.GeneratedSupportRows{}, contract.ErrRecord
	}
	return actual, nil
}

// Authority is formed before the successor's administrative index is encoded.
// At that point the selected-state Slice resolver must still reject the
// provisional image. Bind the public projection to the exact admitted
// SupportAfter facts and the derived physical page plan instead.
func (next *StateSession) prospectiveNormalPublicState(c *Comparison, p transitionPlan) (contract.DigestLength, error) {
	if next == nil || c == nil || c.session == nil || c.support == nil && !c.outputChanged ||
		p.snapshot.IsZero() || p.transition.IsZero() || next.root.Domain != c.session.root.Domain ||
		next.root.Snapshot != p.snapshot || next.root.Transition != p.transition ||
		c.normalSupportSnapshot != p.snapshot || c.normalSupportTransition != p.transition ||
		!normalSupportPredecessorMatches(c) ||
		len(next.root.Names) != len(c.intent) || next.root.ValueEntryCount != uint32(len(c.intent)) ||
		len(c.slots) != len(c.intent) || len(c.normalPackedPages) != len(next.support) ||
		len(next.support) != len(next.root.RequiredSupport) {
		return contract.DigestLength{}, contract.ErrRecord
	}
	for i, row := range c.intent {
		if next.root.Names[i].Name != row.Name || next.root.Names[i].Slot != c.slots[i] {
			return contract.DigestLength{}, contract.ErrRecord
		}
	}
	var count uint32
	selected := len(next.supportFacts) != 0
	if c.session.fragmentFacts != nil && !selected || selected && len(next.supportFacts) != len(next.support) {
		return contract.DigestLength{}, contract.ErrRecord
	}
	for i, planned := range c.normalPackedPages {
		view, ref := next.support[i], next.root.RequiredSupport[i]
		if ref.Index >= contract.MaxChildPages || view.Domain != next.root.Domain || view.Object != ref.Object || view.Index != ref.Index ||
			planned.index != ref.Index || len(planned.records) != len(view.Records) ||
			len(planned.facts) != len(view.Records) ||
			!planned.retained.ref.Object.IsZero() && len(planned.retained.ordinals) != len(view.Records) {
			return contract.DigestLength{}, contract.ErrRecord
		}
		if !planned.retained.ref.Object.IsZero() && planned.retained.ref != ref ||
			planned.retained.ref.Object.IsZero() && p.supportPages[ref.Index] != ref.Object {
			return contract.DigestLength{}, contract.ErrRecord
		}
		if selected && (next.supportFacts[i].ref != ref ||
			!slices.Equal(next.supportFacts[i].rows, planned.facts) ||
			len(next.supportFacts[i].ordinals) != len(view.Records)) {
			return contract.DigestLength{}, contract.ErrRecord
		}
		for slot, row := range view.Records {
			if row.Kind != planned.records[slot].Kind || row.RecordID != planned.records[slot].RecordID {
				return contract.DigestLength{}, contract.ErrRecord
			}
			if selected {
				want := uint16(slot)
				if !planned.retained.ref.Object.IsZero() {
					want = planned.retained.ordinals[slot]
				}
				if next.supportFacts[i].ordinals[slot] != want {
					return contract.DigestLength{}, contract.ErrRecord
				}
			}
		}
		count += uint32(len(view.Records))
	}
	if count != next.root.RequiredSupportRecordCount {
		return contract.DigestLength{}, contract.ErrRecord
	}
	actual, err := next.plannedNormalSupportRows(c)
	if err != nil || !slices.Equal(actual.Facts, c.normalSupportRows.Facts) ||
		len(actual.Records) != len(c.normalSupportRows.Records) {
		return contract.DigestLength{}, contract.ErrRecord
	}
	support, err := contract.RequiredSupportDescriptorFromDigests(next.root.Domain, actual.Facts)
	if err != nil {
		return contract.DigestLength{}, err
	}
	projection, err := next.publicStateWithSupport(support)
	if err != nil {
		return contract.DigestLength{}, err
	}
	descriptor, err := contract.PublicStateDescriptor(projection)
	if err != nil {
		return contract.DigestLength{}, err
	}
	return contract.DigestLength{Digest: descriptor.Digest, Length: descriptor.Length}, nil
}

// Prospective generated metadata is copied from the predecessor in intent order.
// It supplies classification facts only, without a session or selected-state claim.
func prospectiveNormalGeneratedEntryMetadata(c *Comparison) ([]contract.GeneratedEntryMetadata, error) {
	if c == nil || c.session == nil || len(c.intent) != len(c.slots) || len(c.intent) > contract.CryptoMaxValueEntries {
		return nil, contract.ErrRecord
	}
	var occupied [contract.CryptoMaxValueEntries]bool
	generated := 0
	for i, intended := range c.intent {
		slot := c.slots[i]
		if int(slot) >= len(occupied) || occupied[slot] ||
			len(intended.Name) > contract.CryptoMaxName || !utf8.ValidString(intended.Name) ||
			i > 0 && c.intent[i-1].Name >= intended.Name {
			return nil, contract.ErrRecord
		}
		occupied[slot] = true
		switch intended.ValueSource {
		case contract.Generated:
			generated++
		case contract.Supplied:
		default:
			return nil, contract.ErrRecord
		}
	}
	if generated > contract.GeneratedCurrentEntryLimit {
		return nil, contract.ErrRecord
	}
	entryMetadata := make([]contract.GeneratedEntryMetadata, 0, generated)
	for i, intended := range c.intent {
		if intended.ValueSource != contract.Generated {
			continue
		}
		entry := c.session.valueEntry(c.slots[i])
		if entry == nil || entry.Name != intended.Name || entry.ValueSource != contract.Generated {
			return nil, contract.ErrRecord
		}
		entryMetadata = append(entryMetadata, entry.Generated)
	}
	return entryMetadata, nil
}

func generatedNormalSupportTag(class format.SupportStorageGroup) int {
	switch class {
	case format.OldValueSupport:
		return contract.GeneratorCapacityOldValues
	case format.CandidateValueSupport:
		return contract.GeneratorCapacityCandidateValues
	case format.ResultSupport:
		return contract.GeneratorCapacityCreateResults
	case format.MaterialSupport:
		return contract.GeneratorCapacityMaterial
	case format.CreateContinuationSupport:
		return contract.GeneratorCapacityCreates
	case format.DeleteContinuationSupport:
		return contract.GeneratorCapacityDeletes
	case format.OwnerSupport:
		return contract.GeneratorCapacityOwners
	case format.ReceiptSupport:
		return contract.GeneratorCapacityReceipts
	case format.IntentFragmentSupport:
		return contract.GeneratorCapacityIntents
	case format.GraphFragmentSupport, format.GraphIndexSupport:
		return contract.GeneratorCapacityGraph
	default:
		return contract.GeneratorCapacityAuxiliary
	}
}

// checkNormalCapacity checks actual contributor counts, framed bytes and
// whole-row pages before candidate writes or K2. Access tags use filtered
// whole-row streams; the complete global packing and joint limits are also
// checked by the ordinary complete-successor encoder.
func (next *StateSession) normalCapacityUsage(ctx context.Context, c *Comparison) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, error) {
	var actual [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	if c == nil || c.session == nil {
		return actual, contract.ErrRecord
	}
	current := make(map[contract.ID]bool)
	for _, entry := range next.root.Names {
		m := next.valueEntry(entry.Slot)
		if m == nil {
			return actual, contract.ErrRecord
		}
		n, err := contract.ValueEntryLength(*m)
		if err != nil {
			return actual, err
		}
		a := &actual[contract.GeneratorCapacityCurrentValueEntries]
		a.MaxCount++
		a.MaxFramedBytes += uint64(n)
		if m.ConfidentialityClass == contract.Secret {
			current[m.ValueState] = true
		}
	}
	for _, p := range next.pages {
		if p != nil {
			actual[contract.GeneratorCapacityCurrentValueEntries].MaxPages++
		}
	}
	for _, p := range next.recipients {
		if p == nil {
			continue
		}
		a := &actual[contract.GeneratorCapacityCurrentRecipients]
		a.MaxPages++
		for _, r := range p.Slots {
			if r == nil {
				continue
			}
			n, err := contract.RecipientRecordLength(*r)
			if err != nil {
				return actual, err
			}
			a.MaxCount++
			a.MaxFramedBytes += uint64(n)
		}
	}
	var accessUsed, accessCount [contract.GeneratorCapacityGroupCount]int
	for _, row := range next.accessRecords() {
		tag := contract.GeneratorCapacityOldAccess
		if row.MaterialKind == contract.OperationSeedMaterialKind {
			tag = contract.GeneratorCapacitySeedAccess
		} else if current[row.MaterialID] {
			tag = contract.GeneratorCapacityCurrentAccess
		}
		n, err := contract.AccessRecordLength(row)
		if err != nil {
			return actual, err
		}
		a := &actual[tag]
		a.MaxCount++
		a.MaxFramedBytes += uint64(n)
		if accessCount[tag] == 0 {
			accessUsed[tag] = contract.AccessPageHeaderLength
			a.MaxPages++
		}
		if accessUsed[tag]+n > contract.MaxAccessPageLength || accessCount[tag] == contract.AccessPageRecordLimit {
			accessUsed[tag] = contract.AccessPageHeaderLength
			accessCount[tag] = 0
			a.MaxPages++
		}
		accessUsed[tag] += n
		accessCount[tag]++
	}
	// The successor's Slice carriers already name its new Snapshot, but its
	// administrative index is installed only after this pre-effect check.
	// The predecessor supplies the validated immutable graph and locations;
	// the groups below still classify the prospective successor rows.
	g, err := c.session.selectedGeneratedWork(ctx)
	if err != nil {
		return actual, err
	}
	var locations []contract.GeneratorSliceLocation
	for _, l := range g.content.locations {
		locations = append(locations, l)
	}
	selected, err := next.plannedNormalSupportRows(c)
	if err != nil {
		return actual, err
	}
	groups, err := generatedReservationGroupsWithSource(next, c.session, selected.Records, locations, g.bundles)
	if err != nil {
		return actual, err
	}
	if len(selected.Records) != len(selected.Facts) {
		return actual, contract.ErrRecord
	}
	facts := make(map[generatedRecordKey]contract.SupportRecordDigest, len(selected.Facts))
	for i, row := range selected.Records {
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		fact := selected.Facts[i]
		if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
			return actual, contract.ErrRecord
		}
		if _, duplicate := facts[key]; duplicate {
			return actual, contract.ErrRecord
		}
		facts[key] = fact
	}
	tags := make(map[generatedRecordKey]int)
	for _, group := range groups {
		tag := generatedNormalSupportTag(group.Class)
		a := &actual[tag]
		count := uint64(1)
		if group.Class >= format.IntentFragmentSupport && group.Class <= format.OutputConfigurationSupport {
			count = uint64(len(group.Records))
		}
		a.MaxCount += count
		for _, row := range group.Records {
			key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
			fact, found := facts[key]
			if !found {
				return actual, contract.ErrRecord
			}
			if row.Body == nil {
				if !opaqueSupportKind(row.Kind) {
					return actual, contract.ErrRecord
				}
			} else {
				inspected, err := contract.InspectSupportRecordDigest(next.root.Domain, row)
				if err != nil {
					return actual, err
				}
				if inspected != fact {
					return actual, contract.ErrRecord
				}
			}
			a.MaxFramedBytes += uint64(contract.SupportRecordOverhead) + uint64(fact.BodyLength())
			tags[key] = tag
			delete(facts, key)
		}
	}
	if len(facts) != 0 {
		return actual, contract.ErrRecord
	}
	for _, page := range next.support {
		if len(page.Records) == 0 {
			return actual, contract.ErrRecord
		}
		tag, ok := tags[generatedRecordKey{page.Records[0].Kind, page.Records[0].RecordID}]
		if !ok {
			return actual, contract.ErrRecord
		}
		for _, row := range page.Records {
			actualTag, ok := tags[generatedRecordKey{row.Kind, row.RecordID}]
			if !ok || actualTag != tag {
				return actual, contract.ErrRecord
			}
		}
		actual[tag].MaxPages++
	}
	return actual, nil
}

func (next *StateSession) checkNormalCapacity(ctx context.Context, c *Comparison) error {
	actual, err := next.normalCapacityUsage(ctx, c)
	if err != nil {
		return err
	}
	for i, a := range actual {
		bound := c.support.Groups[i]
		if a.MaxCount > bound.MaxCount || a.MaxFramedBytes > bound.MaxFramedBytes || a.MaxPages > bound.MaxPages {
			return contract.ErrRecord
		}
	}
	return nil
}

func (c *Comparison) freshIncarnationSlots() []uint16 {
	result := slices.Clone(c.added)
	for i, v := range c.desiredEntries {
		old := c.session.valueEntry(c.slots[i])
		if old != nil && old.ValueSource != v.ValueSource && !slices.Contains(result, c.slots[i]) {
			result = append(result, c.slots[i])
		}
	}
	return result
}

// normalAccessShape fixes page count from admitted reader sets and fixed wrap
// widths after value identities exist, before any ciphertext is prepared.
func normalAccessShape(c *Comparison, p transitionPlan) (int, bool, error) {
	if c == nil || c.session == nil {
		return 0, false, contract.ErrRecord
	}
	if c.support == nil {
		// A configuration-only change keeps the exact selected access pages.
		// A secret access change still needs the admitted support witness.
		for _, changed := range c.secretPages() {
			if changed {
				return 0, false, contract.ErrRecord
			}
		}
		return 0, true, nil
	}
	type shape struct {
		kind     uint16
		id       contract.ID
		ids      []contract.ID
		recovery bool
	}
	var rows []shape
	for i, old := range c.support.AccessRecords {
		r := c.support.Readers[i]
		if old.MaterialKind == contract.OperationSeedMaterialKind || len(r.Retained) != 0 {
			rows = append(rows, shape{old.MaterialKind, old.MaterialID, slices.Clone(r.Retained), r.Recovery != nil})
		}
	}
	for i, intended := range c.intent {
		if intended.ConfidentialityClass != contract.Secret {
			continue
		}
		id, fresh := p.values[c.slots[i]]
		if !fresh {
			old := c.session.valueEntry(c.slots[i])
			if old == nil {
				return 0, false, contract.ErrRecord
			}
			id = old.ValueState
		}
		index := slices.IndexFunc(rows, func(row shape) bool { return row.kind == contract.ValueMaterialKind && row.id == id })
		if index < 0 {
			rows = append(rows, shape{contract.ValueMaterialKind, id, slices.Clone(intended.Recipients), c.support.BeforeAccess.Recovery != nil})
		} else {
			rows[index].ids = slices.Concat(rows[index].ids, intended.Recipients)
			slices.SortFunc(rows[index].ids, func(a, b contract.ID) int {
				return compareMaterial(contract.ValueMaterialKind, a, contract.ValueMaterialKind, b)
			})
			rows[index].ids = slices.Compact(rows[index].ids)
		}
	}
	slices.SortFunc(rows, func(a, b shape) int { return compareMaterial(a.kind, a.id, b.kind, b.id) })
	unchanged := len(rows) == len(c.support.AccessRecords)
	for i, row := range rows {
		if len(row.ids) > contract.CryptoMaxRecipients {
			return 0, false, contract.ErrRecordCapacity
		}
		if !unchanged {
			continue
		}
		old := c.support.AccessRecords[i]
		if row.kind != old.MaterialKind || row.id != old.MaterialID || len(old.Wraps) != len(row.ids)+boolInt(row.recovery) {
			unchanged = false
			continue
		}
		for j, id := range row.ids {
			if old.Wraps[j].SubjectKind != contract.OrdinaryWrapSubject || old.Wraps[j].SubjectID != id {
				unchanged = false
				break
			}
		}
	}
	if unchanged {
		return 0, true, nil
	}
	pages, used, count := 0, contract.AccessPageHeaderLength, 0
	for _, row := range rows {
		n := contract.AccessRecordFixedLength + contract.WrapRowWireLength*(len(row.ids)+boolInt(row.recovery))
		if used+n > contract.MaxAccessPageLength || count == contract.AccessPageRecordLimit {
			pages++
			used, count = contract.AccessPageHeaderLength, 0
		}
		used += n
		count++
	}
	if count != 0 {
		pages++
	}
	if pages > contract.MaxChildPages {
		return 0, false, contract.ErrRecordCapacity
	}
	return pages, false, nil
}

type normalSupportPage struct {
	index    uint16
	retained selectedSupportPageFacts
	records  []contract.SupportRecord
	facts    []contract.SupportRecordDigest
}

func normalSupportPacking(ctx context.Context, c *Comparison, p transitionPlan) ([]normalSupportPage, error) {
	if ctx == nil || c == nil || c.session == nil {
		return nil, contract.ErrRecord
	}
	if ctx.Err() != nil {
		return nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	children, err := normalSupportOtherChildren(c, p)
	if err != nil {
		return nil, err
	}
	if !c.outputChanged && c.normalSupportSnapshot == p.snapshot && c.normalSupportTransition == p.transition &&
		!p.snapshot.IsZero() && !p.transition.IsZero() && c.normalPackedChildren == children {
		return c.normalPackedPages, nil
	}
	output, err := generatedNormalSupportRows(c, p)
	if err != nil {
		return nil, err
	}
	g, err := c.session.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	_, locations, err := normalSupportSlices(c.session.root.Domain, normalSupportSliceOwner(c, p), output.Records)
	if err != nil {
		return nil, err
	}
	entryMetadata, err := prospectiveNormalGeneratedEntryMetadata(c)
	if err != nil {
		return nil, err
	}
	groups, err := generatedReservationGroupsFromEntries(entryMetadata, c.session, output.Records, locations, g.bundles)
	if err != nil {
		return nil, err
	}
	fragments, err := c.session.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	packed, err := generatedSupportPages(c.session.root.Domain, groups, children, fragments)
	if err != nil {
		return nil, err
	}
	packedFacts, err := normalSupportPackedFacts(c.session.root.Domain, output, packed, fragments)
	if err != nil {
		return nil, err
	}
	pages, err := normalSupportPhysicalPages(c.session, packed, packedFacts, fragments)
	if err != nil {
		return nil, err
	}
	c.normalSupportRows = output
	c.normalPackedPages = pages
	c.normalPackedChildren = children
	c.normalSupportSnapshot = p.snapshot
	c.normalSupportTransition = p.transition
	return pages, nil
}

// PackRequiredSupportRows can reorder and split groups. Match every packed
// row to exactly one SupportAfter fact before an ID is reserved or a byte is
// encoded; a bodyless fragment must be the old authenticated selected fact.
func normalSupportPackedFacts(domain contract.ID, output contract.GeneratedSupportRows,
	packed [][]contract.SupportRecord, fragments map[contract.ID]selectedFragmentFact) ([][]contract.SupportRecordDigest, error) {
	if len(output.Records) != len(output.Facts) {
		return nil, contract.ErrRecord
	}
	want := make(map[generatedRecordKey]contract.SupportRecordDigest, len(output.Records))
	for i, row := range output.Records {
		fact := output.Facts[i]
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
			return nil, contract.ErrRecord
		}
		if _, duplicate := want[key]; duplicate {
			return nil, contract.ErrRecord
		}
		want[key] = fact
	}
	byPage := make([][]contract.SupportRecordDigest, len(packed))
	for i, page := range packed {
		byPage[i] = make([]contract.SupportRecordDigest, len(page))
		for j, row := range page {
			key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
			fact, ok := want[key]
			if !ok {
				return nil, contract.ErrRecord
			}
			if row.Body == nil {
				selected, found := fragments[row.RecordID]
				if !found || !opaqueSupportKind(row.Kind) || selected.row != fact {
					return nil, contract.ErrRecord
				}
			} else {
				inspected, err := contract.InspectSupportRecordDigest(domain, row)
				if err != nil || inspected != fact {
					return nil, contract.ErrRecord
				}
			}
			byPage[i][j] = fact
			delete(want, key)
		}
	}
	if len(want) != 0 {
		return nil, contract.ErrRecord
	}
	return byPage, nil
}

// Matching is by the authenticated physical Ref, not its compact Root slot.
// A new page before the fragment class must not copy otherwise unchanged old
// fragment pages into new candidate objects.
func matchingNormalSupportPage(s *StateSession, rows []contract.SupportRecord,
	facts []contract.SupportRecordDigest, used map[uint16]bool,
	fragments map[contract.ID]selectedFragmentFact) (selectedSupportPageFacts, bool) {
	if s == nil || len(rows) == 0 || len(rows) != len(facts) || len(s.support) != len(s.root.RequiredSupport) {
		return selectedSupportPageFacts{}, false
	}
	selected := len(s.supportFacts) == len(s.support)
	for position, ref := range s.root.RequiredSupport {
		view := s.support[position]
		if used[ref.Index] || view.Domain != s.root.Domain || view.Object != ref.Object ||
			view.Index != ref.Index || len(view.Records) != len(rows) {
			continue
		}
		page := selectedSupportPageFacts{ref: ref}
		if selected {
			page = s.supportFacts[position]
			if page.ref != ref || len(page.rows) != len(rows) || len(page.ordinals) != len(rows) {
				continue
			}
		}
		matched := true
		for slot, row := range rows {
			old := view.Records[slot]
			if old.Kind != row.Kind || old.RecordID != row.RecordID || selected && page.rows[slot] != facts[slot] {
				matched = false
				break
			}
			if row.Body == nil {
				fragment, ok := fragments[row.RecordID]
				if !selected || !ok || !opaqueSupportKind(row.Kind) || old.Body != nil ||
					fragment.ref != ref || fragment.row != facts[slot] || int(fragment.logical) != slot ||
					fragment.physical != page.ordinals[slot] ||
					row.Kind == contract.GeneratedFragmentSupportKind && !slices.Contains(s.root.Generated.Fragments, format.FragmentLocation{
						BlobID: fragment.blob, FragmentIndex: fragment.index,
						SupportPageIndex: ref.Index, RowSlot: fragment.logical}) {
					matched = false
					break
				}
			} else if !bytes.Equal(old.Body, row.Body) {
				matched = false
				break
			}
		}
		if matched {
			return page, true
		}
	}
	return selectedSupportPageFacts{}, false
}

// Reserve every exact retained physical Ref first. New pages receive the
// lowest unused physical indexes, then the one plan is ordered for Root and
// administrative index encoding. No old page is rewritten due to a shift in
// the temporary packed order.
func normalSupportPhysicalPages(s *StateSession, packed [][]contract.SupportRecord,
	facts [][]contract.SupportRecordDigest,
	fragments map[contract.ID]selectedFragmentFact) ([]normalSupportPage, error) {
	if s == nil || len(packed) > contract.MaxChildPages || len(packed) != len(facts) {
		return nil, contract.ErrRecord
	}
	pages := make([]normalSupportPage, 0, len(packed))
	used := make(map[uint16]bool, len(packed))
	var fresh []normalSupportPage
	for i, rows := range packed {
		if len(rows) != len(facts[i]) {
			return nil, contract.ErrRecord
		}
		page := normalSupportPage{records: rows, facts: facts[i]}
		if retained, ok := matchingNormalSupportPage(s, rows, facts[i], used, fragments); ok {
			if retained.ref.Index >= contract.MaxChildPages {
				return nil, contract.ErrRecord
			}
			page.index, page.retained = retained.ref.Index, retained
			used[page.index] = true
			pages = append(pages, page)
		} else {
			fresh = append(fresh, page)
		}
	}
	index := 0
	for _, page := range fresh {
		for index < contract.MaxChildPages && used[uint16(index)] {
			index++
		}
		if index >= contract.MaxChildPages {
			return nil, contract.ErrRecordCapacity
		}
		page.index = uint16(index)
		used[page.index] = true
		pages = append(pages, page)
	}
	slices.SortFunc(pages, func(a, b normalSupportPage) int { return int(a.index) - int(b.index) })
	return pages, nil
}

// Only public page counts are needed to pack support rows. Exact entry and
// access bodies are prepared later; their fixed widths determine this count.
func normalSupportOtherChildren(c *Comparison, p transitionPlan) (uint32, error) {
	var entries uint32
	for _, occupied := range c.nonemptyPages() {
		if occupied {
			entries++
		}
	}
	access, unchanged, err := normalAccessShape(c, p)
	if err != nil {
		return 0, err
	}
	if unchanged {
		if c.support == nil {
			access = len(c.session.root.CurrentAccess.Core.AccessPageRefs)
		} else {
			access = len(c.support.BeforeAccess.AccessPageRefs)
		}
	}
	return 1 + uint32(len(c.session.root.AdministrativeIndexShards)) + entries +
		uint32((c.session.root.RecipientCount+7)/8) + uint32(access), nil
}

func (next *StateSession) deriveNormalGeneratedSupport(ctx context.Context, c *Comparison, p transitionPlan) error {
	packed, err := normalSupportPacking(ctx, c, p)
	if err != nil {
		return err
	}
	descriptor, err := contract.IdentityPlanDescriptor(identityPlan(c, p))
	if err != nil {
		return err
	}
	if !c.normalSupportPlan.Digest.IsZero() && c.normalSupportPlan != descriptor {
		return contract.ErrRecord
	}
	if c.outputChanged {
		next.root.OutputConfiguration = c.outputAfter.descriptor
	}
	next.support = nil
	next.supportFacts = nil
	next.fragmentFacts = nil
	next.root.RequiredSupport = nil
	next.root.RequiredSupportRecordCount = 0
	var pages []format.RequiredSupportPage
	fragmentLocations, err := c.session.selectedFragmentLocationsByRecord()
	if err != nil {
		return err
	}
	objects := c.normalSupportObjects
	if c.normalSupportPlan.Digest.IsZero() {
		objects = nil
	}
	selected := c.session.fragmentFacts != nil
	if selected && len(c.session.supportFacts) != len(c.session.support) {
		return contract.ErrRecord
	}
	for _, planned := range packed {
		rows, facts, physical := planned.records, planned.facts, planned.index
		if len(facts) != len(rows) || int(physical) >= len(p.supportPages) {
			return contract.ErrRecord
		}
		pageID := p.supportPages[physical]
		if !planned.retained.ref.Object.IsZero() {
			if !pageID.IsZero() {
				return contract.ErrRecord
			}
			oldPosition := slices.Index(c.session.root.RequiredSupport, planned.retained.ref)
			if oldPosition < 0 || c.session.support[oldPosition].Index != physical {
				return contract.ErrRecord
			}
			view := c.session.support[oldPosition]
			next.support = append(next.support, view)
			next.root.RequiredSupport = append(next.root.RequiredSupport, planned.retained.ref)
			next.root.RequiredSupportRecordCount += uint32(len(rows))
			pages = append(pages, format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index, Records: rows})
			if selected {
				if c.session.supportFacts[oldPosition].ref != planned.retained.ref ||
					!slices.Equal(c.session.supportFacts[oldPosition].rows, facts) {
					return contract.ErrRecord
				}
				next.supportFacts = append(next.supportFacts, planned.retained)
			}
			continue
		}
		if pageID.IsZero() {
			return contract.ErrRecord
		}
		var page format.RequiredSupportPage
		var view format.RequiredSupportPageView
		var ref format.Ref
		if c.normalSupportPlan.Digest.IsZero() {
			materialized, err := c.session.materializeGeneratedSupportPageAt(ctx, rows,
				pageID, physical, nil, fragmentLocations)
			if err != nil {
				return err
			}
			page, view, ref = materialized.page, materialized.view, materialized.object.ref
			objects = append(objects, materialized.object)
		} else {
			object := slices.IndexFunc(c.normalSupportObjects, func(object objectImage) bool { return object.ref.Index == physical })
			if object < 0 {
				return contract.ErrRecord
			}
			stored := c.normalSupportObjects[object]
			view, err = format.InspectRequiredSupportPage(stored.body)
			if err != nil {
				return err
			}
			if view.Domain != next.root.Domain || view.Object != pageID ||
				view.Index != physical || len(view.Records) != len(rows) {
				return contract.ErrRecord
			}
			ref, err = format.Reference(contract.RequiredSupportKind, view.Domain, view.Object, view.Index, stored.body)
			if err != nil {
				return err
			}
			if ref != stored.ref {
				return contract.ErrRecord
			}
			page = format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index,
				Records: make([]contract.SupportRecord, len(view.Records))}
			for j, encoded := range view.Records {
				if encoded.Kind != rows[j].Kind || encoded.RecordID != rows[j].RecordID ||
					rows[j].Body != nil && !slices.Equal(encoded.Body, rows[j].Body) {
					return contract.ErrRecord
				}
				page.Records[j] = contract.SupportRecord(encoded)
			}
		}
		if !normalSupportPageMatchesFacts(next.root.Domain, view, facts) {
			return contract.ErrRecord
		}
		next.support = append(next.support, view)
		next.root.RequiredSupport = append(next.root.RequiredSupport, ref)
		next.root.RequiredSupportRecordCount += uint32(len(rows))
		pages = append(pages, page)
		if selected {
			pageFacts := selectedSupportPageFacts{ref: ref, rows: slices.Clone(facts),
				ordinals: make([]uint16, len(rows))}
			for slot := range rows {
				pageFacts.ordinals[slot] = uint16(slot)
			}
			next.supportFacts = append(next.supportFacts, pageFacts)
		}
	}
	changed := 0
	for _, id := range p.supportPages {
		if !id.IsZero() {
			changed++
		}
	}
	if len(objects) != changed {
		return contract.ErrRecord
	}
	fragments, err := c.session.selectedFragmentFactsByRecord()
	if err != nil {
		return err
	}
	next.root.Generated.Fragments, err = generatedFragmentDirectoryWithSelectedFacts(pages, fragments)
	if err != nil {
		return err
	}
	if selected && !next.bindNormalGeneratedFragmentFacts(fragments) {
		return contract.ErrRecord
	}
	next.root.Generated.GeneratedCurrent = 0
	for _, name := range next.root.Names {
		if next.valueEntry(name.Slot).ValueSource == contract.Generated {
			next.root.Generated.GeneratedCurrent++
		}
	}
	output, err := generatedNormalSupportRows(c, p)
	if err != nil {
		return err
	}
	generatedRefreshClosureCounts(&next.root.Generated, output.Records)
	next.root.ChildCount = 1 + uint32(len(next.root.AdministrativeIndexShards)+len(next.root.RequiredSupport)+len(next.root.CurrentAccess.Core.AccessPageRefs))
	for _, page := range next.pages {
		if page != nil {
			next.root.ChildCount++
		}
	}
	for _, page := range next.recipients {
		if page != nil {
			next.root.ChildCount++
		}
	}
	c.normalSupportObjects = objects
	c.normalSupportPlan = descriptor
	return nil
}

// Build successor facts from the exact retained Ref or the bytes of each new
// page. The generated directory gives the compact slot; each page fact keeps
// the physical row ordinal that the administrative index must use.
func (next *StateSession) bindNormalGeneratedFragmentFacts(old map[contract.ID]selectedFragmentFact) bool {
	if next == nil || len(next.supportFacts) != len(next.support) {
		return false
	}
	next.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact, len(next.root.Generated.Fragments))
	for _, location := range next.root.Generated.Fragments {
		position := slices.IndexFunc(next.root.RequiredSupport, func(ref format.Ref) bool {
			return ref.Index == location.SupportPageIndex
		})
		if position < 0 || int(location.RowSlot) >= len(next.support[position].Records) ||
			int(location.RowSlot) >= len(next.supportFacts[position].rows) ||
			int(location.RowSlot) >= len(next.supportFacts[position].ordinals) {
			return false
		}
		page, pageFacts := next.support[position], next.supportFacts[position]
		ref := next.root.RequiredSupport[position]
		row, fact := page.Records[location.RowSlot], pageFacts.rows[location.RowSlot]
		if pageFacts.ref != ref || row.Kind != contract.GeneratedFragmentSupportKind ||
			fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
			return false
		}
		selected := selectedFragmentFact{ref: ref, row: fact, physical: pageFacts.ordinals[location.RowSlot],
			logical: location.RowSlot, blob: location.BlobID, index: location.FragmentIndex}
		if row.Body == nil {
			prior, ok := old[row.RecordID]
			if !ok || prior.ref != ref || prior.row != fact || prior.physical != selected.physical ||
				prior.logical != selected.logical || prior.blob != selected.blob || prior.index != selected.index {
				return false
			}
			selected = prior
		} else {
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil || fragment.BlobID != location.BlobID || fragment.Index != location.FragmentIndex {
				return false
			}
			selected.count, selected.total, selected.whole = fragment.Count, fragment.TotalLength, fragment.WholeDigest
			selected.offset, selected.payloadLength = fragment.Offset, uint32(len(fragment.Payload))
		}
		if _, duplicate := next.fragmentFacts[location]; duplicate {
			return false
		}
		next.fragmentFacts[location] = selected
	}
	return true
}

func normalSupportPageMatchesFacts(domain contract.ID, view format.RequiredSupportPageView,
	facts []contract.SupportRecordDigest) bool {
	if len(view.Records) != len(facts) {
		return false
	}
	for i, row := range view.Records {
		fact, err := contract.InspectSupportRecordDigest(domain, contract.SupportRecord(row))
		if err != nil || fact != facts[i] {
			return false
		}
	}
	return true
}

func (next *StateSession) deriveNormalGeneratedAccess(c *Comparison, p transitionPlan) bool {
	var current []contract.CryptoCurrentSecret
	if c.operation != nil {
		request, ok := c.session.comparisonRequest(c, c.operation.context)
		if !ok {
			return false
		}
		current = request.Current
	}
	// Public-only work has no current secrets and needs no Crypto context.
	rows, err := c.support.AccessAfter(c.intent, current, c.preparedRows)
	if err != nil {
		return false
	}
	core, pages, err := c.support.AccessCoreAfter(rows, identityPlan(c, p))
	if err != nil {
		return false
	}
	recipients, err := recipientRefsDescriptor(next.root)
	if err != nil {
		return false
	}
	if recipients != core.RecipientRefsDescriptor {
		core.RecipientRefsDescriptor = recipients
		if core.AccessRecordsDescriptor == c.support.BeforeAccess.AccessRecordsDescriptor {
			if err := contract.AdvanceAccessGeneration(&core, p.transition); err != nil {
				return false
			}
		}
	}
	next.root.CurrentAccess.Core = core
	next.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(core)
	if err != nil {
		return false
	}
	next.root.AccessRecordCount = uint32(len(rows))
	if pages == nil {
		next.access = c.session.access
	} else {
		next.access = [contract.MaxChildPages]*format.AccessPage{}
		for _, page := range pages {
			next.access[page.Ref.Index] = &format.AccessPage{Domain: page.Ref.Domain, Object: page.Ref.Object, Index: page.Ref.Index, Records: page.Records}
		}
	}
	return true
}
