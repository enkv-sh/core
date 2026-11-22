package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (next *StateSession) installGeneratedFinalEntries(g *generatedSelection, plan *generatedFinalPlan,
	prepared map[uint16]contract.CryptoGeneratedValueEntryResult, supplied map[uint16]generatedFinalSuppliedEntry,
	support []contract.SupportRecord, phase contract.ID, candidate *Candidate, grants map[contract.ID][]contract.ID) error {
	before := g.session
	next.pages = [contract.MaxValueEntryPages]*format.ValueEntryPage{}
	next.root.ValueEntryPages = [contract.MaxValueEntryPages]*format.Ref{}
	next.root.Names = nil
	next.root.ValueEntryCount, next.root.SecretCount, next.root.RawBytes = 0, 0, 0
	next.root.MembershipCount, next.root.SecretOrdinaryWrapCount = 0, 0
	valueIDs := make(map[contract.ID]bool)
	readers := make(map[contract.ID][]contract.ID)
	var generated uint32
	for _, entryPlan := range g.bundles[0].ValueEntryPlans {
		var entry contract.ValueEntry
		if row, ok := prepared[entryPlan.Slot]; ok {
			entry = row.Entry
		} else if row, ok := supplied[entryPlan.Slot]; ok {
			entry = row.entry
		} else {
			current := before.valueEntry(entryPlan.Slot)
			if current == nil || current.Name != entryPlan.Name || current.Incarnation != entryPlan.EntryIncarnationID ||
				current.ValueSource != entryPlan.ValueSource || current.ConfidentialityClass != entryPlan.ConfidentialityClass {
				return contract.ErrRecord
			}
			entry = *current
			entry.OutputEncoding = entryPlan.OutputEncoding
		}
		membership, err := contract.GeneratorIntendedMembershipDescriptor(entry.Recipients)
		if err != nil || membership != entryPlan.IntendedMembership || entry.Name != entryPlan.Name ||
			entry.InputEncoding != entryPlan.InputEncoding || entry.OutputEncoding != entryPlan.OutputEncoding || entry.Incarnation != entryPlan.EntryIncarnationID || entry.ValueSource != entryPlan.ValueSource || entry.ConfidentialityClass != entryPlan.ConfidentialityClass {
			return contract.ErrRecord
		}
		entry.ValueBytes = bytes.Clone(entry.ValueBytes)
		entry.Recipients = slices.Clone(entry.Recipients)
		pageIndex := entryPlan.Slot / format.PageSlots
		if next.pages[pageIndex] == nil {
			id, err := contract.GeneratorPhasePageID(phase, format.ValueEntryPageKind, pageIndex)
			if err != nil {
				return err
			}
			next.pages[pageIndex] = &format.ValueEntryPage{Domain: next.root.Domain, Object: id, Index: pageIndex}
		}
		entryCopy := entry
		next.pages[pageIndex].Slots[entryPlan.Slot%format.PageSlots] = &entryCopy
		next.root.Names = append(next.root.Names, format.NameEntry{Name: entry.Name, Slot: entryPlan.Slot})
		next.root.ValueEntryCount++
		next.root.MembershipCount += uint32(len(entry.Recipients))
		if entry.ConfidentialityClass == contract.Secret {
			payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
			if err != nil {
				return err
			}
			next.root.SecretCount++
			next.root.RawBytes += uint64(payload.ContentLength)
			next.root.SecretOrdinaryWrapCount += uint32(len(entry.Recipients))
			valueIDs[entry.ValueState] = true
			readers[entry.ValueState] = append(readers[entry.ValueState], entry.Recipients...)
		} else {
			next.root.RawBytes += uint64(entry.ContentLength)
		}
		if entry.ValueSource == contract.Generated {
			generated++
		}
	}
	next.root.Generated.GeneratedCurrent = generated
	slices.SortFunc(next.root.Names, func(a, b format.NameEntry) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	next.root.ChildCount = 1 + uint32(len(next.root.AdministrativeIndexShards)) + uint32((int(next.root.RecipientCount)+format.RecipientSlots-1)/format.RecipientSlots)
	for i, page := range next.pages {
		if page == nil {
			continue
		}
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			return err
		}
		ref, err := format.Reference(format.ValueEntryPageKind, next.root.Domain, page.Object, uint16(i), body)
		if err != nil {
			return err
		}
		next.root.ValueEntryPages[i] = &ref
		next.root.ChildCount++
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	// The same closed support projection selects real retained consumers and
	// operation seeds. Do not retain dead active rows or drop unrelated owners.
	retained := make(map[materialIdentity]bool)
	for _, row := range support {
		switch row.Kind {
		case contract.OperationMaterialSupportKind:
			retained[materialIdentity{contract.OperationSeedMaterialKind, row.RecordID}] = true
		case contract.RetainedCanonicalSupportKind:
			canonical, err := contract.DecodeRetainedCanonicalRecord(row.Body)
			if err != nil {
				return contract.ErrRecord
			}
			retained[materialIdentity{contract.ValueMaterialKind, canonical.Entry.ValueState}] = true
			readers[canonical.Entry.ValueState] = append(readers[canonical.Entry.ValueState], canonical.Entry.Recipients...)
		}
	}
	replacedAccess := make(map[contract.ID]bool, len(prepared)+len(supplied))
	for _, row := range prepared {
		replacedAccess[row.Access.MaterialID] = true
	}
	for _, row := range supplied {
		if row.access != nil {
			replacedAccess[row.access.MaterialID] = true
		}
	}
	access := make([]contract.AccessRecord, 0, len(valueIDs)+len(retained))
	for _, row := range next.accessRecords() {
		needed := row.MaterialKind == contract.ValueMaterialKind && valueIDs[row.MaterialID] || retained[materialIdentity{row.MaterialKind, row.MaterialID}]
		if needed && (row.MaterialKind != contract.ValueMaterialKind || !replacedAccess[row.MaterialID]) {
			access = append(access, row)
		}
	}
	for _, row := range prepared {
		access = append(access, row.Access)
	}
	for _, row := range supplied {
		if row.access != nil {
			value := *row.access
			if row.currentOnlyReplay {
				original, ok := before.materialAccess(contract.ValueMaterialKind, value.MaterialID)
				if !ok || original.MaterialContextDigest != value.MaterialContextDigest || original.PackageCheck != value.PackageCheck {
					return contract.ErrRecord
				}
				value.Wraps = slices.Clone(value.Wraps)
				for _, wrap := range original.Wraps {
					if wrap.SubjectKind == contract.OrdinaryWrapSubject && slices.Contains(readers[value.MaterialID], wrap.SubjectID) &&
						!slices.Contains(row.entry.Recipients, wrap.SubjectID) {
						value.Wraps = append(value.Wraps, wrap)
					}
				}
				slices.SortFunc(value.Wraps, func(a, b contract.WrapRow) int {
					if a.SubjectKind != b.SubjectKind {
						return int(a.SubjectKind) - int(b.SubjectKind)
					}
					return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
				})
			}
			access = append(access, value)
		}
	}
	// Preparation preserves the predecessor's canonical obligations. Only the
	// closed support projection determines which readers survive actual Final.
	// This also covers carried entries that did not need a prepared row.
	for i := range access {
		row := &access[i]
		if row.MaterialKind != contract.ValueMaterialKind {
			continue
		}
		wanted := readers[row.MaterialID]
		slices.SortFunc(wanted, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		wanted = slices.Compact(wanted)
		row.Wraps = slices.DeleteFunc(slices.Clone(row.Wraps), func(w contract.WrapRow) bool {
			return w.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(wanted, w.SubjectID)
		})
		if !next.validateMaterialWraps(*row, wanted) {
			return contract.ErrRecord
		}
	}
	return next.packGeneratedFinalAccess(access, phase, candidate, grants)
}

func generatedFinalActiveHazards(g *generatedSelection) (map[contract.ID]bool, map[contract.ID]bool, error) {
	attempts, hazards := make(map[contract.ID]bool), make(map[contract.ID]bool)
	if g == nil || g.parent == nil {
		return attempts, hazards, contract.ErrRecord
	}
	for key, row := range g.records {
		if key.kind != contract.GeneratedHazardSupportKind {
			continue
		}
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return nil, nil, err
		}
		if hazard.OriginalOperationID == g.parent.OperationID {
			attempts[hazard.OriginalAttemptID] = true
			hazards[hazard.HazardID] = true
		}
	}
	return attempts, hazards, nil
}

func (s *StateSession) packGeneratedFinalAccess(rows []contract.AccessRecord, phase contract.ID, candidate *Candidate, grants map[contract.ID][]contract.ID) error {
	slices.SortFunc(rows, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	descriptor, err := contract.AccessRecordsDescriptor(s.root.Domain, rows)
	if err != nil {
		return err
	}
	var pages []format.AccessPage
	page := format.AccessPage{Domain: s.root.Domain}
	length := contract.AccessPageHeaderLength
	flush := func() error {
		if len(page.Records) == 0 {
			return nil
		}
		if len(pages) == contract.MaxChildPages {
			return contract.ErrRecordCapacity
		}
		page.Index = uint16(len(pages))
		page.Object, err = contract.GeneratorPhasePageID(phase, format.AccessKind, page.Index)
		if err != nil {
			return err
		}
		pages = append(pages, page)
		page, length = format.AccessPage{Domain: s.root.Domain}, contract.AccessPageHeaderLength
		return nil
	}
	for _, row := range rows {
		row.Wraps = slices.Clone(row.Wraps)
		for i := range row.Wraps {
			row.Wraps[i].RSACiphertext = bytes.Clone(row.Wraps[i].RSACiphertext)
		}
		size, err := contract.AccessRecordLength(row)
		if err != nil {
			return err
		}
		if length+size > contract.MaxAccessPageLength || len(page.Records) == contract.AccessPageRecordLimit {
			if err := flush(); err != nil {
				return err
			}
		}
		page.Records, length = append(page.Records, row), length+size
	}
	if err := flush(); err != nil {
		return err
	}
	s.root.CurrentAccess.Core.AccessPageRefs, s.access = nil, [contract.MaxChildPages]*format.AccessPage{}
	for i := range pages {
		page := &pages[i]
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			return err
		}
		ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			return err
		}
		s.access[i] = page
		s.root.CurrentAccess.Core.AccessPageRefs = append(s.root.CurrentAccess.Core.AccessPageRefs, ref)
		if len(grants) != 0 {
			base, rows, err := format.SplitGrantPage(*page, grants)
			if err != nil {
				return err
			}
			if len(rows) != 0 {
				body, err = format.EncodeAccessPage(base)
				if err != nil {
					return err
				}
				ref, err = format.Reference(format.AccessKind, base.Domain, base.Object, base.Index, body)
				if err != nil {
					return err
				}
				s.root.GrantPages = append(s.root.GrantPages, ref)
				candidate.head.GrantWraps = append(candidate.head.GrantWraps, rows...)
			}
		}
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	s.root.AccessRecordCount = uint32(len(rows))
	s.root.CurrentAccess.Core.AccessRecordsDescriptor = descriptor
	if err := contract.AdvanceAccessGeneration(&s.root.CurrentAccess.Core, phase); err != nil {
		return err
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	return err
}

func generatedSelectedFragmentBlob(row contract.SupportRecord, facts map[contract.ID]selectedFragmentFact) (contract.ID, error) {
	if row.Kind != contract.GeneratedFragmentSupportKind {
		return contract.ID{}, contract.ErrRecord
	}
	if len(row.Body) != 0 {
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil {
			return contract.ID{}, err
		}
		return fragment.BlobID, nil
	}
	fact, ok := facts[row.RecordID]
	if !ok || fact.row.Kind() != row.Kind || fact.row.RecordID() != row.RecordID {
		return contract.ID{}, contract.ErrRecord
	}
	return fact.blob, nil
}

func (s *StateSession) generatedFinalSupport(g *generatedSelection, plan *generatedFinalPlan,
	prepared []contract.CryptoGeneratedValueEntryResult, snapshot contract.ID) ([]contract.SupportRecord, []contract.GeneratorSliceLocation,
	[]contract.GeneratorPlanBundle, contract.GeneratorDescriptor, error) {
	if !plan.selecting {
		return s.generatedFailedFinalSupport(g, plan, snapshot)
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	active := g.parent.OperationID
	enclosed := len(contract.GeneratedAutomaticRetirementIndices(g.bundles[0])) != 0
	activeAttempts, activeDuties, activeLineages := make(map[contract.ID]bool), make(map[contract.ID]bool), make(map[contract.ID]bool)
	for _, lineage := range g.bundles[0].Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			activeLineages[lineage.LineageID] = true
		}
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			activeAttempts[x.AttemptID], activeDuties[x.DutyID] = true, true
		}
	}
	hazardAttempts, activeHazards, err := generatedFinalActiveHazards(g)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	var currentMetadata []contract.GeneratedEntryMetadata
	for _, entryPlan := range g.bundles[0].ValueEntryPlans {
		if entryPlan.ValueSource != contract.Generated {
			continue
		}
		if at := slices.IndexFunc(prepared, func(row contract.CryptoGeneratedValueEntryResult) bool { return row.Slot == entryPlan.Slot }); at >= 0 {
			currentMetadata = append(currentMetadata, prepared[at].Entry.Generated)
		} else {
			entry := s.valueEntry(entryPlan.Slot)
			if entry == nil || entry.ValueSource != contract.Generated || entry.Name != entryPlan.Name {
				return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
			}
			currentMetadata = append(currentMetadata, entry.Generated)
		}
	}
	keptCanonical := make(map[contract.ID]bool)
	var canonicalRows []contract.SupportRecord
	for key, row := range g.records {
		if key.kind != contract.RetainedCanonicalSupportKind {
			continue
		}
		canonical, err := contract.InspectRetainedCanonicalRecord(row.Body)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		for _, consumer := range g.consumers[materialIdentity{contract.ValueMaterialKind, canonical.Entry.ValueState}] {
			if consumer.SubjectID != row.RecordID || consumer.SubjectKind != contract.GeneratorConsumerRetainedCanonicalValue {
				continue
			}
			if dutyRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: consumer.OwnerID}]; ok {
				duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
				if err != nil {
					return nil, nil, nil, contract.GeneratorDescriptor{}, err
				}
				keptCanonical[row.RecordID] = keptCanonical[row.RecordID] || duty.OriginalOperationID != active
			}
			if hazardRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: consumer.OwnerID}]; ok {
				hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
				if err != nil {
					return nil, nil, nil, contract.GeneratorDescriptor{}, err
				}
				keptCanonical[row.RecordID] = keptCanonical[row.RecordID] || hazard.OriginalOperationID != active || activeHazards[hazard.HazardID]
			}
		}
		if keptCanonical[row.RecordID] {
			canonicalRows = append(canonicalRows, row)
		}
	}
	neededLocalEvidence, err := contract.LocalGeneratedEvidenceNeeded(currentMetadata, canonicalRows)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	wantedIntents := make(map[contract.ID]bool)
	for _, attempt := range g.attempts {
		if attempt.record.OperationID != active {
			wantedIntents[attempt.expected.Template.IntentDigest] = true
		}
	}
	activeSupport := make(map[contract.GeneratorDescriptor]bool)
	for attemptID := range hazardAttempts {
		attempt, ok := g.attempts[attemptID]
		if !ok {
			return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		wantedIntents[attempt.expected.Template.IntentDigest] = true
		activeSupport[attempt.record.Support] = true
	}
	for hazardID := range activeHazards {
		row, ok := g.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: hazardID}]
		if !ok {
			return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		hazard, inspectErr := contract.InspectGeneratedHazardRecord(row.Body)
		if inspectErr != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, inspectErr
		}
		activeSupport[hazard.Support] = true
	}
	replacedEvidence := make(map[contract.ID]bool, len(prepared))
	var rows []contract.SupportRecord
	for _, result := range prepared {
		index := slices.IndexFunc(plan.entryPlans, func(v contract.CryptoGeneratedValueEntryPlan) bool { return v.Slot == result.Slot })
		if index < 0 {
			return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		input := plan.entryPlans[index]
		original, err := contract.DecodeGeneratedResultRecord(input.Result)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		attempt, ok := g.attempts[original.Core.AttemptID]
		if !ok || !bytes.Equal(attempt.result, input.Result) || attempt.expected.Template.ResultID != result.ResultID {
			return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		core, err := contract.EncodeGeneratedResultCore(original.Core)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		facts, err := contract.EncodeGeneratorSafeFacts(original.SafeFacts)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		key := generatedContentKey{contract.GeneratorContentIntent, input.Generated.IntentDigest}
		location, ok := g.content.locations[key]
		if !ok {
			return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		evidence := contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema, OriginalResultID: result.ResultID, CredentialRouteID: attempt.expected.Template.CredentialRouteID, ResultCore: core, SafeFacts: facts,
			CompletionClass: input.Generated.CompletionClass}
		evidence.LifecycleMode = input.Generated.LifecycleMode
		evidence.Intent, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical()})
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		body, err := contract.EncodeGeneratedCreateEvidence(evidence)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedCreateEvidenceSupportKind, RecordID: result.ResultID, Body: body})
		replacedEvidence[result.ResultID] = true
		wantedIntents[input.Generated.IntentDigest] = true
	}
	for key, row := range g.records {
		if key.kind != contract.GeneratedCreateEvidenceSupportKind || replacedEvidence[row.RecordID] {
			continue
		}
		evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		if evidence.LifecycleMode == contract.GeneratorLifecycleNone && !neededLocalEvidence[row.RecordID] {
			continue
		}
		facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		wantedIntents[facts.IntentDigest] = true
	}
	for _, m := range currentMetadata {
		wantedIntents[m.IntentDigest] = true
	}
	var bundles []contract.GeneratorPlanBundle
	for _, bundle := range g.bundles {
		if enclosed || bundle.Header.OperationID != active || len(hazardAttempts) != 0 {
			bundles = append(bundles, bundle)
		}
	}
	keepLocation := make(map[generatedContentKey]bool)
	for key, location := range g.content.locations {
		keep := key.kind == contract.GeneratorContentIntent && wantedIntents[key.id]
		if key.kind == contract.GeneratorContentDeclaration && (enclosed || key.id != active) ||
			key.kind == contract.GeneratorContentGraph && (enclosed || key.id != g.parent.PlanGraphID || len(hazardAttempts) != 0) ||
			key.kind == contract.GeneratorContentConfiguration && key.id != g.parent.MaterialID ||
			enclosed && (key.kind == contract.GeneratorContentRecipientRegistry || key.kind == contract.GeneratorContentOutputConfiguration) && key.id == active {
			keep = true
		}
		if keep {
			keepLocation[key] = true
			_ = location
		}
	}
	var locations []contract.GeneratorSliceLocation
	usedBlobs := make(map[contract.ID]bool)
	receiptIndex, err := s.receiptIndexID()
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	if !receiptIndex.IsZero() {
		usedBlobs[receiptIndex] = true
	}
	for key := range keepLocation {
		location := g.content.locations[key]
		locations = append(locations, location)
		usedBlobs[location.BlobID] = true
	}
	locations, _ = generatedUniqueLocations(locations)
	for _, row := range s.supportRecords() {
		keep := true
		switch row.Kind {
		case contract.OperationMaterialSupportKind:
			keep = enclosed || row.RecordID != g.parent.MaterialID || len(hazardAttempts) != 0
		case contract.GeneratedParentSupportKind, contract.GeneratedPhaseSupportKind:
			keep = enclosed || row.RecordID != active
		case contract.GeneratedFinalPreparationSupportKind:
			keep = row.RecordID != active
		case contract.GeneratedFragmentSupportKind:
			blob, err := generatedSelectedFragmentBlob(row, fragments)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = usedBlobs[blob]
		case contract.GeneratedResultSupportKind:
			result, err := contract.InspectGeneratedResultRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = enclosed || result.Core.OperationID != active || hazardAttempts[result.Core.AttemptID]
		case contract.RetainedCanonicalSupportKind:
			keep = keptCanonical[row.RecordID]
		case contract.GeneratedLineageSupportKind:
			keep = enclosed || !activeLineages[row.RecordID]
		case contract.GeneratedAttemptSupportKind:
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = enclosed || attempt.OperationID != active || hazardAttempts[attempt.AttemptID]
		case contract.GeneratedDutySupportKind:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = duty.OriginalOperationID != active || enclosed && duty.Kind == contract.GeneratedDutyCreate
		case contract.GeneratedHazardSupportKind:
			hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = hazard.OriginalOperationID != active || activeHazards[hazard.HazardID]
		case contract.GeneratedCreateEvidenceSupportKind:
			evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = !replacedEvidence[row.RecordID] && (evidence.LifecycleMode != contract.GeneratorLifecycleNone || neededLocalEvidence[row.RecordID])
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			switch {
			case carrier.VectorKind == contract.GeneratorVectorSlices:
				keep = false
			case carrier.OwnerKind == contract.GeneratedAttemptSupportKind && activeAttempts[carrier.OwnerID]:
				keep = enclosed || hazardAttempts[carrier.OwnerID]
			case carrier.OwnerKind == contract.GeneratedHazardSupportKind && activeHazards[carrier.OwnerID]:
				keep = true
			case carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == active:
				keep = carrier.VectorKind == contract.GeneratorVectorSupport && (enclosed || activeSupport[carrier.Vector])
			default:
				keep = carrier.OwnerID != active && (enclosed || !activeDuties[carrier.OwnerID] && !activeLineages[carrier.OwnerID])
			}
		}
		if keep {
			rows = append(rows, row)
		}
	}
	retirementRows, err := s.generatedFinalRetirementRows(plan)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	rows = append(rows, retirementRows...)
	if enclosed {
		rows, err = generatedEndCreateInputConsumers(g, rows)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
	}
	var sliceBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		sliceBodies = append(sliceBodies, body)
	}
	descriptor, carriers, err := generatedCarrierRows(s.root.Domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	rows = append(rows, carriers...)
	return rows, locations, bundles, descriptor, nil
}

func (s *StateSession) generatedFinalRetirementRows(plan *generatedFinalPlan) ([]contract.SupportRecord, error) {
	if s == nil || plan == nil {
		return nil, contract.ErrRecord
	}
	var rows []contract.SupportRecord
	for _, retirement := range plan.retirements {
		x, target := retirement.template, retirement.target
		body, err := contract.EncodeGeneratorTarget(target)
		if err != nil {
			return nil, err
		}
		targets, carriers, err := generatedCarrierRows(s.root.Domain, contract.GeneratedDutySupportKind, x.DutyID, contract.GeneratorVectorTargets, [][]byte{body})
		if err != nil {
			return nil, err
		}
		empty := contract.EmptyGeneratorVector
		duty := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, DomainID: s.root.Domain, DutyID: x.DutyID, OwnerID: x.DutyID,
			OriginalOperationID: target.OriginalOperationID, OriginalAttemptID: target.OriginalAttemptID,
			ResourceID: target.ResourceID, ConfigContractID: target.ConfigContractID, ResourceContractID: target.ResourceContractID,
			ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID, DescriptorID: x.DescriptorID,
			ResultContractID: x.ResultContractID, Kind: contract.GeneratedDutyRetirement, CompletionClass: target.CompletionClass,
			Step: 1, Status: contract.GeneratedEffectNotStarted, CapacityReservation: plan.request.Parent.Capacity, Target: targets,
			Progress: empty(contract.GeneratorVectorProgress), History: empty(contract.GeneratorVectorHistory),
			Support: retirement.support, Consumers: empty(contract.GeneratorVectorConsumers)}
		duty.LifecycleMode = x.LifecycleMode
		body, err = contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			return nil, err
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: duty.DutyID, Body: body})
		rows = append(rows, carriers...)
	}
	return rows, nil
}

func generatedRowsContainMaterial(rows []contract.SupportRecord, material contract.ID) bool {
	return slices.ContainsFunc(rows, func(row contract.SupportRecord) bool {
		return row.Kind == contract.OperationMaterialSupportKind && row.RecordID == material
	})
}

// A failed parent detaches only the work that remains actionable. Successful
// creates become cleanup Duties. Owned-unusable creates retain their exact
// resource Hazard and original-result readers; failed selection is not proof
// of no provider effect. Unrelated live work and receipts remain unchanged.
func (s *StateSession) generatedFailedFinalSupport(g *generatedSelection, plan *generatedFinalPlan, snapshot contract.ID) (
	[]contract.SupportRecord, []contract.GeneratorSliceLocation, []contract.GeneratorPlanBundle, contract.GeneratorDescriptor, error) {
	if g == nil || g.parent == nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	active := g.parent.OperationID
	successAttempts := make(map[contract.ID]bool)
	successDuties := make(map[contract.ID]bool)
	releasedAttempts := make(map[contract.ID]contract.GeneratedAttemptRecord)
	var releasedRows []contract.SupportRecord
	ownedAttempts := make(map[contract.ID]bool)
	var ownedRows []contract.SupportRecord
	for _, selected := range plan.results {
		result, err := contract.InspectGeneratedResultRecord(selected.attempt.result)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		if selected.attempt.record.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			a := selected.attempt
			row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.record.OwnerID}]
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if !ok || err != nil || !generatedCreateDutyMatches(duty, a.record) || !generatedAttemptMatches(a.record, a.expected.Template) ||
				!result.MatchesLocalCreateAttempt(a.record) {
				return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
			}
			phase, err := contract.GeneratorPhaseID(plan.phase)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			revision, err := contract.GeneratorPhaseRevisionID(phase)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			mapping := a.record
			mapping.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
			mapping.History = contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
			body, err := contract.EncodeGeneratedAttemptRecord(mapping)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			release, err := contract.EncodePendingInboxReleaseRecord(contract.PendingInboxReleaseRecord{Schema: 1,
				DomainID: mapping.DomainID, InboxID: mapping.InboxID, OriginalResultID: mapping.ResultID,
				SelectedHandoffDigest: contract.Hash(a.result), HandoffRevisionID: revision, ObjectLength: uint32(len(a.result)),
				CapacityReservation: duty.CapacityReservation, State: contract.GeneratedReleasePending})
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			releasedAttempts[mapping.AttemptID] = mapping
			releasedRows = append(releasedRows, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: mapping.AttemptID, Body: body},
				contract.SupportRecord{Kind: contract.PendingInboxReleaseSupportKind, RecordID: mapping.InboxID, Body: release})
			continue
		}
		if result.Disposition() == contract.GeneratorDispositionCompleteCreate {
			successAttempts[selected.attempt.record.AttemptID] = true
			successDuties[selected.attempt.record.OwnerID] = true
		}
		if result.Disposition() == contract.GeneratorDispositionOwnedUnusableCreate {
			a := selected.attempt
			row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.record.OwnerID}]
			d, err := contract.InspectGeneratedDutyRecord(row.Body)
			if !ok || err != nil || !generatedCreateDutyMatches(d, a.record) || len(result.SafeFacts.Target) == 0 || len(result.SafeFacts.ResourceData) == 0 ||
				a.record.State != contract.GeneratedEffectFailedTerminal || a.expected.Template.Action != contract.GeneratorActionCreate {
				return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
			}
			h := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: d.DomainID, HazardID: a.expected.Template.HazardID,
				OriginalOperationID: d.OriginalOperationID, OriginalAttemptID: d.OriginalAttemptID, OwnerID: d.OwnerID,
				ResourceID: d.ResourceID, ConfigContractID: d.ConfigContractID, ResourceContractID: d.ResourceContractID, ExecutorID: d.ExecutorID,
				CredentialRouteID: d.CredentialRouteID, DescriptorID: d.DescriptorID, ResultContractID: d.ResultContractID,
				Exposure: contract.GeneratedExposureLateEffect, CompletionClass: d.CompletionClass, Fenced: 1,
				Eligibility: contract.GeneratedExposureLateEffect, CapacityReservation: d.CapacityReservation, Support: d.Support}
			h.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, d.DomainID,
				[]contract.SupportRecord{{Kind: contract.GeneratedResultSupportKind, RecordID: a.record.ResultID, Body: a.result}})
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			for _, vector := range []struct {
				kind   contract.GeneratorVectorKind
				before contract.GeneratorDescriptor
				after  *contract.GeneratorDescriptor
			}{{contract.GeneratorVectorTargets, d.Target, &h.Target}, {contract.GeneratorVectorHistory, d.History, &h.History},
				{contract.GeneratorVectorConsumers, d.Consumers, &h.Consumers}} {
				bodies, err := g.vectors.resolve(contract.GeneratedDutySupportKind, d.DutyID, vector.kind, vector.before)
				if err != nil {
					return nil, nil, nil, contract.GeneratorDescriptor{}, err
				}
				if vector.kind == contract.GeneratorVectorConsumers {
					var retained [][]byte
					for _, body := range bodies {
						c, err := contract.InspectGeneratorConsumer(body)
						if err != nil {
							return nil, nil, nil, contract.GeneratorDescriptor{}, err
						}
						if c.SubjectKind == contract.GeneratorConsumerOriginalResult && c.Purpose != contract.GeneratorConsumerAdoptLateOriginalResult {
							continue
						}
						c.OwnerID = h.HazardID
						body, err = contract.EncodeGeneratorConsumer(c)
						if err != nil {
							return nil, nil, nil, contract.GeneratorDescriptor{}, err
						}
						retained = append(retained, body)
					}
					bodies = retained
				}
				var carriers []contract.SupportRecord
				*vector.after, carriers, err = generatedCarrierRows(d.DomainID, contract.GeneratedHazardSupportKind, h.HazardID, vector.kind, bodies)
				if err != nil {
					return nil, nil, nil, contract.GeneratorDescriptor{}, err
				}
				ownedRows = append(ownedRows, carriers...)
			}
			body, err := contract.EncodeGeneratedHazardRecord(h)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			ownedRows = append(ownedRows, contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: h.HazardID, Body: body})
			ownedAttempts[a.record.AttemptID] = true
		}
	}
	hazardAttempts := make(map[contract.ID]bool)
	for id := range ownedAttempts {
		hazardAttempts[id] = true
	}
	for _, row := range s.supportRecords() {
		if row.Kind != contract.GeneratedHazardSupportKind {
			continue
		}
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		if hazard.OriginalOperationID == active {
			hazardAttempts[hazard.OriginalAttemptID] = true
		}
	}
	cleanupBodies := make(map[contract.ID][]byte, len(successDuties))
	var cleanupCarriers []contract.SupportRecord
	for dutyID := range successDuties {
		row, ok := g.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: dutyID}]
		if !ok {
			return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		consumers, err := g.vectors.resolve(contract.GeneratedDutySupportKind, dutyID, contract.GeneratorVectorConsumers, duty.Consumers)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		kept := consumers[:0]
		for _, body := range consumers {
			consumer, err := contract.InspectGeneratorConsumer(body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			if consumer.SubjectKind != contract.GeneratorConsumerOriginalResult || consumer.Purpose == contract.GeneratorConsumerAdoptLateOriginalResult {
				kept = append(kept, body)
			}
		}
		var consumersRows []contract.SupportRecord
		duty.Consumers, consumersRows, err = generatedCarrierRows(s.root.Domain, contract.GeneratedDutySupportKind, dutyID, contract.GeneratorVectorConsumers, kept)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		cleanupCarriers = append(cleanupCarriers, consumersRows...)
		duty.Kind = contract.GeneratedDutyUnselectedCleanup
		cleanupBodies[dutyID], err = contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
	}
	retainActive := len(successAttempts) != 0 || len(hazardAttempts) != 0
	retainGraph := retainActive || len(releasedAttempts) != 0
	var rows []contract.SupportRecord
	for _, row := range s.supportRecords() {
		keep := true
		switch row.Kind {
		case contract.OperationMaterialSupportKind:
			keep = row.RecordID != g.parent.MaterialID || retainActive
		case contract.GeneratedParentSupportKind, contract.GeneratedPhaseSupportKind, contract.GeneratedFinalPreparationSupportKind:
			keep = row.RecordID != active
		case contract.GeneratedResultSupportKind:
			result, err := contract.InspectGeneratedResultRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = result.Core.OperationID != active || successAttempts[result.Core.AttemptID] || hazardAttempts[result.Core.AttemptID]
		case contract.GeneratedLineageSupportKind:
			lineage, err := contract.InspectGeneratedLineageRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = lineage.OperationID != active
		case contract.GeneratedAttemptSupportKind:
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			keep = attempt.OperationID != active || successAttempts[attempt.AttemptID] || hazardAttempts[attempt.AttemptID]
		case contract.GeneratedDutySupportKind:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			if duty.OriginalOperationID == active {
				keep = successDuties[duty.DutyID]
				if keep {
					row.Body = cleanupBodies[duty.DutyID]
				}
			}
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			switch {
			case carrier.VectorKind == contract.GeneratorVectorSlices:
				keep = false
			case carrier.OwnerKind == contract.GeneratedAttemptSupportKind:
				owner, ok := g.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, carrier.OwnerID}]
				if !ok {
					return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
				}
				a, err := contract.InspectGeneratedAttemptRecord(owner.Body)
				if err != nil {
					return nil, nil, nil, contract.GeneratorDescriptor{}, err
				}
				keep = a.OperationID != active || successAttempts[carrier.OwnerID] || hazardAttempts[carrier.OwnerID]
			case carrier.OwnerKind == contract.GeneratedDutySupportKind:
				owner, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, carrier.OwnerID}]
				if !ok {
					return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
				}
				d, err := contract.InspectGeneratedDutyRecord(owner.Body)
				if err != nil {
					return nil, nil, nil, contract.GeneratorDescriptor{}, err
				}
				keep = d.OriginalOperationID != active || successDuties[carrier.OwnerID] && carrier.VectorKind != contract.GeneratorVectorConsumers
			case carrier.OwnerKind == contract.GeneratedLineageSupportKind:
				owner, ok := g.records[generatedRecordKey{contract.GeneratedLineageSupportKind, carrier.OwnerID}]
				if !ok {
					return nil, nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
				}
				l, err := contract.InspectGeneratedLineageRecord(owner.Body)
				if err != nil {
					return nil, nil, nil, contract.GeneratorDescriptor{}, err
				}
				keep = l.OperationID != active
			case carrier.OwnerID == active:
				keep = carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.VectorKind == contract.GeneratorVectorSupport
			}
		}
		if keep {
			rows = append(rows, row)
		}
	}
	rows = append(rows, cleanupCarriers...)
	rows = append(rows, ownedRows...)
	rows = append(rows, releasedRows...)
	vectors, err := newGeneratedVectorSet(s.root.Domain, rows)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	retainedSupport, err := g.generatedSupportOwners(rows, vectors)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	keptSupport := rows[:0]
	for _, row := range rows {
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			if carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == active &&
				carrier.VectorKind == contract.GeneratorVectorSupport &&
				!retainedSupport[generatedVectorKey{carrier.OwnerKind, carrier.OwnerID, carrier.VectorKind, carrier.Vector}] {
				continue
			}
		}
		keptSupport = append(keptSupport, row)
	}
	rows = keptSupport
	var bundles []contract.GeneratorPlanBundle
	for _, bundle := range g.bundles {
		if bundle.Header.OperationID != active || retainGraph {
			bundles = append(bundles, bundle)
		}
	}
	wantedIntents := make(map[contract.ID]bool, len(successAttempts)+len(hazardAttempts))
	for _, a := range g.attempts {
		if a.record.OperationID != active {
			wantedIntents[a.expected.Template.IntentDigest] = true
		}
	}
	for attempt := range successAttempts {
		wantedIntents[g.attempts[attempt].expected.Template.IntentDigest] = true
	}
	for attempt := range hazardAttempts {
		wantedIntents[g.attempts[attempt].expected.Template.IntentDigest] = true
	}
	for _, row := range rows {
		if row.Kind != contract.GeneratedCreateEvidenceSupportKind {
			continue
		}
		evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		wantedIntents[facts.IntentDigest] = true
	}
	for _, entry := range s.root.Names {
		valueEntry := s.valueEntry(entry.Slot)
		if valueEntry != nil && valueEntry.ValueSource == contract.Generated {
			wantedIntents[valueEntry.Generated.IntentDigest] = true
		}
	}
	locations := make([]contract.GeneratorSliceLocation, 0, len(g.content.locations))
	usedBlobs := make(map[contract.ID]bool)
	for key, location := range g.content.locations {
		keep := key.kind == contract.GeneratorContentIntent && wantedIntents[key.id]
		if key.kind == contract.GeneratorContentGraph && key.id == g.parent.PlanGraphID {
			keep = retainGraph
		} else if key.kind == contract.GeneratorContentDeclaration && key.id != active ||
			key.kind == contract.GeneratorContentGraph && key.id != g.parent.PlanGraphID ||
			key.kind == contract.GeneratorContentConfiguration && key.id != g.parent.MaterialID {
			keep = true
		}
		if keep {
			locations = append(locations, location)
			usedBlobs[location.BlobID] = true
		}
	}
	receiptIndex, err := s.receiptIndexID()
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	if !receiptIndex.IsZero() {
		usedBlobs[receiptIndex] = true
	}
	filtered := rows[:0]
	for _, row := range rows {
		if row.Kind == contract.GeneratedFragmentSupportKind {
			blob, err := generatedSelectedFragmentBlob(row, fragments)
			if err != nil {
				return nil, nil, nil, contract.GeneratorDescriptor{}, err
			}
			if !usedBlobs[blob] {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	rows = filtered
	locations, err = generatedUniqueLocations(locations)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	var sliceBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			return nil, nil, nil, contract.GeneratorDescriptor{}, err
		}
		sliceBodies = append(sliceBodies, body)
	}
	descriptor, carriers, err := generatedCarrierRows(s.root.Domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		return nil, nil, nil, contract.GeneratorDescriptor{}, err
	}
	rows = append(rows, carriers...)
	return rows, locations, bundles, descriptor, nil
}

func (s *StateSession) generatedFinalSubject(ctx context.Context, next *StateSession, g *generatedSelection, plan *generatedFinalPlan,
	head format.HeadCore, phase, revision contract.ID) (contract.GeneratorAuthoritySubject, error) {
	parent := *g.parent
	subject := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityFinal,
		DomainID: parent.DomainID, OperationID: parent.OperationID, RequestIdentityDigest: parent.RequestIdentityDigest,
		PlanGraphID: parent.PlanGraphID, UsePlanDigest: parent.UsePlanDigest, PhaseID: phase,
		PreviousHEADDigest: contract.Hash(s.body), PreviousRevisionID: s.head.Core.Revision,
		ConditionDigest: plan.phase.ConditionDigest, BeforeRootDigest: s.head.Core.Root.Digest, AfterRootDigest: head.Root.Digest,
		BeforeAccessDigest: s.root.CurrentAccess.AccessRoot, AfterAccessDigest: next.root.CurrentAccess.AccessRoot,
		OwnerID: parent.OperationID, Intent: parent.Declaration, CapacityReservation: parent.Capacity,
		BeforePhase: plan.phase.BeforePhase, AfterPhase: plan.phase.AfterPhase}
	identity := contract.IdentityPlan{Operation: parent.OperationID, Snapshot: next.root.Snapshot, Transition: next.root.Transition, Revision: revision}
	for _, ref := range next.root.Recipients {
		if ref != nil {
			id, e := contract.GeneratorPhasePageID(phase, contract.RecipientKind, ref.Index)
			if e == nil && id == ref.Object {
				identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
			}
		}
	}
	for i, ref := range next.root.ValueEntryPages {
		if ref != nil {
			identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: uint16(i), Object: ref.Object})
		}
	}
	for _, ref := range next.root.CurrentAccess.Core.AccessPageRefs {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	for _, ref := range next.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	var err error
	slices.SortFunc(identity.Pages, func(a, b contract.IdentityPage) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return int(a.Index) - int(b.Index)
	})
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		return subject, err
	}
	entryUnionRows := generatedEntryUnion(s, next)
	subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(s.root.Domain, entryUnionRows)
	if err != nil {
		return subject, err
	}
	var membership []contract.UnionRow
	if plan.selecting {
		var declaration []byte
		if len(s.fragmentFacts) != 0 {
			declaration, err = g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, parent.OperationID, contract.GeneratorDeclarationMaxLength)
		} else {
			declaration, err = g.content.read(contract.GeneratorContentDeclaration, parent.OperationID, contract.GeneratorDeclarationMaxLength)
		}
		if err != nil {
			return subject, err
		}
		membership, err = s.generatedMembershipPlan(g.bundles[0], declaration)
		if err != nil {
			return subject, err
		}
	} else {
		membership = s.generatedUnchangedEntryUnion()
		for i := range membership {
			membership[i].After.EntryDigest = contract.ID{}
		}
	}
	subject.RequiredAuthoritySet = generatedMembershipAuthority(membership)
	subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(s.root.Domain, membership)
	if err != nil {
		return subject, err
	}
	before, err := s.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	after, err := next.workSupportRecords(ctx)
	if err != nil {
		return subject, err
	}
	subject.BeforeWork, err = s.workSupportDescriptor(before)
	if err != nil {
		return subject, err
	}
	subject.AfterWork, err = next.workSupportDescriptor(after)
	if err != nil {
		return subject, err
	}
	references := make([]contract.GeneratorResultReference, len(plan.results))
	for i := range plan.results {
		references[i] = plan.results[i].reference
	}
	slices.SortFunc(references, func(a, b contract.GeneratorResultReference) int { return bytes.Compare(a.ResultID[:], b.ResultID[:]) })
	results, err := contract.GeneratorResultReferencesDescriptor(references)
	if err != nil {
		return subject, err
	}
	subject.ResultVector = contract.GeneratorDescriptor(results)
	headBody, err := format.EncodeHeadCore(head)
	if err != nil {
		return subject, err
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head, headBody))
	if err != nil {
		return subject, err
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(headBody), uint32(len(headBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(conditionalBody), uint32(len(conditionalBody))
	_, err = contract.NewGeneratorRequest(subject)
	return subject, err
}

func generatedEntryUnion(before, after *StateSession) []contract.UnionRow {
	rows := make(map[string]contract.UnionRow, len(before.root.Names)+len(after.root.Names))
	for _, entry := range before.root.Names {
		valueEntry := before.valueEntry(entry.Slot)
		row := membership(before.root.Domain, entry.Slot, valueEntry)
		rows[entry.Name] = contract.UnionRow{Name: entry.Name, BeforePresent: true, Before: row.Side()}
	}
	for _, entry := range after.root.Names {
		valueEntry := after.valueEntry(entry.Slot)
		row := membership(after.root.Domain, entry.Slot, valueEntry)
		value := rows[entry.Name]
		value.Name, value.AfterPresent, value.After = entry.Name, true, row.Side()
		rows[entry.Name] = value
	}
	out := make([]contract.UnionRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b contract.UnionRow) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	return out
}
