package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

type generatedFinalOperationalResult struct {
	effects, duties, hazards []contract.SupportRecord
	classes                  map[contract.ID]int
	relatedDuties            map[contract.ID]bool
}

func generatedFinalChangedSubjects(ctx context.Context, before, after *StateSession) (contract.GeneratorDescriptor, error) {
	return generatedChangedSubjects(ctx, before, after, nil)
}

func generatedChangedSubjects(ctx context.Context, before, after *StateSession, detail *changeObservation) (contract.GeneratorDescriptor, error) {
	return generatedChangedSubjectsCollect(ctx, before, after, detail, nil)
}

func generatedChangedSubjectsCollect(ctx context.Context, before, after *StateSession, detail *changeObservation, subjects *[]contract.ChangedSubjectIdentity) (contract.GeneratorDescriptor, error) {
	type selected struct {
		entry  contract.ValueEntry
		digest contract.ID
	}
	read := func(s *StateSession) (map[string]selected, error) {
		out := make(map[string]selected, len(s.root.Names))
		for _, entry := range s.root.Names {
			valueEntry := s.valueEntry(entry.Slot)
			if valueEntry == nil {
				return nil, contract.ErrRecord
			}
			digest, err := contract.PublicValueEntryDigest(s.root.Domain, entry.Slot, *valueEntry)
			if err != nil {
				return nil, err
			}
			out[entry.Name] = selected{entry: *valueEntry, digest: digest}
		}
		return out, nil
	}
	old, err := read(before)
	if err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	current, err := read(after)
	if err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	if detail != nil {
		memberships, generations := 0, 0
		for _, side := range []map[string]selected{old, current} {
			for _, entry := range side {
				memberships += len(entry.entry.Recipients)
				if entry.entry.ValueSource == contract.Generated {
					generations++
				}
			}
		}
		detail.Entries = make([]observationEntry, 0, len(old)+len(current))
		detail.Names = make([]observationName, 0, len(old)+len(current))
		detail.Memberships = make([]observationMembership, 0, memberships)
		detail.Subjects = make([]observationSubject, 0, len(old)+len(current)+memberships+generations)
		detail.Generations = make([]observationGeneration, 0, generations)
	}
	var rows []contract.ChangedSubjectIdentity
	var fields observationFields
	appendIdentity := func(kind, change uint8, primary, secondary contract.ID) error {
		identity, err := contract.ChangedSubjectIdentityID(before.root.Domain, kind, primary, secondary)
		if err != nil {
			return err
		}
		row := contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: identity}
		rows = append(rows, row)
		if detail != nil {
			rowFields := fields
			if kind == contract.ChangedSubjectMembership {
				rowFields = observationFieldMembership
			}
			if kind == contract.ChangedSubjectGeneratedValue {
				rowFields = observationFieldGeneration
			}
			detail.Subjects = append(detail.Subjects, observationSubject{Row: row, PrimaryID: primary, SecondaryID: secondary, Fields: rowFields})
			if kind == contract.ChangedSubjectMembership {
				detail.Memberships = append(detail.Memberships, observationMembership{EntryIncarnationID: primary, RecipientID: secondary, Change: change})
			}
		}
		return nil
	}
	names := make([]string, 0, len(old)+len(current))
	for name := range old {
		names = append(names, name)
	}
	for name := range current {
		if _, exists := old[name]; !exists {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		prior, beforePresent := old[name]
		next, afterPresent := current[name]
		if detail != nil {
			var beforeEntry, afterEntry *contract.ValueEntry
			if beforePresent {
				beforeEntry = &prior.entry
			}
			if afterPresent {
				afterEntry = &next.entry
			}
			fields = entryObservationFields(beforeEntry, afterEntry)
			entry := observationEntry{BeforePresent: beforePresent, AfterPresent: afterPresent}
			if beforePresent {
				entry.BeforeIncarnationID, entry.BeforeSource, entry.BeforeConfidentiality = prior.entry.Incarnation, prior.entry.ValueSource, prior.entry.ConfidentialityClass
				detail.Names = append(detail.Names, observationName{EntryIncarnationID: prior.entry.Incarnation, Name: name, Side: observationBefore})
				if prior.entry.ValueSource == contract.Generated {
					detail.Generations = append(detail.Generations, observationGeneration{EntryIncarnationID: prior.entry.Incarnation, GenerationID: prior.entry.Generated.GenerationID, Side: observationBefore})
				}
			}
			if afterPresent {
				entry.AfterIncarnationID, entry.AfterSource, entry.AfterConfidentiality = next.entry.Incarnation, next.entry.ValueSource, next.entry.ConfidentialityClass
				detail.Names = append(detail.Names, observationName{EntryIncarnationID: next.entry.Incarnation, Name: name, Side: observationAfter})
				if next.entry.ValueSource == contract.Generated {
					detail.Generations = append(detail.Generations, observationGeneration{EntryIncarnationID: next.entry.Incarnation, GenerationID: next.entry.Generated.GenerationID, Side: observationAfter})
				}
			}
			detail.Entries = append(detail.Entries, entry)
		}
		switch {
		case !beforePresent:
			if err := appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, next.entry.Incarnation, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		case !afterPresent:
			if err := appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, prior.entry.Incarnation, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		case prior.entry.Incarnation != next.entry.Incarnation:
			if err := appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, prior.entry.Incarnation, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
			if err := appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, next.entry.Incarnation, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		case prior.digest != next.digest:
			if err := appendIdentity(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, next.entry.Incarnation, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		}
		beforeRecipients, afterRecipients := map[contract.ID]bool{}, map[contract.ID]bool{}
		if beforePresent {
			for _, recipient := range prior.entry.Recipients {
				beforeRecipients[recipient] = true
			}
		}
		if afterPresent {
			for _, recipient := range next.entry.Recipients {
				afterRecipients[recipient] = true
			}
		}
		for recipient := range beforeRecipients {
			if !afterRecipients[recipient] || !afterPresent || prior.entry.Incarnation != next.entry.Incarnation {
				if err := appendIdentity(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, prior.entry.Incarnation, recipient); err != nil {
					return contract.GeneratorDescriptor{}, err
				}
			}
		}
		for recipient := range afterRecipients {
			if !beforeRecipients[recipient] || !beforePresent || prior.entry.Incarnation != next.entry.Incarnation {
				if err := appendIdentity(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, next.entry.Incarnation, recipient); err != nil {
					return contract.GeneratorDescriptor{}, err
				}
			}
		}
		beforeGenerated := beforePresent && prior.entry.ValueSource == contract.Generated
		afterGenerated := afterPresent && next.entry.ValueSource == contract.Generated
		switch {
		case beforeGenerated && (!afterGenerated || prior.entry.Generated.GenerationID != next.entry.Generated.GenerationID):
			if err := appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved,
				prior.entry.Generated.GenerationID, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
			if afterGenerated {
				if err := appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded,
					next.entry.Generated.GenerationID, contract.ID{}); err != nil {
					return contract.GeneratorDescriptor{}, err
				}
			}
		case !beforeGenerated && afterGenerated:
			if err := appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded,
				next.entry.Generated.GenerationID, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		case beforeGenerated && afterGenerated && (!bytes.Equal(prior.entry.ValueBytes, next.entry.ValueBytes) || prior.digest != next.digest):
			if err := appendIdentity(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectUpdated,
				next.entry.Generated.GenerationID, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		}
	}
	registryRows, err := generatedRegistryChangedSubjects(before, after)
	if err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	rows = append(rows, registryRows...)
	if before.root.OutputConfiguration != after.root.OutputConfiguration {
		oldOutput, result := before.currentOutputConfigurationForApply(ctx)
		if result.Outcome != 0 {
			return contract.GeneratorDescriptor{}, selectedReadFailure(result)
		}
		newOutput, err := before.generatedChangedOutputConfiguration(ctx, after)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		outputRows, err := contract.OutputConfigurationChangedSubjects(oldOutput, newOutput)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		rows = append(rows, outputRows...)
	}
	if subjects != nil {
		*subjects = slices.Clone(rows)
	}
	descriptor, err := contract.ChangedSubjectDescriptor(rows)
	if err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	if detail != nil {
		detail.HasChangedSubjects, detail.Descriptor = true, descriptor
		slices.SortFunc(detail.Subjects, func(a, b observationSubject) int {
			if a.Row.Kind != b.Row.Kind {
				return int(a.Row.Kind) - int(b.Row.Kind)
			}
			if a.Row.Change != b.Row.Change {
				return int(a.Row.Change) - int(b.Row.Change)
			}
			return bytes.Compare(a.Row.Identity[:], b.Row.Identity[:])
		})
		slices.SortFunc(detail.Memberships, func(a, b observationMembership) int {
			if n := bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:]); n != 0 {
				return n
			}
			if a.Change != b.Change {
				return int(a.Change) - int(b.Change)
			}
			return bytes.Compare(a.RecipientID[:], b.RecipientID[:])
		})
	}
	return descriptor, nil
}

func (s *StateSession) generatedChangedOutputConfiguration(ctx context.Context, after *StateSession) (contract.OutputConfiguration, error) {
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return contract.OutputConfiguration{}, err
	}
	if g.parent == nil {
		return contract.OutputConfiguration{}, contract.ErrRecord
	}
	graph := g.bundles[0]
	declaration, err := g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	if err != nil {
		return contract.OutputConfiguration{}, err
	}
	view, err := contract.InspectGeneratorDeclaration(declaration)
	if err != nil {
		return contract.OutputConfiguration{}, err
	}
	entries, err := generatedDeclarationOutputEntries(view)
	if err != nil {
		return contract.OutputConfiguration{}, err
	}
	var image []byte
	if graph.Request.Schema == contract.GeneratorApplyRequestCoreSchema {
		image, err = g.readSelectedSlice(ctx, contract.GeneratorContentOutputConfiguration, g.parent.OperationID, contract.MaxOutputConfigurationBytes)
		if err != nil {
			return contract.OutputConfiguration{}, err
		}
	}
	transition, err := s.generatedRequestedOutputTransition(ctx, graph, after.registry(), entries, image)
	if err != nil {
		return contract.OutputConfiguration{}, err
	}
	configuration, err := transition.ConfigurationAfter(graph.Header.OperationID, graph.ValueEntryPlans)
	if err != nil {
		return contract.OutputConfiguration{}, err
	}
	encoded, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		return contract.OutputConfiguration{}, err
	}
	descriptor, _, err := contract.SplitOutputConfiguration(s.root.Domain, encoded)
	if err != nil || descriptor != after.root.OutputConfiguration {
		return contract.OutputConfiguration{}, contract.ErrRecord
	}
	return configuration, nil
}

func generatedFinalOperationalRows(g *generatedSelection, plan *generatedFinalPlan,
	after []contract.SupportRecord) (generatedFinalOperationalResult, error) {
	var out generatedFinalOperationalResult
	if g == nil || g.parent == nil || plan == nil || len(g.bundles) == 0 {
		return out, contract.ErrRecord
	}
	out.classes = make(map[contract.ID]int)
	out.relatedDuties = make(map[contract.ID]bool, len(plan.retirements))
	afterRows := make(map[generatedRecordKey]contract.SupportRecord, len(after))
	for _, row := range after {
		afterRows[generatedRecordKey{kind: row.Kind, id: row.RecordID}] = row
	}
	bundle := g.bundles[0]
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		var entered []generatedAttempt
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			attempt, ok := g.attempts[template.AttemptID]
			if ok {
				entered = append(entered, attempt)
			}
		}
		if len(entered) == 0 {
			return out, contract.ErrRecord
		}
		for i, attempt := range entered {
			row, ok := g.records[generatedRecordKey{kind: contract.GeneratedAttemptSupportKind, id: attempt.record.AttemptID}]
			if !ok {
				return out, contract.ErrRecord
			}
			var class int
			if i != len(entered)-1 {
				switch attempt.record.State {
				case contract.GeneratedEffectConfirmedNoEffect:
					class = contract.ReceiptNoEffectPredecessorCount
				case contract.GeneratedEffectClosedWithResidue:
					class = contract.ReceiptPreservedResidueCount
				default:
					return out, contract.ErrRecord
				}
			} else {
				switch attempt.record.State {
				case contract.GeneratedEffectSucceeded:
					class = contract.ReceiptSummarySuccessCount
				case contract.GeneratedEffectConfirmedNoEffect, contract.GeneratedEffectFailedTerminal:
					class = contract.ReceiptSummaryFailureCount
				case contract.GeneratedEffectTransmitted, contract.GeneratedEffectUnknown, contract.GeneratedEffectPossibleLive,
					contract.GeneratedEffectClosedWithResidue:
					class = contract.ReceiptSummaryUnknownCount
				default:
					return out, contract.ErrRecord
				}
			}
			out.effects = append(out.effects, row)
			out.classes[attempt.record.AttemptID] = class
		}
	}
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			row, ok := afterRows[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: template.DutyID}]
			if !ok {
				continue
			}
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil || duty.OriginalOperationID != g.parent.OperationID {
				return out, contract.ErrRecord
			}
			out.duties = append(out.duties, row)
		}
	}
	for _, retirement := range plan.retirements {
		row, ok := afterRows[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: retirement.template.DutyID}]
		if !ok {
			return out, contract.ErrRecord
		}
		out.duties = append(out.duties, row)
		out.relatedDuties[row.RecordID] = true
	}
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			if row, ok := afterRows[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: template.HazardID}]; ok {
				out.hazards = append(out.hazards, row)
			}
		}
	}
	slices.SortFunc(out.duties, func(a, b contract.SupportRecord) int { return compareGeneratedIDs(a.RecordID, b.RecordID) })
	slices.SortFunc(out.hazards, func(a, b contract.SupportRecord) int { return compareGeneratedIDs(a.RecordID, b.RecordID) })
	return out, nil
}

func (s *StateSession) generatedFinalReceiptSupport(ctx context.Context, next *StateSession, g *generatedSelection, plan *generatedFinalPlan,
	rows []contract.SupportRecord, revision contract.ID, detail *changeObservation) ([]contract.SupportRecord, contract.GeneratorDescriptor, contract.GeneratorDescriptor, contract.GeneratorDescriptor, error) {
	var zero contract.GeneratorDescriptor
	operational, err := generatedFinalOperationalRows(g, plan, rows)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	projection := detail
	changedSubjects, err := generatedChangedSubjects(ctx, s, next, projection)
	if projection != nil && err == nil {
		addGeneratedPlanObservation(projection, g.bundles[0])
	}
	if err != nil {
		return nil, zero, zero, zero, err
	}
	changedAccess, err := generatedFinalChangedAccess(s, next)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	request := g.bundles[0].Request
	observed := s.head.Core.Revision
	if plan.selecting {
		observed = revision
	}
	delta, retained, err := s.generatedTerminalMutation(ctx, generatedMutationTerminalInput{Parent: *g.parent,
		OperationKind: request.OperationKind, OriginalPredecessorRevisionID: request.PredecessorRevisionID,
		RequestedRevisionID: revision, ObservedRevisionID: observed, ChangedSubjects: changedSubjects, ChangedAccess: changedAccess,
		Effects: operational.effects, Duties: operational.duties, Hazards: operational.hazards,
		EffectClasses: operational.classes, RelatedDutyIDs: operational.relatedDuties, Selected: plan.selecting})
	if err != nil {
		return nil, zero, zero, zero, err
	}
	if !retained {
		return nil, zero, zero, zero, contract.ErrRecord
	}
	rows, successes, failures, order, err := s.generatedReceiptSupport(rows, delta, g.parent.RequestIdentityDigest)
	return rows, successes, failures, order, err
}

func generatedFinalChangedAccess(before, after *StateSession) (contract.GeneratorDescriptor, error) {
	current := make(map[materialIdentity]contract.AccessRecord, after.root.AccessRecordCount)
	for _, row := range after.accessRecords() {
		current[materialIdentity{row.MaterialKind, row.MaterialID}] = row
	}
	var changes []contract.AccessChangeRow
	for _, old := range before.accessRecords() {
		newRow, present := current[materialIdentity{old.MaterialKind, old.MaterialID}]
		if !present {
			continue
		}
		oldDigest, err := contract.AccessRecordDigest(old)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		newDigest, err := contract.AccessRecordDigest(newRow)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		if oldDigest != newDigest {
			changes = append(changes, contract.AccessChangeRow{Before: old, After: newRow})
		}
	}
	return contract.AccessChangeDescriptor(before.root.Domain, changes)
}

func (s *StateSession) generatedReceiptSupport(rows []contract.SupportRecord, delta contract.MutationReceiptDeltaPlan,
	requestIdentity contract.ID) ([]contract.SupportRecord, contract.GeneratorDescriptor, contract.GeneratorDescriptor, contract.GeneratorDescriptor, error) {
	var zero contract.GeneratorDescriptor
	oldIndex, err := s.receiptIndexID()
	if err != nil {
		return nil, zero, zero, zero, err
	}
	selectedFragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, zero, zero, zero, err
	}
	kept := rows[:0]
	for _, row := range rows {
		if row.Kind == contract.MutationReceiptSupportKind {
			continue
		}
		if row.Kind == contract.GeneratedFragmentSupportKind && !oldIndex.IsZero() {
			var blob contract.ID
			if len(row.Body) == 0 {
				fact, ok := selectedFragments[row.RecordID]
				if !ok {
					return nil, zero, zero, zero, contract.ErrRecord
				}
				blob = fact.blob
			} else {
				fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
				if inspectErr != nil {
					return nil, zero, zero, zero, inspectErr
				}
				blob = fragment.BlobID
			}
			if blob == oldIndex {
				continue
			}
		}
		kept = append(kept, row)
	}
	rows = kept
	receipts, err := delta.AfterSupportRecords()
	if err != nil {
		return nil, zero, zero, zero, err
	}
	newReceipt := contract.CompactMutationReceipt(delta.NewReceipt)
	newReceipt.RequestIdentityDigest = requestIdentity
	newBody, err := contract.EncodeCompactMutationReceipt(newReceipt)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	for i := range receipts {
		if receipts[i].RecordID == newReceipt.OperationID {
			receipts[i].Body = newBody
		}
	}
	rows = append(rows, receipts...)
	indexes, err := delta.AfterIndexes()
	if err != nil {
		return nil, zero, zero, zero, err
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		return nil, zero, zero, zero, err
	}
	indexID, err := contract.MutationReceiptIndexBlobID(s.root.Domain, successes, failures, order)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	fragment := contract.GeneratedFragment{Schema: 1, BlobID: indexID, Count: 1, TotalLength: uint64(len(indexBody)),
		WholeDigest: contract.Hash(indexBody), Payload: indexBody}
	fragmentBody, err := contract.EncodeGeneratedFragment(fragment)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	fragmentID, err := contract.GeneratorFragmentID(indexID, 0)
	if err != nil {
		return nil, zero, zero, zero, err
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragmentBody})
	return rows, successes, failures, order, nil
}
