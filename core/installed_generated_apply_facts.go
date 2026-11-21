package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Passive custody inputs are rebuilt from the authenticated selected owner.
// They do not retain a permit or a callback from the public declaration.
func (s *StateSession) installedGeneratedSession(ctx context.Context, graph contract.GeneratorPlanBundle, declaration []byte, registry []byte, outputImage []byte) (contract.GeneratedSessionInput, contract.GeneratedPlanInput, error) {
	var session contract.GeneratedSessionInput
	plan := contract.GeneratedPlanInput{Declaration: declaration, RegistryImage: registry}
	var err error
	session.Graph, err = contract.EncodeGeneratorPlanBundle(graph)
	if err != nil {
		return session, plan, err
	}
	session.BeforePublic, err = s.publicProjection()
	if err != nil {
		return session, plan, err
	}
	session.CurrentRecipients = s.registry()
	core := s.root.CurrentAccess.Core
	session.BeforeAccess, session.BeforeAccessRecords = &core, s.accessRecords()
	for _, row := range s.supportRecords() {
		if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == graph.Header.OperationID && row.RecordID == s.root.Generated.ActiveOwner {
			phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
			if err != nil {
				return session, plan, err
			}
			session.SelectionPhase = &phase
		}
	}
	selectionAnchored := session.SelectionPhase != nil && !session.SelectionPhase.SelectionPhaseID.IsZero()
	for _, ref := range s.root.Recipients {
		if ref != nil {
			session.CurrentRecipientRefs = append(session.CurrentRecipientRefs, *ref)
		}
	}
	session.BeforeReceipts, err = s.receiptWindows(ctx)
	if err != nil {
		return session, plan, err
	}
	view, err := contract.InspectGeneratorDeclaration(declaration)
	if err != nil {
		return session, plan, err
	}
	desired, err := generatedDeclarationOutputEntries(view)
	if err != nil {
		return session, plan, err
	}
	registryRows := s.registry()
	if len(registry) != 0 {
		image, decodeErr := contract.DecodeGeneratedRecipientRegistryImage(registry)
		if decodeErr != nil {
			return session, plan, decodeErr
		}
		registryRows, err = effectiveGeneratedRecipients(s.root, registryRows, image, selectionAnchored)
		if err != nil {
			return session, plan, err
		}
	}
	if graph.Request.OperationKind == contract.OperationApplyDeclaration || graph.Request.OperationKind == contract.OperationRotateValueEntryValue {
		session.Output, err = s.generatedRequestedOutputTransition(ctx, graph, registryRows, desired, outputImage)
	} else {
		session.Output, err = s.generatedOutputTransition(ctx)
	}
	if err != nil {
		return session, plan, err
	}
	if selectionAnchored {
		return session, plan, nil
	}
	plan.CurrentIntents, err = s.generatedPlanCurrentIntents(ctx, graph, view)
	if err != nil {
		return session, plan, err
	}
	for at, p := range graph.ValueEntryPlans {
		entry, _, err := view.Entry(at)
		if err != nil {
			return session, plan, err
		}
		current := s.valueEntry(p.Slot)
		if current == nil || current.Name != p.Name || current.ConfidentialityClass != contract.Secret {
			continue
		}
		readers := make([]contract.ID, len(entry.RecipientIDs)/32)
		for j := range readers {
			readers[j] = contract.ID(entry.RecipientIDs[j*32 : (j+1)*32])
		}
		unchangedSealed := p.ChangeMask&contract.GeneratorValueChangeContent == 0 && p.ValueSource == contract.Supplied && entry.Kind == contract.GeneratorDeclarationSealed && current.ValueSource == contract.Supplied
		exclusion := p.ChangeMask&contract.GeneratorValueChangeContent != 0 && entry.Kind != contract.GeneratorDeclarationRetained && generatedFinalExcludesReader(*current, readers)
		selectionNeeded := unchangedSealed || exclusion || entry.Kind == contract.GeneratorDeclarationRetained
		if selectionNeeded {
			selection, _, err := s.publicationConsumer(p.Slot, s.admission.recipient)
			if err != nil {
				return session, plan, err
			}
			if unchangedSealed || exclusion {
				plan.CurrentValues = append(plan.CurrentValues, *selection)
			}
			if entry.Kind == contract.GeneratorDeclarationRetained {
				record, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
				if err != nil {
					return session, plan, err
				}
				plan.Canonical = append(plan.Canonical, contract.GeneratedCanonicalSelection{Selection: *selection, Record: record})
			}
		}
	}
	slices.SortFunc(plan.CurrentValues, func(a, b contract.ConsumerSelection) int { return int(a.Slot) - int(b.Slot) })
	return session, plan, nil
}

func (s *StateSession) installedGeneratedCommon(ctx context.Context, g *generatedSelection) (contract.GeneratedSessionInput, contract.GeneratedPlanInput, contract.GeneratedCustodyInput, error) {
	var session contract.GeneratedSessionInput
	var plan contract.GeneratedPlanInput
	var custody contract.GeneratedCustodyInput
	if g == nil || g.parent == nil || len(g.bundles) == 0 {
		return session, plan, custody, contract.ErrRecord
	}
	declaration, err := g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	if err != nil {
		return session, plan, custody, err
	}
	var outputImage []byte
	if g.bundles[0].Request.Schema == contract.GeneratorApplyRequestCoreSchema {
		outputImage, err = g.readSelectedSlice(ctx, contract.GeneratorContentOutputConfiguration, g.parent.OperationID, contract.MaxOutputConfigurationBytes)
		if err != nil {
			return session, plan, custody, err
		}
	}
	session, plan, err = s.installedGeneratedSession(ctx, g.bundles[0], declaration, g.registryBody, outputImage)
	if err != nil {
		return session, plan, custody, err
	}
	if g.bundles[0].Request.OperationKind == contract.OperationApplyDeclaration || g.bundles[0].Request.OperationKind == contract.OperationRotateValueEntryValue {
		plan.Canonical = nil
	}
	plan.LiveSourceUses = g.sources[g.parent.MaterialID]
	custody.SourceProtections = g.protected[g.parent.MaterialID]
	seed, ok := g.session.materialAccess(contract.OperationSeedMaterialKind, g.parent.MaterialID)
	if !ok {
		return session, plan, custody, contract.ErrRecord
	}
	custody.SeedAccess, err = contract.EncodeAccessRecord(seed)
	if err != nil {
		return session, plan, custody, err
	}
	for _, attempt := range g.attempts {
		if attempt.record.OperationID == g.parent.OperationID {
			custody.Material = attempt.material
			break
		}
	}
	if generatedSelectionAnchored(g) {
		return session, plan, custody, nil
	}
	// A retained canonical already selected by an older owner must keep that
	// exact observation. Current declarations were added above from s itself.
	seen := make(map[contract.ID]bool)
	for _, row := range plan.Canonical {
		id, err := contract.AdmissionEntryDigest(row.Record)
		if err != nil {
			return session, plan, custody, err
		}
		seen[id] = true
	}
	for value, source := range g.canonical {
		if !g.declaredCanonicals[value] {
			continue
		}
		id, err := contract.AdmissionEntryDigest(source.record)
		if err != nil {
			return session, plan, custody, err
		}
		if seen[id] {
			continue
		}
		uses := g.consumers[materialIdentity{contract.ValueMaterialKind, source.core.ValueStateID}]
		var owner generatedRecordKey
		found := false
		for _, use := range uses {
			if use.SubjectID != value {
				continue
			}
			for _, kind := range []contract.SupportRecordKind{contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind} {
				key := generatedRecordKey{kind: kind, id: use.OwnerID}
				if _, ok := g.records[key]; ok {
					owner, found = key, true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return session, plan, custody, contract.ErrRecord
		}
		selected, err := g.canonicalConsumerView(owner, source.core.ValueStateID, s.admission.recipient)
		if err != nil {
			return session, plan, custody, err
		}
		if current := s.valueEntry(selected.Record.OriginalSlot); current != nil && current.Name == selected.Record.Entry.Name {
			digest, err := contract.PublicValueEntryDigest(s.root.Domain, selected.Record.OriginalSlot, *current)
			if err == nil && digest == selected.Selection.EntryDigest {
				local, _, err := s.publicationConsumer(selected.Record.OriginalSlot, s.admission.recipient)
				if err != nil {
					return session, plan, custody, err
				}
				selected.Selection = *local
			}
		}
		plan.Canonical = append(plan.Canonical, selected)
		seen[id] = true
	}
	slices.SortFunc(plan.Canonical, func(a, b contract.GeneratedCanonicalSelection) int {
		return int(a.Record.OriginalSlot) - int(b.Record.OriginalSlot)
	})
	return session, plan, custody, nil
}
func (s *StateSession) installedGeneratedProducerInput(ctx context.Context, g *generatedSelection, attempt contract.ID, phase *contract.GeneratorPhaseIdentity, preparation contract.GeneratedProducerPreparation) (contract.GeneratedProducerInput, error) {
	session, plan, custody, err := s.installedGeneratedCommon(ctx, g)
	if err != nil {
		return contract.GeneratedProducerInput{}, err
	}
	a, ok := g.attempts[attempt]
	if !ok {
		return contract.GeneratedProducerInput{}, contract.ErrRecord
	}
	custody.Material = a.material
	input := contract.GeneratedProducerInput{Session: session, Plan: plan, Custody: custody, Expected: a.expected, Preparation: preparation, Phase: phase, Attempt: a.record}
	input.Intent, err = g.readSelectedSlice(ctx, contract.GeneratorContentIntent, a.expected.Template.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return input, err
	}
	if a.expected.Template.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
		row, ok := g.records[generatedRecordKey{contract.GeneratedDutySupportKind, a.record.OwnerID}]
		if !ok {
			return input, contract.ErrRecord
		}
		input.Duty, err = contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || input.Duty.SemanticLifecycleMode() != contract.GeneratorLifecycleNone || input.Duty.Kind != contract.GeneratedDutyCreate {
			return input, contract.ErrRecord
		}
		input.Consumers, err = g.vectors.resolve(row.Kind, row.RecordID, contract.GeneratorVectorConsumers, input.Duty.Consumers)
		return input, err
	}
	source, err := g.generatedDeleteSource(a.record.OwnerID)
	if err != nil {
		return input, err
	}
	if source.Record.Kind == contract.GeneratedDutySupportKind {
		input.Duty = source.Duty
	} else {
		input.Source = source.Record
	}
	input.Consumers, err = g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorConsumers, source.Consumers)
	if err != nil {
		return input, err
	}
	if a.expected.Template.Action == contract.GeneratorActionDelete {
		bundle, err := g.retainedGraph(a.record.OperationID)
		if err != nil {
			return input, err
		}
		target, _, err := g.generatedDeleteAttemptTargetAndSource(ctx, bundle, a.record)
		if err != nil {
			return input, err
		}
		input.Target = &target
		original, err := g.createTargetEvidence(ctx, target)
		if err != nil {
			return input, err
		}
		input.OriginalFacts, err = contract.EncodeGeneratorSafeFacts(original.GeneratorSafeFacts)
		if err != nil {
			return input, err
		}
		if source.CompletionClass == contract.GeneratedCompletionConfirmed {
			progress, err := g.controlledDeleteSourceProgress(source, nil, true)
			if err != nil {
				return input, err
			}
			input.Progress = progress.rows
			selected, err := s.selectedGeneratedWork(ctx)
			if err != nil {
				return input, err
			}
			beforeSource, err := selected.generatedDeleteSource(source.OwnerID)
			if err != nil {
				return input, err
			}
			input.ControlledPredecessor, err = s.installedGeneratedControlledPredecessor(ctx, selected, beforeSource)
			if err != nil {
				return input, err
			}
		} else if source.Record.Kind == contract.GeneratedDutySupportKind {
			input.Progress, err = g.vectors.resolve(contract.GeneratedDutySupportKind, source.SourceID, contract.GeneratorVectorProgress, source.Duty.Progress)
			if err != nil {
				return input, err
			}
		}
	}
	return input, nil
}

func (s *StateSession) installedGeneratedFinalInput(ctx context.Context, g *generatedSelection, plan *generatedFinalPlan) (contract.GeneratedFinalInput, error) {
	session, proposal, custody, err := s.installedGeneratedCommon(ctx, g)
	if err != nil {
		return contract.GeneratedFinalInput{}, err
	}
	out := contract.GeneratedFinalInput{Session: session, Plan: proposal, Custody: custody, Phase: plan.phase, Preparation: plan.materialization, QualifyLegacy: plan.qualifyLegacy}
	for _, result := range plan.results {
		out.Results = append(out.Results, contract.GeneratedResultAdmissionInput{Expected: result.attempt.expected, Reference: result.reference})
		out.ResultBodies = append(out.ResultBodies, result.attempt.result)
	}
	for _, entry := range plan.entryPlans {
		out.EntryAdmissions = append(out.EntryAdmissions, contract.GeneratedFinalEntryInput{Slot: entry.Slot, Generated: entry.Generated})
	}
	if plan.materialization != nil || plan.qualifyLegacy {
		if g.preparation == nil {
			return out, contract.ErrRecord
		}
		out.Preparation = g.preparation
		out.PreparationPhase = g.phase
		out.PreparedImage, err = g.readSelectedSlice(ctx, contract.GeneratorContentFinalPreparation, g.preparation.Image.ContentID, contract.GeneratedFinalPreparationMaxLength)
		if err != nil {
			return out, err
		}
	}
	if len(out.EntryAdmissions) != 0 {
		for _, entry := range g.bundles[0].ValueEntryPlans {
			if entry.ConfidentialityClass == contract.Secret && entry.ChangeMask&contract.GeneratorValueChangeMembership != 0 && entry.ChangeMask&contract.GeneratorValueChangeContent == 0 {
				selection, _, err := s.publicationConsumer(entry.Slot, s.admission.recipient)
				if err != nil {
					return out, err
				}
				out.Membership = append(out.Membership, contract.GeneratedMembershipInput{Selection: *selection})
			}
		}
	}
	slices.SortFunc(out.Membership, func(a, b contract.GeneratedMembershipInput) int { return int(a.Selection.Slot) - int(b.Selection.Slot) })
	selected, err := s.installedGeneratedSupport(ctx)
	if err != nil {
		return out, err
	}
	// Exact selected support is bounded by the admitted support aggregate. Crypto
	// uses the checkpoint subset below to prove replacement, not caller claims.
	oldBlobs := make(map[contract.ID]bool)
	if g.preparation != nil {
		for key, loc := range g.content.locations {
			if key.kind == contract.GeneratorContentFinalPreparation && key.id == g.preparation.Image.ContentID {
				shared := false
				for other, otherLoc := range g.content.locations {
					if other != key && otherLoc.BlobID == loc.BlobID {
						shared = true
					}
				}
				if !shared {
					oldBlobs[loc.BlobID] = true
				}
			}
		}
	}
	localAttempts := make(map[contract.ID]bool)
	localDuties := make(map[contract.ID]bool)
	if !plan.selecting {
		for id, attempt := range g.attempts {
			if attempt.record.OperationID != g.parent.OperationID || attempt.record.SemanticLifecycleMode() != contract.GeneratorLifecycleNone {
				continue
			}
			if generatedFinalLocalFailure(g, attempt) {
				localAttempts[id] = true
				continue
			}
			result, err := contract.InspectGeneratedResultRecord(attempt.result)
			if err != nil || !result.MatchesLocalCreateAttempt(attempt.record) {
				return out, contract.ErrRecord
			}
			localAttempts[id], localDuties[attempt.record.OwnerID] = true, true
		}
		if len(localAttempts) > contract.GeneratorMaxCreateLineages {
			return out, contract.ErrRecordCapacity
		}
	}
	for _, row := range selected {
		keep := row.Kind == contract.GeneratedAttemptSupportKind && localAttempts[row.RecordID] ||
			row.Kind == contract.GeneratedDutySupportKind && localDuties[row.RecordID] ||
			(row.Kind == contract.GeneratedPhaseSupportKind || row.Kind == contract.GeneratedFinalPreparationSupportKind) && row.RecordID == g.parent.OperationID
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return out, err
			}
			keep = carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
		}
		if row.Kind == contract.GeneratedFragmentSupportKind {
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				return out, err
			}
			keep = oldBlobs[fragment.BlobID]
		}
		if keep {
			out.CheckpointSupport = append(out.CheckpointSupport, row)
		}
	}
	reader := s.recipientRecord(s.admission.recipient)
	if reader == nil || reader.CurrentBinding == nil {
		return out, contract.ErrRecord
	}
	seen := make(map[contract.ID]bool)
	for _, row := range session.Output.Retained {
		source, ok := g.canonical[row.RecordID]
		if !ok {
			return out, contract.ErrRecord
		}
		if seen[source.core.ValueStateID] {
			continue
		}
		seen[source.core.ValueStateID] = true
		digest, err := contract.PublicValueEntryDigest(s.root.Domain, source.record.OriginalSlot, source.record.Entry)
		if err != nil {
			return out, err
		}
		out.CanonicalAccess = append(out.CanonicalAccess, contract.ConsumerSelection{DomainID: s.root.Domain, SnapshotID: s.root.Snapshot, HEADDigest: contract.Hash(s.body), AccessRoot: s.root.CurrentAccess.AccessRoot, Root: s.head.Core.Root, HEADRevision: s.head.Core.Revision, HEADToken: s.token, Slot: source.record.OriginalSlot, EntryDigest: digest, Entry: source.record.Entry, Core: source.core, Payload: source.payload, Access: source.access, Binding: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: s.admission.recipient, Binding: *reader.CurrentBinding}})
	}
	slices.SortFunc(out.CanonicalAccess, func(a, b contract.ConsumerSelection) int {
		return bytes.Compare(a.Core.ValueStateID[:], b.Core.ValueStateID[:])
	})
	return out, nil
}

func (s *StateSession) installedGeneratedSupport(ctx context.Context) ([]contract.SupportRecord, error) {
	var rows []contract.SupportRecord
	for index, page := range s.support {
		if !slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool { return row.Body == nil }) {
			for _, row := range page.Records {
				rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
			}
			continue
		}
		if index >= len(s.supportFacts) || index >= len(s.root.RequiredSupport) || s.supportFacts[index].ref != s.root.RequiredSupport[index] || len(s.supportFacts[index].rows) != len(page.Records) {
			return nil, contract.ErrRecord
		}
		result, err := withAuthenticatedSupportRows(ctx, s.readObjectBorrowedUncached, s.root.Domain, s.supportFacts[index], func(_ uint16, _ uint16, row contract.SupportRecordView) error {
			rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
			return nil
		})
		if err != nil {
			return nil, err
		}
		if result.Outcome != 0 {
			return nil, selectedReadFailure(result)
		}
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	return rows, nil
}

func (s *StateSession) installedGeneratedCandidate(ctx context.Context, reservation *generatedReservation, final *generatedFinalPlan) (contract.GeneratedCandidateInput, error) {
	var out contract.GeneratedCandidateInput
	next := reservation.state
	g, err := next.selectedGeneratedWork(ctx)
	if err != nil || next.head.Generator == nil {
		return out, contract.ErrRecord
	}
	out = contract.GeneratedCandidateInput{ActiveOwner: next.root.Generated.ActiveOwner, ActivePhase: next.root.Generated.ActivePhase, ActiveGraph: next.root.Generated.ActiveGraph, Subject: *next.head.Generator, CurrentAccess: next.root.CurrentAccess.Core, AccessRecords: next.accessRecords()}
	out.PublicState, err = next.publicProjection()
	if err != nil {
		return out, err
	}
	out.SupportRecords, err = next.installedGeneratedSupport(ctx)
	if err != nil {
		return out, err
	}
	if g.parent != nil {
		out.LiveSourceUses = g.sources[g.parent.MaterialID]
		out.SourceProtections = g.protected[g.parent.MaterialID]
	}
	for _, entry := range next.root.Names {
		out.Entries = append(out.Entries, contract.GeneratedCandidateEntry{Slot: entry.Slot, Entry: *next.valueEntry(entry.Slot)})
	}
	out.HeadCore, err = format.EncodeHeadCore(next.head.Core)
	if err != nil {
		return out, err
	}
	out.Conditional, err = format.EncodeConditionalPlan(conditional(next.head.Core, out.HeadCore))
	if err != nil {
		return out, err
	}
	before, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return out, err
	}
	registryBody := g.registryBody
	if before.registry != nil {
		registryBody = before.registryBody
	}
	if len(registryBody) != 0 {
		registry := &contract.GeneratedCandidateRegistryInput{Image: registryBody, Recipients: next.registry(), IdentityPlan: contract.IdentityPlan{Operation: out.Subject.OperationID, Snapshot: next.root.Snapshot, Transition: next.root.Transition, Revision: next.head.Core.Revision}}
		registry.Root, err = format.EncodeRoot(next.root)
		if err != nil {
			return out, err
		}
		for _, ref := range next.root.Recipients {
			if ref != nil {
				registry.RecipientRefs = append(registry.RecipientRefs, *ref)
				id, e := contract.GeneratorPhasePageID(out.Subject.PhaseID, contract.RecipientKind, ref.Index)
				if e == nil && id == ref.Object {
					registry.IdentityPlan.Pages = append(registry.IdentityPlan.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				}
			}
		}
		if final != nil && next.root.Generated.ActiveOwner.IsZero() {
			var subjects []contract.ChangedSubjectIdentity
			changed, err := generatedChangedSubjectsCollect(ctx, s, next, nil, &subjects)
			if err != nil {
				return out, err
			}
			access, err := generatedFinalChangedAccess(s, next)
			if err != nil {
				return out, err
			}
			operational, err := generatedFinalOperationalRows(before, final, out.SupportRecords)
			if err != nil {
				return out, err
			}
			observed := s.head.Core.Revision
			if final.selecting {
				observed = next.head.Core.Revision
			}
			request := before.bundles[0].Request
			delta, retained, err := s.generatedTerminalMutation(ctx, generatedMutationTerminalInput{Parent: *before.parent, OperationKind: request.OperationKind, OriginalPredecessorRevisionID: request.PredecessorRevisionID, RequestedRevisionID: next.head.Core.Revision, ObservedRevisionID: observed, ChangedSubjects: changed, ChangedAccess: access, Effects: operational.effects, Duties: operational.duties, Hazards: operational.hazards, EffectClasses: operational.classes, RelatedDutyIDs: operational.relatedDuties, Selected: final.selecting})
			if err != nil || !retained {
				return out, contract.ErrRecord
			}
			after, err := next.receiptWindows(ctx)
			if err != nil {
				return out, err
			}
			registry.ReceiptDelta = &contract.GeneratedRecipientReceiptInput{Plan: delta, After: after, ChangedSubjects: subjects}
		}
		out.Registry = registry
	}
	return out, nil
}

func (s *StateSession) installedGeneratedControlledPredecessor(ctx context.Context, g *generatedSelection, source contract.GeneratedDeleteSource) (*contract.GeneratedControlledPredecessor, error) {
	records, err := s.installedGeneratedSupport(ctx)
	if err != nil {
		return nil, err
	}
	input := &contract.GeneratedControlledPredecessor{Source: source.Record, BeforeRecords: records}
	progress, err := g.controlledDeleteSourceProgress(source, nil, true)
	if err != nil {
		return nil, err
	}
	if len(progress.rows) == 0 {
		return input, nil
	}
	a := progress.ack
	if a.record.AttemptID.IsZero() {
		return nil, contract.ErrRecord
	}
	input.Expected, input.Material, input.Result = a.expected, a.material, bytes.Clone(a.result)
	graph, err := g.retainedGraph(a.record.OperationID)
	if err != nil {
		return nil, err
	}
	input.Graph, err = contract.EncodeGeneratorPlanBundle(graph)
	if err != nil {
		return nil, err
	}
	access, ok := s.materialAccess(contract.OperationSeedMaterialKind, a.material.Core.OperationMaterialID)
	if !ok {
		return nil, contract.ErrRecord
	}
	input.SeedAccess, err = contract.EncodeAccessRecord(access)
	return input, err
}

func (s *StateSession) installedGeneratedAdoptionInput(ctx context.Context, g *generatedSelection, plan *generatedRecordPlan) (contract.GeneratedAdoptionInput, error) {
	session, proposal, custody, err := s.installedGeneratedCommon(ctx, g)
	if err != nil {
		return contract.GeneratedAdoptionInput{}, err
	}
	input := contract.GeneratedAdoptionInput{Session: session, Plan: proposal, Custody: custody, Phase: plan.phase, Result: contract.GeneratedResultAdmissionInput{Expected: plan.expected, Reference: plan.reference}}
	a, ok := g.attempts[plan.expected.Template.AttemptID]
	if !ok {
		return input, contract.ErrRecord
	}
	input.Custody.Material = a.material
	if a.expected.Template.Action == contract.GeneratorActionDelete {
		bundle, err := g.retainedGraph(a.record.OperationID)
		if err != nil {
			return input, err
		}
		target, source, err := g.generatedDeleteAttemptTargetAndSource(ctx, bundle, a.record)
		if err != nil {
			return input, err
		}
		input.Target = &target
		if source.CompletionClass == contract.GeneratedCompletionConfirmed {
			input.ControlledPredecessor, err = s.installedGeneratedControlledPredecessor(ctx, g, source)
			if err != nil {
				return input, err
			}
		}
	}
	return input, nil
}

func (s *StateSession) installedGeneratedLocalFailureInput(ctx context.Context, g *generatedSelection, plan *generatedRecordPlan) (contract.GeneratedLocalFailureInput, error) {
	if plan == nil || plan.failureReason == 0 {
		return contract.GeneratedLocalFailureInput{}, contract.ErrRecord
	}
	session, proposal, custody, err := s.installedGeneratedCommon(ctx, g)
	if err != nil {
		return contract.GeneratedLocalFailureInput{}, err
	}
	a, ok := g.attempts[plan.expected.Template.AttemptID]
	if !ok {
		return contract.GeneratedLocalFailureInput{}, contract.ErrRecord
	}
	terminal := a.record
	terminal.State, terminal.Stage, terminal.FailureReason = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal, plan.failureReason
	custody.Material = a.material
	return contract.GeneratedLocalFailureInput{Session: session, Plan: proposal, Custody: custody, Phase: plan.phase, Attempt: terminal, BeforeSliceSnapshot: s.adminIndex.SliceSnapshot}, nil
}
