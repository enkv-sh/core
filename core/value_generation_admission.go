package core

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The enclosing private admission supplies the qualified registry and recovery
// policy. Neither is learned from a plugin or from the proposed graph itself.
type generatedPlanInput struct {
	graph               contract.GeneratorPlanBundle
	declaration         []byte
	registryImage       []byte
	outputConfiguration []byte
	registry            contract.GeneratorDescriptor
	recoveryPolicy      contract.ID
	context             contract.ApplyContext
	requestBindings     []generatedRequestBinding
}

type generatedRequestBinding struct {
	LineageID, AttemptID, Digest contract.ID
}

func generatedRequestBindingsValid(g contract.GeneratorPlanBundle, bindings []generatedRequestBinding) bool {
	index := 0
	for _, lineage := range g.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate && lineage.Purpose != contract.GeneratorLineageRetirement &&
			lineage.Purpose != contract.GeneratorLineageCleanup {
			return false
		}
		if lineage.Purpose != contract.GeneratorLineageCreate && g.Request.OperationKind != contract.OperationCleanOwnedFailureResidue && g.Request.OperationKind != contract.OperationRetireGeneratedGeneration {
			continue
		}
		if index >= len(bindings) || bindings[index].LineageID != lineage.LineageID ||
			bindings[index].AttemptID != lineage.Templates[0].AttemptID || bindings[index].Digest.IsZero() {
			return false
		}
		index++
	}
	return index != 0 && index == len(bindings)
}

func generatedRequestDigest(bindings []generatedRequestBinding, x contract.GeneratorAttemptTemplate) (contract.ID, bool) {
	for _, binding := range bindings {
		if binding.LineageID == x.LineageID {
			return binding.Digest, true
		}
	}
	return contract.ID{}, false
}

type generatedPlan struct {
	input    generatedPlanInput
	bindings []generatedRequestBinding
	request  contract.CryptoGeneratedCompareRequest
	capacity contract.GeneratorCapacityEvidence
	phase    *contract.GeneratorPhaseIdentity
	intents  generatedCurrentIntentProjection
}

func (s *StateSession) generatedPlanRequest(ctx context.Context, input generatedPlanInput) (*generatedPlan, error) {
	c, g := input.context, input.graph
	if (g.Request.Schema == contract.GeneratorPublicRequestCoreSchema || g.Request.Schema == contract.GeneratorApplyRequestCoreSchema) && g.Request.RecoveryPolicyID != contract.GeneratorRecoveryPolicyID() {
		return nil, contract.ErrRecord
	}
	if s == nil || !s.root.ActiveGC.IsZero() || s.prepared || !generatedRequestBindingsValid(g, input.requestBindings) || c.OperationClass != contract.CryptoGeneratedClass ||
		c.IntentDescriptor != (contract.DescriptorVector{}) || c.Expiry > uint64(1<<63-1) || !validPrivateDeadline(time.Unix(0, int64(c.Expiry))) ||
		c.DomainID != s.admission.domain ||
		c.CompatibilityID != s.root.CurrentAccess.Core.CompatibilityID || c.CurrentAccessRoot != s.root.CurrentAccess.AccessRoot ||
		c.PredecessorHEADDigest != contract.Hash(s.body) || contract.ValidateGeneratorEffectGraph(g) != nil || !generatedOperationGraphValid(g) {
		return nil, contract.ErrRecord
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil || !bytes.Equal(root, c.PredecessorRootRef[:]) {
		return nil, contract.ErrRecord
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	q := g.Request
	if err != nil || condition != c.OriginalConditionDigest || q.DomainID != c.DomainID || q.CompatibilityID != c.CompatibilityID || q.PredecessorRevisionID != s.head.Core.Revision ||
		q.PredecessorHEADDigest != c.PredecessorHEADDigest || q.ConditionDigest != condition || q.Registry != input.registry ||
		q.RecoveryPolicyID != input.recoveryPolicy {
		return nil, contract.ErrRecord
	}
	selected, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if selected.parent != nil {
		return nil, contract.ErrRecord
	}
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		return nil, err
	}
	if contract.ValidateGeneratorDeclarationGraph(declaration, g) != nil {
		return nil, contract.ErrRecord
	}
	registryImage, err := s.admitGeneratedRegistry(ctx, input.registryImage, q, true)
	if err != nil {
		return nil, err
	}
	shape, err := s.generatedAdmissionShapeWithRegistry(ctx, g, declaration, selected, registryImage, input.outputConfiguration)
	if err != nil {
		return nil, err
	}
	intentProjection, err := planGeneratedCurrentIntents(ctx, s, selected, selectedGeneratedLocations(selected))
	if err != nil {
		return nil, err
	}
	if intentProjection.changed && intentProjection.emit {
		shape.ProjectedCurrentIntentFragments = uint64(intentProjection.fragments)
	}
	shape.DeclarationBytes = uint64(len(input.declaration))
	shape.RegistryBytes = uint64(len(input.registryImage))
	groups, err := generatedCapacityWithProjectedBacklog(shape, selected, &intentProjection)
	if err != nil {
		return nil, err
	}
	groups, err = s.generatedPublicationCapacity(ctx, groups)
	if err != nil {
		return nil, err
	}
	shards, err := s.generatedAdministrativeShardReserve(shape)
	if err != nil {
		return nil, err
	}
	exitShards, err := s.generatedAdministrativeFirstExitShardReserve(shape)
	if err != nil {
		return nil, err
	}
	// Charge the prospective authenticated index as well as every permitted
	// continuation before private preparation or an effect can enter.
	reservedChildren := shards
	for _, group := range groups {
		reservedChildren += group.MaxPages
	}
	if reservedChildren > ordinaryChildPageLimit {
		return nil, contract.ErrRecordCapacity
	}
	// The closed continuation envelope must also leave room for a first
	// administrative exit before any generated effect is admitted. No old
	// support or access page is credited as released in this pre-effect bound.
	publicationExitPages := uint32(0)
	for _, group := range s.adminIndex.Groups {
		if group.OwnerKind == format.AdministrativePublicationMarker {
			publicationExitPages = 1
			break
		}
	}
	if reservedChildren-shards+2+publicationExitPages+exitShards > contract.MaxChildPages {
		return nil, contract.ErrRecordCapacity
	}
	capacity := contract.GeneratorCapacityEvidence{Schema: 1, BeforeRootDigest: s.head.Core.Root.Digest, PlanGraphID: g.UsePlan.PlanGraphID,
		Declaration: q.Declaration, Groups: groups}
	capacityDescriptor, err := contract.GeneratorCapacityDescriptor(capacity)
	if err != nil {
		return nil, err
	}
	graph, err := contract.GeneratorPlanBundleDescriptor(g)
	if err != nil {
		return nil, err
	}
	use, err := contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		return nil, err
	}
	entryPlansDescriptor, err := contract.GeneratorValueEntryPlansDescriptor(g.ValueEntryPlans)
	if err != nil {
		return nil, err
	}
	p := contract.GeneratedParentPlan{Schema: contract.GeneratedParentSchema, DomainID: c.DomainID, OperationID: q.OperationID, RequestCoreDigest: g.Header.RequestCoreDigest,
		PlanGraphID: g.UsePlan.PlanGraphID, UsePlanDigest: use, MaterialID: g.Header.MaterialID, RecoveryPolicyID: input.recoveryPolicy, ValueEntryPlanCount: g.Header.ValueEntryPlanCount, LineageCount: g.Header.LineageCount, TemplateCount: g.Header.TemplateCount,
		Declaration: q.Declaration, Registry: q.Registry, Graph: graph, SourceUses: g.UsePlan.SourceUses, IntendedEntryPlans: entryPlansDescriptor,
		Capacity: capacityDescriptor, InitialPredecessorDigest: q.PredecessorHEADDigest, ConditionDigest: condition}
	request := contract.CryptoGeneratedCompareRequest{Context: c, Purpose: contract.CryptoGeneratedReservationPurpose, ParentPlan: p, PlanGraph: graph,
		UsePlanDigest: use, MaterialID: p.MaterialID, AcceptedSources: p.SourceUses, IntendedEntryPlans: entryPlansDescriptor}
	request.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(request)
	if err != nil {
		return nil, err
	}
	if _, err := contract.EncodeCryptoGeneratedCompareRequest(request); err != nil {
		return nil, err
	}
	input.requestBindings = slices.Clone(input.requestBindings)
	plan := &generatedPlan{input: input, bindings: slices.Clone(input.requestBindings), request: request, capacity: capacity, intents: intentProjection}
	deletion, deleteOnly, err := s.generatedDeleteReservationSelection(ctx, g, selected)
	if err != nil {
		return nil, err
	}
	_, hasCreate := generatedFirstCreateIndex(g)
	if !hasCreate && !deleteOnly {
		return nil, contract.ErrRecord
	}
	if deleteOnly {
		if deletion.source.CompletionClass == contract.GeneratedCompletionConfirmed {
			progress, err := selected.controlledDeleteSourceProgress(deletion.source, nil, true)
			if err != nil {
				return nil, err
			}
			ack := progress.ack
			if len(progress.rows) != 0 {
				want := contract.GeneratorControlledRetirementProbeDigest(s.root.Domain, deletion.target.ResourceID, deletion.target.ResourceDigest,
					contract.GeneratorControlledRetirementScope(deletion.template.DescriptorID, deletion.template.ConfigContractID, deletion.template.ResultContractID), ack.record.ResultID, contract.Hash(ack.result))
				if len(input.requestBindings) != 1 || input.requestBindings[0].Digest != want {
					return nil, contract.ErrRecord
				}
			}
		}
		plan.phase = new(contract.GeneratorPhaseIdentity)
		*plan.phase = deletion.phase
	}
	return plan, nil
}

func generatedOperationGraphValid(g contract.GeneratorPlanBundle) bool {
	switch g.Request.OperationKind {
	case contract.OperationApplyDeclaration, contract.OperationRotateValueEntryValue:
		creates := uint16(0)
		for _, lineage := range g.Lineages {
			if lineage.Purpose != contract.GeneratorLineageCreate && lineage.Purpose != contract.GeneratorLineageCleanup &&
				lineage.Purpose != contract.GeneratorLineageRetirement {
				return false
			}
			if lineage.Purpose == contract.GeneratorLineageCreate {
				creates++
			}
		}
		return creates != 0 && creates == g.Header.LineageCount
	case contract.OperationCleanOwnedFailureResidue, contract.OperationRetireGeneratedGeneration:
		if len(g.Lineages) != 1 || g.Header.LineageCount != 0 || g.Header.TemplateCount != 1 || g.Lineages[0].TemplateCount != 1 ||
			g.Lineages[0].Templates[0].Action != contract.GeneratorActionDelete {
			return false
		}
		if g.Request.OperationKind == contract.OperationCleanOwnedFailureResidue {
			return g.Lineages[0].Purpose == contract.GeneratorLineageCleanup
		}
		return g.Lineages[0].Purpose == contract.GeneratorLineageRetirement
	default:
		return false
	}
}

func (s *StateSession) generatedAdmissionShape(ctx context.Context, g contract.GeneratorPlanBundle, d contract.GeneratorDeclarationView, selected *generatedSelection) (generatedCapacityShape, error) {
	return s.generatedAdmissionShapeWithRegistry(ctx, g, d, selected, nil, nil)
}

func (s *StateSession) generatedAdmissionShapeWithRegistry(ctx context.Context, g contract.GeneratorPlanBundle, d contract.GeneratorDeclarationView, selected *generatedSelection, image *contract.GeneratedRecipientRegistryImage, outputImage []byte) (generatedCapacityShape, error) {
	fail := func() (generatedCapacityShape, error) { return generatedCapacityShape{}, contract.ErrRecord }
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return generatedCapacityShape{}, err
	}
	if image != nil {
		for _, row := range image.Recipients {
			if slices.Contains(image.InitiallyAbsent, row.Recipient.RecipientID) {
				used[row.Recipient.RecipientID] = true
				used[row.Recipient.CurrentBinding.BindingID] = true
				used[row.Recipient.CurrentBinding.BindingIncarnationID] = true
			}
		}
	}
	if used[g.Request.OperationID] || used[g.Header.MaterialID] || used[g.UsePlan.PlanGraphID] {
		return fail()
	}
	before := make(map[string]uint16, len(s.root.Names))
	currentOnlyDelete := g.Request.OperationKind == contract.OperationCleanOwnedFailureResidue ||
		g.Request.OperationKind == contract.OperationRetireGeneratedGeneration
	shape := generatedCapacityShape{publicRecovery: g.Header.RecoveryPolicyID == contract.GeneratorRecoveryPolicyID()}
	var finalImageReaders uint64
	shape.finalImageReaders = &finalImageReaders
	shape.Recipients, shape.Recovery = uint64(s.root.RecipientCount), s.root.CurrentAccess.Core.Recovery != nil
	recipients := s.registry()
	if image != nil {
		recipients, err = effectiveGeneratedRecipients(s.root, recipients, *image)
		if err != nil {
			return fail()
		}
		shape.Recipients = max(shape.Recipients, uint64(len(recipients)))
	}
	recipientForID := func(id contract.ID) *contract.RecipientRecord {
		for i := range recipients {
			if recipients[i].RecipientID == id {
				return &recipients[i]
			}
		}
		return nil
	}
	shape.ValueEntryPlanCount, shape.Sources = uint64(len(g.ValueEntryPlans)), uint64(len(g.SourceUses))
	var oldSecrets, oldMemberships, oldSecretMemberships uint64
	oldPages := uint64(0)
	oldIntents := make(map[contract.ID]bool)
	for _, page := range s.pages {
		if page != nil {
			oldPages++
		}
	}
	for _, entry := range s.root.Names {
		m := s.valueEntry(entry.Slot)
		if m == nil {
			return fail()
		}
		before[entry.Name] = entry.Slot
		oldMemberships += uint64(len(m.Recipients))
		if m.ConfidentialityClass == contract.Secret {
			oldSecrets++
			oldSecretMemberships += uint64(len(m.Recipients))
		}
		if m.ValueSource == contract.Generated {
			shape.OldGenerated++
			if !oldIntents[m.Generated.IntentDigest] {
				intent, err := selected.readSelectedSlice(ctx, contract.GeneratorContentIntent, m.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
				if err != nil {
					return generatedCapacityShape{}, err
				}
				shape.OldIntentBytes += uint64(len(intent))
				oldIntents[m.Generated.IntentDigest] = true
			}
		}
	}
	var occupied [contract.CryptoMaxValueEntries]bool
	for _, m := range g.ValueEntryPlans {
		if slot, ok := before[m.Name]; ok {
			current := s.valueEntry(slot)
			if m.Slot != slot || m.ConfidentialityClass != current.ConfidentialityClass {
				return fail()
			}
			membership, err := contract.GeneratorIntendedMembershipDescriptor(current.Recipients)
			if err != nil || membership != m.IntendedMembership && m.ChangeMask&contract.GeneratorValueChangeMembership == 0 {
				return fail()
			}
			if m.ValueSource != current.ValueSource {
				// A source conversion is a fresh membership even when the
				// recipients or secret bytes are unchanged.
				if m.ConfidentialityClass != contract.Secret ||
					m.ChangeMask&contract.GeneratorValueChangeContent == 0 || m.EntryIncarnationID == current.Incarnation || used[m.EntryIncarnationID] {
					return fail()
				}
				if current.ValueSource == contract.Generated && current.Generated.SemanticLifecycleMode() == contract.GeneratorLifecycleManaged {
					if _, ok := generatedRetirementTemplate(g, *current); !ok {
						return fail()
					}
				}
				used[m.EntryIncarnationID] = true
			} else if m.EntryIncarnationID != current.Incarnation {
				return fail()
			}
			occupied[slot] = true
		}
	}
	var pages [contract.MaxValueEntryPages]bool
	raw := uint64(0)
	for i, m := range g.ValueEntryPlans {
		entry, _, err := d.Entry(i)
		if err != nil {
			return fail()
		}
		if m.ValueSource == contract.Supplied && m.ChangeMask&contract.GeneratorValueChangeContent == 0 {
			slot, present := before[m.Name]
			if !present {
				return fail()
			}
			current := s.valueEntry(slot)
			if current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != m.ConfidentialityClass ||
				current.InputEncoding != m.InputEncoding || current.Incarnation != m.EntryIncarnationID || current.ConfidentialityClass == contract.Plain && !bytes.Equal(current.ValueBytes, entry.Payload) {
				return fail()
			}
		}
		if _, ok := before[m.Name]; !ok {
			free := slices.Index(occupied[:], false)
			if free < 0 || m.Slot != uint16(free) || used[m.EntryIncarnationID] {
				return fail()
			}
			used[m.EntryIncarnationID], occupied[free] = true, true
		}
		pages[m.Slot/format.PageSlots] = true
		ids := make([]contract.ID, len(entry.RecipientIDs)/32)
		refs := make([]contract.RecipientBindingReference, len(ids))
		for j := range ids {
			ids[j] = contract.ID(entry.RecipientIDs[j*32 : (j+1)*32])
			r := recipientForID(ids[j])
			if r == nil || r.Status != contract.CurrentRecipient || r.CurrentBinding == nil {
				return fail()
			}
			digest, err := contract.PublicBindingDigest(*r.CurrentBinding)
			if err != nil {
				return fail()
			}
			refs[j] = contract.RecipientBindingReference{RecipientID: ids[j], PublicBindingDigest: digest}
		}
		if !slices.Contains(ids, s.admission.recipient) {
			return fail()
		}
		shape.Memberships += uint64(len(ids))
		if m.ConfidentialityClass == contract.Secret {
			shape.Secrets++
			shape.SecretMemberships += uint64(len(ids))
			if slot, ok := before[m.Name]; ok {
				grantCount, err := generatedDeclarationGrantCount(s.valueEntry(slot), m, entry, ids, selected)
				if err != nil {
					return generatedCapacityShape{}, err
				}
				shape.finalImageGrants += grantCount
			}
		}
		// Fresh generated outputs are charged by CurrentAccess and the create
		// image rows. Every other planned secret may preserve old material.
		// Bound that image by its exact intended/current/canonical reader union;
		// keep fresh/exclusion branches conservative instead of crediting release.
		if m.ConfidentialityClass == contract.Secret && (m.ValueSource != contract.Generated || m.ChangeMask&contract.GeneratorValueChangeContent == 0) {
			var current *contract.ValueEntry
			if slot, present := before[m.Name]; present {
				current = s.valueEntry(slot)
			}
			readers, err := generatedFinalImageReaderCount(current, ids, selected, shape.Recipients)
			if err != nil {
				return generatedCapacityShape{}, err
			}
			finalImageReaders += readers
		}
		n := uint64(len(entry.Payload))
		switch entry.Kind {
		case contract.GeneratorDeclarationPlain:
			content, err := contract.InputContentLength(entry.InputEncoding, entry.Payload)
			if err != nil {
				return fail()
			}
			n = uint64(content)
		case contract.GeneratorDeclarationSealed:
			source, err := contract.InspectSealedInputEnvelope(entry.Payload)
			if err != nil {
				return fail()
			}
			bindingSet, err := contract.IntendedRecipientBindingSetDigest(s.root.Domain, s.admission.recipient, refs)
			if err != nil || source.Core.CompatibilityID != s.root.CurrentAccess.Core.CompatibilityID ||
				source.Core.CryptoSupportID != s.root.CurrentAccess.Core.CryptoSupportID {
				return fail()
			}
			if source.Core.IntendedRecipientBindingSetDigest != bindingSet {
				slot, present := before[m.Name]
				if !present || m.ValueSource != contract.Supplied || m.ConfidentialityClass != contract.Secret || m.ChangeMask&contract.GeneratorValueChangeContent != 0 {
					return generatedCapacityShape{}, &sealedInputBindingError{name: strings.Clone(m.Name)}
				}
				current := s.valueEntry(slot)
				if current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret || current.Incarnation != m.EntryIncarnationID ||
					slices.ContainsFunc(ids, func(id contract.ID) bool { return !slices.Contains(current.Recipients, id) }) {
					return generatedCapacityShape{}, &sealedInputBindingError{name: strings.Clone(m.Name)}
				}
			}
			n = uint64(source.Core.ContentLength)
		case contract.GeneratorDeclarationRetained:
			r, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
			slot, ok := before[m.Name]
			if err != nil || !ok || r.OriginalSlot != slot {
				return fail()
			}
			current, err := contract.EncodeValueEntry(*s.valueEntry(slot))
			original, originalErr := contract.EncodeValueEntry(r.Entry)
			if err != nil || originalErr != nil || !bytes.Equal(current, original) {
				return fail()
			}
			// Delete declarations qualify unchanged current values. They do not
			// install canonical support or replace historical reader metadata.
			// Declaration/current material and selected backlog remain charged.
			if !currentOnlyDelete {
				if shape.RetainedRows == nil {
					shape.RetainedRows = make(map[contract.ID][]byte)
				}
				sourceID, err := contract.AdmissionEntryDigest(r)
				if err != nil {
					return fail()
				}
				if _, exists := shape.RetainedRows[sourceID]; exists {
					return fail()
				}
				shape.RetainedRows[sourceID] = entry.Payload
				shape.RetainedSources++
			}
			core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, r.Entry)
			if err != nil {
				return fail()
			}
			n = uint64(core.ContentLength)
		case contract.GeneratorDeclarationGenerated, contract.GeneratorDeclarationGeneratedReference:
			shape.Generated++
			var meta contract.GeneratorDeclaredGeneration
			var logical contract.GeneratorLogicalSlice
			if entry.Kind == contract.GeneratorDeclarationGeneratedReference {
				ref, err := contract.InspectGeneratorDeclaredGenerationReferenceForEntry(entry.Schema, entry.Payload)
				if err != nil || m.ChangeMask&contract.GeneratorValueChangeContent != 0 {
					return fail()
				}
				meta = contract.GeneratorDeclaredGeneration{Schema: ref.Schema, LifecycleMode: ref.LifecycleMode, Epoch: ref.Epoch, RetirementMode: ref.RetirementMode, ConfigContractID: ref.ConfigContractID,
					ResourceContractID: ref.ResourceContractID, CompletionClass: ref.CompletionClass}
				logical = ref.Intent
			} else {
				var err error
				meta, err = contract.InspectGeneratorDeclaredGenerationForEntry(entry.Schema, entry.Payload)
				if err != nil {
					return fail()
				}
				logical = contract.GeneratorLogicalSlice{Schema: 1, ContentKind: contract.GeneratorContentIntent,
					ContentID: m.IntentDigest, Length: uint32(len(meta.Intent)), Digest: contract.Hash(meta.Intent)}
			}
			var current *contract.ValueEntry
			if slot, ok := before[m.Name]; ok {
				current = s.valueEntry(slot)
			}
			if !generatedEpochValid(current, m, meta) {
				return fail()
			}
			if m.ChangeMask&contract.GeneratorValueChangeContent != 0 {
				// All permitted return branches use the same declared value bound.
				n = 0
				for _, lineage := range g.Lineages {
					if lineage.Purpose != contract.GeneratorLineageCreate || lineage.LineageID != m.LineageID {
						continue
					}
					for _, x := range lineage.Templates[:lineage.TemplateCount] {
						_, use, ok := generatedTemplate(g, x.AttemptID)
						if !ok {
							return fail()
						}
						n = max(n, uint64(use.MaxSecret))
					}
				}
			} else {
				if _, err := s.generatedCurrentIntentSelection(ctx, selected, m, logical); err != nil {
					return generatedCapacityShape{}, err
				}
				core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, *current)
				if err != nil {
					return fail()
				}
				n = uint64(core.ContentLength)
			}
		}
		raw += n
		if n > contract.CryptoMaxRawValue || raw > contract.CryptoMaxRawSet || shape.Memberships > contract.CryptoMaxMemberships || shape.Generated > contract.GeneratedCurrentEntryLimit {
			return generatedCapacityShape{}, contract.ErrRecordCapacity
		}
	}
	for _, lineage := range g.Lineages {
		if used[lineage.LineageID] {
			return fail()
		}
		switch lineage.Purpose {
		case contract.GeneratorLineageCreate:
			shape.Creates++
		case contract.GeneratorLineageRetirement:
			shape.Retirements++
			if lineage.Templates[0].CompletionClass == contract.GeneratedCompletionConfirmed {
				shape.ControlledRetirements++
			}
		case contract.GeneratorLineageCleanup:
			if g.Header.LineageCount == 0 {
				shape.Cleanups++
				if lineage.Templates[0].CompletionClass == contract.GeneratedCompletionConfirmed {
					shape.ControlledCleanups++
				}
			}
		}
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			for _, id := range []contract.ID{x.AttemptID, x.PlannedValueSlotID, x.TransmissionID, x.ResultID, x.InboxID} {
				if used[id] {
					return fail()
				}
			}
			if x.SemanticLifecycleMode() != contract.GeneratorLifecycleNone && used[x.HazardID] {
				return fail()
			}
			if x.Action == contract.GeneratorActionCreate && (used[x.ResourceIncarnationID] || used[x.DutyID]) {
				return fail()
			}
		}
	}
	planned := make(map[string]contract.GeneratorValueEntryPlan, len(g.ValueEntryPlans))
	for _, entryPlan := range g.ValueEntryPlans {
		planned[entryPlan.Name] = entryPlan
	}
	retirements := uint64(0)
	for _, entry := range s.root.Names {
		current := s.valueEntry(entry.Slot)
		if current == nil || current.ValueSource != contract.Generated || current.Generated.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			continue
		}
		next, present := planned[current.Name]
		if present && next.ValueSource == contract.Generated && next.ChangeMask&contract.GeneratorValueChangeContent == 0 {
			continue
		}
		if _, ok := generatedRetirementTemplate(g, *current); !ok {
			return fail()
		}
		retirements++
	}
	deletion, deleteOnly, err := s.generatedDeleteReservationSelection(ctx, g, selected)
	if err != nil {
		return generatedCapacityShape{}, err
	}
	if deleteOnly {
		shape.deleteSupport = deletion.source.Support
	}
	if shape.Retirements != retirements && (!deleteOnly || shape.Retirements != 1 || retirements != 0) {
		return fail()
	}
	for _, present := range pages {
		if present {
			shape.ValueEntryPageCount++
		}
	}
	shape.ValueEntryCount, shape.ValueEntryPageCount = max(uint64(len(s.root.Names)), uint64(len(g.ValueEntryPlans))), max(oldPages, shape.ValueEntryPageCount)
	shape.Secrets, shape.Generated = max(shape.Secrets, oldSecrets), max(shape.Generated, shape.OldGenerated)
	shape.Memberships, shape.SecretMemberships = max(shape.Memberships, oldMemberships), max(shape.SecretMemberships, oldSecretMemberships)
	outputEntries, err := generatedDeclarationOutputEntries(d)
	if err != nil {
		return generatedCapacityShape{}, err
	}
	output, err := s.generatedRequestedOutputTransition(ctx, g, recipients, outputEntries, outputImage)
	if err != nil {
		return generatedCapacityShape{}, err
	}
	if err := output.ValidateSuccessorRouting(g, d); err != nil {
		return fail()
	}
	if g.Request.Schema == contract.GeneratorApplyRequestCoreSchema {
		shape.DesiredOutputBytes = uint64(len(outputImage))
		shape.outputSupport, err = s.generatedOutputSupportCapacity(ctx, output, g)
		if err != nil {
			return generatedCapacityShape{}, err
		}
	}
	if err := s.checkGeneratedGrantCount(int(shape.finalImageGrants)); err != nil {
		return generatedCapacityShape{}, err
	}
	return shape, nil
}

func generatedEpochValid(current *contract.ValueEntry, plan contract.GeneratorValueEntryPlan, meta contract.GeneratorDeclaredGeneration) bool {
	if current == nil || current.ValueSource == contract.Supplied {
		return plan.Epoch == 0 && plan.ChangeMask&contract.GeneratorValueChangeContent != 0
	}
	g := current.Generated
	if plan.Epoch < g.Epoch || plan.Epoch == g.Epoch && (plan.IntentDigest != g.IntentDigest || plan.InputEncoding != current.InputEncoding) {
		return false
	}
	if plan.Epoch > g.Epoch {
		return plan.ChangeMask&contract.GeneratorValueChangeContent != 0
	}
	return plan.ChangeMask&contract.GeneratorValueChangeContent == 0 && meta.ConfigContractID == g.ConfigContractID && meta.ResourceContractID == g.ResourceContractID && meta.LifecycleMode == g.LifecycleMode &&
		meta.CompletionClass == g.CompletionClass && meta.RetirementMode == g.RetirementMode
}

func (g *generatedSelection) continuationCurrentOpens(ctx context.Context) (uint32, error) {
	if g == nil || g.parent == nil || len(g.bundles) == 0 {
		return 0, contract.ErrRecord
	}
	live := g.sources[g.parent.MaterialID]
	if len(live) == 0 {
		return 0, nil
	}
	read, err := g.fragmentReader()
	if err != nil {
		return 0, err
	}
	body, err := g.content.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength, read)
	if err != nil {
		return 0, err
	}
	defer clear(body[:cap(body)])
	declaration, err := contract.InspectGeneratorDeclaration(body)
	if err != nil || declaration.EntryCount() != len(g.bundles[0].ValueEntryPlans) {
		return 0, contract.ErrRecord
	}
	var opens uint32
	for at, plan := range g.bundles[0].ValueEntryPlans {
		if plan.ValueSource != contract.Supplied || plan.ConfidentialityClass != contract.Secret || plan.ChangeMask&contract.GeneratorValueChangeContent != 0 {
			continue
		}
		entry, _, err := declaration.Entry(at)
		if err != nil {
			return 0, err
		}
		if entry.Kind != contract.GeneratorDeclarationSealed {
			continue
		}
		source, err := contract.InspectSealedInputEnvelope(entry.Payload)
		if err != nil {
			return 0, err
		}
		if slices.ContainsFunc(live, func(use contract.GeneratorSourceUse) bool { return use.SourceID == source.Core.SourceID }) {
			opens++
		}
	}
	return opens, nil
}

// generatedFinalImageReaderCount uses only the authenticated predecessor and
// exact declared membership. An active generated parent blocks changed ordinary
// declarations, so its continuation cannot add a new unreserved reader set.
// Aliased canonical records do not duplicate a reader within one material.
// The complete union remains charged even when exclusion will use new material.
func generatedFinalImageReaderCount(current *contract.ValueEntry, intended []contract.ID, selected *generatedSelection, registryCount uint64) (uint64, error) {
	if selected == nil || registryCount == 0 || registryCount > contract.CryptoMaxRecipients {
		return 0, contract.ErrRecord
	}
	readers := slices.Clone(intended)
	if current != nil && current.ConfidentialityClass == contract.Secret {
		readers = append(readers, current.Recipients...)
		readers = append(readers, selected.retainedReaders(current.ValueState)...)
	}
	slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	readers = slices.Compact(readers)
	if uint64(len(readers)) > registryCount {
		return 0, contract.ErrRecordCapacity
	}
	return uint64(len(readers)), nil
}
