package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
)

// Both the mutation owner and read-only continuation inspection use these
// selected facts. Request admission, current HEAD identity and Crypto envelopes
// remain with the mutation owner.
type generatedFinalProjection struct {
	results      []generatedFinalResult
	entryPlans   []contract.CryptoGeneratedValueEntryPlan
	supplied     contract.IdentityPlan
	sealedInputs []contract.CryptoSealedInput
	plain        []contract.ValueEntry
	retirements  []generatedFinalRetirement
	selecting    bool
}

type generatedFinalResultFacts struct {
	results   []generatedFinalResult
	byLineage map[contract.ID]generatedFinalResult
	selecting bool
	evidence  contract.GeneratorDescriptor
}

func generatedFinalPhaseSteps(bundle contract.GeneratorPlanBundle, materialized bool) uint64 {
	steps := uint64(1 + 3*len(contract.GeneratedAutomaticRetirementIndices(bundle)))
	if !materialized {
		steps++
	}
	return steps
}

func selectedFinalResults(g *generatedSelection) (generatedFinalResultFacts, error) {
	var out generatedFinalResultFacts
	if g == nil || g.parent == nil || g.phase == nil || len(g.bundles) == 0 || g.phase.Stage != contract.GeneratedStageTerminal || generatedSelectionAnchored(g) {
		return out, contract.ErrRecord
	}
	bundle, parent := g.bundles[0], *g.parent
	results := make([]generatedFinalResult, 0, parent.LineageCount)
	byLineage := make(map[contract.ID]generatedFinalResult, parent.LineageCount)
	selecting := true
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		var frontier *generatedAttempt
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			a, entered := g.attempts[x.AttemptID]
			if !entered {
				continue
			}
			attemptCopy := a
			frontier = &attemptCopy
			if len(a.result) == 0 {
				if !generatedFinalLocalFailure(g, a) && (a.record.State != contract.GeneratedEffectClosedWithResidue || a.record.Stage != contract.GeneratedStageTerminal) {
					return out, contract.ErrRecord
				}
				continue
			}
			result, err := contract.InspectGeneratedResultRecord(a.result)
			state := uint8(contract.GeneratedEffectSucceeded)
			switch result.SafeFacts.Disposition {
			case contract.GeneratorDispositionCompleteCreate:
			case contract.GeneratorDispositionOwnedUnusableCreate:
				state = contract.GeneratedEffectFailedTerminal
			case contract.GeneratorDispositionConfirmedNoEffect:
				state = contract.GeneratedEffectConfirmedNoEffect
			case contract.GeneratorDispositionUnknown:
				state = contract.GeneratedEffectClosedWithResidue
			default:
				return out, contract.ErrRecord
			}
			if err != nil || a.record.State != state || a.record.Stage != contract.GeneratedStageTerminal {
				return out, contract.ErrRecord
			}
			results = append(results, generatedFinalResult{attempt: a, reference: contract.GeneratorResultReference{Schema: 1,
				ResultID: result.Core.ResultID, ResultBodyDigest: contract.Hash(a.result), ResultLength: uint32(len(a.result))}})
		}
		if frontier == nil {
			return out, contract.ErrRecord
		}
		if len(frontier.result) == 0 {
			if !generatedFinalLocalFailure(g, *frontier) && !generatedLineageTerminalUncertain(g, lineage) {
				return out, contract.ErrRecord
			}
			selecting = false
			continue
		}
		result, err := contract.InspectGeneratedResultRecord(frontier.result)
		if err != nil || result.SafeFacts.Disposition < contract.GeneratorDispositionCompleteCreate || result.SafeFacts.Disposition > contract.GeneratorDispositionUnknown {
			return out, contract.ErrRecord
		}
		if result.SafeFacts.Disposition != contract.GeneratorDispositionCompleteCreate {
			selecting = false
			continue
		}
		byLineage[lineage.LineageID] = generatedFinalResult{attempt: *frontier, reference: contract.GeneratorResultReference{Schema: 1,
			ResultID: result.Core.ResultID, ResultBodyDigest: contract.Hash(frontier.result), ResultLength: uint32(len(frontier.result))}}
	}
	references := make([]contract.GeneratorResultReference, len(results))
	for i := range results {
		references[i] = results[i].reference
	}
	slices.SortFunc(references, func(a, b contract.GeneratorResultReference) int { return bytes.Compare(a.ResultID[:], b.ResultID[:]) })
	evidence, err := contract.GeneratorResultReferencesDescriptor(references)
	if err != nil {
		return out, fmt.Errorf("generated final results: %w", err)
	}
	return generatedFinalResultFacts{results: results, byLineage: byLineage, selecting: selecting, evidence: contract.GeneratorDescriptor(evidence)}, nil
}

func generatedFinalLocalFailure(g *generatedSelection, a generatedAttempt) bool {
	if g == nil || g.parent == nil || !generatedLocalFailureAttempt(a) ||
		a.record.DomainID != g.parent.DomainID || a.record.OperationID != g.parent.OperationID {
		return false
	}
	_, present := g.records[generatedRecordKey{contract.GeneratedResultSupportKind, a.record.ResultID}]
	return !present
}

func selectedFinalProjection(ctx context.Context, image *selectedImage, g *generatedSelection, phaseID contract.ID, facts generatedFinalResultFacts) (generatedFinalProjection, error) {
	var out generatedFinalProjection
	if ctx == nil || image == nil || g == nil || g.parent == nil || len(g.bundles) == 0 {
		return out, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	bundle, parent := g.bundles[0], *g.parent
	results, byLineage, selecting := facts.results, facts.byLineage, facts.selecting
	snapshot, err := contract.GeneratorPhaseSnapshotID(phaseID)
	if err != nil {
		return out, err
	}
	transition, err := contract.GeneratorPhaseTransitionID(phaseID)
	if err != nil {
		return out, err
	}
	revision, err := contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		return out, err
	}
	var declaration contract.GeneratorDeclarationView
	if selecting {
		var declarationBody []byte
		if len(image.fragmentFacts) != 0 {
			declarationBody, err = g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, parent.OperationID, contract.GeneratorDeclarationMaxLength)
		} else {
			declarationBody, err = g.content.read(contract.GeneratorContentDeclaration, parent.OperationID, contract.GeneratorDeclarationMaxLength)
		}
		if err != nil {
			return out, fmt.Errorf("generated final declaration: %w", err)
		}
		declaration, err = contract.InspectGeneratorDeclaration(declarationBody)
		if err != nil {
			return out, fmt.Errorf("generated final declaration: %w", err)
		}
	}
	var retirements []generatedFinalRetirement
	if selecting {
		retirements, err = image.generatedFinalRetirements(g, bundle)
		if err != nil {
			return out, fmt.Errorf("generated final retirements: %w", err)
		}
	}
	retiring := make(map[string]contract.ID, len(retirements))
	for _, retirement := range retirements {
		retiring[retirement.target.Name] = retirement.template.DutyID
	}
	// Removal can leave an exact retirement without a current entry. A later
	// generated re-add gets a fresh incarnation and the same retiring pointer.
	for key, row := range g.records {
		if key.kind != contract.GeneratedDutySupportKind {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return out, err
		}
		if duty.Kind != contract.GeneratedDutyRetirement {
			continue
		}
		target, err := g.retirementTarget(ctx, duty)
		if err != nil {
			return out, err
		}
		if prior, ok := retiring[target.Name]; ok && prior != duty.DutyID {
			return out, contract.ErrRecord
		}
		retiring[target.Name] = duty.DutyID
	}
	entryPlans := make([]contract.CryptoGeneratedValueEntryPlan, 0, len(results))
	if !selecting {
		entryPlans = nil
	}
	for i, entryPlan := range bundle.ValueEntryPlans {
		if entryPlan.ValueSource != contract.Generated || entryPlan.ChangeMask&contract.GeneratorValueChangeContent == 0 {
			continue
		}
		if !selecting {
			continue
		}
		selected, ok := byLineage[entryPlan.LineageID]
		if !ok {
			return out, contract.ErrRecord
		}
		result, err := contract.DecodeGeneratedResultRecord(selected.attempt.result)
		if err != nil {
			return out, err
		}
		coreBody, err := contract.EncodeGeneratedResultCore(result.Core)
		if err != nil {
			return out, err
		}
		factsBody, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
		if err != nil {
			return out, err
		}
		location, ok := g.content.locations[generatedContentKey{contract.GeneratorContentIntent, entryPlan.IntentDigest}]
		if !ok {
			return out, contract.ErrRecord
		}
		intent, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical()})
		if err != nil {
			return out, err
		}
		evidence := contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema, OriginalResultID: selected.reference.ResultID,
			CredentialRouteID: selected.attempt.expected.Template.CredentialRouteID, ResultCore: coreBody, SafeFacts: factsBody, Intent: intent, CompletionClass: selected.attempt.expected.Template.CompletionClass}
		evidence.LifecycleMode = selected.attempt.expected.Template.LifecycleMode
		evidenceDescriptor, err := contract.GeneratedCreateEvidenceDescriptor(evidence)
		if err != nil {
			return out, err
		}
		x := selected.attempt.expected.Template
		var resourceDigest contract.ID
		if x.LifecycleMode == contract.GeneratorLifecycleManaged {
			resourceDigest, err = contract.GeneratorResourceDigest(result.SafeFacts)
			if err != nil {
				return out, err
			}
		}
		meta := contract.GeneratedEntryMetadata{Schema: contract.GeneratedEntryMetadataSchema, Epoch: entryPlan.Epoch, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID,
			IntentDigest: x.IntentDigest, ResourceIncarnationID: x.ResourceIncarnationID, OriginOperationID: parent.OperationID,
			OriginAttemptID: x.AttemptID, GenerationID: x.PlannedValueSlotID, ResourceDigest: resourceDigest,
			CreateResultID: selected.reference.ResultID, CreateEvidence: evidenceDescriptor,
			RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), CompletionClass: x.CompletionClass,
			RetirementMode: entryPlan.RetirementMode}
		meta.LifecycleMode = x.LifecycleMode
		if duty, ok := retiring[entryPlan.Name]; ok {
			meta.RetiringDutyPresent, meta.RetiringDutyID = 1, duty
		}
		binding, err := contract.GeneratedBindingDigest(meta)
		if err != nil {
			return out, fmt.Errorf("generated final binding: %w", err)
		}
		identity, err := contract.DeriveGeneratedValueIdentity(x.PlannedValueSlotID, phaseID, selected.reference.ResultID, binding)
		if err != nil {
			return out, fmt.Errorf("generated final identity: %w", err)
		}
		meta.GenerationID = identity.ValueStateID
		value := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: parent.DomainID,
			CompatibilityID: image.root.CurrentAccess.Core.CompatibilityID, CryptoSupportID: image.root.CurrentAccess.Core.CryptoSupportID,
			Name: entryPlan.Name, EntryIncarnationID: entryPlan.EntryIncarnationID, ValueStateID: identity.ValueStateID,
			OriginSnapshotID: identity.OriginSnapshotID, OriginTransitionID: identity.OriginTransitionID,
			DataKeyID: identity.DataKeyID, DataKeyEpoch: 1, CommitmentKeyID: identity.CommitmentKeyID, CommitmentKeyEpoch: 1,
			InputEncoding: result.Payload.InputEncoding, ContentLength: result.Payload.ContentLength, RetainedLength: result.Payload.RetainedLength, ValueSource: contract.Generated, GeneratedBindingDigest: binding}
		entry, _, err := declaration.Entry(i)
		if err != nil || string(entry.Name) != entryPlan.Name {
			return out, contract.ErrRecord
		}
		recipients := make([]contract.ID, len(entry.RecipientIDs)/32)
		for j := range recipients {
			recipients[j] = contract.ID(entry.RecipientIDs[j*32 : (j+1)*32])
		}
		entryPlans = append(entryPlans, contract.CryptoGeneratedValueEntryPlan{Slot: entryPlan.Slot, OutputEncoding: entryPlan.OutputEncoding, Result: bytes.Clone(selected.attempt.result),
			ValueCore: value, Generated: meta, Recipients: recipients})
	}
	slices.SortFunc(entryPlans, func(a, b contract.CryptoGeneratedValueEntryPlan) int { return int(a.Slot) - int(b.Slot) })
	supplied := contract.IdentityPlan{Operation: parent.OperationID, Transition: transition, Snapshot: snapshot, Revision: revision}
	var sealedInputs []contract.CryptoSealedInput
	var plain []contract.ValueEntry
	if selecting {
		for i, entryPlan := range bundle.ValueEntryPlans {
			prepareSupplied := entryPlan.ValueSource == contract.Supplied && entryPlan.ChangeMask&contract.GeneratorValueChangeContent != 0
			prepareMembership := entryPlan.ChangeMask&contract.GeneratorValueChangeMembership != 0 && entryPlan.ChangeMask&contract.GeneratorValueChangeContent == 0
			if !prepareSupplied && !prepareMembership {
				continue
			}
			entry, _, err := declaration.Entry(i)
			if err != nil || string(entry.Name) != entryPlan.Name || entry.ValueSource() != entryPlan.ValueSource || entry.ConfidentialityClass() != entryPlan.ConfidentialityClass {
				return out, contract.ErrRecord
			}
			recipients := make([]contract.ID, len(entry.RecipientIDs)/32)
			for j := range recipients {
				recipients[j] = contract.ID(entry.RecipientIDs[j*32 : (j+1)*32])
			}
			var identity contract.IdentityRow
			if prepareMembership {
				current := image.valueEntry(entryPlan.Slot)
				if current == nil || current.ValueSource != entryPlan.ValueSource || current.Incarnation != entryPlan.EntryIncarnationID {
					return out, contract.ErrRecord
				}
				identity = contract.IdentityRow{Name: current.Name, Slot: entryPlan.Slot, Incarnation: current.Incarnation,
					ValueState: current.ValueState, OriginSnapshot: current.OriginSnapshot, OriginTransition: current.OriginTransition}
			} else if entry.Kind == contract.GeneratorDeclarationRetained {
				record, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
				current := image.valueEntry(entryPlan.Slot)
				if err != nil || record.OriginalSlot != entryPlan.Slot || current == nil || !sameRetainedEntryValue(*current, record.Entry) {
					return out, contract.ErrRecord
				}
				identity = contract.IdentityRow{Name: record.Entry.Name, Slot: entryPlan.Slot, Incarnation: record.Entry.Incarnation,
					ValueState: record.Entry.ValueState, OriginSnapshot: record.Entry.OriginSnapshot, OriginTransition: record.Entry.OriginTransition}
			} else {
				value, err := contract.GeneratorPhaseValueID(phaseID, entryPlan.Slot)
				if err != nil {
					return out, err
				}
				identity = contract.IdentityRow{Name: entryPlan.Name, Slot: entryPlan.Slot, Incarnation: entryPlan.EntryIncarnationID,
					ValueState: value, OriginSnapshot: snapshot, OriginTransition: transition}
			}
			if current := image.generatedFinalPredecessor(entryPlan.Slot, entryPlan.Name); current != nil && current.ConfidentialityClass == contract.Secret &&
				entryPlan.ConfidentialityClass == contract.Secret && generatedFinalExcludesReader(*current, recipients) {
				value, err := contract.GeneratorPhaseValueID(phaseID, entryPlan.Slot)
				if err != nil {
					return out, err
				}
				identity.ValueState, identity.OriginSnapshot, identity.OriginTransition = value, snapshot, transition
			}
			supplied.Rows = append(supplied.Rows, identity)
			switch entry.Kind {
			case contract.GeneratorDeclarationPlain:
				content, err := contract.InputContentLength(entryPlan.InputEncoding, entry.Payload)
				if err != nil {
					return out, err
				}
				plain = append(plain, contract.ValueEntry{Name: entryPlan.Name, Incarnation: identity.Incarnation, ValueState: identity.ValueState,
					OriginSnapshot: identity.OriginSnapshot, OriginTransition: identity.OriginTransition, ValueSource: contract.Supplied,
					ConfidentialityClass: contract.Plain, InputEncoding: entryPlan.InputEncoding, OutputEncoding: entryPlan.OutputEncoding, ContentLength: content, RetainedLength: uint32(len(entry.Payload)), Recipients: recipients, ValueBytes: bytes.Clone(entry.Payload)})
			case contract.GeneratorDeclarationSealed:
				sealedInputs = append(sealedInputs, contract.CryptoSealedInput{Name: entryPlan.Name, EnvelopeBytes: bytes.Clone(entry.Payload)})
			case contract.GeneratorDeclarationRetained, contract.GeneratorDeclarationGenerated, contract.GeneratorDeclarationGeneratedReference:
			default:
				return out, contract.ErrRecord
			}
		}
	}
	if _, err := contract.IdentityPlanDescriptor(supplied); err != nil {
		return out, err
	}
	return generatedFinalProjection{results: results, entryPlans: entryPlans, supplied: supplied, sealedInputs: sealedInputs, plain: plain, retirements: retirements, selecting: selecting}, nil
}

func (s *selectedImage) generatedFinalRetirements(g *generatedSelection, bundle contract.GeneratorPlanBundle) ([]generatedFinalRetirement, error) {
	if s == nil || g == nil {
		return nil, contract.ErrRecord
	}
	planned := make(map[string]contract.GeneratorValueEntryPlan, len(bundle.ValueEntryPlans))
	for _, entryPlan := range bundle.ValueEntryPlans {
		planned[entryPlan.Name] = entryPlan
	}
	retirementCount := 0
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose == contract.GeneratorLineageRetirement {
			retirementCount++
		}
	}
	retirements := make([]generatedFinalRetirement, 0, retirementCount)
	for _, entry := range s.root.Names {
		old := s.valueEntry(entry.Slot)
		if old == nil || old.ValueSource != contract.Generated || old.Generated.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			continue
		}
		next, present := planned[old.Name]
		if present && next.ValueSource == contract.Generated && next.ChangeMask&contract.GeneratorValueChangeContent == 0 {
			continue
		}
		x, ok := generatedRetirementTemplate(bundle, *old)
		if !ok {
			return nil, contract.ErrRecord
		}
		evidenceRow, ok := g.records[generatedRecordKey{kind: contract.GeneratedCreateEvidenceSupportKind, id: old.Generated.CreateResultID}]
		if !ok {
			return nil, contract.ErrRecord
		}
		evidence, err := contract.InspectGeneratedCreateEvidence(evidenceRow.Body)
		if err != nil {
			return nil, err
		}
		created, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
		if err != nil {
			return nil, err
		}
		target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: old.Name, IncarnationID: old.Incarnation, Epoch: old.Generated.Epoch,
			ResourceID: old.Generated.ResourceIncarnationID, ResourceDigest: old.Generated.ResourceDigest,
			ConfigContractID: old.Generated.ConfigContractID, ResourceContractID: old.Generated.ResourceContractID,
			OriginalOperationID: old.Generated.OriginOperationID, OriginalAttemptID: old.Generated.OriginAttemptID,
			ResultContractID: created.ResultContractID, CompletionClass: old.Generated.CompletionClass}
		retirements = append(retirements, generatedFinalRetirement{template: x, target: target, support: old.Generated.RequiredSupport})
	}
	if len(retirements) != retirementCount {
		return nil, contract.ErrRecord
	}
	slices.SortFunc(retirements, func(a, b generatedFinalRetirement) int {
		return bytes.Compare([]byte(a.target.Name), []byte(b.target.Name))
	})
	return retirements, nil
}

func (p *generatedFinalProjection) clearOwnedInputs() {
	if p == nil {
		return
	}
	for i := range p.entryPlans {
		clear(p.entryPlans[i].Result[:cap(p.entryPlans[i].Result)])
		p.entryPlans[i].Result = nil
	}
	for i := range p.sealedInputs {
		clear(p.sealedInputs[i].EnvelopeBytes[:cap(p.sealedInputs[i].EnvelopeBytes)])
		p.sealedInputs[i].EnvelopeBytes = nil
	}
	for i := range p.plain {
		clear(p.plain[i].ValueBytes[:cap(p.plain[i].ValueBytes)])
		p.plain[i].ValueBytes = nil
	}
	p.entryPlans, p.sealedInputs, p.plain = nil, nil, nil
}

// Matching the selected preparation's current controls is necessary before its
// encrypted rows can be reused. Full historical row qualification follows.
func selectedFinalMaterialization(ctx context.Context, image *selectedImage, g *generatedSelection, facts generatedFinalResultFacts, reuse bool) (*contract.GeneratedFinalPreparationRecord, error) {
	if ctx == nil || image == nil || g == nil {
		return nil, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if g.preparation == nil {
		return nil, nil
	}
	if !facts.selecting || g.preparation.MaterializationPhase.Evidence != facts.evidence {
		return nil, contract.ErrRecord
	}
	bindings, err := image.generatedBindings(g)
	if err != nil {
		return nil, err
	}
	control, valid := selectedControlFrom(image.root, &image.recipients, image.root.CurrentAccess.Core.AuthorityRecipientID)
	if !valid {
		return nil, contract.ErrRecord
	}
	digest, err := contract.GeneratedFinalPreparationBindingDigest(control, bindings)
	if err != nil {
		return nil, err
	}
	if reuse && digest == g.preparation.ControlBindingDigest {
		return g.preparation, nil
	}
	return nil, nil
}

func selectedFinalPreparationReusable(ctx context.Context, image *selectedImage, g *generatedSelection) (bool, error) {
	facts, err := selectedFinalResults(g)
	if err != nil {
		return false, err
	}
	materialization, err := selectedFinalMaterialization(ctx, image, g, facts, true)
	if err != nil || materialization == nil {
		return false, err
	}
	phaseID, err := contract.GeneratorPhaseID(materialization.MaterializationPhase)
	if err != nil {
		return false, err
	}
	projection, err := selectedFinalProjection(ctx, image, g, phaseID, facts)
	if err != nil {
		return false, err
	}
	defer projection.clearOwnedInputs()
	prepared, err := selectedFinalPreparationImage(ctx, g)
	if err != nil {
		return false, err
	}
	defer prepared.Clear()
	rows, err := image.validateGeneratedFinalRows(ctx, g, &projection, true, prepared.Generated, prepared.Supplied, true)
	if err != nil {
		return false, err
	}
	defer rows.clearOwnedSupplied()
	return !rows.legacyExclusion, nil
}
