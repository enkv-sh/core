package core

import (
	"bytes"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
)

func generatedTemplate(g contract.GeneratorPlanBundle, attempt contract.ID) (contract.GeneratorAttemptTemplate, contract.GeneratorResultUse, bool) {
	for _, lineage := range g.Lineages {
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			if template.AttemptID != attempt {
				continue
			}
			for _, use := range g.ResultUses {
				if use.AttemptID == attempt {
					return template, use, true
				}
			}
		}
	}
	return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
}

func generatedAttemptMatches(a contract.GeneratedAttemptRecord, x contract.GeneratorAttemptTemplate) bool {
	id, err := contract.GeneratorTemplateID(x)
	return err == nil && (a.Schema == contract.GeneratedAttemptRecordSchema && x.Schema == contract.GeneratorAttemptTemplateSchema) && a.SemanticLifecycleMode() == x.SemanticLifecycleMode() && a.LineageID == x.LineageID && a.AttemptID == x.AttemptID && a.TemplateDigest == id &&
		a.PredecessorAttemptID == x.PredecessorAttemptID && a.OwnerID == x.DutyID && a.ResourceID == x.ResourceIncarnationID &&
		a.TransmissionID == x.TransmissionID && a.ResultID == x.ResultID && a.InboxID == x.InboxID && a.ConfigContractID == x.ConfigContractID &&
		a.ResourceContractID == x.ResourceContractID && a.ExecutorID == x.ExecutorID && a.CredentialRouteID == x.CredentialRouteID &&
		a.DescriptorID == x.DescriptorID && a.ResultContractID == x.ResultContractID && a.CompletionClass == x.CompletionClass
}

func (b *generatedSelectionBuilder) operationMaterial(bundle contract.GeneratorPlanBundle) (contract.OperationMaterialRecord, error) {
	if b == nil || b.facts == nil {
		return contract.OperationMaterialRecord{}, contract.ErrRecord
	}
	g := b.facts
	row, ok := b.claimRecord(contract.OperationMaterialSupportKind, bundle.Header.MaterialID)
	if !ok {
		return contract.OperationMaterialRecord{}, contract.ErrRecord
	}
	material, err := contract.InspectOperationMaterialRecord(row.Body)
	use, useErr := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	c := g.image.root.CurrentAccess.Core
	if err != nil || useErr != nil || material.Core.DomainID != g.image.root.Domain || material.Core.OperationID != bundle.Header.OperationID ||
		material.Core.OperationMaterialID != bundle.Header.MaterialID || material.Core.UsePlanDigest != use || material.Core.CompatibilityID != c.CompatibilityID ||
		material.Core.CryptoSupportID != c.CryptoSupportID {
		return contract.OperationMaterialRecord{}, contract.ErrRecord
	}
	access, ok := g.materialAccess(contract.OperationSeedMaterialKind, material.Core.OperationMaterialID)
	context, err := contract.OperationMaterialContextDigest(material.Core)
	if !ok || err != nil || access.MaterialContextDigest != context || access.PackageCheck != material.SeedCheck ||
		!g.validateMaterialWraps(access, []contract.ID{c.AuthorityRecipientID}) {
		return contract.OperationMaterialRecord{}, contract.ErrRecord
	}
	if !b.claimMaterial(materialIdentity{contract.OperationSeedMaterialKind, material.Core.OperationMaterialID}) {
		return contract.OperationMaterialRecord{}, contract.ErrRecord
	}
	return material, nil
}

func (b *generatedSelectionBuilder) resolveActive(rows []contract.SupportRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	c := g.image.root.Generated
	var graphs, owners []contract.ID
	if !c.ActiveOwner.IsZero() {
		row, ok := b.claimRecord(contract.GeneratedParentSupportKind, c.ActiveOwner)
		if !ok {
			return contract.ErrRecord
		}
		parent, err := contract.InspectGeneratedParentRecord(row.Body)
		if err != nil || parent.PlanGraphID != c.ActiveGraph {
			return contract.ErrRecord
		}
		row, ok = b.claimRecord(contract.GeneratedPhaseSupportKind, parent.OperationID)
		if !ok {
			return contract.ErrRecord
		}
		phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
		if err != nil || phase.DomainID != parent.DomainID || phase.OperationID != parent.OperationID || phase.OwnerID != parent.OperationID ||
			phase.PhaseID != c.ActivePhase || phase.PlanGraphID != parent.PlanGraphID || phase.UsePlanDigest != parent.UsePlanDigest {
			return contract.ErrRecord
		}
		bundle, err := b.content.parent(parent, !phase.SelectionPhaseID.IsZero())
		if err != nil {
			return err
		}
		if !generatedOperationGraphValid(bundle) {
			return contract.ErrRecord
		}
		g.parent, g.phase, g.bundles = &parent, &phase, []contract.GeneratorPlanBundle{bundle}
		material, err := b.operationMaterial(bundle)
		if err != nil {
			return err
		}
		// An active cleanup delete targets a retained result from an earlier,
		// detached create. Resolve that create before the active delete target;
		// the target validator must not depend on iteration order.
		if err := b.resolveUnselectedCreates(rows); err != nil {
			return err
		}
		if err := b.resolveHazards(rows); err != nil {
			return err
		}
		owners = append(owners, parent.OperationID)
		for _, row := range rows {
			if row.Kind != contract.GeneratedAttemptSupportKind {
				continue
			}
			a, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return err
			}
			if a.OperationID != parent.OperationID {
				continue
			}
			if _, released := g.records[generatedRecordKey{contract.PendingInboxReleaseSupportKind, a.InboxID}]; released {
				// The release resolver must validate the original mapping and
				// refuse any remaining adoption owner before this row is usable.
				continue
			}
			x, _, ok := generatedTemplate(bundle, a.AttemptID)
			if !ok {
				return contract.ErrRecord
			}
			var target contract.ID
			if x.Action == contract.GeneratorActionDelete {
				selected, err := g.generatedDeleteAttemptTarget(b.content.ctx, bundle, a)
				if err != nil {
					return fmt.Errorf("active delete target: %w", err)
				}
				if err := b.claimTargetEvidence(selected); err != nil {
					return err
				}
				target = selected.ResourceDigest
			}
			if err := b.resolveAttempt(bundle, material, a, target); err != nil {
				return err
			}
		}
		for _, row := range rows {
			if row.Kind != contract.GeneratedDutySupportKind {
				continue
			}
			d, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return err
			}
			if d.Kind != contract.GeneratedDutyCreate {
				continue
			}
			a, ok := g.attempts[d.OriginalAttemptID]
			if !ok || !generatedCreateDutyMatches(d, a.record) || d.CapacityReservation != parent.Capacity {
				return contract.ErrRecord
			}
			b.claimRecord(contract.GeneratedDutySupportKind, d.DutyID)
			owners = append(owners, d.DutyID)
		}
	} else if !c.ActivePhase.IsZero() || !c.ActiveGraph.IsZero() {
		return contract.ErrRecord
	}
	if err := b.resolveGeneratedRegistry(); err != nil {
		return fmt.Errorf("selected recipient proposal: %w", err)
	}
	if err := b.resolveFinalPreparation(); err != nil {
		return fmt.Errorf("selected final preparation: %w", err)
	}
	if err := b.resolveRetirementAttempts(rows); err != nil {
		return fmt.Errorf("retirement attempts: %w", err)
	}
	if g.parent == nil {
		if err := b.resolveUnselectedCreates(rows); err != nil {
			return err
		}
	}
	if err := b.resolveHazards(rows); err != nil {
		return fmt.Errorf("hazards: %w", err)
	}
	if err := b.resolveOrdinaryCleanupAttempts(rows); err != nil {
		return fmt.Errorf("ordinary cleanup history: %w", err)
	}
	if err := b.resolveInboxReleases(rows); err != nil {
		return err
	}
	if generatedSelectionAnchored(g) {
		for _, released := range g.releases {
			if released.attempt.OperationID != g.parent.OperationID {
				continue
			}
			target, err := generatedAutomaticReleasedTarget(b.content.ctx, g, released.template)
			if err != nil {
				return err
			}
			if target != nil {
				if err := b.claimTargetEvidence(*target); err != nil {
					return err
				}
			}
		}
	}
	for _, bundle := range g.bundles {
		graphs = append(graphs, bundle.UsePlan.PlanGraphID)
	}
	for _, row := range rows {
		if row.Kind == contract.GeneratedHazardSupportKind || row.Kind == contract.PendingInboxReleaseSupportKind {
			owners = append(owners, row.RecordID)
		}
		if row.Kind != contract.GeneratedDutySupportKind {
			continue
		}
		d, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return err
		}
		if d.Kind == contract.GeneratedDutyRetirement || d.Kind == contract.GeneratedDutyUnselectedCleanup {
			owners = append(owners, d.DutyID)
		}
	}
	counts := make(map[uint8]uint32)
	for key := range g.records {
		counts[key.kind]++
	}
	if c.Attempts != counts[9] || c.Duties != counts[10] || c.Hazards != counts[11] || c.Results != counts[4] || c.Materials != counts[1] || c.PendingReleases != counts[12] ||
		counts[2] != uint32(boolInt(g.parent != nil)) || counts[5] != uint32(boolInt(g.phase != nil)) {
		return contract.ErrRecord
	}
	for _, set := range []struct {
		kind contract.GeneratorIndexKind
		ids  []contract.ID
		want contract.GeneratorDescriptor
	}{{contract.GeneratorGraphSet, graphs, c.Graphs}, {contract.GeneratorLiveOwnerSet, owners, c.LiveOwners}} {
		slices.SortFunc(set.ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		descriptor, err := contract.GeneratorIndexDescriptor(set.kind, slices.Compact(set.ids))
		if err != nil || descriptor != set.want {
			return contract.ErrRecord
		}
	}
	return nil
}

func (b *generatedSelectionBuilder) resolveAttempt(bundle contract.GeneratorPlanBundle, material contract.OperationMaterialRecord, a contract.GeneratedAttemptRecord, target contract.ID) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	x, use, ok := generatedTemplate(bundle, a.AttemptID)
	if !ok || a.DomainID != bundle.Header.DomainID || a.OperationID != bundle.Header.OperationID || !generatedAttemptMatches(a, x) || a.RetryUsed != 0 {
		return contract.ErrRecord
	}
	inputEncoding, err := contract.GeneratorResultInputEncoding(bundle, x)
	if err != nil {
		return err
	}
	expected := contract.GeneratorResultExpectation{InputEncoding: inputEncoding, Plan: bundle.UsePlan, Template: x, Use: use, RequestDigest: a.RequestDigest, TargetResourceDigest: target}
	if expected.Validate(material) != nil {
		return contract.ErrRecord
	}
	selected := generatedAttempt{record: a, expected: expected, material: material}
	if result, present := b.claimRecord(contract.GeneratedResultSupportKind, a.ResultID); present {
		v, err := contract.DecodeGeneratedResultRecord(result.Body)
		if err != nil || contract.ValidateGeneratedResult(expected, material, v) != nil {
			return contract.ErrRecord
		}
		selected.result = result.Body
	}
	b.claimRecord(contract.GeneratedAttemptSupportKind, a.AttemptID)
	g.attempts[a.AttemptID] = selected
	return nil
}

func generatedCreateDutyMatches(d contract.GeneratedDutyRecord, a contract.GeneratedAttemptRecord) bool {
	return d.SemanticLifecycleMode() == a.SemanticLifecycleMode() && d.DomainID == a.DomainID && d.DutyID == a.OwnerID && d.OwnerID == d.DutyID && d.OriginalOperationID == a.OperationID &&
		d.OriginalAttemptID == a.AttemptID && d.ResourceID == a.ResourceID && d.ConfigContractID == a.ConfigContractID && d.ResourceContractID == a.ResourceContractID &&
		d.ExecutorID == a.ExecutorID && d.CredentialRouteID == a.CredentialRouteID && d.DescriptorID == a.DescriptorID &&
		d.ResultContractID == a.ResultContractID && d.CompletionClass == a.CompletionClass &&
		(d.Kind == contract.GeneratedDutyCreate || d.Kind == contract.GeneratedDutyUnselectedCleanup) &&
		(d.Step == 1 || d.Kind == contract.GeneratedDutyUnselectedCleanup && d.CompletionClass == contract.GeneratedCompletionConfirmed && d.Step == 2) && d.Status == a.State
}

func (g *generatedSelection) activePhaseOwns(row contract.SupportRecord) bool {
	if g.parent == nil {
		return false
	}
	if generatedSelectionAnchored(g) && row.Kind == contract.GeneratedDutySupportKind {
		for _, index := range contract.GeneratedAutomaticRetirementIndices(g.bundles[0]) {
			if row.RecordID == g.bundles[0].Lineages[index].Templates[0].DutyID {
				return true
			}
		}
	}
	matches := func(a contract.GeneratedAttemptRecord, x contract.GeneratorAttemptTemplate) bool {
		if a.OperationID != g.parent.OperationID {
			return false
		}
		return row.Kind == contract.GeneratedResultSupportKind && row.RecordID == a.ResultID || row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == a.AttemptID || row.Kind == contract.GeneratedDutySupportKind && row.RecordID == a.OwnerID ||
			row.Kind == contract.GeneratedHazardSupportKind && (row.RecordID == x.HazardID || x.Action == contract.GeneratorActionDelete && g.sourceHazardOwns(row, a.OwnerID)) || row.Kind == contract.PendingInboxReleaseSupportKind && row.RecordID == a.InboxID
	}
	for _, attempt := range g.attempts {
		if matches(attempt.record, attempt.expected.Template) {
			return true
		}
	}
	for _, released := range g.releases {
		if matches(released.attempt, released.template) {
			return true
		}
	}
	return false
}

func (g *generatedSelection) sourceHazardOwns(row contract.SupportRecord, owner contract.ID) bool {
	h, err := contract.InspectGeneratedHazardRecord(row.Body)
	return err == nil && h.OwnerID == owner
}

func (b *generatedSelectionBuilder) validateActivePhase(rows []contract.SupportRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	p, bundle := *g.phase, g.bundles[0]
	if !p.SelectionPhaseID.IsZero() {
		if _, _, ok := generatedAutomaticTemplate(g, p.LineageIndex); !ok || p.Branch != 0 || p.NoEffectUsed != 0 || p.ResidueUsed != 0 {
			return contract.ErrRecord
		}
	}
	if int(p.LineageIndex) >= len(bundle.Lineages) {
		return contract.ErrRecord
	}
	lineage := bundle.Lineages[p.LineageIndex]
	if p.Branch >= lineage.TemplateCount {
		return contract.ErrRecord
	}
	template := lineage.Templates[p.Branch]
	if p.FrontierAttemptID != template.AttemptID {
		return contract.ErrRecord
	}
	a, entered := g.attempts[p.FrontierAttemptID]
	frontier, resultDigest := a.record, contract.ID{}
	if len(a.result) != 0 {
		resultDigest = contract.Hash(a.result)
	}
	if released, ok := g.releases[p.FrontierAttemptID]; ok {
		frontier, resultDigest, entered = released.attempt, released.release.SelectedHandoffDigest, true
	}
	if entered {
		if frontier.OperationID != p.OperationID || frontier.LineageID != lineage.LineageID || frontier.Stage != p.Stage {
			return contract.ErrRecord
		}
	} else {
		if x, _, ok := generatedAutomaticTemplate(g, p.LineageIndex); ok && x.AttemptID == p.FrontierAttemptID && p.Stage == contract.GeneratedStageRetainedResult && p.Branch == 0 && p.NoEffectUsed == 0 && p.ResidueUsed == 0 {
			if !p.AcceptedResultID.IsZero() || !p.ResultDigest.IsZero() {
				return contract.ErrRecord
			}
		} else {
			v, err := contract.InspectGeneratedLineageRecord(g.records[generatedRecordKey{contract.GeneratedLineageSupportKind, lineage.LineageID}].Body)
			if err != nil || lineage.Purpose != contract.GeneratorLineageCreate || v.Branch != p.Branch || v.Branch == v.Frontier || p.Stage != contract.GeneratedStageRetainedResult {
				return contract.ErrRecord
			}
		}
	}
	if p.Phase == 1 {
		initialIndex := uint16(0)
		initialAttempts := uint32(1)
		if template.Action == contract.GeneratorActionCreate {
			var ok bool
			initialIndex, ok = generatedFirstCreateIndex(bundle)
			if !ok {
				return contract.ErrRecord
			}
			initialAttempts = 0
			for _, original := range bundle.Lineages {
				if original.Purpose == contract.GeneratorLineageCreate {
					initialAttempts++
				}
			}
		}
		phaseID, err := contract.GeneratorInitialPhaseID(bundle.Header.RequestCoreDigest)
		if err != nil || phaseID != p.PhaseID || p.LineageIndex != initialIndex || p.Branch != contract.GeneratorBranchInitial || p.NoEffectUsed != 0 || p.ResidueUsed != 0 ||
			p.Attempts.Count != initialAttempts || frontier.State != contract.GeneratedEffectTransmitted || p.Stage != contract.GeneratedStageRetainedResult || !p.AcceptedResultID.IsZero() ||
			p.Proofs != contract.EmptyGeneratorVector(contract.GeneratorVectorProofs) {
			return contract.ErrRecord
		}
	}
	if resultDigest != p.ResultDigest || resultDigest.IsZero() != p.AcceptedResultID.IsZero() || !resultDigest.IsZero() && p.AcceptedResultID != template.ResultID {
		return contract.ErrRecord
	}
	for _, family := range []struct {
		kind    contract.GeneratorRecordSetKind
		rowKind uint8
		want    contract.GeneratorDescriptor
	}{{contract.GeneratorPhaseResults, 4, p.AcceptedResults}, {contract.GeneratorPhaseAttempts, 9, p.Attempts},
		{contract.GeneratorPhaseDuties, 10, p.Duties}, {contract.GeneratorPhaseHazards, 11, p.Hazards}, {contract.GeneratorPhaseReleases, 12, p.PendingReleases}} {
		var selected []contract.SupportRecord
		for _, row := range rows {
			if row.Kind == family.rowKind && g.activePhaseOwns(row) {
				selected = append(selected, row)
			}
		}
		slices.SortFunc(selected, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
		descriptor, err := contract.GeneratorRecordSetDescriptor(family.kind, g.image.root.Domain, selected)
		if err != nil || descriptor != family.want {
			return contract.ErrRecord
		}
	}
	return nil
}

func (b *generatedSelectionBuilder) validateActiveVectors() error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	if g.parent != nil {
		if err := b.resolveActiveCanonicals(); err != nil {
			return err
		}
	}
	for _, selected := range g.attempts {
		a := selected.record
		if owner := g.deleteHazards[a.AttemptID]; !owner.IsZero() {
			row, ok := b.claimRecord(contract.GeneratedHazardSupportKind, owner)
			if !ok {
				return contract.ErrRecord
			}
			h, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return err
			}
			if h.OriginalAttemptID == a.AttemptID {
				if err := b.validateDeleteHazardVectors(selected, h); err != nil {
					return err
				}
			}
			continue
		}
		if row, ok := b.claimRecord(contract.GeneratedHazardSupportKind, selected.expected.Template.HazardID); ok {
			h, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return err
			}
			if selected.expected.Template.Action == contract.GeneratorActionDelete {
				err = b.validateDeleteHazardVectors(selected, h)
			} else {
				err = b.validateCreateHazardVectors(selected, h)
			}
			if err != nil {
				return err
			}
			continue
		}
		if selected.expected.Template.Action == contract.GeneratorActionDelete {
			if err := b.validateGeneratedDeleteAttempt(selected); err != nil {
				return fmt.Errorf("active delete vectors: %w", err)
			}
			continue
		}
		row, ok := b.claimRecord(contract.GeneratedDutySupportKind, a.OwnerID)
		if !ok {
			return contract.ErrRecord
		}
		d, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return err
		}
		if err := b.resolveResultConsumers(selected, contract.GeneratedDutySupportKind, d.DutyID, d.Consumers, d.Kind == contract.GeneratedDutyCreate); err != nil {
			return err
		}
		if len(selected.result) == 0 {
			target := contract.EmptyGeneratorVector(contract.GeneratorVectorTargets)
			if a.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				target = contract.EmptyGeneratorVector(contract.GeneratorVectorTargets)
			}
			if d.Target != target || a.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) ||
				a.State != contract.GeneratedEffectTransmitted && !generatedLocalFailureAttempt(selected) {
				return contract.ErrRecord
			}
		} else if err := b.validateRecordedAttempt(selected, d); err != nil {
			return err
		}
	}
	for id, source := range g.canonical {
		found := false
		for _, consumer := range g.consumers[materialIdentity{contract.ValueMaterialKind, source.record.Entry.ValueState}] {
			found = found || consumer.SubjectKind == contract.GeneratorConsumerRetainedCanonicalValue && consumer.SubjectID == id
		}
		if !found {
			return contract.ErrRecord
		}
	}
	return b.resolveActiveSources()
}

func (b *generatedSelectionBuilder) resolveResultConsumers(a generatedAttempt, ownerKind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor, active bool) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	consumers, err := b.vectors.resolve(ownerKind, owner, contract.GeneratorVectorConsumers, descriptor)
	if err != nil {
		return contract.ErrRecord
	}
	context, err := contract.GeneratorResultUseDigest(a.expected.Use)
	if err != nil {
		return err
	}
	var resultUses [2]bool
	cleanupUses := make(map[contract.ID]generatedAttempt)
	if !active && (ownerKind == contract.GeneratedDutySupportKind || ownerKind == contract.GeneratedHazardSupportKind) {
		stableOwner := owner
		if ownerKind == contract.GeneratedHazardSupportKind {
			h, err := contract.InspectGeneratedHazardRecord(g.records[generatedRecordKey{ownerKind, owner}].Body)
			if err != nil {
				return err
			}
			stableOwner = h.OwnerID
		}
		for _, candidate := range g.attempts {
			if candidate.record.OwnerID == stableOwner && candidate.expected.Template.Action == contract.GeneratorActionDelete {
				if _, duplicate := cleanupUses[candidate.record.ResultID]; duplicate {
					return contract.ErrRecord
				}
				cleanupUses[candidate.record.ResultID] = candidate
			}
		}
	}
	for _, body := range consumers {
		consumer, err := contract.InspectGeneratorConsumer(body)
		if err != nil {
			return err
		}
		if consumer.SubjectKind == contract.GeneratorConsumerRetainedCanonicalValue {
			if err := b.claimCanonicalConsumer(ownerKind, owner, active, consumer); err != nil {
				return err
			}
			continue
		}
		// An unselected-create Duty also owns each fresh exact cleanup
		// invocation. Its original result use remains distinct from the delete
		// result use; neither can stand in for the other's retained material.
		if !active && (ownerKind == contract.GeneratedDutySupportKind || ownerKind == contract.GeneratedHazardSupportKind) && consumer.SubjectKind == contract.GeneratorConsumerOriginalResult && consumer.SubjectID != a.record.ResultID {
			cleanup, present := cleanupUses[consumer.SubjectID]
			use, err := contract.GeneratorResultUseDigest(cleanup.expected.Use)
			want := contract.GeneratorConsumer{Schema: 1, OwnerID: owner, MaterialID: cleanup.material.Core.OperationMaterialID,
				ContextDigest: use, SubjectKind: contract.GeneratorConsumerOriginalResult, SubjectID: cleanup.record.ResultID, Purpose: contract.GeneratorConsumerAdoptLateOriginalResult}
			if err != nil || !present || consumer != want {
				return contract.ErrRecord
			}
			key := materialIdentity{contract.OperationSeedMaterialKind, consumer.MaterialID}
			g.consumers[key] = append(g.consumers[key], consumer)
			delete(cleanupUses, consumer.SubjectID)
			continue
		}
		if consumer.Purpose < contract.GeneratorConsumerDeriveSelectedResult || consumer.Purpose > contract.GeneratorConsumerAdoptLateOriginalResult || resultUses[consumer.Purpose-contract.GeneratorConsumerDeriveSelectedResult] {
			return contract.ErrRecord
		}
		want := contract.GeneratorConsumer{Schema: 1, OwnerID: owner, MaterialID: a.material.Core.OperationMaterialID,
			ContextDigest: context, SubjectKind: contract.GeneratorConsumerOriginalResult, SubjectID: a.record.ResultID, Purpose: consumer.Purpose}
		if consumer != want {
			return contract.ErrRecord
		}
		resultUses[consumer.Purpose-contract.GeneratorConsumerDeriveSelectedResult] = true
		key := materialIdentity{contract.OperationSeedMaterialKind, consumer.MaterialID}
		g.consumers[key] = append(g.consumers[key], consumer)
	}
	if resultUses[0] != active || !resultUses[1] || len(cleanupUses) != 0 {
		return contract.ErrRecord
	}
	return nil
}

// generatedLocalFailureAttempt describes stored local failure facts. It grants
// no receiver authority to construct or sign a transition.
func generatedLocalFailureAttempt(a generatedAttempt) bool {
	x, r := a.expected.Template, a.record
	return x.Schema == contract.GeneratorAttemptTemplateSchema && x.SemanticLifecycleMode() == contract.GeneratorLifecycleNone &&
		x.Action == contract.GeneratorActionCreate && x.Branch == contract.GeneratorBranchInitial && x.PredecessorAttemptID.IsZero() &&
		r.Schema == contract.GeneratedAttemptRecordSchema && r.SemanticLifecycleMode() == contract.GeneratorLifecycleNone && generatedAttemptMatches(r, x) &&
		r.State == contract.GeneratedEffectFailedTerminal && r.Stage == contract.GeneratedStageTerminal && r.RetryUsed == 0 &&
		r.FailureReason >= contract.GeneratorFailureInvalid && r.FailureReason <= contract.GeneratorFailureProtocol &&
		r.Facts == contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) && r.Progress == contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) && len(a.result) == 0
}

func (b *generatedSelectionBuilder) validateRecordedAttempt(a generatedAttempt, duty contract.GeneratedDutyRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	result, err := contract.InspectGeneratedResultRecord(a.result)
	if err != nil {
		return err
	}
	state := uint8(contract.GeneratedEffectSucceeded)
	switch result.SafeFacts.Disposition {
	case contract.GeneratorDispositionCompleteCreate:
	case contract.GeneratorDispositionOwnedUnusableCreate:
		state = contract.GeneratedEffectFailedTerminal
	case contract.GeneratorDispositionConfirmedNoEffect:
		state = contract.GeneratedEffectConfirmedNoEffect
	default:
		return contract.ErrRecord
	}
	if a.record.State != state || duty.Status != state || a.record.Stage != contract.GeneratedStageTerminal {
		return contract.ErrRecord
	}
	return b.validateCreateFactsAndTarget(a, contract.GeneratedDutySupportKind, duty.DutyID, duty.Target)
}

func (b *generatedSelectionBuilder) validateCreateFactsAndTarget(a generatedAttempt, ownerKind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	result, err := contract.InspectGeneratedResultRecord(a.result)
	if err != nil {
		return err
	}
	facts, err := b.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, a.record.Facts)
	if err != nil || len(facts) != 1 {
		return contract.ErrRecord
	}
	fact, err := contract.InspectGeneratorFactsRow(facts[0])
	if err != nil || fact.ResultID != a.record.ResultID {
		return contract.ErrRecord
	}
	ownedFacts, err := result.SafeFacts.Own()
	if err != nil {
		return err
	}
	actual, err := contract.EncodeGeneratorSafeFacts(ownedFacts)
	if err != nil || !bytes.Equal(actual, fact.Facts) {
		return contract.ErrRecord
	}
	if a.expected.Template.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
		if a.record.SemanticLifecycleMode() != contract.GeneratorLifecycleNone || descriptor != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) || result.SafeFacts.LifecycleMode != contract.GeneratorLifecycleNone ||
			result.SafeFacts.Disposition != contract.GeneratorDispositionCompleteCreate && result.SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect {
			return contract.ErrRecord
		}
		return nil
	}
	if result.SafeFacts.Disposition == contract.GeneratorDispositionConfirmedNoEffect {
		if descriptor != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) {
			return contract.ErrRecord
		}
		return nil
	}
	targets, err := b.vectors.resolve(ownerKind, owner, contract.GeneratorVectorTargets, descriptor)
	if err != nil || len(targets) != 1 {
		return contract.ErrRecord
	}
	target, err := contract.InspectGeneratorTarget(targets[0])
	if err != nil {
		return err
	}
	bi := slices.IndexFunc(g.bundles, func(v contract.GeneratorPlanBundle) bool { return v.Header.OperationID == a.record.OperationID })
	if bi < 0 {
		return contract.ErrRecord
	}
	i := slices.IndexFunc(g.bundles[bi].Lineages, func(v contract.GeneratorLineageTemplate) bool { return v.LineageID == a.record.LineageID })
	if i < 0 {
		return contract.ErrRecord
	}
	lineage := g.bundles[bi].Lineages[i]
	resourceDigest, err := contract.GeneratorResourceDigest(result.SafeFacts.GeneratorSafeFacts)
	if err != nil {
		return err
	}
	want := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: lineage.Name, IncarnationID: lineage.EntryIncarnationID, Epoch: lineage.Epoch,
		ResourceID: a.record.ResourceID, ResourceDigest: resourceDigest, ConfigContractID: a.record.ConfigContractID,
		ResourceContractID: a.record.ResourceContractID, OriginalOperationID: a.record.OperationID, OriginalAttemptID: a.record.AttemptID,
		ResultContractID: a.record.ResultContractID, CompletionClass: a.record.CompletionClass}
	if target != want {
		return contract.ErrRecord
	}
	return nil
}
