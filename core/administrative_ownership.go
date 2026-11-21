package core

import (
	"bytes"
	"crypto/sha256"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The consumer relation is derived from the selected typed support rows.
// Several independent work groups may use one operation or attempt record;
// they share that row without acquiring a dependency on each other.
type administrativeConsumers struct {
	operation, attempt  map[contract.ID][]contract.ID
	material            map[contract.ID][]contract.ID
	canonical           map[contract.ID][]contract.ID
	history             map[contract.ID][]contract.ID
	historyOwners       map[contract.ID][]contract.ID
	historyDependencies map[contract.ID][]contract.ID
	actions             map[contract.ID]uint8
	lineage             map[contract.ID][]contract.ID
	intentAttempts      map[contract.ID][]contract.ID
	attemptIntent       map[contract.ID]administrativeAttemptIntent
	targetOperation     map[contract.ID]contract.ID
	inbox               map[contract.ID]contract.ID
	attempts            map[contract.ID]contract.GeneratedAttemptRecord
	graphOperation      map[contract.ID]contract.ID
	materialOperation   map[contract.ID]contract.ID
	intentOperation     map[contract.ID][]contract.ID
	sourceOperation     map[contract.ID][]contract.ID
	slices              map[contract.ID]contract.GeneratorSliceLocation
	finalPreparations   map[contract.ID]contract.GeneratedFinalPreparationRecord
	blobs               map[contract.ID][]contract.ID
}

type administrativeAttemptIntent struct {
	operation, intent contract.ID
}

func (c *administrativeConsumers) bindIntentAttempt(operation, attempt, intent contract.ID) error {
	if operation.IsZero() || attempt.IsZero() || intent.IsZero() {
		return contract.ErrRecord
	}
	if prior, present := c.attemptIntent[attempt]; present {
		if prior != (administrativeAttemptIntent{operation: operation, intent: intent}) {
			return contract.ErrRecord
		}
		return nil
	}
	c.attemptIntent[attempt] = administrativeAttemptIntent{operation: operation, intent: intent}
	c.intentAttempts[intent] = append(c.intentAttempts[intent], attempt)
	return nil
}

func (c *administrativeConsumers) bindTargetOperation(operation, attempt contract.ID) error {
	if operation.IsZero() || attempt.IsZero() {
		return contract.ErrRecord
	}
	if prior := c.targetOperation[attempt]; !prior.IsZero() && prior != operation {
		return contract.ErrRecord
	}
	c.targetOperation[attempt] = operation
	return nil
}

func appendAdministrativeConsumer(m map[contract.ID][]contract.ID, key, group contract.ID) {
	if !key.IsZero() && !group.IsZero() && !slices.Contains(m[key], group) {
		m[key] = append(m[key], group)
	}
}

func selectedAdministrativeConsumers(pages []format.RequiredSupportPage, projectedParent *contract.GeneratedParentPlan,
	bundles []contract.GeneratorPlanBundle) (administrativeConsumers, error) {
	return selectedAdministrativeConsumersWithValidated(pages, projectedParent, bundles, nil)
}

func selectedAdministrativeConsumersWithValidated(pages []format.RequiredSupportPage, projectedParent *contract.GeneratedParentPlan,
	bundles []contract.GeneratorPlanBundle, selected *generatedSelection) (administrativeConsumers, error) {
	c := administrativeConsumers{operation: make(map[contract.ID][]contract.ID), attempt: make(map[contract.ID][]contract.ID),
		canonical: make(map[contract.ID][]contract.ID), material: make(map[contract.ID][]contract.ID), history: make(map[contract.ID][]contract.ID), historyOwners: make(map[contract.ID][]contract.ID), historyDependencies: make(map[contract.ID][]contract.ID), actions: make(map[contract.ID]uint8),
		lineage: make(map[contract.ID][]contract.ID), inbox: make(map[contract.ID]contract.ID), attempts: make(map[contract.ID]contract.GeneratedAttemptRecord),
		intentAttempts: make(map[contract.ID][]contract.ID), attemptIntent: make(map[contract.ID]administrativeAttemptIntent),
		targetOperation: make(map[contract.ID]contract.ID),
		graphOperation:  make(map[contract.ID]contract.ID), materialOperation: make(map[contract.ID]contract.ID),
		intentOperation: make(map[contract.ID][]contract.ID), sourceOperation: make(map[contract.ID][]contract.ID),
		slices: make(map[contract.ID]contract.GeneratorSliceLocation), blobs: make(map[contract.ID][]contract.ID),
		finalPreparations: make(map[contract.ID]contract.GeneratedFinalPreparationRecord)}
	var releases []contract.SupportRecord
	preparationParents := make(map[contract.ID]bool)
	type historyConsumer struct {
		group contract.ID
		row   contract.GeneratorHistory
	}
	var histories []historyConsumer
	for _, bundle := range bundles {
		operation := bundle.Header.OperationID
		c.graphOperation[bundle.UsePlan.PlanGraphID] = operation
		c.materialOperation[bundle.Header.MaterialID] = operation
		for _, lineage := range bundle.Lineages {
			for _, template := range lineage.Templates[:lineage.TemplateCount] {
				c.actions[template.AttemptID] = template.Action
				appendAdministrativeConsumer(c.intentOperation, template.IntentDigest, operation)
				if err := c.bindIntentAttempt(operation, template.AttemptID, template.IntentDigest); err != nil {
					return c, err
				}
			}
		}
		for _, source := range bundle.SourceUses {
			appendAdministrativeConsumer(c.sourceOperation, source.SourceID, operation)
		}
	}
	for _, page := range pages {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.OperationMaterialSupportKind:
				material, err := contract.InspectOperationMaterialRecord(row.Body)
				if err != nil {
					return c, err
				}
				c.materialOperation[material.Core.OperationMaterialID] = material.Core.OperationID
			case contract.GeneratedParentSupportKind:
				if projectedParent != nil && row.RecordID == projectedParent.OperationID {
					appendAdministrativeConsumer(c.operation, projectedParent.OperationID, projectedParent.OperationID)
					c.graphOperation[projectedParent.PlanGraphID] = projectedParent.OperationID
					c.materialOperation[projectedParent.MaterialID] = projectedParent.OperationID
					continue
				}
				parent, err := contract.InspectGeneratedParentRecord(row.Body)
				if err != nil {
					return c, err
				}
				appendAdministrativeConsumer(c.operation, parent.OperationID, parent.OperationID)
				c.graphOperation[parent.PlanGraphID] = parent.OperationID
				c.materialOperation[parent.MaterialID] = parent.OperationID
			case contract.GeneratedFinalPreparationSupportKind:
				preparation, err := contract.InspectGeneratedFinalPreparationRecord(row.Body)
				if err != nil || preparation.OperationID != row.RecordID {
					return c, contract.ErrRecord
				}
				if _, duplicate := c.finalPreparations[preparation.Image.ContentID]; duplicate || preparationParents[preparation.OperationID] {
					return c, contract.ErrRecord
				}
				preparationParents[preparation.OperationID] = true
				c.finalPreparations[preparation.Image.ContentID] = preparation
			case contract.GeneratedPhaseSupportKind:
				phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
				if err != nil {
					return c, err
				}
				c.graphOperation[phase.PlanGraphID] = phase.OperationID
			case contract.GeneratedDutySupportKind:
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil {
					return c, err
				}
				appendAdministrativeConsumer(c.operation, duty.OriginalOperationID, duty.DutyID)
				appendAdministrativeConsumer(c.attempt, duty.OriginalAttemptID, duty.DutyID)
				if duty.Kind == contract.GeneratedDutyCreate || duty.Kind == contract.GeneratedDutyUnselectedCleanup {
					appendAdministrativeConsumer(c.historyOwners, duty.OriginalAttemptID, duty.DutyID)
				}
				if err := c.bindTargetOperation(duty.OriginalOperationID, duty.OriginalAttemptID); err != nil {
					return c, err
				}
			case contract.GeneratedHazardSupportKind:
				hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
				if err != nil {
					return c, err
				}
				appendAdministrativeConsumer(c.operation, hazard.OriginalOperationID, hazard.HazardID)
				appendAdministrativeConsumer(c.attempt, hazard.OriginalAttemptID, hazard.HazardID)
				appendAdministrativeConsumer(c.historyOwners, hazard.OriginalAttemptID, hazard.HazardID)
				if err := c.bindTargetOperation(hazard.OriginalOperationID, hazard.OriginalAttemptID); err != nil {
					return c, err
				}
			case contract.GeneratedAttemptSupportKind:
				attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
				_, duplicate := c.attempts[attempt.AttemptID]
				if err != nil || c.inbox[attempt.InboxID] != (contract.ID{}) || duplicate {
					return c, contract.ErrRecord
				}
				c.attempts[attempt.AttemptID] = attempt
				c.inbox[attempt.InboxID] = attempt.AttemptID
				// A retained cleanup attempt belongs to its exact duty or
				// hazard even after the cleanup parent leaves selection.
				appendAdministrativeConsumer(c.operation, attempt.OperationID, attempt.OwnerID)
				appendAdministrativeConsumer(c.attempt, attempt.AttemptID, attempt.OwnerID)
				appendAdministrativeConsumer(c.lineage, attempt.LineageID, attempt.AttemptID)
			case contract.GeneratedResultSupportKind:
				result, err := contract.InspectGeneratedResultRecord(row.Body)
				if err != nil {
					return c, err
				}
				c.graphOperation[result.Core.PlanGraphID] = result.Core.OperationID
				c.materialOperation[result.Core.MaterialID] = result.Core.OperationID
				appendAdministrativeConsumer(c.intentOperation, result.SafeFacts.IntentDigest, result.Core.OperationID)
				if err := c.bindIntentAttempt(result.Core.OperationID, result.Core.AttemptID, result.SafeFacts.IntentDigest); err != nil {
					return c, err
				}
			case contract.GeneratedCreateEvidenceSupportKind:
				// A detached retirement can retain create evidence and its intent
				// after the original result and parent leave the selected rows.
				evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
				if err != nil {
					return c, err
				}
				core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
				if err != nil {
					return c, err
				}
				facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
				if err != nil {
					return c, err
				}
				appendAdministrativeConsumer(c.intentOperation, facts.IntentDigest, core.OperationID)
				if err := c.bindIntentAttempt(core.OperationID, core.AttemptID, facts.IntentDigest); err != nil {
					return c, err
				}
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					return c, err
				}
				if carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices {
					location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil {
						return c, err
					}
					c.slices[row.RecordID] = location
				} else if (carrier.OwnerKind == contract.GeneratedDutySupportKind || carrier.OwnerKind == contract.GeneratedHazardSupportKind) &&
					carrier.VectorKind == contract.GeneratorVectorTargets {
					// A detached delete duty carries the original create target.
					// Its evidence belongs to that duty even when the create
					// attempt and parent have left the selected support rows.
					target, err := contract.InspectGeneratorTarget(carrier.Row)
					if err != nil {
						return c, err
					}
					appendAdministrativeConsumer(c.operation, target.OriginalOperationID, carrier.OwnerID)
					appendAdministrativeConsumer(c.attempt, target.OriginalAttemptID, carrier.OwnerID)
					if err := c.bindTargetOperation(target.OriginalOperationID, target.OriginalAttemptID); err != nil {
						return c, err
					}
				} else if carrier.OwnerKind == contract.GeneratedDutySupportKind || carrier.OwnerKind == contract.GeneratedHazardSupportKind {
					switch carrier.VectorKind {
					case contract.GeneratorVectorHistory:
						history, err := contract.InspectGeneratorHistory(carrier.Row)
						if err != nil {
							return c, err
						}
						histories = append(histories, historyConsumer{carrier.OwnerID, history})
					case contract.GeneratorVectorConsumers:
						consumer, err := contract.InspectGeneratorConsumer(carrier.Row)
						if err != nil || consumer.OwnerID != carrier.OwnerID {
							return c, contract.ErrRecord
						}
						appendAdministrativeConsumer(c.material, consumer.MaterialID, carrier.OwnerID)
						if consumer.SubjectKind == contract.GeneratorConsumerRetainedCanonicalValue {
							appendAdministrativeConsumer(c.canonical, consumer.SubjectID, carrier.OwnerID)
						}
					}
				}
			case contract.PendingInboxReleaseSupportKind:
				releases = append(releases, row)
			}
		}
	}
	// An actual retained generated copy still needs its exact create evidence
	// and intent. Its existing consumers own those rows, without creating a
	// new administrative group or a provider target.
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind != contract.RetainedCanonicalSupportKind {
				continue
			}
			canonical, err := contract.InspectRetainedCanonicalRecord(row.Body)
			if err != nil {
				return c, err
			}
			if canonical.Entry.ValueSource != contract.Generated {
				continue
			}
			m := canonical.Entry.Generated
			if err := c.bindIntentAttempt(m.OriginOperationID, m.OriginAttemptID, m.IntentDigest); err != nil {
				return c, err
			}
			for _, group := range c.canonical[row.RecordID] {
				appendAdministrativeConsumer(c.attempt, m.OriginAttemptID, group)
			}
		}
	}
	preparationSlices := make(map[contract.ID]bool, len(c.finalPreparations))
	for _, location := range c.slices {
		if location.ContentKind != contract.GeneratorContentFinalPreparation {
			continue
		}
		preparation, present := c.finalPreparations[location.ContentID]
		if !present || preparationSlices[location.ContentID] || preparation.Image != location.Logical() ||
			!slices.Contains(c.operation[preparation.OperationID], preparation.OperationID) {
			return c, contract.ErrRecord
		}
		preparationSlices[location.ContentID] = true
	}
	for id := range c.finalPreparations {
		if !preparationSlices[id] {
			return c, contract.ErrRecord
		}
	}
	var err error
	if selected != nil {
		err = c.bindDeclarationSourcesFromValidated(selected, bundles)
	} else {
		err = c.bindDeclarationSources(pages, bundles)
	}
	if err != nil {
		return c, err
	}
	for _, consumer := range histories {
		h := consumer.row
		action := c.actions[h.PredecessorAttemptID]
		if action != contract.GeneratorActionCreate && action != contract.GeneratorActionDelete {
			return c, contract.ErrRecord
		}
		unresolved := action == contract.GeneratorActionCreate && h.Outcome == contract.GeneratedEffectClosedWithResidue && h.ResultID.IsZero()
		// Qualified create ancestry authenticates itself. Cleanup/delete
		// history still requires each actual selected Delete Attempt.
		if action == contract.GeneratorActionDelete || unresolved {
			appendAdministrativeConsumer(c.history, h.PredecessorAttemptID, consumer.group)
			if unresolved {
				appendAdministrativeConsumer(c.historyDependencies, h.PredecessorAttemptID, consumer.group)
			}
		}
	}
	for attemptID, groups := range c.history {
		attempt, ok := c.attempts[attemptID]
		if !ok {
			return c, contract.ErrRecord
		}
		for _, group := range groups {
			appendAdministrativeConsumer(c.attempt, attemptID, group)
			appendAdministrativeConsumer(c.operation, attempt.OperationID, group)
		}
	}
	for attemptID, operation := range c.targetOperation {
		if binding, present := c.attemptIntent[attemptID]; present && binding.operation != operation {
			return c, contract.ErrRecord
		}
	}
	for attemptID, attempt := range c.attempts {
		if binding, present := c.attemptIntent[attemptID]; present && binding.operation != attempt.OperationID {
			return c, contract.ErrRecord
		}
	}
	releasesByInbox := make(map[contract.ID]contract.PendingInboxReleaseRecord, len(releases))
	for _, row := range releases {
		release, err := contract.InspectPendingInboxReleaseRecord(row.Body)
		if err != nil {
			return c, err
		}
		if _, present := releasesByInbox[release.InboxID]; !present {
			releasesByInbox[release.InboxID] = release
		}
		attemptID := c.inbox[release.InboxID]
		if attemptID.IsZero() {
			continue // The complete generated selection validates release ancestry.
		}
		attempt := c.attempts[attemptID]
		appendAdministrativeConsumer(c.operation, attempt.OperationID, release.InboxID)
		appendAdministrativeConsumer(c.attempt, attemptID, release.InboxID)
		appendAdministrativeConsumer(c.historyOwners, attemptID, release.InboxID)
	}
	var releaseVectors *generatedVectorSet
	// A disposed ACK no longer has an Attempt mapping. The released probe's
	// exact retained ACK prefix still owns its immutable graph, through the
	// probe's existing inbox-release group rather than the removed source.
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return c, err
			}
			if carrier.OwnerKind != contract.GeneratedAttemptSupportKind || carrier.VectorKind != contract.GeneratorVectorProgress {
				continue
			}
			owner, present := c.attempts[carrier.OwnerID]
			if !present || owner.Progress != carrier.Vector {
				return c, contract.ErrRecord
			}
			release := releasesByInbox[owner.InboxID]
			if release.InboxID.IsZero() {
				continue
			}
			prefix, err := contract.InspectGeneratorProgress(carrier.Row)
			if err != nil || owner.CompletionClass != contract.GeneratedCompletionConfirmed || owner.Stage != contract.GeneratedStageTerminal ||
				release.State == contract.GeneratedReleaseUnobserved || release.OriginalResultID != owner.ResultID || carrier.Vector.Count != 1 ||
				prefix.CompletionClass != owner.CompletionClass || prefix.CompletedSteps != contract.GeneratorProgressAcknowledged || prefix.AttemptID == owner.AttemptID {
				return c, contract.ErrRecord
			}
			binding, known := c.attemptIntent[prefix.AttemptID]
			if !known || c.actions[prefix.AttemptID] != contract.GeneratorActionDelete {
				return c, contract.ErrRecord
			}
			if releaseVectors == nil {
				var supportRows []contract.SupportRecord
				for _, sourcePage := range pages {
					supportRows = append(supportRows, sourcePage.Records...)
				}
				vectors, err := newGeneratedVectorSet(page.Domain, supportRows)
				if err != nil {
					return c, err
				}
				releaseVectors = &vectors
			}
			facts, err := releaseVectors.resolve(contract.GeneratedAttemptSupportKind, owner.AttemptID, contract.GeneratorVectorFacts, owner.Facts)
			if err != nil || len(facts) != 1 {
				return c, contract.ErrRecord
			}
			factRow, err := contract.InspectGeneratorFactsRow(facts[0])
			if err != nil || factRow.ResultID != owner.ResultID {
				return c, contract.ErrRecord
			}
			fact, err := contract.InspectGeneratorSafeFacts(factRow.Facts)
			if err != nil || fact.Disposition != contract.GeneratorDispositionScopedUnusability || fact.PrecedingResultID != prefix.ResultID || fact.PrecedingResultBodyDigest != prefix.Evidence.Digest {
				return c, contract.ErrRecord
			}
			appendAdministrativeConsumer(c.operation, binding.operation, release.InboxID)
		}
	}
	for _, location := range c.slices {
		for _, group := range c.contentOwners(location) {
			appendAdministrativeConsumer(c.blobs, location.BlobID, group)
		}
	}
	for _, m := range []map[contract.ID][]contract.ID{c.operation, c.attempt, c.material, c.lineage, c.intentOperation, c.sourceOperation, c.blobs} {
		for key, groups := range m {
			slices.SortFunc(groups, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			m[key] = groups
		}
	}
	return c, nil
}

// selectedAdministrativeSlice reads one bounded logical slice and hashes its
// whole physical blob. The body allocation is bounded by the content kind,
// even when other logical slices share the blob.
func selectedAdministrativeSlice(location contract.GeneratorSliceLocation, parts []contract.GeneratedFragment,
	limit uint64) ([]byte, error) {
	if len(parts) == 0 || uint64(location.Length) > limit || uint64(location.Length) == 0 ||
		location.Offset > parts[0].TotalLength || uint64(location.Length) > parts[0].TotalLength-location.Offset {
		return nil, contract.ErrRecord
	}
	slices.SortFunc(parts, func(a, b contract.GeneratedFragment) int { return int(a.Index) - int(b.Index) })
	body := make([]byte, location.Length)
	h := sha256.New()
	var offset uint64
	for i, part := range parts {
		if int(part.Index) != i || uint64(part.Offset) != offset || part.Count != uint16(len(parts)) ||
			part.TotalLength != parts[0].TotalLength || part.WholeDigest != parts[0].WholeDigest || part.BlobID != location.BlobID {
			return nil, contract.ErrRecord
		}
		h.Write(part.Payload)
		start := max(offset, location.Offset)
		end := min(offset+uint64(len(part.Payload)), location.Offset+uint64(location.Length))
		if start < end {
			copy(body[start-location.Offset:end-location.Offset], part.Payload[start-offset:end-offset])
		}
		offset += uint64(len(part.Payload))
	}
	var whole contract.ID
	copy(whole[:], h.Sum(nil))
	if offset != parts[0].TotalLength || whole != parts[0].WholeDigest || contract.Hash(body) != location.Digest {
		return nil, contract.ErrRecord
	}
	return body, nil
}

func (c administrativeConsumers) bindDeclarationSources(pages []format.RequiredSupportPage, bundles []contract.GeneratorPlanBundle) error {
	operations := make(map[contract.ID]bool, len(bundles))
	for _, bundle := range bundles {
		operations[bundle.Header.OperationID] = true
	}
	fragments := make(map[contract.ID][]contract.GeneratedFragment)
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				return err
			}
			fragments[fragment.BlobID] = append(fragments[fragment.BlobID], contract.GeneratedFragment(fragment))
		}
	}
	for _, location := range c.slices {
		if location.ContentKind != contract.GeneratorContentGraph {
			continue
		}
		body, err := selectedAdministrativeSlice(location, fragments[location.BlobID], contract.GeneratorGraphMaxLength)
		if err != nil {
			return err
		}
		graph, err := contract.DecodeGeneratorPlanBundle(body)
		if err != nil || len(pages) == 0 || graph.Header.DomainID != pages[0].Domain ||
			graph.UsePlan.PlanGraphID != location.ContentID {
			return contract.ErrRecord
		}
		c.graphOperation[location.ContentID] = graph.Header.OperationID
		for _, lineage := range graph.Lineages {
			for _, template := range lineage.Templates[:lineage.TemplateCount] {
				c.actions[template.AttemptID] = template.Action
				appendAdministrativeConsumer(c.intentOperation, template.IntentDigest, graph.Header.OperationID)
				if err := c.bindIntentAttempt(graph.Header.OperationID, template.AttemptID, template.IntentDigest); err != nil {
					return err
				}
			}
		}
	}
	for _, location := range c.slices {
		if location.ContentKind != contract.GeneratorContentDeclaration || (len(bundles) != 0 && !operations[location.ContentID]) {
			continue
		}
		body, err := selectedAdministrativeSlice(location, fragments[location.BlobID], contract.GeneratorDeclarationMaxLength)
		if err != nil {
			return err
		}
		declaration, err := contract.InspectGeneratorDeclaration(body)
		if err != nil || declaration.OperationID != location.ContentID || len(pages) == 0 || declaration.DomainID != pages[0].Domain {
			return contract.ErrRecord
		}
		logical, err := declaration.LogicalSlices()
		if err != nil {
			return err
		}
		allowed := make(map[contract.ID]bool)
		for _, slice := range logical {
			switch slice.ContentKind {
			case contract.GeneratorContentIntent:
				appendAdministrativeConsumer(c.intentOperation, slice.ContentID, location.ContentID)
			case contract.GeneratorContentSource:
				allowed[slice.ContentID] = true
				appendAdministrativeConsumer(c.sourceOperation, slice.ContentID, location.ContentID)
			}
		}
		for _, candidate := range c.slices {
			if candidate.BlobID == location.BlobID && candidate.ContentKind == contract.GeneratorContentSource && !allowed[candidate.ContentID] {
				return contract.ErrRecord
			}
		}
	}
	return nil
}

// The complete predecessor already checked each selected graph and active
// declaration against its logical Slice and bundle. A bodyless successor uses
// those immutable relations and the admitted projected bundles; it must not
// join all old fragment payloads merely to rebuild page ownership.
func (c administrativeConsumers) bindDeclarationSourcesFromValidated(selected *generatedSelection,
	projected []contract.GeneratorPlanBundle) error {
	if selected == nil || selected.content == nil {
		return contract.ErrRecord
	}
	byOperation := make(map[contract.ID]contract.GeneratorPlanBundle)
	byGraph := make(map[contract.ID]contract.GeneratorPlanBundle)
	for _, bundle := range append(slices.Clone(selected.bundles), projected...) {
		operation, graph := bundle.Header.OperationID, bundle.UsePlan.PlanGraphID
		if operation.IsZero() || graph.IsZero() || bundle.Header.DomainID != selected.content.domain {
			return contract.ErrRecord
		}
		if prior, present := byOperation[operation]; present && prior.UsePlan.PlanGraphID != graph {
			return contract.ErrRecord
		}
		if prior, present := byGraph[graph]; present && prior.Header.OperationID != operation {
			return contract.ErrRecord
		}
		byOperation[operation], byGraph[graph] = bundle, bundle
		for _, lineage := range bundle.Lineages {
			for _, template := range lineage.Templates[:lineage.TemplateCount] {
				c.actions[template.AttemptID] = template.Action
				appendAdministrativeConsumer(c.intentOperation, template.IntentDigest, operation)
				if err := c.bindIntentAttempt(operation, template.AttemptID, template.IntentDigest); err != nil {
					return err
				}
			}
		}
		for _, plan := range bundle.ValueEntryPlans {
			switch plan.ValueSource {
			case contract.Generated:
				appendAdministrativeConsumer(c.intentOperation, plan.IntentDigest, operation)
			case contract.Supplied:
				entryID, err := contract.GeneratorDeclarationEntryID(bundle.Header.DomainID, operation, plan.Name)
				if err != nil {
					return err
				}
				appendAdministrativeConsumer(c.sourceOperation, entryID, operation)
			}
		}
		for _, source := range bundle.SourceUses {
			appendAdministrativeConsumer(c.sourceOperation, source.SourceID, operation)
		}
	}
	for _, location := range c.slices {
		key := generatedContentKey{kind: location.ContentKind, id: location.ContentID}
		if prior, present := selected.content.locations[key]; present && prior.Logical() != location.Logical() {
			return contract.ErrRecord
		}
		switch location.ContentKind {
		case contract.GeneratorContentGraph:
			bundle, present := byGraph[location.ContentID]
			if !present {
				return contract.ErrRecord
			}
			c.graphOperation[location.ContentID] = bundle.Header.OperationID
		case contract.GeneratorContentDeclaration, contract.GeneratorContentRecipientRegistry, contract.GeneratorContentOutputConfiguration:
			if _, present := byOperation[location.ContentID]; !present {
				return contract.ErrRecord
			}
		case contract.GeneratorContentSource:
			if len(c.sourceOperation[location.ContentID]) == 0 {
				return contract.ErrRecord
			}
		}
	}
	return nil
}

func (c administrativeConsumers) contentOwners(location contract.GeneratorSliceLocation) []contract.ID {
	var owners []contract.ID
	switch location.ContentKind {
	case contract.GeneratorContentFinalPreparation:
		preparation, present := c.finalPreparations[location.ContentID]
		if present && preparation.Image == location.Logical() &&
			slices.Contains(c.operation[preparation.OperationID], preparation.OperationID) {
			owners = append(owners, preparation.OperationID)
		}
	case contract.GeneratorContentDeclaration, contract.GeneratorContentRecipientRegistry, contract.GeneratorContentOutputConfiguration:
		if slices.Contains(c.operation[location.ContentID], location.ContentID) {
			owners = append(owners, location.ContentID)
		}
	case contract.GeneratorContentGraph:
		owners = append(owners, c.operation[c.graphOperation[location.ContentID]]...)
	case contract.GeneratorContentConfiguration:
		operation := c.materialOperation[location.ContentID]
		if slices.Contains(c.operation[operation], operation) {
			owners = append(owners, operation)
		}
	case contract.GeneratorContentIntent:
		for _, operation := range c.intentOperation[location.ContentID] {
			if slices.Contains(c.operation[operation], operation) {
				owners = append(owners, operation)
			}
		}
		for _, attempt := range c.intentAttempts[location.ContentID] {
			for _, group := range c.attempt[attempt] {
				if group != c.attempts[attempt].InboxID {
					owners = append(owners, group)
				}
			}
		}
	case contract.GeneratorContentSource:
		for _, operation := range c.sourceOperation[location.ContentID] {
			if slices.Contains(c.operation[operation], operation) {
				owners = append(owners, operation)
			}
		}
	}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(owners)
}

func (c administrativeConsumers) sliceOwners(location contract.GeneratorSliceLocation, complete bool) []contract.ID {
	owners := c.contentOwners(location)
	if !complete && len(owners) == 0 {
		owners = slices.Clone(c.blobs[location.BlobID])
	}
	return owners
}

func (c administrativeConsumers) attemptOwners(attempt, operation contract.ID) []contract.ID {
	out := slices.Clone(c.attempt[attempt])
	if slices.Contains(c.operation[operation], operation) && !slices.Contains(out, operation) {
		out = append(out, operation)
	}
	slices.SortFunc(out, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return out
}

func (c administrativeConsumers) operationOwners(operation contract.ID) []contract.ID {
	return slices.Clone(c.operation[operation])
}

func (c administrativeConsumers) materialOwners(material, operation contract.ID) []contract.ID {
	out := slices.Clone(c.material[material])
	if slices.Contains(c.operation[operation], operation) && !slices.Contains(out, operation) {
		out = append(out, operation)
	}
	slices.SortFunc(out, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return out
}

// An enclosed apply retains the exact displaced Create evidence after an auto
// Duty closes, so its released Delete still has a public target. This is an
// administrative metadata owner, not a live CREATE input consumer.
func (s *StateSession) bindAutomaticHistoricalConsumers(root format.Root, pages []format.RequiredSupportPage, bundles []contract.GeneratorPlanBundle, prior map[generatedRecordKey]priorAdministrativeRow, c *administrativeConsumers) error {
	if root.Generated.ActiveOwner.IsZero() {
		return nil
	}
	var parentBody []byte
	var phase contract.GeneratedPhaseRecord
	for _, page := range pages {
		for _, row := range page.Records {
			if row.RecordID != root.Generated.ActiveOwner {
				continue
			}
			var err error
			switch row.Kind {
			case contract.GeneratedParentSupportKind:
				parentBody = row.Body
			case contract.GeneratedPhaseSupportKind:
				phase, err = contract.InspectGeneratedPhaseRecord(row.Body)
			}
			if err != nil {
				return err
			}
		}
	}
	if phase.SelectionPhaseID.IsZero() {
		return nil
	}
	parent, err := contract.InspectGeneratedParentRecord(parentBody)
	if err != nil {
		return err
	}
	if parent.DomainID != root.Domain || parent.OperationID != root.Generated.ActiveOwner || parent.PlanGraphID != root.Generated.ActiveGraph ||
		phase.DomainID != parent.DomainID || phase.OperationID != parent.OperationID || phase.OwnerID != parent.OperationID ||
		phase.PlanGraphID != parent.PlanGraphID || phase.UsePlanDigest != parent.UsePlanDigest || phase.PhaseID != root.Generated.ActivePhase {
		return contract.ErrRecord
	}
	var graph *contract.GeneratorPlanBundle
	for i := range bundles {
		if bundles[i].Header.OperationID == parent.OperationID && bundles[i].UsePlan.PlanGraphID == parent.PlanGraphID {
			graph = &bundles[i]
			break
		}
	}
	if graph != nil && (graph.Header.DomainID != root.Domain || graph.Request.OperationID != parent.OperationID || graph.Request.OperationKind != contract.OperationApplyDeclaration && graph.Request.OperationKind != contract.OperationRotateValueEntryValue) {
		return contract.ErrRecord
	}
	var automatic []uint16
	if graph != nil {
		automatic = contract.GeneratedAutomaticRetirementIndices(*graph)
	}
	// A generic successor does not reopen the graph. Exact unchanged anchored
	// rows may retain only the Parent ownership authenticated by its predecessor.
	preserved := s.sameAutomaticIndexAnchor(root, pages)
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind != contract.GeneratedCreateEvidenceSupportKind {
				continue
			}
			evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
			if err != nil {
				return err
			}
			core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
			if err != nil {
				return err
			}
			// The graph establishes a historical consumer, not new evidence.
			// Retain only the exact kind/key/body already authenticated before
			// selection; token and original result-contract bytes stay frozen.
			key := generatedRecordKey{row.Kind, row.RecordID}
			position, present := prior[key]
			if !present {
				continue
			}
			previous := s.support[position.page].Records
			at := slices.IndexFunc(previous, func(old contract.SupportRecordView) bool {
				return old.Kind == key.kind && old.RecordID == key.id
			})
			if at < 0 || !bytes.Equal(previous[at].Body, row.Body) {
				continue
			}
			owned := false
			if graph != nil {
				facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
				if err != nil {
					return err
				}
				duty, err := contract.GeneratorDutyID(root.Domain, core.OperationID, core.AttemptID, contract.GeneratedDutyRetirement)
				if err != nil {
					return err
				}
				resource, err := contract.GeneratorResourceID(root.Domain, core.OperationID, core.AttemptID)
				if err != nil {
					return err
				}
				for _, index := range automatic {
					lineage := graph.Lineages[index]
					x := lineage.Templates[0]
					// The admitted Delete can use a different implementation from
					// the original Create; their shared relation is the resource and intent.
					if duty != x.DutyID || resource != x.ResourceIncarnationID || core.DomainID != root.Domain || core.ConfigContractID != x.ConfigContractID ||
						x.Action != contract.GeneratorActionDelete || facts.Action != contract.GeneratorActionCreate || core.Disposition(facts.Disposition) != contract.GeneratorDispositionCompleteCreate ||
						facts.LifecycleMode != x.LifecycleMode || facts.ResourceContractID != x.ResourceContractID || !generatedResourceFactsMatch(facts.GeneratorSafeFacts, x.ResourceDigest) ||
						facts.IntentDigest != x.IntentDigest || facts.IntentDigest != lineage.IntentDigest || evidence.CompletionClass != x.CompletionClass {
						continue
					}
					original, err := contract.GeneratorLineageID(root.Domain, core.OperationID, lineage.Name, lineage.EntryIncarnationID, lineage.Epoch, lineage.IntentDigest)
					if err != nil {
						return err
					}
					for branch := uint8(0); branch < contract.GeneratorCreateLineageTemplates; branch++ {
						attempt, err := contract.GeneratorAttemptID(original, branch)
						if err != nil {
							return err
						}
						owned = owned || attempt == core.AttemptID
					}
				}
			} else if preserved {
				owned = slices.Contains(s.priorAdministrativeOwnership(position).groups, parent.OperationID)
			}
			if owned {
				appendAdministrativeConsumer(c.attempt, core.AttemptID, parent.OperationID)
				appendAdministrativeConsumer(c.operation, core.OperationID, parent.OperationID)
			}
		}
	}
	for _, location := range c.slices {
		for _, group := range c.contentOwners(location) {
			appendAdministrativeConsumer(c.blobs, location.BlobID, group)
		}
	}
	return nil
}
