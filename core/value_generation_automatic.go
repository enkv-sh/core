package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

func generatedSelectionAnchored(g *generatedSelection) bool {
	return g != nil && g.parent != nil && g.phase != nil && !g.phase.SelectionPhaseID.IsZero()
}

func generatedAutomaticTemplate(g *generatedSelection, index uint16) (contract.GeneratorAttemptTemplate, contract.GeneratorResultUse, bool) {
	if !generatedSelectionAnchored(g) || len(g.bundles) == 0 || !slices.Contains(contract.GeneratedAutomaticRetirementIndices(g.bundles[0]), index) {
		return contract.GeneratorAttemptTemplate{}, contract.GeneratorResultUse{}, false
	}
	x := g.bundles[0].Lineages[index].Templates[0]
	_, use, ok := generatedTemplate(g.bundles[0], x.AttemptID)
	return x, use, ok
}

func generatedAutomaticNext(g *generatedSelection, after int) (uint16, contract.GeneratorAttemptTemplate, bool) {
	for _, index := range contract.GeneratedAutomaticRetirementIndices(g.bundles[0]) {
		if int(index) > after {
			x := g.bundles[0].Lineages[index].Templates[0]
			return index, x, true
		}
	}
	return 0, contract.GeneratorAttemptTemplate{}, false
}

func generatedAutomaticAccessPreserved(before, after []contract.AccessRecord) error {
	old := make(map[materialIdentity]contract.ID, len(before))
	for _, row := range before {
		digest, err := contract.AccessRecordDigest(row)
		if err != nil {
			return err
		}
		old[materialIdentity{row.MaterialKind, row.MaterialID}] = digest
	}
	for _, row := range after {
		digest, err := contract.AccessRecordDigest(row)
		if err != nil || old[materialIdentity{row.MaterialKind, row.MaterialID}] != digest {
			return contract.ErrRecord
		}
	}
	return nil
}

func generatedAutomaticPhaseRows(g *generatedSelection, phase contract.GeneratedPhaseRecord, rows []contract.SupportRecord) ([]contract.SupportRecord, error) {
	view := *g
	view.phase = &phase
	view.attempts = make(map[contract.ID]generatedAttempt)
	for _, row := range rows {
		if row.Kind == contract.GeneratedAttemptSupportKind {
			a, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return nil, err
			}
			if a.OperationID == phase.OperationID {
				x, use, ok := generatedTemplate(g.bundles[0], a.AttemptID)
				if !ok {
					return nil, contract.ErrRecord
				}
				view.attempts[a.AttemptID] = generatedAttempt{record: a, expected: contract.GeneratorResultExpectation{Template: x, Use: use}}
			}
		}
	}
	for _, set := range []struct {
		kind   uint8
		family contract.GeneratorRecordSetKind
		value  *contract.GeneratorDescriptor
	}{
		{contract.GeneratedResultSupportKind, contract.GeneratorPhaseResults, &phase.AcceptedResults},
		{contract.GeneratedAttemptSupportKind, contract.GeneratorPhaseAttempts, &phase.Attempts},
		{contract.GeneratedDutySupportKind, contract.GeneratorPhaseDuties, &phase.Duties},
		{contract.GeneratedHazardSupportKind, contract.GeneratorPhaseHazards, &phase.Hazards},
		{contract.PendingInboxReleaseSupportKind, contract.GeneratorPhaseReleases, &phase.PendingReleases},
	} {
		var selected []contract.SupportRecord
		for _, row := range rows {
			if row.Kind == set.kind && view.activePhaseOwns(row) {
				selected = append(selected, row)
			}
		}
		slices.SortFunc(selected, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
		var err error
		*set.value, err = contract.GeneratorRecordSetDescriptor(set.family, phase.DomainID, selected)
		if err != nil {
			return nil, err
		}
	}
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == contract.GeneratedPhaseSupportKind && rows[i].RecordID == phase.OperationID {
			rows[i].Body = body
			return rows, nil
		}
	}
	return append(rows, contract.SupportRecord{Kind: contract.GeneratedPhaseSupportKind, RecordID: phase.OperationID, Body: body}), nil
}

func generatedAutomaticInvocationScope(ctx context.Context, state *StateSession, work *generatedSelection) (generatedInvocationResultScope, error) {
	var scope generatedInvocationResultScope
	if !generatedSelectionAnchored(work) || state == nil {
		return scope, contract.ErrRecord
	}
	scope.OperationKind = work.bundles[0].Request.OperationKind
	scope.OperationID, scope.RequestIdentity = work.parent.OperationID, work.parent.RequestIdentityDigest
	scope.OriginalPredecessorRevisionID = work.bundles[0].Request.PredecessorRevisionID
	scope.ChangedSubjects, scope.ChangedAccess = work.phase.ChangedSubjects, work.phase.ChangedAccess
	scope.CanonicalSuccessor, scope.receiptOptional = true, true
	scope.EffectClasses = make(map[contract.ID]int)
	scope.CompletionClasses = make(map[contract.ID]uint8)
	seenDuty := make(map[contract.ID]bool)
	for _, lineage := range work.bundles[0].Lineages {
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			a, entered := work.attempts[x.AttemptID]
			if released, ok := work.releases[x.AttemptID]; ok {
				a.record = released.attempt
				entered = true
			}
			if entered {
				row := work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, x.AttemptID}]
				scope.Effects = append(scope.Effects, row)
				class := contract.ReceiptSummaryPendingCount
				switch a.record.State {
				case contract.GeneratedEffectSucceeded:
					class = contract.ReceiptSummarySuccessCount
				case contract.GeneratedEffectConfirmedNoEffect:
					class = contract.ReceiptNoEffectPredecessorCount
				case contract.GeneratedEffectClosedWithResidue:
					class = contract.ReceiptPreservedResidueCount
				case contract.GeneratedEffectFailedTerminal:
					class = contract.ReceiptSummaryFailureCount
				case contract.GeneratedEffectTransmitted, contract.GeneratedEffectUnknown:
					class = contract.ReceiptSummaryUnknownCount
				}
				scope.EffectClasses[x.AttemptID] = class
				if x.Action == contract.GeneratorActionDelete && a.record.State == contract.GeneratedEffectSucceeded {
					if a.record.CompletionClass == contract.GeneratedCompletionAcknowledged {
						scope.CompletionClasses[x.AttemptID] = a.record.CompletionClass
					} else {
						if released, ok := work.releases[x.AttemptID]; ok {
							progress, err := work.controlledReleasedProgress(released)
							if err != nil {
								return scope, err
							}
							if len(progress) == 2 {
								scope.CompletionClasses[x.AttemptID] = a.record.CompletionClass
							}
						} else if row, ok := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, x.DutyID}]; ok {
							duty, err := contract.InspectGeneratedDutyRecord(row.Body)
							if err != nil {
								return scope, err
							}
							progress, err := work.controlledRetirementProgress(duty, nil, true)
							if err != nil {
								return scope, err
							}
							if len(progress.rows) == 2 && !progress.contradiction {
								scope.CompletionClasses[x.AttemptID] = a.record.CompletionClass
							}
						}
					}
				}
			}
			if row, ok := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, x.DutyID}]; ok && !seenDuty[x.DutyID] {
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil {
					return scope, err
				}
				if duty.Kind == contract.GeneratedDutyRetirement || duty.Kind == contract.GeneratedDutyUnselectedCleanup {
					scope.Duties = append(scope.Duties, row)
					scope.RelatedDutyIDs = append(scope.RelatedDutyIDs, x.DutyID)
					seenDuty[x.DutyID] = true
				}
			}
			if row, ok := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, x.HazardID}]; ok {
				scope.Hazards = append(scope.Hazards, row)
				scope.RelatedHazardIDs = append(scope.RelatedHazardIDs, x.HazardID)
			}
		}
	}
	// Work records use ID order in the terminal receipt. Keep that same
	// complete-set order through capture; Effects retain graph order above.
	slices.SortFunc(scope.Duties, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	slices.SortFunc(scope.Hazards, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	for index, row := range scope.Duties {
		scope.RelatedDutyIDs[index] = row.RecordID
	}
	for index, row := range scope.Hazards {
		scope.RelatedHazardIDs[index] = row.RecordID
	}
	return scope, nil
}

// Canonical selection ends the CREATE input lifetime. Original result readers
// remain until the original apply receipt closes their parent.
func generatedEndCreateInputConsumers(g *generatedSelection, rows []contract.SupportRecord) ([]contract.SupportRecord, error) {
	owners := make(map[contract.ID]bool)
	for _, a := range g.attempts {
		if a.record.OperationID == g.parent.OperationID && a.expected.Template.Action == contract.GeneratorActionCreate {
			owners[a.record.OwnerID] = true
		}
	}
	var out, carriers []contract.SupportRecord
	for _, row := range rows {
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			if v.VectorKind == contract.GeneratorVectorConsumers && (v.OwnerKind == contract.GeneratedParentSupportKind && v.OwnerID == g.parent.OperationID || v.OwnerKind == contract.GeneratedDutySupportKind && owners[v.OwnerID]) {
				continue
			}
		}
		if row.Kind == contract.GeneratedDutySupportKind && owners[row.RecordID] {
			d, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return nil, err
			}
			bodies, err := g.vectors.resolve(row.Kind, row.RecordID, contract.GeneratorVectorConsumers, d.Consumers)
			if err != nil {
				return nil, err
			}
			var kept [][]byte
			for _, body := range bodies {
				c, err := contract.InspectGeneratorConsumer(body)
				if err != nil {
					return nil, err
				}
				if c.SubjectKind == contract.GeneratorConsumerOriginalResult {
					kept = append(kept, body)
				}
			}
			var added []contract.SupportRecord
			d.Consumers, added, err = generatedCarrierRows(g.parent.DomainID, row.Kind, row.RecordID, contract.GeneratorVectorConsumers, kept)
			if err != nil {
				return nil, err
			}
			carriers = append(carriers, added...)
			row.Body, err = contract.EncodeGeneratedDutyRecord(d)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, row)
	}
	return append(out, carriers...), nil
}

func (s *StateSession) generatedAutomaticReservationRequest(ctx context.Context, admitted contract.ApplyContext, digest contract.ID) (*generatedSuccessorReservationPlan, error) {
	if s == nil || s.prepared || digest.IsZero() || !s.generatedContextValid(admitted) {
		return nil, contract.ErrRecord
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if !generatedSelectionAnchored(g) || g.phase.Phase == ^uint32(0) || g.phase.Stage != contract.GeneratedStageRetainedResult {
		return nil, contract.ErrRecord
	}
	x, _, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok || x.AttemptID != g.phase.FrontierAttemptID {
		return nil, contract.ErrRecord
	}
	if _, entered := g.attempts[x.AttemptID]; entered {
		return nil, contract.ErrRecord
	}
	source, err := g.generatedDeleteSource(x.DutyID)
	if err != nil || source.Record.Kind != contract.GeneratedDutySupportKind || source.Duty.Kind != contract.GeneratedDutyRetirement || source.Duty.Status != contract.GeneratedEffectNotStarted {
		return nil, contract.ErrRecord
	}
	evidence, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, s.root.Domain, []contract.SupportRecord{source.Record})
	if err != nil {
		return nil, err
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: g.parent.RequestIdentityDigest, ObservedHEADDigest: admitted.PredecessorHEADDigest, ConditionDigest: admitted.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityRetireReserve, BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1, Evidence: evidence}
	if _, err := contract.GeneratorPhaseID(phase); err != nil {
		return nil, err
	}
	return &generatedSuccessorReservationPlan{context: admitted, phase: phase, attempt: x.AttemptID, requestDigest: digest, source: observationSource{ParentID: g.parent.OperationID, AttemptID: x.AttemptID}}, nil
}

func (s *StateSession) deriveGeneratedAutomaticReservation(ctx context.Context, g *generatedSelection, plan *generatedSuccessorReservationPlan) (*generatedReservation, error) {
	x, use, ok := generatedAutomaticTemplate(g, g.phase.LineageIndex)
	if !ok || x.AttemptID != plan.attempt {
		return nil, contract.ErrRecord
	}
	source, err := g.generatedDeleteSource(x.DutyID)
	if err != nil {
		return nil, err
	}
	target, err := g.retirementTarget(ctx, source.Duty)
	if err != nil {
		return nil, err
	}
	a := contract.GeneratedAttemptRecord{DomainID: g.parent.DomainID, OperationID: g.parent.OperationID, OwnerID: x.DutyID, LineageID: x.LineageID, ResourceID: x.ResourceIncarnationID, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID, DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, CompletionClass: x.CompletionClass}
	if err := g.validateDeleteTarget(ctx, g.bundles[0], a, target); err != nil {
		return nil, err
	}
	selected := generatedDeleteReservationSelection{purpose: contract.GeneratorAuthorityRetireReserve, lineageIndex: g.phase.LineageIndex, template: x, use: use, duty: source.Duty, dutyRow: source.Record, source: source, target: target, phase: plan.phase}
	graph := g.bundles[0]
	graph.SourceUses = nil
	material, err := contract.InspectOperationMaterialRecord(g.records[generatedRecordKey{contract.OperationMaterialSupportKind, g.parent.MaterialID}].Body)
	if err != nil {
		return nil, err
	}
	phaseID, err := contract.GeneratorPhaseID(plan.phase)
	if err != nil {
		return nil, err
	}
	entered, err := generatedInitialDeleteRows(generatedReservationInput{graph: graph, parent: contract.GeneratedParentPlan(*g.parent), finished: contract.CryptoGeneratedFinishPlanResult{Material: material}, requestBindings: []generatedRequestBinding{{LineageID: x.LineageID, AttemptID: x.AttemptID, Digest: plan.requestDigest}}}, phaseID, selected, g)
	if err != nil {
		return nil, err
	}
	var rows []contract.SupportRecord
	for _, row := range s.supportRecords() {
		if generatedDeleteReservationReplaces(row, selected) {
			continue
		}
		if slices.ContainsFunc(entered, func(v contract.SupportRecord) bool { return v.Kind == row.Kind && v.RecordID == row.RecordID }) {
			continue
		}
		rows = append(rows, row)
	}
	rows = append(rows, entered...)
	phase := *g.phase
	phase.PhaseID, phase.Phase = phaseID, plan.phase.AfterPhase
	rows, err = generatedAutomaticPhaseRows(g, phase, rows)
	if err != nil {
		return nil, err
	}
	return s.deriveGeneratedSuccessorCandidate(ctx, g, plan, x, phaseID, rows)
}

func (s *StateSession) generatedAutomaticCandidatePreserved(next *StateSession) error {
	var before, after *contract.GeneratedPhaseRecord
	read := func(state *StateSession) (*contract.GeneratedPhaseRecord, error) {
		for _, row := range state.supportRecords() {
			if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == s.root.Generated.ActiveOwner {
				p, err := contract.InspectGeneratedPhaseRecord(row.Body)
				if err != nil {
					return nil, err
				}
				return &p, nil
			}
		}
		return nil, nil
	}
	var err error
	before, err = read(s)
	if err != nil {
		return err
	}
	if before == nil || before.SelectionPhaseID.IsZero() {
		return nil
	}
	after, err = read(next)
	if err != nil {
		return err
	}
	if after != nil && (after.SelectionPhaseID != before.SelectionPhaseID || after.ChangedSubjects != before.ChangedSubjects || after.ChangedAccess != before.ChangedAccess) {
		return contract.ErrRecord
	}
	if after == nil && !next.root.Generated.ActiveOwner.IsZero() {
		return contract.ErrRecord
	}
	return generatedAutomaticAccessPreserved(s.accessRecords(), next.accessRecords())
}

// A closed delete's exact public target remains derivable during the same
// anchored apply. It roots immutable create evidence, not private CREATE input.
func generatedAutomaticReleasedTarget(ctx context.Context, g *generatedSelection, x contract.GeneratorAttemptTemplate) (*contract.GeneratorTarget, error) {
	if !generatedSelectionAnchored(g) {
		return nil, nil
	}
	var lineage *contract.GeneratorLineageTemplate
	for _, index := range contract.GeneratedAutomaticRetirementIndices(g.bundles[0]) {
		v := g.bundles[0].Lineages[index]
		if v.Templates[0] == x {
			copy := v
			lineage = &copy
		}
	}
	if lineage == nil {
		return nil, nil
	}
	if _, released := g.releases[x.AttemptID]; !released {
		return nil, nil
	}
	var target *contract.GeneratorTarget
	for key, row := range g.records {
		if key.kind != contract.GeneratedCreateEvidenceSupportKind {
			continue
		}
		evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
		if err != nil {
			return nil, err
		}
		core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
		if err != nil {
			return nil, err
		}
		duty, err := contract.GeneratorDutyID(g.image.root.Domain, core.OperationID, core.AttemptID, contract.GeneratedDutyRetirement)
		if err != nil {
			return nil, err
		}
		if duty != x.DutyID {
			continue
		}
		if core.Schema == contract.GeneratedResultEncodingFailureSchema || target != nil {
			return nil, contract.ErrRecord
		}
		facts, err := contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
		if err != nil {
			return nil, err
		}
		resourceDigest, err := contract.GeneratorResourceDigest(facts.GeneratorSafeFacts)
		if err != nil {
			return nil, err
		}
		value := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: lineage.Name, IncarnationID: lineage.EntryIncarnationID, Epoch: lineage.Epoch, ResourceID: x.ResourceIncarnationID, ResourceDigest: resourceDigest, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, OriginalOperationID: core.OperationID, OriginalAttemptID: core.AttemptID, ResultContractID: core.ResultContractID, CompletionClass: x.CompletionClass}
		if _, err := g.createTargetEvidence(ctx, value); err != nil {
			return nil, err
		}
		target = &value
	}
	if target == nil {
		return nil, contract.ErrRecord
	}
	return target, nil
}
