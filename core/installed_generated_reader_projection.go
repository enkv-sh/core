package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

type GeneratedCurrentGeneration struct {
	Name                                                 string
	EntryIncarnationID, GenerationID                     contract.ID
	Epoch                                                uint64
	OriginOperationID, OriginAttemptID, ResourceID       contract.ID
	ResourceDigest, ConfigContractID, ResourceContractID contract.ID
	LifecycleMode                                        contract.GeneratorLifecycleMode
	CompletionClass, RetirementMode                      uint8
	RetiringDutyID                                       contract.ID
}

type GeneratedActiveOperation struct {
	OperationID, PhaseID, FrontierAttemptID contract.ID
	OperationKind                           uint16
	Phase                                   uint32
	Stage                                   uint8
}

// GeneratedNextAction identifies a supported request form, not an admission or
// evidence that its selectors will remain eligible at a later observation.
type GeneratedNextAction struct {
	Command                        string
	OperationID, DutyID, AttemptID contract.ID
}

// GeneratedPendingResultCleanup keeps selected release provenance and the exact
// public effect row. It grants no cleanup or retry permission.
type GeneratedPendingResultCleanup struct {
	contract.PendingInboxReleaseRecord
	OriginalOperationID, OriginalAttemptID contract.ID
	Action, EffectState, CompletionClass   uint8
	EffectIndex                            uint32 `json:"-"`
}

func ValidateGeneratedPendingResultCleanup(domain contract.ID, rows []GeneratedPendingResultCleanup, effects []GeneratedEffectFact) error {
	if domain.IsZero() {
		return contract.ErrRecord
	}
	if uint64(len(rows)) > GeneratedResultAttemptLimit || uint64(len(effects)) > GeneratedResultEffectLimit {
		return contract.ErrRecordCapacity
	}
	for i, row := range rows {
		if _, err := contract.PendingInboxReleaseRecordLength(row.PendingInboxReleaseRecord); err != nil || row.DomainID != domain || row.OriginalOperationID.IsZero() || row.OriginalAttemptID.IsZero() || uint64(row.EffectIndex) >= uint64(len(effects)) || i > 0 && bytes.Compare(rows[i-1].InboxID[:], row.InboxID[:]) >= 0 {
			return contract.ErrRecord
		}
		effect := effects[row.EffectIndex]
		if _, err := contract.GeneratedAttemptRecordLength(effect.Record); err != nil || effect.Record.DomainID != domain || effect.Record.Stage != contract.GeneratedStageTerminal || row.InboxID != effect.Record.InboxID || row.OriginalResultID != effect.Record.ResultID || row.OriginalOperationID != effect.Record.OperationID || row.OriginalAttemptID != effect.Record.AttemptID || row.Action != effect.Action || row.Action != contract.GeneratorActionCreate && row.Action != contract.GeneratorActionDelete || row.EffectState != effect.Record.State || row.CompletionClass != effect.Record.CompletionClass {
			return contract.ErrRecord
		}
	}
	return nil
}

// GeneratedListView owns the complete bounded selected live-work projection.
// Retained rows are not a complete operation or provider-resource history.
type GeneratedListView struct {
	DomainID, RevisionID, SnapshotID contract.ID
	CurrentGenerations               []GeneratedCurrentGeneration
	ActiveOperation                  *GeneratedActiveOperation
	Effects                          []GeneratedEffectFact
	Duties                           []GeneratedDutyFact
	Hazards                          []GeneratedHazardFact
	PendingReleases                  []GeneratedPendingResultCleanup
	NextActions                      []GeneratedNextAction
	DomainWarningBits                uint8
	Warnings                         GeneratedResultWarnings
	PossibleGarbage                  bool
}

// The selected state supplies all work identities. Only an exact active standalone
// retirement can require a separate evidence read for its next action.
func projectGeneratedList(ctx context.Context, g *generatedSelection, evidence retirementEvidenceReader) (GeneratedListView, error) {
	var out GeneratedListView
	if ctx == nil || g == nil || g.image == nil || g.content == nil {
		return out, contract.ErrRecord
	}
	root := g.image.root
	if uint64(root.Generated.Attempts) > GeneratedResultAttemptLimit ||
		uint64(root.Generated.Duties)+uint64(root.Generated.Hazards) > GeneratedResultWorkLimit || uint64(root.Generated.PendingReleases) > GeneratedResultAttemptLimit {
		return out, contract.ErrRecordCapacity
	}
	if uint32(len(g.releases)) != root.Generated.PendingReleases {
		return out, contract.ErrRecord
	}
	if root.Generated.PendingReleases != 0 {
		out.PendingReleases = make([]GeneratedPendingResultCleanup, 0, int(root.Generated.PendingReleases))
	}
	out.DomainWarningBits = root.WarningBits
	for _, name := range root.Names {
		entry := g.image.valueEntry(name.Slot)
		if entry == nil || entry.Name != name.Name {
			return GeneratedListView{}, contract.ErrRecord
		}
		if entry.ValueSource != contract.Generated {
			continue
		}
		m := entry.Generated
		out.CurrentGenerations = append(out.CurrentGenerations, GeneratedCurrentGeneration{
			Name: entry.Name, EntryIncarnationID: entry.Incarnation, GenerationID: m.GenerationID, Epoch: m.Epoch,
			OriginOperationID: m.OriginOperationID, OriginAttemptID: m.OriginAttemptID, ResourceID: m.ResourceIncarnationID,
			ResourceDigest: m.ResourceDigest, ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID,
			LifecycleMode: m.SemanticLifecycleMode(), CompletionClass: m.CompletionClass, RetirementMode: m.RetirementMode, RetiringDutyID: m.RetiringDutyID,
		})
	}
	if uint32(len(out.CurrentGenerations)) != root.Generated.GeneratedCurrent {
		return GeneratedListView{}, contract.ErrRecord
	}
	if g.parent != nil {
		if g.phase == nil {
			return GeneratedListView{}, contract.ErrRecord
		}
		var kind uint16
		for _, bundle := range g.bundles {
			if bundle.Header.OperationID == g.parent.OperationID {
				kind = bundle.Request.OperationKind
				break
			}
		}
		if kind == 0 {
			return GeneratedListView{}, contract.ErrRecord
		}
		out.ActiveOperation = &GeneratedActiveOperation{OperationID: g.parent.OperationID, OperationKind: kind,
			PhaseID: g.phase.PhaseID, Phase: g.phase.Phase, Stage: g.phase.Stage, FrontierAttemptID: g.phase.FrontierAttemptID}
		switch kind {
		case contract.OperationApplyDeclaration:
			out.NextActions = append(out.NextActions, GeneratedNextAction{Command: "apply", OperationID: g.parent.OperationID})
		case contract.OperationRetireGeneratedGeneration:
			out.NextActions = append(out.NextActions, GeneratedNextAction{Command: "generated retire", OperationID: g.parent.OperationID})
		case contract.OperationCleanOwnedFailureResidue:
			out.NextActions = append(out.NextActions, GeneratedNextAction{Command: "generated cleanup", OperationID: g.parent.OperationID})
		}
	}
	var progressCount uint64
	for key := range g.records {
		if err := ctx.Err(); err != nil {
			return GeneratedListView{}, err
		}
		switch key.kind {
		case contract.GeneratedDutySupportKind:
			row, err := generatedDutyFact(ctx, g, key.id)
			if err != nil {
				return GeneratedListView{}, err
			}
			out.Duties = append(out.Duties, row)
			progressCount += uint64(len(row.Progress))
			out.Warnings = mergeGeneratedResultWarnings(out.Warnings, row.Warnings)
		case contract.GeneratedHazardSupportKind:
			row, err := generatedHazardFact(ctx, g, key.id)
			if err != nil {
				return GeneratedListView{}, err
			}
			out.Hazards = append(out.Hazards, row)
			out.Warnings = mergeGeneratedResultWarnings(out.Warnings, row.Warnings)
		}
		if progressCount > GeneratedResultProgressLimit {
			return GeneratedListView{}, contract.ErrRecordCapacity
		}
	}
	graphs := make([]int, len(g.bundles))
	for at := range graphs {
		graphs[at] = at
	}
	slices.SortFunc(graphs, func(a, b int) int {
		return bytes.Compare(g.bundles[a].Header.OperationID[:], g.bundles[b].Header.OperationID[:])
	})
	for _, at := range graphs {
		for _, lineage := range g.bundles[at].Lineages {
			if err := ctx.Err(); err != nil {
				return GeneratedListView{}, err
			}
			for _, template := range lineage.Templates[:lineage.TemplateCount] {
				_, live := g.attempts[template.AttemptID]
				_, released := g.releases[template.AttemptID]
				if !live && !released {
					continue
				}
				row, err := generatedEffectFactForLineage(ctx, g, template.AttemptID, lineage)
				if err != nil {
					return GeneratedListView{}, err
				}
				out.Effects = append(out.Effects, row)
				if released {
					original := g.releases[template.AttemptID]
					out.PendingReleases = append(out.PendingReleases, GeneratedPendingResultCleanup{PendingInboxReleaseRecord: original.release, OriginalOperationID: original.attempt.OperationID, OriginalAttemptID: original.attempt.AttemptID, Action: original.template.Action, EffectState: original.attempt.State, CompletionClass: original.attempt.CompletionClass, EffectIndex: uint32(len(out.Effects) - 1)})
					out.PossibleGarbage = out.PossibleGarbage || original.release.State == contract.GeneratedReleaseUnknown || original.release.State == contract.GeneratedReleaseUnobserved
				}
				progressCount += uint64(len(row.Progress))
				out.Warnings = mergeGeneratedResultWarnings(out.Warnings, row.Warnings)
				if progressCount > GeneratedResultProgressLimit {
					return GeneratedListView{}, contract.ErrRecordCapacity
				}
			}
		}
	}
	if uint32(len(out.Effects)) != root.Generated.Attempts || uint32(len(out.Duties)) != root.Generated.Duties ||
		uint32(len(out.Hazards)) != root.Generated.Hazards || uint32(len(out.PendingReleases)) != root.Generated.PendingReleases {
		return GeneratedListView{}, contract.ErrRecord
	}
	slices.SortFunc(out.Duties, func(a, b GeneratedDutyFact) int {
		return compareGeneratedOwnerOrder(a.Record.OriginalOperationID, a.Record.OriginalAttemptID, a.Record.DutyID,
			b.Record.OriginalOperationID, b.Record.OriginalAttemptID, b.Record.DutyID)
	})
	slices.SortFunc(out.Hazards, func(a, b GeneratedHazardFact) int {
		return compareGeneratedOwnerOrder(a.Record.OriginalOperationID, a.Record.OriginalAttemptID, a.Record.HazardID,
			b.Record.OriginalOperationID, b.Record.OriginalAttemptID, b.Record.HazardID)
	})
	slices.SortFunc(out.PendingReleases, func(a, b GeneratedPendingResultCleanup) int { return bytes.Compare(a.InboxID[:], b.InboxID[:]) })
	if err := ValidateGeneratedPendingResultCleanup(root.Domain, out.PendingReleases, out.Effects); err != nil {
		return GeneratedListView{}, err
	}
	cleanup := false
	for _, fact := range out.Duties {
		duty := fact.Record
		if g.parent == nil && duty.Kind == contract.GeneratedDutyRetirement {
			out.NextActions = append(out.NextActions, GeneratedNextAction{Command: "generated retire", DutyID: duty.DutyID})
		}
		attempt, _, err := evidence.riskAttempt(ctx, g, duty, contract.ID{})
		if err != nil {
			return GeneratedListView{}, err
		}
		if !attempt.IsZero() {
			out.NextActions = append(out.NextActions, GeneratedNextAction{Command: "generated accept-retirement-risk", DutyID: duty.DutyID, AttemptID: attempt})
		}
		cleanup = cleanup || duty.Kind == contract.GeneratedDutyUnselectedCleanup && !g.cleanupConflicts[duty.DutyID]
	}
	for _, fact := range out.Hazards {
		cleanup = cleanup || fact.Record.Fenced == 1 && fact.Record.Eligibility != 0
	}
	if cleanup && g.parent == nil {
		out.NextActions = append(out.NextActions, GeneratedNextAction{Command: "generated cleanup"})
	}
	return out, nil
}

func (r retirementEvidenceReader) riskAttempt(ctx context.Context, g *generatedSelection, duty contract.GeneratedDutyRecord, requested contract.ID) (contract.ID, []byte, error) {
	if duty.Kind != contract.GeneratedDutyRetirement || duty.Status != contract.GeneratedEffectUnknown && duty.Status != contract.GeneratedEffectTransmitted {
		return contract.ID{}, nil, nil
	}
	rows, err := g.vectors.resolve(contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorHistory, duty.History)
	if err != nil {
		return contract.ID{}, nil, err
	}
	if len(rows) == 0 {
		return contract.ID{}, nil, contract.ErrRecord
	}
	var latest contract.GeneratorHistory
	for _, body := range rows {
		latest, err = contract.InspectGeneratorHistory(body)
		if err != nil {
			return contract.ID{}, nil, err
		}
		attempt, ok := g.attempts[latest.PredecessorAttemptID]
		if !ok {
			return contract.ID{}, nil, contract.ErrRecord
		}
		contradiction, err := g.validateDeleteFacts(attempt)
		if err != nil || contradiction {
			return contract.ID{}, nil, err
		}
	}
	a := g.attempts[latest.PredecessorAttemptID]
	if g.parent != nil && (g.phase == nil || g.parent.OperationID != a.record.OperationID || g.phase.FrontierAttemptID != a.record.AttemptID) ||
		g.parent == nil && duty.Status != contract.GeneratedEffectUnknown {
		return contract.ID{}, nil, nil
	}
	if !requested.IsZero() && requested != a.record.AttemptID {
		return contract.ID{}, nil, nil
	}
	if g.parent != nil {
		if a.record.State != contract.GeneratedEffectTransmitted || a.record.Stage != contract.GeneratedStageRetainedResult || len(a.result) != 0 || len(g.bundles) == 0 || g.bundles[0].Request.OperationKind != contract.OperationRetireGeneratedGeneration {
			return contract.ID{}, nil, nil
		}
		facts, err := r.activeRiskFacts(ctx, g, a)
		if err != nil || len(facts) == 0 {
			return contract.ID{}, nil, err
		}
		return a.record.AttemptID, facts, nil
	}
	facts, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, a.record.Facts)
	if err != nil {
		return contract.ID{}, nil, err
	}
	if len(facts) != 1 {
		return contract.ID{}, nil, nil
	}
	row, err := contract.InspectGeneratorFactsRow(facts[0])
	if err != nil {
		return contract.ID{}, nil, err
	}
	evidence, err := contract.InspectGeneratorSafeFacts(row.Facts)
	if err != nil {
		return contract.ID{}, nil, err
	}
	if evidence.Disposition != contract.GeneratorDispositionUnknown {
		return contract.ID{}, nil, nil
	}
	return a.record.AttemptID, nil, nil
}
