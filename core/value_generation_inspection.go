package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

// This private projection reads live authenticated work, not receipt history.
// It grants no dispatch, reflection, release or cleanup permission.
type generatedInspection struct {
	activeOwner     contract.ID
	effects         []generatedInspectedEffect
	duties          []contract.GeneratedDutyRecord
	dutyProgress    map[contract.ID][][]byte
	hazards         []contract.GeneratedHazardRecord
	releases        []contract.PendingInboxReleaseRecord
	warnings        uint64
	possibleGarbage bool
}

type generatedInspectedEffect struct {
	attempt         contract.GeneratedAttemptRecord
	facts           [][]byte
	progress        [][]byte
	evidenceCeiling uint16
	templateOrder   int
}

func (s *StateSession) inspectGeneratedWork(ctx context.Context) (generatedInspection, error) {
	var out generatedInspection
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return out, err
	}
	out.activeOwner = s.root.Generated.ActiveOwner
	out.dutyProgress = make(map[contract.ID][][]byte)
	order := make(map[contract.ID]int, len(g.attempts))
	for _, bundle := range g.bundles {
		for i, lineage := range bundle.Lineages {
			for j, template := range lineage.Templates[:lineage.TemplateCount] {
				order[template.AttemptID] = i*5 + j
			}
		}
	}
	copyBodies := func(rows [][]byte) [][]byte {
		out := make([][]byte, len(rows))
		for i := range rows {
			out[i] = bytes.Clone(rows[i])
		}
		return out
	}
	for _, a := range g.attempts {
		facts, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorFacts, a.record.Facts)
		if err != nil {
			return generatedInspection{}, err
		}
		progress, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorProgress, a.record.Progress)
		if err != nil {
			return generatedInspection{}, err
		}
		ceiling := contract.ReceiptEvidenceProviderFacts
		if a.expected.Template.Action == contract.GeneratorActionDelete && len(a.result) != 0 {
			r, err := contract.InspectGeneratedResultRecord(a.result)
			if err != nil {
				return generatedInspection{}, err
			}
			if r.SafeFacts.Disposition == contract.GeneratorDispositionRetirementAcknowledged {
				ceiling = contract.ReceiptEvidenceAcknowledged
				out.warnings |= contract.ReceiptWarningInvalidationNotConfirmed
			}
			if r.SafeFacts.Disposition == contract.GeneratorDispositionScopedUnusability {
				ceiling = contract.ReceiptEvidenceConfirmed
			}
		}
		position, ok := order[a.record.AttemptID]
		if !ok {
			return generatedInspection{}, contract.ErrRecord
		}
		progress = copyBodies(progress)
		if a.record.CompletionClass == contract.GeneratedCompletionConfirmed {
			generatedInspectionOrderProgress(progress)
		}
		out.effects = append(out.effects, generatedInspectedEffect{attempt: a.record, facts: copyBodies(facts), progress: progress, evidenceCeiling: ceiling, templateOrder: position})
	}
	for _, released := range g.releases {
		if released.template.Action != contract.GeneratorActionDelete {
			continue
		}
		position, ok := order[released.attempt.AttemptID]
		if !ok {
			return generatedInspection{}, contract.ErrRecord
		}
		ceiling := contract.ReceiptEvidenceAcknowledged
		var facts [][]byte
		var progress [][]byte
		if released.attempt.CompletionClass == contract.GeneratedCompletionConfirmed && released.release.State != contract.GeneratedReleaseUnobserved {
			progress, err = g.controlledReleasedProgress(released)
			if err != nil {
				return generatedInspection{}, err
			}
			facts, err = g.vectors.resolve(contract.GeneratedAttemptSupportKind, released.attempt.AttemptID, contract.GeneratorVectorFacts, released.attempt.Facts)
			if err != nil || len(facts) != 1 {
				return generatedInspection{}, contract.ErrRecord
			}
			row, err := contract.InspectGeneratorFactsRow(facts[0])
			if err != nil {
				return generatedInspection{}, err
			}
			f, err := contract.InspectGeneratorSafeFacts(row.Facts)
			if err != nil {
				return generatedInspection{}, err
			}
			if f.Disposition == contract.GeneratorDispositionScopedUnusability {
				ceiling = contract.ReceiptEvidenceConfirmed
			}
		}
		if released.release.State == contract.GeneratedReleaseUnobserved {
			ceiling = contract.ReceiptEvidenceProviderFacts
			facts, err = g.vectors.resolve(contract.GeneratedAttemptSupportKind, released.attempt.AttemptID, contract.GeneratorVectorFacts, released.attempt.Facts)
			if err != nil {
				return generatedInspection{}, err
			}
		} else if ceiling == contract.ReceiptEvidenceAcknowledged {
			out.warnings |= contract.ReceiptWarningInvalidationNotConfirmed
		}
		for i := range facts {
			facts[i] = bytes.Clone(facts[i])
		}
		if len(progress) != 0 {
			progress = copyBodies(progress)
		}
		if released.attempt.CompletionClass == contract.GeneratedCompletionConfirmed {
			generatedInspectionOrderProgress(progress)
		}
		out.effects = append(out.effects, generatedInspectedEffect{attempt: released.attempt,
			facts: facts, progress: progress, evidenceCeiling: ceiling, templateOrder: position})
	}
	slices.SortFunc(out.effects, func(a, b generatedInspectedEffect) int {
		if n := bytes.Compare(a.attempt.OperationID[:], b.attempt.OperationID[:]); n != 0 {
			return n
		}
		return a.templateOrder - b.templateOrder
	})
	for key, row := range g.records {
		switch key.kind {
		case contract.GeneratedDutySupportKind:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return generatedInspection{}, err
			}
			out.duties = append(out.duties, duty)
			progress, err := g.vectors.resolve(contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorProgress, duty.Progress)
			if err != nil {
				return generatedInspection{}, err
			}
			for _, row := range progress {
				out.dutyProgress[duty.DutyID] = append(out.dutyProgress[duty.DutyID], bytes.Clone(row))
			}
			if duty.CompletionClass == contract.GeneratedCompletionConfirmed {
				generatedInspectionOrderProgress(out.dutyProgress[duty.DutyID])
			}
		case contract.GeneratedHazardSupportKind:
			hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return generatedInspection{}, err
			}
			out.hazards = append(out.hazards, hazard)
			if hazard.Exposure == contract.GeneratedExposurePossibleLive {
				out.warnings |= contract.ReceiptWarningPossibleLive
			}
		case contract.PendingInboxReleaseSupportKind:
			release, err := contract.InspectPendingInboxReleaseRecord(row.Body)
			if err != nil {
				return generatedInspection{}, err
			}
			out.releases = append(out.releases, release)
			out.possibleGarbage = out.possibleGarbage || release.State == contract.GeneratedReleaseUnknown || release.State == contract.GeneratedReleaseUnobserved
		}
	}
	slices.SortFunc(out.duties, func(a, b contract.GeneratedDutyRecord) int {
		return compareGeneratedOwnerOrder(a.OriginalOperationID, a.OriginalAttemptID, a.DutyID, b.OriginalOperationID, b.OriginalAttemptID, b.DutyID)
	})
	slices.SortFunc(out.hazards, func(a, b contract.GeneratedHazardRecord) int {
		return compareGeneratedOwnerOrder(a.OriginalOperationID, a.OriginalAttemptID, a.HazardID, b.OriginalOperationID, b.OriginalAttemptID, b.HazardID)
	})
	slices.SortFunc(out.releases, func(a, b contract.PendingInboxReleaseRecord) int { return bytes.Compare(a.InboxID[:], b.InboxID[:]) })
	return out, nil
}

// All inputs are qualified 113-byte progress rows. Wire vectors keep their
// ID order; inspection displays the immutable ordered step mask instead.
func generatedInspectionOrderProgress(rows [][]byte) {
	slices.SortFunc(rows, func(a, b []byte) int { return int(a[111]) - int(b[111]) })
}
