package core

import (
	"context"
	"enkv.sh/core/contract"
)

// generatedMutationTerminalInput is the exact terminal projection assembled by
// the generated final owner. Changed subjects/access are transient canonical
// commitments; the three record slices are already in Product result order.
type generatedMutationTerminalInput struct {
	Parent                                                                 contract.GeneratedParentRecord
	OperationKind                                                          uint16
	OriginalPredecessorRevisionID, RequestedRevisionID, ObservedRevisionID contract.ID
	ChangedSubjects, ChangedAccess                                         contract.GeneratorDescriptor
	Effects, Duties, Hazards                                               []contract.SupportRecord
	EffectClasses                                                          map[contract.ID]int
	CompletionClasses                                                      map[contract.ID]uint8
	RelatedDutyIDs                                                         map[contract.ID]bool
	RelatedHazardIDs                                                       map[contract.ID]bool
	Selected                                                               bool
}

// generatedTerminalMutation constructs the general terminal result and the
// one-receipt append plan. Replacement and cleanup are the two receipt-free
// mutation classes and return retained=false.
func (s *StateSession) generatedTerminalMutation(ctx context.Context, input generatedMutationTerminalInput) (contract.MutationReceiptDeltaPlan, bool, error) {
	var zero contract.MutationReceiptDeltaPlan
	if s == nil || input.Parent.DomainID != s.admission.domain || input.Parent.RequestIdentityDigest.IsZero() ||
		input.Parent.RequestCoreDigest.IsZero() || input.OriginalPredecessorRevisionID.IsZero() || input.RequestedRevisionID.IsZero() ||
		input.ObservedRevisionID.IsZero() {
		return zero, false, contract.ErrRecord
	}
	if _, err := contract.GeneratedParentRecordLength(input.Parent); err != nil {
		return zero, false, err
	}
	if input.OperationKind == contract.OperationReplaceAuthorityKeys || input.OperationKind == contract.OperationCleanOwnedFailureResidue {
		return zero, false, nil
	}
	effects, err := contract.MutationResultRecordDescriptor(contract.MutationResultEffects, input.Parent.DomainID, input.Effects)
	if err != nil {
		return zero, false, err
	}
	duties, err := contract.MutationResultRecordDescriptor(contract.MutationResultDuties, input.Parent.DomainID, input.Duties)
	if err != nil {
		return zero, false, err
	}
	hazards, err := contract.MutationResultRecordDescriptor(contract.MutationResultHazards, input.Parent.DomainID, input.Hazards)
	if err != nil {
		return zero, false, err
	}
	var counts [contract.ReceiptSummaryCount]uint32
	counts[contract.ReceiptEffectCount] = effects.Count
	counts[contract.ReceiptDutyCount] = duties.Count
	counts[contract.ReceiptHazardCount] = hazards.Count
	counts[contract.ReceiptChangedAccessCount] = input.ChangedAccess.Count
	effectsByID := make(map[contract.ID]contract.GeneratedAttemptRecord, len(input.Effects))
	for _, row := range input.Effects {
		attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || attempt.DomainID != input.Parent.DomainID || attempt.OperationID != input.Parent.OperationID || attempt.AttemptID != row.RecordID {
			return zero, false, contract.ErrRecord
		}
		class, ok := input.EffectClasses[row.RecordID]
		if !ok || class < contract.ReceiptSummarySuccessCount || class > contract.ReceiptNoEffectPredecessorCount {
			return zero, false, contract.ErrRecord
		}
		valid := class == contract.ReceiptSummarySuccessCount && attempt.State == contract.GeneratedEffectSucceeded ||
			class == contract.ReceiptSummaryFailureCount && (attempt.State == contract.GeneratedEffectFailedTerminal ||
				attempt.State == contract.GeneratedEffectConfirmedNoEffect || attempt.State == contract.GeneratedEffectClosedWithResidue) ||
			class == contract.ReceiptSummaryUnknownCount && (attempt.State == contract.GeneratedEffectTransmitted ||
				attempt.State == contract.GeneratedEffectUnknown || attempt.State == contract.GeneratedEffectPossibleLive ||
				attempt.State == contract.GeneratedEffectClosedWithResidue) ||
			class == contract.ReceiptPreservedResidueCount && attempt.State == contract.GeneratedEffectClosedWithResidue ||
			class == contract.ReceiptNoEffectPredecessorCount && attempt.State == contract.GeneratedEffectConfirmedNoEffect
		if !valid {
			return zero, false, contract.ErrRecord
		}
		counts[class]++
		effectsByID[row.RecordID] = attempt
	}
	for _, row := range input.Duties {
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || duty.DomainID != input.Parent.DomainID || duty.DutyID != row.RecordID ||
			duty.OriginalOperationID != input.Parent.OperationID && !input.RelatedDutyIDs[row.RecordID] {
			return zero, false, contract.ErrRecord
		}
	}
	for _, row := range input.Hazards {
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil || hazard.DomainID != input.Parent.DomainID ||
			hazard.OriginalOperationID != input.Parent.OperationID && !input.RelatedHazardIDs[row.RecordID] || hazard.HazardID != row.RecordID {
			return zero, false, contract.ErrRecord
		}
	}
	var acknowledged, confirmed uint32
	for attemptID, class := range input.CompletionClasses {
		attempt, ok := effectsByID[attemptID]
		if !ok || attempt.State != contract.GeneratedEffectSucceeded || attempt.CompletionClass != class {
			return zero, false, contract.ErrRecord
		}
		switch class {
		case contract.GeneratedCompletionAcknowledged:
			acknowledged++
		case contract.GeneratedCompletionConfirmed:
			confirmed++
		default:
			return zero, false, contract.ErrRecord
		}
	}
	effectSummary := generatedOperationEffectSummary(input.OperationKind, counts)
	row := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema, OperationKind: input.OperationKind,
		DomainID: input.Parent.DomainID, OperationID: input.Parent.OperationID,
		PredecessorRevisionID: input.OriginalPredecessorRevisionID, RequestedRevisionID: input.RequestedRevisionID, ObservedRevisionID: input.ObservedRevisionID,
		StateResult: contract.ReceiptStateSuccess, EffectSummary: effectSummary, EvidenceCeiling: contract.ReceiptEvidenceProviderFacts,
		CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: input.ChangedSubjects, SummaryCounts: counts,
		AcknowledgedCount: acknowledged, ConfirmedCount: confirmed,
		UnknownCount: counts[contract.ReceiptSummaryUnknownCount] + counts[contract.ReceiptPreservedResidueCount]}
	if effects.Count == 0 {
		row.EvidenceCeiling = contract.ReceiptEvidenceCanonical
	}
	switch {
	case acknowledged != 0 && confirmed != 0:
		row.EvidenceCeiling = contract.ReceiptEvidenceMixedCompletion
	case acknowledged != 0:
		row.EvidenceCeiling = contract.ReceiptEvidenceAcknowledged
	case confirmed != 0:
		row.EvidenceCeiling = contract.ReceiptEvidenceConfirmed
	}
	var effectWarnings uint64
	if acknowledged != 0 {
		effectWarnings |= contract.ReceiptWarningInvalidationNotConfirmed
	}
	if hazards.Count != 0 || counts[contract.ReceiptPreservedResidueCount] != 0 {
		effectWarnings |= contract.ReceiptWarningPossibleLive
	}
	row.WarningBits, err = contract.EncodeReceiptWarningBits(input.OperationKind, s.root.WarningBits, effectWarnings)
	if err != nil {
		return zero, false, err
	}
	if input.Selected {
		switch {
		case input.OperationKind == contract.OperationAcceptGeneratedRetirementResidue && hazards.Count != 0:
			row.StateResult = contract.ReceiptStatePossibleLiveResidueAccepted
		case (input.OperationKind == contract.OperationApplyDeclaration || input.OperationKind == contract.OperationRotateValueEntryValue) && duties.Count != 0:
			row.StateResult = contract.ReceiptStateRetirementPending
		}
	} else {
		row.CanonicalOutcome = contract.ReceiptCanonicalNotSelected
		if counts[contract.ReceiptSummaryUnknownCount] != 0 {
			row.StateResult = contract.ReceiptStateEffectUnknown
		} else {
			row.StateResult = contract.ReceiptStateEffectTerminalFailure
		}
	}
	empty := contract.EmptyMutationResultDescriptors()
	row.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: row,
		RequestCoreDigest: input.Parent.RequestCoreDigest, ChangedAccess: input.ChangedAccess, Effects: effects,
		Outputs: empty[2], Duties: duties, Hazards: hazards})
	if err != nil {
		return zero, false, err
	}
	before, err := s.receiptWindows(ctx)
	if err != nil {
		return zero, false, err
	}
	delta := contract.MutationReceiptDeltaPlan{DomainID: input.Parent.DomainID, OperationKind: input.OperationKind,
		AddedCount: 1, Before: before, NewReceipt: row}
	if _, err := contract.MutationReceiptDeltaPlanDigest(delta); err != nil {
		return zero, false, err
	}
	return delta, true, nil
}

func generatedOperationEffectSummary(kind uint16, counts [contract.ReceiptSummaryCount]uint32) uint16 {
	if kind == contract.OperationAcceptGeneratedRetirementResidue && counts[contract.ReceiptEffectCount] == 0 {
		return contract.ReceiptEffectNotApplicable
	}
	return generatedMutationEffectSummary(counts)
}

func generatedMutationEffectSummary(counts [contract.ReceiptSummaryCount]uint32) uint16 {
	success, failure := counts[contract.ReceiptSummarySuccessCount], counts[contract.ReceiptSummaryFailureCount]
	pending, unknown := counts[contract.ReceiptSummaryPendingCount], counts[contract.ReceiptSummaryUnknownCount]
	switch {
	case unknown != 0:
		return contract.ReceiptEffectUnknown
	case pending != 0 && success == 0 && failure == 0:
		return contract.ReceiptEffectPending
	case pending != 0:
		return contract.ReceiptEffectPartial
	case success != 0 && failure != 0:
		return contract.ReceiptEffectMixedTerminal
	case failure != 0:
		return contract.ReceiptEffectFailed
	case success != 0:
		return contract.ReceiptEffectComplete
	default:
		return contract.ReceiptEffectNoChange
	}
}
