package core

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unsafe"

	"enkv.sh/core/contract"
)

// The terminal owner supplies record order and frontier classes while its
// operational support is still present. This input does not escape capture.
type generatedInvocationResultScope struct {
	OperationKind                                               uint16
	OperationID, RequestIdentity, OriginalPredecessorRevisionID contract.ID
	Effects, Duties, Hazards                                    []contract.SupportRecord
	EffectClasses                                               map[contract.ID]int
	CompletionClasses                                           map[contract.ID]uint8
	RelatedDutyIDs, RelatedHazardIDs                            []contract.ID
	ChangedSubjects, ChangedAccess                              contract.GeneratorDescriptor
	CanonicalSuccessor                                          bool
	observedEffects                                             []contract.SupportRecord
	observedEffectClasses                                       map[contract.ID]int
	requestCoreDigest                                           contract.ID
	receiptOptional                                             bool
	effectOperationID                                           contract.ID
	receiptFree                                                 bool
	receiptFreeState                                            string
	borrowedObserved                                            *GeneratedInvocationResult
}

type generatedInvocationResultCapture struct {
	observed, selected GeneratedInvocationResult
	candidate          Candidate
	hasCandidate, used bool
	backingBytes       uint64
}

// Complete-result hashing excludes the final request identity and its own
// descriptor. The authenticated receipt remains unchanged for exact comparison.
func generatedReceiptDescriptorPlan(row contract.CompactMutationReceipt) contract.CompactMutationReceiptPlan {
	row.RequestIdentityDigest = contract.ID{}
	row.CompleteResult = contract.GeneratorDescriptor{}
	return contract.CompactMutationReceiptPlan(row)
}

func generatedReceiptObservationResult(row contract.CompactMutationReceipt) (*GeneratedInvocationResult, error) {
	if !contract.CompactMutationReceiptValid(row) {
		return nil, contract.ErrRecord
	}
	_, warnings, err := contract.DecodeReceiptWarningBits(row.OperationKind, row.WarningBits)
	if err != nil {
		return nil, err
	}
	state := installedGeneratedReceiptState(row.StateResult)
	if state == "" {
		return nil, contract.ErrRecord
	}
	return &GeneratedInvocationResult{OperationKind: row.OperationKind, StateResult: state, CanonicalOutcome: row.CanonicalOutcome,
		EffectSummary: row.EffectSummary, EvidenceCeiling: row.EvidenceCeiling, SummaryCountsAvailable: true, SummaryCounts: row.SummaryCounts,
		AcknowledgedCount: row.AcknowledgedCount, ConfirmedCount: row.ConfirmedCount, UnknownCount: row.UnknownCount,
		Warnings: GeneratedResultWarnings{PossibleLiveResidue: warnings&contract.ReceiptWarningPossibleLive != 0, InvalidationNotConfirmed: warnings&contract.ReceiptWarningInvalidationNotConfirmed != 0}, ReceiptObservation: true}, nil
}

func captureGeneratedLifecycleInvocationResult(ctx context.Context, before *StateSession, work *generatedSelection, plan *generatedLifecyclePlan, proposal *generatedReservation, checkpoint *generatedSelectionCheckpoint) (*generatedInvocationResultCapture, error) {
	if before == nil || work == nil || plan == nil || proposal == nil || proposal.state == nil {
		return nil, contract.ErrRecord
	}
	attempt, present := work.attempts[plan.source.AttemptID]
	if !present || attempt.record.OwnerID != plan.owner {
		return nil, contract.ErrRecord
	}
	selected, err := proposal.state.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	access, err := contract.AccessChangeDescriptor(before.root.Domain, nil)
	if err != nil {
		return nil, err
	}
	scope := generatedInvocationResultScope{ChangedAccess: access, RelatedDutyIDs: []contract.ID{plan.owner}, EffectClasses: map[contract.ID]int{}}
	switch plan.kind {
	case generatedLifecycleRetirementClose, generatedLifecycleRetirementUnknown:
		if work.parent == nil || len(work.bundles) == 0 {
			return nil, contract.ErrRecord
		}
		scope.OperationKind, scope.OperationID, scope.RequestIdentity = contract.OperationRetireGeneratedGeneration, work.parent.OperationID, work.parent.RequestIdentityDigest
		scope.OriginalPredecessorRevisionID = work.bundles[0].Request.PredecessorRevisionID
		row, present := work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, attempt.record.AttemptID}]
		if !present {
			return nil, contract.ErrRecord
		}
		scope.Effects = []contract.SupportRecord{row}
		if plan.kind == generatedLifecycleRetirementClose {
			scope.CanonicalSuccessor = true
			scope.EffectClasses[row.RecordID] = contract.ReceiptSummarySuccessCount
			scope.CompletionClasses = map[contract.ID]uint8{row.RecordID: attempt.record.CompletionClass}
			scope.ChangedSubjects, err = before.generatedRetiringChangedSubjects(ctx, plan.owner)
			if attempt.record.CompletionClass == contract.GeneratedCompletionConfirmed {
				dutyRow, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, plan.owner}]
				if !present {
					return nil, contract.ErrRecord
				}
				duty, inspectErr := contract.InspectGeneratedDutyRecord(dutyRow.Body)
				if inspectErr != nil {
					return nil, inspectErr
				}
				progress, readErr := work.controlledRetirementProgress(duty, nil, true)
				if readErr != nil {
					return nil, readErr
				}
				if len(progress.rows) != 2 || progress.contradiction {
					pending, present := selected.records[generatedRecordKey{contract.GeneratedDutySupportKind, plan.owner}]
					if !present {
						return nil, contract.ErrRecord
					}
					scope.CanonicalSuccessor, scope.receiptOptional = false, true
					scope.CompletionClasses = nil
					scope.EffectClasses[row.RecordID] = contract.ReceiptSummaryPendingCount
					scope.Duties = []contract.SupportRecord{pending}
				}
			}
		} else {
			scope.observedEffects = scope.Effects
			scope.observedEffectClasses = map[contract.ID]int{row.RecordID: contract.ReceiptSummaryPendingCount}
			changed, present := selected.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, attempt.record.AttemptID}]
			if !present {
				return nil, contract.ErrRecord
			}
			scope.Effects = []contract.SupportRecord{changed}
			scope.EffectClasses[row.RecordID] = contract.ReceiptSummaryUnknownCount
			duty, present := selected.records[generatedRecordKey{contract.GeneratedDutySupportKind, plan.owner}]
			if !present {
				return nil, contract.ErrRecord
			}
			scope.Duties = []contract.SupportRecord{duty}
			scope.ChangedSubjects, err = generatedFinalChangedSubjects(ctx, before, before)
		}
	case generatedLifecycleRetirementResidue:
		bundle, readErr := work.retainedGraph(attempt.record.OperationID)
		if readErr != nil {
			return nil, readErr
		}
		request := generatedRetirementResidueRequest(before, bundle.Request, plan)
		scope.requestCoreDigest, err = contract.GeneratorRequestCoreDigest(request)
		if err != nil {
			return nil, err
		}
		scope.OperationKind, scope.OperationID, scope.RequestIdentity = request.OperationKind, request.OperationID, plan.requestIdentity
		scope.OriginalPredecessorRevisionID = before.head.Core.Revision
		scope.CanonicalSuccessor = true
		hazard, present := selected.records[generatedRecordKey{contract.GeneratedHazardSupportKind, attempt.expected.Template.HazardID}]
		if !present {
			return nil, contract.ErrRecord
		}
		scope.Hazards = []contract.SupportRecord{hazard}
		scope.RelatedHazardIDs = []contract.ID{hazard.RecordID}
		scope.ChangedSubjects, err = before.generatedRetiringChangedSubjects(ctx, plan.owner)
	default:
		return nil, contract.ErrRecord
	}
	if err != nil {
		return nil, err
	}
	scope.borrowedObserved = checkpoint.ownedBefore(before, scope.OperationKind, scope.OperationID)
	if scope.borrowedObserved != nil && scope.OperationKind == contract.OperationRetireGeneratedGeneration {
		observed, readErr := generatedActiveResultScope(work)
		if readErr != nil {
			return nil, readErr
		}
		scope.observedEffects, scope.observedEffectClasses = observed.Effects, observed.EffectClasses
	}
	return captureGeneratedInvocationResult(ctx, before, work, scope, proposal)
}

// Normal Apply commits the complete domain work in its receipt. Only accepted
// new handoffs belong to this invocation's generated result.
func captureNormalGeneratedHandoffResult(ctx context.Context, before *StateSession, comparison *Comparison, plan transitionPlan, proposed *StateSession, candidate *Candidate, work installedApplyRetainedWork) (*generatedInvocationResultCapture, error) {
	if len(work.relatedDutyRows) == 0 {
		return nil, nil
	}
	if comparison == nil || comparison.applyReceipt == nil || proposed == nil || candidate == nil || !candidateMatches(proposed, candidate) || comparison.lifecycleOperationKind() != contract.OperationApplyDeclaration {
		return nil, contract.ErrRecord
	}
	selected, err := proposed.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	prior, err := before.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	scope := generatedInvocationResultScope{OperationKind: contract.OperationApplyDeclaration, OperationID: plan.operation,
		RequestIdentity: comparison.applyReceipt.identity, OriginalPredecessorRevisionID: before.head.Core.Revision, Duties: work.relatedDutyRows}
	for _, row := range work.relatedDutyRows {
		scope.RelatedDutyIDs = append(scope.RelatedDutyIDs, row.RecordID)
	}
	result := &generatedInvocationResultCapture{}
	result.observed, err = generatedInvocationFacts(ctx, prior, scope, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	result.selected, err = generatedInvocationFacts(ctx, selected, scope, nil, work.relatedDutyRows, nil)
	if err != nil {
		return nil, err
	}
	row, raw, found, err := proposed.retainedMutationReceipt(plan.operation)
	if err != nil {
		return nil, err
	}
	if !found || !slices.Equal(raw, comparison.applyReceipt.receipt) || row.OperationKind != scope.OperationKind || row.OperationID != plan.operation || row.RequestIdentityDigest != scope.RequestIdentity ||
		row.PredecessorRevisionID != scope.OriginalPredecessorRevisionID || row.RequestedRevisionID != plan.revision || row.ObservedRevisionID != plan.revision || row.CanonicalOutcome != contract.ReceiptCanonicalSelected ||
		row.StateResult != contract.ReceiptStateRetirementPending || row.EffectSummary != contract.ReceiptEffectNoChange || row.EvidenceCeiling != contract.ReceiptEvidenceCanonical ||
		row.ChangedSubjects != comparison.applyReceipt.subjects || row.SummaryCounts[contract.ReceiptEffectCount] != 0 || row.SummaryCounts[contract.ReceiptDutyCount] != work.duties.Count || row.SummaryCounts[contract.ReceiptHazardCount] != work.hazards.Count {
		return nil, contract.ErrRecord
	}
	access, err := installedApplyAccessChanges(before.accessRecords(), proposed.accessRecords(), before.root.Domain)
	if err != nil {
		return nil, err
	}
	request := requestCommitment(before.successorCore(plan), contract.LifecycleSubject{IdentityPlan: identityCommitment(comparison, plan), Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: comparison.desired, Length: comparison.desiredLength}}})
	complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: generatedReceiptDescriptorPlan(row), RequestCoreDigest: request, ChangedAccess: access,
		Effects: contract.EmptyMutationResultDescriptors()[1], Outputs: contract.EmptyMutationResultDescriptors()[2], Duties: work.duties, Hazards: work.hazards})
	if err != nil || complete != row.CompleteResult {
		return nil, contract.ErrRecord
	}
	result.selected.StateResult, result.selected.CanonicalOutcome, result.selected.EffectSummary, result.selected.EvidenceCeiling = installedGeneratedReceiptState(row.StateResult), row.CanonicalOutcome, row.EffectSummary, row.EvidenceCeiling
	result.selected.SummaryCounts, result.selected.AcknowledgedCount, result.selected.ConfirmedCount, result.selected.UnknownCount = row.SummaryCounts, row.AcknowledgedCount, row.ConfirmedCount, row.UnknownCount
	result.candidate.head.Core, result.candidate.head.AuthKind, result.candidate.head.Subject = candidate.head.Core, candidate.head.AuthKind, candidate.head.Subject
	result.candidate.head.Core.PreviousToken.Value = strings.Clone(candidate.head.Core.PreviousToken.Value)
	result.hasCandidate = true
	result.backingBytes, err = generatedInvocationCaptureBackingBytes(result)
	return result, err
}

func captureGeneratedFinalInvocationResult(ctx context.Context, before *StateSession, work *generatedSelection, plan *generatedFinalPlan, proposal *generatedReservation, checkpoint *generatedSelectionCheckpoint) (*generatedInvocationResultCapture, error) {
	if work == nil || work.parent == nil || len(work.bundles) == 0 || plan == nil || proposal == nil || proposal.state == nil {
		return nil, contract.ErrRecord
	}
	if generatedSelectionAnchored(work) {
		scope, err := generatedAutomaticInvocationScope(ctx, before, work)
		if err != nil {
			return nil, err
		}
		selected, err := proposal.state.selectedGeneratedWork(ctx)
		if err != nil {
			return nil, err
		}
		// Terminal Park commits its changed live Attempt. ACK closure receipts
		// retain the original before row when the Attempt becomes a release.
		for index, row := range scope.Effects {
			live, present := selected.attempts[row.RecordID]
			if !present {
				continue
			}
			candidateRow, present := selected.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, row.RecordID}]
			if !present {
				return nil, contract.ErrRecord
			}
			if slices.Equal(candidateRow.Body, row.Body) {
				continue
			}
			if live.record.State != contract.GeneratedEffectUnknown || live.record.Stage != contract.GeneratedStageTerminal {
				return nil, contract.ErrRecord
			}
			if scope.observedEffects == nil {
				scope.observedEffects, scope.observedEffectClasses = scope.Effects, scope.EffectClasses
				scope.Effects = slices.Clone(scope.Effects)
				scope.EffectClasses = maps.Clone(scope.EffectClasses)
				scope.CompletionClasses = maps.Clone(scope.CompletionClasses)
			}
			scope.Effects[index] = candidateRow
			scope.EffectClasses[row.RecordID] = contract.ReceiptSummaryUnknownCount
			delete(scope.CompletionClasses, row.RecordID)
		}

		scope.Duties, scope.Hazards = nil, nil
		for _, id := range scope.RelatedDutyIDs {
			if row, present := selected.records[generatedRecordKey{contract.GeneratedDutySupportKind, id}]; present {
				scope.Duties = append(scope.Duties, row)
			}
		}
		for _, id := range scope.RelatedHazardIDs {
			if row, present := selected.records[generatedRecordKey{contract.GeneratedHazardSupportKind, id}]; present {
				scope.Hazards = append(scope.Hazards, row)
			}
		}
		scope.receiptOptional = false
		scope.borrowedObserved = checkpoint.ownedBefore(before, scope.OperationKind, scope.OperationID)
		return captureGeneratedInvocationResult(ctx, before, work, scope, proposal)
	}

	operational, err := generatedFinalOperationalRows(work, plan, proposal.state.supportRecords())
	if err != nil {
		return nil, err
	}
	subjects, err := generatedFinalChangedSubjects(ctx, before, proposal.state)
	if err != nil {
		return nil, err
	}
	access, err := generatedFinalChangedAccess(before, proposal.state)
	if err != nil {
		return nil, err
	}
	scope := generatedInvocationResultScope{OperationKind: work.bundles[0].Request.OperationKind,
		OperationID: work.parent.OperationID, RequestIdentity: work.parent.RequestIdentityDigest,
		OriginalPredecessorRevisionID: work.bundles[0].Request.PredecessorRevisionID,
		Effects:                       operational.effects, Duties: operational.duties, Hazards: operational.hazards,
		EffectClasses: operational.classes, ChangedSubjects: subjects, ChangedAccess: access,
		CanonicalSuccessor: plan.selecting}
	for id := range operational.relatedDuties {
		scope.RelatedDutyIDs = append(scope.RelatedDutyIDs, id)
	}
	scope.borrowedObserved = checkpoint.ownedBefore(before, scope.OperationKind, scope.OperationID)
	return captureGeneratedInvocationResult(ctx, before, work, scope, proposal)
}

func captureGeneratedInvocationResult(ctx context.Context, before *StateSession, work *generatedSelection, scope generatedInvocationResultScope, proposal *generatedReservation) (*generatedInvocationResultCapture, error) {
	if ctx == nil || ctx.Err() != nil || before == nil || work == nil || work.image == nil ||
		scope.OperationID.IsZero() || scope.RequestIdentity.IsZero() || scope.OriginalPredecessorRevisionID.IsZero() ||
		before.root.Domain != work.image.root.Domain || before.root.Snapshot != work.image.root.Snapshot || before.root.Transition != work.image.root.Transition || uint64(len(scope.Effects)) > GeneratedResultEffectLimit ||
		uint64(len(scope.Duties))+uint64(len(scope.Hazards)) > GeneratedResultWorkLimit {
		return nil, contract.ErrRecord
	}
	result := &generatedInvocationResultCapture{}
	var baseDuties, baseHazards []contract.SupportRecord
	var err error
	if generatedSelectionAnchored(work) && scope.OperationID == work.parent.OperationID &&
		(scope.OperationKind == contract.OperationApplyDeclaration || scope.OperationKind == contract.OperationRotateValueEntryValue) {
		// The original apply still owns CREATE support after selection. Its
		// automatic owner includes only the invocation's remaining work.
		observed, scopeErr := generatedAutomaticInvocationScope(ctx, before, work)
		if scopeErr != nil {
			return nil, scopeErr
		}
		baseDuties, baseHazards = observed.Duties, observed.Hazards
	} else {
		baseDuties, baseHazards, err = generatedObservedInvocationWork(work, scope)
		if err != nil {
			return nil, err
		}
	}
	observedEffects := scope.Effects
	observedScope := scope
	if scope.observedEffects != nil {
		observedEffects = scope.observedEffects
		observedScope.CompletionClasses = nil
	}
	if scope.observedEffectClasses != nil {
		observedScope.EffectClasses = scope.observedEffectClasses
	}
	if scope.borrowedObserved != nil {
		if !generatedBorrowedScopeMatches(scope.borrowedObserved, observedScope, observedEffects, baseDuties, baseHazards) {
			return nil, contract.ErrRecord
		}
		result.observed = *scope.borrowedObserved
	} else {
		result.observed, err = generatedInvocationFacts(ctx, work, observedScope, observedEffects, baseDuties, baseHazards)
		if err != nil {
			return nil, fmt.Errorf("capture observed generated facts: %w", err)
		}
	}
	if proposal != nil {
		if proposal.state == nil || proposal.candidate == nil || !candidateMatches(proposal.state, proposal.candidate) || proposal.state.root.Domain != before.root.Domain {
			return nil, contract.ErrRecord
		}
		selected, err := proposal.state.selectedGeneratedWork(ctx)
		if err != nil {
			return nil, err
		}
		result.selected, err = generatedInvocationFacts(ctx, selected, scope, nil, scope.Duties, scope.Hazards)
		if err != nil {
			return nil, fmt.Errorf("capture selected generated work: %w", err)
		}
		// Final can remove its operational graph. Retain the exact safe effect
		// facts captured above, and change only relations proved by the candidate.
		if result.observed.HasObservedCanonicalSelection(before.root.Domain, scope.OperationID, scope.RequestIdentity) {
			result.selected.canonicalSelection = result.observed.canonicalSelection
			result.selected.CanonicalOutcome = contract.ReceiptCanonicalSelected
		}
		result.selected.Effects = result.observed.Effects
		if len(result.observed.Effects) != len(scope.Effects) {
			return nil, contract.ErrRecord
		}
		for i, original := range result.observed.Effects {
			effect := original
			record, err := contract.InspectGeneratedAttemptRecord(scope.Effects[i].Body)
			if err != nil {
				return nil, err
			}
			changed := record != effect.Record
			if changed {
				effect, err = generatedEffectFact(ctx, selected, record.AttemptID)
				if err != nil {
					return nil, fmt.Errorf("capture selected generated effect: %w", err)
				}
				if effect.Record != record {
					return nil, fmt.Errorf("capture selected effect record mismatch: %w", contract.ErrRecord)
				}
				if original.Action == contract.GeneratorActionDelete && original.Target != nil && effect.Target == nil {
					if _, released := selected.releases[record.AttemptID]; released {
						effect.Target, err = generatedReleasedDeleteTarget(work, selected, original, effect)
						if err != nil {
							return nil, fmt.Errorf("capture released Delete target: %w", err)
						}
					}
				}
			}
			class, known := scope.EffectClasses[record.AttemptID]
			if !known || class < contract.ReceiptSummarySuccessCount || class > contract.ReceiptNoEffectPredecessorCount {
				return nil, contract.ErrRecord
			}
			changed = changed || effect.SummaryClass != class
			effect.SummaryClass = class
			generation := generatedPublicEffectGeneration(selected, effect)
			duty, hazard := effect.DutyID, effect.HazardID
			if !selected.hasRecord(generatedRecordKey{contract.GeneratedDutySupportKind, duty}) {
				duty = contract.ID{}
			}
			if !selected.hasRecord(generatedRecordKey{contract.GeneratedHazardSupportKind, hazard}) {
				hazard = contract.ID{}
			}
			if !changed && generation == effect.GenerationID && duty == effect.DutyID && hazard == effect.HazardID {
				continue
			}
			if len(result.selected.Effects) != 0 && &result.selected.Effects[0] == &result.observed.Effects[0] {
				result.selected.Effects = make([]GeneratedEffectFact, len(result.observed.Effects))
				copy(result.selected.Effects, result.observed.Effects)
			}
			effect.GenerationID, effect.DutyID, effect.HazardID = generation, duty, hazard
			result.selected.Effects[i] = effect
		}
		effectsCommitment, err := contract.MutationResultRecordDescriptor(contract.MutationResultEffects, before.root.Domain, scope.Effects)
		if err != nil {
			return nil, err
		}
		result.selected.EffectsCommitment = &effectsCommitment
		result.selected.SummaryCounts[contract.ReceiptEffectCount] = uint32(len(result.selected.Effects))
		result.selected.SummaryCounts[contract.ReceiptDutyCount] = uint32(len(result.selected.Duties))
		result.selected.SummaryCounts[contract.ReceiptHazardCount] = uint32(len(result.selected.Hazards))
		for _, effect := range result.selected.Effects {
			result.selected.SummaryCounts[effect.SummaryClass]++
			if completion, present := scope.CompletionClasses[effect.Record.AttemptID]; present {
				if !generatedInvocationCompletionValid(effect, completion) {
					return nil, fmt.Errorf("capture selected completion: %w", contract.ErrRecord)
				}
				switch completion {
				case contract.GeneratedCompletionAcknowledged:
					result.selected.AcknowledgedCount++
				case contract.GeneratedCompletionConfirmed:
					result.selected.ConfirmedCount++
				default:
					return nil, contract.ErrRecord
				}
			}
		}
		result.selected.UnknownCount = result.selected.SummaryCounts[contract.ReceiptSummaryUnknownCount] + result.selected.SummaryCounts[contract.ReceiptPreservedResidueCount]
		result.selected.EffectSummary = generatedOperationEffectSummary(scope.OperationKind, result.selected.SummaryCounts)
		result.selected.Warnings = generatedInvocationWarnings(result.selected)
		if err := generatedInvocationReceipt(ctx, proposal.state, work, scope, &result.selected); err != nil {
			return nil, fmt.Errorf("capture generated receipt agreement: %w", err)
		}
		result.candidate.head.Core = proposal.candidate.head.Core
		result.candidate.head.Core.PreviousToken.Value = strings.Clone(proposal.candidate.head.Core.PreviousToken.Value)
		result.candidate.head.AuthKind, result.candidate.head.Subject = proposal.candidate.head.AuthKind, proposal.candidate.head.Subject
		if proposal.candidate.head.Generator != nil {
			subject := *proposal.candidate.head.Generator
			result.candidate.head.Generator = &subject
		}
		result.hasCandidate = true
	}
	result.backingBytes, err = generatedInvocationCaptureBackingBytes(result)
	if err != nil {
		return nil, err
	}
	return result, ctx.Err()
}

// Closing an owner can remove its Target vector while retaining the exact
// original Delete mapping. Transfer only that already-owned request-bound
// Target; selected work identities and evidence are still collected anew.
func generatedReleasedDeleteTarget(before, selected *generatedSelection, original, effect GeneratedEffectFact) (*contract.GeneratorTarget, error) {
	if before == nil || selected == nil || before.image == nil || selected.image == nil || original.Target == nil || original.Action != contract.GeneratorActionDelete || effect.Action != original.Action {
		return nil, contract.ErrRecord
	}
	prior, present := before.attempts[original.Record.AttemptID]
	released, ended := selected.releases[effect.Record.AttemptID]
	if !present || !ended || prior.record != original.Record || released.attempt != effect.Record || prior.expected.Template != released.template ||
		released.release.State == contract.GeneratedReleaseUnobserved || released.release.DomainID != effect.Record.DomainID || released.release.OriginalResultID != effect.Record.ResultID || released.release.InboxID != effect.Record.InboxID ||
		before.image.root.Domain != selected.image.root.Domain || effect.Record.DomainID != selected.image.root.Domain || !generatedAttemptMatches(effect.Record, released.template) {
		return nil, contract.ErrRecord
	}
	stable := effect.Record
	stable.State, stable.Facts, stable.Progress, stable.History = original.Record.State, original.Record.Facts, original.Record.Progress, original.Record.History
	if stable != original.Record || original.Name != effect.Name || original.EntryIncarnationID != effect.EntryIncarnationID || original.Epoch != effect.Epoch || original.PlannedValueSlotID != effect.PlannedValueSlotID || original.ResourceDigest != effect.ResourceDigest {
		return nil, contract.ErrRecord
	}
	target, x := original.Target, released.template
	if target.Name != effect.Name || target.IncarnationID != effect.EntryIncarnationID || target.Epoch != effect.Epoch || target.ResourceID != effect.Record.ResourceID ||
		!x.ResourceDigest.IsZero() && target.ResourceDigest != x.ResourceDigest || target.ConfigContractID != x.ConfigContractID || target.ResourceContractID != x.ResourceContractID || target.CompletionClass != x.CompletionClass ||
		target.ResourceDigest.IsZero() || target.ResourceDigest != prior.expected.TargetResourceDigest {
		return nil, contract.ErrRecord
	}
	return target, nil
}

func generatedBorrowedScopeMatches(owned *GeneratedInvocationResult, scope generatedInvocationResultScope, effects, duties, hazards []contract.SupportRecord) bool {
	if owned == nil || owned.OperationKind != scope.OperationKind || !owned.EffectsAvailable || !owned.RelatedWorkAvailable || !owned.SummaryCountsAvailable || len(owned.Effects) != len(effects) || len(owned.Duties) != len(duties) || len(owned.Hazards) != len(hazards) {
		return false
	}
	var counts [contract.ReceiptSummaryCount]uint32
	counts[contract.ReceiptEffectCount], counts[contract.ReceiptDutyCount], counts[contract.ReceiptHazardCount] = uint32(len(effects)), uint32(len(duties)), uint32(len(hazards))
	var acknowledged, confirmed uint32
	for i, row := range effects {
		record, err := contract.InspectGeneratedAttemptRecord(row.Body)
		class, known := scope.EffectClasses[row.RecordID]
		if err != nil || owned.Effects[i].Record != record || !known || class != owned.Effects[i].SummaryClass || class < contract.ReceiptSummarySuccessCount || class > contract.ReceiptNoEffectPredecessorCount {
			return false
		}
		counts[class]++
		if completion, present := scope.CompletionClasses[row.RecordID]; present {
			if !generatedInvocationCompletionValid(owned.Effects[i], completion) {
				return false
			}
			switch completion {
			case contract.GeneratedCompletionAcknowledged:
				acknowledged++
			case contract.GeneratedCompletionConfirmed:
				confirmed++
			default:
				return false
			}
		}
	}
	if counts != owned.SummaryCounts || scope.CompletionClasses != nil && (acknowledged != owned.AcknowledgedCount || confirmed != owned.ConfirmedCount) {
		return false
	}
	for _, row := range duties {
		record, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			return false
		}
		n, found := slices.BinarySearchFunc(owned.Duties, record.DutyID, func(f GeneratedDutyFact, id contract.ID) int { return compareGeneratedIDs(f.Record.DutyID, id) })
		if !found || owned.Duties[n].Record != record {
			return false
		}
	}
	for _, row := range hazards {
		record, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			return false
		}
		n, found := slices.BinarySearchFunc(owned.Hazards, record.HazardID, func(f GeneratedHazardFact, id contract.ID) int { return compareGeneratedIDs(f.Record.HazardID, id) })
		if !found || owned.Hazards[n].Record != record {
			return false
		}
	}
	return true
}

func generatedObservedInvocationWork(work *generatedSelection, scope generatedInvocationResultScope) ([]contract.SupportRecord, []contract.SupportRecord, error) {
	var duties, hazards []contract.SupportRecord
	seen := make(map[generatedRecordKey]bool)
	appendRow := func(kind uint8, id contract.ID) {
		key := generatedRecordKey{kind, id}
		if row, present := work.records[key]; present && !seen[key] {
			seen[key] = true
			if kind == contract.GeneratedDutySupportKind {
				duties = append(duties, row)
			} else {
				hazards = append(hazards, row)
			}
		}
	}
	for _, row := range scope.Effects {
		a, present := work.attempts[row.RecordID]
		if present {
			appendRow(contract.GeneratedDutySupportKind, a.expected.Template.DutyID)
			hazard := a.expected.Template.HazardID
			if actual := work.deleteHazards[row.RecordID]; !actual.IsZero() {
				hazard = actual
			}
			appendRow(contract.GeneratedHazardSupportKind, hazard)
		}
	}
	for _, id := range scope.RelatedDutyIDs {
		appendRow(contract.GeneratedDutySupportKind, id)
	}
	for _, id := range scope.RelatedHazardIDs {
		appendRow(contract.GeneratedHazardSupportKind, id)
	}
	if uint64(len(duties))+uint64(len(hazards)) > GeneratedResultWorkLimit {
		return nil, nil, contract.ErrRecordCapacity
	}
	return duties, hazards, nil
}

func generatedInvocationFacts(ctx context.Context, work *generatedSelection, scope generatedInvocationResultScope, effects, duties, hazards []contract.SupportRecord) (GeneratedInvocationResult, error) {
	duties, hazards = slices.Clone(duties), slices.Clone(hazards)
	slices.SortFunc(duties, func(a, b contract.SupportRecord) int { return compareGeneratedIDs(a.RecordID, b.RecordID) })
	slices.SortFunc(hazards, func(a, b contract.SupportRecord) int { return compareGeneratedIDs(a.RecordID, b.RecordID) })
	out := GeneratedInvocationResult{OperationKind: scope.OperationKind, CanonicalOutcome: contract.ReceiptCanonicalNotSelected,
		EffectsAvailable: true, RelatedWorkAvailable: true, SummaryCountsAvailable: true, EvidenceCeiling: contract.ReceiptEvidenceCanonical,
		Effects: make([]GeneratedEffectFact, len(effects)), Duties: make([]GeneratedDutyFact, len(duties)), Hazards: make([]GeneratedHazardFact, len(hazards)),
		RelatedDutyIDs: make([]contract.ID, len(duties)), RelatedHazardIDs: make([]contract.ID, len(hazards))}
	for i, row := range effects {
		fact, err := generatedEffectFact(ctx, work, row.RecordID)
		if err != nil {
			return GeneratedInvocationResult{}, err
		}
		record, err := contract.InspectGeneratedAttemptRecord(row.Body)
		class, known := scope.EffectClasses[row.RecordID]
		operation := scope.effectOperationID
		if operation.IsZero() {
			operation = scope.OperationID
		}
		if err != nil || row.Kind != contract.GeneratedAttemptSupportKind || fact.Record != record || record.OperationID != operation || !known || class < contract.ReceiptSummarySuccessCount || class > contract.ReceiptNoEffectPredecessorCount {
			return GeneratedInvocationResult{}, contract.ErrRecord
		}
		fact.SummaryClass = class
		out.Effects[i] = fact
		out.SummaryCounts[class]++
		if completion, known := scope.CompletionClasses[row.RecordID]; known {
			if !generatedInvocationCompletionValid(fact, completion) {
				return GeneratedInvocationResult{}, contract.ErrRecord
			}
			switch completion {
			case contract.GeneratedCompletionConfirmed:
				out.ConfirmedCount++
			case contract.GeneratedCompletionAcknowledged:
				out.AcknowledgedCount++
			default:
				return GeneratedInvocationResult{}, contract.ErrRecord
			}
		}
	}
	for i, row := range duties {
		fact, err := generatedDutyFact(ctx, work, row.RecordID)
		if err != nil {
			return GeneratedInvocationResult{}, err
		}
		record, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || row.Kind != contract.GeneratedDutySupportKind || fact.Record != record || record.OriginalOperationID != scope.OperationID && !slices.Contains(scope.RelatedDutyIDs, row.RecordID) {
			return GeneratedInvocationResult{}, contract.ErrRecord
		}
		out.Duties[i], out.RelatedDutyIDs[i] = fact, row.RecordID
	}
	for i, row := range hazards {
		fact, err := generatedHazardFact(ctx, work, row.RecordID)
		if err != nil {
			return GeneratedInvocationResult{}, err
		}
		record, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil || row.Kind != contract.GeneratedHazardSupportKind || fact.Record != record || record.OriginalOperationID != scope.OperationID && !slices.Contains(scope.RelatedHazardIDs, row.RecordID) {
			return GeneratedInvocationResult{}, contract.ErrRecord
		}
		out.Hazards[i], out.RelatedHazardIDs[i] = fact, row.RecordID
	}
	for _, set := range []struct {
		kind contract.MutationResultRecordKind
		rows []contract.SupportRecord
		to   **contract.GeneratorDescriptor
	}{
		{contract.MutationResultEffects, effects, &out.EffectsCommitment}, {contract.MutationResultDuties, duties, &out.RelatedDutiesCommitment}, {contract.MutationResultHazards, hazards, &out.RelatedHazardsCommitment}} {
		descriptor, err := contract.MutationResultRecordDescriptor(set.kind, work.image.root.Domain, set.rows)
		if err != nil {
			return GeneratedInvocationResult{}, err
		}
		*set.to = &descriptor
	}
	out.SummaryCounts[contract.ReceiptEffectCount], out.SummaryCounts[contract.ReceiptDutyCount], out.SummaryCounts[contract.ReceiptHazardCount] = uint32(len(effects)), uint32(len(duties)), uint32(len(hazards))
	out.UnknownCount = out.SummaryCounts[contract.ReceiptSummaryUnknownCount] + out.SummaryCounts[contract.ReceiptPreservedResidueCount]
	out.EffectSummary = generatedOperationEffectSummary(scope.OperationKind, out.SummaryCounts)
	for _, effect := range out.Effects {
		if effect.EvidenceCeiling > out.EvidenceCeiling {
			out.EvidenceCeiling = effect.EvidenceCeiling
		}
	}
	out.StateResult = generatedInvocationEffectState(out.EffectSummary)
	proof, err := generatedCanonicalSelection(work, scope)
	if err != nil {
		return GeneratedInvocationResult{}, err
	}
	out.canonicalSelection = proof
	if !out.canonicalSelection.selectionPhase.IsZero() {
		out.CanonicalOutcome = contract.ReceiptCanonicalSelected
		out.StateResult = "retirement-pending"
	}
	out.Warnings = generatedInvocationWarnings(out)
	return out, ctx.Err()
}

// Reflected Confirmed Delete preserves its original mapping state. The owning
// release reader supplies the exact acknowledged and confirmed proof rows.
func generatedInvocationCompletionValid(effect GeneratedEffectFact, completion uint8) bool {
	if completion != effect.Record.CompletionClass {
		return false
	}
	if effect.Record.State == contract.GeneratedEffectSucceeded {
		return true
	}
	if effect.Action != contract.GeneratorActionDelete || completion != contract.GeneratedCompletionConfirmed || len(effect.Progress) != 2 {
		return false
	}
	var acknowledged, confirmed bool
	for _, row := range effect.Progress {
		if row.AttemptID.IsZero() || row.CompletionClass != completion || row.RequiredSteps != contract.GeneratorConfirmedRequiredSteps || !row.Evidence.Valid() || row.Evidence.Count != 1 {
			return false
		}
		switch row.CompletedSteps {
		case contract.GeneratorProgressAcknowledged:
			if acknowledged {
				return false
			}
			acknowledged = true
		case contract.GeneratorProgressConfirmed:
			if row.AttemptID != effect.Record.AttemptID || confirmed {
				return false
			}
			confirmed = true
		default:
			return false
		}
	}
	return acknowledged && confirmed
}

func generatedInvocationWarnings(result GeneratedInvocationResult) GeneratedResultWarnings {
	var out GeneratedResultWarnings
	for _, row := range result.Effects {
		out = mergeGeneratedResultWarnings(out, row.Warnings)
	}
	for _, row := range result.Duties {
		out = mergeGeneratedResultWarnings(out, row.Warnings)
	}
	for _, row := range result.Hazards {
		out = mergeGeneratedResultWarnings(out, row.Warnings)
	}
	return out
}

func generatedInvocationEffectState(summary uint16) string {
	switch summary {
	case contract.ReceiptEffectUnknown:
		return "effect-unknown"
	case contract.ReceiptEffectPending:
		return "effect-pending"
	case contract.ReceiptEffectPartial:
		return "effect-partial"
	case contract.ReceiptEffectFailed, contract.ReceiptEffectMixedTerminal:
		return "effect-terminal-failure"
	}
	return "unavailable"
}

func generatedInvocationReceipt(ctx context.Context, state *StateSession, work *generatedSelection, scope generatedInvocationResultScope, out *GeneratedInvocationResult) error {
	row, _, found, err := state.retainedMutationReceipt(scope.OperationID)
	if err != nil {
		return err
	}
	if scope.receiptFree {
		if found {
			return contract.ErrRecord
		}
		switch scope.receiptFreeState {
		case "success", "effect-pending", "effect-partial", "effect-unknown", "effect-terminal-failure":
		default:
			return contract.ErrRecord
		}
		out.StateResult = scope.receiptFreeState
		if scope.CanonicalSuccessor {
			out.CanonicalOutcome = contract.ReceiptCanonicalSelected
		} else {
			out.CanonicalOutcome = contract.ReceiptCanonicalNotSelected
		}
		for _, effect := range out.Effects {
			if effect.EvidenceCeiling > out.EvidenceCeiling {
				out.EvidenceCeiling = effect.EvidenceCeiling
			}
		}
		return ctx.Err()
	}
	if !found && scope.receiptOptional {
		if out.HasObservedCanonicalSelection(state.root.Domain, scope.OperationID, scope.RequestIdentity) {
			out.StateResult = "retirement-pending"
		} else {
			out.CanonicalOutcome = contract.ReceiptCanonicalNotSelected
			out.StateResult = generatedInvocationEffectState(out.EffectSummary)
		}
		for _, effect := range out.Effects {
			if effect.EvidenceCeiling > out.EvidenceCeiling {
				out.EvidenceCeiling = effect.EvidenceCeiling
			}
		}
		return ctx.Err()
	}
	if !found {
		return contract.ErrRecord
	}
	if row.OperationKind != scope.OperationKind || row.RequestIdentityDigest != scope.RequestIdentity || row.PredecessorRevisionID != scope.OriginalPredecessorRevisionID ||
		row.ChangedSubjects != scope.ChangedSubjects || row.SummaryCounts[contract.ReceiptEffectCount] != uint32(len(out.Effects)) ||
		row.SummaryCounts[contract.ReceiptDutyCount] != uint32(len(out.Duties)) || row.SummaryCounts[contract.ReceiptHazardCount] != uint32(len(out.Hazards)) ||
		(row.CanonicalOutcome == contract.ReceiptCanonicalSelected) != scope.CanonicalSuccessor {
		return contract.ErrRecord
	}
	for at := contract.ReceiptSummarySuccessCount; at < contract.ReceiptSummaryCount; at++ {
		if row.SummaryCounts[at] != out.SummaryCounts[at] {
			return contract.ErrRecord
		}
	}
	if row.EffectSummary != out.EffectSummary || row.AcknowledgedCount != out.AcknowledgedCount || row.ConfirmedCount != out.ConfirmedCount || row.UnknownCount != out.UnknownCount {
		return contract.ErrRecord
	}
	requestCore := scope.requestCoreDigest
	if requestCore.IsZero() && work.parent != nil {
		requestCore = work.parent.RequestCoreDigest
	}
	if requestCore.IsZero() {
		return contract.ErrRecord
	}
	complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: generatedReceiptDescriptorPlan(row), RequestCoreDigest: requestCore,
		ChangedAccess: scope.ChangedAccess, Effects: *out.EffectsCommitment, Outputs: contract.EmptyMutationResultDescriptors()[2], Duties: *out.RelatedDutiesCommitment, Hazards: *out.RelatedHazardsCommitment})
	if err != nil || complete != row.CompleteResult {
		return contract.ErrRecord
	}
	out.StateResult, out.CanonicalOutcome, out.EffectSummary, out.EvidenceCeiling = installedGeneratedReceiptState(row.StateResult), row.CanonicalOutcome, row.EffectSummary, row.EvidenceCeiling
	out.SummaryCounts, out.AcknowledgedCount, out.ConfirmedCount, out.UnknownCount = row.SummaryCounts, row.AcknowledgedCount, row.ConfirmedCount, row.UnknownCount
	return ctx.Err()
}

// Only the returned invocation header changes. Its authenticated safe fact
// backing stays immutable and shared across passive stop projections.
func generatedInvocationStopped(out *GeneratedInvocationResult, result Result) {
	proof := out.canonicalSelection
	if !out.HasObservedCanonicalSelection(proof.domain, proof.operation, proof.requestIdentity) {
		out.CanonicalOutcome = contract.ReceiptCanonicalNotSelected
	}
	switch result.Outcome {
	case Contention:
		out.StateResult = "contention"
	case UnresolvedCommit:
		out.StateResult = "commit-outcome-unknown"
	case AdmissionRefused:
		out.StateResult = "refused"
	case IntegrityFailure:
		out.StateResult = "positive-defect"
	case EvidenceUnavailable:
		out.StateResult = "unavailable"
	}
}

func (capture *generatedInvocationResultCapture) observe(ctx context.Context, actual *StateSession, result Result) (*GeneratedInvocationResult, error) {
	if ctx == nil || capture == nil || capture.used {
		return nil, contract.ErrRecord
	}
	capture.used = true
	defer func() {
		capture.candidate = Candidate{}
		capture.hasCandidate = false
	}()
	out := &capture.observed
	if result.Outcome == ObservedCurrent && capture.hasCandidate && (result.Evidence != AuthenticatedClosure || !candidateMatches(actual, &capture.candidate)) {
		capture.observed, capture.selected = GeneratedInvocationResult{}, GeneratedInvocationResult{}
		return nil, contract.ErrRecord
	}
	if result.Outcome == ObservedCurrent && result.Evidence == AuthenticatedClosure && capture.hasCandidate && candidateMatches(actual, &capture.candidate) {
		out = &capture.selected
	} else {
		generatedInvocationStopped(out, result)
	}

	if out == &capture.selected {
		capture.observed = GeneratedInvocationResult{}
	} else {
		capture.selected = GeneratedInvocationResult{}
	}
	return out, nil
}

// Account both retained variants and each independently owned allocation once.
// This is application backing only, not an allocator or total-process bound.
func generatedInvocationBackingBytes(results ...*GeneratedInvocationResult) (uint64, error) {
	var bytes uint64
	effects := make(map[*GeneratedEffectFact]bool)
	duties := make(map[*GeneratedDutyFact]bool)
	hazards := make(map[*GeneratedHazardFact]bool)
	targets := make(map[*contract.GeneratorTarget]bool)
	progress := make(map[*contract.GeneratorProgress]bool)
	var progressRows uint64
	names := make(map[*byte]bool)
	ids := make(map[*contract.ID]bool)
	descriptors := make(map[*contract.GeneratorDescriptor]bool)
	name := func(value string) {
		if len(value) != 0 && !names[unsafe.StringData(value)] {
			names[unsafe.StringData(value)] = true
			bytes += uint64(len(value))
		}
	}
	target := func(value *contract.GeneratorTarget) {
		if value != nil && !targets[value] {
			targets[value] = true
			bytes += uint64(unsafe.Sizeof(*value))
			name(value.Name)
		}
	}
	steps := func(value []contract.GeneratorProgress) error {
		if uint64(cap(value)) > GeneratedResultProgressLimit {
			return contract.ErrRecordCapacity
		}
		if len(value) != 0 && !progress[unsafe.SliceData(value)] {
			progress[unsafe.SliceData(value)] = true
			progressRows += uint64(cap(value))
			if progressRows > 2*GeneratedResultProgressLimit {
				return contract.ErrRecordCapacity
			}
			bytes += uint64(cap(value)) * uint64(unsafe.Sizeof(value[0]))
		}
		return nil
	}
	for _, result := range results {
		if result == nil {
			continue
		}
		if uint64(cap(result.Effects)) > GeneratedResultEffectLimit || uint64(cap(result.Duties))+uint64(cap(result.Hazards)) > GeneratedResultWorkLimit {
			return 0, contract.ErrRecordCapacity
		}
		bytes += uint64(unsafe.Sizeof(*result))
		if len(result.Effects) != 0 && !effects[unsafe.SliceData(result.Effects)] {
			effects[unsafe.SliceData(result.Effects)] = true
			bytes += uint64(cap(result.Effects)) * uint64(unsafe.Sizeof(result.Effects[0]))
		}
		if len(result.Duties) != 0 && !duties[unsafe.SliceData(result.Duties)] {
			duties[unsafe.SliceData(result.Duties)] = true
			bytes += uint64(cap(result.Duties)) * uint64(unsafe.Sizeof(result.Duties[0]))
		}
		if len(result.Hazards) != 0 && !hazards[unsafe.SliceData(result.Hazards)] {
			hazards[unsafe.SliceData(result.Hazards)] = true
			bytes += uint64(cap(result.Hazards)) * uint64(unsafe.Sizeof(result.Hazards[0]))
		}
		for _, row := range result.Effects {
			name(row.Name)
			target(row.Target)
			if err := steps(row.Progress); err != nil {
				return 0, err
			}
		}
		for _, row := range result.Duties {
			target(row.Target)
			if err := steps(row.Progress); err != nil {
				return 0, err
			}
		}
		for _, row := range result.Hazards {
			target(row.Target)
		}
		for _, rows := range [][]contract.ID{result.RelatedDutyIDs, result.RelatedHazardIDs} {
			if uint64(cap(rows)) > GeneratedResultWorkLimit {
				return 0, contract.ErrRecordCapacity
			}
			if len(rows) != 0 && !ids[unsafe.SliceData(rows)] {
				ids[unsafe.SliceData(rows)] = true
				bytes += uint64(cap(rows)) * 32
			}
		}
		for _, descriptor := range []*contract.GeneratorDescriptor{result.EffectsCommitment, result.RelatedDutiesCommitment, result.RelatedHazardsCommitment} {
			if descriptor != nil && !descriptors[descriptor] {
				descriptors[descriptor] = true
				bytes += uint64(unsafe.Sizeof(*descriptor))
			}
		}
	}
	return bytes, nil
}

func generatedInvocationCaptureBackingBytes(capture *generatedInvocationResultCapture) (uint64, error) {
	bytes, err := generatedInvocationBackingBytes(&capture.observed, &capture.selected)
	if err != nil {
		return 0, err
	}
	// A previous returned interior header can coexist while the next capture
	// borrows its sole live variant. Charge that fixed allocation and checkpoint;
	// their dynamic fact backing is already counted by exact shared addresses.
	bytes += uint64(unsafe.Sizeof(generatedInvocationResultCapture{})) + uint64(unsafe.Sizeof(generatedSelectionCheckpoint{}))
	bytes += uint64(unsafe.Sizeof(*capture)) - 2*uint64(unsafe.Sizeof(GeneratedInvocationResult{})) + uint64(len(capture.candidate.head.Core.PreviousToken.Value))
	if capture.candidate.head.Generator != nil {
		bytes += uint64(unsafe.Sizeof(*capture.candidate.head.Generator))
	}
	return bytes, nil
}
