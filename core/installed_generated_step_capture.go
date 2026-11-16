package core

import (
	"context"
	"strings"

	"enkv.sh/core/contract"
)

// Nonterminal transitions retain their complete operational owners. The two
// actual scopes can differ in cardinality when a reservation enters an Attempt.
func captureGeneratedSelectionStep(ctx context.Context, before *StateSession, work *generatedSelection, proposal *generatedReservation, checkpoint *generatedSelectionCheckpoint) (*generatedInvocationResultCapture, error) {
	if ctx == nil || ctx.Err() != nil || before == nil || work == nil || work.image == nil || proposal == nil || proposal.state == nil || proposal.candidate == nil || !candidateMatches(proposal.state, proposal.candidate) || before.root.Domain != proposal.state.root.Domain {
		return nil, contract.ErrRecord
	}
	selected, err := proposal.state.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	selectedScope, err := generatedCurrentResultScope(ctx, proposal.state, selected)
	if err != nil {
		return nil, err
	}
	capture := &generatedInvocationResultCapture{observed: GeneratedInvocationResult{OperationKind: selectedScope.OperationKind, StateResult: "unavailable", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical}}
	if owned := checkpoint.ownedBefore(before, selectedScope.OperationKind, selectedScope.OperationID); owned != nil {
		capture.observed = *owned
	} else if work.parent != nil && work.parent.OperationID == selectedScope.OperationID {
		observedScope, err := generatedCurrentResultScope(ctx, before, work)
		if err != nil {
			return nil, err
		}
		capture.observed, err = generatedInvocationFacts(ctx, work, observedScope, observedScope.Effects, observedScope.Duties, observedScope.Hazards)
		if err != nil {
			return nil, err
		}
	}
	capture.selected, err = generatedInvocationFacts(ctx, selected, selectedScope, selectedScope.Effects, selectedScope.Duties, selectedScope.Hazards)
	if err != nil {
		return nil, err
	}
	capture.bindCandidate(proposal.candidate)
	capture.backingBytes, err = generatedInvocationCaptureBackingBytes(capture)
	return capture, err
}

func generatedCurrentResultScope(ctx context.Context, state *StateSession, work *generatedSelection) (generatedInvocationResultScope, error) {
	if generatedSelectionAnchored(work) {
		return generatedAutomaticInvocationScope(ctx, state, work)
	}
	return generatedActiveResultScope(work)
}

func generatedActiveResultScope(work *generatedSelection) (generatedInvocationResultScope, error) {
	if work == nil || work.parent == nil || work.phase == nil || len(work.bundles) == 0 {
		return generatedInvocationResultScope{}, contract.ErrRecord
	}
	scope := generatedInvocationResultScope{OperationKind: work.bundles[0].Request.OperationKind, OperationID: work.parent.OperationID, RequestIdentity: work.parent.RequestIdentityDigest, OriginalPredecessorRevisionID: work.bundles[0].Request.PredecessorRevisionID}
	switch scope.OperationKind {
	case contract.OperationApplyDeclaration, contract.OperationRotateValueEntryValue:
		operational, err := generatedFinalOperationalRows(work, &generatedFinalPlan{}, work.image.supportRecords())
		if err != nil {
			return scope, err
		}
		scope.Effects, scope.Duties, scope.Hazards, scope.EffectClasses = operational.effects, operational.duties, operational.hazards, operational.classes
	case contract.OperationRetireGeneratedGeneration:
		a, present := work.attempts[work.phase.FrontierAttemptID]
		if !present {
			return scope, contract.ErrRecord
		}
		row, present := work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, a.record.AttemptID}]
		if !present {
			return scope, contract.ErrRecord
		}
		class := contract.ReceiptSummaryUnknownCount
		switch a.record.State {
		case contract.GeneratedEffectSucceeded:
			class = contract.ReceiptSummaryPendingCount
		case contract.GeneratedEffectFailedTerminal, contract.GeneratedEffectConfirmedNoEffect:
			class = contract.ReceiptSummaryFailureCount
		}
		scope.Effects = []contract.SupportRecord{row}
		scope.EffectClasses = map[contract.ID]int{a.record.AttemptID: class}
		scope.RelatedDutyIDs = []contract.ID{a.record.OwnerID}
		var err error
		scope.Duties, scope.Hazards, err = generatedObservedInvocationWork(work, scope)
		if err != nil {
			return scope, err
		}
	default:
		return scope, contract.ErrRecord
	}
	return scope, nil
}

func (c *generatedInvocationResultCapture) bindCandidate(candidate *Candidate) {
	c.candidate.head.Core = candidate.head.Core
	c.candidate.head.Core.PreviousToken.Value = strings.Clone(candidate.head.Core.PreviousToken.Value)
	c.candidate.head.AuthKind, c.candidate.head.Subject = candidate.head.AuthKind, candidate.head.Subject
	if candidate.head.Generator != nil {
		subject := *candidate.head.Generator
		c.candidate.head.Generator = &subject
	}
	c.hasCandidate = true
}

// The selector's Result is authoritative even if response projection is defective.
func recordGeneratedSelection(ctx context.Context, out *PublicApplyResult, actual *StateSession, result Result, capture *generatedInvocationResultCapture, checkpoint *generatedSelectionCheckpoint) {
	if result.RequestedRevision.IsZero() {
		*out = checkpoint.preparationFailure(ctx, *out, result)
		return
	}
	out.Result = result
	out.Payload, out.Receipt = nil, nil
	facts, err := capture.observe(ctx, actual, result)
	out.Generated = facts
	if err != nil {
		out.Generated = nil
		out.Diagnostics = append(out.Diagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedRelationInvalid})
	}
	if actual != nil && result.Outcome == ObservedCurrent {
		out.WarningBits = actual.root.WarningBits
	}
	checkpoint.recordSelected(*out)
}
