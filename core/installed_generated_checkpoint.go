package core

import (
	"context"

	"enkv.sh/core/contract"
)

// Only actual selection sites establish this invocation's checkpoint. Safe
// immutable result backing is shared; no selected session or graph is retained.
type generatedSelectionCheckpoint struct {
	valid                              bool
	operation                          contract.ID
	observedRevision, observedSnapshot contract.ID
	result                             Result
	generated                          *GeneratedInvocationResult
	payload                            *TransitionPayload
	cleanup                            *GeneratedCleanupPayload
	receipt                            []byte
	warnings                           uint8
}

func (c *generatedSelectionCheckpoint) recordSelected(out PublicApplyResult) {
	if out.Result.RequestedRevision.IsZero() {
		return
	}
	c.valid = true
	c.operation = out.OperationID
	c.observedRevision, c.observedSnapshot = out.Result.ObservedRevision, out.Result.ObservedSnapshotID
	c.result, c.generated, c.payload, c.cleanup = out.Result, out.Generated, out.Payload, out.Cleanup
	c.receipt, c.warnings = out.Receipt, out.WarningBits
}

// This guard is usable only with a checkpoint established at this invocation's
// actual selection boundary. A read-only continuation never establishes it.
func (c *generatedSelectionCheckpoint) matchesBefore(before *StateSession) bool {
	return c != nil && c.valid && before != nil && c.result.Outcome == ObservedCurrent &&
		c.result.Evidence == AuthenticatedClosure && c.result.ObservedRevision == before.head.Core.Revision &&
		c.result.ObservedSnapshotID == before.root.Snapshot
}

func (c *generatedSelectionCheckpoint) ownedBefore(before *StateSession, kind uint16, operation contract.ID) *GeneratedInvocationResult {
	if c == nil || before == nil || !c.matchesBefore(before) && (c.valid || c.observedRevision != before.head.Core.Revision || c.observedSnapshot != before.root.Snapshot) || c.operation != operation || c.generated == nil || c.generated.OperationKind != kind ||
		!c.generated.EffectsAvailable || !c.generated.RelatedWorkAvailable || !c.generated.SummaryCountsAvailable {
		return nil
	}
	return c.generated
}

// A passive read can own a before vector without owning a selection result.
// Its fixed authenticated basis permits reuse when preparing the first CAS.
func (c *generatedSelectionCheckpoint) rememberObserved(before *StateSession, out PublicApplyResult) {
	if c == nil || c.valid || before == nil {
		return
	}
	c.operation, c.generated = out.OperationID, out.Generated
	c.observedRevision, c.observedSnapshot = before.head.Core.Revision, before.root.Snapshot
}

func (c *generatedSelectionCheckpoint) preparationFailure(ctx context.Context, out PublicApplyResult, failure Result) PublicApplyResult {
	if c == nil || !c.valid {
		out.Result = failure
		if out.Generated != nil {
			header := *out.Generated
			generatedInvocationStopped(&header, failure)
			out.Generated = &header
		}
		return out
	}
	out.Result, out.Generated, out.Payload, out.Cleanup = c.result, c.generated, c.payload, c.cleanup
	out.Receipt, out.WarningBits = c.receipt, c.warnings
	reason := generatedPreparationDiagnostic(ctx, failure)
	out.Diagnostics = append(out.Diagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation},
		Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason})
	return out
}

func generatedPreparationDiagnostic(ctx context.Context, failure Result) contract.DiagnosticReason {
	if ctx != nil {
		if ctx.Err() == context.Canceled {
			return contract.ReasonCancelled
		}
		if ctx.Err() == context.DeadlineExceeded {
			return contract.ReasonExpired
		}
	}
	if failure.Reason == CapacityExceeded || failure.StoreReason == contract.ReasonLimit {
		return contract.ReasonLimitExceeded
	}
	if failure.Outcome == IntegrityFailure {
		switch failure.Reason {
		case InvalidProof:
			return contract.ReasonProofInvalid
		case InvalidFormat, InvalidReference:
			return contract.ReasonSelectedObjectInvalid
		default:
			return contract.ReasonSelectedRelationInvalid
		}
	}
	switch failure.Reason {
	case AdmissionInvalid, ConstructionMismatch, InvalidIntent, AlreadyUsed:
		return contract.ReasonInvalidInput
	case InvalidProof:
		return contract.ReasonProofInvalid
	case InvalidFormat, InvalidReference:
		return contract.ReasonSelectedObjectInvalid
	case InvalidRelation:
		return contract.ReasonSelectedRelationInvalid
	case MissingSelectedObject, ReadUnavailable:
		return contract.ReasonSelectedObjectUnavailable
	case StalePrecondition, DifferentSelection:
		return contract.ReasonReadContention
	}
	return contract.ReasonEvidenceUnavailable
}
