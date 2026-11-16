package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// PublicRecipientRegistry owns the complete authenticated selected registry.
type PublicRecipientRegistry struct {
	DomainID, SnapshotID, AuthorityRecipientID contract.ID
	Recipients                                 []contract.RecipientRecord
}

// PublicRecipientRegistryResult returns no registry when authentication or
// invocation completion fails.
type PublicRecipientRegistryResult struct {
	Context       ReaderOperationContext
	Result        Result
	StateResult   contract.ReaderStateResult
	FailureReason contract.DiagnosticReason
	Registry      *PublicRecipientRegistry
}

func (e *ReaderEngine) readRecipientRegistry(ctx context.Context, requestID contract.ID, call *telemetry.Call) PublicRecipientRegistryResult {
	r := PublicRecipientRegistryResult{Context: ReaderOperationContext{Operation: contract.ReaderRecipientsOperation, RequestID: requestID}, Result: refused(AdmissionInvalid), StateResult: contract.ReaderRefused}
	if e != nil {
		e.mu.Lock()
		r.Context.ExpectedDomain = e.expectedDomain
		e.mu.Unlock()
	}
	fail := func(f readerFailure) PublicRecipientRegistryResult {
		r.Result, r.FailureReason, r.StateResult = f.Result, f.diagnostic, readerFailureState(f.diagnostic)
		return r
	}
	inv, f := e.beginReaderInvocation(ctx, contract.ReaderRecipientsOperation, requestID)
	if f.Outcome != 0 {
		return fail(f)
	}
	defer inv.Close()
	r.Context.OperationID = readerOperationID(inv.admission, contract.ID{}, contract.ID{})
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	selected, f := inv.loadPublicSelection(ctx, contract.ReaderRecipientsOperation, requestID, nil)
	if f.Outcome != 0 {
		return fail(f)
	}
	head, root := selected.basis.anchor.head, selected.image.root
	r.Context.OperationID = readerOperationID(inv.admission, head.Core.Revision, root.Snapshot)
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	// Decoding already owns the strings and public key bytes. Transfer those
	// nested owners into one bounded result slice; no page or support body escapes.
	rows := selectedRecipientRegistry(&selected.image.recipients, root.RecipientCount)
	if reason := inv.admission.failure(ctx, contract.ReaderRecipientsOperation, requestID); reason != "" {
		return fail(readerRefusal(reason))
	}
	r.Registry = &PublicRecipientRegistry{DomainID: root.Domain, SnapshotID: root.Snapshot, AuthorityRecipientID: selected.authorityID, Recipients: rows}
	r.Result = Result{Outcome: ObservedCurrent, ObservedRevision: head.Core.Revision, ObservedSnapshotID: root.Snapshot, Evidence: AuthenticatedClosure}
	r.StateResult = contract.ReaderSuccess
	return r
}
