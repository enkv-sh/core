package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

const GeneratedListOperation = "generated-list"

// GeneratedReadInstallation provides only public verification and exact GET
// reach. Its selected reader belongs to one finite List call.
type GeneratedReadInstallation struct {
	Candidate      PublicCandidateReader
	Construct      func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result)
	ExpectedDomain contract.ID
	ExpectedStore  contract.Descriptor
	PublicBasis    PublicBasis
	CloseInstalled func()
	// ResolveImplementation is optional passive installed metadata only.
	ResolveImplementation func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error)
}

type InstalledGeneratedReader struct {
	reader                *ReaderEngine
	resolveImplementation func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error)
}

func NewInstalledGeneratedReader(i GeneratedReadInstallation) (*InstalledGeneratedReader, error) {
	reader, err := newInstalledPublicReader(ReaderInstallation{
		Candidate: i.Candidate, Construct: i.Construct, ExpectedDomain: i.ExpectedDomain,
		ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, CloseInstalled: i.CloseInstalled,
	})
	if err != nil {
		return nil, err
	}
	return &InstalledGeneratedReader{reader: reader, resolveImplementation: i.ResolveImplementation}, nil
}

type PublicGeneratedListResult struct {
	Context       ReaderOperationContext
	Result        Result
	StateResult   contract.ReaderStateResult
	FailureReason contract.DiagnosticReason
	View          *GeneratedListView
}

// List fixes one complete authenticated observation. Returned selectors identify
// supported requests; they grant no authority or future eligibility.
func (e *InstalledGeneratedReader) List(ctx context.Context, requestID contract.ID) PublicGeneratedListResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedList)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	r := e.list(telemetry.CallContext(ctx, call), requestID, call)
	finishReaderCall(call, r.StateResult, r.FailureReason)
	return r
}

func (e *InstalledGeneratedReader) list(ctx context.Context, requestID contract.ID, call *telemetry.Call) PublicGeneratedListResult {
	r := PublicGeneratedListResult{Context: ReaderOperationContext{Operation: GeneratedListOperation, RequestID: requestID},
		Result: refused(AdmissionInvalid), StateResult: contract.ReaderRefused}
	var reader *ReaderEngine
	if e != nil {
		reader = e.reader
	}
	if reader != nil {
		r.Context.ExpectedDomain = reader.expectedDomain
	}
	fail := func(f readerFailure) PublicGeneratedListResult {
		r.Result, r.FailureReason, r.StateResult = f.Result, f.diagnostic, readerFailureState(f.diagnostic)
		return r
	}
	inv, failed := reader.beginReaderInvocation(ctx, GeneratedListOperation, requestID)
	if failed.Outcome != 0 {
		return fail(failed)
	}
	defer inv.Close()
	r.Context.OperationID = readerOperationID(inv.admission, contract.ID{}, contract.ID{})
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	var view GeneratedListView
	selected, failed := inv.loadPublicSelection(ctx, GeneratedListOperation, requestID, func(ctx context.Context, work *generatedSelection) error {
		var err error
		view, err = projectGeneratedList(ctx, work)
		return err
	})
	if failed.Outcome != 0 {
		return fail(failed)
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	if reason := inv.admission.failure(ctx, GeneratedListOperation, requestID); reason != "" {
		return fail(readerRefusal(reason))
	}
	head, root := selected.basis.anchor.head, selected.image.root
	r.Context.OperationID = readerOperationID(inv.admission, head.Core.Revision, root.Snapshot)
	view.DomainID, view.RevisionID, view.SnapshotID = root.Domain, head.Core.Revision, root.Snapshot
	qualifyGeneratedHazards(e.resolveImplementation, view.Hazards)
	if reason := inv.admission.failure(ctx, GeneratedListOperation, requestID); reason != "" {
		return fail(readerRefusal(reason))
	}
	r.Result = Result{Outcome: ObservedCurrent, ObservedRevision: head.Core.Revision, ObservedSnapshotID: root.Snapshot, Evidence: AuthenticatedClosure}
	r.StateResult, r.View = contract.ReaderSuccess, &view
	return r
}

func (e *InstalledGeneratedReader) Close() {
	if e != nil && e.reader != nil {
		e.reader.Close()
	}
}
