package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type InspectionReadInstallation struct {
	Candidate             PublicCandidateReader
	Construct             func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result)
	ExpectedDomain        contract.ID
	ExpectedStore         contract.Descriptor
	PublicBasis           PublicBasis
	Validator             *PublicConfigurationValidator
	SourcePins            AdministrativeSourcePins
	CheckSource           func(context.Context) error
	CloseInstalled        func()
	ResolveImplementation func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error)
}

type InstalledInspectionReader struct {
	reader                *ReaderEngine
	pins                  AdministrativeSourcePins
	checkSource           func(context.Context) error
	resolveImplementation func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error)
}

// NewInstalledInspectionReader transfers installation cleanup on success only.
// Its dependencies have public GET and passive interpretation reach only.
func NewInstalledInspectionReader(i InspectionReadInstallation) (*InstalledInspectionReader, error) {
	if !i.SourcePins.Valid() || i.CheckSource == nil || i.Validator == nil {
		return nil, contract.ErrRecord
	}
	reader, err := newInstalledPublicReader(ReaderInstallation{Candidate: i.Candidate, Construct: i.Construct,
		ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis,
		Validator: i.Validator, CloseInstalled: i.CloseInstalled})
	if err != nil {
		return nil, err
	}
	return &InstalledInspectionReader{reader: reader, pins: i.SourcePins, checkSource: i.CheckSource, resolveImplementation: i.ResolveImplementation}, nil
}

func (r *InstalledInspectionReader) Close() {
	if r != nil && r.reader != nil {
		r.reader.Close()
	}
}

type DomainInspectionRequest struct{ RequestNonce contract.ID }
type RecipientInspectionRequest struct{ RequestNonce, RecipientID contract.ID }

type DomainInspectionQueryIdentity struct {
	PublicQueryBasis
	Digest contract.ID
}

type RecipientInspectionQueryIdentity struct {
	PublicQueryBasis
	RecipientID, Digest contract.ID
}

type PublicDomainInspectionResult struct {
	PublicQueryResult
	Query *DomainInspectionQueryIdentity
	View  *DomainInspection
}

type PublicRecipientInspectionResult struct {
	PublicQueryResult
	Query *RecipientInspectionQueryIdentity
	View  *RecipientInspection
}

func (r *InstalledInspectionReader) begin(ctx context.Context, operation string, nonce, selector contract.ID) (PublicQueryResult, PublicQueryBasis, *readerInvocation, readerFailure) {
	out := PublicQueryResult{Operation: operation, RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: PublicQueryRefused, FailureReason: contract.ReasonInvalidInput}
	if r == nil || r.reader == nil {
		return out, PublicQueryBasis{}, nil, readerRefusal(contract.ReasonInvalidInput)
	}
	out.DomainID = r.reader.expectedDomain
	q, ok := newPublicQueryBasis(r.reader, r.pins, operation, 15, nonce)
	if !ok {
		return out, q, nil, readerRefusal(contract.ReasonInvalidInput)
	}
	digest, ok := q.digest(selector)
	if !ok {
		return out, q, nil, readerRefusal(contract.ReasonInvalidInput)
	}
	out.RequestIdentity, out.OperationID = digest, publicQueryOperationID(digest)
	inv, failed := r.reader.beginReaderInvocation(ctx, operation, digest)
	if failed.Outcome != 0 {
		return out, q, nil, failed
	}
	transferred := false
	defer func() {
		if !transferred {
			inv.Close()
		}
	}()
	if err := r.checkSource(ctx); err != nil {
		failed = readerRefusal(contract.ReasonInvalidInput)
	}
	if failed = publicQueryFailure(ctx, inv, failed); failed.Outcome != 0 {
		return out, q, nil, failed
	}
	transferred = true
	return out, q, inv, readerFailure{}
}

func (r *InstalledInspectionReader) Inspect(ctx context.Context, request DomainInspectionRequest) PublicDomainInspectionResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreInspect)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	ctx = telemetry.CallContext(ctx, call)
	out, q, inv, failed := r.begin(ctx, InspectOperation, request.RequestNonce, contract.ID{})
	result := PublicDomainInspectionResult{PublicQueryResult: out}
	defer func() { finishPublicQueryCall(call, result.PublicQueryResult) }()
	if q.valid() {
		result.Query = &DomainInspectionQueryIdentity{PublicQueryBasis: q, Digest: out.RequestIdentity}
	}
	fail := func(f readerFailure) PublicDomainInspectionResult {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, f))
		result.View = nil
		return result
	}
	if failed.Outcome != 0 {
		return fail(failed)
	}
	defer inv.Close()
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	var generated GeneratedListView
	selected, failed := inv.loadPublicSelection(ctx, InspectOperation, out.RequestIdentity, func(ctx context.Context, facts *generatedSelection) error {
		var err error
		generated, err = projectGeneratedList(ctx, facts)
		return err
	})
	if failed.Outcome != 0 {
		return fail(failed)
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	entries, recipients, err := projectInspectionMetadata(ctx, &selected)
	if err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	output, facts, failed := projectInspectionOutput(ctx, &selected)
	if failed.Outcome != 0 {
		return fail(failed)
	}
	work, err := projectInspectionWork(selected.image.root, selected.image.adminIndex, facts.coordinates)
	if err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	qualifyGeneratedHazards(r.resolveImplementation, generated.Hazards)
	observation := inspectionObservation(selected)
	view := DomainInspection{Observation: observation, Entries: entries, Recipients: recipients,
		ActiveOperation: generated.ActiveOperation, Generated: InspectionGeneratedWork{CurrentGenerations: generated.CurrentGenerations,
			Effects: generated.Effects, Duties: generated.Duties, Hazards: generated.Hazards, PendingReleases: generated.PendingReleases, NextActions: generated.NextActions},
		Work: work, Output: output, DomainWarningBits: selected.image.root.WarningBits,
		Warnings: InspectionWarnings{Domain: publicDomainWarnings(selected.image.root.WarningBits), Generated: generated.Warnings,
			Output: output.Warnings, PossibleStoreGarbage: generated.PossibleGarbage || selected.image.root.WarningBits&WarningPossibleStoreGarbage != 0}}
	if err := view.ValidateMetadataWorkOutput(); err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return fail(failed)
	}
	if err := r.checkSource(ctx); err != nil {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return fail(failed)
	}
	q.Observation = &observation
	digest, ok := q.digest(contract.ID{})
	if !ok {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	result.Query = &DomainInspectionQueryIdentity{PublicQueryBasis: q, Digest: digest}
	result.PublicQueryResult = successfulInspectionQuery(result.PublicQueryResult, observation, digest)
	result.View = &view
	return result
}

func (r *InstalledInspectionReader) InspectRecipient(ctx context.Context, request RecipientInspectionRequest) PublicRecipientInspectionResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreInspectRecipient)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	ctx = telemetry.CallContext(ctx, call)
	out, q, inv, failed := r.begin(ctx, InspectRecipientOperation, request.RequestNonce, request.RecipientID)
	result := PublicRecipientInspectionResult{PublicQueryResult: out}
	defer func() { finishPublicQueryCall(call, result.PublicQueryResult) }()
	if q.valid() && !request.RecipientID.IsZero() {
		result.Query = &RecipientInspectionQueryIdentity{PublicQueryBasis: q, RecipientID: request.RecipientID, Digest: out.RequestIdentity}
	}
	fail := func(f readerFailure) PublicRecipientInspectionResult {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, f))
		result.View = nil
		return result
	}
	if failed.Outcome != 0 {
		return fail(failed)
	}
	defer inv.Close()
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	selected, failed := inv.loadPublicSelection(ctx, InspectRecipientOperation, out.RequestIdentity, nil)
	if failed.Outcome != 0 {
		return fail(failed)
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	current := selectedRecipientRecord(&selected.image.recipients, request.RecipientID)
	if current == nil || current.Status != contract.CurrentRecipient {
		return fail(readerRefusal(contract.ReasonTargetAbsent))
	}
	view, err := projectRecipientInspection(ctx, &selected, request.RecipientID)
	if err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	observation := inspectionObservation(selected)
	view.Observation = observation
	if err := view.Validate(); err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return fail(failed)
	}
	if err := r.checkSource(ctx); err != nil {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return fail(failed)
	}
	q.Observation = &observation
	digest, ok := q.digest(request.RecipientID)
	if !ok {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	result.Query = &RecipientInspectionQueryIdentity{PublicQueryBasis: q, RecipientID: request.RecipientID, Digest: digest}
	result.PublicQueryResult = successfulInspectionQuery(result.PublicQueryResult, observation, digest)
	result.View = &view
	return result
}

func inspectionObservation(selected publicSelection) PublicObservation {
	return PublicObservation{DomainID: selected.image.root.Domain, HeadRevisionID: selected.basis.anchor.head.Core.Revision,
		SnapshotID: selected.image.root.Snapshot, RootDigest: selected.basis.anchor.head.Core.Root.Digest}
}

func successfulInspectionQuery(out PublicQueryResult, observation PublicObservation, digest contract.ID) PublicQueryResult {
	out.RequestIdentity, out.OperationID = digest, publicQueryOperationID(digest)
	out.Result = Result{Outcome: ObservedCurrent, ObservedRevision: observation.HeadRevisionID, ObservedSnapshotID: observation.SnapshotID, Evidence: AuthenticatedClosure}
	out.StateResult, out.FailureReason = PublicQuerySuccess, ""
	return out
}

func (q DomainInspectionQueryIdentity) Validate() error {
	digest, ok := q.digest(contract.ID{})
	if !ok || q.Operation != InspectOperation || q.SemanticOperation != 15 || digest != q.Digest {
		return contract.ErrRecord
	}
	return nil
}

func (q RecipientInspectionQueryIdentity) Validate() error {
	digest, ok := q.digest(q.RecipientID)
	if !ok || q.Operation != InspectRecipientOperation || q.SemanticOperation != 15 || digest != q.Digest {
		return contract.ErrRecord
	}
	return nil
}
