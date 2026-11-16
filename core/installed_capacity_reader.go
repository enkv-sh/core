package core

import (
	"bytes"
	"context"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// PublicCapacityReader has public exact GET and one-page LIST reach only.
// Each Read is one physical provider call; Core owns any transport retry.
type PublicCapacityReader interface {
	PublicSelectedReader
	contract.BoundedEnumerationStore
}

type CapacityReadInstallation struct {
	Candidate      PublicCandidateReader
	Construct      func(context.Context, contract.StoreConfiguration) (PublicCapacityReader, Result)
	ExpectedDomain contract.ID
	ExpectedStore  contract.Descriptor
	PublicBasis    PublicBasis
	SourcePins     AdministrativeSourcePins
	CheckSource    func(context.Context) error
	CloseInstalled func()
}

type InstalledCapacityReader struct {
	reader      *ReaderEngine
	pins        AdministrativeSourcePins
	checkSource func(context.Context) error
}

func NewInstalledCapacityReader(i CapacityReadInstallation) (*InstalledCapacityReader, error) {
	if i.Construct == nil || !i.SourcePins.Valid() || i.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	construct := func(ctx context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return i.Construct(ctx, configuration)
	}
	reader, err := newInstalledPublicReader(ReaderInstallation{Candidate: i.Candidate, Construct: construct, ExpectedDomain: i.ExpectedDomain,
		ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, CloseInstalled: i.CloseInstalled})
	if err != nil {
		return nil, err
	}
	return &InstalledCapacityReader{reader: reader, pins: i.SourcePins, checkSource: i.CheckSource}, nil
}

func (r *InstalledCapacityReader) Close() {
	if r != nil && r.reader != nil {
		r.reader.Close()
	}
}

type CapacityInspectionRequest struct {
	RequestNonce contract.ID
	Cursor       string
}

type GCPreviewRequest struct {
	RequestNonce, OperationID contract.ID
	Cursor                    string
}

type PublicCapacityInspectionResult struct {
	PublicQueryResult
	Query *CapacityInspectionQueryIdentity
	View  *CapacityInspection
}

type GCPreviewPayload struct {
	Observation                 PublicObservation
	Plan                        contract.GCPlan
	EncodedPlan                 []byte
	PlanDigest, RequestIdentity contract.ID
	Garbage                     GCCandidatePage
}

type PublicGCPreviewResult struct {
	PublicQueryResult
	Query   *GCPreviewQueryIdentity
	Payload *GCPreviewPayload
}

func (r *InstalledCapacityReader) begin(ctx context.Context, operation string, nonce, proposed contract.ID, cursor string) (PublicQueryResult, PublicQueryBasis, string, *readerInvocation, readerFailure) {
	out := PublicQueryResult{Operation: operation, RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: PublicQueryRefused, FailureReason: contract.ReasonInvalidInput}
	if r == nil || r.reader == nil {
		return out, PublicQueryBasis{}, "", nil, readerRefusal(contract.ReasonInvalidInput)
	}
	out.DomainID = r.reader.expectedDomain
	providerCursor, err := DecodeGCCursor(cursor, r.reader.expectedDomain, r.reader.expectedStore)
	if err != nil {
		return out, PublicQueryBasis{}, "", nil, readerRefusal(contract.ReasonInvalidInput)
	}
	semantic := uint16(30)
	if operation == GCPlanOperation {
		semantic = 40
	}
	q, ok := newPublicQueryBasis(r.reader, r.pins, operation, semantic, nonce)
	if !ok {
		return out, q, "", nil, readerRefusal(contract.ReasonInvalidInput)
	}
	digest, ok := gcQueryDigest(q, cursor, proposed, contract.ID{}, contract.ID{})
	if !ok {
		return out, PublicQueryBasis{}, "", nil, readerRefusal(contract.ReasonInvalidInput)
	}
	out.RequestIdentity, out.OperationID = digest, publicQueryOperationID(digest)
	inv, failed := r.reader.beginReaderInvocation(ctx, operation, digest)
	if failed.Outcome != 0 {
		return out, q, providerCursor, nil, failed
	}
	transferred := false
	defer func() {
		if !transferred {
			inv.Close()
		}
	}()
	if r.checkSource(ctx) != nil {
		failed = readerRefusal(contract.ReasonInvalidInput)
	}
	if failed = publicQueryFailure(ctx, inv, failed); failed.Outcome != 0 {
		return out, q, providerCursor, nil, failed
	}
	transferred = true
	return out, q, providerCursor, inv, readerFailure{}
}

func (r *InstalledCapacityReader) load(ctx context.Context, inv *readerInvocation, includeCapacity bool) (publicSelection, gcSelectedObservation, readerFailure) {
	var facts gcSelectedObservation
	selected, failed := inv.loadPublicSelection(ctx, inv.admission.operation, inv.admission.request, func(ctx context.Context, generated *generatedSelection) error {
		var err error
		facts, err = captureGCSelectedObservation(ctx, generated.image, generated, inv.admission.store, includeCapacity)
		return err
	})
	if failed.Outcome != 0 {
		return publicSelection{}, gcSelectedObservation{}, failed
	}
	return selected, facts, readerFailure{}
}

func (r *InstalledCapacityReader) observePage(ctx context.Context, inv *readerInvocation, selected publicSelection, facts gcSelectedObservation, providerCursor string) (GCCandidatePage, readerFailure) {
	var out GCCandidatePage
	if r.checkSource(ctx) != nil {
		return out, readerRefusal(contract.ReasonInvalidInput)
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return out, failed
	}
	lister, ok := inv.source.(PublicCapacityReader)
	if !ok {
		return out, readerRefusal(contract.ReasonUnsupportedProfile)
	}
	physical, err := newGCPhysicalReader(ctx, inv.source)
	if err != nil {
		return out, readerRefusal(contract.ReasonExpired)
	}
	page := lister.ListPage(ctx, providerCursor)
	headDigest := contract.Hash(selected.basis.anchor.headBody)
	observed, result := gcObservePage(ctx, physical, inv.admission.store, inv.admission.domain, headDigest, facts.marks, providerCursor, page)
	if result.Outcome != 0 {
		return out, readerSelectionFailure(result)
	}
	mark, err := facts.marks.digest(inv.admission.store, inv.admission.domain, headDigest)
	if err != nil {
		return out, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
	}
	next, err := EncodeGCCursor(observed.next, inv.admission.domain, inv.admission.store)
	if err != nil {
		return out, readerSelectionFailure(failure(IntegrityFailure, InvalidFormat))
	}
	targets, err := contract.GCTargetsDescriptor(observed.targets)
	if err != nil {
		return out, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))
	}
	if r.checkSource(ctx) != nil {
		return out, readerRefusal(contract.ReasonInvalidInput)
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return out, failed
	}
	return GCCandidatePage{MarkDigest: mark, EnumerationDigest: observed.digest, ProtectedObjectCount: uint64(len(facts.marks.objects)) + 1,
		Candidates: observed.candidates, EligibleTargets: observed.targets, Targets: targets, NextCursor: next, ObservationLimit: "one-page-no-snapshot"}, readerFailure{}
}

func (r *InstalledCapacityReader) InspectCapacity(ctx context.Context, request CapacityInspectionRequest) PublicCapacityInspectionResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreInspectCapacity)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	result := r.inspectCapacity(telemetry.CallContext(ctx, call), request, call)
	finishPublicQueryCall(call, result.PublicQueryResult)
	return result
}

func (r *InstalledCapacityReader) inspectCapacity(ctx context.Context, request CapacityInspectionRequest, call *telemetry.Call) (result PublicCapacityInspectionResult) {
	out, q, cursor, inv, failed := r.begin(ctx, InspectCapacityOperation, request.RequestNonce, contract.ID{}, request.Cursor)
	result.PublicQueryResult = out
	if q.valid() {
		result.Query = &CapacityInspectionQueryIdentity{PublicQueryBasis: q, Cursor: request.Cursor, Digest: out.RequestIdentity}
	}
	fail := func(f readerFailure) PublicCapacityInspectionResult {
		result.PublicQueryResult = out
		if q.valid() {
			initial := q
			initial.Observation = nil
			result.Query = &CapacityInspectionQueryIdentity{PublicQueryBasis: initial, Cursor: request.Cursor, Digest: out.RequestIdentity}
		}
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, f))
		result.View = nil
		return result
	}
	if failed.Outcome != 0 {
		return fail(failed)
	}
	defer inv.Close()
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	selected, facts, failed := r.load(ctx, inv, true)
	if failed.Outcome != 0 {
		return fail(failed)
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	page, failed := r.observePage(ctx, inv, selected, facts, cursor)
	if failed.Outcome != 0 {
		return fail(failed)
	}
	view, err := projectCapacityInspection(&selected, facts, page)
	if err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	q.Observation = &view.Observation
	digest, ok := gcQueryDigest(q, request.Cursor, contract.ID{}, page.MarkDigest, page.EnumerationDigest)
	if !ok {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	result.Query = &CapacityInspectionQueryIdentity{PublicQueryBasis: q, Cursor: request.Cursor, MarkDigest: page.MarkDigest, EnumerationDigest: page.EnumerationDigest, Digest: digest}
	result.PublicQueryResult = successfulInspectionQuery(out, view.Observation, digest)
	result.View = &view
	if err := result.Validate(); err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	if r.checkSource(ctx) != nil {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return fail(failed)
	}
	return result
}

func (r *InstalledCapacityReader) PlanGC(ctx context.Context, request GCPreviewRequest) PublicGCPreviewResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGCPlan)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	result := r.planGC(telemetry.CallContext(ctx, call), request, call)
	finishPublicQueryCall(call, result.PublicQueryResult)
	return result
}

func (r *InstalledCapacityReader) planGC(ctx context.Context, request GCPreviewRequest, call *telemetry.Call) (result PublicGCPreviewResult) {
	out, q, cursor, inv, failed := r.begin(ctx, GCPlanOperation, request.RequestNonce, request.OperationID, request.Cursor)
	result.PublicQueryResult = out
	if q.valid() {
		result.Query = &GCPreviewQueryIdentity{PublicQueryBasis: q, Cursor: request.Cursor, ProposedOperationID: request.OperationID, Digest: out.RequestIdentity}
	}
	fail := func(f readerFailure) PublicGCPreviewResult {
		result.PublicQueryResult = out
		if q.valid() {
			initial := q
			initial.Observation = nil
			result.Query = &GCPreviewQueryIdentity{PublicQueryBasis: initial, Cursor: request.Cursor, ProposedOperationID: request.OperationID, Digest: out.RequestIdentity}
		}
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, f))
		result.Payload = nil
		return result
	}
	if failed.Outcome != 0 {
		return fail(failed)
	}
	defer inv.Close()
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	selected, facts, failed := r.load(ctx, inv, false)
	if failed.Outcome != 0 {
		return fail(failed)
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	for _, group := range selected.image.adminIndex.Groups {
		if group.GroupID == request.OperationID {
			return fail(readerRefusal(contract.ReasonInvalidInput))
		}
	}
	page, failed := r.observePage(ctx, inv, selected, facts, cursor)
	if failed.Outcome != 0 {
		return fail(failed)
	}
	next, err := DecodeGCCursor(page.NextCursor, inv.admission.domain, inv.admission.store)
	if err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidFormat)))
	}
	pins, err := gcSourcePinsDigest(r.pins)
	if err != nil {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	observation := inspectionObservation(selected)
	plan := contract.GCPlan{DomainID: inv.admission.domain, OperationID: request.OperationID, RequestNonce: request.RequestNonce,
		StoreDescriptorDigest: q.StoreDescriptorDigest, PublicBasisDigest: q.PublicBasisDigest, SourcePinsDigest: pins,
		HeadRevisionID: observation.HeadRevisionID, FullHEADDigest: contract.Hash(selected.basis.anchor.headBody), SnapshotID: observation.SnapshotID, RootDigest: observation.RootDigest,
		MarkDigest: page.MarkDigest, EnumerationDigest: page.EnumerationDigest, TargetsDigest: page.Targets.Digest, PredecessorToken: selected.basis.anchor.headToken,
		InputProviderCursor: cursor, NextProviderCursor: next, Targets: page.EligibleTargets, Candidates: page.Candidates}
	encoded, err := contract.EncodeGCPlan(plan)
	if err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	identity, err := contract.GCPlanRequestIdentity(plan)
	if err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	q.Observation = &observation
	digest, ok := gcQueryDigest(q, request.Cursor, request.OperationID, page.MarkDigest, page.EnumerationDigest)
	if !ok {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	result.Query = &GCPreviewQueryIdentity{PublicQueryBasis: q, Cursor: request.Cursor, ProposedOperationID: request.OperationID, MarkDigest: page.MarkDigest, EnumerationDigest: page.EnumerationDigest, Digest: digest}
	result.PublicQueryResult = successfulInspectionQuery(out, observation, digest)
	result.Payload = &GCPreviewPayload{Observation: observation, Plan: plan, EncodedPlan: encoded, PlanDigest: contract.Hash(encoded), RequestIdentity: identity, Garbage: page}
	if err := result.Validate(); err != nil {
		return fail(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
	}
	if r.checkSource(ctx) != nil {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return fail(failed)
	}
	return result
}

// ValidatedGCPlan owns public preflight facts. Its source owner must remain open
// until the mutation consumes it; no target body or private capability is retained.
type ValidatedGCPlan struct {
	issued                                                 bool
	used                                                   atomic.Bool
	plan                                                   contract.GCPlan
	encoded, head                                          []byte
	root                                                   contract.Ref
	descriptor                                             contract.Descriptor
	pins                                                   AdministrativeSourcePins
	publicBasisDigest                                      contract.ID
	observation                                            PublicObservation
	deadline                                               time.Time
	done                                                   <-chan struct{}
	reader                                                 *InstalledCapacityReader
	targetsChecked, equalHeadRechecked, emptyHeadRechecked bool
}

func (v *ValidatedGCPlan) current(ctx context.Context) bool {
	if v == nil || !v.issued || ctx == nil || ctx.Err() != nil || ctx.Done() != v.done || !validPrivateDeadline(v.deadline) || v.reader == nil || v.reader.reader == nil || !v.targetsChecked || !v.equalHeadRechecked {
		return false
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(v.deadline) {
		return false
	}
	v.reader.reader.mu.Lock()
	closed := v.reader.reader.closed
	v.reader.reader.mu.Unlock()
	return !closed && v.reader.checkSource(ctx) == nil
}

func (v *ValidatedGCPlan) consume(ctx context.Context) bool {
	return v.current(ctx) && v.used.CompareAndSwap(false, true)
}

func gcEqualHEAD(ctx context.Context, physical gcPhysicalReader, selected publicSelection) Result {
	read := gcReadExact(ctx, physical, selected.basis.reader.descriptor.HeadKey, contract.MaxHeadLength)
	checked := ownCandidateRead(read, contract.MaxHeadLength, nil, 0)
	if checked.Status != contract.ReadOK {
		return candidateReadFailure(checked, true)
	}
	if checked.Token != selected.basis.anchor.headToken || !bytes.Equal(checked.Body, selected.basis.anchor.headBody) {
		return failure(Contention, DifferentSelection)
	}
	return Result{}
}

// ValidateGCPlan performs the sole fresh target preflight before lazy mutation
// construction. It never lists again and cannot rebase a stale artifact.
func (r *InstalledCapacityReader) ValidateGCPlan(ctx context.Context, encoded []byte) (validated *ValidatedGCPlan, result Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGCValidatePlan)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	validated, result = r.validateGCPlan(telemetry.CallContext(ctx, call), encoded, call)
	finishCore(call, result)
	return validated, result
}

func (r *InstalledCapacityReader) validateGCPlan(ctx context.Context, encoded []byte, call *telemetry.Call) (validated *ValidatedGCPlan, result Result) {
	if r == nil || r.reader == nil {
		return nil, refused(AdmissionInvalid)
	}
	plan, err := contract.DecodeGCPlan(encoded)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	request, err := contract.GCPlanRequestIdentity(plan)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	inv, failed := r.reader.beginReaderInvocation(ctx, gcPlanValidationOperation, request)
	if failed.Outcome != 0 {
		return nil, failed.Result
	}
	defer inv.Close()
	if ValidateGCPlanScope(plan, inv.admission.domain, inv.admission.store, r.reader.publicBasis, r.pins) != nil || r.checkSource(ctx) != nil {
		return nil, refused(AdmissionInvalid)
	}
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	selected, facts, failed := r.load(ctx, inv, false)
	if failed.Outcome != 0 {
		return nil, failed.Result
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	anchor := selected.basis.anchor
	if plan.FullHEADDigest != contract.Hash(anchor.headBody) || plan.HeadRevisionID != anchor.head.Core.Revision || plan.PredecessorToken != anchor.headToken || plan.SnapshotID != selected.image.root.Snapshot || plan.RootDigest != anchor.head.Core.Root.Digest {
		return nil, failure(Contention, DifferentSelection)
	}
	mark, err := facts.marks.digest(inv.admission.store, inv.admission.domain, contract.Hash(anchor.headBody))
	if err != nil || mark != plan.MarkDigest {
		return nil, refused(InvalidRelation)
	}
	physical, err := newGCPhysicalReader(ctx, inv.source)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	if checked := gcValidateTargets(ctx, physical, inv.admission.store, plan, facts.marks); checked.Outcome != 0 {
		return nil, checked
	}
	if r.checkSource(ctx) != nil {
		return nil, refused(AdmissionInvalid)
	}
	if checked := gcEqualHEAD(ctx, physical, selected); checked.Outcome != 0 {
		return nil, checked
	}
	if r.checkSource(ctx) != nil {
		return nil, refused(AdmissionInvalid)
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return nil, failed.Result
	}
	validated = &ValidatedGCPlan{issued: true, plan: plan, encoded: bytes.Clone(encoded), head: bytes.Clone(anchor.headBody), root: anchor.head.Core.Root, descriptor: inv.admission.store, pins: r.pins,
		publicBasisDigest: inv.admission.basis.digest, observation: inspectionObservation(selected), deadline: inv.admission.deadline, done: ctx.Done(), reader: r,
		targetsChecked: true, equalHeadRechecked: true, emptyHeadRechecked: len(plan.Targets) == 0}
	return validated, Result{Outcome: ObservedCurrent, ObservedRevision: plan.HeadRevisionID, ObservedSnapshotID: plan.SnapshotID, Evidence: AuthenticatedClosure}
}
