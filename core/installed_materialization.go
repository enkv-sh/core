package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// MaterializationCustody completes all native work and cleanup before returning
// its safe facts. Close cancels and joins retained work and releases custody.
type MaterializationCustody interface {
	Materialize(context.Context) contract.MaterializationCompletion
	Close()
}

type MaterializationInstallation struct {
	Reader          ReaderInstallation
	SourcePins      AdministrativeSourcePins
	CheckSource     func(context.Context) error
	CredentialRoute contract.ID
	Target          contract.MaterializationTarget
	AdmitCustody    func(context.Context, contract.MaterializationAdmission) (MaterializationCustody, error)
}

type InstalledMaterialization struct {
	mu           sync.Mutex
	reader       *ReaderEngine
	installation MaterializationInstallation
	used, closed bool
	activeDone   chan struct{}
	cancel       context.CancelFunc
	closeOnce    sync.Once
}

func NewInstalledMaterialization(i MaterializationInstallation) (*InstalledMaterialization, error) {
	if !materializationSourcePins(i.SourcePins).Valid() || i.CheckSource == nil || i.CredentialRoute.IsZero() || !i.Target.Valid() || i.AdmitCustody == nil {
		return nil, contract.ErrRecord
	}
	reader, err := newInstalledPublicReader(i.Reader)
	if err != nil {
		return nil, err
	}
	i.Target.Path = strings.Clone(i.Target.Path)
	i.Target.Format = strings.Clone(i.Target.Format)
	i.Target.NativeProfile = strings.Clone(i.Target.NativeProfile)
	i.Reader = ReaderInstallation{}
	return &InstalledMaterialization{reader: reader, installation: i}, nil
}

type MaterializationResult struct {
	Operation                                         string
	RequestID, OperationID, RequestIdentity, DomainID contract.ID
	PreAdmission                                      *PreAdmissionRequestIdentity
	Result                                            Result
	StateResult                                       contract.MaterializationStateResult
	Failure                                           *contract.MaterializationFailure
	Payload                                           *contract.MaterializationPayload
}

func newMaterializationResult(nonce contract.ID) MaterializationResult {
	return MaterializationResult{Operation: contract.MaterializationOperation, RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: contract.MaterializationRefused, Failure: &contract.MaterializationFailure{Stage: contract.MaterializationAdmissionStage, Reason: contract.MaterializationInvalidRequest}}
}

func materializationOperationID(identity contract.ID) contract.ID {
	return contract.Hash(append([]byte("ENKV/materialization-operation/v1\x00"), identity[:]...))
}

func (r MaterializationResult) Validate() error {
	if r.Operation != contract.MaterializationOperation || !r.StateResult.Valid() || r.Result != materializationCoreResult(r.StateResult, r.Payload) {
		return contract.ErrRecord
	}
	if p := r.PreAdmission; p != nil {
		if !r.RequestIdentity.IsZero() || r.OperationID.IsZero() || r.Payload != nil || p.RequestNonce != r.RequestID || p.Stage == "" || p.Code == "" || p.SourceSchema == "" || p.SourceProfile == "" {
			return contract.ErrRecord
		}
	} else if r.RequestIdentity.IsZero() != r.OperationID.IsZero() || !r.RequestIdentity.IsZero() && (r.DomainID.IsZero() || r.OperationID != materializationOperationID(r.RequestIdentity)) {
		return contract.ErrRecord
	}
	if r.StateResult == contract.MaterializationSuccess {
		if r.Failure != nil || r.Payload == nil {
			return contract.ErrRecord
		}
	} else if r.Failure == nil || !r.Failure.Valid() {
		return contract.ErrRecord
	}
	if r.Payload != nil {
		if r.Payload.RequestIdentity != r.RequestIdentity || r.Payload.DomainID != r.DomainID || !reflect.DeepEqual(r.Payload.Facts.Failure, r.Failure) {
			return contract.ErrRecord
		}
		return r.Payload.Validate(r.StateResult)
	}
	if r.Failure == nil || !r.Failure.Stage.BeforeStaging() {
		return contract.ErrRecord
	}
	facts := contract.InitialMaterializationFacts()
	facts.Failure = r.Failure
	return (contract.MaterializationCompletion{StateResult: r.StateResult, Facts: facts}).Validate()
}

func materializationFailureClass(f readerFailure) (contract.MaterializationStateResult, contract.MaterializationFailureReason) {
	switch {
	case f.Outcome == RootLossUnsupported:
		return contract.MaterializationRootLossUnsupported, contract.MaterializationRootLoss
	case f.Outcome == Contention:
		return contract.MaterializationUnavailable, contract.MaterializationChangingSelection
	case f.Outcome == IntegrityFailure:
		return contract.MaterializationPositiveDefect, contract.MaterializationIntegrityContradiction
	case f.diagnostic == contract.ReasonCancelled:
		return contract.MaterializationUnavailable, contract.MaterializationCanceled
	case f.diagnostic == contract.ReasonExpired:
		return contract.MaterializationRefused, contract.MaterializationDeadlineExceeded
	case f.diagnostic == contract.ReasonUnsupportedProfile || f.diagnostic == contract.ReasonUnsupportedSchema:
		return contract.MaterializationProfileBlocked, contract.MaterializationProfileUnqualified
	case f.Outcome == EvidenceUnavailable:
		return contract.MaterializationUnavailable, contract.MaterializationRequiredReadUnavailable
	case f.diagnostic == contract.ReasonTargetAbsent || f.diagnostic == contract.ReasonTargetNotAuthorized:
		return contract.MaterializationRefused, contract.MaterializationUnauthorizedSelection
	case f.diagnostic == contract.ReasonEntryAbsent:
		return contract.MaterializationRefused, contract.MaterializationMissingSelection
	case f.diagnostic == contract.ReasonLimitExceeded || f.Reason == CapacityExceeded:
		return contract.MaterializationRefused, contract.MaterializationCapacityLimit
	default:
		return contract.MaterializationRefused, contract.MaterializationInvalidRequest
	}
}

func (r *MaterializationResult) fail(f readerFailure, stage contract.MaterializationStage) {
	state, reason := materializationFailureClass(f)
	r.StateResult = state
	r.Failure = &contract.MaterializationFailure{Stage: stage, Reason: reason}
	r.setStateResult()
	if r.Payload != nil {
		r.Payload.Facts.Failure = r.Failure
	}
}

func materializationCoreResult(state contract.MaterializationStateResult, payload *contract.MaterializationPayload) Result {
	var result Result
	switch state {
	case contract.MaterializationSuccess:
		result = Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure}
	case contract.MaterializationRootLossUnsupported:
		result = failure(RootLossUnsupported, MissingSelectedObject)
	case contract.MaterializationUnavailable:
		result = failure(EvidenceUnavailable, CustodyUnavailable)
	case contract.MaterializationPositiveDefect:
		result = failure(IntegrityFailure, InvalidRelation)
	default:
		result = refused(AdmissionInvalid)
	}
	if payload != nil {
		result.ObservedRevision = payload.HEADRevision
		result.ObservedSnapshotID = payload.SnapshotID
		result.Evidence = AuthenticatedClosure
	}
	return result
}
func (r *MaterializationResult) setStateResult() {
	r.Result = materializationCoreResult(r.StateResult, r.Payload)
}

func (e *InstalledMaterialization) Materialize(ctx context.Context, request contract.MaterializationRequest) MaterializationResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreMaterialize)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	result := e.materialize(telemetry.CallContext(ctx, call), request, call)
	finishCore(call, result.Result)
	return result
}

func (e *InstalledMaterialization) materialize(ctx context.Context, request contract.MaterializationRequest, call *telemetry.Call) (out MaterializationResult) {
	out = newMaterializationResult(request.RequestNonce)
	if e == nil || ctx == nil {
		return out
	}
	e.mu.Lock()
	if e.closed || e.used || e.reader == nil {
		e.mu.Unlock()
		return out
	}
	e.used = true
	i, reader := e.installation, e.reader
	out.DomainID = reader.expectedDomain
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	e.cancel, e.activeDone = cancel, done
	e.mu.Unlock()
	defer func() { cancel(); e.mu.Lock(); e.cancel, e.activeDone = nil, nil; close(done); e.mu.Unlock() }()
	owned, err := contract.OwnMaterializationRequest(request)
	if err != nil {
		return out
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) || ctx.Err() != nil {
		failed := readerRefusal(contract.ReasonExpired)
		if ctx.Err() == context.Canceled {
			failed = readerRefusal(contract.ReasonCancelled)
		}
		out.fail(failed, contract.MaterializationAdmissionStage)
		return out
	}
	basisDigest, reason := readerPublicBasisDigest(reader.publicBasis, reader.expectedDomain, reader.expectedStore)
	if reason != "" {
		out.fail(readerRefusal(reason), contract.MaterializationAdmissionStage)
		return out
	}
	invocationID := materializationInvocationIdentity(owned, reader, basisDigest, i, deadline)
	inv, failed := reader.beginReaderInvocation(ctx, contract.MaterializationOperation, invocationID)
	if failed.Outcome != 0 {
		out.fail(failed, contract.MaterializationAdmissionStage)
		return out
	}
	defer inv.Close()
	if i.CheckSource(ctx) != nil {
		out.fail(readerRefusal(contract.ReasonInvalidInput), contract.MaterializationAdmissionStage)
		return out
	}
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	selected, failed := inv.loadMaterializationSelection(ctx, invocationID, call)
	if failed.Outcome != 0 {
		out.fail(failed, contract.MaterializationLoad)
		return out
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	admission, payload, failed := materializationAdmissionForSelection(ctx, &selected, invocationID, basisDigest, i, owned)
	if failed.Outcome != 0 {
		out.fail(failed, contract.MaterializationAdmissionStage)
		return out
	}
	out.RequestIdentity = admission.RequestID
	out.OperationID = materializationOperationID(out.RequestIdentity)
	out.Payload = payload
	if i.CheckSource(ctx) != nil {
		out.fail(readerRefusal(contract.ReasonInvalidInput), contract.MaterializationAdmissionStage)
		return out
	}
	if reason := inv.admission.failure(ctx, contract.MaterializationOperation, invocationID); reason != "" {
		out.fail(readerRefusal(reason), contract.MaterializationAdmissionStage)
		return out
	}
	inv.selection = publicSelection{}
	selected = publicSelection{}
	inv.source.Close()
	inv.source = nil
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	private, err := i.AdmitCustody(ctx, admission)
	if err != nil || private == nil {
		if private != nil {
			private.Close()
		}
		code := contract.CryptoInvalidAdmission
		var typed contract.MaterializationAdmissionError
		if errors.As(err, &typed) {
			code = typed.Code
		}
		failure := planningCryptoFailure(code)
		out.fail(failure, contract.MaterializationAuthentication)
		if code == contract.CryptoPrivateRouteUnavailable || code == contract.CryptoCustodyUnavailable || code == contract.CryptoResponseUnknown {
			out.Failure.Reason = contract.MaterializationPrivateRouteUnavailable
		}
		if code == contract.CryptoInvalidAdmission || code == contract.CryptoAlreadyUsed {
			out.Failure.Reason = contract.MaterializationInvalidAdmission
		}
		return out
	}
	completion := func() contract.MaterializationCompletion {
		defer private.Close()
		return private.Materialize(ctx)
	}()
	if completion.Validate() != nil {
		completion.StateResult = contract.MaterializationUnavailable
		if completion.Facts.NativeCompletion == contract.MaterializationComplete {
			completion.Facts.NativeCompletion = contract.MaterializationIncomplete
		}
		if completion.Facts.Failure == nil {
			completion.Facts.Failure = &contract.MaterializationFailure{Stage: contract.MaterializationSinkClose, Reason: contract.MaterializationIntegrityContradiction}
		}
	}
	out.StateResult = completion.StateResult
	out.Payload.Facts = completion.Facts
	out.Failure = completion.Facts.Failure
	out.setStateResult()
	return out
}

func materializationInvocationIdentity(request contract.MaterializationRequest, reader *ReaderEngine, basis contract.ID, i MaterializationInstallation, deadline time.Time) contract.ID {
	h := sha256.New()
	h.Write([]byte("ENKV/materialization-invocation/v2\x00"))
	for _, value := range []any{contract.MaterializationOperation, request, reader.expectedDomain, reader.expectedStore, basis, i.SourcePins, i.CredentialRoute, i.Target, uint64(deadline.UnixNano())} {
		hashPublicSemantic(h, reflect.ValueOf(value))
	}
	return contract.ID(h.Sum(nil))
}

func materializationProjectionIdentity(invocationID contract.ID, admission contract.MaterializationAdmission, entries []contract.MaterializationEntryIdentity) contract.ID {
	h := sha256.New()
	h.Write([]byte("ENKV/materialization-projection/v2\x00"))
	for _, value := range []any{invocationID, admission.DomainID, admission.HEADDigest, admission.HEADRevision, admission.SnapshotID, admission.Recipient, entries, materializationEntryEncodings(admission.Entries)} {
		hashPublicSemantic(h, reflect.ValueOf(value))
	}
	return contract.ID(h.Sum(nil))
}

func materializationSourcePins(p AdministrativeSourcePins) contract.MaterializationSourcePins {
	return contract.MaterializationSourcePins(p)
}

func materializationAdmissionForSelection(ctx context.Context, selected *publicSelection, invocationID, publicBasis contract.ID, i MaterializationInstallation, request contract.MaterializationRequest) (contract.MaterializationAdmission, *contract.MaterializationPayload, readerFailure) {
	invalid := func(f readerFailure) (contract.MaterializationAdmission, *contract.MaterializationPayload, readerFailure) {
		return contract.MaterializationAdmission{}, nil, f
	}
	if selected == nil || !selected.complete || !publicReadInvocationCurrent(ctx, selected.basis.anchor) {
		return invalid(readerRefusal(contract.ReasonInvalidInput))
	}
	owned, err := contract.OwnMaterializationRequest(request)
	if err != nil {
		return invalid(readerRefusal(contract.ReasonInvalidInput))
	}
	acting := owned.RecipientID
	if acting.IsZero() {
		acting = selected.authorityID
	}
	slots, result, reason := consumerMembershipSlots(&selected.image, owned.Names, acting)
	if result.Outcome != 0 {
		return invalid(readerFailure{Result: result, diagnostic: reason})
	}
	recipient := selected.image.recipientRecord(acting)
	binding := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: acting, Binding: *recipient.CurrentBinding}
	binding.Binding.SPKI = bytes.Clone(binding.Binding.SPKI)
	binding.Binding.KeySelector = strings.Clone(binding.Binding.KeySelector)
	anchor := selected.basis.anchor
	q := contract.MaterializationAdmission{Purpose: contract.MaterializationOperation, DomainID: selected.image.root.Domain,
		HEADDigest: contract.Hash(anchor.headBody), HEADRevision: anchor.head.Core.Revision, SnapshotID: selected.image.root.Snapshot, AccessRoot: selected.image.root.CurrentAccess.AccessRoot,
		CredentialRoute: i.CredentialRoute, PublicBasisDigest: publicBasis, Store: selected.basis.reader.descriptor, Root: anchor.head.Core.Root, HEADToken: anchor.headToken,
		SourcePins: materializationSourcePins(i.SourcePins), Recipient: binding, Target: i.Target, ExpiresAt: anchor.deadline, Entries: make([]contract.MaterializationEntry, 0, len(slots))}
	if _, err := rand.Read(q.SessionID[:]); err != nil || q.SessionID.IsZero() {
		return invalid(readerRefusal(contract.ReasonEvidenceUnavailable))
	}
	payload := &contract.MaterializationPayload{Schema: contract.MaterializationPayloadSchema, DomainID: q.DomainID, HEADRevision: q.HEADRevision, SnapshotID: q.SnapshotID,
		Recipient: binding, Target: q.Target, Entries: make([]contract.MaterializationEntryIdentity, 0, len(slots)), Facts: contract.InitialMaterializationFacts()}
	payload.Recipient.Binding.SPKI = bytes.Clone(binding.Binding.SPKI)
	for at, slot := range slots {
		entry := selected.image.valueEntry(slot)
		row := contract.MaterializationEntry{Name: owned.Names[at], Slot: slot, Entry: *entry}
		if entry.ConfidentialityClass == contract.Secret {
			core, value, access, ok := selectedValueFrom(q.DomainID, selected.image.root, &selected.image.pages, &selected.image.recipients, &selected.image.access, selected.materials.accessLocations, selected.materials.valueReaders, slot)
			digest, err := contract.PublicValueEntryDigest(q.DomainID, slot, *entry)
			if !ok || err != nil {
				return invalid(readerSelectionFailure(failure(IntegrityFailure, InvalidRelation)))
			}
			row.Secret = &contract.ConsumerSelection{DomainID: q.DomainID, SnapshotID: q.SnapshotID, HEADDigest: q.HEADDigest, AccessRoot: q.AccessRoot, EntryDigest: digest, Root: q.Root, HEADRevision: q.HEADRevision, HEADToken: q.HEADToken, Slot: slot, Entry: *entry, Core: core, Payload: value, Access: access, Binding: binding}
		}
		q.Entries = append(q.Entries, row)
		payload.Entries = append(payload.Entries, contract.MaterializationEntryIdentity{Name: strings.Clone(entry.Name), Slot: slot, EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState, ValueSource: entry.ValueSource, ConfidentialityClass: entry.ConfidentialityClass})
	}
	q.RequestID = materializationProjectionIdentity(invocationID, q, payload.Entries)
	payload.RequestIdentity = q.RequestID
	return q, payload, readerFailure{}
}

func (e *InstalledMaterialization) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	cancel, done := e.cancel, e.activeDone
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	e.closeOnce.Do(func() { e.reader.Close(); e.mu.Lock(); e.installation = MaterializationInstallation{}; e.mu.Unlock() })
}

func materializationEntryEncodings(entries []contract.MaterializationEntry) []uint8 {
	encodings := make([]uint8, len(entries))
	for i, entry := range entries {
		encodings[i] = entry.Entry.OutputEncoding
	}
	return encodings
}
