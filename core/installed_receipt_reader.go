package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

type ReceiptReadInstallation struct {
	Candidate      PublicCandidateReader
	Construct      func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result)
	ExpectedDomain contract.ID
	ExpectedStore  contract.Descriptor
	PublicBasis    PublicBasis
	CompositionID  contract.ID
	SourcePins     AdministrativeSourcePins
	CheckSource    func(context.Context) error
	CloseInstalled func()
}

type InstalledReceiptReader struct {
	reader      *ReaderEngine
	composition contract.ID
	pins        AdministrativeSourcePins
	checkSource func(context.Context) error
}

// NewInstalledReceiptReader qualifies local public inputs only. Success
// transfers CloseInstalled ownership; each constructed GET source closes once.
func NewInstalledReceiptReader(i ReceiptReadInstallation) (*InstalledReceiptReader, error) {
	if i.CompositionID.IsZero() || !i.SourcePins.Valid() || i.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	reader, err := newInstalledPublicReader(ReaderInstallation{Candidate: i.Candidate, Construct: i.Construct,
		ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, CloseInstalled: i.CloseInstalled})
	if err != nil {
		return nil, err
	}
	return &InstalledReceiptReader{reader: reader, composition: i.CompositionID, pins: i.SourcePins, checkSource: i.CheckSource}, nil
}

func (r *InstalledReceiptReader) Close() {
	if r != nil && r.reader != nil {
		r.reader.Close()
	}
}

type ReceiptListRequest struct{ RequestNonce contract.ID }
type ReceiptDetailRequest struct{ RequestNonce, OperationID contract.ID }

type ReceiptListQueryIdentity struct {
	PublicQueryBasis
	Digest contract.ID
}
type ReceiptDetailQueryIdentity struct {
	PublicQueryBasis
	RequestedOperationID, Digest contract.ID
}

type ReceiptSummary struct {
	OperationID                             contract.ID
	OperationKind                           uint16
	CanonicalOutcome                        uint8
	StateResult                             uint16
	ObservedRevisionID, RequestedRevisionID contract.ID
	WarningBits                             uint64
	EvidenceCeiling                         uint16
}

type ReceiptListPayload struct {
	Observation              PublicObservation
	CurrentDomainWarningBits uint8
	CurrentWarnings          PublicDomainWarnings
	Receipts                 []ReceiptSummary
}

type ReceiptDetailPayload struct {
	Observation              PublicObservation
	CurrentDomainWarningBits uint8
	CurrentWarnings          PublicDomainWarnings
	Receipt                  contract.CompactMutationReceipt
	EncodedReceipt           []byte
	Authenticity, Retention  string
}

type PublicReceiptListResult struct {
	PublicQueryResult
	Query   *ReceiptListQueryIdentity
	Payload *ReceiptListPayload
}

type PublicReceiptDetailResult struct {
	PublicQueryResult
	Query   *ReceiptDetailQueryIdentity
	Payload *ReceiptDetailPayload
}

func receiptSummary(row contract.CompactMutationReceipt) ReceiptSummary {
	return ReceiptSummary{row.OperationID, row.OperationKind, row.CanonicalOutcome, row.StateResult,
		row.ObservedRevisionID, row.RequestedRevisionID, row.WarningBits, row.EvidenceCeiling}
}

func projectReceiptList(state *StateSession) ([]ReceiptSummary, error) {
	windows, _, err := state.retainedMutationReceiptBodies()
	if err != nil {
		return nil, err
	}
	byID := make(map[contract.ID]contract.CompactMutationReceipt, len(windows.Order))
	for _, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, row := range rows {
			byID[row.OperationID] = row
		}
	}
	rows := make([]ReceiptSummary, 0, len(windows.Order))
	for i := len(windows.Order) - 1; i >= 0; i-- {
		rows = append(rows, receiptSummary(byID[windows.Order[i]]))
	}
	return rows, nil
}

func (r *InstalledReceiptReader) begin(ctx context.Context, operation string, nonce, selector contract.ID) (PublicQueryResult, PublicQueryBasis, *readerInvocation, readerFailure) {
	out := PublicQueryResult{Operation: operation, RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: PublicQueryRefused, FailureReason: contract.ReasonInvalidInput}
	if r == nil || r.reader == nil {
		return out, PublicQueryBasis{}, nil, readerRefusal(contract.ReasonInvalidInput)
	}
	out.DomainID = r.reader.expectedDomain
	q, ok := newPublicQueryBasis(r.reader, r.pins, operation, 16, nonce)
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
	if r.checkSource(ctx) != nil {
		failed = readerRefusal(contract.ReasonInvalidInput)
	}
	if failed = publicQueryFailure(ctx, inv, failed); failed.Outcome != 0 {
		return out, q, nil, failed
	}
	transferred = true
	return out, q, inv, readerFailure{}
}

func (r *InstalledReceiptReader) load(ctx context.Context, inv *readerInvocation) (*StateSession, readerFailure) {
	basis, failed := inv.loadPublicReadBasis(ctx, inv.admission.operation, inv.admission.request)
	if failed.Outcome != 0 {
		return nil, publicQueryFailure(ctx, inv, failed)
	}
	store := administrativeReadStore{source: inv.source}
	admitted, result := admitQualifiedPublicNormal(ctx, inv.admission.domain, inv.admission.store, inv.admission.basis, store, r.composition, nil)
	if result.Outcome != ObservedCurrent {
		return nil, publicQueryFailure(ctx, inv, readerSelectionFailure(result))
	}
	key, ok := publicKey(admitted.admission.publicKey)
	if !ok {
		return nil, publicQueryFailure(ctx, inv, readerSelectionFailure(failure(IntegrityFailure, InvalidProof)))
	}
	state := &StateSession{admission: *admitted.admission, store: store, key: key, administrativeReceiptRead: true,
		cache: map[format.Ref][]byte{basis.anchor.head.Core.Root: basis.anchor.rootBody}}
	loaded, result := state.readImageFromHead(ctx, authenticatedHead{head: basis.anchor.head, body: basis.anchor.headBody, token: basis.anchor.headToken}, true, true)
	if result.Outcome != ObservedCurrent {
		return nil, publicQueryFailure(ctx, inv, readerSelectionFailure(result))
	}
	if loaded.head.AuthKind == format.GenesisAuth {
		descriptor, ok := loaded.admission.domainBasis()
		if !ok || !loaded.validGenesisSelection(descriptor) || !selectedHeadProofs(loaded.head, currentControlOf(loaded), &descriptor) {
			return nil, publicQueryFailure(ctx, inv, readerSelectionFailure(failure(IntegrityFailure, InvalidProof)))
		}
	}
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return nil, failed
	}
	return loaded, readerFailure{}
}

func (r *InstalledReceiptReader) finishRead(ctx context.Context, inv *readerInvocation) readerFailure {
	if failed := publicQueryFailure(ctx, inv, readerFailure{}); failed.Outcome != 0 {
		return failed
	}
	var failed readerFailure
	if r.checkSource(ctx) != nil {
		failed = readerRefusal(contract.ReasonInvalidInput)
	}
	return publicQueryFailure(ctx, inv, failed)
}

func receiptObservation(state *StateSession) PublicObservation {
	return PublicObservation{state.root.Domain, state.head.Core.Revision, state.root.Snapshot, state.head.Core.Root.Digest}
}

func (r *InstalledReceiptReader) List(ctx context.Context, request ReceiptListRequest) PublicReceiptListResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReceiptList)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	ctx = telemetry.CallContext(ctx, call)
	out, q, inv, failed := r.begin(ctx, ReceiptListOperation, request.RequestNonce, contract.ID{})
	result := PublicReceiptListResult{PublicQueryResult: out}
	if !out.RequestIdentity.IsZero() {
		result.Query = &ReceiptListQueryIdentity{q, out.RequestIdentity}
	}
	defer func() { finishPublicQueryCall(call, result.PublicQueryResult) }()
	if failed.Outcome != 0 {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, failed))
		return result
	}
	defer inv.Close()
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	state, failed := r.load(ctx, inv)
	if failed.Outcome != 0 {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, failed))
		return result
	}
	rows, err := projectReceiptList(state)
	if err != nil {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))))
		return result
	}
	observation := receiptObservation(state)
	result.Query.Observation = &observation
	digest, ok := result.Query.digest(contract.ID{})
	if !ok {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, readerRefusal(contract.ReasonInvalidInput)))
		return result
	}
	result.Query.Digest, result.RequestIdentity, result.OperationID = digest, digest, publicQueryOperationID(digest)
	if failed := r.finishRead(ctx, inv); failed.Outcome != 0 {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, failed))
		return result
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	result.Result, result.StateResult, result.FailureReason = state.observed(ObservedCurrent), PublicQuerySuccess, ""
	result.Payload = &ReceiptListPayload{observation, state.root.WarningBits, publicDomainWarnings(state.root.WarningBits), rows}
	return result
}

func (r *InstalledReceiptReader) Detail(ctx context.Context, request ReceiptDetailRequest) PublicReceiptDetailResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReceiptDetail)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	ctx = telemetry.CallContext(ctx, call)
	out, q, inv, failed := r.begin(ctx, ReceiptDetailOperation, request.RequestNonce, request.OperationID)
	result := PublicReceiptDetailResult{PublicQueryResult: out}
	if !out.RequestIdentity.IsZero() {
		result.Query = &ReceiptDetailQueryIdentity{q, request.OperationID, out.RequestIdentity}
	}
	defer func() { finishPublicQueryCall(call, result.PublicQueryResult) }()
	if failed.Outcome != 0 {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, failed))
		return result
	}
	defer inv.Close()
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	state, failed := r.load(ctx, inv)
	if failed.Outcome != 0 {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, failed))
		return result
	}
	row, body, found, err := state.retainedMutationReceipt(request.OperationID)
	if err != nil {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))))
		return result
	}
	observation := receiptObservation(state)
	result.Query.Observation = &observation
	digest, ok := result.Query.digest(request.OperationID)
	if !ok {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, readerRefusal(contract.ReasonInvalidInput)))
		return result
	}
	result.Query.Digest, result.RequestIdentity, result.OperationID = digest, digest, publicQueryOperationID(digest)
	if failed := r.finishRead(ctx, inv); failed.Outcome != 0 {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, failed))
		return result
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	if !found {
		setPublicQueryFailure(&result.PublicQueryResult, publicQueryFailure(ctx, inv, readerSelectionFailure(failure(EvidenceUnavailable, MissingSelectedObject))))
		return result
	}
	result.Result, result.StateResult, result.FailureReason = state.observed(ObservedCurrent), PublicQuerySuccess, ""
	result.Payload = &ReceiptDetailPayload{observation, state.root.WarningBits, publicDomainWarnings(state.root.WarningBits), row, body, "authenticated-retained", "retained"}
	return result
}
