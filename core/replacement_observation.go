package core

import (
	"bytes"
	"context"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

type ReplacementObservationInstallation struct {
	ExpectedDomain                  contract.ID
	ExpectedStore                   contract.Descriptor
	SourceBasis, SuccessorBasis     PublicBasis
	SourcePins, OutputPins          AdministrativeSourcePins
	CompositionID                   contract.ID
	Correlation                     ReplacementCorrelation
	Goal                            RoleReplacementGoal
	RecipientBefore, RecipientAfter contract.KMSBinding
	Source                          PublicSelectedReader
	CheckSourceOutput               func(context.Context) error
}
type ReplacementObserver struct {
	mu            sync.Mutex
	input         ReplacementObservationInstallation
	before, after readerPublicBasis
	candidate     format.Head
	guard         *installedMutationGuard
	used, closed  bool
	done          chan struct{}
	cancel        context.CancelFunc
	closeOnce     sync.Once
	closeErr      error
}

// NewInstalledReplacementObserver qualifies only fixed public facts. On
// success it owns Source.Close. No provider read or identity allocation occurs.
func NewInstalledReplacementObserver(i ReplacementObservationInstallation) (*ReplacementObserver, error) {
	if i.Source == nil || i.CheckSourceOutput == nil || i.ExpectedDomain.IsZero() || !i.ExpectedStore.Valid() || i.Source.Descriptor() != i.ExpectedStore || i.CompositionID.IsZero() || !i.SourcePins.Valid() || !i.OutputPins.Valid() || i.SourcePins.FileID != i.OutputPins.FileID || i.SourcePins.Format != i.OutputPins.Format {
		return nil, contract.ErrRecord
	}
	if _, _, _, ok := replacementReadOperation(i.Correlation.Target); !ok {
		return nil, contract.ErrRecord
	}
	if len(i.Correlation.SignedCandidate) > contract.MaxHeadLength {
		return nil, contract.ErrRecordCapacity
	}
	source, err := i.SourceBasis.own()
	if err != nil {
		return nil, err
	}
	successor, err := i.SuccessorBasis.own()
	if err != nil {
		return nil, err
	}
	i.SourceBasis, i.SuccessorBasis = source, successor
	before, reason := qualifyBorrowedReaderPublicBasis(source, i.ExpectedDomain, i.ExpectedStore)
	if reason != "" {
		return nil, contract.ErrRecord
	}
	after, reason := qualifyBorrowedReaderPublicBasis(successor, i.ExpectedDomain, i.ExpectedStore)
	if reason != "" {
		return nil, contract.ErrRecord
	}
	if i.Correlation.Target == ReplacementTargetRecipient {
		beforeBody, err := contract.EncodeKMSBinding(i.RecipientBefore)
		if err != nil {
			return nil, err
		}
		afterBody, err := contract.EncodeKMSBinding(i.RecipientAfter)
		if err != nil {
			return nil, err
		}
		i.RecipientBefore, err = contract.DecodeKMSBinding(beforeBody)
		if err != nil {
			return nil, err
		}
		i.RecipientAfter, err = contract.DecodeKMSBinding(afterBody)
		if err != nil {
			return nil, err
		}
	}
	i.Correlation.SignedCandidate = bytes.Clone(i.Correlation.SignedCandidate)
	candidate, err := format.DecodeHead(i.Correlation.SignedCandidate)
	if err != nil || candidate.Core.Form != format.SuccessorHead || !qualifyReplacementObservation(i, before, after, candidate) {
		return nil, contract.ErrRecord
	}
	guard, err := newInstalledMutationGuard(administrativeReadStore{source: i.Source}, i.CheckSourceOutput)
	if err != nil {
		return nil, err
	}
	return &ReplacementObserver{input: i, before: before, after: after, candidate: candidate, guard: guard}, nil
}
func (p *ReplacementObserver) query(nonce contract.ID) *ReplacementQueryIdentity {
	i := p.input
	op, semantic, stored, _ := replacementReadOperation(i.Correlation.Target)
	q := &ReplacementQueryIdentity{Schema: "QueryRequestIdentity/v1", Operation: op, SemanticOperation: semantic, ExpectedDomain: i.ExpectedDomain, StoreID: i.ExpectedStore.Identity, CoordinateID: i.ExpectedStore.Coordinate, NonBodyID: i.ExpectedStore.NonBody, StoreDescriptorDigest: administrativeStoreDescriptorDigest(i.ExpectedStore), SourceBasisDigest: p.before.digest, SuccessorBasisDigest: p.after.digest, SourcePins: i.SourcePins, OutputPins: i.OutputPins, RequestNonce: nonce, Target: i.Correlation.Target, Goal: i.Goal, OriginalRequestIdentity: i.Correlation.RequestIdentity, CandidateDigest: contract.Hash(i.Correlation.SignedCandidate), RequestedRevisionID: p.candidate.Core.Revision, RecipientID: i.Correlation.RecipientID}
	if p.candidate.Succession != nil {
		q.OriginalOperationID = p.candidate.Succession.Subject.OperationID
	} else {
		q.OriginalOperationID = p.candidate.Subject.Operation
	}
	if semantic == 16 {
		q.RequiredStoredKind = stored
	}
	if digest, ok := q.digest(); ok {
		q.Digest = digest
		return q
	}
	return nil
}
func (p *ReplacementObserver) begin(ctx context.Context, nonce contract.ID) (context.Context, func(), PublicReplacementObservationResult, bool) {
	out := PublicReplacementObservationResult{RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: contract.ReaderRefused}
	if p == nil {
		return nil, nil, out, false
	}
	i := p.input
	out.Operation, _, out.UnderlyingOperation, _ = replacementReadOperation(i.Correlation.Target)
	out.Target = i.Correlation.Target
	out.DomainID = i.ExpectedDomain
	out.Correlation = i.Correlation
	out.Correlation.SignedCandidate = bytes.Clone(i.Correlation.SignedCandidate)
	out.Query = p.query(nonce)
	if out.Query != nil {
		out.RequestIdentity = out.Query.Digest
		body := append([]byte("ENKV/replacement-query-operation/v1\x00"), nonce[:]...)
		body = append(body, i.ExpectedDomain[:]...)
		body = append(body, byte(i.Correlation.Target))
		out.OperationID = contract.Hash(body)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.used {
		return nil, nil, out, false
	}
	p.used = true
	deadline, finite := time.Time{}, false
	if ctx != nil {
		deadline, finite = ctx.Deadline()
	}
	if ctx == nil || ctx.Err() != nil || !finite || !validPrivateDeadline(deadline) || out.Query == nil {
		return nil, nil, out, false
	}
	owned, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	p.cancel, p.done = cancel, done
	finish := func() { cancel(); p.mu.Lock(); p.cancel, p.done = nil, nil; close(done); p.mu.Unlock() }
	return owned, finish, out, true
}
func (p *ReplacementObserver) base(ctx context.Context, basis readerPublicBasis) (*StateSession, Result) {
	admitted, result := admitQualifiedPublicNormal(ctx, p.input.ExpectedDomain, p.input.ExpectedStore, basis, p.guard.Store(), p.input.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		return nil, result
	}
	a := *admitted.admission
	key, ok := publicKey(a.publicKey)
	if !ok {
		return nil, refused(InvalidProof)
	}
	return &StateSession{admission: a, store: p.guard.Store(), key: key, administrativeReceiptRead: true, cache: make(map[format.Ref][]byte)}, Result{}
}
func replacementAlternativeProof(result Result) bool {
	return result.Outcome == EvidenceUnavailable && result.Reason == SigningUnavailable || result.Outcome == IntegrityFailure && (result.Reason == InvalidProof || result.Reason == ConstructionMismatch)
}
func (p *ReplacementObserver) load(ctx context.Context, q *ReplacementQueryIdentity) (*StateSession, Result) {
	source, result := p.base(ctx, p.before)
	if source == nil {
		return nil, result
	}
	captured := source.storeRead(ctx, p.input.ExpectedStore.HeadKey, contract.MaxHeadLength)
	if len(captured.Body) <= contract.MaxHeadLength {
		captured.Body = bytes.Clone(captured.Body)
	}
	primary, secondary := p.after, p.before
	primaryDigest, secondaryDigest := p.after.digest, p.before.digest
	if captured.Status == contract.ReadOK && len(captured.Body) <= contract.MaxHeadLength {
		parsed, err := format.DecodeHead(captured.Body)
		if err == nil && parsed.Core.Revision == p.candidate.Core.PreviousRevision && contract.Hash(captured.Body) == p.candidate.Core.PreviousDigest && captured.Token == p.candidate.Core.PreviousToken {
			primary, secondary = p.before, p.after
			primaryDigest, secondaryDigest = p.before.digest, p.after.digest
		}
	}
	chosen, result := p.base(ctx, primary)
	if chosen == nil {
		return nil, result
	}
	head, result := chosen.authenticateHeadResponse(ctx, captured)
	if result.Outcome != 0 && primaryDigest != secondaryDigest && replacementAlternativeProof(result) {
		alternate, admission := p.base(ctx, secondary)
		if alternate == nil {
			return nil, admission
		}
		checked, proof := alternate.authenticateHeadResponse(ctx, captured)
		if proof.Outcome != 0 {
			if result.Outcome == IntegrityFailure && result.Reason == InvalidProof && proof.Outcome == EvidenceUnavailable && proof.Reason == SigningUnavailable {

				parsed, err := format.DecodeHead(captured.Body)
				control, ok := chosen.admission.currentControl()
				if err == nil && ok && (chosen.admission.successionSelected(parsed) || !chosen.outOfBasisHeadKnownProofsValid(parsed, control)) {
					return nil, result
				}
			}
			return nil, proof
		}
		chosen, head, result, primaryDigest = alternate, checked, Result{}, secondaryDigest
	}
	if result.Outcome != 0 {
		return nil, result
	}
	q.AuthenticatedBasisDigest = primaryDigest
	// Only an exact predecessor tuple selects the old control before loading.
	// Unrelated old-basis advancement may remain unavailable. A closure failure
	// is terminal; no other basis or HEAD read is tried after this point.
	return chosen.readImageFromHead(ctx, head, true, true)
}

func (p *ReplacementObserver) Observe(ctx context.Context, nonce contract.ID) PublicReplacementObservationResult {
	operation := telemetry.OpCoreInspectSelectedWork
	if p != nil && p.input.Correlation.Target != ReplacementTargetAuthority {
		operation = telemetry.OpCoreMutationReceipt
	}
	call := telemetry.Start(ctx, telemetry.ProviderCore, operation)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	ctx, finish, out, ok := p.begin(ctx, nonce)
	if !ok {
		finishCore(call, out.Result)
		return out
	}
	defer finish()
	ctx = telemetry.CallContext(ctx, call)
	if p.guard.check(ctx) != contract.ReasonNone {
		finishCore(call, out.Result)
		return out
	}
	state, result := p.load(ctx, out.Query)
	out.Result = result
	if state != nil {
		out.Query.Observation = &AdministrativeObservation{DomainID: state.root.Domain, Revision: state.head.Core.Revision, Snapshot: state.root.Snapshot}
		out.CurrentWarningBits = state.root.WarningBits
		selected := bytes.Equal(state.body, p.input.Correlation.SignedCandidate)
		if out.Target == ReplacementTargetAuthority {
			actual, valid := state.selectedControl()
			if !valid {
				out.Result = failure(IntegrityFailure, InvalidRelation)
			} else {
				current, err := cloneReplacementObservationControl(actual)
				requested, requestErr := cloneReplacementObservationControl(p.after.control)
				if err != nil || requestErr != nil {
					out.Result = failure(IntegrityFailure, InvalidRelation)
				} else {
					usable := CurrentControlMatches(actual, p.after.control)
					out.Selection = &ReplacementCurrentSelection{RequestedControl: requested, CurrentControl: current, SuccessorSourceUsable: usable, CandidateSelected: selected, EvidenceLimit: "historical-attribution-unavailable"}
					if !usable {
						out.Result = state.observed(EvidenceUnavailable)
						out.Result.Reason = DifferentSelection
					}
				}
			}
		} else {
			out.Receipt, out.Result = p.receipt(state, out.Query, selected)
		}
	}
	if p.guard.check(ctx) != contract.ReasonNone {
		out.Result = refused(AdmissionInvalid)
		out.Selection, out.Receipt = nil, nil
		out.CurrentWarningBits = 0
		out.Query.Observation = nil
	}
	if digest, valid := out.Query.digest(); valid {
		out.Query.Digest = digest
		out.RequestIdentity = digest
	} else {
		out.Query = nil
		out.RequestIdentity = contract.ID{}
		out.Result = refused(AdmissionInvalid)
		out.Selection, out.Receipt = nil, nil
		out.CurrentWarningBits = 0
	}
	if out.Result.Outcome == Contention {
		out.Selection, out.Receipt = nil, nil
	}
	out.Result = replacementReadResult(out.Result)
	out.StateResult = replacementReadState(out.Result)
	finishCore(call, out.Result)
	return out
}
func (p *ReplacementObserver) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	p.closed = true
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	p.closeOnce.Do(func() { p.input.Source.Close(); p.closeErr = p.guard.SourceError() })
	return p.closeErr
}

func (p *ReplacementObserver) receipt(state *StateSession, q *ReplacementQueryIdentity, current bool) (*ReplacementReceiptObservation, Result) {
	row, raw, found, err := state.retainedMutationReceipt(q.OriginalOperationID)
	switch {
	case err != nil:
		return nil, failure(IntegrityFailure, InvalidRelation)
	case !found && current:
		return nil, failure(IntegrityFailure, MissingSelectedObject)
	case !found:
		result := state.observed(EvidenceUnavailable)
		result.Reason = MissingSelectedObject
		return nil, result
	case row.OperationKind != q.RequiredStoredKind:
		return nil, refused(InvalidRelation)
	case row.DomainID != p.input.ExpectedDomain || row.RequestIdentityDigest != p.input.Correlation.RequestIdentity || row.PredecessorRevisionID != p.candidate.Core.PreviousRevision || row.RequestedRevisionID != p.candidate.Core.Revision || row.ObservedRevisionID != p.candidate.Core.Revision:
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	return &ReplacementReceiptObservation{Receipt: row, ReceiptBytes: raw, CandidateSelected: current, EvidenceLimit: "retained-original-receipt-currentness-separate"}, state.observed(ObservedCurrent)
}
