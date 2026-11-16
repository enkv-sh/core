package core

import (
	"context"
	"crypto/rand"
	"errors"
	"reflect"
	"slices"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type AdministrativeReadInstallation struct {
	ExpectedDomain contract.ID
	ExpectedStore  contract.Descriptor
	PublicBasis    PublicBasis
	CompositionID  contract.ID
	SourcePins     AdministrativeSourcePins
	Source         PublicSelectedReader
	CheckSource    func(context.Context) error
}

type AdministrativeAuthorityInstallation struct {
	ExpectedDomain contract.ID
	ExpectedStore  contract.Descriptor
	PublicBasis    PublicBasis
	CompositionID  contract.ID
	SourcePins     AdministrativeSourcePins
	Store          contract.Store
	Trust          contract.Trust
	CheckSource    func(context.Context) error
	CloseInstalled func() error
}

type installedAdministrativeParent struct {
	mu                               sync.Mutex
	domain, composition, basisDigest contract.ID
	descriptor                       contract.Descriptor
	basis                            PublicBasis
	pins                             AdministrativeSourcePins
	operation                        AdministrativeOperation
	guard                            *installedMutationGuard
	trust                            contract.Trust
	closeSource                      func()
	closeInstalled                   func() error
	used, closed                     bool
	activeDone                       chan struct{}
	cancel                           context.CancelFunc
	deadline                         time.Time
	issued                           *PublicAdministrativeResult
	bound                            bool
	closeOnce                        sync.Once
	closeErr                         error
}

func administrativeParent(domain contract.ID, descriptor contract.Descriptor, basis PublicBasis, composition contract.ID, pins AdministrativeSourcePins, store contract.Store, checkSource func(context.Context) error, operation AdministrativeOperation) (*installedAdministrativeParent, error) {
	if domain.IsZero() || !descriptor.Valid() || composition.IsZero() || !pins.Valid() || store == nil || store.Descriptor() != descriptor || checkSource == nil {
		return nil, contract.ErrRecord
	}
	owned, err := basis.own()
	if err != nil {
		return nil, err
	}
	digest, err := AdministrativePublicBasisDigest(domain, descriptor, owned)
	if err != nil {
		return nil, err
	}
	guard, err := newInstalledMutationGuard(store, checkSource)
	if err != nil {
		return nil, err
	}
	return &installedAdministrativeParent{domain: domain, composition: composition, basisDigest: digest, descriptor: descriptor, basis: owned, pins: pins, operation: operation, guard: guard}, nil
}

// NewInstalledAdministrativeReader does local qualification only. Success
// transfers Source.Close ownership; failure leaves it with the caller.
func NewInstalledAdministrativeReader(i AdministrativeReadInstallation, operation AdministrativeOperation) (*AuthoritySession, error) {
	if i.Source == nil || operation != AdministrativeList && operation != AdministrativePlan && operation != AdministrativeReceipt {
		return nil, contract.ErrRecord
	}
	parent, err := administrativeParent(i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, i.CompositionID, i.SourcePins, administrativeReadStore{source: i.Source}, i.CheckSource, operation)
	if err != nil {
		return nil, err
	}
	parent.closeSource = i.Source.Close
	return &AuthoritySession{installed: parent}, nil
}

// NewInstalledAdministrativeAuthority qualifies only the independently supplied
// current Normal route. No Recovery, Crypto or effect capability is installed.
// Success transfers CloseInstalled ownership; failure leaves it with the caller.
func NewInstalledAdministrativeAuthority(i AdministrativeAuthorityInstallation) (*AuthoritySession, error) {
	if i.Trust == nil || i.CloseInstalled == nil {
		return nil, contract.ErrRecord
	}
	parent, err := administrativeParent(i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, i.CompositionID, i.SourcePins, i.Store, i.CheckSource, AdministrativeApply)
	if err != nil {
		return nil, err
	}
	control, err := parent.basis.ControlCore(parent.domain, parent.descriptor)
	if err != nil || i.Trust.Family() != control.Provider || i.Trust.Identity() != control.NormalSigning.Binding.Trust {
		return nil, contract.ErrRecord
	}
	parent.trust = parent.guard.Trust(i.Trust)
	parent.closeInstalled = i.CloseInstalled
	return &AuthoritySession{installed: parent}, nil
}

func (p *installedAdministrativeParent) query(operation AdministrativeOperation, nonce, requested, target contract.ID, path string) *AdministrativeQueryIdentity {
	q := &AdministrativeQueryIdentity{Schema: "QueryRequestIdentity/v1", Operation: operation, SemanticOperation: 15, ExpectedDomain: p.domain, StoreID: p.descriptor.Identity, CoordinateID: p.descriptor.Coordinate, NonBodyID: p.descriptor.NonBody, StoreDescriptorDigest: administrativeStoreDescriptorDigest(p.descriptor), PublicBasisDigest: p.basisDigest, SourcePins: p.pins, RequestNonce: nonce, RequestedOperationID: requested, TargetGroupID: target, ArtifactPath: path}
	if operation == AdministrativeReceipt {
		q.SemanticOperation = 16
		q.RequiredStoredKind = contract.OperationEndSelectedWork
	}
	if digest, ok := q.digest(); ok {
		q.Digest = digest
		return q
	}
	return nil
}

func (a *AuthoritySession) beginInstalled(ctx context.Context, operation AdministrativeOperation, nonce, requested, target contract.ID, path string) (context.Context, func(), PublicAdministrativeResult, bool) {
	out := PublicAdministrativeResult{Operation: operation, RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: AdministrativeRefused}
	if a == nil || a.installed == nil {
		return nil, nil, out, false
	}
	p := a.installed
	out.DomainID = p.domain
	if operation != AdministrativeApply {
		out.Query = p.query(operation, nonce, requested, target, path)
		if out.Query != nil {
			out.RequestIdentity = out.Query.Digest
			body := append([]byte("ENKV/administrative-query-operation/v1\x00"), []byte(operation)...)
			body = append(body, nonce[:]...)
			body = append(body, p.domain[:]...)
			out.OperationID = contract.Hash(body)
		}
	}
	p.mu.Lock()
	if p.used || p.closed {
		p.mu.Unlock()
		return nil, nil, out, false
	}
	p.used = true
	deadline, finite := time.Time{}, false
	if ctx != nil {
		deadline, finite = ctx.Deadline()
	}
	if ctx == nil || ctx.Err() != nil || !finite || !validPrivateDeadline(deadline) || nonce.IsZero() || operation != p.operation || operation != AdministrativeApply && out.Query == nil {
		p.mu.Unlock()
		return nil, nil, out, false
	}
	owned, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	p.activeDone, p.cancel, p.deadline = done, cancel, deadline
	p.mu.Unlock()
	finish := func() {
		cancel()
		p.mu.Lock()
		p.cancel = nil
		p.activeDone = nil
		close(done)
		p.mu.Unlock()
	}
	return owned, finish, out, true
}

func (a *AuthoritySession) loadInstalled(ctx context.Context, operation AdministrativeOperation) Result {
	p := a.installed
	if reason := p.guard.check(ctx); reason != contract.ReasonNone {
		return refused(AdmissionInvalid)
	}
	admitted, result := admitBorrowedPublicNormal(ctx, p.domain, p.descriptor, p.basis, p.guard.Store(), p.composition, nil)
	if result.Outcome != ObservedCurrent {
		return result
	}
	switch operation {
	case AdministrativeList:
		a.mode = LocalAuthorityInspect
	case AdministrativePlan:
		a.mode = LocalAuthorityPreview
	case AdministrativeApply:
		a.mode = LocalAuthorityEnd
	case AdministrativeReceipt:
		a.mode = LocalAuthorityRecheck
	default:
		return refused(AdmissionInvalid)
	}
	if operation == AdministrativePlan || operation == AdministrativeApply {
		if _, err := rand.Read(admitted.admission.endWorkInvocation[:]); err != nil || admitted.admission.endWorkInvocation.IsZero() {
			return refused(AdmissionInvalid)
		}
	}
	state, result := openAdministrative(ctx, admitted, p.guard.Store())
	if state == nil {
		return result
	}
	a.state, a.trust = state, p.trust
	return result
}

func administrativeReadResult(result Result) Result {
	if result.Outcome == Contention {
		result.Outcome = EvidenceUnavailable
	}
	return result
}

func (a *AuthoritySession) finishInstalledRead(ctx context.Context, out PublicAdministrativeResult) PublicAdministrativeResult {
	if out.Result.Outcome == Contention {
		out.Result = administrativeReadResult(out.Result)
		out.List, out.Plan, out.Receipt = nil, nil, nil
	}
	if a.state != nil {
		out.CurrentWarningBits = a.state.root.WarningBits
		if out.Query != nil {
			out.Query.Observation = &AdministrativeObservation{DomainID: a.state.root.Domain, Revision: a.state.head.Core.Revision, Snapshot: a.state.root.Snapshot}
		}
	}
	// No semantic result leaves this boundary until the full image/projection's
	// source check succeeds. Individual Store GETs delegate without source I/O.
	if reason := a.installed.guard.check(ctx); reason != contract.ReasonNone {
		out.Result = refused(AdmissionInvalid)
		out.List, out.Plan, out.Receipt = nil, nil, nil
		out.CurrentWarningBits = 0
	}
	if out.Query != nil {
		if digest, ok := out.Query.digest(); ok {
			out.Query.Digest = digest
			out.RequestIdentity = digest
		} else {
			out.Query = nil
			out.RequestIdentity = contract.ID{}
			out.Result = refused(AdmissionInvalid)
			out.List, out.Plan, out.Receipt = nil, nil, nil
			out.CurrentWarningBits = 0
		}
	}
	out.StateResult = administrativeState(out.Operation, out.Result)
	return out
}

func (a *AuthoritySession) List(ctx context.Context, nonce contract.ID) PublicAdministrativeResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreInspectSelectedWork)
	ctx, finish, out, ok := a.beginInstalled(ctx, AdministrativeList, nonce, contract.ID{}, contract.ID{}, "")
	if !ok {
		finishCore(call, out.Result)
		return out
	}
	defer finish()
	ctx = telemetry.CallContext(ctx, call)
	out.Result = a.loadInstalled(ctx, AdministrativeList)
	if out.Result.Outcome == ObservedCurrent {
		view, result := a.inspect(ctx)
		out.Result = result
		if result.Outcome == ObservedCurrent {
			out.List = &view
		}
	}
	out = a.finishInstalledRead(ctx, out)
	finishCore(call, out.Result)
	return out
}

func (a *AuthoritySession) Plan(ctx context.Context, nonce contract.ID, request AdministrativePlanRequest) PublicAdministrativeResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePrepareEndSelectedWork)
	ctx, finish, out, ok := a.beginInstalled(ctx, AdministrativePlan, nonce, contract.ID{}, request.TargetGroupID, request.ArtifactPath)
	if !ok {
		finishCore(call, out.Result)
		return out
	}
	defer finish()
	ctx = telemetry.CallContext(ctx, call)
	out.Result = a.loadInstalled(ctx, AdministrativePlan)
	if out.Result.Outcome == ObservedCurrent {
		view, result := a.preview(ctx, request.TargetGroupID)
		out.Result = result
		if result.Outcome == ObservedCurrent {
			out.Plan = &AdministrativePlanPayload{Preview: view, ArtifactPath: request.ArtifactPath}
			out.Query.PlanIdentity = view.Identity
		}
	}
	out = a.finishInstalledRead(ctx, out)
	if out.Result.Outcome == ObservedCurrent && out.Plan != nil {
		out.planIssue = &administrativePlanIssue{parent: a.installed}
		owned := cloneAdministrativePlanResult(out)
		a.installed.mu.Lock()
		a.installed.issued = &owned
		a.installed.mu.Unlock()
	}
	finishCore(call, out.Result)
	return out
}

// BindPlanArtifact accepts a descriptor only after the composition's strict
// codec, protected creation and exact readback. Core owns the issued preview
// and all semantic facts; it does not encode or parse artifact bytes.
func (a *AuthoritySession) BindPlanArtifact(ctx context.Context, result PublicAdministrativeResult, artifact AdministrativeArtifact) (PublicAdministrativeResult, Result) {
	if a == nil || a.installed == nil || ctx == nil || ctx.Err() != nil {
		return PublicAdministrativeResult{}, refused(AdmissionInvalid)
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) {
		return PublicAdministrativeResult{}, refused(AdmissionInvalid)
	}
	p := a.installed
	p.mu.Lock()
	if p.closed || p.activeDone != nil || p.issued == nil || p.bound || result.planIssue == nil || result.planIssue.parent != p || !time.Now().Before(p.deadline) || !reflect.DeepEqual(*p.issued, result) || artifact.Path != p.issued.Plan.ArtifactPath || artifact.Digest.IsZero() || artifact.Length == 0 {
		p.mu.Unlock()
		return PublicAdministrativeResult{}, refused(AdmissionInvalid)
	}
	// Joinable ownership also covers the final source check during binding.
	ownedCtx, cancel := context.WithDeadline(ctx, p.deadline)
	done := make(chan struct{})
	p.activeDone, p.cancel = done, cancel
	p.mu.Unlock()
	defer func() {
		cancel()
		p.mu.Lock()
		p.activeDone = nil
		p.cancel = nil
		close(done)
		p.mu.Unlock()
	}()
	if reason := p.guard.check(ownedCtx); reason != contract.ReasonNone {
		return PublicAdministrativeResult{}, refused(AdmissionInvalid)
	}
	out := cloneAdministrativePlanResult(result)
	out.Plan.Artifact = &artifact
	out.Query.Artifact = &AdministrativeArtifact{Path: artifact.Path, Digest: artifact.Digest, Length: artifact.Length}
	digest, ok := out.Query.digest()
	if !ok {
		return PublicAdministrativeResult{}, refused(AdmissionInvalid)
	}
	out.Query.Digest, out.RequestIdentity = digest, digest
	p.mu.Lock()
	if p.closed || ownedCtx.Err() != nil {
		p.mu.Unlock()
		return PublicAdministrativeResult{}, refused(AdmissionInvalid)
	}
	p.bound = true
	p.mu.Unlock()
	return out, out.Result
}

func (a *AuthoritySession) Receipt(ctx context.Context, nonce, operation contract.ID) PublicAdministrativeResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreMutationReceipt)
	ctx, finish, out, ok := a.beginInstalled(ctx, AdministrativeReceipt, nonce, operation, contract.ID{}, "")
	if !ok {
		finishCore(call, out.Result)
		return out
	}
	defer finish()
	ctx = telemetry.CallContext(ctx, call)
	out.Result = a.loadInstalled(ctx, AdministrativeReceipt)
	if out.Result.Outcome == ObservedCurrent {
		row, result := a.installedReceipt(operation)
		out.Result = result
		if result.Outcome == ObservedCurrent {
			out.Receipt = &row
		}
	}
	out = a.finishInstalledRead(ctx, out)
	finishCore(call, out.Result)
	return out
}

func (a *AuthoritySession) installedReceipt(operation contract.ID) (AuthorityAbandonment, Result) {
	receipt, body, found, err := a.state.retainedMutationReceipt(operation)
	if err != nil {
		return AuthorityAbandonment{}, failure(IntegrityFailure, InvalidRelation)
	}
	if !found {
		return AuthorityAbandonment{}, failure(EvidenceUnavailable, MissingSelectedObject)
	}
	if receipt.OperationKind != contract.OperationEndSelectedWork {
		return AuthorityAbandonment{}, refused(InvalidRelation)
	}
	row := AuthorityAbandonment{Receipt: receipt, ReceiptBytes: body}
	if receipt.AdministrativeTargetKind == contract.AdministrativeGeneratedParent && receipt.AdministrativeGroupID == receipt.AdministrativeTargetID {
		row.OriginalOperation = &AdministrativeOriginalOperation{OperationID: receipt.AdministrativeGroupID}
	}
	return row, a.state.observed(ObservedCurrent)
}

func (a *AuthoritySession) Apply(ctx context.Context, nonce contract.ID, expected EndWorkPreview) PublicAdministrativeResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreSelectEndSelectedWork)
	ctx, finish, out, ok := a.beginInstalled(ctx, AdministrativeApply, nonce, contract.ID{}, contract.ID{}, "")
	if !ok {
		finishCore(call, out.Result)
		return out
	}
	defer finish()
	if expected.Identity.IsZero() || expected.TargetGroupID.IsZero() || len(expected.EndedGroupIDs) == 0 || len(expected.EndedGroupIDs) > 0xffff {
		finishCore(call, out.Result)
		return out
	}
	expected.EndedGroupIDs = slices.Clone(expected.EndedGroupIDs)
	ctx = telemetry.CallContext(ctx, call)
	out.Result = a.loadInstalled(ctx, AdministrativeApply)
	if out.Result.Outcome == ObservedCurrent {
		out.CurrentWarningBits = a.state.root.WarningBits
		ended := a.end(ctx, expected, call)
		out.Result, out.OperationID, out.RequestIdentity = ended.Result, ended.OperationID, ended.RequestIdentity
		if ended.Result.Outcome == ObservedCurrent {
			receipt, err := contract.InspectCompactMutationReceipt(ended.Receipt)
			if err != nil || receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != ended.OperationID || receipt.RequestIdentityDigest != ended.RequestIdentity || receipt.DomainID != out.DomainID || receipt.RequestedRevisionID != ended.Revision || receipt.ObservedRevisionID != ended.Revision || receipt.WarningBits != uint64(ended.Warnings) || receipt.AdministrativeGroupID != expected.TargetGroupID {
				out.Result = ended.Result
				out.Result.Outcome = IntegrityFailure
				out.Result.Reason = InvalidRelation
			} else {
				preview := expected
				preview.EndedGroupIDs = slices.Clone(expected.EndedGroupIDs)
				out.End = &AdministrativeEndPayload{Preview: preview, Receipt: receipt, ReceiptBytes: slices.Clone(ended.Receipt)}
				out.CurrentWarningBits = ended.Warnings
			}
		}
	}
	// Preserve the mutation's actual selection/uncertainty even if this final
	// local check fails. Close returns the retained source error separately.
	a.installed.guard.check(ctx)
	out.StateResult = administrativeState(AdministrativeApply, out.Result)
	finishCore(call, out.Result)
	return out
}

func (p *installedAdministrativeParent) close(a *AuthoritySession) error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		cancel, done := p.cancel, p.activeDone
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
		if p.closeSource != nil {
			p.closeSource()
		}
		if p.closeInstalled != nil {
			p.closeErr = p.closeInstalled()
		}
		p.closeErr = errors.Join(p.guard.SourceError(), p.closeErr)
		a.state = nil
		a.trust = nil
		p.mu.Lock()
		p.issued = nil
		p.mu.Unlock()
	})
	return p.closeErr
}
