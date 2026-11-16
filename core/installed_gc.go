package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

const GCApplyOperation = "gc-apply"

type GCMutationResources struct {
	Store contract.Store
	Trust contract.Trust
	Close func() error
}
type GCInstallation struct {
	Reader            *InstalledCapacityReader
	CompositionID     contract.ID
	ConstructMutation func(context.Context) (GCMutationResources, error)
}
type GCApplyPlanRequest struct {
	RequestNonce contract.ID
	EncodedPlan  []byte
}
type GCContinueRequest struct{ RequestNonce, OperationID contract.ID }
type InstalledGC struct {
	mu           sync.Mutex
	installation GCInstallation
	used, closed bool
	activeDone   chan struct{}
	cancel       context.CancelFunc
	resources    GCMutationResources
	guard        *installedGCGuard
	closeOnce    sync.Once
	closeErr     error
	localErr     error
}

// Success transfers Reader.Close ownership. Failure leaves it with the caller.
// The mutation factory is never called by this constructor.
func NewInstalledGC(i GCInstallation) (*InstalledGC, error) {
	if i.Reader == nil || i.Reader.reader == nil || i.CompositionID.IsZero() || i.ConstructMutation == nil {
		return nil, contract.ErrRecord
	}
	i.Reader.reader.mu.Lock()
	closed := i.Reader.reader.closed
	i.Reader.reader.mu.Unlock()
	if closed {
		return nil, contract.ErrRecord
	}
	g := &InstalledGC{installation: i}
	owned := *i.Reader
	check := owned.checkSource
	owned.checkSource = func(ctx context.Context) error {
		err := check(ctx)
		g.rememberError(err)
		return err
	}
	g.installation.Reader = &owned
	return g, nil
}
func (g *InstalledGC) begin(ctx context.Context, nonce contract.ID) (context.Context, func(), PublicGCResult, bool) {
	out := PublicGCResult{Operation: GCApplyOperation, RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: "refused"}
	if g == nil || ctx == nil || nonce.IsZero() || ctx.Err() != nil {
		return nil, nil, out, false
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) {
		return nil, nil, out, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used || g.closed {
		return nil, nil, out, false
	}
	g.used = true
	owned, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	g.cancel, g.activeDone = cancel, done
	out.DomainID = g.installation.Reader.reader.expectedDomain
	finish := func() {
		cancel()
		g.mu.Lock()
		g.cancel = nil
		g.activeDone = nil
		close(done)
		g.mu.Unlock()
	}
	return owned, finish, out, true
}
func (g *InstalledGC) sourceCurrent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errGCSourceChanged
	}
	r := g.installation.Reader
	r.reader.mu.Lock()
	closed := r.reader.closed
	r.reader.mu.Unlock()
	if closed {
		return errGCSourceChanged
	}
	return r.checkSource(ctx)
}
func (g *InstalledGC) ApplyPlan(ctx context.Context, request GCApplyPlanRequest) (out PublicGCResult) {
	ctx, finish, out, ok := g.begin(ctx, request.RequestNonce)
	if !ok {
		return out
	}
	defer finish()
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGCApply)
	ctx = telemetry.CallContext(ctx, call)
	out = g.applyPlan(ctx, request, out)
	if err := RefreshGCResult(&out); err != nil {
		g.rememberError(err)
	}
	finishCore(call, out.Result)
	return out
}

func (g *InstalledGC) applyPlan(ctx context.Context, request GCApplyPlanRequest, out PublicGCResult) PublicGCResult {
	proof, result := g.installation.Reader.ValidateGCPlan(ctx, request.EncodedPlan)
	if proof == nil {
		out.Result = result
		out.StateResult = gcStateResult(result)
		return out
	}
	if !proof.consume(ctx) {
		return out
	}
	bound := gcResultForPlan(out, proof.plan, proof.observation)
	if len(proof.plan.Targets) == 0 {
		if !proof.emptyHeadRechecked {
			g.rememberError(contract.ErrRecord)
			out.Result = refused(InvalidRelation)
			return out
		}
		condition, err := contract.MatchHeadCondition(proof.plan.PredecessorToken)
		if err != nil {
			g.rememberError(err)
			out.Result = refused(InvalidRelation)
			return out
		}
		token, err := contract.CryptoConditionDigest(condition)
		if err != nil {
			g.rememberError(err)
			out.Result = refused(InvalidRelation)
			return out
		}
		bound.Payload.NoWork = &GCNoWorkObservation{FullHEADDigest: proof.plan.FullHEADDigest, TokenDigest: token, Snapshot: proof.root}
		identity, err := gcNoWorkRequestIdentity(bound)
		if err != nil {
			g.rememberError(err)
			out.Result = refused(InvalidRelation)
			return out
		}
		bound.RequestIdentity = identity
		bound.Result = Result{Outcome: Unchanged, ObservedRevision: proof.plan.HeadRevisionID, ObservedSnapshotID: proof.plan.SnapshotID, Evidence: AuthenticatedClosure}
		bound.StateResult = "no-op"
		return bound
	}
	check := func(ctx context.Context) error {
		if !proof.current(ctx) {
			return errGCSourceChanged
		}
		return nil
	}
	return g.executeGC(ctx, bound, proof.plan, proof.head, nil, true, check)
}
func (g *InstalledGC) Continue(ctx context.Context, request GCContinueRequest) (out PublicGCResult) {
	ctx, finish, out, ok := g.begin(ctx, request.RequestNonce)
	if !ok {
		return out
	}
	defer finish()
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGCContinue)
	ctx = telemetry.CallContext(ctx, call)
	out = g.continueGC(ctx, request, out)
	if err := RefreshGCResult(&out); err != nil {
		g.rememberError(err)
	}
	finishCore(call, out.Result)
	return out
}

func (g *InstalledGC) continueGC(ctx context.Context, request GCContinueRequest, out PublicGCResult) PublicGCResult {
	if request.OperationID.IsZero() || g.sourceCurrent(ctx) != nil {
		return out
	}
	r := g.installation.Reader
	body := append([]byte("ENKV/GC-CONTINUE/v1\x00"), request.RequestNonce[:]...)
	body = append(body, request.OperationID[:]...)
	inv, failed := r.reader.beginReaderInvocation(ctx, gcPlanValidationOperation, contract.Hash(body))
	if failed.Outcome != 0 {
		out.Result = failed.Result
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	defer inv.Close()
	var retained selectedGCObligation
	selected, failed := inv.loadPublicSelection(ctx, gcPlanValidationOperation, inv.admission.request, func(ctx context.Context, facts *generatedSelection) error {
		states, err := selectedGCState(facts.image, true)
		if err != nil {
			return err
		}
		if err := selectedGCStore(states, inv.admission.store); err != nil {
			return err
		}
		var exists bool
		retained, exists = states[request.OperationID]
		if !exists {
			return selectedReadFailure(refused(InvalidRelation))
		}
		if retained.plan == nil {
			return contract.ErrRecord
		}
		retained.progress = retained.progress.Own()
		return nil
	})
	if failed.Outcome != 0 {
		inv.Close()
		out.Result = failed.Result
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	head := bytes.Clone(selected.basis.anchor.headBody)
	observation := inspectionObservation(selected)
	inv.Close()
	if g.sourceCurrent(ctx) != nil {
		return out
	}
	out = gcResultForPlan(out, *retained.plan, observation)
	gcApplyProgress(&out, retained.progress, selected.image.root.ActiveGC == request.OperationID)
	return g.executeGC(ctx, out, *retained.plan, head, &retained.progress, false, g.sourceCurrent)
}
func (g *InstalledGC) mutation(ctx context.Context, check func(context.Context) error) (*installedGCGuard, contract.Trust, Result) {
	if check(ctx) != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	resources, err := g.installation.ConstructMutation(ctx)
	g.rememberError(err)
	g.mu.Lock()
	g.resources = resources
	g.mu.Unlock()
	if err != nil || resources.Store == nil || resources.Trust == nil || resources.Close == nil {
		return nil, nil, refused(ConstructionMismatch)
	}
	r := g.installation.Reader
	control, err := r.reader.publicBasis.ControlCore(r.reader.expectedDomain, r.reader.expectedStore)
	if err != nil || resources.Store.Descriptor() != r.reader.expectedStore || resources.Trust.Family() != control.Provider || resources.Trust.Identity() != control.NormalSigning.Binding.Trust {
		return nil, nil, refused(ConstructionMismatch)
	}
	if _, ok := resources.Store.(contract.ConditionalDeleteStore); !ok {
		return nil, nil, refused(ConstructionMismatch)
	}
	guard, err := newInstalledGCGuard(ctx, resources.Store, check)
	if err != nil {
		return nil, nil, refused(ConstructionMismatch)
	}
	g.mu.Lock()
	g.guard = guard
	g.mu.Unlock()
	return guard, gcGuardTrust{guard: guard, backend: resources.Trust}, Result{}
}
func (g *InstalledGC) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	g.closed = true
	cancel, done := g.cancel, g.activeDone
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	g.closeOnce.Do(func() {
		if g.resources.Close != nil {
			g.closeErr = g.resources.Close()
		}
		g.installation.Reader.Close()
	})
	return g.closeErr
}

// OperationError returns the first retained operation error, including after
// Close. Resource cleanup errors are returned separately by Close.
func (g *InstalledGC) OperationError() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.localErr
}

func (g *InstalledGC) rememberError(err error) {
	if err == nil {
		return
	}
	g.mu.Lock()
	if g.localErr == nil {
		g.localErr = err
	}
	g.mu.Unlock()
}

func gcRandomAdmission() (contract.ID, error) {
	var id contract.ID
	_, err := rand.Read(id[:])
	if err == nil && id.IsZero() {
		err = errors.New("zero GC admission")
	}
	return id, err
}
