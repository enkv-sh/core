package core

import (
	"context"
	"errors"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// ReconstructionSigningAnchor qualifies one selected public binding against
// an independently installed signing resource. It has no Sign method.
type ReconstructionSigningAnchor interface {
	QualifySigningBinding(context.Context, contract.PublicSigningBinding) contract.SigningQualificationResult
}

// ReconstructionVerifier checks and discards one selected secret at a time.
// It has no plaintext result, sink or ordinary operation authority.
type ReconstructionVerifier interface {
	Verify(context.Context, contract.ConsumerSelection) contract.CryptoResultCode
	Close()
}

// ErrReconstructionKeyMismatch reports that the independently expected
// Authority encryption selector differs from the authenticated selected binding.
var ErrReconstructionKeyMismatch = errors.New("reconstruction Authority encryption key mismatch")

// ReconstructionInstallation is fixed by the trusted compiled composition.
// Candidate data and Reconstruct callers cannot supply selection facts, a
// verifier, success, or a projection sink. ExpectedDomain is an optional
// independent pin; zero uses the qualified signed current domain.
type ReconstructionInstallation struct {
	Candidate      PublicCandidateReader
	Normal         ReconstructionSigningAnchor
	Recovery       ReconstructionSigningAnchor
	Construct      func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result)
	Verify         func(context.Context, contract.ReconstructionVerificationPins, time.Time) (ReconstructionVerifier, error)
	ExpectedDomain contract.ID
	// CloseInstalled releases composition-owned private resources once the
	// active finite-deadline invocation has ended. Shared clients remain with
	// their own constructor's owner.
	CloseInstalled func()
}

// ReconstructionEngine owns one installed, purpose-specific reconstruction
// route. It admits one invocation at a time and never waits to admit a second.
type ReconstructionEngine struct {
	mu              sync.Mutex
	input           reconstructionInputs
	closeInstalled  func()
	activeDone      chan struct{}
	shutdownDone    chan struct{}
	closed, closing bool
}

// NewInstalledReconstruction retains only fixed read, qualification and
// verify/discard dependencies. It does not open or select a current state.
func NewInstalledReconstruction(i ReconstructionInstallation) (*ReconstructionEngine, error) {
	if i.Candidate == nil || i.Normal == nil && i.Recovery == nil ||
		i.Construct == nil || i.Verify == nil || i.CloseInstalled == nil {
		return nil, contract.ErrRecord
	}
	return &ReconstructionEngine{input: reconstructionInputs{candidate: i.Candidate,
		normal: i.Normal, recovery: i.Recovery, construct: i.Construct,
		verifier: i.Verify, expectedDomain: i.ExpectedDomain},
		closeInstalled: i.CloseInstalled, shutdownDone: make(chan struct{})}, nil
}

// Reconstruct returns only a complete owned projection after every selected
// part, all-current-secret verify/discard and an identical final HEAD/token.
// The caller supplies one original finite context. An active or closed engine
// refuses immediately, without waiting beyond that context's deadline.
func (e *ReconstructionEngine) Reconstruct(ctx context.Context) (projection *ReconstructionProjection, result Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReconstruct)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	active := false
	defer func() {
		finishCore(call, result)
		if active {
			e.finishInvocation()
		}
	}()
	if e == nil {
		return nil, refused(AdmissionInvalid)
	}
	ctx = telemetry.CallContext(ctx, call)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, refused(AdmissionInvalid)
	}
	if e.activeDone != nil {
		e.mu.Unlock()
		return nil, refused(AlreadyUsed)
	}
	e.activeDone = make(chan struct{})
	active = true
	input := e.input
	e.mu.Unlock()
	return reconstructOwnedCurrent(ctx, input)
}

func (e *ReconstructionEngine) finishInvocation() {
	e.mu.Lock()
	done := e.activeDone
	shouldClose := e.closed
	e.mu.Unlock()
	if shouldClose {
		e.closeResources()
	}
	e.mu.Lock()
	close(done)
	e.activeDone = nil
	e.mu.Unlock()
}

func (e *ReconstructionEngine) closeResources() {
	e.mu.Lock()
	if e.closing {
		done := e.shutdownDone
		e.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	e.closing = true
	closeInstalled, done := e.closeInstalled, e.shutdownDone
	e.closeInstalled = nil
	e.mu.Unlock()
	if closeInstalled != nil {
		closeInstalled()
	}
	if done != nil {
		close(done)
	}
}

// Close refuses later invocations immediately, then joins the active
// original-deadline invocation and the installed private resource Close.
// Concurrent Close callers join the same shutdown. It is not called by an
// invocation callback, which would otherwise wait on itself.
func (e *ReconstructionEngine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	done := e.activeDone
	e.mu.Unlock()
	if done != nil {
		<-done
	}
	e.closeResources()
}
