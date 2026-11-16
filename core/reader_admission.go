package core

import (
	"context"
	"sync"
	"time"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

// ReaderInstallation contains only public verification and keyed read reach.
// The trusted composition chooses interpretation; operation inputs cannot do so.
type ReaderInstallation struct {
	SelectPolicyAction func(context.Context, PublicationPolicyActionInput) (uint8, error)
	Candidate          PublicCandidateReader
	Construct          func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result)
	ExpectedDomain     contract.ID
	ExpectedStore      contract.Descriptor
	PublicBasis        PublicBasis
	Validator          *PublicConfigurationValidator
	// Preparation runs only for admitted manifest requests, before selected loading.
	// It returns the exact captured build after settings normalization.
	PrepareManifestRenderer func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)
	CloseInstalled          func()
}

// ReaderEngine owns one native invocation at a time. It grants no ordinary
// state admission, private key use or provider effects.
type ReaderEngine struct {
	selectPolicyAction      publicationPolicyActionSelector
	mu                      sync.Mutex
	candidate               candidateReadSource
	construct               func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result)
	expectedDomain          contract.ID
	expectedStore           contract.Descriptor
	publicBasis             PublicBasis
	validator               *PublicConfigurationValidator
	prepareManifestRenderer func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)
	activeDone              chan struct{}
	closed                  bool
	closeOnce               sync.Once
	closeInstalled          func()
}

func NewInstalledReader(i ReaderInstallation) (*ReaderEngine, error) {
	if i.Validator == nil {
		return nil, contract.ErrRecord
	}
	return newInstalledPublicReader(i)
}

func newInstalledPublicReader(i ReaderInstallation) (*ReaderEngine, error) {
	if i.Candidate == nil || i.Construct == nil || i.ExpectedDomain.IsZero() || !i.ExpectedStore.Valid() || i.CloseInstalled == nil {
		return nil, contract.ErrRecord
	}
	basis, err := i.PublicBasis.own()
	if err != nil {
		return nil, err
	}
	location := i.Candidate.CandidateLocation()
	if !contract.StoreLocationValid(location) || location.Provider != i.ExpectedStore.Family || location.PrefixBeforeHEAD != i.ExpectedStore.Prefix || i.ExpectedStore.HeadKey != location.PrefixBeforeHEAD+"/HEAD" {
		return nil, contract.ErrRecord
	}
	var selectPolicy publicationPolicyActionSelector
	if i.SelectPolicyAction != nil {
		selectPolicy = func(ctx context.Context, in publicationPolicyActionInput) (uint8, error) {
			return i.SelectPolicyAction(ctx, PublicationPolicyActionInput(in))
		}
	}
	return &ReaderEngine{selectPolicyAction: selectPolicy, candidate: i.Candidate, construct: i.Construct, expectedDomain: i.ExpectedDomain, expectedStore: i.ExpectedStore, publicBasis: basis, validator: i.Validator, prepareManifestRenderer: i.PrepareManifestRenderer, closeInstalled: i.CloseInstalled}, nil
}

type readerFailure struct {
	Result
	diagnostic contract.DiagnosticReason
}

func readerRefusal(reason contract.DiagnosticReason) readerFailure {
	return readerFailure{Result: refused(AdmissionInvalid), diagnostic: reason}
}

type readerAdmission struct {
	issued                                                            bool
	request                                                           contract.ID
	operation                                                         string
	domain                                                            contract.ID
	store                                                             contract.Descriptor
	interpretation, trustInterpretation, compatibility, cryptoSupport contract.ID
	basis                                                             readerPublicBasis
	deadline                                                          time.Time
	done                                                              <-chan struct{}
}

type readerInvocation struct {
	engine         *ReaderEngine
	admission      readerAdmission
	done           chan struct{}
	source         PublicSelectedReader
	selection      publicSelection
	loaded, closed bool
	closeOnce      sync.Once
}

func (e *ReaderEngine) beginReaderInvocation(ctx context.Context, operation string, request contract.ID) (*readerInvocation, readerFailure) {
	if e == nil || ctx == nil || request.IsZero() || operation != contract.ReaderCompareOperation && operation != contract.ReaderManifestOperation && operation != contract.ReaderRecipientsOperation && operation != GeneratedListOperation && operation != ReceiptListOperation && operation != ReceiptDetailOperation && operation != InspectOperation && operation != InspectRecipientOperation && operation != InspectCapacityOperation && operation != GCPlanOperation && operation != gcPlanValidationOperation && operation != contract.MaterializationOperation {
		return nil, readerRefusal(contract.ReasonInvalidInput)
	}
	deadline, finite := ctx.Deadline()
	if ctx.Err() != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, readerRefusal(contract.ReasonExpired)
		}
		return nil, readerRefusal(contract.ReasonCancelled)
	}
	if !finite || !validPrivateDeadline(deadline) {
		return nil, readerRefusal(contract.ReasonExpired)
	}
	e.mu.Lock()
	if e.closed || e.activeDone != nil {
		e.mu.Unlock()
		return nil, readerRefusal(contract.ReasonInvalidInput)
	}
	done := make(chan struct{})
	e.activeDone = done
	e.mu.Unlock()
	inv := &readerInvocation{engine: e, done: done}
	transferred := false
	defer func() {
		if !transferred {
			inv.Close()
		}
	}()
	basis, reason := qualifyBorrowedReaderPublicBasis(e.publicBasis, e.expectedDomain, e.expectedStore)
	if reason != "" {
		return nil, readerRefusal(reason)
	}
	inv.admission = readerAdmission{issued: true, request: request, operation: operation, domain: e.expectedDomain, store: e.expectedStore, interpretation: contract.InterpretationID(), trustInterpretation: contract.TrustInterpretationID(), compatibility: contract.CompatibilityID(), cryptoSupport: contract.CryptoSupportID(), basis: basis, deadline: deadline, done: ctx.Done()}
	if reason := inv.admission.failure(ctx, operation, request); reason != "" {
		return nil, readerRefusal(reason)
	}
	transferred = true
	return inv, readerFailure{}
}

func readerFailureState(reason contract.DiagnosticReason) contract.ReaderStateResult {
	switch reason {
	case contract.ReasonEvidenceUnavailable, contract.ReasonSelectedObjectUnavailable, contract.ReasonPublicFactUnavailable:
		return contract.ReaderUnavailable
	case contract.ReasonReadContention:
		return contract.ReaderContention
	case contract.ReasonHeadInvalid, contract.ReasonProofInvalid, contract.ReasonSelectedObjectInvalid, contract.ReasonSelectedRelationInvalid:
		return contract.ReaderPositiveDefect
	case contract.ReasonUnsupportedProfile, contract.ReasonUnsupportedSchema:
		return contract.ReaderProfileBlocked
	default:
		return contract.ReaderRefused
	}
}

func (a *readerAdmission) failure(ctx context.Context, operation string, request contract.ID) contract.DiagnosticReason {
	if a == nil || !a.issued || a.request != request || a.operation != operation || a.domain.IsZero() || !a.store.Valid() || a.interpretation != contract.InterpretationID() || a.trustInterpretation != contract.TrustInterpretationID() || a.compatibility != contract.CompatibilityID() || a.cryptoSupport != contract.CryptoSupportID() {
		return contract.ReasonInvalidInput
	}
	if ctx == nil || ctx.Done() != a.done {
		return contract.ReasonInvalidInput
	}
	if ctx.Err() != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return contract.ReasonExpired
		}
		return contract.ReasonCancelled
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline != a.deadline || !validPrivateDeadline(deadline) {
		return contract.ReasonExpired
	}
	return ""
}

// Close releases the invocation's borrowed image before closing its exact read
// source. The engine can then admit a fresh native invocation with a fresh basis.
func (i *readerInvocation) Close() {
	if i == nil {
		return
	}
	i.closeOnce.Do(func() {
		i.closed = true
		i.admission.issued = false
		i.selection = publicSelection{}
		i.admission.basis = readerPublicBasis{}
		if i.source != nil {
			i.source.Close()
			i.source = nil
		}
		if i.engine != nil {
			i.engine.mu.Lock()
			if i.engine.activeDone == i.done {
				i.engine.activeDone = nil
				close(i.done)
			}
			i.engine.mu.Unlock()
		}
	})
}

// Close refuses later operations, joins the active finite invocation, then
// releases installation resources exactly once.
func (e *ReaderEngine) Close() {
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
	e.closeOnce.Do(func() {
		e.mu.Lock()
		closeInstalled := e.closeInstalled
		e.candidate, e.construct, e.validator, e.closeInstalled = nil, nil, nil, nil
		e.prepareManifestRenderer = nil
		e.publicBasis.clear()
		e.mu.Unlock()
		if closeInstalled != nil {
			closeInstalled()
		}
	})
}
