package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type InitializationArtifactSink func(context.Context, contract.ID, []byte) (contract.GenesisArtifactFact, error)

// InitializationInstallation is supplied by the trusted static composition.
// Sinks validate native persistence receipts before returning exact public
// facts. Invocation inputs cannot replace sinks, routes or custody admission.
type InitializationInstallation struct {
	Descriptor                         contract.GenesisDescriptorCore
	Store                              contract.Store
	Normal, Recovery                   contract.QualifyingTrust
	CompositionID, SetupDigest         contract.ID
	PersistDescriptor, PersistManifest InitializationArtifactSink
	AdmitCustody                       func(context.Context, contract.CryptoQualifyInitKeysRequest) (contract.Crypto, func(), error)
	CloseInstalled                     func()
}

// InitializationObservationInstallation has only public read reach. A retained
// manifest permits exact ready observation; it cannot resume pre-HEAD work.
type InitializationObservationInstallation struct {
	Descriptor, Manifest []byte
	Store                contract.Store
	CompositionID        contract.ID
	CloseInstalled       func()
}

type InstalledInitializer struct {
	mu                                sync.Mutex
	installation                      *InitializationInstallation
	descriptor                        contract.GenesisDescriptorCore
	descriptorBytes, retainedManifest []byte
	store                             contract.Store
	composition                       contract.ID
	activeDone                        chan struct{}
	used, closed                      bool
	closeOnce                         sync.Once
	closeInstalled                    func()
}

type PublicInitializationResult struct {
	Result                       Result
	OperationID, RequestIdentity contract.ID
	StateResult                  contract.InitializationStateResult
	EffectSummary                string
	Payload                      *contract.InitPayload
	Receipt                      []byte
	PublicBasis                  *PublicBasis
}

func NewInstalledInitializer(allocation *InitializationAllocation, i InitializationInstallation) (*InstalledInitializer, error) {
	if allocation == nil || i.Store == nil || i.Normal == nil || i.CompositionID.IsZero() || i.SetupDigest.IsZero() ||
		i.PersistDescriptor == nil || i.PersistManifest == nil || i.AdmitCustody == nil || i.CloseInstalled == nil {
		return nil, contract.ErrRecord
	}
	body, err := contract.EncodeGenesisDescriptorCore(i.Descriptor)
	if err != nil {
		return nil, err
	}
	d, err := contract.DecodeGenesisDescriptorCore(body)
	if err != nil || !initializationStoreMatches(d, i.Store) || i.Normal.Identity() != d.TrustID || i.Normal.Family() != d.Provider ||
		(d.Recovery == nil) != (i.Recovery == nil) || i.Recovery != nil && (i.Recovery.Family() != d.Provider || i.Recovery.Identity() != d.Recovery.Signing.Binding.Trust) {
		return nil, contract.ErrRecord
	}
	allocation.mu.Lock()
	defer allocation.mu.Unlock()
	if allocation.installed || !initializationIDsMatch(allocation.ids, d) {
		return nil, contract.ErrRecord
	}
	allocation.installed = true
	i.Descriptor = contract.GenesisDescriptorCore{}
	return &InstalledInitializer{installation: &i, descriptor: d, descriptorBytes: body, store: i.Store,
		composition: i.CompositionID, closeInstalled: i.CloseInstalled}, nil
}

func NewInstalledInitializationObserver(i InitializationObservationInstallation) (*InstalledInitializer, error) {
	if i.Store == nil || i.CompositionID.IsZero() || i.CloseInstalled == nil {
		return nil, contract.ErrRecord
	}
	d, err := contract.DecodeGenesisDescriptorCore(i.Descriptor)
	if err != nil || !initializationStoreMatches(d, i.Store) {
		return nil, contract.ErrRecord
	}
	if _, err := contract.DecodeGenesisBootstrapManifestCore(i.Manifest); err != nil {
		return nil, err
	}
	return &InstalledInitializer{descriptor: d, descriptorBytes: bytes.Clone(i.Descriptor), retainedManifest: bytes.Clone(i.Manifest),
		store: i.Store, composition: i.CompositionID, closeInstalled: i.CloseInstalled}, nil
}

func initializationStoreMatches(d contract.GenesisDescriptorCore, store contract.Store) bool {
	if store == nil {
		return false
	}
	descriptor := store.Descriptor()
	if !descriptor.Valid() || descriptor.Family != d.Provider || descriptor.Identity != d.StoreID ||
		descriptor.Coordinate != d.CoordinateID || descriptor.NonBody != d.NonBodyID {
		return false
	}
	source, ok := store.(contract.StoreConfigurationSource)
	if !ok {
		return false
	}
	configuration := source.StoreConfiguration()
	body, err := contract.EncodeStoreConfiguration(configuration)
	return err == nil && configuration.DomainID == d.DomainID && configuration.Provider == d.Provider && contract.Hash(body) == d.StoreID
}

func (e *InstalledInitializer) Initialize(ctx context.Context) PublicInitializationResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreInitialize)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := PublicInitializationResult{Result: refused(AdmissionInvalid), StateResult: contract.InitializationRefused, EffectSummary: "effect-no-change"}
	if e == nil || ctx == nil {
		finishCore(call, out.Result)
		return out
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) || ctx.Err() != nil {
		finishCore(call, out.Result)
		return out
	}
	e.mu.Lock()
	if e.closed || e.used || e.activeDone != nil {
		e.mu.Unlock()
		finishCore(call, out.Result)
		return out
	}
	e.used = true
	done := make(chan struct{})
	e.activeDone = done
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.activeDone = nil; close(done); e.mu.Unlock() }()
	ctx = telemetry.CallContext(ctx, call)
	out.OperationID = e.descriptor.InitID
	a := openAdmission{domain: e.descriptor.DomainID, trust: e.descriptor.TrustID, interpretation: contract.InterpretationID(),
		recipient: e.descriptor.AuthorityRecipientID, composition: e.composition, store: e.store.Descriptor(), epoch: 1,
		controlIncarnation: e.descriptor.NormalSigning.Binding.ControlIncarnationID, publicKey: e.descriptor.NormalSigning.SPKI,
		descriptor: e.descriptorBytes, expires: deadline}
	var state *StateSession
	var request contract.GenesisRequestCore
	if e.installation == nil {
		state, out.Result = e.observe(ctx, a)
		if state != nil {
			request = state.head.Genesis.Request
			out.RequestIdentity = state.head.Genesis.Subject.RequestCoreDigest
		}
	} else {
		state, request, out.RequestIdentity, out.Result = e.initialize(ctx, a, deadline)
	}
	out.StateResult = initializationState(out.Result)
	if state != nil && out.Result.Evidence == AuthenticatedClosure && out.Result.Outcome == ObservedCurrent {
		expected, err := genesisReceipt(request, state.head.Core.Revision)
		body, encodeErr := contract.EncodeCompactMutationReceipt(expected)
		retained, found := state.mutationReceipts[request.InitID]
		if err != nil || encodeErr != nil || !found || retained != expected {
			out.Result = failure(IntegrityFailure, InvalidRelation)
			out.StateResult = contract.InitializationPositiveDefect
		} else {
			out.Receipt = body
			out.Payload = &contract.InitPayload{InitID: e.descriptor.InitID, DomainID: e.descriptor.DomainID,
				DescriptorArtifactID: e.descriptor.DescriptorArtifactID, ManifestArtifactID: e.descriptor.ManifestArtifactID,
				DescriptorDigest: contract.Hash(e.descriptorBytes), StoreID: e.descriptor.StoreID,
				HeadRevisionID: state.head.Core.Revision, SnapshotID: state.root.Snapshot}
			basis := PublicBasis{Descriptor: bytes.Clone(e.descriptorBytes)}
			out.PublicBasis = &basis
			if e.installation == nil {
				out.StateResult = contract.InitializationExactResume
			}
		}
	}
	finishCore(call, out.Result)
	return out
}

func initializationState(result Result) contract.InitializationStateResult {
	switch result.Outcome {
	case ObservedCurrent:
		return contract.InitializationSuccess
	case Contention:
		return contract.InitializationContention
	case UnresolvedCommit:
		return contract.InitializationCommitUnknown
	case IntegrityFailure:
		return contract.InitializationPositiveDefect
	case EvidenceUnavailable, RootLossUnsupported:
		return contract.InitializationUnavailable
	default:
		return contract.InitializationRefused
	}
}

func (e *InstalledInitializer) initialize(ctx context.Context, a openAdmission, deadline time.Time) (*StateSession, contract.GenesisRequestCore, contract.ID, Result) {
	i := e.installation
	fact, err := i.PersistDescriptor(ctx, e.descriptor.DescriptorArtifactID, bytes.Clone(e.descriptorBytes))
	if err != nil || ctx.Err() != nil || !artifactMatches(fact, 1, e.descriptor.DescriptorArtifactID, e.descriptorBytes) {
		return nil, contract.GenesisRequestCore{}, contract.ID{}, failure(EvidenceUnavailable, WriteUncertain)
	}
	p, err := planGenesisScope(a, i.SetupDigest, uint64(deadline.UnixNano()))
	if err != nil {
		return nil, contract.GenesisRequestCore{}, contract.ID{}, refused(InvalidFormat)
	}
	requestIdentity := contract.Hash(p.requestBytes)
	manifest, err := i.PersistManifest(ctx, e.descriptor.ManifestArtifactID, bytes.Clone(p.manifestBytes))
	if err != nil || ctx.Err() != nil || !artifactMatches(manifest, 2, e.descriptor.ManifestArtifactID, p.manifestBytes) {
		return nil, p.request, requestIdentity, failure(EvidenceUnavailable, WriteUncertain)
	}
	ids, err := allocateGenesisIDs(rand.Reader)
	if err != nil {
		return nil, p.request, requestIdentity, refused(AdmissionInvalid)
	}
	bindings, err := e.descriptor.BindingTable()
	if err != nil {
		return nil, p.request, requestIdentity, refused(InvalidFormat)
	}
	q := contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: contract.GenesisProfile,
		AdmissionID: ids.Init, SessionID: ids.Domain, DomainID: e.descriptor.DomainID, CompatibilityID: contract.CompatibilityID(),
		Expiry: uint64(deadline.UnixNano()), InitID: e.descriptor.InitID, DescriptorDigest: contract.Hash(e.descriptorBytes),
		GenesisPlanDigest: contract.Hash(p.planBytes), RequestDescriptor: contract.DescriptorVector{Digest: requestIdentity, Length: uint64(len(p.requestBytes)), Count: 1}},
		Bindings: bindings, Probes: append([]contract.InitProbePlanRow(nil), p.plan.Probes...)}
	if ctx.Err() != nil {
		return nil, p.request, requestIdentity, refused(AdmissionInvalid)
	}
	custody, closeCustody, err := i.AdmitCustody(ctx, q)
	if err != nil || custody == nil || closeCustody == nil {
		if closeCustody != nil {
			closeCustody()
		}
		return nil, p.request, requestIdentity, refused(CustodyUnavailable)
	}
	defer closeCustody()
	admitted := InitContext{admission: &initAdmission{open: OpenContext{admission: &a}, prepared: p,
		descriptor: artifactReceipt{fact: fact}, manifest: artifactReceipt{fact: manifest}, qualification: q,
		requestID: ids.DescriptorArtifact, custodyID: custody.InstanceID(), custody: custody, deadline: deadline}}
	state, result := initialize(ctx, admitted, e.store, i.Normal, i.Recovery, custody)
	return state, p.request, requestIdentity, result
}

func (e *InstalledInitializer) observe(ctx context.Context, a openAdmission) (*StateSession, Result) {
	selected, result := open(ctx, OpenContext{admission: &a}, e.store)
	if selected == nil {
		return nil, result
	}
	if selected.head.Genesis == nil || selected.head.Genesis.Subject.InitID != e.descriptor.InitID ||
		!selected.validGenesisSelection(e.descriptor) {
		return nil, failure(Contention, DifferentSelection)
	}
	g := selected.head.Genesis
	p, err := reconstructGenesisPlan(e.descriptor, g.Plan.IdentityPlan, g.Plan.Probes, g.Plan.K3ChallengeID, g.Request.SetupDigest, g.Request.Expiry)
	if err != nil || !bytes.Equal(p.manifestBytes, e.retainedManifest) || !selectedGenesisPreparation(selected.head, p) {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	return selected, result
}

func (e *InstalledInitializer) Close() {
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
		e.installation, e.store, e.closeInstalled = nil, nil, nil
		e.descriptorBytes, e.retainedManifest = nil, nil
		e.descriptor = contract.GenesisDescriptorCore{}
		e.mu.Unlock()
		if closeInstalled != nil {
			closeInstalled()
		}
	})
}
