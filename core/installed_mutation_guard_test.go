package core

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
)

type installedGuardFixtureStore struct {
	descriptor contract.Descriptor
	calls      []string
	read       contract.ReadResult
	write      contract.WriteResult
	onCreate   func()
}

func (s *installedGuardFixtureStore) Descriptor() contract.Descriptor { return s.descriptor }
func (s *installedGuardFixtureStore) Read(context.Context, string, uint32) contract.ReadResult {
	s.calls = append(s.calls, "read")
	return s.read
}
func (s *installedGuardFixtureStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.calls = append(s.calls, "create")
	if s.onCreate != nil {
		s.onCreate()
	}
	return s.write
}
func (s *installedGuardFixtureStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.calls = append(s.calls, "create-head")
	return s.write
}
func (s *installedGuardFixtureStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.calls = append(s.calls, "cas")
	return s.write
}

type installedGuardFixtureConfiguration struct {
	*installedGuardFixtureStore
	configuration contract.StoreConfiguration
}

func (s *installedGuardFixtureConfiguration) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}

type installedGuardFixtureTrust struct {
	id                    contract.ID
	signs, qualifications int
	binding               contract.PublicSigningBinding
	qualification         contract.SigningQualificationResult
	request               contract.SignRequest
}

func (t *installedGuardFixtureTrust) Identity() contract.ID { return t.id }
func (*installedGuardFixtureTrust) Family() contract.Family { return contract.GCP }
func (t *installedGuardFixtureTrust) Sign(_ context.Context, request contract.SignRequest) contract.SignResult {
	t.signs++
	t.request = request
	return contract.SignResult{Signature: []byte{3, 1, 4}}
}
func (t *installedGuardFixtureTrust) QualifySigningBinding(_ context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	t.qualifications++
	t.binding = binding
	return t.qualification
}

// full_only: false
func TestInstalledMutationGuardChecksSourcesBeforeCalls(t *testing.T) {
	sourceErr := errors.New("source changed")
	for _, operation := range []string{"logical-read-boundary", "create", "sign", "qualifying-sign", "cas"} {
		t.Run(operation, func(t *testing.T) {
			backend := &installedGuardFixtureStore{}
			checks := 0
			g, err := newInstalledMutationGuard(backend, func(context.Context) error { checks++; return sourceErr })
			if err != nil {
				t.Fatal(err)
			}
			trust := &installedGuardFixtureTrust{}
			refusedWrite := contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
			switch operation {
			case "logical-read-boundary":
				if got := g.check(t.Context()); got != contract.ReasonConstruction {
					t.Fatal(got)
				}
			case "create":
				if got := g.Store().Create(t.Context(), "object", []byte{1}); got != refusedWrite {
					t.Fatal(got)
				}
			case "sign", "qualifying-sign":
				signer := g.Trust(trust)
				if operation == "qualifying-sign" {
					signer = g.QualifyingTrust(trust)
				}
				if got := signer.Sign(t.Context(), contract.SignRequest{}); !reflect.DeepEqual(got, contract.SignResult{Reason: contract.ReasonConstruction}) {
					t.Fatal(got)
				}
			case "cas":
				if got := g.Store().CompareAndSwap(t.Context(), "HEAD", contract.Token{}, []byte{1}); got != refusedWrite {
					t.Fatal(got)
				}
			}
			if len(backend.calls) != 0 || trust.signs != 0 || checks != 1 || !errors.Is(g.SourceError(), sourceErr) {
				t.Fatal("source refusal reached backend or lost source error", backend.calls, trust.signs, checks, g.SourceError())
			}
			// Restoring the source cannot resume an invocation that already failed.
			g.checkSource = func(context.Context) error { t.Fatal("failed invocation checked source again"); return nil }
			if got := g.Store().Create(t.Context(), "object", []byte{1}); got != refusedWrite || len(backend.calls) != 0 {
				t.Fatal("source failure was not retained", got, backend.calls)
			}
		})
	}
}

// full_only: false
func TestInstalledMutationGuardPreservesCapabilitiesAndResults(t *testing.T) {
	descriptor := contract.Descriptor{Family: contract.GCP, Identity: generatedVectorID(1), Coordinate: generatedVectorID(2), NonBody: generatedVectorID(3), Prefix: "installed", HeadKey: "installed/HEAD"}
	read := contract.ReadResult{Status: contract.ReadOK, Body: []byte{1, 2}, Token: contract.Token{Family: contract.GCP, Value: "7"}}
	write := contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	backend := &installedGuardFixtureStore{descriptor: descriptor, read: read, write: write}
	checks := 0
	g, err := newInstalledMutationGuard(backend, func(context.Context) error { checks++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if g.Store() != g.Store() || g.Store().Descriptor() != descriptor {
		t.Fatal("unstable store delegate or descriptor")
	}
	if _, ok := g.Store().(contract.StoreConfigurationSource); ok {
		t.Fatal("invented configuration capability")
	}
	if got := g.Store().Read(t.Context(), "object", 64); !reflect.DeepEqual(got, read) {
		t.Fatal("read result changed", got)
	}
	for range 2 {
		if got := g.Store().Create(t.Context(), "object", []byte{3}); got != write {
			t.Fatal("immutable write result changed", got)
		}
	}
	if got := g.Store().CompareAndSwap(t.Context(), descriptor.HeadKey, read.Token, []byte{4}); got != write {
		t.Fatal("first CAS result changed", got)
	}
	if got := g.Store().CompareAndSwap(t.Context(), descriptor.HeadKey, read.Token, []byte{4}); got != (contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}) {
		t.Fatal("blocked CAS invented physical attempt", got)
	}
	request, err := contract.NewHeadCreateRequest(descriptor, []byte{5})
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Store().CreateHead(t.Context(), request); got != (contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}) {
		t.Fatal("installed guard allowed HEAD creation", got)
	}
	if !reflect.DeepEqual(backend.calls, []string{"read", "create", "create", "cas"}) || checks != 3 || g.SourceError() != nil {
		t.Fatal("unexpected backend calls or checks", backend.calls, checks, g.SourceError())
	}
	configuration := contract.StoreConfiguration{Provider: contract.GCP, ConstructionProfile: contract.StoreConstructionProfile, DomainID: generatedVectorID(4), Region: "us-central1", Bucket: "fixture-bucket", PrefixBeforeHEAD: "installed"}
	configured, err := newInstalledMutationGuard(&installedGuardFixtureConfiguration{installedGuardFixtureStore: backend, configuration: configuration}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	source, ok := configured.Store().(contract.StoreConfigurationSource)
	if !ok || source.StoreConfiguration() != configuration {
		t.Fatal("configuration capability or facts lost")
	}
	trust := &installedGuardFixtureTrust{id: generatedVectorID(5), qualification: contract.SigningQualificationResult{TargetRole: contract.NormalSignerTarget, Provider: contract.GCP, Qualified: 1, SigningBindingDigest: generatedVectorID(6)}}
	signer := g.QualifyingTrust(trust)
	binding := contract.PublicSigningBinding{Schema: 1, Role: contract.NormalSigningRole, Provider: contract.GCP, SigningProfile: 2, BindingID: generatedVectorID(7), KeySelector: "exact-key", SPKI: []byte{1, 2, 3}, Fingerprint: generatedVectorID(8), Binding: contract.BindingSubject{Domain: generatedVectorID(9), Epoch: 2}}
	if got := signer.QualifySigningBinding(t.Context(), binding); got != trust.qualification || trust.qualifications != 1 || !reflect.DeepEqual(trust.binding, binding) {
		t.Fatal("qualification changed", got)
	}
	if signer.Identity() != trust.id || signer.Family() != contract.GCP {
		t.Fatal("signing route changed")
	}
	signRequest, err := contract.NewBindingRequest(contract.BindingSubject{Domain: generatedVectorID(10), Coordinate: generatedVectorID(11), Store: generatedVectorID(12), Trust: trust.id, PublicKey: generatedVectorID(13), Interpretation: generatedVectorID(14), ControlIncarnationID: generatedVectorID(15), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := signer.Sign(t.Context(), signRequest); !reflect.DeepEqual(got, contract.SignResult{Signature: []byte{3, 1, 4}}) || trust.signs != 1 || checks != 4 || trust.request != signRequest {
		t.Fatal("guarded sign changed", got, trust.signs, checks)
	}
}

// full_only: false
func TestInstalledMutationGuardLogicalReadChecksDoNotRepeatPerGET(t *testing.T) {
	sourceErr := errors.New("source changed during selected image read")
	var currentErr error
	checks := 0
	read := contract.ReadResult{Status: contract.ReadOK, Body: []byte{1}}
	backend := &installedGuardFixtureStore{read: read}
	g, err := newInstalledMutationGuard(backend, func(context.Context) error { checks++; return currentErr })
	if err != nil {
		t.Fatal(err)
	}
	if reason := g.check(t.Context()); reason != contract.ReasonNone {
		t.Fatal(reason)
	}
	for _, key := range []string{"HEAD", "root", "child"} {
		if got := g.Store().Read(t.Context(), key, 64); !reflect.DeepEqual(got, read) {
			t.Fatal("GET result changed", got)
		}
	}
	currentErr = sourceErr
	if reason := g.check(t.Context()); reason != contract.ReasonConstruction || checks != 2 || !errors.Is(g.SourceError(), sourceErr) {
		t.Fatal("logical read boundary lost source error", reason, checks, g.SourceError())
	}
	if !reflect.DeepEqual(backend.calls, []string{"read", "read", "read"}) {
		t.Fatal("logical read changed backend reads", backend.calls)
	}
}

// full_only: false
func TestInstalledMutationGuardCancellationAndConstruction(t *testing.T) {
	backend := &installedGuardFixtureStore{}
	if _, err := newInstalledMutationGuard(nil, func(context.Context) error { return nil }); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := newInstalledMutationGuard(backend, nil); err == nil {
		t.Fatal("nil source check accepted")
	}
	checks := 0
	g, err := newInstalledMutationGuard(backend, func(context.Context) error { checks++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := g.check(ctx); got != contract.ReasonLimit {
		t.Fatal(got)
	}
	if got := g.Store().CompareAndSwap(ctx, "HEAD", contract.Token{}, nil); got != (contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}) {
		t.Fatal(got)
	}
	if checks != 0 || len(backend.calls) != 0 || g.SourceError() != nil {
		t.Fatal("cancelled call reached source or backend")
	}
	// A cancelled call did not consume the physical CAS allowance.
	if got := g.Store().CompareAndSwap(t.Context(), "HEAD", contract.Token{}, nil); got != backend.write || checks != 1 || !reflect.DeepEqual(backend.calls, []string{"cas"}) {
		t.Fatal("cancelled call consumed CAS allowance", got, checks, backend.calls)
	}
}

// full_only: false
func TestInstalledMutationGuardStopsAfterSourceChangesDuringCreate(t *testing.T) {
	sourceErr := errors.New("source replaced during immutable create")
	var currentErr error
	backend := &installedGuardFixtureStore{write: contract.WriteResult{Status: contract.WriteAcknowledged}}
	backend.onCreate = func() { currentErr = sourceErr }
	g, err := newInstalledMutationGuard(backend, func(context.Context) error { return currentErr })
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Store().Create(t.Context(), "object", []byte{1}); got != backend.write {
		t.Fatal("initial immutable create changed", got)
	}
	trust := &installedGuardFixtureTrust{}
	if got := g.Trust(trust).Sign(t.Context(), contract.SignRequest{}); !reflect.DeepEqual(got, contract.SignResult{Reason: contract.ReasonConstruction}) {
		t.Fatal("changed source reached signer", got)
	}
	if got := g.Store().CompareAndSwap(t.Context(), "HEAD", contract.Token{}, []byte{2}); got != (contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}) {
		t.Fatal("changed source reached CAS", got)
	}
	if !reflect.DeepEqual(backend.calls, []string{"create"}) || trust.signs != 0 || !errors.Is(g.SourceError(), sourceErr) {
		t.Fatal("late source failure lost", backend.calls, trust.signs, g.SourceError())
	}
}

type installedGuardConcurrentStore struct {
	contract.Store
	sends   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (s *installedGuardConcurrentStore) CompareAndSwap(ctx context.Context, _ string, _ contract.Token, _ []byte) contract.WriteResult {
	s.sends.Add(1)
	close(s.entered)
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
}

// full_only: false
func TestInstalledMutationGuardConcurrentCASHasOnePhysicalCall(t *testing.T) {
	backend := &installedGuardConcurrentStore{Store: &installedGuardFixtureStore{}, entered: make(chan struct{}), release: make(chan struct{})}
	g, err := newInstalledMutationGuard(backend, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	joined.Add(1)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); joined.Wait() }()
	first := make(chan contract.WriteResult, 1)
	go func() {
		defer joined.Done()
		first <- g.Store().CompareAndSwap(ctx, "HEAD", contract.Token{}, []byte{1})
	}()
	select {
	case <-backend.entered:
	case <-t.Context().Done():
		t.Fatal("first CAS did not enter backend")
	}
	second := g.Store().CompareAndSwap(t.Context(), "HEAD", contract.Token{}, []byte{1})
	close(backend.release)
	joined.Wait()
	if second != (contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}) || <-first != (contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}) || backend.sends.Load() != 1 {
		t.Fatal("concurrent CAS changed physical effect facts", second, backend.sends.Load())
	}
}

type installedGuardSelectionTraceStore struct {
	contract.Store
	headKey string
	events  []string
	results []contract.WriteResult
}

func (s *installedGuardSelectionTraceStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if key == s.headKey {
		s.events = append(s.events, "head")
	}
	return s.Store.Read(ctx, key, limit)
}
func (s *installedGuardSelectionTraceStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.events = append(s.events, "cas")
	result := s.Store.CompareAndSwap(ctx, key, token, body)
	s.results = append(s.results, result)
	return result
}

// full_only: false
func TestInstalledMutationGuardUnknownCASPreservesSelectionFacts(t *testing.T) {
	for _, name := range []string{"predecessor remains", "exact candidate selected", "first call not sent"} {
		t.Run(name, func(t *testing.T) {
			commit := name == "exact candidate selected"
			s, _, backend := observationSelectedPredecessor(t)
			c, owner, _ := observationPrepareNextSelection(t, s, 105000, "guarded", "enabled")
			before, _ := owner.read()
			backend.commit = commit
			backend.write = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: name == "first call not sent"}
			g, err := newInstalledMutationGuard(backend, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			trace := &installedGuardSelectionTraceStore{Store: g.Store(), headKey: s.admission.store.HeadKey}
			s.store = trace
			sendsBefore := backend.sends
			selected, result := s.selectCandidate(t.Context(), c)
			want := Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: c.head.Core.Revision, ObservedRevision: s.head.Core.Revision, ObservedSnapshotID: s.root.Snapshot, Evidence: AuthenticatedClosure, StoreReason: contract.ReasonTransport, CommitMayHaveOccurred: true}
			events := []string{"cas", "head", "head", "cas", "head"}
			writes := []contract.WriteResult{{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, {Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}}
			if commit {
				want = Result{Outcome: ObservedCurrent, RequestedRevision: c.head.Core.Revision, ObservedRevision: c.head.Core.Revision, ObservedSnapshotID: c.head.Core.Root.Object, Evidence: AuthenticatedClosure}
				events, writes = events[:3], writes[:1]
			}
			if name == "first call not sent" {
				want = Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, RequestedRevision: c.head.Core.Revision, StoreReason: contract.ReasonLimit}
				events = []string{"cas", "head", "head", "cas"}
				writes[0].NotSent = true
			}
			selectedMatches := selected != nil && selected.head.Core.Revision == want.ObservedRevision
			if name == "first call not sent" {
				selectedMatches = selected == nil
			}
			if result != want || !selectedMatches || backend.sends-sendsBefore != 1 || !reflect.DeepEqual(trace.events, events) || !reflect.DeepEqual(trace.results, writes) {
				t.Fatal("guard changed selection or physical attempts", result, want, backend.sends-sendsBefore, trace.events, trace.results)
			}
			observationCheckSelectionFact(t, s, c, owner, before, want)
		})
	}
}
