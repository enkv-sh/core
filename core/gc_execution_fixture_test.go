package core

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type gcDeleteCall struct {
	key   string
	token contract.Token
}
type gcExecutionStore struct {
	mu sync.Mutex
	*gcPublicFixtureStore
	deletes   []gcDeleteCall
	phases    []contract.GCPhase
	onCAS     func(contract.GCPhase, []byte) *contract.WriteResult
	onDelete  func(string, contract.Token) *contract.WriteResult
	onRead    func(string) *contract.ReadResult
	beforeCAS func(contract.GCPhase, []byte)
}

func (s *gcExecutionStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.onRead != nil {
		if result := s.onRead(key); result != nil {
			s.reads[key]++
			return *result
		}
	}
	return s.gcPublicFixtureStore.Read(ctx, key, limit)
}
func (s *gcExecutionStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gcPublicFixtureStore.Create(ctx, key, body)
}
func (s *gcExecutionStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	head, err := format.DecodeHead(body)
	if err != nil || head.GC == nil {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonMalformed, NotSent: true}
	}
	if s.beforeCAS != nil {
		s.beforeCAS(head.GC.Phase, body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phases = append(s.phases, head.GC.Phase)
	if s.onCAS != nil {
		if result := s.onCAS(head.GC.Phase, body); result != nil {
			return *result
		}
	}
	return s.gcPublicFixtureStore.CompareAndSwap(ctx, key, token, body)
}
func (s *gcExecutionStore) DeleteIfToken(_ context.Context, key string, token contract.Token) contract.WriteResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes = append(s.deletes, gcDeleteCall{key, token})
	if s.onDelete != nil {
		if result := s.onDelete(key, token); result != nil {
			return *result
		}
	}
	if token != (contract.Token{Family: contract.GCP, Value: "1"}) {
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	delete(s.objects, key)
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

type gcExecutionCandidate struct{ store *gcExecutionStore }

func (c gcExecutionCandidate) CandidateLocation() contract.StoreLocation {
	return gcPublicFixtureCandidate{c.store.gcPublicFixtureStore}.CandidateLocation()
}
func (c gcExecutionCandidate) ReadHEAD(ctx context.Context) contract.ReadResult {
	return c.store.Read(ctx, c.store.descriptor.HeadKey, contract.MaxHeadLength)
}
func (c gcExecutionCandidate) ReadConfiguration(ctx context.Context, domain, id contract.ID) contract.ReadResult {
	key, err := contract.StoreConfigurationKeyForID(contract.GCP, c.store.descriptor.Prefix, domain, id)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	return c.store.Read(ctx, key, contract.MaxStoreConfigurationLength)
}
func (c gcExecutionCandidate) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	key, err := format.Key(c.store.descriptor.Prefix, ref)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	return c.store.Read(ctx, key, ref.Length)
}

type gcExecutionRead struct {
	store         *gcExecutionStore
	page          contract.ListPageResult
	lists, closes *atomic.Int32
}

func (r *gcExecutionRead) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return r.store.Read(ctx, key, limit)
}
func (r *gcExecutionRead) Descriptor() contract.Descriptor { return r.store.Descriptor() }
func (r *gcExecutionRead) StoreConfiguration() contract.StoreConfiguration {
	return r.store.configuration
}
func (r *gcExecutionRead) Close() { r.closes.Add(1) }
func (r *gcExecutionRead) ListPage(context.Context, string) contract.ListPageResult {
	r.lists.Add(1)
	return r.page
}

func gcExecutionFixture(t *testing.T) (*StateSession, *gcExecutionStore, CapacityReadInstallation, contract.GCPlan, []byte) {
	t.Helper()
	state, base, basis := gcInstalledFixture(t)
	store := &gcExecutionStore{gcPublicFixtureStore: base}
	state.store = store
	page := *state.recipients[0]
	page.Object = gcTestID("runtime-obsolete-page")
	body, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	object := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: page.Object}
	key := gcObjectTestKey(t, base.descriptor, state.root.Domain, object)
	base.objects[key] = bytes.Clone(body)
	var lists, closes atomic.Int32
	input := CapacityReadInstallation{Candidate: gcExecutionCandidate{store}, Construct: func(context.Context, contract.StoreConfiguration) (PublicCapacityReader, Result) {
		return &gcExecutionRead{store: store, page: contract.ListPageResult{Status: contract.ListPageOK, Keys: []string{key}}, lists: &lists, closes: &closes}, Result{}
	}, ExpectedDomain: state.root.Domain, ExpectedStore: base.descriptor, PublicBasis: basis, SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() {}}
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	preview := reader.PlanGC(gcReadContext(t), GCPreviewRequest{RequestNonce: gcTestID("runtime-preview"), OperationID: gcTestID("runtime-operation")})
	reader.Close()
	if preview.Payload == nil || len(preview.Payload.Plan.Targets) != 1 {
		t.Fatal("real runtime GC preview", preview.Result)
	}
	return state, store, input, preview.Payload.Plan, bytes.Clone(preview.Payload.EncodedPlan)
}
func gcExecutionEngine(t *testing.T, state *StateSession, store *gcExecutionStore, input CapacityReadInstallation) (*InstalledGC, *int) {
	t.Helper()
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	factories := 0
	engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
		factories++
		return GCMutationResources{Store: store, Trust: testtrust.New(t, contract.GCP, state.admission.trust), Close: func() error { return nil }}, nil
	}})
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error("GC cleanup failed", err)
		}
	})
	return engine, &factories
}
