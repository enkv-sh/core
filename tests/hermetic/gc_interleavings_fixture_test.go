package core

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Callbacks run after the physical Store call releases its mutex. They are
// configured before invocation, so a competing selection can use the same Store.
type gcInterleavingStore struct {
	*memoryStore
	traceMu     sync.Mutex
	readCounts  map[string]int
	deleteCalls []gcDeleteCall
	phases      []contract.GCPhase
	afterRead   func(context.Context, string, contract.ReadResult)
	afterCAS    func(context.Context, format.Head, contract.WriteResult)
	delete      func(context.Context, string, contract.Token) *contract.WriteResult
}

func newGCInterleavingStore(store *memoryStore) *gcInterleavingStore {
	return &gcInterleavingStore{memoryStore: store, readCounts: make(map[string]int)}
}

func (s *gcInterleavingStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	result := s.memoryStore.Read(ctx, key, maximum)
	s.traceMu.Lock()
	s.readCounts[key]++
	s.traceMu.Unlock()
	if s.afterRead != nil {
		result.Body = bytes.Clone(result.Body)
		s.afterRead(ctx, key, result)
	}
	return result
}

func (s *gcInterleavingStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	result := s.memoryStore.CompareAndSwap(ctx, key, token, body)
	head, err := format.DecodeHead(body)
	if err == nil {
		if head.GC != nil {
			s.traceMu.Lock()
			s.phases = append(s.phases, head.GC.Phase)
			s.traceMu.Unlock()
		}
		if s.afterCAS != nil {
			s.afterCAS(ctx, head, result)
		}
	}
	return result
}

func (s *gcInterleavingStore) DeleteIfToken(ctx context.Context, key string, token contract.Token) contract.WriteResult {
	s.traceMu.Lock()
	s.deleteCalls = append(s.deleteCalls, gcDeleteCall{key: key, token: token})
	s.traceMu.Unlock()
	if s.delete != nil {
		if result := s.delete(ctx, key, token); result != nil {
			return *result
		}
	}
	return s.deleteExact(key, token)
}

func (s *gcInterleavingStore) deleteExact(key string, token contract.Token) contract.WriteResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == s.desc.HeadKey || !token.Valid() || token.Family != s.desc.Family {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction, NotSent: true}
	}
	object, present := s.objects[key]
	if !present || object.Token != token {
		return contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	delete(s.objects, key)
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

type gcInterleavingCandidate struct{ store contract.Store }

func (c gcInterleavingCandidate) CandidateLocation() contract.StoreLocation {
	configuration := fixtureStoreConfiguration(c.store)
	return contract.StoreLocation{Provider: configuration.Provider, Bucket: configuration.Bucket, PrefixBeforeHEAD: configuration.PrefixBeforeHEAD, Region: configuration.Region, ExpectedOwner: configuration.ExpectedOwner}
}

func (c gcInterleavingCandidate) ReadHEAD(ctx context.Context) contract.ReadResult {
	return c.store.Read(ctx, c.store.Descriptor().HeadKey, contract.MaxHeadLength)
}

func (c gcInterleavingCandidate) ReadHEADGuarded(ctx context.Context, owner string) contract.ReadResult {
	configuration := fixtureStoreConfiguration(c.store)
	if configuration.Provider != contract.AWS || owner == "" || owner != configuration.ExpectedOwner {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return c.ReadHEAD(ctx)
}

func (c gcInterleavingCandidate) ReadConfiguration(ctx context.Context, domain, id contract.ID) contract.ReadResult {
	d := c.store.Descriptor()
	key, err := contract.StoreConfigurationKeyForID(d.Family, d.Prefix, domain, id)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return c.store.Read(ctx, key, contract.MaxStoreConfigurationLength)
}

func (c gcInterleavingCandidate) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	key, err := contract.StoreObjectKey(c.store.Descriptor().Prefix, ref.Domain, gcPageIdentity(ref))
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return c.store.Read(ctx, key, ref.Length)
}

type gcInterleavingRead struct {
	store contract.Store
	keys  []string
}

func (r *gcInterleavingRead) Descriptor() contract.Descriptor { return r.store.Descriptor() }
func (r *gcInterleavingRead) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(r.store)
}
func (r *gcInterleavingRead) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	return r.store.Read(ctx, key, maximum)
}
func (*gcInterleavingRead) Close() {}
func (r *gcInterleavingRead) ListPage(ctx context.Context, cursor string) contract.ListPageResult {
	if ctx == nil || ctx.Err() != nil || cursor != "" || len(r.keys) > contract.StoreListPageEntries {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: contract.ReasonConstruction}
	}
	return contract.ListPageResult{Status: contract.ListPageOK, Keys: slices.Clone(r.keys)}
}

func gcInterleavingReadInput(t testing.TB, selected *StateSession, store contract.Store, keys []string) CapacityReadInstallation {
	t.Helper()
	ownedKeys := slices.Clone(keys)
	return CapacityReadInstallation{Candidate: gcInterleavingCandidate{store: store},
		Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicCapacityReader, Result) {
			if configuration != fixtureStoreConfiguration(store) {
				return nil, refused(ConstructionMismatch)
			}
			return &gcInterleavingRead{store: store, keys: ownedKeys}, Result{}
		}, ExpectedDomain: selected.root.Domain, ExpectedStore: store.Descriptor(), PublicBasis: selected.admission.publicBasis(),
		SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() {}}
}

func gcInterleavingPreview(t *testing.T, ctx context.Context, selected *StateSession, store contract.Store, keys []string, label string) (contract.GCPlan, []byte) {
	t.Helper()
	reader, err := NewInstalledCapacityReader(gcInterleavingReadInput(t, selected, store, keys))
	if err != nil {
		t.Fatal("GC interleaving preview reader", err)
	}
	defer reader.Close()
	preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: fixtureID(selected.root.Domain, label+" request"), OperationID: fixtureID(selected.root.Domain, label+" operation")})
	if preview.Payload == nil || preview.StateResult != PublicQuerySuccess {
		deadline, finite := ctx.Deadline()
		t.Logf("GC preview failure: state=%s diagnostic=%s finite_context=%t deadline_unix_nano=%d context_failed=%t provider=%d", preview.StateResult, preview.FailureReason, finite, deadline.UnixNano(), ctx.Err() != nil, store.Descriptor().Family)
		if observed, ok := store.(*gcInterleavingStore); ok {
			observed.traceMu.Lock()
			headReads, reads := observed.readCounts[store.Descriptor().HeadKey], 0
			for _, count := range observed.readCounts {
				reads += count
			}
			deletes := len(observed.deleteCalls)
			observed.traceMu.Unlock()
			t.Logf("GC preview Store inventory: reads=%d head_reads=%d deletes=%d", reads, headReads, deletes)
		}
		t.Fatal("GC interleaving preview failed", preview.Result)
	}
	return preview.Payload.Plan, bytes.Clone(preview.Payload.EncodedPlan)
}

func gcInterleavingEngine(t *testing.T, selected *StateSession, store contract.Store, keys []string, trust contract.Trust) *InstalledGC {
	t.Helper()
	reader, err := NewInstalledCapacityReader(gcInterleavingReadInput(t, selected, store, keys))
	if err != nil {
		t.Fatal("GC interleaving mutation reader", err)
	}
	engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: selected.admission.composition,
		ConstructMutation: func(context.Context) (GCMutationResources, error) {
			return GCMutationResources{Store: store, Trust: trust, Close: func() error { return nil }}, nil
		}})
	if err != nil {
		reader.Close()
		t.Fatal("GC interleaving engine", err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error("GC interleaving join failed", err)
		}
	})
	return engine
}

func gcSelectPlanAndReopen(t *testing.T, ctx context.Context, source *StateSession, store *gcInterleavingStore, trust contract.Trust, plan contract.GCPlan) *StateSession {
	t.Helper()
	progress, err := gcInitialProgress(plan)
	if err != nil {
		t.Fatal(err)
	}
	candidate, result := source.prepareGCPhase(ctx, plan, fixtureID(plan.OperationID, "GC admission"), contract.GCSelect, &progress)
	if candidate == nil {
		t.Fatal("prepare GC", result)
	}
	candidate, result = source.persistCandidate(ctx, candidate, trust)
	if candidate == nil {
		t.Fatal("sign GC", result)
	}
	if outcome := source.selectGCCandidate(ctx, candidate); !outcome.confirmed {
		t.Fatal("select GC", outcome.result)
	}
	active := retainedReaderColdOpen(t, source, store)
	if active.root.ActiveGC != plan.OperationID {
		t.Fatal("cold open lost the selected GC operation")
	}
	return active
}
