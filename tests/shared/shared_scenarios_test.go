package core

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	catalog "enkv.sh/core/internal/testcatalog"
)

// These spies assert protocol effects independently of production telemetry.
// They are test controls and never supply report measurements.
type scenarioEffects struct {
	StoreRead            uint64
	StoreTransportRead   uint64
	StoreTransportCreate uint64
	StoreCreate          uint64
	StoreCAS             uint64
	TrustSign            uint64
	UnknownWrites        uint64
	PreconditionWrites   uint64
	ConflictWrites       uint64
	InjectedLostReplies  uint64
}

type scenarioSpy struct {
	mu sync.Mutex
	scenarioEffects
}

type scenarioRun struct {
	t   testing.TB
	ctx context.Context
	env fixtureEnvironment
	spy *scenarioSpy
}

func (r *scenarioRun) phase(name string, work func()) {
	r.t.Helper()
	r.spy.mu.Lock()
	r.spy.scenarioEffects = scenarioEffects{}
	r.spy.mu.Unlock()
	if r.env.Phase != nil {
		r.env.Phase(name)
	}
	defer func() {
		if r.env.EndPhase != nil {
			r.env.EndPhase(name)
		}
	}()
	work()
}

type scenarioStore struct {
	contract.Store
	spy *scenarioSpy
}

func (s scenarioStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s scenarioStore) admittedMemoryStore() *memoryStore {
	provider, ok := s.Store.(admittedMemoryStoreProvider)
	if !ok {
		return nil
	}
	return provider.admittedMemoryStore()
}

func (s scenarioStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.spy.mu.Lock()
	s.spy.StoreRead++
	s.spy.mu.Unlock()
	result := s.Store.Read(ctx, key, limit)
	if result.Status == contract.ReadUnavailable && result.Reason == contract.ReasonTransport {
		s.spy.mu.Lock()
		s.spy.StoreTransportRead++
		s.spy.mu.Unlock()
	}
	return result
}

func (s scenarioStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	s.spy.mu.Lock()
	s.spy.StoreCreate++
	s.spy.mu.Unlock()
	result := s.Store.Create(ctx, key, body)
	if result.Status == contract.WriteUnknown && result.Reason == contract.ReasonTransport {
		s.spy.mu.Lock()
		s.spy.StoreTransportCreate++
		s.spy.mu.Unlock()
	}
	return s.recordWrite(result)
}

func (s scenarioStore) CreateHead(ctx context.Context, request contract.HeadCreateRequest) contract.WriteResult {
	s.spy.mu.Lock()
	s.spy.StoreCreate++
	s.spy.mu.Unlock()
	result := s.Store.CreateHead(ctx, request)
	if result.Status == contract.WriteUnknown && result.Reason == contract.ReasonTransport {
		s.spy.mu.Lock()
		s.spy.StoreTransportCreate++
		s.spy.mu.Unlock()
	}
	return s.recordWrite(result)
}

func (s scenarioStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.spy.mu.Lock()
	s.spy.StoreCAS++
	s.spy.mu.Unlock()
	return s.recordWrite(s.Store.CompareAndSwap(ctx, key, token, body))
}

func (s scenarioStore) recordWrite(result contract.WriteResult) contract.WriteResult {
	s.spy.mu.Lock()
	defer s.spy.mu.Unlock()
	if result.Status == contract.WriteUnknown {
		s.spy.UnknownWrites++
	}
	if result.Status == contract.WritePrecondition {
		s.spy.PreconditionWrites++
	}
	if result.Status == contract.WriteConflict {
		s.spy.ConflictWrites++
	}
	return result
}

type scenarioTrust struct {
	contract.Trust
	spy *scenarioSpy
}

func (s scenarioTrust) admittedFixtureTrust() *fixtureTrust {
	provider, ok := s.Trust.(admittedFixtureTrustProvider)
	if !ok {
		return nil
	}
	return provider.admittedFixtureTrust()
}

func (s scenarioTrust) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	s.spy.mu.Lock()
	s.spy.TrustSign++
	s.spy.mu.Unlock()
	return s.Trust.Sign(ctx, request)
}

func (s scenarioTrust) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	trust, ok := s.Trust.(contract.QualifyingTrust)
	if !ok {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	return trust.QualifySigningBinding(ctx, binding)
}

func newScenarioRun(t testing.TB, ctx context.Context, env fixtureEnvironment) *scenarioRun {
	if env.Context == nil {
		env.Context = ctx
	}
	r := &scenarioRun{t: t, ctx: ctx, env: env, spy: &scenarioSpy{}}
	r.env.Store = scenarioStore{Store: env.Store, spy: r.spy}
	r.env.Trust = scenarioTrust{Trust: env.Trust, spy: r.spy}
	return r
}

func (r *scenarioRun) open(admission OpenContext) *StateSession {
	r.t.Helper()
	session, result := Open(r.ctx, admission, r.env.Store)
	if session == nil || result.Outcome != ObservedCurrent {
		r.t.Fatalf("open: %+v", result)
	}
	return session
}

func (r *scenarioRun) compare(session *StateSession, requested []ApplyEntryInput) (*Comparison, *AdmittedParentTransition, stateImage) {
	r.t.Helper()
	original := observeSelectedState(r.t, session)
	comparison, result := session.Compare(r.ctx, requested, admitSuppliedComparison(r.t, session, nil, requested))
	if comparison == nil || result.Outcome != ObservedCurrent {
		r.t.Fatalf("compare: %+v", result)
	}
	permit, inputs := admitTransition(r.t, session, comparison)
	return comparison, permit, expectedSuccessorImage(r.t, original, requested, inputs)
}

func (r *scenarioRun) prepare(session *StateSession, comparison *Comparison, permit *AdmittedParentTransition) (*Candidate, Result) {
	r.t.Helper()
	return session.Prepare(r.ctx, comparison, permit, r.env.Trust)
}

func (r *scenarioRun) selectCandidate(session *StateSession, candidate *Candidate) Result {
	return session.Select(r.ctx, candidate)
}

func (r *scenarioRun) verify(admission OpenContext, want stateImage) *StateSession {
	r.t.Helper()
	var session *StateSession
	r.phase("verification", func() {
		session = r.open(admission)
		assertStateImage(r.t, session, want)
	})
	r.phase("reopen", func() {
		if r.env.FreshCurrent != nil {
			assertStateImage(r.t, session, want)
			r.env.FreshCurrent(r.t, admission, session)
		} else if r.env.FreshOpen != nil {
			r.env.FreshOpen(r.t, want)
		} else {
			r.t.Fatal("scenario requires fresh-process verification")
		}
		if r.t.Failed() {
			r.t.FailNow()
		}
	})
	return session
}

func runOrdinaryStateScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	t.Helper()
	// Fixture parameters belong to the selected scenario, even when its actions
	// are shared with another scenario.
	sizes, fragmented, err := catalog.FixtureSizes(name)
	if err != nil {
		t.Fatal(err)
	}
	behavior, known := catalog.Behavior(name)
	if !known {
		t.Fatal("unknown scenario")
	}
	name = behavior
	if env.Store == nil || env.Trust == nil || env.Put == nil || env.Delete == nil {
		t.Fatal("invalid scenario environment")
	}
	r := newScenarioRun(t, ctx, env)
	var f *environmentFixture
	r.phase("setup", func() {
		var names []string
		if name == "capacity.maximum-disjoint-replacement-reuses-successor-slots" {
			names = maximumLifecycleNames("before")
		}
		f = newNamedEnvironmentFixture(t, ctx, r.env, sizes, fragmented, names)
	})
	original := observeSelectedState(t, f.session)
	want := original
	if name == "state.transient-before-send-rerun" {
		requested := original.entryInputs()
		requested[0].InputBytes = append(requested[0].InputBytes, 99)
		if r.env.RecoveryHandoff != nil {
			if err := r.env.RecoveryHandoff(f.session, requested); err != nil {
				t.Fatal("same-domain goal handoff unavailable", err)
			}
		}
		r.phase("transition", func() {
			comparison, permit, next := r.compare(f.session, requested)
			candidate, result := r.prepare(f.session, comparison, permit)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("recovery fixture preparation", result)
			}
			if r.env.InjectBeforeSend != nil {
				r.env.InjectBeforeSend()
			}
			result = r.selectCandidate(f.session, candidate)
			if result.Outcome == EvidenceUnavailable && result.StoreReason == contract.ReasonTransport && r.env.ReportTransportFailure != nil {
				r.env.ReportTransportFailure(result)
				t.FailNow()
			}
			if result.Outcome != ObservedCurrent {
				t.Fatal("recovery fixture selection", result)
			}
			want = next
		})
		r.verify(f.admission, want)
		return
	}
	switch name {
	case "lifecycle.empty-state-preserves-domain-and-readd":
		r.emptyLifecycle(f, original)
		return
	case "lifecycle.mixed-membership-preserves-retained-records":
		r.mixedLifecycle(f, original)
		return
	case "capacity.maximum-disjoint-replacement-reuses-successor-slots":
		r.maximumReplacement(f, original)
		return
	}
	if name == "state.historical-bytes-get-new-identities" {
		r.history(f, original)
		return
	}
	damaged := name == "evidence.missing-selected-child-prevents-open" || name == "evidence.corrupt-selected-child-prevents-open"
	if damaged {
		r.phase("setup", func() {
			r.damageSelectedObject(*original.Root.ValueEntryPages[1], name == "evidence.corrupt-selected-child-prevents-open")
		})
		r.phase("verification", func() {
			session, result := Open(ctx, f.admission, r.env.Store)
			if session != nil || (name == "evidence.missing-selected-child-prevents-open" && (result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject)) || (name == "evidence.corrupt-selected-child-prevents-open" && result.Outcome != IntegrityFailure) {
				t.Fatalf("damaged closure accepted: %+v", result)
			}
		})
		return
	}
	var collisionComparison *Comparison
	var collisionPermit *AdmittedParentTransition
	var collisionNext stateImage
	if name == "storage.equal-immutable-objects-allow-selection" || name == "storage.conflicting-immutable-object-refuses-selection" {
		r.phase("transition", func() {
			requested := original.entryInputs()
			requested[0].InputBytes = append(requested[0].InputBytes, 99)
			collisionComparison, collisionPermit, collisionNext = r.compare(f.session, requested)
		})
		r.phase("setup", func() {
			r.seedExpectedObjects(original, collisionNext, name == "storage.conflicting-immutable-object-refuses-selection")
		})
	}
	r.phase("transition", func() {
		if name == "state.identical-input-keeps-current-state" {
			reads, transportReads := r.spy.StoreRead, r.spy.StoreTransportRead
			comparison, result := f.session.Compare(ctx, original.entryInputs(), admitSuppliedComparison(t, f.session, nil, original.entryInputs()))
			if comparison != nil || result.Outcome != Unchanged || r.spy.StoreRead-reads != 2*uint64(original.Root.OutputConfiguration.SliceCount)+r.spy.StoreTransportRead-transportReads || r.spy.StoreCreate+r.spy.StoreCAS+r.spy.TrustSign != 0 {
				t.Fatal("unchanged comparison changed state or read outside its configuration")
			}
			return
		}

		if name == "selection.concurrent-writers-select-one-complete-state" {
			want = r.twoWriters(f, original)
			return
		}
		requested := original.entryInputs()
		requested[0].InputBytes = append(requested[0].InputBytes, 99)
		if name == "state.same-page-updates-preserve-other-pages" {
			requested[1].InputBytes = append(requested[1].InputBytes, 99)
		}
		if name == "state.cross-page-updates-preserve-other-values" {
			requested[16].InputBytes = append(requested[16].InputBytes, 99)
		}
		if name == "capacity.maximum-size-state-refuses-growth-and-allows-update" {
			if comparison, result := f.session.Compare(ctx, requested, nil); comparison != nil || result.Outcome != AdmissionRefused || result.Reason != CapacityExceeded {
				t.Fatal("oversized image was not refused before writes")
			}
			requested = original.entryInputs()
			for i := range requested {
				requested[i].InputBytes[0] ^= 255
			}
		}
		comparison, permit, next := collisionComparison, collisionPermit, collisionNext
		var comparisonReads uint64
		if comparison == nil {
			comparisonReads = 2 * uint64(original.Root.OutputConfiguration.SliceCount)
			comparison, permit, next = r.compare(f.session, requested)
		}
		if name == "storage.lost-create-reply-recovers-from-readback" || name == "selection.lost-head-reply-recovers-from-observation" {
			r.discardCompletedWriteReply(f.session, name == "selection.lost-head-reply-recovers-from-observation")
		}
		candidate, result := r.prepare(f.session, comparison, permit)
		if name == "storage.conflicting-immutable-object-refuses-selection" {
			if candidate != nil || result.Outcome != IntegrityFailure || result.Reason != ImmutableConflict || r.spy.StoreCAS != 0 || r.spy.TrustSign != 0 || r.spy.PreconditionWrites != 1 {
				t.Fatalf("immutable conflict: %+v", result)
			}
			return
		}
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatalf("prepare: %+v", result)
		}
		if name == "storage.equal-immutable-objects-allow-selection" && r.spy.PreconditionWrites != r.spy.StoreCreate {
			t.Fatal("equal immutable objects did not exercise conditional rejection")
		}
		if name == "selection.prepared-candidate-keeps-current-state" {
			if r.spy.StoreCAS != 0 {
				t.Fatal("preparation selected a HEAD")
			}
			return
		}
		result = r.selectCandidate(f.session, candidate)
		if result.Outcome != ObservedCurrent || result.ObservedRevision != next.Revision || result.ObservedSnapshotID != next.Root.Snapshot || result.Evidence != AuthenticatedClosure || result.CommitMayHaveOccurred {
			t.Fatalf("select: %+v", result)
		}
		want = next
		if name == "storage.lost-create-reply-recovers-from-readback" || name == "selection.lost-head-reply-recovers-from-observation" {
			if r.spy.InjectedLostReplies != 1 || r.spy.UnknownWrites != 1 {
				t.Fatal("completed-reply loss was not exercised exactly once")
			}
		}
		created, _ := successorObjectCounts(original, want)
		configurationReads, materializationReads, retainedPageReads := successorSupportReadCounts(original, want)
		if comparisonReads == 0 {
			// Collision setup already compared and admitted the transition.
			materializationReads = 0
		}
		// The prospective image has no root-bound receipt cache. Prepare
		// authenticates its retained index once before immutable persistence.
		prospectiveReceiptReads := receiptIndexFragmentCount(t, want.Root)
		reads := comparisonReads + r.spy.StoreCreate + 1 + configurationReads +
			retainedPageReads + uint64(want.Root.OutputConfiguration.SliceCount) +
			3*uint64(len(want.Root.Generated.Fragments)) + materializationReads + prospectiveReceiptReads
		if name == "selection.lost-head-reply-recovers-from-observation" {
			// An unknown HEAD reply requires an additional exact HEAD read.
			reads++
		}
		if r.spy.StoreCreate < created || r.spy.StoreCreate > created+2*r.spy.StoreTransportCreate || r.spy.StoreCAS != 1 || r.spy.TrustSign != 1 || r.spy.StoreRead != reads+r.spy.StoreTransportRead {
			t.Fatalf("transition operation counts differ from the state change: creates=%d/%d CAS=%d signs=%d reads=%d/%d transport reads=%d transport creates=%d", r.spy.StoreCreate, created, r.spy.StoreCAS, r.spy.TrustSign, r.spy.StoreRead, reads, r.spy.StoreTransportRead, r.spy.StoreTransportCreate)
		}
	})

	r.verify(f.admission, want)
}

// full_only: false
func TestGeneratedHistoryScenariosUseEveryCatalogStep(t *testing.T) {
	for _, name := range catalog.GeneratedHistoryNames("both") {
		execution, known := catalog.ExecutionFor(name, "hermetic")
		if !known {
			t.Fatal("generated history execution facts unavailable", name)
		}
		if execution.Family == catalog.FamilyCombinedHistory {
			continue
		}
		definition, ok := catalog.DefinitionFor(name)
		if !ok {
			t.Fatal("generated history is absent from the catalog", name)
		}
		for _, mode := range definition.RecoveryModes {
			t.Run(name+"/"+mode, func(t *testing.T) {
				env := memoryScenarioEnvironmentMode(t, mode == "enabled")
				env = syntheticAuthorityScenarioEnvironment(t, env)
				step := 0
				env.Phase = func(phase string) {
					if step >= len(definition.Steps) || definition.Steps[step].Name != phase {
						t.Fatal("generated history action differs from catalog plan", step, phase)
					}
					step++
				}
				runStateScenario(t, context.Background(), env, name)
				if step != len(definition.Steps) {
					t.Fatal("generated history omitted catalog steps", step, len(definition.Steps))
				}
			})
		}
	}
}

func (r *scenarioRun) seedExpectedObjects(original, next stateImage, conflict bool) {
	r.t.Helper()
	for i, ref := range next.Root.ValueEntryPages {
		if ref == nil || (original.Root.ValueEntryPages[i] != nil && *ref == *original.Root.ValueEntryPages[i]) {
			continue
		}
		body, err := format.EncodeValueEntryPage(*next.Pages[i])
		if err != nil {
			r.t.Fatal(err)
		}
		if conflict {
			body = []byte("different owned immutable bytes")
		}
		if err := r.env.Put(r.ctx, mustKey(r.t, r.env.Store.Descriptor().Prefix, *ref), body); err != nil {
			r.t.Fatal("immutable fixture creation failed")
		}
		if conflict {
			return
		}
	}
	indexPages, err := format.EncodeAdministrativeIndexPages(next.AdministrativeIndex)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, page := range indexPages {
		if err := r.env.Put(r.ctx, mustKey(r.t, r.env.Store.Descriptor().Prefix, page.Ref), page.Body); err != nil {
			r.t.Fatal("immutable administrative index creation failed")
		}
	}
	body, err := format.EncodeRoot(next.Root)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.env.Put(r.ctx, mustKey(r.t, r.env.Store.Descriptor().Prefix, next.RootRef), body); err != nil {
		r.t.Fatal("immutable root creation failed")
	}
}

func (r *scenarioRun) twoWriters(f *environmentFixture, original stateImage) stateImage {
	r.t.Helper()
	sessions := []*StateSession{f.session, r.open(f.admission)}
	var candidates [2]*Candidate
	var expected [2]stateImage
	for i, session := range sessions {
		input := original.entryInputs()
		input[i].InputBytes = []byte{byte(100 + i)}
		comparison, permit, want := r.compare(session, input)
		candidate, result := r.prepare(session, comparison, permit)
		if candidate == nil || result.Outcome != ObservedCurrent {
			r.t.Fatalf("prepare competing writer: %+v", result)
		}
		candidates[i], expected[i] = candidate, want
	}
	var results [2]Result
	var finished sync.WaitGroup
	if r.env.ControlDelayedCAS {
		// Hold A before provider entry. B selects first; A then sends its
		// unchanged original condition through the real Store.
		delayed := &barrierCASStore{Store: sessions[0].store, entered: make(chan struct{}), release: make(chan struct{})}
		sessions[0].store = delayed
		finished.Add(1)
		go func() {
			defer finished.Done()
			results[0] = r.selectCandidate(sessions[0], candidates[0])
		}()
		select {
		case <-delayed.entered:
		case <-r.ctx.Done():
			close(delayed.release)
			finished.Wait()
			r.t.Fatal("delayed selection did not reach the Store")
		}
		results[1] = r.selectCandidate(sessions[1], candidates[1])
		close(delayed.release)
		finished.Wait()
	} else {
		ready := make(chan struct{})
		for i := range sessions {
			finished.Add(1)
			go func(i int) {
				defer finished.Done()
				<-ready
				results[i] = r.selectCandidate(sessions[i], candidates[i])
			}(i)
		}
		close(ready)
		finished.Wait()
	}
	winner, loser := 0, 1
	if results[1].Outcome == ObservedCurrent {
		winner, loser = 1, 0
	}
	winning, losing := results[winner], results[loser]
	if winning.Outcome != ObservedCurrent || winning.RequestedRevision != expected[winner].Revision || winning.ObservedRevision != expected[winner].Revision || winning.ObservedSnapshotID != expected[winner].Root.Snapshot || winning.Evidence != AuthenticatedClosure || winning.CommitMayHaveOccurred || losing.RequestedRevision != expected[loser].Revision || r.spy.StoreCAS != 2 || r.spy.UnknownWrites != 0 || r.spy.PreconditionWrites+r.spy.ConflictWrites != 1 {
		r.t.Fatalf("competing selections: %+v", results)
	}
	switch {
	case r.spy.PreconditionWrites == 1:
		if losing.Outcome != Contention || losing.Reason != StalePrecondition || losing.CommitMayHaveOccurred || losing.ObservedRevision != original.Revision || losing.ObservedSnapshotID != original.Root.Snapshot || losing.Evidence != AuthenticatedClosure {
			r.t.Fatalf("precondition loser: %+v", losing)
		}
	case r.spy.ConflictWrites == 1:
		observedOriginal := losing.ObservedRevision == original.Revision && losing.ObservedSnapshotID == original.Root.Snapshot
		observedWinner := losing.ObservedRevision == winning.ObservedRevision && losing.ObservedSnapshotID == winning.ObservedSnapshotID
		reason := WriteUncertain
		if observedWinner {
			reason = DifferentSelection
		}
		if losing.Outcome != UnresolvedCommit || losing.Reason != reason || !losing.CommitMayHaveOccurred || (!observedOriginal && !observedWinner) || losing.Evidence != AuthenticatedClosure {
			r.t.Fatalf("conflict loser: %+v", losing)
		}
	}
	return expected[winner]
}

type barrierCASStore struct {
	contract.Store
	entered chan struct{}
	release chan struct{}
}

func (s *barrierCASStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s *barrierCASStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	close(s.entered)
	select {
	case <-s.release:
		return s.Store.CompareAndSwap(ctx, key, token, body)
	case <-ctx.Done():
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	}
}

func (r *scenarioRun) history(f *environmentFixture, original stateImage) {
	r.t.Helper()
	seen := historyIDs(original)
	var staleSession *StateSession
	var staleCandidate *Candidate
	r.phase("transition", func() {
		staleSession = r.open(f.admission)
		input := original.entryInputs()
		input[0].InputBytes, input[16].InputBytes = []byte("B"), []byte("B")
		comparison, permit, _ := r.compare(staleSession, input)
		assertFreshAllocatedIDs(r.t, seen, observeAllocatedTransitionInputs(permit))
		var result Result
		staleCandidate, result = r.prepare(staleSession, comparison, permit)
		if staleCandidate == nil || result.Outcome != ObservedCurrent {
			r.t.Fatalf("prepare retained candidate: %+v", result)
		}
	})
	want := original
	for step := 0; step < 3; step++ {
		r.phase("transition", func() {
			session := r.open(f.admission)
			input := want.entryInputs()
			switch step {
			case 0:
				input[0].InputBytes, input[16].InputBytes = []byte("B"), []byte("B")
			case 1:
				input[1].InputBytes = []byte("second generation")
			case 2:
				input[0].InputBytes, input[16].InputBytes = original.entryInputs()[0].InputBytes, original.entryInputs()[16].InputBytes
			}
			comparison, permit, next := r.compare(session, input)
			assertFreshAllocatedIDs(r.t, seen, observeAllocatedTransitionInputs(permit))
			candidate, result := r.prepare(session, comparison, permit)
			if candidate == nil || result.Outcome != ObservedCurrent {
				r.t.Fatalf("history preparation: %+v", result)
			}
			if result := r.selectCandidate(session, candidate); result.Outcome != ObservedCurrent || result.ObservedRevision != next.Revision {
				r.t.Fatalf("history selection: %+v", result)
			}
			want = next
		})
		r.verify(f.admission, want)
	}
	for _, slot := range []uint16{0, 16} {
		before := original.Pages[slot/format.PageSlots].Slots[slot%format.PageSlots]
		after := want.Pages[slot/format.PageSlots].Slots[slot%format.PageSlots]
		if !bytes.Equal(before.ValueBytes, after.ValueBytes) || before.ValueState == after.ValueState || before.OriginSnapshot == after.OriginSnapshot || before.OriginTransition == after.OriginTransition {
			r.t.Fatal("equal historical bytes reused identity or origins")
		}
	}
	r.phase("transition", func() {
		result := r.selectCandidate(staleSession, staleCandidate)
		if result.Outcome != Contention || result.Reason != StalePrecondition || r.spy.StoreCAS != 1 || r.spy.StoreRead+r.spy.StoreCreate+r.spy.TrustSign != 0 {
			r.t.Fatalf("stale history candidate: %+v", result)
		}
	})
	r.verify(f.admission, want)
}

// The underlying call has completed before this wrapper discards its reply.
type completedReplyLoss struct {
	contract.Store
	head bool
	lost bool
	spy  *scenarioSpy
}

func (s *completedReplyLoss) lose(result contract.WriteResult) contract.WriteResult {
	if !s.lost && result.Status == contract.WriteAcknowledged {
		s.lost = true
		s.spy.mu.Lock()
		s.spy.InjectedLostReplies++
		s.spy.mu.Unlock()
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	return result
}

func (s *completedReplyLoss) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	result := s.Store.Create(ctx, key, body)
	if !s.head {
		return s.lose(result)
	}
	return result
}

func (s *completedReplyLoss) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	result := s.Store.CompareAndSwap(ctx, key, token, body)
	if s.head {
		return s.lose(result)
	}
	return result
}
