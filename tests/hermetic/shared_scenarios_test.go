package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type conditionalConflictStore struct {
	contract.Store
	mu       sync.Mutex
	active   bool
	started  bool
	readBack chan struct{}
	readOnce sync.Once
}

func (s *conditionalConflictStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s *conditionalConflictStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.mu.Lock()
	active := s.active
	s.mu.Unlock()
	if !active {
		return s.Store.CompareAndSwap(ctx, key, token, body)
	}
	if s.readBack != nil {
		s.mu.Lock()
		winner := !s.started
		s.started = true
		s.mu.Unlock()
		if !winner {
			return contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
		}
		select {
		case <-s.readBack:
		case <-ctx.Done():
			return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
		}
	}
	result := s.Store.CompareAndSwap(ctx, key, token, body)
	if result.Status == contract.WritePrecondition {
		return contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
	}
	return result
}

func (s *conditionalConflictStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	result := s.Store.Read(ctx, key, limit)
	if s.readBack != nil && key == s.Descriptor().HeadKey {
		s.mu.Lock()
		started := s.started
		s.mu.Unlock()
		if started {
			s.readOnce.Do(func() { close(s.readBack) })
		}
	}
	return result
}

// full_only: false
func TestSharedTwoWritersConditionalOutcomes(t *testing.T) {
	for _, name := range []string{"precondition", "conflict-after-write", "conflict-before-write"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			env := memoryScenarioEnvironment(t)
			conflict := name != "precondition"
			var fault *conditionalConflictStore
			if conflict {
				fault = &conditionalConflictStore{Store: env.Store}
				if name == "conflict-before-write" {
					fault.readBack = make(chan struct{})
				}
				env.Store = fault
			}
			spy := &scenarioSpy{}
			env.Store = scenarioStore{Store: env.Store, spy: spy}
			env.EndPhase = func(phase string) {
				if phase == "setup" {
					spy.mu.Lock()
					spy.scenarioEffects = scenarioEffects{}
					spy.mu.Unlock()
					if fault != nil {
						fault.mu.Lock()
						fault.active = true
						fault.mu.Unlock()
					}
				}
			}
			runStateScenario(t, ctx, env, "selection.concurrent-writers-select-one-complete-state/members_32_two_writers")
			preconditions, conflicts := uint64(1), uint64(0)
			if conflict {
				preconditions, conflicts = 0, 1
			}
			if spy.StoreCAS != 2 || spy.PreconditionWrites != preconditions || spy.ConflictWrites != conflicts || spy.UnknownWrites != 0 {
				t.Fatalf("conditional write effects: %+v", spy.scenarioEffects)
			}
		})
	}
}

// full_only: false
func TestSmallPointMemberCounts(t *testing.T) {
	for _, count := range []int{1, 2, 16, 32, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			env := memoryScenarioEnvironment(t)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			var reads, creates, cas, signs int
			env.Phase = func(name string) {
				if name == "transition" {
					reads, creates, cas, signs = store.reads, store.creates, store.cas, trust.signs
				}
			}
			env.EndPhase = func(name string) {
				// Compare borrows configuration twice. Prepare reads the retained
				// configuration, receipt index and three immutable readbacks.
				// Select reads HEAD, two opaque pages, the configuration slice,
				// and the receipt fragment in three distinct checks.
				const transitionReads = 2 + (1 + 1 + 3) + (1 + 2 + 1 + 3)
				if name == "transition" && (store.reads-reads != transitionReads || store.creates-creates != 3 || store.cas-cas != 1 || trust.signs-signs != 1) {
					t.Fatalf("point change effects differ: reads=%d/%d creates=%d/3 CAS=%d/1 signs=%d/1", store.reads-reads, transitionReads, store.creates-creates, store.cas-cas, trust.signs-signs)
				}
			}
			runStateScenario(t, context.Background(), env, fmt.Sprintf("state.single-value-update-preserves-other-values/members_%d", count))
		})
	}
}

// full_only: false
func TestEmptyGenesisScenarioAuthenticatesDuringTransition(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env := memoryScenarioEnvironmentMode(t, recovery)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			var reads, creates, cas, signs, public, private int
			env.Phase = func(name string) {
				if name == "transition" {
					reads, creates, cas, signs = store.reads, store.creates, store.cas, trust.signs
					public, private = env.Custody.Calls()
				}
			}
			env.EndPhase = func(name string) {
				if name != "transition" {
					return
				}
				gotPublic, gotPrivate := env.Custody.Calls()
				if store.reads == reads {
					t.Fatal("empty-genesis transition did not authenticate selected storage")
				}
				if store.creates != creates || store.cas != cas || trust.signs != signs || gotPublic != public || gotPrivate != private {
					t.Fatal("empty-genesis public authentication changed state or used private custody")
				}
			}
			runFirstFlowScenario(t, context.Background(), env, "genesis.empty-domain-reopens/empty_genesis")
		})
	}
}

// full_only: false
func TestEnvironmentFixtureUsesSuppliedBindings(t *testing.T) {
	for _, family := range []contract.Family{contract.GCP, contract.AWS} {
		env, _ := genesisEnvironment(t, family, false)
		store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
		store.desc = contract.Descriptor{Family: family, Coordinate: testID("alternate-coordinate"), NonBody: testID("alternate-nonbody"), Prefix: "alternate", HeadKey: "alternate/HEAD"}
		store.configure(t, family, env.Domain)
		trust.Signer = testtrust.New(t, family, testID("alternate-trust"))
		env.PublicKey, env.SigningSelector = trust.PublicKey(), trust.KeySelector()
		f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
		head := f.session.head.Core
		if head.Domain != env.Domain || head.Store != store.desc.Identity || head.Trust != trust.Identity() || head.Coordinate != store.desc.Coordinate || head.NonBody != store.desc.NonBody || head.PreviousToken.Family != family || trust.signs != 3 {
			t.Fatal("fixture ignored supplied admission bindings or signing source")
		}
		if !bytes.Equal(f.admission.admission.publicKey, env.PublicKey) {
			t.Fatal("fixture replaced the supplied public trust basis")
		}
		fresh, result := Open(context.Background(), fixtureAdmission(env), env.Store)
		if fresh == nil || result.Outcome != ObservedCurrent {
			t.Fatalf("independent admission could not reopen supplied environment: %+v", result)
		}
		assertStateImage(t, fresh, sessionStateImage(t, f.session))
	}
}

// full_only: false
func TestDistinctDomainsHaveDistinctInitialIdentities(t *testing.T) {
	first, second := memoryScenarioEnvironment(t), memoryScenarioEnvironment(t)
	if first.Domain == second.Domain {
		t.Fatal("Core reused a domain identity")
	}
	a := newEnvironmentFixture(t, context.Background(), first, []int{1}, false).session
	b := newEnvironmentFixture(t, context.Background(), second, []int{1}, false).session
	for _, pair := range [][2]contract.ID{{a.root.Snapshot, b.root.Snapshot}, {a.root.Transition, b.root.Transition}, {a.head.Core.Revision, b.head.Core.Revision}, {a.head.Subject.Operation, b.head.Subject.Operation}, {a.pages[0].Object, b.pages[0].Object}, {a.pages[0].Slots[0].Incarnation, b.pages[0].Slots[0].Incarnation}, {a.pages[0].Slots[0].ValueState, b.pages[0].Slots[0].ValueState}, {a.recipient.Object, b.recipient.Object}, {a.recipient.Slots[0].RecipientID, b.recipient.Slots[0].RecipientID}} {
		if pair[0] == pair[1] {
			t.Fatal("distinct fixture domains reused an initial identity")
		}
	}
}

type phaseCompletion struct {
	Name          string
	Failed        bool
	EffectPresent bool
}

// full_only: false
func TestScenarioPhaseRetainsFailureEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "completion.json")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, exe, "-test.run=^TestScenarioPhaseFailureChild$")
	command.Env = append(os.Environ(), "ENKV_PHASE_COMPLETION="+path)
	if err := command.Run(); err == nil {
		t.Fatal("deliberately failed phase did not fail the child")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var completion phaseCompletion
	if err := json.Unmarshal(body, &completion); err != nil {
		t.Fatal(err)
	}
	if completion.Name != "transition" || !completion.Failed || !completion.EffectPresent {
		t.Fatal("failed phase lost its identity, failure or completed effect")
	}
}

// full_only: false
func TestScenarioPhaseFailureChild(t *testing.T) {
	path := os.Getenv("ENKV_PHASE_COMPLETION")
	if path == "" {
		t.Skip("phase failure entry requires a parent invocation")
	}
	ctx := context.Background()
	env := memoryScenarioEnvironment(t)
	key, effect := env.Store.Descriptor().Prefix+"/phase-effect", []byte("completed before failure")
	env.EndPhase = func(name string) {
		result := env.Store.Read(ctx, key, uint32(len(effect)))
		completion := phaseCompletion{Name: name, Failed: t.Failed(), EffectPresent: result.Status == contract.ReadOK && bytes.Equal(result.Body, effect)}
		body, err := json.Marshal(completion)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := newScenarioRun(t, ctx, env)
	r.phase("transition", func() {
		if result := r.env.Store.Create(ctx, key, effect); result.Status != contract.WriteAcknowledged {
			t.Fatal("controlled phase effect was not created")
		}
		t.Fatal("deliberate phase failure")
	})
}
