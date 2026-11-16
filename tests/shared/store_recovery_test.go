package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestColdOpenRetriesEachTransportUnavailableStoreRead(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	defer keys.RetireGenerated()
	fixture := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	store := env.Store.(*memoryStore)
	seen := make(map[string]int)
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		seen[key]++
		if seen[key] == 1 {
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport, Body: []byte("partial")}
		}
		return result
	}
	creates, cas := store.creates, store.cas
	fresh, result := Open(ctx, fixture.admission, store)
	if fresh == nil || result.Outcome != ObservedCurrent || len(seen) < 3 {
		t.Fatal("cold open did not recover its selected closure", result, seen)
	}
	for key, calls := range seen {
		if calls < 2 {
			t.Fatal("transport failure did not retry exact key", key, calls)
		}
	}
	if store.creates != creates || store.cas != cas {
		t.Fatal("read recovery changed selected state")
	}
}

// full_only: false
func TestColdOpenDoesNotRetryNonTransportHEADFailures(t *testing.T) {
	for _, fault := range []contract.ReadResult{
		{Status: contract.ReadMissing},
		{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess},
		{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed},
	} {
		ctx := context.Background()
		env, keys := genesisEnvironment(t, contract.GCP, false)
		fixture := newEnvironmentFixture(t, ctx, env, []int{1}, false)
		store := env.Store.(*memoryStore)
		store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
			if key == store.desc.HeadKey {
				return fault
			}
			return result
		}
		before := store.reads
		fresh, _ := Open(ctx, fixture.admission, store)
		keys.RetireGenerated()
		if fresh != nil || store.reads != before+1 {
			t.Fatal("non-transport HEAD failure was retried")
		}
	}
}

// full_only: false
func TestStateScenarioCountsTransportReadRetryWithoutLosingEffectCheck(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.AWS, false)
	defer keys.RetireGenerated()
	store := env.Store.(*memoryStore)
	var transitionCAS int
	var injected bool
	env.Phase = func(name string) {
		if name != "transition" {
			return
		}
		transitionCAS = store.cas
		store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
			if key == store.desc.HeadKey && store.cas > transitionCAS && !injected {
				injected = true
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
			}
			return result
		}
	}
	runOrdinaryStateScenario(t, ctx, env, "state.single-value-update-preserves-other-values/members_32")
	if !injected {
		t.Fatal("transition did not exercise a transport read retry")
	}
}

// full_only: false
func TestSameDomainFreshApplyRevalidatesGoalAfterTransportFailure(t *testing.T) {
	for _, mode := range []string{"lost-before", "lost-after"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			defer keys.RetireGenerated()
			fixture := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			store := env.Store.(*memoryStore)
			desired := fixture.session.currentEntryInputs()
			desired[0].InputBytes = []byte("fresh desired value")
			first, result := fixture.session.Compare(ctx, desired, admitSuppliedComparison(t, fixture.session, nil, desired))
			if first == nil || result.Outcome != ObservedCurrent {
				t.Fatal("first comparison", result)
			}
			candidate, result := fixture.session.Prepare(ctx, first, admit(t, fixture.session, first), env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("first preparation", result)
			}
			store.casMode = mode
			firstResult := fixture.session.Select(ctx, candidate)
			if mode == "lost-before" && (firstResult.Outcome != EvidenceUnavailable || firstResult.StoreReason != contract.ReasonTransport) || mode == "lost-after" && firstResult.Outcome != ObservedCurrent {
				t.Fatal("first transport result", firstResult)
			}
			store.casMode = ""
			fresh, result := Open(ctx, fixture.admission, store)
			if fresh == nil || result.Outcome != ObservedCurrent {
				t.Fatal("same-domain fresh open", result)
			}
			comparison, result := fresh.Compare(ctx, desired, admitSuppliedComparison(t, fresh, nil, desired))
			if mode == "lost-after" {
				if comparison != nil || result.Outcome != Unchanged {
					t.Fatal("already current goal did not observe no change", result)
				}
				return
			}
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("fresh goal was not admitted against current state", result)
			}
			newCandidate, result := fresh.Prepare(ctx, comparison, admit(t, fresh, comparison), env.Trust)
			if newCandidate == nil || result.Outcome != ObservedCurrent || newCandidate.head.Core.Revision == candidate.head.Core.Revision {
				t.Fatal("fresh invocation reused old candidate identity", result)
			}
			if result := fresh.Select(ctx, newCandidate); result.Outcome != ObservedCurrent {
				t.Fatal("fresh selection", result)
			}
			cold, result := Open(ctx, fixture.admission, store)
			if cold == nil || result.Outcome != ObservedCurrent {
				t.Fatal("cold verification", result)
			}
			if comparison, result := cold.Compare(ctx, desired, admitSuppliedComparison(t, cold, nil, desired)); comparison != nil || result.Outcome != Unchanged {
				t.Fatal("cold goal verification", result)
			}
		})
	}
}

type configurationTestStore struct {
	contract.Store
	create func(context.Context, string, []byte) contract.WriteResult
}

func (s configurationTestStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	if s.create != nil {
		return s.create(ctx, key, body)
	}
	return s.Store.Create(ctx, key, body)
}

type configurationSourceTestStore struct {
	configurationTestStore
	configuration contract.StoreConfiguration
}

func (s configurationSourceTestStore) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}

// full_only: false
func TestGenesisConfigurationFailurePreventsSelectedWrites(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, fault := range []string{"create refused", "missing", "changed", "invalid", "unavailable", "collision"} {
			t.Run(fmt.Sprintf("%d/%s", family, fault), func(t *testing.T) {
				env, _ := genesisEnvironment(t, family, false)
				memory := env.Store.(*memoryStore)
				admission := fixtureAdmission(env)
				init, _ := fixtureInitAdmission(t, env, admission)
				key, err := contract.StoreConfigurationKey(memory.configuration)
				if err != nil {
					t.Fatal(err)
				}
				store := configurationSourceTestStore{configurationTestStore: configurationTestStore{Store: memory}, configuration: memory.configuration}
				want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}
				switch fault {
				case "create refused":
					store.create = func(ctx context.Context, actual string, body []byte) contract.WriteResult {
						if actual != key {
							t.Fatal("dependent write before helper", actual)
						}
						return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
					}
					want = Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, StoreReason: contract.ReasonAccess}
				case "collision":
					memory.put(key, []byte("unequal immutable helper"))
					want = failure(IntegrityFailure, ImmutableConflict)
				default:
					memory.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
						if actual != key {
							return read
						}
						switch fault {
						case "missing":
							return contract.ReadResult{Status: contract.ReadMissing}
						case "unavailable":
							return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
						case "invalid":
							return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
						default:
							read.Body = bytes.Clone(read.Body)
							read.Body[len(read.Body)-1] ^= 1
							return read
						}
					}
					if fault == "unavailable" {
						want.StoreReason = contract.ReasonAccess
					}
					if fault == "changed" || fault == "invalid" {
						want = failure(IntegrityFailure, ImmutableConflict)
					}
				}
				s, result := Initialize(t.Context(), init, store, env.Trust.(contract.QualifyingTrust), nil, env.Crypto)
				if s != nil || result != want || memory.cas != 0 {
					t.Fatal("helper failure did not refuse", result, want)
				}
				if _, present := memory.objects[memory.desc.HeadKey]; present {
					t.Fatal("helper failure selected HEAD")
				}
				for actual := range memory.objects {
					if actual != key {
						t.Fatal("helper failure wrote selected child", actual)
					}
				}
			})
		}
	}
}

// full_only: false
func TestGenesisConfigurationSourceRefusesBeforeQualification(t *testing.T) {
	for _, fault := range []string{"absent", "domain", "provider", "construction", "invalid profile"} {
		t.Run(fault, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			memory := env.Store.(*memoryStore)
			init, _ := fixtureInitAdmission(t, env, fixtureAdmission(env))
			var store contract.Store = configurationTestStore{Store: memory}
			configuration := memory.configuration
			switch fault {
			case "domain":
				configuration.DomainID[0] ^= 1
			case "provider":
				configuration.Provider = contract.AWS
			case "construction":
				configuration.Bucket = "another-bucket"
			case "invalid profile":
				configuration.ConstructionProfile++
			}
			if fault != "absent" {
				store = configurationSourceTestStore{configurationTestStore: configurationTestStore{Store: memory}, configuration: configuration}
			}
			public, private := keys.Calls()
			trust := env.Trust.(*fixtureTrust)
			signs := trust.signs
			qualifications := trust.QualificationCalls()
			s, result := Initialize(t.Context(), init, store, trust, nil, env.Crypto)
			if s != nil || result != refused(ConstructionMismatch) || memory.creates != 0 || memory.cas != 0 || memory.reads != 1 || trust.signs != signs || trust.QualificationCalls() != qualifications {
				t.Fatal("invalid Source reached qualification or dependent effects", result)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
				t.Fatal("invalid Source reached custody")
			}
		})
	}
}

// full_only: false
func TestGenesisConfigurationEqualReuseAndReadbackOrder(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			env, _ := genesisEnvironment(t, family, true)
			memory := env.Store.(*memoryStore)
			init, _ := fixtureInitAdmission(t, env, fixtureAdmission(env))
			key, err := contract.StoreConfigurationKey(memory.configuration)
			if err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodeStoreConfiguration(memory.configuration)
			if err != nil {
				t.Fatal(err)
			}
			memory.put(key, body)
			original := memory.objects[key]
			verified := false
			memory.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					verified = read.Status == contract.ReadOK && bytes.Equal(read.Body, body)
				}
				return read
			}
			store := configurationSourceTestStore{configurationTestStore: configurationTestStore{Store: memory}, configuration: memory.configuration}
			store.create = func(ctx context.Context, actual string, bytes []byte) contract.WriteResult {
				if actual != key && !verified {
					t.Fatal("selected write before helper readback", actual)
				}
				return memory.Create(ctx, actual, bytes)
			}
			s, result := Initialize(t.Context(), init, store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
			if s == nil || result.Outcome != ObservedCurrent || !verified || memory.objects[key].Token != original.Token || !bytes.Equal(memory.objects[key].Body, body) {
				t.Fatal("equal helper was not reused exactly", result)
			}
			fact := s.head.Genesis.Closure.ConfigurationReadbackFact
			if fact.Kind != 3 || fact.ArtifactID != memory.desc.Identity || fact.BodyDigest != memory.desc.Identity || fact.BodyLength != uint64(len(body)) {
				t.Fatal("signed helper readback differs", fact)
			}
		})
	}
}

// full_only: false
func TestOrdinaryLifecycleMakesNoConfigurationGET(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", family, recovery), func(t *testing.T) {
				env, keys := genesisEnvironment(t, family, recovery)
				f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
				memory := env.Store.(*memoryStore)
				key, err := contract.StoreConfigurationKey(memory.configuration)
				if err != nil {
					t.Fatal(err)
				}
				delete(memory.objects, key)
				helperReads := 0
				memory.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
					if actual == key {
						helperReads++
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
					}
					return read
				}
				keys.SetUnavailable(true)
				public, private := keys.Calls()
				current, result := Open(t.Context(), f.admission, memory)
				if current == nil || result.Outcome != ObservedCurrent {
					t.Fatal("ordinary Open", result)
				}
				input := current.currentEntryInputs()
				input[0].InputBytes = []byte("new plain bytes")
				comparison, result := current.Compare(t.Context(), input, admitSuppliedComparison(t, current, nil, input))
				if comparison == nil {
					t.Fatal("ordinary Compare", result)
				}
				candidate, result := current.Prepare(t.Context(), comparison, admit(t, current, comparison), env.Trust)
				if candidate == nil {
					t.Fatal("ordinary Prepare", result)
				}
				if result = current.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
					t.Fatal("ordinary Select", result)
				}
				fresh, result := Open(t.Context(), f.admission, memory)
				if fresh == nil || result.Outcome != ObservedCurrent {
					t.Fatal("ordinary reopen", result)
				}
				if c, result := fresh.Compare(t.Context(), input, admitSuppliedComparison(t, fresh, nil, input)); c != nil || result.Outcome != Unchanged {
					t.Fatal("ordinary no-op", result)
				}
				if gotPublic, gotPrivate := keys.Calls(); helperReads != 0 || gotPublic != public || gotPrivate != private {
					t.Fatal("ordinary operation fetched helper or unavailable custody", helperReads)
				}
			})
		}
	}
}

type refusedGenesisHeadStore struct{ configurationSourceTestStore }

func (s refusedGenesisHeadStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}

// full_only: false
func TestGenesisHeadFailureLeavesConfigurationUnselected(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	memory := env.Store.(*memoryStore)
	init, _ := fixtureInitAdmission(t, env, fixtureAdmission(env))
	key, err := contract.StoreConfigurationKey(memory.configuration)
	if err != nil {
		t.Fatal(err)
	}
	store := refusedGenesisHeadStore{configurationSourceTestStore{configurationTestStore: configurationTestStore{Store: memory}, configuration: memory.configuration}}
	s, result := Initialize(t.Context(), init, store, env.Trust.(contract.QualifyingTrust), nil, env.Crypto)
	want := Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, StoreReason: contract.ReasonAccess}
	if s != nil || result != want {
		t.Fatal("failed HEAD publication returned a selection", result, want)
	}
	body, err := contract.EncodeStoreConfiguration(memory.configuration)
	if err != nil || !bytes.Equal(memory.objects[key].Body, body) {
		t.Fatal("helper was not durably written before failed HEAD", err)
	}
	if _, ok := memory.objects[memory.desc.HeadKey]; ok {
		t.Fatal("failed HEAD publication selected a helper")
	}
	newer := memory.configuration
	newer.Bucket = "unrelated-helper"
	newerKey, err := contract.StoreConfigurationKey(newer)
	if err != nil {
		t.Fatal(err)
	}
	newerBody, err := contract.EncodeStoreConfiguration(newer)
	if err != nil {
		t.Fatal(err)
	}
	memory.put(newerKey, newerBody)
	if selected, result := Open(t.Context(), fixtureAdmission(env), memory); selected != nil || result != failure(RootLossUnsupported, MissingSelectedObject) {
		t.Fatal("unselected or newer helper fabricated current state", result)
	}
}
