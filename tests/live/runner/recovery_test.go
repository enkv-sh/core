package core

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
)

const beforeSendRecoveryScenario = "state.transient-before-send-rerun/one_value_before_send"

type beforeSendRecoveryStore struct {
	contract.Store
	active atomic.Bool
}

func (s *beforeSendRecoveryStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

// Discard one completed provider read so Core must repeat the exact request.
type completedReadLoss struct {
	contract.Store
	lost bool
}

func (s *completedReadLoss) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s *completedReadLoss) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	result := s.Store.Read(ctx, key, limit)
	if !s.lost && result.Status == contract.ReadOK {
		s.lost = true
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport, Body: []byte("discarded reply")}
	}
	return result
}

func (s *beforeSendRecoveryStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	if s.active.Load() {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	}
	return s.Store.CompareAndSwap(ctx, key, token, body)
}

func saveRecoveryHandoff(inv records.Invocation, input liveRunInput, env fixtureEnvironment, desired []ApplyEntryInput) error {
	if len(desired) == 0 || env.Domain.IsZero() {
		return errors.New("recovery goal unavailable")
	}
	admission := fixtureAdmission(env)
	if admission.admission == nil {
		return errors.New("independent domain basis unavailable")
	}
	handoff := records.RecoveryHandoff{
		Version: 1, RunID: input.RunID, Scenario: input.Scenarios[0], Prefix: input.Prefix, Domain: env.Domain,
		Genesis: records.RecoveryGenesisIDs{Init: env.GenesisIDs.Init, Domain: env.GenesisIDs.Domain, DescriptorArtifact: env.GenesisIDs.DescriptorArtifact, ManifestArtifact: env.GenesisIDs.ManifestArtifact},
		Basis:   bytes.Clone(admission.admission.descriptor),
	}
	for _, value := range desired {
		if value.ValueSource != format.Supplied || value.ConfidentialityClass != format.Plain {
			return errors.New("recovery goal requires protected private custody")
		}
		handoff.Desired = append(handoff.Desired, records.RecoveryPlainValue{Name: value.Name, Recipients: append([]contract.ID(nil), value.Recipients...), Value: bytes.Clone(value.InputBytes)})
	}
	if handoff.Validate(input.RunID, input.Scenarios[0], input.Prefix) != nil {
		return errors.New("recovery goal refused")
	}
	path, err := records.SafePath(inv.StateDir, "recovery-handoff.json")
	if err != nil {
		return err
	}
	if err := writeNewLiveJSON(path, handoff); err != nil {
		return err
	}
	var saved records.RecoveryHandoff
	if records.ReadJSON(filepath.Clean(path), &saved) != nil || saved.Validate(input.RunID, input.Scenarios[0], input.Prefix) != nil || !bytes.Equal(saved.Basis, handoff.Basis) || len(saved.Desired) != len(handoff.Desired) {
		return errors.New("recovery handoff readback unavailable")
	}
	for i, value := range saved.Desired {
		if value.Name != handoff.Desired[i].Name || !slices.Equal(value.Recipients, handoff.Desired[i].Recipients) || !bytes.Equal(value.Value, handoff.Desired[i].Value) {
			return errors.New("recovery handoff goal changed")
		}
	}
	return nil
}

// full_only: false
func TestRecoveryGoalIsDurableBeforeMutation(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	defer keys.RetireGenerated()
	fixture := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := liveRunInput{RunID: "0123456789abcdef0123456789abcdef", Prefix: "enkv-test/0123456789abcdef0123456789abcdef/0000", Scenarios: []string{beforeSendRecoveryScenario}}
	inv := records.Invocation{StateDir: state}
	desired := []ApplyEntryInput{{Name: "desired", Recipients: []contract.ID{fixture.session.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("plain value")}}
	if err := saveRecoveryHandoff(inv, input, env, desired); err != nil {
		t.Fatal("goal was not durably saved", err)
	}
	path, err := records.SafePath(state, "recovery-handoff.json")
	var saved records.RecoveryHandoff
	if err != nil || records.ReadJSON(path, &saved) != nil || saved.Validate(input.RunID, beforeSendRecoveryScenario, input.Prefix) != nil || !bytes.Equal(saved.Desired[0].Value, desired[0].InputBytes) {
		t.Fatal("saved goal or independent domain basis differs")
	}
	desired[0].InputBytes[0] = 'X'
	if bytes.Equal(saved.Desired[0].Value, desired[0].InputBytes) || saveRecoveryHandoff(inv, input, env, desired) == nil {
		t.Fatal("saved goal was mutable or overwritten")
	}
}

// full_only: false
func TestLiveRecovery(t *testing.T) {
	handle, inv, input, failure := readLiveInvocation(t, "rerun")
	runLiveRecovery(handle, inv, input, failure)
}

func runLiveRecovery(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	if input.Scenarios[0] != beforeSendRecoveryScenario {
		t.Fatal("same-domain rerun scenario refused")
	}
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("rerun worker output refused")
	}
	worker.Result.Actor = input.Participants["authority"]
	budget := &runBudget{limits: input.Limits, keys: make(map[string]bool)}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("rerun inventory unavailable")
	}
	defer lease.Close()
	var handoff records.RecoveryHandoff
	handoffPath, err := records.SafePath(inv.StateDir, "recovery-handoff.json")
	if err != nil || records.ReadJSON(handoffPath, &handoff) != nil || handoff.Validate(input.RunID, input.Scenarios[0], input.Prefix) != nil {
		t.Fatal("durable same-domain goal unavailable")
	}
	inventoryPath, err := records.SafePath(inv.StateDir, "inventory.json")
	var image inventoryImage
	if err != nil || records.ReadJSON(inventoryPath, &image) != nil || image.Version != 1 || image.RunID != input.RunID || image.Domain != handoff.Domain || image.Prefix != input.Prefix || image.Binding != settingsBinding(input.Settings) {
		t.Fatal("same-domain inventory identity unavailable")
	}
	inventory := &objectInventory{path: inventoryPath, image: image}
	defer inventory.stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(input.Limits.ElapsedSeconds)*time.Second)
	defer cancel()
	ctx = worker.Context(ctx)
	sequence := liveBeginPhase(t, worker, "authentication", true)
	backend, err := openLiveBackend(ctx, input.Settings, input.Prefix, handoff.Domain)
	var keys *custody.Fixture
	var recovery contract.QualifyingTrust
	if err == nil {
		keys, recovery, err = openLiveCustody(t, ctx, input, handoff.Domain, budget)
	}
	liveEndPhase(t, worker, sequence, err == nil)
	if err != nil {
		t.Fatal("rerun provider admission refused")
	}
	sequence = liveBeginPhase(t, worker, "resource_check", true)
	admitted := budget.reserve(24, 24*operationBodyAllowance, "", 0) && backend.Check(ctx) == nil
	liveEndPhase(t, worker, sequence, admitted)
	if !admitted {
		t.Fatal("rerun resource admission failed")
	}
	store := &completedReadLoss{Store: recordedStore{Store: backend.Store, inventory: inventory, budget: budget}}
	ids := genesisIDs{Init: handoff.Genesis.Init, Domain: handoff.Genesis.Domain, DescriptorArtifact: handoff.Genesis.DescriptorArtifact, ManifestArtifact: handoff.Genesis.ManifestArtifact}
	env := fixtureEnvironment{GenesisIDs: ids, Store: store, Trust: budgetTrust{Trust: backend.Trust, budget: budget}, Domain: handoff.Domain, PublicKey: backend.PublicKey,
		SigningSelector: input.Settings.KeyID, Bindings: keys.Bindings(), Crypto: keys.Crypto(), Custody: keys, Recovery: recovery, RecoverySelector: input.Settings.RecoveryKeyID}
	if recovery != nil {
		env.RecoveryPublicKey, err = livePublicDER(input.Settings.RecoveryPublicKeyPEM)
		if err != nil {
			t.Fatal("rerun recovery basis unavailable")
		}
	}
	admission := fixtureAdmission(env)
	if admission.admission == nil || !bytes.Equal(admission.admission.descriptor, handoff.Basis) {
		t.Fatal("rerun changed independent domain basis")
	}
	sequence = liveBeginPhase(t, worker, "transition", true)
	current, result := Open(ctx, admission, store)
	if current == nil || result.Outcome != ObservedCurrent || !store.lost {
		t.Fatal("same-domain current state unavailable", result)
	}
	desired := make([]ApplyEntryInput, 0, len(handoff.Desired))
	for _, value := range handoff.Desired {
		desired = append(desired, ApplyEntryInput{Name: value.Name, Recipients: slices.Clone(value.Recipients), ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: bytes.Clone(value.Value), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	}
	comparison, result := current.Compare(ctx, desired, admitSuppliedComparison(t, current, nil, desired))
	selected := current
	if comparison == nil {
		if result.Outcome != Unchanged {
			t.Fatal("rerun goal comparison unavailable", result)
		}
	} else {
		if result.Outcome != ObservedCurrent {
			t.Fatal("rerun goal comparison refused", result)
		}
		candidate, prepared := current.Prepare(ctx, comparison, admit(t, current, comparison), env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("rerun fresh preparation refused", prepared)
		}
		result = current.Select(ctx, candidate)
		if result.Outcome != ObservedCurrent {
			t.Fatal("rerun fresh selection unavailable", result)
		}
		selected, result = Open(ctx, admission, store)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("rerun selected state unavailable", result)
		}
	}
	liveEndPhase(t, worker, sequence, !t.Failed())
	facts := freshFacts{DomainBasis: bytes.Clone(handoff.Basis), Domain: handoff.Domain, Prefix: input.Prefix, Expected: sessionStateImage(t, selected), Receipts: freshReceiptExpectations(t, selected)}
	reads, ok := freshSelectedReadAllowance(facts.Expected)
	reads += freshReceiptReadCount(facts.Receipts)
	if !ok || !budget.admitFreshReads(reads, 1) {
		t.Fatal("rerun cold verification budget exhausted")
	}
	path, err := records.SafePath(inv.StateDir, "recovery-fresh.json")
	if err != nil || writeNewLiveJSON(path, facts) != nil {
		t.Fatal("rerun cold verification facts unavailable")
	}
	worker.Result.FreshChecks = []records.FreshCheck{{Facts: "recovery-fresh.json"}}
	if worker.Save() != nil {
		t.Fatal("rerun evidence unavailable")
	}
}

// full_only: false
func TestLiveStoreWrappersPreserveGenesisConfiguration(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		mode := "disabled"
		if recovery {
			mode = "enabled"
		}
		for _, name := range []string{"before-send", "completed-read", "read-only"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				env, keys := genesisEnvironment(t, liveFamily, recovery)
				defer keys.RetireGenerated()
				store := env.Store.(*memoryStore)
				want := store.StoreConfiguration()
				inventory := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{Version: 1, Prefix: store.desc.Prefix, Deleted: make(map[string]int)}}
				budget := &runBudget{limits: liveLimits{Requests: 1000, BodyBytes: 1 << 33, Objects: 100, ObjectBytes: 1 << 20}, keys: make(map[string]bool)}
				recorded := recordedStore{Store: store, inventory: inventory, budget: budget}
				env.Store = recorded
				var beforeSend *beforeSendRecoveryStore
				if name == "before-send" {
					beforeSend = &beforeSendRecoveryStore{Store: store}
					recorded.Store = beforeSend
					env.Store = recorded
				}
				fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
				if fixture.session.head.Genesis == nil {
					t.Fatal("regression requires selected genesis")
				}
				var loss *completedReadLoss
				switch name {
				case "completed-read":
					loss = &completedReadLoss{Store: recorded}
					env.Store = loss
				case "read-only":
					env.Store = liveReadOnlyStore{Store: recorded, t: t}
				}
				configuration := fixtureStoreConfiguration(env.Store)
				if configuration != want {
					t.Errorf("%s wrapper changed Store configuration", name)
				}
				body, err := contract.EncodeStoreConfiguration(configuration)
				if err != nil {
					t.Error("wrapper configuration cannot be encoded", err)
				} else {
					decoded, err := contract.DecodeStoreConfiguration(body)
					if err != nil || decoded != want || contract.Hash(body) != env.Store.Descriptor().Identity {
						t.Error("wrapper configuration does not round-trip to its descriptor", err)
					}
				}
				reads, creates, cas := store.reads, store.creates, store.cas
				cold, result := Open(t.Context(), fixture.admission, env.Store)
				if cold == nil || result.Outcome != ObservedCurrent || cold.head.Genesis == nil {
					t.Fatal("wrapped cold genesis open refused", result)
				}
				if store.creates != creates || store.cas != cas {
					t.Fatal("cold genesis open changed the Store")
				}
				if loss != nil && (!loss.lost || store.reads <= reads+1) {
					t.Fatal("completed-read loss did not retain its failed read and recovery")
				}
				if beforeSend != nil {
					beforeSend.active.Store(true)
					got := beforeSend.CompareAndSwap(t.Context(), store.desc.HeadKey, cold.token, []byte("refused candidate"))
					want := contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
					if got != want || store.cas != cas {
						t.Fatal("before-send failure injection changed", got)
					}
				}
			})
		}
	}
}
