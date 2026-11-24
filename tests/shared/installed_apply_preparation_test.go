package core

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type applyPreparationTestStore struct {
	mu sync.Mutex
	contract.Store
	memory      *memoryStore
	create      func(context.Context, string, []byte) contract.WriteResult
	read        func(context.Context, string, uint32) contract.ReadResult
	puts, sends int
}

func (s *applyPreparationTestStore) admittedMemoryStore() *memoryStore { return s.memory }
func (s *applyPreparationTestStore) StoreConfiguration() contract.StoreConfiguration {
	return s.memory.StoreConfiguration()
}
func (s *applyPreparationTestStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	s.mu.Lock()
	s.puts++
	s.mu.Unlock()
	return s.create(ctx, key, body)
}
func (s *applyPreparationTestStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return s.read(ctx, key, limit)
}
func (s *applyPreparationTestStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.mu.Lock()
	s.sends++
	s.mu.Unlock()
	return s.Store.CompareAndSwap(ctx, key, token, body)
}

func readApplyPreparation(t testing.TB, out PublicApplyResult) (uint64, uint64, bool, bool) {
	t.Helper()
	if out.Preparation == nil {
		return 0, 0, false, false
	}
	facts := out.Preparation
	return facts.AcknowledgedCreates, facts.VerifiedPreparations, facts.PossibleUnacknowledgedCreate, true
}

func assertPositiveApplyPreparation(t testing.TB, out PublicApplyResult) {
	t.Helper()
	ack, verified, possible, present := readApplyPreparation(t, out)
	if !present || ack == 0 || verified == 0 || possible {
		t.Fatal("completed immutable preparation lost its invocation facts", ack, verified, possible, present)
	}
}

// full_only: false
func TestInstalledApplyPreparationRetainsActualImmutableEvidence(t *testing.T) {
	for _, test := range []struct {
		name          string
		ack, verified uint64
		possible      bool
		puts          int
		outcome       Outcome
	}{
		{"acknowledged-verified", 1, 1, false, 1, EvidenceUnavailable},
		{"acknowledged-unverified", 1, 0, false, 1, EvidenceUnavailable},
		{"equal-preexisting", 0, 1, false, 1, EvidenceUnavailable},
		{"lost-acknowledgement-verified", 0, 1, true, 1, EvidenceUnavailable},
		{"possible-create-unreadable", 0, 0, true, 1, EvidenceUnavailable},
		{"proved-unsent-unreadable", 0, 0, false, 1, EvidenceUnavailable},
		{"transport-retries-one-episode", 1, 1, true, 3, EvidenceUnavailable},
		{"earlier-unknown-then-refused", 0, 0, true, 2, EvidenceUnavailable},
		{"received-conflict-exact-readback", 0, 1, false, 1, EvidenceUnavailable},
		{"acknowledged-wrong-readback", 1, 0, false, 1, IntegrityFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseCtx, finish := context.WithTimeout(t.Context(), time.Minute)
			defer finish()
			f := newInstalledApplyTestFixture(t, baseCtx, contract.AWS, false)
			ctx, cancel := context.WithCancel(baseCtx)
			defer cancel()
			base := f.env.Store
			store := &applyPreparationTestStore{Store: base, memory: requireAdmittedMemoryStore(t, base)}
			var key string
			var frozen []byte
			store.create = func(ctx context.Context, nextKey string, body []byte) contract.WriteResult {
				if key == "" {
					key, frozen = nextKey, bytes.Clone(body)
				}
				if nextKey != key || !bytes.Equal(body, frozen) {
					t.Fatal("one logical persistence episode changed its key or bytes")
				}
				switch test.name {
				case "equal-preexisting", "received-conflict-exact-readback":
					// An independent existing object has the exact proposed bytes.
					if w := base.Create(ctx, key, frozen); w.Status != contract.WriteAcknowledged {
						t.Fatal("preexisting object fixture", w)
					}
					if test.name == "received-conflict-exact-readback" {
						return contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
					}
					return base.Create(ctx, key, frozen)
				case "lost-acknowledgement-verified":
					if w := base.Create(ctx, key, frozen); w.Status != contract.WriteAcknowledged {
						t.Fatal("lost acknowledgement fixture", w)
					}
					return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
				case "possible-create-unreadable":
					return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
				case "proved-unsent-unreadable":
					return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
				case "transport-retries-one-episode":
					if store.puts < 3 {
						return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
					}
				case "earlier-unknown-then-refused":
					if store.puts == 1 {
						return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
					}
					return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
				}
				return base.Create(ctx, key, frozen)
			}
			store.read = func(ctx context.Context, readKey string, limit uint32) contract.ReadResult {
				if key == "" || readKey != key {
					return base.Read(ctx, readKey, limit)
				}
				switch test.name {
				case "acknowledged-unverified", "possible-create-unreadable", "proved-unsent-unreadable":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				case "transport-retries-one-episode":
					if store.puts < 3 {
						return contract.ReadResult{Status: contract.ReadMissing}
					}
				case "earlier-unknown-then-refused":
					return contract.ReadResult{Status: contract.ReadMissing}
				case "acknowledged-wrong-readback":
					return contract.ReadResult{Status: contract.ReadOK, Body: []byte("different immutable bytes")}
				}
				read := base.Read(ctx, readKey, limit)
				if read.Status != contract.ReadOK || !bytes.Equal(read.Body, frozen) {
					t.Fatal("exact readback fixture", read.Status)
				}
				cancel()
				return read
			}
			f.env.Store = store
			input := []ApplyEntryInput{{Name: "plain", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("preparation evidence")}}
			engine := f.engine(t, f.selected, input, nil)
			out := engine.Apply(ctx, testID("immutable preparation "+test.name), input)
			engine.Close()
			if out.Result.Outcome != test.outcome || out.Result.CommitMayHaveOccurred || out.Payload != nil || len(out.Receipt) != 0 || store.puts != test.puts || store.sends != 0 || key == "" {
				t.Fatal("controlled preparation crossed its actual stage", out.Result, store.puts, store.sends)
			}
			ack, verified, possible, present := readApplyPreparation(t, out)
			if !present || ack != test.ack || verified != test.verified || possible != test.possible {
				t.Fatalf("preparation facts differ: got=%d/%d/%t present=%t want=%d/%d/%t", ack, verified, possible, present, test.ack, test.verified, test.possible)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedPreparationSpansJoinedWritersAndResetsOnContinue(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	x := newInstalledGeneratedCheckpointFixture(t, ctx, "apply")
	second := x.input[0]
	second.Name = "second-generated"
	x.input = append(x.input, second)
	base := x.f.env.Store
	store := &applyPreparationTestStore{Store: base, memory: requireAdmittedMemoryStore(t, base)}
	var mu sync.Mutex
	var acknowledged, verified uint64
	seen := make(map[string]int)
	pending := make(map[string][]byte)
	resultWriters, joined := 0, make(chan struct{})
	store.create = func(ctx context.Context, key string, body []byte) contract.WriteResult {
		if _, err := contract.DecodeGeneratedResultRecord(body); err == nil {
			mu.Lock()
			resultWriters++
			if resultWriters == 2 {
				close(joined)
			}
			mu.Unlock()
			select {
			case <-joined:
			case <-ctx.Done():
				return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonLimit, NotSent: true}
			}
		}
		mu.Lock()
		seen[key]++
		pending[key] = bytes.Clone(body)
		mu.Unlock()
		written := base.Create(ctx, key, body)
		if written.Status == contract.WriteAcknowledged {
			mu.Lock()
			acknowledged++
			mu.Unlock()
		}
		return written
	}
	store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
		read := base.Read(ctx, key, limit)
		mu.Lock()
		if expected, ok := pending[key]; ok && read.Status == contract.ReadOK && bytes.Equal(read.Body, expected) {
			verified++
			delete(pending, key)
		}
		mu.Unlock()
		return read
	}
	x.f.env.Store = store
	adoption := x.callbacks.AdmitAdoption
	x.callbacks.AdmitAdoption = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedAdoptionInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, errors.New("controlled preparation unavailable")
	}
	first := x.invoke(t, ctx, "apply", contract.ID{})
	if first.Result.Outcome != ObservedCurrent || first.Result.Evidence != AuthenticatedClosure || first.OperationID.IsZero() || first.RequestIdentity.IsZero() || len(first.Receipt) != 0 || first.Generated == nil || len(first.Diagnostics) == 0 {
		t.Fatal("controlled adoption failure lost its actual selected checkpoint", first.Result)
	}
	mu.Lock()
	firstAck, firstVerified, writers, outstanding := acknowledged, verified, resultWriters, len(pending)
	repeated := false
	for _, calls := range seen {
		repeated = repeated || calls > 1
	}
	mu.Unlock()
	creates, deletes := x.effects()
	if writers != 2 || outstanding != 0 || !repeated || firstAck == 0 || firstVerified <= firstAck || creates != 2 || len(deletes) != 0 || store.sends != 1 {
		t.Fatal("joined writer/repeated episode controls did not reach the selected checkpoint", writers, outstanding, repeated, firstAck, firstVerified, creates, len(deletes), store.sends)
	}
	ack, verifiedCount, possible, present := readApplyPreparation(t, first)
	if !present || ack != firstAck || verifiedCount != firstVerified || possible {
		t.Fatal("selected checkpoint erased earlier invocation preparation", ack, verifiedCount, possible, firstAck, firstVerified)
	}
	x.selected = x.f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, x.selected)
	if work.parent == nil || work.parent.OperationID != first.OperationID || len(work.attempts) != 2 {
		t.Fatal("cold checkpoint lost its original operation")
	}
	x.callbacks.AdmitAdoption = adoption
	continued := x.invoke(t, ctx, "apply", first.OperationID)
	if continued.Result.Outcome != ObservedCurrent || len(continued.Receipt) == 0 || continued.Generated == nil {
		t.Fatal("fresh Continue did not complete the original selected work", continued.Result)
	}
	mu.Lock()
	continueAck, continueVerified := acknowledged-firstAck, verified-firstVerified
	mu.Unlock()
	ack, verifiedCount, possible, present = readApplyPreparation(t, continued)
	if !present || ack != continueAck || verifiedCount != continueVerified || possible || continueVerified == 0 {
		t.Fatal("fresh Continue reused an earlier invocation collector", ack, verifiedCount, possible, continueAck, continueVerified)
	}
	oldAck, oldVerified, oldPossible, oldPresent := readApplyPreparation(t, first)
	if !oldPresent || oldAck != firstAck || oldVerified != firstVerified || oldPossible {
		t.Fatal("later joined writes changed returned preparation backing")
	}
	x.selected = x.f.open(t, ctx)
	beforePuts, beforeSends := store.puts, store.sends
	retained := x.invoke(t, ctx, "apply", first.OperationID)
	if retained.Result.Outcome != ObservedCurrent || len(retained.Receipt) == 0 || retained.Generated == nil || store.puts != beforePuts || store.sends != beforeSends {
		t.Fatal("retained receipt observation performed another preparation", retained.Result)
	}
	ack, verifiedCount, possible, present = readApplyPreparation(t, retained)
	if !present || ack != 0 || verifiedCount != 0 || possible {
		t.Fatal("retained receipt restored historical preparation counts", ack, verifiedCount, possible)
	}
}

// full_only: false
func TestInstalledApplyPreparationKeepsUnavailableDistinctFromCollectedZero(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	input := []ApplyEntryInput{{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("not admitted")}}
	engine := f.engine(t, f.selected, input, nil)
	defer engine.Close()
	cancelled, stop := context.WithCancel(ctx)
	stop()
	for _, test := range []struct {
		name      string
		ctx       context.Context
		available bool
	}{
		{"nil", nil, false},
		{"cancelled", cancelled, true},
	} {
		out := engine.Apply(test.ctx, testID(test.name+" preparation context"), input)
		if out.Result.Outcome != AdmissionRefused {
			t.Fatal("invalid invocation context admitted", test.name)
		}
		ack, verified, possible, present := readApplyPreparation(t, out)
		if present != test.available || ack != 0 || verified != 0 || possible {
			t.Fatal("invalid invocation changed preparation availability or zero facts", test.name)
		}
	}

}
