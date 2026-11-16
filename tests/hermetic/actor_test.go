package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

type hermeticReaderStore struct {
	mu            sync.Mutex
	store         *memoryStore
	deny, refused bool
	reads, writes int
}

func (s *hermeticReaderStore) StoreConfiguration() contract.StoreConfiguration {
	return s.store.StoreConfiguration()
}

func (s *hermeticReaderStore) Descriptor() contract.Descriptor { return s.store.Descriptor() }

func (s *hermeticReaderStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	s.mu.Lock()
	s.reads++
	s.refused = false
	deny := s.deny
	s.mu.Unlock()
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	if deny {
		s.mu.Lock()
		s.refused = true
		s.mu.Unlock()
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	}
	return s.store.Read(ctx, key, maximum)
}

func (s *hermeticReaderStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}

func (s *hermeticReaderStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}

func (s *hermeticReaderStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}

// full_only: false
func TestHermeticScenarioParticipantsAndOutcomes(t *testing.T) {
	for _, test := range []struct{ scenario, outcome, participant string }{
		{"state.single-value-update-preserves-other-values/members_32", "success", "operator"},
		{"access.observer-sees-selected-state/members_32_observer", "success", "auditor"},
		{"access.distinct-observer-sees-selected-state/members_32_distinct_observer", "success", "auditor"},
		{"access.provider-refuses-observer/members_32_denied_observer", "access-refused", "denied-auditor"},
	} {
		t.Run(test.scenario, func(t *testing.T) {
			inv := hermeticCheckInvocation(t, test.scenario)
			var input hermeticWorkerInput
			if records.ReadJSON(inv.Input, &input) != nil {
				t.Fatal("input unavailable")
			}
			if catalog.HasFixtureCapability(test.scenario, catalog.FixtureObserver) {
				execution, _ := catalog.ExecutionFor(test.scenario, "hermetic")
				input.Participants[execution.FreshAfter[0].Role] = test.participant
			}

			if records.WriteJSON(inv.Input, input, 0o400) != nil {
				t.Fatal("actor input could not be saved")
			}
			if output, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err != nil {
				t.Fatalf("point writer: %v %s", err, output)
			}
			writer := hermeticCheckResult(t, inv)
			if writer.Actor != "operator" || writer.Outcome != "passed" || len(writer.Children) != 2 || len(writer.FreshChecks) != 2 {
				t.Fatal("writer did not retain the complete actor witness")
			}
			owner, _, _, err := records.PrivateOwner(inv.StateDir)
			if err != nil {
				t.Fatal("actor owner unavailable")
			}
			for index, check := range writer.FreshChecks {
				before, err := records.LoadInvocation(filepath.Join(owner, writer.Children[index].Invocation))
				if err != nil {
					t.Fatal("fresh reader invocation unavailable")
				}
				after := hermeticCheckAfter(t, inv, check.Facts, check.RecoveryMode)
				if output, err := hermeticCheckCommand(t, after, "", "TestHermeticChild"); err != nil {
					t.Fatalf("point reader after writer exit: %v %s", err, output)
				}
				for _, fresh := range []records.Invocation{before, after} {
					result := hermeticCheckResult(t, fresh)
					if result.Actor != test.participant || result.Outcome != "passed" || len(result.Phases) != 1 || result.Phases[0].Actor != test.participant || result.Phases[0].Expected != test.outcome || result.Phases[0].Actual != test.outcome || result.Phases[0].RecoveryMode != []string{"disabled", "enabled"}[index] {
						t.Fatal("fresh actor result lost the exact expected or actual outcome")
					}
				}
			}
		})
	}
}

// full_only: false
func TestHermeticActorsOwnReadBoundaryWithoutWriterFallback(t *testing.T) {
	f := newFixture(t, 32, false, 1)
	want := sessionStateImage(t, f.session)
	for _, outcome := range []string{"success", "access-refused", "unavailable"} {
		t.Run(outcome, func(t *testing.T) {
			objects := make(map[string]stored, len(f.store.objects))
			for key, value := range f.store.objects {
				objects[key] = stored{Body: bytes.Clone(value.Body), Token: value.Token}
			}
			owned := &memoryStore{desc: f.store.desc, configuration: f.store.configuration, objects: objects}
			if outcome == "unavailable" {
				owned.readHook = func(string, contract.ReadResult) contract.ReadResult {
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				}
			}
			reader := &hermeticReaderStore{store: owned, deny: outcome == "access-refused"}
			writerReads, writerCreates, writerCAS, signs := f.store.reads, f.store.creates, f.store.cas, f.trust.signs
			session, result := Open(context.Background(), f.admission, reader)
			if got := readerReadOutcome(result, reader.refused); got != outcome {
				t.Fatalf("reader outcome = %s; want %s", got, outcome)
			}
			if outcome == "success" {
				if session == nil {
					t.Fatal("reader could not open complete state")
				}
				assertStateImage(t, session, want)
				if reader.reads != len(processPlainReadRequests(t, f.store.desc, want)) || session.admission.recipient != f.admission.admission.recipient {
					t.Fatal("reader skipped state or changed the single Product recipient")
				}
			} else if expectedReads := map[string]int{"access-refused": 1, "unavailable": 3}[outcome]; session != nil || reader.reads != expectedReads {
				t.Fatal("reader crossed its bounded read-failure result")
			}
			if reader.Descriptor() != f.store.Descriptor() || reader.writes != 0 || owned.creates != 0 || owned.cas != 0 || f.store.reads != writerReads || f.store.creates != writerCreates || f.store.cas != writerCAS || f.trust.signs != signs {
				t.Fatal("reader changed bindings, used writer state, wrote, or signed")
			}
		})
	}
}

// full_only: false
func TestHermeticMissingParticipantsFailBeforeFixtures(t *testing.T) {
	inv := hermeticCheckInvocation(t, "access.observer-sees-selected-state/members_32_observer")
	var input hermeticWorkerInput
	if err := records.ReadJSON(inv.Input, &input); err != nil {
		t.Fatal(err)
	}
	delete(input.Participants, "observer")
	if err := records.WriteJSON(inv.Input, input, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := hermeticCheckCommand(t, inv, "", "TestHermeticRun"); err == nil {
		t.Fatal("missing observer admitted")
	}
	for _, path := range []string{filepath.Join(inv.OutputDir, "worker.json"), filepath.Join(inv.StateDir, "facts")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("missing participant created fixture effects")
		}
	}
}
