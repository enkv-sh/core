package main

import (
	"math"
	"path/filepath"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestSameDomainInventoryReadsTheCompleteStrictRecord(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "inventory.json")
	domain := contract.Hash([]byte("same-domain-inventory"))
	full := map[string]any{
		"version": 1, "run_id": "run", "binding": "binding", "prefix": "prefix", "domain": domain,
		"intents": []any{map[string]any{"key": "prefix/object"}}, "deleted": map[string]int{},
	}
	if err := records.WriteJSON(path, full, 0400); err != nil {
		t.Fatal(err)
	}
	var image sameDomainInventoryRecord
	if err := records.ReadJSON(path, &image); err != nil || image.Version != 1 || image.RunID != "run" || image.Binding != "binding" || image.Prefix != "prefix" || image.Domain != domain || len(image.Intents) != 1 || image.Deleted == nil {
		t.Fatal("complete live inventory was refused", err)
	}
	full["unexpected"] = true
	if err := records.WriteJSON(path, full, 0400); err != nil {
		t.Fatal(err)
	}
	if err := records.ReadJSON(path, &image); err == nil {
		t.Fatal("unknown inventory field was accepted")
	}
}

// full_only: false
func TestSameDomainRerunRequiresJoinedTypedTransportFailure(t *testing.T) {
	worker := records.WorkerResult{Role: "writer", Outcome: "failed", Failure: &records.Failure{Class: "store_transport_exhausted", Stage: "transition"},
		StoreFailure: &records.StoreFailure{StoreReason: "transport", Outcome: "evidence-unavailable", Reason: "write-uncertain"},
		Phases:       []records.PhaseResult{{Name: "transition", Outcome: "failed", Actual: "failed"}}}
	process := processResult{Status: "process_failed", Joined: true}
	if !eligibleSameDomainRerun(sameDomainRecoveryScenario, process, worker, nil) {
		t.Fatal("joined typed transport failure was not eligible")
	}
	for _, test := range []struct {
		name    string
		process processResult
		worker  records.WorkerResult
		child   []workerEvidence
	}{
		{name: "unjoined", process: processResult{Status: "process_failed"}, worker: worker},
		{name: "interrupted", process: processResult{Status: "interrupted", Joined: true}, worker: worker},
		{name: "child", process: process, worker: worker, child: []workerEvidence{{Role: "fresh_before"}}},
		{name: "missing_failure", process: process, worker: func() records.WorkerResult { v := worker; v.StoreFailure = nil; return v }()},
		{name: "wrong_reason", process: process, worker: func() records.WorkerResult {
			v := worker
			v.StoreFailure = &records.StoreFailure{StoreReason: "access", Outcome: "evidence-unavailable", Reason: "write-uncertain"}
			return v
		}()},
		{name: "wrong_phase", process: process, worker: func() records.WorkerResult {
			v := worker
			v.Phases = []records.PhaseResult{{Name: "setup", Outcome: "failed", Actual: "failed"}}
			return v
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if eligibleSameDomainRerun(sameDomainRecoveryScenario, test.process, test.worker, test.child) {
				t.Fatal("ineligible worker triggered a fresh command")
			}
		})
	}
	for _, name := range []string{"state.single-value-update-preserves-other-values/members_32", "state.transient-before-send-rerun"} {
		if eligibleSameDomainRerun(name, process, worker, nil) {
			t.Fatal("unrelated or historical scenario triggered a fresh command", name)
		}
	}
}

// full_only: false
func TestSameDomainRerunNeedsDurableHandoffAndInventory(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := workerInput{RunID: "0123456789abcdef0123456789abcdef", Prefix: "enkv-test/0123456789abcdef0123456789abcdef/0000", Scenarios: []string{sameDomainRecoveryScenario}}
	if _, err := readSameDomainHandoff(state, input); err == nil {
		t.Fatal("missing handoff permitted rerun")
	}
	if err := records.WriteJSON(filepath.Join(state, "recovery-handoff.json"), records.RecoveryHandoff{Version: 1}, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := readSameDomainHandoff(state, input); err == nil {
		t.Fatal("malformed handoff permitted rerun")
	}
}

// full_only: false
func TestSameDomainRerunBudgetsAddWithoutOverflow(t *testing.T) {
	a := &records.BudgetReservation{Requests: 3, BodyBytes: 4, Objects: 5, ObjectBytes: 6, GeneratorCreates: 7, GeneratorRetires: 8}
	b := &records.BudgetReservation{Requests: 11, BodyBytes: 12, Objects: 13, ObjectBytes: 14, GeneratorCreates: 15, GeneratorRetires: 16}
	got, err := addReservations(a, b)
	if err != nil || *got != (records.BudgetReservation{Requests: 14, BodyBytes: 16, Objects: 18, ObjectBytes: 20, GeneratorCreates: 22, GeneratorRetires: 24}) || a.Requests != 3 || b.Requests != 11 {
		t.Fatal("rerun reservation was lost or changed source evidence", got, err)
	}
	a.Requests = math.MaxUint64
	if _, err := addReservations(a, b); err == nil {
		t.Fatal("reservation overflow permitted rerun")
	}
	if _, err := addReservations(nil, b); err == nil {
		t.Fatal("missing first reservation permitted rerun")
	}
}
