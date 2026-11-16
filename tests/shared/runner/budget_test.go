package main

import (
	"encoding/json"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestBudgetEvidenceRequiresEveryApplicableField(t *testing.T) {
	for _, body := range []string{
		`null`, `{}`, `{"requests":0,"body_bytes":0}`, `{"requests":false,"body_bytes":0,"objects":0,"object_bytes":0,"generator_creates":0,"generator_retires":0}`,
		`{"requests":-1,"body_bytes":0,"objects":0,"object_bytes":0,"generator_creates":0,"generator_retires":0}`, `{"requests":0,"body_bytes":0,"objects":null,"object_bytes":0,"generator_creates":0,"generator_retires":0}`,
		`{"REQUESTS":0,"body_bytes":0,"objects":0,"object_bytes":0,"generator_creates":0,"generator_retires":0}`, `{"requests":0,"body_bytes":0,"objects":0,"object_bytes":0,"generator_creates":0,"generator_retires":0,"requests":null}`,
	} {
		if _, err := decodeReservation(json.RawMessage(body), false); err == nil {
			t.Fatalf("invalid workload reservation admitted: %s", body)
		}
	}
	for _, cleanup := range []bool{false, true} {
		if _, err := decodeReservation(json.RawMessage(`{"requests":0,"body_bytes":0,"objects":0,"object_bytes":0,"generator_creates":0,"generator_retires":0}`), cleanup); err != nil {
			t.Fatal("explicit zero reservation refused")
		}
	}
	if _, err := decodeReservation(json.RawMessage(`{"requests":1,"body_bytes":2,"generator_creates":0,"generator_retires":3}`), true); err != nil {
		t.Fatal("cleanup reservation requires unrelated workload fields")
	}
	if _, err := decodeReservation(json.RawMessage(`{"requests":1,"body_bytes":2,"generator_creates":1,"generator_retires":0}`), true); err == nil {
		t.Fatal("cleanup reserved a generated create")
	}
}

// full_only: false
func TestBudgetDebitPreservesIndependentCleanupAndRoundsUpTime(t *testing.T) {
	remaining := testLimits()
	work := &records.BudgetReservation{Requests: 2, BodyBytes: 3, Objects: 4, ObjectBytes: 5, GeneratorCreates: 8, GeneratorRetires: 9}
	cleanup := &records.BudgetReservation{Requests: 6, BodyBytes: 7, GeneratorRetires: 10}
	if err := debitBudget(&remaining, work, cleanup, time.Nanosecond, time.Second+time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if remaining.Requests != 998 || remaining.CleanupRequests != 994 || remaining.GeneratorCreates != 120 || remaining.GeneratorRetires != 237 || remaining.ElapsedSeconds != 9 || remaining.CleanupSeconds != 8 {
		t.Fatalf("budget ownership changed: %+v", remaining)
	}
	original := remaining
	cleanup.BodyBytes = remaining.CleanupBytes + 1
	if debitBudget(&remaining, work, cleanup, time.Second, time.Second) == nil || remaining != original {
		t.Fatal("invalid reservation partially debited the allowance")
	}
	if debitBudget(&remaining, nil, cleanup, 0, 0) == nil || debitBudget(&remaining, work, cleanup, -1, 0) == nil {
		t.Fatal("missing or invalid budget evidence admitted")
	}
}
