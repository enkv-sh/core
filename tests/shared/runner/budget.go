package main

import (
	"encoding/json"
	"errors"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// Required pointers distinguish a recorded zero from missing evidence. Run
// control reads reservations, never telemetry counts.
func decodeReservation(body json.RawMessage, cleanup bool) (*records.BudgetReservation, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return nil, errors.New("budget evidence unavailable")
	}
	result := &records.BudgetReservation{}
	destinations := map[string]*uint64{
		"requests": &result.Requests, "body_bytes": &result.BodyBytes,
		"generator_creates": &result.GeneratorCreates, "generator_retires": &result.GeneratorRetires,
	}
	if !cleanup {
		destinations["objects"], destinations["object_bytes"] = &result.Objects, &result.ObjectBytes
	}
	for name, destination := range destinations {
		var number *uint64
		if json.Unmarshal(fields[name], &number) != nil || number == nil {
			return nil, errors.New("budget evidence unavailable")
		}
		*destination = *number
	}
	if cleanup && result.GeneratorCreates != 0 {
		return nil, errors.New("cleanup cannot reserve generator creates")
	}
	return result, nil
}

func debitBudget(remaining *limits, work, cleanup *records.BudgetReservation, workloadElapsed, cleanupElapsed time.Duration) error {
	if work == nil || cleanup == nil || workloadElapsed < 0 || cleanupElapsed < 0 {
		return errors.New("budget evidence unavailable")
	}
	// Check the entire debit first so rejected evidence cannot partially consume
	// or wrap the remaining allowance.
	items := []struct {
		remaining *uint64
		reserved  uint64
	}{
		{&remaining.Requests, work.Requests}, {&remaining.BodyBytes, work.BodyBytes},
		{&remaining.Objects, work.Objects}, {&remaining.ObjectBytes, work.ObjectBytes},
		{&remaining.GeneratorCreates, work.GeneratorCreates},
		{&remaining.CleanupRequests, cleanup.Requests}, {&remaining.CleanupBytes, cleanup.BodyBytes},
		{&remaining.ElapsedSeconds, elapsedSeconds(workloadElapsed)}, {&remaining.CleanupSeconds, elapsedSeconds(cleanupElapsed)},
	}
	if work.GeneratorRetires > remaining.GeneratorRetires || cleanup.GeneratorRetires > remaining.GeneratorRetires-work.GeneratorRetires {
		return errors.New("budget reservation exceeds allowance")
	}
	for _, item := range items {
		if item.reserved > *item.remaining {
			return errors.New("budget reservation exceeds allowance")
		}
	}
	for _, item := range items {
		*item.remaining -= item.reserved
	}
	remaining.GeneratorRetires -= work.GeneratorRetires + cleanup.GeneratorRetires
	return nil
}

func elapsedSeconds(elapsed time.Duration) uint64 {
	seconds := uint64(elapsed / time.Second)
	if elapsed%time.Second != 0 {
		seconds++
	}
	return seconds
}
