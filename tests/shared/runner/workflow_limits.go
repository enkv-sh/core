package main

import (
	"encoding/json"
	"errors"
	"path/filepath"

	records "enkv.sh/core/internal/testrecords"
)

const (
	maximumBudgetRequests         = 1000000
	maximumBudgetBodyBytes        = 1 << 40
	maximumBudgetObjects          = 100000
	maximumBudgetObjectBytes      = 1 << 36
	maximumBudgetGeneratorCreates = 100000
	maximumBudgetGeneratorRetires = 100000
	maximumBudgetElapsedSeconds   = 3600
	maximumCleanupBudgetRequests  = 1000000
	maximumCleanupBudgetBytes     = 1 << 40
	maximumCleanupBudgetSeconds   = 3600
)

type limits records.LiveLimits

func loadLimits(path string) (limits, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return limits{}, errors.New("limits unavailable")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return limits{}, errors.New("limits unavailable")
	}
	var fields map[string]json.RawMessage
	if records.ReadJSON(path, &fields) != nil || len(fields) != 10 {
		return limits{}, errors.New("finite run and cleanup limits required")
	}
	var value limits
	for name, destination := range map[string]*uint64{
		"requests": &value.Requests, "body_bytes": &value.BodyBytes,
		"objects": &value.Objects, "object_bytes": &value.ObjectBytes,
		"generator_creates": &value.GeneratorCreates, "generator_retires": &value.GeneratorRetires,
		"elapsed_seconds": &value.ElapsedSeconds, "cleanup_requests": &value.CleanupRequests,
		"cleanup_bytes": &value.CleanupBytes, "cleanup_seconds": &value.CleanupSeconds,
	} {
		var number *uint64
		if json.Unmarshal(fields[name], &number) != nil || number == nil {
			return limits{}, errors.New("finite run and cleanup limits required")
		}
		*destination = *number
	}
	if !value.valid() {
		return limits{}, errors.New("finite run and cleanup limits required")
	}
	return value, nil
}

func (l limits) valid() bool {
	for _, item := range []struct{ value, cap uint64 }{
		{l.Requests, maximumBudgetRequests}, {l.BodyBytes, maximumBudgetBodyBytes}, {l.Objects, maximumBudgetObjects}, {l.ObjectBytes, maximumBudgetObjectBytes},
		{l.GeneratorCreates, maximumBudgetGeneratorCreates}, {l.GeneratorRetires, maximumBudgetGeneratorRetires},
		{l.ElapsedSeconds, maximumBudgetElapsedSeconds}, {l.CleanupRequests, maximumCleanupBudgetRequests}, {l.CleanupBytes, maximumCleanupBudgetBytes}, {l.CleanupSeconds, maximumCleanupBudgetSeconds},
	} {
		if item.value == 0 || item.value > item.cap {
			return false
		}
	}
	return true
}
