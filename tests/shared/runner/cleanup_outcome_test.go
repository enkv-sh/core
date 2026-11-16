package main

import (
	"context"
	"testing"
)

// full_only: false

// full_only: false
func TestCleanupOnlyCaseFailureKeepsRunCleanupStage(t *testing.T) {
	s, binary := coordinatorFixture(t)
	s.record.Scenarios = nil
	if err := s.executeSchedule(context.Background(), binary,
		liveSettings{"recovery_mode": "disabled", "test_mode": "typed_cleanup_cause"}, testLimits()); err != nil {
		t.Fatal(err)
	}
	if len(s.record.Scenarios) != 1 || !s.record.Scenarios[0].CorrectnessPassed ||
		s.record.Scenarios[0].Outcome != "failed" || s.record.Scenarios[0].Failure != nil ||
		s.record.Scenarios[0].Cleanup.HarnessFailure == nil ||
		s.record.Failure == nil || s.record.Failure.Class != "cleanup_unresolved" || s.record.Failure.Stage != "cleanup" {
		t.Fatalf("cleanup-only failure was classified as a Product execution failure: run=%+v case=%+v correct=%t",
			s.record.Failure, s.record.Scenarios[0].Failure, s.record.Scenarios[0].CorrectnessPassed)
	}
}
