package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

// full_only: false
func TestLocalFailureRequiresEveryCauseToBeContained(t *testing.T) {
	parent := context.Background()
	exit := &exec.ExitError{}
	valid := processResult{Status: "process_failed", Started: true, Joined: true, Cause: exit}
	for _, test := range []struct {
		name     string
		process  processResult
		cleanup  error
		overflow bool
		want     bool
	}{
		{name: "child exit", process: valid, want: true},
		{name: "child deadline", process: processResult{Status: "timed_out", Started: true, Joined: true, Cause: errors.Join(exit, context.DeadlineExceeded)}, want: true},
		{name: "observation failure", process: processResult{Status: "process_failed", Started: true, Joined: true, Cause: errors.Join(exit, errors.New("observation unavailable"))}},
		{name: "unexpected deadline", process: processResult{Status: "process_failed", Started: true, Joined: true, Cause: errors.Join(exit, context.DeadlineExceeded)}},
		{name: "unjoined", process: processResult{Status: "process_failed", Started: true, Cause: exit}},
		{name: "not started", process: processResult{Status: "process_failed", Joined: true, Cause: exit}},
		{name: "unknown cause", process: processResult{Status: "process_failed", Started: true, Joined: true, Cause: errors.New("unknown")}},
		{name: "cleanup", process: valid, cleanup: errors.New("cleanup")},
		{name: "output bound", process: valid, overflow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := &toolFailure{process: test.process, cleanup: test.cleanup, overflow: test.overflow}
			got := containProcessFailure(parent, original)
			if containedCheckFailure(parent, got) != test.want || !errors.Is(got, original) {
				t.Fatal("failure classification or original cause changed")
			}
		})
	}
	marked := containProcessFailure(parent, &toolFailure{process: valid})
	if !containedCheckFailure(parent, errors.Join(marked, fmt.Errorf("wrapped: %w", marked))) {
		t.Fatal("contained siblings stopped independent work")
	}
	for _, combined := range []error{
		errors.Join(marked, errors.New("record write failed")),
		errors.Join(errors.New("source changed"), marked),
	} {
		if containedCheckFailure(parent, combined) || containedCheckFailure(parent, containProcessFailure(parent, combined)) {
			t.Fatal("contained sibling concealed a stop condition")
		}
	}
	cancelled, cancel := context.WithCancel(parent)
	cancel()
	if containedCheckFailure(cancelled, marked) {
		t.Fatal("parent cancellation permitted continuation")
	}
}
