package main

import (
	"context"
	"errors"
	"os/exec"
)

// localCheckFailure is assigned only by an owner that has checked settlement,
// result custody and the inputs needed by independent work.
type localCheckFailure struct{ cause error }

type liveCheckFailure struct{ cause error }

func (failure *liveCheckFailure) Error() string { return failure.cause.Error() }
func (failure *liveCheckFailure) Unwrap() error { return failure.cause }

func (failure *localCheckFailure) Error() string { return failure.cause.Error() }
func (failure *localCheckFailure) Unwrap() error { return failure.cause }

func containedCheckFailure(parent context.Context, cause error) bool {
	if parent.Err() != nil || cause == nil {
		return false
	}
	return allFailureBranches(cause, func(err error) (bool, bool) {
		if failure, ok := err.(*liveCheckFailure); ok {
			return true, failure != nil && failure.cause != nil
		}
		failure, ok := err.(*localCheckFailure)
		return ok, ok && failure != nil && failure.cause != nil
	})
}

// containProcessFailure is used at local discovery, build and test owners,
// before diagnostic and verification failures are joined with the result.
func containProcessFailure(parent context.Context, cause error) error {
	if parent.Err() != nil || cause == nil {
		return cause
	}
	contained := allFailureBranches(cause, func(err error) (bool, bool) {
		if failure, ok := err.(*localCheckFailure); ok {
			return true, failure != nil && failure.cause != nil
		}
		failure, ok := err.(*toolFailure)
		if !ok {
			return false, false
		}
		return true, failure != nil && failure.cleanup == nil && !failure.overflow && settledLocalProcessFailure(parent, failure.process)
	})
	if !contained {
		return cause
	}
	return &localCheckFailure{cause: cause}
}

// Classify the test process and its valid failed/incomplete event prefix before
// callers add converter, output, source, diagnostic or cleanup failures.
func containTestFailure(parent context.Context, processErr, completionErr error) error {
	cause := errors.Join(processErr, completionErr)
	if !containedCheckFailure(parent, containProcessFailure(parent, processErr)) {
		return cause
	}
	if completionErr != nil && !allFailureBranches(completionErr, func(err error) (bool, bool) {
		failure, ok := err.(*testCompletionFailure)
		return ok, ok && failure != nil && failure.cause != nil
	}) {
		return cause
	}
	return &localCheckFailure{cause: cause}
}

func settledLocalProcessFailure(parent context.Context, process processResult) bool {
	if parent.Err() != nil || !process.Started || !process.Joined || process.Cause == nil || (process.Status != "process_failed" && process.Status != "timed_out") {
		return false
	}
	return allFailureBranches(process.Cause, func(err error) (bool, bool) {
		if _, ok := err.(*exec.ExitError); ok {
			return true, true
		}
		if err == context.DeadlineExceeded {
			return true, process.Status == "timed_out"
		}
		return false, false
	})
}

// Go uses exit 1 for completed assertion failures. A timeout, signal or other
// exit leaves the rest of this package execution unfinished; it is not a reason
// to start another process for the remaining roots.
func packageProcessTerminated(process processResult) bool {
	if !process.Joined {
		return false
	}
	if process.Status == "timed_out" {
		return true
	}
	var exit *exec.ExitError
	return process.Status == "process_failed" && errors.As(process.Cause, &exit) && exit.ExitCode() != 1
}

func allFailureBranches(cause error, classify func(error) (bool, bool)) bool {
	if cause == nil {
		return false
	}
	pending := []error{cause}
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if known, accepted := classify(current); known {
			if !accepted {
				return false
			}
			continue
		}
		switch value := current.(type) {
		case interface{ Unwrap() []error }:
			found := false
			for _, child := range value.Unwrap() {
				if child != nil {
					pending = append(pending, child)
					found = true
				}
			}
			if !found {
				return false
			}
		case interface{ Unwrap() error }:
			child := value.Unwrap()
			if child == nil {
				return false
			}
			pending = append(pending, child)
		default:
			return false
		}
	}
	return true
}
