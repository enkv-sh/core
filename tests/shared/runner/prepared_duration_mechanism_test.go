package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// full_only: false
func TestPreparedGroupOwnWorkDuration(t *testing.T) {
	for _, row := range []struct {
		name, profile string
		step          resolvedWorkflowStep
		want          time.Duration
	}{
		{"complete-allocation", "full", resolvedWorkflowStep{Kind: "runner-tests"}, 0},
		{"focused-allocation", "full", resolvedWorkflowStep{Kind: "runner-tests", OrdinaryFocus: &ordinaryFocus{}}, 0},
		{"repeated-allocation", "full", resolvedWorkflowStep{Kind: "runner-tests", Repetitions: 2}, 0},
		{"unit-allocation", "full", resolvedWorkflowStep{Kind: "unit"}, 0},
		{"dev-allocation", "dev", resolvedWorkflowStep{Kind: "runner-tests"}, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			// Allocation only: the existing missing-owner guard stops before
			// source/tool work. This is not completed preparation evidence.
			before := time.Now()
			group, err := prepareOrdinaryGroup(t.Context(), "", "", row.profile, "", row.step, &ordinaryStepEvidence{}, io.Discard)
			elapsed := time.Since(before)
			if err == nil || err.Error() != "ordinary build owner unavailable" || group == nil {
				t.Fatal("allocation fixture did not stop at its owner guard", err)
			}
			if group.duration.bounded != (row.want != 0) || group.duration.remaining > row.want || group.duration.remaining < max(0, row.want-elapsed) {
				t.Fatal("ordinary allocation changed", group.duration.remaining, row.want)
			}
		})
	}
	t.Run("zero-keeps-cancellation-without-a-local-deadline", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
		defer cancel()
		direct, stop := cumulativeContext(parent, 0)
		defer stop()
		owner := newPreparedGroupDuration(parent, 0)
		defer owner.cancel()
		for range 2 {
			preparation, finish := owner.preparationContext(direct)
			if _, bounded := preparation.Deadline(); bounded || preparation.Err() != nil {
				t.Fatal("zero preparation allowance installed a deadline", preparation.Err())
			}
			finish()
			execution, finish := owner.executionContext(direct)
			if _, bounded := execution.Deadline(); bounded || execution.Err() != nil {
				t.Fatal("zero execution allowance installed a deadline", execution.Err())
			}
			finish()
		}
		cancel()
		if !errors.Is(direct.Err(), context.Canceled) || !errors.Is(owner.ctx.Err(), context.Canceled) {
			t.Fatal("zero allowance lost parent cancellation")
		}
	})
	t.Run("direct-positive-and-earlier-parent-deadlines", func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		deadline, _ := parent.Deadline()
		for _, allowance := range []time.Duration{0, time.Hour} {
			ctx, stop := cumulativeContext(parent, allowance)
			got, bounded := ctx.Deadline()
			stop()
			if !bounded || !got.Equal(deadline) {
				t.Fatal("cumulative setting extended parent deadline", allowance, got, deadline)
			}
		}
		ctx, stop := cumulativeContext(context.WithoutCancel(parent), 10*time.Millisecond)
		defer stop()
		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal(ctx.Err())
			}
		case <-time.After(time.Second):
			t.Fatal("positive cumulative limit did not expire")
		}
	})
	t.Run("preparation-rechecks-and-queue", func(t *testing.T) {
		parent, stop := context.WithTimeout(t.Context(), 5*time.Second)
		defer stop()
		const allowance = time.Second
		duration := newPreparedGroupDuration(parent, allowance)
		defer duration.cancel()
		ownWork := func() (time.Duration, time.Duration) {
			beforeScope := time.Now()
			ctx, finish := duration.preparationContext(parent)
			afterScope := time.Now()
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal("own preparation had no finite remaining allowance", ctx.Err())
			}
			beforeFinish := time.Now()
			finish()
			afterFinish := time.Now()
			finish() // Releasing a scope twice cannot debit it twice.
			return beforeFinish.Sub(afterScope), afterFinish.Sub(beforeScope)
		}
		minimumSpent, maximumSpent := ownWork()
		// A different configured group can run longer than this allowance.
		time.Sleep(allowance + 100*time.Millisecond)
		minimumRecheck, maximumRecheck := ownWork()
		minimumSpent, maximumSpent = minimumSpent+minimumRecheck, maximumSpent+maximumRecheck
		before := time.Now()
		ctx, release := duration.executionContext(parent)
		defer release()
		after := time.Now()
		deadline, ok := ctx.Deadline()
		minimumRemaining, maximumRemaining := max(0, allowance-maximumSpent), max(0, allowance-minimumSpent)
		if ctx.Err() != nil || !ok || deadline.Before(before.Add(minimumRemaining)) || deadline.After(after.Add(maximumRemaining)) {
			t.Fatal("dispatch did not use only the debited own-work remainder", deadline, minimumRemaining, maximumRemaining, ctx.Err())
		}
		check, finish := duration.preparationContext(parent)
		defer finish()
		if current, ok := check.Deadline(); !ok || !current.Equal(deadline) {
			t.Fatal("post-dispatch verification reset the deadline", current, deadline)
		}
	})
	t.Run("repetitions-and-partitions-share-one-deadline", func(t *testing.T) {
		duration := newPreparedGroupDuration(t.Context(), 200*time.Millisecond)
		defer duration.cancel()
		first, release := duration.executionContext(t.Context())
		deadline, ok := first.Deadline()
		release()
		second, finish := duration.executionContext(t.Context())
		defer finish()
		if current, bound := second.Deadline(); !ok || !bound || !current.Equal(deadline) || second.Err() != nil {
			t.Fatal("repetition restarted the deadline or inherited a canceled borrower", current, deadline, second.Err())
		}
		select {
		case <-second.Done():
		case <-time.After(time.Second):
			t.Fatal("fixed group deadline did not expire")
		}
		third, done := duration.executionContext(t.Context())
		defer done()
		if current, _ := third.Deadline(); !current.Equal(deadline) || !errors.Is(third.Err(), context.DeadlineExceeded) {
			t.Fatal("later partition reset the exhausted allowance", current, third.Err())
		}
	})
	t.Run("earlier-callers-values-and-lifetime", func(t *testing.T) {
		parent, stop := context.WithTimeout(withExecutionParallel(t.Context(), 4), 5*time.Second)
		defer stop()
		duration := newPreparedGroupDuration(parent, time.Hour)
		defer duration.cancel()
		caller, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 512}}), time.Second)
		defer cancel()
		first, release := duration.executionContext(caller)
		defer release()
		want, _ := caller.Deadline()
		if got, _ := first.Deadline(); !got.Equal(want) || executionCapacityFromContext(first) != (executionCapacity{Parallel: 1, MemoryLimitMiB: 512}) {
			t.Fatal("group restored preparation values or extended the caller deadline")
		}
		cancel()
		second, finish := duration.executionContext(parent)
		defer finish()
		parentDeadline, _ := parent.Deadline()
		if got, _ := second.Deadline(); !got.Equal(parentDeadline) || second.Err() != nil {
			t.Fatal("persistent timer borrowed the canceled repetition lifetime", second.Err())
		}
		stop()
		if duration.ctx.Err() == nil {
			t.Fatal("owner lost parent cancellation")
		}
	})
	t.Run("canceled-before-dispatch", func(t *testing.T) {
		parent, stop := context.WithCancel(t.Context())
		duration := newPreparedGroupDuration(parent, time.Second)
		defer duration.cancel()
		stop()
		ctx, finish := duration.executionContext(t.Context())
		defer finish()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("dispatch revived a canceled lifetime", ctx.Err())
		}
	})
	t.Run("failed-preparation-exhausts-balance", func(t *testing.T) {
		duration := newPreparedGroupDuration(t.Context(), 10*time.Millisecond)
		defer duration.cancel()
		ctx, finish := duration.preparationContext(t.Context())
		<-ctx.Done()
		finish()
		next, release := duration.executionContext(t.Context())
		defer release()
		if duration.remaining != 0 || !errors.Is(next.Err(), context.DeadlineExceeded) {
			t.Fatal("failed own preparation received a fresh execution budget", duration.remaining, next.Err())
		}
	})
}
