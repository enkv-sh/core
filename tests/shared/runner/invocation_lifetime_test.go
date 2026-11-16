package main

import (
	"context"
	"testing"
	"time"
)

// full_only: false
func TestInvocationCancellationHasOneFinalizationTail(t *testing.T) {
	owner := newInvocationLifetime(context.Background())
	defer owner.close()
	if err := owner.admitCleanup(2); err != nil {
		t.Fatal(err)
	}
	if err := owner.admitCleanup(0); err != nil || owner.cleanupSeconds != 2 {
		t.Fatal("normal resource phase reset admitted cleanup", err, owner.cleanupSeconds)
	}
	if err := owner.admitCleanup(1); err != nil || owner.cleanupSeconds != 2 {
		t.Fatal("later resource phase changed the cumulative cleanup horizon", err, owner.cleanupSeconds)
	}
	owner.interrupt()
	if owner.work.Err() == nil || owner.hard.Err() != nil {
		t.Fatal("first signal did not separate work and cleanup")
	}
	timer := owner.timer
	owner.interrupt()
	if owner.timer != timer {
		t.Fatal("repeated signal reset the cleanup horizon")
	}
	if err := owner.admitCleanup(3600); err == nil {
		t.Fatal("cancellation admitted a longer cleanup")
	}
	first, releaseFirst := finalizationContext(owner.work)
	defer releaseFirst()
	second, releaseSecond := finalizationContext(first)
	defer releaseSecond()
	if first.Err() != nil || second.Err() != nil {
		t.Fatal("work cancellation removed cleanup tail")
	}
	owner.hardStop()
	for _, ctx := range []context.Context{first, second} {
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("finalizer escaped the shared horizon")
		}
	}
	third, releaseThird := finalizationContext(owner.work)
	defer releaseThird()
	if third.Err() == nil {
		t.Fatal("late finalizer renewed the stopped horizon")
	}
}

// full_only: false
func TestInvocationSignalTailExpiresWithoutRenewal(t *testing.T) {
	owner := newInvocationLifetime(context.Background())
	defer owner.close()
	start := time.Now()
	owner.interrupt()
	select {
	case <-owner.hard.Done():
		if elapsed := time.Since(start); elapsed < 29*time.Second || elapsed > 35*time.Second {
			t.Fatal("signal horizon differs", elapsed)
		}
	case <-time.After(35 * time.Second):
		t.Fatal("signal horizon did not expire")
	}
}
