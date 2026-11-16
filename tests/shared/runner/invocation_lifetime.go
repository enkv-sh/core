package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

type finalizationTailKey struct{}

// Every finalizer in one invocation borrows this single cancellation horizon.
type invocationLifetime struct {
	work, hard             context.Context
	cancelWork, cancelHard context.CancelFunc
	mu                     sync.Mutex
	cleanupSeconds         int
	interrupted            bool
	closed                 bool
	timer                  *time.Timer
	timerDone              chan struct{}
}

func newInvocationLifetime(parent context.Context) *invocationLifetime {
	hard, cancelHard := context.WithCancel(parent)
	work, cancelWork := context.WithCancel(hard)
	return &invocationLifetime{
		work:       context.WithValue(work, finalizationTailKey{}, hard),
		hard:       context.WithValue(hard, finalizationTailKey{}, hard),
		cancelWork: cancelWork, cancelHard: cancelHard,
	}
}

func (owner *invocationLifetime) admitCleanup(seconds int) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if seconds < 0 || seconds > 3600 {
		return errors.New("cleanup horizon refused")
	}
	if owner.interrupted || owner.closed || owner.work.Err() != nil {
		return context.Canceled
	}
	owner.cleanupSeconds = max(owner.cleanupSeconds, seconds)
	return nil
}

func (owner *invocationLifetime) interrupt() {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.interrupted || owner.closed {
		return
	}
	owner.interrupted = true
	owner.cancelWork()
	owner.timerDone = make(chan struct{})
	owner.timer = time.AfterFunc(time.Duration(owner.cleanupSeconds)*time.Second+30*time.Second, func() {
		owner.cancelHard()
		close(owner.timerDone)
	})
}

func (owner *invocationLifetime) hardStop() {
	owner.cancelWork()
	owner.cancelHard()
}

func (owner *invocationLifetime) close() {
	owner.mu.Lock()
	owner.closed = true
	owner.hardStop()
	var wait <-chan struct{}
	if owner.timer != nil && !owner.timer.Stop() {
		wait = owner.timerDone
	}
	owner.mu.Unlock()
	if wait != nil {
		<-wait
	}
}

func finalizationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	finish, cancel := context.WithCancel(context.WithoutCancel(ctx))
	tail, present := ctx.Value(finalizationTailKey{}).(context.Context)
	if !present {
		return finish, cancel
	}
	done := make(chan struct{})
	stop := context.AfterFunc(tail, func() { cancel(); close(done) })
	if tail.Err() != nil {
		cancel()
	}
	return finish, func() {
		if !stop() {
			<-done
		}
		cancel()
	}
}
