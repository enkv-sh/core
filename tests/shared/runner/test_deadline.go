package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nativeRootClock struct {
	remaining time.Duration
	started   time.Time
	state     byte
	resumed   bool
}

type nativeTestDeadline struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	capture  io.Writer
	backstop time.Duration
	idle     time.Duration
	mu       sync.Mutex
	roots    map[string]*nativeRootClock
	active   map[string]*nativeRootClock
	idleAt   time.Time
	frame    []byte
	framed   bool
	escaped  bool
	failure  error
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
}

type nativeDeadlineContext struct{ context.Context }

func (ctx nativeDeadlineContext) Err() error {
	err := ctx.Context.Err()
	if err != nil && errors.Is(context.Cause(ctx.Context), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}

func nativeTestBackstop(allowances map[string]time.Duration, idle time.Duration) (time.Duration, error) {
	if idle <= 0 || len(allowances) > maximumOrdinaryTests {
		return 0, errors.New("native test deadline allowance is invalid")
	}
	total := time.Duration(0)
	for name, allowance := range allowances {
		if name == "" || strings.Contains(name, "/") || allowance <= 0 || allowance > time.Duration(math.MaxInt64)-total {
			return 0, errors.New("native test deadline allowance is invalid or overflows")
		}
		total += allowance
	}
	intervals := int64(2*len(allowances) + 1)
	if int64(idle) > (math.MaxInt64-int64(total))/intervals {
		return 0, errors.New("native test safety alarm overflows")
	}
	return total + time.Duration(intervals)*idle, nil
}

func newNativeTestDeadline(parent context.Context, allowances map[string]time.Duration, idle time.Duration, capture io.Writer) (*nativeTestDeadline, error) {
	backstop, err := nativeTestBackstop(allowances, idle)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(parent)
	owner := &nativeTestDeadline{ctx: nativeDeadlineContext{ctx}, cancel: cancel, capture: capture, backstop: backstop, idle: idle,
		roots: map[string]*nativeRootClock{}, active: map[string]*nativeRootClock{}, idleAt: time.Now().Add(idle),
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	for name, allowance := range allowances {
		owner.roots[name] = &nativeRootClock{remaining: allowance}
	}
	go owner.watch()
	return owner, nil
}

func (owner *nativeTestDeadline) fail(err error) {
	if owner.failure == nil && owner.ctx.Err() == nil {
		owner.failure = err
		owner.cancel(err)
	}
}

func (owner *nativeTestDeadline) next() (time.Time, error) {
	if len(owner.active) == 0 {
		return owner.idleAt, fmt.Errorf("native test startup, idle or teardown allowance exceeded: %w", context.DeadlineExceeded)
	}
	var earliest time.Time
	var cause error
	for name, clock := range owner.active {
		deadline := clock.started.Add(clock.remaining)
		if earliest.IsZero() || deadline.Before(earliest) {
			earliest = deadline
			cause = fmt.Errorf("test %s active allowance exceeded: %w", name, context.DeadlineExceeded)
		}
	}
	return earliest, cause
}

func (owner *nativeTestDeadline) watch() {
	defer close(owner.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		owner.mu.Lock()
		deadline, cause := owner.next()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			owner.fail(cause)
			owner.mu.Unlock()
			return
		}
		owner.mu.Unlock()
		timer.Reset(remaining)
		select {
		case <-owner.ctx.Done():
			return
		case <-owner.stop:
			return
		case <-owner.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func (owner *nativeTestDeadline) Write(body []byte) (int, error) {
	n, err := owner.capture.Write(body)
	owner.mu.Lock()
	defer owner.mu.Unlock()
	for _, b := range body[:n] {
		if owner.ctx.Err() != nil {
			break
		}
		if b == '\n' {
			owner.control()
			owner.frame, owner.framed = owner.frame[:0], false
			continue
		}
		if owner.escaped {
			owner.escaped = false
		} else if b == 0x1b {
			owner.escaped = true
		} else if b == 0x16 {
			owner.control()
			owner.frame, owner.framed = owner.frame[:0], true
			continue
		}
		if owner.framed {
			if len(owner.frame) >= maximumToolOutputBytes {
				owner.fail(errors.New("native test deadline frame exceeds the output bound"))
				break
			}
			owner.frame = append(owner.frame, b)
		}
	}
	return n, err
}

func (owner *nativeTestDeadline) control() {
	if !owner.framed || len(owner.frame) == 0 {
		return
	}
	line := strings.TrimRight(string(owner.frame), "\r")
	action, name := byte(0), ""
	for index, prefix := range []string{"=== RUN   ", "=== PAUSE ", "=== CONT  ", "--- PASS: ", "--- FAIL: ", "--- SKIP: "} {
		if strings.HasPrefix(line, prefix) {
			action, name = byte(index+1), line[len(prefix):]
			break
		}
	}
	if action == 0 {
		return
	}
	if action >= 4 {
		index := strings.LastIndex(name, " (")
		if index < 0 || !strings.HasSuffix(name, "s)") {
			owner.fail(errors.New("native test deadline terminal framing is invalid"))
			return
		}
		elapsed, err := strconv.ParseFloat(name[index+2:len(name)-2], 64)
		if err != nil || elapsed < 0 || math.IsNaN(elapsed) || math.IsInf(elapsed, 0) {
			owner.fail(errors.New("native test deadline terminal framing is invalid"))
			return
		}
		name = name[:index]
	}
	root, _, child := strings.Cut(name, "/")
	clock := owner.roots[root]
	if clock == nil {
		owner.fail(errors.New("native test deadline control has no admitted root"))
		return
	}
	if child {
		return
	}
	now := time.Now()
	if len(owner.active) == 0 && !now.Before(owner.idleAt) {
		owner.fail(fmt.Errorf("native test startup, idle or teardown allowance exceeded: %w", context.DeadlineExceeded))
		return
	}
	if clock.state == 'r' && !now.Before(clock.started.Add(clock.remaining)) {
		owner.fail(fmt.Errorf("test %s active allowance exceeded: %w", name, context.DeadlineExceeded))
		return
	}
	switch {
	case action == 1 && clock.state == 0:
		clock.state, clock.started = 'r', now
		owner.active[name] = clock
	case action == 2 && clock.state == 'r' && !clock.resumed:
		clock.remaining -= now.Sub(clock.started)
		clock.state = 'p'
		delete(owner.active, name)
	case action == 3 && clock.state == 'p':
		clock.state, clock.started, clock.resumed = 'r', now, true
		owner.active[name] = clock
	case action >= 4 && clock.state == 'r':
		clock.state = 'd'
		delete(owner.active, name)
	default:
		owner.fail(errors.New("native test deadline control repeats or changes an inactive root"))
		return
	}
	if len(owner.active) == 0 {
		owner.idleAt = now.Add(owner.idle)
	}
	select {
	case owner.wake <- struct{}{}:
	default:
	}
}

func (owner *nativeTestDeadline) joined(process processResult) processResult {
	close(owner.stop)
	<-owner.done
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if deadline, cause := owner.next(); !time.Now().Before(deadline) {
		owner.fail(cause)
	}
	if owner.failure != nil {
		process.Cause = errors.Join(process.Cause, owner.failure)
		if process.Status != "group_stop_failed" {
			process.Status = "process_failed"
			if errors.Is(owner.failure, context.DeadlineExceeded) {
				process.Status = "timed_out"
			}
		}
	}
	if owner.ctx.Err() != nil {
		process.Cause = errors.Join(process.Cause, context.Cause(owner.ctx))
	}
	return process
}

func (owner *nativeTestDeadline) conversionContext() (context.Context, context.CancelFunc) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.ctx.Err() != nil {
		return owner.ctx, func() {}
	}
	shutdown := owner.idleAt
	if len(owner.active) != 0 {
		shutdown = time.Now().Add(owner.idle)
	}
	return context.WithDeadline(owner.ctx, shutdown)
}

func (owner *nativeTestDeadline) converted(work context.Context, process processResult) processResult {
	if err := owner.shutdownError(work); err != nil {
		process.Cause = errors.Join(process.Cause, err)
		if process.Status != "group_stop_failed" {
			process.Status = processContextStatus(err)
		}
	}
	return process
}

func (owner *nativeTestDeadline) shutdownError(work context.Context) error {
	if owner.ctx.Err() == nil {
		return work.Err()
	}
	return nil
}
