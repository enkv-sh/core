package crypto

import (
	"context"
	"math"
	"sync"
	"time"

	"enkv.sh/core/contract"
)

// session is the runtime's sole private operation slot. Each owner installs
// its cleanup before starting the observer. Retirement joins all admitted work
// before another operation can occupy the same runtime.
type session struct {
	id             contract.ID
	deadline       time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	originalDone   <-chan struct{}
	work           sync.WaitGroup
	used, terminal bool
	clear          func()
}

func validDeadline(t time.Time) bool {
	return t.After(time.Unix(0, 0)) && !t.After(time.Unix(0, math.MaxInt64)) && time.Now().Before(t)
}

// installSession requires r.mu and an already validated, original deadline.
func (r *Runtime) installSession(id contract.ID, deadline time.Time, originalDone <-chan struct{}, clear func()) *session {
	if r.closed || r.slot != nil || id.IsZero() || id == r.retiredID {
		return nil
	}
	a := &session{id: id, deadline: deadline, done: make(chan struct{}), originalDone: originalDone, clear: clear}
	a.ctx, a.cancel = context.WithDeadline(context.Background(), deadline)
	r.slot = a
	r.retiredID = contract.ID{}
	go r.observeSession(a)
	return a
}

func (r *Runtime) observeSession(a *session) {
	select {
	case <-a.ctx.Done():
	case <-a.originalDone:
		a.cancel()
	}
	r.mu.Lock()
	a.used = true
	r.mu.Unlock()
	a.work.Wait()
	r.mu.Lock()
	a.clear()
	a.clear = nil
	r.mu.Unlock()
	close(a.done)
}

func (r *Runtime) finishSession(a *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a.terminal = true
	a.cancel()
}

func (r *Runtime) retireSession(a *session) {
	if r == nil || a == nil {
		return
	}
	a.cancel()
	<-a.done
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.slot == a {
		r.retiredID = a.id
		r.slot = nil
		r.init = nil
		r.inputSeal = nil
		r.consumer = nil
		r.publication = nil
		r.apply = nil
		r.access = nil
		r.generated = nil
	}
}

func sessionCancellation(ctx context.Context, a *session) contract.CryptoResultCode {
	if ctx.Err() != nil {
		return contract.CryptoCancelled
	}
	if !time.Now().Before(a.deadline) {
		return contract.CryptoExpired
	}
	select {
	case <-a.originalDone:
		return contract.CryptoCancelled
	default:
	}
	if a.ctx.Err() != nil {
		return contract.CryptoCancelled
	}
	return contract.CryptoSuccess
}

// sessionCancellationObserved checks a caller cancellation channel that was
// captured before Runtime.mu was acquired. Receiving from the captured channel
// cannot invoke caller code.
func sessionCancellationObserved(callerDone <-chan struct{}, a *session) contract.CryptoResultCode {
	select {
	case <-callerDone:
		return contract.CryptoCancelled
	default:
	}
	if !time.Now().Before(a.deadline) {
		return contract.CryptoExpired
	}
	select {
	case <-a.originalDone:
		return contract.CryptoCancelled
	case <-a.ctx.Done():
		return contract.CryptoCancelled
	default:
		return contract.CryptoSuccess
	}
}
