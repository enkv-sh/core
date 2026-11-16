package httptransport

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// A RoundTripper can return before it finishes reading and closing a request.
// Join both operations before the owned call returns, even with telemetry off.
// The wrapper sits outside any telemetry body so completed reads are observed
// before they release the join.
type RequestCompletion struct {
	io.ReadCloser
	mu              sync.Mutex
	reads           int
	closing, closed bool
	done            chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

func TrackRequestCompletion(r *http.Request) *RequestCompletion {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	body := &RequestCompletion{ReadCloser: r.Body, done: make(chan struct{})}
	r.Body = body
	return body
}

func (b *RequestCompletion) Wait(ctx context.Context) bool {
	if b == nil {
		return true
	}
	select {
	case <-b.done:
		return true
	default:
	}
	select {
	case <-b.done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (b *RequestCompletion) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.reads++
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	b.reads--
	if b.closed && b.reads == 0 {
		close(b.done)
	}
	b.mu.Unlock()
	return n, err
}

func (b *RequestCompletion) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closing = true
		b.mu.Unlock()
		// Close must be able to unblock a Read without waiting for its lock.
		b.closeErr = b.ReadCloser.Close()
		b.mu.Lock()
		b.closed = true
		if b.reads == 0 {
			close(b.done)
		}
		b.mu.Unlock()
	})
	return b.closeErr
}

func (b *RequestCompletion) Done() <-chan struct{} { return b.done }
