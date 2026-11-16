package httptransport

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"enkv.sh/telemetry"
)

type readAfterCloseBody struct {
	started, closed, release chan struct{}
}

func (b readAfterCloseBody) Read(p []byte) (int, error) {
	close(b.started)
	<-b.closed
	<-b.release
	return copy(p, "abc"), io.EOF
}

func (b readAfterCloseBody) Close() error {
	close(b.closed)
	return nil
}

// full_only: false
func TestRequestCompletionWaitsForReadAccountingAfterClose(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx := context.Background()
	body := readAfterCloseBody{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", body)
	if err != nil {
		t.Fatal(err)
	}
	observation := telemetry.TrackBody(r.Body, -1)
	r.Body = observation
	completion := TrackRequestCompletion(r)
	readDone := make(chan struct{})
	go func() {
		buffer := make([]byte, 8)
		n, err := r.Body.Read(buffer)
		if n != 3 || err != io.EOF || string(buffer[:n]) != "abc" {
			t.Error("closing the request changed an active Read result")
		}
		close(readDone)
	}()
	<-body.started
	closeDone := make(chan struct{})
	go func() {
		_ = r.Body.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close could not unblock an active Read")
	}
	select {
	case <-completion.done:
		t.Error("request completion ignored active Read accounting")
	default:
	}
	close(body.release)
	<-readDone
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if !completion.Wait(ctx) {
		t.Fatal("request completion did not join the final Read")
	}
	bytes, complete := observation.Snapshot()
	if bytes != 3 || !complete {
		t.Fatal("request completion did not retain the final Read bytes")
	}
}
