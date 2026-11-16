package manifesthost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// full_only: false
func TestTransportCancellationJoinsBorrowersWithOppositeEndsRetained(t *testing.T) {
	pipe := func() (*os.File, *os.File) {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			for _, f := range []*os.File{r, w} {
				if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Error(err)
				}
			}
		})
		return r, w
	}
	requestR, requestW := pipe()
	artifactR, artifactW := pipe()
	statusR, statusW := pipe()
	request, artifact, status := &nativeStream{file: requestW}, &nativeStream{file: artifactR}, &nativeStream{file: statusR}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	finish := watchTransport(ctx, request, artifact, status)
	body := bytes.Repeat([]byte{0x5a}, 1<<20)
	done := make(chan error, 3)
	joined := 0
	defer func() {
		cancel()
		if err := finish(); err != nil {
			t.Error(err)
		}
		for joined < 3 {
			select {
			case <-done:
				joined++
			case <-time.After(time.Second):
				t.Error("borrower cleanup did not join")
				return
			}
		}
	}()
	entered := make(chan struct{}, 3)
	go func() { entered <- struct{}{}; _, err := request.Write(body); done <- err }()
	go func() { entered <- struct{}{}; var b [1]byte; _, err := artifact.Read(b[:]); done <- err }()
	go func() { entered <- struct{}{}; var b [1]byte; _, err := status.Read(b[:]); done <- err }()
	for range 3 {
		<-entered
	}
	// Counterparts deliberately stay open and send neither data nor EOF.
	select {
	case err := <-done:
		joined++
		t.Fatal("borrower completed before cancellation", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	for range 3 {
		select {
		case err := <-done:
			joined++
			if err == nil {
				t.Fatal("cancelled I/O completed")
			}
		case <-time.After(time.Second):
			t.Fatal("retained opposite endpoint blocked a parent borrower")
		}
	}
	for _, b := range body {
		if b != 0x5a {
			t.Fatal("transport changed borrowed write backing")
		}
	}
	for _, f := range []*os.File{requestR, artifactW, statusW} {
		if _, err := f.Stat(); err != nil {
			t.Fatal("transport closed borrowed opposite endpoint", err)
		}
	}
}
