package awsprovider

import (
	"context"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/telemetry"
)

type delayedRequestTransport struct {
	started, release, consumed chan struct{}
}

func (d delayedRequestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	go func() {
		close(d.started)
		<-d.release
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		close(d.consumed)
	}()
	return response(200, "", nil), nil
}

// full_only: false
func TestTransportWaitsForRequestBodyOrDeadlineWithoutTelemetry(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	ctx, snapshot := collectTelemetry(t)
	for _, mode := range []string{"complete", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			base := delayedRequestTransport{make(chan struct{}), make(chan struct{}), make(chan struct{})}
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			transport := boundedTransport{host: "fixture.invalid", next: base}
			body := &countedBody{ReadCloser: io.NopCloser(strings.NewReader("abc"))}
			r, err := http.NewRequestWithContext(operationContext(ctx, 8), http.MethodPost, "https://fixture.invalid/", body)
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				resp, err := transport.RoundTrip(r)
				if resp != nil {
					if err := resp.Body.Close(); err != nil {
						t.Error(err)
					}
				}
				returned <- err
			}()
			<-base.started
			if mode == "cancelled" {
				cancel()
				if err := <-returned; err != errTransport {
					t.Errorf("request completion did not refuse on deadline: %v", err)
				}
				close(base.release)
			} else {
				early := false
				select {
				case <-returned:
					early = true
					t.Error("transport returned before request completion")
				case <-time.After(20 * time.Millisecond):
				}
				close(base.release)
				if !early {
					if err := <-returned; err != nil {
						t.Error(err)
					}
				}
			}
			<-base.consumed
			if body.bytes != 3 || !body.closed {
				t.Fatal("request body was not consumed and closed")
			}
		})
	}
	if len(snapshot().ScopeMetrics) != 0 {
		t.Fatal("disabled telemetry recorded metrics")
	}
}

// full_only: false
func TestHTTPTelemetryIncludesPartialAndFailedTransfers(t *testing.T) {
	for _, mode := range []string{"success", "send-error", "body-error", "oversized", "http-error"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			ctx, call := startTelemetry(ctx, telemetry.OpStoreCreate)
			defer call.Finish(telemetry.ResultSuccess)
			calls := 0
			transport := boundedTransport{host: "fixture.invalid", next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if n, err := io.CopyN(io.Discard, r.Body, 2); n != 2 || err != nil {
					t.Fatal("request body unavailable")
				}
				if mode == "send-error" {
					return nil, io.ErrUnexpectedEOF
				}
				resp := response(200, "abc", nil)
				if mode == "body-error" {
					resp.Body = &failingBody{data: []byte("abc")}
				}
				if mode == "oversized" {
					resp = response(200, "abcdefgh", nil)
				}
				if mode == "http-error" {
					resp.StatusCode = 503
				}
				return resp, nil
			})}
			r, err := http.NewRequestWithContext(operationContext(ctx, 4), http.MethodPost, "https://fixture.invalid/", strings.NewReader("abcdef"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(r)
			if resp != nil {
				if err := resp.Body.Close(); err != nil {
					t.Error(err)
				}
			}
			responseBytes := int64(3)
			responseStatus, httpStatus, result := "complete", "2xx", "success"
			if mode == "send-error" {
				responseBytes, responseStatus, httpStatus = 0, "incomplete", "none"
			}
			if mode == "body-error" {
				responseStatus = "incomplete"
			}
			if mode == "oversized" {
				responseBytes, responseStatus = 5, "incomplete"
			}
			if mode == "send-error" || mode == "body-error" || mode == "oversized" {
				result = "failure"
			}
			if mode == "http-error" {
				httpStatus = "5xx"
			}
			if (err != nil) != (result == "failure") || calls != 1 {
				t.Fatalf("error=%v calls=%d, want result %s and one physical request", err, calls, result)
			}
			if _, err := transport.RoundTrip(r); err != errTransport || calls != 1 {
				t.Fatal("refused replay reached the physical transport")
			}
			data := snapshot()
			if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreCreate, "", "") != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreCreate, result, httpStatus) != 1 || telemetrySum(data, telemetry.HTTPResults, telemetry.OpStoreCreate, "", "") != 1 {
				t.Fatal("HTTP attempt or result differs from the physical transport")
			}
			if telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCreate, "", "incomplete") != 2 || telemetrySum(data, telemetry.HTTPRequestBodyObservations, telemetry.OpStoreCreate, "", "incomplete") != 1 {
				t.Fatal("partial request bytes or completeness were lost")
			}
			if telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpStoreCreate, "", responseStatus) != responseBytes || telemetrySum(data, telemetry.HTTPResponseBodyObservations, telemetry.OpStoreCreate, "", responseStatus) != 1 {
				t.Fatal("response bytes or completeness were lost")
			}
		})
	}
}

// full_only: false
func TestHTTPTelemetryIsSafeDuringConcurrentTransfers(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	const transfers = 16
	want := map[string]struct {
		result   telemetry.Result
		status   string
		value    int64
		duration bool
	}{
		telemetry.OperationCalls:               {value: 1},
		telemetry.OperationResults:             {result: telemetry.ResultSuccess, value: 1},
		telemetry.OperationDuration:            {result: telemetry.ResultSuccess, duration: true},
		telemetry.HTTPAttempts:                 {value: 1},
		telemetry.HTTPResults:                  {result: telemetry.ResultSuccess, status: "2xx", value: 1},
		telemetry.HTTPDuration:                 {result: telemetry.ResultSuccess, status: "2xx", duration: true},
		telemetry.HTTPRequestBodyBytes:         {result: telemetry.ResultSuccess, status: "complete", value: 4},
		telemetry.HTTPRequestBodyObservations:  {result: telemetry.ResultSuccess, status: "complete", value: 1},
		telemetry.HTTPResponseBodyBytes:        {result: telemetry.ResultSuccess, status: "complete", value: 5},
		telemetry.HTTPResponseBodyObservations: {result: telemetry.ResultSuccess, status: "complete", value: 1},
	}
	points := make(chan telemetry.MetricPoint, transfers*len(want))
	var capabilities [transfers]*telemetry.Capability
	transport := boundedTransport{host: "fixture.invalid", next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_, err := io.Copy(io.Discard, r.Body)
		return response(200, "reply", nil), err
	})}
	var workers sync.WaitGroup
	t.Cleanup(func() {
		workers.Wait()
		for _, capability := range capabilities {
			capability.Deactivate()
		}
	})
	// Each transfer has its own capability because shared admission can drop contended points.
	// The transport calls remain concurrent.
	for i := range capabilities {
		capabilities[i] = telemetry.NewCapability(points, nil)
		ctx := telemetry.WithCapability(context.Background(), capabilities[i])
		workers.Add(1)
		go func() {
			defer workers.Done()
			ctx, call := startTelemetry(ctx, telemetry.OpStoreCreate)
			defer call.Finish(telemetry.ResultSuccess)
			r, err := http.NewRequestWithContext(operationContext(ctx, 8), http.MethodPost, "https://fixture.invalid/", strings.NewReader("body"))
			if err != nil {
				t.Error(err)
				return
			}
			resp, err := transport.RoundTrip(r)
			if err != nil {
				t.Error(err)
				return
			}
			if err := resp.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	for i, capability := range capabilities {
		if capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
			t.Errorf("transfer %d lost=%d rejected=%d", i, capability.LostMetrics(), capability.RejectedMetrics())
		}
	}
	seen := make(map[string]int, len(want))
	for len(points) != 0 {
		point := <-points
		expected, ok := want[point.Name]
		if !ok {
			t.Errorf("unexpected metric point %q", point.Name)
			continue
		}
		seen[point.Name]++
		if point.Provider != telemetry.ProviderAWS || point.Operation != telemetry.OpStoreCreate || point.Result != expected.result || point.Status != expected.status || point.Barrier != nil || point.IntValue != expected.value || math.IsNaN(point.FloatValue) || math.IsInf(point.FloatValue, 0) || point.FloatValue < 0 || !expected.duration && point.FloatValue != 0 {
			t.Errorf("concurrent transfer metric differs: %+v", point)
		}
	}
	for name := range want {
		if seen[name] != transfers {
			t.Errorf("metric %s observations=%d want=%d", name, seen[name], transfers)
		}
	}
}

// full_only: false
func TestRequestCompletionPreservesKnownEmptyRequestBody(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "https://fixture.invalid/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	body := trackRequestCompletion(r)
	if body != nil || r.Body != http.NoBody || r.ContentLength != 0 {
		t.Fatal("request completion changed empty-body framing")
	}
}

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
func TestRequestCompletionWaitsForReadAfterClose(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	body := readAfterCloseBody{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	ctx, call := startTelemetry(ctx, telemetry.OpStoreCreate)
	defer call.Finish(telemetry.ResultSuccess)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/", body)
	if err != nil {
		t.Fatal(err)
	}
	observation := startHTTPTelemetry(r)
	joined := trackRequestCompletion(r)
	readDone := make(chan struct{})
	go func() {
		_, _ = r.Body.Read(make([]byte, 8))
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
	case <-joined.done:
		t.Error("request completion ignored active Read accounting")
	default:
	}
	close(body.release)
	<-readDone
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if !joined.wait(ctx) {
		t.Fatal("request completion did not join the active Read")
	}
	observation.finish(false)
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpStoreCreate, "", "complete") != 3 || telemetrySum(data, telemetry.HTTPRequestBodyObservations, telemetry.OpStoreCreate, "", "complete") != 1 {
		t.Fatal("request completion did not retain the final Read bytes")
	}
}
