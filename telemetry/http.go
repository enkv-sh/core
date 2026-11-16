package telemetry

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// HTTPAttempt observes one underlying RoundTrip. It neither executes transport
// policy nor joins body readers; the owning transport must retain those rules.
type HTTPAttempt struct {
	ctx                                         context.Context
	started                                     time.Time
	capability                                  *Capability
	provider                                    Provider
	operation                                   Operation
	request, response                           int64
	requestComplete, responseComplete, finished bool
}

func StartHTTP(ctx context.Context, provider Provider, operation Operation) *HTTPAttempt {
	capability := capabilityFromContext(ctx)
	if !capability.MetricsEnabled() || !ValidOperationOwner(provider, operation) || provider != ProviderAWS && provider != ProviderGCP {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	observation := &HTTPAttempt{ctx: ctx, started: time.Now(), capability: capability, provider: provider, operation: operation}
	capability.emitMetric(MetricPoint{Name: HTTPAttempts, Provider: provider, Operation: operation, IntValue: 1})
	return observation
}

func (attempt *HTTPAttempt) ObserveRequest(bytes int64, complete bool) {
	if attempt != nil && !attempt.finished && bytes >= 0 {
		attempt.request, attempt.requestComplete = bytes, complete
	}
}

func (attempt *HTTPAttempt) ObserveResponse(bytes int64, complete bool) {
	if attempt != nil && !attempt.finished && bytes >= 0 {
		attempt.response, attempt.responseComplete = bytes, complete
	}
}

func statusClass(status int) string {
	switch {
	case status == 0:
		return "none"
	case status >= http.StatusContinue && status < http.StatusOK:
		return "1xx"
	case status >= http.StatusOK && status < http.StatusMultipleChoices:
		return "2xx"
	case status >= http.StatusMultipleChoices && status < http.StatusBadRequest:
		return "3xx"
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		return "4xx"
	case status >= http.StatusInternalServerError && status < maximumHTTPStatus+1:
		return "5xx"
	default:
		return "other"
	}
}

func (attempt *HTTPAttempt) Finish(statusCode int, failed bool) {
	if attempt == nil || attempt.finished {
		return
	}
	attempt.finished = true
	result := ResultSuccess
	if failed {
		result = ResultFailure
	}
	point := MetricPoint{Provider: attempt.provider, Operation: attempt.operation, Result: result, Status: statusClass(statusCode)}
	point.Name, point.IntValue = HTTPResults, 1
	attempt.capability.emitMetric(point)
	point.Name, point.IntValue, point.FloatValue = HTTPDuration, 0, time.Since(attempt.started).Seconds()
	attempt.capability.emitMetric(point)
	for _, body := range []struct {
		bytes              int64
		complete           bool
		size, observations string
	}{
		{attempt.request, attempt.requestComplete, HTTPRequestBodyBytes, HTTPRequestBodyObservations},
		{attempt.response, attempt.responseComplete, HTTPResponseBodyBytes, HTTPResponseBodyObservations},
	} {
		status := "incomplete"
		if body.complete {
			status = "complete"
		}
		point.Status = status
		point.Name, point.IntValue, point.FloatValue = body.size, body.bytes, 0
		attempt.capability.emitMetric(point)
		point.Name, point.IntValue = body.observations, 1
		attempt.capability.emitMetric(point)
	}
}

// BodyObservation is a passive byte observation. Read and Close errors are
// returned unchanged. The owner, not this helper, decides when to close or join.
type BodyObservation struct {
	source              io.ReadCloser
	expected            int64
	mu                  sync.Mutex
	bytes               int64
	reads               int
	eof, failed, closed bool
}

// TrackBody must be called only on the enabled path. A nil observation denotes
// an absent request body. An absent response must instead remain incomplete.
func TrackBody(body io.ReadCloser, expectedLength int64) *BodyObservation {
	if body == nil {
		return nil
	}
	return &BodyObservation{source: body, expected: expectedLength}
}

func (body *BodyObservation) Read(p []byte) (int, error) {
	body.mu.Lock()
	body.reads++
	body.mu.Unlock()
	n, err := body.source.Read(p)
	body.mu.Lock()
	body.reads--
	body.bytes += int64(n)
	body.eof = body.eof || err == io.EOF
	body.failed = body.failed || (err != nil && err != io.EOF)
	body.mu.Unlock()
	return n, err
}

func (body *BodyObservation) Close() error {
	err := body.source.Close()
	body.mu.Lock()
	body.closed = true
	body.failed = body.failed || err != nil
	body.mu.Unlock()
	return err
}

func (body *BodyObservation) Snapshot() (bytes int64, complete bool) {
	if body == nil {
		return 0, true
	}
	body.mu.Lock()
	defer body.mu.Unlock()
	lengthComplete := body.eof
	if body.expected >= 0 {
		lengthComplete = body.bytes == body.expected
	}
	return body.bytes, body.closed && body.reads == 0 && !body.failed && lengthComplete
}
