package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// full_only: false
func TestOperationMetricPointsRetainExactCountsAndUnfinishedCalls(t *testing.T) {
	points := make(chan MetricPoint, 16)
	capability := NewCapability(points, nil)
	ctx := WithCapability(context.Background(), capability)
	call := Start(ctx, ProviderAWS, OpStoreRead)
	Start(ctx, ProviderAWS, OpStoreRead)
	call.OutputBytes(1<<53 + 1)
	call.Finish(ResultSuccess)
	call.Finish(ResultFailure)
	counts := map[string]int{}
	for len(points) > 0 {
		point := <-points
		counts[point.Name]++
		if point.Name == OperationOutputBytes && point.IntValue != 1<<53+1 {
			t.Fatalf("byte count lost precision: %+v", point)
		}
	}
	if counts[OperationCalls] != 2 || counts[OperationResults] != 1 || counts[OperationDuration] != 1 || counts[OperationOutputBytes] != 1 {
		t.Fatalf("wrong point counts: %+v", counts)
	}
}

// full_only: false
func TestStoreListOperationHasOnlyProviderOwners(t *testing.T) {
	points := make(chan MetricPoint, 32)
	ctx := WithCapability(context.Background(), NewCapability(points, nil))
	for _, provider := range []Provider{ProviderAWS, ProviderGCP} {
		call := Start(ctx, provider, OpStoreList)
		if call == nil {
			t.Fatal("Store listing operation has no provider owner")
		}
		call.OutputBytes(31)
		call.Finish(ResultReadOK)
	}
	if Start(ctx, ProviderCore, OpStoreList) != nil || Start(context.Background(), ProviderAWS, OpStoreList) != nil {
		t.Fatal("Store listing escaped its provider or disabled boundary")
	}
	results := 0
	for len(points) > 0 {
		point := <-points
		if !validMetricPoint(point) || point.Operation != OpStoreList {
			t.Fatal("unbounded Store listing metric")
		}
		if point.Name == OperationResults {
			results++
		}
	}
	if results != 2 {
		t.Fatal("Store listing result count differs", results)
	}
}

// full_only: false
func TestHTTPPointsPreserveCompleteAndIncompleteBodies(t *testing.T) {
	points := make(chan MetricPoint, 32)
	ctx := WithCapability(context.Background(), NewCapability(points, nil))
	complete := StartHTTP(ctx, ProviderGCP, OpStoreRead)
	complete.ObserveRequest(0, true)
	complete.ObserveResponse(9, true)
	complete.Finish(200, false)
	incomplete := StartHTTP(ctx, ProviderGCP, OpStoreRead)
	incomplete.ObserveRequest(4, false)
	incomplete.ObserveResponse(3, false)
	incomplete.Finish(200, true)
	StartHTTP(ctx, ProviderGCP, OpStoreRead)
	counts := map[string]int64{}
	for len(points) > 0 {
		point := <-points
		counts[point.Name+":"+point.Status] += point.IntValue
	}
	if counts[HTTPAttempts+":"] != 3 || counts[HTTPResults+":2xx"] != 2 || counts[HTTPRequestBodyObservations+":complete"] != 1 || counts[HTTPRequestBodyObservations+":incomplete"] != 1 || counts[HTTPResponseBodyBytes+":complete"] != 9 || counts[HTTPResponseBodyBytes+":incomplete"] != 3 {
		t.Fatalf("wrong HTTP points: %+v", counts)
	}
}

// full_only: false
func TestSensitiveLabelsCannotEnterMetricQueue(t *testing.T) {
	secret := "synthetic-secret-resource-key-url-credential"
	points := make(chan MetricPoint, 8)
	capability := NewCapability(points, nil)
	ctx := WithCapability(context.Background(), capability)
	if Start(ctx, Provider(secret), OpStoreRead) != nil || Start(ctx, ProviderAWS, Operation(secret)) != nil {
		t.Fatal("unsafe operation identity accepted")
	}
	Start(ctx, ProviderAWS, OpStoreRead).Finish(Result(secret))
	for len(points) > 0 {
		point := <-points
		if string(point.Provider) == secret || string(point.Operation) == secret || string(point.Result) == secret || point.Status == secret || point.Name == secret {
			t.Fatal("secret entered metric queue")
		}
		if !validMetricPoint(point) {
			t.Fatalf("invalid point entered queue: %+v", point)
		}
	}
}

// full_only: false
func TestMetricQueueFullNeverWaitsForConsumer(t *testing.T) {
	points := make(chan MetricPoint, 1)
	capability := NewCapability(points, nil)
	ctx := WithCapability(context.Background(), capability)
	done := make(chan struct{})
	go func() { Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultSuccess); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Product call waited for full metric queue")
	}
	if capability.LostMetrics() == 0 {
		t.Fatal("metric loss was not counted")
	}
	capability.Deactivate()
	Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultSuccess)
}

// full_only: false
func TestNilContextAndNoCapabilityRemainDisabled(t *testing.T) {
	var nilContext context.Context
	if WithCapability(nilContext, NewCapability(make(chan MetricPoint, 1), nil)) != nil {
		t.Fatal("nil Product context was changed")
	}
	if allocations := testing.AllocsPerRun(100, func() {
		call := Start(context.Background(), ProviderCore, OpCoreOpen)
		call.InputBytes(5)
		call.Finish(ResultSuccess)
		attempt := StartHTTP(context.Background(), ProviderAWS, OpStoreRead)
		attempt.ObserveRequest(5, true)
		attempt.Finish(200, false)
	}); allocations != 0 {
		t.Fatalf("disabled allocations = %g", allocations)
	}
}

type bodyError struct{ closeErr error }

func (b bodyError) Read(p []byte) (int, error) { copy(p, "x"); return 1, io.ErrUnexpectedEOF }
func (b bodyError) Close() error               { return b.closeErr }

// full_only: false
func TestTrackBodyForwardsFailuresAndObservesActualBytes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		source          io.ReadCloser
		expected, bytes int64
		complete        bool
	}{
		{"complete", io.NopCloser(bytes.NewBufferString("abc")), 3, 3, true},
		{"unknown-length", io.NopCloser(bytes.NewBufferString("abc")), -1, 3, true},
		{"truncated", io.NopCloser(bytes.NewBufferString("abc")), 10, 3, false},
		{"read-error", bodyError{}, 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := TrackBody(tc.source, tc.expected)
			_, readErr := io.ReadAll(body)
			if tc.name == "read-error" && !errors.Is(readErr, io.ErrUnexpectedEOF) {
				t.Fatal("read error was changed")
			}
			if err := body.Close(); err != nil {
				t.Fatal(err)
			}
			n, complete := body.Snapshot()
			if n != tc.bytes || complete != tc.complete {
				t.Fatalf("body = (%d,%v), want (%d,%v)", n, complete, tc.bytes, tc.complete)
			}
		})
	}
	sentinel := errors.New("synthetic-close-error")
	body := TrackBody(bodyError{closeErr: sentinel}, 0)
	if err := body.Close(); !errors.Is(err, sentinel) {
		t.Fatal("close error was changed")
	}
	if _, complete := body.Snapshot(); complete {
		t.Fatal("failed close was complete")
	}
	var empty *BodyObservation
	if n, complete := empty.Snapshot(); n != 0 || !complete {
		t.Fatal("absent body is not known empty")
	}
}

type blockingBody struct {
	start, stop chan struct{}
	once        sync.Once
}

func (b *blockingBody) Read(p []byte) (int, error) { close(b.start); <-b.stop; return 0, io.EOF }
func (b *blockingBody) Close() error               { b.once.Do(func() { close(b.stop) }); return nil }

// full_only: false
func TestTrackBodyCloseDoesNotBlockOnRead(t *testing.T) {
	source := &blockingBody{start: make(chan struct{}), stop: make(chan struct{})}
	body := TrackBody(source, -1)
	done := make(chan struct{})
	go func() { _, _ = body.Read(make([]byte, 1)); close(done) }()
	<-source.start
	if _, complete := body.Snapshot(); complete {
		t.Fatal("active read marked complete")
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	if _, complete := body.Snapshot(); !complete {
		t.Fatal("joined EOF and close not complete")
	}
}
