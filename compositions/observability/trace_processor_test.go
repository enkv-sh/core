package observability

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// full_only: false
func TestFailedTraceInitializationCannotAcknowledgeFlush(t *testing.T) {
	release := make(chan struct{})
	processor := newDeferredTraceProcessor(func(context.Context) (sdktrace.SpanExporter, error) {
		<-release
		return nil, errFileDelivery
	}, new(deliveryCounter))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	flushed := make(chan error, 1)
	go func() { flushed <- processor.ForceFlush(ctx) }()
	for len(processor.queue) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("flush barrier was not handed off")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	if err := <-flushed; !errors.Is(err, errFileDelivery) {
		t.Fatalf("failed constructor acknowledged complete flush: %v", err)
	}
	if err := processor.Shutdown(ctx); !errors.Is(err, errFileDelivery) {
		t.Fatalf("failed constructor reported complete shutdown: %v", err)
	}
}

// full_only: false
func TestExpiredTraceCloseDropsSpansWhenConstructorReturnsLate(t *testing.T) {
	release := make(chan struct{})
	exporter := capturedTraceExporter{spans: make(chan sdktrace.ReadOnlySpan, traceQueueSlots)}
	status := new(deliveryCounter)
	processor := newDeferredTraceProcessor(func(context.Context) (sdktrace.SpanExporter, error) {
		<-release
		return exporter, nil
	}, status)
	span := (tracetest.SpanStub{Name: "safe"}).Snapshot()
	for range traceQueueSlots {
		processor.OnEnd(span)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := processor.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired close did not return its deadline: %v", err)
	}
	close(release)
	select {
	case <-processor.done:
	case <-time.After(time.Second):
		t.Fatal("late constructor left its trace worker running")
	}
	got := status.snapshot()
	if got.Accepted != traceQueueSlots || got.Dropped != traceQueueSlots || got.Written != 0 || len(exporter.spans) != 0 {
		t.Fatalf("expired close exported a queued span: %+v", got)
	}
}

type acceptingTraceExporter struct{}

func (acceptingTraceExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return nil }
func (acceptingTraceExporter) Shutdown(context.Context) error                             { return nil }

type blockedTraceExporter struct {
	entered chan struct{}
	release chan struct{}
	ready   sync.Once
}

func (exporter *blockedTraceExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	exporter.ready.Do(func() { close(exporter.entered) })
	<-exporter.release
	return nil
}
func (*blockedTraceExporter) Shutdown(context.Context) error { return nil }

// full_only: false
func TestBlockedTraceDestinationCannotDelayProductHandoffOrClose(t *testing.T) {
	exporter := &blockedTraceExporter{entered: make(chan struct{}), release: make(chan struct{})}
	status := new(deliveryCounter)
	processor := newBoundedTraceProcessor(exporter, status)
	span := (tracetest.SpanStub{Name: "safe"}).Snapshot()
	processor.OnEnd(span)
	select {
	case <-exporter.entered:
	case <-time.After(time.Second):
		t.Fatal("trace destination was not entered")
	}
	productDone := make(chan struct{})
	go func() {
		for range traceQueueSlots + 1 {
			processor.OnEnd(span)
		}
		close(productDone)
	}()
	select {
	case <-productDone:
	case <-time.After(200 * time.Millisecond):
		close(exporter.release)
		t.Fatal("Product handoff waited for blocked trace destination")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if processor.Shutdown(ctx) == nil {
		close(exporter.release)
		t.Fatal("blocked trace destination reported complete shutdown")
	}
	if status.snapshot().Dropped == 0 || !status.snapshot().Incomplete {
		close(exporter.release)
		t.Fatal("blocked trace loss was not counted")
	}
	close(exporter.release)
	select {
	case <-processor.done:
	case <-time.After(time.Second):
		t.Fatal("trace worker did not settle after the sink was released")
	}
}

// full_only: false
func TestTraceAdmissionAndShutdownAccountForConcurrentEnd(t *testing.T) {
	status := new(deliveryCounter)
	processor := newBoundedTraceProcessor(acceptingTraceExporter{}, status)
	span := (tracetest.SpanStub{Name: "safe"}).Snapshot()
	start := make(chan struct{})
	var producers sync.WaitGroup
	for range 32 {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for range 32 {
				processor.OnEnd(span)
			}
		}()
	}
	close(start)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := processor.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	producers.Wait()
	got := status.snapshot()
	if got.Written > got.Accepted {
		t.Fatalf("exported span was not accepted: %+v", got)
	}
	if got.Accepted > got.Written+got.Dropped+got.Failed {
		t.Fatalf("accepted span was stranded: %+v", got)
	}
	if got.Accepted+got.Dropped == 0 {
		t.Fatal("race did not exercise admission")
	}
}

// full_only: false
func TestExpiredTraceDrainWaitsForLateAdmissionHandoff(t *testing.T) {
	status := new(deliveryCounter)
	processor := newBoundedTraceProcessor(acceptingTraceExporter{}, status)
	span := (tracetest.SpanStub{Name: "safe"}).Snapshot()
	processor.inFlight.Add(1) // Model OnEnd paused after its pre-close check.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = processor.Shutdown(ctx)
	time.Sleep(2 * time.Millisecond)
	select {
	case <-processor.done:
		t.Fatal("worker exited while a producer could still enqueue")
	default:
	}
	processor.queue <- traceItem{span: span}
	status.accepted.Add(1)
	processor.inFlight.Add(-1)
	select {
	case <-processor.done:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish after late handoff")
	}
	got := status.snapshot()
	if got.Accepted != 1 || got.Dropped != 1 || !got.Incomplete {
		t.Fatalf("late accepted span was not counted as dropped: %+v", got)
	}
}
