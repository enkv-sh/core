package observability

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type capturedTraceExporter struct{ spans chan sdktrace.ReadOnlySpan }

func (exporter capturedTraceExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	for _, span := range spans {
		exporter.spans <- span
	}
	return nil
}

func (capturedTraceExporter) Shutdown(context.Context) error { return nil }

func traceFileSettings(t *testing.T) Resolved {
	t.Helper()
	settings, err := Decode([]byte(`{"schema_version":1,"scopes":{"core":{"name":"safe.core","version":"v3"}},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return settings
}

// full_only: false
func TestTraceProviderAdmitsAndCountsSpansDuringStalledExporterConstruction(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	spans := make(chan sdktrace.ReadOnlySpan, traceQueueSlots)
	settings := traceFileSettings(t)
	root := t.TempDir()
	started := make(chan struct {
		runtime *Runtime
		err     error
	}, 1)
	go func() {
		runtime, err := Start(settings, SetupOptions{BaseDirectory: root, traceExporterFactory: func(context.Context, Exporter, *fileTransport) (sdktrace.SpanExporter, error) {
			close(entered)
			<-release
			return capturedTraceExporter{spans: spans}, nil
		}})
		started <- struct {
			runtime *Runtime
			err     error
		}{runtime, err}
	}()
	var runtime *Runtime
	select {
	case result := <-started:
		if result.err != nil {
			t.Fatal(result.err)
		}
		runtime = result.runtime
	case <-time.After(time.Second):
		t.Fatal("trace exporter construction delayed setup")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("trace exporter constructor did not start")
	}
	if runtime.TracerProvider() == nil || runtime.Capability() == nil {
		t.Fatal("trace provider was not ready at setup return")
	}
	tracer := runtime.TracerProvider().Tracer("safe.core", trace.WithInstrumentationVersion("v3"))
	productDone := make(chan struct{})
	go func() {
		for range traceQueueSlots + 1 {
			_, span := tracer.Start(context.Background(), "safe")
			span.End()
		}
		close(productDone)
	}()
	select {
	case <-productDone:
	case <-time.After(time.Second):
		t.Fatal("span handoff waited for exporter construction")
	}
	before := runtime.TraceStatus("capture")
	if before.Accepted != traceQueueSlots || before.Dropped != 1 || before.Written != 0 || !before.Incomplete {
		t.Fatalf("stalled destination did not account for its bounded queue: %+v", before)
	}
	releaseOnce.Do(func() { close(release) })
	if err := runtime.AwaitTraces(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(context.Background()); !errors.Is(err, errDeliveryIncomplete) {
		t.Fatal("dropped span lacks an incomplete-delivery result", err)
	}
	select {
	case <-runtime.closeDone:
	default:
		t.Fatal("released trace worker did not join")
	}
	after := runtime.TraceStatus("capture")
	if after.Accepted != traceQueueSlots || after.Written != traceQueueSlots || after.Dropped != 1 || len(spans) != traceQueueSlots {
		t.Fatalf("queued spans were not settled: %+v, captured=%d", after, len(spans))
	}
}

// full_only: false
func TestTraceConstructorFailureDropsQueuedSpans(t *testing.T) {
	for _, panicConstructor := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panicConstructor], func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			runtime, err := Start(traceFileSettings(t), SetupOptions{BaseDirectory: t.TempDir(), traceExporterFactory: func(context.Context, Exporter, *fileTransport) (sdktrace.SpanExporter, error) {
				close(entered)
				<-release
				if panicConstructor {
					panic("private exporter failure")
				}
				return nil, errors.New("private exporter failure")
			}})
			if err != nil {
				t.Fatal(err)
			}
			<-entered
			_, span := runtime.TracerProvider().Tracer("safe.core").Start(context.Background(), "safe")
			span.End()
			releaseOnce.Do(func() { close(release) })
			if err := runtime.AwaitTraces(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Close(context.Background()); !errors.Is(err, errFileDelivery) {
				t.Fatalf("failed trace destination reported complete shutdown: %v", err)
			}
			status := runtime.TraceStatus("capture")
			if status.Accepted != 1 || status.Dropped != 1 || status.Failed != 1 || !status.Incomplete {
				t.Fatalf("constructor failure did not account for accepted span: %+v", status)
			}
		})
	}
}

// full_only: false
func TestTraceProviderOverridesAmbientSpanLimits(t *testing.T) {
	for key, value := range map[string]string{
		"OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT": "1",
		"OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT":        "0",
		"OTEL_SPAN_EVENT_COUNT_LIMIT":            "0",
		"OTEL_SPAN_LINK_COUNT_LIMIT":             "0",
		"OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT":       "0",
		"OTEL_LINK_ATTRIBUTE_COUNT_LIMIT":        "0",
	} {
		t.Setenv(key, value)
	}
	spans := make(chan sdktrace.ReadOnlySpan, 1)
	runtime, err := Start(traceFileSettings(t), SetupOptions{BaseDirectory: t.TempDir(), traceExporterFactory: func(context.Context, Exporter, *fileTransport) (sdktrace.SpanExporter, error) {
		return capturedTraceExporter{spans: spans}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	linkContext := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}})
	_, span := runtime.TracerProvider().Tracer("safe.core", trace.WithInstrumentationVersion("v3")).Start(context.Background(), "safe", trace.WithAttributes(attribute.String("source", "retained")), trace.WithLinks(trace.Link{SpanContext: linkContext, Attributes: []attribute.KeyValue{attribute.String("link", "retained")}}))
	span.AddEvent("safe", trace.WithAttributes(attribute.String("event", "retained")))
	span.End()
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-spans:
		if got.InstrumentationScope().Name != "safe.core" || got.InstrumentationScope().Version != "v3" || len(got.Attributes()) != 1 || got.Attributes()[0].Value.AsString() != "retained" || len(got.Events()) != 1 || len(got.Events()[0].Attributes) != 1 || len(got.Links()) != 1 || len(got.Links()[0].Attributes) != 1 {
			t.Fatal("ambient SDK span limits overrode resolved setup")
		}
	default:
		t.Fatal("span was not exported")
	}
}
