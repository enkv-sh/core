package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type operationContextValueKey struct{}

type operationContextSpan struct{ trace.Span }

type operationContextTracer struct {
	trace.Tracer
	span trace.Span
}

func (t operationContextTracer) Start(ctx context.Context, _ string, _ ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.ContextWithSpan(ctx, t.span), t.span
}

// full_only: false
func TestCallContextPreservesSuppliedLifetimeAndValues(t *testing.T) {
	for _, mode := range []string{"disabled", "diagnostics", "metrics", "tracing"} {
		t.Run(mode, func(t *testing.T) {
			parent := context.Background()
			recorder := NewRecorder()
			var activeSpan *operationContextSpan
			switch mode {
			case "diagnostics":
				parent = WithCapability(parent, NewCapability(nil, recorder))
			case "metrics":
				parent = WithCapability(parent, NewCapability(make(chan MetricPoint, 32), nil))
			case "tracing":
				span := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled})
				activeSpan = &operationContextSpan{Span: trace.SpanFromContext(trace.ContextWithSpanContext(parent, span))}
				parent = WithCapability(parent, NewCapabilityWithTracers(nil, recorder, map[Provider]trace.Tracer{
					ProviderCore: operationContextTracer{Tracer: noop.NewTracerProvider().Tracer("context-test"), span: activeSpan},
				}))
			}
			call := Start(parent, ProviderCore, OpCoreInspectSelectedWork)
			defer call.Finish(ResultSuccess)
			deadline := time.Now().Add(time.Minute)
			owned, cancel := context.WithDeadline(context.WithValue(parent, operationContextValueKey{}, "owned-value"), deadline)
			defer cancel()
			got := CallContext(owned, call)
			if got.Done() != owned.Done() || got.Value(operationContextValueKey{}) != "owned-value" {
				t.Error("call context replaced the supplied owner or its values")
			}
			if actual, ok := got.Deadline(); !ok || actual != deadline {
				t.Error("call context replaced the supplied earlier deadline", actual, ok)
			}
			if mode == "disabled" && got != owned {
				t.Error("disabled telemetry changed the context")
			}
			if call != nil && call.recorder != nil {
				child := Start(got, ProviderCore, OpCoreInspectSelectedWork)
				if child == nil || child.parentCall != call.diagnosticCall {
					t.Error("call context lost diagnostic parent")
				}
				child.Finish(ResultSuccess)
			}
			if mode == "tracing" {
				actual, ok := trace.SpanFromContext(got).(*operationContextSpan)
				if !ok || actual != activeSpan || !actual.SpanContext().Equal(activeSpan.SpanContext()) {
					t.Error("call context lost its active span or identity")
				}
			}
			cancel()
			if got.Err() != context.Canceled {
				t.Error("call context discarded owner cancellation", got.Err())
			}
		})
	}
}
