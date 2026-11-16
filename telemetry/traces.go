package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func (capability *Capability) startSpan(ctx context.Context, tracer trace.Tracer, provider Provider, operation Operation, details DiagnosticDetails) (next context.Context, span trace.Span) {
	if tracer == nil {
		return ctx, nil
	}
	next = ctx
	defer func() {
		if recover() != nil {
			capability.lostTraces.Add(1)
			next, span = ctx, nil
		}
	}()
	next, span = tracer.Start(ctx, string(operation), trace.WithAttributes(startSpanAttributes(provider, operation, details)...))
	if next == nil || span == nil {
		capability.lostTraces.Add(1)
		return ctx, nil
	}
	return next, span
}

func (capability *Capability) spanIdentity(span trace.Span) (traceID, spanID string, sampled bool) {
	if span == nil {
		return "", "", false
	}
	defer func() {
		if recover() != nil {
			capability.lostTraces.Add(1)
			traceID, spanID, sampled = "", "", false
		}
	}()
	context := span.SpanContext()
	if context.IsValid() {
		return context.TraceID().String(), context.SpanID().String(), context.IsSampled()
	}
	return "", "", false
}

func startSpanAttributes(provider Provider, operation Operation, details DiagnosticDetails) []attribute.KeyValue {
	attributes := []attribute.KeyValue{attribute.String("provider", string(provider)), attribute.String("operation", string(operation))}
	if !validDetails(details) {
		return attributes
	}
	if details.entryName != "" {
		attributes = append(attributes, attribute.String("member.name", details.entryName))
	}
	if details.keyID != "" {
		attributes = append(attributes, attribute.String("key.id", details.keyID))
	}
	if details.commandID != "" {
		attributes = append(attributes, attribute.String("command.id", details.commandID))
	}
	if details.attemptID != "" {
		attributes = append(attributes, attribute.String("attempt.id", details.attemptID))
	}
	if details.invocationID != "" {
		attributes = append(attributes, attribute.String("invocation.id", details.invocationID))
	}
	if details.workerID != "" {
		attributes = append(attributes, attribute.String("worker.id", details.workerID))
	}
	if details.pathKind != "" {
		attributes = append(attributes, attribute.String("path.kind", details.pathKind))
	}
	if details.path != "" {
		attributes = append(attributes, attribute.String("path", details.path))
	}
	if details.configField != "" {
		attributes = append(attributes, attribute.String("config.field", details.configField))
	}
	return attributes
}

func (call *Call) endSpan(result Result, reason DiagnosticReason) {
	if call == nil || call.span == nil {
		return
	}
	defer func() {
		if recover() != nil {
			call.capability.lostTraces.Add(1)
		}
	}()
	attributes := []attribute.KeyValue{attribute.String("result", string(result))}
	if reason != "" {
		attributes = append(attributes, attribute.String("reason", string(reason)))
	}
	if validDetails(call.details) && call.details.errorClass != "" {
		attributes = append(attributes, attribute.String("error.class", string(call.details.errorClass)))
		if call.details.httpStatus != 0 {
			attributes = append(attributes, attribute.Int("error.http_status", call.details.httpStatus))
		}
		attributes = append(attributes, attribute.String("error.detail_status", errorDetailStatus(call.details)))
		if call.details.errorText != "" {
			attributes = append(attributes, attribute.String("error.detail", call.details.errorText))
		}
	}
	call.span.SetAttributes(attributes...)
	call.span.End()
}
