package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// Call is local to one synchronous invocation. A nil Call is the disabled path.
// It retains bounded, source-reviewed diagnostic identities and error details.
type Call struct {
	ctx                                    context.Context
	started                                time.Time
	provider                               Provider
	operation                              Operation
	recorder                               *Recorder
	capability                             *Capability
	span                                   trace.Span
	details                                DiagnosticDetails
	traceID, spanID                        string
	traceSampled                           bool
	diagnosticCall, parentCall             uint64
	input, output                          int64
	manifestEntries                        [3]int64
	hasManifestEntries                     bool
	hasInput, hasOutput, metrics, finished bool
}

// Start captures a fixed metric point before the operation. A full queue loses
// the point without delaying the Product call.
func Start(ctx context.Context, provider Provider, operation Operation) *Call {
	return StartWithDetails(ctx, provider, operation, DiagnosticDetails{})
}

func StartWithDetails(ctx context.Context, provider Provider, operation Operation, details DiagnosticDetails) *Call {
	if !ValidOperationOwner(provider, operation) {
		return nil
	}
	diagnostic := diagnosticFromContext(ctx)
	capability := capabilityFromContext(ctx)
	metricsEnabled := capability.MetricsEnabled()
	tracer := capability.tracer(provider)
	if !metricsEnabled && diagnostic.recorder == nil && tracer == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	spanContext, span := capability.startSpan(ctx, tracer, provider, operation, details)
	call := &Call{ctx: spanContext, started: started, provider: provider, operation: operation, recorder: diagnostic.recorder, capability: capability, span: span, parentCall: diagnostic.call, details: details}
	call.traceID, call.spanID, call.traceSampled = capability.spanIdentity(span)
	if call.recorder != nil {
		call.diagnosticCall = call.recorder.nextCall()
		call.recorder.emit(diagnosticRecord{call: call.diagnosticCall, parent: call.parentCall, provider: provider, operation: operation, event: DiagnosticStart, details: details,
			traceID: call.traceID, spanID: call.spanID, traceSampled: call.traceSampled})
	}
	if !metricsEnabled {
		return call
	}
	call.metrics = true
	capability.emitMetric(MetricPoint{Name: OperationCalls, Provider: provider, Operation: operation, IntValue: 1})
	return call
}

func (call *Call) Context() context.Context {
	if call == nil {
		return context.Background()
	}
	if call.recorder == nil || call.diagnosticCall == 0 {
		return call.ctx
	}
	return context.WithValue(call.ctx, diagnosticContextKey{}, diagnosticContext{recorder: call.recorder, call: call.diagnosticCall})
}

func CallContext(ctx context.Context, call *Call) context.Context {
	if call == nil {
		return ctx
	}
	ctx = PrivateContext(ctx, call.Context())
	if span := trace.SpanFromContext(call.ctx); call.span != nil || span.SpanContext().IsValid() {
		ctx = trace.ContextWithSpan(ctx, span)
	}
	return ctx
}

func (call *Call) Checkpoint(stage DiagnosticStage, reason DiagnosticReason) {
	if call == nil || call.finished || call.recorder == nil {
		return
	}
	call.recorder.emit(diagnosticRecord{call: call.diagnosticCall, parent: call.parentCall, provider: call.provider, operation: call.operation, event: DiagnosticCheckpoint, stage: stage, reason: reason, details: call.details, elapsedNanos: time.Since(call.started).Nanoseconds(),
		traceID: call.traceID, spanID: call.spanID, traceSampled: call.traceSampled})
}

func (call *Call) InputBytes(bytes int64) {
	if call != nil && call.metrics && !call.finished && bytes >= 0 {
		call.input += bytes
		call.hasInput = true
	}
}

func (call *Call) OutputBytes(bytes int64) {
	if call != nil && call.metrics && !call.finished && bytes >= 0 {
		call.output += bytes
		call.hasOutput = true
	}
}

// ManifestEntries records only the complete, jointly bounded partition counts.
func (call *Call) ManifestEntries(selected, included, excluded int) {
	if call == nil || !call.metrics || call.finished || call.provider != ProviderCore || call.operation != OpCoreReaderManifest || selected < 0 || selected > 512 || included < 0 || excluded < 0 || included > selected || excluded != selected-included {
		return
	}
	call.manifestEntries = [3]int64{int64(selected), int64(included), int64(excluded)}
	call.hasManifestEntries = true
}

// ReturnDetails adds source-reviewed error facts to the return record. The
// identity and path captured at Start remain unchanged. Invalid detail makes
// that return record fail admission without changing the Product result.
func (call *Call) ReturnDetails(details DiagnosticDetails) {
	if call == nil || call.finished {
		return
	}
	if !validDetails(details) || details.entryName != "" || details.keyID != "" || details.commandID != "" || details.attemptID != "" || details.invocationID != "" || details.workerID != "" ||
		details.pathKind != "" || details.path != "" || details.configField != "" {
		call.details.invalid = true
		return
	}
	call.details.errorClass = details.errorClass
	call.details.httpStatus = details.httpStatus
	call.details.errorText = details.errorText
}

func (call *Call) Finish(result Result) {
	call.FinishReason(result, diagnosticReasonForResult(result))
}

func (call *Call) FinishReason(result Result, reason DiagnosticReason) {
	if call == nil || call.finished {
		return
	}
	call.finished = true
	if !AllowedAttribute("result", string(result)) {
		result = ResultUnknown
	}
	if !validDiagnosticReason(reason) {
		reason = DiagnosticReasonInvalid
	}
	if call.recorder != nil {
		call.recorder.emit(diagnosticRecord{call: call.diagnosticCall, parent: call.parentCall, provider: call.provider, operation: call.operation, event: DiagnosticReturn, result: result, reason: reason, details: call.details, elapsedNanos: time.Since(call.started).Nanoseconds(),
			traceID: call.traceID, spanID: call.spanID, traceSampled: call.traceSampled})
	}
	call.endSpan(result, reason)
	if !call.metrics {
		return
	}
	point := MetricPoint{Provider: call.provider, Operation: call.operation, Result: result}
	if call.hasManifestEntries && result == ResultSuccess {
		for i, name := range [...]string{ManifestSelectedEntries, ManifestIncludedEntries, ManifestExcludedEntries} {
			point.Name, point.IntValue = name, call.manifestEntries[i]
			call.capability.emitMetric(point)
		}
	}
	point.Name, point.IntValue = OperationResults, 1
	call.capability.emitMetric(point)
	point.Name, point.IntValue, point.FloatValue = OperationDuration, 0, time.Since(call.started).Seconds()
	call.capability.emitMetric(point)
	if call.hasInput {
		point.Name, point.IntValue, point.FloatValue = OperationInputBytes, call.input, 0
		call.capability.emitMetric(point)
	}
	if call.hasOutput {
		point.Name, point.IntValue, point.FloatValue = OperationOutputBytes, call.output, 0
		call.capability.emitMetric(point)
	}
}
