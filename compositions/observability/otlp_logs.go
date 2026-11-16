package observability

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"sync/atomic"

	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
)

const logAttributeCountLimit = 128

type safeLogExporter struct {
	underlying sdklog.Exporter
	failed     atomic.Uint64
}

// The output worker owns this processor. It groups only the records already
// admitted to its fixed queue, so the SDK has no second unaccounted queue.
type batchLogProcessor struct {
	exporter *safeLogExporter
	records  []sdklog.Record
}

func (processor *batchLogProcessor) OnEmit(_ context.Context, record *sdklog.Record) error {
	processor.records = append(processor.records, record.Clone())
	return nil
}

func (processor *batchLogProcessor) export(ctx context.Context) error {
	if len(processor.records) == 0 {
		return nil
	}
	before := processor.exporter.failed.Load()
	_ = processor.exporter.Export(ctx, processor.records)
	clear(processor.records)
	processor.records = processor.records[:0]
	if processor.exporter.failed.Load() != before {
		return errFileDelivery
	}
	return nil
}

func (processor *batchLogProcessor) ForceFlush(ctx context.Context) error {
	result := processor.export(ctx)
	before := processor.exporter.failed.Load()
	_ = processor.exporter.ForceFlush(ctx)
	if result != nil || processor.exporter.failed.Load() != before {
		return errFileDelivery
	}
	return nil
}

func (processor *batchLogProcessor) Shutdown(ctx context.Context) error {
	result := processor.export(ctx)
	before := processor.exporter.failed.Load()
	_ = processor.exporter.Shutdown(ctx)
	if result != nil || processor.exporter.failed.Load() != before {
		return errFileDelivery
	}
	return nil
}

func (exporter *safeLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	if exporter.underlying.Export(ctx, records) != nil {
		exporter.failed.Add(uint64(len(records)))
	}
	return nil
}

func (exporter *safeLogExporter) Shutdown(ctx context.Context) error {
	if exporter.underlying.Shutdown(ctx) != nil {
		exporter.failed.Add(1)
	}
	return nil
}

func (exporter *safeLogExporter) ForceFlush(ctx context.Context) error {
	if exporter.underlying.ForceFlush(ctx) != nil {
		exporter.failed.Add(1)
	}
	return nil
}

type otlpLogWriter struct {
	settings  Resolved
	transport *fileTransport
	remote    *remoteTransport
	endpoint  string
	once      sync.Once
	provider  *sdklog.LoggerProvider
	exporter  *safeLogExporter
	processor *batchLogProcessor
	failed    bool
}

func newFileLogWriter(settings Resolved, base, directory string) *otlpLogWriter {
	return &otlpLogWriter{settings: settings, transport: newFileTransport(base, directory, "logs"), endpoint: "http://localhost/v1/logs"}
}

func newRemoteLogWriter(settings Resolved, exporter Exporter, transport *remoteTransport) *otlpLogWriter {
	return &otlpLogWriter{settings: settings, remote: transport, endpoint: remoteEndpoint(exporter, "logs")}
}

func (writer *otlpLogWriter) initialize() {
	var client *http.Client
	if writer.remote != nil {
		if !writer.remote.ready() {
			writer.failed = true
			return
		}
		client = writer.remote.client()
	} else {
		client = &http.Client{Transport: writer.transport, Timeout: exportRequestTimeout}
	}
	exporter, err := otlploghttp.New(context.Background(),
		otlploghttp.WithEndpointURL(writer.endpoint),
		otlploghttp.WithHTTPClient(client),
		// The supplied client owns TLS. Mark this setting explicit so the SDK
		// does not open ambient certificate files that the client cannot use.
		otlploghttp.WithTLSClientConfig(&tls.Config{}),
		otlploghttp.WithRetry(otlploghttp.RetryConfig{Enabled: false}),
		otlploghttp.WithCompression(otlploghttp.NoCompression),
	)
	if err != nil {
		writer.failed = true
		return
	}
	writer.exporter = &safeLogExporter{underlying: exporter}
	writer.processor = &batchLogProcessor{exporter: writer.exporter, records: make([]sdklog.Record, 0, logQueueSlots)}
	writer.provider = sdklog.NewLoggerProvider(
		sdklog.WithResource(resource.NewSchemaless(resourceAttributes(writer.settings.Resource)...)),
		sdklog.WithProcessor(writer.processor),
		// Admission bounds each record. Ambient SDK limits must not remove
		// fields or truncate values from an admitted record.
		sdklog.WithAttributeCountLimit(logAttributeCountLimit),
		sdklog.WithAttributeValueLengthLimit(telemetry.MaximumLogRecordBytes),
	)
}

func (writer *otlpLogWriter) write(ctx context.Context, record telemetry.DiagnosticRecord) error {
	return writer.writeBatch(ctx, []telemetry.DiagnosticRecord{record})
}

func (writer *otlpLogWriter) writeBatch(ctx context.Context, records []telemetry.DiagnosticRecord) error {
	writer.once.Do(writer.initialize)
	if writer.failed || writer.provider == nil {
		return errFileDelivery
	}
	for _, record := range records {
		if writer.emit(ctx, record) != nil {
			return errFileDelivery
		}
	}
	return writer.processor.export(ctx)
}

func (writer *otlpLogWriter) emit(ctx context.Context, record telemetry.DiagnosticRecord) error {
	scope := writer.settings.Scopes[record.Component]
	logger := writer.provider.Logger(scope.Name, log.WithInstrumentationVersion(scope.Version))
	var output log.Record
	output.SetTimestamp(record.OccurredAt)
	output.SetSeverity(log.Severity(record.SeverityNumber))
	output.SetSeverityText(record.SeverityText)
	output.SetBody(log.StringValue(string(record.Event)))
	output.AddAttributes(
		log.Int64("schema.version", int64(record.SchemaVersion)),
		log.Int64("sequence", int64(record.Sequence)),
		log.Int64("call", int64(record.Call)),
		log.String("component", record.Component),
		log.String("provider", string(record.Provider)),
		log.String("operation", string(record.Operation)),
		log.String("event", string(record.Event)),
		log.String("stage", string(record.Stage)),
		log.String("result", string(record.Result)),
		log.String("reason", string(record.Reason)),
		log.String("member.name", record.EntryName),
		log.String("key.id", record.KeyID),
		log.String("command.id", record.CommandID),
		log.String("attempt.id", record.AttemptID),
		log.String("invocation.id", record.InvocationID),
		log.String("worker.id", record.WorkerID),
		log.String("path.kind", record.PathKind),
		log.String("path", record.Path),
		log.String("config.field", record.ConfigField),
		log.String("error.class", string(record.ErrorClass)),
		log.Int64("error.http_status", int64(record.HTTPStatus)),
		log.String("error.detail", record.ErrorDetail),
		log.String("error.detail_status", record.ErrorDetailStatus),
	)
	if record.ParentCall != 0 {
		output.AddAttributes(log.Int64("parent.call", int64(record.ParentCall)))
	}
	emitContext := ctx
	if record.TraceID != "" {
		traceID, traceErr := trace.TraceIDFromHex(record.TraceID)
		spanID, spanErr := trace.SpanIDFromHex(record.SpanID)
		if traceErr != nil || spanErr != nil || !traceID.IsValid() || !spanID.IsValid() {
			return errFileDelivery
		}
		flags := trace.TraceFlags(0)
		if record.TraceSampled {
			flags = trace.FlagsSampled
		}
		emitContext = trace.ContextWithSpanContext(emitContext, trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: traceID, SpanID: spanID, TraceFlags: flags,
		}))
	}
	logger.Emit(emitContext, output)
	return nil
}

func (writer *otlpLogWriter) close(ctx context.Context) error {
	failed := false
	if writer.provider != nil {
		before := writer.exporter.failed.Load()
		if writer.provider.Shutdown(ctx) != nil || writer.exporter.failed.Load() != before {
			failed = true
		}
	}
	if writer.transport != nil {
		if writer.transport.Close() != nil {
			failed = true
		}
	}
	if failed {
		return errFileDelivery
	}
	return nil
}
