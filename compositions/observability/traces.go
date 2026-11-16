package observability

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	spanAttributeValueLengthLimit = 8 << 10
	spanAttributeCountLimit       = 128
	spanEventCountLimit           = 128
	spanLinkCountLimit            = 128
	spanEventAttributeCountLimit  = 128
	spanLinkAttributeCountLimit   = 128
)

type traceExporterFactory func(context.Context, Exporter, *fileTransport) (sdktrace.SpanExporter, error)

func fileTraceExporter(ctx context.Context, exporter Exporter, transport *fileTransport) (sdktrace.SpanExporter, error) {
	if exporter.Type != "otlp_file" || transport == nil {
		return nil, errFileDelivery
	}
	if !ambientTLSFilesAbsent("TRACES") {
		return nil, errConfiguration
	}
	client := &http.Client{Transport: transport, Timeout: exportRequestTimeout}
	return otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL("http://localhost/v1/traces"),
		otlptracehttp.WithHTTPClient(client),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
		otlptracehttp.WithCompression(otlptracehttp.NoCompression),
	)
}

func (runtime *Runtime) traceExporter(ctx context.Context, exporter Exporter, transport *fileTransport) (sdktrace.SpanExporter, error) {
	if exporter.Type == "otlp_file" {
		return fileTraceExporter(ctx, exporter, transport)
	}
	if exporter.Type != "otlp_http" {
		return nil, errRemoteDelivery
	}
	if !ambientTLSFilesAbsent("TRACES") {
		return nil, errConfiguration
	}
	if !runtime.remote.ready() {
		return nil, errRemoteDelivery
	}
	return otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(remoteEndpoint(exporter, "traces")),
		otlptracehttp.WithHTTPClient(runtime.remote.client()),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
		otlptracehttp.WithCompression(otlptracehttp.NoCompression),
	)
}

func (runtime *Runtime) startTraces(options SetupOptions) {
	if len(runtime.settings.TraceExporters) == 0 {
		return
	}
	runtime.traceReady = make(chan struct{})
	runtime.traceDone = make(chan struct{})
	runtime.traceStop = make(chan struct{})
	providerOptions := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(resource.NewSchemaless(resourceAttributes(runtime.settings.Resource)...)),
		// These fixed values override the pinned SDK's ambient span limits.
		sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{
			AttributeValueLengthLimit:   spanAttributeValueLengthLimit,
			AttributeCountLimit:         spanAttributeCountLimit,
			EventCountLimit:             spanEventCountLimit,
			LinkCountLimit:              spanLinkCountLimit,
			AttributePerEventCountLimit: spanEventAttributeCountLimit,
			AttributePerLinkCountLimit:  spanLinkAttributeCountLimit,
		}),
	}
	if runtime.settings.TraceSampleRatio == 0 {
		providerOptions = append(providerOptions, sdktrace.WithSampler(sdktrace.NeverSample()))
	} else {
		providerOptions = append(providerOptions, sdktrace.WithSampler(sdktrace.TraceIDRatioBased(runtime.settings.TraceSampleRatio)))
	}
	factory := options.traceExporterFactory
	if factory == nil {
		factory = runtime.traceExporter
	}
	initialized := make([]<-chan struct{}, 0, len(runtime.settings.TraceExporters))
	for _, name := range runtime.settings.TraceExporters {
		exporter := runtime.settings.ActiveExporters[name]
		var transport *fileTransport
		if exporter.Type == "otlp_file" {
			// This allocation does no file or network I/O.
			transport = newFileTransport(runtime.baseDirectory, exporter.Directory, "traces")
		}
		processor := newDeferredTraceProcessor(func(ctx context.Context) (sdktrace.SpanExporter, error) {
			return factory(ctx, exporter, transport)
		}, runtime.traceStatus[name])
		runtime.traceRoutes = append(runtime.traceRoutes, traceRoute{name: name, processor: processor, file: transport})
		providerOptions = append(providerOptions, sdktrace.WithSpanProcessor(processor))
		initialized = append(initialized, processor.initialized)
	}
	// Product work can use this provider as soon as Start returns. Exporter
	// constructors and destination I/O remain in the bounded workers.
	runtime.tracerProvider = sdktrace.NewTracerProvider(providerOptions...)
	go func() {
		defer close(runtime.traceDone)
		for _, ready := range initialized {
			select {
			case <-ready:
			case <-runtime.traceStop:
				return
			}
		}
		close(runtime.traceReady)
		<-runtime.traceStop
	}()
}

func (runtime *Runtime) AwaitTraces(ctx context.Context) error {
	if runtime == nil || runtime.traceReady == nil {
		return nil
	}
	select {
	case <-runtime.traceReady:
		return nil
	case <-runtime.traceDone:
		return errFileDelivery
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *Runtime) TracerProvider() *sdktrace.TracerProvider {
	if runtime == nil {
		return nil
	}
	return runtime.tracerProvider
}
