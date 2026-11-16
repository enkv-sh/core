package observability

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// A burst of ordinary concurrent transfers can emit several operation and
// HTTP points per caller before the SDK worker has created its instruments.
// This fixed bound keeps that burst local while preserving nonblocking loss.
const metricQueueSlots = 1024
const shutdownDeadline = 10 * time.Second

var errMetricUnavailable = errors.New("telemetry metric worker unavailable")
var errDeliveryIncomplete = errors.New("telemetry delivery incomplete")

type SetupOptions struct {
	BaseDirectory string
	Console       io.Writer
	// ManualMetrics adds a delta ManualReader when metric exporters are enabled.
	// It does not enable metrics or replace configured exporter readers.
	ManualMetrics        bool
	traceExporterFactory traceExporterFactory
	remoteBase           http.RoundTripper
}

type traceRoute struct {
	name      string
	processor *boundedTraceProcessor
	file      *fileTransport
}

type metricRoute struct {
	name   string
	reader sdkmetric.Reader
	file   *fileTransport
}

type Runtime struct {
	settings         Resolved
	baseDirectory    string
	remote           *remoteTransport
	capability       *telemetry.Capability
	metrics          chan telemetry.MetricPoint
	metricDone       chan struct{}
	metricStop       chan struct{}
	metricReady      chan struct{}
	meterProvider    *sdkmetric.MeterProvider
	manualReader     *sdkmetric.ManualReader
	metricRoutes     []metricRoute
	metricStatus     map[string]*deliveryCounter
	traceRoutes      []traceRoute
	traceStatus      map[string]*deliveryCounter
	tracerProvider   *sdktrace.TracerProvider
	traceReady       chan struct{}
	traceDone        chan struct{}
	traceStop        chan struct{}
	recorder         *telemetry.Recorder
	logOutputs       []*logOutput
	logStop          chan struct{}
	logDone          chan struct{}
	closeOnce        sync.Once
	closeDone        chan struct{}
	closeErr         error
	closing          atomic.Bool
	sdkCallbackStart uint64
}

// Start accepts a validated, resolved configuration and takes its own copy.
// Sink construction and output I/O belong to background workers. When any
// exporter is enabled, Start installs the process-wide SDK logger and error
// handler once. Their counters discard callback content; they are not assigned
// to one runtime and are not restored by Close.
func Start(settings Resolved, options SetupOptions) (*Runtime, error) {
	settings = settings.Clone()
	for key, value := range settings.Resource {
		normalized, ok := resourceValue(value)
		if !ok {
			return nil, errConfiguration
		}
		settings.Resource[key] = normalized
	}
	for name, exporter := range settings.ActiveExporters {
		if exporter.Type == "otlp_http" {
			normalized, ok := normalizeRemoteEndpoint(exporter.Endpoint)
			if !ok {
				return nil, errConfiguration
			}
			exporter.Endpoint = normalized
			settings.ActiveExporters[name] = exporter
		}
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if len(settings.MetricExporters) != 0 && !ambientTLSFilesAbsent("METRICS") || len(settings.TraceExporters) != 0 && !ambientTLSFilesAbsent("TRACES") {
		return nil, errConfiguration
	}
	runtime := &Runtime{settings: settings, baseDirectory: options.BaseDirectory, metricStatus: map[string]*deliveryCounter{}, traceStatus: map[string]*deliveryCounter{}}
	runtime.remote = newRemoteTransport(settings, options.remoteBase)
	if len(settings.LogExporters) != 0 || len(settings.MetricExporters) != 0 || len(settings.TraceExporters) != 0 {
		installSDKErrorHandler()
		runtime.sdkCallbackStart = sdkCallbackCount.Load()
	}
	for _, name := range settings.MetricExporters {
		runtime.metricStatus[name] = new(deliveryCounter)
	}
	for _, name := range settings.TraceExporters {
		runtime.traceStatus[name] = new(deliveryCounter)
	}
	runtime.startLogs(options)
	runtime.startTraces(options)
	if len(settings.MetricExporters) != 0 {
		runtime.metrics = make(chan telemetry.MetricPoint, metricQueueSlots)
		runtime.metricDone = make(chan struct{})
		runtime.metricStop = make(chan struct{})
		runtime.metricReady = make(chan struct{})
		go runtime.runMetrics(options.ManualMetrics)
	}
	if runtime.tracerProvider == nil {
		runtime.capability = telemetry.NewCapability(runtime.metrics, runtime.recorder)
	} else {
		tracers := make(map[telemetry.Provider]trace.Tracer, len(settings.Scopes))
		for component, scope := range settings.Scopes {
			tracers[telemetry.Provider(component)] = runtime.tracerProvider.Tracer(scope.Name, trace.WithInstrumentationVersion(scope.Version))
		}
		runtime.capability = telemetry.NewCapabilityWithTracers(runtime.metrics, runtime.recorder, tracers)
	}
	return runtime, nil
}

func (runtime *Runtime) Context(ctx context.Context) context.Context {
	if runtime == nil {
		return ctx
	}
	return telemetry.WithCapability(ctx, runtime.capability)
}

func (runtime *Runtime) Capability() *telemetry.Capability {
	if runtime == nil {
		return nil
	}
	return runtime.capability
}

func (runtime *Runtime) RecorderStatus() telemetry.RecorderStatus {
	if runtime == nil || runtime.recorder == nil {
		return telemetry.RecorderStatus{}
	}
	return runtime.recorder.Status()
}

// MeterProvider returns nil for a nil runtime or disabled metrics. With metrics
// enabled, first require a successful AwaitMetrics; this getter does not wait.
func (runtime *Runtime) MeterProvider() *sdkmetric.MeterProvider {
	if runtime == nil {
		return nil
	}
	return runtime.meterProvider
}

// ManualReader returns nil for a nil runtime, disabled metrics, or setup without
// ManualMetrics. With metrics enabled, first require a successful AwaitMetrics;
// this getter does not wait. The reader collects delta metrics.
func (runtime *Runtime) ManualReader() *sdkmetric.ManualReader {
	if runtime == nil {
		return nil
	}
	return runtime.manualReader
}

func (runtime *Runtime) MetricsEnabled() bool {
	return runtime != nil && len(runtime.settings.MetricExporters) != 0
}

func (runtime *Runtime) MetricStatus(name string) DeliveryStatus {
	if runtime == nil {
		return DeliveryStatus{}
	}
	status := runtime.metricStatus[name].snapshot()
	if runtime.capability != nil && runtime.metricStatus[name] != nil {
		status.Dropped += runtime.capability.LostMetrics() + runtime.capability.RejectedMetrics()
		status.Incomplete = status.Incomplete || status.Dropped != 0
	}
	return status
}

func (runtime *Runtime) TraceStatus(name string) DeliveryStatus {
	if runtime == nil {
		return DeliveryStatus{}
	}
	status := runtime.traceStatus[name].snapshot()
	if runtime.capability != nil && runtime.traceStatus[name] != nil {
		status.Dropped += runtime.capability.LostTraces()
		status.Incomplete = status.Incomplete || status.Dropped != 0
	}
	return status
}

func (runtime *Runtime) DeliveryStatuses() map[string]DeliveryStatus {
	if runtime == nil {
		return nil
	}
	statuses := map[string]DeliveryStatus{}
	if runtime.settings.Console && runtime.settings.LogLevel != Off {
		statuses["logs.console"] = runtime.LogStatus("console")
	}
	if runtime.settings.LogLevel != Off {
		for _, name := range runtime.settings.LogExporters {
			statuses["logs."+name] = runtime.LogStatus(name)
		}
	}
	for _, name := range runtime.settings.MetricExporters {
		statuses["metrics."+name] = runtime.MetricStatus(name)
	}
	for _, name := range runtime.settings.TraceExporters {
		statuses["traces."+name] = runtime.TraceStatus(name)
	}
	return statuses
}

func (runtime *Runtime) LogsEnabled() bool {
	return runtime != nil && runtime.settings.LogLevel != Off && (runtime.settings.Console || len(runtime.settings.LogExporters) != 0)
}

func (runtime *Runtime) LogFileSource() string {
	if runtime == nil {
		return ""
	}
	for _, name := range runtime.settings.LogExporters {
		exporter := runtime.settings.ActiveExporters[name]
		if exporter.Type == "otlp_file" {
			return path.Join(exporter.Directory, "logs.jsonl")
		}
	}
	return ""
}

func (runtime *Runtime) ScopeNames() map[string]string {
	if runtime == nil {
		return nil
	}
	names := make(map[string]string, len(runtime.settings.Scopes))
	for component, scope := range runtime.settings.Scopes {
		names[component] = scope.Name
	}
	return names
}

func (runtime *Runtime) Resource() map[string]any {
	if runtime == nil {
		return nil
	}
	return runtime.settings.Clone().Resource
}

// AwaitMetrics joins metric-provider initialization before enabled SDK getters
// can be used. It returns nil for a nil runtime or disabled metrics. For enabled
// metrics it requires a live context and returns an error on cancellation or an
// unavailable worker. It does not flush queued measurements.
func (runtime *Runtime) AwaitMetrics(ctx context.Context) error {
	if runtime == nil || runtime.metricReady == nil {
		return nil
	}
	if runtime.closing.Load() {
		return errMetricUnavailable
	}
	select {
	case <-runtime.metricReady:
		return nil
	case <-runtime.metricDone:
		return errMetricUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *Runtime) FlushMetrics(ctx context.Context) error {
	if runtime != nil && runtime.closing.Load() {
		return errMetricUnavailable
	}
	return runtime.flushMetrics(ctx)
}

func (runtime *Runtime) flushMetrics(ctx context.Context) error {
	if runtime == nil || runtime.metrics == nil {
		return nil
	}
	barrier := make(chan struct{})
	select {
	case <-runtime.metricDone:
		return errMetricUnavailable
	default:
	}
	select {
	case runtime.metrics <- telemetry.MetricPoint{Barrier: barrier}:
	case <-runtime.metricDone:
		return errMetricUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-barrier:
		return nil
	case <-runtime.metricDone:
		return errMetricUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close waits for owned workers and reports both cleanup and configured delivery
// failures. A delivery error does not imply that a joined worker is still active.
func (runtime *Runtime) Close(ctx context.Context) error {
	if runtime == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runtime.closeOnce.Do(func() {
		runtime.closing.Store(true)
		runtime.closeDone = make(chan struct{})
		// The invocation retains cleanup ownership after any caller stops waiting.
		// Delivery has one fresh setup-owned deadline, independent of Product ctx.
		go func() {
			defer close(runtime.closeDone)
			defer func() { runtime.closeErr = errors.Join(runtime.closeErr, runtime.remote.close()) }()
			settle, cancel := context.WithTimeout(context.Background(), shutdownDeadline)
			defer cancel()
			runtime.capability.Deactivate()
			results := make(chan error, 3)
			go func() { results <- runtime.closeLogs(settle) }()
			go func() { results <- runtime.closeTraces(settle) }()
			go func() { results <- runtime.closeMetrics(settle) }()
			for range 3 {
				runtime.closeErr = errors.Join(runtime.closeErr, <-results)
			}
		}()
	})
	wait, cancel := context.WithTimeout(ctx, shutdownDeadline)
	defer cancel()
	if err := wait.Err(); err != nil {
		runtime.markUnsettled()
		return err
	}
	select {
	case <-runtime.closeDone:
		for _, status := range runtime.DeliveryStatuses() {
			if status.Incomplete || status.Dropped != 0 || status.Failed != 0 || status.Accepted != status.Written {
				return errors.Join(runtime.closeErr, errDeliveryIncomplete)
			}
		}
		return runtime.closeErr
	case <-wait.Done():
		runtime.markUnsettled()
		return wait.Err()
	}
}

func (runtime *Runtime) closeTraces(ctx context.Context) error {
	if runtime.traceStop == nil {
		return nil
	}
	close(runtime.traceStop)
	// Coordinator completion precedes processor/file finalization even when
	// the caller's bounded wait or the delivery deadline has ended.
	<-runtime.traceDone
	var result error
	// A remote route can use the whole deadline. Settle each processor and
	// its file independently so one blocked destination cannot fail another.
	results := make(chan error, len(runtime.traceRoutes))
	for _, route := range runtime.traceRoutes {
		go func() {
			err := route.processor.Shutdown(ctx)
			<-route.processor.done
			if route.file != nil {
				if closeErr := route.file.Close(); closeErr != nil {
					runtime.traceStatus[route.name].fail()
					err = errors.Join(err, closeErr)
				}
			}
			runtime.traceStatus[route.name].settled.Store(true)
			results <- err
		}()
	}
	for range runtime.traceRoutes {
		result = errors.Join(result, <-results)
	}
	if runtime.tracerProvider != nil {
		result = errors.Join(result, runtime.tracerProvider.Shutdown(ctx))
	}
	if result != nil {
		runtime.markUnsettledTraces()
	}
	return result
}

func (runtime *Runtime) closeMetrics(ctx context.Context) error {
	if runtime.metrics == nil {
		return nil
	}
	result := runtime.flushMetrics(ctx)
	close(runtime.metricStop)
	<-runtime.metricDone
	results := make(chan error, len(runtime.metricRoutes))
	for _, route := range runtime.metricRoutes {
		go func() {
			err := route.reader.Shutdown(ctx)
			if route.file != nil {
				if closeErr := route.file.Close(); closeErr != nil {
					runtime.metricStatus[route.name].fail()
					err = errors.Join(err, closeErr)
				}
			}
			runtime.metricStatus[route.name].settled.Store(true)
			results <- err
		}()
	}
	for range runtime.metricRoutes {
		result = errors.Join(result, <-results)
	}
	if runtime.manualReader != nil {
		result = errors.Join(result, runtime.manualReader.Shutdown(ctx))
	}
	if runtime.meterProvider != nil {
		// Each reader has already settled. The SDK reports a repeated reader
		// shutdown while it changes the provider to its stopped state.
		if err := runtime.meterProvider.Shutdown(ctx); err != nil && !errors.Is(err, sdkmetric.ErrReaderShutdown) {
			result = errors.Join(result, err)
		}
	}
	if result != nil {
		runtime.markUnsettledMetrics()
	}
	return result
}

func (runtime *Runtime) markUnsettledMetrics() {
	for _, status := range runtime.metricStatus {
		if status.accepted.Load() > status.written.Load()+status.failed.Load()+status.dropped.Load() {
			status.incomplete.Store(true)
		}
	}
}
func (runtime *Runtime) markUnsettledTraces() {
	for _, status := range runtime.traceStatus {
		if status.accepted.Load() > status.written.Load()+status.failed.Load()+status.dropped.Load() {
			status.incomplete.Store(true)
		}
	}
}
func (runtime *Runtime) markUnsettled() {
	runtime.markUnsettledMetrics()
	runtime.markUnsettledTraces()
	for _, status := range runtime.metricStatus {
		if !status.settled.Load() {
			status.incomplete.Store(true)
		}
	}
	for _, status := range runtime.traceStatus {
		if !status.settled.Load() {
			status.incomplete.Store(true)
		}
	}
	for _, output := range runtime.logOutputs {
		select {
		case <-output.done:
		default:
			output.incomplete.Store(true)
		}
	}

	for _, output := range runtime.logOutputs {
		if output.accepted.Load() > output.written.Load()+output.failed.Load()+output.dropped.Load() {
			output.incomplete.Store(true)
		}
	}
}

func (runtime *Runtime) runMetrics(manual bool) {
	defer close(runtime.metricDone)
	defer func() {
		if recover() != nil {
			for _, status := range runtime.metricStatus {
				status.fail()
			}
		}
	}()
	providerOptions := []sdkmetric.Option{sdkmetric.WithResource(resource.NewSchemaless(resourceAttributes(runtime.settings.Resource)...))}
	for _, reader := range runtime.metricReaders() {
		providerOptions = append(providerOptions, sdkmetric.WithReader(reader))
	}
	if manual {
		runtime.manualReader = sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality {
			return metricdata.DeltaTemporality
		}))
		providerOptions = append(providerOptions, sdkmetric.WithReader(runtime.manualReader))
	}
	runtime.meterProvider = sdkmetric.NewMeterProvider(providerOptions...)
	close(runtime.metricReady)
	counters := map[string]metric.Int64Counter{}
	histograms := map[string]metric.Float64Histogram{}
	for {
		var point telemetry.MetricPoint
		select {
		case point = <-runtime.metrics:
		case <-runtime.metricStop:
			// Admission has joined before stop. Drain every remaining point even
			// when an expired flush could not enqueue or await its barrier.
			select {
			case point = <-runtime.metrics:
			default:
				return
			}
		}
		if point.Barrier != nil {
			close(point.Barrier)
			continue
		}
		component := string(point.Provider)
		scope := runtime.settings.Scopes[component]
		meter := runtime.meterProvider.Meter(scope.Name, metric.WithInstrumentationVersion(scope.Version))
		key := component + "\x00" + point.Name
		attrs := []attribute.KeyValue{attribute.String("provider", component), attribute.String("operation", string(point.Operation))}
		if point.Result != "" {
			attrs = append(attrs, attribute.String("result", string(point.Result)))
		}
		if point.Status != "" {
			attrs = append(attrs, attribute.String("status", point.Status))
		}
		if point.Name == telemetry.OperationDuration || point.Name == telemetry.HTTPDuration {
			instrument := histograms[key]
			if instrument == nil {
				created, err := meter.Float64Histogram(point.Name, metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(durationBuckets...))
				if err != nil {
					continue
				}
				instrument = created
				histograms[key] = instrument
			}
			instrument.Record(context.Background(), point.FloatValue, metric.WithAttributes(attrs...))
			continue
		}
		instrument := counters[key]
		if instrument == nil {
			unit := "{call}"
			switch point.Name {
			case telemetry.ManifestSelectedEntries, telemetry.ManifestIncludedEntries, telemetry.ManifestExcludedEntries:
				unit = "{entry}"
			case telemetry.OperationInputBytes, telemetry.OperationOutputBytes, telemetry.HTTPRequestBodyBytes, telemetry.HTTPResponseBodyBytes:
				unit = "B"
			case telemetry.HTTPAttempts, telemetry.HTTPResults:
				unit = "{attempt}"
			case telemetry.HTTPRequestBodyObservations, telemetry.HTTPResponseBodyObservations:
				unit = "{observation}"
			}
			created, err := meter.Int64Counter(point.Name, metric.WithUnit(unit))
			if err != nil {
				continue
			}
			instrument = created
			counters[key] = instrument
		}
		instrument.Add(context.Background(), point.IntValue, metric.WithAttributes(attrs...))
	}
}

var durationBuckets = []float64{
	0.000001, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005,
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.5, 0.75,
	1, 1.5, 2.5, 5, 10, 30, 60,
}

func resourceAttributes(values map[string]any) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(values))
	for key, value := range values {
		switch typed := value.(type) {
		case string:
			attrs = append(attrs, attribute.String(key, typed))
		case bool:
			attrs = append(attrs, attribute.Bool(key, typed))
		case int64:
			attrs = append(attrs, attribute.Int64(key, typed))
		case float64:
			attrs = append(attrs, attribute.Float64(key, typed))
		case []any:
			switch typed[0].(type) {
			case string:
				items := make([]string, len(typed))
				for i, item := range typed {
					items[i] = item.(string)
				}
				attrs = append(attrs, attribute.StringSlice(key, items))
			case bool:
				items := make([]bool, len(typed))
				for i, item := range typed {
					items[i] = item.(bool)
				}
				attrs = append(attrs, attribute.BoolSlice(key, items))
			case int64:
				items := make([]int64, len(typed))
				for i, item := range typed {
					items[i] = item.(int64)
				}
				attrs = append(attrs, attribute.Int64Slice(key, items))
			case float64:
				items := make([]float64, len(typed))
				for i, item := range typed {
					items[i] = item.(float64)
				}
				attrs = append(attrs, attribute.Float64Slice(key, items))
			}
		}
	}
	return attrs
}
