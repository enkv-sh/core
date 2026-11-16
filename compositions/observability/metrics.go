package observability

import (
	"context"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const (
	metricReadInterval = time.Hour
	metricReadTimeout  = 2 * time.Second
)

type safeMetricExporter struct {
	underlying sdkmetric.Exporter
	status     *deliveryCounter
}

func (exporter *safeMetricExporter) Temporality(kind sdkmetric.InstrumentKind) (value metricdata.Temporality) {
	defer func() {
		if recover() != nil {
			exporter.status.fail()
			value = metricdata.DeltaTemporality
		}
	}()
	return exporter.underlying.Temporality(kind)
}

func (exporter *safeMetricExporter) Aggregation(kind sdkmetric.InstrumentKind) (value sdkmetric.Aggregation) {
	defer func() {
		if recover() != nil {
			exporter.status.fail()
			value = sdkmetric.AggregationDefault{}
		}
	}()
	return exporter.underlying.Aggregation(kind)
}

func (exporter *safeMetricExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	exporter.status.accepted.Add(1)
	defer func() {
		if recover() != nil {
			exporter.status.fail()
		}
	}()
	if exporter.underlying.Export(ctx, data) != nil {
		exporter.status.fail()
	} else {
		exporter.status.written.Add(1)
	}
	return nil
}

func (exporter *safeMetricExporter) ForceFlush(ctx context.Context) error {
	defer func() {
		if recover() != nil {
			exporter.status.fail()
		}
	}()
	if exporter.underlying.ForceFlush(ctx) != nil {
		exporter.status.fail()
	}
	return nil
}

func (exporter *safeMetricExporter) Shutdown(ctx context.Context) error {
	defer func() {
		if recover() != nil {
			exporter.status.fail()
		}
	}()
	if exporter.underlying.Shutdown(ctx) != nil {
		exporter.status.fail()
	}
	return nil
}

func (runtime *Runtime) metricReaders() []sdkmetric.Reader {
	readers := []sdkmetric.Reader{}
	for _, name := range runtime.settings.MetricExporters {
		if !ambientTLSFilesAbsent("METRICS") {
			runtime.metricStatus[name].fail()
			continue
		}
		exporter := runtime.settings.ActiveExporters[name]
		var client *http.Client
		var endpoint string
		var transport *fileTransport
		switch exporter.Type {
		case "otlp_file":
			transport = newFileTransport(runtime.baseDirectory, exporter.Directory, "metrics")
			client = &http.Client{Transport: transport, Timeout: exportRequestTimeout}
			endpoint = "http://localhost/v1/metrics"
		case "otlp_http":
			if runtime.remote.ready() {
				client = runtime.remote.client()
				endpoint = remoteEndpoint(exporter, "metrics")
			}
		}
		if client == nil {
			runtime.metricStatus[name].fail()
			continue
		}
		otlp, err := otlpmetrichttp.New(context.Background(),
			otlpmetrichttp.WithEndpointURL(endpoint),
			otlpmetrichttp.WithHTTPClient(client),
			otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}),
			otlpmetrichttp.WithCompression(otlpmetrichttp.NoCompression),
			otlpmetrichttp.WithTemporalitySelector(sdkmetric.DefaultTemporalitySelector),
			otlpmetrichttp.WithAggregationSelector(sdkmetric.DefaultAggregationSelector),
		)
		if err != nil {
			runtime.metricStatus[name].fail()
			continue
		}
		safe := &safeMetricExporter{underlying: otlp, status: runtime.metricStatus[name]}
		reader := sdkmetric.NewPeriodicReader(safe, sdkmetric.WithInterval(metricReadInterval), sdkmetric.WithTimeout(metricReadTimeout))
		runtime.metricRoutes = append(runtime.metricRoutes, metricRoute{name: name, reader: reader, file: transport})
		readers = append(readers, reader)
	}
	return readers
}
