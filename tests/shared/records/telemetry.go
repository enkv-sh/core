package records

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type Collector struct {
	enabled    bool
	shutdownOK bool
	runtime    *observability.Runtime
	once       sync.Once
}

func NewCollector(runtime *observability.Runtime) *Collector {
	return &Collector{enabled: runtime.MetricsEnabled(), shutdownOK: true, runtime: runtime}
}

func (c *Collector) Enabled() bool { return c != nil && c.enabled }

func (c *Collector) Close(ctx context.Context) bool {
	if c == nil || c.runtime == nil {
		return true
	}
	c.once.Do(func() {
		c.shutdownOK = c.runtime.Close(ctx) == nil
	})
	return c.shutdownOK
}

func (c *Collector) Collect(ctx context.Context, runID, worker, phase string) Snapshot {
	out := Snapshot{SchemaVersion: TelemetryVersion, RunID: runID, Worker: worker, Phase: phase, Status: "disabled", Temporality: "delta", Metrics: []Metric{}}
	if !c.Enabled() {
		return out
	}
	out.CollectedAt = time.Now().UTC()
	out.Status = "incomplete"
	if c.runtime.AwaitMetrics(ctx) != nil {
		out.FailureClass = "collection_failed"
		return out
	}
	if c.runtime.FlushMetrics(ctx) != nil {
		out.FailureClass = "collection_failed"
		return out
	}
	reader := c.runtime.ManualReader()
	if reader == nil {
		out.FailureClass = "setup_failed"
		return out
	}
	var data metricdata.ResourceMetrics
	if reader.Collect(ctx, &data) != nil {
		out.FailureClass = "collection_failed"
		return out
	}
	out.Resource = c.runtime.Resource()
	scopes := c.runtime.ScopeNames()
	out.Scopes = scopes
	for _, scope := range data.ScopeMetrics {
		known := false
		for _, name := range scopes {
			if scope.Scope.Name == name {
				known = true
				break
			}
		}
		if !known {
			continue
		}
		for _, measurement := range scope.Metrics {
			rows, ok := metricRows(measurement)
			if !ok {
				out.Metrics = []Metric{}
				out.FailureClass = "invalid_metric"
				return out
			}
			out.Metrics = append(out.Metrics, rows...)
		}
	}
	sort.SliceStable(out.Metrics, func(i, j int) bool { return out.Metrics[i].Name < out.Metrics[j].Name })
	out.Status = "complete"
	return out
}

func safeAttributes(values []attribute.KeyValue) (map[string]string, bool) {
	attrs := make(map[string]string, len(values))
	for _, value := range values {
		if value.Value.Type() != attribute.STRING {
			return nil, false
		}
		attrs[string(value.Key)] = value.Value.AsString()
	}
	return attrs, telemetry.ValidAttributes(attrs)
}

func finite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }

func metricRows(measurement metricdata.Metrics) ([]Metric, bool) {
	rows := []Metric{}
	appendValue := func(attrs attribute.Set, kind string, value float64) bool {
		values, ok := safeAttributes(attrs.ToSlice())
		if !ok || !finite(value) {
			return false
		}
		rows = append(rows, Metric{Name: measurement.Name, Unit: measurement.Unit, Attributes: values, Kind: kind, Value: &value})
		return true
	}
	appendHistogram := func(attrs attribute.Set, count uint64, sum float64, bounds []float64, buckets []uint64) bool {
		values, ok := safeAttributes(attrs.ToSlice())
		if !ok || !finite(sum) {
			return false
		}
		for _, bound := range bounds {
			if !finite(bound) {
				return false
			}
		}
		rows = append(rows, Metric{Name: measurement.Name, Unit: measurement.Unit, Attributes: values, Kind: "histogram", Count: &count, Sum: &sum, Bounds: bounds, Buckets: buckets})
		return true
	}
	switch values := measurement.Data.(type) {
	case metricdata.Sum[int64]:
		if values.Temporality != metricdata.DeltaTemporality {
			return nil, false
		}
		for _, point := range values.DataPoints {
			if !appendValue(point.Attributes, "sum", float64(point.Value)) {
				return nil, false
			}
		}
	case metricdata.Sum[float64]:
		if values.Temporality != metricdata.DeltaTemporality {
			return nil, false
		}
		for _, point := range values.DataPoints {
			if !appendValue(point.Attributes, "sum", point.Value) {
				return nil, false
			}
		}
	case metricdata.Gauge[int64]:
		for _, point := range values.DataPoints {
			if !appendValue(point.Attributes, "gauge", float64(point.Value)) {
				return nil, false
			}
		}
	case metricdata.Gauge[float64]:
		for _, point := range values.DataPoints {
			if !appendValue(point.Attributes, "gauge", point.Value) {
				return nil, false
			}
		}
	case metricdata.Histogram[int64]:
		if values.Temporality != metricdata.DeltaTemporality {
			return nil, false
		}
		for _, point := range values.DataPoints {
			if !appendHistogram(point.Attributes, point.Count, float64(point.Sum), point.Bounds, point.BucketCounts) {
				return nil, false
			}
		}
	case metricdata.Histogram[float64]:
		if values.Temporality != metricdata.DeltaTemporality {
			return nil, false
		}
		for _, point := range values.DataPoints {
			if !appendHistogram(point.Attributes, point.Count, point.Sum, point.Bounds, point.BucketCounts) {
				return nil, false
			}
		}
	default:
		return nil, false
	}
	return rows, true
}
