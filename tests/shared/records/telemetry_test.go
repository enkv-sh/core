package records

import (
	"context"
	"testing"

	"enkv.sh/compositions/observability"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func metricRuntime(t *testing.T) *observability.Runtime {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}},"scopes":{"core":{"name":"test.core"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: t.TempDir(), ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitMetrics(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return runtime
}

// full_only: false
func TestCollectorDisabledCreatesNoSDK(t *testing.T) {
	before := otel.GetMeterProvider()
	settings, err := observability.Resolve(observability.Config{}, observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := NewCollector(runtime)
	if c.Enabled() || runtime.MeterProvider() != nil || otel.GetMeterProvider() != before {
		t.Fatal("disabled collector changed SDK")
	}
	if got := c.Collect(context.Background(), "run", "worker", "transition"); got.Status != "disabled" || len(got.Metrics) != 0 {
		t.Fatal("disabled measurements were available")
	}
	_ = c.Close(context.Background())
}

// full_only: false
func TestCollectorKeepsMetricNamesScopesAndDelta(t *testing.T) {
	runtime := metricRuntime(t)
	c := NewCollector(runtime)
	counter, err := runtime.MeterProvider().Meter("test.core").Int64Counter("enkv.future.calls", metric.WithUnit("{call}"))
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 3, metric.WithAttributes(attribute.String("provider", "core")))
	first := c.Collect(context.Background(), "run", "worker", "transition")
	if first.Status != "complete" || len(first.Metrics) != 1 || first.Metrics[0].Value == nil || *first.Metrics[0].Value != 3 || first.Scopes["core"] != "test.core" || first.Resource["service.name"] != "enkv" {
		t.Fatalf("first delta: %+v", first)
	}
	counter.Add(context.Background(), 2, metric.WithAttributes(attribute.String("provider", "core")))
	second := c.Collect(context.Background(), "run", "worker", "verification")
	if second.Status != "complete" || len(second.Metrics) != 1 || *second.Metrics[0].Value != 2 {
		t.Fatalf("second delta: %+v", second)
	}
}

// full_only: false
func TestCollectorRejectsUnsafeAttributes(t *testing.T) {
	runtime := metricRuntime(t)
	c := NewCollector(runtime)
	counter, err := runtime.MeterProvider().Meter("test.core").Int64Counter(telemetry.OperationCalls)
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("credential_path", "SYNTHETIC_SECRET")))
	got := c.Collect(context.Background(), "run", "worker", "transition")
	if got.Status != "incomplete" || len(got.Metrics) != 0 || got.FailureClass != "invalid_metric" {
		t.Fatalf("unsafe telemetry retained: %+v", got)
	}
}
