package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

type liveTelemetryProbe struct {
	*records.Collector
	Context context.Context
}

func liveMetricSettings(t *testing.T) *observability.Resolved {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return &settings
}

func liveTelemetry(t *testing.T) *liveTelemetryProbe {
	t.Helper()
	runtime, err := observability.Start(*liveMetricSettings(t), observability.SetupOptions{BaseDirectory: t.TempDir(), ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	ready, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.AwaitMetrics(ready); err != nil {
		t.Fatal(err)
	}
	collector := records.NewCollector(runtime)
	t.Cleanup(func() {
		if !collector.Close(context.Background()) {
			t.Error("controlled telemetry shutdown failed", runtime.DeliveryStatuses())
		}
	})
	return &liveTelemetryProbe{Collector: collector, Context: runtime.Context(context.Background())}
}

func liveTelemetrySnapshot(t *testing.T, collector *liveTelemetryProbe) records.Snapshot {
	t.Helper()
	snapshot := collector.Collect(context.Background(), "legacy-baseline", "setup-check", "setup")
	if snapshot.Status != "complete" {
		t.Fatalf("controlled telemetry unavailable: %s", snapshot.FailureClass)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal("controlled telemetry encoding failed")
	}
	for _, secret := range []string{"synthetic-access-token", "test-secret", "test-session", "selected-secret", "private diagnostic", "private credential diagnostic", "https://", "fixture-bucket", "test-bucket", "credential_file", "run/HEAD"} {
		if strings.Contains(string(body), secret) {
			t.Fatal("private setup data escaped into telemetry")
		}
	}
	for _, metric := range snapshot.Metrics {
		if !telemetry.ValidMetric(metric.Name, metric.Unit) || !telemetry.ValidAttributes(metric.Attributes) {
			t.Fatal("setup telemetry contract changed")
		}
	}
	return snapshot
}

func liveMetricSum(snapshot records.Snapshot, name, operation, result, status string) uint64 {
	var sum uint64
	for _, metric := range snapshot.Metrics {
		if metric.Name == name && metric.Attributes["provider"] == liveProvider() && (operation == "" || metric.Attributes["operation"] == operation) && (result == "" || metric.Attributes["result"] == result) && (status == "" || metric.Attributes["status"] == status) && metric.Value != nil {
			sum += uint64(*metric.Value)
		}
	}
	return sum
}

func liveHTTPErrorCount(snapshot records.Snapshot) uint64 {
	return liveMetricSum(snapshot, telemetry.HTTPResults, "", "", "3xx") + liveMetricSum(snapshot, telemetry.HTTPResults, "", "", "4xx") + liveMetricSum(snapshot, telemetry.HTTPResults, "", "", "5xx")
}
