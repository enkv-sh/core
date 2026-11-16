package crypto

import (
	"context"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func cryptoTelemetryReader(t *testing.T) (context.Context, *observability.Runtime) {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"level":"off","exporters":[]},"metrics":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: t.TempDir(), ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	ready, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.AwaitMetrics(ready); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(closeContext); err != nil {
			t.Error(err)
		}
	})
	return runtime.Context(context.Background()), runtime
}

func cryptoTelemetrySnapshot(t *testing.T, runtime *observability.Runtime) metricdata.ResourceMetrics {
	t.Helper()
	flushContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.FlushMetrics(flushContext); err != nil {
		t.Fatal(err)
	}
	var data metricdata.ResourceMetrics
	if err := runtime.ManualReader().Collect(flushContext, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func assertCryptoTelemetry(t *testing.T, runtime *observability.Runtime, operation string, results map[string]int64) {
	t.Helper()
	assertCryptoTelemetryData(t, cryptoTelemetrySnapshot(t, runtime), operation, results)
}

func assertCryptoTelemetryData(t *testing.T, data metricdata.ResourceMetrics, operation string, results map[string]int64) {
	t.Helper()
	var calls int64
	var duration uint64
	actual := map[string]int64{}
	check := func(attrs attribute.Set) (string, string) {
		for _, a := range attrs.ToSlice() {
			if !telemetry.AllowedAttribute(string(a.Key), a.Value.AsString()) {
				t.Fatal("unsafe Crypto metric attribute")
			}
		}
		op, _ := attrs.Value("operation")
		result, _ := attrs.Value("result")
		provider, _ := attrs.Value("provider")
		if provider.AsString() != "crypto" {
			t.Fatal("wrong Crypto metric provider")
		}
		return op.AsString(), result.AsString()
	}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == telemetry.OperationInputBytes || m.Name == telemetry.OperationOutputBytes {
				t.Fatal("Crypto recorded private lengths")
			}
			switch values := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, p := range values.DataPoints {
					op, result := check(p.Attributes)
					if op != operation {
						continue
					}
					if m.Name == telemetry.OperationCalls {
						calls += p.Value
					}
					if m.Name == telemetry.OperationResults {
						actual[result] += p.Value
					}
				}
			case metricdata.Histogram[float64]:
				for _, p := range values.DataPoints {
					op, _ := check(p.Attributes)
					if op == operation && m.Name == telemetry.OperationDuration {
						if m.Unit != "s" || p.Sum < 0 {
							t.Fatal("invalid Crypto duration")
						}
						duration += p.Count
					}
				}
			}
		}
	}
	var total int64
	for result, count := range results {
		total += count
		if actual[result] != count {
			t.Fatalf("%s %s count=%d want=%d", operation, result, actual[result], count)
		}
	}
	if len(actual) != len(results) || calls != total || duration != uint64(total) {
		t.Fatalf("%s starts/results/durations do not match", operation)
	}
}

// full_only: false
func TestCryptoTelemetry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		legacy  string
	}{
		{name: "explicit-capability", enabled: true},
		{name: "no-capability"},
		{name: "legacy-env-does-not-enable", legacy: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.legacy != "" {
				t.Setenv("ENKV_TELEMETRY", tc.legacy)
			}
			ctx, reader := cryptoTelemetryReader(t)
			if !tc.enabled {
				ctx = context.Background()
			}
			r, err := New(contract.GCP, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			for _, operation := range []struct {
				kind contract.CryptoKind
				op   string
			}{
				{contract.CryptoCompare, "crypto.compare"}, {contract.CryptoPrepare, "crypto.prepare"},
				{contract.CryptoFreeze, "crypto.freeze"}, {contract.CryptoClaim, "crypto.claim"},
				{contract.CryptoDiscard, "crypto.discard"}, {contract.CryptoAccessReplace, "crypto.access_replace"},
				{contract.CryptoQualifyInitKeys, "crypto.qualify_init_keys"},
				{255, "crypto.exchange"},
			} {
				q := contract.CryptoRequest{Kind: operation.kind, RequestID: consumerID("private-sentinel"), CustodyInstanceID: r.InstanceID(), Body: []byte("private-sentinel")}
				if got := r.Exchange(ctx, q); got.ResultCode != contract.CryptoInvalidInput {
					t.Fatal("instrumentation changed refusal")
				}
				want := map[string]int64{}
				if tc.enabled {
					want["invalid"] = 1
				}
				assertCryptoTelemetry(t, reader, operation.op, want)
			}
			var absent *Runtime
			if _, code := absent.sealInput(ctx, contract.ID{}); code != contract.CryptoInvalidAdmission {
				t.Fatal("nil source admission changed")
			}
			if result := absent.consume(ctx, contract.ID{}); result.code != contract.CryptoInvalidAdmission {
				t.Fatal("nil consumer admission changed")
			}
			want := map[string]int64{}
			if tc.enabled {
				want["admission_refused"] = 1
			}
			data := cryptoTelemetrySnapshot(t, reader)
			assertCryptoTelemetryData(t, data, "crypto.seal_source", want)
			assertCryptoTelemetryData(t, data, "crypto.consume", want)
		})
	}
}
