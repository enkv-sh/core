package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestAbandonmentPlanTelemetryFinishesOnlyAfterNormalReturn(t *testing.T) {
	parent := os.Getenv("ENKV_TEST_PROTECTED_FIXTURES")
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		t.Fatal("plan telemetry test requires the runner protected directory")
	}
	dir, err := os.MkdirTemp(parent, "plan-telemetry-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error("plan telemetry cleanup failed", err)
		}
	})
	for _, mode := range []string{"success", "refusal", "panic"} {
		t.Run(mode, func(t *testing.T) {
			body := []byte("private-plan-body-sentinel")
			path := filepath.Join(dir, mode+"-private-path-sentinel.json")
			recorder := telemetry.NewRecorder()
			metrics := make(chan telemetry.MetricPoint, 16)
			capability := telemetry.NewCapability(metrics, recorder)
			ctx := telemetry.WithCapability(t.Context(), capability)
			ops := nativeAbandonPlanIO()
			failure := errors.New("private-readback-error-sentinel")
			panicValue := &struct{ message string }{"private-panic-value-sentinel"}
			readbacks := 0
			nativeReadback := ops.readback
			ops.readback = func(ctx context.Context, path string, limit int64) ([]byte, error) {
				readbacks++
				switch mode {
				case "refusal":
					return nil, failure
				case "panic":
					panic(panicValue)
				}
				return nativeReadback(ctx, path, limit)
			}
			var delivery AbandonmentDelivery
			var callErr error
			var recovered any
			returned := false
			func() {
				// Only the test boundary recovers. The operation must propagate
				// the exact panic and must not convert it to a Product refusal.
				defer func() { recovered = recover() }()
				delivery, callErr = writeAbandonPlan(ctx, path, body, ops)
				returned = true
			}()
			if readbacks != 1 {
				t.Fatal("control did not reach the actual readback callback")
			}
			switch mode {
			case "panic":
				if returned || recovered != panicValue {
					t.Fatal("IO panic was swallowed or changed")
				}
			case "success":
				if !returned || recovered != nil || callErr != nil || !delivery.PlanCreated || !delivery.PlanSynced || !delivery.PlanReadback {
					t.Fatal("normal successful control lost its delivery facts")
				}
			case "refusal":
				if !returned || recovered != nil || !errors.Is(callErr, failure) || !errors.Is(callErr, ErrAbandonmentPlan) || !delivery.PlanCreated || !delivery.PlanSynced || delivery.PlanReadback {
					t.Fatal("normal refusal control lost its exact cause or delivery facts")
				}
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 4))
			wantRecords := 3
			wantResult := telemetry.ResultSuccess
			if mode == "refusal" {
				wantResult = telemetry.ResultFailure
			}
			if mode == "panic" {
				wantRecords = 2
			}
			if len(records) != wantRecords {
				t.Errorf("panic emitted a normal return or normal control lost its return: mode=%s records=%d", mode, len(records))
			}
			for i, record := range records {
				if err := record.Validate(); err != nil || record.Provider != telemetry.ProviderApplication || record.Operation != telemetry.OpAdministrativePlanWrite {
					t.Fatal("plan telemetry has an open owner or diagnostic shape")
				}
				if i == 0 && record.Event != telemetry.DiagnosticStart || i == 1 && (record.Event != telemetry.DiagnosticCheckpoint || record.Stage != telemetry.DiagnosticCandidatePersistence) || i == 2 && (record.Event != telemetry.DiagnosticReturn || record.Result != wantResult) {
					t.Fatal("plan telemetry does not describe the actual return boundary")
				}
			}
			points := map[string]telemetry.MetricPoint{}
			for len(metrics) != 0 {
				point := <-metrics
				if point.Provider != telemetry.ProviderApplication || point.Operation != telemetry.OpAdministrativePlanWrite {
					t.Fatal("plan metric has another owner")
				}
				if _, duplicate := points[point.Name]; duplicate {
					t.Fatal("plan emitted a repeated operation metric")
				}
				points[point.Name] = point
				for _, text := range []string{point.Name, string(point.Provider), string(point.Operation), string(point.Result), point.Status} {
					if strings.Contains(text, "sentinel") {
						t.Fatal("plan metric recorded private panic, path, body or error text")
					}
				}
			}
			if capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 || points[telemetry.OperationCalls].IntValue != 1 {
				t.Fatal("metric control was disabled or lost its start")
			}
			if mode == "panic" {
				if len(points) != 1 {
					t.Error("panic claimed normal completion, duration or byte metrics")
				}
			} else {
				wantPoints := 4
				if mode == "success" {
					wantPoints = 5
				}
				if len(points) != wantPoints || points[telemetry.OperationResults].IntValue != 1 || points[telemetry.OperationResults].Result != wantResult || points[telemetry.OperationDuration].Result != wantResult || points[telemetry.OperationInputBytes].IntValue != int64(len(body)) {
					t.Fatal("normal control lost exact result or numeric input metrics")
				}
				output, present := points[telemetry.OperationOutputBytes]
				if present != (mode == "success") || present && (output.Result != telemetry.ResultSuccess || output.IntValue != int64(len(body))) {
					t.Fatal("plan output metric does not match complete normal delivery")
				}
			}
			encoded, err := json.Marshal(records)
			if err != nil || bytes.Contains(encoded, []byte("sentinel")) {
				t.Fatal("diagnostics recorded private panic, path, body or raw error")
			}
		})
	}
}
