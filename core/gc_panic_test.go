package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestInstalledGCPanicKeepsIncompleteTelemetryAndJoinsClose(t *testing.T) {
	for _, operation := range []telemetry.Operation{telemetry.OpCoreGCApply, telemetry.OpCoreGCContinue} {
		t.Run(string(operation), func(t *testing.T) {
			state, store, input, plan, encoded := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			if operation == telemetry.OpCoreGCContinue {
				state, _ = gcRuntimeSelectOnly(t, ctx, state, input, plan, encoded)
			}
			phaseCount := len(store.phases)
			var closed atomic.Int32
			input.CloseInstalled = func() { closed.Add(1) }
			reader, err := NewInstalledCapacityReader(input)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("GC mutation factory panic")
			engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
				panic(sentinel)
			}})
			if err != nil {
				t.Fatal(err)
			}
			recorder := telemetry.NewRecorder()
			points := make(chan telemetry.MetricPoint, 512)
			capability := telemetry.NewCapability(points, recorder)
			ctx = telemetry.WithCapability(ctx, capability)
			completed := false
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				if operation == telemetry.OpCoreGCApply {
					engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("panic-apply"), EncodedPlan: encoded})
				} else {
					engine.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("panic-continue"), OperationID: plan.OperationID})
				}
				completed = true
			}()
			if recovered != sentinel || completed {
				t.Fatal("GC panic was replaced or treated as a completed result", recovered, completed)
			}
			if err := engine.Close(); err != nil || closed.Load() != 1 {
				t.Error("panic left installed invocation or reader unjoined", err, closed.Load())
			}
			starts, returns := 0, 0
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512)) {
				if record.Operation == operation {
					if record.Event == telemetry.DiagnosticStart {
						starts++
					}
					if record.Event == telemetry.DiagnosticReturn {
						returns++
					}
				}
			}
			if starts != 1 || returns != 0 {
				t.Error("panicking GC parent emitted normal completion", starts, returns)
			}
			calls, results, durations := 0, 0, 0
			for len(points) != 0 {
				point := <-points
				if point.Operation != operation {
					continue
				}
				switch point.Name {
				case telemetry.OperationCalls:
					calls++
				case telemetry.OperationResults:
					results++
				case telemetry.OperationDuration:
					durations++
				}
			}
			if calls != 1 || results != 0 || durations != 0 || capability.LostMetrics() != 0 {
				t.Error("panic was counted as a completed GC operation", calls, results, durations, capability.LostMetrics())
			}
			if len(store.phases) != phaseCount || len(store.deletes) != 0 {
				t.Fatal("panicking factory reached mutation", store.phases, store.deletes)
			}
		})
	}
}
