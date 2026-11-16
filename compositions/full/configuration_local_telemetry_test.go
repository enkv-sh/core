package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/telemetry"
)

// full_only: false
func TestLocalConfigurationTelemetryReturnsOneSafeOwner(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(map[bool]string{false: "edited", true: "refused"}[refused], func(t *testing.T) {
			source := configurationSetPair(t, "aws", configuration.JSON, nil)
			configurationSetWritable(t, source)
			points := make(chan telemetry.MetricPoint, 2048)
			recorder := telemetry.NewRecorder()
			capability := telemetry.NewCapability(points, recorder)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			name := "next"
			want := telemetry.ResultSuccess
			if refused {
				name, want = "invalid-private-name-sentinel/", telemetry.ResultWriteRefused
			}
			result, err := RenameConfigurationDomain(telemetry.WithCapability(ctx, capability), source.path, configuration.JSON, name)
			if (err != nil) != refused || LocalEditExitCode(result, err) != map[bool]int{false: 0, true: 2}[refused] {
				t.Fatal("unexpected local edit outcome", err)
			}
			status := recorder.Status()
			if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 || capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
				t.Fatal("local edit telemetry was lost")
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 256))
			starts, returns := 0, 0
			var owner uint64
			ownerReturns := 0
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation != telemetry.OpConfigurationWrite {
					continue
				}
				if record.Event == telemetry.DiagnosticStart {
					starts++
					if record.ParentCall == 0 {
						if owner != 0 {
							t.Fatal("local edit acquired another return owner")
						}
						owner = record.Call
					}
				}
				if record.Event == telemetry.DiagnosticReturn {
					returns++
					if record.Call == owner {
						ownerReturns++
						if record.Result != want {
							t.Fatal("local edit owner changed bounded outcome")
						}
					}
				}
			}
			if starts != returns || starts == 0 || owner == 0 || ownerReturns != 1 {
				t.Fatal("local edit telemetry did not join each started call")
			}
			calls, results, durations := int64(0), int64(0), 0
			for len(points) != 0 {
				point := <-points
				if point.Operation != telemetry.OpConfigurationWrite {
					continue
				}
				switch point.Name {
				case telemetry.OperationCalls:
					calls += point.IntValue
				case telemetry.OperationResults:
					results += point.IntValue
				case telemetry.OperationDuration:
					durations++
				}
			}
			if calls != int64(starts) || results != int64(returns) || durations != returns {
				t.Fatal("local edit metrics lost call, outcome or duration")
			}
			body, err := json.Marshal(records)
			if err != nil || bytes.Contains(body, []byte("invalid-private-name-sentinel")) || bytes.Contains(body, []byte(source.path)) {
				t.Fatal("raw input or path entered telemetry", err)
			}
		})
	}
}
