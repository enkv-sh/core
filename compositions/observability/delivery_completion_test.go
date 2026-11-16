package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestDefaultConsoleFiltersBeforeCapture(t *testing.T) {
	settings, err := Decode(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	runtime, err := Start(settings, SetupOptions{Console: &output})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(context.Background()); err != nil {
			t.Error("filtered calls changed configured delivery completion", err)
		}
		select {
		case <-runtime.closeDone:
		default:
			t.Error("Close did not join its owned workers")
		}
		if output.Len() != 0 || runtime.LogStatus("console") != (DeliveryStatus{}) {
			t.Error("filtered calls entered configured console delivery", runtime.LogStatus("console"))
		}
	})
	ctx := runtime.Context(t.Context())
	for range 64 {
		telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultSuccess)
	}
	// Successful calls emit only DEBUG starts and INFO returns. Neither is
	// selected by default WARN output, so neither can consume capture capacity
	// or contribute a loss, regardless of the drain worker's schedule.
	if status := runtime.RecorderStatus(); status != (telemetry.RecorderStatus{}) {
		t.Error("filtered calls consumed capture or contributed loss", status)
	}
}

// full_only: false
func TestConfiguredDeliveryFailureCannotReportCompleteClose(t *testing.T) {
	for _, signals := range [][]string{{"logs"}, {"metrics"}, {"traces"}, {"logs", "metrics", "traces"}} {
		for _, fail := range []bool{false, true} {
			name := strings.Join(signals, "+") + "/healthy"
			if fail {
				name = strings.Join(signals, "+") + "/failed"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				if fail {
					if err := os.WriteFile(filepath.Join(root, "delivery"), []byte("private-destination-error-sentinel"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				settings := map[string]any{
					"schema_version": 1,
					"logs":           map[string]any{"level": "off"},
					"exporters":      map[string]any{"selected": map[string]any{"type": "otlp_file", "directory": "delivery"}},
				}
				for _, signal := range signals {
					setting := map[string]any{"exporters": []string{"selected"}}
					if signal == "logs" {
						setting["level"] = "warn"
					}
					if signal == "traces" {
						setting["sample_ratio"] = 1
					}
					settings[signal] = setting
				}
				body, err := json.Marshal(settings)
				if err != nil {
					t.Fatal(err)
				}
				resolved, err := Decode(body, Options{})
				if err != nil {
					t.Fatal(err)
				}
				runtime, err := Start(resolved, SetupOptions{BaseDirectory: root})
				if err != nil {
					t.Fatal(err)
				}
				call := telemetry.Start(runtime.Context(t.Context()), telemetry.ProviderCore, telemetry.OpCoreOpen)
				call.Finish(telemetry.ResultAdmissionRefused)
				closeErr := runtime.Close(context.Background())
				if (closeErr != nil) != fail {
					t.Errorf("configured delivery failure=%t returned Close error %v", fail, closeErr)
				}
				for _, signal := range signals {
					status := runtime.DeliveryStatuses()[signal+".selected"]
					if status.Accepted == 0 || status.Incomplete != fail || (status.Failed != 0) != fail || !fail && status.Accepted != status.Written {
						t.Errorf("configured %s delivery facts differ: %+v", signal, status)
					}
				}
				select {
				case <-runtime.closeDone:
				default:
					t.Fatal("Close did not join its owned workers")
				}
				if closeErr != nil && strings.Contains(closeErr.Error(), "private-destination-error-sentinel") {
					t.Fatal("private destination content entered completion error")
				}
			})
		}
	}
	t.Run("disabled", func(t *testing.T) {
		settings, err := Decode([]byte(`{"schema_version":1,"logs":{"level":"off"}}`), Options{})
		if err != nil {
			t.Fatal(err)
		}
		runtime, err := Start(settings, SetupOptions{Console: &bytes.Buffer{}})
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Close(context.Background()); err != nil || len(runtime.DeliveryStatuses()) != 0 {
			t.Fatal("disabled routes acquired a delivery failure", err)
		}
	})
}
