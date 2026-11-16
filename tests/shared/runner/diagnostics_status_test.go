package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/compositions/observability"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestRunDiagnosticsStatusFollowsEffectiveLogConfiguration(t *testing.T) {
	for _, entrypoint := range []string{"direct", "workflow"} {
		t.Run(entrypoint, func(t *testing.T) {
			for _, test := range []struct {
				name, configuration         string
				environmentLevel, flagLevel string
				stepLevel                   string
				level                       observability.Severity
				enabled, console            bool
				logExporters, signals       int
			}{
				{name: "default_console", level: observability.Warn, enabled: true, console: true},
				{name: "command_off_default_console", flagLevel: "off", level: observability.Off, console: true},
				{name: "environment_off_default_console", environmentLevel: "off", level: observability.Off, console: true},
				{name: "configured_off_default_console", configuration: `{"schema_version":1,"logs":{"level":"off"}}`, level: observability.Off, console: true},
				{name: "configured_off_keeps_metrics_and_traces", configuration: `{"schema_version":1,"logs":{"level":"off"},"metrics":{"exporters":["capture"]},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, level: observability.Off, console: true, signals: 1},
				{name: "configured_off_explicit_console_and_file", configuration: `{"schema_version":1,"logs":{"level":"off","exporters":["console","capture"]},"metrics":{"exporters":["capture"]},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, level: observability.Off, console: true, logExporters: 1, signals: 1},
				{name: "command_off_explicit_file", configuration: `{"schema_version":1,"logs":{"level":"warn","exporters":["capture"]},"metrics":{"exporters":["capture"]},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, flagLevel: "off", level: observability.Off, logExporters: 1, signals: 1},
				{name: "no_log_routes", configuration: `{"schema_version":1,"logs":{"exporters":[]},"metrics":{"exporters":["capture"]},"traces":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, level: observability.Warn, signals: 1},
				{name: "explicit_file_enabled", configuration: `{"schema_version":1,"logs":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`, level: observability.Warn, enabled: true, logExporters: 1},
				{name: "command_warn_over_environment_off", environmentLevel: "off", flagLevel: "warn", level: observability.Warn, enabled: true, console: true},
				{name: "environment_warn_over_configured_off", configuration: `{"schema_version":1,"logs":{"level":"off"}}`, environmentLevel: "warn", level: observability.Warn, enabled: true, console: true},
				{name: "workflow_step_off", stepLevel: "off", level: observability.Off, console: true},
			} {
				if entrypoint == "direct" && test.stepLevel != "" {
					continue
				}
				t.Run(test.name, func(t *testing.T) {
					t.Setenv("ENKV_LOG_LEVEL", test.environmentLevel)
					t.Setenv("OTEL_SERVICE_NAME", "")
					t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
					root, suite, environment := savedSelectionFixture(t)
					configuration := ""
					if test.configuration != "" {
						configuration = filepath.Join(root, "telemetry.json")
						if err := os.WriteFile(configuration, []byte(test.configuration), 0600); err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"run"}
					if test.flagLevel != "" {
						args = append(args, "--log-level", test.flagLevel)
					}
					var request runRequest
					if entrypoint == "direct" {
						args = append(args, "--suite", suite, "--environment", environment)
						if configuration != "" {
							args = append(args, "--telemetry-config", configuration)
						}
						var err error
						request, err = parseRunRequest(args)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						path := filepath.Join(root, "workflow.json")
						saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "diagnostics", Steps: []workflowStep{{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: environment, TelemetryConfig: configuration, LogLevel: test.stepLevel}}})
						selected, err := workflowArguments(append(args, "--workflow", path))
						if err != nil {
							t.Fatal(err)
						}
						plan, err := resolveWorkflow(context.Background(), root, selected)
						if err != nil || len(plan.Steps) != 1 || !plan.Steps[0].Selected || plan.Steps[0].Run == nil {
							t.Fatalf("workflow run unavailable: %+v, %v", plan, err)
						}
						request = plan.Steps[0].request
					}
					settings := request.telemetrySettings
					if settings == nil || settings.LogLevel != test.level || settings.Console != test.console || len(settings.LogExporters) != test.logExporters || len(settings.MetricExporters) != test.signals || len(settings.TraceExporters) != test.signals {
						t.Fatalf("resolved log controls or signal routes differ: %+v", settings)
					}
					state, err := newRunState(root, request, records.Source{}, "test")
					if err != nil {
						t.Fatal(err)
					}
					initial := "disabled"
					final := "disabled"
					if test.enabled {
						initial, final = "incomplete", "complete"
					}
					if state.record.Diagnostics.Enabled != test.enabled || state.record.Diagnostics.Status != initial {
						t.Fatalf("initial diagnostics = %+v, want enabled=%t, status=%s", state.record.Diagnostics, test.enabled, initial)
					}
					worker := records.InspectLogs(records.Invocation{TelemetrySettings: state.telemetrySettings}, records.Diagnostics{Enabled: true, Status: "complete"})
					want := records.Diagnostics{Enabled: test.enabled, Status: final}
					if worker != want {
						t.Fatalf("worker diagnostics = %+v, want %+v", worker, want)
					}
					state.diagnostics = []records.Diagnostics{worker}
					if err := state.save(); err != nil {
						t.Fatal(err)
					}
					saved := state.record
					if saved.Diagnostics != want || saved.Telemetry.Enabled != (test.signals != 0) || !reflect.DeepEqual(state.telemetrySettings, settings) {
						t.Fatalf("saved diagnostics or retained signal configuration differ: diagnostics=%+v, telemetry=%+v, settings=%+v", saved.Diagnostics, saved.Telemetry, state.telemetrySettings)
					}
				})
			}
		})
	}
}
