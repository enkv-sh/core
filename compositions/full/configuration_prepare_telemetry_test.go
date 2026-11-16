package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestPrepareTelemetryKeepsSafeFactsWhenCollectionIsDisabled(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "invalid-request"}[refused], func(t *testing.T) {
			source := configurationApplyPair(t, "aws", configuration.JSON, nil)
			request := PrepareRequest{Source: source.path, Format: configuration.JSON}
			if refused {
				request.Source = "private-invalid-source-sentinel"
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			disabled, disabledErr := PrepareConfiguration(ctx, request)
			points := make(chan telemetry.MetricPoint, 1024)
			recorder := telemetry.NewRecorder()
			capability := telemetry.NewCapability(points, recorder)
			enabled, enabledErr := PrepareConfiguration(telemetry.WithCapability(ctx, capability), request)
			if refused {
				if !errors.Is(disabledErr, ErrPrepare) || !errors.Is(enabledErr, ErrPrepare) {
					t.Fatal("telemetry changed request refusal")
				}
			} else if disabledErr != nil || enabledErr != nil || PrepareExitCode(disabled, nil) != 0 || PrepareExitCode(enabled, nil) != 0 {
				t.Fatal("artifact-free preparation did not complete")
			}
			disabledFacts, enabledFacts := prepareResultWire(t, disabled), prepareResultWire(t, enabled)
			delete(disabledFacts, "request_id")
			delete(enabledFacts, "request_id")
			if !reflect.DeepEqual(disabledFacts, enabledFacts) || PrepareExitCode(disabled, nil) != PrepareExitCode(enabled, nil) {
				t.Fatal("collection changed immutable operation facts")
			}
			status := recorder.Status()
			if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 || capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
				t.Fatal("prepare telemetry was lost or rejected", status)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 128))
			starts, returns := 0, 0
			var owner uint64
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation != telemetry.OpConfigurationPrepare {
					continue
				}
				switch record.Event {
				case telemetry.DiagnosticStart:
					starts++
					owner = record.Call
				case telemetry.DiagnosticReturn:
					returns++
					want := telemetry.ResultSuccess
					if refused {
						want = telemetry.ResultWriteRefused
					}
					if record.Result != want || record.Call != owner {
						t.Fatal("prepare terminal changed result ownership")
					}
				}
			}
			if starts != 1 || returns != 1 {
				t.Fatal("prepare did not emit one normal terminal", starts, returns)
			}
			calls, results := int64(0), int64(0)
			for len(points) != 0 {
				point := <-points
				if point.Operation != telemetry.OpConfigurationPrepare {
					continue
				}
				if point.Name == telemetry.OperationCalls {
					calls += point.IntValue
				}
				if point.Name == telemetry.OperationResults {
					results += point.IntValue
				}
			}
			if calls != 1 || results != 1 {
				t.Fatal("prepare metrics changed terminal accounting", calls, results)
			}
			body, err := json.Marshal(records)
			if err != nil || bytes.Contains(body, []byte(source.path)) || bytes.Contains(body, []byte("private-invalid-source-sentinel")) {
				t.Fatal("source text entered telemetry", err)
			}
			source.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestPrepareReconstructionWithMissingDependenciesReportsKnownSetup(t *testing.T) {
	projection, _, selected := configurationReconstructionProjection(t, "gcp")
	projection.Close()
	request := prepareRecoveryRequestForTest(configurationReaderSource{archive: selected.archive}, filepath.Join(t.TempDir(), "recovered.json"), configuration.JSON)
	recorder := telemetry.NewRecorder()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder)), time.Minute)
	defer cancel()
	result, err := prepareConfiguration(ctx, request, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
		return core.NewInstalledReconstruction(core.ReconstructionInstallation{Candidate: selected, Normal: selected,
			Construct: func(context.Context, contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
				return selected, core.Result{}
			},
			Verify: func(_ context.Context, pins contract.ReconstructionVerificationPins, _ time.Time) (core.ReconstructionVerifier, error) {
				return &configurationReconstructionVerifier{source: selected, pins: pins}, nil
			},
			CloseInstalled: func() {}})
	})
	if err != nil || PrepareExitCode(result, nil) != 2 || result.facts.Recovery.Status != "complete" || result.facts.Delivery.Outcome != "recorded" || result.facts.Outcome != "incomplete" {
		t.Fatal("known setup changed reconstruction or delivery facts", result, err)
	}
	warnings, terminals := 0, 0
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 128)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Operation != telemetry.OpConfigurationPrepare && record.Operation != telemetry.OpConfigurationPrepareDependencies || record.Event != telemetry.DiagnosticReturn {
			continue
		}
		terminals++
		if string(record.Result) != "setup_incomplete" || string(record.Reason) != "setup_required" || record.SeverityNumber >= telemetry.SeverityError {
			t.Fatal("completed reconstruction reported uncertain failure", record)
		}
		if record.SeverityNumber == telemetry.SeverityWarn {
			warnings++
		}
	}
	if terminals != 2 || warnings != 0 {
		t.Fatal("known setup duplicated the command warning", terminals, warnings)
	}
}

// full_only: false
func TestPrepareKnownSetupExcludesRecoveryDeliveryAndEvidenceFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*prepareResultFacts)
		want   bool
	}{
		{"known-missing", func(*prepareResultFacts) {}, true},
		{"administration-not-ready", func(f *prepareResultFacts) { f.Dependencies.MinimumAdministrativeReady = false }, false},
		{"known-incompatible", func(f *prepareResultFacts) {
			f.Dependencies.Requirements[0].Status = "incompatible"
			f.Dependencies.Requirements[0].Reason = "unsupported-protocol"
			f.Dependencies.Requirements[0].Plugin = dependencyPluginName("output-plugin")
			f.Diagnostics[0].Reason = "dependency-invalid"
		}, true},
		{"dependency-unavailable", func(f *prepareResultFacts) {
			f.Dependencies.Requirements[0].Status = "unavailable"
			f.Dependencies.Requirements[0].Reason = "unavailable"
			f.Dependencies.Requirements[0].Plugin = dependencyPluginName("output-plugin")
			f.Diagnostics[0].Reason = "dependency-unavailable"
		}, false},
		{"recovery-failed", func(f *prepareResultFacts) {
			f.Recovery = prepareRecoveryFacts{Status: "failed"}
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Diagnostics = []prepareDiagnostic{{Reason: "state-invalid", Subject: "recovery"}}
		}, false},
		{"delivery-failed", func(f *prepareResultFacts) {
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Diagnostics = []prepareDiagnostic{{Reason: "delivery-failed", Subject: "delivery"}}
		}, false},
		{"cleanup-failed", func(f *prepareResultFacts) {
			f.Delivery.CleanupFailed = true
			f.Diagnostics = append(f.Diagnostics, prepareDiagnostic{Reason: "cleanup-failed", Subject: "delivery"})
		}, false},
		{"source-changed", func(f *prepareResultFacts) {
			f.Dependencies.MinimumAdministrativeReady = false
			f.Diagnostics = append(f.Diagnostics, prepareDiagnostic{Reason: "source-changed", Subject: "source"})
		}, false},
		{"settings-invalid", func(f *prepareResultFacts) {
			f.Dependencies.Assessment = "incomplete"
			path := "/private/plugins.json"
			f.Dependencies.SettingsFailure = &plugininstallation.SettingsFailure{Stage: "settings", Reason: "invalid-json", Path: &path, Object: "plugins.json", Action: "correct-settings"}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := prepareResultFactsForTest()
			facts.Outcome = "incomplete"
			facts.Dependencies.AllDeclaredReady = false
			facts.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "output", Subjects: []uint16{0}, Contract: "fixture/output/config/v1", ProtocolVersion: 6, Status: "missing", Reason: "selection-required"}}
			facts.Diagnostics = []prepareDiagnostic{{Reason: "dependency-missing", Subject: "dependencies"}}
			tc.change(&facts)
			result := &PrepareResult{facts: facts}
			if !result.valid() {
				t.Fatal("test did not retain valid result facts", facts)
			}
			if result.SetupRequired() != tc.want {
				t.Fatal("known setup consumed another outcome", tc.name, result.facts)
			}
		})
	}
}
