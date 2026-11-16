package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

const installedReplacementPanicSentinel = "private-installed-replacement-panic-sentinel"

type installedReplacementTelemetryStore struct{ contract.Store }

func (s *installedReplacementTelemetryStore) StoreConfiguration() contract.StoreConfiguration {
	return s.Store.(contract.StoreConfigurationSource).StoreConfiguration()
}
func (s *installedReplacementTelemetryStore) Read(context.Context, string, uint32) contract.ReadResult {
	panic(installedReplacementPanicSentinel)
}

// full_only: false
func TestInstalledReplacementTelemetryRecordsOnlyNormalReturns(t *testing.T) {
	for _, condition := range []string{"success", "refusal", "Store panic", "public resolver panic", "signer factory panic", "custody factory panic", "publisher panic"} {
		t.Run(condition, func(t *testing.T) {
			base, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, 3, 1, ReplacementMaterialAuthority)
			switch condition {
			case "refusal":
				h.installation.ResolvePublicGoal = func(context.Context, ReplacementPublicRequest) (ReplacementPublicGoal, error) {
					return ReplacementPublicGoal{}, errors.New("refused fixture public metadata")
				}
			case "Store panic":
				h.installation.Store = &installedReplacementTelemetryStore{Store: h.installation.Store}
			case "public resolver panic":
				h.installation.ResolvePublicGoal = func(context.Context, ReplacementPublicRequest) (ReplacementPublicGoal, error) {
					panic(installedReplacementPanicSentinel)
				}
			case "signer factory panic":
				h.installation.ConstructSigners = func(context.Context, contract.PublicSigningBinding, *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
					panic(installedReplacementPanicSentinel)
				}
			case "custody factory panic":
				h.installation.AdmitSuccessionCustody = func(context.Context, contract.CryptoAccessReplaceRequest, contract.SuccessionRequestCore, contract.ControlCore, contract.BindingTableRow, contract.SuccessorKEKProbeCore, []contract.CompactRow, time.Time) (*InstalledReplacementCustody, error) {
					panic(installedReplacementPanicSentinel)
				}
			case "publisher panic":
				h.installation.PublishSuccessor = func(context.Context, ReplacementSuccessor) (ReplacementReadback, error) {
					panic(installedReplacementPanicSentinel)
				}
			}
			engine := h.engine(t)
			points := make(chan telemetry.MetricPoint, 2048)
			recorder := telemetry.NewRecorder()
			capability := telemetry.NewCapability(points, recorder)
			ctx := telemetry.WithCapability(base, capability)
			var out PublicReplacementResult
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				out = engine.Replace(ctx, testID("replacement normal-return telemetry"))
			}()
			engine.Close()
			wantReturns := int64(1)
			wantResult := telemetry.ResultObservedCurrent
			switch condition {
			case "success":
				if recovered != nil || out.Result.Outcome != ObservedCurrent || h.delivered != 1 {
					t.Fatal("normal success control failed", out.Result, recovered)
				}
			case "refusal":
				wantResult = telemetry.ResultAdmissionRefused
				if recovered != nil || out.Result.Outcome != AdmissionRefused {
					t.Fatal("normal refusal control failed", out.Result, recovered)
				}
			default:
				wantReturns = 0
				if recovered != installedReplacementPanicSentinel {
					t.Fatal("delegated panic was not propagated", recovered)
				}
			}
			if capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
				t.Fatal("metric evidence lost")
			}
			status := recorder.Status()
			if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 {
				t.Fatal("diagnostic evidence lost")
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512))
			starts, admissions, returns := int64(0), int64(0), int64(0)
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation != telemetry.OpCoreReplaceAuthorityKeys {
					continue
				}
				switch record.Event {
				case telemetry.DiagnosticStart:
					starts++
				case telemetry.DiagnosticCheckpoint:
					if record.Stage == telemetry.DiagnosticAdmission {
						admissions++
					}
				case telemetry.DiagnosticReturn:
					returns++
					if record.Result != wantResult {
						t.Fatal("normal diagnostic result changed", record.Result)
					}
				}
			}
			encoded, err := json.Marshal(records)
			if err != nil || bytes.Contains(encoded, []byte(installedReplacementPanicSentinel)) {
				t.Fatal("private panic text entered diagnostics", err)
			}
			calls, resultPoints, durations := int64(0), int64(0), int64(0)
			for len(points) != 0 {
				point := <-points
				if point.Operation != telemetry.OpCoreReplaceAuthorityKeys {
					continue
				}
				switch point.Name {
				case telemetry.OperationCalls:
					calls += point.IntValue
				case telemetry.OperationResults:
					resultPoints += point.IntValue
					if point.Result != wantResult {
						t.Fatal("normal metric result changed", point.Result)
					}
				case telemetry.OperationDuration:
					durations++
				}
			}
			if starts != 1 || admissions != 1 || calls != 1 || returns != wantReturns || resultPoints != wantReturns || durations != wantReturns {
				t.Fatalf("normal-return evidence differs: starts=%d admission=%d calls=%d returns=%d results=%d durations=%d want=%d", starts, admissions, calls, returns, resultPoints, durations, wantReturns)
			}
		})
	}
}
