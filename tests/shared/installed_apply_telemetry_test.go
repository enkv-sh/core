package core

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

const installedApplyPanicSentinel = "private-installed-apply-panic-sentinel"

type installedApplyTelemetryStore struct {
	contract.Store
	panicRead bool
	reads     int
}

func (s *installedApplyTelemetryStore) StoreConfiguration() contract.StoreConfiguration {
	return s.Store.(contract.StoreConfigurationSource).StoreConfiguration()
}

func (s *installedApplyTelemetryStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.reads++
	if s.panicRead {
		panic(installedApplyPanicSentinel)
	}
	return s.Store.Read(ctx, key, limit)
}

// full_only: false
func TestInstalledApplyTelemetryRecordsOnlyNormalReturns(t *testing.T) {
	for _, condition := range []string{"success", "refusal", "panic"} {
		t.Run(condition, func(t *testing.T) {
			base, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, base, contract.AWS, false)
			input := []ApplyEntryInput{suppliedSecret(t, f.env, "alpha", "telemetry source", custody.StandardValue, f.selected.admission.recipient)}
			if condition == "refusal" {
				input[0].Recipients = nil
			}
			store := &installedApplyTelemetryStore{Store: f.env.Store, panicRead: condition == "panic"}
			f.env.Store = store
			var stages []contract.CryptoKind
			engine := f.engine(t, f.selected, input, func(kind contract.CryptoKind) { stages = append(stages, kind) })
			points := make(chan telemetry.MetricPoint, 2048)
			recorder := telemetry.NewRecorder()
			capability := telemetry.NewCapability(points, recorder)
			ctx := telemetry.WithCapability(base, capability)
			var result PublicApplyResult
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				result = engine.Apply(ctx, fixtureID(f.env.Domain, "telemetry apply request"), input)
			}()
			engine.Close()
			if store.reads == 0 {
				t.Fatal("installed apply did not reach its delegated Store")
			}
			wantResult := telemetry.ResultObservedCurrent
			wantReason := telemetry.DiagnosticReasonNone
			wantReturns := int64(1)
			switch condition {
			case "success":
				if recovered != nil || result.Result.Outcome != ObservedCurrent || len(result.Receipt) == 0 || !slices.Equal(stages, []contract.CryptoKind{contract.CryptoCompare, contract.CryptoPrepare, contract.CryptoFreeze, contract.CryptoClaim}) {
					t.Fatal("success control did not complete real private custody", result.Result, stages)
				}
			case "refusal":
				wantResult = telemetry.ResultAdmissionRefused
				wantReason = telemetry.DiagnosticReasonInvalidIntent
				if recovered != nil || result.Result.Outcome != AdmissionRefused || result.Result.Reason != InvalidIntent || len(stages) != 0 {
					t.Fatal("refusal control changed admission meaning", result.Result, stages)
				}
			case "panic":
				wantReturns = 0
				if recovered != installedApplyPanicSentinel || store.reads != 1 || len(stages) != 0 {
					t.Fatal("delegated panic did not propagate exactly once before custody")
				}
			}
			if capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
				t.Fatal("telemetry capture lost metric evidence")
			}
			status := recorder.Status()
			if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 {
				t.Fatal("telemetry capture lost diagnostic evidence")
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512))
			starts, admissions, returns := int64(0), int64(0), int64(0)
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation != telemetry.OpCoreApply {
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
					if condition != "panic" && (record.Result != wantResult || record.Reason != wantReason) {
						t.Fatal("normal return telemetry changed result or reason")
					}
				}
			}
			encoded, err := json.Marshal(records)
			if err != nil || bytes.Contains(encoded, []byte(installedApplyPanicSentinel)) || bytes.Contains(encoded, []byte("enkv first secret test value")) {
				t.Fatal("private panic or plaintext entered telemetry")
			}
			calls, resultPoints, durations := int64(0), int64(0), int64(0)
			for len(points) != 0 {
				point := <-points
				if point.Operation != telemetry.OpCoreApply {
					continue
				}
				switch point.Name {
				case telemetry.OperationCalls:
					calls += point.IntValue
				case telemetry.OperationResults:
					resultPoints += point.IntValue
					if condition != "panic" && point.Result != wantResult {
						t.Fatal("normal metric changed result")
					}
				case telemetry.OperationDuration:
					durations++
				}
			}
			if starts != 1 || admissions != 1 || calls != 1 || returns != wantReturns || resultPoints != wantReturns || durations != wantReturns {
				t.Fatalf("normal-return evidence differs: starts=%d admission=%d calls=%d returns=%d results=%d durations=%d, want terminal=%d", starts, admissions, calls, returns, resultPoints, durations, wantReturns)
			}
		})
	}
}
