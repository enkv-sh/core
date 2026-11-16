package core

import (
	"context"
	"encoding/json"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestReaderOperationTelemetryKeepsSafeRefusalWithCollectionOff(t *testing.T) {
	for _, operation := range []string{contract.ReaderCompareOperation, contract.ReaderManifestOperation, contract.ReaderRecipientsOperation} {
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
		var engine *ReaderEngine
		invoke := func(ctx context.Context) contract.ReaderStateResult {
			if operation == contract.ReaderRecipientsOperation {
				return engine.ReadRecipientRegistry(ctx, contract.ID{}).StateResult
			}
			if operation == contract.ReaderManifestOperation {
				return engine.Manifest(ctx, contract.ID{}, contract.ManifestRequest{}).StateResult
			}
			return engine.Compare(ctx, contract.ID{}, contract.PublicConfiguration{}).StateResult
		}
		if invoke(ctx) != contract.ReaderRefused {
			t.Fatal("invalid request accepted")
		}
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16))
		if len(records) < 3 || records[0].Event != telemetry.DiagnosticStart || records[len(records)-1].Event != telemetry.DiagnosticReturn {
			t.Fatal("Reader return has no complete telemetry", records)
		}
		for _, record := range records {
			if record.Validate() != nil {
				t.Fatal("invalid Reader telemetry", record)
			}
			body, err := json.Marshal(record)
			if err != nil || strings.Contains(string(body), "secret-sentinel") || record.ErrorDetail != "" {
				t.Fatal("unsafe Reader telemetry")
			}
		}
		if invoke(context.Background()) != contract.ReaderRefused {
			t.Fatal("disabled collection changed refusal")
		}
		if len(recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16))) != 0 {
			t.Fatal("disabled collection emitted records")
		}
	}
}

// full_only: false
func TestReaderTelemetryExcludesActualInputAndProfileErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	e, _, _ := readerEngineFixture(t, env, f.session)
	input := comparisonCurrentInput(t, env, f.session)
	input.Entries.Value[0].PlainValue.Value = []byte("secret-sentinel")
	recorder := telemetry.NewRecorder()
	observed := telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
	got := e.Compare(observed, contract.Hash([]byte("safe comparison telemetry")), input)
	if got.Verdict != contract.ComparisonMismatch || got.StateResult != contract.ReaderSuccess {
		t.Fatal("supplied source changed comparison contract", got)
	}
	assertReaderTelemetry(t, recorder, telemetry.OpCoreReaderCompare, telemetry.ResultSuccess, "")
	registry := e.ReadRecipientRegistry(observed, contract.Hash([]byte("safe registry telemetry")))
	if registry.StateResult != contract.ReaderSuccess || registry.Registry == nil {
		t.Fatal("registry telemetry changed authenticated read", registry)
	}
	assertReaderTelemetry(t, recorder, telemetry.OpCoreReaderRecipients, telemetry.ResultSuccess, "")
	canceled, stop := context.WithCancel(observed)
	stop()
	got = e.Compare(canceled, contract.Hash([]byte("canceled telemetry")), input)
	if got.StateResult != contract.ReaderRefused {
		t.Fatal("cancelled call accepted")
	}
	assertReaderTelemetry(t, recorder, telemetry.OpCoreReaderCompare, telemetry.ResultCancelled, contract.ReasonCancelled)
	registry = e.ReadRecipientRegistry(canceled, contract.Hash([]byte("cancelled registry telemetry")))
	if registry.StateResult != contract.ReaderRefused || registry.Registry != nil {
		t.Fatal("cancelled registry call accepted")
	}
	assertReaderTelemetry(t, recorder, telemetry.OpCoreReaderRecipients, telemetry.ResultCancelled, contract.ReasonCancelled)

	_, _, selected, manifestEnv, target := manifestFixture(t, true)
	manifest, _, _ := readerEngineFixture(t, manifestEnv, selected)
	rawErrors := 0
	manifest.prepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifestsdk.Renderer, manifestsdk.Failure) {
		rawErrors++
		return nil, manifestsdk.Failure("raw-error-sentinel secret-sentinel")
	}
	result := manifest.Manifest(observed, contract.Hash([]byte("profile error telemetry")), hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"secret"}}))
	if rawErrors == 0 || result.FailureReason != contract.ReasonInvalidInput || result.Artifact != nil || result.Payload != nil {
		t.Fatal("raw profile refusal changed artifact contract", result)
	}
	assertReaderTelemetry(t, recorder, telemetry.OpCoreReaderManifest, telemetry.ResultAdmissionRefused, contract.ReasonInvalidInput)
}

func assertReaderTelemetry(t *testing.T, recorder *telemetry.Recorder, operation telemetry.Operation, result telemetry.Result, reason contract.DiagnosticReason) {
	t.Helper()
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 256))
	starts, returns := 0, 0
	for _, record := range records {
		body, err := json.Marshal(record)
		if err != nil || record.Validate() != nil || strings.Contains(string(body), "secret-sentinel") || strings.Contains(string(body), "raw-error-sentinel") || record.ErrorDetail != "" {
			t.Fatal("unsafe operation record")
		}
		if record.Operation != operation {
			continue
		}
		if record.Event == telemetry.DiagnosticStart {
			starts++
		}
		if record.Event == telemetry.DiagnosticReturn {
			returns++
			if record.Result != result || record.Reason != telemetry.DiagnosticReason(reason) {
				t.Fatal("wrong bounded result", record)
			}
		}
		if record.Stage == telemetry.DiagnosticProviderCall || record.Stage == telemetry.DiagnosticPrivateCustody || record.Stage == telemetry.DiagnosticCandidatePersistence || record.Stage == telemetry.DiagnosticCommitObservation {
			t.Fatal("Reader reported effect stage")
		}
	}
	if starts != 1 || returns != 1 || recorder.Status().Rejected != 0 {
		t.Fatal("Reader signal has no exact start/return", starts, returns, recorder.Status())
	}
}

// full_only: false
func TestReaderTelemetryUsesExistingLocalMetricsSetup(t *testing.T) {
	ctx, runtime, _ := coreTelemetryReader(t)
	var engine *ReaderEngine
	engine.Compare(ctx, contract.ID{}, contract.PublicConfiguration{})
	engine.ReadRecipientRegistry(ctx, contract.ID{})
	data := coreTelemetrySnapshot(t, runtime)
	if coreMetricSum(data, telemetry.OperationCalls, string(telemetry.OpCoreReaderCompare), "") != 1 || coreMetricSum(data, telemetry.OperationResults, string(telemetry.OpCoreReaderCompare), string(telemetry.ResultAdmissionRefused)) != 1 {
		t.Fatal("Reader metrics lost call/return")
	}
	if coreMetricSum(data, telemetry.OperationCalls, string(telemetry.OpCoreReaderRecipients), "") != 1 || coreMetricSum(data, telemetry.OperationResults, string(telemetry.OpCoreReaderRecipients), string(telemetry.ResultAdmissionRefused)) != 1 {
		t.Fatal("registry metrics lost call/return")
	}
}
