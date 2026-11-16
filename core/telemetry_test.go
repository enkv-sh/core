package core

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func coreTelemetryReader(t *testing.T) (context.Context, *observability.Runtime, func()) {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"exporters":[]},"metrics":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
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
	shutdown := func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(closeContext); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(shutdown)
	return runtime.Context(context.Background()), runtime, shutdown
}

// full_only: false
func TestGeneratedCoreBoundariesReportOneAdmissionRefusal(t *testing.T) {
	var session *StateSession
	checks := []struct {
		operation telemetry.Operation
		invoke    func(context.Context) Result
	}{
		{telemetry.OpCoreGeneratedPreparePlan, func(ctx context.Context) Result { _, result := session.PrepareGeneratedPlan(ctx, nil); return result }},
		{telemetry.OpCoreGeneratedPrepareProducer, func(ctx context.Context) Result {
			_, result := session.PrepareGeneratedProducer(ctx, nil)
			return result
		}},
		{telemetry.OpCoreGeneratedPrepareRecord, func(ctx context.Context) Result { _, result := session.PrepareGeneratedRecord(ctx, nil); return result }},
		{telemetry.OpCoreGeneratedPrepareFinal, func(ctx context.Context) Result { _, result := session.PrepareGeneratedFinal(ctx, nil); return result }},
		{telemetry.OpCoreGeneratedPrepareCreateResidue, func(ctx context.Context) Result {
			_, result := session.PrepareGeneratedCreateResidue(ctx, nil, nil)
			return result
		}},
		{telemetry.OpCoreGeneratedPrepareLifecycle, func(ctx context.Context) Result {
			_, result := session.PrepareGeneratedLifecycle(ctx, nil, nil)
			return result
		}},
		{telemetry.OpCoreGeneratedPrepareSuccessorReservation, func(ctx context.Context) Result {
			_, result := session.PrepareGeneratedSuccessorReservation(ctx, nil)
			return result
		}},
		{telemetry.OpCoreGeneratedClaimPreparation, func(ctx context.Context) Result {
			_, result := session.ClaimGeneratedPreparation(ctx, nil, nil)
			return result
		}},
		{telemetry.OpCoreGeneratedClaimDetachedProducer, func(ctx context.Context) Result {
			_, result := session.ClaimGeneratedOriginalProducer(ctx, nil)
			return result
		}},
		{telemetry.OpCoreGeneratedClaimOriginalSet, func(ctx context.Context) Result {
			_, result := session.ClaimGeneratedOriginalSet(ctx, nil, nil)
			return result
		}},
		{telemetry.OpCoreGeneratedReadResult, func(ctx context.Context) Result {
			_, _, result := session.ReadGeneratedResult(ctx, contract.ID{})
			return result
		}},
	}
	for _, check := range checks {
		t.Run(string(check.operation), func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			if result := check.invoke(ctx); result.Outcome != AdmissionRefused || result.Reason != AdmissionInvalid {
				t.Fatalf("refusal = %+v", result)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
			if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint || records[2].Event != telemetry.DiagnosticReturn ||
				records[2].Operation != check.operation || records[2].Result != telemetry.ResultAdmissionRefused || records[2].Reason != telemetry.DiagnosticReasonAdmissionInvalid {
				t.Fatalf("generated boundary records = %+v", records)
			}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatalf("invalid record: %v", err)
				}
			}
		})
	}
}

// full_only: false
func TestCoreReasonCodesRemainDistinct(t *testing.T) {
	reasons := []Reason{AdmissionInvalid, ConstructionMismatch, InvalidFormat, InvalidProof, InvalidReference,
		InvalidRelation, MissingSelectedObject, ReadUnavailable, ImmutableConflict, CapacityExceeded,
		InvalidIntent, SigningUnavailable, WriteUncertain, StalePrecondition, DifferentSelection,
		AlreadyUsed, CustodyUnavailable}
	seen := make(map[telemetry.DiagnosticReason]bool, len(reasons))
	for _, reason := range reasons {
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
		finishCore(telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen), Result{Outcome: AdmissionRefused, Reason: reason})
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 2))
		if len(records) != 2 || records[1].Reason == telemetry.DiagnosticReasonNone || seen[records[1].Reason] || records[1].Validate() != nil {
			t.Fatalf("reason %d has missing, duplicate or invalid diagnostic: %+v", reason, records)
		}
		seen[records[1].Reason] = true
	}
}

// full_only: false
func TestLocalOperatorTelemetryRefusalAndDisabled(t *testing.T) {
	checks := []struct {
		operation telemetry.Operation
		invoke    func(context.Context) Result
	}{
		{telemetry.OpCoreOpen, func(ctx context.Context) Result {
			_, result := Open(ctx, OpenContext{}, nil)
			return result
		}},
		{telemetry.OpCoreInspectSelectedWork, func(ctx context.Context) Result {
			var session *AuthoritySession
			_, result := session.Inspect(ctx)
			return result
		}},
		{telemetry.OpCorePrepareEndSelectedWork, func(ctx context.Context) Result {
			var session *AuthoritySession
			_, result := session.Preview(ctx, contract.ID{1})
			return result
		}},
		{telemetry.OpCoreSelectEndSelectedWork, func(ctx context.Context) Result {
			var session *AuthoritySession
			return session.End(ctx, EndWorkPreview{}).Result
		}},
		{telemetry.OpCoreMutationReceipt, func(ctx context.Context) Result {
			var session *AuthoritySession
			_, result := session.Recheck(ctx, contract.ID{1})
			return result
		}},
	}
	for _, check := range checks {
		t.Run(string(check.operation), func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			if result := check.invoke(ctx); result != refused(AdmissionInvalid) {
				t.Fatal("wrong refusal", result)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
			if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart ||
				records[1].Event != telemetry.DiagnosticCheckpoint || records[2].Event != telemetry.DiagnosticReturn ||
				records[2].Operation != check.operation || records[2].Result != telemetry.ResultAdmissionRefused ||
				records[2].Reason != telemetry.DiagnosticReasonAdmissionInvalid {
				t.Fatal("operator refusal diagnostic", records)
			}
			for _, record := range records {
				if record.Validate() != nil || record.Path != "" || record.ErrorDetail != "" {
					t.Fatal("invalid or unsafe operator diagnostic", record)
				}
			}
			if result := check.invoke(context.Background()); result != refused(AdmissionInvalid) {
				t.Fatal("disabled telemetry changed outcome", result)
			}
			if extra := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3)); len(extra) != 0 {
				t.Fatal("disabled operator emitted diagnostics", extra)
			}
		})
	}
}

// full_only: false
func TestGeneratedReadRetainsAttemptIdentityWithoutKeyMaterial(t *testing.T) {
	var session *StateSession
	attempt := contract.ID{1, 2, 3}
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	_, _, result := session.ReadGeneratedResult(ctx, attempt)
	if result.Outcome != AdmissionRefused {
		t.Fatal(result)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
	if len(records) != 3 || records[0].AttemptID != hex.EncodeToString(attempt[:]) || records[2].AttemptID != records[0].AttemptID || records[2].KeyID != "" || records[2].Validate() != nil {
		t.Fatalf("generated read identity = %+v", records)
	}
}

func coreTelemetrySnapshot(t *testing.T, runtime *observability.Runtime) metricdata.ResourceMetrics {
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

func coreMetricSum(data metricdata.ResourceMetrics, name, operation, result string) int64 {
	var total int64
	for _, scope := range data.ScopeMetrics {
		for _, measurement := range scope.Metrics {
			if measurement.Name != name {
				continue
			}
			sum, ok := measurement.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, point := range sum.DataPoints {
				op, _ := point.Attributes.Value("operation")
				res, _ := point.Attributes.Value("result")
				if op.AsString() == operation && (result == "" || res.AsString() == result) {
					total += point.Value
				}
			}
		}
	}
	return total
}

// full_only: false
func TestCoreTelemetryRefusedAndDisabled(t *testing.T) {
	ctx, reader, _ := coreTelemetryReader(t)
	var session *StateSession
	want := Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}
	if comparison, result := session.Compare(ctx, nil, nil); comparison != nil || result != want {
		t.Fatalf("nil session comparison: comparison = %v, result = %+v", comparison, result)
	}
	if candidate, result := session.Prepare(ctx, nil, nil, nil); candidate != nil || result != want {
		t.Fatalf("nil session preparation: candidate = %v, result = %+v", candidate, result)
	}
	if result := session.Select(ctx, nil); result != want {
		t.Fatalf("nil session selection: %+v", result)
	}
	_, result := Open(ctx, OpenContext{}, nil)
	if result.Outcome != AdmissionRefused {
		t.Fatal(result)
	}
	if _, result := Initialize(ctx, InitContext{}, nil, nil, nil, nil); result.Outcome != AdmissionRefused {
		t.Fatal(result)
	}
	if _, result := session.PrepareRecipientReplacement(ctx, nil, nil); result.Outcome != AdmissionRefused {
		t.Fatal(result)
	}
	if _, result := session.PrepareSuccession(ctx, nil, SuccessionSigners{}); result.Outcome != AdmissionRefused {
		t.Fatal(result)
	}
	if _, result := session.MutationReceipt(ctx, contract.ID{}); result.Outcome != AdmissionRefused {
		t.Fatal(result)
	}
	before := coreTelemetrySnapshot(t, reader)
	if got := coreMetricSum(before, "enkv.operation.results", "core.open", "admission_refused"); got != 1 {
		t.Fatalf("refused result count = %d, want 1", got)
	}
	if got := coreMetricSum(before, "enkv.operation.results", "core.initialize", "admission_refused"); got != 1 {
		t.Fatalf("initialization refusal count = %d, want 1", got)
	}
	for _, operation := range []string{"core.compare", "core.prepare", "core.select", "core.prepare_recipient_replacement", "core.prepare_succession", "core.mutation_receipt"} {
		if got := coreMetricSum(before, "enkv.operation.results", operation, "admission_refused"); got != 1 {
			t.Fatalf("%s refusal count = %d, want 1", operation, got)
		}
	}
	for _, setting := range []string{"", "0", "1", "true", " 1", "1 "} {
		t.Setenv("ENKV_TELEMETRY", setting)
		if comparison, result := session.Compare(context.Background(), nil, nil); comparison != nil || result != want {
			t.Fatalf("disabled nil session comparison: comparison = %v, result = %+v", comparison, result)
		}
		if candidate, result := session.Prepare(context.Background(), nil, nil, nil); candidate != nil || result != want {
			t.Fatalf("disabled nil session preparation: candidate = %v, result = %+v", candidate, result)
		}
		if result := session.Select(context.Background(), nil); result != want {
			t.Fatalf("disabled nil session selection: %+v", result)
		}
		if _, result := Open(context.Background(), OpenContext{}, nil); result.Outcome != AdmissionRefused {
			t.Fatal(result)
		}
		if _, result := Initialize(context.Background(), InitContext{}, nil, nil, nil, nil); result.Outcome != AdmissionRefused {
			t.Fatal(result)
		}
		_, _ = session.PrepareRecipientReplacement(context.Background(), nil, nil)
		_, _ = session.PrepareSuccession(context.Background(), nil, SuccessionSigners{})
		_, _ = session.MutationReceipt(context.Background(), contract.ID{})
	}
	after := coreTelemetrySnapshot(t, reader)
	if got := coreMetricSum(after, "enkv.operation.calls", "core.open", ""); got != 0 {
		t.Fatalf("disabled calls recorded; delta = %d, want 0", got)
	}
	if got := coreMetricSum(after, "enkv.operation.calls", "core.initialize", ""); got != 0 {
		t.Fatalf("disabled initialization recorded; delta = %d, want 0", got)
	}
	for _, operation := range []string{"core.compare", "core.prepare", "core.select", "core.prepare_recipient_replacement", "core.prepare_succession", "core.mutation_receipt"} {
		if got := coreMetricSum(after, "enkv.operation.calls", operation, ""); got != 0 {
			t.Fatalf("disabled %s calls recorded; delta = %d, want 0", operation, got)
		}
	}
}
