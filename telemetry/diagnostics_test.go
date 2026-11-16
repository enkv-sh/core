package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"

	"go.opentelemetry.io/otel/trace"
)

func testDiagnosticContext(recorder *Recorder) context.Context {
	return WithCapability(context.Background(), NewCapability(nil, recorder))
}

// full_only: false
func TestDiagnosticReturnSeverityCoversResultVocabulary(t *testing.T) {
	// These expectations come from the operation meanings: normal observations
	// are INFO, refusals and uncertain outcomes are WARN, and failures are ERROR.
	for _, test := range []struct {
		result    Result
		provider  Provider
		operation Operation
		text      string
		number    int
	}{
		{ResultSuccess, ProviderCrypto, OpCryptoPrepare, "INFO", 9},
		{ResultFailure, ProviderWorker, OpWorkerInvocation, "ERROR", 17},
		{ResultUnknown, ProviderCrypto, OpCryptoExchange, "WARN", 13},
		{ResultUnchanged, ProviderCore, OpCoreCompare, "INFO", 9},
		{ResultObservedCurrent, ProviderCore, OpCoreSelect, "INFO", 9},
		{ResultContention, ProviderCore, OpCoreSelect, "WARN", 13},
		{ResultUnresolvedCommit, ProviderCore, OpCoreSelect, "WARN", 13},
		{ResultIntegrityFailure, ProviderCore, OpCoreOpen, "ERROR", 17},
		{ResultEvidenceUnavailable, ProviderCore, OpCoreOpen, "ERROR", 17},
		{ResultRootLossUnsupported, ProviderCore, OpCoreOpen, "WARN", 13},
		{ResultAdmissionRefused, ProviderCore, OpCorePrepare, "WARN", 13},
		{ResultInvalid, ProviderCrypto, OpCryptoPrepare, "ERROR", 17},
		{ResultDenied, ProviderAWS, OpKeyDecrypt, "WARN", 13},
		{ResultCancelled, ProviderGeneratorHost, OpGeneratorHostJoin, "WARN", 13},
		{ResultExpired, ProviderGeneratorHost, OpGeneratorHostJoin, "WARN", 13},
		{ResultAlreadyUsed, ProviderCrypto, OpCryptoClaim, "WARN", 13},
		{ResultCapacityExceeded, ProviderCrypto, OpCryptoPrepare, "WARN", 13},
		{ResultReadOK, ProviderAWS, OpStoreRead, "INFO", 9},
		{ResultReadMissing, ProviderCore, OpCoreGeneratedReadResult, "INFO", 9},
		{ResultReadUnavailable, ProviderGCP, OpStoreRead, "ERROR", 17},
		{ResultReadInvalid, ProviderAWS, OpStoreRead, "ERROR", 17},
		{ResultWriteAcknowledged, ProviderCore, OpCoreStoreCreate, "INFO", 9},
		{ResultWritePrecondition, ProviderCore, OpCoreStoreCompareAndSwap, "WARN", 13},
		{ResultWriteConflict, ProviderAWS, OpStoreCreate, "WARN", 13},
		{ResultWriteUnknown, ProviderGCP, OpStoreCompareAndSwap, "WARN", 13},
		{ResultWriteRefused, ProviderCore, OpCoreStoreCreate, "WARN", 13},
		{ResultSignOK, ProviderCore, OpCoreTrustSign, "INFO", 9},
		{ResultSignUnavailable, ProviderAWS, OpTrustSign, "ERROR", 17},
		{ResultSignInvalid, ProviderGCP, OpTrustSign, "ERROR", 17},
	} {
		t.Run(string(test.result), func(t *testing.T) {
			recorder := NewRecorder()
			call := Start(testDiagnosticContext(recorder), test.provider, test.operation)
			call.Finish(test.result)
			records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
			if len(records) != 2 || records[0].Event != DiagnosticStart || records[0].SeverityText != "DEBUG" || records[0].SeverityNumber != 5 {
				t.Fatalf("operation start differs: %+v", records)
			}
			got := records[1]
			if got.Event != DiagnosticReturn || got.Result != test.result || got.SeverityText != test.text || got.SeverityNumber != test.number || got.Validate() != nil {
				t.Fatalf("return = %+v, want %s (%d)", got, test.text, test.number)
			}
		})
	}
}

// full_only: false
func TestLocalOperatorOperationsKeepClosedOwnerAndStage(t *testing.T) {
	for _, test := range []struct {
		operation Operation
		stage     DiagnosticStage
	}{
		{OpCoreInspectSelectedWork, DiagnosticAdmission},
		{OpCorePrepareEndSelectedWork, DiagnosticAdmission},
		{OpCoreSelectEndSelectedWork, DiagnosticCommitObservation},
		{OpCoreReplaceAuthorityKeys, DiagnosticAdmission},
		{OpCoreReplaceRecoveryKeys, DiagnosticAdmission},
		{OpCoreReplaceRecipientKey, DiagnosticAdmission},
	} {
		t.Run(string(test.operation), func(t *testing.T) {
			recorder := NewRecorder()
			ctx := testDiagnosticContext(recorder)
			if Start(ctx, ProviderCrypto, test.operation) != nil {
				t.Fatal("Core operator operation accepted another owner")
			}
			call := Start(ctx, ProviderCore, test.operation)
			if call == nil {
				t.Fatal("Core operator operation was not registered")
			}
			call.Checkpoint(test.stage, DiagnosticReasonNone)
			call.Finish(ResultAdmissionRefused)
			records := recorder.Drain(make([]DiagnosticRecord, 0, 3))
			if len(records) != 3 || records[1].Stage != test.stage || records[2].Operation != test.operation ||
				records[2].Result != ResultAdmissionRefused {
				t.Fatal("operator diagnostic shape", records)
			}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal("operator diagnostic refused", err, record)
				}
			}
		})
	}
}

// full_only: false
func TestRetiredRestoreSignerTelemetryHasNoOwnerOrDimension(t *testing.T) {
	operation := Operation("core.restore_local_signer")
	if AllowedAttribute("operation", string(operation)) {
		t.Fatal("retired restoration remains an allowed telemetry dimension")
	}
	for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderApplication, ProviderWorker, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost} {
		if ValidOperationOwner(provider, operation) || Start(testDiagnosticContext(NewRecorder()), provider, operation) != nil {
			t.Fatal("retired restoration retains telemetry owner", provider)
		}
	}
}

// full_only: false
func TestDiagnosticReturnSeverityPreservesOutcomeWithSpecificReasons(t *testing.T) {
	for _, test := range []struct {
		result  Result
		reasons []DiagnosticReason
		text    string
		number  int
	}{
		{ResultAdmissionRefused, []DiagnosticReason{DiagnosticReasonAdmissionInvalid, DiagnosticReasonConstructionMismatch, DiagnosticReasonInvalidFormat, DiagnosticReasonInvalidProof, DiagnosticReasonInvalidReference, DiagnosticReasonInvalidRelation, DiagnosticReasonCapacityExceeded, DiagnosticReasonInvalidIntent, DiagnosticReasonAlreadyUsed}, "WARN", 13},
		{ResultIntegrityFailure, []DiagnosticReason{DiagnosticReasonConstructionMismatch, DiagnosticReasonInvalidFormat, DiagnosticReasonInvalidProof, DiagnosticReasonInvalidReference, DiagnosticReasonInvalidRelation, DiagnosticReasonImmutableConflict}, "ERROR", 17},
		{ResultEvidenceUnavailable, []DiagnosticReason{DiagnosticReasonMissingSelectedObject, DiagnosticReasonReadUnavailable, DiagnosticReasonSigningUnavailable, DiagnosticReasonWriteUncertain, DiagnosticReasonCustodyUnavailable}, "ERROR", 17},
		{ResultRootLossUnsupported, []DiagnosticReason{DiagnosticReasonMissingSelectedObject}, "WARN", 13},
		{ResultContention, []DiagnosticReason{DiagnosticReasonStalePrecondition, DiagnosticReasonDifferentSelection}, "WARN", 13},
		{ResultUnresolvedCommit, []DiagnosticReason{DiagnosticReasonWriteUncertain, DiagnosticReasonDifferentSelection, DiagnosticReasonReadUnavailable, DiagnosticReasonMissingSelectedObject, DiagnosticReasonInvalidFormat, DiagnosticReasonInvalidProof, DiagnosticReasonInvalidReference, DiagnosticReasonInvalidRelation, DiagnosticReasonConstructionMismatch, DiagnosticReasonAdmissionInvalid}, "WARN", 13},
		{ResultObservedCurrent, []DiagnosticReason{DiagnosticReasonCustodyUnavailable}, "WARN", 13},
		{ResultFailure, []DiagnosticReason{DiagnosticReasonNone, DiagnosticReasonUncertain, DiagnosticReasonEvidenceUnavailable}, "ERROR", 17},
		{ResultSuccess, []DiagnosticReason{DiagnosticReasonUncertain}, "WARN", 13},
		{ResultReadMissing, []DiagnosticReason{DiagnosticReasonNone, DiagnosticReasonEvidenceUnavailable}, "INFO", 9},
	} {
		for _, reason := range test.reasons {
			t.Run(string(test.result)+"/"+string(reason), func(t *testing.T) {
				recorder := NewRecorder()
				call := Start(testDiagnosticContext(recorder), ProviderCore, OpCoreSelect)
				call.FinishReason(test.result, reason)
				records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
				if len(records) != 2 {
					t.Fatalf("operation records = %+v", records)
				}
				got := records[1]
				if got.Result != test.result || got.Reason != reason || got.SeverityText != test.text || got.SeverityNumber != test.number || got.Validate() != nil {
					t.Fatalf("return = %+v, want %s (%d) with unchanged result and reason", got, test.text, test.number)
				}
			})
		}
	}
}

// full_only: false
func TestDiagnosticCheckpointSeverityKeepsProblemsVisible(t *testing.T) {
	for _, test := range []struct {
		reason DiagnosticReason
		text   string
		number int
	}{
		{DiagnosticReasonNone, "DEBUG", 5},
		{DiagnosticReasonReadUnavailable, "WARN", 13},
		{DiagnosticReasonUncertain, "WARN", 13},
	} {
		t.Run(string(test.reason), func(t *testing.T) {
			recorder := NewRecorder()
			call := Start(testDiagnosticContext(recorder), ProviderCore, OpCoreStoreRead)
			call.Checkpoint(DiagnosticStateLoading, test.reason)
			records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
			if len(records) != 2 || records[1].Event != DiagnosticCheckpoint || records[1].Reason != test.reason || records[1].SeverityText != test.text || records[1].SeverityNumber != test.number || records[1].Validate() != nil {
				t.Fatalf("checkpoint = %+v, want %s (%d)", records, test.text, test.number)
			}
		})
	}
}

// full_only: false
func TestRecorderFitsCaptureBudgetAndDropsNew(t *testing.T) {
	if size := unsafe.Sizeof(Recorder{}); size > RecorderCaptureBytes {
		t.Fatalf("recorder size = %d, limit = %d", size, RecorderCaptureBytes)
	}
	recorder := NewRecorder()
	ctx := testDiagnosticContext(recorder)
	for range diagnosticSlotCount + 1 {
		Start(ctx, ProviderCore, OpCoreOpen)
	}
	status := recorder.Status()
	if status.Accepted != uint64(diagnosticSlotCount) || status.DroppedFull != 1 {
		t.Fatalf("capture status = %+v, slots = %d", status, diagnosticSlotCount)
	}
	first := recorder.Drain(make([]DiagnosticRecord, 0, 1))
	Start(ctx, ProviderCore, OpCoreOpen)
	records := recorder.Drain(make([]DiagnosticRecord, 0, diagnosticSlotCount))
	if len(first) != 1 || first[0].Sequence != 1 || len(records) != diagnosticSlotCount || records[0].Sequence != 2 || records[len(records)-1].Sequence != uint64(diagnosticSlotCount+1) {
		t.Fatal("accepted prefix or record order changed")
	}
}

// full_only: false
func TestDiagnosticsStayEnabledWhenMetricsAreOffOrFail(t *testing.T) {
	for _, mode := range []string{"metrics-off", "metrics-failed"} {
		t.Run(mode, func(t *testing.T) {
			var metrics chan MetricPoint
			if mode == "metrics-failed" {
				metrics = make(chan MetricPoint, 1)
				metrics <- MetricPoint{Name: OperationCalls, Provider: ProviderCore, Operation: OpCoreOpen, IntValue: 1}
			}
			recorder := NewRecorder()
			capability := NewCapability(metrics, recorder)
			call := Start(WithCapability(context.Background(), capability), ProviderCore, OpCoreOpen)
			if call == nil {
				t.Fatal("diagnostic call followed metric availability")
			}
			call.Finish(ResultObservedCurrent)
			records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
			if len(records) != 2 || records[0].Event != DiagnosticStart || records[1].Event != DiagnosticReturn || records[1].Result != ResultObservedCurrent {
				t.Fatalf("diagnostic sequence differs: %+v", records)
			}
			if mode == "metrics-failed" && capability.LostMetrics() == 0 {
				t.Fatal("full metric queue did not count loss")
			}
		})
	}
	if Start(context.Background(), ProviderCore, OpCoreOpen) != nil {
		t.Fatal("fully disabled call allocated state")
	}
}

// full_only: false
func TestReturnDetailsPreserveStartIdentityAndRejectUnsafeDetail(t *testing.T) {
	recorder := NewRecorder()
	ctx := testDiagnosticContext(recorder)
	commandID := "abababababababababababababababababababababababababababababababab"
	call := StartWithDetails(ctx, ProviderCore, OpCoreOpen,
		(DiagnosticDetails{}).WithCommandID(commandID).WithPathKind("state_head"))
	call.ReturnDetails((DiagnosticDetails{}).WithErrorFacts(DiagnosticReasonReadUnavailable, 503).WithReviewedErrorText("state read returned HTTP 503"))
	call.Finish(ResultEvidenceUnavailable)
	records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
	if len(records) != 2 || records[0].CommandID != commandID || records[1].CommandID != commandID ||
		records[1].PathKind != "state_head" || records[1].ErrorDetail != "state read returned HTTP 503" || records[1].Validate() != nil {
		t.Fatalf("return details lost reviewed facts: %+v", records)
	}
	call = Start(ctx, ProviderCore, OpCoreOpen)
	call.ReturnDetails((DiagnosticDetails{}).WithReviewedErrorText("unclassified raw error"))
	call.Finish(ResultFailure)
	if got := recorder.Drain(make([]DiagnosticRecord, 0, 2)); len(got) != 1 || got[0].Event != DiagnosticStart || recorder.Status().Rejected != 1 {
		t.Fatalf("unsafe return entered capture: %+v, status=%+v", got, recorder.Status())
	}
}

// full_only: false
func TestDiagnosticParentCheckpointAndClosedValidation(t *testing.T) {
	recorder := NewRecorder()
	parent := Start(testDiagnosticContext(recorder), ProviderCore, OpCorePrepare)
	child := Start(parent.Context(), ProviderCrypto, OpCryptoPrepare)
	child.Checkpoint(DiagnosticPrivateCustody, DiagnosticReasonNone)
	child.Finish(ResultSuccess)
	parent.Finish(ResultObservedCurrent)
	records := recorder.Drain(make([]DiagnosticRecord, 0, 5))
	if len(records) != 5 || records[1].ParentCall != records[0].Call || records[2].Stage != DiagnosticPrivateCustody {
		t.Fatalf("parent or checkpoint differs: %+v", records)
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatalf("accepted invalid record: %v", err)
		}
	}
	before := recorder.Status()
	recorder.emit(diagnosticRecord{provider: Provider("synthetic-secret"), operation: Operation("synthetic-secret"), event: DiagnosticStart})
	recorder.emit(diagnosticRecord{call: 99, provider: ProviderAWS, operation: OpCoreOpen, event: DiagnosticStart})
	recorder.emit(diagnosticRecord{call: 100, provider: ProviderCore, operation: OpCoreOpen, event: DiagnosticCheckpoint, stage: DiagnosticProviderCall})
	after := recorder.Status()
	if after.Rejected != before.Rejected+3 {
		t.Fatal("hostile categories or invalid owner combinations were not rejected")
	}
}

// full_only: false
func TestCaptureDoesNotWaitForRecorderLock(t *testing.T) {
	recorder := NewRecorder()
	ctx := testDiagnosticContext(recorder)
	recorder.mu.Lock()
	done := make(chan struct{})
	go func() {
		Start(ctx, ProviderCore, OpCoreOpen)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		recorder.mu.Unlock()
		t.Fatal("capture waited for recorder progress")
	}
	recorder.mu.Unlock()
	if recorder.Status().DroppedContention != 1 {
		t.Fatal("contention loss was not counted")
	}
}

// full_only: false
func TestRecorderMinimumSeverityPrecedesCaptureLoss(t *testing.T) {
	t.Run("contention", func(t *testing.T) {
		recorder := NewRecorderWithMinimumSeverity(SeverityWarn)
		ctx := testDiagnosticContext(recorder)
		recorder.mu.Lock()
		Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultSuccess)
		Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultAdmissionRefused)
		recorder.mu.Unlock()
		if status := recorder.Status(); status != (RecorderStatus{DroppedContention: 1}) {
			t.Fatal("filtered calls or selected warning changed contention loss", status)
		}
	})
	t.Run("full", func(t *testing.T) {
		recorder := NewRecorderWithMinimumSeverity(SeverityWarn)
		ctx := testDiagnosticContext(recorder)
		for range diagnosticSlotCount {
			Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultAdmissionRefused)
		}
		Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultSuccess)
		Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultAdmissionRefused)
		if status := recorder.Status(); status != (RecorderStatus{Accepted: uint64(diagnosticSlotCount), DroppedFull: 1}) {
			t.Fatal("filtered calls or selected warning changed capacity loss", status)
		}
	})
	t.Run("closed", func(t *testing.T) {
		recorder := NewRecorderWithMinimumSeverity(SeverityWarn)
		ctx := testDiagnosticContext(recorder)
		recorder.Close()
		Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultSuccess)
		Start(ctx, ProviderCore, OpCoreOpen).Finish(ResultAdmissionRefused)
		if status := recorder.Status(); status != (RecorderStatus{DroppedClosed: 1, Closed: true}) {
			t.Fatal("filtered calls or selected warning changed closed loss", status)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		recorder := NewRecorderWithMinimumSeverity(SeverityWarn)
		if recorder.emit(diagnosticRecord{}) || recorder.Status() != (RecorderStatus{Rejected: 1}) {
			t.Fatal("threshold hid invalid diagnostic input", recorder.Status())
		}
	})
}

type privateDiagnosticBaggageKey struct{}

// full_only: false
func TestPrivateContextKeepsBaseLifetimeAndOnlyDiagnosticLinkage(t *testing.T) {
	recorder := NewRecorder()
	parent := Start(testDiagnosticContext(recorder), ProviderCore, OpCorePrepare)
	source, sourceCancel := context.WithCancel(context.WithValue(parent.Context(), privateDiagnosticBaggageKey{}, "private-sentinel"))
	base, baseCancel := context.WithCancel(context.Background())
	private := PrivateContext(base, source)
	if private.Value(privateDiagnosticBaggageKey{}) != nil {
		t.Fatal("private context transferred caller baggage")
	}
	sourceCancel()
	if private.Err() != nil {
		t.Fatal("private context retained the caller lifetime")
	}
	child := Start(private, ProviderCrypto, OpCryptoConsume)
	child.Finish(ResultDenied)
	baseCancel()
	if !errors.Is(private.Err(), context.Canceled) {
		t.Fatal("private context did not retain the admitted lifetime")
	}
	parent.Finish(ResultObservedCurrent)
	records := recorder.Drain(make([]DiagnosticRecord, 0, 4))
	if len(records) != 4 || records[1].ParentCall != records[0].Call || records[2].Reason != DiagnosticReasonDenied {
		t.Fatalf("private diagnostic linkage differs: %+v", records)
	}
}

// full_only: false
func TestPrivateContextCopiesOnlyTraceIdentity(t *testing.T) {
	traceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	state, err := trace.ParseTraceState("tenant=private")
	if err != nil {
		t.Fatal(err)
	}
	sourceSpan := trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled, TraceState: state, Remote: true})
	source := trace.ContextWithSpanContext(context.WithValue(context.Background(), privateDiagnosticBaggageKey{}, "private-sentinel"), sourceSpan)
	private := PrivateContext(context.Background(), source)
	got := trace.SpanContextFromContext(private)
	if got.TraceID() != traceID || got.SpanID() != spanID || !got.IsSampled() || got.IsRemote() || got.TraceState().Len() != 0 {
		t.Fatalf("private trace identity = %v", got)
	}
	if private.Value(privateDiagnosticBaggageKey{}) != nil {
		t.Fatal("private context copied an arbitrary caller value")
	}
}

// full_only: false
func TestPrivateContextDoesNotRetainAnEarlierRecorder(t *testing.T) {
	first, second := NewRecorder(), NewRecorder()
	base := context.Background()
	firstCall := Start(PrivateContext(base, WithCapability(base, NewCapability(nil, first))), ProviderCrypto, OpCryptoSealSource)
	firstCall.Finish(ResultSuccess)
	secondCall := Start(PrivateContext(base, WithCapability(base, NewCapability(nil, second))), ProviderCrypto, OpCryptoConsume)
	secondCall.Finish(ResultSuccess)
	if got := len(first.Drain(make([]DiagnosticRecord, 0, 2))); got != 2 {
		t.Fatalf("first recorder count = %d", got)
	}
	if records := second.Drain(make([]DiagnosticRecord, 0, 2)); len(records) != 2 || records[0].Call != 1 || records[0].ParentCall != 0 {
		t.Fatalf("second recorder retained earlier correlation: %+v", records)
	}
}

// full_only: false
func TestPersistenceAndSetupDiagnosticFactsKeepTheirSemanticOwner(t *testing.T) {
	for _, tc := range []struct {
		provider  Provider
		operation Operation
		result    Result
		severity  string
		reason    DiagnosticReason
	}{
		{ProviderCore, OpCoreStorePersistImmutable, ResultImmutableCreated, "INFO", DiagnosticReasonNone},
		{ProviderCore, OpCoreStorePersistImmutable, ResultImmutableReused, "INFO", DiagnosticReasonNone},
		{ProviderCore, OpCoreStorePersistImmutable, ResultImmutableVerified, "INFO", DiagnosticReasonNone},
		{ProviderCore, OpCoreStoreCreate, ResultVerificationPending, "INFO", DiagnosticReasonNone},
		{ProviderAWS, OpStoreCreate, ResultVerificationPending, "INFO", DiagnosticReasonNone},
		{ProviderGCP, OpStoreCreate, ResultVerificationPending, "INFO", DiagnosticReasonNone},
		{ProviderCore, OpCoreStoreCreate, ResultWriteUnknown, "DEBUG", DiagnosticReasonUncertain},
		{ProviderAWS, OpStoreCreate, ResultWriteUnknown, "WARN", DiagnosticReasonUncertain},
		{ProviderCore, OpCoreStoreCreateHead, ResultWritePrecondition, "WARN", DiagnosticReasonUncertain},
		{ProviderCore, OpCoreStoreCompareAndSwap, ResultWritePrecondition, "WARN", DiagnosticReasonUncertain},
		{ProviderApplication, OpConfigurationPrepare, ResultSetupIncomplete, "DEBUG", DiagnosticReasonSetupRequired},
		{ProviderApplication, OpConfigurationPrepareDependencies, ResultSetupIncomplete, "DEBUG", DiagnosticReasonSetupRequired},
		{ProviderApplication, OpApplicationInvocation, ResultSetupIncomplete, "DEBUG", DiagnosticReasonSetupRequired},
		{ProviderApplication, OpConfigurationPrepare, ResultFailure, "ERROR", DiagnosticReasonUncertain},
		{ProviderApplication, OpConfigurationPrepare, ResultWriteUnknown, "WARN", DiagnosticReasonUncertain},
	} {
		t.Run(string(tc.operation)+"/"+string(tc.result), func(t *testing.T) {
			recorder := NewRecorder()
			call := Start(testDiagnosticContext(recorder), tc.provider, tc.operation)
			call.Finish(tc.result)
			records := recorder.Drain(make([]DiagnosticRecord, 0, 2))
			if len(records) != 2 || records[1].Result != tc.result || records[1].Reason != tc.reason || records[1].SeverityText != tc.severity || records[1].Validate() != nil {
				t.Fatal("semantic diagnostic fact changed", records)
			}
		})
	}
}
