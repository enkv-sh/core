package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// full_only: false
func TestCaptureBudgetIncludesOwnedStringPayloads(t *testing.T) {
	for _, field := range []string{"reviewed-error", "store-path"} {
		t.Run(field, func(t *testing.T) {
			recorder := NewRecorder()
			ctx := WithCapability(context.Background(), NewCapability(nil, recorder))
			for i := 0; i < diagnosticSlotCount; i++ {
				details := DiagnosticDetails{}
				if field == "reviewed-error" {
					details = details.WithErrorFacts(DiagnosticReasonInvalid, 0).WithReviewedErrorText(strings.Repeat("s", MaximumErrorBytes))
				} else {
					details = details.WithPathKind("state_object").WithReviewedPath(fmt.Sprintf("state/objects/%064d", i))
				}
				StartWithDetails(ctx, ProviderAWS, OpStoreRead, details)
			}
			fixed := int(unsafe.Sizeof(*recorder))
			payload := 0
			seen := map[*byte]bool{}
			for i := 0; i < recorder.count; i++ {
				d := recorder.slots[i].details
				for _, s := range []string{d.entryName, d.keyID, d.commandID, d.attemptID, d.invocationID, d.workerID, d.path, d.errorText} {
					if s != "" && !seen[unsafe.StringData(s)] {
						seen[unsafe.StringData(s)] = true
						payload += len(s)
					}
				}
			}
			if fixed+payload+(64<<10) > RecorderCaptureBytes {
				t.Errorf("capture=%d+%d plus 64KiB scratch exceeds %d", fixed, payload, RecorderCaptureBytes)
			}
			status := recorder.Status()
			if status.Accepted == 0 || status.Accepted+status.DroppedFull != uint64(diagnosticSlotCount) || status.Rejected != 0 || status.DroppedContention != 0 {
				t.Fatalf("prefix accounting %+v", status)
			}
			records := recorder.Drain(make([]DiagnosticRecord, 0, diagnosticSlotCount))
			for i, r := range records {
				if r.Sequence != uint64(i+1) || r.Validate() != nil {
					t.Fatal("prefix or wire", i, r)
				}
			}
			StartWithDetails(ctx, ProviderAWS, OpStoreRead, (DiagnosticDetails{}).WithReviewedPath("state/new"))
			if got := recorder.Drain(make([]DiagnosticRecord, 0, 1)); len(got) != 1 || got[0].Sequence != status.Accepted+1 {
				t.Fatal("drain did not release dynamic capacity", got)
			}
		})
	}
}

// full_only: false
func TestEncodedRecordSizeIsCheckedBeforeAdmission(t *testing.T) {
	for _, text := range []string{strings.Repeat("<", MaximumErrorBytes), strings.Repeat("&", MaximumErrorBytes), strings.Repeat("s", MaximumErrorBytes)} {
		t.Run(text[:1], func(t *testing.T) {
			r := NewRecorder()
			ctx := WithCapability(context.Background(), NewCapability(nil, r))
			details := (DiagnosticDetails{}).WithErrorFacts(DiagnosticReasonInvalid, 0).WithReviewedErrorText(text)
			call := StartWithDetails(ctx, ProviderCore, OpCoreOpen, details)
			call.Finish(ResultAdmissionRefused)
			records := r.Drain(make([]DiagnosticRecord, 0, 2))
			status := r.Status()
			// JSON encodes each '<' or '&' as six bytes. 8192*6 alone exceeds
			// the 16384-byte ceiling; plain ASCII leaves room for the fixed envelope.
			if text[0] != 's' {
				if len(records) != 0 || status.Accepted != 0 || status.Rejected != 2 {
					t.Errorf("oversized records admitted len=%d status=%+v", len(records), status)
				}
			} else if len(records) != 2 || status.Accepted != 2 || status.Rejected != 0 {
				t.Errorf("valid maximum text refused len=%d status=%+v", len(records), status)
			}
			for _, record := range records {
				wire, e := json.Marshal(record)
				if e != nil || len(wire) > MaximumLogRecordBytes || record.Validate() != nil {
					t.Error("invalid accepted wire", len(wire), e)
				}
			}
		})
	}
}

// full_only: false
func TestCaptureAdmissionMatchesIndependentJSONLength(t *testing.T) {
	for _, text := range []string{strings.Repeat("<", 2600), strings.Repeat("<", 2700), strings.Repeat("\u2028", 2600), strings.Repeat("\\", MaximumErrorBytes), strings.Repeat("s", MaximumErrorBytes)} {
		t.Run(fmt.Sprintf("%x-%d", []byte(text[:1]), len(text)), func(t *testing.T) {
			recorder := NewRecorder()
			details := (DiagnosticDetails{}).WithErrorFacts(DiagnosticReasonInvalid, 599).WithReviewedErrorText(text)
			input := diagnosticRecord{call: 2, parent: 1, provider: ProviderAWS, operation: OpStoreRead, event: DiagnosticReturn, result: ResultReadUnavailable, reason: DiagnosticReasonReadUnavailable, details: details}
			// Construct the whole public expectation independently of the production
			// projection and escaping precheck. Standard-library JSON is the wire rule.
			expected := DiagnosticRecord{SchemaVersion: 2, OccurredAt: recorder.started.UTC(), Component: "aws", SeverityText: "ERROR", SeverityNumber: 17, Call: 2, ParentCall: 1, Sequence: 1, Provider: ProviderAWS, Operation: OpStoreRead, Event: DiagnosticReturn, Result: ResultReadUnavailable, Reason: DiagnosticReasonReadUnavailable, ErrorClass: DiagnosticReasonInvalid, HTTPStatus: 599, ErrorDetail: text, ErrorDetailStatus: "reviewed"}
			// Bound numeric widths independently so elapsed capture time cannot change
			// the expected admission at a marginal digit transition.
			expected.OffsetNanos = math.MaxInt64
			expected.ElapsedNanos = math.MaxInt64
			wire, e := json.Marshal(expected)
			if e != nil {
				t.Fatal(e)
			}
			wantAccepted := len(wire) <= MaximumLogRecordBytes
			if got := recorder.emit(input); got != wantAccepted {
				t.Errorf("accepted=%t independent encoded=%d", got, len(wire))
			}
			status := recorder.Status()
			if wantAccepted {
				if status.Accepted != 1 || status.Rejected != 0 {
					t.Fatal(status)
				}
			} else if status.Accepted != 0 || status.Rejected != 1 {
				t.Fatal(status)
			}
		})
	}
}

// full_only: false
func TestCaptureOwnsAndChargesEveryRetainedString(t *testing.T) {
	recorder := NewRecorder()
	backing := strings.Repeat("s", MaximumErrorBytes) + "unused-tail"
	text := backing[:MaximumErrorBytes]
	details := (DiagnosticDetails{}).WithEntryName("entry").WithKeyID(strings.Repeat("a", 64)).WithCommandID(strings.Repeat("b", 64)).WithAttemptID(strings.Repeat("c", 64)).WithInvocationID("invocation").WithWorkerID("worker").WithPathKind("state_object").WithReviewedPath("state/objects/safe").WithConfigField("provider").WithErrorFacts(DiagnosticReasonInvalid, 503).WithReviewedErrorText(text)
	input := diagnosticRecord{call: 1, provider: ProviderAWS, operation: OpStoreRead, event: DiagnosticReturn, result: ResultReadUnavailable, reason: DiagnosticReasonReadUnavailable, details: details, traceID: strings.Repeat("a", 32), spanID: strings.Repeat("b", 16), traceSampled: true}
	if !recorder.emit(input) {
		t.Fatal("valid maximum owned detail refused", recorder.Status())
	}
	expectedStrings := []string{"aws", "store.read", "return", "read_unavailable", "read_unavailable", input.traceID, input.spanID, "entry", strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), "invocation", "worker", "state_object", "state/objects/safe", "provider", "invalid", text}
	expectedBytes := 0
	for _, value := range expectedStrings {
		expectedBytes += len(value)
	}
	if recorder.payloadBytes != expectedBytes {
		t.Fatalf("retained charge=%d want=%d", recorder.payloadBytes, expectedBytes)
	}
	stored := recorder.slots[0]
	if unsafe.StringData(stored.details.errorText) == unsafe.StringData(details.errorText) || unsafe.StringData(stored.traceID) == unsafe.StringData(input.traceID) {
		t.Fatal("capture borrowed string backing")
	}
	if int(unsafe.Sizeof(*recorder))+expectedBytes+(64<<10) > RecorderCaptureBytes {
		t.Fatal("capture+encoding reservation exceeds ceiling")
	}
	records := recorder.Drain(make([]DiagnosticRecord, 0, 1))
	if len(records) != 1 || recorder.payloadBytes != 0 || records[0].Validate() != nil {
		t.Fatal("drain did not release exact retained charge")
	}
}

// full_only: false
func TestCaptureEncodingEnvelopeFitsScratchReservation(t *testing.T) {
	record := DiagnosticRecord{SchemaVersion: 2, OccurredAt: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC), Component: "generatorhost", SeverityText: "ERROR", SeverityNumber: 17, TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), TraceSampled: true, EntryName: strings.Repeat("n", 256), KeyID: strings.Repeat("a", 64), CommandID: strings.Repeat("a", 64), AttemptID: strings.Repeat("a", 64), InvocationID: strings.Repeat("i", 64), WorkerID: strings.Repeat("w", 96), PathKind: "generator_artifact", Path: strings.Repeat("p", 1024), ConfigField: "recovery_mode", ErrorClass: DiagnosticReasonEvidenceUnavailable, HTTPStatus: 599, ErrorDetail: strings.Repeat("s", MaximumErrorBytes), ErrorDetailStatus: "unavailable", Sequence: math.MaxUint64, Call: math.MaxUint64 - 1, ParentCall: math.MaxUint64 - 2, Provider: ProviderGeneratorHost, Operation: OpCoreGeneratedPrepareSuccessorReservation, Event: DiagnosticCheckpoint, Stage: DiagnosticProviderCall, Result: ResultEvidenceUnavailable, Reason: DiagnosticReasonEvidenceUnavailable, OffsetNanos: math.MaxInt64, ElapsedNanos: math.MaxInt64}
	wire, e := json.Marshal(record)
	if e != nil {
		t.Fatal(e)
	}
	// Subtract only strings varied by admitted source facts; keep every fixed
	// field, name, quote, separator and worst-width numeric value in the envelope.
	dynamic := len(record.EntryName) + len(record.KeyID) + len(record.CommandID) + len(record.AttemptID) + len(record.InvocationID) + len(record.WorkerID) + len(record.Path) + len(record.ErrorDetail) + len(record.TraceID) + len(record.SpanID)
	if envelope := len(wire) - dynamic; envelope > 2048 {
		t.Fatalf("JSON envelope=%d exceeds 2KiB reservation", envelope)
	}
	// After the lower-bound precheck, at most 16KiB string bytes can reach
	// Marshal. An envelope below2KiB fits a32KiB growth buffer plus returned
	// <18KiB copy in the64KiB scratch reservation.
}

// full_only: false
func TestMetricAdmissionContentionNeverWaitsAndCountsExactLoss(t *testing.T) {
	points := make(chan MetricPoint, 16)
	capability := NewCapability(points, nil)
	call := Start(WithCapability(context.Background(), capability), ProviderCore, OpCoreOpen)
	call.InputBytes(5)
	call.OutputBytes(7)
	capability.metricMu.Lock()
	done := make(chan struct{})
	go func() { call.Finish(ResultSuccess); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		capability.metricMu.Unlock()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("contended metric producer did not join")
		}
		t.Fatal("Product return waited for metric admission lock")
	}
	capability.metricMu.Unlock()
	// Finish emits exactly result, duration, input bytes and output bytes. The
	// earlier call point stays accepted in a queue with ample spare capacity.
	if len(points) != 1 || capability.LostMetrics() != 4 || capability.RejectedMetrics() != 0 {
		t.Fatalf("queued=%d lost=%d rejected=%d", len(points), capability.LostMetrics(), capability.RejectedMetrics())
	}
	capability.Deactivate()
	t.Run("concurrent_producers_with_queue_space", func(t *testing.T) {
		const producers, perProducer = 16, 128
		points := make(chan MetricPoint, producers*perProducer)
		capture := NewCapability(points, nil)
		var workers sync.WaitGroup
		start := make(chan struct{})
		for range producers {
			workers.Go(func() {
				<-start
				for range perProducer {
					capture.emitMetric(MetricPoint{Name: OperationCalls, Provider: ProviderCore, Operation: OpCoreOpen, IntValue: 1})
				}
			})
		}
		close(start)
		workers.Wait()
		capture.Deactivate()
		if len(points) != producers*perProducer || capture.LostMetrics() != 0 || capture.RejectedMetrics() != 0 {
			t.Fatalf("queued=%d lost=%d rejected=%d", len(points), capture.LostMetrics(), capture.RejectedMetrics())
		}
	})
}
