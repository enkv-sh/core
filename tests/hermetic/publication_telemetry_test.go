package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// full_only: false
func TestPublicationTelemetryDisabledAndAcknowledged(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "acknowledged"
		}
		t.Run(name, func(t *testing.T) {
			configured, runtime, _ := coreTelemetryReader(t)
			ctx := context.Background()
			if enabled {
				ctx = configured
			}
			f, input, private := publicationEngineFixture(t)
			before := f.session.currentEntryInputs()
			plan, state := f.session.planPublication(ctx, input, private.callbacks())
			if plan == nil || state.Outcome != ObservedCurrent {
				t.Fatalf("plan present=%t outcome=%d reason=%d", plan != nil, state.Outcome, state.Reason)
			}
			got := plan.execute(ctx, private.callbacks(), publicationEngineCurrent(f))
			if got.summary != contract.PublicationSummaryComplete || got.state.Outcome != ObservedCurrent || len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 1 || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
				t.Fatalf("ACK summary=%d outcome=%d entries=%d", got.summary, got.state.Outcome, len(got.output.Entries))
			}
			if len(private.owners) != 1 || private.owners[0].prepared != 1 || private.owners[0].armed != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 1 {
				t.Fatal("one-use lifecycle changed")
			}
			selected := publicationEngineReopen(t, f)
			row := got.output.Entries[0].Actions[0]
			if selected.markers[row.AttemptID].State != contract.PublicationAcknowledged || !reflect.DeepEqual(before, f.session.currentEntryInputs()) {
				t.Fatal("selected ACK or canonical entries changed")
			}
			after := coreTelemetrySnapshot(t, runtime)
			want := int64(0)
			if enabled {
				want = 1
			}
			for operation, result := range map[string]string{
				"core.publication.plan":                "observed_current",
				"core.publication.execute":             "write_acknowledged",
				"core.publication.prepare_reservation": "observed_current",
				"core.publication.prepare_close":       "observed_current",
			} {
				if calls := coreMetricSum(after, "enkv.operation.calls", operation, ""); calls != want {
					t.Errorf("%s calls=%d want=%d", operation, calls, want)
				}
				if results := coreMetricSum(after, "enkv.operation.results", operation, result); results != want {
					t.Errorf("%s results=%d want=%d", operation, results, want)
				}
			}
		})
	}
}

// full_only: false
func TestPublicationTelemetryOutcomeFacts(t *testing.T) {
	for _, test := range []struct {
		name                string
		disposition, marker uint8
		arms, sends         int
		label               telemetry.Result
		severity            string
	}{
		{"ack", contract.PublicationOutcomeAcknowledged, contract.PublicationAcknowledged, 1, 1, telemetry.ResultWriteAcknowledged, "INFO"},
		{"cleanup_failure", contract.PublicationOutcomeAcknowledged, contract.PublicationAcknowledged, 1, 1, telemetry.ResultFailure, "ERROR"},
		{"qualified_no_effect", contract.PublicationOutcomeQualifiedNoEffect, contract.PublicationQualifiedNoEffectState, 1, 1, telemetry.ResultFailure, "ERROR"},
		{"unknown", contract.PublicationOutcomeUnknown, contract.PublicationUnknown, 1, 1, telemetry.ResultUnknown, "WARN"},
		{"wrong_result", contract.PublicationOutcomeUnknown, contract.PublicationUnknown, 1, 1, telemetry.ResultUnknown, "WARN"},
		{"lost_selection", contract.PublicationOutcomeUnknown, contract.PublicationMayHaveEntered, 0, 0, telemetry.ResultUnknown, "WARN"},
		{"cancel_after_arm", contract.PublicationOutcomeUnknown, contract.PublicationMayHaveEntered, 1, 0, telemetry.ResultUnknown, "WARN"},
		{"close_refused", contract.PublicationOutcomeUnknown, contract.PublicationMayHaveEntered, 1, 1, telemetry.ResultUnknown, "WARN"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, input, private := publicationEngineFixture(t)
			// Complete source capture is independent of best-effort background delivery.
			if test.name == "cleanup_failure" {
				entries := f.session.currentEntryInputs()
				entries[0].InputBytes = []byte("PRIVATE-PAYLOAD-VALUE-SENTINEL")
				parent := admitSuppliedComparison(t, f.session, nil, entries)
				comparison, state := f.session.Compare(t.Context(), entries, parent)
				if comparison == nil || state.Outcome != ObservedCurrent {
					t.Fatal("value change comparison missing")
				}
				candidate := prepare(t, f, comparison)
				if state := f.session.Select(t.Context(), candidate); state.Outcome != ObservedCurrent {
					t.Fatal("value change selection failed")
				}
				publicationEngineReopen(t, f)
			}
			before := f.session.currentEntryInputs()
			capture := newPublicationDiagnosticCapture()
			recorder := capture.recorder
			points := make(chan telemetry.MetricPoint, 2048)
			exporter := tracetest.NewInMemoryExporter()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
			t.Cleanup(func() {
				if err := provider.Shutdown(context.Background()); err != nil {
					t.Error(err)
				}
			})
			capability := telemetry.NewCapabilityWithTracers(points, recorder, map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: provider.Tracer(telemetry.ScopeName)})
			ctx, cancel := context.WithCancel(telemetry.WithCapability(t.Context(), capability))
			defer cancel()
			switch test.name {
			case "cleanup_failure":
				private.configureOwner = func(owner *publicationControlledOwner) {
					owner.retireError = errors.New("PRIVATE-CREDENTIAL-ERROR-SENTINEL")
				}
			case "qualified_no_effect":
				private.evidence = contract.PublicationQualifiedNoEffect
			case "unknown":
				private.evidence = contract.PublicationUnproved
			case "wrong_result":
				private.corrupt = true
			case "cancel_after_arm":
				private.configureOwner = func(owner *publicationControlledOwner) { owner.onArm = cancel }
			case "close_refused":
				private.onSend = func() { f.store.casMode = "refused" }
			}
			plan, state := f.session.planPublication(ctx, input, private.callbacks())
			capture.collect()
			if plan == nil || state.Outcome != ObservedCurrent {
				t.Fatal("admitted plan missing")
			}
			if test.name == "lost_selection" {
				f.store.casMode = "lost-after"
			}
			got := plan.execute(ctx, private.callbacks(), capture.current(publicationEngineCurrent(f)))
			if len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 1 {
				t.Fatal("complete result vector changed")
			}
			row := got.output.Entries[0].Actions[0]
			if row.Disposition != test.disposition || row.AttemptID.IsZero() || len(private.owners) != 1 || private.owners[0].armed != test.arms || private.owners[0].sent != test.sends || private.owners[0].retired != 1 {
				t.Fatalf("result disposition=%d arms=%d sends=%d retires=%d", row.Disposition, private.owners[0].armed, private.owners[0].sent, private.owners[0].retired)
			}
			if test.name == "cleanup_failure" && (got.state != refused(CustodyUnavailable) || got.summary != contract.PublicationSummaryComplete || private.owners[0].prepared != 1) {
				t.Fatal("cleanup failure changed complete ACK or one-use preparation", got.state)
			}
			if _, err := contract.EncodePublicationOutcomeVector(got.output); err != nil {
				t.Fatal(err)
			}
			f.store.casMode = ""
			selected := publicationEngineReopen(t, f)
			if selected.markers[row.AttemptID].State != test.marker || !reflect.DeepEqual(before, f.session.currentEntryInputs()) {
				t.Fatal("selected effect/canonical values changed")
			}
			records := drainNativePublicationDiagnostics(t, capture)
			var returned telemetry.DiagnosticRecord
			starts, returns := map[uint64]telemetry.DiagnosticRecord{}, map[uint64]telemetry.DiagnosticRecord{}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Event == telemetry.DiagnosticStart {
					starts[record.Call] = record
				}
				if record.Event == telemetry.DiagnosticReturn {
					returns[record.Call] = record
				}
				if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpCorePublicationExecute {
					returned = record
				}
				if record.Path != "" || record.EntryName != "" || record.KeyID != "" || record.ErrorDetail != "" {
					t.Fatal("unreviewed publication data entered diagnostics")
				}
				if record.Operation == telemetry.OpCorePublicationPrepareReservation || record.Operation == telemetry.OpCorePublicationPrepareClose {
					if record.CommandID != hex.EncodeToString(plan.operation[:]) || record.AttemptID != hex.EncodeToString(row.AttemptID[:]) {
						t.Fatal("publication identity missing")
					}
				}
			}
			if returned.Result != test.label || returned.SeverityText != test.severity || returned.CommandID != hex.EncodeToString(plan.operation[:]) {
				t.Fatalf("execute result=%s severity=%s", returned.Result, returned.SeverityText)
			}
			if test.name == "cleanup_failure" && returned.Reason != telemetry.DiagnosticReasonCustodyUnavailable {
				t.Fatal("cleanup error reason changed", returned.Reason)
			}
			if len(starts) != len(returns) {
				t.Fatalf("starts=%d returns=%d", len(starts), len(returns))
			}
			spans := map[string]tracetest.SpanStub{}
			for _, span := range exporter.GetSpans() {
				spans[span.SpanContext.SpanID().String()] = span
			}
			for id, start := range starts {
				end, ok := returns[id]
				span, found := spans[start.SpanID]
				if !ok || !found || span.EndTime.IsZero() || start.SpanID != end.SpanID || start.TraceID != end.TraceID || span.Name != string(start.Operation) {
					t.Fatal("call/span return link missing")
				}
				if start.ParentCall != 0 {
					parent, ok := starts[start.ParentCall]
					if !ok || parent.TraceID != start.TraceID || span.Parent.SpanID().String() != parent.SpanID {
						t.Fatal("child span lost Core parent")
					}
				}
			}
			if test.name == "cleanup_failure" && len(spans) != len(starts) {
				t.Fatal("cleanup span census differs from its calls")
			}
			counts := map[telemetry.Operation]int64{}
			type operationResult struct {
				operation telemetry.Operation
				result    telemetry.Result
			}
			metricCalls := map[telemetry.Operation]int64{}
			metricResults := map[operationResult]int64{}
			var metricStrings []string
			for len(points) != 0 {
				point := <-points
				if test.name == "cleanup_failure" {
					if point.Barrier != nil {
						t.Fatal("unexpected metric barrier")
					}
					metricStrings = append(metricStrings, string(point.Name), string(point.Provider), string(point.Operation), string(point.Result), point.Status)
					if point.Name == telemetry.OperationCalls || point.Name == telemetry.OperationResults {
						if point.IntValue != 1 {
							t.Fatal("operation metric is not one occurrence")
						}
						if point.Name == telemetry.OperationCalls {
							metricCalls[point.Operation]++
						} else {
							metricResults[operationResult{point.Operation, point.Result}]++
						}
					}
				}
				if point.Name == telemetry.OperationCalls {
					counts[point.Operation] += point.IntValue
				}
				if point.Name == telemetry.OperationResults {
					counts[point.Operation] -= point.IntValue
				}
			}
			for operation, count := range counts {
				if count != 0 {
					t.Fatal("unmatched metric calls", operation, count)
				}
			}
			if test.name == "cleanup_failure" {
				wantCalls := map[telemetry.Operation]int64{}
				wantResults := map[operationResult]int64{}
				for _, record := range starts {
					wantCalls[record.Operation]++
				}
				for _, record := range returns {
					wantResults[operationResult{record.Operation, record.Result}]++
				}
				if metricCalls[telemetry.OpCorePublicationExecute] != 1 || metricResults[operationResult{telemetry.OpCorePublicationExecute, telemetry.ResultFailure}] != 1 || !reflect.DeepEqual(metricCalls, wantCalls) || !reflect.DeepEqual(metricResults, wantResults) {
					t.Fatal("cleanup metric census differs from complete call/result facts", metricCalls, metricResults, wantCalls, wantResults)
				}
			}
			if status := recorder.Status(); status.Accepted != uint64(len(records)) || status.Rejected != 0 || status.DroppedFull != 0 || status.DroppedContention != 0 || status.DroppedClosed != 0 || capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 || capability.LostTraces() != 0 {
				t.Fatal("telemetry evidence incomplete", status)
			}
			if test.name == "cleanup_failure" {
				for _, signal := range []any{records, exporter.GetSpans(), metricStrings} {
					body, err := json.Marshal(signal)
					if err != nil {
						t.Fatal("source telemetry encoding", err)
					}
					for _, sentinel := range []string{"PRIVATE-PAYLOAD-VALUE-SENTINEL", "PRIVATE-CREDENTIAL-ERROR-SENTINEL"} {
						if bytes.Contains(body, []byte(sentinel)) {
							t.Fatal("private data entered complete source telemetry")
						}
					}
				}
			}
		})
	}
}

// full_only: false
func TestPublicationTelemetryRefusalNoOpAndCleanup(t *testing.T) {
	t.Run("admission_refused", func(t *testing.T) {
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
		var session *StateSession
		plan, state := session.planPublication(ctx, publicationInput{}, publicationPrivate{})
		if plan != nil || state != refused(AdmissionInvalid) {
			t.Fatal("refusal changed")
		}
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512))
		if len(records) != 3 || records[2].Result != telemetry.ResultAdmissionRefused || records[2].Reason != telemetry.DiagnosticReasonAdmissionInvalid || records[2].SeverityText != "WARN" {
			t.Fatal("admission refusal diagnostic missing")
		}
	})
	for _, mode := range []string{"current_unavailable", "cancel_before_reserve"} {
		t.Run(mode, func(t *testing.T) {
			f, input, private := publicationEngineFixture(t)
			plan := publicationEnginePlan(t, f, input, private)
			recorder := telemetry.NewRecorder()
			ctx, cancel := context.WithCancel(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder)))
			defer cancel()
			current := publicationEngineCurrent(f)
			if mode == "current_unavailable" {
				current = nil
			} else {
				cancel()
			}
			got := plan.execute(ctx, private.callbacks(), current)
			if got.state != refused(AdmissionInvalid) || got.output.Entries[0].Actions[0].Disposition != contract.PublicationNotSent || len(private.owners) != 0 {
				t.Fatal("pre-reserve refusal acquired rights")
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512))
			var returned telemetry.DiagnosticRecord
			for _, record := range records {
				if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpCorePublicationExecute {
					returned = record
				}
			}
			if returned.Result != telemetry.ResultAdmissionRefused || returned.Reason != telemetry.DiagnosticReasonAdmissionInvalid || returned.SeverityText != "WARN" {
				t.Fatal("execute refusal became terminal effect failure")
			}
		})
	}
	t.Run("mixed_complete_vector", func(t *testing.T) {
		f, input, private := publicationEngineFixture(t)
		entries := f.session.currentEntryInputs()
		a, b := publicationEngineTarget(entries[0].Name, "first"), publicationEngineTarget(entries[0].Name, "second")

		selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "first", targets: []outputApplyTarget{a}}, {destinationID: "second", targets: []outputApplyTarget{b}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"first", "second"}}}})
		pins := []publicationNamespace{{domain: f.session.root.Domain, service: "controlled-provider", physical: "first", premise: publicationRelationID(99)}, {domain: f.session.root.Domain, service: "controlled-provider", physical: "second", premise: publicationRelationID(99)}}
		f.admission.admission.publicationNamespaces, f.session.admission.publicationNamespaces = pins, pins
		private.configureOwner = func(owner *publicationControlledOwner) {
			if len(private.owners) == 1 {
				owner.evidence = contract.PublicationQualifiedNoEffect
			}
		}
		capture := newPublicationDiagnosticCapture()
		recorder := capture.recorder
		ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
		plan, state := f.session.planPublication(ctx, input, private.callbacks())
		capture.collect()
		if plan == nil || state.Outcome != ObservedCurrent {
			t.Fatal("mixed plan missing")
		}
		got := plan.execute(ctx, private.callbacks(), capture.current(publicationEngineCurrent(f)))
		if got.summary != contract.PublicationSummaryMixedTerminal || len(got.output.Entries) != 2 || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || got.output.Entries[1].Actions[0].Disposition != contract.PublicationOutcomeQualifiedNoEffect || bytes.Compare(got.output.Entries[0].CoordinateID[:], got.output.Entries[1].CoordinateID[:]) >= 0 {
			t.Fatal("mixed complete vector changed")
		}
		records := drainNativePublicationDiagnostics(t, capture)
		var returned telemetry.DiagnosticRecord
		for _, record := range records {
			if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpCorePublicationExecute {
				returned = record
			}
		}
		if returned.Result != telemetry.ResultFailure || returned.SeverityText != "ERROR" {
			t.Fatal("mixed terminal failure hidden by selected observation")
		}
	})
	t.Run("no_op", func(t *testing.T) {
		f, input, private := publicationEngineFixture(t)
		publicationEnginePlan(t, f, input, private).execute(t.Context(), private.callbacks(), publicationEngineCurrent(f))
		publicationEngineReopen(t, f)
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
		checks, owners := private.checks, len(private.owners)
		plan, state := f.session.planPublication(ctx, input, private.callbacks())
		if plan == nil || state.Outcome != ObservedCurrent {
			t.Fatal("no-op plan missing")
		}
		got := plan.execute(ctx, private.callbacks(), publicationEngineCurrent(f))
		if got.summary != contract.PublicationSummaryNoChange || private.checks != checks || len(private.owners) != owners {
			t.Fatal("no-op acquired private work")
		}
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512))
		var returned telemetry.DiagnosticRecord
		for _, record := range records {
			if record.Operation == telemetry.OpCorePublicationExecute && record.Event == telemetry.DiagnosticReturn {
				returned = record
			}
			if record.Operation == telemetry.OpCorePublicationPrepareReservation || record.Operation == telemetry.OpCorePublicationPrepareClose {
				t.Fatal("no-op recorded an action")
			}
		}
		if returned.Result != telemetry.ResultUnchanged || returned.SeverityText != "INFO" {
			t.Fatal("no-op diagnostic missing")
		}
	})
	for _, mode := range []string{"ack", "unknown", "persist_refused", "unarmed"} {
		t.Run("cleanup_"+mode, func(t *testing.T) {
			f, input, private := publicationEngineFixture(t)
			capture := newPublicationDiagnosticCapture()
			recorder := capture.recorder
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			private.configureOwner = func(owner *publicationControlledOwner) {
				owner.retireError = errors.New("PRIVATE-CREDENTIAL-ERROR-SENTINEL")
				switch mode {
				case "unknown":
					owner.evidence = contract.PublicationUnproved
				case "persist_refused":
					f.store.createMode = "conflict"
				case "unarmed":
					f.store.casMode = "lost-after"
				}
			}
			plan, state := f.session.planPublication(ctx, input, private.callbacks())
			capture.collect()
			if plan == nil || state.Outcome != ObservedCurrent {
				t.Fatal("plan missing")
			}
			got := plan.execute(ctx, private.callbacks(), capture.current(publicationEngineCurrent(f)))
			if got.state != refused(CustodyUnavailable) || len(private.owners) != 1 || private.owners[0].retired != 1 {
				t.Fatal("cleanup result/right changed")
			}
			want := uint8(contract.PublicationOutcomeAcknowledged)
			if mode == "unknown" || mode == "unarmed" {
				want = contract.PublicationOutcomeUnknown
			}
			if mode == "persist_refused" {
				want = contract.PublicationNotSent
			}
			if got.output.Entries[0].Actions[0].Disposition != want {
				t.Fatal("cleanup erased effect outcome")
			}
			if _, err := contract.EncodePublicationOutcomeVector(got.output); err != nil {
				t.Fatal(err)
			}
			records := drainNativePublicationDiagnostics(t, capture)
			var returned telemetry.DiagnosticRecord
			for _, record := range records {
				if record.Operation == telemetry.OpCorePublicationExecute && record.Event == telemetry.DiagnosticReturn {
					returned = record
				}
			}
			if returned.Result != telemetry.ResultFailure || returned.Reason != telemetry.DiagnosticReasonCustodyUnavailable || returned.SeverityText != "ERROR" {
				t.Fatal("cleanup failure was hidden by effect/state")
			}
			wire, err := json.Marshal(records)
			if err != nil || bytes.Contains(wire, []byte("PRIVATE-CREDENTIAL-ERROR-SENTINEL")) {
				t.Fatal("private error entered telemetry")
			}
		})
	}
}

// full_only: false
func TestPublicationTelemetryPanicHasNoReturn(t *testing.T) {
	f, input, private := publicationEngineFixture(t)
	plan := publicationEnginePlan(t, f, input, private)
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	func() {
		defer func() {
			if recover() != "PRIVATE-PANIC-SENTINEL" {
				t.Fatal("panic did not propagate")
			}
		}()
		plan.execute(ctx, private.callbacks(), func(context.Context) (*StateSession, contract.Trust, Result) { panic("PRIVATE-PANIC-SENTINEL") })
	}()
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512))
	if len(records) != 2 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint {
		t.Fatal("panic emitted a normal return")
	}
	wire, err := json.Marshal(records)
	if err != nil || strings.Contains(string(wire), "PRIVATE-PANIC-SENTINEL") {
		t.Fatal("panic text entered telemetry")
	}
}

// full_only: false
func TestPublicationTelemetryLaterRefusalKeepsTerminalFailure(t *testing.T) {
	for _, first := range []uint8{contract.PublicationRequestAcknowledged, contract.PublicationQualifiedNoEffect} {
		for _, cut := range []string{"admission", "reservation"} {
			name := "ack_then_" + cut
			if first == contract.PublicationQualifiedNoEffect {
				name = "no_effect_then_" + cut
			}
			t.Run(name, func(t *testing.T) {
				f, input, private := publicationEngineFixture(t)
				entries := f.session.currentEntryInputs()
				a, b := publicationEngineTarget(entries[0].Name, "first"), publicationEngineTarget(entries[0].Name, "second")

				selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "first", targets: []outputApplyTarget{a}}, {destinationID: "second", targets: []outputApplyTarget{b}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"first", "second"}}}})
				pins := []publicationNamespace{{domain: f.session.root.Domain, service: "controlled-provider", physical: "first", premise: publicationRelationID(99)}, {domain: f.session.root.Domain, service: "controlled-provider", physical: "second", premise: publicationRelationID(99)}}
				f.admission.admission.publicationNamespaces, f.session.admission.publicationNamespaces = pins, pins
				private.evidence = first
				callbacks := private.callbacks()
				check, checks := callbacks.Check, 0
				callbacks.Check = func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
					checks++
					if cut == "reservation" && checks == 4 {
						return publicationActionCheckFacts{}, errors.New("PRIVATE-CHECK-ERROR-SENTINEL")
					}
					return check(ctx, in)
				}
				capture := newPublicationDiagnosticCapture()
				recorder := capture.recorder
				ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
				plan, state := f.session.planPublication(ctx, input, callbacks)
				capture.collect()
				if plan == nil || state.Outcome != ObservedCurrent {
					t.Fatal("complete plan missing")
				}
				current, calls := publicationEngineCurrent(f), 0
				got := plan.execute(ctx, callbacks, capture.current(func(ctx context.Context) (*StateSession, contract.Trust, Result) {
					calls++
					if cut == "admission" && calls == 3 {
						return nil, nil, refused(AdmissionInvalid)
					}
					return current(ctx)
				}))
				wantReason, wantDiagnostic := AdmissionInvalid, telemetry.DiagnosticReasonAdmissionInvalid
				if cut == "reservation" {
					wantReason, wantDiagnostic = InvalidIntent, telemetry.DiagnosticReasonInvalidIntent
				}
				wantSummary, wantDisposition, wantMarker := uint8(contract.PublicationSummaryMixedTerminal), uint8(contract.PublicationOutcomeAcknowledged), uint8(contract.PublicationAcknowledged)
				if first == contract.PublicationQualifiedNoEffect {
					wantSummary, wantDisposition, wantMarker = contract.PublicationSummaryFailed, contract.PublicationOutcomeQualifiedNoEffect, contract.PublicationQualifiedNoEffectState
				}
				if got.state != refused(wantReason) || got.summary != wantSummary || len(got.output.Entries) != 2 || len(got.output.Entries[0].Actions) != 1 || len(got.output.Entries[1].Actions) != 1 {
					t.Fatal("later refusal changed complete result/state")
				}
				done, refusedRow := got.output.Entries[0].Actions[0], got.output.Entries[1].Actions[0]
				if done.Disposition != wantDisposition || refusedRow.Disposition != contract.PublicationNotSent || !refusedRow.AttemptID.IsZero() || refusedRow.CoreReason != uint16(wantReason) || bytes.Compare(got.output.Entries[0].CoordinateID[:], got.output.Entries[1].CoordinateID[:]) >= 0 {
					t.Fatal("later refusal erased or reordered effect facts")
				}
				selected := publicationEngineReopen(t, f)
				if selected.markers[done.AttemptID].State != wantMarker || len(private.owners) != 1 || private.owners[0].armed != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 1 {
					t.Fatal("later refusal changed selected evidence/rights")
				}
				if _, err := contract.EncodePublicationOutcomeVector(got.output); err != nil {
					t.Fatal(err)
				}
				records := drainNativePublicationDiagnostics(t, capture)
				var returned telemetry.DiagnosticRecord
				for _, record := range records {
					if record.Operation == telemetry.OpCorePublicationExecute && record.Event == telemetry.DiagnosticReturn {
						returned = record
					}
				}
				if returned.Result != telemetry.ResultFailure || returned.SeverityText != "ERROR" || returned.Reason != wantDiagnostic {
					t.Fatalf("terminal failure result=%s severity=%s reason=%s", returned.Result, returned.SeverityText, returned.Reason)
				}
				wire, err := json.Marshal(records)
				if err != nil || bytes.Contains(wire, []byte("PRIVATE-CHECK-ERROR-SENTINEL")) {
					t.Fatal("raw check error entered telemetry")
				}
			})
		}
	}
}

// full_only: false
func TestPublicationTelemetryStartupKeepsValuesAndErrorsOutOfSignals(t *testing.T) {
	for _, configured := range []bool{false, true} {
		name, config := "default", []byte(`{"schema_version":1}`)
		if configured {
			name = "local_signals"
			var err error
			config, err = os.ReadFile(filepath.Join("tests", "telemetry", "local.json"))
			if err != nil {
				t.Fatal(err)
			}
		}
		t.Run(name, func(t *testing.T) {
			settings, err := observability.Decode(config, observability.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !configured && (settings.LogLevel != observability.Warn || !settings.Console || len(settings.MetricExporters) != 0 || len(settings.TraceExporters) != 0 || len(settings.LogExporters) != 0) {
				t.Fatal("default WARN console/no-export controls changed")
			}
			var console bytes.Buffer
			directory := t.TempDir()
			runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: directory, Console: &console})
			if err != nil {
				t.Fatal(err)
			}
			closeRuntime := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := runtime.Close(ctx); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(closeRuntime)
			f, input, private := publicationEngineFixture(t)
			entries := f.session.currentEntryInputs()
			entries[0].InputBytes = []byte("PRIVATE-PAYLOAD-VALUE-SENTINEL")
			parent := admitSuppliedComparison(t, f.session, nil, entries)
			comparison, state := f.session.Compare(t.Context(), entries, parent)
			if comparison == nil || state.Outcome != ObservedCurrent {
				t.Fatal("value change comparison missing")
			}
			candidate := prepare(t, f, comparison)
			if state := f.session.Select(t.Context(), candidate); state.Outcome != ObservedCurrent {
				t.Fatal("value change selection failed")
			}
			publicationEngineReopen(t, f)
			before := f.session.currentEntryInputs()
			private.configureOwner = func(owner *publicationControlledOwner) {
				owner.retireError = errors.New("PRIVATE-CREDENTIAL-ERROR-SENTINEL")
			}
			ctx := runtime.Context(t.Context())
			plan, state := f.session.planPublication(ctx, input, private.callbacks())
			if plan == nil || state.Outcome != ObservedCurrent {
				t.Fatal("plan missing")
			}
			got := plan.execute(ctx, private.callbacks(), publicationEngineCurrent(f))
			if got.state != refused(CustodyUnavailable) || got.summary != contract.PublicationSummaryComplete || len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 1 || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || len(private.owners) != 1 || private.owners[0].prepared != 1 || private.owners[0].armed != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 1 {
				t.Fatal("telemetry changed cleanup/effect")
			}
			selected := publicationEngineReopen(t, f)
			if selected.markers[got.output.Entries[0].Actions[0].AttemptID].State != contract.PublicationAcknowledged || !reflect.DeepEqual(before, f.session.currentEntryInputs()) {
				t.Fatal("startup changed selected ACK or canonical values")
			}
			closeRuntime()
			capture := runtime.RecorderStatus()
			statuses := runtime.DeliveryStatuses()
			if !capture.Closed || capture.Rejected != 0 || capture.DroppedClosed != 0 {
				t.Fatalf("invalid settled log capture: %+v", capture)
			}
			captureLoss := capture.DroppedContention + capture.DroppedFull
			checkLogs := func(status observability.DeliveryStatus, records uint64, cleanupFailure bool) {
				t.Helper()
				if status.Accepted != status.Written || status.Failed != 0 || status.Dropped < captureLoss || status.Incomplete != (status.Dropped != 0) || records != status.Written || status.Written == 0 && status.Dropped == 0 {
					t.Fatalf("log delivery accounting: status=%+v records=%d recorder=%+v", status, records, capture)
				}
				if status.Dropped == 0 && !cleanupFailure {
					t.Fatal("complete log delivery omitted ERROR cleanup failure")
				}
			}
			bodies := [][]byte{console.Bytes()}
			if configured {
				if len(statuses) != 3 || len(console.Bytes()) != 0 {
					t.Fatal("local startup activated an unselected signal route")
				}
				for _, signal := range []string{"logs", "metrics", "traces"} {
					status, present := statuses[signal+".local"]
					if !present {
						t.Fatal("selected signal status missing", signal)
					}
					body, err := os.ReadFile(filepath.Join(directory, "telemetry", signal+".jsonl"))
					if err != nil && (signal != "logs" || !os.IsNotExist(err) || status.Written != 0 || status.Dropped == 0) {
						t.Fatal("local signal read failed", signal, err)
					}
					bodies = append(bodies, body)
					if signal != "logs" {
						if len(body) == 0 || status.Incomplete || status.Written == 0 || status.Accepted != status.Written || status.Failed != 0 || status.Dropped != 0 {
							t.Fatalf("signal delivery incomplete: signal=%s status=%+v recorder=%+v signals=%+v", signal, status, capture, statuses)
						}
						continue
					}
					var records uint64
					cleanupFailure := false
					if len(body) != 0 {
						if body[len(body)-1] != '\n' {
							t.Fatal("incomplete OTLP log line")
						}
						for _, line := range bytes.Split(bytes.TrimSuffix(body, []byte{'\n'}), []byte{'\n'}) {
							var batch struct {
								ResourceLogs []struct {
									ScopeLogs []struct {
										LogRecords []struct {
											SeverityText string `json:"severityText"`
											Attributes   []struct {
												Key   string `json:"key"`
												Value struct {
													StringValue string `json:"stringValue"`
												} `json:"value"`
											} `json:"attributes"`
										} `json:"logRecords"`
									} `json:"scopeLogs"`
								} `json:"resourceLogs"`
							}
							if err := json.Unmarshal(line, &batch); err != nil {
								t.Fatal("invalid OTLP log line", err)
							}
							for _, resource := range batch.ResourceLogs {
								for _, scope := range resource.ScopeLogs {
									for _, record := range scope.LogRecords {
										records++
										attributes := map[string]string{}
										for _, attribute := range record.Attributes {
											attributes[attribute.Key] = attribute.Value.StringValue
										}
										cleanupFailure = cleanupFailure || record.SeverityText == "ERROR" && attributes["operation"] == "core.publication.execute" && attributes["event"] == "return" && attributes["result"] == "failure" && attributes["reason"] == "custody_unavailable"
									}
								}
							}
						}
					}
					checkLogs(status, records, cleanupFailure)
				}
			} else {
				if _, err := os.Stat(filepath.Join(directory, "telemetry")); !os.IsNotExist(err) {
					t.Fatal("default startup created export files")
				}
				status, present := statuses["logs.console"]
				if !present || len(statuses) != 1 {
					t.Fatal("default startup changed console route")
				}
				var records uint64
				cleanupFailure := false
				if console.Len() != 0 {
					if console.Bytes()[console.Len()-1] != '\n' {
						t.Fatal("incomplete console log line")
					}
					for _, line := range strings.Split(strings.TrimSuffix(console.String(), "\n"), "\n") {
						records++
						cleanupFailure = cleanupFailure || strings.Contains(line, " ERROR (17) ") && strings.Contains(line, `operation="core.publication.execute"`) && strings.Contains(line, `event="return"`) && strings.Contains(line, `result="failure"`) && strings.Contains(line, `reason="custody_unavailable"`)
					}
				}
				checkLogs(status, records, cleanupFailure)
			}
			for _, body := range bodies {
				for _, sentinel := range []string{"PRIVATE-PAYLOAD-VALUE-SENTINEL", "PRIVATE-CREDENTIAL-ERROR-SENTINEL"} {
					if bytes.Contains(body, []byte(sentinel)) {
						t.Fatal("private data entered a telemetry signal")
					}
				}
			}
		})
	}
}
