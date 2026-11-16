package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type capacityPanicSource struct {
	PublicCapacityReader
	boundary   string
	panicValue error
	panics     *atomic.Int32
	closes     *atomic.Int32
}

func (r *capacityPanicSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if r.boundary == "selected-read" {
		r.panics.Add(1)
		panic(r.panicValue)
	}
	return r.PublicCapacityReader.Read(ctx, key, limit)
}

func (r *capacityPanicSource) ListPage(ctx context.Context, cursor string) contract.ListPageResult {
	if r.boundary == "list" {
		r.panics.Add(1)
		panic(r.panicValue)
	}
	return r.PublicCapacityReader.ListPage(ctx, cursor)
}

func (r *capacityPanicSource) Close() {
	r.closes.Add(1)
	r.PublicCapacityReader.Close()
}

func capacityReaderInvoke(ctx context.Context, reader *InstalledCapacityReader, operation telemetry.Operation, encoded []byte) Result {
	switch operation {
	case telemetry.OpCoreInspectCapacity:
		return reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: gcTestID("capacity-panic-inspect")}).Result
	case telemetry.OpCoreGCPlan:
		return reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("capacity-panic-plan"), OperationID: gcTestID("capacity-panic-operation")}).Result
	default:
		_, result := reader.ValidateGCPlan(ctx, encoded)
		return result
	}
}

func assertCapacityReaderTelemetry(t *testing.T, recorder *telemetry.Recorder, points chan telemetry.MetricPoint, capability *telemetry.Capability, operation telemetry.Operation, completed bool) {
	t.Helper()
	starts, returns := 0, 0
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512)) {
		if record.Operation != operation {
			continue
		}
		if record.Event == telemetry.DiagnosticStart {
			starts++
		}
		if record.Event == telemetry.DiagnosticReturn {
			returns++
		}
	}
	calls, results, durations := 0, 0, 0
	for len(points) != 0 {
		point := <-points
		if point.Operation != operation {
			continue
		}
		switch point.Name {
		case telemetry.OperationCalls:
			calls++
		case telemetry.OperationResults:
			results++
		case telemetry.OperationDuration:
			durations++
		}
	}
	wantCompleted := 0
	if completed {
		wantCompleted = 1
	}
	if starts != 1 || calls != 1 || returns != wantCompleted || results != wantCompleted || durations != wantCompleted || capability.LostMetrics() != 0 {
		t.Error("reader telemetry has wrong completion counts", starts, calls, returns, results, durations, capability.LostMetrics())
	}
}

func assertReaderInvocationReleased(t *testing.T, reader *ReaderEngine) {
	t.Helper()
	reader.mu.Lock()
	active := reader.activeDone
	reader.mu.Unlock()
	if active != nil {
		t.Error("panic retained reader invocation ownership")
		// The initial source-check defect owns no constructed source. Release the
		// test's leaked invocation before Close so the regression cannot hang.
		(&readerInvocation{engine: reader, done: active}).Close()
	}
}

type readerAdmissionPanicContext struct {
	context.Context
	reader     *ReaderEngine
	panicValue error
	acquired   bool
}

func (c *readerAdmissionPanicContext) Done() <-chan struct{} {
	c.reader.mu.Lock()
	c.acquired = c.reader.activeDone != nil
	c.reader.mu.Unlock()
	panic(c.panicValue)
}

// full_only: false
func TestReaderInvocationAdmissionPanicReleasesOwnership(t *testing.T) {
	_, _, input, _, _ := gcExecutionFixture(t)
	var installedCloses atomic.Int32
	input.CloseInstalled = func() { installedCloses.Add(1) }
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("reader admission context Done panic")
	ctx := &readerAdmissionPanicContext{Context: gcReadContext(t), reader: reader.reader, panicValue: sentinel}
	completed := false
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		reader.reader.beginReaderInvocation(ctx, InspectCapacityOperation, gcTestID("admission-context-panic"))
		completed = true
	}()
	if recovered != sentinel || completed || !ctx.acquired {
		t.Error("context callback did not propagate its panic after invocation acquisition", recovered, completed, ctx.acquired)
	}
	assertReaderInvocationReleased(t, reader.reader)
	reader.Close()
	reader.Close()
	if installedCloses.Load() != 1 {
		t.Error("admission panic cleanup did not join installed ownership once", installedCloses.Load())
	}
}

// full_only: false
func TestCapacityReaderPanicKeepsIncompleteTelemetryAndJoinsClose(t *testing.T) {
	for _, operation := range []telemetry.Operation{telemetry.OpCoreInspectCapacity, telemetry.OpCoreGCPlan, telemetry.OpCoreGCValidatePlan} {
		for _, boundary := range []string{"initial-source", "selected-read", "list"} {
			if operation == telemetry.OpCoreGCValidatePlan && boundary == "list" {
				continue // Artifact validation has no LIST reach.
			}
			t.Run(string(operation)+"/"+boundary, func(t *testing.T) {
				_, store, input, _, encoded := gcExecutionFixture(t)
				sentinel := errors.New("capacity reader callback panic")
				var panics, sourceCloses, installedCloses atomic.Int32
				construct := input.Construct
				input.Construct = func(ctx context.Context, configuration contract.StoreConfiguration) (PublicCapacityReader, Result) {
					source, result := construct(ctx, configuration)
					if source == nil {
						return nil, result
					}
					return &capacityPanicSource{PublicCapacityReader: source, boundary: boundary, panicValue: sentinel, panics: &panics, closes: &sourceCloses}, result
				}
				if boundary == "initial-source" {
					input.CheckSource = func(context.Context) error {
						panics.Add(1)
						panic(sentinel)
					}
				}
				input.CloseInstalled = func() { installedCloses.Add(1) }
				reader, err := NewInstalledCapacityReader(input)
				if err != nil {
					t.Fatal(err)
				}
				recorder := telemetry.NewRecorder()
				points := make(chan telemetry.MetricPoint, 512)
				capability := telemetry.NewCapability(points, recorder)
				ctx := telemetry.WithCapability(gcReadContext(t), capability)
				completed := false
				var recovered any
				func() {
					defer func() { recovered = recover() }()
					capacityReaderInvoke(ctx, reader, operation, encoded)
					completed = true
				}()
				if recovered != sentinel || completed || panics.Load() != 1 {
					t.Error("callback panic was replaced or returned normally", recovered, completed, panics.Load())
				}
				assertReaderInvocationReleased(t, reader.reader)
				reader.Close()
				reader.Close()
				wantSourceCloses := int32(1)
				if boundary == "initial-source" {
					wantSourceCloses = 0
				}
				if sourceCloses.Load() != wantSourceCloses || installedCloses.Load() != 1 {
					t.Error("panic cleanup did not join each owner once", sourceCloses.Load(), installedCloses.Load())
				}
				assertCapacityReaderTelemetry(t, recorder, points, capability, operation, false)
				if len(store.phases) != 0 || len(store.deletes) != 0 {
					t.Error("public callback panic reached mutation", store.phases, store.deletes)
				}
			})
		}
	}
}

// full_only: false
func TestPublicReadersInitialSourcePanicReleasesInvocation(t *testing.T) {
	for _, operation := range []telemetry.Operation{telemetry.OpCoreInspect, telemetry.OpCoreInspectRecipient, telemetry.OpCoreReceiptList, telemetry.OpCoreReceiptDetail} {
		t.Run(string(operation), func(t *testing.T) {
			state, _, input, _, _ := gcExecutionFixture(t)
			sentinel := errors.New("initial public source check panic")
			var installedCloses atomic.Int32
			input.CloseInstalled = func() { installedCloses.Add(1) }
			reader, err := NewInstalledCapacityReader(input)
			if err != nil {
				t.Fatal(err)
			}
			checkSource := func(context.Context) error { panic(sentinel) }
			inspection := &InstalledInspectionReader{reader: reader.reader, pins: input.SourcePins, checkSource: checkSource}
			receipts := &InstalledReceiptReader{reader: reader.reader, pins: input.SourcePins, checkSource: checkSource, composition: state.admission.composition}
			ctx := gcReadContext(t)
			completed := false
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				switch operation {
				case telemetry.OpCoreInspect:
					inspection.Inspect(ctx, DomainInspectionRequest{RequestNonce: gcTestID("inspection-source-panic")})
				case telemetry.OpCoreInspectRecipient:
					inspection.InspectRecipient(ctx, RecipientInspectionRequest{RequestNonce: gcTestID("recipient-source-panic"), RecipientID: gcTestID("recipient")})
				case telemetry.OpCoreReceiptList:
					receipts.List(ctx, ReceiptListRequest{RequestNonce: gcTestID("receipts-source-panic")})
				case telemetry.OpCoreReceiptDetail:
					receipts.Detail(ctx, ReceiptDetailRequest{RequestNonce: gcTestID("receipt-source-panic"), OperationID: gcTestID("receipt")})
				}
				completed = true
			}()
			if recovered != sentinel || completed {
				t.Error("initial source panic was replaced or returned normally", recovered, completed)
			}
			assertReaderInvocationReleased(t, reader.reader)
			inspection.Close()
			receipts.Close()
			if installedCloses.Load() != 1 {
				t.Error("panic cleanup did not join the installed owner once", installedCloses.Load())
			}
		})
	}
}

// full_only: false
func TestCapacityReaderNormalReturnCompletesTelemetryOnce(t *testing.T) {
	for _, operation := range []telemetry.Operation{telemetry.OpCoreInspectCapacity, telemetry.OpCoreGCPlan, telemetry.OpCoreGCValidatePlan} {
		for _, refusal := range []bool{false, true} {
			name := "success"
			if refusal {
				name = "source-refusal"
			}
			t.Run(string(operation)+"/"+name, func(t *testing.T) {
				_, _, input, _, encoded := gcExecutionFixture(t)
				var installedCloses atomic.Int32
				input.CloseInstalled = func() { installedCloses.Add(1) }
				if refusal {
					input.CheckSource = func(context.Context) error { return errors.New("changed source") }
				}
				reader, err := NewInstalledCapacityReader(input)
				if err != nil {
					t.Fatal(err)
				}
				recorder := telemetry.NewRecorder()
				points := make(chan telemetry.MetricPoint, 512)
				capability := telemetry.NewCapability(points, recorder)
				result := capacityReaderInvoke(telemetry.WithCapability(gcReadContext(t), capability), reader, operation, encoded)
				want := ObservedCurrent
				if refusal {
					want = AdmissionRefused
				}
				if result.Outcome != want {
					t.Error("normal return changed its result", result, want)
				}
				assertReaderInvocationReleased(t, reader.reader)
				reader.Close()
				reader.Close()
				if installedCloses.Load() != 1 {
					t.Error("normal return did not close installed ownership once", installedCloses.Load())
				}
				assertCapacityReaderTelemetry(t, recorder, points, capability, operation, true)
			})
		}
	}
}
