package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
)

type gcPanickingPublicReader struct {
	PublicCapacityReader
	panicValue error
	closes     *atomic.Int32
}

func (r *gcPanickingPublicReader) Read(context.Context, string, uint32) contract.ReadResult {
	panic(r.panicValue)
}
func (r *gcPanickingPublicReader) Close() {
	r.closes.Add(1)
	r.PublicCapacityReader.Close()
}

// full_only: false
func TestGCContinuePublicReadPanicReleasesReaderInvocation(t *testing.T) {
	state, store, input, plan, encoded := gcExecutionFixture(t)
	ctx := gcReadContext(t)
	state, _ = gcRuntimeSelectOnly(t, ctx, state, input, plan, encoded)
	phaseCount := len(store.phases)
	sentinel := errors.New("GC continuation public read panic")
	var sourceCloses, installedCloses atomic.Int32
	construct := input.Construct
	input.Construct = func(ctx context.Context, configuration contract.StoreConfiguration) (PublicCapacityReader, Result) {
		source, result := construct(ctx, configuration)
		if source == nil {
			return nil, result
		}
		return &gcPanickingPublicReader{PublicCapacityReader: source, panicValue: sentinel, closes: &sourceCloses}, result
	}
	input.CloseInstalled = func() { installedCloses.Add(1) }
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	factoryCalls := 0
	engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
		factoryCalls++
		return GCMutationResources{}, errors.New("unexpected mutation construction after public read panic")
	}})
	if err != nil {
		t.Fatal(err)
	}
	var recovered any
	completed := false
	func() {
		defer func() { recovered = recover() }()
		engine.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("public-read-panic"), OperationID: plan.OperationID})
		completed = true
	}()
	if recovered != sentinel || completed {
		t.Error("public read panic was replaced or returned normally", recovered, completed)
	}
	if factoryCalls != 0 || len(store.phases) != phaseCount || len(store.deletes) != 0 {
		t.Error("public read panic reached mutation", factoryCalls, store.phases, store.deletes)
	}
	reader.reader.mu.Lock()
	active := reader.reader.activeDone
	reader.reader.mu.Unlock()
	if active != nil || sourceCloses.Load() != 1 {
		// No Close call is safe while this fake-only leaked invocation is live.
		// Do not manufacture a join or block the test runner on the known defect.
		t.Fatal("public read panic retained invocation ownership", active != nil, sourceCloses.Load())
	}
	if err := engine.Close(); err != nil || installedCloses.Load() != 1 || sourceCloses.Load() != 1 {
		t.Fatal("panic cleanup did not join each owner once", err, installedCloses.Load(), sourceCloses.Load())
	}
}
