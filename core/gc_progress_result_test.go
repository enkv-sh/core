package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func gcSelectRuntimePhase(t *testing.T, ctx context.Context, state *StateSession, plan contract.GCPlan, progress contract.GCProgress, phase contract.GCPhase) *StateSession {
	t.Helper()
	candidate, result := state.prepareGCPhase(ctx, plan, gcTestID("runtime-state-admission"), phase, &progress)
	if candidate == nil {
		t.Fatal("prepare real runtime phase", phase, result)
	}
	candidate, result = state.persistCandidate(ctx, candidate, testtrust.New(t, contract.GCP, state.admission.trust))
	if candidate == nil {
		t.Fatal("persist real runtime phase", phase, result)
	}
	selected := state.selectGCCandidate(ctx, candidate)
	if !selected.confirmed {
		t.Fatal("select real runtime phase", phase, selected.result)
	}
	return selected.state
}

// full_only: false
func TestGCContinueRetainsCapturedProgressOnFactoryRefusal(t *testing.T) {
	state, store, input, plan, encoded := gcExecutionFixture(t)
	ctx := gcReadContext(t)
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	proof, result := reader.ValidateGCPlan(ctx, encoded)
	if proof == nil || !proof.consume(ctx) {
		t.Fatal("real original validation", result)
	}
	reader.Close()
	progress, err := gcInitialProgress(plan)
	if err != nil {
		t.Fatal(err)
	}
	state = gcSelectRuntimePhase(t, ctx, state, plan, progress, contract.GCSelect)
	progress.Ordinal++
	progress.Targets[0].Consumed = 1
	state = gcSelectRuntimePhase(t, ctx, state, plan, progress, contract.GCReserve)
	progress.Ordinal++
	progress.Targets[0].Disposition = contract.GCTargetUnknown
	state = gcSelectRuntimePhase(t, ctx, state, plan, progress, contract.GCRecordProgress)
	state = gcSelectRuntimePhase(t, ctx, state, plan, progress, contract.GCClose)
	reader, err = NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("retained GC mutation construction cause")
	engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) { return GCMutationResources{}, sentinel }})
	if err != nil {
		t.Fatal(err)
	}
	out := engine.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("failed-resume"), OperationID: plan.OperationID})
	if out.Payload == nil || out.Payload.ProgressOrdinal != progress.Ordinal || out.Payload.RemainingCount != progress.RemainingCount || out.Payload.Active || !reflect.DeepEqual(out.Payload.Targets[0].Selected, progress.Targets[0]) {
		t.Error("factory refusal lost authenticated retained progress", out)
	}
	if len(store.deletes) != 0 {
		t.Error("construction refusal dispatched delete", store.deletes)
	}
	if err := engine.Close(); err != nil || !errors.Is(engine.OperationError(), sentinel) {
		t.Error("constructor cause was discarded or became a cleanup failure", err, engine.OperationError())
	}
}

// full_only: false
func TestGCResultObservationNamesLastConfirmedSelection(t *testing.T) {
	state, store, input, _, encoded := gcExecutionFixture(t)
	ctx := gcReadContext(t)
	var selected []byte
	store.onCAS = func(phase contract.GCPhase, body []byte) *contract.WriteResult {
		if phase == contract.GCSelect {
			selected = bytes.Clone(body)
		}
		if phase == contract.GCReserve {
			return &contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
		}
		return nil
	}
	engine, _ := gcExecutionEngine(t, state, store, input)
	out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("select-then-reserve-conflict"), EncodedPlan: encoded})
	if len(selected) == 0 {
		t.Fatal("real select did not occur", out.Result)
	}
	head, err := format.DecodeHead(selected)
	if err != nil {
		t.Fatal(err)
	}
	want := PublicObservation{DomainID: state.root.Domain, HeadRevisionID: head.Core.Revision, SnapshotID: head.Core.Root.Object, RootDigest: head.Core.Root.Digest}
	if out.Result.Outcome != Contention || out.Payload == nil || out.Payload.ProgressOrdinal != 1 || !out.Payload.Active || out.Payload.Observation != want || out.Result.ObservedRevision != want.HeadRevisionID {
		t.Fatal("selected progress has another observation basis", out.Result, out.Payload, want)
	}
	if len(store.deletes) != 0 {
		t.Fatal("reserve conflict dispatched deletion", store.deletes)
	}
}
