package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGCReceivedConstructionFailureKeepsUnknownEffect(t *testing.T) {
	for _, invalid := range []contract.WriteResult{
		{Status: contract.WriteUnknown, Reason: contract.ReasonConstruction, NotSent: true},
		{Status: contract.WriteAcknowledged, Reason: contract.ReasonConstruction},
		{Status: contract.WriteUnknown, Reason: 255},
		{Status: 255, Reason: contract.ReasonConstruction},
	} {
		if normalized, malformed := gcNormalizeWriteResult(invalid); !malformed || normalized != (contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}) {
			t.Fatal("construction reason admitted an impossible write tuple", invalid, normalized)
		}
	}
	state, store, input, _, encoded := gcExecutionFixture(t)
	providerResult := contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonConstruction}
	store.onDelete = func(string, contract.Token) *contract.WriteResult { return &providerResult }
	engine, _ := gcExecutionEngine(t, state, store, input)
	out := engine.ApplyPlan(gcReadContext(t), GCApplyPlanRequest{RequestNonce: gcTestID("received-construction"), EncodedPlan: encoded})
	if out.Validate() != nil || out.Payload == nil || len(out.Payload.Targets) != 1 || len(store.deletes) != 1 {
		t.Fatal("received construction failure lost selected GC result", out)
	}
	row := out.Payload.Targets[0]
	if !row.DeleteAttempted || row.DeleteResult != providerResult || row.Selected.Consumed != 1 || row.Selected.Disposition != contract.GCTargetUnknown || !row.Selected.EvidenceDigest.IsZero() {
		t.Fatal("received construction failure changed cause or restored dispatch rights", row)
	}
	if token, err := GCTargetEffectToken(row); err != nil || token != "unknown" {
		t.Fatal("received construction failure claimed a stronger effect", token, err)
	}
}

// full_only: false
func TestGCNotSentAccessKeepsConsumedCallbackSeparateFromRetry(t *testing.T) {
	state, store, input, plan, encoded := gcExecutionFixture(t)
	providerResult := contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
	store.onDelete = func(string, contract.Token) *contract.WriteResult { return &providerResult }
	ctx := gcReadContext(t)
	engine, _ := gcExecutionEngine(t, state, store, input)
	out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("not-sent-access"), EncodedPlan: encoded})
	if out.Validate() != nil || out.Payload == nil || len(out.Payload.Targets) != 1 || len(store.deletes) != 1 || out.StateResult != "gc-partial-garbage" {
		t.Fatal("access refusal lost current GC result", out)
	}
	row := out.Payload.Targets[0]
	if !row.DeleteAttempted || row.DeleteResult != providerResult || row.Selected.Consumed != 1 || row.Selected.Disposition != contract.GCTargetTerminalFailure || !row.Selected.EvidenceDigest.IsZero() {
		t.Fatal("access refusal lost one consumed callback or invented retry evidence", row)
	}
	if token, err := GCTargetEffectToken(row); err != nil || token != "not-started" {
		t.Fatal("positive not-sent fact did not describe this invocation", token, err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	continued, _ := gcExecutionEngine(t, state, store, input)
	next := continued.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("not-sent-access-continuation"), OperationID: plan.OperationID})
	if next.Validate() != nil || next.Payload == nil || next.Payload.Targets[0].Selected.Consumed != 1 || next.Payload.Targets[0].Selected.Disposition == contract.GCTargetRetryableNotSent || len(store.deletes) != 1 {
		t.Fatal("access refusal restored a spent callback", next)
	}
}
