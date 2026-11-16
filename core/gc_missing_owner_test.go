package core

import "testing"

// full_only: false
func TestGCContinueMissingSelectedOwnerIsRefusal(t *testing.T) {
	state, store, input, plan, _ := gcExecutionFixture(t)
	engine, factories := gcExecutionEngine(t, state, store, input)
	out := engine.Continue(gcReadContext(t), GCContinueRequest{RequestNonce: gcTestID("missing-selected-owner-refusal"), OperationID: plan.OperationID})
	if out.Result.Outcome != AdmissionRefused || out.Result.Reason != InvalidRelation || out.StateResult != "refused" || out.Payload != nil {
		t.Error("valid absence of selected GC owner became corruption", out)
	}
	if *factories != 0 || len(store.phases) != 0 || len(store.deletes) != 0 {
		t.Fatal("missing selected owner reached mutation", *factories, store.phases, store.deletes)
	}
}
