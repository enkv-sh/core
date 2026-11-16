package compositionfull

import (
	"context"
	"io"
)

func WriteGCPlanJSON(ctx context.Context, out io.Writer, result GCPlanResult) error {
	return writeGCPlanResult(ctx, out, result, false)
}
func WriteGCPlanHuman(ctx context.Context, out io.Writer, result GCPlanResult) error {
	return writeGCPlanResult(ctx, out, result, true)
}

func writeGCPlanResult(ctx context.Context, out io.Writer, result GCPlanResult, human bool) error {
	if result.Operation.Validate() != nil || result.Delivery.PlanReadback && !result.Delivery.PlanSynced || result.Delivery.PlanSynced && !result.Delivery.PlanCreated {
		return ErrPublicQueryResult
	}
	var emit func(*queryObject)
	kind := "none"
	if p := result.Operation.Payload; p != nil {
		kind = "CleanupPayload/v1"
		emit = func(q *queryObject) {
			q.field("schema", kind)
			q.field("phase", "preview")
			q.object("observation", func(o *queryObject) { queryObservation(o, p.Observation) })
			q.id("proposed_operation_id", p.Plan.OperationID)
			q.id("plan_digest", p.PlanDigest)
			q.id("request_identity", p.RequestIdentity)
			q.id("full_head_digest", p.Plan.FullHEADDigest)
			q.id("source_pins_digest", p.Plan.SourcePinsDigest)
			q.id("public_basis_digest", p.Plan.PublicBasisDigest)
			q.id("store_descriptor_digest", p.Plan.StoreDescriptorDigest)
			q.field("selected", false)
			q.field("consumed_allowances", 0)
			q.object("garbage", func(o *queryObject) { queryGCCandidatePage(o, p.Garbage) })
		}
	}
	// A local delivery failure remains separate from a successful public
	// preview. No preview or protected file is a selected delete permission.
	return writePublicQueryDelivery(ctx, out, result.Operation.PublicQueryResult, human, kind, emit, func(w *resultStreamWriter) {
		if human {
			w.text("Observation limit: one page; no Store snapshot\nThe plan is a preview; no delete permission is selected.\n")
		}
	}, &result.Delivery, result.SourceFailure)
}

func GCPlanExitCode(result GCPlanResult) int {
	if result.Delivery.PlanFailed || result.Delivery.CleanupFailed {
		return 2
	}
	if result.Operation.StateResult == "success" && !result.Delivery.PlanReadback {
		return 2
	}
	return PublicQueryExitCode(result.Operation.PublicQueryResult)
}
