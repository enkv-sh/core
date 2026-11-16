package compositionfull

import (
	"fmt"

	"enkv.sh/core"
)

// The closed projection has at most twelve structural levels, so human
// indentation is at most 24 bytes. Field labels retain the existing key bytes
// and replace JSON framing with ": " and LF. An array count/row label adds at
// most 32 bytes, including a full-width decimal index. A scalar row adds at
// most 88 bytes for its two indents, row label, "Value: " and LF; its scalar
// and comma/open bracket occupy at least two compact bytes. Object rows and
// count headings charge their braces/brackets and existing key framing. Thus
// 60*C covers all row layout and unchanged escaped/Base64 scalar bytes.
//
// Repeated receipt, hazard, release and action explanations cost less than
// 6*C: receipt warnings total below 1,200 bytes per row with three mandatory
// IDs; hazard explanations below 1,024 with at least five mandatory IDs;
// release explanations below 768 with at least six IDs; and action lines
// below 320 with either their exact IDs or the shorter no-ID command. Their
// closed row framing pays the remaining text. 67*C covers both accounts.
//
// The separate 8,192-byte fixed reserve pays 1,024 for command/outcome/IDs,
// 2,048 for one source failure, 1,024 for one Store location, 2,048 for singleton
// warnings, and 2,048 for plan delivery, unavailable-data and final text. No
// complete document image is retained: validation/count and write stream the
// same borrowed facts. Map sorting retains keys for only one fixed-size row.
const publicQueryHumanOutputLimit = 67*publicQueryCompactOutputLimit + 8192

func publicQueryHumanHeading(operation string) string {
	switch operation {
	case core.InspectOperation:
		return "Domain inspection"
	case core.InspectRecipientOperation:
		return "Recipient inspection"
	case core.InspectCapacityOperation:
		return "Capacity inspection"
	case core.ReceiptListOperation:
		return "Receipt list"
	case core.ReceiptDetailOperation:
		return "Receipt detail"
	case core.GCPlanOperation:
		return "GC plan"
	}
	return operation
}

func writePublicQueryHuman(w *resultStreamWriter, base core.PublicQueryResult, emit func(*queryObject), warnings func(*resultStreamWriter), delivery *GCPlanDelivery, sourceFailure *ConfigurationSourceFailure, location *resultStoreLocation) {
	w.text(publicQueryHumanHeading(base.Operation) + ": " + string(base.StateResult) + "\n")
	if base.FailureReason != "" {
		w.text("Reason: " + string(base.FailureReason) + "\n")
	}
	w.text(configurationSourceFailureHuman(sourceFailure))
	if record, ok := administrativeCoreResult(base.Result); ok && record.StoreReason != "" {
		w.text("Store failure: " + record.StoreReason + "\n")
	}
	evidence := "unavailable"
	if base.Result.Evidence == core.AuthenticatedClosure {
		evidence = "canonical"
	}
	w.text("Evidence ceiling: " + evidence + "\n")
	for _, p := range []struct {
		label string
		value any
	}{
		{"Request id", generatedID(base.RequestID)},
		{"Operation id", generatedID(base.OperationID)},
		{"Domain id", generatedID(base.DomainID)},
	} {
		if p.value != nil {
			w.text(p.label + ": ")
			w.value(p.value)
			w.text("\n")
		}
	}
	writeResultStoreLocationHuman(w, location)
	if warnings != nil {
		warnings(w)
	}
	if delivery != nil {
		w.text(fmt.Sprintf("Plan file created: %t\nPlan file synced: %t\nPlan file read back: %t\nPlan delivery failed: %t\nLocal source cleanup failed: %t\n", delivery.PlanCreated, delivery.PlanSynced, delivery.PlanReadback, delivery.PlanFailed, delivery.CleanupFailed))
	}
	if emit == nil {
		w.text("No query data is available.\n")
	} else {
		emit(&queryObject{w: w, human: true})
	}
	if base.Operation == core.GCPlanOperation {
		w.text("No remote objects were deleted.")
	} else {
		w.text("Query only; no domain changes were made.")
	}
	w.text("\n")
}

func inspectionGCProgressHuman(q *queryObject, v *gcProgressRecord) {
	q.field("plan_digest", v.Plan)
	q.field("targets_digest", v.TargetsDigest)
	q.field("targets_length", v.TargetsLength)
	q.field("target_count", v.TargetCount)
	q.field("request_identity", v.Request)
	q.field("observation_digest", v.Observation)
	q.field("remaining_count", v.Remaining)
	q.field("progress_ordinal", v.Ordinal)
	q.array("targets", len(v.Targets), func(i int) {
		row := q.begin()
		p := v.Targets[i]
		row.field("consumed", p.Consumed)
		row.field("disposition", p.Disposition)
		row.field("evidence_digest", p.Evidence)
	})
}
