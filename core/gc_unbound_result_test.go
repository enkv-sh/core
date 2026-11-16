package core

import "testing"

// full_only: false
func TestGCUnboundRefusalAllowsOnlyLocalOperationIdentity(t *testing.T) {
	base := PublicGCResult{Operation: GCApplyOperation, OperationID: gcTestID("local-proposed-operation"), Result: refused(AdmissionInvalid), StateResult: "refused"}
	if err := base.Validate(); err != nil {
		t.Fatal("local operation identity rejected on unbound refusal", err)
	}
	for _, name := range []string{"operation", "request-identity", "domain", "result", "state", "effect", "output", "evidence", "counts", "payload"} {
		t.Run(name, func(t *testing.T) {
			out := base
			switch name {
			case "operation":
				out.Operation = "other"
			case "request-identity":
				out.RequestIdentity = gcTestID("unadmitted-request")
			case "domain":
				out.DomainID = gcTestID("unadmitted-domain")
			case "result":
				out.Result = refused(InvalidRelation)
			case "state":
				out.StateResult = "unavailable"
			case "effect":
				out.EffectSummary = 1
			case "output":
				out.OutputSummary = 1
			case "evidence":
				out.EvidenceCeiling = 1
			case "counts":
				out.SummaryCounts[0] = 1
			case "payload":
				out.Payload = &GCCleanupPayload{}
			}
			if err := out.Validate(); err == nil {
				t.Fatal("unbound refusal admitted facts beyond local operation identity", name)
			}
		})
	}
}
