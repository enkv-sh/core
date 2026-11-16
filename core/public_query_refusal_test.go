package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicQueryUnboundUnsupportedInputHasClosedProfileBlockedResult(t *testing.T) {
	for _, reason := range []contract.DiagnosticReason{contract.ReasonUnsupportedSchema, contract.ReasonUnsupportedProfile} {
		for _, operation := range []string{ReceiptListOperation, ReceiptDetailOperation, InspectOperation, InspectRecipientOperation, InspectCapacityOperation, GCPlanOperation} {
			t.Run(operation+"/"+string(reason), func(t *testing.T) {
				out := PublicQueryResult{Operation: operation, RequestID: contract.ID{1}, Result: refused(AdmissionInvalid), StateResult: PublicQueryProfileBlocked, FailureReason: reason}
				for _, local := range []bool{false, true} {
					if local {
						out.OperationID = contract.ID{2}
						out.PreAdmission = &PreAdmissionRequestIdentity{Stage: "capture", Code: string(reason), SourceSchema: "enkv/configuration/v1", SourceProfile: "direct-candidate", RequestNonce: out.RequestID}
					}
					var err error
					switch operation {
					case ReceiptListOperation:
						err = (PublicReceiptListResult{PublicQueryResult: out}).Validate()
					case ReceiptDetailOperation:
						err = (PublicReceiptDetailResult{PublicQueryResult: out}).Validate()
					case InspectOperation:
						err = (PublicDomainInspectionResult{PublicQueryResult: out}).ValidateMetadataWorkOutput()
					case InspectRecipientOperation:
						err = (PublicRecipientInspectionResult{PublicQueryResult: out}).Validate()
					case InspectCapacityOperation:
						err = (PublicCapacityInspectionResult{PublicQueryResult: out}).Validate()
					case GCPlanOperation:
						err = (PublicGCPreviewResult{PublicQueryResult: out}).Validate()
					}
					if err != nil {
						t.Error("closed unsupported-input failure rejected", local, err)
					}
				}
				for _, mutate := range []func(*PublicQueryResult){
					func(r *PublicQueryResult) { r.StateResult = PublicQueryRefused },
					func(r *PublicQueryResult) { r.Result = failure(EvidenceUnavailable, ReadUnavailable) },
					func(r *PublicQueryResult) { r.Result.CommitMayHaveOccurred = true },
					func(r *PublicQueryResult) { r.Result.Evidence = AuthenticatedClosure },
					func(r *PublicQueryResult) { r.Result.Reason = InvalidProof },
					func(r *PublicQueryResult) { r.Result.Reason = ReadUnavailable },
					func(r *PublicQueryResult) { r.Result.Reason = SigningUnavailable },
					func(r *PublicQueryResult) { r.Result.ObservedRevision = contract.ID{3} },
					func(r *PublicQueryResult) { r.Result.RequestedRevision = contract.ID{3} },
					func(r *PublicQueryResult) { r.RequestIdentity = contract.ID{3} },
					func(r *PublicQueryResult) { r.FailureReason = contract.ReasonInvalidInput },
				} {
					bad := out
					mutate(&bad)
					if validateUnboundPublicQuery(bad) == nil {
						t.Error("unsupported-input result admitted incompatible facts", bad)
					}
				}
			})
		}
	}
}
