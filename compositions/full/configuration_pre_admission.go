package compositionfull

import (
	"context"
	"crypto/rand"
	"errors"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type preAdmissionIdentityRecord struct {
	Schema        string `json:"schema"`
	OperationID   string `json:"operation_id"`
	OperationKind string `json:"operation_kind"`
	Stage         string `json:"stage"`
	Code          string `json:"code"`
	RequestNonce  string `json:"request_nonce,omitempty"`
	SourceSchema  string `json:"source_schema"`
	SourceProfile string `json:"source_profile"`
	Format        string `json:"format,omitempty"`
}

func configurationPreAdmission(format configuration.Format, nonce contract.ID) (contract.ID, *core.PreAdmissionRequestIdentity, error) {
	var operation contract.ID
	if _, err := rand.Read(operation[:]); err != nil || operation.IsZero() {
		return operation, nil, errors.New("operation correlation unavailable")
	}
	q := &core.PreAdmissionRequestIdentity{Stage: "dispatch", Code: string(contract.ReasonInvalidInput), RequestNonce: nonce,
		SourceSchema: "enkv/configuration/v3", SourceProfile: "direct-candidate"}
	q.Format = configurationSourceFormat(format)
	return operation, q, nil
}

func configurationSourceFormat(format configuration.Format) string {
	switch format {
	case configuration.JSON:
		return "json"
	case configuration.YAML:
		return "yaml"
	}
	return ""
}

func preAdmissionIdentity(operation string, id contract.ID, q *core.PreAdmissionRequestIdentity) (preAdmissionIdentityRecord, bool) {
	if q == nil || id.IsZero() || q.SourceSchema != "enkv/configuration/v3" || q.SourceProfile != "direct-candidate" ||
		q.Format != "" && q.Format != "json" && q.Format != "yaml" || !validPreAdmissionStage(q.Stage) ||
		!validReaderReason(contract.DiagnosticReason(q.Code)) && !validSetFailureStage(q.Code) && q.Code != "unsupported-apply-change" {
		return preAdmissionIdentityRecord{}, false
	}
	return preAdmissionIdentityRecord{Schema: "PreAdmissionRequestIdentity/v1", OperationID: readerID(id), OperationKind: operation,
		Stage: q.Stage, Code: q.Code, RequestNonce: readerID(q.RequestNonce), SourceSchema: q.SourceSchema, SourceProfile: q.SourceProfile, Format: q.Format}, true
}

func validPreAdmissionStage(stage string) bool {
	if validSetFailureStage(stage) {
		return true
	}
	switch stage {
	case "context", "output", "capture", "parse", "declaration", "construction", "resolution", "observation", "installation", "initialize", "apply", "compare", "rekey", "retire":
		return true
	}
	return false
}

func configurationFailureCode(ctx context.Context, err error) string {
	result := configurationComparisonFailure(ctx, contract.ID{}, contract.ID{}, "source", err)
	return configurationFailureReasonCode(err, result.Diagnostics[0].Reason)
}

func configurationFailureReasonCode(err error, reason contract.DiagnosticReason) string {
	var diagnostic *configuration.Diagnostic
	if reason == contract.ReasonInvalidInput && errors.As(err, &diagnostic) && diagnostic.Reason == "unsupported-apply-change" {
		return diagnostic.Reason
	}
	return string(reason)
}

// NewApplyRefusal reports invalid command fields without source or provider access.
func NewApplyRefusal(format configuration.Format) (core.PublicApplyResult, error) {
	id, q, err := configurationPreAdmission(format, contract.ID{})
	return core.PublicApplyResult{OperationID: id, PreAdmission: q, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}}, err
}

// NewInitializationRefusal reports invalid command fields without source access.
func NewInitializationRefusal(format configuration.Format) (InitializationResult, error) {
	id, q, err := configurationPreAdmission(format, contract.ID{})
	return InitializationResult{PublicInitializationResult: core.PublicInitializationResult{OperationID: id,
		Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.InitializationRefused, EffectSummary: "effect-no-change"}, PreAdmission: q}, err
}

// NewComparisonRefusal reports invalid command fields without Reader construction.
func NewComparisonRefusal(format configuration.Format) (ConfigurationComparisonResult, error) {
	id, q, err := configurationPreAdmission(format, contract.ID{})
	out := configurationComparisonFailure(context.Background(), contract.ID{}, contract.ID{}, "source", nil)
	out.Context.OperationID, out.PreAdmission = id, q
	return out, err
}
