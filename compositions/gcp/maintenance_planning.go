package compositiongcp

import (
	"context"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	provider "enkv.sh/providers/gcp"
)

// NewMaintenancePlanningCustody admits only the exact maintenance source check.
// It exposes no signer, Store writer or mutable Crypto runtime.
func NewMaintenancePlanningCustody(ctx context.Context, installed provider.KeyAccessConfig, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
	if admission.Options.Purpose != contract.PlanningRetirementFeasibility && admission.Options.Purpose != contract.PlanningEquality {
		return nil, contract.PlanningAdmissionError{Code: contract.CryptoInvalidAdmission}
	}
	return newPlanningCustody(ctx, installed, admission, nil)
}
