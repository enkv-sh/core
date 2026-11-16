package compositionfull

import (
	"context"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func openMaintenancePlanningCustody(ctx context.Context, domain contract.ID, provider contract.Family, location contract.StoreLocation, expected contract.ControlCore, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
	if domain != admission.DomainID {
		return nil, contract.ErrRecord
	}
	if admission.Options.Purpose != contract.PlanningRetirementFeasibility && admission.Options.Purpose != contract.PlanningEquality {
		return nil, contract.ErrRecord
	}
	expectedRoute := contract.Hash(append([]byte("enkv/planning/authority-credential-route/v1\x00"), domain[:]...))
	if admission.CredentialRoute != expectedRoute {
		return nil, contract.ErrRecord
	}
	if !core.CurrentControlMatches(admission.Control, expected) {
		return nil, contract.ErrRecord
	}
	config, _, err := configurationApplyConfig(&configuration.Model{DomainID: domain, Provider: provider, Store: location}, admission.Control)
	if err != nil {
		return nil, err
	}
	config, err = LoadDefaultConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return newProviderMaintenancePlanningCustody(ctx, config, admission)
}
