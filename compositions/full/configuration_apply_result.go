package compositionfull

import (
	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type ConfigurationApplyResult struct {
	core.PublicApplyResult
	SourceFailure *ConfigurationSourceFailure
	storeLocation *resultStoreLocation
}

// The installed invocation still returns its unchanged Core DTO. These two
// explicit consumers retain only composition-owned source/location facts.
type configurationMutationResultFacts struct {
	sourceFailure **ConfigurationSourceFailure
	storeLocation **resultStoreLocation
}

func mutationSourceFailureTarget(facts []configurationMutationResultFacts) **ConfigurationSourceFailure {
	if len(facts) == 0 {
		return nil
	}
	return facts[0].sourceFailure
}

func retainMutationStoreLocation(facts []configurationMutationResultFacts, model *configuration.Model, result core.PublicApplyResult) {
	if len(facts) != 0 && facts[0].storeLocation != nil {
		*facts[0].storeLocation = newMutationResultStoreLocation(model, result)
	}
}

func (r ConfigurationApplyResult) render(operation uint16, human bool) ([]byte, error) {
	if !validConfigurationAdmissionSourceFailure(r.SourceFailure, r.PreAdmission, r.RequestIdentity, r.Result) || !validSourceFailureDiagnostics(r.SourceFailure, r.Diagnostics) || r.SourceFailure != nil && (r.Generated != nil || r.Cleanup != nil || r.RetirementBlockers != nil || r.Payload != nil || len(r.Receipt) != 0) {
		return nil, errApplyResult
	}
	if r.storeLocation != nil {
		if r.SourceFailure != nil || r.Generated == nil {
			return nil, errApplyResult
		}
		actual := operation
		if operation == contract.OperationApplyDeclaration {
			actual = r.Generated.OperationKind
			if actual != contract.OperationApplyDeclaration && actual != contract.OperationRotateValueEntryValue {
				return nil, errApplyResult
			}
		}
		return renderGeneratedMutation(r.PublicApplyResult, actual, human, r.storeLocation)
	}
	if r.SourceFailure == nil {
		if operation == contract.OperationApplyDeclaration {
			if human {
				return RenderApplyHuman(r.PublicApplyResult)
			}
			return RenderApplyJSON(r.PublicApplyResult)
		}
		return renderGeneratedMutation(r.PublicApplyResult, operation, human)
	}
	v, err := transitionResultProjection(r.PublicApplyResult, operation)
	if err != nil {
		return nil, err
	}
	v.SourceFailure = r.SourceFailure
	if human {
		return renderTransitionHuman(r.PublicApplyResult, v)
	}
	return renderTransitionResultJSON(v)
}

func (r ConfigurationApplyResult) RenderJSON() ([]byte, error) {
	return r.render(contract.OperationApplyDeclaration, false)
}
func (r ConfigurationApplyResult) RenderHuman() ([]byte, error) {
	return r.render(contract.OperationApplyDeclaration, true)
}
func (r ConfigurationApplyResult) RenderGeneratedJSON(operation uint16) ([]byte, error) {
	return r.render(operation, false)
}
func (r ConfigurationApplyResult) RenderGeneratedHuman(operation uint16) ([]byte, error) {
	return r.render(operation, true)
}
