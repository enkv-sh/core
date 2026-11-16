package core

import (
	"context"

	"enkv.sh/core/contract"
)

func (s *StateSession) admitGeneratedRetirementResidueFixture(dutyID contract.ID,
	admitted contract.ApplyContext) (*admittedGeneratedLifecycle, error) {
	plan, err := s.generatedRetirementAmbiguityPlan(context.Background(), dutyID, nil, admitted, true)
	if err != nil {
		return nil, err
	}
	return s.admitGeneratedLifecyclePlan(context.Background(), plan)
}
