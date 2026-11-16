package core

import (
	"context"

	"enkv.sh/core/contract"
)

func (s *StateSession) generatedRetirementResidueFixturePlan(ctx context.Context, dutyID contract.ID, admitted contract.ApplyContext) (*generatedLifecyclePlan, error) {
	return s.generatedRetirementAmbiguityPlan(ctx, dutyID, nil, admitted, true)
}

func (g *generatedSelection) generatedRetirementResidueFixture(ctx context.Context, dutyID contract.ID) (generatedResidueClosure, error) {
	return g.generatedRetirementResidueWithFactsFixture(ctx, dutyID, nil)
}

func (g *generatedSelection) generatedRetirementResidueWithFactsFixture(ctx context.Context, dutyID contract.ID, ambiguity []byte) (generatedResidueClosure, error) {
	return g.generatedRetirementAmbiguity(ctx, dutyID, ambiguity, true)
}

func (s *StateSession) preservedWorkSupportRecords(ctx context.Context) ([]contract.SupportRecord, error) {
	rows, err := s.workSupportRecords(ctx)
	if err != nil {
		return nil, err
	}
	return rebindSnapshotSliceRecords(rows, s.admission.domain, s.adminIndex.SliceSnapshot, s.admission.domain)
}

func planBodyBackedGeneratedCurrentIntents(ctx context.Context, s *StateSession, selected *generatedSelection,
	retained []contract.GeneratorSliceLocation) (generatedCurrentIntentProjection, error) {
	if selected == nil || selected.content == nil || selected.content.fragmentFacts != nil {
		return generatedCurrentIntentProjection{}, contract.ErrRecord
	}
	return planGeneratedCurrentIntents(ctx, s, selected, retained)
}

func emitBodyBackedGeneratedCurrentIntents(ctx context.Context, selected *generatedSelection, plan generatedCurrentIntentProjection) ([]contract.SupportRecord, error) {
	if selected == nil || selected.content == nil || selected.content.fragmentFacts != nil {
		return nil, contract.ErrRecord
	}
	return emitGeneratedCurrentIntents(ctx, selected, plan)
}
