package core

import (
	"context"

	"enkv.sh/core/contract"
)

func (s *StateSession) generatedOriginalVerificationRequest(ctx context.Context, plan *generatedLifecyclePlan) (contract.CryptoGeneratedCompareRequest, observationSource, error) {
	if plan == nil || plan.kind != generatedLifecycleReflection && plan.kind != generatedLifecycleCleanupClose ||
		!s.generatedContextValid(plan.context) || contract.Hash(plan.result) != plan.evidence {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, contract.ErrRecord
	}
	result, err := contract.InspectGeneratedResultRecord(plan.result)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	selection, ok, err := g.selectGeneratedCleanup(ctx, map[contract.ID][]byte{result.Core.ResultID: plan.result})
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	if !ok || selection.kind != generatedCleanupReflection || selection.sourceKey().id != plan.owner ||
		selection.closeOwner != (plan.kind == generatedLifecycleCleanupClose) {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, contract.ErrRecord
	}
	owner, err := contract.InspectGeneratedDeleteSource(g.records[selection.sourceKey()])
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	a := selection.attempt
	graph, err := g.content.graphForOperation(a.record.OperationID)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	descriptor, err := contract.GeneratorPlanBundleDescriptor(graph)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	use, err := contract.GeneratorUsePlanDigest(graph.UsePlan)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	target := contract.EmptyGeneratorVector(contract.GeneratorVectorTargets)
	if a.expected.Template.Action == contract.GeneratorActionDelete {
		target = owner.Target
	}
	q := contract.CryptoGeneratedCompareRequest{Context: plan.context, Purpose: contract.CryptoGeneratedOriginalVerificationPurpose, Original: a.record,
		OriginalResult: contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID,
			ResultBodyDigest: contract.Hash(plan.result), ResultLength: uint32(len(plan.result))},
		PlanGraph: descriptor, UsePlanDigest: use, MaterialID: a.material.Core.OperationMaterialID,
		OriginalOwnerKind: owner.Record.Kind, OriginalOwnerID: plan.owner, Target: target}
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	if _, err := contract.EncodeCryptoGeneratedCompareRequest(q); err != nil {
		return contract.CryptoGeneratedCompareRequest{}, observationSource{}, err
	}
	source := generatedExchangeSource(q)

	return q, source, nil
}
