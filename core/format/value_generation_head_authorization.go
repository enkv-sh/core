package format

import "enkv.sh/core/contract"

func generatorHeadRelations(p Head, core []byte) bool {
	if p.Core.Form != SuccessorHead || p.Generator == nil || p.Genesis != nil || p.Succession != nil ||
		p.Subject != (contract.LifecycleSubject{}) || len(p.K3) != 0 && !signatureValid(p.K3) {
		return false
	}
	s := *p.Generator
	if _, err := contract.NewGeneratorRequest(s); err != nil || s.DomainID != p.Core.Domain ||
		s.PreviousRevisionID != p.Core.PreviousRevision || s.PreviousHEADDigest != p.Core.PreviousDigest ||
		s.AfterRootDigest != p.Core.Root.Digest || s.HeadCoreDigest != contract.Hash(core) || s.HeadCoreLength != uint32(len(core)) {
		return false
	}
	condition, err := contract.MatchHeadCondition(p.Core.PreviousToken)
	if err != nil {
		return false
	}
	digest, err := contract.CryptoConditionDigest(condition)
	if err != nil || s.ConditionDigest != digest {
		return false
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: p.Core.PreviousToken.Family, Store: p.Core.Store,
		Coordinate: p.Core.Coordinate, NonBody: p.Core.NonBody, Condition: condition,
		HeadCore: s.HeadCoreDigest, HeadCoreLength: s.HeadCoreLength})
	return err == nil && s.ConditionalPlanDigest == contract.Hash(plan) && s.ConditionalLength == uint32(len(plan))
}
