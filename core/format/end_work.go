package format

import "enkv.sh/core/contract"

func endWorkHeadRelations(h Head, core []byte) bool {
	if h.AuthKind != AdministrativeAuth || len(h.K3) != 0 && !signatureValid(h.K3) || h.Core.Form != SuccessorHead || h.EndWork == nil ||
		h.Subject != (contract.LifecycleSubject{}) || h.Genesis != nil || h.Succession != nil || h.Generator != nil ||
		h.EndWork.DomainID != h.Core.Domain || h.EndWork.PredecessorRevisionID != h.Core.PreviousRevision ||
		h.EndWork.PredecessorFullHEADDigest != h.Core.PreviousDigest ||
		h.EndWork.PredecessorToken != h.Core.PreviousToken ||
		h.EndWork.HeadCoreDigest != contract.Hash(core) || h.EndWork.HeadCoreLength != uint32(len(core)) {
		return false
	}
	condition, err := contract.MatchHeadCondition(h.Core.PreviousToken)
	if err != nil {
		return false
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: h.Core.PreviousToken.Family,
		Store: h.Core.Store, Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody,
		Condition: condition, HeadCore: h.EndWork.HeadCoreDigest, HeadCoreLength: h.EndWork.HeadCoreLength})
	return err == nil && h.EndWork.ConditionalPlanDigest == contract.Hash(plan)
}
