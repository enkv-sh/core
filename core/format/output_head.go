package format

import "enkv.sh/core/contract"

func outputHeadRelations(h Head, core []byte) bool {
	if h.Core.Form != SuccessorHead || h.Subject != (contract.LifecycleSubject{}) ||
		h.Genesis != nil || h.Succession != nil || h.Generator != nil || h.EndWork != nil ||
		len(h.K3) != 0 && !signatureValid(h.K3) {
		return false
	}
	var domain, previousRevision, previousDigest, headCore, planDigest ID
	var previousToken contract.Token
	var headCoreLength uint32
	switch h.AuthKind {
	case OutputReserveAuth:
		if h.OutputReserve == nil || h.OutputClose != nil {
			return false
		}
		s := *h.OutputReserve
		if _, err := contract.NewOutputReserveRequest(s); err != nil {
			return false
		}
		domain, previousRevision, previousDigest, previousToken = s.DomainID, s.PredecessorRevisionID, s.PredecessorFullHEADDigest, s.PredecessorToken
		headCore, headCoreLength, planDigest = s.HeadCoreDigest, s.HeadCoreLength, s.ConditionalPlanDigest
	case OutputCloseAuth:
		if h.OutputClose == nil || h.OutputReserve != nil {
			return false
		}
		s := *h.OutputClose
		if _, err := contract.NewOutputCloseRequest(s); err != nil {
			return false
		}
		domain, previousRevision, previousDigest, previousToken = s.DomainID, s.PredecessorRevisionID, s.PredecessorFullHEADDigest, s.PredecessorToken
		headCore, headCoreLength, planDigest = s.HeadCoreDigest, s.HeadCoreLength, s.ConditionalPlanDigest
	default:
		return false
	}
	if domain != h.Core.Domain || previousRevision != h.Core.PreviousRevision ||
		previousDigest != h.Core.PreviousDigest || previousToken != h.Core.PreviousToken ||
		headCore != contract.Hash(core) || headCoreLength != uint32(len(core)) {
		return false
	}
	condition, err := contract.MatchHeadCondition(h.Core.PreviousToken)
	if err != nil {
		return false
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: h.Core.PreviousToken.Family,
		Store: h.Core.Store, Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody,
		Condition: condition, HeadCore: headCore, HeadCoreLength: headCoreLength})
	return err == nil && planDigest == contract.Hash(plan)
}
