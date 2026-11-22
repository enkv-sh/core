package format

import "enkv.sh/core/contract"

func GCPlansDescriptor(index AdministrativeIndex) (contract.GCDescriptor, error) {
	rows := make([]contract.GCOwner, 0)
	for _, group := range index.Groups {
		if group.OwnerKind == AdministrativeGC {
			if group.GC == nil {
				return contract.GCDescriptor{}, ErrFormat
			}
			rows = append(rows, contract.GCOwner{OperationID: group.GroupID, Progress: *group.GC})
		}
	}
	return contract.GCOwnersDescriptor(rows)
}
func GCGroupValid(group AdministrativeGroup) bool {
	if group.OwnerKind != AdministrativeGC {
		return group.GC == nil
	}
	return group.GC != nil && group.GC.Valid() && group.Affected == (contract.GeneratorDescriptor{Digest: group.GC.TargetsDescriptor.Digest, Length: group.GC.TargetsDescriptor.Length, Count: group.GC.TargetsDescriptor.Count}) && group.SelectedEvidenceSummary == group.GC.EvidenceSummary() && group.EffectEntryCeiling == group.GC.EffectEntryCeiling() && group.GroupID == group.OwnerID && group.GroupID == group.TargetID && group.DutyKind == 0 && group.DestructiveEffect == 0 && group.UncertainCreateProof == 0 && !group.ReferencesOwnedBirth && group.PublicationIncarnationID.IsZero() && group.AdmissionOrdinal == 0
}
func (group AdministrativeGroup) Own() AdministrativeGroup {
	if group.RelatedGroupIndexes != nil {
		group.RelatedGroupIndexes = append([]uint16{}, group.RelatedGroupIndexes...)
	}
	if group.GC != nil {
		v := group.GC.Own()
		group.GC = &v
	}
	return group
}
func SameGCProgress(a, b *contract.GCProgress) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return contract.GCProgressEqual(*a, *b)
}
func gcHeadRelations(h Head, core []byte) bool {
	if h.AuthKind != GCAuth || len(h.K3) > 0 && !signatureValid(h.K3) || h.Core.Form != SuccessorHead || h.GC == nil || h.Genesis != nil || h.Succession != nil || h.Generator != nil || h.EndWork != nil || h.OutputReserve != nil || h.OutputClose != nil || h.Subject != (contract.LifecycleSubject{}) {
		return false
	}
	q := h.GC
	if !q.Valid() || q.DomainID != h.Core.Domain || q.PredecessorRevisionID != h.Core.PreviousRevision || q.PredecessorFullHEADDigest != h.Core.PreviousDigest || q.PredecessorToken != h.Core.PreviousToken || q.HeadCoreDigest != contract.Hash(core) || q.HeadCoreLength != uint32(len(core)) {
		return false
	}
	condition, e := contract.MatchHeadCondition(h.Core.PreviousToken)
	if e != nil {
		return false
	}
	plan, e := EncodeConditionalPlan(ConditionalPlan{Family: h.Core.PreviousToken.Family, Store: h.Core.Store, Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody, Condition: condition, HeadCore: q.HeadCoreDigest, HeadCoreLength: q.HeadCoreLength})
	return e == nil && q.ConditionalPlanDigest == contract.Hash(plan)
}
