package crypto

import "enkv.sh/core/contract"

func (a *generatedAdmission) deleteTarget() *contract.GeneratorTarget {
	switch {
	case a.purpose.reservation != nil:
		return a.purpose.reservation.target
	case a.purpose.adoption != nil:
		return a.purpose.adoption.target
	case a.purpose.final != nil:
		return a.purpose.final.target
	case a.purpose.producer != nil:
		return a.purpose.producer.target
	case a.purpose.verification != nil && !a.purpose.verification.target.ResourceDigest.IsZero():
		return &a.purpose.verification.target
	default:
		return nil
	}
}

func (a *generatedAdmission) deleteTargetTemplateMatches(x contract.GeneratorAttemptTemplate) bool {
	target := a.deleteTarget()
	if target == nil || x.Action != contract.GeneratorActionDelete {
		return false
	}
	t := *target
	if t.ResourceID != x.ResourceIncarnationID || t.ConfigContractID != x.ConfigContractID || t.ResourceContractID != x.ResourceContractID ||
		t.LifecycleMode != x.LifecycleMode || t.CompletionClass != x.CompletionClass {
		return false
	}
	found := false
	for _, lineage := range a.graph.Lineages {
		if lineage.LineageID != x.LineageID {
			continue
		}
		if found || lineage.Name != t.Name || lineage.EntryIncarnationID != t.IncarnationID || lineage.Epoch != t.Epoch {
			return false
		}
		found = true
		if lineage.Purpose == contract.GeneratorLineageRetirement {
			duty, err := contract.GeneratorDutyID(a.graph.Header.DomainID, t.OriginalOperationID, t.OriginalAttemptID, contract.GeneratedDutyRetirement)
			if err != nil || x.DutyID != duty {
				return false
			}
		}
		switch lineage.Purpose {
		case contract.GeneratorLineageRetirement:
			if x.TargetKind != contract.GeneratorTargetOwnedResource || x.TargetSourceID != t.ResourceID {
				return false
			}
		case contract.GeneratorLineageCleanup:
			transmission, err := contract.GeneratorTransmissionID(t.OriginalAttemptID, contract.GeneratorActionCreate)
			if err != nil {
				return false
			}
			result, err := contract.GeneratorResultID(a.graph.Header.DomainID, t.OriginalOperationID, t.OriginalAttemptID, transmission, contract.GeneratorActionCreate)
			if err != nil || x.TargetKind != contract.GeneratorTargetResultResourceSlot || x.TargetSourceID != result || t.OriginalOperationID == a.graph.Header.OperationID {
				return false
			}
		default:
			return false
		}
	}
	return found
}

func (a *generatedAdmission) deleteTargetSourceMatches(source contract.GeneratedDeleteSource, x contract.GeneratorAttemptTemplate) bool {
	if source.Record.Kind == contract.GeneratedDutySupportKind {
		return a.deleteTargetDutyMatches(source.Duty, x)
	}
	h := source.Hazard
	if !a.deleteTargetTemplateMatches(x) || h.DomainID != a.graph.Header.DomainID || h.OwnerID != x.DutyID ||
		h.ResourceID != x.ResourceIncarnationID || h.DescriptorID != x.DescriptorID || h.ConfigContractID != x.ConfigContractID ||
		h.ExecutorID != x.ExecutorID || h.CredentialRouteID != x.CredentialRouteID || h.ResourceContractID != x.ResourceContractID ||
		h.CompletionClass != x.CompletionClass || h.Fenced != 1 || h.Eligibility == 0 || h.Eligibility != h.Exposure {
		return false
	}
	target := a.deleteTarget()
	if target == nil {
		return false
	}
	body, err := contract.EncodeGeneratorTarget(*target)
	if err != nil {
		return false
	}
	descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{body})
	if err != nil || h.Target != descriptor {
		return false
	}
	for _, l := range a.graph.Lineages {
		if l.LineageID == x.LineageID {
			// A Hazard can be transferred from an unfinished retirement Duty.
			// Its older original graph keeps the retirement lineage, while a
			// fresh continuation for this same Hazard uses a cleanup lineage.
			return l.Purpose == contract.GeneratorLineageCleanup || l.Purpose == contract.GeneratorLineageRetirement
		}
	}
	return false
}

func (a *generatedAdmission) deleteTargetDutyMatches(d contract.GeneratedDutyRecord, x contract.GeneratorAttemptTemplate) bool {
	target := a.deleteTarget()
	if target == nil || !a.deleteTargetTemplateMatches(x) || d.DomainID != a.graph.Header.DomainID || d.OriginalOperationID != target.OriginalOperationID ||
		d.OriginalAttemptID != target.OriginalAttemptID {
		return false
	}
	body, err := contract.EncodeGeneratorTarget(*target)
	if err != nil {
		return false
	}
	descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{body})
	if err != nil || d.Target != descriptor {
		return false
	}
	if d.Kind == contract.GeneratedDutyUnselectedCleanup {
		owner, err := contract.GeneratorDutyID(d.DomainID, target.OriginalOperationID, target.OriginalAttemptID, contract.GeneratedDutyCreate)
		return err == nil && d.DutyID == owner && d.ResultContractID == target.ResultContractID
	}
	return d.Kind == contract.GeneratedDutyRetirement && d.ResultContractID == x.ResultContractID
}
