package contract

// SuccessorBranch returns the next branch permitted by this template.
func (v GeneratorAttemptTemplate) SuccessorBranch(guard uint8) (uint8, bool, error) {
	next, present, err := GeneratorSuccessorBranch(v.Branch, guard)
	if err != nil || !present {
		return 0, false, err
	}
	if v.Action != GeneratorActionCreate || v.NoEffectBudget == 0 && guard == GeneratorGuardQualifiedNoEffect || v.ResidueBudget == 0 && guard == GeneratorGuardResidue {
		return 0, false, nil
	}
	return next, true, nil
}

func (v GeneratorAttemptTemplate) valid() bool {
	if v.Schema != GeneratorAttemptTemplateSchema || (v.ResultReaderID != GeneratorResultReaderID() && !v.SupportsValueEncodingFailure()) || !v.LifecycleMode.resourceValid(v.ResourceContractID) || !publicIDsValid(v.LineageID, v.AttemptID, v.ResourceIncarnationID, v.PlannedValueSlotID, v.DutyID, v.TransmissionID, v.ResultID, v.InboxID, v.DescriptorID, v.ConfigContractID, v.ExecutorID, v.CredentialRouteID, v.ResultContractID, v.RequestPlanDigest, v.IntentDigest) || v.RequiredAuthoritySet&GeneratorAuthorityNormal == 0 || v.RequiredAuthoritySet > GeneratorAuthorityMask || v.Branch > GeneratorBranchResidueThenNoEffect {
		return false
	}
	if v.LifecycleMode == GeneratorLifecycleNone {
		if v.Action != GeneratorActionCreate || v.Branch != GeneratorBranchInitial || !v.HazardID.IsZero() || v.CompletionClass != 0 || v.NoEffectBudget != 0 || v.ResidueBudget != 0 {
			return false
		}
	} else if v.HazardID.IsZero() || !generatedCompletionValid(v.CompletionClass) {
		return false
	}
	attempt, err := GeneratorAttemptID(v.LineageID, v.Branch)
	if err != nil || attempt != v.AttemptID {
		return false
	}
	transmission, err := GeneratorTransmissionID(v.AttemptID, v.Action)
	if err != nil || transmission != v.TransmissionID {
		return false
	}
	if v.Branch == GeneratorBranchInitial {
		if !v.PredecessorAttemptID.IsZero() {
			return false
		}
	} else {
		previous := uint8(GeneratorBranchInitial)
		if v.Branch > GeneratorBranchResidue {
			previous = v.Branch - 2
		}
		id, err := GeneratorAttemptID(v.LineageID, previous)
		if err != nil || id != v.PredecessorAttemptID {
			return false
		}
	}
	if v.Action == GeneratorActionDelete {
		if v.Branch != GeneratorBranchInitial || v.NoEffectBudget != 0 || v.ResidueBudget != 0 {
			return false
		}
	} else if v.Action != GeneratorActionCreate {
		return false
	} else if v.LifecycleMode == GeneratorLifecycleManaged {
		var noEffect, residue uint8
		if v.Branch == GeneratorBranchInitial || v.Branch == GeneratorBranchResidue {
			noEffect = 1
		}
		if v.Branch == GeneratorBranchInitial || v.Branch == GeneratorBranchNoEffect {
			residue = 1
		}
		if v.NoEffectBudget != noEffect || v.ResidueBudget > residue {
			return false
		}
	}
	digest, err := GeneratorRequestPlanDigest(v)
	return err == nil && digest == v.RequestPlanDigest
}
func generatorAttemptTemplateEncodedLength(v GeneratorAttemptTemplate) int {
	return GeneratorAttemptTemplateLength
}
func GeneratorAttemptTemplateEncodedLength(v GeneratorAttemptTemplate) (int, error) {
	if !v.valid() {
		return 0, ErrRecord
	}
	return generatorAttemptTemplateEncodedLength(v), nil
}
