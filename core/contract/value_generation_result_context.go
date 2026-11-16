package contract

// GeneratorResultExpectation is fixed by the admitted graph and original facts.
type GeneratorResultExpectation struct {
	InputEncoding        uint8
	Plan                 GeneratorUsePlanCore
	Template             GeneratorAttemptTemplate
	Use                  GeneratorResultUse
	RequestDigest        ID
	TargetResourceDigest ID
}

func GeneratorResourceDigest(v GeneratorSafeFacts) (ID, error) {
	if !v.valid() || v.LifecycleMode != GeneratorLifecycleManaged || len(v.Target) == 0 || len(v.ResourceData) == 0 {
		return ID{}, ErrRecord
	}
	var w cryptoWriter
	w.id(v.ResourceContractID)
	w.blob(v.Target)
	w.blob(v.ResourceData)
	return generatorDigest("resource-v1", w.b), nil
}
func GeneratorResultKeyIDs(result ID) (data, commitment ID, err error) {
	if result.IsZero() {
		return ID{}, ID{}, ErrRecord
	}
	return generatorDigest("result-data-key-id", result[:]), generatorDigest("result-commitment-key-id", result[:]), nil
}
func (v GeneratorResultExpectation) Validate(material OperationMaterialRecord) error {
	digest, err := GeneratorUsePlanDigest(v.Plan)
	if err != nil || (v.InputEncoding != InputEncodingRaw && v.InputEncoding != InputEncodingBase64) || v.Template.Action == GeneratorActionDelete && v.InputEncoding != InputEncodingRaw || !v.Template.valid() || generatorResultUseError(v.Use) != nil || v.RequestDigest.IsZero() {
		return ErrRecord
	}
	if _, err := OperationMaterialRecordLength(material); err != nil {
		return err
	}
	p, t, u, m := v.Plan, v.Template, v.Use, material.Core
	if m.DomainID != p.DomainID || m.OperationID != p.OperationID || m.OperationMaterialID != p.MaterialID || m.UsePlanDigest != digest || u.AttemptID != t.AttemptID || u.ResultID != t.ResultID || u.InboxID != t.InboxID || u.ExecutorID != t.ExecutorID || u.ResultContractID != t.ResultContractID || u.PlannedValueSlotID != t.PlannedValueSlotID || u.MaterialID != p.MaterialID || (t.Action == GeneratorActionDelete) != (u.MaxSecret == 0) {
		return ErrRecord
	}
	if (t.Action == GeneratorActionCreate) != v.TargetResourceDigest.IsZero() || t.Action == GeneratorActionDelete && !t.ResourceDigest.IsZero() && v.TargetResourceDigest != t.ResourceDigest {
		return ErrRecord
	}
	result, err := GeneratorResultID(p.DomainID, p.OperationID, t.AttemptID, t.TransmissionID, t.Action)
	if err != nil || result != t.ResultID {
		return ErrRecord
	}
	inbox, err := GeneratorInboxID(p.DomainID, p.OperationID, t.AttemptID, result)
	if err != nil || inbox != t.InboxID {
		return ErrRecord
	}
	return nil
}
func ExpectedGeneratedResultCore(v GeneratorResultExpectation, material OperationMaterialRecord, facts GeneratorSafeFacts) (GeneratedResultCore, error) {
	if err := v.Validate(material); err != nil {
		return GeneratedResultCore{}, err
	}
	t := v.Template
	digest, err := GeneratorSafeFactsDigest(facts)
	if err != nil || facts.RequestDigest != v.RequestDigest || facts.IntentDigest != t.IntentDigest || facts.Action != t.Action || facts.LifecycleMode != t.LifecycleMode || facts.ResourceContractID != t.ResourceContractID {
		return GeneratedResultCore{}, ErrRecord
	}
	if t.Action == GeneratorActionCreate {
		if facts.Disposition != GeneratorDispositionCompleteCreate && facts.Disposition != GeneratorDispositionOwnedUnusableCreate && facts.Disposition != GeneratorDispositionConfirmedNoEffect {
			return GeneratedResultCore{}, ErrRecord
		}
	} else {
		resource, err := GeneratorResourceDigest(facts)
		if err != nil || resource != v.TargetResourceDigest {
			return GeneratedResultCore{}, ErrRecord
		}
		if facts.Disposition != GeneratorDispositionRetirementAcknowledged && (t.CompletionClass != GeneratedCompletionConfirmed || facts.Disposition < GeneratorDispositionScopedUnusability || facts.Disposition > GeneratorDispositionConflictingBinding || facts.ScopeID != GeneratorControlledRetirementScope(t.DescriptorID, t.ConfigContractID, t.ResultContractID)) {
			return GeneratedResultCore{}, ErrRecord
		}
		if facts.Disposition >= GeneratorDispositionScopedUnusability {
			match := facts.ObservedResourceID == t.ResourceIncarnationID && facts.ObservedResourceDigest == v.TargetResourceDigest && facts.ObservedScopeID == facts.ScopeID
			if (facts.Disposition == GeneratorDispositionConflictingBinding) == match {
				return GeneratedResultCore{}, ErrRecord
			}
		}
	}
	n, err := GeneratorSafeFactsLength(facts)
	if err != nil || uint32(n) > v.Use.MaxFacts {
		return GeneratedResultCore{}, ErrRecordCapacity
	}
	m := material.Core
	return GeneratedResultCore{Schema: GeneratedResultCoreSchema, Profile: m.Profile, DomainID: m.DomainID, OperationID: m.OperationID, MaterialID: m.OperationMaterialID, UsePlanDigest: m.UsePlanDigest, PlanGraphID: v.Plan.PlanGraphID, AttemptID: t.AttemptID, TransmissionID: t.TransmissionID, ResultID: t.ResultID, ExecutorID: t.ExecutorID, DescriptorID: t.DescriptorID, ConfigContractID: t.ConfigContractID, ResultContractID: t.ResultContractID, RequestDigest: v.RequestDigest, SafeFactsDigest: digest}, nil
}
func ValidateGeneratedResult(v GeneratorResultExpectation, material OperationMaterialRecord, result GeneratedResultRecord) error {
	core, err := ExpectedGeneratedResultCore(v, material, result.SafeFacts)
	if err != nil || result.Core != core || result.Payload.ContentLength > v.Use.MaxSecret || result.Payload.InputEncoding != v.InputEncoding {
		return ErrRecord
	}
	if result.Transfer.Core.CompatibilityID != material.Core.CompatibilityID || result.Transfer.Core.CryptoSupportID != material.Core.CryptoSupportID {
		return ErrRecord
	}
	_, err = GeneratedResultRecordLength(result)
	return err
}
