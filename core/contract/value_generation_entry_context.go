package contract

type GeneratedValueIdentity struct {
	ValueStateID, OriginSnapshotID, OriginTransitionID, DataKeyID, CommitmentKeyID ID
}

func GeneratorValueKeyIDs(value ID) (data, commitment ID, err error) {
	if value.IsZero() {
		return ID{}, ID{}, ErrRecord
	}
	return generatorDigest("member-data-key-id", value[:]), generatorDigest("member-commitment-key-id", value[:]), nil
}

func DeriveGeneratedValueIdentity(slot, phase, result, binding ID) (GeneratedValueIdentity, error) {
	if !publicIDsValid(slot, phase, result, binding) {
		return GeneratedValueIdentity{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 128)}
	w.id(slot)
	w.id(phase)
	out := GeneratedValueIdentity{OriginSnapshotID: generatorDigest("member-origin-snapshot", w.b), OriginTransitionID: generatorDigest("member-origin-transition", w.b)}
	w.id(result)
	w.id(binding)
	out.ValueStateID = generatorDigest("member-value", w.b)
	var err error
	out.DataKeyID, out.CommitmentKeyID, err = GeneratorValueKeyIDs(out.ValueStateID)
	if err != nil {
		return GeneratedValueIdentity{}, err
	}
	return out, nil
}

func GeneratedCreateEvidenceDescriptor(v GeneratedCreateEvidence) (GeneratorDescriptor, error) {
	n, err := GeneratedCreateEvidenceLength(v)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	w := generatorVectorHashWriter("create-evidence", n+8, 1)
	w.u32(uint32(n))
	writeGeneratedCreateEvidence(&w, v)
	return generatorVectorResult(&w, n+8, 1), nil
}

// ValidateGeneratedValueEntryEvidence checks public correspondence after a selected
// handoff. It neither authenticates provider facts nor opens the secret. The
// selected owner separately checks retained support and retirement obligations.
func ValidateGeneratedValueEntryEvidence(domain ID, entry ValueEntry, evidence GeneratedCreateEvidence, intent []byte) error {
	if domain.IsZero() || entry.ValueSource != Generated || entry.ConfidentialityClass != Secret {
		return ErrRecord
	}
	if _, err := ValueEntryLength(entry); err != nil {
		return err
	}
	d, err := GeneratedCreateEvidenceDescriptor(evidence)
	if err != nil || d != entry.Generated.CreateEvidence {
		return ErrRecord
	}
	core, err := InspectGeneratedResultCore(evidence.ResultCore)
	if err != nil {
		return err
	}
	facts, err := InspectGeneratorSafeFacts(evidence.SafeFacts)
	if err != nil {
		return err
	}
	m := entry.Generated
	if core.Disposition(facts.Disposition) != GeneratorDispositionCompleteCreate || core.ResultID != m.CreateResultID || facts.IntentDigest != m.IntentDigest {
		return ErrRecord
	}
	target := GeneratorTarget{Schema: GeneratorTargetSchema, Name: entry.Name, IncarnationID: entry.Incarnation, Epoch: m.Epoch, ResourceID: m.ResourceIncarnationID, ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID, ResourceDigest: m.ResourceDigest, OriginalOperationID: m.OriginOperationID, OriginalAttemptID: m.OriginAttemptID, ResultContractID: core.ResultContractID, LifecycleMode: m.LifecycleMode, CompletionClass: m.CompletionClass}
	if err := ValidateGeneratedTargetEvidence(domain, target, evidence, intent); err != nil {
		return err
	}
	payload, err := InspectCanonicalPayload(entry.ValueBytes)
	if err != nil {
		return err
	}
	if payload.ContentLength == 0 || payload.ContentLength > CryptoMaxRawValue {
		return ErrRecord
	}
	data, commitment, err := GeneratorValueKeyIDs(entry.ValueState)
	if err != nil || payload.DataKeyEpoch == 1 && payload.DataKeyID != data || payload.CommitmentKeyEpoch == 1 && payload.CommitmentKeyID != commitment {
		return ErrRecord
	}
	return nil
}

// ValidateGeneratedTargetEvidence checks the original create correspondence
// without retaining its graph, seed or secret. Selected ownership and effect
// permission are separate checks; an owned target need not have a usable value.
func ValidateGeneratedTargetEvidence(domain ID, target GeneratorTarget, evidence GeneratedCreateEvidence, intent []byte) error {
	if domain.IsZero() || !target.valid() {
		return ErrRecord
	}
	if _, err := GeneratedCreateEvidenceLength(evidence); err != nil {
		return err
	}
	core, err := InspectGeneratedResultCore(evidence.ResultCore)
	if err != nil {
		return err
	}
	facts, err := InspectGeneratorSafeFacts(evidence.SafeFacts)
	if err != nil {
		return err
	}
	semantic, err := InspectGeneratorIntent(intent)
	if err != nil {
		return err
	}
	var resource ID
	if facts.LifecycleMode == GeneratorLifecycleManaged {
		resource, err = GeneratorResourceDigest(facts.GeneratorSafeFacts)
		if err != nil {
			return err
		}
	}
	if core.DomainID != domain || core.OperationID != target.OriginalOperationID || core.AttemptID != target.OriginalAttemptID || core.ConfigContractID != target.ConfigContractID || core.ResultContractID != target.ResultContractID || facts.ResourceContractID != target.ResourceContractID || facts.LifecycleMode != target.LifecycleMode || resource != target.ResourceDigest || semantic.ConfigContractID != target.ConfigContractID || semantic.ResourceContractID != target.ResourceContractID || semantic.LifecycleMode != target.LifecycleMode || evidence.CompletionClass != target.CompletionClass {
		return ErrRecord
	}
	branches := uint8(GeneratorCreateLineageTemplates)
	if target.LifecycleMode == GeneratorLifecycleNone {
		branches = 1
	}
	return validateGeneratedCreateOrigin(domain, target.Name, target.IncarnationID, target.Epoch, target.ResourceID, target.OriginalOperationID, target.OriginalAttemptID, core, facts.IntentDigest, evidence, intent, branches)
}

func validateGeneratedCreateOrigin(domain ID, name string, incarnation ID, epoch uint64, resource, operation, attempt ID, core GeneratedResultCore, intentDigest ID, evidence GeneratedCreateEvidence, intent []byte, branches uint8) error {
	transmission, err := GeneratorTransmissionID(attempt, GeneratorActionCreate)
	if err != nil || core.TransmissionID != transmission {
		return ErrRecord
	}
	result, err := GeneratorResultID(domain, operation, attempt, transmission, GeneratorActionCreate)
	if err != nil || core.ResultID != result {
		return ErrRecord
	}
	material, err := GeneratorMaterialID(domain, operation)
	if err != nil || core.MaterialID != material {
		return ErrRecord
	}
	derivedResource, err := GeneratorResourceID(domain, operation, attempt)
	if err != nil || resource != derivedResource {
		return ErrRecord
	}
	lineage, err := GeneratorLineageID(domain, operation, name, incarnation, epoch, intentDigest)
	if err != nil {
		return err
	}
	matched := false
	for branch := uint8(GeneratorBranchInitial); branch < branches; branch++ {
		candidate, err := GeneratorAttemptID(lineage, branch)
		if err != nil {
			return err
		}
		matched = matched || candidate == attempt
	}
	if !matched {
		return ErrRecord
	}
	intentID, err := GeneratorIntentDigest(intent)
	if err != nil || intentID != intentDigest {
		return ErrRecord
	}
	logical := GeneratorLogicalSlice{Schema: 1, ContentKind: GeneratorContentIntent, ContentID: intentID, Length: uint32(len(intent)), Digest: Hash(intent)}
	intentDescriptor, err := GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{logical})
	if err != nil || intentDescriptor != evidence.Intent {
		return ErrRecord
	}
	return nil
}
