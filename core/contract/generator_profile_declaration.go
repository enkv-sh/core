package contract

func generationLifecycleValid(mode GeneratorLifecycleMode, resource ID, completion, retirement uint8) bool {
	return mode.resourceValid(resource) && (mode == GeneratorLifecycleNone && completion == 0 && retirement == 0 || mode == GeneratorLifecycleManaged && generatedCompletionValid(completion) && retirement >= GeneratedRetirementManual && retirement <= GeneratedRetirementAuto)
}
func (v GeneratorDeclaredGeneration) validate() error {
	if len(v.Intent) > GeneratorIntentMaxLength {
		return ErrRecordCapacity
	}
	intent, err := InspectGeneratorIntent(v.Intent)
	if err != nil {
		return err
	}
	if v.Schema != GeneratorDeclaredGenerationSchema || intent.ConfigContractID != v.ConfigContractID || intent.ResourceContractID != v.ResourceContractID || intent.LifecycleMode != v.LifecycleMode || !generationLifecycleValid(v.LifecycleMode, v.ResourceContractID, v.CompletionClass, v.RetirementMode) {
		return ErrRecord
	}
	return nil
}
func writeGeneratorDeclaredHeader(w *cryptoWriter, schema uint16, epoch uint64, retirement uint8, config, resource ID, mode GeneratorLifecycleMode, completion uint8) {
	w.u16(schema)
	w.u64(epoch)
	w.u8(retirement)
	w.id(config)
	w.id(resource)
	w.u8(uint8(mode))
	w.u8(completion)
}
func EncodeGeneratorDeclaredGeneration(v GeneratorDeclaredGeneration) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	var w cryptoWriter
	writeGeneratorDeclaredHeader(&w, v.Schema, v.Epoch, v.RetirementMode, v.ConfigContractID, v.ResourceContractID, v.LifecycleMode, v.CompletionClass)
	w.blob(v.Intent)
	return w.b, nil
}
func InspectGeneratorDeclaredGeneration(body []byte) (GeneratorDeclaredGeneration, error) {
	if len(body) > generatorDeclaredGenerationFixedLength+GeneratorIntentMaxLength {
		return GeneratorDeclaredGeneration{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := GeneratorDeclaredGeneration{Schema: r.u16(), Epoch: r.u64(), RetirementMode: r.u8(), ConfigContractID: r.requiredID(), ResourceContractID: r.id(), LifecycleMode: GeneratorLifecycleMode(r.u8()), CompletionClass: r.u8(), Intent: r.blob(GeneratorIntentMaxLength)}
	if err := r.end(); err != nil {
		return GeneratorDeclaredGeneration{}, err
	}
	if err := v.validate(); err != nil {
		return GeneratorDeclaredGeneration{}, err
	}
	return v, nil
}
func InspectGeneratorDeclaredGenerationForEntry(schema uint16, body []byte) (GeneratorDeclaredGeneration, error) {
	if schema != GeneratorDeclarationEntrySchema {
		return GeneratorDeclaredGeneration{}, ErrRecord
	}
	return InspectGeneratorDeclaredGeneration(body)
}
func generatorDeclaredIntentOffset(v GeneratorDeclaredGeneration) uint32 {
	return generatorDeclaredGenerationFixedLength
}
func (v GeneratorDeclaredGenerationReference) validate() error {
	if v.Intent.Length > GeneratorIntentMaxLength {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratorDeclaredReferenceSchema || v.ConfigContractID.IsZero() || !generationLifecycleValid(v.LifecycleMode, v.ResourceContractID, v.CompletionClass, v.RetirementMode) || !v.Intent.valid() || v.Intent.ContentKind != GeneratorContentIntent {
		return ErrRecord
	}
	return nil
}
func EncodeGeneratorDeclaredGenerationReference(v GeneratorDeclaredGenerationReference) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	var w cryptoWriter
	writeGeneratorDeclaredHeader(&w, v.Schema, v.Epoch, v.RetirementMode, v.ConfigContractID, v.ResourceContractID, v.LifecycleMode, v.CompletionClass)
	writeGeneratorLogicalSlice(&w, v.Intent)
	return w.b, nil
}
func InspectGeneratorDeclaredGenerationReference(body []byte) (GeneratorDeclaredGenerationReference, error) {
	if len(body) > GeneratorDeclaredGenerationReferenceLength {
		return GeneratorDeclaredGenerationReference{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := GeneratorDeclaredGenerationReference{Schema: r.u16(), Epoch: r.u64(), RetirementMode: r.u8(), ConfigContractID: r.requiredID(), ResourceContractID: r.id(), LifecycleMode: GeneratorLifecycleMode(r.u8()), CompletionClass: r.u8(), Intent: GeneratorLogicalSlice{Schema: r.u16(), ContentKind: r.u8(), ContentID: r.requiredID(), Length: r.u32(), Digest: r.requiredID()}}
	if err := r.end(); err != nil {
		return GeneratorDeclaredGenerationReference{}, err
	}
	if err := v.validate(); err != nil {
		return GeneratorDeclaredGenerationReference{}, err
	}
	return v, nil
}
func InspectGeneratorDeclaredGenerationReferenceForEntry(schema uint16, body []byte) (GeneratorDeclaredGenerationReference, error) {
	if schema != GeneratorDeclarationEntrySchema {
		return GeneratorDeclaredGenerationReference{}, ErrRecord
	}
	return InspectGeneratorDeclaredGenerationReference(body)
}
