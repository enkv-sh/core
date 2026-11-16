package contract

import protocol "enkv.sh/sdk/protocols/generator"

// GeneratorLifecycleMode maps public family lifecycle tags into private
// records. Zero is invalid; none has no managed external retirement resource.
type GeneratorLifecycleMode uint8

// GeneratorLifecycleNone and GeneratorLifecycleManaged retain the public
// protocol's lifecycle meaning without assigning provider semantics.
const (
	GeneratorLifecycleNone    GeneratorLifecycleMode = GeneratorLifecycleMode(protocol.LifecycleNone)
	GeneratorLifecycleManaged GeneratorLifecycleMode = GeneratorLifecycleMode(protocol.LifecycleManaged)
)
const (
	GeneratorImplementationSchema      uint16 = 3
	GeneratorDeclaredGenerationSchema  uint16 = 4
	GeneratorDeclarationEntrySchema    uint16 = 4
	GeneratorDeclaredReferenceSchema   uint16 = 4
	GeneratorSafeFactsSchema           uint16 = 4
	GeneratedEntryMetadataSchema       uint16 = 3
	GeneratedProducerPreparationSchema uint16 = 3
	GeneratedProducerCommandSchema     uint16 = 3
	GeneratedCreateEvidenceSchema      uint16 = 4
	GeneratorAttemptTemplateSchema     uint16 = 3
	GeneratedAttemptRecordSchema       uint16 = 3
	GeneratedDutyRecordSchema          uint16 = 3
	GeneratedHazardRecordSchema        uint16 = 2
	GeneratedResultCoreSchema          uint16 = 4
	GeneratorGraphHeaderSchema         uint16 = 3
	GeneratorValueEntryPlanSchema      uint16 = 4
	GeneratorLineageTemplateSchema     uint16 = 3
	GeneratorPlanBundleSchema          uint16 = 3
	GeneratorTargetSchema              uint16 = 2
	GeneratorSupportBindingSchema      uint16 = 2
)

func (v GeneratorLifecycleMode) resourceValid(resource ID) bool {
	return v == GeneratorLifecycleNone && resource.IsZero() || v == GeneratorLifecycleManaged && !resource.IsZero()
}
func generatorMeaningID(label string) ID {
	var w cryptoWriter
	w.blob([]byte(label))
	return generatorDigest("meaning", w.b)
}
func GeneratorResultReaderID() ID { return generatorMeaningID("GENERATOR-RESULT-READER/v4") }
func (v GeneratorAttemptTemplate) ResultReaderIdentity() ID {
	if v.Schema != GeneratorAttemptTemplateSchema {
		return ID{}
	}
	return v.ResultReaderID
}

const (
	GeneratorFailureNone uint8 = iota
	GeneratorFailureInvalid
	GeneratorFailureUnavailable
	GeneratorFailureCancelled
	GeneratorFailureExpired
	GeneratorFailureProtocol
)

func generatorValueEntryPlanEncodedLength(v GeneratorValueEntryPlan) int {
	return 238 + len(v.Name) + int(boolU8(v.ValueSource == Generated))
}
func generatorLineageTemplateEncodedLength(v GeneratorLineageTemplate) int {
	n := 208 + len(v.Name)
	for _, x := range v.Templates[:v.TemplateCount] {
		n += 4 + generatorAttemptTemplateEncodedLength(x)
	}
	return n
}
func generatorGraphValueDerivationID(schema uint16) ID {
	if schema == GeneratorGraphHeaderSchema {
		return GeneratorValueDerivationID()
	}
	return ID{}
}
func (v GeneratedEntryMetadata) SemanticLifecycleMode() GeneratorLifecycleMode {
	if v.Schema == GeneratedEntryMetadataSchema {
		return v.LifecycleMode
	}
	return 0
}
func (v GeneratorAttemptTemplate) SemanticLifecycleMode() GeneratorLifecycleMode {
	if v.Schema == GeneratorAttemptTemplateSchema {
		return v.LifecycleMode
	}
	return 0
}
func (v GeneratedAttemptRecord) SemanticLifecycleMode() GeneratorLifecycleMode {
	if v.Schema == GeneratedAttemptRecordSchema {
		return v.LifecycleMode
	}
	return 0
}
func (v GeneratedDutyRecord) SemanticLifecycleMode() GeneratorLifecycleMode {
	if v.Schema == GeneratedDutyRecordSchema {
		return v.LifecycleMode
	}
	return 0
}
