package contract

import (
	"bytes"
	"unicode/utf8"
)

const GeneratorRequestCoreSchema uint16 = 2
const GeneratorPublicRequestCoreSchema uint16 = 3
const GeneratorApplyRequestCoreSchema uint16 = 4

const (
	GeneratorUseGeneratedResult    = 1
	GeneratorUseAcceptedSource     = 2
	GeneratorValueChangeContent    = 1
	GeneratorValueChangeMembership = 2
	GeneratorValueChangeRetirement = 4
	GeneratorValueChangeMask       = GeneratorValueChangeContent | GeneratorValueChangeMembership | GeneratorValueChangeRetirement
)

// A create can enter only one three-attempt predecessor path through the five
// reserved templates.
const GeneratorMaxEnteredCreateAttempts = 3

const (
	generatorGuardNoEffectBit = 1 << (GeneratorGuardQualifiedNoEffect - 1)
	generatorGuardResidueBit  = 1 << (GeneratorGuardResidue - 1)
	generatorGuardSuccessBit  = 1 << (GeneratorGuardQualifiedSuccess - 1)
	generatorGuardTerminalBit = 1 << (GeneratorGuardTerminalParent - 1)
)

const (
	GeneratorGuardQualifiedNoEffect = 1
	GeneratorGuardResidue           = 2
	GeneratorGuardQualifiedSuccess  = 3
	GeneratorGuardTerminalParent    = 4
)

const (
	GeneratorRequestCoreLength        = 348
	GeneratorApplyRequestCoreLength   = 394
	GeneratorGraphHeaderLength        = 168
	GeneratorValueEntryPlanMaxLength  = 495
	GeneratorEdgeLength               = 102
	GeneratorResultUseLength          = 235
	GeneratorSourceUseLength          = 187
	GeneratorUsePlanCoreLength        = 248
	GeneratorGraphMaxLength           = 8 << 20
	GeneratorMaxTemplates             = 1408
	GeneratorMaxLineageTemplates      = 896
	GeneratorLineageTemplateMaxLength = 3924
	GeneratorCreateLineageTemplates   = 5
	GeneratorObligationTemplates      = 1
	GeneratorMaxCreateLineages        = 128
)

type GeneratorLineagePurpose uint8

const (
	GeneratorLineageCreate     GeneratorLineagePurpose = 1
	GeneratorLineageRetirement GeneratorLineagePurpose = 2
	GeneratorLineageCleanup    GeneratorLineagePurpose = 3
)

type GeneratorRequestCore struct {
	Schema, OperationKind                                                      uint16
	DomainID, OperationID                                                      ID
	PredecessorRevisionID, PredecessorHEADDigest, ConditionDigest, CallerNonce ID
	Declaration, Registry                                                      GeneratorDescriptor
	CompatibilityID, RecoveryPolicyID                                          ID
	OutputConfiguration                                                        OutputConfigurationDescriptor
}

func generatorRequestCoreValid(v GeneratorRequestCore) bool {
	if v.Schema == GeneratorApplyRequestCoreSchema {
		if v.OperationKind != OperationApplyDeclaration {
			return false
		}
		if _, err := EncodeOutputConfigurationDescriptor(v.OutputConfiguration); err != nil {
			return false
		}
	} else if v.OutputConfiguration != (OutputConfigurationDescriptor{}) {
		return false
	}
	return (v.Schema == GeneratorRequestCoreSchema || v.Schema == GeneratorPublicRequestCoreSchema || v.Schema == GeneratorApplyRequestCoreSchema) && (v.OperationKind == OperationApplyDeclaration || v.OperationKind == OperationRotateValueEntryValue || v.OperationKind == OperationCleanOwnedFailureResidue || v.OperationKind == OperationRetireGeneratedGeneration || v.OperationKind == OperationAcceptGeneratedRetirementResidue) &&
		(v.Schema == GeneratorRequestCoreSchema || v.RecoveryPolicyID == GeneratorRecoveryPolicyID()) &&
		publicIDsValid(v.DomainID, v.OperationID, v.PredecessorRevisionID,
			v.PredecessorHEADDigest, v.ConditionDigest, v.CallerNonce, v.CompatibilityID, v.RecoveryPolicyID) && generatedDescriptorsValid(v.Declaration, v.Registry)
}

func generatorRequestCoreLength(v GeneratorRequestCore) int {
	if v.Schema == GeneratorApplyRequestCoreSchema {
		return GeneratorApplyRequestCoreLength
	}
	return GeneratorRequestCoreLength
}

func writeGeneratorRequestCore(w *cryptoWriter, v GeneratorRequestCore) {
	w.u16(v.Schema)
	w.u16(v.OperationKind)
	w.id(v.DomainID)
	w.id(v.OperationID)

	w.id(v.PredecessorRevisionID)
	w.id(v.PredecessorHEADDigest)
	w.id(v.ConditionDigest)
	w.id(v.CallerNonce)
	writeGeneratorDescriptor(w, v.Declaration)
	writeGeneratorDescriptor(w, v.Registry)
	w.id(v.CompatibilityID)
	w.id(v.RecoveryPolicyID)
	if v.Schema == GeneratorApplyRequestCoreSchema {
		writeOutputConfigurationDescriptor(w, v.OutputConfiguration)
	}
}

func AppendGeneratorRequestCore(dst []byte, v GeneratorRequestCore) ([]byte, error) {
	if !generatorRequestCoreValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeGeneratorRequestCore(&w, v)
	return w.b, nil
}

func EncodeGeneratorRequestCore(v GeneratorRequestCore) ([]byte, error) {
	if !generatorRequestCoreValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, generatorRequestCoreLength(v))}
	writeGeneratorRequestCore(&w, v)
	return w.b, nil
}

func InspectGeneratorRequestCore(b []byte) (GeneratorRequestCore, error) {
	if len(b) > GeneratorApplyRequestCoreLength {
		return GeneratorRequestCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorRequestCore{Schema: r.u16(), OperationKind: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID(), PredecessorRevisionID: r.requiredID(), PredecessorHEADDigest: r.requiredID(),
		ConditionDigest: r.requiredID(), CallerNonce: r.requiredID(), Declaration: readGeneratorDescriptor(&r), Registry: readGeneratorDescriptor(&r),
		CompatibilityID: r.requiredID(), RecoveryPolicyID: r.requiredID()}
	if v.Schema == GeneratorApplyRequestCoreSchema {
		body := r.take(46)
		var err error
		v.OutputConfiguration, err = InspectOutputConfigurationDescriptor(body)
		if err != nil {
			return GeneratorRequestCore{}, err
		}
	}
	if err := r.end(); err != nil {
		return GeneratorRequestCore{}, err
	}
	if !generatorRequestCoreValid(v) {
		return GeneratorRequestCore{}, ErrRecord
	}
	return v, nil
}

func GeneratorRequestCoreDigest(v GeneratorRequestCore) (ID, error) {
	if !generatorRequestCoreValid(v) {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter(generatorIdentityPrefix + "request-core\x00")
	w.u32(uint32(generatorRequestCoreLength(v)))
	writeGeneratorRequestCore(&w, v)
	return w.result(0).Digest, nil
}

type GeneratorGraphHeader struct {
	Schema                                                                 uint16
	DomainID, OperationID, MaterialID, RequestCoreDigest, RecoveryPolicyID ID
	ValueEntryPlanCount, LineageCount, TemplateCount                       uint16
}

func generatorGraphHeaderError(v GeneratorGraphHeader) error {
	if v.ValueEntryPlanCount > CryptoMaxValueEntries || v.LineageCount > GeneratorMaxCreateLineages || v.TemplateCount > GeneratorMaxTemplates {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratorGraphHeaderSchema || !publicIDsValid(v.DomainID, v.OperationID, v.MaterialID, v.RequestCoreDigest, v.RecoveryPolicyID) ||
		v.TemplateCount < v.LineageCount {
		return ErrRecord
	}
	material, err := GeneratorMaterialID(v.DomainID, v.OperationID)
	if err != nil || v.MaterialID != material {
		return ErrRecord
	}
	return nil
}

func writeGeneratorGraphHeader(w *cryptoWriter, v GeneratorGraphHeader) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.MaterialID)
	w.id(v.RequestCoreDigest)
	w.id(v.RecoveryPolicyID)
	w.u16(v.ValueEntryPlanCount)
	w.u16(v.LineageCount)
	w.u16(v.TemplateCount)
}

func EncodeGeneratorGraphHeader(v GeneratorGraphHeader) ([]byte, error) {
	if err := generatorGraphHeaderError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorGraphHeaderLength)}
	writeGeneratorGraphHeader(&w, v)
	return w.b, nil
}

func InspectGeneratorGraphHeader(b []byte) (GeneratorGraphHeader, error) {
	if len(b) > GeneratorGraphHeaderLength {
		return GeneratorGraphHeader{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorGraphHeader{Schema: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID(), MaterialID: r.requiredID(),
		RequestCoreDigest: r.requiredID(), RecoveryPolicyID: r.requiredID(), ValueEntryPlanCount: r.u16(), LineageCount: r.u16(), TemplateCount: r.u16()}
	if err := r.end(); err != nil {
		return GeneratorGraphHeader{}, err
	}
	if err := generatorGraphHeaderError(v); err != nil {
		return GeneratorGraphHeader{}, err
	}
	return v, nil
}

type GeneratorEdge struct {
	Schema                                          uint16
	SourceTemplateID, DestinationTemplateID         ID
	Guard                                           uint8
	ResultSlotID                                    ID
	RequiredAuthoritySet, NoEffectUsed, ResidueUsed uint8
}

func generatorEdgeValid(v GeneratorEdge) bool {
	return v.Schema == GeneratorRecordSchema && publicIDsValid(v.SourceTemplateID, v.DestinationTemplateID, v.ResultSlotID) &&
		v.SourceTemplateID != v.DestinationTemplateID && v.Guard >= GeneratorGuardQualifiedNoEffect && v.Guard <= GeneratorGuardTerminalParent && v.RequiredAuthoritySet&GeneratorAuthorityNormal != 0 &&
		v.RequiredAuthoritySet <= GeneratorAuthorityMask && v.NoEffectUsed <= 1 && v.ResidueUsed <= 1
}

func writeGeneratorEdge(w *cryptoWriter, v GeneratorEdge) {
	w.u16(v.Schema)
	w.id(v.SourceTemplateID)
	w.id(v.DestinationTemplateID)
	w.u8(v.Guard)
	w.id(v.ResultSlotID)
	w.u8(v.RequiredAuthoritySet)
	w.u8(v.NoEffectUsed)
	w.u8(v.ResidueUsed)
}

func EncodeGeneratorEdge(v GeneratorEdge) ([]byte, error) {
	if !generatorEdgeValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorEdgeLength)}
	writeGeneratorEdge(&w, v)
	return w.b, nil
}

func InspectGeneratorEdge(b []byte) (GeneratorEdge, error) {
	if len(b) > GeneratorEdgeLength {
		return GeneratorEdge{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorEdge{Schema: r.u16(), SourceTemplateID: r.requiredID(), DestinationTemplateID: r.requiredID(),
		Guard: r.u8(), ResultSlotID: r.requiredID(), RequiredAuthoritySet: r.u8(), NoEffectUsed: r.u8(), ResidueUsed: r.u8()}
	if err := r.end(); err != nil {
		return GeneratorEdge{}, err
	}
	if !generatorEdgeValid(v) {
		return GeneratorEdge{}, ErrRecord
	}
	return v, nil
}

type GeneratorResultUse struct {
	Schema                                                                                     uint16
	AttemptID, ResultID, InboxID, ExecutorID, ResultContractID, PlannedValueSlotID, MaterialID ID
	Purpose                                                                                    uint8
	MaxSecret, MaxFacts                                                                        uint32
}

func generatorResultUseError(v GeneratorResultUse) error {
	if v.MaxSecret > CryptoMaxRawValue || v.MaxFacts > GeneratorSafeFactsEnvelopeLength {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratorRecordSchema || v.Purpose != GeneratorUseGeneratedResult || v.MaxFacts == 0 ||
		!publicIDsValid(v.AttemptID, v.ResultID, v.InboxID, v.ExecutorID, v.ResultContractID, v.PlannedValueSlotID, v.MaterialID) {
		return ErrRecord
	}
	return nil
}

func writeGeneratorResultUse(w *cryptoWriter, v GeneratorResultUse) {
	w.u16(v.Schema)
	w.id(v.AttemptID)
	w.id(v.ResultID)
	w.id(v.InboxID)
	w.id(v.ExecutorID)
	w.id(v.ResultContractID)
	w.id(v.PlannedValueSlotID)
	w.id(v.MaterialID)
	w.u8(v.Purpose)
	w.u32(v.MaxSecret)
	w.u32(v.MaxFacts)
}

func EncodeGeneratorResultUse(v GeneratorResultUse) ([]byte, error) {
	if err := generatorResultUseError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorResultUseLength)}
	writeGeneratorResultUse(&w, v)
	return w.b, nil
}

func InspectGeneratorResultUse(b []byte) (GeneratorResultUse, error) {
	if len(b) > GeneratorResultUseLength {
		return GeneratorResultUse{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorResultUse{Schema: r.u16(), AttemptID: r.requiredID(), ResultID: r.requiredID(), InboxID: r.requiredID(), ExecutorID: r.requiredID(),
		ResultContractID: r.requiredID(), PlannedValueSlotID: r.requiredID(), MaterialID: r.requiredID(), Purpose: r.u8(), MaxSecret: r.u32(), MaxFacts: r.u32()}
	if err := r.end(); err != nil {
		return GeneratorResultUse{}, err
	}
	if err := generatorResultUseError(v); err != nil {
		return GeneratorResultUse{}, err
	}
	return v, nil
}

type GeneratorSourceUse struct {
	Schema                                          uint16
	SourceID, SealedInputCoreDigest, EnvelopeDigest ID
	SourceSlice, Consumers                          GeneratorDescriptor
	Purpose                                         uint8
}

func generatorSourceUseValid(v GeneratorSourceUse) bool {
	return v.Schema == GeneratorRecordSchema && v.Purpose == GeneratorUseAcceptedSource && publicIDsValid(v.SourceID, v.SealedInputCoreDigest, v.EnvelopeDigest) &&
		generatedDescriptorsValid(v.SourceSlice, v.Consumers)
}

func writeGeneratorSourceUse(w *cryptoWriter, v GeneratorSourceUse) {
	w.u16(v.Schema)
	w.id(v.SourceID)
	w.id(v.SealedInputCoreDigest)
	w.id(v.EnvelopeDigest)
	writeGeneratorDescriptor(w, v.SourceSlice)
	writeGeneratorDescriptor(w, v.Consumers)
	w.u8(v.Purpose)
}

func EncodeGeneratorSourceUse(v GeneratorSourceUse) ([]byte, error) {
	if !generatorSourceUseValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorSourceUseLength)}
	writeGeneratorSourceUse(&w, v)
	return w.b, nil
}

func InspectGeneratorSourceUse(b []byte) (GeneratorSourceUse, error) {
	if len(b) > GeneratorSourceUseLength {
		return GeneratorSourceUse{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorSourceUse{Schema: r.u16(), SourceID: r.requiredID(), SealedInputCoreDigest: r.requiredID(), EnvelopeDigest: r.requiredID(),
		SourceSlice: readGeneratorDescriptor(&r), Consumers: readGeneratorDescriptor(&r), Purpose: r.u8()}
	if err := r.end(); err != nil {
		return GeneratorSourceUse{}, err
	}
	if !generatorSourceUseValid(v) {
		return GeneratorSourceUse{}, ErrRecord
	}
	return v, nil
}

func generatorVectorHashWriter(label string, length, count int) cryptoWriter {
	w := cryptoHashWriter(generatorIdentityPrefix + label + "\x00")
	w.u32(uint32(length))
	w.u32(uint32(count))
	return w
}

func generatorVectorResult(w *cryptoWriter, length, count int) GeneratorDescriptor {
	return GeneratorDescriptor{Digest: w.result(count).Digest, Length: uint64(length), Count: uint32(count)}
}

func GeneratorResultUsesDescriptor(rows []GeneratorResultUse) (GeneratorDescriptor, error) {
	if len(rows) > GeneratorMaxTemplates {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	for i, v := range rows {
		if err := generatorResultUseError(v); err != nil {
			return GeneratorDescriptor{}, err
		}
		if i > 0 && (bytes.Compare(rows[i-1].AttemptID[:], v.AttemptID[:]) > 0 || rows[i-1].AttemptID == v.AttemptID && bytes.Compare(rows[i-1].ResultID[:], v.ResultID[:]) >= 0) {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	n := 4 + len(rows)*(4+GeneratorResultUseLength)
	w := generatorVectorHashWriter("result-uses", n, len(rows))
	for _, v := range rows {
		w.u32(GeneratorResultUseLength)
		writeGeneratorResultUse(&w, v)
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

func GeneratorSourceUsesDescriptor(rows []GeneratorSourceUse) (GeneratorDescriptor, error) {
	if len(rows) > CryptoMaxValueEntries {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	for i, v := range rows {
		if !generatorSourceUseValid(v) || i > 0 && bytes.Compare(rows[i-1].SourceID[:], v.SourceID[:]) >= 0 {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	n := 4 + len(rows)*(4+GeneratorSourceUseLength)
	w := generatorVectorHashWriter("source-uses", n, len(rows))
	for _, v := range rows {
		w.u32(GeneratorSourceUseLength)
		writeGeneratorSourceUse(&w, v)
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

func generatorEdgeCompare(a, b GeneratorEdge) int {
	if c := bytes.Compare(a.SourceTemplateID[:], b.SourceTemplateID[:]); c != 0 {
		return c
	}
	if a.Guard < b.Guard {
		return -1
	}
	if a.Guard > b.Guard {
		return 1
	}
	return bytes.Compare(a.DestinationTemplateID[:], b.DestinationTemplateID[:])
}

func GeneratorTransitionRulesDescriptor(rows []GeneratorEdge) (GeneratorDescriptor, error) {
	if len(rows) > 4*GeneratorMaxTemplates {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	for i, v := range rows {
		if !generatorEdgeValid(v) || i > 0 && generatorEdgeCompare(rows[i-1], v) >= 0 {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	n := 4 + len(rows)*(4+GeneratorEdgeLength)
	w := generatorVectorHashWriter("transition-rules", n, len(rows))
	for _, v := range rows {
		w.u32(GeneratorEdgeLength)
		writeGeneratorEdge(&w, v)
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

type GeneratorValueEntryPlan struct {
	LifecycleMode                     GeneratorLifecycleMode
	Schema, Slot                      uint16
	Name                              string
	ValueSource, ConfidentialityClass uint8
	InputEncoding, OutputEncoding     uint8
	EntryIncarnationID                ID
	Epoch                             uint64
	IntentDigest, PlannedValueSlotID  ID
	SourceSlice, IntendedMembership   GeneratorDescriptor
	LineageID                         ID
	RetirementMode, ChangeMask        uint8
}

// GeneratorValueEntryPlanView borrows Name; all other fields are fixed values.
type GeneratorValueEntryPlanView struct {
	LifecycleMode                     GeneratorLifecycleMode
	Schema, Slot                      uint16
	Name                              []byte
	ValueSource, ConfidentialityClass uint8
	InputEncoding, OutputEncoding     uint8
	EntryIncarnationID                ID
	Epoch                             uint64
	IntentDigest, PlannedValueSlotID  ID
	SourceSlice, IntendedMembership   GeneratorDescriptor
	LineageID                         ID
	RetirementMode, ChangeMask        uint8
}

func generatorValueEntryPlanError(v GeneratorValueEntryPlan, name []byte) error {
	if len(name) > CryptoMaxName || v.Slot >= CryptoMaxValueEntries {
		return ErrRecordCapacity
	}
	if (v.InputEncoding != InputEncodingRaw && v.InputEncoding != InputEncodingBase64) || (v.OutputEncoding != OutputEncodingRaw && v.OutputEncoding != OutputEncodingBase64) || v.Schema != GeneratorValueEntryPlanSchema || !utf8.Valid(name) || !ValidatePublicEntryTags(v.ValueSource, v.ConfidentialityClass) ||
		v.EntryIncarnationID.IsZero() || !v.IntendedMembership.Valid() || v.ChangeMask > GeneratorValueChangeMask {
		return ErrRecord
	}
	if v.ValueSource == Supplied {
		if v.LifecycleMode != 0 {
			return ErrRecord
		}
		if v.Epoch != 0 || !v.IntentDigest.IsZero() || !v.PlannedValueSlotID.IsZero() || !v.LineageID.IsZero() || v.RetirementMode != 0 || !v.SourceSlice.Valid() {
			return ErrRecord
		}
		return nil
	}
	if v.IntentDigest.IsZero() {
		return ErrRecord
	}
	if v.Schema == GeneratorValueEntryPlanSchema && v.LifecycleMode == GeneratorLifecycleNone {
		if v.RetirementMode != 0 || v.ChangeMask&GeneratorValueChangeRetirement != 0 {
			return ErrRecord
		}
	} else if v.Schema == GeneratorValueEntryPlanSchema && v.LifecycleMode != GeneratorLifecycleManaged || v.RetirementMode < GeneratedRetirementManual || v.RetirementMode > GeneratedRetirementAuto {
		return ErrRecord
	}
	if v.ChangeMask&GeneratorValueChangeContent != 0 {
		if !publicIDsValid(v.LineageID, v.PlannedValueSlotID) || v.SourceSlice != (GeneratorDescriptor{}) {
			return ErrRecord
		}
	} else if !v.LineageID.IsZero() || !v.PlannedValueSlotID.IsZero() || !v.SourceSlice.Valid() {
		return ErrRecord
	}
	return nil
}

func GeneratorValueEntryPlanLength(v GeneratorValueEntryPlan) (int, error) {
	if err := generatorValueEntryPlanError(v, []byte(v.Name)); err != nil {
		return 0, err
	}
	return generatorValueEntryPlanEncodedLength(v), nil
}

func writeGeneratorValueEntryPlan(w *cryptoWriter, v GeneratorValueEntryPlan) {
	w.u16(v.Schema)
	w.u16(v.Slot)
	w.blob([]byte(v.Name))
	w.u8(v.ValueSource)
	w.u8(v.ConfidentialityClass)
	w.u8(v.InputEncoding)
	w.u8(v.OutputEncoding)
	w.id(v.EntryIncarnationID)
	w.u64(v.Epoch)
	w.id(v.IntentDigest)
	w.id(v.PlannedValueSlotID)
	writeGeneratorDescriptor(w, v.SourceSlice)
	writeGeneratorDescriptor(w, v.IntendedMembership)
	w.id(v.LineageID)
	w.u8(v.RetirementMode)
	w.u8(v.ChangeMask)
	if v.ValueSource == Generated {
		w.u8(uint8(v.LifecycleMode))
	}
}

func EncodeGeneratorValueEntryPlan(v GeneratorValueEntryPlan) ([]byte, error) {
	n, err := GeneratorValueEntryPlanLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratorValueEntryPlan(&w, v)
	return w.b, nil
}

func (v GeneratorValueEntryPlanView) fields() GeneratorValueEntryPlan {
	return GeneratorValueEntryPlan{Schema: v.Schema, LifecycleMode: v.LifecycleMode, Slot: v.Slot, ValueSource: v.ValueSource, ConfidentialityClass: v.ConfidentialityClass, InputEncoding: v.InputEncoding, OutputEncoding: v.OutputEncoding, EntryIncarnationID: v.EntryIncarnationID,
		Epoch: v.Epoch, IntentDigest: v.IntentDigest, PlannedValueSlotID: v.PlannedValueSlotID, SourceSlice: v.SourceSlice, IntendedMembership: v.IntendedMembership,
		LineageID: v.LineageID, RetirementMode: v.RetirementMode, ChangeMask: v.ChangeMask}
}

func InspectGeneratorValueEntryPlan(b []byte) (GeneratorValueEntryPlanView, error) {
	if len(b) > GeneratorValueEntryPlanMaxLength {
		return GeneratorValueEntryPlanView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorValueEntryPlanView{Schema: r.u16(), Slot: r.u16(), Name: r.name(), ValueSource: r.u8(), ConfidentialityClass: r.u8(), InputEncoding: r.u8(), OutputEncoding: r.u8(), EntryIncarnationID: r.requiredID(),
		Epoch: r.u64(), IntentDigest: r.id(), PlannedValueSlotID: r.id(), SourceSlice: GeneratorDescriptor{Digest: r.id(), Length: r.u64(), Count: r.u32()},
		IntendedMembership: readGeneratorDescriptor(&r), LineageID: r.id()}
	v.RetirementMode, v.ChangeMask = r.u8(), r.u8()
	if v.ValueSource == Generated {
		v.LifecycleMode = GeneratorLifecycleMode(r.u8())
	}
	if err := r.end(); err != nil {
		return GeneratorValueEntryPlanView{}, err
	}
	if err := generatorValueEntryPlanError(v.fields(), v.Name); err != nil {
		return GeneratorValueEntryPlanView{}, err
	}
	return v, nil
}

func (v GeneratorValueEntryPlanView) Own() (GeneratorValueEntryPlan, error) {
	out := v.fields()
	if err := generatorValueEntryPlanError(out, v.Name); err != nil {
		return GeneratorValueEntryPlan{}, err
	}
	out.Name = string(v.Name)
	return out, nil
}

func GeneratorValueEntryPlansDescriptor(rows []GeneratorValueEntryPlan) (GeneratorDescriptor, error) {
	if len(rows) > CryptoMaxValueEntries {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	n := 4
	var slots [CryptoMaxValueEntries]bool
	for i, v := range rows {
		length, err := GeneratorValueEntryPlanLength(v)
		if err != nil {
			return GeneratorDescriptor{}, err
		}
		if slots[v.Slot] || i > 0 && rows[i-1].Name >= v.Name {
			return GeneratorDescriptor{}, ErrRecord
		}
		slots[v.Slot] = true
		n += 4 + length
	}
	w := generatorVectorHashWriter("member-plans", n, len(rows))
	for _, v := range rows {
		w.u32(uint32(generatorValueEntryPlanEncodedLength(v)))
		writeGeneratorValueEntryPlan(&w, v)
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

// GeneratorLineageTemplate is immutable plan input. It contains no phase,
// observed result, current frontier or consumed allowance.
type GeneratorLineageTemplate struct {
	Schema                              uint16
	Purpose                             GeneratorLineagePurpose
	DomainID, OperationID, LineageID    ID
	Name                                string
	EntryIncarnationID                  ID
	Epoch                               uint64
	IntentDigest, ResourceIncarnationID ID
	TemplateCount                       uint8
	Templates                           [5]GeneratorAttemptTemplate
}

type GeneratorLineageTemplateView struct {
	Schema                              uint16
	Purpose                             GeneratorLineagePurpose
	DomainID, OperationID, LineageID    ID
	Name                                []byte
	EntryIncarnationID                  ID
	Epoch                               uint64
	IntentDigest, ResourceIncarnationID ID
	TemplateCount                       uint8
	Templates                           [5]GeneratorAttemptTemplate
}

func generatorLineageTemplateError(v GeneratorLineageTemplate, name []byte) error {
	if len(name) > CryptoMaxName || v.TemplateCount > GeneratorCreateLineageTemplates {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratorLineageTemplateSchema || v.Purpose < GeneratorLineageCreate || v.Purpose > GeneratorLineageCleanup || !utf8.Valid(name) ||
		!publicIDsValid(v.DomainID, v.OperationID, v.LineageID, v.EntryIncarnationID, v.IntentDigest) {
		return ErrRecord
	}
	var wantLineage ID
	var err error
	if v.Purpose == GeneratorLineageCreate {
		if !v.ResourceIncarnationID.IsZero() || v.Schema == GeneratorLineageTemplateSchema && (v.TemplateCount != 1 && v.TemplateCount != 5) {
			return ErrRecord
		}
		wantLineage, err = GeneratorLineageID(v.DomainID, v.OperationID, string(name), v.EntryIncarnationID, v.Epoch, v.IntentDigest)
	} else {
		if v.TemplateCount != GeneratorObligationTemplates || v.ResourceIncarnationID.IsZero() {
			return ErrRecord
		}
		wantLineage, err = GeneratorObligationLineageID(v.DomainID, v.OperationID, v.ResourceIncarnationID, v.Purpose)
	}
	if err != nil || wantLineage != v.LineageID {
		return ErrRecord
	}
	for i := int(v.TemplateCount); i < len(v.Templates); i++ {
		if v.Templates[i] != (GeneratorAttemptTemplate{}) {
			return ErrRecord
		}
	}
	for i := 0; i < int(v.TemplateCount); i++ {
		x := v.Templates[i]
		if !x.valid() || x.Schema != v.Schema || x.LineageID != v.LineageID || x.Branch != uint8(i) || x.IntentDigest != v.IntentDigest {
			return ErrRecord
		}
		if v.Schema == GeneratorLineageTemplateSchema {
			if x.LifecycleMode != v.Templates[0].LifecycleMode || x.LifecycleMode == GeneratorLifecycleNone && (v.Purpose != GeneratorLineageCreate || v.TemplateCount != 1) || x.LifecycleMode == GeneratorLifecycleManaged && v.Purpose == GeneratorLineageCreate && v.TemplateCount != 5 {
				return ErrRecord
			}
		}
		if v.Purpose == GeneratorLineageCreate {
			resource, err := GeneratorResourceID(v.DomainID, v.OperationID, x.AttemptID)
			if err != nil || x.Action != GeneratorActionCreate || x.ResourceIncarnationID != resource {
				return ErrRecord
			}
			duty, err := GeneratorDutyID(v.DomainID, v.OperationID, x.AttemptID, GeneratedDutyCreate)
			if err != nil || x.DutyID != duty {
				return ErrRecord
			}
		} else if x.Action != GeneratorActionDelete || x.ResourceIncarnationID != v.ResourceIncarnationID {
			return ErrRecord
		}
		slot, err := GeneratorValueSlotID(v.DomainID, v.OperationID, x.AttemptID)
		if err != nil || x.PlannedValueSlotID != slot {
			return ErrRecord
		}
		hazard, err := GeneratorHazardID(v.DomainID, x.AttemptID)
		if err != nil || x.LifecycleMode != GeneratorLifecycleNone && x.HazardID != hazard || x.LifecycleMode == GeneratorLifecycleNone && !x.HazardID.IsZero() {
			return ErrRecord
		}
		result, err := GeneratorResultID(v.DomainID, v.OperationID, x.AttemptID, x.TransmissionID, x.Action)
		if err != nil || x.ResultID != result {
			return ErrRecord
		}
		inbox, err := GeneratorInboxID(v.DomainID, v.OperationID, x.AttemptID, x.ResultID)
		if err != nil || x.InboxID != inbox {
			return ErrRecord
		}
		first := v.Templates[0]
		if x.DescriptorID != first.DescriptorID || x.ConfigContractID != first.ConfigContractID || x.ExecutorID != first.ExecutorID ||
			x.CredentialRouteID != first.CredentialRouteID || x.ResourceContractID != first.ResourceContractID || x.ResultContractID != first.ResultContractID ||
			x.ResourceDigest != first.ResourceDigest || x.ResultReaderID != first.ResultReaderID || x.CompletionClass != first.CompletionClass || x.RequiredAuthoritySet != first.RequiredAuthoritySet {
			return ErrRecord
		}
	}
	return nil
}

func GeneratorLineageTemplateLength(v GeneratorLineageTemplate) (int, error) {
	if err := generatorLineageTemplateError(v, []byte(v.Name)); err != nil {
		return 0, err
	}
	return generatorLineageTemplateEncodedLength(v), nil
}

func writeGeneratorLineageTemplate(w *cryptoWriter, v GeneratorLineageTemplate) {
	w.u16(v.Schema)
	w.u8(uint8(v.Purpose))
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.LineageID)
	w.blob([]byte(v.Name))
	w.id(v.EntryIncarnationID)
	w.u64(v.Epoch)
	w.id(v.IntentDigest)
	w.id(v.ResourceIncarnationID)
	w.u8(v.TemplateCount)
	for i := 0; i < int(v.TemplateCount); i++ {
		w.u32(uint32(generatorAttemptTemplateEncodedLength(v.Templates[i])))
		writeGeneratorAttemptTemplate(w, v.Templates[i])
	}
}

func EncodeGeneratorLineageTemplate(v GeneratorLineageTemplate) ([]byte, error) {
	n, err := GeneratorLineageTemplateLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratorLineageTemplate(&w, v)
	return w.b, nil
}

func (v GeneratorLineageTemplateView) fields() GeneratorLineageTemplate {
	return GeneratorLineageTemplate{Schema: v.Schema, Purpose: v.Purpose, DomainID: v.DomainID, OperationID: v.OperationID, LineageID: v.LineageID,
		EntryIncarnationID: v.EntryIncarnationID, Epoch: v.Epoch, IntentDigest: v.IntentDigest, ResourceIncarnationID: v.ResourceIncarnationID,
		TemplateCount: v.TemplateCount, Templates: v.Templates}
}

func InspectGeneratorLineageTemplate(b []byte) (GeneratorLineageTemplateView, error) {
	if len(b) > GeneratorLineageTemplateMaxLength {
		return GeneratorLineageTemplateView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorLineageTemplateView{Schema: r.u16(), Purpose: GeneratorLineagePurpose(r.u8()), DomainID: r.requiredID(), OperationID: r.requiredID(), LineageID: r.requiredID(),
		Name: r.name(), EntryIncarnationID: r.requiredID(), Epoch: r.u64(), IntentDigest: r.requiredID(), ResourceIncarnationID: r.id(), TemplateCount: r.u8()}
	if r.err != nil {
		return GeneratorLineageTemplateView{}, r.failure()
	}
	if v.TemplateCount > GeneratorCreateLineageTemplates {
		return GeneratorLineageTemplateView{}, ErrRecordCapacity
	}
	if v.Purpose < GeneratorLineageCreate || v.Purpose > GeneratorLineageCleanup ||
		v.Purpose == GeneratorLineageCreate && (v.Schema == GeneratorLineageTemplateSchema && v.TemplateCount != 1 && v.TemplateCount != 5) ||
		v.Purpose != GeneratorLineageCreate && v.TemplateCount != GeneratorObligationTemplates {
		return GeneratorLineageTemplateView{}, ErrRecord
	}
	for i := 0; i < int(v.TemplateCount); i++ {
		body := r.blob(GeneratorAttemptTemplateMaxLength)
		if r.err != nil {
			return GeneratorLineageTemplateView{}, r.failure()
		}
		x, err := InspectGeneratorAttemptTemplate(body)
		if err != nil {
			return GeneratorLineageTemplateView{}, err
		}
		v.Templates[i] = x
	}
	if err := r.end(); err != nil {
		return GeneratorLineageTemplateView{}, err
	}
	if err := generatorLineageTemplateError(v.fields(), v.Name); err != nil {
		return GeneratorLineageTemplateView{}, err
	}
	return v, nil
}

func (v GeneratorLineageTemplateView) Own() (GeneratorLineageTemplate, error) {
	out := v.fields()
	if err := generatorLineageTemplateError(out, v.Name); err != nil {
		return GeneratorLineageTemplate{}, err
	}
	out.Name = string(v.Name)
	return out, nil
}

func generatorLineageCompare(a, b GeneratorLineageTemplate) int {
	if a.Name < b.Name {
		return -1
	}
	if a.Name > b.Name {
		return 1
	}
	if a.Purpose < b.Purpose {
		return -1
	}
	if a.Purpose > b.Purpose {
		return 1
	}
	return bytes.Compare(a.ResourceIncarnationID[:], b.ResourceIncarnationID[:])
}

func GeneratorLineageTemplatesDescriptor(rows []GeneratorLineageTemplate) (GeneratorDescriptor, error) {
	if len(rows) > GeneratorMaxLineageTemplates {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	n, creates, templates := 4, 0, 0
	for i, v := range rows {
		length, err := GeneratorLineageTemplateLength(v)
		if err != nil {
			return GeneratorDescriptor{}, err
		}
		if i > 0 && generatorLineageCompare(rows[i-1], v) >= 0 {
			return GeneratorDescriptor{}, ErrRecord
		}
		for j := 0; j < i; j++ {
			if rows[j].LineageID == v.LineageID {
				return GeneratorDescriptor{}, ErrRecord
			}
		}
		n += 4 + length
		templates += int(v.TemplateCount)
		if v.Purpose == GeneratorLineageCreate {
			creates++
		}
	}
	if creates > GeneratorMaxCreateLineages || templates > GeneratorMaxTemplates || n > GeneratorGraphMaxLength {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	w := generatorVectorHashWriter("lineage-templates", n, len(rows))
	for _, v := range rows {
		w.u32(uint32(generatorLineageTemplateEncodedLength(v)))
		writeGeneratorLineageTemplate(&w, v)
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

func GeneratorCompleteJoinID(requestCoreDigest ID) (ID, error) {
	if requestCoreDigest.IsZero() {
		return ID{}, ErrRecord
	}
	return generatorDigest("complete-join", requestCoreDigest[:]), nil
}

func GeneratorValueDerivationID() ID {
	w := cryptoWriter{b: make([]byte, 0, 32)}
	w.blob([]byte("GENERATED-MEMBER-DERIVATION/v2"))
	return generatorDigest("meaning", w.b)
}

type generatorTemplateRef struct {
	id       ID
	template *GeneratorAttemptTemplate
	lineage  *GeneratorLineageTemplate
}

func generatorTemplateRefs(header GeneratorGraphHeader, lineages []GeneratorLineageTemplate, refs *[GeneratorMaxTemplates]generatorTemplateRef) (int, error) {
	count, creates := 0, 0
	for i := range lineages {
		lineage := &lineages[i]
		if lineage.Schema != header.Schema || lineage.DomainID != header.DomainID || lineage.OperationID != header.OperationID {
			return 0, ErrRecord
		}
		if lineage.Purpose == GeneratorLineageCreate {
			creates++
		}
		for j := 0; j < int(lineage.TemplateCount); j++ {
			if count == len(refs) {
				return 0, ErrRecordCapacity
			}
			x := &lineage.Templates[j]
			id, err := GeneratorTemplateID(*x)
			if err != nil {
				return 0, err
			}
			refs[count] = generatorTemplateRef{id: id, template: x, lineage: lineage}
			count++
		}
	}
	if creates != int(header.LineageCount) || count != int(header.TemplateCount) {
		return 0, ErrRecord
	}
	return count, nil
}

func generatorGraphEntryPlansError(entryPlans []GeneratorValueEntryPlan, lineages []GeneratorLineageTemplate) error {
	matched := 0
	for _, entryPlan := range entryPlans {
		if entryPlan.ValueSource != Generated || entryPlan.ChangeMask&GeneratorValueChangeContent == 0 {
			continue
		}
		found := false
		for _, lineage := range lineages {
			if lineage.Purpose != GeneratorLineageCreate || lineage.LineageID != entryPlan.LineageID {
				continue
			}
			if found || lineage.Name != entryPlan.Name || lineage.EntryIncarnationID != entryPlan.EntryIncarnationID || lineage.Epoch != entryPlan.Epoch ||
				lineage.IntentDigest != entryPlan.IntentDigest || lineage.Templates[0].LifecycleMode != entryPlan.LifecycleMode || lineage.Templates[0].PlannedValueSlotID != entryPlan.PlannedValueSlotID {
				return ErrRecord
			}
			found = true
			matched++
		}
		if !found {
			return ErrRecord
		}
	}
	creates := 0
	for _, lineage := range lineages {
		if lineage.Purpose == GeneratorLineageCreate {
			creates++
		}
	}
	if matched != creates {
		return ErrRecord
	}
	return nil
}

func generatorGraphDeleteTargetsError(refs []generatorTemplateRef) error {
	hasCreate := false
	for _, ref := range refs {
		if ref.template.Action == GeneratorActionCreate {
			hasCreate = true
			break
		}
	}
	for _, ref := range refs {
		x := ref.template
		if x.Action != GeneratorActionDelete {
			continue
		}
		if ref.lineage.Purpose == GeneratorLineageRetirement {
			if x.TargetKind != GeneratorTargetOwnedResource {
				return ErrRecord
			}
			continue
		}
		if ref.lineage.Purpose != GeneratorLineageCleanup || x.TargetKind != GeneratorTargetResultResourceSlot {
			return ErrRecord
		}
		// A fresh cleanup reservation names a result produced by an earlier,
		// closed operation. Core binds that external result to the selected
		// detached cleanup obligation. A graph that also creates results must
		// continue to bind every cleanup to its producer in this graph.
		if !hasCreate {
			continue
		}
		found := false
		for _, producer := range refs {
			p := producer.template
			if p.Action != GeneratorActionCreate || p.ResultID != x.TargetSourceID {
				continue
			}
			if found || p.ResourceIncarnationID != x.ResourceIncarnationID || p.DutyID != x.DutyID ||
				p.ResourceDigest != x.ResourceDigest || p.LifecycleMode != x.LifecycleMode || p.ResourceContractID != x.ResourceContractID ||
				p.DescriptorID != x.DescriptorID || p.ExecutorID != x.ExecutorID || p.CredentialRouteID != x.CredentialRouteID || p.ResultReaderID != x.ResultReaderID ||
				p.ConfigContractID != x.ConfigContractID || p.IntentDigest != x.IntentDigest ||
				p.CompletionClass != x.CompletionClass || producer.lineage.Name != ref.lineage.Name || producer.lineage.EntryIncarnationID != ref.lineage.EntryIncarnationID ||
				producer.lineage.Epoch != ref.lineage.Epoch {
				return ErrRecord
			}
			found = true
		}
		if !found {
			return ErrRecord
		}
	}
	return nil
}

func generatorBranchUsed(branch uint8) (uint8, uint8) {
	var noEffect, residue uint8
	if branch == GeneratorBranchNoEffect || branch == GeneratorBranchNoEffectThenResidue || branch == GeneratorBranchResidueThenNoEffect {
		noEffect = 1
	}
	if branch >= GeneratorBranchResidue {
		residue = 1
	}
	return noEffect, residue
}

func generatorGraphEdgesError(join ID, refs []generatorTemplateRef, edges []GeneratorEdge) error {
	var seen [GeneratorMaxTemplates]uint8
	for _, edge := range edges {
		index := -1
		for i, ref := range refs {
			if ref.id == edge.SourceTemplateID {
				index = i
				break
			}
		}
		if index < 0 {
			return ErrRecord
		}
		ref := refs[index]
		x := ref.template
		bit := uint8(1 << (edge.Guard - 1))
		if seen[index]&bit != 0 || edge.ResultSlotID != x.ResultID || edge.RequiredAuthoritySet != x.RequiredAuthoritySet {
			return ErrRecord
		}
		seen[index] |= bit
		targetBranch, destination := x.Branch, join
		if edge.Guard < GeneratorGuardQualifiedSuccess {
			if x.Action != GeneratorActionCreate || x.LifecycleMode == GeneratorLifecycleNone {
				return ErrRecord
			}
			next, present, err := GeneratorSuccessorBranch(x.Branch, edge.Guard)
			if err != nil || !present {
				return ErrRecord
			}
			targetBranch = next
			destination, err = GeneratorTemplateID(ref.lineage.Templates[next])
			if err != nil {
				return err
			}
		}
		noEffect, residue := generatorBranchUsed(targetBranch)
		if edge.DestinationTemplateID != destination || edge.NoEffectUsed != noEffect || edge.ResidueUsed != residue {
			return ErrRecord
		}
	}
	for i, ref := range refs {
		want := uint8(generatorGuardSuccessBit | generatorGuardTerminalBit)
		if ref.template.Action == GeneratorActionCreate && ref.template.LifecycleMode != GeneratorLifecycleNone {
			switch ref.template.Branch {
			case GeneratorBranchInitial:
				want = generatorGuardNoEffectBit | generatorGuardResidueBit | generatorGuardSuccessBit | generatorGuardTerminalBit
			case GeneratorBranchNoEffect:
				want = generatorGuardResidueBit | generatorGuardSuccessBit | generatorGuardTerminalBit
			case GeneratorBranchResidue:
				want = generatorGuardNoEffectBit | generatorGuardSuccessBit | generatorGuardTerminalBit
			}
		}
		if seen[i] != want {
			return ErrRecord
		}
	}
	return nil
}

// GeneratorGraphID validates the complete immutable graph. Its join is an
// aggregation coordinate, never a template or provider dispatch permission.
// Retained-resource ownership and profile evidence need selected Core facts.
func GeneratorGraphID(header GeneratorGraphHeader, entryPlans []GeneratorValueEntryPlan, lineages []GeneratorLineageTemplate, edges []GeneratorEdge) (ID, error) {
	if err := generatorGraphHeaderError(header); err != nil {
		return ID{}, err
	}
	for _, plan := range entryPlans {
		if plan.Schema != GeneratorValueEntryPlanSchema {
			return ID{}, ErrRecord
		}
	}
	entryPlansDescriptor, err := GeneratorValueEntryPlansDescriptor(entryPlans)
	if err != nil {
		return ID{}, err
	}
	lineageDescriptor, err := GeneratorLineageTemplatesDescriptor(lineages)
	if err != nil {
		return ID{}, err
	}
	edgeDescriptor, err := GeneratorTransitionRulesDescriptor(edges)
	if err != nil {
		return ID{}, err
	}
	if entryPlansDescriptor.Count != uint32(header.ValueEntryPlanCount) {
		return ID{}, ErrRecord
	}
	if GeneratorGraphHeaderLength+entryPlansDescriptor.Length+lineageDescriptor.Length+edgeDescriptor.Length > GeneratorGraphMaxLength {
		return ID{}, ErrRecordCapacity
	}
	var storage [GeneratorMaxTemplates]generatorTemplateRef
	count, err := generatorTemplateRefs(header, lineages, &storage)
	if err != nil {
		return ID{}, err
	}
	refs := storage[:count]
	if err := generatorGraphEntryPlansError(entryPlans, lineages); err != nil {
		return ID{}, err
	}
	if err := generatorGraphDeleteTargetsError(refs); err != nil {
		return ID{}, err
	}
	join, err := GeneratorCompleteJoinID(header.RequestCoreDigest)
	if err != nil {
		return ID{}, err
	}
	if err := generatorGraphEdgesError(join, refs, edges); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(generatorIdentityPrefix + "graph\x00")
	w.u32(GeneratorGraphHeaderLength + 3*GeneratorDescriptorLength)
	writeGeneratorGraphHeader(&w, header)
	writeGeneratorDescriptor(&w, entryPlansDescriptor)
	writeGeneratorDescriptor(&w, lineageDescriptor)
	writeGeneratorDescriptor(&w, edgeDescriptor)
	return w.result(0).Digest, nil
}

// ValidateGeneratorGraphRequest binds the earlier request to its graph without
// involving operation material, its SeedCheck, or the later request identity.
func ValidateGeneratorGraphRequest(request GeneratorRequestCore, header GeneratorGraphHeader) error {
	digest, err := GeneratorRequestCoreDigest(request)
	if err != nil {
		return err
	}
	if err := generatorGraphHeaderError(header); err != nil {
		return err
	}
	if request.DomainID != header.DomainID || request.OperationID != header.OperationID || request.RecoveryPolicyID != header.RecoveryPolicyID || digest != header.RequestCoreDigest {
		return ErrRecord
	}
	return nil
}

// ValidateGeneratorResultUses requires one exact private-result use for every
// reserved template, including inactive branches. A delete's mechanical value
// slot never permits secret bytes.
func ValidateGeneratorResultUses(header GeneratorGraphHeader, lineages []GeneratorLineageTemplate, uses []GeneratorResultUse) error {
	if err := generatorGraphHeaderError(header); err != nil {
		return err
	}
	if _, err := GeneratorLineageTemplatesDescriptor(lineages); err != nil {
		return err
	}
	if _, err := GeneratorResultUsesDescriptor(uses); err != nil {
		return err
	}
	if len(uses) != int(header.TemplateCount) {
		return ErrRecord
	}
	var storage [GeneratorMaxTemplates]generatorTemplateRef
	count, err := generatorTemplateRefs(header, lineages, &storage)
	if err != nil {
		return err
	}
	var seen [GeneratorMaxTemplates]bool
	for _, use := range uses {
		index := -1
		for i, ref := range storage[:count] {
			if ref.template.AttemptID == use.AttemptID {
				index = i
				break
			}
		}
		if index < 0 || seen[index] {
			return ErrRecord
		}
		seen[index] = true
		x := storage[index].template

		if use.ResultID != x.ResultID || use.InboxID != x.InboxID || use.ExecutorID != x.ExecutorID || use.ResultContractID != x.ResultContractID ||
			use.PlannedValueSlotID != x.PlannedValueSlotID || use.MaterialID != header.MaterialID || (x.Action == GeneratorActionDelete) != (use.MaxSecret == 0) {
			return ErrRecord
		}
	}
	return nil
}

type GeneratorUsePlanCore struct {
	DomainID, OperationID, MaterialID, PlanGraphID ID
	ResultUses, SourceUses                         GeneratorDescriptor
	ValueDerivationID                              ID
}

func generatorUsePlanError(v GeneratorUsePlanCore) error {
	if v.ResultUses.Count > GeneratorMaxTemplates || v.SourceUses.Count > CryptoMaxValueEntries ||
		v.ResultUses.Length > 4+GeneratorMaxTemplates*(4+GeneratorResultUseLength) || v.SourceUses.Length > 4+CryptoMaxValueEntries*(4+GeneratorSourceUseLength) {
		return ErrRecordCapacity
	}
	if !publicIDsValid(v.DomainID, v.OperationID, v.MaterialID, v.PlanGraphID) || !generatedDescriptorsValid(v.ResultUses, v.SourceUses) ||
		v.ResultUses.Length != 4+uint64(v.ResultUses.Count)*(4+GeneratorResultUseLength) || v.SourceUses.Length != 4+uint64(v.SourceUses.Count)*(4+GeneratorSourceUseLength) ||
		v.ValueDerivationID != GeneratorValueDerivationID() {
		return ErrRecord
	}
	material, err := GeneratorMaterialID(v.DomainID, v.OperationID)
	if err != nil || material != v.MaterialID {
		return ErrRecord
	}
	if v.ResultUses.Count == 0 {
		empty, err := GeneratorResultUsesDescriptor(nil)
		if err != nil {
			return err
		}
		if v.ResultUses != empty {
			return ErrRecord
		}
	}
	if v.SourceUses.Count == 0 {
		empty, err := GeneratorSourceUsesDescriptor(nil)
		if err != nil {
			return err
		}
		if v.SourceUses != empty {
			return ErrRecord
		}
	}
	return nil
}

func writeGeneratorUsePlanCore(w *cryptoWriter, v GeneratorUsePlanCore) {
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.MaterialID)
	w.id(v.PlanGraphID)
	writeGeneratorDescriptor(w, v.ResultUses)
	writeGeneratorDescriptor(w, v.SourceUses)
	w.id(v.ValueDerivationID)
}

func EncodeGeneratorUsePlanCore(v GeneratorUsePlanCore) ([]byte, error) {
	if err := generatorUsePlanError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorUsePlanCoreLength)}
	writeGeneratorUsePlanCore(&w, v)
	return w.b, nil
}

func InspectGeneratorUsePlanCore(b []byte) (GeneratorUsePlanCore, error) {
	if len(b) > GeneratorUsePlanCoreLength {
		return GeneratorUsePlanCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorUsePlanCore{DomainID: r.requiredID(), OperationID: r.requiredID(), MaterialID: r.requiredID(), PlanGraphID: r.requiredID(),
		ResultUses: readGeneratorDescriptor(&r), SourceUses: readGeneratorDescriptor(&r), ValueDerivationID: r.requiredID()}
	if err := r.end(); err != nil {
		return GeneratorUsePlanCore{}, err
	}
	if err := generatorUsePlanError(v); err != nil {
		return GeneratorUsePlanCore{}, err
	}
	return v, nil
}

func GeneratorUsePlanDigest(v GeneratorUsePlanCore) (ID, error) {
	if err := generatorUsePlanError(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(generatorIdentityPrefix + "use-plan\x00")
	w.u32(GeneratorUsePlanCoreLength)
	writeGeneratorUsePlanCore(&w, v)
	return w.result(0).Digest, nil
}
