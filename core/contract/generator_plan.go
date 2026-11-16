package contract

import protocol "enkv.sh/sdk/protocols/generator"

const (
	GeneratorActionCreate = protocol.ActionCreate
	GeneratorActionDelete = protocol.ActionRetire
)

const (
	GeneratorBranchInitial             = 0
	GeneratorBranchNoEffect            = 1
	GeneratorBranchResidue             = 2
	GeneratorBranchNoEffectThenResidue = 3
	GeneratorBranchResidueThenNoEffect = 4
)

const (
	GeneratorTargetCreateIntent       = 1
	GeneratorTargetOwnedResource      = 2
	GeneratorTargetResultResourceSlot = 3
)

// GeneratorAttemptTemplateLength is the exact retained schema1 length.
const GeneratorAttemptTemplateLength = 682
const GeneratorAttemptTemplateMaxLength = 682

// GeneratorAttemptTemplate fixes semantic identities before an effect exists.
// Its target slot may be resolved only by the owning admitted graph.
type GeneratorAttemptTemplate struct {
	ResultReaderID        ID
	LifecycleMode         GeneratorLifecycleMode
	Schema                uint16
	Branch, Action        uint8
	LineageID             ID
	AttemptID             ID
	PredecessorAttemptID  ID
	ResourceIncarnationID ID
	PlannedValueSlotID    ID
	DutyID                ID
	HazardID              ID
	TransmissionID        ID
	ResultID              ID
	InboxID               ID
	DescriptorID          ID
	ConfigContractID      ID
	ExecutorID            ID
	CredentialRouteID     ID
	ResourceContractID    ID
	ResultContractID      ID
	RequestPlanDigest     ID
	IntentDigest          ID
	ResourceDigest        ID
	TargetKind            uint8
	TargetSourceID        ID
	CompletionClass       uint8
	NoEffectBudget        uint8
	ResidueBudget         uint8
	RequiredAuthoritySet  uint8
}

func generatorRequestTargetValid(v GeneratorAttemptTemplate) bool {
	if v.IntentDigest.IsZero() {
		return false
	}
	if v.Action == GeneratorActionCreate {
		return v.ResourceDigest.IsZero() && (v.LifecycleMode == GeneratorLifecycleNone && v.TargetKind == 0 && v.TargetSourceID.IsZero() || v.LifecycleMode == GeneratorLifecycleManaged && v.TargetKind == GeneratorTargetCreateIntent && v.TargetSourceID == v.IntentDigest)
	}
	return v.Action == GeneratorActionDelete && v.LifecycleMode == GeneratorLifecycleManaged && !v.TargetSourceID.IsZero() && (v.TargetKind == GeneratorTargetOwnedResource && v.TargetSourceID == v.ResourceIncarnationID && !v.ResourceDigest.IsZero() || v.TargetKind == GeneratorTargetResultResourceSlot)
}

func GeneratorRequestPlanDigest(v GeneratorAttemptTemplate) (ID, error) {
	if v.Schema != GeneratorAttemptTemplateSchema || !v.LifecycleMode.resourceValid(v.ResourceContractID) || !publicIDsValid(v.ConfigContractID, v.IntentDigest, v.ResultContractID) || !generatorRequestTargetValid(v) {
		return ID{}, ErrRecord
	}
	var w cryptoWriter
	w.u8(v.Action)
	w.id(v.ConfigContractID)
	w.u8(uint8(v.LifecycleMode))
	w.id(v.ResourceContractID)
	w.u8(v.TargetKind)
	w.id(v.TargetSourceID)
	w.id(v.ResourceDigest)
	w.id(v.IntentDigest)
	w.id(v.ResultContractID)
	return generatorDigest("request-plan-v4", w.b), nil
}

func writeGeneratorAttemptTemplate(w *cryptoWriter, v GeneratorAttemptTemplate) {
	w.u16(v.Schema)
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.Branch)
	w.u8(v.Action)
	for _, id := range []ID{v.LineageID, v.AttemptID, v.PredecessorAttemptID, v.ResourceIncarnationID,
		v.PlannedValueSlotID, v.DutyID, v.HazardID, v.TransmissionID, v.ResultID, v.InboxID,
		v.DescriptorID, v.ConfigContractID, v.ExecutorID, v.CredentialRouteID, v.ResourceContractID,
		v.ResultContractID, v.RequestPlanDigest, v.IntentDigest, v.ResourceDigest} {
		w.id(id)
	}
	w.u8(v.TargetKind)
	w.id(v.TargetSourceID)
	w.u8(v.CompletionClass)
	w.u8(v.NoEffectBudget)
	w.u8(v.ResidueBudget)
	w.u8(v.RequiredAuthoritySet)
	w.id(v.ResultReaderID)
}

func readGeneratorAttemptTemplateFields(r *cryptoReader) GeneratorAttemptTemplate {
	v := GeneratorAttemptTemplate{Schema: r.u16(), LifecycleMode: GeneratorLifecycleMode(r.u8()), Branch: r.u8(), Action: r.u8(),
		LineageID: r.id(), AttemptID: r.id(), PredecessorAttemptID: r.id(),
		ResourceIncarnationID: r.id(), PlannedValueSlotID: r.id(), DutyID: r.id(), HazardID: r.id(),
		TransmissionID: r.id(), ResultID: r.id(), InboxID: r.id(), DescriptorID: r.id(), ConfigContractID: r.id(),
		ExecutorID: r.id(), CredentialRouteID: r.id(), ResourceContractID: r.id(), ResultContractID: r.id(),
		RequestPlanDigest: r.id(), IntentDigest: r.id(), ResourceDigest: r.id(), TargetKind: r.u8(), TargetSourceID: r.id(),
		CompletionClass: r.u8(), NoEffectBudget: r.u8(), ResidueBudget: r.u8(), RequiredAuthoritySet: r.u8(), ResultReaderID: r.requiredID()}
	return v
}

func AppendGeneratorAttemptTemplate(dst []byte, v GeneratorAttemptTemplate) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeGeneratorAttemptTemplate(&w, v)
	return w.b, nil
}

func EncodeGeneratorAttemptTemplate(v GeneratorAttemptTemplate) ([]byte, error) {
	return AppendGeneratorAttemptTemplate(make([]byte, 0, generatorAttemptTemplateEncodedLength(v)), v)
}

func InspectGeneratorAttemptTemplate(b []byte) (GeneratorAttemptTemplate, error) {
	if len(b) > GeneratorAttemptTemplateMaxLength {
		return GeneratorAttemptTemplate{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readGeneratorAttemptTemplateFields(&r)
	if !v.valid() {
		return GeneratorAttemptTemplate{}, ErrRecord
	}
	if err := r.end(); err != nil {
		return GeneratorAttemptTemplate{}, err
	}
	return v, nil
}

func GeneratorTemplateID(v GeneratorAttemptTemplate) (ID, error) {
	if !v.valid() {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, generatorAttemptTemplateEncodedLength(v))}
	writeGeneratorAttemptTemplate(&w, v)
	label := "template"
	if v.Schema == GeneratorAttemptTemplateSchema {
		label = "template-v2"
	}
	return generatorDigest(label, w.b), nil
}
