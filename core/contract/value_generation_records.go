package contract

import (
	"unicode/utf8"

	protocol "enkv.sh/sdk/protocols/generator"
)

const GeneratedParentSchema uint16 = 2
const GeneratedPhaseSchema uint16 = 2

const GeneratedEntryMetadataFixedLength = 390

const (
	GeneratedCurrentEntryLimit     = 128
	GeneratedRetirementLimit       = 128
	GeneratedHandoffLimit          = 128
	GeneratedFragmentLocationLimit = 512
	GeneratedFragmentHeaderLength  = 86
)

const (
	GeneratorRecordSchema               uint16 = 1
	GeneratorDescriptorLength                  = 44
	GeneratedParentRecordBodyLength            = 592
	GeneratedPhaseRecordBodyLength             = 716
	GeneratedLineageRecordMaxLength            = 534
	GeneratedAttemptRecordBodyLength           = 765
	GeneratedAttemptRecordFixedLength          = 760
	GeneratedDutyRecordBodyLength              = 661
	GeneratedDutyRecordFixedLength             = 655
	GeneratedHazardRecordBodyLength            = 654
	PendingInboxReleaseRecordBodyLength        = 211
	GeneratedFragmentMaxPayload                = 1<<20 - 256
	GeneratedFragmentMaxLength                 = GeneratedFragmentHeaderLength + GeneratedFragmentMaxPayload
	GeneratedCreateEvidenceMaxLength           = 4668
	GeneratedEntryMetadataMaxLength            = 460
)

const (
	GeneratedEffectNotStarted uint8 = iota + 1
	GeneratedEffectPrepared
	GeneratedEffectTransmitted
	GeneratedEffectSucceeded
	GeneratedEffectConfirmedNoEffect
	GeneratedEffectFailedTerminal
	GeneratedEffectUnknown
	GeneratedEffectPossibleLive
	GeneratedEffectClosedWithResidue
)

const (
	GeneratedStageRetainedResult uint8 = iota + 1
	GeneratedStageObservation
	GeneratedStageExactRetry
	GeneratedStageResidue
	GeneratedStageTerminal
)

const (
	GeneratedCompletionAcknowledged uint8 = protocol.CompletionAcknowledged
	GeneratedCompletionConfirmed    uint8 = protocol.CompletionConfirmed
	GeneratedRetirementManual       uint8 = 1
	GeneratedRetirementAuto         uint8 = 2
	GeneratedDutyCreate             uint8 = 1
	GeneratedDutyRetirement         uint8 = 2
	GeneratedDutyUnselectedCleanup  uint8 = 3
	GeneratedExposurePossibleLive   uint8 = 1
	GeneratedExposureLateEffect     uint8 = 2
	GeneratedReleasePending         uint8 = 1
	GeneratedReleaseUnknown         uint8 = 2
	GeneratedReleaseUnobserved      uint8 = 3
)

// GeneratorDescriptor names a count-and-length-framed logical vector. Its
// digest and the exact row family must be verified against selected contents.
type GeneratorDescriptor struct {
	Digest ID
	Length uint64
	Count  uint32
}

func (v GeneratorDescriptor) Valid() bool {
	if v.Digest.IsZero() {
		return false
	}
	if v.Count == 0 {
		return v.Length == 4
	}
	return v.Length >= 4+4*uint64(v.Count)
}

func generatedDescriptorsValid(values ...GeneratorDescriptor) bool {
	for _, v := range values {
		if !v.Valid() {
			return false
		}
	}
	return true
}

func writeGeneratorDescriptor(w *cryptoWriter, v GeneratorDescriptor) {
	w.id(v.Digest)
	w.u64(v.Length)
	w.u32(v.Count)
}

func readGeneratorDescriptor(r *cryptoReader) GeneratorDescriptor {
	v := GeneratorDescriptor{Digest: r.requiredID(), Length: r.u64(), Count: r.u32()}
	if r.err == nil && !v.Valid() {
		r.err = ErrRecord
	}
	return v
}

func AppendGeneratorDescriptor(dst []byte, v GeneratorDescriptor) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeGeneratorDescriptor(&w, v)
	return w.b, nil
}

func ParseGeneratorDescriptor(b []byte) (GeneratorDescriptor, int, error) {
	r := newRecordReader(b)
	v := readGeneratorDescriptor(&r)
	if r.err != nil {
		return GeneratorDescriptor{}, 0, r.failure()
	}
	return v, r.i, nil
}

func DecodeGeneratorDescriptor(b []byte) (GeneratorDescriptor, error) {
	if len(b) > GeneratorDescriptorLength {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readGeneratorDescriptor(&r)
	if err := r.end(); err != nil {
		return GeneratorDescriptor{}, err
	}
	return v, nil
}

func generatedCompletionValid(v uint8) bool {
	return v == GeneratedCompletionAcknowledged || v == GeneratedCompletionConfirmed
}

func generatedStageValid(v uint8) bool {
	return v >= GeneratedStageRetainedResult && v <= GeneratedStageTerminal
}

func generatedBranchValid(branch, noEffectUsed, residueUsed uint8) bool {
	switch branch {
	case GeneratorBranchInitial:
		return noEffectUsed == 0 && residueUsed == 0
	case GeneratorBranchNoEffect:
		return noEffectUsed == 1 && residueUsed == 0
	case GeneratorBranchResidue:
		return noEffectUsed == 0 && residueUsed == 1
	case GeneratorBranchNoEffectThenResidue, GeneratorBranchResidueThenNoEffect:
		return noEffectUsed == 1 && residueUsed == 1
	default:
		return false
	}
}

// GeneratedParentRecord commits the immutable accepted request and plan.
// Structural parsing does not establish selected ownership or authority.
type GeneratedParentRecord struct {
	Schema                                                                 uint16
	DomainID, OperationID, RequestIdentityDigest, RequestCoreDigest        ID
	PlanGraphID, UsePlanDigest, MaterialID, RecoveryPolicyID               ID
	ValueEntryPlanCount, LineageCount, TemplateCount                       uint16
	Declaration, Registry, Graph, SourceUses, IntendedEntryPlans, Capacity GeneratorDescriptor
	InitialPredecessorDigest, ConditionDigest                              ID
}

func generatedParentFieldsError(v GeneratedParentRecord) error {
	if v.ValueEntryPlanCount > CryptoMaxValueEntries || v.LineageCount > GeneratorMaxCreateLineages || v.TemplateCount > GeneratorMaxTemplates {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratedParentSchema || v.TemplateCount < v.LineageCount ||
		!publicIDsValid(v.DomainID, v.OperationID, v.RequestCoreDigest, v.PlanGraphID,
			v.UsePlanDigest, v.MaterialID, v.RecoveryPolicyID,
			v.InitialPredecessorDigest, v.ConditionDigest) ||
		!generatedDescriptorsValid(v.Declaration, v.Registry, v.Graph, v.SourceUses, v.IntendedEntryPlans, v.Capacity) {
		return ErrRecord
	}
	return nil
}

func GeneratedParentRecordLength(v GeneratedParentRecord) (int, error) {
	if err := generatedParentFieldsError(v); err != nil {
		return 0, err
	}
	if v.RequestIdentityDigest.IsZero() {
		return 0, ErrRecord
	}
	return GeneratedParentRecordBodyLength, nil
}

// GeneratedParentPlan is used until the final request identity exists. Its
// one request-identity hole cannot pass the stored parent reader.
type GeneratedParentPlan GeneratedParentRecord

func GeneratedParentPlanLength(v GeneratedParentPlan) (int, error) {
	if err := generatedParentFieldsError(GeneratedParentRecord(v)); err != nil {
		return 0, err
	}
	if !v.RequestIdentityDigest.IsZero() {
		return 0, ErrRecord
	}
	return GeneratedParentRecordBodyLength, nil
}

func EncodeGeneratedParentPlan(v GeneratedParentPlan) ([]byte, error) {
	n, err := GeneratedParentPlanLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedParentRecord(&w, GeneratedParentRecord(v))
	return w.b, nil
}

func InspectGeneratedParentPlan(b []byte) (GeneratedParentPlan, error) {
	if len(b) > GeneratedParentRecordBodyLength {
		return GeneratedParentPlan{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedParentPlan(readGeneratedParentFields(&r))
	if err := r.end(); err != nil {
		return GeneratedParentPlan{}, err
	}
	if _, err := GeneratedParentPlanLength(v); err != nil {
		return GeneratedParentPlan{}, err
	}
	return v, nil
}

func writeGeneratedParentRecord(w *cryptoWriter, v GeneratedParentRecord) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.RequestIdentityDigest)
	w.id(v.RequestCoreDigest)
	w.id(v.PlanGraphID)
	w.id(v.UsePlanDigest)
	w.id(v.MaterialID)

	w.id(v.RecoveryPolicyID)
	w.u16(v.ValueEntryPlanCount)
	w.u16(v.LineageCount)
	w.u16(v.TemplateCount)
	writeGeneratorDescriptor(w, v.Declaration)
	writeGeneratorDescriptor(w, v.Registry)
	writeGeneratorDescriptor(w, v.Graph)
	writeGeneratorDescriptor(w, v.SourceUses)
	writeGeneratorDescriptor(w, v.IntendedEntryPlans)
	writeGeneratorDescriptor(w, v.Capacity)
	w.id(v.InitialPredecessorDigest)
	w.id(v.ConditionDigest)
}

func AppendGeneratedParentRecord(dst []byte, v GeneratedParentRecord) ([]byte, error) {
	if _, err := GeneratedParentRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedParentRecord(&w, v)
	return w.b, nil
}

func EncodeGeneratedParentRecord(v GeneratedParentRecord) ([]byte, error) {
	n, err := GeneratedParentRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedParentRecord(&w, v)
	return w.b, nil
}

func readGeneratedParentFields(r *cryptoReader) GeneratedParentRecord {
	return GeneratedParentRecord{Schema: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID(),
		RequestIdentityDigest: r.id(), RequestCoreDigest: r.requiredID(), PlanGraphID: r.requiredID(),
		UsePlanDigest: r.requiredID(), MaterialID: r.requiredID(),
		RecoveryPolicyID: r.requiredID(), ValueEntryPlanCount: r.u16(), LineageCount: r.u16(), TemplateCount: r.u16(),
		Declaration: readGeneratorDescriptor(r), Registry: readGeneratorDescriptor(r), Graph: readGeneratorDescriptor(r),
		SourceUses: readGeneratorDescriptor(r), IntendedEntryPlans: readGeneratorDescriptor(r), Capacity: readGeneratorDescriptor(r),
		InitialPredecessorDigest: r.requiredID(), ConditionDigest: r.requiredID()}
}

func InspectGeneratedParentRecord(b []byte) (GeneratedParentRecord, error) {
	if len(b) > GeneratedParentRecordBodyLength {
		return GeneratedParentRecord{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readGeneratedParentFields(&r)
	if err := r.end(); err != nil {
		return GeneratedParentRecord{}, err
	}
	if _, err := GeneratedParentRecordLength(v); err != nil {
		return GeneratedParentRecord{}, err
	}
	return v, nil
}

func DecodeGeneratedParentRecord(b []byte) (GeneratedParentRecord, error) {
	return InspectGeneratedParentRecord(b)
}

type GeneratedPhaseRecord struct {
	Schema                                                              uint16
	DomainID, OperationID, PlanGraphID, UsePlanDigest, OwnerID, PhaseID ID
	FrontierAttemptID, AcceptedResultID, ResultDigest                   ID
	Phase                                                               uint32
	LineageIndex                                                        uint16
	Branch, Stage, NoEffectUsed, ResidueUsed                            uint8
	AcceptedResults, Attempts, Duties, Hazards, PendingReleases, Proofs GeneratorDescriptor
	FinalPreparationID                                                  ID
	SelectionPhaseID                                                    ID
	ChangedSubjects, ChangedAccess                                      GeneratorDescriptor
}

func GeneratedPhaseRecordLength(v GeneratedPhaseRecord) (int, error) {
	if v.LineageIndex > GeneratorMaxLineageTemplates {
		return 0, ErrRecordCapacity
	}
	if v.Schema != GeneratedPhaseSchema || v.Phase == 0 || !generatedStageValid(v.Stage) ||
		!publicIDsValid(v.DomainID, v.OperationID, v.PlanGraphID, v.UsePlanDigest, v.OwnerID, v.PhaseID) ||
		v.AcceptedResultID.IsZero() != v.ResultDigest.IsZero() ||
		!generatedDescriptorsValid(v.AcceptedResults, v.Attempts, v.Duties, v.Hazards, v.PendingReleases) ||
		!GeneratorVectorShapeValid(GeneratorVectorProofs, v.Proofs) {
		return 0, ErrRecord
	}
	if v.SelectionPhaseID.IsZero() {
		if v.ChangedSubjects != (GeneratorDescriptor{}) || v.ChangedAccess != (GeneratorDescriptor{}) {
			return 0, ErrRecord
		}
	} else {
		emptySubjects, err := ChangedSubjectDescriptor(nil)
		if err != nil {
			return 0, err
		}
		emptyAccess, err := AccessChangeDescriptor(v.DomainID, nil)
		if err != nil {
			return 0, err
		}
		if !v.ChangedSubjects.Valid() || v.ChangedSubjects.Count > MutationChangedSubjectLimit ||
			v.ChangedSubjects.Length != 4+38*uint64(v.ChangedSubjects.Count) ||
			v.ChangedSubjects.Count == 0 && v.ChangedSubjects != emptySubjects ||
			!v.ChangedAccess.Valid() || v.ChangedAccess.Count > AccessMaterialLimit ||
			v.ChangedAccess.Length != 4+102*uint64(v.ChangedAccess.Count) ||
			v.ChangedAccess.Count == 0 && v.ChangedAccess != emptyAccess {
			return 0, ErrRecord
		}
	}
	if !v.FinalPreparationID.IsZero() && v.Stage != GeneratedStageTerminal {
		return 0, ErrRecord
	}
	if v.LineageIndex == GeneratorMaxLineageTemplates {
		if v.Stage != GeneratedStageTerminal || !v.FrontierAttemptID.IsZero() || v.Branch != GeneratorBranchInitial || v.NoEffectUsed != 0 || v.ResidueUsed != 0 {
			return 0, ErrRecord
		}
	} else if v.FrontierAttemptID.IsZero() || !generatedBranchValid(v.Branch, v.NoEffectUsed, v.ResidueUsed) {
		return 0, ErrRecord
	}
	return GeneratedPhaseRecordBodyLength, nil
}

func writeGeneratedPhaseRecord(w *cryptoWriter, v GeneratedPhaseRecord) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.PlanGraphID)
	w.id(v.UsePlanDigest)
	w.id(v.OwnerID)
	w.id(v.PhaseID)
	w.id(v.FrontierAttemptID)
	w.id(v.AcceptedResultID)
	w.id(v.ResultDigest)
	w.u32(v.Phase)
	w.u16(v.LineageIndex)
	w.u8(v.Branch)
	w.u8(v.Stage)
	w.u8(v.NoEffectUsed)
	w.u8(v.ResidueUsed)
	writeGeneratorDescriptor(w, v.AcceptedResults)
	writeGeneratorDescriptor(w, v.Attempts)
	writeGeneratorDescriptor(w, v.Duties)
	writeGeneratorDescriptor(w, v.Hazards)
	writeGeneratorDescriptor(w, v.PendingReleases)
	writeGeneratorDescriptor(w, v.Proofs)
	w.id(v.FinalPreparationID)
	w.id(v.SelectionPhaseID)
	writeGeneratorDescriptor(w, v.ChangedSubjects)
	writeGeneratorDescriptor(w, v.ChangedAccess)
}

func AppendGeneratedPhaseRecord(dst []byte, v GeneratedPhaseRecord) ([]byte, error) {
	if _, err := GeneratedPhaseRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedPhaseRecord(&w, v)
	return w.b, nil
}

func EncodeGeneratedPhaseRecord(v GeneratedPhaseRecord) ([]byte, error) {
	n, err := GeneratedPhaseRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedPhaseRecord(&w, v)
	return w.b, nil
}

func InspectGeneratedPhaseRecord(b []byte) (GeneratedPhaseRecord, error) {
	if len(b) > GeneratedPhaseRecordBodyLength {
		return GeneratedPhaseRecord{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedPhaseRecord{Schema: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID(), PlanGraphID: r.requiredID(),
		UsePlanDigest: r.requiredID(), OwnerID: r.requiredID(), PhaseID: r.requiredID(), FrontierAttemptID: r.id(),
		AcceptedResultID: r.id(), ResultDigest: r.id(), Phase: r.u32(), LineageIndex: r.u16(), Branch: r.u8(),
		Stage: r.u8(), NoEffectUsed: r.u8(), ResidueUsed: r.u8(), AcceptedResults: readGeneratorDescriptor(&r),
		Attempts: readGeneratorDescriptor(&r), Duties: readGeneratorDescriptor(&r), Hazards: readGeneratorDescriptor(&r), PendingReleases: readGeneratorDescriptor(&r), Proofs: readGeneratorDescriptor(&r), FinalPreparationID: r.id()}
	v.SelectionPhaseID = r.id()
	v.ChangedSubjects = GeneratorDescriptor{Digest: r.id(), Length: r.u64(), Count: r.u32()}
	v.ChangedAccess = GeneratorDescriptor{Digest: r.id(), Length: r.u64(), Count: r.u32()}
	if err := r.end(); err != nil {
		return GeneratedPhaseRecord{}, err
	}
	if _, err := GeneratedPhaseRecordLength(v); err != nil {
		return GeneratedPhaseRecord{}, err
	}
	return v, nil
}

func DecodeGeneratedPhaseRecord(b []byte) (GeneratedPhaseRecord, error) {
	return InspectGeneratedPhaseRecord(b)
}

type GeneratedLineageRecord struct {
	Schema                                          uint16
	DomainID, OperationID, LineageID, IncarnationID ID
	Name                                            string
	Epoch                                           uint64
	Intent, Membership, Templates                   GeneratorDescriptor
	Branch, Frontier, NoEffectUsed, ResidueUsed     uint8
}

// GeneratedLineageRecordView borrows Name until Own copies it.
type GeneratedLineageRecordView struct {
	Schema                                          uint16
	DomainID, OperationID, LineageID, IncarnationID ID
	Name                                            []byte
	Epoch                                           uint64
	Intent, Membership, Templates                   GeneratorDescriptor
	Branch, Frontier, NoEffectUsed, ResidueUsed     uint8
}

func generatedLineageFieldsValid(schema uint16, domain, operation, lineage, incarnation ID,
	intent, membership, templates GeneratorDescriptor, branch, frontier, noEffectUsed, residueUsed uint8) bool {
	return schema == GeneratorRecordSchema && publicIDsValid(domain, operation, lineage, incarnation) &&
		generatedDescriptorsValid(intent, membership, templates) && frontier <= GeneratorBranchResidueThenNoEffect && generatedBranchValid(branch, noEffectUsed, residueUsed)
}

func GeneratedLineageRecordLength(v GeneratedLineageRecord) (int, error) {
	if len(v.Name) > CryptoMaxName {
		return 0, ErrRecordCapacity
	}
	if !utf8.ValidString(v.Name) || !generatedLineageFieldsValid(v.Schema, v.DomainID, v.OperationID, v.LineageID, v.IncarnationID,
		v.Intent, v.Membership, v.Templates, v.Branch, v.Frontier, v.NoEffectUsed, v.ResidueUsed) {
		return 0, ErrRecord
	}
	return 278 + len(v.Name), nil
}

func writeGeneratedLineageRecord(w *cryptoWriter, v GeneratedLineageRecord) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.LineageID)
	w.id(v.IncarnationID)
	w.blob([]byte(v.Name))
	w.u64(v.Epoch)
	writeGeneratorDescriptor(w, v.Intent)
	writeGeneratorDescriptor(w, v.Membership)
	writeGeneratorDescriptor(w, v.Templates)
	w.u8(v.Branch)
	w.u8(v.Frontier)
	w.u8(v.NoEffectUsed)
	w.u8(v.ResidueUsed)
}

func AppendGeneratedLineageRecord(dst []byte, v GeneratedLineageRecord) ([]byte, error) {
	if _, err := GeneratedLineageRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedLineageRecord(&w, v)
	return w.b, nil
}

func EncodeGeneratedLineageRecord(v GeneratedLineageRecord) ([]byte, error) {
	n, err := GeneratedLineageRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedLineageRecord(&w, v)
	return w.b, nil
}

func InspectGeneratedLineageRecord(b []byte) (GeneratedLineageRecordView, error) {
	if len(b) > GeneratedLineageRecordMaxLength {
		return GeneratedLineageRecordView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedLineageRecordView{Schema: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID(), LineageID: r.requiredID(),
		IncarnationID: r.requiredID(), Name: r.name(), Epoch: r.u64(), Intent: readGeneratorDescriptor(&r), Membership: readGeneratorDescriptor(&r),
		Templates: readGeneratorDescriptor(&r), Branch: r.u8(), Frontier: r.u8(), NoEffectUsed: r.u8(), ResidueUsed: r.u8()}
	if err := r.end(); err != nil {
		return GeneratedLineageRecordView{}, err
	}
	if !generatedLineageFieldsValid(v.Schema, v.DomainID, v.OperationID, v.LineageID, v.IncarnationID,
		v.Intent, v.Membership, v.Templates, v.Branch, v.Frontier, v.NoEffectUsed, v.ResidueUsed) {
		return GeneratedLineageRecordView{}, ErrRecord
	}
	return v, nil
}

func (v GeneratedLineageRecordView) Own() (GeneratedLineageRecord, error) {
	if len(v.Name) > CryptoMaxName {
		return GeneratedLineageRecord{}, ErrRecordCapacity
	}
	if !utf8.Valid(v.Name) || !generatedLineageFieldsValid(v.Schema, v.DomainID, v.OperationID, v.LineageID, v.IncarnationID,
		v.Intent, v.Membership, v.Templates, v.Branch, v.Frontier, v.NoEffectUsed, v.ResidueUsed) {
		return GeneratedLineageRecord{}, ErrRecord
	}
	return GeneratedLineageRecord{Schema: v.Schema, DomainID: v.DomainID, OperationID: v.OperationID, LineageID: v.LineageID,
		IncarnationID: v.IncarnationID, Name: string(v.Name), Epoch: v.Epoch, Intent: v.Intent, Membership: v.Membership,
		Templates: v.Templates, Branch: v.Branch, Frontier: v.Frontier, NoEffectUsed: v.NoEffectUsed, ResidueUsed: v.ResidueUsed}, nil
}

func DecodeGeneratedLineageRecord(b []byte) (GeneratedLineageRecord, error) {
	v, err := InspectGeneratedLineageRecord(b)
	if err != nil {
		return GeneratedLineageRecord{}, err
	}
	return v.Own()
}

type GeneratedAttemptRecord struct {
	LifecycleMode                                                                          GeneratorLifecycleMode
	Schema                                                                                 uint16
	DomainID, OperationID, LineageID, AttemptID, TemplateDigest, PredecessorAttemptID      ID
	OwnerID, ResourceID, TransmissionID, ResultID, InboxID, DescriptorID, ConfigContractID ID
	ExecutorID, CredentialRouteID, ResourceContractID, ResultContractID, RequestDigest     ID
	State, Stage, RetryUsed, CompletionClass, FailureReason                                uint8
	Facts, Progress, Support, History                                                      GeneratorDescriptor
}

func GeneratedAttemptRecordLength(v GeneratedAttemptRecord) (int, error) {
	if v.Schema != GeneratedAttemptRecordSchema || !publicIDsValid(v.DomainID, v.OperationID, v.LineageID, v.AttemptID,
		v.TemplateDigest, v.OwnerID, v.ResourceID, v.TransmissionID, v.ResultID, v.InboxID, v.DescriptorID, v.ConfigContractID,
		v.ExecutorID, v.CredentialRouteID, v.ResultContractID, v.RequestDigest) ||
		v.State < GeneratedEffectTransmitted || v.State > GeneratedEffectClosedWithResidue || !generatedStageValid(v.Stage) ||
		v.RetryUsed > 1 || !v.LifecycleMode.resourceValid(v.ResourceContractID) || (v.LifecycleMode == GeneratorLifecycleNone && v.CompletionClass != 0 || v.LifecycleMode == GeneratorLifecycleManaged && !generatedCompletionValid(v.CompletionClass)) || !generatedDescriptorsValid(v.Facts, v.Progress, v.Support, v.History) {
		return 0, ErrRecord
	}
	if v.LifecycleMode == GeneratorLifecycleNone && (v.State > GeneratedEffectUnknown || v.RetryUsed != 0 || v.Progress.Count != 0) {
		return 0, ErrRecord
	}
	if v.FailureReason > GeneratorFailureProtocol || v.LifecycleMode == GeneratorLifecycleNone && (v.State == GeneratedEffectFailedTerminal) != (v.FailureReason != 0) || v.FailureReason != 0 && (v.LifecycleMode != GeneratorLifecycleNone || v.Stage != GeneratedStageTerminal || v.Facts.Count != 0) {
		return 0, ErrRecord
	}
	return GeneratedAttemptRecordFixedLength, nil
}

func writeGeneratedAttemptRecord(w *cryptoWriter, v GeneratedAttemptRecord) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.LineageID)
	w.id(v.AttemptID)
	w.id(v.TemplateDigest)
	w.id(v.PredecessorAttemptID)
	w.id(v.OwnerID)
	w.id(v.ResourceID)
	w.id(v.TransmissionID)
	w.id(v.ResultID)
	w.id(v.InboxID)
	w.id(v.DescriptorID)
	w.id(v.ConfigContractID)
	w.id(v.ExecutorID)
	w.id(v.CredentialRouteID)
	w.id(v.ResourceContractID)
	w.id(v.ResultContractID)
	w.id(v.RequestDigest)
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.State)
	w.u8(v.Stage)
	w.u8(v.RetryUsed)
	w.u8(v.CompletionClass)
	w.u8(v.FailureReason)
	writeGeneratorDescriptor(w, v.Facts)
	writeGeneratorDescriptor(w, v.Progress)
	writeGeneratorDescriptor(w, v.Support)
	writeGeneratorDescriptor(w, v.History)
}

func AppendGeneratedAttemptRecord(dst []byte, v GeneratedAttemptRecord) ([]byte, error) {
	if _, err := GeneratedAttemptRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedAttemptRecord(&w, v)
	return w.b, nil
}

func EncodeGeneratedAttemptRecord(v GeneratedAttemptRecord) ([]byte, error) {
	n, err := GeneratedAttemptRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedAttemptRecord(&w, v)
	return w.b, nil
}

func InspectGeneratedAttemptRecord(b []byte) (GeneratedAttemptRecord, error) {
	if len(b) > GeneratedAttemptRecordBodyLength {
		return GeneratedAttemptRecord{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedAttemptRecord{Schema: r.u16(), DomainID: r.requiredID(), OperationID: r.requiredID(), LineageID: r.requiredID(), AttemptID: r.requiredID(),
		TemplateDigest: r.requiredID(), PredecessorAttemptID: r.id(), OwnerID: r.requiredID(), ResourceID: r.requiredID(), TransmissionID: r.requiredID(),
		ResultID: r.requiredID(), InboxID: r.requiredID(), DescriptorID: r.requiredID(), ConfigContractID: r.requiredID(), ExecutorID: r.requiredID(),
		CredentialRouteID: r.requiredID(), ResourceContractID: r.id(), ResultContractID: r.requiredID(), RequestDigest: r.requiredID(),
		LifecycleMode: GeneratorLifecycleMode(r.u8()), State: r.u8(), Stage: r.u8(), RetryUsed: r.u8(), CompletionClass: r.u8(), FailureReason: r.u8(), Facts: readGeneratorDescriptor(&r),
		Progress: readGeneratorDescriptor(&r), Support: readGeneratorDescriptor(&r), History: readGeneratorDescriptor(&r)}
	if err := r.end(); err != nil {
		return GeneratedAttemptRecord{}, err
	}
	if _, err := GeneratedAttemptRecordLength(v); err != nil {
		return GeneratedAttemptRecord{}, err
	}
	return v, nil
}

func DecodeGeneratedAttemptRecord(b []byte) (GeneratedAttemptRecord, error) {
	return InspectGeneratedAttemptRecord(b)
}

type GeneratedDutyRecord struct {
	LifecycleMode                                                                                       GeneratorLifecycleMode
	Schema                                                                                              uint16
	DomainID, DutyID, OriginalOperationID, OriginalAttemptID, OwnerID, ResourceID                       ID
	DescriptorID, ConfigContractID, ExecutorID, CredentialRouteID, ResourceContractID, ResultContractID ID
	Kind, CompletionClass, Step, Status                                                                 uint8
	CapacityReservation, Target, Progress, History, Support, Consumers                                  GeneratorDescriptor
}

func GeneratedDutyRecordLength(v GeneratedDutyRecord) (int, error) {
	if v.Schema != GeneratedDutyRecordSchema || !publicIDsValid(v.DomainID, v.DutyID, v.OriginalOperationID, v.OriginalAttemptID,
		v.OwnerID, v.ResourceID, v.DescriptorID, v.ConfigContractID, v.ExecutorID, v.CredentialRouteID, v.ResultContractID) ||
		v.Kind < GeneratedDutyCreate || v.Kind > GeneratedDutyUnselectedCleanup || !v.LifecycleMode.resourceValid(v.ResourceContractID) || (v.LifecycleMode == GeneratorLifecycleNone && v.CompletionClass != 0 || v.LifecycleMode == GeneratorLifecycleManaged && !generatedCompletionValid(v.CompletionClass)) ||
		v.Step < 1 || v.Step > 8 || v.Status < GeneratedEffectNotStarted || v.Status > GeneratedEffectClosedWithResidue ||
		v.Kind == GeneratedDutyUnselectedCleanup && v.Status != GeneratedEffectSucceeded ||
		!generatedDescriptorsValid(v.CapacityReservation, v.Target, v.Progress, v.History, v.Support, v.Consumers) {
		return 0, ErrRecord
	}
	if v.LifecycleMode == GeneratorLifecycleNone && (v.Kind != GeneratedDutyCreate || v.Step != 1 || v.Target.Count != 0 || v.Progress.Count != 0) {
		return 0, ErrRecord
	}
	return GeneratedDutyRecordFixedLength, nil
}

func writeGeneratedDutyRecord(w *cryptoWriter, v GeneratedDutyRecord) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.DutyID)
	w.id(v.OriginalOperationID)
	w.id(v.OriginalAttemptID)
	w.id(v.OwnerID)
	w.id(v.ResourceID)
	w.id(v.DescriptorID)
	w.id(v.ConfigContractID)
	w.id(v.ExecutorID)
	w.id(v.CredentialRouteID)
	w.id(v.ResourceContractID)
	w.id(v.ResultContractID)
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.Kind)
	w.u8(v.CompletionClass)
	w.u8(v.Step)
	w.u8(v.Status)
	writeGeneratorDescriptor(w, v.CapacityReservation)
	writeGeneratorDescriptor(w, v.Target)
	writeGeneratorDescriptor(w, v.Progress)
	writeGeneratorDescriptor(w, v.History)
	writeGeneratorDescriptor(w, v.Support)
	writeGeneratorDescriptor(w, v.Consumers)
}

func AppendGeneratedDutyRecord(dst []byte, v GeneratedDutyRecord) ([]byte, error) {
	if _, err := GeneratedDutyRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedDutyRecord(&w, v)
	return w.b, nil
}

func EncodeGeneratedDutyRecord(v GeneratedDutyRecord) ([]byte, error) {
	n, err := GeneratedDutyRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedDutyRecord(&w, v)
	return w.b, nil
}

func InspectGeneratedDutyRecord(b []byte) (GeneratedDutyRecord, error) {
	if len(b) > GeneratedDutyRecordBodyLength {
		return GeneratedDutyRecord{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedDutyRecord{Schema: r.u16(), DomainID: r.requiredID(), DutyID: r.requiredID(), OriginalOperationID: r.requiredID(),
		OriginalAttemptID: r.requiredID(), OwnerID: r.requiredID(), ResourceID: r.requiredID(), DescriptorID: r.requiredID(), ConfigContractID: r.requiredID(),
		ExecutorID: r.requiredID(), CredentialRouteID: r.requiredID(), ResourceContractID: r.id(), ResultContractID: r.requiredID(),
		LifecycleMode: GeneratorLifecycleMode(r.u8()), Kind: r.u8(), CompletionClass: r.u8(), Step: r.u8(), Status: r.u8(), CapacityReservation: readGeneratorDescriptor(&r), Target: readGeneratorDescriptor(&r), Progress: readGeneratorDescriptor(&r),
		History: readGeneratorDescriptor(&r), Support: readGeneratorDescriptor(&r), Consumers: readGeneratorDescriptor(&r)}
	if err := r.end(); err != nil {
		return GeneratedDutyRecord{}, err
	}
	if _, err := GeneratedDutyRecordLength(v); err != nil {
		return GeneratedDutyRecord{}, err
	}
	return v, nil
}

func DecodeGeneratedDutyRecord(b []byte) (GeneratedDutyRecord, error) {
	return InspectGeneratedDutyRecord(b)
}

type GeneratedHazardRecord struct {
	Schema                                                                                              uint16
	DomainID, HazardID, OriginalOperationID, OriginalAttemptID, OwnerID, ResourceID                     ID
	DescriptorID, ConfigContractID, ExecutorID, CredentialRouteID, ResourceContractID, ResultContractID ID
	Exposure, CompletionClass, Fenced, Eligibility                                                      uint8
	CapacityReservation, OriginalResults, Target, History, Support, Consumers                           GeneratorDescriptor
}

func GeneratedHazardRecordLength(v GeneratedHazardRecord) (int, error) {
	if v.Schema != GeneratedHazardRecordSchema || !publicIDsValid(v.DomainID, v.HazardID, v.OriginalOperationID, v.OriginalAttemptID,
		v.OwnerID, v.ResourceID, v.DescriptorID, v.ConfigContractID, v.ExecutorID, v.CredentialRouteID, v.ResourceContractID, v.ResultContractID) ||
		v.Exposure < GeneratedExposurePossibleLive || v.Exposure > GeneratedExposureLateEffect || !generatedCompletionValid(v.CompletionClass) ||
		v.Fenced > 1 || v.Eligibility > GeneratedExposureLateEffect || v.Eligibility != 0 && v.Eligibility != v.Exposure ||
		!generatedDescriptorsValid(v.CapacityReservation, v.OriginalResults, v.Target, v.History, v.Support, v.Consumers) {
		return 0, ErrRecord
	}
	return GeneratedHazardRecordBodyLength, nil
}

func writeGeneratedHazardRecord(w *cryptoWriter, v GeneratedHazardRecord) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.HazardID)
	w.id(v.OriginalOperationID)
	w.id(v.OriginalAttemptID)
	w.id(v.OwnerID)
	w.id(v.ResourceID)
	w.id(v.DescriptorID)
	w.id(v.ConfigContractID)
	w.id(v.ExecutorID)
	w.id(v.CredentialRouteID)
	w.id(v.ResourceContractID)
	w.id(v.ResultContractID)
	w.u8(v.Exposure)
	w.u8(v.CompletionClass)
	w.u8(v.Fenced)
	w.u8(v.Eligibility)
	writeGeneratorDescriptor(w, v.CapacityReservation)
	writeGeneratorDescriptor(w, v.OriginalResults)
	writeGeneratorDescriptor(w, v.Target)
	writeGeneratorDescriptor(w, v.History)
	writeGeneratorDescriptor(w, v.Support)
	writeGeneratorDescriptor(w, v.Consumers)
}

func AppendGeneratedHazardRecord(dst []byte, v GeneratedHazardRecord) ([]byte, error) {
	if _, err := GeneratedHazardRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedHazardRecord(&w, v)
	return w.b, nil
}

func EncodeGeneratedHazardRecord(v GeneratedHazardRecord) ([]byte, error) {
	n, err := GeneratedHazardRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedHazardRecord(&w, v)
	return w.b, nil
}

func InspectGeneratedHazardRecord(b []byte) (GeneratedHazardRecord, error) {
	if len(b) > GeneratedHazardRecordBodyLength {
		return GeneratedHazardRecord{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedHazardRecord{Schema: r.u16(), DomainID: r.requiredID(), HazardID: r.requiredID(), OriginalOperationID: r.requiredID(),
		OriginalAttemptID: r.requiredID(), OwnerID: r.requiredID(), ResourceID: r.requiredID(), DescriptorID: r.requiredID(), ConfigContractID: r.requiredID(),
		ExecutorID: r.requiredID(), CredentialRouteID: r.requiredID(), ResourceContractID: r.requiredID(), ResultContractID: r.requiredID(),
		Exposure: r.u8(), CompletionClass: r.u8(), Fenced: r.u8(), Eligibility: r.u8(), CapacityReservation: readGeneratorDescriptor(&r), OriginalResults: readGeneratorDescriptor(&r), Target: readGeneratorDescriptor(&r),
		History: readGeneratorDescriptor(&r), Support: readGeneratorDescriptor(&r), Consumers: readGeneratorDescriptor(&r)}
	if err := r.end(); err != nil {
		return GeneratedHazardRecord{}, err
	}
	if _, err := GeneratedHazardRecordLength(v); err != nil {
		return GeneratedHazardRecord{}, err
	}
	return v, nil
}

func DecodeGeneratedHazardRecord(b []byte) (GeneratedHazardRecord, error) {
	return InspectGeneratedHazardRecord(b)
}

// The handoff digest commits the complete original result body, not a selected
// root. Its revision records provenance without retaining a historical Snapshot.
type PendingInboxReleaseRecord struct {
	Schema                                                                        uint16
	DomainID, InboxID, OriginalResultID, SelectedHandoffDigest, HandoffRevisionID ID
	CapacityReservation                                                           GeneratorDescriptor
	ObjectLength                                                                  uint32
	State                                                                         uint8
}

func PendingInboxReleaseRecordLength(v PendingInboxReleaseRecord) (int, error) {
	if v.ObjectLength > uint32(GeneratedResultRecordMaxLength) {
		return 0, ErrRecordCapacity
	}
	if v.Schema != GeneratorRecordSchema || !publicIDsValid(v.DomainID, v.InboxID, v.OriginalResultID, v.SelectedHandoffDigest, v.HandoffRevisionID) || !v.CapacityReservation.Valid() ||
		v.State < GeneratedReleasePending || v.State > GeneratedReleaseUnobserved ||
		(v.ObjectLength == 0) != (v.State == GeneratedReleaseUnobserved) {
		return 0, ErrRecord
	}
	return PendingInboxReleaseRecordBodyLength, nil
}

func writePendingInboxReleaseRecord(w *cryptoWriter, v PendingInboxReleaseRecord) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.InboxID)
	w.id(v.OriginalResultID)
	w.id(v.SelectedHandoffDigest)
	w.id(v.HandoffRevisionID)
	writeGeneratorDescriptor(w, v.CapacityReservation)
	w.u32(v.ObjectLength)
	w.u8(v.State)
}

func AppendPendingInboxReleaseRecord(dst []byte, v PendingInboxReleaseRecord) ([]byte, error) {
	if _, err := PendingInboxReleaseRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writePendingInboxReleaseRecord(&w, v)
	return w.b, nil
}

func EncodePendingInboxReleaseRecord(v PendingInboxReleaseRecord) ([]byte, error) {
	n, err := PendingInboxReleaseRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writePendingInboxReleaseRecord(&w, v)
	return w.b, nil
}

func InspectPendingInboxReleaseRecord(b []byte) (PendingInboxReleaseRecord, error) {
	if len(b) > PendingInboxReleaseRecordBodyLength {
		return PendingInboxReleaseRecord{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := PendingInboxReleaseRecord{Schema: r.u16(), DomainID: r.requiredID(), InboxID: r.requiredID(), OriginalResultID: r.requiredID(),
		SelectedHandoffDigest: r.requiredID(), HandoffRevisionID: r.requiredID(), CapacityReservation: readGeneratorDescriptor(&r), ObjectLength: r.u32(), State: r.u8()}
	if err := r.end(); err != nil {
		return PendingInboxReleaseRecord{}, err
	}
	if _, err := PendingInboxReleaseRecordLength(v); err != nil {
		return PendingInboxReleaseRecord{}, err
	}
	return v, nil
}

func DecodePendingInboxReleaseRecord(b []byte) (PendingInboxReleaseRecord, error) {
	return InspectPendingInboxReleaseRecord(b)
}

type GeneratedFragment struct {
	Schema       uint16
	BlobID       ID
	Index, Count uint16
	TotalLength  uint64
	WholeDigest  ID
	Offset       uint32
	Payload      []byte
}

// GeneratedFragmentView borrows Payload. Own checks its shape before copying.
type GeneratedFragmentView GeneratedFragment

func GeneratedFragmentLength(v GeneratedFragment) (int, error) {
	if len(v.Payload) > GeneratedFragmentMaxPayload || v.Count > MaxChildPages*2 || v.TotalLength > uint64(MaxChildPages*2)*GeneratedFragmentMaxPayload {
		return 0, ErrRecordCapacity
	}
	if v.Schema != GeneratorRecordSchema || !publicIDsValid(v.BlobID, v.WholeDigest) || v.Count == 0 || v.Index >= v.Count || v.TotalLength == 0 ||
		uint64(v.Count) != (v.TotalLength+GeneratedFragmentMaxPayload-1)/GeneratedFragmentMaxPayload ||
		v.Offset != uint32(v.Index)*GeneratedFragmentMaxPayload {
		return 0, ErrRecord
	}
	want := min(uint64(GeneratedFragmentMaxPayload), v.TotalLength-uint64(v.Offset))
	if uint64(len(v.Payload)) != want {
		return 0, ErrRecord
	}
	return GeneratedFragmentHeaderLength + len(v.Payload), nil
}

func writeGeneratedFragment(w *cryptoWriter, v GeneratedFragment) {
	w.u16(v.Schema)
	w.id(v.BlobID)
	w.u16(v.Index)
	w.u16(v.Count)
	w.u64(v.TotalLength)
	w.id(v.WholeDigest)
	w.u32(v.Offset)
	w.blob(v.Payload)
}

func AppendGeneratedFragment(dst []byte, v GeneratedFragment) ([]byte, error) {
	if _, err := GeneratedFragmentLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedFragment(&w, v)
	return w.b, nil
}

func EncodeGeneratedFragment(v GeneratedFragment) ([]byte, error) {
	n, err := GeneratedFragmentLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedFragment(&w, v)
	return w.b, nil
}

func InspectGeneratedFragment(b []byte) (GeneratedFragmentView, error) {
	if len(b) > GeneratedFragmentMaxLength {
		return GeneratedFragmentView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedFragmentView{Schema: r.u16(), BlobID: r.requiredID(), Index: r.u16(), Count: r.u16(), TotalLength: r.u64(),
		WholeDigest: r.requiredID(), Offset: r.u32(), Payload: r.blob(GeneratedFragmentMaxPayload)}
	if err := r.end(); err != nil {
		return GeneratedFragmentView{}, err
	}
	if _, err := GeneratedFragmentLength(GeneratedFragment(v)); err != nil {
		return GeneratedFragmentView{}, err
	}
	return v, nil
}

func (v GeneratedFragmentView) Own() (GeneratedFragment, error) {
	out := GeneratedFragment(v)
	if _, err := GeneratedFragmentLength(out); err != nil {
		return GeneratedFragment{}, err
	}
	out.Payload = ownedBytes(v.Payload)
	return out, nil
}

func DecodeGeneratedFragment(b []byte) (GeneratedFragment, error) {
	v, err := InspectGeneratedFragment(b)
	if err != nil {
		return GeneratedFragment{}, err
	}
	return v.Own()
}

// GeneratedCreateEvidence carries a detached original result context. The
// admitted result reader must qualify these facts before a selected handoff.
type GeneratedCreateEvidence struct {
	LifecycleMode         GeneratorLifecycleMode
	Schema                uint16
	OriginalResultID      ID
	CredentialRouteID     ID
	ResultCore, SafeFacts []byte
	Intent                GeneratorDescriptor
	CompletionClass       uint8
}

// GeneratedCreateEvidenceView borrows ResultCore and SafeFacts until Own.
type GeneratedCreateEvidenceView GeneratedCreateEvidence

func GeneratedCreateEvidenceLength(v GeneratedCreateEvidence) (int, error) {
	if len(v.ResultCore) > GeneratedResultCoreLength || len(v.SafeFacts) > GeneratorSafeFactsEnvelopeLength {
		return 0, ErrRecordCapacity
	}
	if v.Schema != GeneratedCreateEvidenceSchema || v.OriginalResultID.IsZero() || v.CredentialRouteID.IsZero() || !v.Intent.Valid() {
		return 0, ErrRecord
	}
	core, err := InspectGeneratedResultCore(v.ResultCore)
	if err != nil {
		return 0, err
	}
	facts, err := InspectGeneratorSafeFacts(v.SafeFacts)
	if err != nil {
		return 0, err
	}
	digest, err := GeneratorSafeFactsDigest(facts.GeneratorSafeFacts)
	if err != nil || core.ResultID != v.OriginalResultID || core.RequestDigest != facts.RequestDigest || core.SafeFactsDigest != digest || facts.Action != GeneratorActionCreate || facts.LifecycleMode != v.LifecycleMode || facts.Disposition != GeneratorDispositionCompleteCreate && facts.Disposition != GeneratorDispositionOwnedUnusableCreate || v.LifecycleMode == GeneratorLifecycleNone && v.CompletionClass != 0 || v.LifecycleMode == GeneratorLifecycleManaged && !generatedCompletionValid(v.CompletionClass) {
		return 0, ErrRecord
	}
	return 120 + len(v.ResultCore) + len(v.SafeFacts), nil
}

func writeGeneratedCreateEvidence(w *cryptoWriter, v GeneratedCreateEvidence) {
	w.u16(v.Schema)
	w.id(v.OriginalResultID)
	w.id(v.CredentialRouteID)
	w.blob(v.ResultCore)
	w.blob(v.SafeFacts)
	writeGeneratorDescriptor(w, v.Intent)
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.CompletionClass)
}

func AppendGeneratedCreateEvidence(dst []byte, v GeneratedCreateEvidence) ([]byte, error) {
	if _, err := GeneratedCreateEvidenceLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedCreateEvidence(&w, v)
	return w.b, nil
}

func EncodeGeneratedCreateEvidence(v GeneratedCreateEvidence) ([]byte, error) {
	n, err := GeneratedCreateEvidenceLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedCreateEvidence(&w, v)
	return w.b, nil
}

func InspectGeneratedCreateEvidence(b []byte) (GeneratedCreateEvidenceView, error) {
	if len(b) > GeneratedCreateEvidenceMaxLength {
		return GeneratedCreateEvidenceView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedCreateEvidenceView{Schema: r.u16(), OriginalResultID: r.requiredID(), CredentialRouteID: r.requiredID(), ResultCore: r.blob(GeneratedResultCoreLength), SafeFacts: r.blob(GeneratorSafeFactsEnvelopeLength),
		Intent: readGeneratorDescriptor(&r), LifecycleMode: GeneratorLifecycleMode(r.u8()), CompletionClass: r.u8()}
	if err := r.end(); err != nil {
		return GeneratedCreateEvidenceView{}, err
	}
	if _, err := GeneratedCreateEvidenceLength(GeneratedCreateEvidence(v)); err != nil {
		return GeneratedCreateEvidenceView{}, err
	}
	return v, nil
}

func (v GeneratedCreateEvidenceView) Own() (GeneratedCreateEvidence, error) {
	out := GeneratedCreateEvidence(v)
	if _, err := GeneratedCreateEvidenceLength(out); err != nil {
		return GeneratedCreateEvidence{}, err
	}
	out.ResultCore, out.SafeFacts = ownedBytes(v.ResultCore), ownedBytes(v.SafeFacts)
	return out, nil
}

func DecodeGeneratedCreateEvidence(b []byte) (GeneratedCreateEvidence, error) {
	v, err := InspectGeneratedCreateEvidence(b)
	if err != nil {
		return GeneratedCreateEvidence{}, err
	}
	return v.Own()
}

type GeneratedEntryMetadata struct {
	Schema                                                                                    uint16
	Epoch                                                                                     uint64
	ConfigContractID, IntentDigest, ResourceContractID, ResourceDigest, ResourceIncarnationID ID
	OriginOperationID, OriginAttemptID, GenerationID, CreateResultID                          ID
	CreateEvidence, RequiredSupport                                                           GeneratorDescriptor
	LifecycleMode                                                                             GeneratorLifecycleMode
	CompletionClass, RetirementMode, RetiringDutyPresent                                      uint8
	RetiringDutyID                                                                            ID
}

func GeneratedEntryMetadataLength(v GeneratedEntryMetadata) (int, error) {
	if v.Schema != GeneratedEntryMetadataSchema || !publicIDsValid(v.ConfigContractID, v.IntentDigest, v.ResourceIncarnationID, v.OriginOperationID, v.OriginAttemptID, v.GenerationID, v.CreateResultID) || !generationLifecycleValid(v.LifecycleMode, v.ResourceContractID, v.CompletionClass, v.RetirementMode) || (v.LifecycleMode == GeneratorLifecycleNone) != v.ResourceDigest.IsZero() || !generatedDescriptorsValid(v.CreateEvidence, v.RequiredSupport) || v.RetiringDutyPresent > 1 || (v.RetiringDutyPresent == 0) != v.RetiringDutyID.IsZero() {
		return 0, ErrRecord
	}
	return 390 + 32*int(v.RetiringDutyPresent), nil
}
func writeGeneratedEntryMetadata(w *cryptoWriter, v GeneratedEntryMetadata) {
	w.u16(v.Schema)
	w.u64(v.Epoch)
	for _, id := range [...]ID{v.ConfigContractID, v.IntentDigest, v.ResourceContractID, v.ResourceDigest, v.ResourceIncarnationID, v.OriginOperationID, v.OriginAttemptID, v.GenerationID, v.CreateResultID} {
		w.id(id)
	}
	writeGeneratorDescriptor(w, v.CreateEvidence)
	writeGeneratorDescriptor(w, v.RequiredSupport)
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.CompletionClass)
	w.u8(v.RetirementMode)
	w.u8(v.RetiringDutyPresent)
	if v.RetiringDutyPresent == 1 {
		w.id(v.RetiringDutyID)
	}
}
func AppendGeneratedEntryMetadata(dst []byte, v GeneratedEntryMetadata) ([]byte, error) {
	if _, err := GeneratedEntryMetadataLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratedEntryMetadata(&w, v)
	return w.b, nil
}
func EncodeGeneratedEntryMetadata(v GeneratedEntryMetadata) ([]byte, error) {
	return AppendGeneratedEntryMetadata(nil, v)
}
func InspectGeneratedEntryMetadata(body []byte) (GeneratedEntryMetadata, error) {
	if len(body) > GeneratedEntryMetadataMaxLength {
		return GeneratedEntryMetadata{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := GeneratedEntryMetadata{Schema: r.u16(), Epoch: r.u64(), ConfigContractID: r.requiredID(), IntentDigest: r.requiredID(), ResourceContractID: r.id(), ResourceDigest: r.id(), ResourceIncarnationID: r.requiredID(), OriginOperationID: r.requiredID(), OriginAttemptID: r.requiredID(), GenerationID: r.requiredID(), CreateResultID: r.requiredID(), CreateEvidence: readGeneratorDescriptor(&r), RequiredSupport: readGeneratorDescriptor(&r), LifecycleMode: GeneratorLifecycleMode(r.u8()), CompletionClass: r.u8(), RetirementMode: r.u8(), RetiringDutyPresent: r.u8()}
	if v.RetiringDutyPresent == 1 {
		v.RetiringDutyID = r.requiredID()
	}
	if err := r.end(); err != nil {
		return GeneratedEntryMetadata{}, err
	}
	if _, err := GeneratedEntryMetadataLength(v); err != nil {
		return GeneratedEntryMetadata{}, err
	}
	return v, nil
}
func DecodeGeneratedEntryMetadata(body []byte) (GeneratedEntryMetadata, error) {
	return InspectGeneratedEntryMetadata(body)
}
