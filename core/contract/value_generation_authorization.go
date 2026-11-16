package contract

const (
	GeneratorAuthorityNormal    = 1
	GeneratorAuthorityGrant     = 2
	GeneratorAuthorityExclusion = 4
	GeneratorAuthorityMask      = GeneratorAuthorityNormal | GeneratorAuthorityGrant | GeneratorAuthorityExclusion
)

const (
	GeneratorAuthoritySubjectLength        = 1140
	GeneratorAuthoritySubjectSchema uint16 = 2
	generatorAuthorityPrefix               = "ENKV/GENERATOR-AUTH/v2/"
)

type GeneratorAuthorityPurpose uint8

func NewGeneratorRequest(v GeneratorAuthoritySubject) (SignRequest, error) {
	digest, err := GeneratorAuthorityDigest(v)
	if err != nil {
		return SignRequest{}, err
	}
	return SignRequest{purpose: GeneratorPurpose, digest: digest}, nil
}

const (
	GeneratorAuthorityReservation GeneratorAuthorityPurpose = iota + 1
	GeneratorAuthorityRecord
	GeneratorAuthorityNoEffectBranch
	GeneratorAuthorityResidue
	GeneratorAuthorityFinal
	GeneratorAuthorityRetireReserve
	GeneratorAuthorityRetireClose
	GeneratorAuthorityCleanupReserve
	GeneratorAuthorityCleanupClose
	GeneratorAuthorityReflection
	GeneratorAuthorityInboxRelease
	GeneratorAuthorityFinalPreparation
	GeneratorAuthorityFailedTerminal
)

func (p GeneratorAuthorityPurpose) Name() string {
	switch p {
	case GeneratorAuthorityReservation:
		return "reservation"
	case GeneratorAuthorityRecord:
		return "record"
	case GeneratorAuthorityNoEffectBranch:
		return "no-effect-branch"
	case GeneratorAuthorityResidue:
		return "residue"
	case GeneratorAuthorityFinal:
		return "final"
	case GeneratorAuthorityRetireReserve:
		return "retire-reserve"
	case GeneratorAuthorityRetireClose:
		return "retire-close"
	case GeneratorAuthorityCleanupReserve:
		return "cleanup-reserve"
	case GeneratorAuthorityCleanupClose:
		return "cleanup-close"
	case GeneratorAuthorityReflection:
		return "reflection"
	case GeneratorAuthorityInboxRelease:
		return "inbox-release"
	case GeneratorAuthorityFinalPreparation:
		return "final-preparation"
	case GeneratorAuthorityFailedTerminal:
		return "failed-terminal"
	default:
		return ""
	}
}

// GeneratorAuthoritySubject binds one exact normal-authority transition. Core
// must check its selected owner, purpose, graph, evidence and membership-derived
// authority requirements. Valid bytes alone grant no effect or selection right.
type GeneratorAuthoritySubject struct {
	Schema               uint16
	Purpose              GeneratorAuthorityPurpose
	RequiredAuthoritySet uint8

	DomainID, OperationID, RequestIdentityDigest, PlanGraphID, UsePlanDigest, PhaseID       ID
	PreviousHEADDigest, PreviousRevisionID, ConditionDigest, BeforeRootDigest               ID
	AfterRootDigest, BeforeAccessDigest, AfterAccessDigest, OwnerID                         ID
	LineageID, AttemptID, PredecessorAttemptID, ResultID, ResultDigest                      ID
	DescriptorID, ConfigContractID, ResultContractID, HeadCoreDigest, ConditionalPlanDigest ID

	Intent, IdentityPlan, ValueEntryUnion, MembershipChanges   GeneratorDescriptor
	BeforeWork, AfterWork, ResultVector, CapacityReservation   GeneratorDescriptor
	BeforePhase, AfterPhase, HeadCoreLength, ConditionalLength uint32
}

func (v GeneratorAuthoritySubject) operationFieldsAbsent() bool {
	return v.LineageID.IsZero() && v.AttemptID.IsZero() && v.PredecessorAttemptID.IsZero() &&
		v.ResultID.IsZero() && v.ResultDigest.IsZero() && v.DescriptorID.IsZero() &&
		v.ConfigContractID.IsZero() && v.ResultContractID.IsZero()
}

func (v GeneratorAuthoritySubject) templateFieldsPresent() bool {
	return publicIDsValid(v.LineageID, v.AttemptID, v.ResultID, v.DescriptorID, v.ConfigContractID, v.ResultContractID)
}

func (v GeneratorAuthoritySubject) purposeFieldsValid() bool {
	switch v.Purpose {
	case GeneratorAuthorityReservation:
		return v.operationFieldsAbsent() || v.templateFieldsPresent() && v.ResultDigest.IsZero()
	case GeneratorAuthorityFinal, GeneratorAuthorityFinalPreparation:
		return v.operationFieldsAbsent()
	case GeneratorAuthorityRetireReserve, GeneratorAuthorityCleanupReserve:
		return v.templateFieldsPresent() && v.ResultDigest.IsZero() && v.PredecessorAttemptID.IsZero()
	case GeneratorAuthorityResidue:
		// Residue may have no qualified terminal result. The planned result
		// coordinate still belongs to the original Attempt.
		return v.templateFieldsPresent()
	case GeneratorAuthorityFailedTerminal:
		empty, err := GeneratorResultReferencesDescriptor(nil)
		return err == nil && v.templateFieldsPresent() && v.ResultDigest.IsZero() && v.PredecessorAttemptID.IsZero() && v.ResultVector == GeneratorDescriptor(empty)
	case GeneratorAuthorityRecord, GeneratorAuthorityNoEffectBranch,
		GeneratorAuthorityRetireClose, GeneratorAuthorityCleanupClose, GeneratorAuthorityReflection:
		return v.templateFieldsPresent() && !v.ResultDigest.IsZero()
	case GeneratorAuthorityInboxRelease:
		// This is the frozen original object's digest, not a claim that the
		// object exists now. Core must establish the selected handoff and no
		// remaining adoption or consumer need before permitting deletion.
		return v.templateFieldsPresent() && !v.ResultDigest.IsZero()
	default:
		return false
	}
}

func (v GeneratorAuthoritySubject) validate() error {
	if v.Schema != GeneratorAuthoritySubjectSchema || v.RequiredAuthoritySet&GeneratorAuthorityNormal == 0 || v.RequiredAuthoritySet > GeneratorAuthorityMask ||
		!publicIDsValid(v.DomainID, v.OperationID, v.RequestIdentityDigest, v.PlanGraphID, v.UsePlanDigest, v.PhaseID,
			v.PreviousHEADDigest, v.PreviousRevisionID, v.ConditionDigest, v.BeforeRootDigest, v.AfterRootDigest,
			v.BeforeAccessDigest, v.AfterAccessDigest, v.OwnerID, v.HeadCoreDigest, v.ConditionalPlanDigest) ||
		!generatedDescriptorsValid(v.Intent, v.IdentityPlan, v.ValueEntryUnion, v.MembershipChanges,
			v.BeforeWork, v.AfterWork, v.ResultVector, v.CapacityReservation) ||
		!v.purposeFieldsValid() || v.BeforePhase == ^uint32(0) || v.AfterPhase != v.BeforePhase+1 ||
		v.BeforePhase == 0 && v.Purpose != GeneratorAuthorityReservation {
		return ErrRecord
	}
	if v.HeadCoreLength > SuccessorHeadCoreMaxLength || v.ConditionalLength > SuccessorHeadCoreMaxLength-265 {
		return ErrRecordCapacity
	}
	if v.HeadCoreLength < SuccessorHeadCoreMinLength ||
		v.ConditionalLength != v.HeadCoreLength-266 && v.ConditionalLength != v.HeadCoreLength-265 {
		return ErrRecord
	}
	// The subject has no provider tag. Its owning HEAD codec verifies which
	// of the two admitted conditional-plan lengths matches the exact body.
	return nil
}

func writeGeneratorAuthoritySubject(w *cryptoWriter, v GeneratorAuthoritySubject) {
	w.u16(v.Schema)
	w.u8(uint8(v.Purpose))
	w.u8(v.RequiredAuthoritySet)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.RequestIdentityDigest)
	w.id(v.PlanGraphID)
	w.id(v.UsePlanDigest)
	w.id(v.PhaseID)
	w.id(v.PreviousHEADDigest)
	w.id(v.PreviousRevisionID)
	w.id(v.ConditionDigest)
	w.id(v.BeforeRootDigest)
	w.id(v.AfterRootDigest)
	w.id(v.BeforeAccessDigest)
	w.id(v.AfterAccessDigest)
	w.id(v.OwnerID)
	w.id(v.LineageID)
	w.id(v.AttemptID)
	w.id(v.PredecessorAttemptID)
	w.id(v.ResultID)
	w.id(v.ResultDigest)
	w.id(v.DescriptorID)
	w.id(v.ConfigContractID)
	w.id(v.ResultContractID)
	w.id(v.HeadCoreDigest)
	w.id(v.ConditionalPlanDigest)
	writeGeneratorDescriptor(w, v.Intent)
	writeGeneratorDescriptor(w, v.IdentityPlan)
	writeGeneratorDescriptor(w, v.ValueEntryUnion)
	writeGeneratorDescriptor(w, v.MembershipChanges)
	writeGeneratorDescriptor(w, v.BeforeWork)
	writeGeneratorDescriptor(w, v.AfterWork)
	writeGeneratorDescriptor(w, v.ResultVector)
	writeGeneratorDescriptor(w, v.CapacityReservation)
	w.u32(v.BeforePhase)
	w.u32(v.AfterPhase)
	w.u32(v.HeadCoreLength)
	w.u32(v.ConditionalLength)
}

func EncodeGeneratorAuthoritySubject(v GeneratorAuthoritySubject) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorAuthoritySubjectLength)}
	writeGeneratorAuthoritySubject(&w, v)
	return w.b, nil
}

func DecodeGeneratorAuthoritySubject(b []byte) (GeneratorAuthoritySubject, error) {
	if len(b) > GeneratorAuthoritySubjectLength {
		return GeneratorAuthoritySubject{}, ErrRecordCapacity
	}
	if len(b) != GeneratorAuthoritySubjectLength {
		return GeneratorAuthoritySubject{}, ErrRecord
	}
	r := newRecordReader(b)
	v := GeneratorAuthoritySubject{
		Schema: r.u16(), Purpose: GeneratorAuthorityPurpose(r.u8()), RequiredAuthoritySet: r.u8(),
		DomainID: r.id(), OperationID: r.id(), RequestIdentityDigest: r.id(), PlanGraphID: r.id(), UsePlanDigest: r.id(), PhaseID: r.id(),
		PreviousHEADDigest: r.id(), PreviousRevisionID: r.id(), ConditionDigest: r.id(), BeforeRootDigest: r.id(), AfterRootDigest: r.id(),
		BeforeAccessDigest: r.id(), AfterAccessDigest: r.id(), OwnerID: r.id(), LineageID: r.id(), AttemptID: r.id(), PredecessorAttemptID: r.id(),
		ResultID: r.id(), ResultDigest: r.id(), DescriptorID: r.id(), ConfigContractID: r.id(), ResultContractID: r.id(),
		HeadCoreDigest: r.id(), ConditionalPlanDigest: r.id(),
		Intent: readGeneratorDescriptor(&r), IdentityPlan: readGeneratorDescriptor(&r), ValueEntryUnion: readGeneratorDescriptor(&r), MembershipChanges: readGeneratorDescriptor(&r),
		BeforeWork: readGeneratorDescriptor(&r), AfterWork: readGeneratorDescriptor(&r), ResultVector: readGeneratorDescriptor(&r), CapacityReservation: readGeneratorDescriptor(&r),
		BeforePhase: r.u32(), AfterPhase: r.u32(), HeadCoreLength: r.u32(), ConditionalLength: r.u32(),
	}
	if err := r.end(); err != nil {
		return GeneratorAuthoritySubject{}, err
	}
	if err := v.validate(); err != nil {
		return GeneratorAuthoritySubject{}, err
	}
	return v, nil
}

func GeneratorAuthoritySigningBytes(v GeneratorAuthoritySubject) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	prefix := generatorAuthorityPrefix + v.Purpose.Name() + "\x00"
	w := cryptoWriter{b: make([]byte, 0, len(prefix)+4+GeneratorAuthoritySubjectLength)}
	w.raw([]byte(prefix))
	w.u32(GeneratorAuthoritySubjectLength)
	writeGeneratorAuthoritySubject(&w, v)
	return w.b, nil
}

func GeneratorAuthorityDigest(v GeneratorAuthoritySubject) (ID, error) {
	if err := v.validate(); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(generatorAuthorityPrefix + v.Purpose.Name() + "\x00")
	w.u32(GeneratorAuthoritySubjectLength)
	writeGeneratorAuthoritySubject(&w, v)
	return w.result(0).Digest, nil
}

// GeneratorPhaseIdentity describes a later phase only. Initial physical IDs
// depend on RequestCoreDigest so they can precede the complete request identity.
type GeneratorPhaseIdentity struct {
	RequestIdentityDigest, ObservedHEADDigest, ConditionDigest ID
	TransitionKind                                             GeneratorAuthorityPurpose
	BeforePhase, AfterPhase                                    uint32
	Evidence                                                   GeneratorDescriptor
}

func GeneratorPhaseID(v GeneratorPhaseIdentity) (ID, error) {
	if !publicIDsValid(v.RequestIdentityDigest, v.ObservedHEADDigest, v.ConditionDigest) ||
		v.TransitionKind.Name() == "" || v.BeforePhase == 0 || v.BeforePhase == ^uint32(0) ||
		v.AfterPhase != v.BeforePhase+1 || !v.Evidence.Valid() {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 149)}
	w.id(v.RequestIdentityDigest)
	w.id(v.ObservedHEADDigest)
	w.id(v.ConditionDigest)
	w.u8(uint8(v.TransitionKind))
	w.u32(v.BeforePhase)
	w.u32(v.AfterPhase)
	writeGeneratorDescriptor(&w, v.Evidence)
	return generatorDigest("phase", w.b), nil
}

func generatorPhysicalID(label string, source ID) (ID, error) {
	if source.IsZero() {
		return ID{}, ErrRecord
	}
	return generatorDigest(label, source[:]), nil
}

func generatorPhysicalPageID(label string, source ID, kind Kind, index uint16) (ID, error) {
	if source.IsZero() || index >= childPageIndexCount(kind) {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 35)}
	w.id(source)
	w.u8(uint8(kind))
	w.u16(index)
	return generatorDigest(label, w.b), nil
}

func GeneratorInitialPhaseID(requestCoreDigest ID) (ID, error) {
	return generatorPhysicalID("initial-phase", requestCoreDigest)
}

func GeneratorInitialSnapshotID(requestCoreDigest ID) (ID, error) {
	return generatorPhysicalID("initial-snapshot", requestCoreDigest)
}

func GeneratorInitialTransitionID(requestCoreDigest ID) (ID, error) {
	return generatorPhysicalID("initial-transition", requestCoreDigest)
}

func GeneratorInitialRevisionID(requestCoreDigest ID) (ID, error) {
	return generatorPhysicalID("initial-revision", requestCoreDigest)
}

func GeneratorInitialPageID(requestCoreDigest ID, kind Kind, index uint16) (ID, error) {
	return generatorPhysicalPageID("initial-page", requestCoreDigest, kind, index)
}

// GeneratorDeleteReservationRequestID separates a fresh delete-only operation's
// request identity from its public request-core digest. The latter is already
// committed by the graph; this identity roots the admitted reserve phase.
func GeneratorDeleteReservationRequestID(requestCoreDigest ID) (ID, error) {
	return generatorPhysicalID("delete-reservation-request", requestCoreDigest)
}

func GeneratorPhaseSnapshotID(phaseID ID) (ID, error) {
	return generatorPhysicalID("phase-snapshot", phaseID)
}

func GeneratorPhaseTransitionID(phaseID ID) (ID, error) {
	return generatorPhysicalID("phase-transition", phaseID)
}

func GeneratorPhaseRevisionID(phaseID ID) (ID, error) {
	return generatorPhysicalID("phase-revision", phaseID)
}

func GeneratorPhasePageID(phaseID ID, kind Kind, index uint16) (ID, error) {
	return generatorPhysicalPageID("phase-page", phaseID, kind, index)
}
