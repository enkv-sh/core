package contract

// These inputs borrow authenticated public facts for one synchronous installed
// custody admission. They contain no execution capability or caller assertion.
type GeneratedSessionInput struct {
	Graph                []byte
	BeforePublic         PublicState
	Output               *GeneratedOutputTransition
	CurrentRecipients    []RecipientRecord
	CurrentRecipientRefs []Ref
	BeforeReceipts       MutationReceiptWindows
	// SelectionPhase supplies the matching selected predecessor Phase whenever
	// Output contains its fact, including before canonical selection with a zero
	// SelectionPhaseID.
	SelectionPhase      *GeneratedPhaseRecord
	BeforeAccess        *CurrentAccessCore
	BeforeAccessRecords []AccessRecord
}

type GeneratedPlanInput struct {
	Declaration, RegistryImage []byte
	Canonical                  []GeneratedCanonicalSelection
	LiveSourceUses             []GeneratorSourceUse
	CurrentIntents             []GeneratedCurrentIntentSelection
	CurrentValues              []ConsumerSelection
}

type GeneratedCustodyInput struct {
	Material                      OperationMaterialRecord
	SeedAccess, SourceProtections []byte
}

type GeneratedResultAdmissionInput struct {
	Expected  GeneratorResultExpectation
	Reference GeneratorResultReference
}

type GeneratedReservationInput struct {
	Session               GeneratedSessionInput
	Plan                  GeneratedPlanInput
	Phase                 *GeneratorPhaseIdentity
	Target                *GeneratorTarget
	ControlledPredecessor *GeneratedControlledPredecessor
}

type GeneratedProducerInput struct {
	Session               GeneratedSessionInput
	Plan                  GeneratedPlanInput
	Custody               GeneratedCustodyInput
	Phase                 *GeneratorPhaseIdentity
	Target                *GeneratorTarget
	ControlledPredecessor *GeneratedControlledPredecessor
	Expected              GeneratorResultExpectation
	Preparation           GeneratedProducerPreparation
	Intent, OriginalFacts []byte
	Duty                  GeneratedDutyRecord
	Source                SupportRecord
	Attempt               GeneratedAttemptRecord
	Consumers, Progress   [][]byte
}

// GeneratedProducerResult transfers one invocation's encrypted record and safe
// facts. ExecutableCleanupFailed reports the host-qualified local removal
// failure separately; it grants no effect or replay authority.
type GeneratedProducerResult struct {
	Record                  []byte
	Facts                   GeneratorSafeFacts
	Code                    CryptoResultCode
	ExecutableCleanupFailed bool
}

type GeneratedAdoptionInput struct {
	Session               GeneratedSessionInput
	Plan                  GeneratedPlanInput
	Custody               GeneratedCustodyInput
	Phase                 GeneratorPhaseIdentity
	Result                GeneratedResultAdmissionInput
	Target                *GeneratorTarget
	ControlledPredecessor *GeneratedControlledPredecessor
}

// GeneratedLocalFailureInput carries the exact proposed terminal row. The
// original private receiver supplies failure authority; these public facts do
// not assert that the callback or original-result publication joined.
type GeneratedLocalFailureInput struct {
	Session             GeneratedSessionInput
	Plan                GeneratedPlanInput
	Custody             GeneratedCustodyInput
	Phase               GeneratorPhaseIdentity
	Attempt             GeneratedAttemptRecord
	BeforeSliceSnapshot ID
}

type GeneratedFinalEntryInput struct {
	Slot      uint16
	Generated GeneratedEntryMetadata
}

type GeneratedMembershipInput struct{ Selection ConsumerSelection }

type GeneratedFinalInput struct {
	Session               GeneratedSessionInput
	Plan                  GeneratedPlanInput
	Custody               GeneratedCustodyInput
	Phase                 GeneratorPhaseIdentity
	CanonicalAccess       []ConsumerSelection
	Results               []GeneratedResultAdmissionInput
	ResultBodies          [][]byte
	Preparation           *GeneratedFinalPreparationRecord
	PreparationPhase      *GeneratedPhaseRecord
	PreparedImage         []byte
	QualifyLegacy         bool
	CheckpointSupport     []SupportRecord
	EntryAdmissions       []GeneratedFinalEntryInput
	Membership            []GeneratedMembershipInput
	Target                *GeneratorTarget
	ControlledPredecessor *GeneratedControlledPredecessor
}

type GeneratedVerificationInput struct {
	Owner      SupportRecord
	Session    GeneratedSessionInput
	Material   OperationMaterialRecord
	SeedAccess []byte
	Result     GeneratedResultAdmissionInput
	Target     *GeneratorTarget
}

type GeneratedCandidateEntry struct {
	Slot  uint16
	Entry ValueEntry
}

type GeneratedRecipientReceiptInput struct {
	Plan            MutationReceiptDeltaPlan
	After           MutationReceiptWindows
	ChangedSubjects []ChangedSubjectIdentity
}

type GeneratedCandidateRegistryInput struct {
	Image, Root   []byte
	Recipients    []RecipientRecord
	RecipientRefs []Ref
	IdentityPlan  IdentityPlan
	ReceiptDelta  *GeneratedRecipientReceiptInput
}

type GeneratedCandidateInput struct {
	ActiveOwner, ActivePhase, ActiveGraph                ID
	Subject                                              GeneratorAuthoritySubject
	PublicState                                          PublicState
	CurrentAccess                                        CurrentAccessCore
	AccessRecords                                        []AccessRecord
	SupportRecords                                       []SupportRecord
	Entries                                              []GeneratedCandidateEntry
	HeadCore, Conditional, GrantWraps, SourceProtections []byte
	LiveSourceUses                                       []GeneratorSourceUse
	Registry                                             *GeneratedCandidateRegistryInput
}
