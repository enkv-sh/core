package contract

type ComparisonVerdict string
type ComparisonScopeStatus string
type ComparisonFieldFamily string

const (
	ReaderCompareOperation                             = "compare-public-configuration"
	ReaderManifestOperation                            = "issue-consumption-manifest"
	MaxComparisonResultJSONBytes                       = 2356478048
	ComparisonMatch              ComparisonVerdict     = "match"
	ComparisonMismatch           ComparisonVerdict     = "mismatch"
	ComparisonUnable             ComparisonVerdict     = "unable to verify"
	ScopeComplete                ComparisonScopeStatus = "complete"
	ScopePartial                 ComparisonScopeStatus = "partial"
	ScopeUnchecked               ComparisonScopeStatus = "unchecked"
	ScopeEntries                 ComparisonFieldFamily = "entries"
	ScopePlainValues             ComparisonFieldFamily = "plain_values"
	ScopeSecretSettings          ComparisonFieldFamily = "secret_settings"
	ScopeMemberships             ComparisonFieldFamily = "memberships"
	ScopeRecipients              ComparisonFieldFamily = "recipients"
	ScopeEncryption              ComparisonFieldFamily = "encryption"
	ScopeGenerated               ComparisonFieldFamily = "generated"
	ScopeOutputs                 ComparisonFieldFamily = "outputs"
	ScopeRouting                 ComparisonFieldFamily = "routing"
	ScopeDomainStore             ComparisonFieldFamily = "domain_store"
	ScopeAuthorityRecovery       ComparisonFieldFamily = "authority_recovery"
	ScopeCompatibilityProfiles   ComparisonFieldFamily = "compatibility_profiles"
	ReasonExpectedEntryAbsent    DiagnosticReason      = "expected-entry-absent"
	ReasonObservedEntryAbsent    DiagnosticReason      = "observed-entry-absent"
	ReasonExpectedSettingAbsent  DiagnosticReason      = "expected-setting-absent"
	ReasonObservedSettingAbsent  DiagnosticReason      = "observed-setting-absent"
	ReasonFieldDiffers           DiagnosticReason      = "field-differs"
	ReasonSetDiffers             DiagnosticReason      = "set-differs"
	ReasonBytesDiffer            DiagnosticReason      = "bytes-differ"
	ComparisonEvidenceLimit                            = "Fixed authenticated public settings and requested generated intent only; future generated content is unavailable and secret-value equality is unchecked. Excludes apply admission or no-op, performed effects or credential validity, remote output contents or IAM, historical application, and continued currentness."
)

type ComparisonScope struct {
	Family ComparisonFieldFamily
	Status ComparisonScopeStatus
}
type ComparisonObservation struct{ DomainID, HeadRevisionID, SnapshotID ID }

// Changes and Diagnostics partition one subject/field union. Their combined
// length is bounded by MaxPublicDiagnostics; only failures are diagnostics.
type ComparisonPayload struct {
	Verdict              ComparisonVerdict
	Diagnostics          []Diagnostic
	Changes              []ComparisonChange
	BeforeRecipients     []ComparisonRecipientLabel
	AfterRecipients      []ComparisonRecipientLabel
	CheckedScope         []ComparisonScope
	DiagnosticsComplete  bool
	Observation          *ComparisonObservation
	EvidenceLimit        string
	GeneratedEntries     []GeneratedPlanningEntry
	PublicationRequested bool
	Publication          *PublicationPreview
}

// ComparisonChange owns one verified public field difference at its observation.
// Before is authenticated observed meaning; After is validated proposed meaning.
type ComparisonChange struct {
	Subject        DiagnosticSubject
	Path           []DiagnosticField
	Action         ComparisonChangeAction
	Before, After  ComparisonSide
	SourceLocation *SourceLocation
}

type ComparisonChangeAction string
type ComparisonSideState string
type ComparisonValueType string
type ComparisonMemberChange string

const (
	ComparisonAdded           ComparisonChangeAction = "added"
	ComparisonRemoved         ComparisonChangeAction = "removed"
	ComparisonChanged         ComparisonChangeAction = "changed"
	ComparisonAbsent          ComparisonSideState    = "absent"
	ComparisonPresent         ComparisonSideState    = "present"
	ComparisonTypeNull        ComparisonValueType    = "null"
	ComparisonTypeBoolean     ComparisonValueType    = "boolean"
	ComparisonTypeUint        ComparisonValueType    = "uint"
	ComparisonTypeText        ComparisonValueType    = "text"
	ComparisonTypeBytes       ComparisonValueType    = "bytes"
	ComparisonTypeID          ComparisonValueType    = "id"
	ComparisonTypeIDSet       ComparisonValueType    = "id-set"
	ComparisonTypeTextSet     ComparisonValueType    = "text-set"
	ComparisonTypeGroups      ComparisonValueType    = "groups"
	ComparisonTypeDestination ComparisonValueType    = "destination"
	ComparisonTypePolicy      ComparisonValueType    = "policy"
	ComparisonTypeBounds      ComparisonValueType    = "bounds"
	ComparisonMemberUnchanged ComparisonMemberChange = "unchanged"
	ComparisonMemberAdded     ComparisonMemberChange = "added"
	ComparisonMemberRemoved   ComparisonMemberChange = "removed"
)

// An absent side has no Value. A present side has one closed value arm, including
// when its bytes, text or collection is empty. Unavailable facts are diagnostics.
type ComparisonSide struct {
	State ComparisonSideState
	Value ComparisonValue
}

// ComparisonValue admits only the public value arms below. Bytes and collections
// belong to the result; they never contain secret input or private records.
type ComparisonValue interface{ comparisonValue() }

// ComparisonNull is reserved for an admitted nullable public field. It is not
// an unavailable fact or the canonical bytes of a plugin null root.
type ComparisonNull struct{}
type ComparisonBoolean bool
type ComparisonUint uint64
type ComparisonText string
type ComparisonBytes []byte
type ComparisonID ID
type ComparisonIDSet []ComparisonMember
type ComparisonTextSet []string
type ComparisonGroups [][]string
type ComparisonDestination OutputDestination
type ComparisonPolicy OutputPolicy
type ComparisonBounds OutputPayloadBounds

func (ComparisonNull) comparisonValue()        {}
func (ComparisonBoolean) comparisonValue()     {}
func (ComparisonUint) comparisonValue()        {}
func (ComparisonText) comparisonValue()        {}
func (ComparisonBytes) comparisonValue()       {}
func (ComparisonID) comparisonValue()          {}
func (ComparisonIDSet) comparisonValue()       {}
func (ComparisonTextSet) comparisonValue()     {}
func (ComparisonGroups) comparisonValue()      {}
func (ComparisonDestination) comparisonValue() {}
func (ComparisonPolicy) comparisonValue()      {}
func (ComparisonBounds) comparisonValue()      {}

// ComparisonValueTypeOf returns no type for an unsupported arm. The field owner
// must also admit that type for its exact subject and relative field.
func ComparisonValueTypeOf(value ComparisonValue) ComparisonValueType {
	switch value.(type) {
	case ComparisonNull:
		return ComparisonTypeNull
	case ComparisonBoolean:
		return ComparisonTypeBoolean
	case ComparisonUint:
		return ComparisonTypeUint
	case ComparisonText:
		return ComparisonTypeText
	case ComparisonBytes:
		return ComparisonTypeBytes
	case ComparisonID:
		return ComparisonTypeID
	case ComparisonIDSet:
		return ComparisonTypeIDSet
	case ComparisonTextSet:
		return ComparisonTypeTextSet
	case ComparisonGroups:
		return ComparisonTypeGroups
	case ComparisonDestination:
		return ComparisonTypeDestination
	case ComparisonPolicy:
		return ComparisonTypePolicy
	case ComparisonBounds:
		return ComparisonTypeBounds
	default:
		return ""
	}
}

type ComparisonMember struct {
	ID     ID
	Change ComparisonMemberChange
}

// Labels are shared by exact ID on each side. A nil label is unavailable; a
// pointer to an empty string preserves an available empty label.
type ComparisonRecipientLabel struct {
	RecipientID       ID
	Name, DisplayName *string
}

const (
	MaxGeneratedPlanningEntries      = 2 * GeneratedCurrentEntryLimit
	MaxGeneratedPlanningRowJSONBytes = 4096
)

type GeneratedPlanningAction uint8

const (
	GeneratedPlanningCreate GeneratedPlanningAction = iota + 1
	GeneratedPlanningRotate
	GeneratedPlanningUnchanged
	GeneratedPlanningPolicyChange
	GeneratedPlanningAccessChange
	GeneratedPlanningPolicyAccessChange
	GeneratedPlanningSourceChange
	GeneratedPlanningRemoval
)

type GeneratedPlanningRetirement uint8

const (
	GeneratedPlanningNoRetirement GeneratedPlanningRetirement = iota + 1
	GeneratedPlanningRetireAfterSuccessor
	GeneratedPlanningRetireAfterRemoval
)

const (
	GeneratedPlanningPresence uint16 = 1 << iota
	GeneratedPlanningClass
	GeneratedPlanningSource
	GeneratedPlanningMemberships
	GeneratedPlanningEpoch
	GeneratedPlanningConfigContract
	GeneratedPlanningResourceContract
	GeneratedPlanningLifecycle
	GeneratedPlanningContentIntent
	GeneratedPlanningRetirementPolicy
	GeneratedPlanningCompletion
	GeneratedPlanningAllFields = 1<<11 - 1
)

const (
	GeneratedPlanningStaleEpoch uint16 = 1 << iota
	GeneratedPlanningInitialEpoch
	GeneratedPlanningIntentConflict
	GeneratedPlanningClassConflict
	GeneratedPlanningRetiring
	GeneratedPlanningActiveOperation
	GeneratedPlanningAllBlockers = 1<<6 - 1
)

// GeneratedPlanningEntry describes a request against one fixed observation.
// Detached retirement retains its original target coordinates; no unavailable
// historical canonical GenerationID or future generated value is inferred.
type GeneratedPlanningEntry struct {
	Name                                                                                      string
	CurrentIncarnation, CurrentGeneration                                                     ID
	RetiringDutyID, RetiringIncarnation, RetiringResource                                     ID
	RetiringOriginalOperation, RetiringOriginalAttempt, ActiveOperation                       ID
	CurrentEpoch, RequestedEpoch, RetiringEpoch                                               uint64
	ChangedFields, Blockers                                                                   uint16
	Action                                                                                    GeneratedPlanningAction
	Retirement                                                                                GeneratedPlanningRetirement
	CurrentSource, ProposedSource, CurrentPolicy, ProposedPolicy, CurrentClass, ProposedClass uint8
	CurrentLifecycleMode, ProposedLifecycleMode                                               GeneratorLifecycleMode
}

type ReaderStateResult string

const (
	ReaderSuccess        ReaderStateResult = "success"
	ReaderRefused        ReaderStateResult = "refused"
	ReaderProfileBlocked ReaderStateResult = "profile-blocked"
	ReaderPositiveDefect ReaderStateResult = "positive-defect"
	ReaderUnavailable    ReaderStateResult = "unavailable"
	ReaderContention     ReaderStateResult = "contention"
)
