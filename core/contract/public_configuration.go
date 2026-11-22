package contract

// PublicField separates omission, available meaning (including empty), and an
// expected public fact that the source cannot supply. It grants no validation.
type PublicField[T any] struct {
	State          PublicFieldState
	Value          T
	SourceLocation *SourceLocation
}

type PublicFieldState uint8

const (
	PublicMissing PublicFieldState = iota
	PublicPresent
	PublicUnavailable
	// PublicInvalid is derived by Core; offering it as input always refuses.
	PublicInvalid
)

type SourceLocation struct {
	SourceID     string
	Line, Column uint64
}

// PublicConfiguration contains only complete desired public settings. It has
// no source codec, observed state, private resolver or caller validation flags.
type PublicConfiguration struct {
	Entries        PublicField[[]PublicEntry]
	Recipients     PublicField[[]PublicRecipient]
	OutputBindings PublicField[[]PublicOutputBinding]
	Routing        PublicField[[]PublicRoutingRule]
	Groups         PublicField[[][]string]
	Store          PublicStoreSettings
	Authority      PublicAuthoritySettings
	Recovery       PublicRecoverySettings
}

type PublicEntry struct {
	Name                          string
	Class, Source                 PublicField[uint8]
	InputEncoding, OutputEncoding PublicField[uint8]
	PlainValue                    PublicField[[]byte]
	Memberships                   PublicField[[]ID]
	Generated                     *PublicGeneratedSettings
}

type PublicGeneratedSettings struct {
	Epoch                  PublicField[uint64]
	ConfigContractID       PublicField[ID]
	ResourceContractID     PublicField[ID]
	LifecycleMode          PublicField[GeneratorLifecycleMode]
	ContentIntent          PublicField[[]byte]
	Retirement, Completion PublicField[uint8]
}

type PublicRecipient struct {
	RecipientID ID
	DisplayName PublicField[string]
	Encryption  PublicEncryptionSettings
}

type PublicEncryptionSettings struct {
	Provider        PublicField[Family]
	Selector        PublicField[string]
	PublicKey       PublicField[[]byte]
	Fingerprint     PublicField[ID]
	WrapProfile     PublicField[uint16]
	ProtectionClass PublicField[uint8]
}

type PublicSigningSettings struct {
	Provider    PublicField[Family]
	Selector    PublicField[string]
	PublicKey   PublicField[[]byte]
	Fingerprint PublicField[ID]
	Role        PublicField[uint8]
	Profile     PublicField[uint16]
}

type PublicStoreSettings struct {
	DomainID                              PublicField[ID]
	Provider                              PublicField[Family]
	ConstructionProfile                   PublicField[uint16]
	Region, Bucket, Prefix, ExpectedOwner PublicField[string]
}

type PublicAuthoritySettings struct {
	RecipientID PublicField[ID]
	Signing     PublicSigningSettings
}

type PublicRecoverySettings struct {
	Enabled    PublicField[bool]
	Signing    *PublicSigningSettings
	Encryption *PublicEncryptionSettings
}

type PublicOutputBinding struct {
	DestinationID string
	Destination   PublicField[OutputDestination]

	Targets PublicField[[]PublicOutputTarget]
}

type PublicOutputTarget struct {
	EntryName                                           string
	ServiceContractID, CanonicalTarget, ConsumerLocator PublicField[string]
	TargetContractID                                    PublicField[string]
	TargetData                                          PublicField[[]byte]
	PayloadEncoding                                     PublicField[uint8]
	LocatorRequiresCreation                             PublicField[bool]
	Capabilities                                        PublicField[OutputActionCapabilities]
	CreateValueBounds, WriteValueBounds                 PublicField[OutputPayloadBounds]
	ConsumerPolicy                                      PublicField[OutputPolicy]
}

type PublicEntrySelector uint8

const (
	PublicNamedEntry PublicEntrySelector = iota + 1
	PublicDefaultRoute
)

type PublicRoutingKey struct {
	EntrySelector PublicEntrySelector
	EntryName     string
}

type PublicRoutingRule struct {
	Key          PublicRoutingKey
	Destinations PublicField[[]string]
}

type PublicOutputMeaning struct{ CanonicalTarget, ConsumerLocator, Physical string }

const (
	MaxPublicConfigurationBytes      = 121158832
	MaxPublicRoutingRules            = CryptoMaxValueEntries + 1
	MaxPublicDiagnostics             = 160060
	MaxPublicGeneratedIntents        = 48 << 20
	MaxPublicRegistryBytes           = 8 << 20
	MaxPublicTypedConfigurationBytes = 119531256
	MaxPublicSourceLocationBytes     = 7026912
	MaxPublicValidationBytes         = 30664442
)

type DiagnosticSubjectKind string
type DiagnosticOutcome string
type DiagnosticReason string
type DiagnosticField string

const (
	SubjectEntry                    DiagnosticSubjectKind = "entry"
	SubjectRecipient                DiagnosticSubjectKind = "recipient"
	SubjectOutputBinding            DiagnosticSubjectKind = "output_binding"
	SubjectOutputTarget             DiagnosticSubjectKind = "output_target"
	SubjectRoutingRule              DiagnosticSubjectKind = "routing_rule"
	SubjectDomain                   DiagnosticSubjectKind = "domain"
	SubjectStore                    DiagnosticSubjectKind = "store"
	SubjectAuthority                DiagnosticSubjectKind = "authority"
	SubjectRecovery                 DiagnosticSubjectKind = "recovery"
	SubjectConfiguration            DiagnosticSubjectKind = "configuration"
	SubjectObservation              DiagnosticSubjectKind = "observation"
	DiagnosticUnable                DiagnosticOutcome     = "unable to verify"
	DiagnosticDifference            DiagnosticOutcome     = "difference"
	ReasonPublicFactUnavailable     DiagnosticReason      = "required-public-fact-unavailable"
	ReasonInvalidInput              DiagnosticReason      = "invalid-input"
	ReasonMissingRequiredField      DiagnosticReason      = "missing-required-field"
	ReasonDuplicateKey              DiagnosticReason      = "duplicate-key"
	ReasonDuplicateMember           DiagnosticReason      = "duplicate-member"
	ReasonUnresolvedReference       DiagnosticReason      = "unresolved-reference"
	ReasonInvalidUTF8               DiagnosticReason      = "invalid-utf8"
	ReasonLimitExceeded             DiagnosticReason      = "limit-exceeded"
	ReasonInvalidFieldCombination   DiagnosticReason      = "invalid-field-combination"
	ReasonUnsupportedSchema         DiagnosticReason      = "unsupported-schema"
	ReasonUnsupportedProfile        DiagnosticReason      = "unsupported-profile"
	ReasonTrustBasisInvalid         DiagnosticReason      = "trust-basis-invalid"
	ReasonDomainBasisInvalid        DiagnosticReason      = "domain-basis-invalid"
	ReasonStoreBasisInvalid         DiagnosticReason      = "store-basis-invalid"
	ReasonExpired                   DiagnosticReason      = "expired"
	ReasonHeadInvalid               DiagnosticReason      = "head-invalid"
	ReasonProofInvalid              DiagnosticReason      = "proof-invalid"
	ReasonSelectedObjectInvalid     DiagnosticReason      = "selected-object-invalid"
	ReasonImmutableConflict         DiagnosticReason      = "immutable-conflict"
	ReasonSelectedRelationInvalid   DiagnosticReason      = "selected-relation-invalid"
	ReasonEvidenceUnavailable       DiagnosticReason      = "evidence-unavailable"
	ReasonSelectedObjectUnavailable DiagnosticReason      = "selected-object-unavailable"
	ReasonReadContention            DiagnosticReason      = "read-contention"
	ReasonCancelled                 DiagnosticReason      = "cancelled"
	ReasonDiagnosticsIncomplete     DiagnosticReason      = "diagnostics-incomplete"
	ReasonStaleSealedInputBinding   DiagnosticReason      = "stale-sealed-input-binding"
)

const (
	FieldPresence                DiagnosticField = "presence"
	FieldName                    DiagnosticField = "name"
	FieldClass                   DiagnosticField = "class"
	FieldSource                  DiagnosticField = "source"
	FieldInputEncoding           DiagnosticField = "input_encoding"
	FieldOutputEncoding          DiagnosticField = "output_encoding"
	FieldPlainValue              DiagnosticField = "plain_value"
	FieldMemberships             DiagnosticField = "memberships"
	FieldGenerated               DiagnosticField = "generated"
	FieldEpoch                   DiagnosticField = "epoch"
	FieldResourceContract        DiagnosticField = "resource_contract"
	FieldConfigContract          DiagnosticField = "config_contract"
	FieldLifecycle               DiagnosticField = "lifecycle"
	FieldContentIntent           DiagnosticField = "content_intent"
	FieldRetirement              DiagnosticField = "retirement"
	FieldCompletion              DiagnosticField = "completion"
	FieldDisplayName             DiagnosticField = "display_name"
	FieldDestination             DiagnosticField = "destination"
	FieldGroups                  DiagnosticField = "groups"
	FieldEncryptionProvider      DiagnosticField = "encryption_provider"
	FieldEncryptionSelector      DiagnosticField = "encryption_selector"
	FieldEncryptionPublicKey     DiagnosticField = "encryption_public_key"
	FieldEncryptionFingerprint   DiagnosticField = "encryption_fingerprint"
	FieldWrapProfile             DiagnosticField = "wrap_profile"
	FieldProtectionClass         DiagnosticField = "protection_class"
	FieldTargets                 DiagnosticField = "targets"
	FieldProvider                DiagnosticField = "provider"
	FieldCanonicalTarget         DiagnosticField = "canonical_target"
	FieldConsumerLocator         DiagnosticField = "consumer_locator"
	FieldServiceContract         DiagnosticField = "service_contract"
	FieldCanonicalSettings       DiagnosticField = "canonical_settings"
	FieldCapabilities            DiagnosticField = "capabilities"
	FieldCreateValueBounds       DiagnosticField = "create_value_bounds"
	FieldWriteValueBounds        DiagnosticField = "write_value_bounds"
	FieldLocatorRequiresCreation DiagnosticField = "locator_requires_creation"
	FieldTargetContract          DiagnosticField = "target_contract"
	FieldTargetData              DiagnosticField = "target_data"
	FieldPayloadEncoding         DiagnosticField = "payload_encoding"
	FieldConsumerPolicy          DiagnosticField = "consumer_policy"
	FieldDestinations            DiagnosticField = "destinations"
	FieldDomainID                DiagnosticField = "domain_id"
	FieldConstructionProfile     DiagnosticField = "construction_profile"
	FieldRegion                  DiagnosticField = "region"
	FieldBucket                  DiagnosticField = "bucket"
	FieldPrefix                  DiagnosticField = "prefix"
	FieldExpectedOwner           DiagnosticField = "expected_owner"
	FieldRecipientID             DiagnosticField = "recipient_id"
	FieldSigningProvider         DiagnosticField = "signing_provider"
	FieldSigningSelector         DiagnosticField = "signing_selector"
	FieldSigningPublicKey        DiagnosticField = "signing_public_key"
	FieldSigningFingerprint      DiagnosticField = "signing_fingerprint"
	FieldSigningRole             DiagnosticField = "signing_role"
	FieldSigningProfile          DiagnosticField = "signing_profile"
	FieldEnabled                 DiagnosticField = "enabled"
)

// The subject carries logical keys once. Paths contain only relative closed
// fields, so names with slashes, empty names and fallback remain unambiguous.
type DiagnosticSubject struct {
	Kind          DiagnosticSubjectKind
	Name          string
	RecipientID   ID
	DestinationID string
	RoutingKey    PublicRoutingKey
}

type Diagnostic struct {
	Subject        DiagnosticSubject
	Path           []DiagnosticField
	Outcome        DiagnosticOutcome
	Reason         DiagnosticReason
	SourceLocation *SourceLocation
}

// ImmutableConflictShape checks the single Store diagnostic that can carry
// an exact immutable-write conflict in a public mutation response.
func (d Diagnostic) ImmutableConflictShape() bool {
	return d.Subject == (DiagnosticSubject{Kind: SubjectStore}) && d.Outcome == DiagnosticUnable &&
		len(d.Path) == 1 && d.Path[0] == FieldPresence && d.SourceLocation == nil
}

// OutputPolicyLength checks the same canonical policy fields without retaining
// a serialized policy image.
func OutputPolicyLength(v OutputPolicy) (int, error) {
	w, err := writeOutputPolicy(v, false)
	return w.length, err
}
