// Package format owns canonical state containers. Embedded public records use
// their single field traversal in contract.
package format

import "enkv.sh/core/contract"

type ID = contract.ID
type Kind = contract.Kind
type Ref = contract.Ref
type ValueEntry = contract.ValueEntry
type Recipient = contract.RecipientRecord

const Version uint16 = contract.CanonicalSchema
const (
	PageSlots                = 16
	RecipientSlots           = 8
	MaxValueEntryPage        = contract.MaxValueEntryPageLength
	MaxRecipientPage         = contract.MaxRecipientPageLength
	MaxRoot                  = contract.MaxRootLength
	ValueEntryPageKind       = contract.ValueEntryPageKind
	RecipientKind            = contract.RecipientKind
	RootKind                 = contract.RootKind
	HeadKind                 = contract.HeadKind
	AccessKind               = contract.AccessKind
	Supplied                 = contract.Supplied
	Plain                    = contract.Plain
	Secret                   = contract.Secret
	Current                  = contract.CurrentRecipient
	SuccessorHead      uint8 = 1
	GenesisHead        uint8 = 2
	LifecycleAuth      uint8 = 1
	SuccessionAuth     uint8 = 2
	GenesisAuth        uint8 = 4
	GeneratorAuth      uint8 = 5
	AdministrativeAuth uint8 = 6
	OutputReserveAuth  uint8 = 7
	OutputCloseAuth    uint8 = 8
	GCAuth             uint8 = 9
)

type ValueEntryPage struct {
	Domain, Object ID
	Index          uint16
	Slots          [PageSlots]*ValueEntry
}
type RecipientPage struct {
	Domain, Object ID
	Index          uint16
	Slots          [RecipientSlots]*Recipient
}
type AccessPage struct {
	Domain, Object ID
	Index          uint16
	Records        []contract.AccessRecord
}
type NameEntry struct {
	Name string
	Slot uint16
}
type Root struct {
	Domain, Snapshot, Transition                              ID
	ValueEntryPages                                           [contract.MaxValueEntryPages]*Ref
	Recipients                                                [contract.MaxRecipientPages]*Ref
	CurrentAccess                                             contract.CurrentAccessSection
	GrantPages                                                []Ref
	AdministrativeIndex                                       Ref
	AdministrativeIndexShards                                 []Ref
	WarningBits                                               uint8
	RequiredSupport                                           []Ref
	OutputConfiguration                                       contract.OutputConfigurationDescriptor
	Names                                                     []NameEntry
	ValueEntryCount, SecretCount                              uint32
	RawBytes                                                  uint64
	MembershipCount, SecretOrdinaryWrapCount                  uint32
	RecipientCount                                            uint16
	AccessRecordCount, RequiredSupportRecordCount, ChildCount uint32
	ChildEncodedBytes                                         uint64
	Unsupported                                               uint32
	Generated                                                 GeneratedClosure
	ActiveGC                                                  ID
	GCPlans                                                   contract.GCDescriptor
}
type HeadCore struct {
	Form                                              uint8
	Domain, Revision                                  ID
	PreviousRevision, PreviousDigest                  ID
	PreviousToken                                     contract.Token
	Root                                              Ref
	GrantDigest                                       ID
	Store, Trust, Coordinate, NonBody, Interpretation ID
	Epoch                                             uint64
	Unsupported                                       uint32
}
type ConditionalPlan struct {
	Family                     contract.Family
	Store, Coordinate, NonBody ID
	Condition                  contract.HeadCondition
	HeadCore                   ID
	HeadCoreLength             uint32
}
type GenesisPlanCore struct {
	DescriptorDigest ID
	IdentityPlan     contract.IdentityPlan
	Root             Root
	HeadCore         HeadCore
	ConditionalPlan  ConditionalPlan
	RecoveryMode     uint8
	K3ChallengeID    ID
	Probes           []contract.InitProbePlanRow
}
type GenesisProof struct {
	Subject     contract.GenesisSubject
	Request     contract.GenesisRequestCore
	Plan        GenesisPlanCore
	Closure     contract.GenesisBootstrapClosureCore
	K3Challenge []byte
}
type Head struct {
	Core                   HeadCore
	K1, K3                 []byte
	AuthKind               uint8
	Subject                contract.LifecycleSubject
	Genesis                *GenesisProof
	Succession             *SuccessionProof
	Generator              *contract.GeneratorAuthoritySubject
	EndWork                *contract.EndWorkSubject
	OutputReserve          *contract.OutputReserveSubject
	OutputClose            *contract.OutputCloseSubject
	GC                     *contract.GCSubject
	AuthorizationSignature []byte
	GrantWraps             []byte
}
