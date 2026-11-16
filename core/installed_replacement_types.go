package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
)

type ReplacementTarget uint8

const (
	ReplacementTargetAuthority ReplacementTarget = iota + 1
	ReplacementTargetRecovery
	ReplacementTargetRecipient
)

type ReplacementMaterialSource uint8

const (
	ReplacementMaterialAuthority ReplacementMaterialSource = iota + 1
	ReplacementMaterialRecovery
)

type RoleReplacementGoal struct {
	ApprovalRole                        uint8
	SigningSelector, EncryptionSelector string
	MaterialSource                      ReplacementMaterialSource
}

// ReplacementRecipientFact is one captured generated row, including pending
// rows. Slice order and duplicate multiplicity belong to its captured source.
type ReplacementRecipientFact struct {
	RecipientID contract.ID
	Encryption  contract.KMSBinding
}

type ReplacementSigningKey struct {
	Selector           string
	SPKI               []byte
	Fingerprint, Trust contract.ID
	Profile            uint16
}

type ReplacementEncryptionKey struct {
	Selector        string
	SPKI            []byte
	Fingerprint     contract.ID
	Profile         uint16
	ProtectionClass uint8
}

type ReplacementPublicRequest struct {
	Provider                            contract.Family
	SigningRole                         uint8
	SigningSelector, EncryptionSelector string
}

type ReplacementPublicGoal struct {
	Provider   contract.Family
	Signing    *ReplacementSigningKey
	Encryption *ReplacementEncryptionKey
}

// ReplacementCorrelation contains the actual signed candidate. It grants no
// selection, execution or historical attribution by itself.
type ReplacementCorrelation struct {
	Target          ReplacementTarget
	RecipientID     contract.ID
	RequestIdentity contract.ID
	SignedCandidate []byte
}

type ReplacementSuccessor struct {
	DomainID, OperationID, RequestIdentity contract.ID
	Control                                contract.ControlCore
	Recipients                             []ReplacementRecipientFact
	Basis                                  PublicBasis
	Correlation                            ReplacementCorrelation
}

// ReplacementReadback is reconstructed from the reopened output pair. Core
// compares it with its privately retained candidate and admitted source facts.
type ReplacementReadback struct {
	Basis        PublicBasis
	FileIdentity contract.ID
	Control      contract.ControlCore
	Recipients   []ReplacementRecipientFact
	Correlation  ReplacementCorrelation
}

type InstalledReplacementCustody struct {
	Crypto contract.Crypto
	Close  func()
}

// ReplacementInstallation fixes independent source trust and static provider
// construction. Public key resolution and private capability construction are
// separate deferred boundaries.
type ReplacementInstallation struct {
	ExpectedDomain              contract.ID
	ExpectedStore               contract.Descriptor
	PublicBasis                 PublicBasis
	ExpectedControl             contract.ControlCore
	CapturedRecipients          []ReplacementRecipientFact
	Store                       contract.Store
	CompositionID, FileIdentity contract.ID
	ResolvePublicGoal           func(context.Context, ReplacementPublicRequest) (ReplacementPublicGoal, error)
	ConstructSigners            func(context.Context, contract.PublicSigningBinding, *contract.PublicSigningBinding) (SuccessionSigners, func(), error)
	AdmitSuccessionCustody      func(context.Context, contract.CryptoAccessReplaceRequest, contract.SuccessionRequestCore, contract.ControlCore, contract.BindingTableRow, contract.SuccessorKEKProbeCore, []contract.CompactRow, time.Time) (*InstalledReplacementCustody, error)
	AdmitRecipientCustody       func(context.Context, contract.CryptoAccessReplaceRequest, contract.RecipientReplacementIntent, contract.RequestCore, contract.ControlCore, []contract.CompactRow, time.Time) (*InstalledReplacementCustody, error)
	PublishSuccessor            func(context.Context, ReplacementSuccessor) (ReplacementReadback, error)
	SourceUnchanged             func(context.Context) error
	CloseInstalled              func()
}

type AuthorityReplacementInstallation struct {
	ReplacementInstallation
	Goal RoleReplacementGoal
}

type RecoveryReplacementInstallation struct {
	ReplacementInstallation
	Goal RoleReplacementGoal
}

type RecipientReplacementInstallation struct {
	ReplacementInstallation
	RecipientID        contract.ID
	RecipientRow       uint16
	EncryptionSelector string
}

type PublicReplacementResult struct {
	NoWorkObservation                                 *AuthorityReplacementNoWorkObservation
	RequestID, OperationID, RequestIdentity, DomainID contract.ID
	Result                                            Result
	Payload                                           *TransitionPayload
	Receipt                                           []byte
	WarningBits                                       uint8
	Diagnostics                                       []contract.Diagnostic
}
