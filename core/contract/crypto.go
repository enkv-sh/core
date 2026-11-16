package contract

import (
	"context"
	"errors"
)

const (
	cryptoPurposePrefix                  = "ENKV/CRYPTO/v2/"
	CryptoSchema                  uint16 = 4
	CryptoFrameLimit                     = 32 << 20
	CryptoRequestLimit                   = 31_573_219
	CryptoResponseLimit                  = 19_043_992
	CryptoApplyContextLength             = 1 + 4*32 + 8 + 32 + RefLength + 32 + descriptorSize + 32
	CryptoRefLength                      = RefLength
	CryptoMaxValueEntries                = 512
	CryptoMaxValueEntryRecipients        = 64
	CryptoMaxMemberships                 = 4096
	CryptoMaxRecipients                  = 256
	CryptoMaxUnion                       = 1024
	CryptoMaxName                        = 256
	CryptoMaxRawValue                    = 65536
	CryptoMaxRawSet                      = 8 << 20
	CryptoMaxSealedInputLength           = SealedInputEnvelopeFixedLength + CryptoMaxName + CryptoMaxRetainedValue
	CryptoMaxValueEntryLength            = ValueEntryFixedLength + CryptoMaxName + 32*CryptoMaxValueEntryRecipients + CanonicalPayloadOverhead + CryptoMaxRetainedValue + GeneratedEntryMetadataMaxLength
)

var (
	ErrCryptoMessage  = errors.New("invalid custody message")
	ErrCryptoCapacity = errors.New("custody message capacity exceeded")
)

type CryptoKind uint8

const (
	CryptoCompare         CryptoKind = 1
	CryptoPrepare         CryptoKind = 2
	CryptoFreeze          CryptoKind = 3
	CryptoClaim           CryptoKind = 4
	CryptoDiscard         CryptoKind = 5
	CryptoAccessReplace   CryptoKind = 6
	CryptoQualifyInitKeys CryptoKind = 7
)

func (k CryptoKind) Valid() bool {
	return k >= CryptoCompare && k <= CryptoQualifyInitKeys
}

type CryptoResultCode uint16

const (
	CryptoSuccess                    CryptoResultCode = 1
	CryptoInvalidInput               CryptoResultCode = 2
	CryptoInvalidAdmission           CryptoResultCode = 3
	CryptoExpired                    CryptoResultCode = 4
	CryptoCancelled                  CryptoResultCode = 5
	CryptoAlreadyUsed                CryptoResultCode = 6
	CryptoSourceAuthenticationFailed CryptoResultCode = 7
	CryptoPrivateRouteUnavailable    CryptoResultCode = 8
	CryptoCustodyUnavailable         CryptoResultCode = 9
	CryptoResponseUnknown            CryptoResultCode = 10
	CryptoCapacityExceeded           CryptoResultCode = 11
	CryptoStoredAuthenticationFailed CryptoResultCode = 12
)

func (c CryptoResultCode) Valid() bool {
	return c >= CryptoSuccess && c <= CryptoStoredAuthenticationFailed
}

// Crypto exchanges public facts and encrypted records. Context controls only
// the local call; it supplies no admission or request meaning.
type Crypto interface {
	InstanceID() ID
	Exchange(context.Context, CryptoRequest) CryptoResponse
}

type CryptoRequest struct {
	Schema                       uint16
	Kind                         CryptoKind
	RequestID, CustodyInstanceID ID
	Body                         []byte
}

type CryptoResponse struct {
	Schema                       uint16
	Kind                         CryptoKind
	RequestID, CustodyInstanceID ID
	ResultCode                   CryptoResultCode
	KeyUseRows                   []KeyUseRow
	Body                         []byte
}

// ApplyContext is a public copy of independently admitted custody facts.
// Expiry is positive Unix nanoseconds, limited to the int64 range. The private
// parent retains and checks the original deadline; this value cannot renew it.
type ApplyContext struct {
	OperationClass                                    CryptoOperationClass
	AdmissionID, SessionID, DomainID, CompatibilityID ID
	Expiry                                            uint64
	PredecessorHEADDigest                             ID
	PredecessorRootRef                                [CryptoRefLength]byte
	OriginalConditionDigest                           ID
	IntentDescriptor                                  DescriptorVector
	CurrentAccessRoot                                 ID
}

type CryptoIntentRow struct {
	Name                          string
	Recipients                    []ID
	ValueSource                   uint8
	ConfidentialityClass          uint8
	ContentLength                 uint32
	InputEncoding, OutputEncoding uint8
	RetainedLength                uint32
	PayloadDigest                 ID
	PayloadLength                 uint32
	Retained                      RetainedSecretInput
}

// RetainedSecretInput identifies the exact current supplied secret. A zero
// value in a CryptoIntentRow selects its ordinary input representation.
type RetainedSecretInput struct {
	Incarnation, Material ID
}

type CryptoCurrentSecret struct {
	Slot                     uint16
	EntryBytes, AccessRecord []byte
}

type CryptoSealedInput struct {
	Name          string
	EnvelopeBytes []byte
}

type CryptoSealedInputMetadata struct {
	SealedInputCore
	AuthorityRecipientID, AuthorityBindingID, AuthorityBindingDigest ID
	AuthorityBindingSerial                                           uint64
}

type CryptoCompareRequest struct {
	Context      ApplyContext
	Intent       []CryptoIntentRow
	Recipients   []ApplyRecipientInput
	Current      []CryptoCurrentSecret
	SealedInputs []CryptoSealedInput
	Bindings     []BindingTableRow
	SecretAccess *CryptoSecretAccessIntent
	Retirement   *RecipientRetirementRow
}

type CryptoRelation uint8

const (
	CryptoEqual CryptoRelation = iota + 1
	CryptoChanged
	CryptoAdded
	CryptoRemoved
)

type CryptoComparisonRow struct {
	Name                    string
	BeforePresent           bool
	AfterPresent            bool
	Relation                CryptoRelation
	BeforePublicEntryDigest ID
	SourceDigest            ID
	AfterRawLength          uint32
	ExclusionPathDigest     ID
}

type CryptoCompareResult struct {
	OperationRef     ID
	Rows             []CryptoComparisonRow
	ComparisonDigest ID
}

type CryptoPrepareRequest struct {
	OperationRef ID
	Context      ApplyContext
	IdentityPlan []byte
}

type CryptoPreparedSecret struct {
	Name         string
	Slot         uint16
	EntryBytes   []byte
	AccessRecord []byte
}

type CryptoPrepareResult struct{ Rows []CryptoPreparedSecret }

type CryptoFreezeRequest struct {
	OperationRef                                    ID
	Context                                         ApplyContext
	IdentityPlanDescriptor, CanonicalRowsDescriptor DescriptorVector
	CandidatePublicState, Exclusions                []byte
	Recipients                                      []RecipientRecord
}

type CryptoFreezeResult struct{ FactDigest ID }

type CryptoClaimRequest struct {
	OperationRef                                           ID
	Context                                                ApplyContext
	IdentityPlanDescriptor, CandidatePublicStateDescriptor DescriptorVector
	CanonicalRowsDescriptor, ExclusionDescriptor           DescriptorVector
	FactDigest                                             ID
}

type CryptoDiscardRequest struct {
	OperationRef ID
	Context      ApplyContext
}
