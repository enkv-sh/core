package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
)

// GeneratedApplyInstallation fixes the only producers and custody constructors
// available to the installed coordinator. Public requests carry no callbacks.
type GeneratedApplyInstallation struct {
	ResolveImplementation func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error)
	// CheckCreateReadiness checks exact intent through the selected current build before a new CREATE is admitted.
	CheckCreateReadiness         func(context.Context, string, contract.GeneratorImplementation, []byte) error
	CheckRetirementCompatibility func(context.Context, contract.GeneratorImplementation, []byte, contract.GeneratorSafeFacts, uint8) ([]byte, []byte, error)
	RequestDigest                func(context.Context, contract.GeneratorImplementation, uint8, []byte, *contract.GeneratorTarget) (contract.ID, error)
	AdmitReservation             func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedReservationInput, time.Time) (*InstalledGeneratedCustody, error)
	AdmitProducer                func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error)
	AdmitAdoption                func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedAdoptionInput, time.Time) (*InstalledGeneratedCustody, error)
	AdmitFinal                   func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error)
	AdmitVerification            func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedVerificationInput, time.Time) (*InstalledGeneratedCustody, error)
}

type GeneratedImplementationRequest struct {
	EntryName                            string
	ConfigContractID, ResourceContractID contract.ID
	LifecycleMode                        contract.GeneratorLifecycleMode
	Retained                             *GeneratedImplementationIdentity
}
type GeneratedImplementationIdentity struct {
	DescriptorID, ExecutorID, CredentialRouteID, ResultContractID contract.ID
	Action, CompletionClass, InputEncoding                        uint8
	MaxSecret, MaxFacts                                           uint32
}
type InstalledGeneratedCustody struct {
	Crypto        contract.Crypto
	BindCandidate func(context.Context, contract.GeneratedCandidateInput) contract.CryptoResultCode
	Close         func()
}
type InstalledGeneratedProducerCustody struct {
	InstalledGeneratedCustody
	InvokeProducer     func(context.Context, contract.ID, contract.ID) contract.GeneratedProducerResult
	LocalFailureReason func() uint8
	AdmitLocalFailure  func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedLocalFailureInput, time.Time) (*InstalledGeneratedCustody, error)
}

func validInstalledGeneratedCustody(c *InstalledGeneratedCustody) bool {
	return c != nil && c.Crypto != nil && !c.Crypto.InstanceID().IsZero() && c.BindCandidate != nil && c.Close != nil
}

// These closures retain only the original receiver's private failure state and
// the installation's ordinary custody constructor. They outlive producer Close.
type installedGeneratedLocalFailure struct {
	attempt contract.ID
	reason  func() uint8
	admit   func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedLocalFailureInput, time.Time) (*InstalledGeneratedCustody, error)
}
