package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
)

type publicationExecutionInput struct {
	DestinationID, ConfigContractID string
	Target                          contract.OutputTarget
	DeleteCoordinate                contract.ID
}

type publicationActionFacts struct {
	ProtocolID, DescriptorID, ConfigContractDigest, ArtifactContractID contract.ID
	ExecutorID, CredentialRouteID                                      contract.ID
	CredentialRouteContractID                                          string
}

type publicationActionCheckInput struct {
	DestinationID, ConfigContractID string
	DomainID                        contract.ID
	Action                          uint8
	Target                          contract.OutputTarget
	Coordinate                      contract.PublicationCoordinate
	Birth                           *contract.PublicationMarker
	UncertainCreate                 *contract.PublicationMarker
	ExclusiveNamespaceDigest        contract.ID
	PayloadLength                   uint32
	Deadline                        time.Time
}

type publicationActionCheckFacts struct {
	MinimumPayload, MaximumPayload                                     uint32
	ProtocolID, DescriptorID, ConfigContractDigest, ArtifactContractID contract.ID
	ExecutorID, CredentialRouteID                                      contract.ID
	CredentialRouteContractID                                          string
}

type publicationOwnerInput struct {
	Projection                      contract.PublicationProjection
	DestinationID, ConfigContractID string
	Target                          contract.OutputTarget
	Coordinate                      contract.PublicationCoordinate
	Birth                           *contract.PublicationMarker
	UncertainCreate                 *contract.PublicationMarker
	ActionCheck                     publicationActionCheckFacts
	Deadline                        time.Time
}

// Each action owns one private lifetime. Prepare borrows the selected public
// representation only until return; Send returns the full correlated result.
// Retire cancels and joins owned work even when its caller context has expired.
type publicationPrivateOwner interface {
	InstanceID() contract.ID
	Prepare(context.Context, contract.ID, *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode)
	Arm(context.Context, contract.ID, contract.PublicationDispatch) error
	Send(context.Context, contract.ID) (contract.PublicationResult, contract.CryptoResultCode)
	Retire(context.Context) error
}

// A retirement error can retain this positive local failure fact without
// qualifying a provider result or granting any execution right.
type publicationExecutableCleanupFailure interface {
	ExecutableCleanupFailed() bool
}

type publicationPrivate struct {
	SelectPolicyAction publicationPolicyActionSelector
	Actions            func(context.Context, publicationExecutionInput) (publicationActionFacts, error)
	Check              func(context.Context, publicationActionCheckInput) (publicationActionCheckFacts, error)
	NewOwner           func(context.Context, publicationOwnerInput) (publicationPrivateOwner, error)
}

func publicationPrepareKeyUsesValid(selection *contract.ConsumerSelection, code contract.CryptoResultCode, rows []contract.KeyUseRow) bool {
	if !code.Valid() {
		return false
	}
	if _, err := contract.KeyUseRowsLength(rows); err != nil {
		return false
	}
	if selection == nil || selection.Entry.ConfidentialityClass != contract.Secret {
		return len(rows) == 0
	}
	if len(rows) == 0 {
		return code != contract.CryptoSuccess
	}
	if len(rows) != 1 {
		return false
	}
	binding, row := selection.Binding, rows[0]
	digest, err := contract.PublicBindingDigest(binding.Binding)
	return err == nil && row.BindingID == binding.Binding.BindingID && row.PublicBindingDigest == digest &&
		row.SubjectKind == binding.SubjectKind && row.SubjectID == binding.SubjectID && row.Provider == binding.Binding.Provider &&
		row.Purpose == contract.KeyUseMaterialOpen && row.Count == 1 && (code != contract.CryptoSuccess || row.Outcome == contract.KeyUseCompleted)
}
