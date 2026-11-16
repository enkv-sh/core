package custody

import (
	"context"
	"maps"
	"path/filepath"
	"time"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
)

type publicationOutput struct {
	config           outputhost.Config
	configContractID string
}

// PublicationConfig carries passive expectations for one exact installed output.
type PublicationConfig struct {
	ArtifactPath string
	Artifact     outputhost.Artifact
	Metadata     []byte
	Dependency   []byte
}

// Validate checks passive expectations without opening an executable or credential.
func (config PublicationConfig) Validate(configContractID string) error {
	_, err := config.installation(configContractID)
	return err
}

func (config PublicationConfig) installation(configContractID string) (*outputhost.Installation, error) {
	if !filepath.IsAbs(config.ArtifactPath) || len(config.Metadata) == 0 || len(config.Metadata) > artifact.MaxMetadataBytes || len(config.Dependency) == 0 || len(config.Dependency) > artifact.MaxDependencyBytes {
		return nil, outputhost.ErrAdmission
	}
	if _, err := contract.OutputConfigContractDigest(configContractID); err != nil {
		return nil, outputhost.ErrAdmission
	}
	metadata, err := artifact.DecodeMetadata(config.Metadata)
	if err != nil {
		return nil, err
	}
	installed, err := outputhost.NewInstallation(metadata, config.Dependency)
	if err != nil {
		return nil, err
	}
	if installed.Artifact() != config.Artifact {
		return nil, outputhost.ErrAdmission
	}
	return installed, nil
}

// InstallPublication selects an exact installation for one destination and config contract.
// Its descriptor declares the credential route; installation does not read it.
func (f *Fixture) InstallPublication(ctx context.Context, config PublicationConfig, destinationID, configContractID string) error {
	if f == nil || destinationID == "" {
		return outputhost.ErrAdmission
	}
	installed, err := config.installation(configContractID)
	if err != nil {
		return err
	}
	private := outputhost.Config{ArtifactPath: config.ArtifactPath, Installation: installed}
	_, err = outputhost.NewPublicValidator(ctx, private.ArtifactPath, private.Installation)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runtime == nil {
		return privatecrypto.ErrAdmission
	}
	if _, exists := f.publicationOutputs[destinationID]; exists {
		return outputhost.ErrAdmission
	}
	if f.publicationOutputs == nil {
		f.publicationOutputs = make(map[string]publicationOutput)
	}
	f.publicationOutputs[destinationID] = publicationOutput{config: private, configContractID: configContractID}
	return nil
}

func (f *Fixture) publicationOutput(destinationID, configContractID string) (publicationOutput, error) {
	if f == nil {
		return publicationOutput{}, outputhost.ErrAdmission
	}
	if _, err := contract.OutputConfigContractDigest(configContractID); err != nil {
		return publicationOutput{}, outputhost.ErrAdmission
	}
	f.mu.Lock()
	row, ok := f.publicationOutputs[destinationID]
	f.mu.Unlock()
	if !ok || row.config.Installation == nil || row.configContractID != configContractID {
		return publicationOutput{}, outputhost.ErrAdmission
	}
	return row, nil
}

// PublicationArtifact returns measured support for the explicitly selected
// installation. Action capabilities and bounds belong to the admitted target.
func (f *Fixture) PublicationArtifact(ctx context.Context, destinationID, configContractID string) (outputhost.Artifact, error) {
	if ctx == nil || ctx.Err() != nil {
		return outputhost.Artifact{}, privatecrypto.ErrAdmission
	}
	row, err := f.publicationOutput(destinationID, configContractID)
	if err != nil {
		return outputhost.Artifact{}, err
	}
	return row.config.Installation.Artifact(), nil
}

// CheckPublication checks the selected public target through its installed
// passive child. Qualified ownership comes only from the selected birth.
func (f *Fixture) CheckPublication(ctx context.Context, destinationID, configContractID string, domain contract.ID, action uint8, target contract.OutputTarget, coordinate contract.PublicationCoordinate, birth, uncertainCreate *contract.PublicationMarker, exclusiveNamespaceDigest contract.ID, payloadLength uint32, deadline time.Time) (protocol.ActionCheckResult, outputhost.Artifact, error) {
	row, err := f.publicationOutput(destinationID, configContractID)
	if err != nil {
		return protocol.ActionCheckResult{}, outputhost.Artifact{}, err
	}
	result, err := privatecrypto.CheckPublicationAction(ctx, row.config.ArtifactPath, row.config.Installation, privatecrypto.PublicationActionCheckInput{DestinationID: destinationID, ConfigContractID: configContractID, DomainID: domain, Action: action, Target: target, Coordinate: coordinate, Birth: birth, UncertainCreate: uncertainCreate, ExclusiveNamespaceDigest: exclusiveNamespaceDigest, PayloadLength: payloadLength, Deadline: deadline})
	return result, row.config.Installation.Artifact(), err
}

// SelectPublicationPolicyAction uses the exact installed passive executable.
func (f *Fixture) SelectPublicationPolicyAction(ctx context.Context, destinationID, configContractID string, domain contract.ID, target contract.OutputTarget, present bool, previous contract.ID, deadline time.Time) (uint8, error) {
	row, err := f.publicationOutput(destinationID, configContractID)
	if err != nil {
		return 0, err
	}
	action, err := privatecrypto.SelectPublicationPolicyAction(ctx, row.config.ArtifactPath, row.config.Installation, privatecrypto.PublicationPolicyActionInput{
		DomainID: domain, Target: target, HasPreviousPolicyDigest: present, PreviousPolicyDigest: previous, Deadline: deadline})
	return uint8(action), err
}

// PublicationOwner selects a fixture key route; custody and native mechanics
// are the production installation used by public publication.
type PublicationOwner struct {
	owner  *privatecrypto.PublicationCustody
	routes map[contract.ID]contract.ID
}

func (f *Fixture) NewPublicationOwner(ctx context.Context, projection contract.PublicationProjection, destinationID, configContractID string, target contract.OutputTarget, coordinate contract.PublicationCoordinate, birth, uncertainCreate *contract.PublicationMarker, protocolID, descriptorID, configContractDigest, artifactID, executorID, credentialRouteID contract.ID, credentialRouteContractID string, minimum, maximum uint32, deadline time.Time) (*PublicationOwner, error) {
	row, err := f.publicationOutput(destinationID, configContractID)
	if err != nil {
		return nil, err
	}
	a := row.config.Installation.Artifact()
	configDigest, err := contract.OutputConfigContractDigest(configContractID)
	if err != nil || configContractDigest != configDigest || protocolID != contract.ID(a.ProtocolID) || descriptorID != contract.ID(a.DescriptorID) || artifactID != contract.ID(a.ArtifactContractID) || executorID != contract.ID(a.ExecutorID) || credentialRouteID != contract.ID(a.CredentialRouteID) || credentialRouteContractID != a.CredentialRouteContractID {
		return nil, outputhost.ErrAdmission
	}
	native, err := outputhost.NewNative(ctx, row.config)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	runtime, routes := f.runtime, maps.Clone(f.routes)
	f.mu.Unlock()
	owner, err := privatecrypto.NewPublicationCustody(ctx, runtime, privatecrypto.PublicationCustodyInput{Projection: projection, DestinationID: destinationID, ConfigContractID: configContractID, Target: target, Coordinate: coordinate, Birth: birth, UncertainCreate: uncertainCreate, Native: native, Minimum: minimum, Maximum: maximum, Deadline: deadline})
	if err != nil {
		return nil, err
	}
	return &PublicationOwner{owner: owner, routes: routes}, nil
}

func (o *PublicationOwner) InstanceID() contract.ID {
	if o == nil || o.owner == nil {
		return contract.ID{}
	}
	return o.owner.InstanceID()
}

func (o *PublicationOwner) Prepare(ctx context.Context, id contract.ID, selected *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	if o == nil || o.owner == nil {
		return nil, contract.CryptoInvalidAdmission
	}
	var route contract.ID
	if selected != nil && selected.Entry.ConfidentialityClass == contract.Secret {
		route = o.routes[selected.Binding.Binding.BindingID]
	}
	return o.owner.Prepare(ctx, id, selected, route)
}

func (o *PublicationOwner) Arm(ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	if o == nil || o.owner == nil {
		return privatecrypto.ErrAdmission
	}
	return o.owner.Arm(ctx, id, dispatch)
}

func (o *PublicationOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	if o == nil || o.owner == nil {
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	return o.owner.Send(ctx, id)
}

func (o *PublicationOwner) Retire(ctx context.Context) error {
	if o == nil || o.owner == nil {
		return nil
	}
	return o.owner.Retire(ctx)
}
