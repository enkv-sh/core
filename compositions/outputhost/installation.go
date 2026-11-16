package outputhost

import (
	"bytes"
	"errors"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
)

// Installation owns exact output metadata already authenticated by its caller.
type Installation struct {
	artifact Artifact
	manifest DependencyManifest
	metadata []byte
}

// NewInstallation copies and checks output family metadata and exact
// dependency bytes. The caller authenticates their source; executable bytes
// are checked separately before launch. No credential is read here.
func NewInstallation(metadata artifact.Metadata, dependency []byte) (*Installation, error) {
	body, err := artifact.EncodeMetadata(metadata)
	if err != nil || metadata.Role != "output" {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	owned, err := artifact.DecodeMetadata(body)
	if err != nil {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	facts, err := owned.OutputFacts()
	if err != nil || facts.Descriptor.Wire.Version != uint32(protocol.Version) || facts.Descriptor.Wire.Identity != artifact.Digest(protocol.ProtocolID()).String() {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	canonical, err := artifact.EncodeDependency(owned.BuildFacts())
	if err != nil || !bytes.Equal(canonical, dependency) || owned.Family.Dependency.Length != uint64(len(dependency)) || owned.Family.Dependency.SHA256 != artifact.Hash(dependency) {
		return nil, errors.Join(ErrAdmission, ErrArtifactIdentity, err)
	}
	identity, err := artifact.DependencyID("output", dependency)
	if err != nil || facts.DependencyManifestID != identity {
		return nil, errors.Join(ErrAdmission, ErrArtifactIdentity, err)
	}
	manifest, err := DecodeDependencyManifest(dependency)
	if err != nil {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	a, err := artifactFromFacts(facts)
	if err != nil || !a.valid() {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	return &Installation{artifact: a, manifest: manifest, metadata: body}, nil
}

// ValidateInstallation checks the same family and dependency relations as
// NewInstallation without retaining the resulting owner.
func ValidateInstallation(metadata artifact.Metadata, dependency []byte) error {
	_, err := NewInstallation(metadata, dependency)
	return err
}

// Artifact returns scalar build facts by value, or zero for a nil installation.
func (i *Installation) Artifact() Artifact {
	if i == nil {
		return Artifact{}
	}
	return i.artifact
}

// CredentialRoute returns a freshly decoded public route without reading
// credentials. A nil or invalid installation returns ErrAdmission.
func (i *Installation) CredentialRoute() (credentialroute.Route, error) {
	if !i.valid() {
		return credentialroute.Route{}, ErrAdmission
	}
	metadata, err := artifact.DecodeMetadata(i.metadata)
	if err != nil {
		return credentialroute.Route{}, errors.Join(ErrAdmission, err)
	}
	descriptor, err := metadata.Descriptor()
	if err != nil {
		return credentialroute.Route{}, errors.Join(ErrAdmission, err)
	}
	return credentialroute.Decode(descriptor.Output.CredentialRoute)
}
func (i *Installation) valid() bool {
	return i != nil && i.artifact.valid() && i.manifest.Facts != nil && i.manifest.Facts.Role == "output" && len(i.metadata) != 0
}
func artifactFromFacts(f artifact.OutputFacts) (Artifact, error) {
	if f.Descriptor.Output == nil {
		return Artifact{}, ErrAdmission
	}
	route, err := credentialroute.Decode(f.Descriptor.Output.CredentialRoute)
	if err != nil {
		return Artifact{}, err
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Schema: f.Schema, ProtocolID: protocol.ProtocolID(), DescriptorID: protocol.ID(f.DescriptorID),
		ArtifactContractID: protocol.ID(f.ArtifactContractID), ExecutorID: protocol.ID(f.ExecutorID), CredentialRouteID: protocol.ID(routeID),
		DependencyManifestID: protocol.ID(f.DependencyManifestID), SHA256: protocol.ID(f.ArtifactSHA256), Length: f.ArtifactLength,
		ConfigContractID: f.Descriptor.Output.ConfigContractID, CredentialRouteContractID: artifact.Digest(route.ContractID).String(),
		ModulePath: f.Module, CommandPath: f.Command, GoVersion: f.GoVersion, NativeTuple: f.NativeTuple}, nil
}
