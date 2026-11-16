package generatorhost

import (
	"bytes"
	"errors"
	"runtime"
	"runtime/debug"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
)

// Installation owns exact measured build facts authenticated by its caller.
type Installation struct {
	artifact     contract.GeneratorImplementation
	facts        artifact.BuildFacts
	dependencyID contract.ID
}

// Artifact returns owned build facts, including a copied credential route.
// A nil installation returns the zero value.
func (i *Installation) Artifact() contract.GeneratorImplementation {
	if i == nil {
		return contract.GeneratorImplementation{}
	}
	v := i.artifact
	v.CredentialRoute = bytes.Clone(v.CredentialRoute)
	return v
}

// NewInstallation copies and checks measured generator metadata and exact
// dependency bytes. The caller must authenticate their source; this constructor
// neither verifies an executable file nor authorizes execution.
func NewInstallation(metadata artifact.Metadata, dependency []byte) (*Installation, error) {
	body, err := artifact.EncodeMetadata(metadata)
	if err != nil {
		return nil, errors.Join(ErrAdmission, err)
	}
	owned, err := artifact.DecodeMetadata(body)
	if err != nil || owned.Role != "generator" || owned.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	facts, err := owned.GeneratorFacts()
	if err != nil || facts.Descriptor.Generator == nil || facts.Descriptor.Wire.Version != uint32(protocol.Version) || facts.Descriptor.Wire.Identity != artifact.Digest(protocol.ProtocolID()).String() {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	canonical, err := artifact.EncodeDependency(owned.BuildFacts())
	if err != nil || !bytes.Equal(canonical, dependency) || owned.Family.Dependency.SHA256 != artifact.Hash(dependency) || owned.Family.Dependency.Length != uint64(len(dependency)) {
		return nil, errors.Join(ErrAdmission, ErrArtifactIdentity, err)
	}
	id, err := artifact.DependencyID("generator", dependency)
	if err != nil || facts.DependencyManifestID != id {
		return nil, errors.Join(ErrAdmission, ErrArtifactIdentity, err)
	}
	route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
	if err != nil {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	row := contract.GeneratorImplementation{
		Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind,
		DescriptorID: contract.ID(facts.DescriptorID), ProtocolID: contract.ID(protocol.ProtocolID()),
		ExecutorID: contract.ID(facts.ExecutorID), ArtifactContractID: contract.ID(facts.ArtifactContractID),
		DependencyManifestID: contract.ID(facts.DependencyManifestID), ArtifactSHA256: contract.ID(facts.ArtifactSHA256),
		ConfigContractID: contract.ID(facts.Descriptor.Generator.ConfigContractID), CredentialRouteID: contract.ID(routeID),
		CredentialRoute: bytes.Clone(facts.Descriptor.Generator.CredentialRoute), ArtifactLength: facts.ArtifactLength,
		Module: facts.Module, Command: facts.Command, Version: facts.Descriptor.Version, GoVersion: facts.GoVersion, NativeTuple: facts.NativeTuple,
	}
	if err := row.Validate(); err != nil {
		return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	return &Installation{artifact: row, facts: owned.BuildFacts(), dependencyID: row.DependencyManifestID}, nil
}

// NewRetainedInstallation admits the same exact family construction. Core must
// independently match the complete original accepted executor and route tuple.
func NewRetainedInstallation(metadata artifact.Metadata, dependency []byte) (*Installation, error) {
	return NewInstallation(metadata, dependency)
}

// ValidateInstallation checks the same family and dependency relations as
// NewInstallation without retaining the resulting owner.
func ValidateInstallation(metadata artifact.Metadata, dependency []byte) error {
	_, err := NewInstallation(metadata, dependency)
	return err
}

// CredentialRoute decodes a fresh public route. It reads no environment and
// returns ErrAdmission for a nil or invalid installation.
func (i *Installation) CredentialRoute() (credentialroute.Route, error) {
	if i == nil || i.artifact.Validate() != nil {
		return credentialroute.Route{}, ErrAdmission
	}
	return credentialroute.Decode(i.artifact.CredentialRoute)
}

func implementationEqual(a, b contract.GeneratorImplementation) bool {
	ar, br := a.CredentialRoute, b.CredentialRoute
	return a.Schema == b.Schema && a.Kind == b.Kind && a.DescriptorID == b.DescriptorID && a.ProtocolID == b.ProtocolID &&
		a.ExecutorID == b.ExecutorID && a.ArtifactContractID == b.ArtifactContractID && a.DependencyManifestID == b.DependencyManifestID &&
		a.ArtifactSHA256 == b.ArtifactSHA256 && a.ConfigContractID == b.ConfigContractID && a.CredentialRouteID == b.CredentialRouteID &&
		a.ArtifactLength == b.ArtifactLength && a.Module == b.Module && a.Command == b.Command && a.Version == b.Version &&
		a.GoVersion == b.GoVersion && a.NativeTuple == b.NativeTuple && bytes.Equal(ar, br)
}
func (i *Installation) validRuntime(row contract.GeneratorImplementation) bool {
	return i != nil && row.Validate() == nil && implementationEqual(row, i.artifact)
}
func (i *Installation) verifyBuildInfo(info *debug.BuildInfo) error {
	if i == nil || i.artifact.DependencyManifestID != i.dependencyID {
		return ErrArtifactIncompatible
	}
	return artifact.VerifyBuildInfo(info, i.facts)
}
