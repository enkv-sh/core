package compositionfull

import (
	"context"
	"encoding/binary"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
)

func configurationOutputArtifact(plugins *configurationInstalledPlugins, name string) (string, *outputhost.Installation, error) {
	if !artifact.ValidPluginID(name) {
		return "", nil, outputhost.ErrAdmission
	}
	selected, ok := plugins.lookup(name)
	if !ok {
		return "", nil, outputhost.ErrArtifactMissing
	}
	metadata, err := selected.Metadata()
	if err != nil {
		return "", nil, err
	}
	installed, err := outputhost.NewInstallation(metadata, selected.DependencyBytes())
	if err != nil {
		return "", nil, err
	}
	return selected.Executable(), installed, nil
}
func configurationOutputCapturedNative(ctx context.Context, path string, installed *outputhost.Installation) (*outputhost.Native, outputhost.Artifact, error) {
	if ctx == nil || installed == nil {
		return nil, outputhost.Artifact{}, outputhost.ErrAdmission
	}
	if err := ctx.Err(); err != nil {
		return nil, outputhost.Artifact{}, err
	}
	native, err := outputhost.NewNative(ctx, outputhost.Config{ArtifactPath: path, Installation: installed})
	if err != nil {
		return nil, outputhost.Artifact{}, err
	}
	return native, installed.Artifact(), nil
}
func configurationOutputPremise(domain contract.ID, target contract.OutputTarget) (contract.ID, error) {
	if _, err := contract.PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget); err != nil {
		return contract.ID{}, err
	}
	body := append([]byte("ENKV/OUTPUT/MANAGED-NAME-EXCLUSIVE-USE/v2\x00"), domain[:]...)
	for _, value := range []string{target.ServiceContractID, target.CanonicalTarget} {
		body = binary.BigEndian.AppendUint32(body, uint32(len(value)))
		body = append(body, value...)
	}
	return contract.Hash(body), nil
}
