package compositiongcp

import (
	"context"

	core "enkv.sh/core"
	"enkv.sh/core/contract"
	gcpprovider "enkv.sh/providers/gcp"
	manifest "enkv.sh/sdk/manifest-generator"
)

// ReaderConfig fixes independent Store access, public trust and passive interpretation.
// It contains no private-key or effect route.
type ReaderConfig struct {
	SelectPolicyAction             func(context.Context, core.PublicationPolicyActionInput) (uint8, error)
	Candidate                      gcpprovider.CandidateReadConfig
	ExpectedDomain                 contract.ID
	ExpectedStore                  contract.Descriptor
	PublicBasis                    core.PublicBasis
	Validator                      *core.PublicConfigurationValidator
	PrepareManifestRenderer        func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)
	ResolveGeneratedImplementation func(core.GeneratedImplementationRequest) (contract.GeneratorImplementation, error)
}

// NewReader installs keyed GET readers and local public verification only.
func NewReader(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
	i, err := newReaderInstallation(ctx, c)
	if err != nil {
		return nil, err
	}
	return core.NewInstalledReader(i)
}

func newReaderInstallation(ctx context.Context, c ReaderConfig) (core.ReaderInstallation, error) {
	if ctx == nil || ctx.Err() != nil {
		return core.ReaderInstallation{}, ErrClass
	}
	candidate, err := gcpprovider.NewCandidateReader(ctx, c.Candidate)
	if err != nil {
		return core.ReaderInstallation{}, err
	}
	candidateConfig := c.Candidate
	prepare := c.PrepareManifestRenderer
	if prepare == nil {
		prepare = func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
			return nil, manifest.InvalidInput
		}
	}
	return core.ReaderInstallation{
		Candidate: candidate, ExpectedDomain: c.ExpectedDomain, ExpectedStore: c.ExpectedStore,
		PublicBasis: c.PublicBasis, Validator: c.Validator, PrepareManifestRenderer: prepare, SelectPolicyAction: c.SelectPolicyAction,
		Construct: func(ctx context.Context, selected contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
			return newPublicSelectedStore(ctx, candidateConfig, selected)
		},
		CloseInstalled: func() {},
	}, nil
}
