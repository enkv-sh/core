//go:build enkv_gcp && !enkv_aws

package compositionfull

import (
	"context"
	"net/http"

	"enkv.sh/compositions/configuration"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	gcpprovider "enkv.sh/providers/gcp"
	manifest "enkv.sh/sdk/manifest-generator"
)

type Config struct {
	Family contract.Family
	GCP    *compositiongcp.Config
}
type ReaderConfig struct {
	SelectPolicyAction      func(context.Context, core.PublicationPolicyActionInput) (uint8, error)
	InterpretOutput         core.PublicOutputInterpreter
	Family                  contract.Family
	GCP                     *compositiongcp.ReaderConfig
	PrepareManifestRenderer func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)
}
type PlanningConfig struct {
	Reader                    ReaderConfig
	GCP                       *gcpprovider.KeyAccessConfig
	Sources                   contract.PlanningSources
	FileIdentity, InputDigest contract.ID
	DisplayFactory            privatecrypto.PlanningDisplayFactory
}
type ReconstructionConfig struct {
	Family contract.Family
	GCP    *compositiongcp.ReconstructionConfig
}

func CompatibilityManifest() contract.CompatibilityManifest {
	return compositiongcp.CompatibilityManifest()
}
func validConfig(c Config) bool             { return c.Family == contract.GCP && c.GCP != nil }
func validReaderConfig(c ReaderConfig) bool { return c.Family == contract.GCP && c.GCP != nil }
func validReconstructionConfig(c ReconstructionConfig) bool {
	return c.Family == contract.GCP && c.GCP != nil
}
func validPlanningConfig(c PlanningConfig) bool {
	return c.Reader.Family == contract.GCP && c.GCP != nil
}

func loadDefaultConfig(ctx context.Context, c Config) (Config, error) {
	v, err := compositiongcp.LoadDefaultConfig(ctx, *c.GCP)
	if err != nil {
		return Config{}, err
	}
	c.GCP = &v
	return c, nil
}
func newCell(ctx context.Context, c Config) (contract.Cell, error) {
	return compositiongcp.New(ctx, *c.GCP)
}
func newAuthority(ctx context.Context, c Config) (contract.Store, contract.Trust, error) {
	return compositiongcp.NewAuthority(ctx, *c.GCP)
}
func providerReaderConfigWithValidator(c ReaderConfig, validator *core.PublicConfigurationValidator, prepare func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)) ReaderConfig {
	return gcpReaderConfigWithValidator(c, validator, prepare)
}
func newProviderReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.ReaderEngine, error) {
	return newGCPReader(ctx, c, defaults)
}
func newProviderReconstruction(ctx context.Context, c ReconstructionConfig, defaults bool) (*core.ReconstructionEngine, error) {
	return newGCPReconstruction(ctx, c, defaults)
}
func newProviderPlanning(ctx context.Context, c PlanningConfig, reader ReaderConfig, defaults bool) (*core.InstalledPlanning, error) {
	return newGCPPlanning(ctx, c, reader, defaults)
}
func newProviderCapacityReader(ctx context.Context, c CapacityReaderConfig, defaults bool) (*core.InstalledCapacityReader, error) {
	return newGCPCapacityReader(ctx, c, defaults)
}
func newProviderMaterialization(ctx context.Context, c MaterializationConfig, defaults bool) (*core.InstalledMaterialization, error) {
	return newGCPMaterialization(ctx, c, defaults)
}
func newProviderReceiptReader(ctx context.Context, c ReceiptReaderConfig, defaults bool) (*core.InstalledReceiptReader, error) {
	return newGCPReceiptReader(ctx, c, defaults)
}
func newProviderInspectionReader(ctx context.Context, c InspectionReaderConfig, defaults bool) (*core.InstalledInspectionReader, error) {
	return newGCPInspectionReader(ctx, c, defaults)
}
func newProviderGeneratedReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.InstalledGeneratedReader, error) {
	return newGCPGeneratedReader(ctx, c, defaults)
}
func selectConfigurationReader(m *configuration.Model, basis core.PublicBasis, descriptor contract.Descriptor, route contract.ID) (ReaderConfig, error) {
	if m.Provider != contract.GCP {
		return ReaderConfig{}, ErrCell
	}
	return configurationGCPReaderConfig(m, basis, descriptor, route), nil
}
func selectConfigurationApplyConfig(m *configuration.Model, control contract.ControlCore, route contract.ID) (Config, error) {
	if m.Provider != contract.GCP {
		return Config{}, ErrCell
	}
	return configurationGCPApplyConfig(m, control, route)
}
func selectConfigurationApplyQualifier(ctx context.Context, c Config, binding contract.KMSBinding, route contract.ID) (privatecrypto.PublicKeyQualifier, error) {
	if !validConfig(c) {
		return nil, ErrCell
	}
	return configurationGCPApplyQualifier(ctx, c, binding, route)
}
func selectConfigurationPlanningConfig(provider contract.Family, reader ReaderConfig, binding contract.KMSBinding, route contract.ID) (PlanningConfig, error) {
	if provider != contract.GCP {
		return PlanningConfig{}, ErrCell
	}
	return configurationGCPPlanningConfig(reader, binding, route)
}
func selectPrepareReconstruction(r PrepareRecoveryRequest, domain contract.ID, kek string, route contract.ID) ReconstructionConfig {
	if r.Provider != contract.GCP {
		return ReconstructionConfig{}
	}
	return prepareGCPReconstructionConfig(r, domain, kek, route)
}
func selectDefaultInitializationResources(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (initializationResources, error) {
	if m.Provider != contract.GCP {
		return initializationResources{}, errInitializationConfiguration
	}
	return defaultGCPInitializationResources(ctx, m, route, transport)
}
func selectRecipientPublicKey(ctx context.Context, provider contract.Family, selector string, route contract.ID, transport *http.Transport) ([]byte, uint8, error) {
	if provider != contract.GCP {
		return nil, 0, ErrLocalEdit
	}
	return resolveGCPConfigurationRecipientPublicKey(ctx, selector, route, transport)
}
func selectReplacementProviders(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (configurationReplacementProviders, error) {
	if m.Provider != contract.GCP {
		return configurationReplacementProviders{}, errConfigurationReplacement
	}
	return openGCPConfigurationReplacementProviders(ctx, m, route, transport)
}
func openConfigurationPublicSource(ctx context.Context, m *configuration.Model, transport *http.Transport) (core.PublicSelectedReader, error) {
	if m == nil || m.Provider != contract.GCP {
		return nil, errConfigurationPublicRead
	}
	return openGCPConfigurationPublicSource(ctx, m, transport, gcpprovider.NewClient)
}
func openNativeAbandonmentResources(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport, out abandonmentResources) (abandonmentResources, error) {
	if m.Provider != contract.GCP {
		return out, ErrAbandonmentPlan
	}
	return openGCPNativeAbandonmentResources(ctx, m, s, mutation, transport, out, gcpprovider.NewClient)
}
func newProviderMaintenancePlanningCustody(ctx context.Context, c Config, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
	return newGCPMaintenancePlanningCustody(ctx, c, admission)
}
func capacityReaderScope(c ReaderConfig) (contract.ID, contract.Descriptor) {
	if !validReaderConfig(c) {
		return contract.ID{}, contract.Descriptor{}
	}
	return c.GCP.ExpectedDomain, c.GCP.ExpectedStore
}
func releaseConfigurationReader(c *ReaderConfig) {
	if c.GCP != nil {
		clearReconstructionBasis(&c.GCP.PublicBasis)
	}
	*c = ReaderConfig{}
}
