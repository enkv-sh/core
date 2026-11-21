//go:build enkv_aws && !enkv_gcp

package compositionfull

import (
	"context"
	"net/http"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
	manifest "enkv.sh/sdk/manifest-generator"
)

type Config struct {
	Family contract.Family
	AWS    *compositionaws.Config
}
type ReaderConfig struct {
	checkedRoutes           *core.PublicConfigurationValidator
	SelectPolicyAction      func(context.Context, core.PublicationPolicyActionInput) (uint8, error)
	InterpretOutput         core.PublicOutputInterpreter
	Family                  contract.Family
	AWS                     *compositionaws.ReaderConfig
	PrepareManifestRenderer func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)
}
type PlanningConfig struct {
	Reader                    ReaderConfig
	AWS                       *awsprovider.KeyAccessConfig
	Sources                   contract.PlanningSources
	FileIdentity, InputDigest contract.ID
	DisplayFactory            privatecrypto.PlanningDisplayFactory
}
type ReconstructionConfig struct {
	Family contract.Family
	AWS    *compositionaws.ReconstructionConfig
}

func CompatibilityManifest() contract.CompatibilityManifest {
	return compositionaws.CompatibilityManifest()
}
func validConfig(c Config) bool             { return c.Family == contract.AWS && c.AWS != nil }
func validReaderConfig(c ReaderConfig) bool { return c.Family == contract.AWS && c.AWS != nil }
func validReconstructionConfig(c ReconstructionConfig) bool {
	return c.Family == contract.AWS && c.AWS != nil
}
func validPlanningConfig(c PlanningConfig) bool {
	return c.Reader.Family == contract.AWS && c.AWS != nil
}

func loadDefaultConfig(ctx context.Context, c Config) (Config, error) {
	v, err := compositionaws.LoadDefaultConfig(ctx, *c.AWS)
	if err != nil {
		return Config{}, err
	}
	c.AWS = &v
	return c, nil
}
func newCell(_ context.Context, c Config) (contract.Cell, error) { return compositionaws.New(*c.AWS) }
func newAuthority(_ context.Context, c Config) (contract.Store, contract.Trust, error) {
	return compositionaws.NewAuthority(*c.AWS)
}
func providerReaderConfigWithValidator(c ReaderConfig, validator *core.PublicConfigurationValidator, prepare func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)) ReaderConfig {
	return awsReaderConfigWithValidator(c, validator, prepare)
}
func newProviderReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.ReaderEngine, error) {
	return newAWSReader(ctx, c, defaults)
}
func newProviderReconstruction(ctx context.Context, c ReconstructionConfig, defaults bool) (*core.ReconstructionEngine, error) {
	return newAWSReconstruction(ctx, c, defaults)
}
func newProviderPlanning(ctx context.Context, c PlanningConfig, reader ReaderConfig, defaults bool) (*core.InstalledPlanning, error) {
	return newAWSPlanning(ctx, c, reader, defaults)
}
func newProviderCapacityReader(ctx context.Context, c CapacityReaderConfig, defaults bool) (*core.InstalledCapacityReader, error) {
	return newAWSCapacityReader(ctx, c, defaults)
}
func newProviderMaterialization(ctx context.Context, c MaterializationConfig, defaults bool) (*core.InstalledMaterialization, error) {
	return newAWSMaterialization(ctx, c, defaults)
}
func newProviderReceiptReader(ctx context.Context, c ReceiptReaderConfig, defaults bool) (*core.InstalledReceiptReader, error) {
	return newAWSReceiptReader(ctx, c, defaults)
}
func newProviderInspectionReader(ctx context.Context, c InspectionReaderConfig, defaults bool) (*core.InstalledInspectionReader, error) {
	return newAWSInspectionReader(ctx, c, defaults)
}
func newProviderGeneratedReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.InstalledGeneratedReader, error) {
	return newAWSGeneratedReader(ctx, c, defaults)
}
func selectConfigurationReader(m *configuration.Model, basis core.PublicBasis, descriptor contract.Descriptor, route contract.ID) (ReaderConfig, error) {
	if m.Provider != contract.AWS {
		return ReaderConfig{}, ErrCell
	}
	return configurationAWSReaderConfig(m, basis, descriptor, route), nil
}
func selectConfigurationApplyConfig(m *configuration.Model, control contract.ControlCore, route contract.ID) (Config, error) {
	if m.Provider != contract.AWS {
		return Config{}, ErrCell
	}
	return configurationAWSApplyConfig(m, control, route)
}
func selectConfigurationApplyQualifier(ctx context.Context, c Config, binding contract.KMSBinding, route contract.ID) (privatecrypto.PublicKeyQualifier, error) {
	if !validConfig(c) {
		return nil, ErrCell
	}
	return configurationAWSApplyQualifier(ctx, c, binding, route)
}
func selectConfigurationPlanningConfig(provider contract.Family, reader ReaderConfig, binding contract.KMSBinding, route contract.ID) (PlanningConfig, error) {
	if provider != contract.AWS {
		return PlanningConfig{}, ErrCell
	}
	return configurationAWSPlanningConfig(reader, binding, route)
}
func selectPrepareReconstruction(r PrepareRecoveryRequest, domain contract.ID, kek string, route contract.ID) ReconstructionConfig {
	if r.Provider != contract.AWS {
		return ReconstructionConfig{}
	}
	return prepareAWSReconstructionConfig(r, domain, kek, route)
}
func selectDefaultInitializationResources(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (initializationResources, error) {
	if m.Provider != contract.AWS {
		return initializationResources{}, errInitializationConfiguration
	}
	return defaultAWSInitializationResources(ctx, m, route, transport)
}
func selectRecipientPublicKey(ctx context.Context, provider contract.Family, selector string, route contract.ID, transport *http.Transport) ([]byte, uint8, error) {
	if provider != contract.AWS {
		return nil, 0, ErrLocalEdit
	}
	return resolveAWSConfigurationRecipientPublicKey(ctx, selector, route, transport)
}
func selectReplacementProviders(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (configurationReplacementProviders, error) {
	if m.Provider != contract.AWS {
		return configurationReplacementProviders{}, errConfigurationReplacement
	}
	return openAWSConfigurationReplacementProviders(ctx, m, route, transport)
}
func openConfigurationPublicSource(ctx context.Context, m *configuration.Model, transport *http.Transport) (core.PublicSelectedReader, error) {
	if m == nil || m.Provider != contract.AWS {
		return nil, errConfigurationPublicRead
	}
	return openAWSConfigurationPublicSource(ctx, m, transport)
}
func openNativeAbandonmentResources(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport, out abandonmentResources) (abandonmentResources, error) {
	if m.Provider != contract.AWS {
		return out, ErrAbandonmentPlan
	}
	return openAWSNativeAbandonmentResources(ctx, m, s, mutation, transport, out)
}
func newProviderMaintenancePlanningCustody(ctx context.Context, c Config, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
	return newAWSMaintenancePlanningCustody(ctx, c, admission)
}
func capacityReaderScope(c ReaderConfig) (contract.ID, contract.Descriptor) {
	if !validReaderConfig(c) {
		return contract.ID{}, contract.Descriptor{}
	}
	return c.AWS.ExpectedDomain, c.AWS.ExpectedStore
}
func releaseConfigurationReader(c *ReaderConfig) {
	if c.AWS != nil {
		clearReconstructionBasis(&c.AWS.PublicBasis)
	}
	*c = ReaderConfig{}
}
