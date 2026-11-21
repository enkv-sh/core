//go:build !enkv_aws && !enkv_gcp

package compositionfull

import (
	"context"
	"errors"
	"net/http"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/compositions/configuration"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
	gcpprovider "enkv.sh/providers/gcp"
	manifest "enkv.sh/sdk/manifest-generator"
)

type Config struct {
	Family contract.Family
	AWS    *compositionaws.Config
	GCP    *compositiongcp.Config
}

// ReaderConfig fixes one GET-only provider and its passive interpretation.
type ReaderConfig struct {
	checkedRoutes           *core.PublicConfigurationValidator
	SelectPolicyAction      func(context.Context, core.PublicationPolicyActionInput) (uint8, error)
	InterpretOutput         core.PublicOutputInterpreter
	Family                  contract.Family
	AWS                     *compositionaws.ReaderConfig
	GCP                     *compositiongcp.ReaderConfig
	PrepareManifestRenderer func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)
}

// PlanningConfig fixes one public Reader and its independent Authority route.
type PlanningConfig struct {
	Reader                    ReaderConfig
	AWS                       *awsprovider.KeyAccessConfig
	GCP                       *gcpprovider.KeyAccessConfig
	Sources                   contract.PlanningSources
	FileIdentity, InputDigest contract.ID
	DisplayFactory            privatecrypto.PlanningDisplayFactory
}

// ReconstructionConfig fixes constructors, not a current selection or sink.
type ReconstructionConfig struct {
	Family contract.Family
	AWS    *compositionaws.ReconstructionConfig
	GCP    *compositiongcp.ReconstructionConfig
}

func CompatibilityManifest() contract.CompatibilityManifest {
	a, g := compositionaws.CompatibilityManifest(), compositiongcp.CompatibilityManifest()
	a.Identity = contract.Hash([]byte("enkv/composition/full/v1"))
	a.Components = append(a.Components, g.Components...)
	a.Verifiers = append(a.Verifiers, g.Verifiers...)
	a.Constructions = append(a.Constructions, g.Constructions...)
	return a
}

func validConfig(c Config) bool {
	return c.Family == contract.AWS && c.AWS != nil && c.GCP == nil || c.Family == contract.GCP && c.GCP != nil && c.AWS == nil
}
func validReaderConfig(c ReaderConfig) bool {
	return c.Family == contract.AWS && c.AWS != nil && c.GCP == nil || c.Family == contract.GCP && c.GCP != nil && c.AWS == nil
}
func validReconstructionConfig(c ReconstructionConfig) bool {
	return c.Family == contract.AWS && c.AWS != nil && c.GCP == nil || c.Family == contract.GCP && c.GCP != nil && c.AWS == nil
}
func validPlanningConfig(c PlanningConfig) bool {
	return c.Reader.Family == contract.AWS && c.AWS != nil && c.GCP == nil || c.Reader.Family == contract.GCP && c.GCP != nil && c.AWS == nil
}

func loadDefaultConfig(ctx context.Context, c Config) (Config, error) {
	if c.Family == contract.AWS {
		v, err := compositionaws.LoadDefaultConfig(ctx, *c.AWS)
		if err != nil {
			return Config{}, err
		}
		c.AWS = &v
	} else {
		v, err := compositiongcp.LoadDefaultConfig(ctx, *c.GCP)
		if err != nil {
			return Config{}, err
		}
		c.GCP = &v
	}
	return c, nil
}
func newCell(ctx context.Context, c Config) (contract.Cell, error) {
	if c.Family == contract.AWS {
		return compositionaws.New(*c.AWS)
	}
	return compositiongcp.New(ctx, *c.GCP)
}
func newAuthority(ctx context.Context, c Config) (contract.Store, contract.Trust, error) {
	if c.Family == contract.AWS {
		return compositionaws.NewAuthority(*c.AWS)
	}
	return compositiongcp.NewAuthority(ctx, *c.GCP)
}
func providerReaderConfigWithValidator(c ReaderConfig, validator *core.PublicConfigurationValidator, prepare func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)) ReaderConfig {
	if c.Family == contract.AWS {
		return awsReaderConfigWithValidator(c, validator, prepare)
	}
	return gcpReaderConfigWithValidator(c, validator, prepare)
}
func newProviderReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.ReaderEngine, error) {
	if c.Family == contract.AWS {
		return newAWSReader(ctx, c, defaults)
	}
	return newGCPReader(ctx, c, defaults)
}
func newProviderReconstruction(ctx context.Context, c ReconstructionConfig, defaults bool) (*core.ReconstructionEngine, error) {
	if c.Family == contract.AWS {
		return newAWSReconstruction(ctx, c, defaults)
	}
	return newGCPReconstruction(ctx, c, defaults)
}
func newProviderPlanning(ctx context.Context, c PlanningConfig, reader ReaderConfig, defaults bool) (*core.InstalledPlanning, error) {
	if reader.Family == contract.AWS {
		return newAWSPlanning(ctx, c, reader, defaults)
	}
	return newGCPPlanning(ctx, c, reader, defaults)
}
func newProviderCapacityReader(ctx context.Context, c CapacityReaderConfig, defaults bool) (*core.InstalledCapacityReader, error) {
	if c.Family == contract.AWS {
		return newAWSCapacityReader(ctx, c, defaults)
	}
	return newGCPCapacityReader(ctx, c, defaults)
}
func newProviderMaterialization(ctx context.Context, c MaterializationConfig, defaults bool) (*core.InstalledMaterialization, error) {
	if c.Family == contract.AWS {
		return newAWSMaterialization(ctx, c, defaults)
	}
	return newGCPMaterialization(ctx, c, defaults)
}
func newProviderReceiptReader(ctx context.Context, c ReceiptReaderConfig, defaults bool) (*core.InstalledReceiptReader, error) {
	if c.Family == contract.AWS {
		return newAWSReceiptReader(ctx, c, defaults)
	}
	return newGCPReceiptReader(ctx, c, defaults)
}
func newProviderInspectionReader(ctx context.Context, c InspectionReaderConfig, defaults bool) (*core.InstalledInspectionReader, error) {
	if c.Family == contract.AWS {
		return newAWSInspectionReader(ctx, c, defaults)
	}
	return newGCPInspectionReader(ctx, c, defaults)
}
func newProviderGeneratedReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.InstalledGeneratedReader, error) {
	if c.Family == contract.AWS {
		return newAWSGeneratedReader(ctx, c, defaults)
	}
	return newGCPGeneratedReader(ctx, c, defaults)
}
func selectConfigurationReader(m *configuration.Model, basis core.PublicBasis, descriptor contract.Descriptor, route contract.ID) (ReaderConfig, error) {
	switch m.Provider {
	case contract.AWS:
		return configurationAWSReaderConfig(m, basis, descriptor, route), nil
	case contract.GCP:
		return configurationGCPReaderConfig(m, basis, descriptor, route), nil
	}
	return ReaderConfig{}, ErrCell
}
func selectConfigurationApplyConfig(m *configuration.Model, control contract.ControlCore, route contract.ID) (Config, error) {
	switch m.Provider {
	case contract.AWS:
		return configurationAWSApplyConfig(m, control, route)
	case contract.GCP:
		return configurationGCPApplyConfig(m, control, route)
	}
	return Config{}, errors.New("unsupported apply cell")
}
func selectConfigurationApplyQualifier(ctx context.Context, c Config, binding contract.KMSBinding, route contract.ID) (privatecrypto.PublicKeyQualifier, error) {
	if !validConfig(c) {
		return nil, ErrCell
	}
	if c.Family == contract.AWS {
		return configurationAWSApplyQualifier(ctx, c, binding, route)
	}
	return configurationGCPApplyQualifier(ctx, c, binding, route)
}
func selectConfigurationPlanningConfig(provider contract.Family, reader ReaderConfig, binding contract.KMSBinding, route contract.ID) (PlanningConfig, error) {
	switch provider {
	case contract.AWS:
		return configurationAWSPlanningConfig(reader, binding, route)
	case contract.GCP:
		return configurationGCPPlanningConfig(reader, binding, route)
	}
	return PlanningConfig{}, ErrCell
}
func selectPrepareReconstruction(r PrepareRecoveryRequest, domain contract.ID, kek string, route contract.ID) ReconstructionConfig {
	if r.Provider == contract.AWS {
		return prepareAWSReconstructionConfig(r, domain, kek, route)
	}
	return prepareGCPReconstructionConfig(r, domain, kek, route)
}
func selectDefaultInitializationResources(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (initializationResources, error) {
	switch m.Provider {
	case contract.AWS:
		return defaultAWSInitializationResources(ctx, m, route, transport)
	case contract.GCP:
		return defaultGCPInitializationResources(ctx, m, route, transport)
	}
	return initializationResources{}, errInitializationConfiguration
}
func selectRecipientPublicKey(ctx context.Context, provider contract.Family, selector string, route contract.ID, transport *http.Transport) ([]byte, uint8, error) {
	switch provider {
	case contract.AWS:
		return resolveAWSConfigurationRecipientPublicKey(ctx, selector, route, transport)
	case contract.GCP:
		return resolveGCPConfigurationRecipientPublicKey(ctx, selector, route, transport)
	}
	return nil, 0, ErrLocalEdit
}
func selectReplacementProviders(ctx context.Context, m *configuration.Model, route contract.ID, transport *http.Transport) (configurationReplacementProviders, error) {
	switch m.Provider {
	case contract.AWS:
		return openAWSConfigurationReplacementProviders(ctx, m, route, transport)
	case contract.GCP:
		return openGCPConfigurationReplacementProviders(ctx, m, route, transport)
	}
	return configurationReplacementProviders{}, errConfigurationReplacement
}
func openConfigurationPublicSource(ctx context.Context, m *configuration.Model, transport *http.Transport) (core.PublicSelectedReader, error) {
	if m == nil {
		return nil, errConfigurationPublicRead
	}
	switch m.Provider {
	case contract.AWS:
		return openAWSConfigurationPublicSource(ctx, m, transport)
	case contract.GCP:
		return openGCPConfigurationPublicSource(ctx, m, transport, gcpprovider.NewClient)
	}
	return nil, errConfigurationPublicRead
}
func openNativeAbandonmentResources(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport, out abandonmentResources) (abandonmentResources, error) {
	switch m.Provider {
	case contract.AWS:
		return openAWSNativeAbandonmentResources(ctx, m, s, mutation, transport, out)
	case contract.GCP:
		return openGCPNativeAbandonmentResources(ctx, m, s, mutation, transport, out, gcpprovider.NewClient)
	}
	return out, ErrAbandonmentPlan
}
func newProviderMaintenancePlanningCustody(ctx context.Context, c Config, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
	if c.Family == contract.AWS {
		return newAWSMaintenancePlanningCustody(ctx, c, admission)
	}
	return newGCPMaintenancePlanningCustody(ctx, c, admission)
}
func capacityReaderScope(c ReaderConfig) (contract.ID, contract.Descriptor) {
	if !validReaderConfig(c) {
		return contract.ID{}, contract.Descriptor{}
	}
	if c.Family == contract.AWS {
		return c.AWS.ExpectedDomain, c.AWS.ExpectedStore
	}
	return c.GCP.ExpectedDomain, c.GCP.ExpectedStore
}
func releaseConfigurationReader(c *ReaderConfig) {
	if c.AWS != nil {
		clearReconstructionBasis(&c.AWS.PublicBasis)
	}
	if c.GCP != nil {
		clearReconstructionBasis(&c.GCP.PublicBasis)
	}
	*c = ReaderConfig{}
}
