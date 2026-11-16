//go:build !enkv_aws

package compositionfull

import (
	"context"
	"encoding/hex"

	"enkv.sh/compositions/configuration"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	gcpprovider "enkv.sh/providers/gcp"
	manifest "enkv.sh/sdk/manifest-generator"
)

func gcpReaderConfigWithValidator(c ReaderConfig, validator *core.PublicConfigurationValidator, prepare func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)) ReaderConfig {
	value := *c.GCP
	value.Validator, value.PrepareManifestRenderer, value.SelectPolicyAction = validator, prepare, c.SelectPolicyAction
	c.GCP = &value
	return c
}

func newGCPReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.ReaderEngine, error) {
	if defaults {
		return compositiongcp.NewDefaultReader(ctx, *c.GCP)
	}
	return compositiongcp.NewReader(ctx, *c.GCP)
}

func newGCPReconstruction(ctx context.Context, c ReconstructionConfig, defaults bool) (*core.ReconstructionEngine, error) {
	if defaults {
		return compositiongcp.NewDefaultReconstruction(ctx, *c.GCP)
	}
	return compositiongcp.NewReconstruction(ctx, *c.GCP)
}

func newGCPPlanning(ctx context.Context, c PlanningConfig, reader ReaderConfig, defaults bool) (*core.InstalledPlanning, error) {
	installed := compositiongcp.PlanningConfig{Reader: *reader.GCP, KeyAccess: *c.GCP, Sources: c.Sources, FileIdentity: c.FileIdentity, InputDigest: c.InputDigest, DisplayFactory: c.DisplayFactory}
	if defaults {
		return compositiongcp.NewDefaultPlanning(ctx, installed)
	}
	return compositiongcp.NewPlanning(ctx, installed)
}

func newGCPCapacityReader(ctx context.Context, c CapacityReaderConfig, defaults bool) (*core.InstalledCapacityReader, error) {
	installed := compositiongcp.CapacityReaderConfig{ReaderConfig: *c.GCP, SourcePins: c.SourcePins, CheckSource: c.CheckSource}
	if defaults {
		return compositiongcp.NewDefaultCapacityReader(ctx, installed)
	}
	return compositiongcp.NewCapacityReader(ctx, installed)
}

func newGCPMaterialization(ctx context.Context, c MaterializationConfig, defaults bool) (*core.InstalledMaterialization, error) {
	installed := compositiongcp.MaterializationConfig{Reader: *c.GCP, SourcePins: c.SourcePins, CheckSource: c.CheckSource, Target: c.Target}
	if defaults {
		return compositiongcp.NewDefaultMaterialization(ctx, installed)
	}
	return compositiongcp.NewMaterialization(ctx, installed)
}

func newGCPReceiptReader(ctx context.Context, c ReceiptReaderConfig, defaults bool) (*core.InstalledReceiptReader, error) {
	installed := compositiongcp.ReceiptReaderConfig{ReaderConfig: *c.GCP, CompositionID: CompatibilityManifest().Identity, SourcePins: c.SourcePins, CheckSource: c.CheckSource}
	if defaults {
		return compositiongcp.NewDefaultReceiptReader(ctx, installed)
	}
	return compositiongcp.NewReceiptReader(ctx, installed)
}

func newGCPInspectionReader(ctx context.Context, c InspectionReaderConfig, defaults bool) (*core.InstalledInspectionReader, error) {
	c.GCP.ResolveGeneratedImplementation = configurationGeneratedResolver(ctx, nil)
	installed := compositiongcp.InspectionReaderConfig{ReaderConfig: *c.GCP, SourcePins: c.SourcePins, CheckSource: c.CheckSource}
	if defaults {
		return compositiongcp.NewDefaultInspectionReader(ctx, installed)
	}
	return compositiongcp.NewInspectionReader(ctx, installed)
}

func newGCPGeneratedReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.InstalledGeneratedReader, error) {
	installed := *c.GCP
	installed.ResolveGeneratedImplementation = configurationGeneratedResolver(ctx, nil)
	if defaults {
		return compositiongcp.NewDefaultGeneratedReader(ctx, installed)
	}
	return compositiongcp.NewGeneratedReader(ctx, installed)
}

func configurationGCPReaderConfig(m *configuration.Model, basis core.PublicBasis, descriptor contract.Descriptor, route contract.ID) ReaderConfig {
	return ReaderConfig{Family: contract.GCP, GCP: &compositiongcp.ReaderConfig{ExpectedDomain: m.DomainID, ExpectedStore: descriptor, PublicBasis: basis,
		Candidate: gcpprovider.CandidateReadConfig{Region: m.Store.Region, Bucket: m.Store.Bucket, Prefix: m.Store.PrefixBeforeHEAD, CredentialRoute: hex.EncodeToString(route[:])}}}
}

func configurationGCPApplyConfig(m *configuration.Model, control contract.ControlCore, route contract.ID) (Config, error) {
	signing, ok := contract.ParseGCPKeySelector(control.NormalSigning.KeySelector, true)
	if !ok {
		return Config{}, ErrCell
	}
	kek, ok := contract.ParseGCPKeySelector(control.AuthorityKMSBinding.KeySelector, false)
	if !ok {
		return Config{}, ErrCell
	}
	text := hex.EncodeToString(route[:])
	return Config{Family: contract.GCP, GCP: &compositiongcp.Config{StoreClass: gcpprovider.StoreClass, TrustClass: gcpprovider.TrustClass, VerifierClass: gcpprovider.VerifierClass,
		Store:     gcpprovider.StoreConfig{Domain: m.DomainID, Region: m.Store.Region, Endpoint: gcpprovider.StorageEndpoint(m.Store.Region), Bucket: m.Store.Bucket, Prefix: m.Store.PrefixBeforeHEAD, CredentialRoute: text},
		Trust:     gcpprovider.TrustConfig{Role: contract.NormalSigningRole, Region: signing.Region, Endpoint: gcpprovider.KMSEndpoint(signing.Region), CredentialRoute: text, KeyVersion: control.NormalSigning.KeySelector, Algorithm: gcpprovider.SigningAlgorithm, Purpose: gcpprovider.SigningPurpose, PublicKey: control.NormalSigning.SPKI},
		KeyAccess: []gcpprovider.KeyAccessConfig{{Project: kek.Project, Region: kek.Region, Endpoint: gcpprovider.KMSEndpoint(kek.Region), CredentialRoute: route}}}}, nil
}

func configurationGCPApplyQualifier(ctx context.Context, config Config, binding contract.KMSBinding, route contract.ID) (enkvcrypto.PublicKeyQualifier, error) {
	key, ok := contract.ParseGCPKeySelector(binding.KeySelector, false)
	if !ok {
		return nil, ErrCell
	}
	return gcpprovider.NewPublicEncryptionQualifier(ctx, gcpprovider.KeyAccessConfig{Client: config.GCP.Store.Client, Project: key.Project, Region: key.Region,
		Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: route}, binding)
}

func configurationGCPPlanningConfig(reader ReaderConfig, binding contract.KMSBinding, route contract.ID) (PlanningConfig, error) {
	key, ok := contract.ParseGCPKeySelector(binding.KeySelector, false)
	if !ok {
		return PlanningConfig{}, ErrCell
	}
	return PlanningConfig{Reader: reader, GCP: &gcpprovider.KeyAccessConfig{Project: key.Project, Region: key.Region, Endpoint: gcpprovider.KMSEndpoint(key.Region), CredentialRoute: route}}, nil
}

func prepareGCPReconstructionConfig(r PrepareRecoveryRequest, domain contract.ID, kek string, route contract.ID) ReconstructionConfig {
	c := &compositiongcp.ReconstructionConfig{Candidate: gcpprovider.CandidateReadConfig{Region: r.Region, Bucket: r.Bucket, Prefix: *r.Prefix, CredentialRoute: hex.EncodeToString(route[:])}, KeyAccess: compositiongcp.ReconstructionKeyAccessConfig{CredentialRoute: route}, ExpectedDomain: domain, ExpectedKEK: kek}
	for i, key := range []*string{r.NormalSigningKey, r.RecoverySigningKey} {
		if key != nil {
			parsed, _ := contract.ParseGCPKeySelector(*key, true)
			anchor := &gcpprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: parsed.Region, KeyVersion: *key, CredentialRoute: hex.EncodeToString(route[:])}
			if i == 0 {
				c.Normal = anchor
			} else {
				anchor.Role = contract.RecoverySigningRole
				c.Recovery = anchor
			}
		}
	}
	return ReconstructionConfig{Family: contract.GCP, GCP: c}
}

func newGCPMaintenancePlanningCustody(ctx context.Context, config Config, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
	if len(config.GCP.KeyAccess) != 1 {
		return nil, ErrCell
	}
	installed := config.GCP.KeyAccess[0]
	installed.CredentialRoute = admission.CredentialRoute
	return compositiongcp.NewMaintenancePlanningCustody(ctx, installed, admission)
}
