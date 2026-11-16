//go:build !enkv_gcp

package compositionfull

import (
	"context"
	"net/http"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
	manifest "enkv.sh/sdk/manifest-generator"
)

func awsReaderConfigWithValidator(c ReaderConfig, validator *core.PublicConfigurationValidator, prepare func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)) ReaderConfig {
	value := *c.AWS
	value.Validator, value.PrepareManifestRenderer, value.SelectPolicyAction = validator, prepare, c.SelectPolicyAction
	c.AWS = &value
	return c
}

func newAWSReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.ReaderEngine, error) {
	if defaults {
		return compositionaws.NewDefaultReader(ctx, *c.AWS)
	}
	return compositionaws.NewReader(*c.AWS)
}

func newAWSReconstruction(ctx context.Context, c ReconstructionConfig, defaults bool) (*core.ReconstructionEngine, error) {
	if defaults {
		return compositionaws.NewDefaultReconstruction(ctx, *c.AWS)
	}
	return compositionaws.NewReconstruction(*c.AWS)
}

func newAWSPlanning(ctx context.Context, c PlanningConfig, reader ReaderConfig, defaults bool) (*core.InstalledPlanning, error) {
	installed := compositionaws.PlanningConfig{Reader: *reader.AWS, KeyAccess: *c.AWS, Sources: c.Sources, FileIdentity: c.FileIdentity, InputDigest: c.InputDigest, DisplayFactory: c.DisplayFactory}
	if defaults {
		return compositionaws.NewDefaultPlanning(ctx, installed)
	}
	return compositionaws.NewPlanning(ctx, installed)
}

func newAWSCapacityReader(ctx context.Context, c CapacityReaderConfig, defaults bool) (*core.InstalledCapacityReader, error) {
	installed := compositionaws.CapacityReaderConfig{ReaderConfig: *c.AWS, SourcePins: c.SourcePins, CheckSource: c.CheckSource}
	if defaults {
		return compositionaws.NewDefaultCapacityReader(ctx, installed)
	}
	return compositionaws.NewCapacityReader(installed)
}

func newAWSMaterialization(ctx context.Context, c MaterializationConfig, defaults bool) (*core.InstalledMaterialization, error) {
	installed := compositionaws.MaterializationConfig{Reader: *c.AWS, SourcePins: c.SourcePins, CheckSource: c.CheckSource, Target: c.Target}
	if defaults {
		return compositionaws.NewDefaultMaterialization(ctx, installed)
	}
	return compositionaws.NewMaterialization(ctx, installed)
}

func newAWSReceiptReader(ctx context.Context, c ReceiptReaderConfig, defaults bool) (*core.InstalledReceiptReader, error) {
	installed := compositionaws.ReceiptReaderConfig{ReaderConfig: *c.AWS, CompositionID: CompatibilityManifest().Identity, SourcePins: c.SourcePins, CheckSource: c.CheckSource}
	if defaults {
		return compositionaws.NewDefaultReceiptReader(ctx, installed)
	}
	return compositionaws.NewReceiptReader(installed)
}

func newAWSInspectionReader(ctx context.Context, c InspectionReaderConfig, defaults bool) (*core.InstalledInspectionReader, error) {
	c.AWS.ResolveGeneratedImplementation = configurationGeneratedResolver(ctx, nil)
	installed := compositionaws.InspectionReaderConfig{ReaderConfig: *c.AWS, SourcePins: c.SourcePins, CheckSource: c.CheckSource}
	if defaults {
		return compositionaws.NewDefaultInspectionReader(ctx, installed)
	}
	return compositionaws.NewInspectionReader(installed)
}

func newAWSGeneratedReader(ctx context.Context, c ReaderConfig, defaults bool) (*core.InstalledGeneratedReader, error) {
	installed := *c.AWS
	installed.ResolveGeneratedImplementation = configurationGeneratedResolver(ctx, nil)
	if defaults {
		return compositionaws.NewDefaultGeneratedReader(ctx, installed)
	}
	return compositionaws.NewGeneratedReader(installed)
}

func configurationAWSReaderConfig(m *configuration.Model, basis core.PublicBasis, descriptor contract.Descriptor, route contract.ID) ReaderConfig {
	return ReaderConfig{Family: contract.AWS, AWS: &compositionaws.ReaderConfig{ExpectedDomain: m.DomainID, ExpectedStore: descriptor, PublicBasis: basis,
		Candidate: awsprovider.CandidateReadConfig{Region: m.Store.Region, Bucket: m.Store.Bucket, Prefix: m.Store.PrefixBeforeHEAD, ExpectedBucketOwner: m.Store.ExpectedOwner,
			CredentialRoute: route, Timeout: time.Minute, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}}}}
}

func configurationAWSApplyConfig(m *configuration.Model, control contract.ControlCore, route contract.ID) (Config, error) {
	signing, ok := contract.ParseAWSKeySelector(control.NormalSigning.KeySelector, true)
	if !ok {
		return Config{}, ErrCell
	}
	kek, ok := contract.ParseAWSKeySelector(control.AuthorityKMSBinding.KeySelector, false)
	if !ok {
		return Config{}, ErrCell
	}
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	return Config{Family: contract.AWS, AWS: &compositionaws.Config{StoreClass: awsprovider.StoreClass, TrustClass: awsprovider.TrustClass, VerifierClass: awsprovider.VerifierClass,
		Store:     awsprovider.StoreConfig{Region: m.Store.Region, Bucket: m.Store.Bucket, ExpectedBucketOwner: m.Store.ExpectedOwner, Prefix: m.Store.PrefixBeforeHEAD, Domain: m.DomainID, CredentialRoute: route, Transport: transport, Timeout: time.Minute},
		Trust:     awsprovider.TrustConfig{Role: contract.NormalSigningRole, Region: signing.Region, KeyARN: control.NormalSigning.KeySelector, PublicKeyDER: control.NormalSigning.SPKI, CredentialRoute: route, Transport: transport, Timeout: time.Minute},
		KeyAccess: []awsprovider.KeyAccessConfig{{Region: kek.Region, Account: kek.Account, CredentialRoute: route, Transport: transport, Timeout: time.Minute}}}}, nil
}

func configurationAWSApplyQualifier(_ context.Context, config Config, binding contract.KMSBinding, route contract.ID) (enkvcrypto.PublicKeyQualifier, error) {
	key, ok := contract.ParseAWSKeySelector(binding.KeySelector, false)
	if !ok {
		return nil, ErrCell
	}
	return awsprovider.NewPublicEncryptionQualifier(awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: route,
		Credentials: config.AWS.Store.Credentials, Transport: config.AWS.Store.Transport, Timeout: time.Minute}, binding)
}

func configurationAWSPlanningConfig(reader ReaderConfig, binding contract.KMSBinding, route contract.ID) (PlanningConfig, error) {
	key, ok := contract.ParseAWSKeySelector(binding.KeySelector, false)
	if !ok {
		return PlanningConfig{}, ErrCell
	}
	return PlanningConfig{Reader: reader, AWS: &awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: route, Timeout: time.Minute,
		Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}}}, nil
}

func prepareAWSReconstructionConfig(r PrepareRecoveryRequest, domain contract.ID, kek string, route contract.ID) ReconstructionConfig {
	owner := ""
	if r.ExpectedOwner != nil {
		owner = *r.ExpectedOwner
	}
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	c := &compositionaws.ReconstructionConfig{Candidate: awsprovider.CandidateReadConfig{Region: r.Region, Bucket: r.Bucket, Prefix: *r.Prefix, ExpectedBucketOwner: owner, CredentialRoute: route, Transport: transport, Timeout: time.Minute}, KeyAccess: compositionaws.ReconstructionKeyAccessConfig{CredentialRoute: route, Transport: transport, Timeout: time.Minute}, ExpectedDomain: domain, ExpectedKEK: kek}
	for i, key := range []*string{r.NormalSigningKey, r.RecoverySigningKey} {
		if key != nil {
			parsed, _ := contract.ParseAWSKeySelector(*key, true)
			anchor := &awsprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: parsed.Region, KeyARN: *key, CredentialRoute: route, Transport: transport, Timeout: time.Minute}
			if i == 0 {
				c.Normal = anchor
			} else {
				anchor.Role = contract.RecoverySigningRole
				c.Recovery = anchor
			}
		}
	}
	return ReconstructionConfig{Family: contract.AWS, AWS: c}
}

func newAWSMaintenancePlanningCustody(ctx context.Context, config Config, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
	if len(config.AWS.KeyAccess) != 1 {
		return nil, ErrCell
	}
	installed := config.AWS.KeyAccess[0]
	installed.CredentialRoute = admission.CredentialRoute
	return compositionaws.NewMaintenancePlanningCustody(ctx, installed, admission)
}
