package compositionaws

import (
	"context"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	provider "enkv.sh/providers/aws"
)

// MaterializationConfig fixes public read trust, captured sources and one native
// target. Candidate credentials serve only GET and the selected Recipient's
// decrypt route; pending source bindings do not select that route.
type MaterializationConfig struct {
	Reader      ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
	Target      *privatecrypto.MaterializationFileTarget
}

// NewMaterialization installs public GET admission and an exact Recipient factory.
func NewMaterialization(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
	basis, err := materializationFixedConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	if c.Reader.Candidate.Transport != nil {
		c.Reader.Candidate.Transport = snapshotReconstructionTransport(c.Reader.Candidate.Transport)
	}
	i, err := newReaderInstallation(c.Reader)
	if err != nil {
		return nil, err
	}
	custodyConfig := c
	custodyConfig.Reader.PublicBasis = core.PublicBasis{}
	return core.NewInstalledMaterialization(core.MaterializationInstallation{
		Reader: i, SourcePins: c.SourcePins, CheckSource: c.CheckSource,
		CredentialRoute: c.Reader.Candidate.CredentialRoute, Target: c.Target.Target(),
		AdmitCustody: func(ctx context.Context, admission contract.MaterializationAdmission) (core.MaterializationCustody, error) {
			return newMaterializationCustody(ctx, custodyConfig, basis, admission)
		},
	})
}

// NewDefaultMaterialization selects the standard AWS credential source after
// validating the fixed public inputs. It constructs no private route.
func NewDefaultMaterialization(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
	if _, err := materializationFixedConfig(ctx, c); err != nil {
		return nil, err
	}
	credentials, err := provider.LoadDefaultCredentials(ctx, c.Reader.Candidate.Region)
	if err != nil {
		return nil, err
	}
	c.Reader.Candidate.Credentials = credentials
	return NewMaterialization(ctx, c)
}

func materializationFixedConfig(ctx context.Context, c MaterializationConfig) (contract.ID, error) {
	if ctx == nil || ctx.Err() != nil || c.CheckSource == nil || !c.SourcePins.Valid() || !c.SourcePins.HasGenerated ||
		c.Reader.Candidate.CredentialRoute.IsZero() || c.Target == nil || !c.Target.Target().Valid() || c.Target.Identity() != c.Target.Target().SurfaceID {
		return contract.ID{}, ErrClass
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return contract.ID{}, ErrClass
	}
	return core.AdministrativePublicBasisDigest(c.Reader.ExpectedDomain, c.Reader.ExpectedStore, c.Reader.PublicBasis)
}

func materializationSourcePins(p core.AdministrativeSourcePins) contract.MaterializationSourcePins {
	return contract.MaterializationSourcePins(p)
}

func newMaterializationCustody(ctx context.Context, c MaterializationConfig, basis contract.ID, admission contract.MaterializationAdmission) (core.MaterializationCustody, error) {
	invalid := contract.MaterializationAdmissionError{Code: contract.CryptoInvalidAdmission}
	if ctx == nil || c.Target == nil || admission.Purpose != contract.MaterializationOperation || admission.DomainID != c.Reader.ExpectedDomain ||
		admission.Store != c.Reader.ExpectedStore || admission.PublicBasisDigest != basis || basis.IsZero() ||
		admission.SourcePins != materializationSourcePins(c.SourcePins) || !admission.SourcePins.Valid() ||
		admission.CredentialRoute != c.Reader.Candidate.CredentialRoute || admission.CredentialRoute.IsZero() ||
		admission.Target != c.Target.Target() || c.Target.Identity() != admission.Target.SurfaceID ||
		admission.Recipient.SubjectKind != contract.OrdinaryWrapSubject || admission.Recipient.SubjectID.IsZero() || len(admission.Entries) == 0 {
		return nil, invalid
	}
	deadline, finite := ctx.Deadline()
	if !finite || deadline != admission.ExpiresAt {
		return nil, invalid
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		code := contract.CryptoExpired
		if ctx.Err() == context.Canceled {
			code = contract.CryptoCancelled
		}
		return nil, contract.MaterializationAdmissionError{Code: code}
	}
	binding := admission.Recipient.Binding
	encoded, err := contract.EncodeKMSBinding(binding)
	if err != nil || binding.Provider != contract.AWS || binding.ProtectionClass != contract.HardwareProtection {
		return nil, invalid
	}
	var decryptor privatecrypto.KeyDecryptor
	for _, entry := range admission.Entries {
		if entry.Entry.ConfidentialityClass != contract.Secret {
			continue
		}
		key, ok := contract.ParseAWSKeySelector(binding.KeySelector, false)
		if !ok {
			return nil, invalid
		}
		route, err := provider.NewKeyAccess(provider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: admission.CredentialRoute,
			Credentials: c.Reader.Candidate.Credentials, Transport: c.Reader.Candidate.Transport, Timeout: c.Reader.Candidate.Timeout})
		if err != nil {
			return nil, contract.MaterializationAdmissionError{Code: contract.CryptoCustodyUnavailable}
		}
		decryptor = &bindingDecryptor{route: route, binding: encoded}
		break
	}
	custody, err := privatecrypto.NewMaterializationCustody(ctx, decryptor, admission, c.Target)
	if err != nil {
		return nil, err
	}
	return custody, nil
}
