package compositiongcp

import (
	"context"
	"encoding/hex"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	provider "enkv.sh/providers/gcp"
)

// MaterializationConfig fixes public read trust, captured sources and one native
// target. Reader.Candidate.CredentialRoute must be a nonzero contract.ID encoded
// as 64 lowercase hexadecimal characters. The selected Recipient alone supplies
// the private key's project, region and version after public admission.
type MaterializationConfig struct {
	Reader      ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
	Target      *privatecrypto.MaterializationFileTarget
}

// NewMaterialization installs public GET admission and an exact Recipient factory.
func NewMaterialization(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
	basis, routeID, err := materializationFixedConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	i, err := newReaderInstallation(ctx, c.Reader)
	if err != nil {
		return nil, err
	}
	custodyConfig := c
	custodyConfig.Reader.PublicBasis = core.PublicBasis{}
	return core.NewInstalledMaterialization(core.MaterializationInstallation{
		Reader: i, SourcePins: c.SourcePins, CheckSource: c.CheckSource,
		CredentialRoute: routeID, Target: c.Target.Target(),
		AdmitCustody: func(ctx context.Context, admission contract.MaterializationAdmission) (core.MaterializationCustody, error) {
			return newMaterializationCustody(ctx, custodyConfig, basis, routeID, admission)
		},
	})
}

// NewDefaultMaterialization selects ADC after validating the fixed public inputs.
// It constructs no private route.
func NewDefaultMaterialization(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
	if _, _, err := materializationFixedConfig(ctx, c); err != nil {
		return nil, err
	}
	client, err := defaultClient(ctx)
	if err != nil {
		return nil, err
	}
	c.Reader.Candidate.Client = client
	return NewMaterialization(ctx, c)
}

func materializationFixedConfig(ctx context.Context, c MaterializationConfig) (contract.ID, contract.ID, error) {
	if ctx == nil || ctx.Err() != nil || c.CheckSource == nil || !c.SourcePins.Valid() || !c.SourcePins.HasGenerated ||
		c.Target == nil || !c.Target.Target().Valid() || c.Target.Identity() != c.Target.Target().SurfaceID {
		return contract.ID{}, contract.ID{}, ErrClass
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return contract.ID{}, contract.ID{}, ErrClass
	}
	var route contract.ID
	if len(c.Reader.Candidate.CredentialRoute) != hex.EncodedLen(len(route)) {
		return contract.ID{}, contract.ID{}, ErrClass
	}
	decoded, err := hex.DecodeString(c.Reader.Candidate.CredentialRoute)
	if err != nil || len(decoded) != len(route) || hex.EncodeToString(decoded) != c.Reader.Candidate.CredentialRoute {
		return contract.ID{}, contract.ID{}, ErrClass
	}
	copy(route[:], decoded)
	if route.IsZero() {
		return contract.ID{}, contract.ID{}, ErrClass
	}
	basis, err := core.AdministrativePublicBasisDigest(c.Reader.ExpectedDomain, c.Reader.ExpectedStore, c.Reader.PublicBasis)
	return basis, route, err
}

func materializationSourcePins(p core.AdministrativeSourcePins) contract.MaterializationSourcePins {
	return contract.MaterializationSourcePins(p)
}

func newMaterializationCustody(ctx context.Context, c MaterializationConfig, basis, routeID contract.ID, admission contract.MaterializationAdmission) (core.MaterializationCustody, error) {
	invalid := contract.MaterializationAdmissionError{Code: contract.CryptoInvalidAdmission}
	if ctx == nil || c.Target == nil || admission.Purpose != contract.MaterializationOperation || admission.DomainID != c.Reader.ExpectedDomain ||
		admission.Store != c.Reader.ExpectedStore || admission.PublicBasisDigest != basis || basis.IsZero() ||
		admission.SourcePins != materializationSourcePins(c.SourcePins) || !admission.SourcePins.Valid() ||
		admission.CredentialRoute != routeID || routeID.IsZero() || admission.Target != c.Target.Target() || c.Target.Identity() != admission.Target.SurfaceID ||
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
	if err != nil || binding.Provider != contract.GCP {
		return nil, invalid
	}
	var decryptor privatecrypto.KeyDecryptor
	for _, entry := range admission.Entries {
		if entry.Entry.ConfidentialityClass != contract.Secret {
			continue
		}
		key, ok := contract.ParseGCPKeySelector(binding.KeySelector, false)
		if !ok {
			return nil, invalid
		}
		route, err := provider.NewKeyAccess(ctx, provider.KeyAccessConfig{Client: c.Reader.Candidate.Client, Project: key.Project, Region: key.Region,
			Endpoint: "https://" + key.Region + "-cloudkms.googleapis.com/", CredentialRoute: routeID})
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
