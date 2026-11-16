package compositionaws

import (
	"bytes"
	"context"
	"errors"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	provider "enkv.sh/providers/aws"
)

// PlanningConfig fixes public read construction and one Authority decrypt route.
// Captured source and input identities cannot be changed by Plan arguments.
type PlanningConfig struct {
	Reader                    ReaderConfig
	KeyAccess                 provider.KeyAccessConfig
	Sources                   contract.PlanningSources
	FileIdentity, InputDigest contract.ID
	DisplayFactory            privatecrypto.PlanningDisplayFactory
}

// NewPlanning installs GET readers and a separately admitted decrypt-only owner.
func NewPlanning(ctx context.Context, c PlanningConfig) (*core.InstalledPlanning, error) {
	if !planningContextValid(ctx) || !planningFixedConfigValid(c) {
		return nil, ErrClass
	}
	if c.Reader.Candidate.Transport != nil {
		c.Reader.Candidate.Transport = snapshotReconstructionTransport(c.Reader.Candidate.Transport)
	}
	if c.KeyAccess.Transport == nil || c.KeyAccess.Credentials == nil || c.KeyAccess.Timeout <= 0 {
		return nil, ErrClass
	}
	c.KeyAccess.Transport = snapshotReconstructionTransport(c.KeyAccess.Transport)
	candidate, err := provider.NewCandidateReader(c.Reader.Candidate)
	if err != nil {
		return nil, err
	}
	candidateConfig, keyAccess, displayFactory := c.Reader.Candidate, c.KeyAccess, c.DisplayFactory
	return core.NewInstalledPlanning(core.PlanningInstallation{
		Reader: core.ReaderInstallation{
			Candidate: candidate, ExpectedDomain: c.Reader.ExpectedDomain, ExpectedStore: c.Reader.ExpectedStore,
			PublicBasis: c.Reader.PublicBasis, Validator: c.Reader.Validator, SelectPolicyAction: c.Reader.SelectPolicyAction,
			Construct: func(ctx context.Context, selected contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
				return newPublicSelectedStore(ctx, candidateConfig, selected)
			},
			CloseInstalled: func() {},
		},
		Sources: c.Sources, FileIdentity: c.FileIdentity, InputDigest: c.InputDigest, CredentialRoute: c.KeyAccess.CredentialRoute,
		AdmitCustody: func(ctx context.Context, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
			return newPlanningCustody(ctx, keyAccess, admission, displayFactory)
		},
	})
}

// NewDefaultPlanning selects standard credentials for GET and Authority decrypt.
func NewDefaultPlanning(ctx context.Context, c PlanningConfig) (*core.InstalledPlanning, error) {
	if !planningContextValid(ctx) || !planningFixedConfigValid(c) {
		return nil, ErrClass
	}
	credentials, err := provider.LoadDefaultCredentials(ctx, c.Reader.Candidate.Region)
	if err != nil {
		return nil, err
	}
	c.Reader.Candidate.Credentials, c.KeyAccess.Credentials = credentials, credentials
	return NewPlanning(ctx, c)
}

func planningFixedConfigValid(c PlanningConfig) bool {
	if c.KeyAccess.CredentialRoute.IsZero() || c.Reader.Validator == nil || !c.Sources.Trusted.Valid() || !c.Sources.Proposed.Valid() ||
		c.FileIdentity.IsZero() || c.FileIdentity != c.Sources.Proposed.FileIdentity || c.InputDigest.IsZero() {
		return false
	}
	control, err := c.Reader.PublicBasis.ControlCore(c.Reader.ExpectedDomain, c.Reader.ExpectedStore)
	return err == nil && planningBindingMatches(c.KeyAccess, control.AuthorityKMSBinding)
}

func planningContextValid(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, finite := ctx.Deadline()
	return finite && time.Now().Before(deadline)
}

func planningBindingMatches(c provider.KeyAccessConfig, b contract.KMSBinding) bool {
	if b.Provider != contract.AWS {
		return false
	}
	if _, err := contract.KMSBindingLength(b); err != nil {
		return false
	}
	key, ok := contract.ParseAWSKeySelector(b.KeySelector, false)
	return ok && key.Region == c.Region && key.Account == c.Account && b.ProtectionClass == contract.HardwareProtection
}

func newPlanningCustody(ctx context.Context, installed provider.KeyAccessConfig, admission contract.PlanningAdmission, factory privatecrypto.PlanningDisplayFactory) (core.PlanningCustody, error) {
	row := admission.Authority
	if !planningContextValid(ctx) || admission.CredentialRoute != installed.CredentialRoute ||
		row.SubjectKind != contract.OrdinaryWrapSubject || row.SubjectID != admission.Control.AuthorityRecipientID ||
		!planningBindingMatches(installed, row.Binding) {
		return nil, contract.PlanningAdmissionError{Code: contract.CryptoInvalidAdmission}
	}
	actual, err := contract.EncodeKMSBinding(row.Binding)
	if err != nil {
		return nil, contract.PlanningAdmissionError{Code: contract.CryptoInvalidAdmission}
	}
	expected, err := contract.EncodeKMSBinding(admission.Control.AuthorityKMSBinding)
	if err != nil || !bytes.Equal(actual, expected) {
		return nil, contract.PlanningAdmissionError{Code: contract.CryptoInvalidAdmission}
	}
	route, err := provider.NewKeyAccess(installed)
	if err != nil {
		return nil, contract.PlanningAdmissionError{Code: contract.CryptoCustodyUnavailable}
	}
	custody, err := privatecrypto.NewPlanningCustody(ctx, &bindingDecryptor{route: route, binding: actual}, admission)
	if err != nil {
		code := contract.CryptoCustodyUnavailable
		if errors.Is(err, privatecrypto.ErrAdmission) {
			code = contract.CryptoInvalidAdmission
		}
		return nil, contract.PlanningAdmissionError{Code: code}
	}
	return &planningDisplayCustody{PlanningCustody: custody, factory: factory}, nil
}

type bindingDecryptor struct {
	route   *provider.KeyAccess
	binding []byte
}

func (d *bindingDecryptor) Family() contract.Family      { return contract.AWS }
func (d *bindingDecryptor) CredentialRoute() contract.ID { return d.route.CredentialRoute() }
func (d *bindingDecryptor) Decrypt(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, packetLength uint16) privatecrypto.PrivateResult {
	encoded, err := contract.EncodeKMSBinding(binding)
	if err != nil || !bytes.Equal(encoded, d.binding) {
		return privatecrypto.PrivateResult{Status: privatecrypto.KeyInvalid}
	}
	return d.route.Decrypt(ctx, binding, ciphertext, packetLength)
}

type planningDisplayCustody struct {
	*privatecrypto.PlanningCustody
	factory privatecrypto.PlanningDisplayFactory
}

func (c *planningDisplayCustody) Display(ctx context.Context) contract.PlanningDisplayResult {
	return c.PlanningCustody.Display(ctx, c.factory)
}
