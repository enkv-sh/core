package compositionaws

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	core "enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// ReconstructionKeyAccessConfig supplies only the private credential route
// and local transport limits. Scope comes from authenticated AuthorityBinding.
type ReconstructionKeyAccessConfig struct {
	CredentialRoute contract.ID
	Credentials     aws.CredentialsProvider
	Transport       *http.Transport
	Timeout         time.Duration
}

// ReconstructionConfig fixes the public location, signing resources and private
// credentials before a candidate is read. ExpectedDomain and ExpectedKEK are
// optional independent pins.
type ReconstructionConfig struct {
	Candidate      awsprovider.CandidateReadConfig
	Normal         *awsprovider.PublicSigningAnchorConfig
	Recovery       *awsprovider.PublicSigningAnchorConfig
	KeyAccess      ReconstructionKeyAccessConfig
	ExpectedDomain contract.ID
	ExpectedKEK    string
}

type publicSelectedStore struct{ store *awsprovider.Store }

func (r *publicSelectedStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if r == nil || r.store == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.store.Read(ctx, key, limit)
}
func (r *publicSelectedStore) Descriptor() contract.Descriptor {
	if r == nil || r.store == nil {
		return contract.Descriptor{}
	}
	return r.store.Descriptor()
}
func (r *publicSelectedStore) StoreConfiguration() contract.StoreConfiguration {
	if r == nil || r.store == nil {
		return contract.StoreConfiguration{}
	}
	return r.store.StoreConfiguration()
}
func (r *publicSelectedStore) Close() {
	if r != nil {
		r.store = nil
	}
}

func newPublicSelectedStore(ctx context.Context, candidate awsprovider.CandidateReadConfig, selected contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
	if ctx == nil || ctx.Err() != nil {
		return nil, core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
	}
	store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: selected.Region, Bucket: selected.Bucket,
		ExpectedBucketOwner: selected.ExpectedOwner, Prefix: selected.PrefixBeforeHEAD,
		Domain: selected.DomainID, CredentialRoute: candidate.CredentialRoute,
		Credentials: candidate.Credentials, Transport: candidate.Transport, Timeout: candidate.Timeout})
	if err != nil {
		return nil, core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
	}
	return &publicSelectedStore{store: store}, core.Result{}
}

// NewReconstruction installs the final-only Core engine. The constructed
// selected Store has only GET reach through the reader adapter; Core checks
// its exact descriptor and rereads the same HEAD before selected child reads.
func NewReconstruction(c ReconstructionConfig) (*core.ReconstructionEngine, error) {
	if c.KeyAccess.CredentialRoute.IsZero() || c.KeyAccess.Credentials == nil || c.KeyAccess.Transport == nil || c.KeyAccess.Timeout <= 0 {
		return nil, ErrClass
	}
	if c.Normal == nil && c.Recovery == nil ||
		c.Normal != nil && c.Normal.Role != contract.NormalSigningRole ||
		c.Recovery != nil && c.Recovery.Role != contract.RecoverySigningRole {
		return nil, ErrClass
	}
	// Keep the Store's future transport construction independent of later
	// mutation of the caller's transport pointer.
	if c.Candidate.Transport != nil {
		c.Candidate.Transport = snapshotReconstructionTransport(c.Candidate.Transport)
	}
	c.KeyAccess.Transport = snapshotReconstructionTransport(c.KeyAccess.Transport)
	candidate, err := awsprovider.NewCandidateReader(c.Candidate)
	if err != nil {
		return nil, err
	}
	var normal, recovery core.ReconstructionSigningAnchor
	if c.Normal != nil {
		anchor, err := awsprovider.NewPublicSigningAnchor(*c.Normal)
		if err != nil {
			return nil, err
		}
		normal = anchor
	}
	if c.Recovery != nil {
		anchor, err := awsprovider.NewPublicSigningAnchor(*c.Recovery)
		if err != nil {
			return nil, err
		}
		recovery = anchor
	}
	installed, err := core.NewInstalledReconstruction(core.ReconstructionInstallation{
		Candidate: candidate, Normal: normal, Recovery: recovery, ExpectedDomain: c.ExpectedDomain,
		Construct: func(ctx context.Context, selected contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
			return newPublicSelectedStore(ctx, c.Candidate, selected)
		},
		Verify: func(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (core.ReconstructionVerifier, error) {
			return newReconstructionVerifier(ctx, c.KeyAccess, c.ExpectedKEK, pins, deadline)
		},
		CloseInstalled: func() {},
	})
	if err != nil {
		return nil, err
	}
	return installed, nil
}

// Each attempt owns its private runtime. Closing the verifier joins its private
// use before the runtime releases any remaining session backing.
type reconstructionPrivateVerifier struct {
	verifier *privatecrypto.ReconstructionVerifier
	runtime  *privatecrypto.Runtime
}

func (v *reconstructionPrivateVerifier) Verify(ctx context.Context, selection contract.ConsumerSelection) contract.CryptoResultCode {
	return v.verifier.Verify(ctx, selection)
}
func (v *reconstructionPrivateVerifier) Close() {
	if v != nil {
		v.verifier.Close()
		v.runtime.Close()
	}
}

func snapshotReconstructionTransport(transport *http.Transport) *http.Transport {
	// Transport.Clone initializes protocol defaults on its source. Retain only
	// fields consumed or refused by the AWS constructors without that mutation.
	owned := &http.Transport{
		Dial:                  transport.Dial,    //nolint:staticcheck // Preserve the deprecated hook for provider refusal.
		DialTLS:               transport.DialTLS, //nolint:staticcheck // Preserve the deprecated TLS hook for provider refusal.
		DialTLSContext:        transport.DialTLSContext,
		DialContext:           transport.DialContext,
		TLSHandshakeTimeout:   transport.TLSHandshakeTimeout,
		ResponseHeaderTimeout: transport.ResponseHeaderTimeout,
		ExpectContinueTimeout: transport.ExpectContinueTimeout,
	}
	if transport.TLSClientConfig != nil {
		owned.TLSClientConfig = transport.TLSClientConfig.Clone()
		owned.TLSClientConfig.NextProtos = slices.Clone(transport.TLSClientConfig.NextProtos)
		owned.TLSClientConfig.CipherSuites = slices.Clone(transport.TLSClientConfig.CipherSuites)
		owned.TLSClientConfig.CurvePreferences = slices.Clone(transport.TLSClientConfig.CurvePreferences)
		if transport.TLSClientConfig.RootCAs != nil {
			owned.TLSClientConfig.RootCAs = transport.TLSClientConfig.RootCAs.Clone()
		}
	}
	return owned
}
func newReconstructionVerifier(ctx context.Context, installed ReconstructionKeyAccessConfig, expected string, pins contract.ReconstructionVerificationPins, deadline time.Time) (core.ReconstructionVerifier, error) {
	row := pins.AuthorityBinding
	if ctx == nil || ctx.Err() != nil || row.SubjectKind != contract.OrdinaryWrapSubject || row.SubjectID != pins.AuthorityRecipientID || row.Binding.Provider != contract.AWS {
		return nil, privatecrypto.ErrAdmission
	}
	if _, err := contract.BindingTableLength([]contract.BindingTableRow{row}); err != nil {
		return nil, privatecrypto.ErrAdmission
	}
	if expected != "" && expected != row.Binding.KeySelector {
		return nil, core.ErrReconstructionKeyMismatch
	}
	fields := strings.Split(row.Binding.KeySelector, ":")
	if len(fields) != 6 || fields[0] != "arn" || fields[1] != "aws" || fields[2] != "kms" {
		return nil, privatecrypto.ErrAdmission
	}
	route, err := awsprovider.NewKeyAccess(awsprovider.KeyAccessConfig{Region: fields[3], Account: fields[4], CredentialRoute: installed.CredentialRoute, Credentials: installed.Credentials, Transport: installed.Transport, Timeout: installed.Timeout})
	if err != nil {
		return nil, err
	}
	runtime, err := privatecrypto.New(contract.AWS, []privatecrypto.KeyAccess{route})
	if err != nil {
		return nil, err
	}
	verifier, err := privatecrypto.NewReconstructionVerifier(runtime, installed.CredentialRoute, pins, deadline)
	if err != nil || ctx.Err() != nil {
		if verifier != nil {
			verifier.Close()
		}
		runtime.Close()
		if err == nil {
			err = privatecrypto.ErrAdmission
		}
		return nil, err
	}
	return &reconstructionPrivateVerifier{verifier: verifier, runtime: runtime}, nil
}
