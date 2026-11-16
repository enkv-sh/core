package compositiongcp

import (
	"context"
	"strings"
	"time"

	core "enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	gcp "enkv.sh/providers/gcp"
)

// ReconstructionKeyAccessConfig supplies the caller-owned private Client
// and local route. Project, region and endpoint come from AuthorityBinding.
type ReconstructionKeyAccessConfig struct {
	Client          *gcp.Client
	CredentialRoute contract.ID
}

// ReconstructionConfig fixes the public location, signing versions and private
// credentials before a candidate is read. ExpectedDomain and ExpectedKEK are
// optional independent pins. The GCP clients remain owned by the caller.
type ReconstructionConfig struct {
	Candidate      gcp.CandidateReadConfig
	Normal         *gcp.PublicSigningAnchorConfig
	Recovery       *gcp.PublicSigningAnchorConfig
	KeyAccess      ReconstructionKeyAccessConfig
	ExpectedDomain contract.ID
	ExpectedKEK    string
}

type publicSelectedStore struct{ store *gcp.Store }

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

func newPublicSelectedStore(ctx context.Context, candidate gcp.CandidateReadConfig, selected contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
	if ctx == nil || ctx.Err() != nil {
		return nil, core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
	}
	store, err := gcp.NewStore(ctx, gcp.StoreConfig{Client: candidate.Client,
		Domain: selected.DomainID, Region: selected.Region,
		Endpoint: "https://storage." + selected.Region + ".rep.googleapis.com/storage/v1/",
		Bucket:   selected.Bucket, Prefix: selected.PrefixBeforeHEAD,
		CredentialRoute: candidate.CredentialRoute})
	if err != nil {
		return nil, core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
	}
	return &publicSelectedStore{store: store}, core.Result{}
}

// NewReconstruction installs the final-only Core engine. The regional REP
// Store endpoint is derived from the authenticated region, never supplied by
// candidate bytes as an independent URL.
func NewReconstruction(ctx context.Context, c ReconstructionConfig) (*core.ReconstructionEngine, error) {
	if c.KeyAccess.CredentialRoute.IsZero() || c.KeyAccess.Client == nil || ctx == nil || ctx.Err() != nil || c.Normal == nil && c.Recovery == nil ||
		c.Normal != nil && c.Normal.Role != contract.NormalSigningRole ||
		c.Recovery != nil && c.Recovery.Role != contract.RecoverySigningRole {
		return nil, ErrClass
	}
	candidate, err := gcp.NewCandidateReader(ctx, c.Candidate)
	if err != nil {
		return nil, err
	}
	var normal, recovery core.ReconstructionSigningAnchor
	if c.Normal != nil {
		anchor, err := gcp.NewPublicSigningAnchor(ctx, *c.Normal)
		if err != nil {
			return nil, err
		}
		normal = anchor
	}
	if c.Recovery != nil {
		anchor, err := gcp.NewPublicSigningAnchor(ctx, *c.Recovery)
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

func newReconstructionVerifier(ctx context.Context, installed ReconstructionKeyAccessConfig, expected string, pins contract.ReconstructionVerificationPins, deadline time.Time) (core.ReconstructionVerifier, error) {
	row := pins.AuthorityBinding
	if ctx == nil || ctx.Err() != nil || row.SubjectKind != contract.OrdinaryWrapSubject || row.SubjectID != pins.AuthorityRecipientID || row.Binding.Provider != contract.GCP {
		return nil, privatecrypto.ErrAdmission
	}
	if _, err := contract.BindingTableLength([]contract.BindingTableRow{row}); err != nil {
		return nil, privatecrypto.ErrAdmission
	}
	if expected != "" && expected != row.Binding.KeySelector {
		return nil, core.ErrReconstructionKeyMismatch
	}
	fields := strings.Split(row.Binding.KeySelector, "/")
	if len(fields) != 10 || fields[0] != "projects" || fields[2] != "locations" || fields[4] != "keyRings" || fields[6] != "cryptoKeys" || fields[8] != "cryptoKeyVersions" {
		return nil, privatecrypto.ErrAdmission
	}
	endpoint := "https://" + fields[3] + "-cloudkms.googleapis.com/"
	route, err := gcp.NewKeyAccess(ctx, gcp.KeyAccessConfig{Client: installed.Client, Project: fields[1], Region: fields[3], Endpoint: endpoint, CredentialRoute: installed.CredentialRoute})
	if err != nil {
		return nil, err
	}
	runtime, err := privatecrypto.New(contract.GCP, []privatecrypto.KeyAccess{route})
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
