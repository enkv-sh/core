package compositiongcp

import (
	"context"
	"enkv.sh/crypto/testsupport/installedarchive"
	"errors"
	"testing"
	"time"

	core "enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	gcp "enkv.sh/providers/gcp"
)

func reconstructionConfig(t *testing.T) (context.Context, ReconstructionConfig) {
	t.Helper()
	ctx, cell := localConfig(t)
	normal := gcp.PublicSigningAnchorConfig{Role: contract.NormalSigningRole,
		Client: cell.Trust.Client, Region: cell.Trust.Region, KeyVersion: cell.Trust.KeyVersion,
		CredentialRoute: cell.Trust.CredentialRoute}
	return ctx, ReconstructionConfig{Candidate: gcp.CandidateReadConfig{Client: cell.Store.Client,
		Region: cell.Store.Region, Bucket: cell.Store.Bucket, Prefix: cell.Store.Prefix,
		CredentialRoute: cell.Store.CredentialRoute},
		Normal: &normal, KeyAccess: ReconstructionKeyAccessConfig{CredentialRoute: cell.KeyAccess[0].CredentialRoute, Client: cell.KeyAccess[0].Client}, ExpectedDomain: cell.Store.Domain}
}

// full_only: false
func TestNewReconstructionPinsGCPComponentsWithoutEffects(t *testing.T) {
	ctx, c := reconstructionConfig(t)
	engine, err := NewReconstruction(ctx, c)
	if err != nil || engine == nil {
		t.Fatal("fixed GCP reconstruction did not construct", err)
	}
	// The caller-owned GCP clients are shared with these provider views. An
	// expired invocation cannot use them merely because construction succeeded.
	expired, cancel := context.WithDeadline(ctx, time.Now().Add(time.Minute))
	cancel()
	if projection, result := engine.Reconstruct(expired); projection != nil || result.Outcome == core.ObservedCurrent {
		t.Fatal("cancelled installation reported a selected projection", result)
	}
	engine.Close()
	engine.Close()
	if projection, result := engine.Reconstruct(expired); projection != nil || result.Outcome != core.AdmissionRefused {
		t.Fatal("closed GCP installation admitted a later call", result)
	}
}

// full_only: false
func TestNewReconstructionRejectsUnfixedGCPRoutes(t *testing.T) {
	for _, name := range []string{"no public signer", "swapped signer role", "missing candidate route", "missing private route", "unadmitted location"} {
		t.Run(name, func(t *testing.T) {
			ctx, c := reconstructionConfig(t)
			switch name {
			case "no public signer":
				c.Normal = nil
			case "swapped signer role":
				c.Normal.Role = contract.RecoverySigningRole
			case "missing candidate route":
				c.Candidate.CredentialRoute = ""
			case "missing private route":
				c.KeyAccess.CredentialRoute = contract.ID{}
			case "unadmitted location":
				c.Candidate.Region = ""
			}
			if engine, err := NewReconstruction(ctx, c); err == nil || engine != nil {
				if engine != nil {
					engine.Close()
				}
				t.Fatal("invalid independent route installed", name, err)
			}
		})
	}
}

// full_only: false
func TestReconstructionPrivateConstructionRejectsInvalidCompleteBinding(t *testing.T) {
	ctx, c := reconstructionConfig(t)
	a := installedarchive.Load(t, "gcp")
	for _, name := range []string{"key", "subject", "provider", "expected", "expected-and-key"} {
		t.Run(name, func(t *testing.T) {
			pins := contract.ReconstructionVerificationPins{AuthorityRecipientID: a.AuthorityID, AuthorityBinding: contract.BindingTableRow{SubjectKind: 1, SubjectID: a.AuthorityID, Binding: a.AuthorityBinding}}
			expected := ""
			switch name {
			case "key":
				pins.AuthorityBinding.Binding.SPKI = nil
			case "subject":
				pins.AuthorityBinding.SubjectID = contract.Hash([]byte("wrong subject"))
			case "provider":
				pins.AuthorityBinding.Binding.Provider = 0
			case "expected":
				expected = "different independent key"
			case "expected-and-key":
				expected = "different independent key"
				pins.AuthorityBinding.Binding.SPKI = nil
			}
			verifier, err := newReconstructionVerifier(ctx, c.KeyAccess, expected, pins, time.Now().Add(time.Minute))
			if verifier != nil {
				verifier.Close()
			}
			if err == nil || verifier != nil {
				t.Fatal("invalid complete binding constructed a private verifier")
			}
			want := privatecrypto.ErrAdmission
			if name == "expected" {
				want = core.ErrReconstructionKeyMismatch
			}
			if !errors.Is(err, want) {
				t.Fatal("expected-selector mismatch lost its distinct boundary or masked invalid binding", name, err)
			}
		})
	}
}
