package compositionaws

import (
	"context"
	"crypto/tls"
	"enkv.sh/crypto/testsupport/installedarchive"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	privatecrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
)

func reconstructionConfig(t *testing.T) ReconstructionConfig {
	t.Helper()
	cell := localConfig(t)
	normal := awsprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole,
		Region: cell.Trust.Region, KeyARN: cell.Trust.KeyARN,
		CredentialRoute: cell.Trust.CredentialRoute, Credentials: cell.Trust.Credentials,
		Transport: cell.Trust.Transport, Timeout: cell.Trust.Timeout}
	return ReconstructionConfig{Candidate: awsprovider.CandidateReadConfig{Region: cell.Store.Region,
		Bucket: cell.Store.Bucket, Prefix: cell.Store.Prefix,
		ExpectedBucketOwner: cell.Store.ExpectedBucketOwner, CredentialRoute: cell.Store.CredentialRoute,
		Credentials: cell.Store.Credentials, Transport: cell.Store.Transport, Timeout: cell.Store.Timeout},
		Normal: &normal, KeyAccess: ReconstructionKeyAccessConfig{CredentialRoute: cell.KeyAccess[0].CredentialRoute, Credentials: cell.KeyAccess[0].Credentials, Transport: cell.KeyAccess[0].Transport, Timeout: cell.KeyAccess[0].Timeout}, ExpectedDomain: cell.Store.Domain}
}

// full_only: false
func TestNewReconstructionPinsAWSComponentsWithoutEffects(t *testing.T) {
	c := reconstructionConfig(t)
	engine, err := NewReconstruction(c)
	if err != nil || engine == nil {
		t.Fatal("fixed AWS reconstruction did not construct", err)
	}
	// A cancelled invocation cannot retrieve credentials or issue an S3/KMS
	// request merely because the installed composition exists.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	cancel()
	if projection, result := engine.Reconstruct(ctx); projection != nil || result.Outcome == core.ObservedCurrent {
		t.Fatal("cancelled installation reported a selected projection", result)
	}
	engine.Close()
	engine.Close()
	if projection, result := engine.Reconstruct(ctx); projection != nil || result.Outcome != core.AdmissionRefused {
		t.Fatal("closed AWS installation admitted a later call", result)
	}

	t.Run("default-candidate-transport", func(t *testing.T) {
		c := reconstructionConfig(t)
		source := &http.Transport{}
		c.Candidate.Transport = source
		engine, err := NewReconstruction(c)
		if err != nil || engine == nil {
			t.Fatal("default candidate transport did not install reconstruction", err)
		}
		engine.Close()
		if source.TLSClientConfig != nil || source.TLSNextProto != nil || source.HTTP2 != nil || source.Protocols != nil {
			t.Fatal("reconstruction initialized caller candidate protocol policy")
		}
	})
	for _, policy := range []string{"default", "alpn", "tls-dial"} {
		t.Run("deferred-private-transport/"+policy, func(t *testing.T) {
			c := reconstructionConfig(t)
			archive := installedarchive.Load(t, "aws")
			headObject := archive.MustObject(t, archive.Location.PrefixBeforeHEAD+"/HEAD")
			head, err := format.DecodeHead(headObject.Body)
			if err != nil {
				t.Fatal("archived HEAD refused", err)
			}
			rootKey, err := format.Key(archive.Location.PrefixBeforeHEAD, head.Core.Root)
			if err != nil {
				t.Fatal("archived Root reference refused", err)
			}
			root, err := format.DecodeRoot(archive.MustObject(t, rootKey).Body)
			if err != nil || head.Core.Domain != archive.Domain || root.Domain != archive.Domain || root.Snapshot != head.Core.Root.Object {
				t.Fatal("archived Root relation refused", err)
			}
			pins := contract.ReconstructionVerificationPins{DomainID: archive.Domain, SnapshotID: head.Core.Root.Object,
				HEADDigest: archive.HeadDigest, HEADRevision: head.Core.Revision, HEADToken: headObject.Token,
				Root: head.Core.Root, AccessRoot: root.CurrentAccess.AccessRoot, AuthorityRecipientID: archive.AuthorityID,
				AuthorityBinding: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: archive.AuthorityID, Binding: archive.AuthorityBinding}}
			baseline, err := newReconstructionVerifier(context.Background(), c.KeyAccess, "", pins, time.Now().Add(time.Minute))
			if err != nil || baseline == nil {
				t.Fatal("complete archived pins did not construct baseline verifier", err)
			}
			baseline.Close()
			source := &http.Transport{}
			if policy == "alpn" {
				source.TLSClientConfig = &tls.Config{NextProtos: []string{"h2"}}
			}
			if policy == "tls-dial" {
				field := reflect.ValueOf(source).Elem().FieldByName("DialTLSContext")
				field.Set(reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value {
					t.Fatal("deferred construction invoked a refused TLS dial hook")
					return nil
				}))
			}
			c.KeyAccess.Transport = snapshotReconstructionTransport(source)
			switch policy {
			case "alpn":
				source.TLSClientConfig.NextProtos[0] = "http/1.1"
			case "tls-dial":
				source.DialTLSContext = nil
			}
			verifier, err := newReconstructionVerifier(context.Background(), c.KeyAccess, "", pins, time.Now().Add(time.Minute))
			if verifier != nil {
				verifier.Close()
			}
			if policy == "default" {
				if err != nil || verifier == nil {
					t.Fatal("default deferred private transport refused", err)
				}
				if source.TLSClientConfig != nil || source.TLSNextProto != nil || source.HTTP2 != nil || source.Protocols != nil {
					t.Fatal("deferred snapshot initialized caller protocol policy")
				}
			} else if !errors.Is(err, awsprovider.ErrConstruction) || verifier != nil {
				t.Fatal("deferred snapshot lost refused transport evidence", err)
			}
		})
	}
}

// full_only: false
func TestNewReconstructionRejectsUnfixedAWSRoutes(t *testing.T) {
	for _, name := range []string{"no public signer", "swapped signer role", "missing candidate route", "missing private route", "unadmitted location"} {
		t.Run(name, func(t *testing.T) {
			c := reconstructionConfig(t)
			switch name {
			case "no public signer":
				c.Normal = nil
			case "swapped signer role":
				c.Normal.Role = contract.RecoverySigningRole
			case "missing candidate route":
				c.Candidate.CredentialRoute = contract.ID{}
			case "missing private route":
				c.KeyAccess.CredentialRoute = contract.ID{}
			case "unadmitted location":
				c.Candidate.Region = ""
			}
			if engine, err := NewReconstruction(c); err == nil || engine != nil {
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
	c := reconstructionConfig(t)
	ctx := context.Background()
	a := installedarchive.Load(t, "aws")
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
