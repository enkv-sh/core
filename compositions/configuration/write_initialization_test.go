package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func nativeArtifactID(text string) contract.ID { return contract.ID(sha256.Sum256([]byte(text))) }

func nativeDescriptor(t *testing.T) (contract.GenesisDescriptorCore, []byte) {
	t.Helper()
	signingSPKI, err := base64.StdEncoding.DecodeString(sourceSigningSPKI)
	if err != nil {
		t.Fatal(err)
	}
	encryptionSPKI, err := base64.StdEncoding.DecodeString(sourceEncryptionSPKI)
	if err != nil {
		t.Fatal(err)
	}
	id := nativeArtifactID
	signing := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: contract.NormalSigningRole, Provider: contract.AWS, SigningProfile: contract.P256SigningProfile, BindingID: id("normal binding"), KeySelector: sourceSigningSelector, SPKI: signingSPKI, Fingerprint: contract.ID(sha256.Sum256(signingSPKI)), Binding: contract.BindingSubject{Domain: id("domain"), Coordinate: id("coordinate"), Store: id("store"), Trust: id("trust"), PublicKey: contract.ID(sha256.Sum256(signingSPKI)), Interpretation: contract.InterpretationID(), ControlIncarnationID: id("control incarnation"), Epoch: 1}}
	kms := contract.KMSBinding{BindingID: id("encryption binding"), BindingIncarnationID: id("binding incarnation"), BindingSerial: 1, Provider: contract.AWS, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: contract.SoftwareProtection, KeySelector: sourceEncryptionSelector, SPKI: encryptionSPKI, Fingerprint: contract.ID(sha256.Sum256(encryptionSPKI))}
	d := contract.GenesisDescriptorCore{InitID: id("init"), DomainID: id("domain"), DescriptorArtifactID: id("descriptor artifact"), ManifestArtifactID: id("manifest artifact"), Provider: contract.AWS, StoreID: id("store"), CoordinateID: id("coordinate"), NonBodyID: id("nonbody"), TrustID: id("trust"), InterpretationID: contract.InterpretationID(), TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AuthorityRecipientID: id("authority"), NormalSigning: signing, Recipients: []contract.RecipientRecord{{RecipientID: id("authority"), Status: contract.CurrentRecipient, CurrentBinding: &kms}}}
	body, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal(err)
	}
	return d, body
}

func nativeManifest(t *testing.T, descriptor []byte) []byte {
	t.Helper()
	id := nativeArtifactID
	row := contract.GenesisPublicBindingRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id("authority"), BindingID: id("encryption binding"), PublicBindingDigest: id("public binding")}
	var refs []contract.Ref
	for i, kind := range []contract.Kind{contract.RecipientKind, contract.AdministrativeIndexKind, contract.RequiredSupportKind, contract.RequiredSupportKind, contract.RootKind} {
		index := uint16(0)
		if i == 3 {
			index = 1
		}
		refs = append(refs, contract.Ref{Kind: kind, Domain: id("domain"), Object: id(string(rune('a' + i))), Digest: id(string(rune('f' + i))), Format: contract.CanonicalSchema, Length: 1, Index: index})
	}
	m := contract.GenesisBootstrapManifestCore{DescriptorDigest: contract.ID(sha256.Sum256(descriptor)), RequestCoreDigest: id("request"), GenesisPlanDigest: id("plan"), NormalBindingSubjectDigest: id("binding subject"), Signers: []contract.GenesisSignerPlanRow{{TargetRole: 1, SigningBindingDigest: id("signing binding")}}, PublicBindings: []contract.GenesisPublicBindingRow{row}, Probes: []contract.InitProbePlanRow{{ProbeID: id("probe"), SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, BindingID: row.BindingID, PublicBindingDigest: row.PublicBindingDigest}}, Immutable: refs, HeadCoreDigest: id("head"), HeadCoreLength: 349, ConditionalPlanDigest: id("conditional plan")}
	body, err := contract.EncodeGenesisBootstrapManifestCore(m)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestInitializationArtifactReceipts(t *testing.T) {
	d, descriptor := nativeDescriptor(t)
	generated := strings.Replace(sourceGeneratedJSON, `"descriptor":"AQ=="`, `"descriptor":"`+base64.StdEncoding.EncodeToString(descriptor)+`"`, 1)
	digest := contract.ID(sha256.Sum256(descriptor))
	t.Run("exact-pair-and-manifest", func(t *testing.T) {
		s, _ := beginSourceEdit(t, JSON, false)
		c, _ := stageSourceEdit(t, s, generated)
		if _, err := s.CommitInitialization(context.Background(), c, nativeArtifactID("wrong"), uint64(len(descriptor)), digest); !errors.Is(err, ErrArtifact) {
			t.Fatal("wrong descriptor artifact accepted")
		}
		if _, err := s.CommitInitialization(context.Background(), c, d.DescriptorArtifactID, uint64(len(descriptor))+1, digest); !errors.Is(err, ErrArtifact) {
			t.Fatal("wrong descriptor length accepted")
		}
		if _, err := s.CommitInitialization(context.Background(), c, d.DescriptorArtifactID, uint64(len(descriptor)), nativeArtifactID("wrong bytes")); !errors.Is(err, ErrArtifact) {
			t.Fatal("wrong descriptor digest accepted")
		}
		receipt, err := s.CommitInitialization(context.Background(), c, d.DescriptorArtifactID, uint64(len(descriptor)), digest)
		if err != nil {
			t.Fatal(err)
		}
		fact, err := receipt.Fact()
		if err != nil {
			t.Fatal(err)
		}
		if fact.ArtifactID != d.DescriptorArtifactID || fact.BodyLength != uint64(len(descriptor)) || fact.BodyDigest != digest || fact.Kind != 1 {
			t.Fatal("descriptor fact differs from independent hash")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		body := nativeManifest(t, descriptor)
		path := filepath.Join(t.TempDir(), "manifest")
		manifest, err := PersistInitializationManifest(context.Background(), path, d.ManifestArtifactID, body, receipt)
		if err != nil {
			t.Fatal(err)
		}
		mf, err := manifest.Fact()
		if err != nil {
			t.Fatal(err)
		}
		if mf.BodyDigest != contract.ID(sha256.Sum256(body)) || mf.BodyLength != uint64(len(body)) || mf.ArtifactID != d.ManifestArtifactID || mf.Kind != 2 || readSource(t, path) != string(body) {
			t.Fatal("manifest fact differs")
		}
		if _, err := PersistInitializationManifest(context.Background(), path, d.ManifestArtifactID, body, receipt); err != nil {
			t.Fatal("exact manifest reuse refused", err)
		}
		wrong := nativeManifest(t, []byte("other descriptor"))
		if _, err := PersistInitializationManifest(context.Background(), path, d.ManifestArtifactID, wrong, receipt); !errors.Is(err, ErrArtifact) {
			t.Fatal("manifest descriptor mismatch accepted")
		}
		if _, err := PersistInitializationManifest(context.Background(), path, nativeArtifactID("wrong"), body, receipt); !errors.Is(err, ErrArtifact) {
			t.Fatal("manifest artifact mismatch accepted")
		}
		if err := os.WriteFile(path, []byte("conflicting immutable manifest"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := PersistInitializationManifest(context.Background(), path, d.ManifestArtifactID, body, receipt); err == nil {
			t.Fatal("conflicting immutable manifest accepted")
		}
		if readSource(t, path) != "conflicting immutable manifest" {
			t.Fatal("conflicting immutable manifest overwritten")
		}
	})
	t.Run("source-shaped-basis-cannot-mint-receipt", func(t *testing.T) {
		s, _ := beginSourceEdit(t, JSON, false)
		c, _ := stageSourceEdit(t, s, sourceGeneratedJSON)
		if _, err := s.CommitInitialization(context.Background(), c, d.DescriptorArtifactID, 1, nativeArtifactID("anything")); !errors.Is(err, ErrArtifact) {
			t.Fatal("noncanonical descriptor accepted")
		}
	})
	t.Run("lost-readback-cannot-mint-receipt", func(t *testing.T) {
		s, _ := beginSourceEdit(t, JSON, false)
		c, _ := stageSourceEdit(t, s, generated)
		operations := s.io
		s.io.readback = func(ctx context.Context, path string, image *Image, predecessor bool) error {
			if !predecessor {
				return errors.New("readback lost")
			}
			return operations.readback(ctx, path, image, predecessor)
		}
		receipt, err := s.CommitInitialization(context.Background(), c, d.DescriptorArtifactID, uint64(len(descriptor)), digest)
		var unknown *UnknownEdit
		if receipt != nil || !errors.As(err, &unknown) {
			t.Fatal("failed readback issued receipt")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := unknown.Observation.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("zero-receipts-refuse", func(t *testing.T) {
		if _, err := new(InitializationDescriptor).Fact(); !errors.Is(err, ErrArtifact) {
			t.Fatal("zero descriptor receipt accepted")
		}
		if _, err := new(InitializationManifest).Fact(); !errors.Is(err, ErrArtifact) {
			t.Fatal("zero manifest receipt accepted")
		}
	})
	t.Run("manifest-flush-failure", func(t *testing.T) {
		s, _ := beginSourceEdit(t, JSON, false)
		c, _ := stageSourceEdit(t, s, generated)
		receipt, err := s.CommitInitialization(context.Background(), c, d.DescriptorArtifactID, uint64(len(descriptor)), digest)
		if err != nil {
			t.Fatal(err)
		}
		ops := nativeEditIO()
		fault := errors.New("manifest sync failure")
		ops.syncFile = func(*os.File) error { return fault }
		path := filepath.Join(t.TempDir(), "manifest")
		manifest, err := persistInitializationManifest(context.Background(), path, d.ManifestArtifactID, nativeManifest(t, descriptor), receipt, ops, nil)
		if manifest != nil || !errors.Is(err, fault) {
			t.Fatal("failed manifest sync issued receipt")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed manifest sync installed artifact")
		}
	})
}

// full_only: false
func TestInitializationManifestCapture(t *testing.T) {
	_, descriptor := nativeDescriptor(t)
	body := nativeManifest(t, descriptor)
	path := filepath.Join(t.TempDir(), "manifest.init")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := CaptureInitializationManifest(context.Background(), path)
	if err != nil || string(got) != string(body) {
		t.Fatal("exact manifest capture failed", err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{{"invalid", []byte("not a manifest")}, {"truncated", body[:len(body)-1]}, {"trailing", append(append([]byte{}, body...), 0)}, {"oversize", make([]byte, contract.GenesisBootstrapLimit+1)}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := CaptureInitializationManifest(context.Background(), path); err == nil || got != nil {
				t.Fatal("invalid manifest capture accepted")
			}
		})
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureInitializationManifest(context.Background(), path); err == nil {
		t.Fatal("missing manifest accepted")
	}
	target := path + ".target"
	if err := os.WriteFile(target, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureInitializationManifest(context.Background(), path); err == nil {
		t.Fatal("symlink manifest accepted")
	}
}
