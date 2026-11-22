package compositionfull

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
	gcpprovider "enkv.sh/providers/gcp"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type inertCredentials struct{ calls atomic.Int32 }

func (c *inertCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls.Add(1)
	return aws.Credentials{}, errors.New("construction must not retrieve AWS credentials")
}

func (c *inertCredentials) Token(context.Context) (string, error) {
	c.calls.Add(1)
	return "", errors.New("construction must not retrieve GCP credentials")
}

func localConfigs(t *testing.T) (context.Context, compositionaws.Config, compositiongcp.Config) {
	t.Helper()
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
	awsStore, awsTrust, gcpStore, gcpTrust := &inertCredentials{}, &inertCredentials{}, &inertCredentials{}, &inertCredentials{}
	var networkCalls atomic.Int32
	awsTransport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		networkCalls.Add(1)
		return nil, errors.New("construction must not use the network")
	}}
	newGCPClient := func(credentials *inertCredentials) *gcpprovider.Client {
		client, err := gcpprovider.NewClient(&http.Transport{}, credentials)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) {
		networkCalls.Add(1)
		cancel()
	}})
	t.Cleanup(func() {
		cancel()
		for name, credentials := range map[string]*inertCredentials{"AWS Store": awsStore, "AWS Trust": awsTrust, "GCP Store": gcpStore, "GCP Trust": gcpTrust} {
			if calls := credentials.calls.Load(); calls != 0 {
				t.Errorf("%s construction retrieved credentials %d times", name, calls)
			}
		}
		if calls := networkCalls.Load(); calls != 0 {
			t.Errorf("construction attempted %d network connections", calls)
		}
	})
	// Fixed public P-256 generator SPKI; construction needs no private key.
	public, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	a := compositionaws.Config{
		StoreClass: awsprovider.StoreClass, TrustClass: awsprovider.TrustClass, VerifierClass: awsprovider.VerifierClass,
		Store:     awsprovider.StoreConfig{Region: "us-east-1", Bucket: "fixture-bucket", ExpectedBucketOwner: "123456789012", Prefix: "fixture/aws", Domain: contract.Hash([]byte("domain")), CredentialRoute: contract.Hash([]byte("store-route")), Credentials: awsStore, Transport: awsTransport, Timeout: time.Second},
		Trust:     awsprovider.TrustConfig{Region: "us-east-1", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: public, CredentialRoute: contract.Hash([]byte("trust-route")), Credentials: awsTrust, Transport: awsTransport, Timeout: time.Second},
		KeyAccess: []awsprovider.KeyAccessConfig{{Region: "us-east-1", Account: "123456789012", CredentialRoute: contract.Hash([]byte("authority-kek-route")), Credentials: awsTrust, Transport: awsTransport, Timeout: time.Second}},
	}
	g := compositiongcp.Config{
		StoreClass: gcpprovider.StoreClass, TrustClass: gcpprovider.TrustClass, VerifierClass: gcpprovider.VerifierClass,
		Store:     gcpprovider.StoreConfig{Client: newGCPClient(gcpStore), Domain: contract.Hash([]byte("domain")), Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "fixture-bucket", Prefix: "fixture/gcp", CredentialRoute: "store-route"},
		Trust:     gcpprovider.TrustConfig{Client: newGCPClient(gcpTrust), Region: "us-central1", Endpoint: "https://us-central1-cloudkms.googleapis.com/", CredentialRoute: "trust-route", KeyVersion: "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: public},
		KeyAccess: []gcpprovider.KeyAccessConfig{{Client: newGCPClient(gcpTrust), Project: "fixture-project", Region: "us-central1", Endpoint: "https://us-central1-cloudkms.googleapis.com/", CredentialRoute: contract.Hash([]byte("authority-kek-route"))}},
	}
	return ctx, a, g
}

// full_only: false
func TestNewConstructsEachSelectedCell(t *testing.T) {
	identities := make(map[contract.Family]contract.ID)
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(map[contract.Family]string{contract.AWS: "AWS", contract.GCP: "GCP"}[family], func(t *testing.T) {
			ctx, a, g := localConfigs(t)
			c := Config{Family: family}
			var want contract.Cell
			var err error
			if family == contract.AWS {
				c.AWS = &a
				want, err = compositionaws.New(a)
			} else {
				c.GCP = &g
				want, err = compositiongcp.New(ctx, g)
			}
			if err != nil {
				t.Fatal(err)
			}
			cell, err := New(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			for _, configured := range []contract.Cell{want, cell} {
				runtime, ok := configured.Crypto.(*enkvcrypto.Runtime)
				if !ok || runtime.InstanceID().IsZero() {
					t.Fatalf("Crypto type = %T", configured.Crypto)
				}
				t.Cleanup(runtime.Close)
			}
			if cell.Crypto.InstanceID() == want.Crypto.InstanceID() {
				t.Fatal("full composition reused a custody instance")
			}
			if family == contract.AWS {
				if _, ok := cell.Store.(*awsprovider.Store); !ok {
					t.Fatalf("AWS Store type = %T", cell.Store)
				}
				if _, ok := cell.Trust.(*awsprovider.Trust); !ok {
					t.Fatalf("AWS Trust type = %T", cell.Trust)
				}
			} else {
				if _, ok := cell.Store.(*gcpprovider.Store); !ok {
					t.Fatalf("GCP Store type = %T", cell.Store)
				}
				if _, ok := cell.Trust.(*gcpprovider.Trust); !ok {
					t.Fatalf("GCP Trust type = %T", cell.Trust)
				}
			}
			d := cell.Store.Descriptor()
			if !d.Valid() || d.Family != family || d != want.Store.Descriptor() || cell.Trust.Family() != family || cell.Trust.Identity().IsZero() || cell.Trust.Identity() != want.Trust.Identity() || cell.Identity.IsZero() || cell.Identity != want.Identity {
				t.Fatal("full composition does not preserve the selected Store, Trust, and cell bindings")
			}
			identities[family] = cell.Identity
		})
	}
	if identities[contract.AWS] == identities[contract.GCP] {
		t.Fatal("AWS and GCP cell identities collapsed")
	}
}

// full_only: false
func TestNewAuthorityConstructsOnlySelectedStoreAndTrust(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		ctx, a, g := localConfigs(t)
		config := Config{Family: family}
		if family == contract.AWS {
			a.KeyAccess = nil
			config.AWS = &a
		} else {
			g.KeyAccess = nil
			config.GCP = &g
		}
		store, trust, err := NewAuthority(ctx, config)
		if err != nil || store == nil || trust == nil || store.Descriptor().Family != family || trust.Family() != family || trust.Identity().IsZero() {
			t.Fatal("Authority construction", family, err)
		}
		if family == contract.AWS {
			config.AWS.KeyAccess = []awsprovider.KeyAccessConfig{{}}
		} else {
			config.GCP.KeyAccess = []gcpprovider.KeyAccessConfig{{}}
		}
		if store, trust, err := NewAuthority(ctx, config); err == nil || store != nil || trust != nil {
			t.Fatal("Authority construction admitted a private KEK route", family, err)
		}
	}
}

// full_only: false
func TestNewRejectsMixedAndAmbiguousCells(t *testing.T) {
	ctx, a, g := localConfigs(t)
	for _, tc := range []struct {
		name   string
		config Config
	}{
		{"empty", Config{}},
		{"unknown family", Config{Family: 255}},
		{"unknown family with AWS", Config{Family: 255, AWS: &a}},
		{"unknown family with GCP", Config{Family: 255, GCP: &g}},
		{"AWS missing", Config{Family: contract.AWS}},
		{"GCP missing", Config{Family: contract.GCP}},
		{"AWS with GCP config", Config{Family: contract.AWS, GCP: &g}},
		{"GCP with AWS config", Config{Family: contract.GCP, AWS: &a}},
		{"AWS with both configs", Config{Family: contract.AWS, AWS: &a, GCP: &g}},
		{"GCP with both configs", Config{Family: contract.GCP, AWS: &a, GCP: &g}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if cell, err := New(ctx, tc.config); err != ErrCell || cell != (contract.Cell{}) {
				t.Fatalf("mixed or ambiguous cell: cell=%+v error=%v", cell, err)
			}
		})
	}
}

// full_only: false
func TestNewPreservesEachClassRefusal(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, class := range []string{"Store", "Trust", "Verifier"} {
			t.Run(map[contract.Family]string{contract.AWS: "AWS", contract.GCP: "GCP"}[family]+"/"+class, func(t *testing.T) {
				ctx, a, g := localConfigs(t)
				c, wantError := Config{Family: family}, compositionaws.ErrClass
				var selected *string
				if family == contract.AWS {
					c.AWS = &a
					selected = map[string]*string{"Store": &a.StoreClass, "Trust": &a.TrustClass, "Verifier": &a.VerifierClass}[class]
				} else {
					c.GCP, wantError = &g, compositiongcp.ErrClass
					selected = map[string]*string{"Store": &g.StoreClass, "Trust": &g.TrustClass, "Verifier": &g.VerifierClass}[class]
				}
				*selected = "unknown-class"
				if cell, err := New(ctx, c); err != wantError || cell != (contract.Cell{}) {
					t.Fatalf("unknown %s class: cell=%+v error=%v", class, cell, err)
				}
			})
		}
	}
}

// full_only: false
func TestNewPreservesMissingCryptoRefusal(t *testing.T) {
	ctx, a, g := localConfigs(t)
	a.KeyAccess, g.KeyAccess = nil, nil
	for _, tc := range []struct {
		name   string
		config Config
		want   error
	}{
		{"AWS", Config{Family: contract.AWS, AWS: &a}, awsprovider.ErrConstruction},
		{"GCP", Config{Family: contract.GCP, GCP: &g}, gcpprovider.ErrConstruction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if cell, err := New(ctx, tc.config); err != tc.want || cell != (contract.Cell{}) {
				t.Fatalf("missing private configuration returned cell=%+v error=%v", cell, err)
			}
		})
	}
}

// full_only: false
func TestExactCellsAndIdenticalNeutralVersions(t *testing.T) {
	_, config, _ := localConfigs(t)
	m, a, g := CompatibilityManifest(), compositionaws.CompatibilityManifest(), compositiongcp.CompatibilityManifest()
	if m.Engine != "state-session/v9" || m.Format != "canonical-state/v16" || m.ComponentContract != "store-trust-crypto/v9" || m.Crypto != "supplied-secret/v4" || m.CryptoProfile != "rsa3072-oaep-sha256-aes256gcm-hmacsha256/v2" {
		t.Fatal("retired interpretation in full composition")
	}
	wantComponents := append(append([]contract.ComponentImplementation{}, a.Components...), g.Components...)
	wantVerifiers := append(append([]contract.VerifierParser{}, a.Verifiers...), g.Verifiers...)
	wantConstructions := append(append([]contract.ConstructionClass{}, a.Constructions...), g.Constructions...)
	check := func(m contract.CompatibilityManifest) {
		t.Helper()
		if len(m.Components) != 4 || len(m.Generators) != 0 || len(a.Generators) != 0 || len(g.Generators) != 0 || len(m.Verifiers) != 2 || len(m.Constructions) != 4 || !reflect.DeepEqual(m.Components, wantComponents) || !reflect.DeepEqual(m.Constructions, wantConstructions) {
			t.Fatal("registry union drift")
		}
		if m.Core != a.Core || m.Core != g.Core || m.Engine != a.Engine || m.Engine != g.Engine || m.Format != a.Format || m.Format != g.Format || m.ComponentContract != a.ComponentContract || m.ComponentContract != g.ComponentContract || m.Crypto != a.Crypto || m.Crypto != g.Crypto || m.CryptoProfile != a.CryptoProfile || m.CryptoProfile != g.CryptoProfile {
			t.Fatal("neutral versions differ")
		}
		if m.Identity != contract.Hash([]byte("enkv/composition/full/v1")) || m.Identity == a.Identity || m.Identity == g.Identity || a.Identity == g.Identity {
			t.Fatal("manifest identities collapsed or drifted")
		}
		for i, verifier := range m.Verifiers {
			if verifier.Family != wantVerifiers[i].Family || verifier.Class != wantVerifiers[i].Class || verifier.Parse == nil {
				t.Fatal("verifier registry union drift")
			}
			if _, err := verifier.Parse(config.Trust.PublicKeyDER); err != nil {
				t.Fatalf("registered verifier rejected P256: %v", err)
			}
			if _, err := verifier.Parse(nil); err == nil {
				t.Fatal("registered verifier accepted an empty key")
			}
		}
	}
	check(m)
	for i := range m.Components {
		m.Components[i] = contract.ComponentImplementation{}
	}
	for i := range m.Verifiers {
		m.Verifiers[i] = contract.VerifierParser{}
	}
	for i := range m.Constructions {
		m.Constructions[i] = contract.ConstructionClass{}
	}
	check(CompatibilityManifest())
}
