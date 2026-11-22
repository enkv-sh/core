package compositiongcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	gcpprovider "enkv.sh/providers/gcp"
)

type inertCredentials struct{ calls atomic.Int32 }

func (c *inertCredentials) Token(context.Context) (string, error) {
	c.calls.Add(1)
	return "", errors.New("construction must not retrieve credentials")
}

func localConfig(t *testing.T) (context.Context, Config) {
	t.Helper()
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
	storeCredentials, trustCredentials := &inertCredentials{}, &inertCredentials{}
	storeClient, err := gcpprovider.NewClient(&http.Transport{}, storeCredentials)
	if err != nil {
		t.Fatal(err)
	}
	trustClient, err := gcpprovider.NewClient(&http.Transport{}, trustCredentials)
	if err != nil {
		t.Fatal(err)
	}
	var networkCalls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) {
		networkCalls.Add(1)
		cancel()
	}})
	t.Cleanup(func() {
		cancel()
		if s, tr, n := storeCredentials.calls.Load(), trustCredentials.calls.Load(), networkCalls.Load(); s != 0 || tr != 0 || n != 0 {
			t.Errorf("construction calls: store credentials=%d trust credentials=%d network=%d", s, tr, n)
		}
	})
	// Fixed public P-256 generator SPKI; construction needs no private key.
	public, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	return ctx, Config{
		StoreClass: gcpprovider.StoreClass, TrustClass: gcpprovider.TrustClass, VerifierClass: gcpprovider.VerifierClass,
		Store:     gcpprovider.StoreConfig{Client: storeClient, Domain: contract.Hash([]byte("domain")), Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "fixture-bucket", Prefix: "fixture/state", CredentialRoute: "store-route"},
		Trust:     gcpprovider.TrustConfig{Client: trustClient, Region: "us-central1", Endpoint: "https://us-central1-cloudkms.googleapis.com/", CredentialRoute: "trust-route", KeyVersion: "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: public},
		KeyAccess: []gcpprovider.KeyAccessConfig{{Client: trustClient, Project: "fixture-project", Region: "us-central1", Endpoint: "https://us-central1-cloudkms.googleapis.com/", CredentialRoute: contract.Hash([]byte("authority-kek-route"))}, {Client: trustClient, Project: "fixture-project", Region: "us-central1", Endpoint: "https://us-central1-cloudkms.googleapis.com/", CredentialRoute: contract.Hash([]byte("recovery-kek-route"))}},
	}
}

// full_only: false
func TestNewConstructsSelectedCell(t *testing.T) {
	ctx, c := localConfig(t)
	wantStore, err := gcpprovider.NewStore(ctx, c.Store)
	if err != nil {
		t.Fatal(err)
	}
	wantTrust, err := gcpprovider.NewTrust(ctx, c.Trust)
	if err != nil {
		t.Fatal(err)
	}
	cell, err := New(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cell.Store.(*gcpprovider.Store); !ok {
		t.Fatalf("Store type = %T", cell.Store)
	}
	if _, ok := cell.Trust.(*gcpprovider.Trust); !ok {
		t.Fatalf("Trust type = %T", cell.Trust)
	}
	d := cell.Store.Descriptor()
	if d != wantStore.Descriptor() || !d.Valid() || d.Family != contract.GCP || d.Prefix != c.Store.Prefix || d.HeadKey != c.Store.Prefix+"/HEAD" {
		t.Fatalf("Store descriptor = %+v; want %+v", d, wantStore.Descriptor())
	}
	if cell.Trust.Family() != contract.GCP || cell.Trust.Identity().IsZero() || cell.Trust.Identity() != wantTrust.Identity() {
		t.Fatal("Trust does not match the configured GCP binding")
	}
	h := sha256.New()
	h.Write([]byte("ENKV/CELL/GCP/v1\x00"))
	sid, tid := wantStore.Descriptor().Identity, wantTrust.Identity()
	h.Write(sid[:])
	h.Write(tid[:])
	var wantID contract.ID
	copy(wantID[:], h.Sum(nil))
	if cell.Identity != wantID {
		t.Fatalf("cell identity = %x; want %x", cell.Identity, wantID)
	}
	for _, role := range []string{"Store", "Store credentials", "Trust", "Trust credentials"} {
		t.Run(role+" binding", func(t *testing.T) {
			changed := c
			switch role {
			case "Store":
				changed.Store.Prefix = "another/state"
			case "Store credentials":
				changed.Store.CredentialRoute = "another-store-route"
			case "Trust":
				changed.Trust.Role = contract.RecoverySigningRole
			case "Trust credentials":
				changed.Trust.CredentialRoute = "another-trust-route"
			}
			other, err := New(ctx, changed)
			if err != nil || (other.Identity == cell.Identity) != (role == "Store credentials" || role == "Trust credentials") {
				t.Fatalf("changed %s binding has incorrect cell identity: %v", role, err)
			}
		})
	}
}

// full_only: false
func TestNewRejectsEachUnknownClass(t *testing.T) {
	for _, class := range []string{"Store", "legacy Store", "Trust", "Verifier"} {
		t.Run(class, func(t *testing.T) {
			ctx, c := localConfig(t)
			switch class {
			case "Store":
				c.StoreClass = "aws-s3-regional-v2"
			case "legacy Store":
				c.StoreClass = "gcp-gcs-json-v1"
			case "Trust":
				c.TrustClass = "aws-kms-p256-v1"
			case "Verifier":
				c.VerifierClass = "aws-kms-p256-spki-v1"
			}
			if cell, err := New(ctx, c); err != ErrClass || cell != (contract.Cell{}) {
				t.Fatalf("unknown %s class: cell=%+v error=%v", class, cell, err)
			}
		})
	}
}

// full_only: false
func TestClosedRegistries(t *testing.T) {
	_, c := localConfig(t)
	check := func(m contract.CompatibilityManifest) {
		t.Helper()
		wantComponents := []contract.ComponentImplementation{
			{Family: contract.GCP, Kind: contract.StoreComponentKind, Class: gcpprovider.StoreClass, Module: "enkv.sh/providers/gcp", Version: contract.CoreVersion},
			{Family: contract.GCP, Kind: contract.TrustComponentKind, Class: gcpprovider.TrustClass, Module: "enkv.sh/providers/gcp", Version: contract.CoreVersion},
		}
		wantConstructions := []contract.ConstructionClass{{Family: contract.GCP, Kind: contract.StoreComponentKind, Class: gcpprovider.StoreClass}, {Family: contract.GCP, Kind: contract.TrustComponentKind, Class: gcpprovider.TrustClass}}
		if m.Identity != contract.Hash([]byte("enkv/composition/gcp/v1")) || m.Core != contract.CoreVersion || m.Engine != "state-session/v9" || m.Format != "canonical-state/v14" || m.ComponentContract != "store-trust-crypto/v9" || m.Crypto != "supplied-secret/v4" || m.CryptoProfile != "rsa3072-oaep-sha256-aes256gcm-hmacsha256/v2" || !reflect.DeepEqual(m.Components, wantComponents) || !reflect.DeepEqual(m.Constructions, wantConstructions) {
			t.Fatalf("manifest drift: %+v", m)
		}
		if len(m.Verifiers) != 1 || m.Verifiers[0].Family != contract.GCP || m.Verifiers[0].Class != gcpprovider.VerifierClass || m.Verifiers[0].Parse == nil {
			t.Fatal("verifier registry drift")
		}
		if len(m.Generators) != 0 {
			t.Fatal("composition manifest contains static generator builds")
		}
		if _, err := m.Verifiers[0].Parse(c.Trust.PublicKey); err != nil {
			t.Fatalf("registered verifier rejected P256: %v", err)
		}
		if _, err := m.Verifiers[0].Parse(nil); err == nil {
			t.Fatal("registered verifier accepted an empty key")
		}
	}
	m := CompatibilityManifest()
	check(m)
	for i := range m.Components {
		m.Components[i] = contract.ComponentImplementation{}
	}
	m.Verifiers[0] = contract.VerifierParser{}
	for i := range m.Constructions {
		m.Constructions[i] = contract.ConstructionClass{}
	}
	check(CompatibilityManifest())
}
