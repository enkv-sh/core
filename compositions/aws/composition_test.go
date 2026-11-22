package compositionaws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type inertCredentials struct{ calls atomic.Int32 }

func (c *inertCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls.Add(1)
	return aws.Credentials{}, errors.New("construction must not retrieve credentials")
}

func localConfig(t *testing.T) Config {
	t.Helper()
	storeCredentials, trustCredentials := &inertCredentials{}, &inertCredentials{}
	var networkCalls atomic.Int32
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		networkCalls.Add(1)
		return nil, errors.New("construction must not use the network")
	}}
	t.Cleanup(func() {
		if s, tr, n := storeCredentials.calls.Load(), trustCredentials.calls.Load(), networkCalls.Load(); s != 0 || tr != 0 || n != 0 {
			t.Errorf("construction calls: store credentials=%d trust credentials=%d network=%d", s, tr, n)
		}
	})
	// Fixed public P-256 generator SPKI; construction needs no private key.
	public, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		StoreClass: awsprovider.StoreClass, TrustClass: awsprovider.TrustClass, VerifierClass: awsprovider.VerifierClass,
		Store:     awsprovider.StoreConfig{Region: "us-east-1", Bucket: "fixture-bucket", ExpectedBucketOwner: "123456789012", Prefix: "fixture/state", Domain: contract.Hash([]byte("domain")), CredentialRoute: contract.Hash([]byte("store-route")), Credentials: storeCredentials, Transport: transport, Timeout: time.Second},
		Trust:     awsprovider.TrustConfig{Region: "us-east-1", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: public, CredentialRoute: contract.Hash([]byte("trust-route")), Credentials: trustCredentials, Transport: transport, Timeout: time.Second},
		KeyAccess: []awsprovider.KeyAccessConfig{{Region: "us-east-1", Account: "123456789012", CredentialRoute: contract.Hash([]byte("authority-kek-route")), Credentials: trustCredentials, Transport: transport, Timeout: time.Second}, {Region: "us-east-1", Account: "123456789012", CredentialRoute: contract.Hash([]byte("recovery-kek-route")), Credentials: trustCredentials, Transport: transport, Timeout: time.Second}},
	}
}

// full_only: false
func TestNewConstructsSelectedCell(t *testing.T) {
	c := localConfig(t)
	wantStore, err := awsprovider.NewStore(c.Store)
	if err != nil {
		t.Fatal(err)
	}
	wantTrust, err := awsprovider.NewTrust(c.Trust)
	if err != nil {
		t.Fatal(err)
	}
	cell, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cell.Store.(*awsprovider.Store); !ok {
		t.Fatalf("Store type = %T", cell.Store)
	}
	if _, ok := cell.Trust.(*awsprovider.Trust); !ok {
		t.Fatalf("Trust type = %T", cell.Trust)
	}
	d := cell.Store.Descriptor()
	if d != wantStore.Descriptor() || !d.Valid() || d.Family != contract.AWS || d.Prefix != c.Store.Prefix || d.HeadKey != c.Store.Prefix+"/HEAD" {
		t.Fatalf("Store descriptor = %+v; want %+v", d, wantStore.Descriptor())
	}
	if cell.Trust.Family() != contract.AWS || cell.Trust.Identity().IsZero() || cell.Trust.Identity() != wantTrust.Identity() {
		t.Fatal("Trust does not match the configured AWS binding")
	}
	h := sha256.New()
	h.Write([]byte("ENKV/CELL/AWS/v1\x00"))
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
				changed.Store.CredentialRoute = contract.Hash([]byte("another-store-route"))
			case "Trust":
				changed.Trust.Role = contract.RecoverySigningRole
			case "Trust credentials":
				changed.Trust.CredentialRoute = contract.Hash([]byte("another-trust-route"))
			}
			other, err := New(changed)
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
			c := localConfig(t)
			switch class {
			case "Store":
				c.StoreClass = "gcp-gcs-json-v2"
			case "legacy Store":
				c.StoreClass = "aws-s3-regional-v1"
			case "Trust":
				c.TrustClass = "gcp-cloudkms-p256-v1"
			case "Verifier":
				c.VerifierClass = "gcp-p256-spki-v1"
			}
			if cell, err := New(c); err != ErrClass || cell != (contract.Cell{}) {
				t.Fatalf("unknown %s class: cell=%+v error=%v", class, cell, err)
			}
		})
	}
}

// full_only: false
func TestClosedRegistries(t *testing.T) {
	public := localConfig(t).Trust.PublicKeyDER
	check := func(m contract.CompatibilityManifest) {
		t.Helper()
		wantComponents := []contract.ComponentImplementation{
			{Family: contract.AWS, Kind: contract.StoreComponentKind, Class: awsprovider.StoreClass, Module: "enkv.sh/providers/aws", Version: contract.CoreVersion},
			{Family: contract.AWS, Kind: contract.TrustComponentKind, Class: awsprovider.TrustClass, Module: "enkv.sh/providers/aws", Version: contract.CoreVersion},
		}
		wantConstructions := []contract.ConstructionClass{{Family: contract.AWS, Kind: contract.StoreComponentKind, Class: awsprovider.StoreClass}, {Family: contract.AWS, Kind: contract.TrustComponentKind, Class: awsprovider.TrustClass}}
		if m.Identity != contract.Hash([]byte("enkv/composition/aws/v1")) || m.Core != contract.CoreVersion || m.Engine != "state-session/v9" || m.Format != "canonical-state/v16" || m.ComponentContract != "store-trust-crypto/v9" || m.Crypto != "supplied-secret/v4" || m.CryptoProfile != "rsa3072-oaep-sha256-aes256gcm-hmacsha256/v2" || !reflect.DeepEqual(m.Components, wantComponents) || !reflect.DeepEqual(m.Constructions, wantConstructions) {
			t.Fatalf("manifest drift: %+v", m)
		}
		if len(m.Verifiers) != 1 || m.Verifiers[0].Family != contract.AWS || m.Verifiers[0].Class != awsprovider.VerifierClass || m.Verifiers[0].Parse == nil {
			t.Fatal("verifier registry drift")
		}
		if len(m.Generators) != 0 {
			t.Fatal("composition manifest contains static generator builds")
		}
		if _, err := m.Verifiers[0].Parse(public); err != nil {
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
