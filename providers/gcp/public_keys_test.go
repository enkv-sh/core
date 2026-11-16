package gcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
)

// full_only: false
func TestPublicEncryptionResolutionConstructsNoPrivateKeyAccess(t *testing.T) {
	constructions := func(source any) []token.Position {
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, "public_keys.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		var found []token.Position
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.CallExpr:
				name, ok := node.Fun.(*ast.Ident)
				if !ok {
					break
				}
				private := name.Name == "NewKeyAccess" || name.Name == "newKeyAccess"
				if name.Name == "new" && len(node.Args) == 1 {
					typ, ok := node.Args[0].(*ast.Ident)
					private = ok && typ.Name == "KeyAccess"
				}
				if private {
					found = append(found, positions.Position(node.Pos()))
				}
			case *ast.CompositeLit:
				if typ, ok := node.Type.(*ast.Ident); ok && typ.Name == "KeyAccess" {
					found = append(found, positions.Position(node.Pos()))
				}
			}
			return true
		})
		return found
	}
	for _, test := range []struct {
		name, source string
		want         int
	}{
		{"exported-constructor", "func resolve() { NewKeyAccess(config) }", 1},
		{"private-constructor", "func resolve() { newKeyAccess(config, transport) }", 1},
		{"pointer-literal", "func resolve() { _ = &KeyAccess{} }", 1},
		{"value-literal", "func resolve() { _ = KeyAccess{} }", 1},
		{"allocation", "func resolve() { _ = new(KeyAccess) }", 1},
		{"borrowed-route", "func resolve(k *KeyAccess) { k.resolveEncryptionKey(ctx, selector, protection, pinned) }", 0},
		{"text", "func resolve() { _ = \"NewKeyAccess(config)\" }", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if found := constructions("package fixture\n" + test.source); len(found) != test.want {
				t.Fatalf("private constructions = %v, want %d", found, test.want)
			}
		})
	}
	t.Run("public-metadata-owner", func(t *testing.T) {
		// Provider calls alone cannot detect an unused private route constructor.
		if found := constructions(nil); len(found) != 0 {
			t.Fatalf("public metadata owner constructs private KeyAccess at %v", found)
		}
	})
}

// full_only: false
func TestPublicSigningResolutionValidatesFetchedMaterial(t *testing.T) {
	der := anchorPublicKey(t)
	version := "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
	for _, mode := range []string{"normal", "recovery", "wrong-resource", "wrong-algorithm", "trailing-der", "malformed-der", "wrong-curve", "bad-crc", "missing-crc", "imported-recovery", "denied", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			role := contract.NormalSigningRole
			if mode == "recovery" || mode == "imported-recovery" {
				role = contract.RecoverySigningRole
			}
			var paths []string
			client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				paths = append(paths, r.URL.Path)
				if r.Method != http.MethodGet {
					t.Fatal("public lookup used private operation")
				}
				var out map[string]any
				switch r.URL.Path {
				case "/v1/" + version + "/publicKey":
					if mode == "denied" {
						return apiFailure(403, "forbidden"), nil
					}
					public := bytes.Clone(der)
					if mode == "trailing-der" {
						public = append(public, 0)
					}
					if mode == "malformed-der" {
						public = []byte("invalid")
					}
					if mode == "wrong-curve" {
						curve := elliptic.P384()
						// The uncompressed public base point is the same point as 1*G.
						point := make([]byte, 97)
						point[0] = 4
						curve.Params().Gx.FillBytes(point[1:49])
						curve.Params().Gy.FillBytes(point[49:])
						key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
						if err != nil {
							t.Fatal(err)
						}
						public, err = x509.MarshalPKIXPublicKey(key)
						if err != nil {
							t.Fatal(err)
						}
					}
					pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})
					out = map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "pem": string(pemBytes), "pemCrc32c": strconv.FormatUint(uint64(crc(pemBytes)), 10)}
					if mode == "wrong-resource" {
						out["name"] = version + "0"
					}
					if mode == "wrong-algorithm" {
						out["algorithm"] = "EC_SIGN_P384_SHA384"
					}
					if mode == "bad-crc" {
						out["pemCrc32c"] = "4294967296"
					}
					if mode == "missing-crc" {
						delete(out, "pemCrc32c")
					}
				case "/v1/" + version:
					out = map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"}
					if mode == "imported-recovery" {
						out["importTime"] = "2026-01-01T00:00:00Z"
					}
				default:
					t.Fatalf("unexpected public path %q", r.URL.Path)
				}
				body, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(body)), nil
			}), &credentials{})
			anchor, err := NewPublicSigningAnchor(ctx, PublicSigningAnchorConfig{Role: role, Client: client, Region: "us-central1", KeyVersion: version, CredentialRoute: "fixture-route"})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, fingerprint, reason := anchor.ResolveSigningKey(ctx)
			success := mode == "normal" || mode == "recovery"
			if success {
				if reason != contract.ReasonNone || !bytes.Equal(got, der) || fingerprint != contract.ID(sha256.Sum256(der)) {
					t.Fatal("wrong resolved signing material", reason)
				}
				want := []string{"/v1/" + version + "/publicKey"}
				if role == contract.RecoverySigningRole {
					want = append(want, "/v1/"+version)
				}
				if !slices.Equal(paths, want) {
					t.Fatal("wrong public requests", paths)
				}
			} else {
				want := contract.ReasonProof
				if mode == "denied" || mode == "cancelled" {
					want = contract.ReasonAccess
				}
				if reason != want || len(got) != 0 || !fingerprint.IsZero() {
					t.Fatal("wrong failed lookup result", reason, want)
				}
				wantCalls := 1
				if mode == "cancelled" {
					wantCalls = 0
				}
				if mode == "imported-recovery" {
					wantCalls = 2
				}
				if len(paths) != wantCalls {
					t.Fatal("wrong failed lookup request count")
				}
			}
			if mode == "cancelled" && len(paths) != 0 {
				t.Fatal("cancelled lookup sent request")
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationCalls, telemetry.OpSetupPublicKey, "", "") != 1 {
				t.Fatal("missing resolution telemetry")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

// full_only: false
func TestPublicEncryptionResolutionUsesNoBindingIdentities(t *testing.T) {
	b := encryptionBinding(t)
	for _, mode := range []string{"generated", "imported", "hsm", "wrong-resource", "wrong-purpose", "external", "trailing-der", "wrong-exponent", "wrong-modulus", "bad-crc", "missing-crc", "denied-metadata", "alias", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			selector := b.KeySelector
			if mode == "alias" {
				selector = strings.TrimSuffix(selector, "/1") + "/latest"
			}
			parent := strings.Join(strings.Split(b.KeySelector, "/")[:8], "/")
			calls := 0
			client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet {
					t.Fatal("public resolution used private operation")
				}
				var out map[string]any
				switch r.URL.Path {
				case "/v1/" + parent:
					out = map[string]any{"name": parent, "purpose": "ASYMMETRIC_DECRYPT"}
					if mode == "wrong-purpose" {
						out["purpose"] = "ASYMMETRIC_SIGN"
					}
				case "/v1/" + selector:
					if mode == "denied-metadata" {
						return apiFailure(403, "forbidden"), nil
					}
					out = map[string]any{"name": selector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"}
					if mode == "hsm" {
						out["protectionLevel"] = "HSM"
					}
					if mode == "imported" {
						delete(out, "generateTime")
						out["importTime"] = "2026-01-01T00:00:00Z"
						out["importJob"] = "projects/fixture-project/locations/us-central1/keyRings/ring/importJobs/job"
					}
					if mode == "external" {
						out["externalProtectionLevelOptions"] = map[string]any{"externalKeyUri": "external"}
					}
				case "/v1/" + selector + "/publicKey":
					public := bytes.Clone(b.SPKI)
					if mode == "trailing-der" {
						public = append(public, 0)
					}
					if mode == "wrong-exponent" || mode == "wrong-modulus" {
						key, err := x509.ParsePKIXPublicKey(public)
						if err != nil {
							t.Fatal(err)
						}
						rsaKey := key.(*rsa.PublicKey)
						if mode == "wrong-exponent" {
							rsaKey.E = 3
						} else {
							rsaKey.N.SetBit(rsaKey.N, 0, 0)
						}
						public, err = x509.MarshalPKIXPublicKey(rsaKey)
						if err != nil {
							t.Fatal(err)
						}
					}
					pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})
					out = map[string]any{"name": selector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "protectionLevel": "SOFTWARE", "pem": string(pemBytes), "pemCrc32c": strconv.FormatUint(uint64(crc(pemBytes)), 10)}
					if mode == "hsm" {
						out["protectionLevel"] = "HSM"
					}
					if mode == "wrong-resource" {
						out["name"] = selector + "0"
					}
					if mode == "bad-crc" {
						out["pemCrc32c"] = "4294967296"
					}
					if mode == "missing-crc" {
						delete(out, "pemCrc32c")
					}
				default:
					t.Fatal("wrong public resource")
				}
				body, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(body)), nil
			}), &credentials{})
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, fingerprint, protection, result := ResolveEncryptionKey(ctx, encryptionConfig(client), selector)
			if mode == "generated" || mode == "imported" || mode == "hsm" {
				wantProtection := contract.SoftwareProtection
				if mode == "hsm" {
					wantProtection = contract.HardwareProtection
				}
				if result.Status != enkvcrypto.KeyOK || protection != wantProtection || !bytes.Equal(got, b.SPKI) || fingerprint != contract.ID(sha256.Sum256(b.SPKI)) || calls != 3 || result.Uses != (enkvcrypto.KeyUses{Completed: 3}) {
					t.Fatal("wrong public resolution", result, calls)
				}
			} else {
				want := enkvcrypto.KeyInvalid
				if mode == "cancelled" {
					want = enkvcrypto.KeyCancelled
				}
				if mode == "denied-metadata" {
					want = enkvcrypto.KeyDenied
				}
				if result.Status != want || len(got) != 0 || protection != 0 || !fingerprint.IsZero() {
					t.Fatal("wrong failed lookup result", result, want)
				}
				wantCalls := 3
				if mode == "alias" || mode == "cancelled" {
					wantCalls = 0
				}
				if mode == "wrong-purpose" {
					wantCalls = 1
				}
				if mode == "external" || mode == "denied-metadata" {
					wantCalls = 2
				}
				if calls != wantCalls {
					t.Fatal("wrong failed lookup request count", calls, wantCalls)
				}
			}
			if (mode == "alias" || mode == "cancelled") && calls != 0 {
				t.Fatal("invalid lookup reached provider")
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationCalls, telemetry.OpSetupPublicKey, "", "") != 1 {
				t.Fatal("missing resolution telemetry")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

// full_only: false
func TestPublicEncryptionQualifierPinsExactSuccessorAcrossLocations(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	source := encryptionBinding(t)
	sourceBytes, err := contract.EncodeKMSBinding(source)
	if err != nil {
		t.Fatal(err)
	}
	binding := source
	binding.SPKI = bytes.Clone(source.SPKI)
	binding.KeySelector = "projects/successor-project/locations/europe-west1/keyRings/ring/cryptoKeys/successor/cryptoKeyVersions/2"
	parent := strings.Join(strings.Split(binding.KeySelector, "/")[:8], "/")
	calls := 0
	denied := false
	client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodGet || r.URL.Host != "europe-west1-cloudkms.googleapis.com" {
			t.Fatal("successor public lookup borrowed a source or private route")
		}
		var reply map[string]any
		switch r.URL.Path {
		case "/v1/" + parent:
			reply = map[string]any{"name": parent, "purpose": "ASYMMETRIC_DECRYPT"}
		case "/v1/" + binding.KeySelector:
			if denied {
				return apiFailure(403, "forbidden"), nil
			}
			reply = map[string]any{"name": binding.KeySelector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"}
		case "/v1/" + binding.KeySelector + "/publicKey":
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: source.SPKI})
			reply = map[string]any{"name": binding.KeySelector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "protectionLevel": "SOFTWARE", "pem": string(pemBytes), "pemCrc32c": strconv.FormatUint(uint64(crc(pemBytes)), 10)}
		default:
			t.Fatal("successor public lookup changed the exact key")
		}
		body, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		return response(200, string(body)), nil
	}), &credentials{})
	config := encryptionConfig(client)
	config.Project, config.Region, config.Endpoint = "successor-project", "europe-west1", "https://europe-west1-cloudkms.googleapis.com/"
	config.CredentialRoute = contract.Hash([]byte("successor public route"))
	qualifier, err := NewPublicEncryptionQualifier(ctx, config, binding)
	if err != nil || qualifier == nil || calls != 0 {
		t.Fatal("public qualifier construction performed lookup", err, calls)
	}
	if qualifier.Family() != binding.Provider || qualifier.CredentialRoute() != config.CredentialRoute {
		t.Fatal("public qualifier lost its selected provider or route")
	}
	if _, private := any(qualifier).(enkvcrypto.KeyAccess); private {
		t.Fatal("public qualifier exposes private decryption")
	}
	valid := binding
	valid.SPKI = bytes.Clone(binding.SPKI)
	clear(binding.SPKI)
	if got := qualifier.Qualify(ctx, valid); got != (enkvcrypto.KeyResult{Status: enkvcrypto.KeyOK, Uses: enkvcrypto.KeyUses{Completed: 3}}) || calls != 3 {
		t.Fatal("public qualifier did not own and qualify the exact successor", got, calls)
	}
	assertKeyTelemetry(t, snapshot(), telemetry.OpKeyQualify, "success", 1, 3)
	for _, test := range []struct {
		name   string
		change func(*contract.KMSBinding)
	}{
		{"binding", func(b *contract.KMSBinding) { b.BindingID = contract.Hash([]byte("other binding")) }},
		{"incarnation", func(b *contract.KMSBinding) { b.BindingIncarnationID = contract.Hash([]byte("other incarnation")) }},
		{"serial", func(b *contract.KMSBinding) { b.BindingSerial++ }},
		{"selector", func(b *contract.KMSBinding) { b.KeySelector += "0" }},
		{"provider", func(b *contract.KMSBinding) { b.Provider = contract.AWS }},
		{"profile", func(b *contract.KMSBinding) { b.WrapProfile++ }},
		{"protection", func(b *contract.KMSBinding) { b.ProtectionClass = contract.HardwareProtection }},
		{"public-key", func(b *contract.KMSBinding) { b.SPKI = nil }},
		{"fingerprint", func(b *contract.KMSBinding) { b.Fingerprint = contract.Hash([]byte("other public key")) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := valid
			test.change(&bad)
			before := calls
			if got := qualifier.Qualify(ctx, bad); got != (enkvcrypto.KeyResult{Status: enkvcrypto.KeyInvalid}) || calls != before {
				t.Fatal("different binding reached public lookup", got, calls, before)
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	before := calls
	if got := qualifier.Qualify(cancelled, valid); got != (enkvcrypto.KeyResult{Status: enkvcrypto.KeyCancelled}) || calls != before {
		t.Fatal("cancelled qualifier reached provider", got, calls, before)
	}
	denied = true
	if got := qualifier.Qualify(ctx, valid); got != (enkvcrypto.KeyResult{Status: enkvcrypto.KeyDenied, Uses: enkvcrypto.KeyUses{Completed: 1, Denied: 1}}) || calls != before+2 {
		t.Fatal("public qualifier lost actual denial evidence", got, calls, before)
	}
	if encoded, err := contract.EncodeKMSBinding(source); err != nil || !bytes.Equal(encoded, sourceBytes) {
		t.Fatal("successor public qualification changed the source binding", err)
	}
	if got := (*PublicEncryptionQualifier)(nil).CredentialRoute(); !got.IsZero() {
		t.Fatal("nil public qualifier has a route")
	}
	assertSafeTelemetry(t, snapshot())
}
