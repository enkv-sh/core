package awsprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"slices"
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
	for _, mode := range []string{"normal", "recovery", "wrong-resource", "wrong-purpose", "wrong-algorithm", "trailing-der", "malformed-der", "wrong-curve", "imported-recovery", "denied", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			c := testStoreConfig()
			role := contract.NormalSigningRole
			if mode == "recovery" || mode == "imported-recovery" {
				role = contract.RecoverySigningRole
			}
			arn := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
			var operations []string
			anchor, err := newPublicSigningAnchor(PublicSigningAnchorConfig{Role: role, Region: c.Region, KeyARN: arn, CredentialRoute: c.CredentialRoute, Credentials: c.Credentials, Timeout: c.Timeout}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				operation := r.Header.Get("X-Amz-Target")
				operations = append(operations, operation)
				var out map[string]any
				switch operation {
				case "TrentService.GetPublicKey":
					if mode == "denied" {
						return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
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
					out = map[string]any{"KeyId": arn, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ECDSA_SHA_256"}, "PublicKey": base64.StdEncoding.EncodeToString(public)}
					if mode == "wrong-resource" {
						out["KeyId"] = arn + "0"
					}
					if mode == "wrong-purpose" {
						out["KeyUsage"] = "ENCRYPT_DECRYPT"
					}
					if mode == "wrong-algorithm" {
						out["SigningAlgorithms"] = []string{"ECDSA_SHA_384"}
					}
				case "TrentService.DescribeKey":
					origin := "AWS_KMS"
					if mode == "imported-recovery" {
						origin = "EXTERNAL"
					}
					out = map[string]any{"KeyMetadata": map[string]any{"Arn": arn, "Enabled": true, "KeyState": "Enabled", "Origin": origin, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}}
				default:
					t.Fatalf("unexpected public operation %q", operation)
				}
				body, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(body), nil), nil
			}))
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
				want := []string{"TrentService.GetPublicKey"}
				if role == contract.RecoverySigningRole {
					want = append(want, "TrentService.DescribeKey")
				}
				if !slices.Equal(operations, want) {
					t.Fatal("wrong public operations", operations)
				}
				if &got[0] == &der[0] {
					t.Fatal("resolution borrowed input")
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
				if len(operations) != wantCalls {
					t.Fatal("wrong failed lookup request count")
				}
			}
			if mode == "cancelled" && len(operations) != 0 {
				t.Fatal("cancelled lookup sent a request")
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationCalls, telemetry.OpSetupPublicKey, "", "") != 1 {
				t.Fatal("missing public resolution telemetry")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

// full_only: false
func TestPublicSigningResolutionClassifiesTypedDenialsAtBothMetadataCalls(t *testing.T) {
	der := anchorPublicKey(t)
	for _, operation := range []string{"TrentService.GetPublicKey", "TrentService.DescribeKey"} {
		for _, status := range []int{400, 401, 403} {
			for _, code := range []string{"AccessDeniedException", "ValidationException"} {
				t.Run(fmt.Sprintf("%s/%d/%s", operation, status, code), func(t *testing.T) {
					t.Setenv("ENKV_TELEMETRY", "1")
					ctx, snapshot := collectTelemetry(t)
					c := testStoreConfig()
					arn := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
					var calls []string
					role := contract.NormalSigningRole
					if operation == "TrentService.DescribeKey" {
						role = contract.RecoverySigningRole
					}
					anchor, err := newPublicSigningAnchor(PublicSigningAnchorConfig{Role: role, Region: c.Region, KeyARN: arn, CredentialRoute: c.CredentialRoute, Credentials: c.Credentials, Timeout: c.Timeout}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
						name := r.Header.Get("X-Amz-Target")
						calls = append(calls, name)
						if name == operation {
							return response(status, `{"__type":"`+code+`","message":"private-provider-sentinel"}`, nil), nil
						}
						if operation != "TrentService.DescribeKey" || name != "TrentService.GetPublicKey" {
							t.Fatal("unexpected metadata call", name)
						}
						body, err := json.Marshal(map[string]any{"KeyId": arn, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ECDSA_SHA_256"}, "PublicKey": base64.StdEncoding.EncodeToString(der)})
						if err != nil {
							t.Fatal(err)
						}
						return response(200, string(body), nil), nil
					}))
					if err != nil {
						t.Fatal(err)
					}
					key, fingerprint, reason := anchor.ResolveSigningKey(ctx)
					want := contract.ReasonAccess
					if status == 400 && code != "AccessDeniedException" {
						want = contract.ReasonTransport
					}
					wantCalls := []string{"TrentService.GetPublicKey"}
					if role == contract.RecoverySigningRole {
						wantCalls = append(wantCalls, "TrentService.DescribeKey")
					}
					if reason != want || len(key) != 0 || !fingerprint.IsZero() || !slices.Equal(calls, wantCalls) {
						t.Fatal("metadata denial lost its typed reason or repeated calls", reason, want, calls)
					}
					assertSafeTelemetry(t, snapshot())
				})
			}
		}
	}
}

// full_only: false
func TestPublicEncryptionResolutionUsesNoBindingIdentities(t *testing.T) {
	b := encryptionBinding(t)
	for _, mode := range []string{"generated", "imported", "wrong-resource", "wrong-purpose", "wrong-origin", "trailing-der", "wrong-exponent", "wrong-modulus", "denied-metadata", "alias", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			selector := b.KeySelector
			if mode == "alias" {
				selector = "alias/key"
			}
			calls := 0
			k, err := newPublicEncryptionLookup(encryptionConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var out map[string]any
				switch r.Header.Get("X-Amz-Target") {
				case "TrentService.GetPublicKey":
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
					out = map[string]any{"KeyId": selector, "KeySpec": "RSA_3072", "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": []string{"RSAES_OAEP_SHA_256"}, "PublicKey": base64.StdEncoding.EncodeToString(public)}
					if mode == "wrong-resource" {
						out["KeyId"] = selector + "0"
					}
					if mode == "wrong-purpose" {
						out["KeyUsage"] = "SIGN_VERIFY"
					}
				case "TrentService.DescribeKey":
					if mode == "denied-metadata" {
						return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
					}
					origin := "AWS_KMS"
					if mode == "imported" {
						origin = "EXTERNAL"
					}
					if mode == "wrong-origin" {
						origin = "AWS_CLOUDHSM"
					}
					out = map[string]any{"KeyMetadata": map[string]any{"Arn": selector, "KeyId": strings.Split(selector, "key/")[1], "AWSAccountId": "123456789012", "KeySpec": "RSA_3072", "KeyUsage": "ENCRYPT_DECRYPT", "Enabled": true, "KeyState": "Enabled", "Origin": origin, "EncryptionAlgorithms": []string{"RSAES_OAEP_SHA_256"}}}
				default:
					t.Fatal("public resolution used private operation")
				}
				body, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(body), nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, protection, result := resolvePublicEncryptionKey(ctx, k, selector)
			if mode == "generated" || mode == "imported" {
				if result.Status != enkvcrypto.KeyOK || protection != contract.HardwareProtection || !bytes.Equal(got, b.SPKI) || calls != 2 || result.Uses != (enkvcrypto.KeyUses{Completed: 2}) {
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
				if result.Status != want || len(got) != 0 || protection != 0 {
					t.Fatal("wrong failed lookup result", result, want)
				}
				wantCalls := 1
				if mode == "alias" || mode == "cancelled" {
					wantCalls = 0
				}
				if mode == "wrong-origin" || mode == "denied-metadata" {
					wantCalls = 2
				}
				if calls != wantCalls {
					t.Fatal("wrong failed lookup request count", calls, wantCalls)
				}
			}
			if (mode == "alias" || mode == "cancelled") && calls != 0 {
				t.Fatal("invalid lookup reached provider")
			}
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
	binding.KeySelector = "arn:aws:kms:us-west-2:210987654321:key/87654321-1234-1234-1234-123456789012"
	config := encryptionConfig()
	config.Region, config.Account = "us-west-2", "210987654321"
	config.CredentialRoute = contract.Hash([]byte("successor public route"))
	calls := 0
	denied := false
	qualifier, err := newPublicEncryptionQualifier(config, binding, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "kms.us-west-2.amazonaws.com" {
			t.Fatal("successor lookup borrowed the source location")
		}
		var request struct{ KeyId string }
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.KeyId != binding.KeySelector {
			t.Fatal("successor lookup changed the exact key")
		}
		var reply map[string]any
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.GetPublicKey":
			reply = map[string]any{"KeyId": binding.KeySelector, "KeySpec": "RSA_3072", "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": []string{"RSAES_OAEP_SHA_256"}, "PublicKey": base64.StdEncoding.EncodeToString(source.SPKI)}
		case "TrentService.DescribeKey":
			if denied {
				return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
			}
			reply = map[string]any{"KeyMetadata": map[string]any{"Arn": binding.KeySelector, "KeyId": strings.Split(binding.KeySelector, "key/")[1], "AWSAccountId": "210987654321", "KeySpec": "RSA_3072", "KeyUsage": "ENCRYPT_DECRYPT", "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "EncryptionAlgorithms": []string{"RSAES_OAEP_SHA_256"}}}
		default:
			t.Fatal("public qualifier attempted a private operation")
		}
		body, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		return response(200, string(body), nil), nil
	}))
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
	if got := qualifier.Qualify(ctx, valid); got != (enkvcrypto.KeyResult{Status: enkvcrypto.KeyOK, Uses: enkvcrypto.KeyUses{Completed: 2}}) || calls != 2 {
		t.Fatal("public qualifier did not own and qualify the exact successor", got, calls)
	}
	assertKeyTelemetry(t, snapshot(), telemetry.OpKeyQualify, "success", 1, 2)
	for _, test := range []struct {
		name   string
		change func(*contract.KMSBinding)
	}{
		{"binding", func(b *contract.KMSBinding) { b.BindingID = contract.Hash([]byte("other binding")) }},
		{"incarnation", func(b *contract.KMSBinding) { b.BindingIncarnationID = contract.Hash([]byte("other incarnation")) }},
		{"serial", func(b *contract.KMSBinding) { b.BindingSerial++ }},
		{"selector", func(b *contract.KMSBinding) { b.KeySelector += "0" }},
		{"provider", func(b *contract.KMSBinding) { b.Provider = contract.GCP }},
		{"profile", func(b *contract.KMSBinding) { b.WrapProfile++ }},
		{"protection", func(b *contract.KMSBinding) { b.ProtectionClass = contract.SoftwareProtection }},
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
