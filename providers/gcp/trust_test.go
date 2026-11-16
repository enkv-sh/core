package gcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func signRequest(t *testing.T) contract.SignRequest {
	t.Helper()
	id := contract.Hash([]byte("id"))
	r, err := contract.NewBindingRequest(contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: id, PublicKey: id, Interpretation: id, ControlIncarnationID: id, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func trustConfig(client *Client, public []byte) TrustConfig {
	return TrustConfig{Client: client, Region: "us-central1", Endpoint: "https://us-central1-cloudkms.googleapis.com/", CredentialRoute: "fixture-route", KeyVersion: "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: public}
}

// full_only: false
func TestTrustIdentityKeepsPublicConstructionAcrossReplacement(t *testing.T) {
	public := make([][]byte, 2)
	for i := range public {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public[i], err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	creds := &credentials{}
	c := trustConfig(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction sent a request")
		return nil, nil
	}), creds), public[0])
	before, err := NewTrust(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		same   bool
		mutate func(*TrustConfig)
	}{
		{"explicit-normal-role", true, func(c *TrustConfig) { c.Role = contract.NormalSigningRole }},
		{"credential-route", true, func(c *TrustConfig) { c.CredentialRoute = "successor-route" }},
		{"signing-key", true, func(c *TrustConfig) {
			c.KeyVersion = strings.Replace(c.KeyVersion, "/cryptoKeys/key/", "/cryptoKeys/successor/", 1)
			c.PublicKey = public[1]
		}},
		{"same-public-key-new-version", true, func(c *TrustConfig) { c.KeyVersion = strings.TrimSuffix(c.KeyVersion, "/1") + "/2" }},
		{"key-project", true, func(c *TrustConfig) {
			c.KeyVersion = strings.Replace(c.KeyVersion, "/fixture-project/", "/successor-project/", 1)
		}},
		{"key-ring", true, func(c *TrustConfig) {
			c.KeyVersion = strings.Replace(c.KeyVersion, "/keyRings/ring/", "/keyRings/successor-ring/", 1)
		}},
		{"recovery-role", false, func(c *TrustConfig) { c.Role = contract.RecoverySigningRole }},
		{"regional-endpoint", false, func(c *TrustConfig) {
			c.Region = "europe-west1"
			c.Endpoint = "https://europe-west1-cloudkms.googleapis.com/"
			c.KeyVersion = strings.Replace(c.KeyVersion, "/us-central1/", "/europe-west1/", 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			afterConfig := c
			tc.mutate(&afterConfig)
			after, err := NewTrust(context.Background(), afterConfig)
			if err != nil {
				t.Fatal(err)
			}
			if after.Identity().IsZero() || (before.Identity() == after.Identity()) != tc.same {
				t.Fatal("Trust identity does not identify the stable public construction")
			}
		})
	}
	if creds.calls != 0 {
		t.Fatal("construction accessed credentials")
	}
}

// full_only: false
func TestTrustReplacementKeepsExactPrivateRoute(t *testing.T) {
	keys := make([]*ecdsa.PrivateKey, 2)
	public := make([][]byte, len(keys))
	for i := range keys {
		var err error
		keys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public[i], err = x509.MarshalPKIXPublicKey(&keys[i].PublicKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name     string
		role     uint8
		keyIndex int
	}{
		{"normal", contract.NormalSigningRole, 1},
		{"recovery", contract.RecoverySigningRole, 1},
		{"normal-credentials-only", contract.NormalSigningRole, 0},
		{"recovery-credentials-only", contract.RecoverySigningRole, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role := tc.role
			oldCredentials := &actorCredentials{err: errors.New("retired credential unavailable")}
			newCredentials := &actorCredentials{token: "successor-token"}
			requests := 0
			old := trustConfig(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("retired route sent a request")
				return nil, nil
			}), oldCredentials), public[0])
			old.Role = role
			before, err := NewTrust(context.Background(), old)
			if err != nil {
				t.Fatal(err)
			}
			id := contract.Hash([]byte("replacement"))
			binding := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: role, Provider: contract.GCP, SigningProfile: 1, BindingID: id, KeySelector: old.KeyVersion, SPKI: public[0], Fingerprint: contract.Hash(public[0]), Binding: contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: before.Identity(), PublicKey: contract.Hash(public[0]), Interpretation: contract.InterpretationID(), ControlIncarnationID: id, Epoch: 2}}
			successor := old
			if tc.keyIndex == 1 {
				successor.KeyVersion = "projects/successor-project/locations/us-central1/keyRings/successor-ring/cryptoKeys/successor/cryptoKeyVersions/2"
				successor.PublicKey = public[1]
				binding.KeySelector = successor.KeyVersion
				binding.SPKI, binding.Fingerprint, binding.Binding.PublicKey = public[1], contract.Hash(public[1]), contract.Hash(public[1])
			}
			originalBinding := binding
			originalBinding.SPKI = append([]byte(nil), binding.SPKI...)
			successor.CredentialRoute = "successor-route"
			successor.Client = makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.URL.Host != "us-central1-cloudkms.googleapis.com" || r.Header.Get("Authorization") != "Bearer successor-token" {
					t.Fatal("request did not use the exact successor endpoint and credential")
				}
				var output map[string]any
				switch r.URL.Path {
				case "/v1/" + successor.KeyVersion + "/publicKey":
					if r.Method != http.MethodGet {
						t.Fatal("unexpected public key operation")
					}
					encoded := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public[tc.keyIndex]}))
					output = map[string]any{"name": successor.KeyVersion, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "pem": encoded, "pemCrc32c": strconv.FormatUint(uint64(crc([]byte(encoded))), 10)}
				case "/v1/" + successor.KeyVersion:
					if r.Method != http.MethodGet {
						t.Fatal("unexpected key metadata operation")
					}
					output = map[string]any{"name": successor.KeyVersion, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "state": "ENABLED", "generateTime": "2026-01-01T00:00:00.123456789Z"}
				case "/v1/" + successor.KeyVersion + ":asymmetricSign":
					var input struct {
						Digest    struct{ SHA256 string } `json:"digest"`
						DigestCRC string                  `json:"digestCrc32c"`
					}
					if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&input) != nil {
						t.Fatal("unexpected signing operation")
					}
					digest, err := base64.StdEncoding.DecodeString(input.Digest.SHA256)
					if err != nil || len(digest) != 32 || input.DigestCRC != strconv.FormatUint(uint64(crc(digest)), 10) {
						t.Fatal("signing request changed the admitted profile")
					}
					signature, err := ecdsa.SignASN1(rand.Reader, keys[tc.keyIndex], digest)
					if err != nil {
						t.Fatal(err)
					}
					output = map[string]any{"name": successor.KeyVersion, "verifiedDigestCrc32c": true, "signature": base64.StdEncoding.EncodeToString(signature), "signatureCrc32c": strconv.FormatUint(uint64(crc(signature)), 10)}
				default:
					t.Fatal("request used another key or provider operation")
				}
				body, err := json.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(body)), nil
			}), newCredentials)
			after, err := NewTrust(context.Background(), successor)
			if err != nil {
				t.Fatal(err)
			}
			if after.Identity() != before.Identity() {
				t.Fatal("credential or key change changed the public Trust identity")
			}
			for _, mutate := range []func(*contract.PublicSigningBinding){
				func(b *contract.PublicSigningBinding) {
					if tc.keyIndex == 0 {
						b.KeySelector = "projects/successor-project/locations/us-central1/keyRings/successor-ring/cryptoKeys/successor/cryptoKeyVersions/2"
					} else {
						b.KeySelector = old.KeyVersion
					}
				},
				func(b *contract.PublicSigningBinding) {
					b.SPKI, b.Fingerprint, b.Binding.PublicKey = public[1-tc.keyIndex], contract.Hash(public[1-tc.keyIndex]), contract.Hash(public[1-tc.keyIndex])
				},
				func(b *contract.PublicSigningBinding) { b.Binding.Trust = id },
				func(b *contract.PublicSigningBinding) { b.Provider = contract.AWS },
				func(b *contract.PublicSigningBinding) { b.Role = 3 - role },
				func(b *contract.PublicSigningBinding) { b.SigningProfile++ },
			} {
				bad := binding
				mutate(&bad)
				if got := after.QualifySigningBinding(context.Background(), bad); got.Reason != contract.ReasonConstruction || got.Qualified != 0 {
					t.Fatal("another exact signing binding was qualified", got)
				}
			}
			if requests != 0 || oldCredentials.calls != 0 || newCredentials.calls != 0 {
				t.Fatal("invalid binding reached a private route")
			}
			if got := after.QualifySigningBinding(context.Background(), binding); got.Reason != contract.ReasonNone || got.Qualified != 1 {
				t.Fatal("successor qualification failed", got)
			}
			req, err := contract.NewBindingRequest(binding.Binding)
			if role == contract.RecoverySigningRole {
				req, err = contract.NewK3BasisRequest(binding)
			}
			if err != nil {
				t.Fatal(err)
			}
			got := after.Sign(context.Background(), req)
			digest := req.Digest()
			if got.Reason != contract.ReasonNone || !ecdsa.VerifyASN1(&keys[tc.keyIndex].PublicKey, digest[:], got.Signature) || ecdsa.VerifyASN1(&keys[1-tc.keyIndex].PublicKey, digest[:], got.Signature) {
				t.Fatal("successor signature was not bound to its exact verifier")
			}
			if !reflect.DeepEqual(binding, originalBinding) {
				t.Fatal("qualification or signing changed the input public binding")
			}
			want := 2
			if role == contract.RecoverySigningRole {
				want++
			}
			if requests != want || newCredentials.calls != want || oldCredentials.calls != 0 {
				t.Fatalf("requests=%d successor credentials=%d retired credentials=%d", requests, newCredentials.calls, oldCredentials.calls)
			}
		})
	}
}

// full_only: false
func TestRecoverySigningQualificationRequiresGeneratedOriginMetadata(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	type responseChange func(publicKey, version map[string]any)
	for _, tc := range []struct {
		name, protection string
		role             uint8
		change           responseChange
		want             bool
	}{
		{name: "generated-software", protection: "SOFTWARE", role: contract.RecoverySigningRole, want: true},
		{name: "generated-hsm", protection: "HSM", role: contract.RecoverySigningRole, want: true},
		{name: "normal-signing-needs-no-origin-metadata", protection: "SOFTWARE", role: contract.NormalSigningRole, want: true, change: func(_ map[string]any, version map[string]any) { delete(version, "generateTime") }},
		{name: "missing-generate-time", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { delete(version, "generateTime") }},
		{name: "malformed-generate-time", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { version["generateTime"] = "not-rfc3339" }},
		{name: "import-time", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { version["importTime"] = "2026-01-01T00:00:00Z" }},
		{name: "import-job", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) {
			version["importJob"] = "projects/fixture-project/locations/us-central1/keyRings/ring/importJobs/job"
		}},
		{name: "reimport-eligible", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { version["reimportEligible"] = true }},
		{name: "external-options", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) {
			version["externalProtectionLevelOptions"] = map[string]any{"externalKeyUri": "external"}
		}},
		{name: "null-external-options", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) {
			version["externalProtectionLevelOptions"] = nil
		}},
		{name: "wrong-name", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { version["name"] = "other" }},
		{name: "wrong-state", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { version["state"] = "DISABLED" }},
		{name: "wrong-algorithm", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { version["algorithm"] = "EC_SIGN_P384_SHA384" }},
		{name: "wrong-protection", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(_ map[string]any, version map[string]any) { version["protectionLevel"] = "HSM" }},
		{name: "wrong-spki", protection: "SOFTWARE", role: contract.RecoverySigningRole, change: func(publicKey map[string]any, _ map[string]any) {
			pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherPublic}))
			publicKey["pem"] = pemValue
			publicKey["pemCrc32c"] = strconv.FormatUint(uint64(crc([]byte(pemValue))), 10)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			calls := 0
			var config TrustConfig
			config = trustConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
				publicKey := map[string]any{"name": config.KeyVersion, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": tc.protection, "pem": pemValue, "pemCrc32c": strconv.FormatUint(uint64(crc([]byte(pemValue))), 10)}
				version := map[string]any{"name": config.KeyVersion, "algorithm": "EC_SIGN_P256_SHA256", "state": "ENABLED", "protectionLevel": tc.protection, "generateTime": "2026-01-01T00:00:00.123456789Z"}
				if tc.change != nil {
					tc.change(publicKey, version)
				}
				var output map[string]any
				switch r.URL.Path {
				case "/v1/" + config.KeyVersion + "/publicKey":
					output = publicKey
				case "/v1/" + config.KeyVersion:
					if tc.role != contract.RecoverySigningRole {
						t.Fatal("normal signing requested recovery origin metadata")
					}
					output = version
				default:
					t.Fatal("qualification used another resource")
				}
				body, err := json.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(body)), nil
			}), &credentials{}), public)
			config.Role = tc.role
			trust, err := NewTrust(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			id := contract.Hash([]byte("qualification"))
			binding := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: tc.role, Provider: contract.GCP, SigningProfile: 1, BindingID: id, KeySelector: config.KeyVersion, SPKI: public, Fingerprint: contract.Hash(public), Binding: contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: trust.Identity(), PublicKey: contract.Hash(public), Interpretation: contract.InterpretationID(), ControlIncarnationID: id, Epoch: 1}}
			got := trust.QualifySigningBinding(ctx, binding)
			if tc.want {
				if got.Reason != contract.ReasonNone || got.Qualified != 1 {
					t.Fatal("complete signing metadata refused", got)
				}
			} else if got.Reason != contract.ReasonProof || got.Qualified != 0 {
				t.Fatal("incomplete recovery signing metadata accepted", got)
			}
			wantCalls := 2
			if tc.role == contract.NormalSigningRole || tc.name == "wrong-spki" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("qualification calls=%d want=%d", calls, wantCalls)
			}
			metricResult := "invalid"
			if tc.want {
				metricResult = "success"
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationResults, telemetry.OpTrustQualify, metricResult, "") != 1 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpTrustQualify, "", "") != int64(calls) {
				t.Error("qualification operation or owned HTTP metrics differ")
			}
		})
	}
}

// full_only: false
func TestKMSSignUsesKeyLocation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []struct{ region, host string }{
		{"us-central1", "us-central1-cloudkms.googleapis.com"},
		{"australia-southeast1", "australia-southeast1-cloudkms.googleapis.com"},
		{"europe-west1", "europe-west1-cloudkms.googleapis.com"},
	} {
		t.Run(location.region, func(t *testing.T) {
			calls := 0
			creds := &credentials{}
			var c TrustConfig
			c = trustConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" || r.URL.Host != location.host || r.URL.Path != "/v1/"+c.KeyVersion+":asymmetricSign" {
					t.Fatalf("unexpected signing route: %s", r.URL)
				}
				return apiFailure(503, "backendError"), nil
			}), creds), public)
			c.Region = location.region
			c.Endpoint = "https://" + location.host + "/"
			c.KeyVersion = strings.Replace(c.KeyVersion, "/us-central1/", "/"+location.region+"/", 1)
			trust, err := NewTrust(context.Background(), c)
			if err != nil {
				t.Fatalf("documented KMS location refused: %v", err)
			}
			if got := trust.Sign(context.Background(), signRequest(t)); got.Reason != contract.ReasonTransport || calls != 1 || creds.calls != 1 {
				t.Fatalf("sign result=%+v sends=%d credentials=%d", got, calls, creds.calls)
			}
		})
	}
}

// full_only: false
func TestKMSExactDigestAndProofValidation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "null", "empty object", "array", "string", "number", "malformed JSON", "wrong key", "missing digest check", "missing signature checksum", "noncanonical signature checksum", "bad signature checksum", "invalid signature", "oversize signature", "lost reply", "503"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			creds := &credentials{}
			var c TrustConfig
			c = trustConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.Host != "us-central1-cloudkms.googleapis.com" || r.URL.Path != "/v1/"+c.KeyVersion+":asymmetricSign" || r.GetBody != nil {
					t.Fatalf("KMS request %s %s", r.Method, r.URL)
				}
				var fields struct {
					Digest struct {
						SHA256 string `json:"sha256"`
					} `json:"digest"`
					DigestCRC string `json:"digestCrc32c"`
				}
				if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
					t.Fatal(err)
				}
				digest, err := base64.StdEncoding.DecodeString(fields.Digest.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				want := signRequest(t).Digest()
				if !bytes.Equal(digest, want[:]) || fields.DigestCRC != strconv.FormatUint(uint64(crc(digest)), 10) {
					t.Fatal("wrong digest/CRC")
				}
				if mode == "lost reply" {
					return nil, io.ErrUnexpectedEOF
				}
				if mode == "503" {
					return apiFailure(503, "backendError"), nil
				}
				for shape, body := range map[string]string{"null": "null", "empty object": "{}", "array": "[]", "string": `"signature"`, "number": "1", "malformed JSON": "{"} {
					if mode == shape {
						return response(200, body), nil
					}
				}
				signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "invalid signature" {
					signature[0] ^= 1
				}
				if mode == "oversize signature" {
					signature = make([]byte, 73)
				}
				out := map[string]any{"name": c.KeyVersion, "verifiedDigestCrc32c": true, "signature": base64.StdEncoding.EncodeToString(signature), "signatureCrc32c": strconv.FormatUint(uint64(crc(signature)), 10)}
				switch mode {
				case "wrong key":
					out["name"] = c.KeyVersion + "0"
				case "missing digest check":
					delete(out, "verifiedDigestCrc32c")
				case "bad signature checksum":
					out["signatureCrc32c"] = "-1"
				case "missing signature checksum":
					delete(out, "signatureCrc32c")
				case "noncanonical signature checksum":
					out["signatureCrc32c"] = "0" + out["signatureCrc32c"].(string)
				}
				raw, _ := json.Marshal(out)
				return response(200, string(raw)), nil
			}), creds), public)
			trust, err := NewTrust(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			if creds.calls != 0 {
				t.Fatal("construction fetched key/credentials")
			}
			got := trust.Sign(context.Background(), signRequest(t))
			if mode == "valid" {
				digest := signRequest(t).Digest()
				if got.Reason != contract.ReasonNone || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], got.Signature) {
					t.Fatal(got)
				}
			} else {
				want := contract.ReasonProof
				switch mode {
				case "array", "string", "number", "malformed JSON", "lost reply", "503":
					want = contract.ReasonTransport
				}
				if got.Reason != want || len(got.Signature) != 0 {
					t.Fatal(got)
				}
			}
			if calls != 1 || creds.calls != 1 {
				t.Fatalf("send=%d credentials=%d", calls, creds.calls)
			}
		})
	}
}

// full_only: false
func TestTrustRejectsWrongProvisioningWithoutCredentials(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	creds := &credentials{}
	c := trustConfig(makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected send"); return nil, nil }), creds), public)
	for _, mutate := range []func(*TrustConfig){
		func(c *TrustConfig) { c.CredentialRoute = "" },
		func(c *TrustConfig) { c.CredentialRoute = "route\n" },
		func(c *TrustConfig) { c.Role = 3 },
		func(c *TrustConfig) { c.Endpoint = "https://cloudkms.googleapis.com/" },
		func(c *TrustConfig) { c.Endpoint = "https://europe-west1-cloudkms.googleapis.com/" },
		func(c *TrustConfig) { c.Endpoint = "https://cloudkms.us-central1.rep.googleapis.com/" },
		func(c *TrustConfig) { c.Algorithm = "RSA_SIGN_PSS_2048_SHA256" }, func(c *TrustConfig) { c.Purpose = "ENCRYPT_DECRYPT" }, func(c *TrustConfig) {
			c.KeyVersion = strings.Replace(c.KeyVersion, "/us-central1/", "/europe-west1/", 1)
		}, func(c *TrustConfig) { c.KeyVersion = strings.TrimSuffix(c.KeyVersion, "/1") }, func(c *TrustConfig) { c.PublicKey = append(c.PublicKey, 0) }} {
		bad := c
		mutate(&bad)
		if _, err := NewTrust(context.Background(), bad); err == nil {
			t.Fatal("invalid provisioning accepted")
		}
	}
	trust, err := NewTrust(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if got := trust.Sign(context.Background(), contract.SignRequest{}); got.Reason != contract.ReasonProof {
		t.Fatal(got)
	}
	if creds.calls != 0 {
		t.Fatal("invalid request accessed credential")
	}
}

// full_only: false
func TestTrustQualificationKeepsIndependentVerifier(t *testing.T) {
	calls := 0
	client := makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		t.Fatal("substituted verifier reached public lookup")
		return nil, nil
	}), &credentials{})
	config := trustConfig(client, anchorPublicKey(t))
	trust, err := NewTrust(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	binding := anchorBinding(contract.NormalSigningRole, config.KeyVersion, anchorPublicKey(t), trust.Identity())
	got := trust.QualifySigningBinding(context.Background(), binding)
	if got != (contract.SigningQualificationResult{Reason: contract.ReasonConstruction}) || calls != 0 {
		t.Fatal("ordinary Trust lost its independent pin", got, calls)
	}
}
