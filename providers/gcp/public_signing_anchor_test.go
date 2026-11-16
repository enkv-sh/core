package gcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func anchorPublicKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func anchorBinding(role uint8, version string, der []byte, trust contract.ID) contract.PublicSigningBinding {
	id := contract.Hash([]byte("public anchor binding"))
	fingerprint := contract.Hash(der)
	return contract.PublicSigningBinding{
		Schema: contract.CanonicalSchema, Role: role, Provider: contract.GCP,
		SigningProfile: contract.P256SigningProfile, BindingID: id, KeySelector: version,
		SPKI: der, Fingerprint: fingerprint,
		Binding: contract.BindingSubject{Domain: id, Coordinate: id, Store: id,
			Trust: trust, PublicKey: fingerprint, Interpretation: contract.InterpretationID(),
			ControlIncarnationID: id, Epoch: 1},
	}
}

// full_only: false
func TestPublicSigningAnchorPinsOneVersionAndHasNoSign(t *testing.T) {
	der, otherDER := anchorPublicKey(t), anchorPublicKey(t)
	for _, role := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
		t.Run(map[uint8]string{contract.NormalSigningRole: "normal", contract.RecoverySigningRole: "recovery"}[role], func(t *testing.T) {
			version := "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
			var paths []string
			creds := &credentials{}
			client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				paths = append(paths, r.URL.Path)
				if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "us-central1-cloudkms.googleapis.com" {
					t.Fatal("public anchor sent a non-GET request")
				}
				var reply map[string]any
				switch r.URL.Path {
				case "/v1/" + version + "/publicKey":
					pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
					reply = map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "pem": string(pemBytes), "pemCrc32c": strconv.FormatUint(uint64(crc(pemBytes)), 10)}
				case "/v1/" + version:
					reply = map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"}
				default:
					t.Fatalf("public anchor requested another resource: %q", r.URL.Path)
				}
				encoded, err := json.Marshal(reply)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(encoded)), nil
			}), creds)
			anchor, err := NewPublicSigningAnchor(context.Background(), PublicSigningAnchorConfig{Role: role, Client: client,
				Region: "us-central1", KeyVersion: version, CredentialRoute: "fixture-route"})
			if err != nil {
				t.Fatal(err)
			}
			if _, has := reflect.TypeOf(anchor).MethodByName("Sign"); has {
				t.Fatal("public anchor exposes Sign")
			}
			existing := trustConfig(client, der)
			existing.Role = role
			trust, err := NewTrust(context.Background(), existing)
			if err != nil || anchor.Identity() != trust.Identity() {
				t.Fatalf("public anchor lost the selected Trust construction identity: %v", err)
			}
			binding := anchorBinding(role, version, der, anchor.identity)
			wrongVersion := binding
			wrongVersion.KeySelector = strings.TrimSuffix(version, "/1") + "/2"
			if got := anchor.QualifySigningBinding(context.Background(), wrongVersion); got.Reason != contract.ReasonConstruction || len(paths) != 0 || creds.calls != 0 {
				t.Fatalf("selected alternate version entered lookup: %+v, %v", got, paths)
			}
			for _, change := range []func(*contract.PublicSigningBinding){
				func(b *contract.PublicSigningBinding) { b.Role = 3 - role },
				func(b *contract.PublicSigningBinding) { b.Provider = contract.AWS },
				func(b *contract.PublicSigningBinding) { b.SigningProfile++ },
				func(b *contract.PublicSigningBinding) { b.Fingerprint = contract.Hash([]byte("wrong fingerprint")) },
				func(b *contract.PublicSigningBinding) { b.SPKI = []byte("malformed SPKI") },
			} {
				bad := binding
				change(&bad)
				if got := anchor.QualifySigningBinding(context.Background(), bad); got.Reason != contract.ReasonConstruction || len(paths) != 0 || creds.calls != 0 {
					t.Fatal("unbound signing evidence entered lookup", got)
				}
			}
			wrongTrust := binding
			wrongTrust.Binding.Trust = contract.Hash([]byte("wrong trust construction"))
			if got := anchor.QualifySigningBinding(context.Background(), wrongTrust); got.Reason != contract.ReasonConstruction || len(paths) != 0 || creds.calls != 0 {
				t.Fatalf("wrong trust construction entered lookup: %+v, %v", got, paths)
			}
			wrongKey := anchorBinding(role, version, otherDER, anchor.identity)
			if got := anchor.QualifySigningBinding(context.Background(), wrongKey); got.Reason != contract.ReasonProof || !slices.Equal(paths, []string{"/v1/" + version + "/publicKey"}) {
				t.Fatalf("wrong SPKI accepted: %+v, %v", got, paths)
			}
			paths = nil
			digest, err := contract.SigningBindingDigest(binding)
			if err != nil {
				t.Fatal(err)
			}
			got := anchor.QualifySigningBinding(context.Background(), binding)
			wantRole := contract.NormalSignerTarget
			wantPaths := []string{"/v1/" + version + "/publicKey"}
			if role == contract.RecoverySigningRole {
				wantRole = contract.RecoverySignerTarget
				wantPaths = append(wantPaths, "/v1/"+version)
			}
			if got != (contract.SigningQualificationResult{TargetRole: wantRole, SigningBindingDigest: digest, Provider: contract.GCP, Qualified: 1}) || !slices.Equal(paths, wantPaths) {
				t.Fatalf("public qualification=%+v paths=%v", got, paths)
			}
		})
	}
}

// full_only: false
func TestPublicSigningAnchorNilIdentity(t *testing.T) {
	if got := (*PublicSigningAnchor)(nil).Identity(); !got.IsZero() {
		t.Fatal("nil public anchor has a construction identity")
	}
}

// full_only: false
func TestPublicSigningAnchorRejectsUnpinnedConstruction(t *testing.T) {
	client := makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction sent a request")
		return nil, nil
	}), &credentials{})
	c := PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Client: client,
		Region: "us-central1", KeyVersion: "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", CredentialRoute: "fixture-route"}
	for _, change := range []func(*PublicSigningAnchorConfig){
		func(c *PublicSigningAnchorConfig) { c.Role = 0 },
		func(c *PublicSigningAnchorConfig) { c.Role = 3 },
		func(c *PublicSigningAnchorConfig) {
			c.KeyVersion = "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/latest"
		},
		func(c *PublicSigningAnchorConfig) { c.Region = "us-east1" },
		func(c *PublicSigningAnchorConfig) { c.CredentialRoute = "" },
		func(c *PublicSigningAnchorConfig) { c.Client = nil },
	} {
		bad := c
		change(&bad)
		if anchor, err := NewPublicSigningAnchor(context.Background(), bad); err != ErrConstruction || anchor != nil {
			t.Fatalf("unpinned public anchor accepted: %v, %v", anchor, err)
		}
	}
	if _, err := NewPublicSigningAnchor(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestPublicSigningAnchorRefusesIncompleteRemoteEvidence(t *testing.T) {
	der := anchorPublicKey(t)
	version := "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
	for _, tc := range []struct {
		mode  string
		want  contract.Reason
		calls int
	}{
		{"public-denied", contract.ReasonAccess, 1},
		{"public-unavailable", contract.ReasonTransport, 1},
		{"public-missing", contract.ReasonTransport, 1},
		{"public-physical-503-body-404", contract.ReasonTransport, 1},
		{"public-physical-503-body-403", contract.ReasonTransport, 1},
		{"public-wrong-version", contract.ReasonProof, 1},
		{"public-wrong-algorithm", contract.ReasonProof, 1},
		{"public-wrong-protection", contract.ReasonProof, 1},
		{"public-crc-negative", contract.ReasonProof, 1},
		{"public-crc-mismatch", contract.ReasonProof, 1},
		{"public-crc-noncanonical", contract.ReasonProof, 1},
		{"public-pem-trailing", contract.ReasonProof, 1},
		{"public-pem-headers", contract.ReasonProof, 1},
		{"public-malformed", contract.ReasonTransport, 1},
		{"public-bad-pem", contract.ReasonProof, 1},
		{"public-missing-crc", contract.ReasonProof, 1},
		{"public-crc-out-of-range", contract.ReasonProof, 1},
		{"public-truncated", contract.ReasonTransport, 1},
		{"public-overlimit", contract.ReasonMalformed, 1},
		{"metadata-imported", contract.ReasonProof, 2},
		{"metadata-denied", contract.ReasonAccess, 2},
		{"metadata-missing", contract.ReasonTransport, 2},
		{"metadata-physical-503-body-404", contract.ReasonTransport, 2},
		{"metadata-physical-503-body-403", contract.ReasonTransport, 2},
		{"metadata-wrong-version", contract.ReasonProof, 2},
		{"metadata-disabled", contract.ReasonProof, 2},
		{"metadata-wrong-algorithm", contract.ReasonProof, 2},
		{"metadata-wrong-protection", contract.ReasonProof, 2},
		{"metadata-missing-origin", contract.ReasonProof, 2},
		{"metadata-external-null", contract.ReasonProof, 2},
		{"metadata-lost", contract.ReasonTransport, 2},
		{"metadata-truncated", contract.ReasonTransport, 2},
		{"metadata-overlimit", contract.ReasonMalformed, 2},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			calls := 0
			client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.Host != "us-central1-cloudkms.googleapis.com" {
					t.Fatal("public anchor sent an unexpected request")
				}
				switch r.URL.Path {
				case "/v1/" + version + "/publicKey":
					if tc.mode == "public-missing" {
						return response(404, `{"error":{"code":404,"status":"NOT_FOUND"}}`), nil
					}
					if tc.mode == "public-physical-503-body-404" {
						return response(503, `{"error":{"code":404,"status":"NOT_FOUND"}}`), nil
					}
					if tc.mode == "public-physical-503-body-403" {
						return response(503, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`), nil
					}
					if tc.mode == "public-denied" {
						return apiFailure(403, "forbidden"), nil
					}
					if tc.mode == "public-unavailable" {
						return apiFailure(503, "backendError"), nil
					}
					if tc.mode == "public-overlimit" {
						return response(200, strings.Repeat("x", maxJSON+1)), nil
					}
					if tc.mode == "public-malformed" {
						return response(200, "{"), nil
					}
					pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
					if tc.mode == "public-bad-pem" {
						pemBytes = []byte("not a PEM")
					}
					out := map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "pem": string(pemBytes), "pemCrc32c": strconv.FormatUint(uint64(crc(pemBytes)), 10)}
					switch tc.mode {
					case "public-wrong-version":
						out["name"] = version + "0"
					case "public-wrong-algorithm":
						out["algorithm"] = "EC_SIGN_P384_SHA384"
					case "public-wrong-protection":
						out["protectionLevel"] = "EXTERNAL"
					case "public-crc-negative":
						out["pemCrc32c"] = "-1"
					case "public-crc-mismatch":
						out["pemCrc32c"] = strconv.FormatUint(uint64(crc(pemBytes)^1), 10)
					case "public-crc-noncanonical":
						out["pemCrc32c"] = "0" + out["pemCrc32c"].(string)
					case "public-pem-trailing":
						out["pem"] = string(pemBytes) + "trailing"
						out["pemCrc32c"] = strconv.FormatUint(uint64(crc([]byte(out["pem"].(string)))), 10)
					case "public-pem-headers":
						headerPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der, Headers: map[string]string{"Comment": "header"}})
						out["pem"] = string(headerPEM)
						out["pemCrc32c"] = strconv.FormatUint(uint64(crc(headerPEM)), 10)
					case "public-missing-crc":
						delete(out, "pemCrc32c")
					case "public-crc-out-of-range":
						out["pemCrc32c"] = "4294967296"
					}
					encoded, err := json.Marshal(out)
					if err != nil {
						t.Fatal(err)
					}
					reply := response(200, string(encoded))
					if tc.mode == "public-truncated" {
						reply.ContentLength++
					}
					return reply, nil
				case "/v1/" + version:
					if tc.mode == "metadata-missing" {
						return response(404, `{"error":{"code":404,"status":"NOT_FOUND"}}`), nil
					}
					if tc.mode == "metadata-physical-503-body-404" {
						return response(503, `{"error":{"code":404,"status":"NOT_FOUND"}}`), nil
					}
					if tc.mode == "metadata-physical-503-body-403" {
						return response(503, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`), nil
					}
					if tc.mode == "metadata-denied" {
						return apiFailure(403, "forbidden"), nil
					}
					if tc.mode == "metadata-lost" {
						return nil, io.ErrUnexpectedEOF
					}
					if tc.mode == "metadata-overlimit" {
						return response(200, strings.Repeat("x", maxJSON+1)), nil
					}
					out := map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"}
					switch tc.mode {
					case "metadata-imported":
						out["importTime"] = "2026-01-01T00:00:00Z"
					case "metadata-wrong-version":
						out["name"] = version + "0"
					case "metadata-disabled":
						out["state"] = "DISABLED"
					case "metadata-wrong-algorithm":
						out["algorithm"] = "EC_SIGN_P384_SHA384"
					case "metadata-wrong-protection":
						out["protectionLevel"] = "HSM"
					case "metadata-missing-origin":
						delete(out, "generateTime")
					case "metadata-external-null":
						out["externalProtectionLevelOptions"] = nil
					}
					encoded, err := json.Marshal(out)
					if err != nil {
						t.Fatal(err)
					}
					reply := response(200, string(encoded))
					if tc.mode == "metadata-truncated" {
						reply.ContentLength++
					}
					return reply, nil
				default:
					t.Fatal("public anchor requested another KMS resource")
					return nil, nil
				}
			}), &credentials{})
			anchor, err := NewPublicSigningAnchor(context.Background(), PublicSigningAnchorConfig{
				Role: contract.RecoverySigningRole, Client: client, Region: "us-central1", KeyVersion: version, CredentialRoute: "fixture-route"})
			if err != nil {
				t.Fatal(err)
			}
			got := anchor.QualifySigningBinding(ctx, anchorBinding(contract.RecoverySigningRole, version, der, anchor.identity))
			if got.Reason != tc.want || got.Qualified != 0 || calls != tc.calls {
				t.Fatalf("mode=%s result=%+v calls=%d", tc.mode, got, calls)
			}
			result := "invalid"
			if tc.want == contract.ReasonAccess || tc.want == contract.ReasonTransport {
				result = "evidence_unavailable"
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationCalls, telemetry.OpTrustQualify, "", "") != 1 ||
				telemetrySum(data, telemetry.OperationResults, telemetry.OpTrustQualify, result, "") != 1 ||
				telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpTrustQualify, "", "") != int64(tc.calls) {
				t.Fatal("public anchor lost safe failure facts")
			}
			assertSafeTelemetry(t, data)
		})
	}
}

// full_only: false
func TestPublicSigningAnchorCancelledBeforeLookup(t *testing.T) {
	version := "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
	calls := 0
	creds := &credentials{}
	client := makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	}), creds)
	anchor, err := NewPublicSigningAnchor(context.Background(), PublicSigningAnchorConfig{
		Role: contract.NormalSigningRole, Client: client, Region: "us-central1", KeyVersion: version, CredentialRoute: "fixture-route"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := anchor.QualifySigningBinding(ctx, anchorBinding(contract.NormalSigningRole, version, anchorPublicKey(t), anchor.identity))
	if got.Reason != contract.ReasonAccess || got.Qualified != 0 || calls != 0 || creds.calls != 0 {
		t.Fatalf("cancelled public lookup=%+v calls=%d credentials=%d", got, calls, creds.calls)
	}
}

type anchorCancelOnToken struct {
	cancel context.CancelFunc
	calls  int
}

func (c *anchorCancelOnToken) Token(context.Context) (string, error) {
	c.calls++
	c.cancel()
	return "fixture-token", nil
}

// full_only: false
func TestPublicSigningAnchorStopsAfterCredentialCancellation(t *testing.T) {
	version := "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	creds := &anchorCancelOnToken{cancel: cancel}
	calls := 0
	client := makeClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	}), creds)
	anchor, err := NewPublicSigningAnchor(context.Background(), PublicSigningAnchorConfig{
		Role: contract.NormalSigningRole, Client: client, Region: "us-central1", KeyVersion: version, CredentialRoute: "fixture-route"})
	if err != nil {
		t.Fatal(err)
	}
	got := anchor.QualifySigningBinding(ctx, anchorBinding(contract.NormalSigningRole, version, anchorPublicKey(t), anchor.identity))
	if got.Reason != contract.ReasonAccess || got.Qualified != 0 || calls != 0 || creds.calls != 1 {
		t.Fatalf("credential cancellation entered lookup: %+v calls=%d credentials=%d", got, calls, creds.calls)
	}
}

// full_only: false
func TestSigningQualificationChecksOriginalPEMBytesAndChecksumPresence(t *testing.T) {
	// SPKI contains the standard P-256 generator point. A standalone bitwise
	// Castagnoli calculation gives the LF and CRLF values below. The whitespace
	// prefix solves the CRC's 32 binary equations and gives a zero checksum.
	const publicPEM = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n"
	const zeroPrefix = " \t  \t\t\t \t \t \t    \t \t\t\t \t \t\t\t\t\t\t\t        \n"
	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil {
		t.Fatal("fixed SPKI fixture is malformed")
	}
	for _, tc := range []struct {
		name, pem, checksum string
		presence            string
		want                bool
	}{
		{"lf", publicPEM, "155966813", "string", true},
		{"crlf-original", strings.ReplaceAll(publicPEM, "\n", "\r\n"), "3995977275", "string", true},
		{"crlf-normalized-checksum", strings.ReplaceAll(publicPEM, "\n", "\r\n"), "155966813", "string", false},
		{"present-zero", zeroPrefix + publicPEM, "0", "string", true},
		{"missing-zero", zeroPrefix + publicPEM, "0", "missing", false},
		{"null-zero", zeroPrefix + publicPEM, "0", "null", false},
		{"numeric-zero", zeroPrefix + publicPEM, "0", "number", false},
	} {
		for _, ordinary := range []bool{false, true} {
			name := tc.name + "/anchor"
			if ordinary {
				name = tc.name + "/trust"
			}
			t.Run(name, func(t *testing.T) {
				version := "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
				calls := 0
				client := makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.Method != http.MethodGet || r.URL.Host != "us-central1-cloudkms.googleapis.com" || r.URL.Path != "/v1/"+version+"/publicKey" {
						t.Fatal("checksum qualification reached another operation")
					}
					out := map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "pem": tc.pem}
					switch tc.presence {
					case "string":
						out["pemCrc32c"] = tc.checksum
					case "null":
						out["pemCrc32c"] = nil
					case "number":
						out["pemCrc32c"] = 0
					}
					body, err := json.Marshal(out)
					if err != nil {
						t.Fatal(err)
					}
					return response(http.StatusOK, string(body)), nil
				}), &credentials{})
				var qualify func(context.Context, contract.PublicSigningBinding) contract.SigningQualificationResult
				var identity contract.ID
				if ordinary {
					trust, err := NewTrust(context.Background(), trustConfig(client, block.Bytes))
					if err != nil {
						t.Fatal(err)
					}
					qualify, identity = trust.QualifySigningBinding, trust.Identity()
				} else {
					anchor, err := NewPublicSigningAnchor(context.Background(), PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Client: client, Region: "us-central1", KeyVersion: version, CredentialRoute: "fixture-route"})
					if err != nil {
						t.Fatal(err)
					}
					qualify, identity = anchor.QualifySigningBinding, anchor.identity
				}
				binding := anchorBinding(contract.NormalSigningRole, version, block.Bytes, identity)
				got := qualify(context.Background(), binding)
				if tc.want {
					digest, err := contract.SigningBindingDigest(binding)
					if err != nil {
						t.Fatal(err)
					}
					if got != (contract.SigningQualificationResult{TargetRole: contract.NormalSignerTarget, SigningBindingDigest: digest, Provider: contract.GCP, Qualified: 1}) {
						t.Fatal("original PEM checksum was refused", got)
					}
				} else {
					want := contract.ReasonProof
					if tc.presence == "number" {
						want = contract.ReasonTransport
					}
					if got != (contract.SigningQualificationResult{Reason: want}) {
						t.Fatal("checksum failure evidence differs", got)
					}
				}
				if calls != 1 {
					t.Fatal("checksum check repeated lookup", calls)
				}
			})
		}
	}
}

type qualificationCloseBody struct {
	io.ReadCloser
	finish func()
}

func (b qualificationCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.finish()
	return err
}

// full_only: false
func TestSigningQualificationRejectsCancellationAtPhysicalResponseClose(t *testing.T) {
	der := anchorPublicKey(t)
	for _, role := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
		for _, ordinary := range []bool{false, true} {
			for _, when := range []string{"last-response", "first-response", "deadline-last-response"} {
				if role == contract.NormalSigningRole && when == "first-response" {
					continue
				}
				name := "normal/anchor/" + when
				if role == contract.RecoverySigningRole {
					name = "recovery/anchor/" + when
				}
				if ordinary {
					name = strings.Replace(name, "/anchor/", "/trust/", 1)
				}
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						recorder := telemetry.NewRecorder()
						measured := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
						ctx, cancel := context.WithCancel(measured)
						defer cancel()
						wantContextError := context.Canceled
						if when == "deadline-last-response" {
							wantContextError = context.DeadlineExceeded
							var deadlineCancel context.CancelFunc
							ctx, deadlineCancel = context.WithTimeout(ctx, 100*time.Millisecond)
							defer deadlineCancel()
						}
						wantCalls := 1
						if role == contract.RecoverySigningRole && when != "first-response" {
							wantCalls = 2
						}
						calls, closes := 0, 0
						version := "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
						client := makeClient(roundTripFunc(func(req *http.Request) (*http.Response, error) {
							calls++
							if req.Method != http.MethodGet || req.URL.Host != "us-central1-cloudkms.googleapis.com" {
								t.Fatal("qualification changed operation or endpoint")
							}
							var out map[string]any
							switch req.URL.Path {
							case "/v1/" + version + "/publicKey":
								if calls != 1 {
									t.Fatal("extra public-key request")
								}
								pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
								out = map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "pem": string(pemBytes), "pemCrc32c": strconv.FormatUint(uint64(crc(pemBytes)), 10)}
							case "/v1/" + version:
								if calls != 2 || role != contract.RecoverySigningRole || when == "first-response" {
									t.Fatal("lookup advanced after cancellation")
								}
								out = map[string]any{"name": version, "algorithm": "EC_SIGN_P256_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"}
							default:
								t.Fatal("qualification requested another resource")
							}
							body, err := json.Marshal(out)
							if err != nil {
								t.Fatal(err)
							}
							reply := response(http.StatusOK, string(body))
							if calls == wantCalls {
								reply.Body = qualificationCloseBody{ReadCloser: reply.Body, finish: func() {
									closes++
									if when == "deadline-last-response" {
										<-ctx.Done()
									} else {
										cancel()
									}
								}}
							}
							return reply, nil
						}), &credentials{})
						var qualify func(context.Context, contract.PublicSigningBinding) contract.SigningQualificationResult
						var identity contract.ID
						if ordinary {
							c := trustConfig(client, der)
							c.Role = role
							trust, err := NewTrust(context.Background(), c)
							if err != nil {
								t.Fatal(err)
							}
							qualify, identity = trust.QualifySigningBinding, trust.Identity()
						} else {
							anchor, err := NewPublicSigningAnchor(context.Background(), PublicSigningAnchorConfig{Role: role, Client: client,
								Region: "us-central1", KeyVersion: version, CredentialRoute: "fixture-route"})
							if err != nil {
								t.Fatal(err)
							}
							qualify, identity = anchor.QualifySigningBinding, anchor.identity
						}
						got := qualify(ctx, anchorBinding(role, version, der, identity))
						var terminals int
						for _, event := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64)) {
							if event.Operation == telemetry.OpTrustQualify && event.Event == telemetry.DiagnosticReturn {
								terminals++
								if event.Result != telemetry.ResultCancelled || event.ErrorClass != telemetry.DiagnosticReasonCancelled {
									t.Fatalf("canceled qualification telemetry=%+v", event)
								}
							}
						}
						if terminals != 1 {
							t.Fatalf("qualification terminals=%d", terminals)
						}

						if got != (contract.SigningQualificationResult{Reason: contract.ReasonLimit}) || ctx.Err() != wantContextError || calls != wantCalls || closes != 1 {
							t.Fatal("canceled qualification released success or changed call count", got, ctx.Err(), calls, closes)
						}
					})
				})
			}
		}
	}
}
