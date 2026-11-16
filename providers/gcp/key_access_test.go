package gcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/api/googleapi"
)

func encryptionBinding(t *testing.T) contract.KMSBinding {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return contract.KMSBinding{BindingID: contract.Hash([]byte("binding")), BindingIncarnationID: contract.Hash([]byte("binding incarnation")), BindingSerial: 1, Provider: contract.GCP, WrapProfile: 2, ProtectionClass: contract.SoftwareProtection, KeySelector: "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", SPKI: der, Fingerprint: contract.Hash(der)}
}

func encryptionConfig(c *Client) KeyAccessConfig {
	return KeyAccessConfig{Client: c, Project: "fixture-project", Region: "us-central1", Endpoint: "https://us-central1-cloudkms.googleapis.com/", CredentialRoute: contract.Hash([]byte("fixture-route"))}
}

// full_only: false
func TestKeyAccessTelemetry(t *testing.T) {
	binding := encryptionBinding(t)
	packet := bytes.Repeat([]byte{0x79}, 100)
	valid, err := json.Marshal(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(packet), "plaintextCrc32c": strconv.FormatUint(uint64(crc(packet)), 10), "verifiedCiphertextCrc32c": true, "protectionLevel": "SOFTWARE"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, setting, label string
		status               enkvcrypto.KeyStatus
		http                 int64
	}{
		{"success", "1", "success", enkvcrypto.KeyOK, 1},
		{"denied", "1", "denied", enkvcrypto.KeyDenied, 1},
		{"invalid", "1", "invalid", enkvcrypto.KeyInvalid, 0},
		{"cancelled", "1", "cancelled", enkvcrypto.KeyCancelled, 0},
		{"disabled", "", "", enkvcrypto.KeyOK, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", tc.setting)
			ctx, snapshot := collectTelemetry(t)
			if tc.name == "disabled" {
				ctx = context.Background()
			}
			k, err := NewKeyAccess(ctx, encryptionConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Fatal(err)
				}
				if tc.name == "denied" {
					return response(403, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel"}}`), nil
				}
				return response(200, string(valid)), nil
			}), &credentials{})))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			if tc.name == "cancelled" {
				cancel()
			}
			ciphertext := make([]byte, 384)
			if tc.name == "invalid" {
				ciphertext = nil
			}
			got := k.Decrypt(ctx, binding, ciphertext, 100)
			defer clear(got.Packet[:cap(got.Packet)])
			if got.Status != tc.status {
				t.Fatalf("status=%d want=%d", got.Status, tc.status)
			}
			if tc.status == enkvcrypto.KeyOK && !bytes.Equal(got.Packet, packet) {
				t.Fatal("telemetry changed the packet")
			}
			want := int64(1)
			if tc.setting != "1" {
				want = 0
			}
			assertKeyTelemetry(t, snapshot(), "key.decrypt", tc.label, want, tc.http)
		})
	}
}

func assertKeyTelemetry(t *testing.T, data metricdata.ResourceMetrics, operation telemetry.Operation, result string, calls, attempts int64) {
	t.Helper()
	if telemetrySum(data, telemetry.OperationCalls, operation, "", "") != calls || telemetrySum(data, telemetry.OperationResults, operation, result, "") != calls || telemetrySum(data, telemetry.HTTPAttempts, operation, "", "") != attempts || telemetrySum(data, telemetry.HTTPResults, operation, "", "") != attempts {
		t.Fatal("key operation starts, results or HTTP attempts differ")
	}
	var duration, httpDuration uint64
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != telemetry.OperationDuration && m.Name != telemetry.HTTPDuration {
				continue
			}
			for _, p := range m.Data.(metricdata.Histogram[float64]).DataPoints {
				op, _ := p.Attributes.Value("operation")
				if op.AsString() == string(operation) {
					if m.Name == telemetry.OperationDuration {
						duration += p.Count
					} else {
						httpDuration += p.Count
					}
				}
			}
		}
	}
	if duration != uint64(calls) || httpDuration != uint64(attempts) {
		t.Fatal("key operation duration missing")
	}
	assertSafeTelemetry(t, data)
}

// full_only: false
func TestPrivateDecryptGeneratedClient(t *testing.T) {
	binding := encryptionBinding(t)
	packet := bytes.Repeat([]byte{0x79}, 100)
	valid, _ := json.Marshal(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(packet), "plaintextCrc32c": strconv.FormatUint(uint64(crc(packet)), 10), "verifiedCiphertextCrc32c": true, "protectionLevel": "SOFTWARE"})
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   enkvcrypto.KeyStatus
	}{
		{"valid", 200, string(valid), enkvcrypto.KeyOK},
		{"wrong-protection", 200, strings.Replace(string(valid), "SOFTWARE", "HSM", 1), enkvcrypto.KeyUnknown},
		{"missing-verified", 200, strings.Replace(string(valid), "true", "false", 1), enkvcrypto.KeyUnknown},
		{"wrong-crc", 200, strings.Replace(string(valid), strconv.FormatUint(uint64(crc(packet)), 10), "0", 1), enkvcrypto.KeyUnknown},
		{"noncanonical-crc", 200, strings.Replace(string(valid), strconv.FormatUint(uint64(crc(packet)), 10), "0"+strconv.FormatUint(uint64(crc(packet)), 10), 1), enkvcrypto.KeyUnknown},
		{"duplicate", 200, strings.TrimSuffix(string(valid), "}") + `,"plaintext":"private-sentinel"}`, enkvcrypto.KeyUnknown},
		{"unknown", 200, strings.TrimSuffix(string(valid), "}") + `,"name":"private-sentinel"}`, enkvcrypto.KeyUnknown},
		{"bad-base64", 200, strings.Replace(string(valid), base64.StdEncoding.EncodeToString(packet), "private-sentinel", 1), enkvcrypto.KeyUnknown},
		{"short", 200, strings.Replace(string(valid), base64.StdEncoding.EncodeToString(packet), base64.StdEncoding.EncodeToString(packet[:68]), 1), enkvcrypto.KeyUnknown},
		{"wrong-status", 201, string(valid), enkvcrypto.KeyUnknown},
		{"trailing", 200, string(valid) + ` {}`, enkvcrypto.KeyUnknown},
		{"oversize", 200, string(valid) + strings.Repeat(" ", 4096), enkvcrypto.KeyUnknown},
		{"denied", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","metadata":{"key":"private-sentinel"}}]}}`, enkvcrypto.KeyDenied},
		{"invalid", 400, `{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"private-sentinel"}}`, enkvcrypto.KeyInvalid},
		{"unknown-error", 403, `{"error":{"code":403,"status":"NEW_ERROR","message":"private-sentinel"}}`, enkvcrypto.KeyUnknown},
		{"inconsistent-error", 500, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`, enkvcrypto.KeyUnknown},
		{"missing-code", 403, `{"error":{"status":"PERMISSION_DENIED"}}`, enkvcrypto.KeyUnknown},
		{"duplicate-code", 403, `{"error":{"code":403,"code":403,"status":"PERMISSION_DENIED"}}`, enkvcrypto.KeyUnknown},
		{"deep-error", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":` + strings.Repeat("[", 15) + `0` + strings.Repeat("]", 15) + `}}`, enkvcrypto.KeyUnknown},
		{"large-error", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"` + strings.Repeat("x", 64<<10) + `"}}`, enkvcrypto.KeyUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			k, err := NewKeyAccess(context.Background(), encryptionConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.Host != "us-central1-cloudkms.googleapis.com" || r.URL.Path != "/v1/"+binding.KeySelector+":asymmetricDecrypt" || r.GetBody != nil {
					t.Fatal("wrong private request route")
				}
				var fields map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&fields) != nil || len(fields) != 2 {
					t.Fatal("private request gained fields")
				}
				var ciphertext, checksum string
				if json.Unmarshal(fields["ciphertext"], &ciphertext) != nil || json.Unmarshal(fields["ciphertextCrc32c"], &checksum) != nil || ciphertext != base64.StdEncoding.EncodeToString(make([]byte, 384)) || checksum != strconv.FormatUint(uint64(crc(make([]byte, 384))), 10) {
					t.Fatal("wrong private ciphertext or CRC")
				}
				return response(tc.status, tc.body), nil
			}), &credentials{})))
			if err != nil {
				t.Fatal(err)
			}
			got := k.Decrypt(context.Background(), binding, make([]byte, 384), 100)
			if got.Status != tc.want || calls != 1 {
				t.Fatalf("status=%d calls=%d want=%d", got.Status, calls, tc.want)
			}
			if tc.want == enkvcrypto.KeyOK {
				if !bytes.Equal(got.Packet, packet) || cap(got.Packet) != 100 || got.Uses.Completed != 1 {
					t.Fatal("wrong owned packet or evidence")
				}
				clear(got.Packet[:cap(got.Packet)])
			} else if len(got.Packet) != 0 {
				t.Fatal("failed call released a packet")
			}
			wantUses := enkvcrypto.KeyUses{Unknown: 1}
			if tc.want == enkvcrypto.KeyOK {
				wantUses = enkvcrypto.KeyUses{Completed: 1}
			}
			if tc.want == enkvcrypto.KeyDenied {
				wantUses = enkvcrypto.KeyUses{Denied: 1}
			}
			if tc.want == enkvcrypto.KeyInvalid || tc.want == enkvcrypto.KeyStatus(7) {
				wantUses = enkvcrypto.KeyUses{Failed: 1}
			}
			if got.Uses != wantUses {
				t.Fatalf("uses=%+v want=%+v", got.Uses, wantUses)
			}
		})
	}
}

// full_only: false
func TestKeyAccessQualificationAndEarlyRefusal(t *testing.T) {
	b := encryptionBinding(t)
	for _, mode := range []string{"generated", "imported", "hsm", "ring-reserved-word", "key-reserved-word", "both-reserved-word", "wrong-project", "alias", "bad-spki", "wrong-purpose", "wrong-algorithm", "disabled", "wrong-protection", "external", "wrong-public", "bad-pem-crc", "denied-last"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			binding := b
			if mode == "ring-reserved-word" || mode == "both-reserved-word" {
				binding.KeySelector = strings.Replace(binding.KeySelector, "/keyRings/ring/", "/keyRings/cryptoKeyVersions/", 1)
			}
			if mode == "key-reserved-word" || mode == "both-reserved-word" {
				binding.KeySelector = strings.Replace(binding.KeySelector, "/cryptoKeys/key/", "/cryptoKeys/cryptoKeyVersions/", 1)
			}
			if mode == "hsm" {
				binding.ProtectionClass = contract.HardwareProtection
			}
			if mode == "wrong-project" {
				binding.KeySelector = strings.Replace(b.KeySelector, "fixture-project", "other-project", 1)
			}
			if mode == "alias" {
				binding.KeySelector = strings.TrimSuffix(b.KeySelector, "/1") + "/latest"
			}
			if mode == "bad-spki" {
				binding.SPKI = []byte("invalid")
			}
			protection := "SOFTWARE"
			if mode == "hsm" {
				protection = "HSM"
			}
			parent := strings.Join(strings.Split(binding.KeySelector, "/")[:8], "/")
			calls := 0
			k, err := NewKeyAccess(ctx, encryptionConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" {
					t.Fatal("qualification used private operation")
				}
				var out map[string]any
				switch r.URL.Path {
				case "/v1/" + parent:
					out = map[string]any{"name": parent, "purpose": "ASYMMETRIC_DECRYPT", "importOnly": false}
					if mode == "wrong-purpose" {
						out["purpose"] = "ASYMMETRIC_SIGN"
					}
				case "/v1/" + binding.KeySelector:
					out = map[string]any{"name": binding.KeySelector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "state": "ENABLED", "protectionLevel": protection, "generateTime": "2026-01-01T00:00:00Z"}
					switch mode {
					case "imported":
						delete(out, "generateTime")
						out["importTime"] = "2026-01-01T00:00:00Z"
						out["importJob"] = "projects/fixture-project/locations/us-central1/keyRings/ring/importJobs/job"
					case "disabled":
						out["state"] = "DISABLED"
					case "wrong-algorithm":
						out["algorithm"] = "RSA_DECRYPT_OAEP_2048_SHA256"
					case "wrong-protection":
						out["protectionLevel"] = "HSM"
					case "external":
						out["externalProtectionLevelOptions"] = map[string]any{"externalKeyUri": "external"}
					}
				case "/v1/" + binding.KeySelector + "/publicKey":
					if mode == "denied-last" {
						return response(403, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`), nil
					}
					der := binding.SPKI
					if mode == "wrong-public" {
						der = bytes.Repeat([]byte{0}, 422)
					}
					public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
					out = map[string]any{"name": binding.KeySelector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "protectionLevel": protection, "pem": public, "pemCrc32c": strconv.FormatUint(uint64(crc([]byte(public))), 10)}
					if mode == "bad-pem-crc" {
						out["pemCrc32c"] = "0"
					}
				default:
					t.Fatal("wrong qualification resource")
				}
				raw, _ := json.Marshal(out)
				return response(200, string(raw)), nil
			}), &credentials{})))
			if err != nil {
				t.Fatal(err)
			}
			got := k.Qualify(ctx, binding)
			assertKeyTelemetry(t, snapshot(), telemetry.OpKeyQualify, "", 1, int64(calls))
			valid := mode == "generated" || mode == "imported" || mode == "hsm" || strings.HasSuffix(mode, "reserved-word")
			if valid {
				if got.Status != enkvcrypto.KeyOK || calls != 3 || got.Uses.Completed != 3 {
					t.Fatalf("qualification status=%d calls=%d", got.Status, calls)
				}
			} else if got.Status == enkvcrypto.KeyOK {
				t.Fatal("invalid qualification accepted")
			}
			if (mode == "wrong-project" || mode == "alias" || mode == "bad-spki") && calls != 0 {
				t.Fatal("invalid binding reached provider")
			}
			if mode == "denied-last" && (got.Status != enkvcrypto.KeyDenied || got.Uses.Completed != 2 || got.Uses.Denied != 1) {
				t.Fatal("lost partial qualification evidence")
			}
		})
	}
}

// full_only: false
func TestKeyAccessQualificationDenialEnvelopeMatrix(t *testing.T) {
	binding := encryptionBinding(t)
	parent := strings.Join(strings.Split(binding.KeySelector, "/")[:8], "/")
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: binding.SPKI}))
	valid := map[string]map[string]any{
		"parent":  {"name": parent, "purpose": "ASYMMETRIC_DECRYPT", "importOnly": false},
		"version": {"name": binding.KeySelector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"},
		"public":  {"name": binding.KeySelector, "algorithm": "RSA_DECRYPT_OAEP_3072_SHA256", "protectionLevel": "SOFTWARE", "pem": publicPEM, "pemCrc32c": strconv.FormatUint(uint64(crc([]byte(publicPEM))), 10)},
	}
	for _, denial := range []struct {
		name   string
		status int
		body   []byte
		want   enkvcrypto.KeyStatus
	}{
		{"physical-503-body-403", 503, []byte(`{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"physical-403-body-503", 403, []byte(`{"error":{"code":503,"status":"UNAVAILABLE","message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"zero-code", 403, []byte(`{"error":{"code":0,"message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"null-code", 403, []byte(`{"error":{"code":null,"message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"string-code", 403, []byte(`{"error":{"code":"403","message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"array-code", 403, []byte(`{"error":{"code":[],"message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"malformed", 403, []byte(`{"error":`), enkvcrypto.KeyUnavailable},
		{"valid-401", 401, []byte(`{"error":{"code":401,"status":"UNAUTHENTICATED","message":"private-sentinel"}}`), enkvcrypto.KeyDenied},
		{"valid-403", 403, []byte(`{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel"}}`), enkvcrypto.KeyDenied},
		{"valid-omitted-code", 403, []byte(`{"error":{"status":"PERMISSION_DENIED","message":"private-sentinel"}}`), enkvcrypto.KeyDenied},
		{"null-root", 403, []byte(`null`), enkvcrypto.KeyUnavailable},
		{"missing-error", 403, []byte(`{"code":403}`), enkvcrypto.KeyUnavailable},
		{"null-error", 403, []byte(`{"error":null}`), enkvcrypto.KeyUnavailable},
		{"array-error", 403, []byte(`{"error":[]}`), enkvcrypto.KeyUnavailable},
		{"duplicate-code", 403, []byte(`{"error":{"code":403,"code":403,"message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"contradictory-code-before-matching", 403, []byte(`{"error":{"code":401,"code":403,"message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"duplicate-error", 403, []byte(`{"error":{"code":403},"error":{"code":403,"message":"private-sentinel"}}`), enkvcrypto.KeyUnavailable},
		{"invalid-utf8", 403, []byte("{\"error\":{\"code\":403,\"message\":\"\xff\"}}"), enkvcrypto.KeyUnavailable},
		{"code-alias-before-canonical", 403, []byte(`{"error":{"Code":401,"code":403}}`), enkvcrypto.KeyUnavailable},
		{"zero-code-alias", 403, []byte(`{"error":{"Code":0}}`), enkvcrypto.KeyUnavailable},
		{"error-alias-before-canonical", 403, []byte(`{"Error":{"code":401},"error":{"code":403}}`), enkvcrypto.KeyUnavailable},
	} {
		for targetIndex, target := range []string{"parent", "version", "public"} {
			t.Run(denial.name+"/"+target, func(t *testing.T) {
				calls := 0
				k, err := NewKeyAccess(context.Background(), encryptionConfig(makeClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
					stage := ""
					switch r.URL.Path {
					case "/v1/" + parent:
						stage = "parent"
					case "/v1/" + binding.KeySelector:
						stage = "version"
					case "/v1/" + binding.KeySelector + "/publicKey":
						stage = "public"
					default:
						t.Fatal("wrong qualification resource")
					}
					calls++
					if stage == target {
						return response(denial.status, string(denial.body)), nil
					}
					body, err := json.Marshal(valid[stage])
					if err != nil {
						t.Fatal(err)
					}
					return response(200, string(body)), nil
				}), &credentials{})))
				if err != nil {
					t.Fatal(err)
				}
				got := k.Qualify(context.Background(), binding)
				denied, unknown := uint32(0), uint32(1)
				if denial.want == enkvcrypto.KeyDenied {
					denied, unknown = 1, 0
				}
				if got.Status != denial.want || got.Uses.Completed != uint32(targetIndex) || got.Uses.Denied != denied || got.Uses.Failed != 0 || got.Uses.Unknown != unknown || calls != targetIndex+1 {
					t.Fatalf("%s denial result: status=%d uses=%+v calls=%d", target, got.Status, got.Uses, calls)
				}
			})
		}
	}
}

// full_only: false
func TestPublicKeyStatusRequiresCompleteConsistentDenial(t *testing.T) {
	valid403 := &operation{status: 403, response: []byte(`{"error":{"code":403,"status":"PERMISSION_DENIED"}}`)}
	for _, tc := range []struct {
		name string
		op   *operation
		err  error
		want enkvcrypto.KeyStatus
	}{
		{"valid-403", valid403, &googleapi.Error{Code: 403}, enkvcrypto.KeyDenied},
		{"valid-401-without-body-code", &operation{status: 401, response: []byte(`{"error":{"status":"UNAUTHENTICATED"}}`)}, &googleapi.Error{Code: 401}, enkvcrypto.KeyDenied},
		{"missing-operation", nil, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"missing-status", &operation{response: valid403.response}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"non-denial-status", &operation{status: 500, response: []byte(`{"error":{"code":500}}`)}, &googleapi.Error{Code: 500}, enkvcrypto.KeyUnavailable},
		{"untyped-error", valid403, errors.New("transport"), enkvcrypto.KeyUnavailable},
		{"sdk-status-mismatch", valid403, &googleapi.Error{Code: 401}, enkvcrypto.KeyUnavailable},
		{"body-status-mismatch", &operation{status: 403, response: []byte(`{"error":{"code":401}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"zero-code", &operation{status: 403, response: []byte(`{"error":{"code":0}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"null-code", &operation{status: 403, response: []byte(`{"error":{"code":null}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"string-code", &operation{status: 403, response: []byte(`{"error":{"code":"403"}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"duplicate-code", &operation{status: 403, response: []byte(`{"error":{"code":403,"code":403}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"duplicate-error", &operation{status: 403, response: []byte(`{"error":{"code":403},"error":{"code":403}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"invalid-utf8", &operation{status: 403, response: []byte("{\"error\":{\"code\":403,\"message\":\"\xff\"}}")}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"code-alias-before-canonical", &operation{status: 403, response: []byte(`{"error":{"Code":401,"code":403}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"zero-code-alias", &operation{status: 403, response: []byte(`{"error":{"Code":0}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"error-alias-before-canonical", &operation{status: 403, response: []byte(`{"Error":{"code":401},"error":{"code":403}}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"missing-error", &operation{status: 403, response: []byte(`{"code":403}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"null-error", &operation{status: 403, response: []byte(`{"error":null}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"non-object-error", &operation{status: 403, response: []byte(`{"error":[]}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"non-object-root", &operation{status: 403, response: []byte(`[]`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"malformed", &operation{status: 403, response: []byte(`{"error":`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"trailing", &operation{status: 403, response: []byte(`{"error":{"code":403}} {}`)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
		{"oversize", &operation{status: 403, response: bytes.Repeat([]byte{' '}, maxJSON+1)}, &googleapi.Error{Code: 403}, enkvcrypto.KeyUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicKeyStatus(tc.op, tc.err); got != tc.want {
				t.Fatalf("status=%d want=%d", got, tc.want)
			}
		})
	}
}
