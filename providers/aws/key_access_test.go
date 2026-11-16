package awsprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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
	return contract.KMSBinding{BindingID: contract.Hash([]byte("binding")), BindingIncarnationID: contract.Hash([]byte("binding incarnation")), BindingSerial: 1, Provider: contract.AWS, WrapProfile: 2, ProtectionClass: contract.HardwareProtection, KeySelector: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", SPKI: der, Fingerprint: contract.Hash(der)}
}

func encryptionConfig() KeyAccessConfig {
	c := testStoreConfig()
	return KeyAccessConfig{Region: c.Region, Account: c.ExpectedBucketOwner, CredentialRoute: c.CredentialRoute, Credentials: c.Credentials, Timeout: c.Timeout}
}

// full_only: false
func TestKeyAccessTelemetry(t *testing.T) {
	binding := encryptionBinding(t)
	packet := bytes.Repeat([]byte{0x79}, 100)
	valid, err := json.Marshal(map[string]any{"KeyId": binding.KeySelector, "EncryptionAlgorithm": "RSAES_OAEP_SHA_256", "Plaintext": base64.StdEncoding.EncodeToString(packet)})
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
			k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Fatal(err)
				}
				if tc.name == "denied" {
					return response(400, `{"__type":"AccessDeniedException","message":"private-sentinel"}`, nil), nil
				}
				return response(200, string(valid), nil), nil
			}))
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
	valid, _ := json.Marshal(map[string]any{"KeyId": binding.KeySelector, "EncryptionAlgorithm": "RSAES_OAEP_SHA_256", "Plaintext": base64.StdEncoding.EncodeToString(packet)})
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   enkvcrypto.KeyStatus
	}{
		{"valid", 200, string(valid), enkvcrypto.KeyOK},
		{"wrong-key", 200, strings.Replace(string(valid), "12345678-1234", "22345678-1234", 1), enkvcrypto.KeyUnknown},
		{"wrong-algorithm", 200, strings.Replace(string(valid), "RSAES_OAEP_SHA_256", "RSAES_OAEP_SHA_1", 1), enkvcrypto.KeyUnknown},
		{"duplicate", 200, strings.TrimSuffix(string(valid), "}") + `,"Plaintext":"` + base64.StdEncoding.EncodeToString(packet) + `"}`, enkvcrypto.KeyUnknown},
		{"unknown", 200, strings.TrimSuffix(string(valid), "}") + `,"KeyMaterialId":"private-sentinel"}`, enkvcrypto.KeyUnknown},
		{"bad-base64", 200, strings.Replace(string(valid), base64.StdEncoding.EncodeToString(packet), "private-sentinel", 1), enkvcrypto.KeyUnknown},
		{"short", 200, strings.Replace(string(valid), base64.StdEncoding.EncodeToString(packet), base64.StdEncoding.EncodeToString(packet[:68]), 1), enkvcrypto.KeyUnknown},
		{"wrong-status", 201, string(valid), enkvcrypto.KeyUnknown},
		{"trailing", 200, string(valid) + ` {}`, enkvcrypto.KeyUnknown},
		{"oversize", 200, string(valid) + strings.Repeat(" ", 4096), enkvcrypto.KeyUnknown},
		{"denied", 400, `{"__type":"AccessDeniedException","message":"private-sentinel"}`, enkvcrypto.KeyDenied},
		{"corrupt", 400, `{"__type":"InvalidCiphertextException","message":"private-sentinel"}`, enkvcrypto.KeyAuthenticationFailed},
		{"incorrect-key", 400, `{"__type":"IncorrectKeyException"}`, enkvcrypto.KeyAuthenticationFailed},
		{"invalid-key-use", 400, `{"__type":"InvalidKeyUsageException"}`, enkvcrypto.KeyInvalid},
		{"unavailable", 500, `{"__type":"KMSInternalException"}`, enkvcrypto.KeyUnavailable},
		{"unknown-error", 403, `{"__type":"NewError","message":"private-sentinel"}`, enkvcrypto.KeyUnknown},
		{"malformed-error", 403, `{"__type":"AccessDeniedException","message":`, enkvcrypto.KeyUnknown},
		{"inconsistent-error", 500, `{"__type":"AccessDeniedException"}`, enkvcrypto.KeyUnknown},
		{"duplicate-error", 400, `{"__type":"NewError","__type":"AccessDeniedException"}`, enkvcrypto.KeyUnknown},
		{"deep-error", 400, `{"__type":"AccessDeniedException","details":` + strings.Repeat("[", 16) + `0` + strings.Repeat("]", 16) + `}`, enkvcrypto.KeyUnknown},
		{"large-error", 400, `{"__type":"AccessDeniedException","message":"` + strings.Repeat("x", 16<<10) + `"}`, enkvcrypto.KeyUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "kms.us-east-1.amazonaws.com" || r.Header.Get("X-Amz-Target") != "TrentService.Decrypt" || r.GetBody != nil {
					t.Fatal("wrong private request route")
				}
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 {
					t.Fatal("private request gained fields")
				}
				var selector, algorithm, ciphertext string
				if json.Unmarshal(fields["KeyId"], &selector) != nil || json.Unmarshal(fields["EncryptionAlgorithm"], &algorithm) != nil || json.Unmarshal(fields["CiphertextBlob"], &ciphertext) != nil || selector != binding.KeySelector || algorithm != "RSAES_OAEP_SHA_256" || ciphertext != base64.StdEncoding.EncodeToString(make([]byte, 384)) {
					t.Fatal("wrong private request binding")
				}
				return response(tc.status, tc.body, nil), nil
			}))
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
			if tc.want == enkvcrypto.KeyInvalid || tc.want == enkvcrypto.KeyAuthenticationFailed || tc.want == enkvcrypto.KeyUnavailable {
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
	for _, mode := range []string{"generated", "imported", "mrk", "wrong-origin", "custom-store", "wrong-key", "wrong-public-key", "disabled", "wrong-spec", "denied-second", "wrong-account", "alias", "bad-spki"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			binding := b
			if mode == "mrk" {
				binding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012"
			}
			if mode == "wrong-account" {
				binding.KeySelector = strings.Replace(b.KeySelector, "123456789012:key", "223456789012:key", 1)
			}
			if mode == "alias" {
				binding.KeySelector = "alias/key"
			}
			if mode == "bad-spki" {
				binding.SPKI = []byte("invalid")
			}
			calls := 0
			k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var in struct{ KeyId string }
				if json.NewDecoder(r.Body).Decode(&in) != nil || in.KeyId != binding.KeySelector {
					t.Fatal("wrong qualification selector")
				}
				var out any
				switch r.Header.Get("X-Amz-Target") {
				case "TrentService.GetPublicKey":
					public := binding.SPKI
					if mode == "wrong-public-key" {
						public = bytes.Repeat([]byte{0}, 422)
					}
					out = map[string]any{"KeyId": binding.KeySelector, "KeySpec": "RSA_3072", "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": []string{"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"}, "PublicKey": base64.StdEncoding.EncodeToString(public)}
				case "TrentService.DescribeKey":
					if mode == "denied-second" {
						return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
					}
					metadata := map[string]any{"Arn": binding.KeySelector, "KeyId": strings.Split(binding.KeySelector, "key/")[1], "AWSAccountId": "123456789012", "KeySpec": "RSA_3072", "KeyUsage": "ENCRYPT_DECRYPT", "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "EncryptionAlgorithms": []string{"RSAES_OAEP_SHA_256"}}
					switch mode {
					case "imported":
						metadata["Origin"] = "EXTERNAL"
					case "wrong-origin":
						metadata["Origin"] = "EXTERNAL_KEY_STORE"
					case "custom-store":
						metadata["CustomKeyStoreId"] = "store"
					case "disabled":
						metadata["Enabled"] = false
					case "wrong-spec":
						metadata["KeySpec"] = "RSA_2048"
					case "wrong-key":
						metadata["Arn"] = binding.KeySelector + "0"
					}
					out = map[string]any{"KeyMetadata": metadata}
				default:
					t.Fatal("qualification used a private or unselected operation")
				}
				raw, _ := json.Marshal(out)
				return response(200, string(raw), nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := k.Qualify(ctx, binding)
			assertKeyTelemetry(t, snapshot(), telemetry.OpKeyQualify, "", 1, int64(calls))
			valid := mode == "generated" || mode == "imported" || mode == "mrk"
			if valid {
				if got.Status != enkvcrypto.KeyOK || calls != 2 || got.Uses.Completed != 2 {
					t.Fatalf("qualification status=%d calls=%d", got.Status, calls)
				}
			} else if got.Status == enkvcrypto.KeyOK {
				t.Fatal("invalid qualification accepted")
			}
			if (mode == "wrong-account" || mode == "alias" || mode == "bad-spki") && calls != 0 {
				t.Fatal("invalid binding reached provider")
			}
			if mode == "denied-second" && (got.Status != enkvcrypto.KeyDenied || got.Uses.Completed != 1 || got.Uses.Denied != 1) {
				t.Fatal("lost partial public qualification evidence")
			}
		})
	}
}

// Real KMS RSA decrypt replies can include KeyOrigin although the pinned SDK's
// DecryptOutput has no field for it. The private guard must validate this field
// before the unchanged response reaches that generated decoder.
// full_only: false
func TestPrivateDecryptKeyOrigin(t *testing.T) {
	binding := encryptionBinding(t)
	for _, length := range []int{68, 100} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			packet := bytes.Repeat([]byte{0x79}, length)
			fields := fmt.Sprintf(`"KeyId":%q,"EncryptionAlgorithm":"RSAES_OAEP_SHA_256","Plaintext":%q`, binding.KeySelector, base64.StdEncoding.EncodeToString(packet))
			for _, tc := range []struct {
				name, extra string
				want        enkvcrypto.KeyStatus
			}{
				{"absent", "", enkvcrypto.KeyOK},
				{"provider-generated", `,"KeyOrigin":"AWS_KMS"`, enkvcrypto.KeyOK},
				{"imported", `,"KeyOrigin":"EXTERNAL"`, enkvcrypto.KeyOK},
				{"cloudhsm", `,"KeyOrigin":"AWS_CLOUDHSM"`, enkvcrypto.KeyUnknown},
				{"external-store", `,"KeyOrigin":"EXTERNAL_KEY_STORE"`, enkvcrypto.KeyUnknown},
				{"unknown-origin", `,"KeyOrigin":"FUTURE_ORIGIN"`, enkvcrypto.KeyUnknown},
				{"empty", `,"KeyOrigin":""`, enkvcrypto.KeyUnknown},
				{"null", `,"KeyOrigin":null`, enkvcrypto.KeyUnknown},
				{"number", `,"KeyOrigin":1`, enkvcrypto.KeyUnknown},
				{"object", `,"KeyOrigin":{}`, enkvcrypto.KeyUnknown},
				{"duplicate", `,"KeyOrigin":"AWS_KMS","KeyOrigin":"AWS_KMS"`, enkvcrypto.KeyUnknown},
				{"unknown-field", `,"KeyOrigin":"AWS_KMS","OtherField":"untrusted"`, enkvcrypto.KeyUnknown},
				{"symmetric-material", `,"KeyOrigin":"AWS_KMS","KeyMaterialId":"untrusted"`, enkvcrypto.KeyUnknown},
			} {
				t.Run(tc.name, func(t *testing.T) {
					calls := 0
					k, err := newKeyAccess(encryptionConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
						calls++
						return response(200, "{"+fields+tc.extra+"}", nil), nil
					}))
					if err != nil {
						t.Fatal(err)
					}
					got := k.Decrypt(context.Background(), binding, make([]byte, 384), uint16(length))
					defer clear(got.Packet[:cap(got.Packet)])
					if got.Status != tc.want || calls != 1 {
						t.Fatalf("status=%d want=%d calls=%d", got.Status, tc.want, calls)
					}
					if tc.want == enkvcrypto.KeyOK {
						if !bytes.Equal(got.Packet, packet) || cap(got.Packet) != length || got.Uses != (enkvcrypto.KeyUses{Completed: 1}) {
							t.Fatal("valid origin lost the exact owned packet or completed evidence")
						}
					} else if len(got.Packet) != 0 || got.Uses != (enkvcrypto.KeyUses{Unknown: 1}) {
						t.Fatal("invalid origin or extra field released a packet or lost unknown evidence")
					}
				})
			}
			for _, omitted := range []string{"KeyId", "EncryptionAlgorithm", "Plaintext"} {
				t.Run("missing-"+omitted, func(t *testing.T) {
					fields := map[string]any{"KeyId": binding.KeySelector, "EncryptionAlgorithm": "RSAES_OAEP_SHA_256", "Plaintext": base64.StdEncoding.EncodeToString(packet), "KeyOrigin": "AWS_KMS"}
					delete(fields, omitted)
					raw, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					p := &privateDecrypt{selector: binding.KeySelector, packetLength: uint16(length)}
					defer p.clear()
					if p.success(raw) {
						t.Fatal("KeyOrigin replaced a required response field")
					}
				})
			}
		})
	}
}
