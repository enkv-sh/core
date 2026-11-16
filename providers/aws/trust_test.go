package awsprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
)

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
	sc := testStoreConfig()
	calls := 0
	c := TrustConfig{Region: sc.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: public[0], CredentialRoute: sc.CredentialRoute, Timeout: sc.Timeout,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			calls++
			return aws.Credentials{}, errors.New("construction must not use credentials")
		}),
	}
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("construction sent a request")
		return nil, nil
	})
	before, err := newTrust(c, transport)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		same   bool
		mutate func(*TrustConfig)
	}{
		{"explicit-normal-role", true, func(c *TrustConfig) { c.Role = contract.NormalSigningRole }},
		{"credential-route", true, func(c *TrustConfig) { c.CredentialRoute = contract.Hash([]byte("successor route")) }},
		{"signing-key", true, func(c *TrustConfig) {
			c.KeyARN = strings.Replace(c.KeyARN, "/12345678-", "/87654321-", 1)
			c.PublicKeyDER = public[1]
		}},
		{"same-public-key-new-resource", true, func(c *TrustConfig) { c.KeyARN = strings.Replace(c.KeyARN, "/12345678-", "/87654321-", 1) }},
		{"key-account", true, func(c *TrustConfig) { c.KeyARN = strings.Replace(c.KeyARN, ":123456789012:", ":210987654321:", 1) }},
		{"recovery-role", false, func(c *TrustConfig) { c.Role = contract.RecoverySigningRole }},
		{"regional-endpoint", false, func(c *TrustConfig) {
			c.Region = "us-west-2"
			c.KeyARN = strings.Replace(c.KeyARN, ":us-east-1:", ":us-west-2:", 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			afterConfig := c
			tc.mutate(&afterConfig)
			after, err := newTrust(afterConfig, transport)
			if err != nil {
				t.Fatal(err)
			}
			if after.Identity().IsZero() || (before.Identity() == after.Identity()) != tc.same {
				t.Fatal("Trust identity does not identify the stable public construction")
			}
		})
	}
	if calls != 0 {
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
			sc := testStoreConfig()
			oldCredentials, newCredentials, requests := 0, 0, 0
			old := TrustConfig{Role: role, Region: sc.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: public[0], CredentialRoute: sc.CredentialRoute, Timeout: sc.Timeout,
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					oldCredentials++
					return aws.Credentials{}, errors.New("retired credential unavailable")
				}),
			}
			before, err := newTrust(old, roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("retired route sent a request")
				return nil, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			id := contract.Hash([]byte("replacement"))
			binding := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: role, Provider: contract.AWS, SigningProfile: 1, BindingID: id, KeySelector: old.KeyARN, SPKI: public[0], Fingerprint: contract.Hash(public[0]), Binding: contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: before.Identity(), PublicKey: contract.Hash(public[0]), Interpretation: contract.InterpretationID(), ControlIncarnationID: id, Epoch: 2}}
			successor := old
			if tc.keyIndex == 1 {
				successor.KeyARN = "arn:aws:kms:us-east-1:210987654321:key/87654321-1234-1234-1234-123456789012"
				successor.PublicKeyDER = public[1]
				binding.KeySelector = successor.KeyARN
				binding.SPKI, binding.Fingerprint, binding.Binding.PublicKey = public[1], contract.Hash(public[1]), contract.Hash(public[1])
			}
			originalBinding := binding
			originalBinding.SPKI = append([]byte(nil), binding.SPKI...)
			successor.CredentialRoute = contract.Hash([]byte("successor credential route"))
			successor.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				newCredentials++
				return aws.Credentials{AccessKeyID: "successor-access", SecretAccessKey: "successor-secret"}, nil
			})
			after, err := newTrust(successor, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				var input struct{ KeyId, Message, MessageType, SigningAlgorithm string }
				if json.NewDecoder(r.Body).Decode(&input) != nil || input.KeyId != successor.KeyARN || r.URL.Host != "kms.us-east-1.amazonaws.com" || !strings.Contains(r.Header.Get("Authorization"), "Credential=successor-access/") {
					t.Fatal("request did not use the exact successor key and credential")
				}
				var output map[string]any
				switch r.Header.Get("X-Amz-Target") {
				case "TrentService.GetPublicKey":
					output = map[string]any{"KeyId": successor.KeyARN, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "PublicKey": base64.StdEncoding.EncodeToString(public[tc.keyIndex]), "SigningAlgorithms": []string{"ECDSA_SHA_256"}}
				case "TrentService.DescribeKey":
					output = map[string]any{"KeyMetadata": map[string]any{"Arn": successor.KeyARN, "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}}
				case "TrentService.Sign":
					digest, err := base64.StdEncoding.DecodeString(input.Message)
					if err != nil || len(digest) != 32 || input.MessageType != "DIGEST" || input.SigningAlgorithm != "ECDSA_SHA_256" {
						t.Fatal("signing request changed the admitted profile")
					}
					signature, err := ecdsa.SignASN1(rand.Reader, keys[tc.keyIndex], digest)
					if err != nil {
						t.Fatal(err)
					}
					output = map[string]any{"KeyId": successor.KeyARN, "SigningAlgorithm": "ECDSA_SHA_256", "Signature": base64.StdEncoding.EncodeToString(signature)}
				default:
					t.Fatal("unexpected provider operation")
				}
				body, err := json.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(body), http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if after.Identity() != before.Identity() {
				t.Fatal("credential or key change changed the public Trust identity")
			}
			for _, mutate := range []func(*contract.PublicSigningBinding){
				func(b *contract.PublicSigningBinding) {
					if tc.keyIndex == 0 {
						b.KeySelector = "arn:aws:kms:us-east-1:210987654321:key/87654321-1234-1234-1234-123456789012"
					} else {
						b.KeySelector = old.KeyARN
					}
				},
				func(b *contract.PublicSigningBinding) {
					b.SPKI, b.Fingerprint, b.Binding.PublicKey = public[1-tc.keyIndex], contract.Hash(public[1-tc.keyIndex]), contract.Hash(public[1-tc.keyIndex])
				},
				func(b *contract.PublicSigningBinding) { b.Binding.Trust = id },
				func(b *contract.PublicSigningBinding) { b.Provider = contract.GCP },
				func(b *contract.PublicSigningBinding) { b.Role = 3 - role },
				func(b *contract.PublicSigningBinding) { b.SigningProfile++ },
			} {
				bad := binding
				mutate(&bad)
				if got := after.QualifySigningBinding(context.Background(), bad); got.Reason != contract.ReasonConstruction || got.Qualified != 0 {
					t.Fatal("another exact signing binding was qualified", got)
				}
			}
			if requests != 0 || oldCredentials != 0 || newCredentials != 0 {
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
			if requests != want || newCredentials != 2 || oldCredentials != 0 {
				t.Fatalf("requests=%d successor credentials=%d retired credentials=%d", requests, newCredentials, oldCredentials)
			}
		})
	}
}

// full_only: false
func TestSigningQualificationUsesOneRequestPerSDKOperation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		role   uint8
		reason contract.Reason
	}{
		{"normal", contract.NormalSigningRole, contract.ReasonNone},
		{"recovery", contract.RecoverySigningRole, contract.ReasonNone},
		{"public-denied", contract.RecoverySigningRole, contract.ReasonAccess},
		{"public-invalid", contract.RecoverySigningRole, contract.ReasonProof},
		{"metadata-denied", contract.RecoverySigningRole, contract.ReasonAccess},
		{"metadata-lost", contract.RecoverySigningRole, contract.ReasonTransport},
		{"metadata-invalid", contract.RecoverySigningRole, contract.ReasonProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			sc := testStoreConfig()
			c := TrustConfig{Role: tc.role, Region: sc.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: der, CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: sc.Timeout}
			var operations []string
			tr, err := newTrust(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				operation := r.Header.Get("X-Amz-Target")
				operations = append(operations, operation)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var request struct{ KeyId string }
				if json.Unmarshal(body, &request) != nil || request.KeyId != c.KeyARN {
					t.Fatal("qualification requested another key")
				}
				var reply map[string]any
				switch operation {
				case "TrentService.GetPublicKey":
					if tc.name == "public-denied" {
						return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
					}
					reply = map[string]any{"KeyId": c.KeyARN, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "PublicKey": base64.StdEncoding.EncodeToString(der), "SigningAlgorithms": []string{"ECDSA_SHA_256"}}
					if tc.name == "public-invalid" {
						reply["KeyUsage"] = "ENCRYPT_DECRYPT"
					}
				case "TrentService.DescribeKey":
					if tc.name == "metadata-denied" {
						return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
					}
					if tc.name == "metadata-lost" {
						return nil, io.ErrUnexpectedEOF
					}
					metadata := map[string]any{"Arn": c.KeyARN, "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}
					if tc.name == "metadata-invalid" {
						metadata["Origin"] = "EXTERNAL"
					}
					reply = map[string]any{"KeyMetadata": metadata}
				default:
					t.Fatalf("qualification used unexpected operation %q", operation)
				}
				encoded, err := json.Marshal(reply)
				if err != nil {
					t.Fatal(err)
				}
				return response(200, string(encoded), http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			id := contract.Hash([]byte("qualification"))
			binding := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: tc.role, Provider: contract.AWS, SigningProfile: 1, BindingID: id, KeySelector: c.KeyARN, SPKI: der, Fingerprint: contract.Hash(der), Binding: contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: tr.Identity(), PublicKey: contract.Hash(der), Interpretation: contract.InterpretationID(), ControlIncarnationID: id, Epoch: 1}}
			digest, err := contract.SigningBindingDigest(binding)
			if err != nil {
				t.Fatal(err)
			}
			got := tr.QualifySigningBinding(ctx, binding)
			wantOperations := []string{"TrentService.GetPublicKey"}
			if tc.role == contract.RecoverySigningRole && tc.name != "public-denied" && tc.name != "public-invalid" {
				wantOperations = append(wantOperations, "TrentService.DescribeKey")
			}
			if !slices.Equal(operations, wantOperations) || got.Reason != tc.reason {
				t.Fatalf("qualification operations=%v result=%+v", operations, got)
			}
			metricResult := "invalid"
			switch tc.reason {
			case contract.ReasonNone:
				metricResult = "success"
			case contract.ReasonAccess, contract.ReasonTransport:
				metricResult = "evidence_unavailable"
			}
			data := snapshot()
			if telemetrySum(data, telemetry.OperationResults, telemetry.OpTrustQualify, metricResult, "") != 1 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpTrustQualify, "", "") != int64(len(operations)) {
				t.Error("qualification operation or owned HTTP metrics differ")
			}
			if tc.reason == contract.ReasonNone {
				target := contract.NormalSignerTarget
				if tc.role == contract.RecoverySigningRole {
					target = contract.RecoverySignerTarget
				}
				if got != (contract.SigningQualificationResult{TargetRole: target, SigningBindingDigest: digest, Provider: contract.AWS, Qualified: 1}) {
					t.Fatalf("qualification success differs: %+v", got)
				}
			} else if got.Qualified != 0 {
				t.Fatal("failed qualification admitted a signer")
			}
		})
	}
}

// full_only: false
func TestNewTrustValidatesBeforeCredentialAccess(t *testing.T) {
	keys := map[string][]byte{}
	for name, curve := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = der
	}
	for _, tc := range []struct {
		name   string
		mutate func(*TrustConfig)
	}{
		{"valid", func(*TrustConfig) {}},
		{"wrong-region-arn", func(c *TrustConfig) { c.Region = "us-west-2" }},
		{"key-alias", func(c *TrustConfig) { c.KeyARN = "arn:aws:kms:us-east-1:123456789012:alias/signing" }},
		{"missing-credential-route", func(c *TrustConfig) { c.CredentialRoute = contract.ID{} }},
		{"missing-credentials", func(c *TrustConfig) { c.Credentials = nil }},
		{"unknown-role", func(c *TrustConfig) { c.Role = 3 }},
		{"malformed-verifier", func(c *TrustConfig) { c.PublicKeyDER = []byte("not an SPKI") }},
		{"non-p256-verifier", func(c *TrustConfig) { c.PublicKeyDER = keys["p384"] }},
		{"insecure-tls", func(c *TrustConfig) { c.Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} }},
		{"server-name-override", func(c *TrustConfig) { c.Transport.TLSClientConfig = &tls.Config{ServerName: "another-host"} }},
		{"tls-dial-override", func(c *TrustConfig) {
			c.Transport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
				t.Error("constructor dialed TLS")
				return nil, io.ErrUnexpectedEOF
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := testStoreConfig()
			credentials, dials := 0, 0
			c := TrustConfig{Region: sc.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: keys["p256"], CredentialRoute: sc.CredentialRoute, Timeout: sc.Timeout,
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					credentials++
					return aws.Credentials{}, errors.New("credentials must remain untouched")
				}),
				Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials++
					return nil, io.ErrUnexpectedEOF
				}},
			}
			tc.mutate(&c)
			trust, err := NewTrust(c)
			if tc.name == "valid" {
				if err != nil || trust == nil || trust.Identity().IsZero() {
					t.Fatalf("valid construction: trust=%v err=%v", trust, err)
				}
			} else if !errors.Is(err, ErrConstruction) || trust != nil {
				t.Fatalf("accepted construction: trust=%v err=%v", trust, err)
			}
			if credentials != 0 || dials != 0 {
				t.Fatalf("constructor reached credential/network: %d/%d", credentials, dials)
			}
		})
	}
}

// full_only: false
func TestTrustUsesClosedDigestAndVerifiesSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sc := testStoreConfig()
	c := TrustConfig{Region: sc.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: der, CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: sc.Timeout}
	id := contract.Hash([]byte("subject"))
	req, err := contract.NewBindingRequest(contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: id, PublicKey: id, Interpretation: id, ControlIncarnationID: id, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "wrong-key", "wrong-algorithm", "wrong-signature", "overlong", "lost-reply"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			calls := 0
			requestBytes, responseBytes := 0, 0
			tr, err := newTrust(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.Host != "kms.us-east-1.amazonaws.com" || r.Header.Get("X-Amz-Target") != "TrentService.Sign" {
					t.Errorf("unexpected KMS operation %s", r.URL)
				}
				b, err := io.ReadAll(r.Body)
				requestBytes += len(b)
				if err != nil {
					t.Fatal(err)
				}
				var in struct{ KeyId, Message, MessageType, SigningAlgorithm string }
				if json.Unmarshal(b, &in) != nil {
					t.Fatal("invalid SDK JSON")
				}
				digest := req.Digest()
				if in.KeyId != c.KeyARN || in.MessageType != "DIGEST" || in.SigningAlgorithm != "ECDSA_SHA_256" || in.Message != base64.StdEncoding.EncodeToString(digest[:]) {
					t.Errorf("wrong closed digest request: %+v", in)
				}
				if mode == "lost-reply" {
					return nil, io.ErrUnexpectedEOF
				}
				sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
				if err != nil {
					t.Fatal(err)
				}
				out := map[string]any{"KeyId": c.KeyARN, "SigningAlgorithm": "ECDSA_SHA_256", "Signature": base64.StdEncoding.EncodeToString(sig)}
				switch mode {
				case "wrong-key":
					out["KeyId"] = "another-key"
				case "wrong-algorithm":
					out["SigningAlgorithm"] = "RSASSA_PKCS1_V1_5_SHA_256"
				case "wrong-signature":
					out["Signature"] = "AQID"
				case "overlong":
					out["Signature"] = base64.StdEncoding.EncodeToString(make([]byte, 73))
				}
				encoded, _ := json.Marshal(out)
				responseBytes += len(encoded)
				return response(200, string(encoded), http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := tr.Sign(ctx, req)
			if mode == "valid" {
				d := req.Digest()
				if got.Reason != contract.ReasonNone || !ecdsa.VerifyASN1(&key.PublicKey, d[:], got.Signature) {
					t.Fatalf("invalid success: %+v", got)
				}
			} else if len(got.Signature) != 0 || got.Reason == contract.ReasonNone {
				t.Fatalf("accepted %s: %+v", mode, got)
			}
			if calls != 1 {
				t.Fatalf("calls=%d", calls)
			}
			data := snapshot()
			if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpTrustSign, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, telemetry.OpTrustSign, "", "complete") != int64(requestBytes) || telemetrySum(data, telemetry.HTTPResponseBodyBytes, telemetry.OpTrustSign, "", "") != int64(responseBytes) {
				t.Fatal("telemetry differs from KMS transport observations")
			}
		})
	}
}

// full_only: false
func TestTrustQualificationKeepsIndependentVerifier(t *testing.T) {
	sc := testStoreConfig()
	der := anchorPublicKey(t)
	calls := 0
	config := TrustConfig{Role: contract.NormalSigningRole, Region: sc.Region,
		KeyARN:       "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		PublicKeyDER: der, CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: sc.Timeout}
	trust, err := newTrust(config, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		t.Fatal("substituted verifier reached public lookup")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	binding := anchorBinding(config.Role, config.KeyARN, anchorPublicKey(t), trust.Identity())
	got := trust.QualifySigningBinding(context.Background(), binding)
	if got != (contract.SigningQualificationResult{Reason: contract.ReasonConstruction}) || calls != 0 {
		t.Fatal("ordinary Trust lost its independent pin", got, calls)
	}
}
