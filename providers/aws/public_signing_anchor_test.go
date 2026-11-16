package awsprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
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

func anchorBinding(role uint8, arn string, der []byte, trust contract.ID) contract.PublicSigningBinding {
	id := contract.Hash([]byte("public anchor binding"))
	fingerprint := contract.Hash(der)
	return contract.PublicSigningBinding{
		Schema: contract.CanonicalSchema, Role: role, Provider: contract.AWS,
		SigningProfile: contract.P256SigningProfile, BindingID: id, KeySelector: arn,
		SPKI: der, Fingerprint: fingerprint,
		Binding: contract.BindingSubject{Domain: id, Coordinate: id, Store: id,
			Trust: trust, PublicKey: fingerprint, Interpretation: contract.InterpretationID(),
			ControlIncarnationID: id, Epoch: 1},
	}
}

// full_only: false
func TestPublicSigningAnchorPinsOneResourceAndHasNoSign(t *testing.T) {
	der, otherDER := anchorPublicKey(t), anchorPublicKey(t)
	for _, role := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
		t.Run(map[uint8]string{contract.NormalSigningRole: "normal", contract.RecoverySigningRole: "recovery"}[role], func(t *testing.T) {
			sc := testStoreConfig()
			credentialCalls := 0
			c := PublicSigningAnchorConfig{Role: role, Region: sc.Region,
				KeyARN:          "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
				CredentialRoute: sc.CredentialRoute, Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
					credentialCalls++
					return sc.Credentials.Retrieve(ctx)
				}), Timeout: sc.Timeout}
			var operations []string
			anchor, err := newPublicSigningAnchor(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				operation := r.Header.Get("X-Amz-Target")
				operations = append(operations, operation)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var request struct{ KeyId string }
				if json.Unmarshal(body, &request) != nil || request.KeyId != c.KeyARN {
					t.Fatal("public lookup used a selected or different key")
				}
				var reply map[string]any
				switch operation {
				case "TrentService.GetPublicKey":
					reply = map[string]any{"KeyId": c.KeyARN, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "PublicKey": base64.StdEncoding.EncodeToString(der), "SigningAlgorithms": []string{"ECDSA_SHA_256"}}
				case "TrentService.DescribeKey":
					reply = map[string]any{"KeyMetadata": map[string]any{"Arn": c.KeyARN, "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}}
				default:
					t.Fatalf("public anchor sent %q", operation)
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
			if _, has := reflect.TypeOf(anchor).MethodByName("Sign"); has {
				t.Fatal("public anchor exposes Sign")
			}
			trust, err := newTrust(TrustConfig{Role: role, Region: c.Region, KeyARN: c.KeyARN,
				PublicKeyDER: der, CredentialRoute: c.CredentialRoute, Credentials: c.Credentials, Timeout: c.Timeout},
				roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Fatal("trust construction sent a request")
					return nil, nil
				}))
			if err != nil || anchor.Identity() != trust.Identity() {
				t.Fatalf("public anchor lost the selected Trust construction identity: %v", err)
			}
			binding := anchorBinding(role, c.KeyARN, der, anchor.identity)
			wrongSelector := binding
			wrongSelector.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/87654321-1234-1234-1234-123456789012"
			if got := anchor.QualifySigningBinding(context.Background(), wrongSelector); got.Reason != contract.ReasonConstruction || len(operations) != 0 || credentialCalls != 0 {
				t.Fatalf("selected alternate key entered lookup: %+v, %v", got, operations)
			}
			for _, change := range []func(*contract.PublicSigningBinding){
				func(b *contract.PublicSigningBinding) { b.Role = 3 - role },
				func(b *contract.PublicSigningBinding) { b.Provider = contract.GCP },
				func(b *contract.PublicSigningBinding) { b.SigningProfile++ },
				func(b *contract.PublicSigningBinding) { b.Fingerprint = contract.Hash([]byte("wrong fingerprint")) },
				func(b *contract.PublicSigningBinding) { b.SPKI = []byte("malformed SPKI") },
			} {
				bad := binding
				change(&bad)
				if got := anchor.QualifySigningBinding(context.Background(), bad); got.Reason != contract.ReasonConstruction || len(operations) != 0 || credentialCalls != 0 {
					t.Fatal("unbound signing evidence entered lookup", got)
				}
			}
			wrongTrust := binding
			wrongTrust.Binding.Trust = contract.Hash([]byte("wrong trust construction"))
			if got := anchor.QualifySigningBinding(context.Background(), wrongTrust); got.Reason != contract.ReasonConstruction || len(operations) != 0 || credentialCalls != 0 {
				t.Fatalf("wrong trust construction entered lookup: %+v, %v", got, operations)
			}
			wrongKey := anchorBinding(role, c.KeyARN, otherDER, anchor.identity)
			if got := anchor.QualifySigningBinding(context.Background(), wrongKey); got.Reason != contract.ReasonProof || !slices.Equal(operations, []string{"TrentService.GetPublicKey"}) {
				t.Fatalf("wrong SPKI accepted: %+v, %v", got, operations)
			}
			operations = nil
			digest, err := contract.SigningBindingDigest(binding)
			if err != nil {
				t.Fatal(err)
			}
			got := anchor.QualifySigningBinding(context.Background(), binding)
			wantRole := contract.NormalSignerTarget
			wantOperations := []string{"TrentService.GetPublicKey"}
			if role == contract.RecoverySigningRole {
				wantRole = contract.RecoverySignerTarget
				wantOperations = append(wantOperations, "TrentService.DescribeKey")
			}
			if got != (contract.SigningQualificationResult{TargetRole: wantRole, SigningBindingDigest: digest, Provider: contract.AWS, Qualified: 1}) || !slices.Equal(operations, wantOperations) {
				t.Fatalf("public qualification=%+v operations=%v", got, operations)
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
	sc := testStoreConfig()
	c := PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: sc.Region,
		KeyARN:          "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: sc.Timeout,
		Transport: &http.Transport{}}
	for _, change := range []func(*PublicSigningAnchorConfig){
		func(c *PublicSigningAnchorConfig) { c.Role = 0 },
		func(c *PublicSigningAnchorConfig) { c.Role = 3 },
		func(c *PublicSigningAnchorConfig) { c.KeyARN = "alias/current" },
		func(c *PublicSigningAnchorConfig) { c.Region = "us-west-2" },
		func(c *PublicSigningAnchorConfig) { c.CredentialRoute = contract.ID{} },
	} {
		bad := c
		change(&bad)
		if anchor, err := NewPublicSigningAnchor(bad); err != ErrConstruction || anchor != nil {
			t.Fatalf("unpinned public anchor accepted: %v, %v", anchor, err)
		}
	}
	if _, err := NewPublicSigningAnchor(c); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestPublicSigningAnchorRefusesIncompleteRemoteEvidence(t *testing.T) {
	der := anchorPublicKey(t)
	for _, tc := range []struct {
		mode  string
		want  contract.Reason
		calls int
	}{
		{"public-denied", contract.ReasonAccess, 1},
		{"public-unavailable", contract.ReasonTransport, 1},
		{"public-wrong-key", contract.ReasonProof, 1},
		{"public-wrong-type", contract.ReasonProof, 1},
		{"public-wrong-usage", contract.ReasonProof, 1},
		{"public-wrong-algorithm", contract.ReasonProof, 1},
		{"public-missing-algorithm", contract.ReasonProof, 1},
		{"public-extra-algorithm", contract.ReasonProof, 1},
		{"public-bad-spki", contract.ReasonProof, 1},
		{"public-malformed", contract.ReasonTransport, 1},
		{"public-truncated", contract.ReasonTransport, 1},
		{"public-overlimit", contract.ReasonTransport, 1},
		{"metadata-denied", contract.ReasonAccess, 2},
		{"metadata-imported", contract.ReasonProof, 2},
		{"metadata-wrong-key", contract.ReasonProof, 2},
		{"metadata-disabled", contract.ReasonProof, 2},
		{"metadata-wrong-state", contract.ReasonProof, 2},
		{"metadata-wrong-type", contract.ReasonProof, 2},
		{"metadata-wrong-usage", contract.ReasonProof, 2},
		{"metadata-lost", contract.ReasonTransport, 2},
		{"metadata-truncated", contract.ReasonTransport, 2},
		{"metadata-overlimit", contract.ReasonTransport, 2},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			sc := testStoreConfig()
			c := PublicSigningAnchorConfig{Role: contract.RecoverySigningRole, Region: sc.Region,
				KeyARN:          "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
				CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: sc.Timeout}
			calls := 0
			anchor, err := newPublicSigningAnchor(c, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				switch r.Header.Get("X-Amz-Target") {
				case "TrentService.GetPublicKey":
					if tc.mode == "public-denied" {
						return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
					}
					if tc.mode == "public-unavailable" {
						return response(503, `{"__type":"KMSInternalException"}`, nil), nil
					}
					if tc.mode == "public-overlimit" {
						return response(200, strings.Repeat("x", maximumPublicResponseBytes+1), nil), nil
					}
					if tc.mode == "public-malformed" {
						return response(200, "{", http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}), nil
					}
					keyARN := c.KeyARN
					if tc.mode == "public-wrong-key" {
						keyARN = strings.Replace(keyARN, "/12345678-", "/87654321-", 1)
					}
					out := map[string]any{"KeyId": keyARN, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "PublicKey": base64.StdEncoding.EncodeToString(der), "SigningAlgorithms": []string{"ECDSA_SHA_256"}}
					switch tc.mode {
					case "public-wrong-type":
						out["KeySpec"] = "RSA_3072"
					case "public-wrong-usage":
						out["KeyUsage"] = "ENCRYPT_DECRYPT"
					case "public-wrong-algorithm":
						out["SigningAlgorithms"] = []string{"ECDSA_SHA_384"}
					case "public-missing-algorithm":
						delete(out, "SigningAlgorithms")
					case "public-extra-algorithm":
						out["SigningAlgorithms"] = []string{"ECDSA_SHA_256", "ECDSA_SHA_384"}
					case "public-bad-spki":
						out["PublicKey"] = base64.StdEncoding.EncodeToString([]byte("malformed SPKI"))
					}
					body, err := json.Marshal(out)
					if err != nil {
						t.Fatal(err)
					}
					reply := response(200, string(body), http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}})
					if tc.mode == "public-truncated" {
						reply.ContentLength++
					}
					return reply, nil
				case "TrentService.DescribeKey":
					if tc.mode == "metadata-denied" {
						return response(403, `{"__type":"AccessDeniedException"}`, nil), nil
					}
					if tc.mode == "metadata-lost" {
						return nil, io.ErrUnexpectedEOF
					}
					if tc.mode == "metadata-overlimit" {
						return response(200, strings.Repeat("x", maximumPublicResponseBytes+1), nil), nil
					}
					origin := "AWS_KMS"
					if tc.mode == "metadata-imported" {
						origin = "EXTERNAL"
					}
					metadata := map[string]any{"Arn": c.KeyARN, "Enabled": true, "KeyState": "Enabled", "Origin": origin, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}
					switch tc.mode {
					case "metadata-wrong-key":
						metadata["Arn"] = strings.Replace(c.KeyARN, "us-east-1", "us-west-2", 1)
					case "metadata-disabled":
						metadata["Enabled"] = false
					case "metadata-wrong-state":
						metadata["KeyState"] = "Disabled"
					case "metadata-wrong-type":
						metadata["KeySpec"] = "ECC_NIST_P384"
					case "metadata-wrong-usage":
						metadata["KeyUsage"] = "ENCRYPT_DECRYPT"
					}
					body, err := json.Marshal(map[string]any{"KeyMetadata": metadata})
					if err != nil {
						t.Fatal(err)
					}
					reply := response(200, string(body), http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}})
					if tc.mode == "metadata-truncated" {
						reply.ContentLength++
					}
					return reply, nil
				default:
					t.Fatal("public anchor sent another KMS operation")
					return nil, nil
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := anchor.QualifySigningBinding(ctx, anchorBinding(c.Role, c.KeyARN, der, anchor.identity))
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
	sc := testStoreConfig()
	credentialCalls := 0
	c := PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: sc.Region,
		KeyARN:          "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		CredentialRoute: sc.CredentialRoute, Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			credentialCalls++
			return sc.Credentials.Retrieve(ctx)
		}), Timeout: sc.Timeout}
	calls := 0
	anchor, err := newPublicSigningAnchor(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := anchor.QualifySigningBinding(ctx, anchorBinding(c.Role, c.KeyARN, anchorPublicKey(t), anchor.identity))
	if got.Reason != contract.ReasonAccess || got.Qualified != 0 || calls != 0 || credentialCalls != 0 {
		t.Fatalf("cancelled public lookup=%+v calls=%d credentials=%d", got, calls, credentialCalls)
	}
}

// full_only: false
func TestPublicSigningAnchorStopsAfterCredentialCancellation(t *testing.T) {
	sc := testStoreConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	credentialCalls := 0
	c := PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: sc.Region,
		KeyARN:          "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		CredentialRoute: sc.CredentialRoute, Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			credentialCalls++
			creds, err := sc.Credentials.Retrieve(ctx)
			cancel()
			return creds, err
		}), Timeout: sc.Timeout}
	calls := 0
	anchor, err := newPublicSigningAnchor(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := anchor.QualifySigningBinding(ctx, anchorBinding(c.Role, c.KeyARN, anchorPublicKey(t), anchor.identity))
	if got.Reason != contract.ReasonAccess || got.Qualified != 0 || calls != 0 || credentialCalls != 1 {
		t.Fatalf("credential cancellation entered lookup: %+v calls=%d credentials=%d", got, calls, credentialCalls)
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
						sc := testStoreConfig()
						c := PublicSigningAnchorConfig{Role: role, Region: sc.Region,
							KeyARN:          "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
							CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: sc.Timeout}
						rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
							calls++
							if _, err := io.Copy(io.Discard, req.Body); err != nil {
								t.Fatal(err)
							}
							if err := req.Body.Close(); err != nil {
								t.Fatal(err)
							}
							var out map[string]any
							switch req.Header.Get("X-Amz-Target") {
							case "TrentService.GetPublicKey":
								if calls != 1 {
									t.Fatal("extra public-key request")
								}
								out = map[string]any{"KeyId": c.KeyARN, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "PublicKey": base64.StdEncoding.EncodeToString(der), "SigningAlgorithms": []string{"ECDSA_SHA_256"}}
							case "TrentService.DescribeKey":
								if calls != 2 || role != contract.RecoverySigningRole || when == "first-response" {
									t.Fatal("lookup advanced after cancellation")
								}
								out = map[string]any{"KeyMetadata": map[string]any{"Arn": c.KeyARN, "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}}
							default:
								t.Fatal("qualification sent another operation")
							}
							body, err := json.Marshal(out)
							if err != nil {
								t.Fatal(err)
							}
							reply := response(http.StatusOK, string(body), http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}})
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
						})
						var qualify func(context.Context, contract.PublicSigningBinding) contract.SigningQualificationResult
						var identity contract.ID
						if ordinary {
							trust, err := newTrust(TrustConfig{Role: role, Region: c.Region, KeyARN: c.KeyARN, PublicKeyDER: der,
								CredentialRoute: c.CredentialRoute, Credentials: c.Credentials, Timeout: c.Timeout}, rt)
							if err != nil {
								t.Fatal(err)
							}
							qualify, identity = trust.QualifySigningBinding, trust.Identity()
						} else {
							anchor, err := newPublicSigningAnchor(c, rt)
							if err != nil {
								t.Fatal(err)
							}
							qualify, identity = anchor.QualifySigningBinding, anchor.identity
						}
						got := qualify(ctx, anchorBinding(role, c.KeyARN, der, identity))
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
