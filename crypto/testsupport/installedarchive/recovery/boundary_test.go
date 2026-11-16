package recovery

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/crypto/testsupport/installedarchive"
)

func validInput() installedarchive.RecoveryInput {
	return installedarchive.RecoveryInput{Provider: "gcp", Bucket: "fixture-bucket", Region: "us-central1", Prefix: "fixture", NormalSigner: "independent-resource", NormalRegion: "us-central1", ReadRoute: "new-read", SignRoute: "new-sign", PrivateRoute: "new-private", Token: "local-token", TimeoutMillis: 1000, Output: "/new/returned.json", Responder: "127.0.0.1:1234"}
}

// full_only: false
func TestRestrictedInputHasNoSavedBasisAndRejectsInvalidFraming(t *testing.T) {
	body, err := json.Marshal(validInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRecoveryInput(bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"domain", "descriptor", "basis", "objects", "public_key", "authority_binding", "expected_value", "setup_path"} {
		t.Run(field, func(t *testing.T) {
			damaged := append(bytes.Clone(body[:len(body)-1]), []byte(`,"`+field+`":"forbidden"}`)...)
			if _, err := DecodeRecoveryInput(bytes.NewReader(damaged)); err == nil {
				t.Fatal("saved basis field admitted")
			}
		})
	}
	for _, spec := range []struct {
		name string
		body []byte
	}{{"trailing", append(bytes.Clone(body), body...)}, {"oversized", append(bytes.Clone(body), bytes.Repeat([]byte(" "), MaximumRecoveryInputBytes)...)}, {"truncated", body[:len(body)-1]}, {"duplicate", append(bytes.Clone(body[:len(body)-1]), []byte(`,"provider":"gcp"}`)...)}} {
		t.Run(spec.name, func(t *testing.T) {
			if _, err := DecodeRecoveryInput(bytes.NewReader(spec.body)); err == nil {
				t.Fatal("invalid framing admitted")
			}
		})
	}
	for _, spec := range []struct {
		name   string
		change func(*installedarchive.RecoveryInput)
	}{
		{"remote_transport", func(v *installedarchive.RecoveryInput) { v.Responder = "192.0.2.1:80" }},
		{"unbounded_time", func(v *installedarchive.RecoveryInput) { v.TimeoutMillis = 60001 }},
		{"relative_output", func(v *installedarchive.RecoveryInput) { v.Output = "returned.json" }},
		{"mixed_credentials", func(v *installedarchive.RecoveryInput) { v.AccessKey = "old-key" }},
		{"missing_anchor", func(v *installedarchive.RecoveryInput) { v.NormalSigner = "" }},
		{"named_port", func(v *installedarchive.RecoveryInput) { v.Responder = "127.0.0.1:https" }},
		{"zero_port", func(v *installedarchive.RecoveryInput) { v.Responder = "127.0.0.1:0" }},
		{"overflow_port", func(v *installedarchive.RecoveryInput) { v.Responder = "127.0.0.1:65536" }},
		{"missing_region", func(v *installedarchive.RecoveryInput) { v.NormalRegion = "" }},
		{"unused_region", func(v *installedarchive.RecoveryInput) { v.RecoveryRegion = "us-central1" }},
	} {
		t.Run(spec.name, func(t *testing.T) {
			value := validInput()
			spec.change(&value)
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRecoveryInput(bytes.NewReader(body)); err == nil {
				t.Fatal("invalid input admitted")
			}
		})
	}
}

// full_only: false
func TestRestrictedEnvironmentRejectsInheritedOrChangedValues(t *testing.T) {
	good := RecoveryEnvironment("/new/home", "/new/tmp")
	if err := validateRecoveryEnvironment(good, "/new/cwd"); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		name    string
		entries []string
	}{
		{"proxy", append(append([]string(nil), good...), "HTTPS_PROXY=http://old")},
		{"credentials", append(append([]string(nil), good...), "AWS_PROFILE=old")},
		{"duplicate", []string{good[0], good[0], good[2], good[3]}},
		{"race", []string{good[0], good[1], "GORACE=exitcode=0", good[3]}},
		{"shared_directory", RecoveryEnvironment("/new/home", "/new/home")},
	} {
		t.Run(spec.name, func(t *testing.T) {
			if err := validateRecoveryEnvironment(spec.entries, "/new/cwd"); err == nil {
				t.Fatal("inherited environment admitted")
			}
		})
	}
}

// full_only: false
func TestReturnedObservationsRequireExactBytesBeforePrivateOpen(t *testing.T) {
	archive := installedarchive.Load(t, "gcp")
	parts, err := archive.SelectedParts()
	if err != nil {
		t.Fatal(err)
	}
	headObject, ok := archive.Object(archive.Location.PrefixBeforeHEAD + "/HEAD")
	if !ok {
		t.Fatal("HEAD missing")
	}
	provenance := Provenance{Domain: archive.Domain, Revision: archive.Revision, Snapshot: parts[2].Ref.Object, HEADDigest: archive.HeadDigest, HEADToken: headObject.Token}
	values := []installedarchive.ExpectedValue{{Name: "installed-positive-secret", Bytes: []byte("enkv first secret test value")}}
	path := filepath.Join(t.TempDir(), "returned.json")
	if err := WriteReturnedParts(path, provenance, parts); err != nil {
		t.Fatal(err)
	}
	opened, err := CheckReturnedParts(archive, path, values)
	if err != nil || opened != 1 {
		t.Fatal(opened, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		name string
		body []byte
	}{{"truncated", body[:len(body)-1]}, {"duplicate", append(bytes.Clone(body[:len(body)-1]), []byte(`,"provider":"gcp"}`)...)}, {"extra", append(bytes.Clone(body), ' ')}, {"wrong_body", bytes.Replace(body, []byte(`"Kind":"root"`), []byte(`"Kind":"ROOT"`), 1)}} {
		t.Run(spec.name, func(t *testing.T) {
			if err := os.WriteFile(path, spec.body, 0600); err != nil {
				t.Fatal(err)
			}
			if opened, err := CheckReturnedParts(archive, path, values); err == nil || opened != 0 {
				t.Fatal("damaged observation privately opened", opened, err)
			}
		})
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckReturnedParts(archive, path, []installedarchive.ExpectedValue{{Name: values[0].Name, Bytes: []byte("wrong independent value")}}); err == nil {
		t.Fatal("wrong application bytes admitted")
	}
}

// full_only: false
func TestResponderRefusesInventoryAndMutationsWithoutChangingRemoteState(t *testing.T) {
	archive := installedarchive.Load(t, "gcp")
	resources := installedarchive.RecoveryResources{Normal: installedarchive.SigningResource{Selector: archive.SignerSelector, PublicKey: archive.SignerPublicKey}}
	r := NewRecoveryResponder(t, archive, resources)
	before, err := r.RemoteBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct{ method, host, path string }{{"GET", "oracle.invalid", "/objects"}, {"POST", "storage." + archive.Location.Region + ".rep.googleapis.com", "/upload/storage/v1/b/fixture-bucket/o"}, {"POST", "us-central1-cloudkms.googleapis.com", "/v1/key:asymmetricSign"}} {
		q, err := http.NewRequest(spec.method, r.server.URL+spec.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		q.Host = spec.host
		q.Header.Set("Authorization", "Bearer local-token")
		response, err := r.server.Client().Do(q)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("unknown request accepted", response.StatusCode)
		}
	}
	after, err := r.RemoteBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || r.Counts().Unknown != 3 || r.Counts().AuthorityDecrypts != 0 || r.Counts().PublicLookups != 0 {
		t.Fatal("responder state changed", r.Counts())
	}
}

// full_only: false
func TestRestrictedGCPExplicitCredentialFileRequiresFiniteTransport(t *testing.T) {
	good := validInput()
	good.Token, good.Responder = "", ""
	good.ServiceAccountFile = "/new/service-account.json"
	good.Requests, good.ResponseBytes, good.BodyBytes = 100, 1<<20, 100<<20
	for _, tc := range []struct {
		name     string
		change   func(*installedarchive.RecoveryInput)
		accepted bool
	}{
		{"direct", func(*installedarchive.RecoveryInput) {}, true},
		{"distinct_credentials", func(v *installedarchive.RecoveryInput) {
			v.NormalServiceAccountFile = "/new/normal.json"
			v.PrivateServiceAccountFile = "/new/private.json"
		}, true},
		{"tls_responder", func(v *installedarchive.RecoveryInput) {
			v.Responder = "127.0.0.1:1234"
			v.TLSCertificate = []byte("bounded-test-certificate")
		}, true},
		{"relative_normal_file", func(v *installedarchive.RecoveryInput) { v.NormalServiceAccountFile = "normal.json" }, false},
		{"unused_recovery_file", func(v *installedarchive.RecoveryInput) { v.RecoveryServiceAccountFile = "/new/recovery.json" }, false},
		{"relative_private_file", func(v *installedarchive.RecoveryInput) { v.PrivateServiceAccountFile = "private.json" }, false},
		{"direct_tls", func(v *installedarchive.RecoveryInput) { v.TLSCertificate = []byte("bounded-test-certificate") }, false},
		{"mixed_token", func(v *installedarchive.RecoveryInput) { v.Token = "synthetic" }, false},
		{"aws_session", func(v *installedarchive.RecoveryInput) { v.SessionToken = "synthetic" }, false},
		{"relative_file", func(v *installedarchive.RecoveryInput) { v.ServiceAccountFile = "service-account.json" }, false},
		{"noncanonical_file", func(v *installedarchive.RecoveryInput) { v.ServiceAccountFile = "/new/../service-account.json" }, false},
		{"missing_budget", func(v *installedarchive.RecoveryInput) { v.Requests = 0 }, false},
		{"overflow_budget", func(v *installedarchive.RecoveryInput) { v.Requests = 4097 }, false},
		{"missing_response_bound", func(v *installedarchive.RecoveryInput) { v.ResponseBytes = 0 }, false},
		{"insufficient_bytes", func(v *installedarchive.RecoveryInput) { v.BodyBytes = v.ResponseBytes - 1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := good
			tc.change(&value)
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRecoveryInput(bytes.NewReader(body)); (err == nil) != tc.accepted {
				t.Fatal("explicit credential boundary", err)
			}
		})
	}
}

// full_only: false
func TestRestrictedAWSCredentialsRemainExplicitAndBounded(t *testing.T) {
	good := validInput()
	good.Provider, good.Token = "aws", ""
	good.AccessKey, good.SecretKey = "read-key", "read-secret"
	good.TLSCertificate = []byte("bounded-test-certificate")
	good.NormalAccessKey, good.NormalSecretKey = "normal-key", "normal-secret"
	good.PrivateAccessKey, good.PrivateSecretKey = "private-key", "private-secret"
	for _, row := range []struct {
		name     string
		change   func(*installedarchive.RecoveryInput)
		accepted bool
	}{
		{"distinct", func(*installedarchive.RecoveryInput) {}, true},
		{"missing_secret", func(v *installedarchive.RecoveryInput) { v.NormalSecretKey = "" }, false},
		{"missing_access", func(v *installedarchive.RecoveryInput) { v.PrivateAccessKey = "" }, false},
		{"orphan_session", func(v *installedarchive.RecoveryInput) { v.RecoverySessionToken = "unpaired" }, false},
		{"unused_recovery", func(v *installedarchive.RecoveryInput) {
			v.RecoveryAccessKey, v.RecoverySecretKey = "recovery-key", "recovery-secret"
		}, false},
		{"gcp_credentials", func(v *installedarchive.RecoveryInput) { v.PrivateServiceAccountFile = "/new/account.json" }, false},
		{"session_bound", func(v *installedarchive.RecoveryInput) {
			v.SessionToken = string(bytes.Repeat([]byte("x"), (16<<10)+1))
		}, false},
		{"session_controls", func(v *installedarchive.RecoveryInput) { v.PrivateSessionToken = "invalid\n" }, false},
		{"full_sessions", func(v *installedarchive.RecoveryInput) {
			v.RecoverySigner, v.RecoveryRegion = "recovery-resource", "us-east-1"
			v.RecoveryAccessKey, v.RecoverySecretKey = "recovery-key", "recovery-secret"
			v.SessionToken = string(bytes.Repeat([]byte("x"), 16<<10))
			v.NormalSessionToken, v.RecoverySessionToken, v.PrivateSessionToken = v.SessionToken, v.SessionToken, v.SessionToken
		}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			value := good
			row.change(&value)
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRecoveryInput(bytes.NewReader(body)); (err == nil) != row.accepted {
				t.Fatal("working credential boundary differs")
			}
		})
	}
}

// full_only: false
func TestRestrictedSyntheticGCPRelayRequiresFiniteLocalTransport(t *testing.T) {
	good := validInput()
	good.TLSCertificate = []byte("bounded-local-test-certificate")
	good.Requests, good.BodyBytes, good.ResponseBytes = 20, 4096, 1024
	for _, row := range []struct {
		name     string
		change   func(*installedarchive.RecoveryInput)
		accepted bool
	}{
		{"finite", func(*installedarchive.RecoveryInput) {}, true},
		{"missing-request-bound", func(v *installedarchive.RecoveryInput) { v.Requests = 0 }, false},
		{"remote", func(v *installedarchive.RecoveryInput) { v.Responder = "192.0.2.1:80" }, false},
		{"missing-responder", func(v *installedarchive.RecoveryInput) { v.Responder = "" }, false},
		{"certificate-bound", func(v *installedarchive.RecoveryInput) { v.TLSCertificate = bytes.Repeat([]byte("x"), (8<<10)+1) }, false},
		{"response-bound", func(v *installedarchive.RecoveryInput) { v.ResponseBytes = (8 << 20) + 1 }, false},
		{"missing-byte-bound", func(v *installedarchive.RecoveryInput) { v.BodyBytes = 0 }, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := good
			row.change(&input)
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRecoveryInput(bytes.NewReader(body)); (err == nil) != row.accepted {
				t.Fatal("local finite transport admission differs", err)
			}
		})
	}
}
