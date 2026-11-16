package awsprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func sharedCredentialFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// full_only: false
func TestSharedCredentialsRejectInvalidOrUnsupportedInput(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	base := "[chosen]\naws_access_key_id = file-access\naws_secret_access_key = file-secret\n"
	for name, content := range map[string]string{
		"empty": "", "malformed": "[chosen", "partial": "[chosen]\naws_access_key_id=x\n",
		"session-without-expiry": base + "aws_session_token=temporary-token\n",
		"role":                   base + "role_arn=arn:aws:iam::123456789012:role/test\n",
		"process":                base + "credential_process=never-execute\n",
		"metadata":               base + "credential_source=Ec2InstanceMetadata\n",
		"source-profile":         base + "source_profile=other\n",
		"web-identity":           base + "web_identity_token_file=never-read\n",
		"sso":                    base + "sso_start_url=https://example.invalid/start\n",
		"sso-session":            base + "sso_session=never-use\n",
		"sso-region":             base + "sso_region=us-east-1\n",
		"sso-account":            base + "sso_account_id=123456789012\n",
		"sso-role":               base + "sso_role_name=test\n",
		"endpoint":               base + "endpoint_url=https://example.invalid\n",
		"services":               base + "services=never-use\n",
		"metadata-endpoint":      base + "ec2_metadata_service_endpoint=http://127.0.0.1\n",
		"oversized":              strings.Repeat("x", 65537),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadSharedCredentialsFile(context.Background(), sharedCredentialFile(t, content), "chosen", time.Time{})
			if err != ErrCredentials {
				t.Fatal("invalid file did not return redacted refusal")
			}
		})
	}
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		if _, err := LoadSharedCredentialsFile(context.Background(), path, "chosen", time.Time{}); err != ErrCredentials {
			t.Fatal("invalid file path accepted")
		}
	}
	path := sharedCredentialFile(t, base)
	if _, err := LoadSharedCredentialsFile(context.Background(), path, "", time.Time{}); err != ErrCredentials {
		t.Fatal("implicit profile accepted")
	}
	if _, err := LoadSharedCredentialsFile(context.Background(), path, "chosen", time.Now().Add(-time.Second)); err != ErrCredentials {
		t.Fatal("expired credentials accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadSharedCredentialsFile(ctx, path, "chosen", time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled load accepted")
	}
}

// full_only: false
func TestSharedCredentialsSessionTokenExpiryAndExplicitReload(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	path := sharedCredentialFile(t, "[chosen]\naws_access_key_id=first-access\naws_secret_access_key=first-secret\naws_session_token=first-token\n")
	expires := time.Now().Add(time.Hour)
	p, err := LoadSharedCredentialsFile(ctx, path, "chosen", expires)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Retrieve(ctx)
	if err != nil || c.SessionToken != "first-token" || !c.CanExpire || !c.Expires.Equal(expires) || c.Source != "shared-file" {
		t.Fatal("temporary credential fields differ")
	}
	if err := os.WriteFile(path, []byte("[chosen]\naws_access_key_id=second-access\naws_secret_access_key=second-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	frozen, _ := p.Retrieve(ctx)
	if frozen.AccessKeyID != "first-access" {
		t.Fatal("provider silently reloaded the file")
	}
	next, err := LoadSharedCredentialsFile(ctx, path, "chosen", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, _ := next.Retrieve(ctx)
	if reloaded.AccessKeyID != "second-access" || reloaded.SessionToken != "" {
		t.Fatal("explicit reload did not replace the credentials")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Retrieve(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled retrieval accepted")
	}
	expired := p.(fileCredentials)
	expired.value.Expires = time.Now().Add(-time.Second)
	config := testStoreConfig()
	config.Credentials = expired
	s, err := newStore(config, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("expired credentials reached the service")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result := s.Create(ctx, testImmutableKey("member", 0), []byte("plain"))
	if result.Status != contract.WriteRefused || result.Reason != contract.ReasonAccess {
		t.Fatal("expired credentials did not refuse the operation")
	}
	if telemetrySum(snapshot(), telemetry.HTTPAttempts, telemetry.OpStoreCreate, "", "") != 0 {
		t.Fatal("pre-send credential refusal was counted as HTTP traffic")
	}
	config.Credentials = p
	calls := 0
	s, err = newStore(config, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("X-Amz-Security-Token") != "first-token" || !strings.Contains(r.Header.Get("Authorization"), "Credential=first-access/") {
			t.Error("selected session credentials did not reach signing")
		}
		return response(403, "<Error><Code>ExpiredToken</Code></Error>", nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	s.Create(ctx, testImmutableKey("member", 0), []byte("plain"))
	if calls != 1 {
		t.Fatal("service refusal replayed the request")
	}
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != 0 || telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpStoreCreate, "", "") != 1 {
		t.Fatal("file-only credentials added HTTP traffic")
	}
}

// full_only: false
func TestSharedCredentialsSelectOnlyExplicitFileAndProfile(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	t.Setenv("AWS_PROFILE", "ambient")
	path := sharedCredentialFile(t, "[default]\naws_access_key_id = default-access\naws_secret_access_key = default-secret\n[chosen]\naws_access_key_id = chosen-access\naws_secret_access_key = chosen-secret\n")
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aws", "config"), []byte("[profile chosen]\nrole_arn=arn:aws:iam::123456789012:role/ambient\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	p, err := LoadSharedCredentialsFile(context.Background(), path, "chosen", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "chosen-access" || c.SecretAccessKey != "chosen-secret" || c.CanExpire {
		t.Fatal("selected credentials differ")
	}
	if _, err := LoadSharedCredentialsFile(context.Background(), path, "absent", time.Time{}); !errors.Is(err, ErrCredentials) {
		t.Fatal("missing profile did not refuse")
	}
}

// full_only: false
func TestSharedCredentialsStaticGrammar(t *testing.T) {
	content := " ; full-line comment\r\n" +
		"[default]\r\naws_access_key_id=default-access\r\naws_secret_access_key=default-secret\r\n" +
		"[unselected]\r\ncredential_process=never-execute\r\n continued junk\r\n" +
		"[chosen] ; selected profile\r\n" +
		"AWS_ACCESS_KEY_ID = access=#literal ; ignored\r\n" +
		"aws_secret_access_key = secret=with=equals#literal;literal # ignored\r\n" +
		"aws_session_token = token#literal;literal\r\n"
	p, err := LoadSharedCredentialsFile(context.Background(), sharedCredentialFile(t, content), "chosen", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "access=#literal" || c.SecretAccessKey != "secret=with=equals#literal;literal" || c.SessionToken != "token#literal;literal" {
		t.Fatal("static credential grammar changed values")
	}
	p, err = LoadSharedCredentialsFile(context.Background(), sharedCredentialFile(t, content), "default", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	c, err = p.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "default-access" || c.SecretAccessKey != "default-secret" || c.SessionToken != "" {
		t.Fatal("default profile did not remain distinct")
	}
}

// full_only: false
func TestSharedCredentialsFileSizeBoundary(t *testing.T) {
	base := "[chosen]\naws_access_key_id=access\naws_secret_access_key=secret\n#"
	exact := base + strings.Repeat("x", credentialLimit-len(base))
	if len(exact) != credentialLimit {
		t.Fatal("invalid exact-boundary fixture")
	}
	if _, err := LoadSharedCredentialsFile(context.Background(), sharedCredentialFile(t, exact), "chosen", time.Time{}); err != nil {
		t.Fatal("exact credential-file boundary refused")
	}
	if _, err := LoadSharedCredentialsFile(context.Background(), sharedCredentialFile(t, exact+"x"), "chosen", time.Time{}); err != ErrCredentials {
		t.Fatal("credential file above boundary accepted")
	}
}

// full_only: false
func TestSharedCredentialsOwnedInputIsCleared(t *testing.T) {
	for name, input := range map[string][]byte{
		"success": []byte("[chosen]\naws_access_key_id=access\naws_secret_access_key=secret\n"),
		"failure": []byte("[chosen]\naws_access_key_id=access\n"),
	} {
		t.Run(name, func(t *testing.T) {
			_, _ = parseOwnedSharedCredentials(input, "chosen")
			for _, b := range input {
				if b != 0 {
					t.Fatal("owned credential input was not cleared")
				}
			}
		})
	}
}

// full_only: false
func TestSharedCredentialsRejectAmbiguousSelectedProfile(t *testing.T) {
	base := "[chosen]\naws_access_key_id=access\naws_secret_access_key=secret\n"
	for name, content := range map[string]string{
		"duplicate-section": base + "[chosen]\naws_access_key_id=other\naws_secret_access_key=other\n",
		"duplicate-field":   base + "aws_access_key_id=other\n",
		"continuation":      "[chosen]\naws_access_key_id=access\naws_secret_access_key=secret\n continued\n",
		"unknown-field":     base + "credential_process=never-execute\n",
		"missing-separator": "[chosen]\naws_access_key_id=access\naws_secret_access_key secret\n",
		"colon-separator":   "[chosen]\naws_access_key_id=access\naws_secret_access_key:secret\n",
		"empty-field":       "[chosen]\naws_access_key_id=access\naws_secret_access_key=\n",
		"empty-section":     "[chosen]\n",
		"malformed-section": base + "[other\n",
		"non-ascii":         "[chosen]\naws_access_key_id=access\naws_secret_access_key=sécret\n",
		"control-byte":      "[chosen]\naws_access_key_id=access\naws_secret_access_key=se\x1fcret\n",
		"delete-byte":       "[chosen]\naws_access_key_id=access\naws_secret_access_key=se\x7fcret\n",
		"bare-cr-terminal":  "[chosen]\naws_access_key_id=access\naws_secret_access_key=secret\r",
		"bare-cr-middle":    "[chosen]\naws_access_key_id=access\raws_secret_access_key=secret\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadSharedCredentialsFile(context.Background(), sharedCredentialFile(t, content), "chosen", time.Time{}); err != ErrCredentials {
				t.Fatal("ambiguous selected profile accepted")
			}
		})
	}
}

// full_only: false
func TestInvalidConstructionAndOperationsDoNotRetrieveCredentials(t *testing.T) {
	c := testStoreConfig()
	credentials := 0
	requests := 0
	c.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		credentials++
		return aws.Credentials{}, errors.New("credentials unavailable")
	})
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if _, err := NewStore(c); err == nil {
		t.Fatal("accepted insecure TLS")
	}
	c.Transport = &http.Transport{}
	for _, mutate := range []func(*StoreConfig){func(c *StoreConfig) { c.Region = "" }, func(c *StoreConfig) { c.Bucket = "bucket--zone--x-s3" }, func(c *StoreConfig) { c.Prefix = "a/../b" }, func(c *StoreConfig) { c.ExpectedBucketOwner = "owner" }, func(c *StoreConfig) { c.CredentialRoute = contract.ID{} }} {
		copy := c
		mutate(&copy)
		if _, err := NewStore(copy); err == nil {
			t.Fatalf("accepted bad config: %+v", copy)
		}
	}
	s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) { requests++; return nil, errors.New("unexpected request") }))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []func() contract.WriteResult{
		func() contract.WriteResult {
			return s.Create(context.Background(), s.Descriptor().HeadKey, []byte("x"))
		},
		func() contract.WriteResult {
			return s.Create(context.Background(), "another-prefix/object", []byte("x"))
		},
		func() contract.WriteResult {
			return s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "3"}, []byte("x"))
		},
		func() contract.WriteResult {
			return s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"old"`}, make([]byte, (64<<10)+1))
		},
	} {
		if got := f(); got.Status != contract.WriteRefused {
			t.Fatalf("invalid operation: %+v", got)
		}
	}
	if credentials != 0 || requests != 0 {
		t.Fatalf("invalid request reached credential/HTTP: %d/%d", credentials, requests)
	}
	got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"old"`}, []byte("x"))
	if got.Status != contract.WriteRefused || got.Reason != contract.ReasonAccess || requests != 0 || credentials != 1 {
		t.Fatalf("credential failure: %+v %d/%d", got, credentials, requests)
	}
}

// full_only: false
func TestInvalidCASTokensRefuseBeforeCredentials(t *testing.T) {
	for _, value := range []string{
		"*",
		"bare",
		`W/"weak"`,
		`"one", "two"`,
		` "outer"`,
		`"outer" `,
		"\"control\x1f\"",
		`"has"quote"`,
		`"` + strings.Repeat("x", 255) + `"`,
	} {
		t.Run(value, func(t *testing.T) {
			credentials, requests := 0, 0
			c := testStoreConfig()
			c.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				credentials++
				return aws.Credentials{AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret"}, nil
			})
			s, err := newStore(c, roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests++
				return response(200, "", nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: value}, []byte("candidate"))
			if got.Status != contract.WriteRefused || got.Reason != contract.ReasonConstruction || credentials != 0 || requests != 0 {
				t.Fatalf("result=%+v credential/HTTP=%d/%d", got, credentials, requests)
			}
		})
	}
}

// full_only: false
func TestCredentialRetrievalRejectsCanceledContextBeforeAndAfterCallback(t *testing.T) {
	for _, mode := range []string{"active", "canceled-before", "expired-before", "canceled-during"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "expired-before":
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer deadlineCancel()
			case "canceled-before":
				cancel()
			}
			calls := 0
			provider, ok := retrieve(ctx, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				calls++
				if mode == "canceled-during" {
					cancel()
				}
				return aws.Credentials{AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret"}, nil
			}))
			wantCalls := 1
			if mode == "canceled-before" || mode == "expired-before" {
				wantCalls = 0
			}
			if ok != (mode == "active") || (provider != nil) != ok || calls != wantCalls {
				t.Fatal("credential cancellation boundary differs", ok, calls)
			}
		})
	}
}

func isolateDefaultCredentialEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_CA_BUNDLE", "AWS_DEFAULTS_MODE", "AWS_ENDPOINT_URL", "AWS_MAX_ATTEMPTS", "AWS_RETRY_MODE"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", sharedCredentialFile(t, ""))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", sharedCredentialFile(t, ""))
}

func defaultEndpointCredentials(t *testing.T, endpoint string) aws.CredentialsProvider {
	t.Helper()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", endpoint)
	p, err := LoadDefaultCredentials(context.Background(), "us-east-1")
	if err != nil {
		t.Fatal("synthetic default credential construction failed")
	}
	return p
}

func runCredentialTestChild(t *testing.T, root, mode string) ([]byte, []byte) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^"+root+"$", "-test.timeout=15s")
	command.Env = append(os.Environ(), "ENKV_TEST_AWS_CREDENTIAL_CHILD="+mode)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("credential child failed: %v\n%s\n%s", err, stdout.Bytes(), stderr.Bytes())
	}
	return stdout.Bytes(), stderr.Bytes()
}

// full_only: false
func TestDefaultCredentialsRejectEndpointRedirects(t *testing.T) {
	isolateDefaultCredentialEnvironment(t)
	for _, status := range []int{307, 308} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var targetCalls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls.Add(1)
				_, _ = io.WriteString(w, `{"AccessKeyId":"endpoint-access","SecretAccessKey":"endpoint-secret"}`)
			}))
			defer target.Close()
			var initialCalls atomic.Int32
			initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				initialCalls.Add(1)
				w.Header().Set("Location", target.URL+"/redirected")
				w.WriteHeader(status)
			}))
			defer initial.Close()
			p := defaultEndpointCredentials(t, initial.URL+"/credentials")
			value, err := p.Retrieve(context.Background())
			if err == nil || value.HasKeys() || initialCalls.Load() != 1 || targetCalls.Load() != 0 {
				t.Fatalf("credential redirect refusal: failed=%t keys=%t initial=%d target=%d", err != nil, value.HasKeys(), initialCalls.Load(), targetCalls.Load())
			}
		})
	}
}

// full_only: false
func TestDefaultCredentialsRejectMalformedEndpointResponses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"success-null", 200, "null"}, {"error-null", 400, "null"},
		{"success-array", 200, "[]"}, {"success-number", 200, "1"},
		{"success-empty", 200, "{}"}, {"success-field-shape", 200, `{"AccessKeyId":[],"SecretAccessKey":"secret"}`},
		{"success-expiration", 200, `{"AccessKeyId":"access","SecretAccessKey":"secret","Expiration":"invalid"}`},
		{"success-trailing", 200, `{"AccessKeyId":"access","SecretAccessKey":"secret"}null`},
		{"success-truncated", 200, `{"AccessKeyId":"access"`}, {"error-array", 400, "[]"},
		{"error-field-shape", 400, `{"code":{},"message":"denied"}`}, {"error-trailing", 400, `{}null`},
	}
	child := os.Getenv("ENKV_TEST_AWS_CREDENTIAL_CHILD")
	for _, tc := range cases {
		if child != "" && child != tc.name {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if child == "" && strings.HasSuffix(tc.name, "-null") {
				runCredentialTestChild(t, "TestDefaultCredentialsRejectMalformedEndpointResponses", tc.name)
				return
			}
			isolateDefaultCredentialEnvironment(t)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			p := defaultEndpointCredentials(t, server.URL)
			value, err := p.Retrieve(context.Background())
			if err == nil || value.HasKeys() || calls.Load() != 1 {
				t.Fatalf("malformed credential refusal: failed=%t keys=%t attempts=%d", err != nil, value.HasKeys(), calls.Load())
			}
		})
	}
}

// full_only: false
func TestDefaultCredentialsEndpointResponseBounds(t *testing.T) {
	for _, content := range []string{"success", "json-error", "text-error"} {
		for _, extra := range []int{0, 1} {
			t.Run(content+"/"+strconv.Itoa(extra), func(t *testing.T) {
				isolateDefaultCredentialEnvironment(t)
				body := `{"AccessKeyId":"endpoint-access","SecretAccessKey":"endpoint-secret","AccountId":"123456789012","Token":"token","Expiration":null,"Unknown":{"retained":true}}`
				status, contentType := 200, "application/json"
				if content == "json-error" {
					status, body = 400, `{"code":"AccessDenied","message":"denied"}`
				}
				if content == "text-error" {
					status, contentType, body = 400, "text/plain", "denied"
				}
				body += strings.Repeat(" ", (64<<10)+extra-len(body))
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", contentType)
					w.WriteHeader(status)
					_, _ = io.WriteString(w, body)
				}))
				defer server.Close()
				p := defaultEndpointCredentials(t, server.URL)
				value, err := p.Retrieve(context.Background())
				if calls.Load() != 1 {
					t.Fatalf("bounded endpoint attempts=%d want=1", calls.Load())
				}
				if content == "success" && extra == 0 {
					if err != nil || value.AccessKeyID != "endpoint-access" || value.SecretAccessKey != "endpoint-secret" || value.SessionToken != "token" || value.AccountID != "123456789012" || value.CanExpire {
						t.Fatal("exact-boundary static credentials changed")
					}
				} else if err == nil || value.HasKeys() {
					t.Fatal("failed endpoint response supplied credentials")
				}
				if extra == 1 && !errors.Is(err, ErrCredentials) {
					t.Fatal("oversized endpoint response did not fail at the bounded owner")
				}
				if extra == 0 && content != "success" && errors.Is(err, ErrCredentials) {
					t.Fatal("bounded endpoint denial lost its original meaning")
				}
			})
		}
	}
}

// full_only: false
func TestDefaultCredentialsPreservePrecedenceAndRefresh(t *testing.T) {
	isolateDefaultCredentialEnvironment(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/credentials" || r.Header.Get("Authorization") != "file-token" {
			t.Error("endpoint request or token-file precedence changed")
		}
		_, _ = io.WriteString(w, `{"AccessKeyId":"endpoint-access","SecretAccessKey":"endpoint-secret","Expiration":"2999-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "environment-token")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", sharedCredentialFile(t, "file-token"))
	p := defaultEndpointCredentials(t, server.URL+"/credentials")
	for i := 0; i < 2; i++ {
		value, err := p.Retrieve(context.Background())
		if err != nil || value.AccessKeyID != "endpoint-access" || !value.CanExpire {
			t.Fatal("healthy endpoint credentials failed")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unexpired endpoint credentials were not reused")
	}
	p.(*aws.CredentialsCache).Invalidate()
	if _, err := p.Retrieve(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatal("explicit cache invalidation did not refresh")
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", sharedCredentialFile(t, "[default]\naws_access_key_id=profile-access\naws_secret_access_key=profile-secret\n[chosen]\naws_access_key_id=chosen-access\naws_secret_access_key=chosen-secret\n"))
	p = defaultEndpointCredentials(t, server.URL)
	value, err := p.Retrieve(context.Background())
	if err != nil || value.AccessKeyID != "profile-access" {
		t.Fatal("default profile precedence changed")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "environment-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret")
	p = defaultEndpointCredentials(t, server.URL)
	value, err = p.Retrieve(context.Background())
	if err != nil || value.AccessKeyID != "environment-access" {
		t.Fatal("environment precedence changed")
	}
	t.Setenv("AWS_PROFILE", "chosen")
	p = defaultEndpointCredentials(t, server.URL)
	value, err = p.Retrieve(context.Background())
	if err != nil || value.AccessKeyID != "environment-access" || calls.Load() != 2 {
		t.Fatal("profile selection displaced environment credentials")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	p = defaultEndpointCredentials(t, server.URL)
	value, err = p.Retrieve(context.Background())
	if err != nil || value.AccessKeyID != "chosen-access" || calls.Load() != 2 {
		t.Fatal("selected profile precedence changed")
	}
}

// full_only: false
func TestDefaultCredentialsPreserveRelativeEndpointPrecedence(t *testing.T) {
	if os.Getenv("ENKV_TEST_AWS_CREDENTIAL_CHILD") != "relative" {
		runCredentialTestChild(t, "TestDefaultCredentialsPreserveRelativeEndpointPrecedence", "relative")
		return
	}
	isolateDefaultCredentialEnvironment(t)
	var fullCalls, relativeCalls atomic.Int32
	full := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fullCalls.Add(1); w.WriteHeader(400) }))
	defer full.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relativeCalls.Add(1)
		if r.URL.Host != "169.254.170.2" || r.URL.Path != "/relative" {
			t.Error("relative credential route changed")
		}
		_, _ = io.WriteString(w, `{"AccessKeyId":"relative-access","SecretAccessKey":"relative-secret"}`)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/relative")
	p := defaultEndpointCredentials(t, full.URL)
	value, err := p.Retrieve(context.Background())
	if err != nil || value.AccessKeyID != "relative-access" || relativeCalls.Load() != 1 || fullCalls.Load() != 0 {
		t.Fatal("relative endpoint did not take precedence over full endpoint")
	}
}

// full_only: false
func TestDefaultCredentialsEndpointRefusalPreventsServiceUse(t *testing.T) {
	isolateDefaultCredentialEnvironment(t)
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	var endpointCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"code":"AccessDenied","message":"fixture-private-denial"}`)
	}))
	defer server.Close()
	p := defaultEndpointCredentials(t, server.URL)
	serviceCalls := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		serviceCalls++
		return nil, errors.New("unexpected service call")
	})
	storeConfig := testStoreConfig()
	storeConfig.Credentials = p
	store, err := newStore(storeConfig, transport)
	if err != nil {
		t.Fatal(err)
	}
	got := store.Create(ctx, testImmutableKey("member", 0), []byte("fixture"))
	if got.Status != contract.WriteRefused || got.Reason != contract.ReasonAccess {
		t.Fatal("credential refusal did not prevent Store use")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := newTrust(TrustConfig{Region: storeConfig.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: der, CredentialRoute: storeConfig.CredentialRoute, Credentials: p, Timeout: storeConfig.Timeout}, transport)
	if err != nil {
		t.Fatal(err)
	}
	id := contract.Hash([]byte("subject"))
	request, err := contract.NewBindingRequest(contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: id, PublicKey: id, Interpretation: id, ControlIncarnationID: id, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := trust.Sign(ctx, request); got.Reason != contract.ReasonAccess || len(got.Signature) != 0 {
		t.Fatal("credential refusal did not prevent Trust use")
	}
	keyConfig := encryptionConfig()
	keyConfig.Credentials = p
	access, err := newKeyAccess(keyConfig, transport)
	if err != nil {
		t.Fatal(err)
	}
	if got := access.Qualify(ctx, encryptionBinding(t)); got.Status != enkvcrypto.KeyDenied {
		t.Fatal("credential refusal did not prevent KeyAccess use")
	}
	if endpointCalls.Load() != 3 || serviceCalls != 0 {
		t.Fatal("credential refusal reached a service or retried its denial")
	}
	data := snapshot()
	if telemetrySum(data, telemetry.HTTPAttempts, telemetry.OpAuthentication, "", "") != 3 {
		t.Fatal("endpoint HTTP attempts were not attributed to authentication")
	}
	for _, forbidden := range []string{"fixture-private-denial", "AccessDenied", server.URL} {
		if strings.Contains(fmt.Sprint(data), forbidden) {
			t.Fatal("credential endpoint private data entered telemetry")
		}
	}
}

// full_only: false
func TestDefaultCredentialsExcludeUnsolicitedIdleDiagnostics(t *testing.T) {
	const marker = "SYNTHETIC_UNREVIEWED_CREDENTIAL_PEER_BYTES"
	mode := os.Getenv("ENKV_TEST_AWS_CREDENTIAL_CHILD")
	if mode == "" {
		for _, mode := range []string{"unsafe-control", "owned"} {
			t.Run(mode, func(t *testing.T) {
				stdout, stderr := runCredentialTestChild(t, "TestDefaultCredentialsExcludeUnsolicitedIdleDiagnostics", mode)
				if !bytes.Contains(stdout, []byte("credential_peer_joined")) {
					t.Fatal("credential peer did not join")
				}
				if found := bytes.Contains(stderr, []byte(marker)); found != (mode == "unsafe-control") {
					t.Fatalf("credential peer marker in stderr=%t for %s", found, mode)
				}
			})
		}
		return
	}
	if mode != "unsafe-control" && mode != "owned" {
		t.Fatal("invalid credential idle child mode")
	}
	isolateDefaultCredentialEnvironment(t)
	release, joined := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var mu sync.Mutex
	var connection net.Conn
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(joined)
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		connection = conn
		mu.Unlock()
		defer func() {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}()
		body := `{"AccessKeyId":"endpoint-access","SecretAccessKey":"endpoint-secret"}`
		if _, err := fmt.Fprintf(buffer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s", len(body), body); err != nil {
			t.Error(err)
			return
		}
		if err := buffer.Flush(); err != nil {
			t.Error(err)
			return
		}
		<-release
		_, _ = conn.Write([]byte(marker + "\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var b [1]byte
		// Unsolicited bytes can race with transport close and cause a TCP reset.
		if n, err := conn.Read(b[:]); n != 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET)) {
			t.Errorf("credential peer did not observe transport close: bytes=%d err=%v", n, err)
		}
	}))
	defer server.Close()
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		if connection != nil {
			if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}
	}()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var p aws.CredentialsProvider
	var err error
	if mode == "unsafe-control" {
		var installed aws.Config
		installed, err = config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
		p = installed.Credentials
	} else {
		p, err = LoadDefaultCredentials(ctx, "us-east-1")
	}
	if err != nil || p == nil {
		t.Fatal("credential discovery failed")
	}
	value, err := p.Retrieve(ctx)
	releaseOnce.Do(func() { close(release) })
	if err != nil || value.AccessKeyID != "endpoint-access" || value.SecretAccessKey != "endpoint-secret" {
		t.Fatal("healthy credential response failed")
	}
	select {
	case <-joined:
	case <-ctx.Done():
		t.Fatal("credential peer did not join")
	}
	fmt.Println("credential_peer_joined")
}

// full_only: false
func TestDefaultCredentialsPreserveEndpointRetrySemantics(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		status                                    int
		contentType, body                         string
		calls                                     int32
		success, localRefusal, permanent, partial bool
	}{
		{name: "malformed-success", status: 200, contentType: "application/json", body: "[]", calls: 1, localRefusal: true},
		{name: "malformed-error", status: 400, contentType: "application/json", body: "[]", calls: 1, localRefusal: true},
		{name: "denied", status: 403, contentType: "application/json", body: `{"code":"AccessDenied","message":"denied"}`, calls: 1, permanent: true},
		{name: "throttled-then-success", status: 429, contentType: "application/json", body: `{"code":"SlowDown","message":"retry"}`, calls: 2, success: true},
		{name: "internal-then-success", status: 500, contentType: "application/json", body: `{"code":"InternalError","message":"retry"}`, calls: 2, success: true},
		{name: "unavailable-then-success", status: 503, contentType: "text/plain", body: "unavailable", calls: 2, success: true},
		{name: "disconnected-then-success", calls: 2, success: true},
		{name: "partial-body-stops-without-retry", calls: 1, partial: true},
		{name: "unavailable-stops-at-budget", status: 503, contentType: "text/plain", body: "unavailable", calls: 3, permanent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateDefaultCredentialEnvironment(t)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := calls.Add(1)
				if attempt == 1 || tc.permanent {
					if tc.status == 0 {
						connection, buffer, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						if tc.partial {
							_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{\"AccessKeyId\":")
							if err := buffer.Flush(); err != nil {
								t.Error(err)
							}
						}
						_ = connection.Close()
						return
					}
					w.Header().Set("Content-Type", tc.contentType)
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
					return
				}
				_, _ = io.WriteString(w, `{"AccessKeyId":"endpoint-access","SecretAccessKey":"endpoint-secret"}`)
			}))
			defer server.Close()
			p := defaultEndpointCredentials(t, server.URL)
			value, err := p.Retrieve(context.Background())
			if calls.Load() != tc.calls {
				t.Fatalf("endpoint attempts=%d want=%d", calls.Load(), tc.calls)
			}
			if tc.success {
				if err != nil || value.AccessKeyID != "endpoint-access" || value.SecretAccessKey != "endpoint-secret" {
					t.Fatal("eligible endpoint retry did not succeed")
				}
			} else if err == nil || value.HasKeys() {
				t.Fatal("endpoint refusal supplied credentials")
			}
			if tc.localRefusal != errors.Is(err, ErrCredentials) {
				t.Fatal("endpoint failure crossed the local response refusal boundary")
			}
		})
	}
}
