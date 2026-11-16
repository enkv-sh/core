package credentials

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// full_only: false
func TestEndpointCredentialUpgradeRefusesBeforeBodyRead(t *testing.T) {
	t.Run("endpoint", func(t *testing.T) {
		checkCredentialUpgrade(t, func(client *http.Client, request *http.Request) (*http.Response, error) {
			response, err := (endpointCredentialClient{client: client}).Do(request)
			if !errors.Is(err, ErrCredentials) {
				t.Error("credential endpoint upgrade lost its local refusal cause")
			}
			return response, err
		})
	})
	t.Run("imds", func(t *testing.T) {
		checkCredentialUpgrade(t, func(client *http.Client, request *http.Request) (*http.Response, error) {
			var boundaryErrors []error
			observe := func(stack *middleware.Stack) error {
				return stack.Deserialize.Insert(middleware.DeserializeMiddlewareFunc("ObserveIMDSCredentialRefusal", func(ctx context.Context, input middleware.DeserializeInput, next middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
					out, metadata, err := next.HandleDeserialize(ctx, input)
					boundaryErrors = append(boundaryErrors, err)
					return out, metadata, err
				}), "EnkvIMDSResponseBoundary", middleware.Before)
			}
			metadata := imds.New(imds.Options{Endpoint: request.URL.Scheme + "://" + request.URL.Host, HTTPClient: client, EnableFallback: aws.FalseTernary, Retryer: aws.NopRetryer{}, APIOptions: []func(*middleware.Stack) error{boundIMDSResponses, observe}})
			result, err := metadata.GetMetadata(request.Context(), &imds.GetMetadataInput{Path: "credentials"})
			if len(boundaryErrors) != 1 || !errors.Is(boundaryErrors[0], ErrCredentials) || retry.NewStandard().IsErrorRetryable(&smithyhttp.RequestSendError{Err: boundaryErrors[0]}) {
				t.Error("IMDS production boundary lost its safe nonretryable refusal")
			}
			if result != nil {
				return &http.Response{Body: result.Content}, err
			}
			return nil, err
		})
	})
}

func checkCredentialUpgrade(t *testing.T, call func(*http.Client, *http.Request) (*http.Response, error)) {
	client, peer := net.Pipe()
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
	defer transport.CloseIdleConnections()
	headersReady, peerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(peerDone)
		defer func() {
			if err := peer.Close(); err != nil {
				t.Error("synthetic upgraded peer cleanup failed", err)
			}
		}()
		request, err := http.ReadRequest(bufio.NewReader(peer))
		if err != nil {
			return
		}
		_ = request.Body.Close()
		if _, err := io.WriteString(peer, "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: synthetic\r\n\r\n"); err != nil {
			return
		}
		close(headersReady)
		_, _ = peer.Read(make([]byte, 1))
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://synthetic.invalid/credentials", nil)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		response *http.Response
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := call(&http.Client{Transport: transport, Timeout: 20 * time.Millisecond}, request)
		done <- result{response, err}
	}()
	joined := false
	defer func() {
		_ = peer.Close()
		cancel()
		if !joined {
			select {
			case got := <-done:
				if got.response != nil && got.response.Body != nil {
					_ = got.response.Body.Close()
				}
			case <-time.After(time.Second):
				t.Error("credential wrapper did not join after synthetic peer closure")
			}
		}
		select {
		case <-peerDone:
		case <-time.After(time.Second):
			t.Error("synthetic upgraded peer did not join")
		}
	}()
	select {
	case <-headersReady:
	case <-time.After(time.Second):
		t.Fatal("synthetic upgrade was not delivered")
	}
	select {
	case got := <-done:
		joined = true
		if got.response != nil {
			if got.response.Body != nil {
				_ = got.response.Body.Close()
			}
			t.Error("upgraded credential response was returned to SDK")
		}
		if got.err == nil || retry.NewStandard().IsErrorRetryable(&smithyhttp.RequestSendError{Err: got.err}) {
			t.Error("credential upgrade lost its safe nonretryable refusal")
		}
		select {
		case <-peerDone:
		case <-time.After(150 * time.Millisecond):
			t.Error("credential refusal did not close the upgraded stream")
		}
	case <-time.After(150 * time.Millisecond):
		t.Error("credential upgrade body outlived HTTP timeout")
	}
}

// full_only: false
func TestDefaultEC2RoleResponsesAreBounded(t *testing.T) {
	for _, kind := range []string{"token", "role-list", "credentials"} {
		for _, size := range []int{64 << 10, 64<<10 + 1} {
			t.Run(fmt.Sprintf("%s/%d", kind, size), func(t *testing.T) {
				defaultEC2RoleEnvironment(t)
				token, roles := "fixture-token", "fixture-role\n"
				credentials := fmt.Sprintf(`{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
				switch kind {
				case "token":
					token = strings.Repeat("t", size)
				case "role-list":
					remaining := size - len(roles)
					roles += strings.Repeat("x\n", remaining/2) + strings.Repeat("x", remaining%2)
				case "credentials":
					credentials += strings.Repeat(" ", size-len(credentials))
				}
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.Header().Set("Connection", "close")
					switch r.URL.Path {
					case "/latest/api/token":
						w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
						_, _ = io.WriteString(w, token)
					case "/latest/meta-data/iam/security-credentials/":
						_, _ = io.WriteString(w, roles)
					case "/latest/meta-data/iam/security-credentials/fixture-role":
						_, _ = io.WriteString(w, credentials)
					default:
						t.Error("unexpected standard IMDS path")
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
				t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				source, err := LoadDefaultCredentials(ctx, "us-east-1")
				if err != nil || source == nil {
					t.Fatal("standard EC2 role construction failed", err)
				}
				value, err := source.Retrieve(ctx)
				if size > 64<<10 {
					if err == nil || value.AccessKeyID != "" || value.SecretAccessKey != "" || value.SessionToken != "" {
						t.Fatal("oversized IMDS reply reached credential capture")
					}
				} else if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" || !value.CanExpire || !value.Expires.After(time.Now()) || calls.Load() != 3 {
					t.Fatal("exact-limit standard IMDS credentials changed", err, calls.Load())
				}
			})
		}
	}
	t.Run("standard-v1-fallback", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Connection", "close")
			switch r.URL.Path {
			case "/latest/api/token":
				w.WriteHeader(http.StatusForbidden)
			case "/latest/meta-data/iam/security-credentials/":
				_, _ = io.WriteString(w, "fixture-role\n")
			case "/latest/meta-data/iam/security-credentials/fixture-role":
				_, _ = fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
			default:
				t.Error("unexpected standard fallback path")
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "false")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		source, err := LoadDefaultCredentials(ctx, "us-east-1")
		if err != nil || source == nil {
			t.Fatal("standard fallback construction failed", err)
		}
		value, err := source.Retrieve(ctx)
		if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || calls.Load() != 3 {
			t.Fatal("standard IMDSv1 fallback changed", err, calls.Load())
		}
	})

	t.Run("configured-v1-disabled", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Connection", "close")
			if r.URL.Path != "/latest/api/token" {
				t.Error("configured IMDSv1 refusal reached metadata without a token")
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		source, err := LoadDefaultCredentials(ctx, "us-east-1")
		if err != nil || source == nil {
			t.Fatal("standard configured-v1-disabled construction failed", err)
		}
		value, err := source.Retrieve(ctx)
		if err == nil || value.AccessKeyID != "" || value.SecretAccessKey != "" || value.SessionToken != "" || calls.Load() != 1 {
			t.Fatal("configured IMDSv1 refusal was lost", err, calls.Load())
		}
	})

	t.Run("bounded-token-refusal-preserves-v1-fallback", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Connection", "close")
			switch r.URL.Path {
			case "/latest/api/token":
				w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
				_, _ = io.WriteString(w, strings.Repeat("t", 64<<10+1))
			case "/latest/meta-data/iam/security-credentials/":
				if r.Header.Get("X-Aws-Ec2-Metadata-Token") != "" {
					t.Error("oversized token reached a metadata request")
				}
				_, _ = io.WriteString(w, "fixture-role\n")
			case "/latest/meta-data/iam/security-credentials/fixture-role":
				if r.Header.Get("X-Aws-Ec2-Metadata-Token") != "" {
					t.Error("oversized token reached a credential request")
				}
				_, _ = fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
			default:
				t.Error("unexpected bounded fallback path")
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "false")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		source, err := LoadDefaultCredentials(ctx, "us-east-1")
		if err != nil || source == nil {
			t.Fatal("bounded token fallback construction failed", err)
		}
		value, err := source.Retrieve(ctx)
		if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" || calls.Load() != 4 {
			t.Fatal("bounded token refusal changed configured fallback", err, calls.Load())
		}
	})
}

func defaultEC2RoleEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE", "AWS_CA_BUNDLE", "AWS_DEFAULTS_MODE"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "empty-config")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")
}

// full_only: false
func TestEndpointCredentialReadFailurePreservesRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cause     error
		retryable bool
	}{
		{name: "unexpected-eof", cause: io.ErrUnexpectedEOF},
		{name: "connection-reset", cause: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, retryable: true},
		{name: "read-timeout", cause: os.ErrDeadlineExceeded, retryable: true},
	} {
		t.Run("read-classification/"+tc.name, func(t *testing.T) {
			body := &countedBody{ReadCloser: io.NopCloser(endpointCredentialFailureReader{cause: tc.cause})}
			client := endpointCredentialClient{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}, nil
			})}}
			request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/credentials", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err == nil || response != nil || !body.closed || !errors.Is(err, tc.cause) {
				t.Fatal("body read failure lost its cause or ownership")
			}
			if got := retry.NewStandard().IsErrorRetryable(&smithyhttp.RequestSendError{Err: err}); got != tc.retryable {
				t.Fatalf("read retry=%t want=%t", got, tc.retryable)
			}
			if err.Error() != ErrCredentials.Error() {
				t.Fatal("body read failure exposed a raw cause")
			}
		})
	}
}

type endpointCredentialFailureReader struct{ cause error }

func (r endpointCredentialFailureReader) Read([]byte) (int, error) { return 0, r.cause }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type countedBody struct {
	io.ReadCloser
	closed bool
}

func (b *countedBody) Close() error { b.closed = true; return b.ReadCloser.Close() }

// full_only: false
func TestDefaultEC2RolePreservesCustomCABundle(t *testing.T) {
	defaultEC2RoleEnvironment(t)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Connection", "close")
		switch r.URL.Path {
		case "/latest/api/token":
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
			_, _ = io.WriteString(w, "fixture-token")
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = io.WriteString(w, "fixture-role\n")
		case "/latest/meta-data/iam/security-credentials/fixture-role":
			_, _ = fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"AKIAAAAAAAAAAAAA","SecretAccessKey":"synthetic-secret","Token":"synthetic-token","Expiration":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			t.Error("unexpected configured HTTPS metadata path")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "metadata-ca.pem")
	if err := os.WriteFile(path, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", path)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
	t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	source, err := LoadDefaultCredentials(ctx, "us-east-1")
	if err != nil || source == nil {
		t.Fatal("configured HTTPS metadata construction failed", err)
	}
	value, err := source.Retrieve(ctx)
	if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" || calls.Load() != 3 {
		t.Fatal("configured metadata CA policy was lost", err, calls.Load())
	}
}

// full_only: false
func TestDefaultAutoModeMetadataResponsesAreBounded(t *testing.T) {
	for _, size := range []int{64 << 10, 64<<10 + 1} {
		t.Run(fmt.Sprintf("token/%d", size), func(t *testing.T) {
			defaultEC2RoleEnvironment(t)
			t.Setenv("AWS_DEFAULTS_MODE", "auto")
			t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAAAAAAAAAAAA")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
			t.Setenv("AWS_SESSION_TOKEN", "synthetic-token")
			t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
			var calls, documents, tokenLength atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Connection", "close")
				switch r.URL.Path {
				case "/latest/api/token":
					w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
					_, _ = io.WriteString(w, strings.Repeat("t", size))
				case "/latest/dynamic/instance-identity/document":
					documents.Add(1)
					tokenLength.Store(int32(len(r.Header.Get("X-Aws-Ec2-Metadata-Token"))))
					_, _ = io.WriteString(w, `{"region":"us-east-1"}`)
				default:
					t.Error("automatic defaults made an unrelated metadata request")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			source, err := LoadDefaultCredentials(ctx, "us-east-1")
			if err != nil || source == nil {
				t.Fatal("automatic metadata introspection prevented static credentials", err)
			}
			value, err := source.Retrieve(ctx)
			if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" {
				t.Fatal("automatic defaults changed independent static credentials", err)
			}
			if size > 64<<10 {
				if documents.Load() != 0 || tokenLength.Load() != 0 || calls.Load() != 1 {
					t.Fatal("automatic defaults forwarded an oversized IMDS token", documents.Load(), tokenLength.Load(), calls.Load())
				}
			} else if documents.Load() != 1 || tokenLength.Load() != int32(size) || calls.Load() != 2 {
				t.Fatal("exact-limit automatic metadata token was changed", documents.Load(), tokenLength.Load(), calls.Load())
			}
		})
	}
	t.Run("identity-document/stops-before-held-tail", func(t *testing.T) {
		defaultEC2RoleEnvironment(t)
		t.Setenv("AWS_DEFAULTS_MODE", "auto")
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAAAAAAAAAAAA")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
		t.Setenv("AWS_SESSION_TOKEN", "synthetic-token")
		t.Setenv("AWS_EC2_METADATA_V1_DISABLED", "true")
		prefixReady, bodyClosed, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
		releaseTail := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseTail) }) }
		var documents atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/latest/api/token" {
				w.Header().Set("Connection", "close")
				w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "300")
				_, _ = io.WriteString(w, "fixture-token")
				return
			}
			if r.URL.Path != "/latest/dynamic/instance-identity/document" || documents.Add(1) != 1 {
				t.Error("unexpected automatic identity-document request")
				w.WriteHeader(http.StatusNotFound)
				return
			}
			defer close(handlerDone)
			connection, writer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error("synthetic identity-document connection could not be owned", err)
				return
			}
			defer func() {
				// The held-tail release branch closes this same connection before joining its reader.
				if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error("synthetic identity-document connection cleanup failed", err)
				}
			}()
			const prefixLength, totalLength = 64<<10 + 1, 64<<10 + 4096
			prefix := `{"region":"us-east-1"}`
			prefix += strings.Repeat(" ", prefixLength-len(prefix))
			if _, err := fmt.Fprintf(writer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", totalLength, prefix); err != nil {
				t.Error("synthetic identity-document prefix failed", err)
				return
			}
			if err := writer.Flush(); err != nil {
				t.Error("synthetic identity-document prefix did not flush", err)
				return
			}
			close(prefixReady)
			peerDone := make(chan struct{})
			go func() {
				_, _ = connection.Read(make([]byte, 1))
				close(peerDone)
			}()
			select {
			case <-peerDone:
				close(bodyClosed)
			case <-releaseTail:
				_, _ = io.WriteString(connection, strings.Repeat(" ", totalLength-prefixLength))
				if err := connection.Close(); err != nil {
					t.Error("synthetic identity-document release failed", err)
				}
				<-peerDone
			}
		}))
		defer server.Close()
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", server.URL)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		type outcome struct {
			source aws.CredentialsProvider
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			source, err := LoadDefaultCredentials(ctx, "us-east-1")
			done <- outcome{source, err}
		}()
		joined := false
		defer func() {
			release()
			cancel()
			if !joined {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("automatic defaults did not join after synthetic release")
				}
			}
			select {
			case <-handlerDone:
			case <-time.After(time.Second):
				t.Error("synthetic identity-document handler did not join")
			}
		}()
		select {
		case <-prefixReady:
		case <-time.After(time.Second):
			t.Fatal("synthetic identity-document prefix was not delivered")
		}
		select {
		case <-bodyClosed:
		case <-time.After(150 * time.Millisecond):
			t.Error("automatic defaults read beyond the bounded metadata prefix")
			release()
		}
		select {
		case got := <-done:
			joined = true
			if got.err != nil || got.source == nil {
				t.Fatal("nonfatal metadata introspection changed loader result", got.err)
			}
			value, err := got.source.Retrieve(ctx)
			if err != nil || value.AccessKeyID != "AKIAAAAAAAAAAAAA" || value.SecretAccessKey != "synthetic-secret" || value.SessionToken != "synthetic-token" {
				t.Fatal("bounded identity-document failure changed static credentials", err)
			}
		case <-time.After(time.Second):
			t.Fatal("automatic defaults did not settle after bounded response handling")
		}
	})
}

// full_only: false
func TestDefaultCredentialChainKeepsWebIdentityResponseOutsideIMDSBoundary(t *testing.T) {
	defaultEC2RoleEnvironment(t)
	tokenPath := filepath.Join(t.TempDir(), "web-identity-token")
	if err := os.WriteFile(tokenPath, []byte("synthetic-web-identity-token"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenPath)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/fixture-role")
	t.Setenv("AWS_ROLE_SESSION_NAME", "fixture-session")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_DEFAULTS_MODE", "legacy")
	expiration := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	reply := `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>` + strings.Repeat(" ", 65<<10) + `<Credentials><AccessKeyId>ASIAAAAAAAAAAAAA</AccessKeyId><SecretAccessKey>assumed-synthetic-secret</SecretAccessKey><SessionToken>assumed-synthetic-token</SessionToken><Expiration>` + expiration + `</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>fixture:session</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/fixture-role/fixture-session</Arn></AssumedRoleUser><SubjectFromWebIdentityToken>synthetic-subject</SubjectFromWebIdentityToken><Audience>synthetic-audience</Audience><Provider>synthetic-provider</Provider></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>synthetic-request</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/fixture-role" || r.Form.Get("RoleSessionName") != "fixture-session" || r.Form.Get("WebIdentityToken") != "synthetic-web-identity-token" {
			t.Error("unrelated SDK fixture received another operation")
		}
		_ = r.Body.Close()
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, reply)
	}))
	defer server.Close()
	t.Setenv("AWS_ENDPOINT_URL", server.URL)
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	source, err := LoadDefaultCredentials(ctx, "us-east-1")
	if err != nil || source == nil {
		t.Fatal("standard web-identity construction failed", err)
	}
	value, err := source.Retrieve(ctx)
	if err != nil || value.AccessKeyID != "ASIAAAAAAAAAAAAA" || value.SecretAccessKey != "assumed-synthetic-secret" || value.SessionToken != "assumed-synthetic-token" || !value.CanExpire || !value.Expires.After(time.Now()) || calls.Load() != 1 {
		t.Fatal("IMDS boundary changed unrelated standard SDK response", err, calls.Load())
	}
}
