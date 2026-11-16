package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestAWSCleanupRetainsSafeFailureCause(t *testing.T) {
	for _, tc := range []struct {
		name, cause, stage, code string
		status                   int
	}{
		{name: "condition", status: 412, code: "PreconditionFailed", stage: "conditional_delete", cause: "condition_refused"},
		{name: "access", status: 403, code: "AccessDenied", stage: "conditional_delete", cause: "access_refused"},
		{name: "server", status: 503, code: "InternalError", stage: "conditional_delete", cause: "provider_refused"},
		{name: "invalid-ack", status: 204, stage: "acknowledgement", cause: "invalid_acknowledgement"},
		{name: "wrong-success-status", status: 200, stage: "acknowledgement", cause: "invalid_acknowledgement"},
		{name: "invalid-encoding", status: 204, stage: "response_intake", cause: "invalid_encoding"},
		{name: "early-eof", status: 200, stage: "response_intake", cause: "early_eof"},
		{name: "overflow", status: 200, stage: "response_intake", cause: "body_overflow"},
		{name: "lost-reply", stage: "conditional_delete", cause: "transport"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, der := awsLiveTestSettings(t)
			var requests atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodDelete || r.Header.Get("If-Match") != `"observed"` {
					t.Error("cleanup lost the exact observed condition")
				}
				if tc.name == "lost-reply" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				body := "<Error><Code>" + tc.code + "</Code><Message>private-body-sentinel</Message></Error>"
				if tc.name == "invalid-ack" {
					w.Header().Set("X-Amz-Delete-Marker", "true")
					body = ""
				}
				if tc.name == "wrong-success-status" {
					body = ""
				}
				if tc.name == "invalid-encoding" {
					w.Header().Set("Content-Encoding", "gzip")
					body = ""
				}
				if tc.name == "early-eof" {
					w.Header().Set("Content-Length", "1000")
				}
				if tc.name == "overflow" {
					body = strings.Repeat("x", awsSetupLimit+1)
				}
				w.WriteHeader(tc.status)
				if _, err := io.WriteString(w, body); err != nil {
					t.Error(err)
				}
			}))
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, &awsLiveTestCredentials{}, transport)
			err := s.delete(context.Background(), "run/HEAD", contract.Token{Family: contract.AWS, Value: `"observed"`})
			var failure *awsSetupFailure
			if !errors.Is(err, errAWSDelete) || !errors.As(err, &failure) {
				t.Fatalf("cleanup lost typed failure: %T %v", err, err)
			}
			if failure.Stage != tc.stage || failure.Cause != tc.cause || failure.HTTPStatus != tc.status || failure.ProviderCode != tc.code || failure.Attempt != 1 || failure.Effect != "unknown" {
				t.Fatalf("incorrect retained failure: stage=%s cause=%s status=%d envelope=%d code=%s attempt=%d effect=%s", failure.Stage, failure.Cause, failure.HTTPStatus, failure.EnvelopeStatus, failure.ProviderCode, failure.Attempt, failure.Effect)
			}
			if tc.code != "" && failure.EnvelopeStatus != tc.status {
				t.Fatalf("SDK envelope status differs from the observed HTTP status: %d and %d", failure.EnvelopeStatus, tc.status)
			}
			safe := failure.SafeHarnessFailure()
			encoded, marshalErr := json.Marshal(safe)
			if marshalErr != nil || !safe.Validate() || strings.Contains(string(encoded), "private-body-sentinel") || strings.Contains(string(encoded), "test-secret") {
				t.Fatalf("unsafe or invalid failure projection: %s %v", encoded, marshalErr)
			}
			if strings.Contains(err.Error(), "private-body-sentinel") || strings.Contains(err.Error(), "test-secret") || requests.Load() != 1 {
				t.Fatal("unsafe diagnostic or repeated cleanup request")
			}
		})
	}
}

// full_only: false
func TestAWSSetupRetainsSafeFailureCause(t *testing.T) {
	for _, tc := range []struct {
		name, stage, cause, code string
		status, attempts         int
	}{
		{name: "credentials", stage: "authentication", cause: "authentication_refused"},
		{name: "cancelled", stage: "authentication", cause: "cancelled"},
		{name: "access", stage: "configuration_check", cause: "access_refused", code: "AccessDenied", status: 403, attempts: 1},
		{name: "configuration", stage: "configuration_check", cause: "invalid_acknowledgement", status: 200, attempts: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, der := awsLiveTestSettings(t)
			var requests atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if tc.name == "access" {
					w.WriteHeader(403)
					io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>private-body-sentinel</Message></Error>")
					return
				}
				status, body := awsLiveConfigurationReply(t, c, der, r, "region")
				w.WriteHeader(status)
				io.WriteString(w, body)
			}))
			credentials := &awsLiveTestCredentials{}
			if tc.name == "credentials" {
				credentials.err = errors.New("private-credential-sentinel")
			}
			ctx := context.Background()
			if tc.name == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
			err := s.check(ctx)
			var failure *awsSetupFailure
			if !errors.Is(err, errAWSSetup) || !errors.As(err, &failure) {
				t.Fatalf("setup lost typed failure: %T %v", err, err)
			}
			if failure.Stage != tc.stage || failure.Cause != tc.cause || failure.HTTPStatus != tc.status || failure.ProviderCode != tc.code || int(failure.Attempt) != tc.attempts || requests.Load() != int32(tc.attempts) {
				t.Fatalf("incorrect setup failure: stage=%s cause=%s status=%d code=%s attempt=%d requests=%d", failure.Stage, failure.Cause, failure.HTTPStatus, failure.ProviderCode, failure.Attempt, requests.Load())
			}
			if !failure.SafeHarnessFailure().Validate() || strings.Contains(err.Error(), "private-") {
				t.Fatal("setup failure escaped private text or invalid diagnostic")
			}
		})
	}
}

// full_only: false
func TestAWSCleanupPreSendFailureHasNoEffect(t *testing.T) {
	for _, tc := range []struct{ name, stage, cause string }{
		{"invalid-input", "admission", "invalid_request"},
		{"credentials", "authentication", "authentication_refused"},
		{"cancelled", "authentication", "cancelled"},
		{"deadline", "authentication", "deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, der := awsLiveTestSettings(t)
			var requests atomic.Int32
			transport := awsLiveTestTransport(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			credentials := &awsLiveTestCredentials{}
			if tc.name == "credentials" {
				credentials.err = errors.New("private-credential-sentinel")
			}
			ctx := context.Background()
			if tc.name == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if tc.name == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			key := "run/HEAD"
			if tc.name == "invalid-input" {
				key = "other/HEAD"
			}
			s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, credentials, transport)
			err := s.delete(ctx, key, contract.Token{Family: contract.AWS, Value: `"observed"`})
			var failure *awsSetupFailure
			if !errors.Is(err, errAWSDelete) || !errors.As(err, &failure) || failure.Stage != tc.stage || failure.Cause != tc.cause || failure.Attempt != 0 || failure.Effect != "no_send" || failure.HTTPStatus != 0 || requests.Load() != 0 {
				t.Fatalf("pre-send cleanup was not closed: err=%v requests=%d", err, requests.Load())
			}
			if !failure.SafeHarnessFailure().Validate() || strings.Contains(err.Error(), "private-credential-sentinel") {
				t.Fatal("pre-send failure escaped private text or invalid facts")
			}
		})
	}
}

// full_only: false
func TestAWSCleanupTimeoutIsNotARefusal(t *testing.T) {
	c, der := awsLiveTestSettings(t)
	transport := awsLiveTestTransport(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("timeout control reached the provider")
	}))
	var dials atomic.Int32
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, &net.DNSError{Err: "private-timeout-sentinel", IsTimeout: true}
	}
	s := newAWSSetup(c, "run", contract.Hash([]byte("domain")), der, &awsLiveTestCredentials{}, transport)
	err := s.delete(context.Background(), "run/HEAD", contract.Token{Family: contract.AWS, Value: `"observed"`})
	var failure *awsSetupFailure
	if !errors.Is(err, errAWSDelete) || !errors.As(err, &failure) || failure.Stage != "conditional_delete" || failure.Cause != "deadline" || failure.HTTPStatus != 0 || failure.Attempt != 1 || failure.Effect != "unknown" || dials.Load() != 1 {
		t.Fatalf("timeout cause or one-attempt boundary lost: err=%v dials=%d", err, dials.Load())
	}
	if !failure.SafeHarnessFailure().Validate() || strings.Contains(err.Error(), "private-timeout-sentinel") {
		t.Fatal("timeout failure escaped private text or invalid facts")
	}
}
