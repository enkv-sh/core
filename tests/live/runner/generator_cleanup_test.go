package core

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

const cloudflareFixtureOrigin = "https://api.cloudflare.com/client/v4"

func validCloudflareFixtureBearer(body []byte) bool {
	if len(body) < 40 || len(body) > 80 {
		return false
	}
	for _, b := range body {
		if b != '_' && b != '-' && (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}

func readCloudflareFixtureBearer() ([]byte, error) {
	body := []byte(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if !validCloudflareFixtureBearer(body) {
		clear(body)
		return nil, errors.New("Cloudflare fixture environment credential refused")
	}
	return body, nil
}

func cloudflareFixtureTransport() *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}).DialContext,
		ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.cloudflare.com", NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: 16 << 10,
		DisableCompression: true, DisableKeepAlives: true, Protocols: protocols}
}

type cloudflareFixtureCleanupError struct{ fact records.HarnessFailure }

func (e cloudflareFixtureCleanupError) Error() string { return "Cloudflare fixture cleanup failed" }

func (e cloudflareFixtureCleanupError) SafeHarnessFailure() records.HarnessFailure { return e.fact }

func cloudflareFixtureFailure(stage, cause, effect string, attempt uint8, status *uint16) error {
	return cloudflareFixtureCleanupError{fact: records.HarnessFailure{Operation: "generator_cleanup", Stage: stage,
		Cause: cause, Effect: effect, Attempt: attempt, HTTPStatus: status}}
}

func cloudflareFixtureCause(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "early_eof"
	default:
		return "transport"
	}
}

func cloudflareFixtureDelete(ctx context.Context, origin string, transport http.RoundTripper, bearer []byte, account, target string) error {
	if ctx == nil || !validCloudflareFixtureBearer(bearer) || !validCloudflareFixtureID(account) || !validCloudflareFixtureID(target) || transport == nil {
		return cloudflareFixtureFailure("admission", "invalid_request", "no_send", 0, nil)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, origin+"/accounts/"+account+"/tokens/"+target, nil)
	if err != nil {
		return cloudflareFixtureFailure("admission", "invalid_request", "no_send", 0, nil)
	}
	request.Header.Set("Authorization", "Bearer "+string(bearer))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Close = true
	if err := ctx.Err(); err != nil {
		return cloudflareFixtureFailure("admission", cloudflareFixtureCause(err), "no_send", 0, nil)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return cloudflareFixtureFailure("conditional_delete", cloudflareFixtureCause(err), "unknown", 1, nil)
	}
	if response == nil || response.Body == nil {
		return cloudflareFixtureFailure("conditional_delete", "missing_response", "unknown", 1, nil)
	}
	var status *uint16
	if response.StatusCode >= 100 && response.StatusCode <= 599 {
		observed := uint16(response.StatusCode)
		status = &observed
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cause := "provider_refused"
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			cause = "access_refused"
		} else if response.StatusCode == http.StatusPreconditionFailed {
			cause = "condition_refused"
		}
		return cloudflareFixtureFailure("conditional_delete", cause, "unknown", 1, status)
	}
	if response.ProtoMajor != 1 || response.Uncompressed || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		response.Body.Close()
		return cloudflareFixtureFailure("response_intake", "invalid_encoding", "unknown", 1, status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	closeErr := response.Body.Close()
	defer clear(body)
	if len(body) > 1<<20 {
		return cloudflareFixtureFailure("response_intake", "body_overflow", "unknown", 1, status)
	}
	if err != nil {
		return cloudflareFixtureFailure("response_intake", cloudflareFixtureCause(err), "unknown", 1, status)
	}
	if closeErr != nil {
		return cloudflareFixtureFailure("response_intake", cloudflareFixtureCause(closeErr), "unknown", 1, status)
	}
	if response.ContentLength >= 0 && int64(len(body)) != response.ContentLength {
		return cloudflareFixtureFailure("response_intake", "invalid_length", "unknown", 1, status)
	}
	var envelope struct {
		Success  *bool             `json:"success"`
		Errors   *[]jsontext.Value `json:"errors"`
		Messages *[]jsontext.Value `json:"messages"`
		Result   *struct {
			ID *string `json:"id"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.Success == nil ||
		envelope.Errors == nil || envelope.Messages == nil {
		return cloudflareFixtureFailure("acknowledgement", "malformed_envelope", "unknown", 1, status)
	}
	if !*envelope.Success || len(*envelope.Errors) != 0 {
		return cloudflareFixtureFailure("acknowledgement", "provider_refused", "unknown", 1, status)
	}
	if envelope.Result == nil || envelope.Result.ID == nil {
		return cloudflareFixtureFailure("acknowledgement", "malformed_envelope", "unknown", 1, status)
	}
	if *envelope.Result.ID != target {
		return cloudflareFixtureFailure("acknowledgement", "invalid_acknowledgement", "unknown", 1, status)
	}
	return nil
}

func validCloudflareFixtureID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' && b < 'a' || b > 'f' {
			return false
		}
	}
	return true
}

// full_only: false
func TestLiveGeneratorCleanupCredentialRequiresEnvironmentBearer(t *testing.T) {
	for _, value := range []string{"", "short", strings.Repeat("x", 39), strings.Repeat("x", 40) + "\n", strings.Repeat("x", 39) + "!", strings.Repeat("x", 81)} {
		t.Setenv("CLOUDFLARE_API_TOKEN", value)
		if body, err := readCloudflareFixtureBearer(); err == nil || body != nil {
			clear(body)
			t.Fatal("invalid environment bearer admitted")
		}
	}
	for _, value := range []string{strings.Repeat("x", 40), "Management_bearer_0123456789_ABCDEFGHIJKLMN", strings.Repeat("x", 80)} {
		t.Setenv("CLOUDFLARE_API_TOKEN", value)
		body, err := readCloudflareFixtureBearer()
		if err != nil || string(body) != value {
			t.Fatal("valid environment bearer refused")
		}
		clear(body)
	}
}

func cleanupCloudflareFixture(ctx context.Context, input liveRunInput, budget *runBudget) error {
	transport := cloudflareFixtureTransport()
	defer transport.CloseIdleConnections()
	return cleanupCloudflareFixtureWithTransport(ctx, input, budget, transport)
}

func cleanupCloudflareFixtureWithTransport(ctx context.Context, input liveRunInput, budget *runBudget, transport http.RoundTripper) error {
	if ctx == nil || budget == nil || transport == nil || input.Generator == nil || input.GeneratorCleanupLedger == "" || len(input.Scenarios) != 1 {
		return cloudflareFixtureFailure("admission", "invalid_request", "no_send", 0, nil)
	}
	g := input.Generator
	marker, err := records.SafePath(filepath.Dir(input.GeneratorCleanupLedger), "generator-writer-joined.json")
	if err != nil || records.ReadGeneratorFixtureJoined(marker, input.RunID, input.Scenarios[0]) != nil {
		return cloudflareFixtureFailure("writer_join", "evidence_unavailable", "no_send", 0, nil)
	}
	ledger, err := records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, g.Account)
	if err != nil {
		return cloudflareFixtureFailure("ledger", "evidence_unavailable", "no_send", 0, nil)
	}
	if input.PublicConfiguration != nil && !publicGeneratorRequestsSettled(ledger) {
		return cloudflareFixtureFailure("ownership_check", "unknown_effect", "no_send", 0, nil)
	}
	targets := ledger.CleanupTargets()
	if len(targets) == 0 {
		if ledger.Clean() {
			return nil
		}
		return cloudflareFixtureFailure("ownership_check", "unknown_effect", "no_send", 0, nil)
	}
	if g.CredentialsFile != "" {
		return cloudflareFixtureFailure("authentication", "authentication_refused", "no_send", 0, nil)
	}
	bearer, err := readCloudflareFixtureBearer()
	if err != nil {
		return cloudflareFixtureFailure("authentication", "authentication_refused", "no_send", 0, nil)
	}
	defer clear(bearer)
	for index, resource := range ledger.Resources {
		if resource.Disposition != "owned" {
			continue
		}
		if index > 1000000 {
			return cloudflareFixtureFailure("ownership_check", "evidence_unavailable", "no_send", 0, nil)
		}
		target := resource.ID
		ref := uint32(index)
		withTarget := func(err error) error {
			var failure cloudflareFixtureCleanupError
			if !errors.As(err, &failure) {
				return cloudflareFixtureFailure("ledger", "evidence_unavailable", "unknown", 1, nil)
			}
			failure.fact.TargetKind, failure.fact.TargetIndex = "generator_ledger", &ref
			return failure
		}
		if !budget.reserveGenerator(false) {
			return withTarget(cloudflareFixtureFailure("admission", "budget_exhausted", "no_send", 0, nil))
		}
		var attempt [32]byte
		if _, err := rand.Read(attempt[:]); err != nil {
			return withTarget(cloudflareFixtureFailure("admission", "evidence_unavailable", "no_send", 0, nil))
		}
		attemptID := fmt.Sprintf("%x", attempt)
		if err := records.UpdateGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, g.Account, func(current *records.GeneratorFixtureLedger) error {
			return current.BeginDelete(attemptID, target)
		}); err != nil {
			return withTarget(cloudflareFixtureFailure("persistence", "persistence_failed", "no_send", 0, nil))
		}
		requestCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		deleteErr := cloudflareFixtureDelete(requestCtx, cloudflareFixtureOrigin, transport, bearer, g.Account, target)
		cancel()
		if deleteErr != nil {
			return withTarget(deleteErr)
		}
		if err := records.UpdateGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, g.Account, func(current *records.GeneratorFixtureLedger) error {
			return current.RecordDelete(attemptID, target)
		}); err != nil {
			return withTarget(cloudflareFixtureFailure("persistence", "persistence_failed", "acknowledged", 1, nil))
		}
		if input.PublicConfiguration != nil {
			path := filepath.Join(filepath.Dir(input.GeneratorCleanupLedger), records.PublicGeneratorFixtureCleanupName)
			if records.RecordPublicGeneratorFixtureCleanup(path, input.RunID, input.Scenarios[0], g.Account, attemptID, target) != nil {
				return withTarget(cloudflareFixtureFailure("persistence", "persistence_failed", "acknowledged", 1, nil))
			}
		}
	}
	ledger, err = records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, g.Account)
	if err != nil || !ledger.Clean() {
		return cloudflareFixtureFailure("post_delete_read", "evidence_unavailable", "unknown", 1, nil)
	}
	return nil
}

// full_only: false
func TestLiveGeneratorCleanupRequiresPositiveWriterJoin(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	runID, account := strings.Repeat("a", 32), strings.Repeat("b", 32)
	scenario := "generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2"
	ledger := filepath.Join(state, "generator-cleanup.json")
	if err := records.NewGeneratorFixtureLedger(ledger, runID, account); err != nil {
		t.Fatal(err)
	}
	input := liveRunInput{RunID: runID, Scenarios: []string{scenario}, GeneratorCleanupLedger: ledger,
		Generator: &liveGeneratorSettings{Account: account}}
	budget := &runBudget{keys: map[string]bool{}}
	if cleanupCloudflareFixture(context.Background(), input, budget) == nil {
		t.Fatal("missing joined marker admitted cleanup")
	}
	marker := filepath.Join(state, "generator-writer-joined.json")
	if err := records.WriteGeneratorFixtureJoined(marker, runID, "generated.retirement-acknowledgement-closes/one_current_one_retiring_manual_ack"); err != nil ||
		cleanupCloudflareFixture(context.Background(), input, budget) == nil {
		t.Fatal("wrong scenario joined marker admitted cleanup", err)
	}
	if err := records.WriteGeneratorFixtureJoined(marker, runID, scenario); err != nil ||
		cleanupCloudflareFixture(context.Background(), input, budget) != nil {
		t.Fatal("valid joined marker could not permit clean ledger", err)
	}
}

// full_only: false
func TestLiveGeneratorFixtureDeleteRequiresExactAcknowledgement(t *testing.T) {
	account, target := strings.Repeat("a", 32), strings.Repeat("b", 32)
	bearer := []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN")
	var calls int
	expectedTarget := target
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodDelete || request.URL.Path != "/client/v4/accounts/"+account+"/tokens/"+expectedTarget || request.Header.Get("Authorization") != "Bearer "+string(bearer) {
			t.Error("fixture delete changed exact target or credential")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"`+target+`"}}`)
	}))
	defer server.Close()
	if cloudflareFixtureDelete(context.Background(), server.URL+"/client/v4", server.Client().Transport, bearer, account, target) != nil || calls != 1 {
		t.Fatal("exact fixture acknowledgement refused")
	}
	expectedTarget = strings.Repeat("c", 32)
	if cloudflareFixtureDelete(context.Background(), server.URL+"/client/v4", server.Client().Transport, bearer, account, strings.Repeat("c", 32)) == nil || calls != 2 {
		t.Fatal("mismatched fixture acknowledgement admitted")
	}
}

// full_only: false
func TestCloudflareCleanupRetainsSafeFailureCause(t *testing.T) {
	account, target := strings.Repeat("a", 32), strings.Repeat("b", 32)
	bearer := []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "private-response-sentinel")
	}))
	defer server.Close()
	err := cloudflareFixtureDelete(context.Background(), server.URL+"/client/v4", server.Client().Transport, bearer, account, target)
	var failure cloudflareFixtureCleanupError
	if !errors.As(err, &failure) {
		t.Fatal("fixture delete discarded its classified failure")
	}
	fact := failure.SafeHarnessFailure()
	if !fact.Validate() || fact.Operation != "generator_cleanup" || fact.Stage != "conditional_delete" ||
		fact.Cause != "provider_refused" || fact.Effect != "unknown" || fact.HTTPStatus == nil || *fact.HTTPStatus != 503 || fact.Attempt != 1 {
		t.Fatal("fixture delete lost the observed response and effect uncertainty", fact)
	}
	if strings.Contains(failure.Error(), "private-response-sentinel") || strings.Contains(fmt.Sprint(fact), "private-response-sentinel") {
		t.Fatal("private provider body escaped the closed failure")
	}
}

type cloudflareFixtureRoundTrip func(*http.Request) (*http.Response, error)

func (fn cloudflareFixtureRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type cloudflareFixtureBrokenReader struct{}

func (cloudflareFixtureBrokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func cloudflareFixtureReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, ProtoMajor: 1, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

// full_only: false
func TestCloudflareFixtureDeleteClassifiesClosedOutcomes(t *testing.T) {
	account, target := strings.Repeat("a", 32), strings.Repeat("b", 32)
	bearer := []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN")
	ack := `{"success":true,"errors":[],"messages":[],"result":{"id":"` + target + `"}}`
	wrong := `{"success":true,"errors":[],"messages":[],"result":{"id":"` + strings.Repeat("c", 32) + `"}}`
	cases := []struct {
		name, stage, cause string
		status             uint16
		reply              func() (*http.Response, error)
	}{
		{"cancel", "conditional_delete", "cancelled", 0, func() (*http.Response, error) { return nil, context.Canceled }},
		{"deadline", "conditional_delete", "deadline", 0, func() (*http.Response, error) { return nil, context.DeadlineExceeded }},
		{"transport", "conditional_delete", "transport", 0, func() (*http.Response, error) { return nil, errors.New("private-transport-sentinel") }},
		{"missing response", "conditional_delete", "missing_response", 0, func() (*http.Response, error) { return nil, nil }},
		{"access refusal", "conditional_delete", "access_refused", 403, func() (*http.Response, error) { return cloudflareFixtureReply(403, "private-response-sentinel"), nil }},
		{"condition refusal", "conditional_delete", "condition_refused", 412, func() (*http.Response, error) { return cloudflareFixtureReply(412, "private-response-sentinel"), nil }},
		{"provider refusal", "conditional_delete", "provider_refused", 503, func() (*http.Response, error) { return cloudflareFixtureReply(503, "private-response-sentinel"), nil }},
		{"early EOF", "response_intake", "early_eof", 200, func() (*http.Response, error) {
			response := cloudflareFixtureReply(200, "")
			response.Body, response.ContentLength = io.NopCloser(cloudflareFixtureBrokenReader{}), -1
			return response, nil
		}},
		{"body overflow", "response_intake", "body_overflow", 200, func() (*http.Response, error) { return cloudflareFixtureReply(200, strings.Repeat("x", 1<<20+1)), nil }},
		{"invalid encoding", "response_intake", "invalid_encoding", 200, func() (*http.Response, error) {
			response := cloudflareFixtureReply(200, ack)
			response.Header.Set("Content-Encoding", "gzip")
			return response, nil
		}},
		{"invalid length", "response_intake", "invalid_length", 200, func() (*http.Response, error) {
			response := cloudflareFixtureReply(200, ack)
			response.ContentLength++
			return response, nil
		}},
		{"malformed envelope", "acknowledgement", "malformed_envelope", 200, func() (*http.Response, error) {
			return cloudflareFixtureReply(200, `{"success":true,"errors":[],"messages":[],"result":"private-response-sentinel"}`), nil
		}},
		{"provider envelope refusal", "acknowledgement", "provider_refused", 200, func() (*http.Response, error) {
			return cloudflareFixtureReply(200, `{"success":false,"errors":[],"messages":[]}`), nil
		}},
		{"wrong ID", "acknowledgement", "invalid_acknowledgement", 200, func() (*http.Response, error) { return cloudflareFixtureReply(200, wrong), nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transport := cloudflareFixtureRoundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != http.MethodDelete || request.URL.Path != "/client/v4/accounts/"+account+"/tokens/"+target {
					t.Fatal("fixture delete changed method or exact target")
				}
				return tc.reply()
			})
			err := cloudflareFixtureDelete(context.Background(), "https://example.test/client/v4", transport, bearer, account, target)
			var failure cloudflareFixtureCleanupError
			if !errors.As(err, &failure) || calls != 1 {
				t.Fatal("failed delete did not retain one classified physical send", err, calls)
			}
			fact := failure.SafeHarnessFailure()
			if !fact.Validate() || fact.Stage != tc.stage || fact.Cause != tc.cause || fact.Effect != "unknown" || fact.Attempt != 1 ||
				(tc.status == 0) != (fact.HTTPStatus == nil) || fact.HTTPStatus != nil && *fact.HTTPStatus != tc.status {
				t.Fatal("delete failure fact is not exact and closed", fact)
			}
			encoded, marshalErr := json.Marshal(fact)
			if marshalErr != nil || strings.Contains(string(encoded), "private-") || strings.Contains(err.Error(), "private-") ||
				strings.Contains(string(encoded), target) || strings.Contains(err.Error(), target) {
				t.Fatal("private response, transport error or target escaped")
			}
		})
	}
	calls := 0
	transport := cloudflareFixtureRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return cloudflareFixtureReply(200, ack), nil })
	err := cloudflareFixtureDelete(context.Background(), "https://example.test/client/v4", transport, nil, account, target)
	var failure cloudflareFixtureCleanupError
	if !errors.As(err, &failure) || calls != 0 || failure.fact.Stage != "admission" || failure.fact.Cause != "invalid_request" ||
		failure.fact.Effect != "no_send" || failure.fact.Attempt != 0 || !failure.fact.Validate() {
		t.Fatal("invalid credential entered the transport", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = cloudflareFixtureDelete(ctx, "https://example.test/client/v4", transport, bearer, account, target)
	if !errors.As(err, &failure) || calls != 0 || failure.fact.Cause != "cancelled" || failure.fact.Effect != "no_send" {
		t.Fatal("pre-send cancellation entered the transport", calls)
	}
}

// full_only: false
func TestCloudflareCleanupRetainsLedgerTargetAndSingleSend(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	runID, account, target := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	scenario := "generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2"
	ledgerPath := filepath.Join(state, "generator-cleanup.json")
	if err := records.NewGeneratorFixtureLedger(ledgerPath, runID, account); err != nil {
		t.Fatal(err)
	}
	createAttempt := strings.Repeat("d", 64)
	if err := records.UpdateGeneratorFixtureLedger(ledgerPath, runID, account, func(ledger *records.GeneratorFixtureLedger) error {
		if err := ledger.BeginCreate(createAttempt); err != nil {
			return err
		}
		return ledger.RecordCreate(createAttempt, target)
	}); err != nil {
		t.Fatal(err)
	}
	if err := records.WriteGeneratorFixtureJoined(filepath.Join(state, "generator-writer-joined.json"), runID, scenario); err != nil {
		t.Fatal(err)
	}
	bearer := []byte("Management_bearer_0123456789_ABCDEFGHIJKLMN")
	t.Setenv("CLOUDFLARE_API_TOKEN", string(bearer))
	input := liveRunInput{RunID: runID, Scenarios: []string{scenario}, GeneratorCleanupLedger: ledgerPath,
		Generator: &liveGeneratorSettings{Account: account}}
	budget := &runBudget{limits: liveLimits{Requests: 1, BodyBytes: operationBodyAllowance, GeneratorRetires: 1}, keys: map[string]bool{}}
	calls := 0
	transport := cloudflareFixtureRoundTrip(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodDelete || request.URL.Path != "/client/v4/accounts/"+account+"/tokens/"+target ||
			request.Header.Get("Authorization") != "Bearer "+string(bearer) {
			t.Fatal("cleanup changed exact target or credential")
		}
		return cloudflareFixtureReply(503, "private-response-sentinel"), nil
	})
	err = cleanupCloudflareFixtureWithTransport(context.Background(), input, budget, transport)
	var failure cloudflareFixtureCleanupError
	if !errors.As(err, &failure) || calls != 1 {
		t.Fatal("cleanup did not retain one failed send", err, calls)
	}
	fact := failure.SafeHarnessFailure()
	if !fact.Validate() || fact.Stage != "conditional_delete" || fact.Cause != "provider_refused" || fact.Effect != "unknown" ||
		fact.TargetKind != "generator_ledger" || fact.TargetIndex == nil || *fact.TargetIndex != 0 || fact.HTTPStatus == nil || *fact.HTTPStatus != 503 {
		t.Fatal("cleanup did not bind its safe failure to the private ledger row", fact)
	}
	ledger, err := records.ReadGeneratorFixtureLedger(ledgerPath, runID, account)
	if err != nil || len(ledger.CleanupTargets()) != 1 || ledger.CleanupTargets()[0] != target ||
		len(ledger.Resources) != 1 || len(ledger.Resources[0].DeleteAttempts) != 1 || ledger.Resources[0].Disposition != "owned" {
		t.Fatal("failed delete lost its exact pending ledger ownership", err)
	}
	encoded, err := json.Marshal(fact)
	if err != nil || strings.Contains(string(encoded), target) || strings.Contains(string(encoded), "private-") ||
		strings.Contains(failure.Error(), target) {
		t.Fatal("private target or response escaped the safe cleanup fact")
	}
}

// A process-group join proves local completion only. A missing normalized
// create result or an earlier unclosed delete cannot be repaired by a new ACK.
func publicGeneratorRequestsSettled(ledger records.GeneratorFixtureLedger) bool {
	if len(ledger.PendingCreates) != 0 || len(ledger.Resources) > 6 {
		return false
	}
	for _, resource := range ledger.Resources {
		if resource.Disposition == "owned" && len(resource.DeleteAttempts) != 0 {
			return false
		}
	}
	return true
}

// full_only: false
func TestPublicGeneratorCleanupBlocksRemoteUnknownAfterLocalJoin(t *testing.T) {
	for _, condition := range []string{"pending-create", "unclosed-delete"} {
		t.Run(condition, func(t *testing.T) {
			state, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
			runID, account, target := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
			scenario := "public-configuration.generated-manual-lifecycle/generated_manual_lifecycle"
			path := filepath.Join(state, "generator-cleanup.json")
			if records.NewGeneratorFixtureLedger(path, runID, account) != nil || records.WriteGeneratorFixtureJoined(filepath.Join(state, "generator-writer-joined.json"), runID, scenario) != nil {
				t.Fatal("fixture setup unavailable")
			}
			if err := records.UpdateGeneratorFixtureLedger(path, runID, account, func(ledger *records.GeneratorFixtureLedger) error {
				attempt := strings.Repeat("d", 64)
				if err := ledger.BeginCreate(attempt); err != nil {
					return err
				}
				if condition == "pending-create" {
					return nil
				}
				if err := ledger.RecordCreate(attempt, target); err != nil {
					return err
				}
				return ledger.BeginDelete(strings.Repeat("e", 64), target)
			}); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CLOUDFLARE_API_TOKEN", strings.Repeat("x", 40))
			input := liveRunInput{RunID: runID, Scenarios: []string{scenario}, GeneratorCleanupLedger: path, Generator: &liveGeneratorSettings{Account: account}, PublicConfiguration: &publicConfigurationInput{}}
			calls := 0
			transport := cloudflareFixtureRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return cloudflareFixtureReply(200, `{"success":true,"errors":[],"messages":[],"result":{"id":"`+target+`"}}`), nil
			})
			budget := &runBudget{limits: liveLimits{Requests: 1, BodyBytes: operationBodyAllowance, GeneratorRetires: 1}, keys: map[string]bool{}}
			err = cleanupCloudflareFixtureWithTransport(context.Background(), input, budget, transport)
			var failure cloudflareFixtureCleanupError
			if !errors.As(err, &failure) || calls != 0 || failure.fact.Cause != "unknown_effect" {
				t.Fatal("local join converted remote unknown into a fresh delete", calls, err)
			}
			ledger, err := records.ReadGeneratorFixtureLedger(path, runID, account)
			if err != nil || ledger.Clean() {
				t.Fatal("blocked cleanup erased unknown ownership", err)
			}
		})
	}
}
