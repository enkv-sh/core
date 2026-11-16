package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	records "enkv.sh/core/internal/testrecords"
	protocol "enkv.sh/sdk/protocols/output"
)

const liveGitHubResponseBytes = 4096
const liveGitHubTimeout = 30 * time.Second

type liveGitHubOutputSpec struct {
	Scope, Owner, Repository, Environment, SecretNamePrefix string
	Writer, Cleaner                                         *liveOutputActor
	Budget                                                  *runBudget
}

type liveGitHubOutput struct {
	writerRoute        liveOutputCredentialRoute
	spec               liveGitHubOutputSpec
	transport          http.RoundTripper
	mu                 sync.Mutex
	attempted          map[string]bool
	preparationStarted bool
}

type liveGitHubFailure struct{ fact records.HarnessFailure }

func (e liveGitHubFailure) Error() string                              { return "GitHub output fixture refused" }
func (e liveGitHubFailure) SafeHarnessFailure() records.HarnessFailure { return e.fact }

func liveGitHubError(target *liveOutputCleanupTarget, stage, cause, effect string, status int) error {
	fact := records.HarnessFailure{Operation: "setup_check", Stage: stage, Cause: cause, Effect: effect}
	if target != nil && target.Index <= 1000000 {
		index := target.Index
		fact.Operation, fact.TargetKind, fact.TargetIndex = "output_cleanup", "output_inventory", &index
	}
	if effect != "no_send" {
		fact.Attempt = 1
	}
	if status >= 100 && status <= 599 {
		value := uint16(status)
		fact.HTTPStatus = &value
	}
	return liveGitHubFailure{fact: fact}
}

// These exact spellings match the admitted GitHub output profile. The prefix
// leaves 34 bytes for the independently reserved fixture suffix.
func liveGitHubName(value string, maximum int, initial, rest string) bool {
	if len(value) == 0 || len(value) > maximum || !strings.ContainsRune(initial, rune(value[0])) {
		return false
	}
	for i := 1; i < len(value); i++ {
		if !strings.ContainsRune(rest, rune(value[i])) {
			return false
		}
	}
	return true
}

func newLiveGitHubOutput(spec liveGitHubOutputSpec) (*liveGitHubOutput, error) {
	refused := liveGitHubError(nil, "admission", "invalid_request", "no_send", 0)
	const lower = "abcdefghijklmnopqrstuvwxyz0123456789"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
	if spec.Budget == nil || (spec.Writer == nil) == (spec.Cleaner == nil) ||
		!liveGitHubName(spec.Owner, 39, lower, lower+"-") || strings.HasSuffix(spec.Owner, "-") ||
		!liveGitHubName(spec.SecretNamePrefix, 66, upper, upper+"0123456789") || strings.HasPrefix(spec.SecretNamePrefix, "GITHUB_") {
		return nil, refused
	}
	switch spec.Scope {
	case "github-organization":
		if spec.Repository != "" || spec.Environment != "" {
			return nil, refused
		}
	case "github-repository", "github-environment":
		if !liveGitHubName(spec.Repository, 100, lower, lower+"._-") || !strings.ContainsRune(lower, rune(spec.Repository[len(spec.Repository)-1])) || strings.HasSuffix(spec.Repository, ".git") {
			return nil, refused
		}
		if spec.Scope == "github-environment" {
			if !liveGitHubName(spec.Environment, 255, lower, lower+"._-") || !strings.ContainsRune(lower, rune(spec.Environment[len(spec.Environment)-1])) {
				return nil, refused
			}
		} else if spec.Environment != "" {
			return nil, refused
		}
	default:
		return nil, refused
	}
	for _, actor := range []**liveOutputActor{&spec.Writer, &spec.Cleaner} {
		if *actor == nil {
			continue
		}
		copy := **actor
		if !liveOutputCredentialPath(copy.CredentialsFile) || copy.Profile != "" || copy.ServiceAccount != "" || copy.Principal != "" {
			return nil, refused
		}
		*actor = &copy
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.github.com", NextProtos: []string{"http/1.1"}},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives: true, DisableCompression: true, Protocols: protocols, MaxConnsPerHost: 1}
	return &liveGitHubOutput{spec: spec, transport: transport, attempted: make(map[string]bool)}, nil
}

// The synchronous loader owns and closes the capture before it returns. One
// optional terminal LF is stripped; the remaining bytes use the native profile.
func readLiveGitHubBearer(actor *liveOutputActor) (body []byte, resultErr error) {
	if actor == nil {
		return nil, liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
	}
	capture, err := captureLiveOutputCredentialFile(actor.CredentialsFile, maximumLiveOutputCredentialSourceBytes)
	if err != nil {
		return nil, liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
	}
	defer func() {
		if capture.Close() != nil {
			clear(body)
			body = nil
			resultErr = liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
		}
	}()
	body, err = os.ReadFile(capture.Path)
	if err != nil {
		clear(body)
		return nil, liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
	}
	if len(body) > 0 && body[len(body)-1] == '\n' {
		body = body[:len(body)-1]
	}
	if len(body) == 0 || len(body) > protocol.MaximumCredentialBytes-36 {
		clear(body)
		return nil, liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
	}
	for _, b := range body {
		if b < 0x21 || b > 0x7e || b == ':' || b == '\\' || b == '"' {
			clear(body)
			return nil, liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
		}
	}
	return body, nil
}

func (g *liveGitHubOutput) PrepareWriter(ctx context.Context, route liveOutputCredentialRoute, deadline time.Time) error {
	if g == nil || ctx == nil || ctx.Err() != nil || deadline.IsZero() || !deadline.After(time.Now()) {
		return liveGitHubError(nil, "admission", "invalid_request", "no_send", 0)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.spec.Writer == nil {
		return liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
	}
	if g.preparationStarted || route.ID.IsZero() || !liveOutputCredentialPath(route.Path) {
		return liveGitHubError(nil, "admission", "invalid_request", "no_send", 0)
	}
	// A failed preparation also ends this fixture's one capture/publication attempt.
	g.preparationStarted = true
	bearer, err := readLiveGitHubBearer(g.spec.Writer)
	if err != nil {
		return err
	}
	defer clear(bearer)
	if ctx.Err() != nil || !deadline.After(time.Now()) {
		return liveGitHubError(nil, "authentication", "cancelled", "no_send", 0)
	}
	if writeLiveOutputCredentialRoute(route, bearer) != nil {
		return liveGitHubError(nil, "authentication", "authentication_refused", "no_send", 0)
	}
	g.writerRoute = route
	return nil
}

func (g *liveGitHubOutput) slotBase() string {
	switch g.spec.Scope {
	case "github-organization":
		return "orgs/" + g.spec.Owner + "/actions/secrets/"
	case "github-environment":
		return "repos/" + g.spec.Owner + "/" + g.spec.Repository + "/environments/" + g.spec.Environment + "/secrets/"
	default:
		return "repos/" + g.spec.Owner + "/" + g.spec.Repository + "/actions/secrets/"
	}
}

// The caller proves a durable writer join before calling this helper. A name
// match is not Product birth proof. A pending create uses only the caller's
// exclusive fixture prefix, which GitHub cannot enforce against co-tenancy.
func (g *liveGitHubOutput) DeleteFixture(ctx context.Context, target liveOutputCleanupTarget) (liveOutputCleanupResult, error) {
	empty := liveOutputCleanupResult{}
	if g == nil || ctx == nil || target.Index > 1000000 {
		return empty, liveGitHubError(nil, "admission", "invalid_request", "no_send", 0)
	}
	base := g.slotBase()
	name := strings.TrimPrefix(target.PlannedSlot, base)
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
	if !strings.HasPrefix(target.PlannedSlot, base) || !liveGitHubName(name, 100, upper, upper+"0123456789") ||
		strings.HasPrefix(name, "GITHUB_") || !strings.HasPrefix(name, g.spec.SecretNamePrefix) || len(name) == len(g.spec.SecretNamePrefix) ||
		target.OwnedInstance != "" && target.OwnedInstance != target.PlannedSlot || target.OwnedInstance == "" && target.CreateAttempt.IsZero() {
		return empty, liveGitHubError(&target, "ownership_check", "ownership_mismatch", "no_send", 0)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.attempted[target.PlannedSlot] {
		return empty, liveGitHubError(&target, "admission", "evidence_unavailable", "no_send", 0)
	}
	if ctx.Err() != nil {
		return empty, liveGitHubError(&target, "admission", "cancelled", "no_send", 0)
	}
	bearer, err := readLiveGitHubBearer(g.spec.Cleaner)
	if err != nil {
		return empty, liveGitHubError(&target, "authentication", "authentication_refused", "no_send", 0)
	}
	defer clear(bearer)
	g.attempted[target.PlannedSlot] = true
	bounded, cancel := context.WithTimeout(ctx, liveGitHubTimeout)
	defer cancel()
	status, body, err := g.request(bounded, http.MethodGet, target, bearer)
	defer clear(body)
	if err != nil {
		return empty, err
	}
	// GitHub masks unauthorized private resources with 404. Bearer syntax alone
	// does not authenticate this scope, so absence cannot be inferred here.
	if status == http.StatusNotFound {
		return empty, liveGitHubError(&target, "ownership_read", "evidence_unavailable", "no_effect", status)
	}
	if status != http.StatusOK {
		return empty, liveGitHubError(&target, "ownership_read", "provider_refused", "no_effect", status)
	}
	metadataName, valid := liveGitHubMetadataName(body)
	if !valid {
		return empty, liveGitHubError(&target, "response_intake", "malformed_envelope", "no_effect", status)
	}
	if metadataName != name {
		return empty, liveGitHubError(&target, "ownership_check", "ownership_mismatch", "no_effect", status)
	}
	status, reply, err := g.request(bounded, http.MethodDelete, target, bearer)
	defer clear(reply)
	if err != nil {
		return empty, err
	}
	if status != http.StatusNoContent || len(reply) != 0 {
		return empty, liveGitHubError(&target, "acknowledgement", "invalid_acknowledgement", "unknown", status)
	}
	return liveOutputCleanupResult{Disposition: liveOutputDeleteAcknowledged, ResolvedInstance: target.PlannedSlot}, nil
}

// Only the exact, unique nonnull name can qualify a target. Other metadata
// fields remain accepted, without mapping them onto permissive struct fields.
func liveGitHubMetadataName(body []byte) (string, bool) {
	if !utf8.Valid(body) {
		return "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", false
	}
	seen := make(map[string]bool)
	name, hasName := "", false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		field, ok := token.(string)
		if !ok {
			return "", false
		}
		folded := strings.ToLower(field)
		if seen[folded] || folded == "name" && field != "name" {
			return "", false
		}
		seen[folded] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return "", false
		}
		if field == "name" {
			value = bytes.TrimSpace(value)
			if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &name) != nil {
				return "", false
			}
			hasName = true
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return "", false
	}
	return name, hasName
}

func (g *liveGitHubOutput) request(ctx context.Context, method string, target liveOutputCleanupTarget, bearer []byte) (int, []byte, error) {
	stage, effect := "ownership_read", "no_effect"
	if method == http.MethodDelete {
		stage, effect = "conditional_delete", "unknown"
	}
	if ctx.Err() != nil {
		return 0, nil, liveGitHubError(&target, stage, "cancelled", "no_send", 0)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://api.github.com/"+target.PlannedSlot, nil)
	if err != nil {
		return 0, nil, liveGitHubError(&target, stage, "invalid_request", "no_send", 0)
	}
	request.Close = true
	request.GetBody = nil
	request.Header.Set("Authorization", "Bearer "+string(bearer))
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	request.Header.Set("User-Agent", "enkv-live-output-fixture")
	if !g.spec.Budget.reserve(1, liveGitHubResponseBytes, "", 0) {
		return 0, nil, liveGitHubError(&target, stage, "budget_exhausted", "no_send", 0)
	}
	// RoundTrip owns exactly one request; it cannot follow redirects.
	response, err := g.transport.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			if response.Body.Close() != nil {
				return 0, nil, liveGitHubError(&target, "response_intake", "early_eof", effect, 0)
			}
		}
		cause := "transport"
		if ctx.Err() != nil {
			cause = "cancelled"
		}
		return 0, nil, liveGitHubError(&target, stage, cause, effect, 0)
	}
	if response == nil || response.Body == nil {
		return 0, nil, liveGitHubError(&target, "response_intake", "missing_response", effect, 0)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, liveGitHubResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		clear(body)
		return response.StatusCode, nil, liveGitHubError(&target, "response_intake", "early_eof", effect, response.StatusCode)
	}
	if len(body) > liveGitHubResponseBytes {
		clear(body)
		return response.StatusCode, nil, liveGitHubError(&target, "response_intake", "body_overflow", effect, response.StatusCode)
	}
	if ctx.Err() != nil {
		clear(body)
		return response.StatusCode, nil, liveGitHubError(&target, "response_intake", "cancelled", effect, response.StatusCode)
	}
	return response.StatusCode, body, nil
}

var _ interface{ SafeHarnessFailure() records.HarnessFailure } = liveGitHubFailure{}

func (g *liveGitHubOutput) BindWriterEnvironment(bind func(string, string)) error {
	if bind == nil || !g.preparationStarted {
		return errLivePublication
	}
	body, err := os.ReadFile(g.writerRoute.Path)
	if err != nil {
		return errLivePublication
	}
	defer clear(body)
	bind("GITHUB_TOKEN", string(body))
	return nil
}
