package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/providers/gcp"
	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

var errGCPOutput = errors.New("GCP output fixture refused")

const (
	gcpOutputTimeout       = 30 * time.Second
	gcpOutputResponseLimit = 128 << 10
	gcpOutputSourceLimit   = 64 << 10
)

var gcpOutputSecretID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
var gcpOutputEmail = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*@[a-z][a-z0-9-]*\.iam\.gserviceaccount\.com$`)

type gcpOutputFailure struct{ facts records.HarnessFailure }

func (f *gcpOutputFailure) Error() string                              { return errGCPOutput.Error() }
func (f *gcpOutputFailure) Is(target error) bool                       { return target == errGCPOutput }
func (f *gcpOutputFailure) SafeHarnessFailure() records.HarnessFailure { return f.facts }

func gcpOutputFail(stage, cause string) *gcpOutputFailure {
	return &gcpOutputFailure{records.HarnessFailure{Operation: "setup_check", Stage: stage, Cause: cause, Effect: "no_send"}}
}

type gcpOutputActor struct {
	actor    liveOutputActor
	identity os.FileInfo
	token    string
	facts    liveOutputCredentialFacts
	source   []byte
}

type gcpCloudOutput struct {
	spec    liveCloudOutputSpec
	actors  [4]*gcpOutputActor
	base    http.RoundTripper
	gate    chan struct{}
	route   liveOutputCredentialRoute
	deletes map[string]bool
}

func newLiveCloudOutput(spec liveCloudOutputSpec) (liveCloudOutput, error) {
	base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: gcpOutputTimeout,
		MaxResponseHeaderBytes: gcpOutputSourceLimit, DisableKeepAlives: true, DisableCompression: true,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	return newGCPCloudOutput(spec, base)
}

func newGCPCloudOutput(spec liveCloudOutputSpec, base http.RoundTripper) (*gcpCloudOutput, error) {
	location := spec.Location
	number, err := strconv.ParseUint(location.ProjectNumber, 10, 64)
	prefix := "projects/" + location.ProjectNumber + "/secrets/"
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != location.ProjectNumber ||
		location.Provider != "gcp" || location.Region != "" || location.Account != "" ||
		!strings.HasPrefix(location.SecretNamePrefix, prefix) ||
		!gcpOutputSecretID.MatchString(strings.TrimPrefix(location.SecretNamePrefix, prefix)) ||
		spec.Budget == nil || base == nil {
		return nil, gcpOutputFail("admission", "invalid_request")
	}
	writer := spec.Writer != nil && spec.Cleaner == nil && spec.ConsumerA != nil && spec.ConsumerB != nil
	cleaner := spec.Cleaner != nil && spec.Writer == nil && spec.ConsumerA == nil && spec.ConsumerB == nil
	if !writer && !cleaner || writer && len(spec.OtherActorPrincipals) != 0 || cleaner && len(spec.OtherActorPrincipals) != 3 {
		return nil, gcpOutputFail("admission", "invalid_request")
	}
	s := &gcpCloudOutput{spec: spec, base: base, gate: make(chan struct{}, 1), deletes: make(map[string]bool)}
	s.spec.OtherActorPrincipals = append([]string(nil), spec.OtherActorPrincipals...)
	paths, principals := map[string]bool{}, map[string]bool{}
	for i, actor := range []*liveOutputActor{spec.Writer, spec.Cleaner, spec.ConsumerA, spec.ConsumerB} {
		if actor == nil {
			continue
		}
		if actor.Profile != "" || !filepath.IsAbs(actor.CredentialsFile) || filepath.Clean(actor.CredentialsFile) != actor.CredentialsFile ||
			!gcpOutputEmail.MatchString(actor.ServiceAccount) || paths[actor.CredentialsFile] || principals[actor.ServiceAccount] ||
			i < 2 && actor.Principal != "" || i >= 2 && actor.Principal != "serviceAccount:"+actor.ServiceAccount {
			return nil, gcpOutputFail("admission", "invalid_request")
		}
		paths[actor.CredentialsFile], principals[actor.ServiceAccount] = true, true
		s.actors[i] = &gcpOutputActor{actor: *actor}
	}
	otherPrincipals := map[string]bool{}
	for _, principal := range s.spec.OtherActorPrincipals {
		if !strings.HasPrefix(principal, "serviceAccount:") || !gcpOutputEmail.MatchString(strings.TrimPrefix(principal, "serviceAccount:")) || otherPrincipals[principal] {
			return nil, gcpOutputFail("admission", "invalid_request")
		}
		otherPrincipals[principal] = true
	}
	// The retained actor values are owned copies; callers can discard their inputs.
	s.spec.Writer, s.spec.Cleaner, s.spec.ConsumerA, s.spec.ConsumerB = nil, nil, nil, nil
	return s, nil
}

func (s *gcpCloudOutput) enter(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, gcpOutputFail("admission", "invalid_request")
	}
	ctx, cancel := context.WithTimeout(ctx, gcpOutputTimeout)
	select {
	case s.gate <- struct{}{}:
		if ctx.Err() == nil {
			return ctx, func() { <-s.gate; cancel() }, nil
		}
		<-s.gate
	case <-ctx.Done():
	}
	cancel()
	return nil, nil, gcpOutputFail("admission", gcpFailureCause(ctx.Err()))
}

func gcpOutputBearer(token string) bool {
	if len(token) == 0 || len(token) > protocol.MaximumCredentialBytes-36 {
		return false
	}
	for _, b := range []byte(token) {
		if b < 0x21 || b > 0x7e || b == ':' || b == '\\' || b == '"' {
			return false
		}
	}
	return true
}

func (s *gcpCloudOutput) capture(ctx context.Context, index int, deadline time.Time) (*gcpOutputActor, error) {
	actor := s.actors[index]
	if actor == nil || deadline.IsZero() || !time.Now().Before(deadline) {
		return nil, gcpOutputFail("admission", "invalid_request")
	}
	if actor.token != "" {
		if !actor.facts.Expires.After(deadline) {
			return nil, gcpOutputFail("authentication", "authentication_refused")
		}
		return actor, nil
	}
	captured, err := captureLiveOutputCredentialFile(actor.actor.CredentialsFile, gcpOutputSourceLimit)
	if err != nil {
		return nil, gcpOutputFail("authentication", "authentication_refused")
	}
	for _, other := range s.actors {
		if other != nil && other.identity != nil && records.SameLocalFile(captured.Identity, other.identity) {
			if captured.Close() != nil {
				return nil, gcpOutputFail("persistence", "persistence_failed")
			}
			return nil, gcpOutputFail("authentication", "ownership_mismatch")
		}
	}
	meter := &gcpOutputTransport{base: s.base, budget: s.spec.Budget, oauth: true}
	source, loadErr := gcp.LoadServiceAccountFileForTest(ctx, captured.Path, meter)
	var sourceBody []byte
	defer func() { clear(sourceBody) }()
	if index == 0 && loadErr == nil {
		sourceBody, loadErr = os.ReadFile(captured.Path)
	}
	closeErr := captured.Close()
	if closeErr != nil {
		clear(sourceBody)
		return nil, gcpOutputFail("persistence", "persistence_failed")
	}
	if loadErr != nil {
		clear(sourceBody)
		return nil, gcpOutputFail("authentication", "authentication_refused")
	}
	email, err := gcp.ServiceAccountEmailForTest(source)
	if err != nil || email != actor.actor.ServiceAccount {
		return nil, gcpOutputFail("authentication", "ownership_mismatch")
	}
	principal := "serviceAccount:" + email
	for _, other := range s.spec.OtherActorPrincipals {
		if other == principal {
			return nil, gcpOutputFail("authentication", "ownership_mismatch")
		}
	}
	token, expiry, err := gcp.CaptureServiceAccountTokenForTest(ctx, source)
	if meter.failure != nil {
		return nil, meter.failure
	}
	if ctx.Err() != nil {
		return nil, gcpOutputFail("authentication", gcpFailureCause(ctx.Err()))
	}
	if err != nil || ctx.Err() != nil || !gcpOutputBearer(token) || !expiry.After(deadline) {
		return nil, gcpOutputFail("authentication", "authentication_refused")
	}
	actor.identity, actor.token = captured.Identity, token
	actor.source = sourceBody
	sourceBody = nil
	actor.facts = liveOutputCredentialFacts{Principal: principal, Expires: expiry}
	return actor, nil
}

func (s *gcpCloudOutput) PrepareWriter(ctx context.Context, route liveOutputCredentialRoute, deadline time.Time) (liveOutputCredentialFacts, error) {
	ctx, done, err := s.enter(ctx)
	if err != nil {
		return liveOutputCredentialFacts{}, err
	}
	defer done()
	if s.actors[0] == nil || route.ID.IsZero() || !filepath.IsAbs(route.Path) || filepath.Clean(route.Path) != route.Path {
		return liveOutputCredentialFacts{}, gcpOutputFail("admission", "invalid_request")
	}
	for _, actor := range s.actors {
		if actor != nil && actor.actor.CredentialsFile == route.Path {
			return liveOutputCredentialFacts{}, gcpOutputFail("admission", "ownership_mismatch")
		}
	}
	if s.route.Path != "" && (s.route.Path != route.Path || s.route.ID != route.ID) {
		return liveOutputCredentialFacts{}, gcpOutputFail("admission", "ownership_mismatch")
	}
	actor, err := s.capture(ctx, 0, deadline)
	if err != nil {
		return liveOutputCredentialFacts{}, err
	}
	defer func() { clear(actor.source); actor.source = nil }()
	for _, index := range []int{2, 3} {
		if _, err := s.capture(ctx, index, deadline); err != nil {
			return liveOutputCredentialFacts{}, err
		}
	}
	if s.route.Path == "" {
		err = writeLiveOutputCredentialRoute(route, actor.source)
		clear(actor.source)
		actor.source = nil
		if err != nil {
			return liveOutputCredentialFacts{}, gcpOutputFail("persistence", "persistence_failed")
		}
		s.route = route
	}
	return actor.facts, nil
}

func (s *gcpCloudOutput) validSecret(name string) bool {
	base := "projects/" + s.spec.Location.ProjectNumber + "/secrets/"
	return strings.HasPrefix(name, s.spec.Location.SecretNamePrefix) && strings.HasPrefix(name, base) &&
		gcpOutputSecretID.MatchString(strings.TrimPrefix(name, base)) && len(name) > len(s.spec.Location.SecretNamePrefix)
}

func (s *gcpCloudOutput) ReadConsumer(ctx context.Context, consumer liveOutputConsumer, locator string, maximum uint32) (liveOutputRead, error) {
	ctx, done, err := s.enter(ctx)
	if err != nil {
		return liveOutputRead{}, err
	}
	defer done()
	name, resolved := strings.CutSuffix(locator, "/versions/latest")
	if !resolved || !s.validSecret(name) || maximum == 0 || maximum > 64<<10 || consumer != liveOutputConsumerA && consumer != liveOutputConsumerB {
		return liveOutputRead{}, gcpOutputFail("admission", "invalid_request")
	}
	deadline, _ := ctx.Deadline()
	actor, err := s.capture(ctx, int(consumer)+1, deadline)
	if err != nil {
		return liveOutputRead{}, err
	}
	status, body, err := s.request(ctx, actor.token, http.MethodGet, locator+":access", "")
	defer clear(body)
	if err != nil {
		return liveOutputRead{}, err
	}
	if gcpOutputErrorEnvelope(status, body, 403, "PERMISSION_DENIED") {
		return liveOutputRead{HTTPStatus: status, AccessRefused: true}, nil
	}
	if status != 200 {
		return liveOutputRead{HTTPStatus: status}, gcpOutputResponseFailure(status, "provider_refused", "no_effect")
	}
	fields, objectOK := gcpOutputObject(body)
	payload, payloadOK := gcpOutputObject(fields["payload"])
	var version string
	var data, checksumText *string
	if !objectOK || !payloadOK || json.Unmarshal(fields["name"], &version) != nil || !gcpOutputVersion(name, version) ||
		json.Unmarshal(payload["data"], &data) != nil || data == nil || json.Unmarshal(payload["dataCrc32c"], &checksumText) != nil || checksumText == nil {
		return liveOutputRead{HTTPStatus: status}, gcpOutputResponseFailure(status, "malformed_envelope", "no_effect")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(*data)
	checksum, checksumErr := strconv.ParseUint(*checksumText, 10, 32)
	if err != nil || len(decoded) > int(maximum) || base64.StdEncoding.EncodeToString(decoded) != *data || checksumErr != nil ||
		strconv.FormatUint(checksum, 10) != *checksumText || uint32(checksum) != crc32.Checksum(decoded, crc32.MakeTable(crc32.Castagnoli)) {
		clear(decoded)
		return liveOutputRead{HTTPStatus: status}, gcpOutputResponseFailure(status, "malformed_envelope", "no_effect")
	}
	return liveOutputRead{HTTPStatus: status, Bytes: decoded}, nil
}

func gcpOutputVersion(parent, name string) bool {
	if !strings.HasPrefix(name, parent+"/versions/") {
		return false
	}
	number := strings.TrimPrefix(name, parent+"/versions/")
	value, err := strconv.ParseInt(number, 10, 64)
	return err == nil && value > 0 && strconv.FormatInt(value, 10) == number
}

// Critical fields are decoded separately after uniqueness checks. A duplicate,
// case alias or null must not retain a prior accepted identity or result.
func gcpOutputObject(body []byte) (map[string]json.RawMessage, bool) {
	if !utf8.Valid(body) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		folded := strings.Map(func(r rune) rune {
			minimum := r
			for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
				if next < minimum {
					minimum = next
				}
			}
			return minimum
		}, key)
		if seen[folded] {
			return nil, false
		}
		seen[folded] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		fields[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

func gcpOutputErrorEnvelope(status int, body []byte, want int, name string) bool {
	if status != want {
		return false
	}
	fields, objectOK := gcpOutputObject(body)
	failure, errorOK := gcpOutputObject(fields["error"])
	var code *int
	var state *string
	return objectOK && errorOK && json.Unmarshal(failure["code"], &code) == nil && code != nil && *code == want &&
		json.Unmarshal(failure["status"], &state) == nil && state != nil && *state == name
}

func gcpOutputResponseFailure(status int, cause, effect string) *gcpOutputFailure {
	f := gcpOutputFail("response_intake", cause)
	f.facts.Effect, f.facts.Attempt = effect, 1
	if status >= 100 && status <= 599 {
		v := uint16(status)
		f.facts.HTTPStatus = &v
	}
	return f
}

func (s *gcpCloudOutput) DeleteFixture(ctx context.Context, target liveOutputCleanupTarget) (result liveOutputCleanupResult, resultErr error) {
	if target.Index > 1000000 {
		return result, gcpOutputFail("admission", "invalid_request")
	}
	defer func() {
		if resultErr != nil {
			var f *gcpOutputFailure
			if errors.As(resultErr, &f) {
				f.facts.Operation, f.facts.TargetKind = "output_cleanup", "output_inventory"
				index := target.Index
				f.facts.TargetIndex = &index
			}
		}
	}()
	ctx, done, err := s.enter(ctx)
	if err != nil {
		return result, err
	}
	defer done()
	if s.actors[1] == nil || target.CreateAttempt.IsZero() || !s.validSecret(target.PlannedSlot) ||
		target.OwnedInstance != "" && target.OwnedInstance != target.PlannedSlot || s.deletes[target.PlannedSlot] {
		return result, gcpOutputFail("admission", "invalid_request")
	}
	deadline, _ := ctx.Deadline()
	actor, err := s.capture(ctx, 1, deadline)
	if err != nil {
		return result, err
	}
	status, body, err := s.request(ctx, actor.token, http.MethodGet, target.PlannedSlot, "")
	defer clear(body)
	if err != nil {
		return result, err
	}
	if gcpOutputErrorEnvelope(status, body, 404, "NOT_FOUND") {
		return liveOutputCleanupResult{Disposition: liveOutputAbsent, ResolvedInstance: target.PlannedSlot}, nil
	}
	metadata, objectOK := gcpOutputObject(body)
	var name, etag string
	if status != 200 || !objectOK || json.Unmarshal(metadata["name"], &name) != nil || name != target.PlannedSlot ||
		json.Unmarshal(metadata["etag"], &etag) != nil || len(etag) == 0 || len(etag) > 1024 || strings.ContainsAny(etag, "\r\n\x00") {
		return result, gcpOutputResponseFailure(status, "ownership_mismatch", "no_effect")
	}
	// A failed reservation has no send. Once DELETE enters, this helper cannot replay it.
	status, deleted, err := s.request(ctx, actor.token, http.MethodDelete, target.PlannedSlot, url.Values{"etag": {etag}}.Encode())
	defer clear(deleted)
	var failure *gcpOutputFailure
	if err == nil || errors.As(err, &failure) && failure.facts.Attempt != 0 {
		s.deletes[target.PlannedSlot] = true
	}
	if err != nil {
		return result, err
	}
	var empty map[string]json.RawMessage
	if status != 200 || len(bytes.TrimSpace(deleted)) != 0 && (json.Unmarshal(deleted, &empty) != nil || empty == nil || len(empty) != 0) {
		return result, gcpOutputResponseFailure(status, "invalid_acknowledgement", "unknown")
	}
	return liveOutputCleanupResult{Disposition: liveOutputDeleteAcknowledged, ResolvedInstance: target.PlannedSlot}, nil
}

func (s *gcpCloudOutput) request(ctx context.Context, token, method, name, query string) (int, []byte, error) {
	u := &url.URL{Scheme: "https", Host: "secretmanager.googleapis.com", Path: "/v1/" + name, RawQuery: query}
	r, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return 0, nil, gcpOutputFail("admission", "invalid_request")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	response, err := (&gcpOutputTransport{base: s.base, budget: s.spec.Budget}).RoundTrip(r)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, gcpOutputResponseFailure(response.StatusCode, "transport", "unknown")
	}
	return response.StatusCode, body, nil
}

type gcpOutputTransport struct {
	base    http.RoundTripper
	budget  *runBudget
	oauth   bool
	sent    bool
	failure *gcpOutputFailure
}

type gcpOutputBody struct {
	mu     sync.Mutex
	reader *bytes.Reader
	bytes  []byte
	closed bool
}

func (b *gcpOutputBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	return b.reader.Read(p)
}
func (b *gcpOutputBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.bytes)
	b.closed = true
	return nil
}
func newGCPOutputBody(body []byte) *gcpOutputBody {
	return &gcpOutputBody{reader: bytes.NewReader(body), bytes: body}
}

func (t *gcpOutputTransport) RoundTrip(r *http.Request) (response *http.Response, resultErr error) {
	defer func() {
		var failure *gcpOutputFailure
		if errors.As(resultErr, &failure) {
			t.failure = failure
		}
	}()
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Fragment != "" ||
		t.oauth && (t.sent || r.Method != http.MethodPost || r.URL.String() != "https://oauth2.googleapis.com/token") ||
		!t.oauth && (r.URL.Host != "secretmanager.googleapis.com" || !strings.HasPrefix(r.URL.Path, "/v1/projects/") || r.Method != http.MethodGet && r.Method != http.MethodDelete) {
		if r != nil && r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, gcpOutputFail("admission", "invalid_request")
	}
	if r.Context().Err() != nil {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, gcpOutputFail("admission", gcpFailureCause(r.Context().Err()))
	}
	frozen := r.Clone(r.Context())
	frozen.GetBody, frozen.Close = nil, true
	if frozen.Header == nil {
		frozen.Header = make(http.Header)
	}
	frozen.Header.Set("Accept-Encoding", "identity")
	frozen.Header.Set("Cache-Control", "no-cache, no-transform")
	var joined *setupRequestBody
	if frozen.Body != nil && frozen.Body != http.NoBody {
		body, readErr := io.ReadAll(io.LimitReader(frozen.Body, gcpOutputSourceLimit+1))
		closeErr := frozen.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > gcpOutputSourceLimit {
			clear(body)
			return nil, gcpOutputFail("admission", "invalid_request")
		}
		joined = &setupRequestBody{ReadCloser: newGCPOutputBody(body), done: make(chan struct{})}
		frozen.Body, frozen.ContentLength = joined, int64(len(body))
	}
	if !t.budget.reserve(1, operationBodyAllowance, "", 0) {
		if joined != nil {
			_ = joined.Close()
		}
		return nil, gcpOutputFail("admission", "budget_exhausted")
	}
	t.sent = true
	metric := telemetry.OpSetupRead
	if t.oauth {
		metric = telemetry.OpAuthentication
	} else if frozen.Method == http.MethodDelete {
		metric = telemetry.OpSetupDelete
	}
	call := telemetry.StartHTTP(frozen.Context(), telemetry.ProviderGCP, metric)
	var requestObservation, responseObservation *telemetry.BodyObservation
	if call != nil && joined != nil {
		requestObservation = telemetry.TrackBody(joined.ReadCloser, frozen.ContentLength)
		joined.ReadCloser = requestObservation
	}
	status := 0
	defer func() {
		if call != nil {
			call.ObserveRequest(requestObservation.Snapshot())
			if responseObservation != nil {
				call.ObserveResponse(responseObservation.Snapshot())
			}
			call.Finish(status, resultErr != nil)
		}
	}()
	effect := "no_effect"
	if frozen.Method == http.MethodDelete {
		effect = "unknown"
	}
	response, err := t.base.RoundTrip(frozen)
	if response != nil {
		status = response.StatusCode
		if call != nil && response.Body != nil {
			responseObservation = telemetry.TrackBody(response.Body, response.ContentLength)
			response.Body = responseObservation
		}
	}
	if !joined.finished(frozen.Context()) {
		// This copy has only finite owned reads. Close rejects later reads, clears
		// the copied assertion, and lets us join admitted reads before returning.
		closeErr := joined.Close()
		<-joined.done
		if response != nil && response.Body != nil {
			closeErr = errors.Join(closeErr, response.Body.Close())
		}
		cause := gcpFailureCause(frozen.Context().Err())
		if closeErr != nil {
			cause = "transport"
		}
		return nil, gcpOutputResponseFailure(0, cause, effect)
	}
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		cause := "missing_response"
		if err != nil {
			cause = gcpFailureCause(err)
		}
		return nil, gcpOutputResponseFailure(0, cause, effect)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, gcpOutputResponseLimit+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > gcpOutputResponseLimit || response.Uncompressed || response.Header.Get("Content-Encoding") != "" ||
		response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		clear(body)
		return nil, gcpOutputResponseFailure(response.StatusCode, "invalid_length", effect)
	}
	copyResponse := *response
	copyResponse.Body = newGCPOutputBody(body)
	return &copyResponse, nil
}

func (s *gcpCloudOutput) BindWriterEnvironment(bind func(string, string)) error {
	if bind == nil || s.route.Path == "" || s.actors[0] == nil || s.actors[0].identity == nil {
		return gcpOutputFail("admission", "invalid_request")
	}
	bind("GOOGLE_APPLICATION_CREDENTIALS", s.route.Path)
	return nil
}
