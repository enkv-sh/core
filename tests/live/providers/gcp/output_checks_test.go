package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

func gcpOutputSyntheticSpec(t *testing.T, cleanup bool) (liveCloudOutputSpec, liveOutputCredentialRoute) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	actor := func(name string, consumer bool) *liveOutputActor {
		email := name + "@fixture-project.iam.gserviceaccount.com"
		path := filepath.Join(dir, name+".json")
		if err := custody.WriteGCPServiceAccountCredential(path, email); err != nil {
			t.Fatal(err)
		}
		result := &liveOutputActor{CredentialsFile: path, ServiceAccount: email}
		if consumer {
			result.Principal = "serviceAccount:" + email
		}
		return result
	}
	spec := liveCloudOutputSpec{Location: liveOutputLocation{Provider: "gcp", ProjectNumber: "123456789", SecretNamePrefix: "projects/123456789/secrets/fixture-output-positive-"},
		Budget: &runBudget{limits: liveLimits{Requests: 20, BodyBytes: 20 * operationBodyAllowance}}}
	if cleanup {
		spec.Cleaner = actor("cleaner", false)
		spec.OtherActorPrincipals = []string{"serviceAccount:writer@fixture-project.iam.gserviceaccount.com", "serviceAccount:consumer-a@fixture-project.iam.gserviceaccount.com", "serviceAccount:consumer-b@fixture-project.iam.gserviceaccount.com"}
	} else {
		spec.Writer, spec.ConsumerA, spec.ConsumerB = actor("writer", false), actor("consumer-a", true), actor("consumer-b", true)
	}
	return spec, liveOutputCredentialRoute{Path: filepath.Join(dir, "writer-bearer"), ID: protocol.ID{1}}
}

func gcpOutputTokenReply() *http.Response {
	return gcpSetupReply(200, `{"access_token":"synthetic-bearer","token_type":"Bearer","expires_in":3600}`)
}

func gcpOutputAssertFailure(t *testing.T, err error, cause, effect string) *gcpOutputFailure {
	t.Helper()
	var failure *gcpOutputFailure
	if !errors.As(err, &failure) {
		t.Fatalf("safe failure absent: type=%T", err)
	}
	fact := failure.SafeHarnessFailure()
	if !fact.Validate() || fact.Cause != cause || fact.Effect != effect {
		t.Fatalf("safe failure differs: operation=%s stage=%s cause=%s effect=%s attempt=%d valid=%t want_cause=%s want_effect=%s", fact.Operation, fact.Stage, fact.Cause, fact.Effect, fact.Attempt, fact.Validate(), cause, effect)
	}
	encoded, marshalErr := json.Marshal(failure.facts)
	if marshalErr != nil || strings.Contains(string(encoded), "synthetic") || strings.Contains(string(encoded), "fixture-output") || strings.Contains(failure.Error(), "private") {
		t.Fatal("private fixture data escaped failure")
	}
	return failure
}

// full_only: false
func TestGCPOutputConstructionIsLazyAndCopiesInputs(t *testing.T) {
	spec := liveCloudOutputSpec{Location: liveOutputLocation{Provider: "gcp", ProjectNumber: "123", SecretNamePrefix: "projects/123/secrets/fixture-"},
		Writer:    &liveOutputActor{CredentialsFile: "/absent/writer", ServiceAccount: "writer@fixture-project.iam.gserviceaccount.com"},
		ConsumerA: &liveOutputActor{CredentialsFile: "/absent/a", ServiceAccount: "a@fixture-project.iam.gserviceaccount.com", Principal: "serviceAccount:a@fixture-project.iam.gserviceaccount.com"},
		ConsumerB: &liveOutputActor{CredentialsFile: "/absent/b", ServiceAccount: "b@fixture-project.iam.gserviceaccount.com", Principal: "serviceAccount:b@fixture-project.iam.gserviceaccount.com"},
		Budget:    &runBudget{}}
	calls := 0
	if _, err := newLiveCloudOutput(spec); err != nil || spec.Budget.snapshot() != (budgetReservation{}) {
		t.Fatal("default construction opened credentials or spent requests", err)
	}
	s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("private sentinel") }))
	if err != nil || calls != 0 || spec.Budget.snapshot() != (budgetReservation{}) {
		t.Fatal("construction touched credentials or transport", err)
	}
	spec.Writer.CredentialsFile = "/changed"
	spec.ConsumerA.ServiceAccount = "changed"
	if s.actors[0].actor.CredentialsFile != "/absent/writer" || s.actors[2].actor.ServiceAccount != "a@fixture-project.iam.gserviceaccount.com" {
		t.Fatal("retained borrowed actor")
	}
	for _, change := range []string{"provider", "project", "prefix", "consumer-principal", "actor-alias", "cleanup-mixed"} {
		t.Run(change, func(t *testing.T) {
			copySpec := s.spec
			writer, a, b := s.actors[0].actor, s.actors[2].actor, s.actors[3].actor
			copySpec.Writer, copySpec.ConsumerA, copySpec.ConsumerB = &writer, &a, &b
			switch change {
			case "provider":
				copySpec.Location.Provider = "aws"
			case "project":
				copySpec.Location.ProjectNumber = "0123"
			case "prefix":
				copySpec.Location.SecretNamePrefix = "projects/456/secrets/fixture-"
			case "consumer-principal":
				a.Principal = "serviceAccount:other@fixture-project.iam.gserviceaccount.com"
			case "actor-alias":
				a.CredentialsFile = writer.CredentialsFile
			case "cleanup-mixed":
				copySpec.Cleaner = &writer
			}
			_, err := newGCPCloudOutput(copySpec, s.base)
			gcpOutputAssertFailure(t, err, "invalid_request", "no_send")
		})
	}
}

// full_only: false
func TestGCPOutputWriterUsesOneSnapshotAndExactDeadline(t *testing.T) {
	spec, route := gcpOutputSyntheticSpec(t, false)
	calls := 0
	s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "secretmanager.googleapis.com" {
			name := spec.Location.SecretNamePrefix + "entry"
			if r.URL.Path != "/v1/"+name+"/versions/latest:access" {
				t.Fatal("cached consumer target differs")
			}
			return gcpSetupReply(200, `{"name":"`+name+`/versions/7","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`), nil
		}
		calls++
		if r.Method != "POST" || r.URL.String() != "https://oauth2.googleapis.com/token" || r.GetBody != nil {
			t.Fatal("OAuth route changed")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), "assertion=") || !strings.Contains(string(body), "grant_type=") {
			t.Fatal("OAuth request malformed")
		}
		return gcpOutputTokenReply(), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	facts, err := s.PrepareWriter(t.Context(), route, deadline)
	if err != nil || facts.Principal != "serviceAccount:writer@fixture-project.iam.gserviceaccount.com" || !facts.Expires.After(deadline) || calls != 3 {
		t.Fatal("same-source writer facts differ", facts, err, calls)
	}
	body, err := os.ReadFile(route.Path)
	want, sourceErr := os.ReadFile(spec.Writer.CredentialsFile)
	if err != nil || sourceErr != nil || !bytes.Equal(body, want) {
		t.Fatal("native ADC source snapshot differs")
	}
	clear(want)
	clear(body)
	info, err := os.Lstat(route.Path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("native bearer permissions differ")
	}
	if err := os.Remove(spec.Writer.CredentialsFile); err != nil {
		t.Fatal(err)
	}
	again, err := s.PrepareWriter(t.Context(), route, deadline)
	if err != nil || again != facts || calls != 3 {
		t.Fatal("active preparation reread or refreshed source", err)
	}
	_, err = s.PrepareWriter(t.Context(), route, facts.Expires)
	gcpOutputAssertFailure(t, err, "authentication_refused", "no_send")
	other := route
	other.ID[0]++
	_, err = s.PrepareWriter(t.Context(), other, deadline)
	gcpOutputAssertFailure(t, err, "ownership_mismatch", "no_send")
	if calls != 3 || spec.Budget.snapshot() != (budgetReservation{Requests: 3, BodyBytes: 3 * operationBodyAllowance}) {
		t.Fatal("cached refusal spent requests")
	}
	for i, actor := range []*liveOutputActor{spec.ConsumerA, spec.ConsumerB} {
		if err := os.Remove(actor.CredentialsFile); err != nil {
			t.Fatal(err)
		}
		result, err := s.ReadConsumer(t.Context(), liveOutputConsumer(i+1), spec.Location.SecretNamePrefix+"entry/versions/latest", 9)
		if err != nil || result.AccessRefused || !bytes.Equal(result.Bytes, []byte("123456789")) {
			t.Fatal("prepared consumer reread/refreshed source", err)
		}
		clear(result.Bytes)
	}
	if calls != 3 || spec.Budget.snapshot().Requests != 5 {
		t.Fatal("prepared consumers minted new tokens")
	}
}

// full_only: false
func TestGCPOutputWriterRefusalsPrecedeNativeFile(t *testing.T) {
	for _, change := range []string{"budget", "email", "permissions", "symlink", "bad-bearer", "short-expiry", "existing-route", "zero-route", "actor-route", "consumer-a-email", "consumer-b-permissions"} {
		t.Run(change, func(t *testing.T) {
			spec, route := gcpOutputSyntheticSpec(t, false)
			wantCause, wantCalls := "authentication_refused", 0
			var tokenReply = `{"access_token":"synthetic-bearer","token_type":"Bearer","expires_in":3600}`
			switch change {
			case "budget":
				spec.Budget.limits.Requests = 0
				wantCause = "budget_exhausted"
			case "email":
				spec.Writer.ServiceAccount = "wrong@fixture-project.iam.gserviceaccount.com"
				wantCause = "ownership_mismatch"
			case "permissions":
				if err := os.Chmod(spec.Writer.CredentialsFile, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := spec.Writer.CredentialsFile
				spec.Writer.CredentialsFile += "-alias"
				if err := os.Symlink(path, spec.Writer.CredentialsFile); err != nil {
					t.Fatal(err)
				}
			case "bad-bearer":
				tokenReply = `{"access_token":"bad:bearer","token_type":"Bearer","expires_in":3600}`
				wantCalls = 1
			case "short-expiry":
				tokenReply = `{"access_token":"synthetic-bearer","token_type":"Bearer","expires_in":1}`
				wantCalls = 1
			case "existing-route":
				if err := os.WriteFile(route.Path, []byte("existing-private"), 0600); err != nil {
					t.Fatal(err)
				}
				wantCause, wantCalls = "persistence_failed", 3
			case "zero-route":
				route.ID = protocol.ID{}
				wantCause = "invalid_request"
			case "actor-route":
				route.Path = spec.ConsumerA.CredentialsFile
				wantCause = "ownership_mismatch"
			case "consumer-a-email":
				spec.ConsumerA.ServiceAccount = "wrong@fixture-project.iam.gserviceaccount.com"
				spec.ConsumerA.Principal = "serviceAccount:" + spec.ConsumerA.ServiceAccount
				wantCause, wantCalls = "ownership_mismatch", 1
			case "consumer-b-permissions":
				if err := os.Chmod(spec.ConsumerB.CredentialsFile, 0644); err != nil {
					t.Fatal(err)
				}
				wantCalls = 2
			}
			calls := 0
			s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return gcpSetupReply(200, tokenReply), nil }))
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute))
			gcpOutputAssertFailure(t, err, wantCause, "no_send")
			if calls != wantCalls {
				t.Fatalf("physical calls=%d want=%d", calls, wantCalls)
			}
			if change == "existing-route" {
				body, err := os.ReadFile(route.Path)
				if err != nil || string(body) != "existing-private" {
					t.Fatal("existing active file rewritten")
				}
			}
			if change != "existing-route" && change != "actor-route" {
				if _, err := os.Lstat(route.Path); !os.IsNotExist(err) {
					t.Fatal("refusal installed a native route")
				}
			}
		})
	}
}

// full_only: false
func TestGCPOutputConsumersKeepSourcesAndCheckCompletePayload(t *testing.T) {
	spec, _ := gcpOutputSyntheticSpec(t, false)
	name := spec.Location.SecretNamePrefix + "entry"
	oauth, reads := 0, 0
	s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth2.googleapis.com" {
			oauth++
			return gcpOutputTokenReply(), nil
		}
		reads++
		if r.Method != "GET" || r.URL.String() != "https://secretmanager.googleapis.com/v1/"+name+"/versions/latest:access" || r.Header.Get("Authorization") != "Bearer synthetic-bearer" {
			t.Fatal("consumer request differs")
		}
		if reads == 2 || reads == 4 {
			return gcpSetupReply(403, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`), nil
		}
		if reads == 7 {
			// Fixed independent CRC32C test vector: ASCII abc -> 0x364b3fb7.
			return gcpSetupReply(200, `{"name":"`+name+`/versions/8","payload":{"data":"YWJj","dataCrc32c":"910901175"}}`), nil
		}
		// Fixed independent CRC32C test vector: ASCII 123456789 -> 0xe3069283.
		return gcpSetupReply(200, `{"name":"`+name+`/versions/7","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ReadConsumer(t.Context(), liveOutputConsumerA, name+"/versions/latest", 9)
	if err != nil || first.HTTPStatus != 200 || first.AccessRefused || !bytes.Equal(first.Bytes, []byte("123456789")) {
		t.Fatal("prior complete access differs", err)
	}
	clear(first.Bytes)
	if err := os.Remove(spec.ConsumerA.CredentialsFile); err != nil {
		t.Fatal(err)
	}
	removed, err := s.ReadConsumer(t.Context(), liveOutputConsumerA, name+"/versions/latest", 9)
	if err != nil || removed.HTTPStatus != 403 || !removed.AccessRefused || removed.Bytes != nil {
		t.Fatal("real denied access differs", err)
	}
	retained, err := s.ReadConsumer(t.Context(), liveOutputConsumerB, name+"/versions/latest", 9)
	if err != nil || retained.HTTPStatus != 200 || retained.AccessRefused || !bytes.Equal(retained.Bytes, []byte("123456789")) {
		t.Fatal("retained complete access differs", err)
	}
	clear(retained.Bytes)
	for i := 4; i <= 7; i++ {
		actor := liveOutputConsumerA
		if i == 5 {
			actor = liveOutputConsumerB
		}
		read, err := s.ReadConsumer(t.Context(), actor, name+"/versions/latest", 9)
		denied := i == 4
		status := 200
		if denied {
			status = 403
		}
		expected := []byte("123456789")
		if i == 7 {
			expected = []byte("abc")
		}
		matches := bytes.Equal(read.Bytes, expected)
		clear(read.Bytes)
		if err != nil || read.HTTPStatus != status || read.AccessRefused != denied || denied && len(read.Bytes) != 0 || !denied && !matches || reads != i {
			t.Fatal("delayed grant, revocation or value observation changed one request", err)
		}
	}
	if oauth != 2 || reads != 7 || spec.Budget.snapshot().Requests != 9 {
		t.Fatal("consumer refresh or physical accounting differs", oauth, reads)
	}

}

// full_only: false
func TestGCPOutputConsumerRejectsNonAccessEvidence(t *testing.T) {
	spec, _ := gcpOutputSyntheticSpec(t, false)
	name := spec.Location.SecretNamePrefix + "entry"
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthenticated", 401, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`},
		{"absent", 404, `{"error":{"code":404,"status":"NOT_FOUND"}}`},
		{"wrong-code", 403, `{"error":{"code":401,"status":"PERMISSION_DENIED"}}`},
		{"wrong-status", 403, `{"error":{"code":403,"status":"UNAUTHENTICATED"}}`},
		{"malformed", 403, `private-malformed-sentinel`},
		{"error-root-null", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED"},"error":null}`},
		{"error-status-null", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED","status":null}}`},
		{"error-status-alias", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED","Status":null}}`},
		{"error-status-unicode-alias", 403, `{"error":{"code":403,"status":"PERMISSION_DENIED","ſtatus":null}}`},
		{"error-code-duplicate", 403, `{"error":{"code":401,"code":403,"status":"PERMISSION_DENIED"}}`},
		{"version-name-null", 200, `{"name":"` + name + `/versions/7","name":null,"payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"version-name-duplicate", 200, `{"name":"` + name + `/versions/8","name":"` + name + `/versions/7","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"version-name-alias", 200, `{"name":"` + name + `/versions/7","Name":null,"payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"payload-duplicate", 200, `{"name":"` + name + `/versions/7","payload":{"data":"","dataCrc32c":"0"},"payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"payload-data-duplicate", 200, `{"name":"` + name + `/versions/7","payload":{"data":"","data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"payload-data-alias", 200, `{"name":"` + name + `/versions/7","payload":{"data":"","Data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"payload-crc-duplicate", 200, `{"name":"` + name + `/versions/7","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"0","dataCrc32c":"3808858755"}}`},
		{"payload-crc-alias", 200, `{"name":"` + name + `/versions/7","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"0","DataCrc32c":"3808858755"}}`},
		{"latest-alias", 200, `{"name":"` + name + `/versions/latest","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"other-secret", 200, `{"name":"` + name + `-other/versions/7","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"3808858755"}}`},
		{"crc-mismatch", 200, `{"name":"` + name + `/versions/7","payload":{"data":"MTIzNDU2Nzg5","dataCrc32c":"0"}}`},
		{"crc-absent", 200, `{"name":"` + name + `/versions/7","payload":{"data":""}}`},
		{"crc-noncanonical", 200, `{"name":"` + name + `/versions/7","payload":{"data":"","dataCrc32c":"00"}}`},
		{"crc-overflow", 200, `{"name":"` + name + `/versions/7","payload":{"data":"","dataCrc32c":"4294967296"}}`},
		{"oversize-decoded", 200, `{"name":"` + name + `/versions/7","payload":{"data":"MTIzNDU2Nzg5MA==","dataCrc32c":"0"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			caseSpec := spec
			caseSpec.Budget = &runBudget{limits: spec.Budget.limits}
			s, err := newGCPCloudOutput(caseSpec, gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "oauth2.googleapis.com" {
					return gcpOutputTokenReply(), nil
				}
				return gcpSetupReply(test.status, test.body), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.ReadConsumer(t.Context(), liveOutputConsumerA, name+"/versions/latest", 9)
			cause := "provider_refused"
			if test.status == 200 {
				cause = "malformed_envelope"
			}
			gcpOutputAssertFailure(t, err, cause, "no_effect")
			if result.HTTPStatus != test.status || result.AccessRefused || result.Bytes != nil {
				t.Fatal("bad evidence became access refusal/value")
			}
		})
	}
}

// full_only: false
func TestGCPOutputAliasesAndExpiredConsumersRefuseBeforeSend(t *testing.T) {
	spec, route := gcpOutputSyntheticSpec(t, false)
	if err := os.Remove(spec.ConsumerA.CredentialsFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(spec.Writer.CredentialsFile, spec.ConsumerA.CredentialsFile); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return gcpOutputTokenReply(), nil }))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute))
	gcpOutputAssertFailure(t, err, "ownership_mismatch", "no_send")
	if calls != 1 {
		t.Fatal("hardlinked source entered OAuth")
	}
	if _, err := os.Lstat(route.Path); !os.IsNotExist(err) {
		t.Fatal("unqualified consumers installed writer route")
	}
	s.actors[2].token, s.actors[2].facts.Expires = "synthetic-bearer", time.Now().Add(time.Second)
	_, err = s.ReadConsumer(t.Context(), liveOutputConsumerA, spec.Location.SecretNamePrefix+"entry/versions/latest", 9)
	gcpOutputAssertFailure(t, err, "authentication_refused", "no_send")
	if calls != 1 {
		t.Fatal("expired snapshot refreshed")
	}
}

// full_only: false
func TestGCPOutputCleanupUsesExactEtagAndOneDelete(t *testing.T) {
	for _, outcome := range []string{"acknowledged", "absent", "unknown", "wrong-name", "empty-etag", "etag-overflow", "malformed-404", "same-principal", "budget", "metadata-extras", "name-duplicate", "name-alias", "name-null", "etag-duplicate", "etag-alias", "etag-null", "error-root-null", "error-status-null", "error-status-alias", "error-code-duplicate", "metadata-invalid-utf8", "metadata-trailing", "name-alias-only"} {
		t.Run(outcome, func(t *testing.T) {
			spec, _ := gcpOutputSyntheticSpec(t, true)
			name := spec.Location.SecretNamePrefix + "entry"
			if outcome == "same-principal" {
				spec.OtherActorPrincipals[0] = "serviceAccount:" + spec.Cleaner.ServiceAccount
			}
			if outcome == "budget" {
				spec.Budget.limits.Requests = 2
			}
			oauth, reads, deletes := 0, 0, 0
			s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "oauth2.googleapis.com" {
					oauth++
					return gcpOutputTokenReply(), nil
				}
				if r.URL.Path != "/v1/"+name || r.Header.Get("Authorization") != "Bearer synthetic-bearer" {
					t.Fatal("cleanup target/credential differs")
				}
				if r.Method == "GET" {
					reads++
					if r.URL.RawQuery != "" {
						t.Fatal("metadata query differs")
					}
					switch outcome {
					case "absent":
						return gcpSetupReply(404, `{"error":{"code":404,"status":"NOT_FOUND","message":"controlled absence","details":[]}}`), nil
					case "malformed-404":
						return gcpSetupReply(404, `private-sentinel`), nil
					case "wrong-name":
						return gcpSetupReply(200, `{"name":"`+name+`-other","etag":"etag"}`), nil
					case "empty-etag":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":""}`), nil
					case "etag-overflow":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":"`+strings.Repeat("e", 1025)+`"}`), nil
					case "metadata-extras":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":"\"etag/+\"","replication":{"automatic":{}},"labels":{"fixture":"controlled"},"createTime":"2026-10-05T00:00:00Z"}`), nil
					case "metadata-invalid-utf8":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":"\"etag/+\"","label":"`+string([]byte{0xff})+`"}`), nil
					case "metadata-trailing":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":"\"etag/+\""} {}`), nil
					case "name-alias-only":
						return gcpSetupReply(200, `{"Name":"`+name+`","etag":"\"etag/+\""}`), nil
					case "name-duplicate":
						return gcpSetupReply(200, `{"name":"foreign","name":"`+name+`","etag":"\"etag/+\""}`), nil
					case "name-alias":
						return gcpSetupReply(200, `{"name":"`+name+`","Name":null,"etag":"\"etag/+\""}`), nil
					case "name-null":
						return gcpSetupReply(200, `{"name":"`+name+`","name":null,"etag":"\"etag/+\""}`), nil
					case "etag-duplicate":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":"other","etag":"\"etag/+\""}`), nil
					case "etag-alias":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":"\"etag/+\"","Etag":null}`), nil
					case "etag-null":
						return gcpSetupReply(200, `{"name":"`+name+`","etag":"\"etag/+\"","etag":null}`), nil
					case "error-root-null":
						return gcpSetupReply(404, `{"error":{"code":404,"status":"NOT_FOUND"},"error":null}`), nil
					case "error-status-null":
						return gcpSetupReply(404, `{"error":{"code":404,"status":"NOT_FOUND","status":null}}`), nil
					case "error-status-alias":
						return gcpSetupReply(404, `{"error":{"code":404,"status":"NOT_FOUND","Status":null}}`), nil
					case "error-code-duplicate":
						return gcpSetupReply(404, `{"error":{"code":403,"code":404,"status":"NOT_FOUND"}}`), nil
					}
					return gcpSetupReply(200, `{"name":"`+name+`","etag":"\"etag/+\""}`), nil
				}
				deletes++
				if r.Method != "DELETE" || r.URL.Query().Get("etag") != `"etag/+"` || len(r.URL.Query()) != 1 || r.Body != nil {
					t.Fatal("conditional delete differs")
				}
				if outcome == "unknown" {
					return nil, errors.New("private-lost-reply")
				}
				return gcpSetupReply(200, `{}`), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			// Mutating the borrowed slice must not change the cleaner's exclusion set.
			spec.OtherActorPrincipals[0] = "serviceAccount:changed@fixture-project.iam.gserviceaccount.com"
			target := liveOutputCleanupTarget{Index: 7, PlannedSlot: name, CreateAttempt: contract.ID{2}}
			if outcome == "acknowledged" {
				target.OwnedInstance = name
			}
			result, err := s.DeleteFixture(t.Context(), target)
			switch outcome {
			case "acknowledged", "metadata-extras", "absent":
				want := liveOutputDeleteAcknowledged
				if outcome == "absent" {
					want = liveOutputAbsent
				}
				if err != nil || result != (liveOutputCleanupResult{Disposition: want, ResolvedInstance: name}) {
					t.Fatal("exact cleanup disposition differs", result, err)
				}
			case "same-principal":
				gcpOutputAssertFailure(t, err, "ownership_mismatch", "no_send")
				if oauth != 0 || reads != 0 {
					t.Fatal("same cleaner principal sent")
				}
			case "budget":
				gcpOutputAssertFailure(t, err, "budget_exhausted", "no_send")
			case "unknown":
				failure := gcpOutputAssertFailure(t, err, "transport", "unknown")
				if failure.facts.Attempt != 1 || failure.facts.Operation != "output_cleanup" || failure.facts.TargetKind != "output_inventory" || *failure.facts.TargetIndex != 7 {
					t.Fatal("unknown lost exact inventory facts")
				}
			default:
				gcpOutputAssertFailure(t, err, "ownership_mismatch", "no_effect")
			}
			if err != nil && result != (liveOutputCleanupResult{}) {
				t.Fatal("failed cleanup became resolved")
			}
			if outcome == "acknowledged" || outcome == "metadata-extras" || outcome == "unknown" {
				_, err = s.DeleteFixture(t.Context(), target)
				gcpOutputAssertFailure(t, err, "invalid_request", "no_send")
				if deletes != 1 || reads != 1 || oauth != 1 {
					t.Fatal("entered delete replayed")
				}
			} else if deletes != 0 {
				t.Fatal("unqualified cleanup deleted")
			}
		})
	}
}

// full_only: false
func TestGCPOutputCleanupLocalTargetRefusals(t *testing.T) {
	spec, _ := gcpOutputSyntheticSpec(t, true)
	calls := 0
	s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []liveOutputCleanupTarget{
		{PlannedSlot: spec.Location.SecretNamePrefix + "entry"},
		{PlannedSlot: "projects/999/secrets/fixture-output-positive-entry", CreateAttempt: contract.ID{1}},
		{PlannedSlot: spec.Location.SecretNamePrefix + "entry", OwnedInstance: spec.Location.SecretNamePrefix + "other", CreateAttempt: contract.ID{1}},
	} {
		_, err := s.DeleteFixture(t.Context(), target)
		gcpOutputAssertFailure(t, err, "invalid_request", "no_send")
	}
	if calls != 0 {
		t.Fatal("invalid cleanup used credential/transport")
	}
}

// full_only: false
func TestGCPOutputTransportBoundsAndReservations(t *testing.T) {
	for _, condition := range []string{"budget", "body-overflow", "early-eof", "compressed", "transport", "nil-body"} {
		t.Run(condition, func(t *testing.T) {
			budget := &runBudget{limits: liveLimits{Requests: 1, BodyBytes: operationBodyAllowance}}
			if condition == "budget" {
				budget.limits.BodyBytes--
			}
			calls := 0
			transport := &gcpOutputTransport{budget: budget, base: gcpSetupRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				if budget.snapshot().Requests != 1 {
					t.Fatal("sent before reservation")
				}
				reply := gcpSetupReply(200, `{}`)
				switch condition {
				case "body-overflow":
					reply = gcpSetupReply(200, strings.Repeat("x", gcpOutputResponseLimit+1))
				case "early-eof":
					reply.ContentLength++
				case "compressed":
					reply.Header.Set("Content-Encoding", "gzip")
				case "transport":
					return nil, errors.New("private-sentinel")
				case "nil-body":
					reply.Body = nil
				}
				return reply, nil
			})}
			request, err := http.NewRequestWithContext(t.Context(), "GET", "https://secretmanager.googleapis.com/v1/projects/123/secrets/fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = transport.RoundTrip(request)
			cause, effect := "invalid_length", "no_effect"
			if condition == "budget" {
				cause, effect = "budget_exhausted", "no_send"
			} else if condition == "transport" {
				cause = "transport"
			} else if condition == "nil-body" {
				cause = "missing_response"
			}
			gcpOutputAssertFailure(t, err, cause, effect)
			wantCalls := 1
			if condition == "budget" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatal("physical call accounting differs")
			}
		})
	}
}

// full_only: false
func TestGCPOutputOAuthWaitsForBodyClose(t *testing.T) {
	for _, name := range []string{"complete", "cancelled", "cancelled-without-telemetry"} {
		cancelled := name != "complete"
		t.Run(name, func(t *testing.T) {
			collector := liveTelemetry(t)
			started, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
			budget := &runBudget{limits: liveLimits{Requests: 1, BodyBytes: operationBodyAllowance}}
			body := make(chan *setupRequestBody, 1)
			base := gcpOutputAsyncTransport{started: started, release: release, joined: joined, body: body}
			var releaseOnce sync.Once
			releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
			defer func() {
				releaseWorker()
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("OAuth body worker cleanup was not joined")
				}
			}()
			transport := &gcpOutputTransport{base: base, budget: budget, oauth: true}
			callCtx := collector.Context
			if name == "cancelled-without-telemetry" {
				callCtx = context.Background()
			}
			ctx, cancel := context.WithTimeout(callCtx, time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader("synthetic=assertion"))
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				response, err := transport.RoundTrip(request)
				if response != nil {
					_ = response.Body.Close()
				}
				returned <- err
			}()
			select {
			case <-started:
			case err := <-returned:
				t.Fatalf("OAuth did not start: %v", err)
			case <-time.After(time.Second):
				t.Fatal("OAuth start was not joined")
			}
			waitReturned := func() error {
				select {
				case err := <-returned:
					return err
				case <-time.After(time.Second):
					t.Fatal("OAuth call was not joined")
					return nil
				}
			}
			waitJoined := func() {
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Fatal("OAuth body worker was not joined")
				}
			}
			if cancelled {
				cancel()
				err := waitReturned()
				owned := <-body
				owned.mu.Lock()
				closed := owned.closed
				reads := owned.reads
				owned.mu.Unlock()
				select {
				case <-owned.done:
				default:
					t.Error("caller returned before owned body completion")
				}
				if !closed || reads != 0 {
					t.Errorf("caller returned with owned body closed=%v reads=%d", closed, reads)
				}
				if name == "cancelled-without-telemetry" {
					copy := owned.ReadCloser.(*gcpOutputBody)
					copy.mu.Lock()
					cleared := copy.closed && bytes.Equal(copy.bytes, make([]byte, len("synthetic=assertion")))
					copy.mu.Unlock()
					if !cleared {
						t.Error("caller returned before copied assertion was closed and cleared")
					}
				}
				releaseWorker()
				gcpOutputAssertFailure(t, err, "cancelled", "no_effect")
			} else {
				select {
				case <-returned:
					releaseWorker()
					waitJoined()
					t.Fatal("returned before request body close")
				case <-time.After(20 * time.Millisecond):
				}
				releaseWorker()
				if err := waitReturned(); err != nil {
					t.Fatal(err)
				}
			}
			waitJoined()
			if budget.snapshot().Requests != 1 {
				t.Fatal("body join changed physical reservation")
			}
			if name == "cancelled-without-telemetry" {
				return
			}
			metrics := liveTelemetrySnapshot(t, collector)
			if cancelled {
				if liveMetricSum(metrics, telemetry.HTTPResults, "authentication", "failure", "") != 1 || liveMetricSum(metrics, telemetry.HTTPRequestBodyObservations, "authentication", "", "incomplete") != 1 {
					t.Fatal("cancelled body telemetry differs")
				}
			} else if liveMetricSum(metrics, telemetry.HTTPRequestBodyBytes, "authentication", "", "complete") != uint64(len("synthetic=assertion")) || liveMetricSum(metrics, telemetry.HTTPResults, "authentication", "success", "") != 1 {
				t.Fatal("completed body telemetry differs")
			}
		})
	}
}

type gcpOutputAsyncTransport struct {
	started, release, joined chan struct{}
	body                     chan *setupRequestBody
}

func (d gcpOutputAsyncTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	go func() {
		d.body <- r.Body.(*setupRequestBody)
		close(d.started)
		<-d.release
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		close(d.joined)
	}()
	return gcpOutputTokenReply(), nil
}

// full_only: false
func TestGCPOutputConsumerEmptyPayloadRequiresPresentZeroChecksum(t *testing.T) {
	spec, _ := gcpOutputSyntheticSpec(t, false)
	name := spec.Location.SecretNamePrefix + "empty"
	s, err := newGCPCloudOutput(spec, gcpSetupRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth2.googleapis.com" {
			return gcpOutputTokenReply(), nil
		}
		return gcpSetupReply(200, `{"name":"`+name+`/versions/1","payload":{"data":"","dataCrc32c":"0"}}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.ReadConsumer(t.Context(), liveOutputConsumerA, name+"/versions/latest", 1)
	if err != nil || result.AccessRefused || len(result.Bytes) != 0 {
		t.Fatal("present zero CRC empty payload differs", err)
	}
	clear(result.Bytes)
}
