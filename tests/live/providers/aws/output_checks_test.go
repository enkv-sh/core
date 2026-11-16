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
	"testing"
	"time"

	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/output"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type awsOutputTestTransport func(*http.Request) (*http.Response, error)

func (f awsOutputTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func awsOutputTestSpec(t *testing.T, cleaner bool) liveCloudOutputSpec {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		awsOutputTestFatal(t, err)
	}
	spec := liveCloudOutputSpec{Location: liveOutputLocation{Provider: "aws", Region: "ap-southeast-2", Account: "123456789012", SecretNamePrefix: "fixture-output-positive-"}, Budget: &runBudget{limits: liveLimits{Requests: 100, BodyBytes: 100 * (awsOutputRequestLimit + awsOutputReplyLimit)}, keys: map[string]bool{}}}
	actor := func(name, key, principal string) *liveOutputActor {
		path := filepath.Join(directory, name)
		body := "[selected]\naws_access_key_id = " + key + "\naws_secret_access_key = FIXEDTESTSECRET\n"
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			awsOutputTestFatal(t, err)
		}
		return &liveOutputActor{CredentialsFile: path, Profile: "selected", Principal: principal}
	}
	a, b := "arn:aws:iam::123456789012:user/consumer-a", "arn:aws:iam::123456789012:user/consumer-b"
	if cleaner {
		spec.Cleaner = actor("cleaner.ini", "AKIACLEANER0000000000", "")
		spec.OtherActorPrincipals = []string{"arn:aws:iam::123456789012:user/writer", a, b}
	} else {
		spec.Writer = actor("writer.ini", "AKIAWRITER00000000000", "")
		spec.ConsumerA = actor("consumer-a.ini", "AKIACONSUMERA00000000", a)
		spec.ConsumerB = actor("consumer-b.ini", "AKIACONSUMERB00000000", b)
	}
	return spec
}
func awsOutputTestOpen(t *testing.T, spec liveCloudOutputSpec, handler func(*http.Request, string) (int, string, error)) *awsLiveOutput {
	t.Helper()
	value, err := newLiveCloudOutput(spec)
	if err != nil {
		awsOutputTestFatal(t, err)
	}
	s := value.(*awsLiveOutput)
	s.transport = awsOutputTestTransport(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		closeErr := r.Body.Close()
		if err != nil || closeErr != nil {
			t.Fatal("controlled request close", err, closeErr)
		}
		if r.URL.Scheme != "https" || r.URL.Path != "/" || r.URL.RawQuery != "" || r.GetBody != nil || r.Header.Get("Authorization") == "" {
			t.Fatal("physical request changed fixed routing or body ownership")
		}
		status, response, err := handler(r, string(body))
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response)), ContentLength: int64(len(response)), Request: r}, nil
	})
	return s
}
func awsOutputTestIdentity(t *testing.T, r *http.Request, body string) (int, string, error) {
	t.Helper()
	if r.URL.Host != "sts.ap-southeast-2.amazonaws.com" || body != "Action=GetCallerIdentity&Version=2011-06-15" {
		t.Fatal("identity request changed fixed regional action")
	}
	authorization := r.Header.Get("Authorization")
	name := ""
	for key, user := range map[string]string{"AKIAWRITER00000000000": "writer", "AKIACONSUMERA00000000": "consumer-a", "AKIACONSUMERB00000000": "consumer-b", "AKIACLEANER0000000000": "cleaner"} {
		if strings.Contains(authorization, "Credential="+key+"/") {
			name = user
		}
	}
	if name == "" {
		t.Fatal("unexpected controlled captured credential")
	}
	return 200, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/` + name + `</Arn><UserId>TEST` + name + `</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>controlled</RequestId></ResponseMetadata></GetCallerIdentityResponse>`, nil
}
func awsOutputTestRoute(t *testing.T) liveOutputCredentialRoute {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		awsOutputTestFatal(t, err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		awsOutputTestFatal(t, err)
	}
	return liveOutputCredentialRoute{Path: filepath.Join(directory, "native-route"), ID: protocol.ID(contract.Hash([]byte("controlled output credential route")))}
}
func awsOutputTestARN(s *awsLiveOutput) string {
	return "arn:aws:secretsmanager:" + s.location.Region + ":" + s.location.Account + ":secret:" + s.location.SecretNamePrefix + "AABBCCDD_P-a1B2c3"
}
func awsOutputTestTarget(s *awsLiveOutput) liveOutputCleanupTarget {
	arn := awsOutputTestARN(s)
	return liveOutputCleanupTarget{Index: 4, PlannedSlot: arn[:len(arn)-7], OwnedInstance: arn, CreateAttempt: contract.Hash([]byte("independent fixture create attempt"))}
}
func awsOutputRequireFailure(t *testing.T, err error, operation, cause, effect string) {
	t.Helper()
	var failure *awsOutputFixtureFailure
	if !errors.As(err, &failure) {
		t.Fatal("missing safe output failure")
	}
	f := failure.SafeHarnessFailure()
	if f.Operation != operation || f.Cause != cause || f.Effect != effect || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("safe failure facts operation=%s cause=%s effect=%s", f.Operation, f.Cause, f.Effect)
	}
	if !f.Validate() {
		t.Fatal("invalid closed failure facts")
	}
}

func awsOutputTestFatal(t *testing.T, err error) {
	t.Helper()
	var failure *awsOutputFixtureFailure
	if errors.As(err, &failure) {
		status := uint16(0)
		if failure.fact.HTTPStatus != nil {
			status = *failure.fact.HTTPStatus
		}
		t.Fatalf("fixture failure operation=%s stage=%s cause=%s effect=%s attempt=%d status=%d", failure.fact.Operation, failure.fact.Stage, failure.fact.Cause, failure.fact.Effect, failure.fact.Attempt, status)
	}
	t.Fatal(err)
}

// full_only: false
func TestAWSOutputFixtureConstructionAndPreparation(t *testing.T) {
	t.Run("lazy-copy-and-one-write", func(t *testing.T) {
		spec := awsOutputTestSpec(t, false)
		calls := 0
		s := awsOutputTestOpen(t, spec, func(r *http.Request, body string) (int, string, error) {
			calls++
			return awsOutputTestIdentity(t, r, body)
		})
		spec.Writer.CredentialsFile = "/missing-mutated"
		spec.ConsumerA.Principal = "mutated"
		if calls != 0 || s.writer.identity != nil {
			t.Fatal("construction opened or requested credentials")
		}
		route := awsOutputTestRoute(t)
		deadline := time.Now().Add(time.Minute)
		facts, err := s.PrepareWriter(t.Context(), route, deadline)
		if err != nil {
			awsOutputTestFatal(t, err)
		}
		// BE-u16 version 1, zero BE-u64 expiry, then BE-u16 lengths 21, 15, 0.
		// These fixed bytes are independent of the credential encoder.
		want := append([]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21}, []byte("AKIAWRITER00000000000")...)
		want = append(want, 0, 15)
		want = append(want, []byte("FIXEDTESTSECRET")...)
		want = append(want, 0, 0)
		got, err := os.ReadFile(route.Path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("native route did not contain the complete versioned credential snapshot")
		}
		clear(got)
		if facts.Principal != "arn:aws:iam::123456789012:user/writer" || !facts.Expires.IsZero() || calls != 3 {
			t.Fatal("actual identity/static expiry or physical identity request count differs")
		}
		info, err := os.Stat(route.Path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("native route privacy differs")
		}
		if err := os.WriteFile(s.writer.selected.CredentialsFile, []byte("now-invalid"), 0600); err != nil {
			awsOutputTestFatal(t, err)
		}
		if again, err := s.PrepareWriter(t.Context(), route, deadline.Add(time.Hour)); err != nil || again != facts || calls != 3 {
			t.Fatal("static snapshot changed on repeated owner preparation")
		}
		if _, err := s.PrepareWriter(t.Context(), awsOutputTestRoute(t), deadline); err == nil || calls != 3 {
			t.Fatal("active route was rewritten")
		}
	})
	t.Run("invalid-public-fields-zero-work", func(t *testing.T) {
		mutations := []func(*liveCloudOutputSpec){func(s *liveCloudOutputSpec) { s.Location.Account = "000" }, func(s *liveCloudOutputSpec) { s.Location.Region = "not-a-region" }, func(s *liveCloudOutputSpec) { s.Location.ProjectNumber = "other" }, func(s *liveCloudOutputSpec) { s.ConsumerB.Principal = s.ConsumerA.Principal }, func(s *liveCloudOutputSpec) { s.ConsumerB.CredentialsFile = s.ConsumerA.CredentialsFile }, func(s *liveCloudOutputSpec) { s.Cleaner = &liveOutputActor{} }, func(s *liveCloudOutputSpec) { s.Budget = nil }}
		for i, mutate := range mutations {
			spec := awsOutputTestSpec(t, false)
			mutate(&spec)
			if _, err := newLiveCloudOutput(spec); err == nil {
				t.Fatalf("public invalid row %d admitted", i)
			}
		}
		spec := awsOutputTestSpec(t, false)
		spec.Writer.CredentialsFile = filepath.Join(t.TempDir(), "does-not-exist")
		s := awsOutputTestOpen(t, spec, func(*http.Request, string) (int, string, error) {
			t.Fatal("unexpected request before source refusal")
			return 0, "", nil
		})
		if _, err := s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(time.Minute)); err == nil {
			t.Fatal("missing source admitted")
		}
	})
	t.Run("same-file-alias-before-identity", func(t *testing.T) {
		spec := awsOutputTestSpec(t, false)
		if err := os.Remove(spec.ConsumerA.CredentialsFile); err != nil {
			awsOutputTestFatal(t, err)
		}
		if err := os.Link(spec.Writer.CredentialsFile, spec.ConsumerA.CredentialsFile); err != nil {
			awsOutputTestFatal(t, err)
		}
		s := awsOutputTestOpen(t, spec, func(*http.Request, string) (int, string, error) {
			t.Fatal("alias caused physical request")
			return 0, "", nil
		})
		_, err := s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(time.Minute))
		awsOutputRequireFailure(t, err, "setup_check", "authentication_refused", "no_send")
		if s.budget.snapshot().Requests != 0 {
			t.Fatal("alias consumed network budget")
		}
	})
	t.Run("native-field-bounds-before-any-identity", func(t *testing.T) {
		for _, actor := range []string{"writer", "consumer", "cleaner"} {
			t.Run(actor, func(t *testing.T) {
				spec := awsOutputTestSpec(t, actor == "cleaner")
				source := spec.Writer
				if actor == "consumer" {
					source = spec.ConsumerA
				}
				if actor == "cleaner" {
					source = spec.Cleaner
				}
				if err := os.WriteFile(source.CredentialsFile, []byte("[selected]\naws_access_key_id = lower-case-key-not-a-valid-native-key\naws_secret_access_key = FIXEDTESTSECRET\n"), 0600); err != nil {
					awsOutputTestFatal(t, err)
				}
				s := awsOutputTestOpen(t, spec, func(*http.Request, string) (int, string, error) {
					t.Fatal("invalid native credential field entered STS")
					return 0, "", nil
				})
				var err error
				if actor == "cleaner" {
					_, err = s.DeleteFixture(t.Context(), awsOutputTestTarget(s))
				} else {
					_, err = s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(time.Minute))
				}
				if err == nil || s.budget.snapshot().Requests != 0 {
					t.Fatal("invalid static field consumed network budget")
				}
			})
		}
	})
	t.Run("session-token-needs-expiry", func(t *testing.T) {
		spec := awsOutputTestSpec(t, false)
		file, err := os.OpenFile(spec.Writer.CredentialsFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			awsOutputTestFatal(t, err)
		}
		_, err = file.WriteString("aws_session_token = PRIVATESESSION\n")
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
		s := awsOutputTestOpen(t, spec, func(*http.Request, string) (int, string, error) {
			t.Fatal("session token caused identity request")
			return 0, "", nil
		})
		_, err = s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(time.Minute))
		awsOutputRequireFailure(t, err, "setup_check", "authentication_refused", "no_send")
	})
	t.Run("actual-account-and-consumer-and-role-identities", func(t *testing.T) {
		for _, condition := range []string{"account", "consumer", "duplicate"} {
			t.Run(condition, func(t *testing.T) {
				spec := awsOutputTestSpec(t, false)
				calls := 0
				s := awsOutputTestOpen(t, spec, func(r *http.Request, body string) (int, string, error) {
					calls++
					status, response, err := awsOutputTestIdentity(t, r, body)
					switch condition {
					case "account":
						response = strings.ReplaceAll(response, "123456789012", "999999999999")
					case "consumer":
						if calls == 2 {
							response = strings.ReplaceAll(response, "consumer-a", "wrong-consumer")
						}
					case "duplicate":
						if calls == 2 {
							response = strings.ReplaceAll(response, "consumer-a", "writer")
						}
					}
					return status, response, err
				})
				route := awsOutputTestRoute(t)
				if _, err := s.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute)); err == nil {
					t.Fatal("wrong actual identity admitted")
				}
				if _, err := os.Stat(route.Path); !os.IsNotExist(err) {
					t.Fatal("wrong identity wrote native route")
				}
			})
		}
	})
	t.Run("cancelled-before-source-capture", func(t *testing.T) {
		s := awsOutputTestOpen(t, awsOutputTestSpec(t, false), func(*http.Request, string) (int, string, error) {
			t.Fatal("cancelled preparation entered identity")
			return 0, "", nil
		})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := s.PrepareWriter(ctx, awsOutputTestRoute(t), time.Now().Add(time.Minute))
		awsOutputRequireFailure(t, err, "setup_check", "cancelled", "no_send")
		if s.writer.identity != nil || s.budget.snapshot().Requests != 0 {
			t.Fatal("cancelled preparation captured source or used budget")
		}
	})
	t.Run("deadline-and-existing-route-refusals", func(t *testing.T) {
		s := awsOutputTestOpen(t, awsOutputTestSpec(t, false), func(r *http.Request, body string) (int, string, error) { return awsOutputTestIdentity(t, r, body) })
		if _, err := s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(-time.Second)); err == nil || s.budget.snapshot().Requests != 0 {
			t.Fatal("expired deadline entered identity")
		}
		route := awsOutputTestRoute(t)
		if err := os.WriteFile(route.Path, []byte("original"), 0600); err != nil {
			awsOutputTestFatal(t, err)
		}
		_, err := s.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute))
		awsOutputRequireFailure(t, err, "setup_check", "persistence_failed", "no_send")
		got, err := os.ReadFile(route.Path)
		if err != nil || string(got) != "original" {
			t.Fatal("exclusive write replaced existing private bytes")
		}
	})
}

// full_only: false
func TestAWSOutputFixtureConsumerCompleteValueAndRefusal(t *testing.T) {
	t.Run("same-capture-before-and-after-removal", func(t *testing.T) {
		removed := false
		s := awsOutputTestOpen(t, awsOutputTestSpec(t, false), func(r *http.Request, body string) (int, string, error) {
			if strings.HasPrefix(r.URL.Host, "sts.") {
				return awsOutputTestIdentity(t, r, body)
			}
			if removed && strings.Contains(r.Header.Get("Authorization"), "Credential=AKIACONSUMERA00000000/") {
				return 400, `{"__type":"AccessDeniedException"}`, nil
			}
			return 200, `{"ARN":"arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:fixture-output-positive-AABBCCDD_P-a1B2c3","Name":"fixture-output-positive-AABBCCDD_P","VersionId":"0123456789abcdef0123456789abcdef","VersionStages":["AWSCURRENT"],"SecretBinary":"AAH/YWI="}`, nil
		})
		if _, err := s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(time.Minute)); err != nil {
			awsOutputTestFatal(t, err)
		}
		expected := []byte{0, 1, 255, 'a', 'b'}
		before, err := s.ReadConsumer(t.Context(), liveOutputConsumerA, awsOutputTestARN(s)+"?stage=AWSCURRENT", 8)
		if err != nil || before.AccessRefused || !bytes.Equal(before.Bytes, expected) {
			t.Fatal("same actor did not have complete baseline access")
		}
		clear(before.Bytes)
		for _, actor := range []*awsOutputActor{s.consumerA, s.consumerB} {
			if err := os.WriteFile(actor.selected.CredentialsFile, []byte("invalid replaced source"), 0600); err != nil {
				awsOutputTestFatal(t, err)
			}
		}
		removed = true
		denied, err := s.ReadConsumer(t.Context(), liveOutputConsumerA, awsOutputTestARN(s)+"?stage=AWSCURRENT", 8)
		if err != nil || !denied.AccessRefused || denied.Bytes != nil {
			t.Fatal("same captured actor did not retain authentic permission refusal")
		}
		retained, err := s.ReadConsumer(t.Context(), liveOutputConsumerB, awsOutputTestARN(s)+"?stage=AWSCURRENT", 8)
		if err != nil || retained.AccessRefused || !bytes.Equal(retained.Bytes, expected) {
			t.Fatal("retained captured consumer lost complete unchanged value")
		}
		clear(retained.Bytes)
		if s.budget.snapshot().Requests != 6 {
			t.Fatal("same actors were reopened or physical read accounting changed")
		}
	})

	t.Run("delayed-grant-revocation-and-value-single-reads", func(t *testing.T) {
		reads := 0
		s := awsOutputTestOpen(t, awsOutputTestSpec(t, false), func(r *http.Request, body string) (int, string, error) {
			if strings.HasPrefix(r.URL.Host, "sts.") {
				return awsOutputTestIdentity(t, r, body)
			}
			reads++
			if reads == 1 || reads == 4 {
				return 400, `{"__type":"AccessDeniedException"}`, nil
			}
			value := "MTIzNDU2Nzg5"
			if reads == 6 {
				value = "YWJj"
			}
			return 200, `{"ARN":"arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:fixture-output-positive-AABBCCDD_P-a1B2c3","Name":"fixture-output-positive-AABBCCDD_P","VersionId":"0123456789abcdef0123456789abcdef","VersionStages":["AWSCURRENT"],"SecretBinary":"` + value + `"}`, nil
		})
		if _, err := s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(time.Minute)); err != nil {
			awsOutputTestFatal(t, err)
		}
		for i := 1; i <= 6; i++ {
			actor := liveOutputConsumerA
			if i == 3 || i == 4 {
				actor = liveOutputConsumerB
			}
			read, err := s.ReadConsumer(t.Context(), actor, awsOutputTestARN(s)+"?stage=AWSCURRENT", 9)
			denied := i == 1 || i == 4
			status := 200
			if denied {
				status = 400
			}
			expected := []byte("123456789")
			if i == 6 {
				expected = []byte("abc")
			}
			matches := bytes.Equal(read.Bytes, expected)
			clear(read.Bytes)
			if err != nil || read.HTTPStatus != status || read.AccessRefused != denied || denied && len(read.Bytes) != 0 || !denied && !matches || reads != i {
				t.Fatal("consumer repeated a single request or changed accepted result")
			}
		}
		if s.budget.snapshot().Requests != 9 {
			t.Fatal("delayed observations changed physical accounting")
		}
	})

	for _, condition := range []string{"binary", "consumer-b", "string", "400-access-denied", "400-not-authorized", "400-generic-denied", "400-null-message", "400-foreign-code", "400-oversize", "403", "403-invalid-token", "403-opt-in", "401", "404", "malformed403", "wrong-arn", "wrong-stage", "both-values", "duplicate", "oversize", "transport"} {
		t.Run(condition, func(t *testing.T) {
			spec := awsOutputTestSpec(t, false)
			var secretCalls int
			var readAuth string
			s := awsOutputTestOpen(t, spec, func(r *http.Request, body string) (int, string, error) {
				if strings.HasPrefix(r.URL.Host, "sts.") {
					return awsOutputTestIdentity(t, r, body)
				}
				secretCalls++
				readAuth = r.Header.Get("Authorization")
				if r.URL.Host != "secretsmanager.ap-southeast-2.amazonaws.com" || r.Header.Get("X-Amz-Target") != "secretsmanager.GetSecretValue" {
					t.Fatal("consumer changed fixed target")
				}
				var request map[string]string
				if json.Unmarshal([]byte(body), &request) != nil || len(request) != 2 || request["VersionStage"] != "AWSCURRENT" || request["SecretId"] != "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:fixture-output-positive-AABBCCDD_P-a1B2c3" {
					t.Fatal("consumer failed exact qualified ARN/stage request")
				}
				switch condition {
				case "400-access-denied":
					return 400, `{"__type":"AccessDeniedException","Message":"PRIVATE"}`, nil
				case "400-generic-denied":
					return 400, `{"__type":"AccessDenied"}`, nil
				case "400-null-message":
					return 400, `{"__type":"AccessDeniedException","Message":null}`, nil
				case "400-foreign-code":
					return 400, `{"__type":"foreign#AccessDeniedException"}`, nil
				case "400-oversize":
					return 400, `{"__type":"AccessDeniedException","Message":"` + strings.Repeat("x", awsOutputRequestLimit) + `"}`, nil
				case "400-not-authorized":
					return 400, `{"__type":"NotAuthorized","Message":"PRIVATE"}`, nil
				case "403-invalid-token":
					return 403, `{"__type":"InvalidClientTokenId"}`, nil
				case "403-opt-in":
					return 403, `{"__type":"OptInRequired"}`, nil
				case "403":
					return 403, `{"__type":"AccessDeniedException","Message":"PRIVATE"}`, nil
				case "401":
					return 401, `{"__type":"AccessDeniedException"}`, nil
				case "404":
					return 404, `{"__type":"ResourceNotFoundException"}`, nil
				case "malformed403":
					return 403, `broken`, nil
				case "transport":
					return 0, "", errors.New("PRIVATE transport failure")
				}
				response := `{"ARN":"` + request["SecretId"] + `","Name":"fixture-output-positive-AABBCCDD_P","VersionId":"0123456789abcdef0123456789abcdef","VersionStages":["AWSCURRENT"],"SecretBinary":"AAH/YWI="}`
				switch condition {
				case "string":
					response = strings.Replace(response, `"SecretBinary":"AAH/YWI="`, `"SecretString":"complete\\nvalue"`, 1)
				case "wrong-arn":
					response = strings.Replace(response, "a1B2c3", "other1", 1)
				case "wrong-stage":
					response = strings.Replace(response, "AWSCURRENT", "AWSPREVIOUS", 1)
				case "both-values":
					response = strings.TrimSuffix(response, "}") + `,"SecretString":"extra"}`
				case "duplicate":
					response = strings.TrimSuffix(response, "}") + `,"ARN":"ignored"}`
				case "oversize":
					response = strings.Replace(response, "AAH/YWI=", strings.Repeat("A", 12), 1)
				}
				return 200, response, nil
			})
			route := awsOutputTestRoute(t)
			if _, err := s.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute)); err != nil {
				awsOutputTestFatal(t, err)
			}
			if err := os.WriteFile(s.consumerA.selected.CredentialsFile, []byte("replacement invalid"), 0600); err != nil {
				awsOutputTestFatal(t, err)
			}
			maximum := uint32(8)
			if condition == "string" {
				maximum = 64
			}
			which := liveOutputConsumerA
			if condition == "consumer-b" {
				which = liveOutputConsumerB
			}
			result, err := s.ReadConsumer(t.Context(), which, awsOutputTestARN(s)+"?stage=AWSCURRENT", maximum)
			switch condition {
			case "binary", "consumer-b":
				if err != nil || result.HTTPStatus != 200 || result.AccessRefused || !bytes.Equal(result.Bytes, []byte{0, 1, 255, 'a', 'b'}) {
					t.Fatal("complete binary value differs")
				}
				clear(result.Bytes)
			case "string":
				if err != nil || result.HTTPStatus != 200 || result.AccessRefused || string(result.Bytes) != "complete\\nvalue" {
					t.Fatal("complete string value differs")
				}
				clear(result.Bytes)
			case "400-access-denied", "400-not-authorized":
				if err != nil || result.HTTPStatus != 400 || !result.AccessRefused || result.Bytes != nil {
					t.Fatal("documented400 permissions error did not produce bytes-free access refusal")
				}
			default:
				if err == nil || result.AccessRefused || result.Bytes != nil {
					t.Fatal("failed consumer read counted as effective access refusal")
				}
			}
			expectedActor := "Credential=AKIACONSUMERA00000000/"
			if condition == "consumer-b" {
				expectedActor = "Credential=AKIACONSUMERB00000000/"
			}
			if secretCalls != 1 || !strings.Contains(readAuth, expectedActor) || s.budget.snapshot().Requests != 4 {
				t.Fatal("consumer changed captured actor or request budget")
			}
		})
	}
}

// full_only: false
func TestAWSOutputFixtureExactCleanupAndUnknown(t *testing.T) {
	for _, condition := range []string{"owned", "possible", "absent", "malformed-absent", "scheduled", "wrong-arn", "wrong-name", "invalid-date", "null-date", "string-date", "unknown-delete", "bad-delete-identity", "null-delete-date", "missing-delete-date", "string-delete-date", "invalid-delete-date", "refused-describe"} {
		t.Run(condition, func(t *testing.T) {
			spec := awsOutputTestSpec(t, true)
			var describes, deletes int
			s := awsOutputTestOpen(t, spec, func(r *http.Request, body string) (int, string, error) {
				if strings.HasPrefix(r.URL.Host, "sts.") {
					return awsOutputTestIdentity(t, r, body)
				}
				if !strings.Contains(r.Header.Get("Authorization"), "Credential=AKIACLEANER0000000000/") {
					t.Fatal("cleanup used non-cleaner credential")
				}
				var request map[string]any
				if json.Unmarshal([]byte(body), &request) != nil {
					t.Fatal("cleanup request malformed")
				}
				arn := "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:fixture-output-positive-AABBCCDD_P-a1B2c3"
				switch r.Header.Get("X-Amz-Target") {
				case "secretsmanager.DescribeSecret":
					describes++
					want := arn
					if condition == "possible" {
						want = "fixture-output-positive-AABBCCDD_P"
					}
					if len(request) != 1 || request["SecretId"] != want {
						t.Fatal("cleanup metadata was not exact ARN/reserved name")
					}
					if condition == "malformed-absent" {
						return 400, `{"__type":"ResourceNotFoundException","Message":null}`, nil
					}
					if condition == "absent" {
						return 400, `{"__type":"ResourceNotFoundException"}`, nil
					}
					if condition == "refused-describe" {
						return 403, `{"__type":"AccessDeniedException"}`, nil
					}
					response := `{"ARN":"` + arn + `","Name":"fixture-output-positive-AABBCCDD_P"}`
					if condition == "wrong-arn" {
						response = strings.Replace(response, "a1B2c3", "wrong1", 1)
					}
					if condition == "wrong-name" {
						response = strings.Replace(response, `"Name":"fixture-output-positive-AABBCCDD_P"`, `"Name":"foreign"`, 1)
					}
					if condition == "scheduled" {
						response = strings.TrimSuffix(response, "}") + `,"DeletedDate":1893456000}`
					}
					if condition == "null-date" {
						response = strings.TrimSuffix(response, "}") + `,"DeletedDate":null}`
					}
					if condition == "string-date" {
						response = strings.TrimSuffix(response, "}") + `,"DeletedDate":"1893456000"}`
					}
					if condition == "invalid-date" {
						response = strings.TrimSuffix(response, "}") + `,"DeletedDate":-1}`
					}
					return 200, response, nil
				case "secretsmanager.DeleteSecret":
					deletes++
					if len(request) != 2 || request["SecretId"] != arn || request["RecoveryWindowInDays"] != float64(7) {
						t.Fatal("cleanup changed exactARN, recovery window, or force deletion")
					}
					if condition == "unknown-delete" {
						return 0, "", errors.New("PRIVATE entered deletion")
					}
					if condition == "bad-delete-identity" {
						arn = strings.Replace(arn, "a1B2c3", "wrong2", 1)
					}
					response := `{"ARN":"` + arn + `","Name":"fixture-output-positive-AABBCCDD_P"}`
					date := `1893456000`
					switch condition {
					case "null-delete-date":
						date = `null`
					case "string-delete-date":
						date = `"1893456000"`
					case "invalid-delete-date":
						date = `-1`
					}
					if condition != "missing-delete-date" {
						response = strings.TrimSuffix(response, "}") + `,"DeletionDate":` + date + `}`
					}
					return 200, response, nil
				default:
					t.Fatal("cleanup listed or read a value")
					return 0, "", nil
				}
			})
			target := awsOutputTestTarget(s)
			if condition == "possible" {
				target.OwnedInstance = ""
			}
			result, err := s.DeleteFixture(t.Context(), target)
			switch condition {
			case "owned", "possible":
				if err != nil || result.Disposition != liveOutputDeletionScheduled || result.ResolvedInstance != awsOutputTestARN(s) || describes != 1 || deletes != 1 {
					t.Fatal("scheduled deletion result did not retain exact resolved identity")
				}
				if _, err := s.DeleteFixture(t.Context(), target); err == nil || describes != 1 || deletes != 1 {
					t.Fatal("one delete replayed")
				}
			case "absent":
				if err != nil || result.Disposition != liveOutputAbsent || deletes != 0 {
					t.Fatal("exact absent result differs")
				}
			case "scheduled":
				if err != nil || result.Disposition != liveOutputDeletionScheduled || deletes != 0 {
					t.Fatal("already scheduled deletion caused another delete")
				}
			default:
				if err == nil || result.Disposition != 0 {
					t.Fatalf("failed cleanup claimed completion: error=%t disposition=%d describes=%d deletes=%d", err != nil, result.Disposition, describes, deletes)
				}
				var failure *awsOutputFixtureFailure
				if !errors.As(err, &failure) || !failure.fact.Validate() || failure.fact.TargetKind != "output_inventory" || failure.fact.TargetIndex == nil || *failure.fact.TargetIndex != 4 || failure.fact.Operation != "output_cleanup" {
					t.Fatal("cleanup failure lost exact safe inventory row")
				}
				if condition == "unknown-delete" || condition == "bad-delete-identity" || strings.HasSuffix(condition, "delete-date") {
					if failure.fact.Effect != "unknown" || deletes != 1 {
						t.Fatal("entered deletion lost uncertain effect")
					}
					if _, err := s.DeleteFixture(t.Context(), target); err == nil || deletes != 1 || describes != 1 {
						t.Fatal("unknown delete replayed")
					}
				} else if deletes != 0 {
					t.Fatal("invalid metadata entered mutation")
				}
			}
		})
	}
	t.Run("cleaner-actual-principal-distinct-and-slice-copy", func(t *testing.T) {
		spec := awsOutputTestSpec(t, true)
		spec.OtherActorPrincipals[0] = "arn:aws:iam::123456789012:user/cleaner"
		calls := 0
		s := awsOutputTestOpen(t, spec, func(r *http.Request, body string) (int, string, error) {
			calls++
			return awsOutputTestIdentity(t, r, body)
		})
		spec.OtherActorPrincipals[0] = "arn:aws:iam::123456789012:user/writer"
		if _, err := s.DeleteFixture(t.Context(), awsOutputTestTarget(s)); err == nil || calls != 1 {
			t.Fatal("cleaner alias or borrowed principal slice admitted mutation")
		}
	})
	t.Run("zero-attempt-and-foreign-coordinate-zero-work", func(t *testing.T) {
		s := awsOutputTestOpen(t, awsOutputTestSpec(t, true), func(*http.Request, string) (int, string, error) {
			t.Fatal("invalid cleanup target entered request")
			return 0, "", nil
		})
		target := awsOutputTestTarget(s)
		target.Index = 1000001
		_, err := s.DeleteFixture(t.Context(), target)
		awsOutputRequireFailure(t, err, "setup_check", "invalid_request", "no_send")
		target = awsOutputTestTarget(s)
		target.CreateAttempt = contract.ID{}
		if _, err := s.DeleteFixture(t.Context(), target); err == nil {
			t.Fatal("zero create attempt accepted")
		}
		target = awsOutputTestTarget(s)
		target.PlannedSlot = strings.Replace(target.PlannedSlot, "123456789012", "999999999999", 1)
		if _, err := s.DeleteFixture(t.Context(), target); err == nil {
			t.Fatal("foreign account accepted")
		}
		target = awsOutputTestTarget(s)
		target.OwnedInstance = strings.Replace(target.OwnedInstance, "AABBCCDD_P", "OTHER_P", 1)
		if _, err := s.DeleteFixture(t.Context(), target); err == nil {
			t.Fatal("qualified identity lost exact planned slot")
		}
		if s.budget.snapshot().Requests != 0 {
			t.Fatal("invalid cleanup spent budget")
		}
	})
}

// full_only: false
func TestAWSOutputFixturePhysicalBudgetAndResponseBounds(t *testing.T) {
	t.Run("identity-budget-before-roundtrip", func(t *testing.T) {
		spec := awsOutputTestSpec(t, false)
		spec.Budget.limits.Requests = 0
		s := awsOutputTestOpen(t, spec, func(*http.Request, string) (int, string, error) {
			t.Fatal("exhausted budget entered physical request")
			return 0, "", nil
		})
		_, err := s.PrepareWriter(t.Context(), awsOutputTestRoute(t), time.Now().Add(time.Minute))
		awsOutputRequireFailure(t, err, "setup_check", "budget_exhausted", "no_send")
	})
	for _, condition := range []string{"overflow", "truncated", "encoding", "close-failure", "redirect"} {
		t.Run(condition, func(t *testing.T) {
			s := awsOutputTestOpen(t, awsOutputTestSpec(t, false), func(r *http.Request, body string) (int, string, error) { return awsOutputTestIdentity(t, r, body) })
			calls := 0
			s.transport = awsOutputTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if err := r.Body.Close(); err != nil {
					awsOutputTestFatal(t, err)
				}
				body := "{}"
				status := 200
				headers := make(http.Header)
				length := int64(len(body))
				var reader io.ReadCloser = io.NopCloser(strings.NewReader(body))
				switch condition {
				case "overflow":
					reader = io.NopCloser(strings.NewReader(strings.Repeat("x", awsOutputRequestLimit+1)))
					length = awsOutputRequestLimit + 1
				case "truncated":
					length = 20
				case "encoding":
					headers.Set("Content-Encoding", "gzip")
				case "close-failure":
					reader = awsOutputCloseFailure{Reader: strings.NewReader(body)}
				case "redirect":
					status = 307
					headers.Set("Location", "https://foreign.invalid/")
				}
				return &http.Response{StatusCode: status, Header: headers, Body: reader, ContentLength: length, Request: r}, nil
			})
			_, err := s.callerIdentity(t.Context(), aws.Credentials{AccessKeyID: "AKIAWRITER00000000000", SecretAccessKey: "FIXEDTESTSECRET"})
			if err == nil || calls != 1 || s.budget.snapshot().Requests != 1 {
				t.Fatal("response bound/failure retried or accepted")
			}
		})
	}
}

type awsOutputCloseFailure struct{ io.Reader }

func (awsOutputCloseFailure) Close() error { return errors.New("PRIVATE close failure") }
