package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	protocol "enkv.sh/sdk/protocols/output"
)

type liveGitHubCheckTransport func(*http.Request) (*http.Response, error)

func (f liveGitHubCheckTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type liveGitHubCheckBody struct {
	io.Reader
	closed     bool
	closeError error
}

func (b *liveGitHubCheckBody) Close() error { b.closed = true; return b.closeError }

func liveGitHubCheckActor(t *testing.T, body string) *liveOutputActor {
	t.Helper()
	path := filepath.Join(liveOutputCredentialTestDirectory(t), "credential")
	if os.WriteFile(path, []byte(body), 0600) != nil {
		t.Fatal("credential fixture")
	}
	return &liveOutputActor{CredentialsFile: path}
}
func liveGitHubCheckSpec(t *testing.T, scope string) liveGitHubOutputSpec {
	t.Helper()
	spec := liveGitHubOutputSpec{Scope: scope, Owner: "fixture-owner", SecretNamePrefix: "ENKV_FIXTURE_", Cleaner: liveGitHubCheckActor(t, "github_pat_CHECK"), Budget: &runBudget{limits: liveLimits{Requests: 8, BodyBytes: 8 * liveGitHubResponseBytes}}}
	if scope != "github-organization" {
		spec.Repository = "fixture-repo"
	}
	if scope == "github-environment" {
		spec.Environment = "fixture-environment"
	}
	return spec
}
func liveGitHubCheckTarget(slot string) liveOutputCleanupTarget {
	return liveOutputCleanupTarget{Index: 3, PlannedSlot: slot, OwnedInstance: slot}
}
func liveGitHubCheckFact(t *testing.T, err error, operation, cause, effect string) records.HarnessFailure {
	t.Helper()
	var safe interface{ SafeHarnessFailure() records.HarnessFailure }
	if err == nil || !errors.As(err, &safe) {
		t.Fatal("missing safe failure")
	}
	f := safe.SafeHarnessFailure()
	if !f.Validate() || f.Operation != operation || f.Cause != cause || f.Effect != effect {
		t.Fatalf("failure facts %+v", f)
	}
	if strings.Contains(err.Error(), "github_pat") || strings.Contains(err.Error(), "ENKV_FIXTURE") {
		t.Fatal("private data in error")
	}
	return f
}

// full_only: false
func TestLiveGitHubConstructionAndPreparation(t *testing.T) {
	for _, scope := range []string{"github-repository", "github-organization", "github-environment"} {
		t.Run("mixed-actors-"+scope, func(t *testing.T) {
			spec := liveGitHubCheckSpec(t, scope)
			spec.Writer = liveGitHubCheckActor(t, "github_pat_WRITER")
			fixture, err := newLiveGitHubOutput(spec)
			if fixture != nil {
				t.Fatal("combined writer and cleaner admitted")
			}
			liveGitHubCheckFact(t, err, "setup_check", "invalid_request", "no_send")
		})
	}
	t.Run("second-route-refused-before-source-reopen", func(t *testing.T) {
		spec := liveGitHubCheckSpec(t, "github-repository")
		spec.Writer, spec.Cleaner = spec.Cleaner, nil
		fixture, err := newLiveGitHubOutput(spec)
		if err != nil {
			t.Fatal(err)
		}
		first := liveOutputCredentialRoute{ID: protocol.ID{1}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "first")}
		if err := fixture.PrepareWriter(t.Context(), first, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if os.WriteFile(spec.Writer.CredentialsFile, []byte("github_pat_CHANGED"), 0600) != nil {
			t.Fatal("source replacement")
		}
		second := liveOutputCredentialRoute{ID: protocol.ID{2}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "second")}
		liveGitHubCheckFact(t, fixture.PrepareWriter(t.Context(), second, time.Now().Add(time.Minute)), "setup_check", "invalid_request", "no_send")
		if _, err := os.Lstat(second.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("second route published")
		}
		body, err := os.ReadFile(first.Path)
		if err != nil || string(body) != "github_pat_CHECK" {
			t.Fatal("first route changed")
		}
	})

	t.Run("lazy-copy-and-exclusive-route", func(t *testing.T) {
		actor := liveGitHubCheckActor(t, "github_pat_CHECK\n")
		spec := liveGitHubCheckSpec(t, "github-repository")
		spec.Writer, spec.Cleaner = actor, nil
		fixture, err := newLiveGitHubOutput(spec)
		if err != nil {
			t.Fatal(err)
		}
		actor.CredentialsFile = filepath.Join(liveOutputCredentialTestDirectory(t), "missing")
		route := liveOutputCredentialRoute{ID: protocol.ID{1}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "native")}
		if fixture.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute)) != nil {
			t.Fatal("writer prepare")
		}
		body, err := os.ReadFile(route.Path)
		if err != nil || string(body) != "github_pat_CHECK" {
			t.Fatal("normalized route")
		}
		if fixture.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute)) == nil {
			t.Fatal("existing route rewritten")
		}
		current, err := os.ReadFile(route.Path)
		if err != nil || string(current) != string(body) {
			t.Fatal("existing route changed")
		}
		if fixture.spec.Budget.snapshot().Requests != 0 {
			t.Fatal("preparation made request")
		}
	})

	t.Run("second-route-after-missing-source-is-admission-refusal", func(t *testing.T) {
		spec := liveGitHubCheckSpec(t, "github-environment")
		spec.Writer, spec.Cleaner = spec.Cleaner, nil
		fixture, err := newLiveGitHubOutput(spec)
		if err != nil {
			t.Fatal(err)
		}
		first := liveOutputCredentialRoute{ID: protocol.ID{1}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "first")}
		if fixture.PrepareWriter(t.Context(), first, time.Now().Add(time.Minute)) != nil {
			t.Fatal("first preparation")
		}
		if os.Remove(spec.Writer.CredentialsFile) != nil {
			t.Fatal("source removal")
		}
		second := liveOutputCredentialRoute{ID: protocol.ID{2}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "second")}
		liveGitHubCheckFact(t, fixture.PrepareWriter(t.Context(), second, time.Now().Add(time.Minute)), "setup_check", "invalid_request", "no_send")
		if _, err := os.Lstat(second.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("second route exists")
		}
	})
	t.Run("concurrent-preparations-publish-once", func(t *testing.T) {
		spec := liveGitHubCheckSpec(t, "github-organization")
		spec.Writer, spec.Cleaner = spec.Cleaner, nil
		fixture, err := newLiveGitHubOutput(spec)
		if err != nil {
			t.Fatal(err)
		}
		routes := []liveOutputCredentialRoute{{ID: protocol.ID{1}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "one")}, {ID: protocol.ID{2}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "two")}}
		start := make(chan struct{})
		type result struct {
			index int
			err   error
		}
		done := make(chan result, 2)
		for i, route := range routes {
			go func() {
				<-start
				done <- result{i, fixture.PrepareWriter(t.Context(), route, time.Now().Add(time.Minute))}
			}()
		}
		close(start)
		results := []result{<-done, <-done}
		success := 0
		for _, result := range results {
			if result.err == nil {
				success++
				body, err := os.ReadFile(routes[result.index].Path)
				if err != nil || string(body) != "github_pat_CHECK" {
					t.Fatal("published bytes")
				}
			} else {
				liveGitHubCheckFact(t, result.err, "setup_check", "invalid_request", "no_send")
				if _, err := os.Lstat(routes[result.index].Path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused route published")
				}
			}
		}
		if success != 1 {
			t.Fatal("concurrent publication count", success)
		}
	})
	t.Run("constructor-does-not-open-source", func(t *testing.T) {
		spec := liveGitHubCheckSpec(t, "github-repository")
		spec.Cleaner.CredentialsFile = filepath.Join(liveOutputCredentialTestDirectory(t), "missing")
		if _, err := newLiveGitHubOutput(spec); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cleaner-only-refuses-prepare", func(t *testing.T) {
		fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
		if err != nil {
			t.Fatal(err)
		}
		liveGitHubCheckFact(t, fixture.PrepareWriter(t.Context(), liveOutputCredentialRoute{ID: protocol.ID{1}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "route")}, time.Now().Add(time.Minute)), "setup_check", "authentication_refused", "no_send")
	})
	for _, tc := range []struct {
		name   string
		change func(*liveGitHubOutputSpec)
	}{
		{"scope", func(s *liveGitHubOutputSpec) { s.Scope = "repository" }},
		{"missing-actor", func(s *liveGitHubOutputSpec) { s.Cleaner = nil }},
		{"budget", func(s *liveGitHubOutputSpec) { s.Budget = nil }},
		{"owner-alias", func(s *liveGitHubOutputSpec) { s.Owner = "Fixture" }},
		{"repo-alias", func(s *liveGitHubOutputSpec) { s.Repository = "fixture.git" }},
		{"environment-in-repository", func(s *liveGitHubOutputSpec) { s.Environment = "extra" }},
		{"prefix", func(s *liveGitHubOutputSpec) { s.SecretNamePrefix = "GITHUB_RESERVED" }},
		{"prefix-bound", func(s *liveGitHubOutputSpec) { s.SecretNamePrefix = strings.Repeat("A", 67) }},
		{"actor-profile", func(s *liveGitHubOutputSpec) { s.Cleaner.Profile = "ambient" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := liveGitHubCheckSpec(t, "github-repository")
			tc.change(&spec)
			fixture, err := newLiveGitHubOutput(spec)
			if fixture != nil {
				t.Fatal("invalid constructor")
			}
			liveGitHubCheckFact(t, err, "setup_check", "invalid_request", "no_send")
		})
	}
}

// full_only: false
func TestLiveGitHubCredentialAndDeadlineBounds(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		accepted   bool
	}{
		{"plain", "github_pat_CHECK", true}, {"one-lf", "github_pat_CHECK\n", true}, {"two-lf", "github_pat_CHECK\n\n", false},
		{"crlf", "github_pat_CHECK\r\n", false}, {"colon", "bad:token", false}, {"quote", "bad\"token", false}, {"slash", "bad\\token", false},
		{"space", "bad token", false}, {"empty", "", false}, {"native-maximum", strings.Repeat("A", protocol.MaximumCredentialBytes-36), true},
		{"native-overflow", strings.Repeat("A", protocol.MaximumCredentialBytes-35), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := readLiveGitHubBearer(liveGitHubCheckActor(t, tc.body))
			defer clear(body)
			if (err == nil) != tc.accepted {
				t.Fatal("credential syntax/bound outcome")
			}
		})
	}
	t.Run("cancel-and-expired-no-file", func(t *testing.T) {
		spec := liveGitHubCheckSpec(t, "github-repository")
		spec.Writer, spec.Cleaner = spec.Cleaner, nil
		fixture, err := newLiveGitHubOutput(spec)
		if err != nil {
			t.Fatal(err)
		}
		route := liveOutputCredentialRoute{ID: protocol.ID{1}, Path: filepath.Join(liveOutputCredentialTestDirectory(t), "route")}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if fixture.PrepareWriter(ctx, route, time.Now().Add(time.Minute)) == nil || fixture.PrepareWriter(t.Context(), route, time.Now().Add(-time.Minute)) == nil {
			t.Fatal("inactive deadline accepted")
		}
		if _, err := os.Lstat(route.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("route created")
		}
	})
}

// full_only: false
func TestLiveGitHubCleanupExactScopes(t *testing.T) {
	for _, tc := range []struct{ scope, slot string }{
		{"github-repository", "repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"},
		{"github-organization", "orgs/fixture-owner/actions/secrets/ENKV_FIXTURE_ALPHA"},
		{"github-environment", "repos/fixture-owner/fixture-repo/environments/fixture-environment/secrets/ENKV_FIXTURE_ALPHA"},
	} {
		for _, pending := range []bool{false, true} {
			name := tc.scope
			if pending {
				name += "-possible-create"
			}
			t.Run(name, func(t *testing.T) {
				fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, tc.scope))
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				var previous *liveGitHubCheckBody
				fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if previous != nil && !previous.closed {
						t.Fatal("response borrower not closed before next request")
					}
					expectedMethod := http.MethodGet
					status, body := 200, `{"name":"ENKV_FIXTURE_ALPHA","created_at":"2026-01-01T00:00:00Z"}`
					if calls == 2 {
						expectedMethod, status, body = http.MethodDelete, 204, ""
					}
					if calls > 2 || r.Method != expectedMethod || r.URL.String() != "https://api.github.com/"+tc.slot || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer github_pat_CHECK" || r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("User-Agent") == "" || !r.Close || r.GetBody != nil {
						t.Fatal("request escaped exact contract")
					}
					previous = &liveGitHubCheckBody{Reader: strings.NewReader(body)}
					return &http.Response{StatusCode: status, Body: previous, Header: make(http.Header), Request: r}, nil
				})
				target := liveGitHubCheckTarget(tc.slot)
				if pending {
					target.OwnedInstance = ""
					target.CreateAttempt = contract.ID{1}
				}
				result, err := fixture.DeleteFixture(t.Context(), target)
				if err != nil || calls != 2 || !previous.closed || result.Disposition != liveOutputDeleteAcknowledged || result.ResolvedInstance != tc.slot {
					t.Fatal("exact cleanup", err, result, calls)
				}
				if fixture.spec.Budget.snapshot().Requests != 2 || fixture.spec.Budget.snapshot().BodyBytes != 2*liveGitHubResponseBytes {
					t.Fatal("physical budget")
				}
				liveGitHubCheckFact(t, func() error { _, err := fixture.DeleteFixture(t.Context(), target); return err }(), "output_cleanup", "evidence_unavailable", "no_send")
				if calls != 2 {
					t.Fatal("cleanup replay")
				}
			})
		}
	}
}

// full_only: false
func TestLiveGitHubCleanupRefusesUnqualifiedRepliesAndReplay(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		getStatus            int
		metadata             string
		deleteStatus         int
		reply, cause, effect string
		calls                int
	}{
		{"ambiguous-duplicate-name", 200, `{"name":"OTHER","name":"ENKV_FIXTURE_ALPHA"}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-null-after-name", 200, `{"name":"ENKV_FIXTURE_ALPHA","name":null}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-case-alias", 200, `{"Name":"OTHER","name":"ENKV_FIXTURE_ALPHA"}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-name-null", 200, `{"name":null}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-missing-name", 200, `{"created_at":"2026-01-01T00:00:00Z"}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-name-number", 200, `{"name":1}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-name-array", 200, `{"name":["ENKV_FIXTURE_ALPHA"]}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-name-case-only", 200, `{"NAME":"ENKV_FIXTURE_ALPHA"}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-duplicate-unknown", 200, `{"name":"ENKV_FIXTURE_ALPHA","visibility":"all","visibility":"private"}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"ambiguous-invalid-utf8", 200, "{\"name\":\"ENKV_FIXTURE_ALPHA\",\"unknown\":\"\xff\"}", 0, "", "malformed_envelope", "no_effect", 1},
		{"masked404", 404, `{"message":"Not Found"}`, 0, "", "evidence_unavailable", "no_effect", 1},
		{"refused", 403, `{"message":"forbidden"}`, 0, "", "provider_refused", "no_effect", 1},
		{"wrong-name", 200, `{"name":"OTHER"}`, 0, "", "ownership_mismatch", "no_effect", 1},
		{"null", 200, `null`, 0, "", "malformed_envelope", "no_effect", 1},
		{"malformed", 200, `{`, 0, "", "malformed_envelope", "no_effect", 1},
		{"trailing", 200, `{"name":"ENKV_FIXTURE_ALPHA"}{}`, 0, "", "malformed_envelope", "no_effect", 1},
		{"delete500", 200, `{"name":"ENKV_FIXTURE_ALPHA"}`, 500, `{"error":"PRIVATE"}`, "invalid_acknowledgement", "unknown", 2},
		{"delete404", 200, `{"name":"ENKV_FIXTURE_ALPHA"}`, 404, "", "invalid_acknowledgement", "unknown", 2},
		{"delete201", 200, `{"name":"ENKV_FIXTURE_ALPHA"}`, 201, "", "invalid_acknowledgement", "unknown", 2},
		{"delete-body", 200, `{"name":"ENKV_FIXTURE_ALPHA"}`, 204, "{}", "invalid_acknowledgement", "unknown", 2},
		{"redirect", 302, "", 0, "", "provider_refused", "no_effect", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			var bodies []*liveGitHubCheckBody
			fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				status, body := tc.getStatus, tc.metadata
				if calls == 2 {
					status, body = tc.deleteStatus, tc.reply
				}
				b := &liveGitHubCheckBody{Reader: strings.NewReader(body)}
				bodies = append(bodies, b)
				return &http.Response{StatusCode: status, Body: b, Header: http.Header{"Location": []string{"https://other.invalid/secret"}}, Request: r}, nil
			})
			target := liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA")
			result, err := fixture.DeleteFixture(t.Context(), target)
			fact := liveGitHubCheckFact(t, err, "output_cleanup", tc.cause, tc.effect)
			if result != (liveOutputCleanupResult{}) || calls != tc.calls || fact.TargetIndex == nil || *fact.TargetIndex != 3 {
				t.Fatal("unqualified cleanup/result")
			}
			for _, b := range bodies {
				if !b.closed {
					t.Fatal("response left open")
				}
			}
			_, err = fixture.DeleteFixture(t.Context(), target)
			liveGitHubCheckFact(t, err, "output_cleanup", "evidence_unavailable", "no_send")
			if calls != tc.calls {
				t.Fatal("failure replayed")
			}
		})
	}
}

// full_only: false
func TestLiveGitHubCleanupRejectsInvalidTargets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		change    func(*liveOutputCleanupTarget)
		operation string
	}{
		{"index", func(x *liveOutputCleanupTarget) { x.Index = 1000001 }, "setup_check"},
		{"other-owner", func(x *liveOutputCleanupTarget) {
			x.PlannedSlot = strings.ReplaceAll(x.PlannedSlot, "fixture-owner", "another-owner")
			x.OwnedInstance = x.PlannedSlot
		}, "output_cleanup"},
		{"prefix", func(x *liveOutputCleanupTarget) {
			x.PlannedSlot = "repos/fixture-owner/fixture-repo/actions/secrets/OTHER_ALPHA"
			x.OwnedInstance = x.PlannedSlot
		}, "output_cleanup"},
		{"empty-suffix", func(x *liveOutputCleanupTarget) {
			x.PlannedSlot = "repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_"
			x.OwnedInstance = x.PlannedSlot
		}, "output_cleanup"},
		{"instance", func(x *liveOutputCleanupTarget) { x.OwnedInstance = "another" }, "output_cleanup"},
		{"no-create", func(x *liveOutputCleanupTarget) { x.OwnedInstance = "" }, "output_cleanup"},
		{"query", func(x *liveOutputCleanupTarget) { x.PlannedSlot += "?token=PRIVATE"; x.OwnedInstance = x.PlannedSlot }, "output_cleanup"},
		{"encoded-alias", func(x *liveOutputCleanupTarget) { x.PlannedSlot += "%2F"; x.OwnedInstance = x.PlannedSlot }, "output_cleanup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
			if err != nil {
				t.Fatal(err)
			}
			fixture.transport = liveGitHubCheckTransport(func(*http.Request) (*http.Response, error) { t.Fatal("invalid target entered"); return nil, nil })
			target := liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA")
			tc.change(&target)
			_, err = fixture.DeleteFixture(t.Context(), target)
			cause := "ownership_mismatch"
			if tc.operation == "setup_check" {
				cause = "invalid_request"
			}
			fact := liveGitHubCheckFact(t, err, tc.operation, cause, "no_send")
			if tc.operation == "setup_check" && (fact.TargetIndex != nil || fact.TargetKind != "") {
				t.Fatal("invalid index was retained")
			}
			if fixture.spec.Budget.snapshot().Requests != 0 {
				t.Fatal("invalid target cost request")
			}
		})
	}
}

// full_only: false
func TestLiveGitHubCleanupBoundsBudgetAndCancellation(t *testing.T) {
	t.Run("exact-response-bound", func(t *testing.T) {
		fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			body := `{"unknown":{"nested":[1,null,true]},"name":"ENKV_FIXTURE_ALPHA","updated_at":"2026-01-01T00:00:00Z"}`
			status := 200
			if calls == 1 {
				body += strings.Repeat(" ", 4096-len(body))
			} else {
				body = ""
				status = 204
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})
		result, err := fixture.DeleteFixture(t.Context(), liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
		if err != nil || calls != 2 || result.Disposition != liveOutputDeleteAcknowledged {
			t.Fatal("exact response limit refused", err)
		}
	})
	t.Run("response-read-error-closes", func(t *testing.T) {
		fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
		if err != nil {
			t.Fatal(err)
		}
		body := &liveGitHubCheckBody{Reader: liveGitHubCheckReadFailure{}}
		fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: body, Request: r}, nil
		})
		_, err = fixture.DeleteFixture(t.Context(), liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
		liveGitHubCheckFact(t, err, "output_cleanup", "early_eof", "no_effect")
		if !body.closed {
			t.Fatal("failed reader left open")
		}
	})
	t.Run("body-budget-no-entry", func(t *testing.T) {
		spec := liveGitHubCheckSpec(t, "github-repository")
		spec.Budget.limits.BodyBytes = 4095
		fixture, err := newLiveGitHubOutput(spec)
		if err != nil {
			t.Fatal(err)
		}
		fixture.transport = liveGitHubCheckTransport(func(*http.Request) (*http.Response, error) { t.Fatal("body budget entered"); return nil, nil })
		_, err = fixture.DeleteFixture(t.Context(), liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
		liveGitHubCheckFact(t, err, "output_cleanup", "budget_exhausted", "no_send")
		if spec.Budget.snapshot().Requests != 0 {
			t.Fatal("partial reservation")
		}
	})
	t.Run("cancel-delete-joins-transport", func(t *testing.T) {
		fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered, joined := make(chan struct{}), make(chan struct{})
		calls := 0
		fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"name":"ENKV_FIXTURE_ALPHA"}`)), Request: r}, nil
			}
			close(entered)
			<-r.Context().Done()
			close(joined)
			return nil, r.Context().Err()
		})
		done := make(chan error, 1)
		go func() {
			_, err := fixture.DeleteFixture(ctx, liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
			done <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("DELETE did not enter")
		}
		cancel()
		select {
		case err := <-done:
			liveGitHubCheckFact(t, err, "output_cleanup", "cancelled", "unknown")
		case <-time.After(time.Second):
			t.Fatal("DELETE cancel did not join")
		}
		select {
		case <-joined:
		default:
			t.Fatal("DELETE transport still running")
		}
		if fixture.spec.Budget.snapshot().Requests != 2 {
			t.Fatal("DELETE cancellation budget")
		}
	})

	t.Run("transport-response-error-closes", func(t *testing.T) {
		fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
		if err != nil {
			t.Fatal(err)
		}
		body := &liveGitHubCheckBody{Reader: strings.NewReader("PRIVATE"), closeError: errors.New("PRIVATE close")}
		fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: body, Request: r}, errors.New("PRIVATE transport")
		})
		_, err = fixture.DeleteFixture(t.Context(), liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
		if !body.closed {
			t.Fatal("response discarded without synchronous close")
		}
		liveGitHubCheckFact(t, err, "output_cleanup", "early_eof", "no_effect")
	})

	for _, tc := range []struct {
		name       string
		atDelete   bool
		closeError bool
	}{
		{"metadata-overflow", false, false}, {"delete-overflow", true, false}, {"metadata-close", false, true}, {"delete-close", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			var last *liveGitHubCheckBody
			fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				status, body := 200, `{"name":"ENKV_FIXTURE_ALPHA"}`
				if calls == 2 {
					status, body = 204, ""
				}
				if (calls == 2) == tc.atDelete {
					if !tc.closeError {
						body = strings.Repeat("A", liveGitHubResponseBytes+1)
					}
				}
				last = &liveGitHubCheckBody{Reader: strings.NewReader(body)}
				if (calls == 2) == tc.atDelete && tc.closeError {
					last.closeError = errors.New("PRIVATE close")
				}
				return &http.Response{StatusCode: status, Body: last, Header: make(http.Header), Request: r}, nil
			})
			_, err = fixture.DeleteFixture(t.Context(), liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
			cause, effect := "body_overflow", "no_effect"
			if tc.closeError {
				cause = "early_eof"
			}
			if tc.atDelete {
				effect = "unknown"
			}
			liveGitHubCheckFact(t, err, "output_cleanup", cause, effect)
			if !last.closed {
				t.Fatal("response not synchronously closed")
			}
		})
	}
	for _, requests := range []uint64{0, 1} {
		t.Run("budget-"+string(rune('0'+requests)), func(t *testing.T) {
			spec := liveGitHubCheckSpec(t, "github-repository")
			spec.Budget.limits.Requests = requests
			fixture, err := newLiveGitHubOutput(spec)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"name":"ENKV_FIXTURE_ALPHA"}`)), Request: r}, nil
			})
			_, err = fixture.DeleteFixture(t.Context(), liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
			liveGitHubCheckFact(t, err, "output_cleanup", "budget_exhausted", "no_send")
			if uint64(calls) != requests || spec.Budget.snapshot().Requests != requests {
				t.Fatal("budget entered extra request")
			}
		})
	}
	t.Run("cancel-joins-transport", func(t *testing.T) {
		fixture, err := newLiveGitHubOutput(liveGitHubCheckSpec(t, "github-repository"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered, joined := make(chan struct{}), make(chan struct{})
		fixture.transport = liveGitHubCheckTransport(func(r *http.Request) (*http.Response, error) {
			close(entered)
			<-r.Context().Done()
			close(joined)
			return nil, r.Context().Err()
		})
		done := make(chan error, 1)
		go func() {
			_, err := fixture.DeleteFixture(ctx, liveGitHubCheckTarget("repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_ALPHA"))
			done <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("request did not enter")
		}
		cancel()
		select {
		case err := <-done:
			liveGitHubCheckFact(t, err, "output_cleanup", "cancelled", "no_effect")
		case <-time.After(time.Second):
			t.Fatal("cancel did not join")
		}
		select {
		case <-joined:
		default:
			t.Fatal("transport still running")
		}
	})
}

type liveGitHubCheckReadFailure struct{}

func (liveGitHubCheckReadFailure) Read([]byte) (int, error) { return 0, errors.New("PRIVATE read") }
