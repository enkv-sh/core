package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func checkInterruptedCommandDiagnostics(t *testing.T, body, result, reason string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line == "" {
			continue
		}
		if !strings.Contains(line, " WARN ") || !strings.Contains(line, `component="application" operation="application.invocation" event="return" result="`+result+`" reason="`+reason+`"`) {
			t.Error("unexpected result-delivery diagnostic", line)
		}
	}
}

// full_only: false
func TestAbandonmentDeliversOwnedUnknownResultAfterExecutionCancellation(t *testing.T) {
	for _, structured := range []bool{false, true} {
		for _, interruption := range []string{"cancel", "deadline"} {
			for _, sink := range []string{"complete", "short", "failed"} {
				t.Run(fmt.Sprintf("json-%t/%s/%s", structured, interruption, sink), func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					if interruption == "deadline" {
						cancel()
						ctx, cancel = context.WithTimeout(t.Context(), time.Millisecond)
					}
					defer cancel()
					var output, diagnostic bytes.Buffer
					var out io.Writer = &output
					if sink != "complete" {
						out = commandWriterFunc(func(b []byte) (int, error) {
							if sink == "short" {
								return len(b) - 1, nil
							}
							return 0, errors.New("controlled result delivery failure")
						})
					}
					calls := 0
					id := contract.ID{2}
					args := []string{"apply", "--source=source.json", "--plan=plan.json"}
					if structured {
						args = append(args, "--json")
					}
					code := runAbandonWithExecutor(ctx, args, out, &diagnostic, func(_ context.Context, nonce contract.ID, _ string, _ configuration.Format, _ compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult {
						calls++
						if interruption == "deadline" {
							<-ctx.Done()
							if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
								t.Fatal("execution deadline did not expire", ctx.Err())
							}
						} else {
							cancel()
						}
						return compositionfull.AbandonmentResult{Operation: core.PublicAdministrativeResult{Operation: core.AdministrativeApply, RequestID: nonce, OperationID: id, DomainID: contract.ID{3}, RequestIdentity: contract.ID{4}, StateResult: "commit-outcome-unknown", Result: core.Result{Outcome: core.UnresolvedCommit, Reason: core.WriteUncertain, RequestedRevision: contract.ID{5}, CommitMayHaveOccurred: true}}}
					})
					if calls != 1 {
						t.Fatal("delivery repeated Product work", calls)
					}
					if sink != "complete" {
						if code != 2 || !strings.Contains(diagnostic.String(), "delivery failed") {
							t.Error("output failure was hidden", code)
						}
						return
					}
					var got struct {
						State     string `json:"state_result"`
						Operation string `json:"operation_id"`
						Result    struct {
							Commit    bool   `json:"commit_may_have_occurred"`
							Requested string `json:"requested_revision"`
						} `json:"result"`
					}
					if structured {
						if code != 3 || json.Unmarshal(output.Bytes(), &got) != nil || got.State != "commit-outcome-unknown" || got.Operation != "02"+strings.Repeat("00", 31) || !got.Result.Commit || got.Result.Requested != "05"+strings.Repeat("00", 31) {
							t.Error("execution interruption hid the owned possible-CAS result", code, got)
						}
					} else if code != 3 || !strings.HasPrefix(output.String(), "abandon-apply: commit-outcome-unknown\n") || !strings.Contains(output.String(), "Operation: 02"+strings.Repeat("00", 31)+".\n") || !strings.Contains(output.String(), "commit may have occurred") || !strings.Contains(output.String(), "Requested revision: 05"+strings.Repeat("00", 31)+".\n") {
						t.Error("human result lost unknown commit and exact observation identity", code, output.String())
					}
					checkInterruptedCommandDiagnostics(t, diagnostic.String(), "unresolved_commit", "uncertain")
				})
			}
		}
	}
}

// full_only: false
func TestAbandonmentGrammarRefusesBeforeProviderConstruction(t *testing.T) {
	type grammarCase struct {
		name      string
		args      []string
		operation string
		human     bool
	}
	cases := []grammarCase{{"plan-target", []string{"plan", "--source=source.json", "--out=plan.json", "--json"}, "abandon-plan", false}, {"plan-out", []string{"plan", "--source=source.json", "--target=" + strings.Repeat("01", 32), "--json"}, "abandon-plan", false}, {"apply-plan", []string{"apply", "--source=source.json", "--json"}, "abandon-apply", false}, {"receipt-operation", []string{"receipt", "--source=source.json", "--json"}, "abandon-receipt", false}, {"conflicting", []string{"list", "--source=source.json", "--target=" + strings.Repeat("01", 32), "--json"}, "abandon-list", false}, {"old-carrier", []string{"list", "--json", "--source=source.json", "--connection=private-sentinel"}, "abandon-list", false}, {"invalid-trailing-json", []string{"list", "--source=source.json", "--pem=private-sentinel", "--json"}, "abandon-list", true}, {"uppercase-id", []string{"receipt", "--source=source.json", "--operation=" + strings.Repeat("AA", 32), "--json"}, "abandon-receipt", false}}
	id := strings.Repeat("01", 32)
	otherID := strings.Repeat("02", 32)
	for _, option := range []struct {
		name, command, first, second string
		base                         []string
	}{
		{"source", "list", "source.json", "other.json", nil},
		{"source-format", "list", "json", "yaml", []string{"--source=source.json"}},
		{"target", "plan", id, otherID, []string{"--source=source.json", "--out=plan.json"}},
		{"out", "plan", "plan.json", "other-plan.json", []string{"--source=source.json", "--target=" + id}},
		{"plan", "apply", "plan.json", "other-plan.json", []string{"--source=source.json"}},
		{"operation", "receipt", id, otherID, []string{"--source=source.json"}},
	} {
		for _, spelling := range []string{"equals", "separate"} {
			for _, value := range []struct{ name, text string }{{"equal", option.first}, {"different", option.second}} {
				args := append([]string{option.command}, option.base...)
				if spelling == "equals" {
					args = append(args, "--"+option.name+"="+option.first, "--"+option.name+"="+value.text, "--json")
				} else {
					args = append(args, "--json", "--"+option.name, option.first, "--"+option.name, value.text)
				}
				cases = append(cases, grammarCase{"duplicate-" + option.name + "-" + spelling + "-" + value.name, args, "abandon-" + option.command, spelling == "equals"})
			}
		}
	}
	for _, command := range []struct {
		name      string
		base      []string
		forbidden []string
	}{
		{"list", []string{"--source=source.json"}, []string{"target", "out", "plan", "operation"}},
		{"plan", []string{"--source=source.json", "--target=" + id, "--out=plan.json"}, []string{"plan", "operation"}},
		{"apply", []string{"--source=source.json", "--plan=plan.json"}, []string{"target", "out", "operation"}},
		{"receipt", []string{"--source=source.json", "--operation=" + id}, []string{"target", "out", "plan"}},
	} {
		for _, name := range command.forbidden {
			for _, spelling := range []string{"equals", "separate"} {
				args := append([]string{command.name}, command.base...)
				if spelling == "equals" {
					args = append(args, "--"+name+"=", "--json")
				} else {
					args = append(args, "--json", "--"+name, "")
				}
				cases = append(cases, grammarCase{"empty-forbidden-" + command.name + "-" + name + "-" + spelling, args, "abandon-" + command.name, false})
			}
		}
	}
	cases = append(cases,
		grammarCase{"zero-target", []string{"plan", "--source=source.json", "--target=" + strings.Repeat("00", 32), "--out=plan.json", "--json"}, "abandon-plan", false},
		grammarCase{"empty-format-equals", []string{"list", "--source=source.json", "--source-format=", "--json"}, "abandon-list", false},
		grammarCase{"empty-format-separate", []string{"list", "--json", "--source", "source.json", "--source-format", ""}, "abandon-list", false})
	for _, option := range []struct {
		name, command string
		base          []string
	}{
		{"source", "list", nil},
		{"target", "plan", []string{"--source=source.json", "--out=plan.json"}},
		{"out", "plan", []string{"--source=source.json", "--target=" + id}},
		{"plan", "apply", []string{"--source=source.json"}},
		{"operation", "receipt", []string{"--source=source.json"}},
	} {
		for _, spelling := range []string{"equals", "separate"} {
			args := append([]string{option.command}, option.base...)
			if spelling == "equals" {
				args = append(args, "--"+option.name+"=", "--json")
			} else {
				args = append(args, "--json", "--"+option.name, "")
			}
			cases = append(cases, grammarCase{"empty-required-" + option.name + "-" + spelling, args, "abandon-" + option.command, false})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output, diagnostic bytes.Buffer
			calls := 0
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			code := runAbandonWithExecutor(ctx, tc.args, &output, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult {
				calls++
				return compositionfull.AbandonmentResult{}
			})
			if tc.human {
				if code != 2 || calls != 0 || !strings.HasPrefix(output.String(), tc.operation+": refused\n") || !strings.Contains(output.String(), "Operation: ") || !strings.Contains(output.String(), "Admission: dispatch / invalid-input.\n") || !strings.Contains(output.String(), "Result: admission_refused / admission_invalid.\n") || strings.Contains(output.String()+diagnostic.String(), "private-sentinel") || strings.Contains(output.String(), `"schema"`) {
					t.Fatal("recognized human grammar refusal lost identity or leaked input", code, calls)
				}
				return
			}
			var result struct {
				Schema    string `json:"schema"`
				Operation string `json:"operation_kind"`
				State     string `json:"state_result"`
				Identity  struct {
					Schema string `json:"schema"`
					Stage  string `json:"stage"`
					Code   string `json:"code"`
				} `json:"request_identity"`
				Payload json.RawMessage `json:"payload"`
			}
			if code != 2 || calls != 0 || json.Unmarshal(output.Bytes(), &result) != nil || result.Schema != "ProductResult/v1" || result.Operation != tc.operation || result.State != "refused" || result.Identity.Schema != "PreAdmissionRequestIdentity/v1" || result.Identity.Stage != "dispatch" || result.Identity.Code != "invalid-input" || string(result.Payload) != "null" || strings.Contains(output.String()+diagnostic.String(), "private-sentinel") {
				t.Fatal("recognized grammar refusal lost identity or leaked input", code, calls)
			}
		})
	}

	for _, structured := range []bool{false, true} {
		name := "flag-stop-human"
		args := []string{"list", "--source=source.json"}
		if structured {
			name = "flag-stop-json"
			args = append(args, "--json")
		}
		args = append(args, "--", "--json", "private-sentinel")
		t.Run(name, func(t *testing.T) {
			var output, diagnostic bytes.Buffer
			calls := 0
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			code := runAbandonWithExecutor(ctx, args, &output, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult {
				calls++
				return compositionfull.AbandonmentResult{}
			})
			body := output.String()
			if !structured {
				if code != 2 || calls != 0 || !strings.HasPrefix(body, "abandon-list: refused\n") || !strings.Contains(body, "Admission: dispatch / invalid-input.\n") || strings.Contains(body+diagnostic.String(), "private-sentinel") {
					t.Fatal("flag stop lost recognized human refusal", code, calls, body)
				}
				return
			}
			var result map[string]json.RawMessage
			if code != 2 || calls != 0 || json.Unmarshal([]byte(body), &result) != nil || string(result["operation_kind"]) != `"abandon-list"` || string(result["state_result"]) != `"refused"` || strings.Contains(output.String()+diagnostic.String(), "private-sentinel") {
				t.Fatal("flag stop lost recognized refusal", code, calls)
			}
		})
	}
}

// full_only: false
func TestAbandonmentFamilyHelpAndRetiredDispatchHaveNoProviders(t *testing.T) {
	var output, diagnostic bytes.Buffer
	if code := run([]string{"abandon"}, &output, &diagnostic); code != 0 || !strings.Contains(output.String(), "abandon plan") || diagnostic.Len() != 0 {
		t.Fatal("bare family help failed", code)
	}
	output.Reset()
	diagnostic.Reset()
	if code := run([]string{"keys"}, &output, &diagnostic); code != 0 {
		t.Fatal("bare keys help failed", code)
	}
	for _, command := range []string{"preview", "end-work", "recheck"} {
		output.Reset()
		diagnostic.Reset()
		if code := run([]string{command, "--json"}, &output, &diagnostic); code != 2 {
			t.Fatal("retired command dispatched", command)
		}
		var result map[string]json.RawMessage
		if json.Unmarshal(output.Bytes(), &result) != nil || len(result) != 15 {
			t.Fatal("unknown dispatch shape changed", command)
		}
		if _, ok := result["operation_kind"]; ok {
			t.Fatal("retired command retained a recognized operation")
		}
		if string(result["request_identity"]) != `"none"` || string(result["warning_summary"]) != `[]` {
			t.Fatal("unknown dispatch acquired evidence")
		}
	}
}

// full_only: false
func TestAbandonmentCapturesRelativePathsOnceAndInfersFormat(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var output, diagnostic bytes.Buffer
	calls := 0
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	execute := func(ctx context.Context, nonce contract.ID, path string, format configuration.Format, q compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult {
		calls++
		if path != filepath.Join(dir, "source.yaml") || q.ArtifactPath != filepath.Join(dir, "plan.json") || format != configuration.YAML || nonce.IsZero() {
			t.Fatal("CLI changed captured path/format/nonce")
		}
		r, err := compositionfull.NewAbandonmentRefusal(q.Operation, format)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if code := runAbandonWithExecutor(ctx, []string{"plan", "--source=source.yaml", "--target=" + strings.Repeat("01", 32), "--out=plan.json", "--json"}, &output, &diagnostic, execute); code != 2 || calls != 1 {
		t.Fatal("valid grammar did not reach exact executor", code, calls)
	}
}

// full_only: false
func TestAbandonmentOutputFailureNeverReportsSuccessfulDelivery(t *testing.T) {
	failure := errors.New("controlled output failure")
	for _, short := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		var diagnostic bytes.Buffer
		out := commandWriterFunc(func(b []byte) (int, error) {
			if short {
				return len(b) - 1, nil
			}
			return 0, failure
		})
		code := runAbandonWithExecutor(ctx, []string{"list", "--json"}, out, &diagnostic, nil)
		cancel()
		if code != 2 || !strings.Contains(diagnostic.String(), "delivery failed") {
			t.Fatal("failed output claimed success", code)
		}
	}
	if _, err := io.WriteString(commandWriterFunc(func([]byte) (int, error) { return 0, failure }), "x"); !errors.Is(err, failure) {
		t.Fatal("writer cause unavailable")
	}
}

// full_only: false
func TestUnknownDispatchHonorsClosedJSONConventionAcrossUnsupportedArguments(t *testing.T) {
	for _, args := range [][]string{{"keys", "replace", "--target", "invalid", "--json"}, {"abandon", "unknown", "--source", "private-sentinel", "--json"}, {"unknown", "--unsupported", "private-sentinel", "--json=true"}} {
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != 2 {
			t.Fatal("unknown dispatch accepted", code)
		}
		var result map[string]json.RawMessage
		if json.Unmarshal(out.Bytes(), &result) != nil || len(result) != 15 || string(result["schema"]) != `"ProductResult/v1"` || string(result["operation_payload"]) != `"none"` || strings.Contains(out.String()+diagnostic.String(), "private-sentinel") {
			t.Fatal("unsupported dispatch lost closed JSON", out.String())
		}
	}
	var out, diagnostic bytes.Buffer
	if code := run([]string{"unknown", "--", "--json"}, &out, &diagnostic); code != 2 || !strings.HasPrefix(out.String(), "Command: refused\n") {
		t.Fatal("explicit flag stop ignored", code)
	}
}

// full_only: false
func TestAbandonmentHelpRequiresCompleteDelivery(t *testing.T) {
	var diagnostic bytes.Buffer
	short := commandWriterFunc(func(b []byte) (int, error) { return len(b) - 1, nil })
	if code := run([]string{"abandon"}, short, &diagnostic); code != 2 {
		t.Fatal("truncated help claimed successful delivery", code)
	}
}

// full_only: false
func TestAbandonmentPlanRejectsUnformablePathsBeforeExecutor(t *testing.T) {
	for _, path := range []struct{ name, value string }{
		{"root", "/"},
		{"nul", "/private-sentinel\x00plan"},
		{"invalid-utf8", "/private-sentinel\xffplan"},
		{"overlength", "/" + strings.Repeat("a", 4096)},
	} {
		for _, structured := range []bool{false, true} {
			mode := "human"
			if structured {
				mode = "json"
			}
			t.Run(path.name+"/"+mode, func(t *testing.T) {
				args := []string{"plan", "--source=source.json", "--target=" + strings.Repeat("01", 32), "--out", path.value}
				if structured {
					args = append(args, "--json")
				}
				var output, diagnostic bytes.Buffer
				calls := 0
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				code := runAbandonWithExecutor(ctx, args, &output, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult {
					calls++
					return compositionfull.AbandonmentResult{}
				})
				body := output.String()
				if !structured {
					if code != 2 || calls != 0 || !strings.HasPrefix(body, "abandon-plan: refused\n") || !strings.Contains(body, "Admission: dispatch / invalid-input.\n") || strings.Contains(body+diagnostic.String(), "private-sentinel") {
						t.Fatal("invalid plan path reached executor or lost human refusal", code, calls, body)
					}
					return
				}
				var result struct {
					Operation string                               `json:"operation_kind"`
					State     string                               `json:"state_result"`
					Identity  struct{ Schema, Stage, Code string } `json:"request_identity"`
					Payload   json.RawMessage                      `json:"payload"`
				}
				if code != 2 || calls != 0 || json.Unmarshal([]byte(body), &result) != nil || result.Operation != "abandon-plan" || result.State != "refused" || result.Identity.Schema != "PreAdmissionRequestIdentity/v1" || result.Identity.Stage != "dispatch" || result.Identity.Code != "invalid-input" || string(result.Payload) != "null" || strings.Contains(output.String()+diagnostic.String(), "private-sentinel") {
					t.Fatal("invalid plan path reached executor or lost refusal", code, calls)
				}
			})
		}
	}
}
