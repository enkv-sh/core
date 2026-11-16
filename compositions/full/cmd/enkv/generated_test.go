package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func generatedCLIRefusal() compositionfull.ConfigurationApplyResult {
	r, _ := compositionfull.NewApplyRefusal(configuration.JSON)
	return compositionfull.ConfigurationApplyResult{PublicApplyResult: r}
}
func generatedCLIListRefusal(_ context.Context, id contract.ID, _ string, _ configuration.Format) compositionfull.ConfigurationGeneratedListResult {
	return compositionfull.ConfigurationGeneratedListResult{PublicGeneratedListResult: core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id}, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.ReaderRefused, FailureReason: contract.ReasonInvalidInput}}
}

// full_only: false
func TestGeneratedCLIRefusalEffectSummaries(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, operation := range []struct {
		command, effect string
		selectors       []string
	}{
		{"retire", "effect-no-change", []string{"--duty", id}},
		{"cleanup", "effect-no-change", nil},
		{"accept-retirement-risk", "not-applicable", []string{"--duty", id, "--attempt", id}},
	} {
		for _, origin := range []string{"invalid-selector", "construction"} {
			for _, format := range []string{"json", "human"} {
				t.Run(operation.command+"/"+origin+"/"+format, func(t *testing.T) {
					args := []string{operation.command, "--source", filepath.Join(t.TempDir(), "source.json"), "--source-format", "json", "--log-level", "off"}
					args = append(args, operation.selectors...)
					if origin == "invalid-selector" {
						args = append(args, "--operation", "invalid")
					}
					if format == "json" {
						args = append(args, "--json")
					}
					calls := 0
					execute := func(context.Context, contract.ID, string, configuration.Format, generatedCommandRequest) compositionfull.ConfigurationApplyResult {
						calls++
						return generatedCLIRefusal()
					}
					var output, diagnostic bytes.Buffer
					code := runGeneratedWithExecutors(t.Context(), args, &output, &diagnostic, execute, generatedCLIListRefusal)
					wantCalls := 0
					if origin == "construction" {
						wantCalls = 1
					}
					state, effect := map[string]string{"retire": "Generated retirement: refused\n", "cleanup": "Generated cleanup: refused\n", "accept-retirement-risk": "Generated retirement risk: refused\n"}[operation.command], "Effect result: "+operation.effect+"\n"
					if format == "json" {
						state, effect = `"state_result": "refused"`, `"effect_summary": "`+operation.effect+`"`
					}
					if code != 2 || calls != wantCalls || !strings.Contains(output.String(), state) || !strings.Contains(output.String(), effect) {
						t.Fatalf("refusal facts differ: exit=%d calls=%d body=%s", code, calls, output.String())
					}
				})
			}
		}
	}
}

// full_only: false
func TestApplyCLIPreservesGeneratedEpochRefusals(t *testing.T) {
	for _, refusal := range []struct {
		reason core.Reason
		state  string
	}{
		{core.StaleGeneratedEpoch, "stale-generated-epoch"},
		{core.GeneratedIntentConflict, "generated-intent-conflict"},
		{core.InvalidIntent, "refused"},
	} {
		for _, format := range []string{"json", "human"} {
			t.Run(refusal.state+"/"+format, func(t *testing.T) {
				calls := 0
				execute := func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
					calls++
					r := generatedCLIRefusal()
					r.Result.Reason = refusal.reason
					return r
				}
				args := []string{"--source", filepath.Join(t.TempDir(), "source.json"), "--source-format", "json", "--log-level", "off"}
				state := "Apply: " + refusal.state + "\n"
				if format == "json" {
					args = append(args, "--json")
					state = `"state_result": "` + refusal.state + `"`
				}
				var output, diagnostic bytes.Buffer
				code := runApplyWithExecutor(t.Context(), args, &output, &diagnostic, execute)
				if code != 2 || calls != 1 || !strings.Contains(output.String(), state) {
					t.Fatalf("generated epoch refusal differs: exit=%d calls=%d body=%s", code, calls, output.String())
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedCLIRejectsAmbiguousSelectorsBeforeExecution(t *testing.T) {
	id := strings.Repeat("a", 64)
	base := []string{"--source", filepath.Join(t.TempDir(), "absent.json"), "--source-format", "json", "--json", "--log-level", "off"}
	cases := [][]string{
		{"list", "--duty", id}, {"list", "--operation", id}, {"retire"},
		{"retire", "--duty", ""}, {"retire", "--duty", strings.Repeat("0", 64)}, {"retire", "--duty", strings.ToUpper(id)},
		{"retire", "--duty", id[:63]}, {"retire", "--duty", id, "--duty", id}, {"retire", "--duty", id, "--operation", id},
		{"retire", "--operation", ""}, {"retire", "--operation", id, "--attempt", id},
		{"accept-retirement-risk", "--duty", id}, {"accept-retirement-risk", "--attempt", id},
		{"accept-retirement-risk", "--duty", id, "--attempt", id, "--operation", id},
		{"cleanup", "--duty", id}, {"cleanup", "--hazard", id}, {"cleanup", "--operation", ""},
		{"cleanup", "--operation", id, "--operation", id}, {"cleanup", "unexpected"},
	}
	for _, row := range cases {
		t.Run(strings.Join(row, " "), func(t *testing.T) {
			args := append([]string{row[0]}, base...)
			args = append(args, row[1:]...)
			var output, diagnostic bytes.Buffer
			mutate := func(context.Context, contract.ID, string, configuration.Format, generatedCommandRequest) compositionfull.ConfigurationApplyResult {
				t.Fatal("invalid selector reached mutation")
				return compositionfull.ConfigurationApplyResult{}
			}
			list := func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationGeneratedListResult {
				t.Fatal("invalid selector reached reader")
				return compositionfull.ConfigurationGeneratedListResult{PublicGeneratedListResult: core.PublicGeneratedListResult{}}
			}
			if code := runGeneratedWithExecutors(t.Context(), args, &output, &diagnostic, mutate, list); code != 2 || !strings.Contains(output.String(), `"state_result": "refused"`) {
				t.Fatal("selector was not refused", code, output.String(), diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestGeneratedCLISelectsOnlyExactInstalledOperation(t *testing.T) {
	id, _ := parseID(strings.Repeat("a", 64))
	path := filepath.Join(t.TempDir(), "read only source.json")
	for _, row := range []struct {
		name                     string
		flags                    []string
		kind                     uint16
		operation, duty, attempt contract.ID
	}{
		{"retire", []string{"--duty", idText(id)}, contract.OperationRetireGeneratedGeneration, contract.ID{}, id, contract.ID{}},
		{"retire", []string{"--operation", idText(id)}, contract.OperationRetireGeneratedGeneration, id, contract.ID{}, contract.ID{}},
		{"accept-retirement-risk", []string{"--duty", idText(id), "--attempt", idText(id)}, contract.OperationAcceptGeneratedRetirementResidue, contract.ID{}, id, id},
		{"cleanup", nil, contract.OperationCleanOwnedFailureResidue, contract.ID{}, contract.ID{}, contract.ID{}},
		{"cleanup", []string{"--operation", idText(id)}, contract.OperationCleanOwnedFailureResidue, id, contract.ID{}, contract.ID{}},
	} {
		t.Run(row.name+strings.Join(row.flags, ""), func(t *testing.T) {
			calls := 0
			execute := func(_ context.Context, nonce contract.ID, gotPath string, format configuration.Format, q generatedCommandRequest) compositionfull.ConfigurationApplyResult {
				calls++
				if nonce.IsZero() || gotPath != path || format != configuration.JSON || q.kind != row.kind || q.operation != row.operation || q.duty != row.duty || q.attempt != row.attempt {
					t.Fatal("selector or literal path changed", q)
				}
				return generatedCLIRefusal()
			}
			args := append([]string{row.name, "--source", path, "--source-format", "json", "--json", "--log-level", "off"}, row.flags...)
			var output, diagnostic bytes.Buffer
			if code := runGeneratedWithExecutors(t.Context(), args, &output, &diagnostic, execute, generatedCLIListRefusal); code != 2 || calls != 1 || !strings.Contains(output.String(), `"state_result": "refused"`) {
				t.Fatal("installed dispatch changed", code, calls, output.String(), diagnostic.String())
			}
		})
	}
	calls := 0
	list := func(ctx context.Context, nonce contract.ID, got string, format configuration.Format) compositionfull.ConfigurationGeneratedListResult {
		calls++
		if got != path || format != configuration.JSON {
			t.Fatal("list source changed")
		}
		return generatedCLIListRefusal(ctx, nonce, got, format)
	}
	var output, diagnostic bytes.Buffer
	if code := runGeneratedWithExecutors(t.Context(), []string{"list", "--source", path, "--source-format", "json", "--json", "--log-level", "off"}, &output, &diagnostic, executeGeneratedMutation, list); code != 2 || calls != 1 {
		t.Fatal("list did not use reader", code, calls)
	}
}

// full_only: false
func TestApplyCLIExactContinuationSelector(t *testing.T) {
	id, _ := parseID(strings.Repeat("b", 64))
	base := []string{"--source", filepath.Join(t.TempDir(), "source.json"), "--source-format", "json", "--json", "--log-level", "off"}
	for _, selectors := range [][]string{{"--operation", ""}, {"--operation", strings.Repeat("0", 64)}, {"--operation", strings.ToUpper(idText(id))}, {"--operation", idText(id), "--operation", idText(id)}} {
		var output, diagnostic bytes.Buffer
		execute := func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
			t.Fatal("invalid apply continuation reached facade")
			return compositionfull.ConfigurationApplyResult{}
		}
		if code := runApplyWithExecutor(t.Context(), append(append([]string{}, base...), selectors...), &output, &diagnostic, execute); code != 2 {
			t.Fatal("invalid apply continuation accepted", code)
		}
	}
	for _, continuation := range []bool{false, true} {
		calls := 0
		execute := func(_ context.Context, nonce contract.ID, path string, format configuration.Format, operation contract.ID, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
			calls++
			if nonce.IsZero() || path != base[1] || format != configuration.JSON || continuation != (operation == id) || !continuation && !operation.IsZero() {
				t.Fatal("apply request changed")
			}
			return generatedCLIRefusal()
		}
		args := append([]string{}, base...)
		if continuation {
			args = append(args, "--operation", idText(id))
		}
		var output, diagnostic bytes.Buffer
		if code := runApplyWithExecutor(t.Context(), args, &output, &diagnostic, execute); code != 2 || calls != 1 {
			t.Fatal("apply dispatch changed", code, calls)
		}
	}
}

// full_only: false
func TestGeneratedCLIOutputFailureDoesNotRepeatMutation(t *testing.T) {
	calls := 0
	execute := func(context.Context, contract.ID, string, configuration.Format, generatedCommandRequest) compositionfull.ConfigurationApplyResult {
		calls++
		return generatedCLIRefusal()
	}
	var diagnostic bytes.Buffer
	code := runGeneratedWithExecutors(t.Context(), []string{"cleanup", "--source", filepath.Join(t.TempDir(), "source.json"), "--source-format", "json", "--json", "--log-level", "off"}, commandShortWriter{}, &diagnostic, execute, generatedCLIListRefusal)
	if code != 2 || calls != 1 || !strings.Contains(diagnostic.String(), "output failed") {
		t.Fatal("failed output repeated or succeeded", code, calls, diagnostic.String())
	}
}

// full_only: false
func TestGeneratedCLIProcessRefusalPreservesReadOnlySource(t *testing.T) {
	if path := os.Getenv("ENKV_GENERATED_CLI_SOURCE"); path != "" {
		command := os.Getenv("ENKV_GENERATED_CLI_COMMAND")
		args := []string{"generated", command, "--source", path, "--source-format", "json", "--json", "--log-level", "off"}
		if command == "retire" {
			args = append(args, "--duty", strings.Repeat("a", 64))
		}
		if command == "accept-retirement-risk" {
			args = append(args, "--duty", strings.Repeat("a", 64), "--attempt", strings.Repeat("b", 64))
		}
		os.Exit(run(args, os.Stdout, os.Stderr))
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "literal source.json")
	original := []byte(`{"private-sentinel":"never-disclose"}`)
	if err := os.WriteFile(path, original, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"list", "retire", "accept-retirement-risk", "cleanup"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestGeneratedCLIProcessRefusalPreservesReadOnlySource$")
			child.Env = append(os.Environ(), "ENKV_GENERATED_CLI_SOURCE="+path, "ENKV_GENERATED_CLI_COMMAND="+command)
			var stdout, stderr bytes.Buffer
			child.Stdout, child.Stderr = &stdout, &stderr
			err := child.Run()
			body := stdout.Bytes()
			exit, ok := err.(*exec.ExitError)
			var wire struct {
				Failure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
			}
			if !ok || exit.ExitCode() != 2 || !bytes.Contains(body, []byte(`"state_result": "refused"`)) || json.Unmarshal(body, &wire) != nil || wire.Failure == nil || wire.Failure.Path != path || bytes.Contains(body, []byte("private-sentinel")) || bytes.Contains(body, []byte("never-disclose")) || bytes.Contains(stderr.Bytes(), []byte("private-sentinel")) || bytes.Contains(stderr.Bytes(), []byte("never-disclose")) || bytes.Contains(stderr.Bytes(), []byte(path)) {
				t.Fatal("unsafe installed process refusal", err, string(body))
			}
			got, err := os.ReadFile(path)
			entries, readErr := os.ReadDir(dir)
			if err != nil || readErr != nil || !bytes.Equal(got, original) || len(entries) != 1 {
				t.Fatal("command changed read-only source", err, readErr)
			}
		})
	}
}

// full_only: false
func TestMutationExitUsesGeneratedFactsAndDiagnostics(t *testing.T) {
	for _, row := range []struct {
		state   string
		summary uint16
		want    int
	}{
		{"success", contract.ReceiptEffectComplete, 0}, {"no-op", contract.ReceiptEffectNoChange, 0}, {"possible-live-residue-accepted", contract.ReceiptEffectNotApplicable, 0},
		{"exact-resume", contract.ReceiptEffectComplete, 0},
		{"retirement-pending", contract.ReceiptEffectNoChange, 3}, {"effect-pending", contract.ReceiptEffectPending, 3},
		{"effect-partial", contract.ReceiptEffectPartial, 3}, {"effect-unknown", contract.ReceiptEffectUnknown, 3},
		{"effect-terminal-failure", contract.ReceiptEffectFailed, 2}, {"success", contract.ReceiptEffectMixedTerminal, 2},
		{"contention", contract.ReceiptEffectNoChange, 3}, {"commit-outcome-unknown", contract.ReceiptEffectUnknown, 3},
		{"positive-defect", contract.ReceiptEffectNotApplicable, 2}, {"unavailable", contract.ReceiptEffectNotApplicable, 3},
		{"refused", contract.ReceiptEffectNotApplicable, 2}, {"snapshot-size-refusal", contract.ReceiptEffectNotApplicable, 2},
		{"invented-state", contract.ReceiptEffectNotApplicable, 2},
	} {
		r := core.PublicApplyResult{Result: core.Result{Outcome: core.ObservedCurrent}, Generated: &core.GeneratedInvocationResult{StateResult: row.state, EffectSummary: row.summary}}
		if got := compositionfull.MutationExitCode(r); got != row.want {
			t.Fatal("selected end was mistaken for success", row, got)
		}
	}
	r := core.PublicApplyResult{Result: core.Result{Outcome: core.ObservedCurrent}, Diagnostics: []contract.Diagnostic{{Outcome: contract.DiagnosticUnable}}}
	if compositionfull.MutationExitCode(r) != 3 {
		t.Fatal("unavailable diagnostic became success")
	}
	r.Result = core.Result{Outcome: core.UnresolvedCommit, CommitMayHaveOccurred: true}
	r.Generated = &core.GeneratedInvocationResult{StateResult: "success", EffectSummary: contract.ReceiptEffectComplete}
	if compositionfull.MutationExitCode(r) != 3 {
		t.Fatal("candidate facts promoted unknown commit")
	}
}
