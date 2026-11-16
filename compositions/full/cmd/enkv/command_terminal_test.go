package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestApplyTerminalUsesEstablishedRefusal(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	var out, diagnostic bytes.Buffer
	calls := 0
	code := runApplyWithExecutor(t.Context(), []string{"--source", filepath.Join(t.TempDir(), "source.yaml"), "--json", "--log-level", "debug"}, &out, &diagnostic,
		func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
			calls++
			r, err := compositionfull.NewApplyRefusal(configuration.YAML)
			if err != nil {
				t.Fatal(err)
			}
			return compositionfull.ConfigurationApplyResult{PublicApplyResult: r}
		})
	if code != 2 || calls != 1 || !bytes.Contains(diagnostic.Bytes(), []byte(`operation="application.invocation" event="return" result="admission_refused" reason="admission_refused"`)) {
		t.Fatalf("established refusal lost terminal classification: exit=%d calls=%d diagnostic=%s", code, calls, diagnostic.String())
	}
}

// full_only: false
func TestCapturedSourceFailureReportsSelectedPathWithoutTelemetryDisclosure(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	for _, command := range []string{"apply", "plan", "inspect", "prepare"} {
		t.Run(command, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "selected-source.json")
			if err := os.WriteFile(path, []byte(`{"schema":"wrong"}`), 0600); err != nil {
				t.Fatal(err)
			}
			option := "--source"
			if command == "plan" {
				option = "--trusted"
			}
			var out, diagnostic bytes.Buffer
			code := run([]string{command, option, path, "--json", "--log-level", "debug"}, &out, &diagnostic)
			var wire struct {
				Source map[string]any `json:"source_failure"`
			}
			if json.Unmarshal(out.Bytes(), &wire) != nil || code != 2 || wire.Source["path"] != path || bytes.Contains(diagnostic.Bytes(), []byte(path)) {
				t.Fatalf("captured path missing or disclosed to diagnostics: exit=%d stdout=%s stderr=%s", code, out.String(), diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestGeneratedSourceFailureRetainsCapturedCompanionPath(t *testing.T) {
	path, _, _, _ := setCommandPreparedSource(t)
	pair, err := configuration.Capture(t.Context(), path, configuration.JSON)
	if err != nil || pair.Generated == nil {
		t.Fatal("prepared pair was not captured", err)
	}
	generated := pair.Generated.OriginalPath()
	if err := pair.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(generated, []byte(`{"schema":"wrong"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"apply", "plan"} {
		t.Run(command, func(t *testing.T) {
			option, source := "--source", "source.generated"
			if command == "plan" {
				option, source = "--trusted", "trusted.generated"
			}
			var out, diagnostic bytes.Buffer
			code := run([]string{command, option, path, "--json", "--log-level", "off"}, &out, &diagnostic)
			var wire struct {
				Failure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
			}
			if json.Unmarshal(out.Bytes(), &wire) != nil || code != 2 || wire.Failure == nil || wire.Failure.SourceID != source || wire.Failure.Path != generated || generated == path+".generated" {
				t.Fatalf("generated failure lost its captured companion: exit=%d stdout=%s stderr=%s", code, out.String(), diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestUncapturedSourceFailureOmitsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-source.yaml")
	for _, args := range [][]string{{"apply", "--source", path}, {"apply", "--source", ""}} {
		var out, diagnostic bytes.Buffer
		args = append(args, "--json", "--log-level", "off")
		code := run(args, &out, &diagnostic)
		var wire struct {
			Failure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
		}
		if code != 2 || json.Unmarshal(out.Bytes(), &wire) != nil || wire.Failure != nil && wire.Failure.Path != "" || bytes.Contains(diagnostic.Bytes(), []byte(path)) {
			t.Fatalf("uncaptured input gained a path fact: exit=%d stdout=%s stderr=%s", code, out.String(), diagnostic.String())
		}
	}
}

// full_only: false
func TestCommandTelemetryKeepsTerminalClassesSeparate(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	for _, row := range []struct {
		name, result, reason string
		outcome              core.Outcome
		exit                 int
		cancel               bool
	}{
		{"refusal", "admission_refused", "admission_refused", core.AdmissionRefused, 2, false},
		{"unavailable", "evidence_unavailable", "evidence_unavailable", core.EvidenceUnavailable, 3, false},
		{"unknown-commit", "unresolved_commit", "uncertain", core.UnresolvedCommit, 3, false},
		{"cancellation", "cancelled", "cancelled", core.EvidenceUnavailable, 2, true},
		{"output-failed-after-success", "failure", "evidence_unavailable", core.ObservedCurrent, 2, false},
		{"unknown-and-output-failed", "unresolved_commit", "uncertain", core.UnresolvedCommit, 2, false},
		{"verified-difference", "success", "", core.ObservedCurrent, 1, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var terminal commandTerminal
			var diagnostic bytes.Buffer
			code := withCommandTelemetry(ctx, commandTelemetryOptions{logLevel: "debug", differenceIsSuccess: row.name == "verified-difference", terminal: &terminal}, &diagnostic, func() int { return 19 }, func(context.Context, io.Writer) int {
				result := core.PublicApplyResult{Result: core.Result{Outcome: row.outcome}}
				if row.cancel {
					result.Diagnostics = []contract.Diagnostic{{Outcome: contract.DiagnosticUnable, Reason: contract.ReasonCancelled}}
				}
				terminal.mutation(result)
				if row.cancel {
					cancel()
				}
				return row.exit
			})
			want := `operation="application.invocation" event="return" result="` + row.result + `" reason="` + row.reason + `"`
			if code != row.exit || !strings.Contains(diagnostic.String(), want) {
				t.Fatalf("terminal class changed: exit=%d want=%d diagnostic=%s", code, row.exit, diagnostic.String())
			}
		})
	}
	var diagnostic bytes.Buffer
	terminal := commandTerminal{result: telemetry.ResultSetupIncomplete}
	code := withCommandTelemetry(t.Context(), commandTelemetryOptions{logLevel: "debug", terminal: &terminal}, &diagnostic, func() int { return 19 }, func(context.Context, io.Writer) int { return 2 })
	if code != 2 || !strings.Contains(diagnostic.String(), `result="setup_incomplete" reason="setup_required"`) {
		t.Fatalf("known setup became uncertainty: exit=%d diagnostic=%s", code, diagnostic.String())
	}
}

// full_only: false
func TestCommandTelemetryUsesCapturedDirectory(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	selected, later := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(selected, "telemetry.json"), []byte(`{"schema_version":1,"logs":{"level":"off"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(later, "telemetry.json"), []byte("private-invalid-settings"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(later)
	calls := 0
	var diagnostic bytes.Buffer
	code := withCommandTelemetry(t.Context(), commandTelemetryOptions{configuration: "telemetry.json", directory: selected}, &diagnostic, func() int { return 19 }, func(context.Context, io.Writer) int {
		calls++
		return 0
	})
	if code != 0 || calls != 1 || diagnostic.Len() != 0 {
		t.Fatalf("relative telemetry configuration moved with cwd: exit=%d calls=%d diagnostic=%s", code, calls, diagnostic.String())
	}
}

// full_only: false
func TestSourceRefusalDoesNotSuggestCompanionForOtherMissingFields(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "source.json")
	if err := os.WriteFile(path, []byte(`{"schema":"enkv/configuration/v3"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"apply", "plan"} {
		t.Run(command, func(t *testing.T) {
			option := "--source"
			if command == "plan" {
				option = "--trusted"
			}
			var out, diagnostic bytes.Buffer
			code := run([]string{command, option, path, "--json", "--log-level", "off"}, &out, &diagnostic)
			if code != 2 || strings.Contains(diagnostic.String(), "Restore the exact generated") {
				t.Fatalf("unrelated missing field received companion advice or uncertainty: exit=%d diagnostic=%q output=%s", code, diagnostic.String(), out.String())
			}
		})
	}
}

// full_only: false
func TestGeneratedTerminalPreservesUnresolvedCommitBeforeRetainedEffects(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	for _, summary := range []uint16{contract.ReceiptEffectPending, contract.ReceiptEffectPartial, contract.ReceiptEffectUnknown} {
		result := core.PublicApplyResult{Result: core.Result{Outcome: core.UnresolvedCommit, Reason: core.WriteUncertain, CommitMayHaveOccurred: true},
			Generated: &core.GeneratedInvocationResult{StateResult: "commit-outcome-unknown", EffectSummary: summary}}
		ctx, cancel := context.WithCancel(t.Context())
		var terminal commandTerminal
		var diagnostic bytes.Buffer
		code := withCommandTelemetry(ctx, commandTelemetryOptions{logLevel: "debug", terminal: &terminal}, &diagnostic, func() int { return 19 }, func(context.Context, io.Writer) int {
			terminal.mutation(result)
			cancel()
			return compositionfull.MutationExitCode(result)
		})
		cancel()
		if code != 3 || !strings.Contains(diagnostic.String(), `result="unresolved_commit" reason="uncertain"`) {
			t.Fatalf("retained effect classification erased commit uncertainty: summary=%d exit=%d diagnostic=%s", summary, code, diagnostic.String())
		}
	}
}

// full_only: false
func TestApplyTerminalRetainsRefusalAfterOutputCancellation(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out, diagnostic bytes.Buffer
	writer := commandWriterFunc(func(p []byte) (int, error) {
		n, err := out.Write(p)
		cancel()
		return n, err
	})
	calls := 0
	code := runApplyWithExecutor(ctx, []string{"--source", filepath.Join(t.TempDir(), "source.yaml"), "--json", "--log-level", "debug"}, writer, &diagnostic,
		func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
			calls++
			r, err := compositionfull.NewApplyRefusal(configuration.YAML)
			if err != nil {
				t.Fatal(err)
			}
			return compositionfull.ConfigurationApplyResult{PublicApplyResult: r}
		})
	var wire struct {
		State string `json:"state_result"`
	}
	if code != 2 || calls != 1 || json.Unmarshal(out.Bytes(), &wire) != nil || wire.State != "refused" || !strings.Contains(diagnostic.String(), `result="admission_refused" reason="admission_refused"`) {
		t.Fatalf("output cancellation replaced an owned refusal: exit=%d calls=%d stdout=%s stderr=%s", code, calls, out.String(), diagnostic.String())
	}
}

// full_only: false
func TestOrdinaryApplyCleanupFailureHasUnavailableTerminal(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	var out, diagnostic bytes.Buffer
	calls := 0
	code := runApplyWithExecutor(t.Context(), []string{"--source", filepath.Join(t.TempDir(), "source.yaml"), "--json", "--log-level", "debug"}, &out, &diagnostic,
		func(_ context.Context, request contract.ID, _ string, _ configuration.Format, _ contract.ID, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
			calls++
			r := core.PublicApplyResult{RequestID: request, OperationID: contract.ID{1}, RequestIdentity: contract.ID{2}, DomainID: contract.ID{3}, Result: core.Result{Outcome: core.Unchanged, Evidence: core.AuthenticatedClosure, ObservedRevision: contract.ID{4}}}
			r.AddCleanupDiagnostic()
			return compositionfull.ConfigurationApplyResult{PublicApplyResult: r}
		})
	var wire struct {
		State       string `json:"state_result"`
		Diagnostics []struct{ Outcome, Reason string }
	}
	if code != 3 || calls != 1 || json.Unmarshal(out.Bytes(), &wire) != nil || wire.State != "no-op" || len(wire.Diagnostics) != 1 || wire.Diagnostics[0].Outcome != "unable to verify" || wire.Diagnostics[0].Reason != "evidence-unavailable" || !strings.Contains(diagnostic.String(), `result="evidence_unavailable" reason="evidence_unavailable"`) || strings.Contains(diagnostic.String(), "apply output failed") {
		t.Fatalf("ordinary cleanup inability became result delivery failure: exit=%d calls=%d stdout=%s stderr=%s", code, calls, out.String(), diagnostic.String())
	}
}

// full_only: false
func TestApplyTerminalUsesOwnedCancellationCause(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	for _, reason := range []contract.DiagnosticReason{contract.ReasonCancelled, contract.ReasonExpired} {
		t.Run(string(reason), func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			code := runApplyWithExecutor(t.Context(), []string{"--source", filepath.Join(t.TempDir(), "source.yaml"), "--json", "--log-level", "debug"}, &out, &diagnostic,
				func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
					r, err := compositionfull.NewApplyRefusal(configuration.YAML)
					if err != nil {
						t.Fatal(err)
					}
					r.PreAdmission.Stage, r.PreAdmission.Code = "context", string(reason)
					r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}}
					return compositionfull.ConfigurationApplyResult{PublicApplyResult: r}
				})
			if code != 2 || !json.Valid(out.Bytes()) || !strings.Contains(diagnostic.String(), `result="cancelled" reason="cancelled"`) {
				t.Fatalf("owned cancellation cause was lost: cause=%s exit=%d stdout=%s stderr=%s", reason, code, out.String(), diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestApplyPublicationTerminalUsesOwnedStageCause(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	for _, row := range []struct {
		reason, result, diagnosticReason string
		outcome                          core.Outcome
		exit                             int
	}{
		{"apply-incomplete", "admission_refused", "admission_refused", core.AdmissionRefused, 2},
		{"selection-unavailable", "evidence_unavailable", "evidence_unavailable", core.Unchanged, 3},
		{"selection-conflict", "contention", "uncertain", core.Unchanged, 2},
		{"deadline-expired", "cancelled", "cancelled", core.Unchanged, 3},
		{"apply-incomplete", "unresolved_commit", "uncertain", core.UnresolvedCommit, 3},
	} {
		t.Run(row.reason+"/"+row.result, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			calls := 0
			code := runApplyWithExecutors(t.Context(), []string{"--source", "/source.json", "--publish", "--json", "--log-level", "debug"}, &out, &diagnostic, nil,
				func(_ context.Context, applyRequest, publicationRequest contract.ID, _ string, _ configuration.Format, _ contract.ID, _ compositionfull.ApplyPublicationOptions, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
					calls++
					result := applyPublicationCLIResult(applyRequest, publicationRequest, false)
					switch row.outcome {
					case core.AdmissionRefused:
						refused, err := compositionfull.NewApplyRefusal(configuration.JSON)
						if err != nil {
							t.Fatal(err)
						}
						refused.RequestID = applyRequest
						result.Apply = refused
					case core.UnresolvedCommit:
						result.Apply.Result = core.Result{Outcome: core.UnresolvedCommit, Reason: core.WriteUncertain, CommitMayHaveOccurred: true, RequestedRevision: contract.ID{9}}
					}
					result.Publication = core.ApplyPublicationStage{Stage: "unstarted", Reason: row.reason}
					return compositionfull.ConfigurationApplyPublicationResult{PublicApplyPublicationResult: result}
				})
			var wire struct {
				Publication struct{ Stage, Reason string }
			}
			want := `result="` + row.result + `" reason="` + row.diagnosticReason + `"`
			if code != row.exit || calls != 1 || json.Unmarshal(out.Bytes(), &wire) != nil || wire.Publication.Stage != "unstarted" || wire.Publication.Reason != row.reason || !strings.Contains(diagnostic.String(), want) {
				t.Fatalf("owned publication stage cause was lost: exit=%d calls=%d stdout=%s stderr=%s", code, calls, out.String(), diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestGeneratedTerminalRetainsPendingEffectsAfterOwnedCancellation(t *testing.T) {
	for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(name, "")
	}
	for _, row := range []struct {
		state   string
		summary uint16
	}{
		{"effect-pending", contract.ReceiptEffectPending},
		{"effect-partial", contract.ReceiptEffectPartial},
	} {
		for _, reason := range []contract.DiagnosticReason{contract.ReasonCancelled, contract.ReasonExpired} {
			t.Run(row.state+"/"+string(reason), func(t *testing.T) {
				result := core.PublicApplyResult{Result: core.Result{Outcome: core.Unchanged}, Generated: &core.GeneratedInvocationResult{StateResult: row.state, EffectSummary: row.summary}, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}}}
				var terminal commandTerminal
				var diagnostic bytes.Buffer
				code := withCommandTelemetry(t.Context(), commandTelemetryOptions{logLevel: "debug", terminal: &terminal}, &diagnostic, func() int { return 19 }, func(context.Context, io.Writer) int {
					terminal.mutation(result)
					return compositionfull.MutationExitCode(result)
				})
				if code != 3 || !strings.Contains(diagnostic.String(), `result="evidence_unavailable" reason="evidence_unavailable"`) {
					t.Fatalf("owned cancellation hid retained effect uncertainty: exit=%d diagnostic=%s", code, diagnostic.String())
				}
			})
		}
	}
}
