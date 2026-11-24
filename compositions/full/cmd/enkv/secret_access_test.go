package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func secretAccessArguments(operation uint16, path string) []string {
	args := []string{"--source", path, "--out", filepath.Join(filepath.Dir(path), "successor", "configuration.json"), "--source-format", "json", "--name", "", "--json", "--log-level", "off"}
	return args
}

func assertSecretAccessGrammarRefusal(t *testing.T, operation uint16, args []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var out, diagnostic bytes.Buffer
	code := runAccessMutationWithExecutor(ctx, operation, args, &out, &diagnostic, func(context.Context, uint16, contract.ID, accessMutationCommand) compositionfull.MaintenanceCommandResult {
		t.Fatal("malformed command reached executor")
		return maintenanceCLIResult(core.PublicApplyResult{})
	})
	var wire struct {
		Operation string         `json:"operation_kind"`
		State     string         `json:"state_result"`
		Effect    string         `json:"effect_summary"`
		Replay    string         `json:"replay_identity"`
		Identity  map[string]any `json:"request_identity"`
	}
	want := "envelope-rekey"
	switch operation {
	case contract.OperationRetireRecipientIdentity:
		want = "retire-recipient-identity"
	}
	if err := json.Unmarshal(out.Bytes(), &wire); err != nil || code != 2 || wire.Operation != want || wire.State != "refused" || wire.Effect != "not-applicable" || wire.Replay != "none" || wire.Identity["operation_kind"] != want {
		t.Fatal("recognized invalid command lost exact safe refusal", code, err, out.String())
	}
}

// full_only: false
func TestSecretAccessCommandGrammarRefusesBeforeExecutor(t *testing.T) {
	assertSecretAccessGrammarRefusal(t, contract.OperationEnvelopeRekey, []string{"--json", "--private-argument-sentinel"})
	for _, row := range []struct {
		name string
		tail []string
	}{
		{"duplicate-source", []string{"--source=/private-source-sentinel"}},
		{"duplicate-format", []string{"--source-format=json"}},
		{"duplicate-name", []string{"--name=other"}},
		{"duplicate-json", []string{"--json=false"}},
		{"duplicate-log-level", []string{"--log-level=off"}},
		{"duplicate-telemetry", []string{"--telemetry-config=", "--telemetry-config="}},
		{"unknown", []string{"--private-argument-sentinel"}},
		{"positional", []string{"private-positional-sentinel"}},
		{"separator-positional", []string{"--", "private-positional-sentinel"}},
	} {
		t.Run(fmt.Sprintf("%d/%s", contract.OperationEnvelopeRekey, row.name), func(t *testing.T) {
			args := append(secretAccessArguments(contract.OperationEnvelopeRekey, filepath.Join(t.TempDir(), "source.json")), row.tail...)
			assertSecretAccessGrammarRefusal(t, contract.OperationEnvelopeRekey, args)
		})
	}
	for _, row := range []struct {
		name, path, format string
		nameArgs           []string
	}{
		{"missing-name", "/absolute/source", "json", nil},
		{"long-name", "/absolute/source", "json", []string{"--name", strings.Repeat("n", 257)}},
		{"invalid-name", "/absolute/source", "json", []string{"--name", string([]byte{255})}},
		{"empty-source", "", "json", []string{"--name", ""}},
		{"root-source", "/", "json", []string{"--name", ""}},
		{"nul-source", "/private\x00source", "json", []string{"--name", ""}},
		{"invalid-source", "/" + string([]byte{255}), "json", []string{"--name", ""}},
		{"missing-format", "/absolute/source", "", []string{"--name", ""}},
		{"automatic-format", "/absolute/source", "automatic", []string{"--name", ""}},
	} {
		t.Run(fmt.Sprintf("%d/%s", contract.OperationEnvelopeRekey, row.name), func(t *testing.T) {
			args := append([]string{"--out", "/absolute-successor/configuration.json", "--source", row.path, "--source-format", row.format, "--json"}, row.nameArgs...)
			assertSecretAccessGrammarRefusal(t, contract.OperationEnvelopeRekey, args)
		})
	}
	assertSecretAccessGrammarRefusal(t, contract.OperationEnvelopeRekey, append(secretAccessArguments(contract.OperationEnvelopeRekey, "/absolute/source"), "--recipient", "first"))
}

// full_only: false
func TestSecretAccessCommandsForwardExactNamesReferencesAndResults(t *testing.T) {
	for _, name := range []string{"", "a/\n雪", strings.Repeat("n", 256)} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		path := filepath.Join(t.TempDir(), "source.json")
		args := []string{"--source", path, "--out", filepath.Join(filepath.Dir(path), "successor", "configuration.json"), "--source-format", "yaml", "--name", name, "--json", "--log-level", "off"}
		calls := 0
		var out, diagnostic bytes.Buffer
		code := runAccessMutationWithExecutor(ctx, contract.OperationEnvelopeRekey, args, &out, &diagnostic, func(_ context.Context, kind uint16, request contract.ID, command accessMutationCommand) compositionfull.MaintenanceCommandResult {
			calls++
			if kind != contract.OperationEnvelopeRekey || request.IsZero() || command != (accessMutationCommand{source: path, output: filepath.Join(filepath.Dir(path), "successor", "configuration.json"), format: configuration.YAML, name: name}) {
				t.Fatal("command changed exact standalone input")
			}
			return maintenanceCLIResult(core.PublicApplyResult{RequestID: request, Result: core.Result{Outcome: core.Contention}})
		})
		cancel()
		if code != 3 || calls != 1 || !bytes.Contains(out.Bytes(), []byte(`"state_result": "contention"`)) || !bytes.Contains(out.Bytes(), []byte(`"effect_summary": "not-applicable"`)) {
			t.Fatal("command lost outcome", code, out.String(), diagnostic.String())
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var diagnostic bytes.Buffer
	if code := runAccessMutationWithExecutor(ctx, contract.OperationEnvelopeRekey, secretAccessArguments(contract.OperationEnvelopeRekey, "/absolute/source"), commandShortWriter{}, &diagnostic, func(context.Context, uint16, contract.ID, accessMutationCommand) compositionfull.MaintenanceCommandResult {
		return maintenanceCLIResult(core.PublicApplyResult{Result: core.Result{Outcome: core.EvidenceUnavailable}})
	}); code != 2 || !bytes.Contains(diagnostic.Bytes(), []byte("delivery failed")) {
		t.Fatal("partial output accepted", code)
	}
}

// full_only: false
func TestSecretAccessDispatchRefusalsPreserveReadOnlySource(t *testing.T) {
	for _, command := range [][]string{{"rekey"}} {
		path := filepath.Join(t.TempDir(), "private-source-sentinel.json")
		body := []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
		if err := os.WriteFile(path, body, 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0444); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0444 {
			t.Fatal("read-only source fixture mode differs", err)
		}
		args := append(slices.Clone(command), "--source", path, "--out", filepath.Join(filepath.Dir(path), "successor", "configuration.json"), "--source-format", "json", "--name", "", "--json", "--log-level", "off")
		var out, diagnostic bytes.Buffer
		code := run(args, &out, &diagnostic)
		want := "envelope-rekey"
		var wire struct {
			Operation string         `json:"operation_kind"`
			State     string         `json:"state_result"`
			Identity  map[string]any `json:"request_identity"`
		}
		if err := json.Unmarshal(out.Bytes(), &wire); err != nil || code != 2 || wire.Operation != want || wire.State != "refused" || wire.Identity["stage"] != "capture" {
			t.Fatal("dispatch did not retain operation refusal", code, err, out.String())
		}
		for _, forbidden := range []string{path, "secret-sentinel", "raw-parser-error-sentinel"} {
			if bytes.Contains(out.Bytes(), []byte(forbidden)) || bytes.Contains(diagnostic.Bytes(), []byte(forbidden)) {
				t.Fatal("source content escaped command")
			}
		}
		actual, err := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if err != nil || statErr != nil || !bytes.Equal(actual, body) || info.Mode().Perm() != 0444 {
			t.Fatal("standalone command changed refused source", err, statErr)
		}
	}
}

// full_only: false
func TestSecretAccessTelemetryRefusalsKeepExactOperation(t *testing.T) {
	for _, operation := range []uint16{contract.OperationEnvelopeRekey, contract.OperationRetireRecipientIdentity} {
		for _, condition := range []string{"invalid-log-level", "missing-configuration"} {
			t.Run(fmt.Sprintf("%d/%s", operation, condition), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				args := secretAccessArguments(operation, filepath.Join(t.TempDir(), "private-source-sentinel.json"))
				if operation == contract.OperationRetireRecipientIdentity {
					args = recipientRetirementArguments(filepath.Join(t.TempDir(), "private-source-sentinel.json"))
				}
				if condition == "invalid-log-level" {
					for at, value := range args {
						if value == "off" {
							args[at] = "private-level-sentinel"
						}
					}
				} else {
					args = append(args, "--telemetry-config", filepath.Join(t.TempDir(), "private-telemetry-sentinel.json"))
				}
				var out, diagnostic bytes.Buffer
				code := runAccessMutationWithExecutor(ctx, operation, args, &out, &diagnostic, func(context.Context, uint16, contract.ID, accessMutationCommand) compositionfull.MaintenanceCommandResult {
					t.Fatal("telemetry refusal entered operation")
					return maintenanceCLIResult(core.PublicApplyResult{})
				})
				var wire struct {
					Operation string         `json:"operation_kind"`
					State     string         `json:"state_result"`
					Identity  map[string]any `json:"request_identity"`
				}
				want := "envelope-rekey"
				switch operation {
				case contract.OperationRetireRecipientIdentity:
					want = "retire-recipient-identity"
				}
				if err := json.Unmarshal(out.Bytes(), &wire); err != nil || code != 2 || wire.Operation != want || wire.State != "refused" || wire.Identity["operation_kind"] != want || wire.Identity["stage"] != "dispatch" || !bytes.Contains(diagnostic.Bytes(), []byte("telemetry configuration refused")) {
					t.Fatal("telemetry refusal lost operation boundary", code, err, out.String(), diagnostic.String())
				}
				for _, forbidden := range []string{"private-source-sentinel", "private-level-sentinel", "private-telemetry-sentinel"} {
					if bytes.Contains(out.Bytes(), []byte(forbidden)) || bytes.Contains(diagnostic.Bytes(), []byte(forbidden)) {
						t.Fatal("telemetry refusal exposed private input")
					}
				}
			})
		}
	}
}

// full_only: false
func TestSecretAccessExitPreservesUncertaintyAndInterruption(t *testing.T) {
	for _, operation := range []uint16{contract.OperationEnvelopeRekey, contract.OperationRetireRecipientIdentity} {
		for _, condition := range []string{"unavailable", "pending", "pending-cleanup", "known-failure", "selected", "cancelled", "expired"} {
			t.Run(fmt.Sprintf("%d/%s", operation, condition), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				path := filepath.Join(t.TempDir(), "source.json")
				args := secretAccessArguments(operation, path)
				if operation == contract.OperationRetireRecipientIdentity {
					args = recipientRetirementArguments(path)
				}
				wantCode, wantState, wantDelivery := 3, "success", "not-attempted"
				var out, diagnostic bytes.Buffer
				calls := 0
				code := runAccessMutationWithExecutor(ctx, operation, args, &out, &diagnostic, func(_ context.Context, _ uint16, request contract.ID, _ accessMutationCommand) compositionfull.MaintenanceCommandResult {
					calls++
					result := maintenanceCLIResult(core.PublicApplyResult{RequestID: request, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}})
					switch condition {
					case "unavailable":
						result.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
						result.Delivery.Failed, wantState = true, "unavailable"
					case "pending":
						result.Delivery.Status, result.Delivery.Failed = "pending", true
						wantDelivery, wantState = "pending", "refused"
					case "pending-cleanup":
						result.Delivery.Status, result.Delivery.CleanupFailed = "pending", true
						wantDelivery, wantState = "pending", "refused"
					case "known-failure":
						result.Delivery.Failed, wantCode, wantState = true, 2, "refused"
					default:
						id := func(n byte) contract.ID { return contract.ID{n} }
						subjects := contract.GeneratorDescriptor{Digest: id(8), Length: 42, Count: 1}
						row := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: operation, StateResult: contract.ReceiptStateSuccess, EffectSummary: contract.ReceiptEffectNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical, DomainID: id(1), OperationID: id(2), RequestIdentityDigest: id(3), PredecessorRevisionID: id(4), RequestedRevisionID: id(5), ObservedRevisionID: id(5), CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: subjects, CompleteResult: contract.GeneratorDescriptor{Digest: id(9), Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
						body, err := contract.EncodeCompactMutationReceipt(row)
						if err != nil {
							t.Fatal(err)
						}
						result.PublicApplyResult = core.PublicApplyResult{RequestID: request, OperationID: id(2), RequestIdentity: id(3), DomainID: id(1), Receipt: body, Result: core.Result{Outcome: core.ObservedCurrent, RequestedRevision: id(5), ObservedRevision: id(5), Evidence: core.AuthenticatedClosure}, Payload: &core.TransitionPayload{PredecessorRevisionID: id(4), RequestedRevisionID: id(5), ObservedRevisionID: id(5), ChangedSubjects: core.ChangedSubjectCommitment{Count: 1, IdentityRootDigest: id(8)}}}
						if condition == "selected" {
							wantCode = 0
						} else {
							reason := contract.ReasonCancelled
							if condition == "expired" {
								reason = contract.ReasonExpired
							}
							result.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}}
						}
					}
					return result
				})
				var wire struct {
					State       string `json:"state_result"`
					Observed    string `json:"observed_revision_id"`
					Receipt     string `json:"receipt_hex"`
					Diagnostics []struct {
						Reason string `json:"reason"`
					} `json:"diagnostics"`
					Delivery struct {
						Status string `json:"status"`
						Failed bool   `json:"failed"`
					} `json:"delivery"`
				}
				if err := json.Unmarshal(out.Bytes(), &wire); err != nil || code != wantCode || calls != 1 || wire.State != wantState || wire.Delivery.Status != wantDelivery {
					t.Fatal("command changed completion precedence or safe body", code, wantCode, calls, err, out.String(), diagnostic.String())
				}
				if condition == "cancelled" || condition == "expired" {
					if wire.Observed == "" || wire.Receipt == "" || len(wire.Diagnostics) != 1 || wire.Diagnostics[0].Reason != condition {
						t.Fatal("interruption erased selection, receipt or diagnostic", out.String())
					}
				}
			})
		}
	}
}
