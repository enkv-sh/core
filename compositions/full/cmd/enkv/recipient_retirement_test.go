package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func recipientRetirementArguments(path string) []string {
	return []string{"--source", path, "--out", filepath.Join(filepath.Dir(path), "successor", "configuration.json"), "--source-format", "json", "--recipient", "exact-reference", "--json", "--log-level", "off"}
}

// full_only: false
func TestRecipientRetirementCommandRequiresOneExactReference(t *testing.T) {
	for _, row := range []struct {
		name string
		tail []string
	}{
		{"duplicate-recipient", []string{"--recipient=exact-reference"}},
		{"different-recipient", []string{"--recipient=another-reference"}},
		{"duplicate-source", []string{"--source=/other"}},
		{"duplicate-format", []string{"--source-format=yaml"}},
		{"duplicate-json", []string{"--json=false"}},
		{"duplicate-log-level", []string{"--log-level=off"}},
		{"duplicate-telemetry", []string{"--telemetry-config=", "--telemetry-config="}},
		{"entry-name", []string{"--name=entry"}},
		{"creation-mode", []string{"--mode=current"}},
		{"display", []string{"--display-name=label"}},
		{"output", []string{"--out=/other"}},
		{"unknown", []string{"--private-argument-sentinel"}},
		{"positional", []string{"private-positional-sentinel"}},
		{"separator-positional", []string{"--", "private-positional-sentinel"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := append(recipientRetirementArguments(filepath.Join(t.TempDir(), "source.json")), row.tail...)
			assertSecretAccessGrammarRefusal(t, contract.OperationRetireRecipientIdentity, args)
		})
	}
	for _, row := range []struct {
		name, source, format string
		reference            []string
	}{
		{"missing-reference", "/absolute/source", "json", nil},
		{"empty-reference", "/absolute/source", "json", []string{"--recipient", ""}},
		{"long-reference", "/absolute/source", "json", []string{"--recipient", strings.Repeat("r", 257)}},
		{"invalid-reference", "/absolute/source", "json", []string{"--recipient", string([]byte{255})}},
		{"empty-source", "", "json", []string{"--recipient", "exact"}},
		{"root-source", "/", "json", []string{"--recipient", "exact"}},
		{"invalid-source", "/" + string([]byte{255}), "json", []string{"--recipient", "exact"}},
		{"nul-source", "/private\x00source", "json", []string{"--recipient", "exact"}},
		{"missing-format", "/absolute/source", "", []string{"--recipient", "exact"}},
		{"automatic-format", "/absolute/source", "automatic", []string{"--recipient", "exact"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := append([]string{"--out", "/absolute-successor/configuration.json", "--source", row.source, "--source-format", row.format, "--json"}, row.reference...)
			assertSecretAccessGrammarRefusal(t, contract.OperationRetireRecipientIdentity, args)
		})
	}
}

// full_only: false
func TestRecipientRetirementCommandPreservesExactReferenceAndBlockerFacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, reference := range []string{"exact-reference", "a/\n雪", strings.Repeat("r", 256)} {
		for _, structured := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "source.yaml")
			args := []string{"--source", path, "--out", filepath.Join(filepath.Dir(path), "successor", "configuration.json"), "--source-format", "yaml", "--recipient", reference, "--log-level", "off"}
			if structured {
				args = append(args, "--json")
			}
			var out, diagnostic bytes.Buffer
			calls := 0
			code := runAccessMutationWithExecutor(ctx, contract.OperationRetireRecipientIdentity, args, &out, &diagnostic, func(_ context.Context, kind uint16, request contract.ID, command accessMutationCommand) compositionfull.MaintenanceCommandResult {
				calls++
				if kind != contract.OperationRetireRecipientIdentity || request.IsZero() || command != (accessMutationCommand{source: path, output: filepath.Join(filepath.Dir(path), "successor", "configuration.json"), format: configuration.YAML, reference: reference}) {
					t.Fatal("retirement command changed exact target")
				}
				r, err := compositionfull.NewRecipientRetirementRefusal(configuration.YAML)
				if err != nil {
					t.Fatal(err)
				}
				r.RequestID = request
				r.PreAdmission.RequestNonce = request
				r.PreAdmission.Stage = "retire"
				r.RetirementBlockers = &core.RecipientRetirementBlockers{Total: 1, Rows: []core.RecipientRetirementBlocker{{MaterialID: contract.ID{1}, OwnerKind: contract.GeneratedParentSupportKind, OwnerID: contract.ID{2}}}}
				return maintenanceCLIResult(r)
			})
			if code != 2 || calls != 1 || !bytes.Contains(out.Bytes(), []byte("retire-recipient-identity")) || !bytes.Contains(out.Bytes(), []byte("recipient_retirement_blockers")) || bytes.Contains(out.Bytes(), []byte("retirement-pending")) {
				t.Fatal("retirement lost exact blocked result", code, out.String(), diagnostic.String())
			}
			if structured {
				var v struct {
					State    string `json:"state_result"`
					Payload  any
					Blockers struct {
						Total uint32
						Rows  []map[string]any
					} `json:"recipient_retirement_blockers"`
				}
				if json.Unmarshal(out.Bytes(), &v) != nil || v.State != "refused" || v.Payload != nil || v.Blockers.Total != 1 || len(v.Blockers.Rows) != 1 || v.Blockers.Rows[0]["owner_kind"] != "parent" {
					t.Fatal("retirement command changed blocker payload")
				}
			}
		}
	}
}

// full_only: false
func TestRecipientRetirementDispatchRefusalPreservesReadOnlySource(t *testing.T) {
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
	args := append([]string{"recipients", "retire"}, recipientRetirementArguments(path)...)
	var out, diagnostic bytes.Buffer
	code := run(args, &out, &diagnostic)
	var v struct {
		Operation string         `json:"operation_kind"`
		State     string         `json:"state_result"`
		Identity  map[string]any `json:"request_identity"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || code != 2 || v.Operation != "retire-recipient-identity" || v.State != "refused" || v.Identity["stage"] != "capture" {
		t.Fatal("retirement dispatch lost safe refusal", code, err, out.String())
	}
	for _, forbidden := range []string{path, "secret-sentinel", "raw-parser-error-sentinel"} {
		if bytes.Contains(out.Bytes(), []byte(forbidden)) || bytes.Contains(diagnostic.Bytes(), []byte(forbidden)) {
			t.Fatal("retirement disclosed private source")
		}
	}
	actual, err := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if err != nil || statErr != nil || !bytes.Equal(actual, body) || info.Mode().Perm() != 0444 {
		t.Fatal("retirement changed refused source", err, statErr)
	}
}
