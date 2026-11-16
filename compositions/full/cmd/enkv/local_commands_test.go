package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
)

func localCommandFields(t *testing.T, body []byte, structured bool) map[string]json.RawMessage {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal("invalid local result", structured, err)
	}
	localCommandKeys(t, fields, "local_delivery", "local_edit", "outcome", "schema", "target", "warning_summary")
	if string(fields["schema"]) != `"LocalEditResult/v1"` {
		t.Fatal("recognized local action did not return LocalEditResult/v1")
	}
	var delivery map[string]json.RawMessage
	if err := json.Unmarshal(fields["local_delivery"], &delivery); err != nil {
		t.Fatal("invalid local delivery", err)
	}
	localCommandKeys(t, delivery, "cleanup_failed", "editable_path", "generated_path", "outcome", "readback", "recovery_source")
	return fields
}

func localCommandArguments(action, source string) []string {
	args := []string{"--source", source, "--source-format", "json", "--json"}
	switch action {
	case "domain-rename":
		return append(args, "--name", "staging")
	case "recipient-preparation":
		return append(args, "--recipient", "member", "--mode", "create", "--display-name", "", "--encryption-key", "exact-resource")
	case "recipient-reference-rename":
		return append(args, "--recipient", "member", "--new-reference", "reader")
	case "recovery":
		return args
	}
	panic("invalid test action")
}

// full_only: false
func TestLocalCommandGrammarRejectsBeforeExecutor(t *testing.T) {
	for _, action := range []string{"domain-rename", "recipient-preparation", "recipient-reference-rename", "recovery"} {
		t.Run(action, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "source.json")
			for _, row := range []struct {
				name string
				tail []string
			}{
				{"duplicate-source", []string{"--source=" + source}},
				{"duplicate-format", []string{"--source-format=json"}},
				{"duplicate-json", []string{"--json=false"}},
				{"duplicate-log-level", []string{"--log-level=warn", "--log-level=warn"}},
				{"duplicate-telemetry", []string{"--telemetry-config=", "--telemetry-config="}},
				{"unknown", []string{"--private-argument-sentinel"}},
				{"positional", []string{"private-positional-sentinel"}},
				{"separator-positional", []string{"--", "private-positional-sentinel"}},
			} {
				t.Run(row.name, func(t *testing.T) {
					args := append(localCommandArguments(action, source), row.tail...)
					assertLocalGrammarRefusal(t, action, args)
				})
			}
			for _, flag := range map[string][]string{
				"domain-rename": {"name"}, "recipient-preparation": {"recipient", "mode", "display-name", "encryption-key"},
				"recipient-reference-rename": {"recipient", "new-reference"},
			}[action] {
				t.Run("duplicate-"+flag, func(t *testing.T) {
					value := "extra"
					assertLocalGrammarRefusal(t, action, append(localCommandArguments(action, source), "--"+flag+"="+value))
				})
			}
		})
	}
	for _, row := range []struct {
		name, action string
		flags        []string
	}{
		{"rename-empty", "domain-rename", []string{"--name", ""}},
		{"rename-missing", "domain-rename", nil},
		{"recipient-empty", "recipient-preparation", []string{"--recipient", "", "--mode", "create"}},
		{"mode-missing", "recipient-preparation", []string{"--recipient", "member"}},
		{"mode-unknown", "recipient-preparation", []string{"--recipient", "member", "--mode", "refresh"}},
		{"display-unpaired", "recipient-preparation", []string{"--recipient", "member", "--mode", "create", "--display-name", ""}},
		{"key-unpaired", "recipient-preparation", []string{"--recipient", "member", "--mode", "create", "--encryption-key", "exact-resource"}},
		{"key-empty", "recipient-preparation", []string{"--recipient", "member", "--mode", "create", "--display-name", "", "--encryption-key", ""}},
		{"declaration-current", "recipient-preparation", []string{"--recipient", "member", "--mode", "current", "--display-name", "", "--encryption-key", "exact-resource"}},
		{"old-reference-empty", "recipient-reference-rename", []string{"--recipient", "", "--new-reference", "reader"}},
		{"new-reference-empty", "recipient-reference-rename", []string{"--recipient", "member", "--new-reference", ""}},
		{"reference-missing", "recipient-reference-rename", []string{"--recipient", "member"}},
		{"recovery-target", "recovery", []string{"--name", "private-target-sentinel"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := append([]string{"--source", filepath.Join(t.TempDir(), "source.json"), "--source-format", "json", "--json"}, row.flags...)
			assertLocalGrammarRefusal(t, row.action, args)
		})
	}
	for _, row := range []struct{ name, source, format string }{
		{"source-empty", "", "json"},
		{"source-root", "/", "json"}, {"source-nul", "/private-path-sentinel\x00", "json"}, {"source-invalid-utf8", "/" + string([]byte{255}), "json"},
		{"source-over-bound", "/" + strings.Repeat("x", 4096), "json"}, {"format-empty", "/source.json", ""}, {"format-unknown", "/source.json", "toml"},
	} {
		t.Run(row.name, func(t *testing.T) {
			assertLocalGrammarRefusal(t, "recovery", []string{"--source", row.source, "--source-format", row.format, "--json"})
		})
	}
}

func assertLocalGrammarRefusal(t *testing.T, action string, args []string) {
	t.Helper()
	var out, diagnostic bytes.Buffer
	calls := 0
	code := runLocalEditWithExecutor(t.Context(), action, args, &out, &diagnostic, func(context.Context, localEditCommand) (*compositionfull.LocalEditResult, error) {
		calls++
		return compositionfull.NewLocalEditRefusal(action)
	})
	if code != 2 || calls != 0 {
		t.Fatal("invalid grammar reached executor", code, calls)
	}
	fields := localCommandFields(t, out.Bytes(), true)
	if string(fields["local_edit"]) != `"`+action+`"` || string(fields["outcome"]) != `"refused"` || string(fields["target"]) != "null" {
		t.Fatal("invalid grammar lost closed action refusal")
	}
	for _, private := range []string{"private-argument-sentinel", "private-positional-sentinel", "private-target-sentinel", "private-path-sentinel"} {
		if strings.Contains(out.String()+diagnostic.String(), private) {
			t.Fatal("invalid grammar exposed a raw argument")
		}
	}
}

// full_only: false
func TestLocalCommandPassesExactActionInputs(t *testing.T) {
	for _, action := range []string{"domain-rename", "recipient-preparation", "recipient-reference-rename", "recovery"} {
		t.Run(action, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "source.json")
			var out, diagnostic bytes.Buffer
			calls := 0
			code := runLocalEditWithExecutor(t.Context(), action, localCommandArguments(action, source), &out, &diagnostic, func(ctx context.Context, command localEditCommand) (*compositionfull.LocalEditResult, error) {
				calls++
				if ctx == nil || command.action != action || command.source != source || command.format != configuration.JSON {
					t.Fatal("command changed selected source, format or action")
				}
				switch action {
				case "domain-rename":
					if command.name != "staging" {
						t.Fatal("domain rename target changed")
					}
				case "recipient-preparation":
					if command.reference != "member" || command.preparation.Mode != compositionfull.RecipientPreparationCreate || command.preparation.Declaration == nil || command.preparation.Declaration.DisplayName != "" || command.preparation.Declaration.EncryptionSelector != "exact-resource" {
						t.Fatal("creation mode or explicitly empty display name changed")
					}
				case "recipient-reference-rename":
					if command.reference != "member" || command.newReference != "reader" {
						t.Fatal("recipient reference target changed")
					}
				}
				return compositionfull.NewLocalEditRefusal(action)
			})
			if code != 2 || calls != 1 {
				t.Fatal("valid grammar did not enter exact action once", code, calls)
			}
		})
	}
	for _, mode := range []compositionfull.RecipientPreparationMode{compositionfull.RecipientPreparationCurrent, compositionfull.RecipientPreparationCreate} {
		t.Run(string(mode)+"-declared-recipient", func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			calls := 0
			args := []string{"--source", filepath.Join(t.TempDir(), "source.json"), "--source-format", "json", "--recipient", "member", "--mode", string(mode)}
			code := runLocalEditWithExecutor(t.Context(), "recipient-preparation", args, &out, &diagnostic, func(_ context.Context, command localEditCommand) (*compositionfull.LocalEditResult, error) {
				calls++
				if command.reference != "member" || command.preparation.Mode != mode || command.preparation.Declaration != nil {
					t.Fatal("existing declaration selected a different preparation mode or added a declaration")
				}
				return compositionfull.NewLocalEditRefusal("recipient-preparation")
			})
			if code != 2 || calls != 1 {
				t.Fatal("valid declared recipient did not enter action", code, calls)
			}
		})
	}
}

// full_only: false
func TestLocalCommandTelemetryRefusalAndDiagnosticsExcludeRawInput(t *testing.T) {
	for _, action := range []string{"domain-rename", "recipient-preparation", "recipient-reference-rename", "recovery"} {
		for _, condition := range []string{"telemetry-config", "log-level", "operation-error"} {
			t.Run(action+"/"+condition, func(t *testing.T) {
				args := localCommandArguments(action, filepath.Join(t.TempDir(), "private-source-sentinel.json"))
				switch condition {
				case "telemetry-config":
					args = append(args, "--telemetry-config", filepath.Join(t.TempDir(), "private-telemetry-sentinel.json"))
				case "log-level":
					args = append(args, "--log-level", "private-log-level-sentinel")
				}
				var out, diagnostic bytes.Buffer
				calls := 0
				code := runLocalEditWithExecutor(t.Context(), action, args, &out, &diagnostic, func(context.Context, localEditCommand) (*compositionfull.LocalEditResult, error) {
					calls++
					result, err := compositionfull.NewLocalEditRefusal(action)
					return result, errors.Join(err, errors.New("private-operation-error-sentinel"))
				})
				wantCalls := 0
				if condition == "operation-error" {
					wantCalls = 1
				}
				if code != 2 || calls != wantCalls {
					t.Fatal("telemetry refusal or operation error entered wrong boundary", code, calls)
				}
				localCommandFields(t, out.Bytes(), true)
				for _, private := range []string{"private-source-sentinel", "private-telemetry-sentinel", "private-log-level-sentinel", "private-operation-error-sentinel"} {
					if strings.Contains(out.String()+diagnostic.String(), private) {
						t.Fatal("raw input or error escaped local command")
					}
				}
			})
		}
	}
}

// full_only: false
func TestLocalCommandOutputFailureRefusesWithoutRetry(t *testing.T) {
	for _, structured := range []bool{false, true} {
		for _, writer := range []io.Writer{commandShortWriter{}, localCommandErrorWriter{}} {
			args := []string{"--source", "/source.json", "--source-format", "json"}
			if structured {
				args = append(args, "--json")
			}
			calls := 0
			var diagnostic bytes.Buffer
			code := runLocalEditWithExecutor(t.Context(), "recovery", args, writer, &diagnostic, func(context.Context, localEditCommand) (*compositionfull.LocalEditResult, error) {
				calls++
				return compositionfull.NewLocalEditRefusal("recovery")
			})
			if code != 2 || calls != 1 || !strings.Contains(diagnostic.String(), "output failed") || strings.Contains(diagnostic.String(), "private-writer-error-sentinel") {
				t.Fatal("output failure retried or exposed raw error", code, calls)
			}
		}
	}
}

type localCommandErrorWriter struct{}

func (localCommandErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("private-writer-error-sentinel")
}

func localCommandKeys(t *testing.T, fields map[string]json.RawMessage, want ...string) {
	t.Helper()
	got := make([]string, 0, len(fields))
	for key := range fields {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("local result has wrong closed field set", got, want)
	}
}

// full_only: false
func TestLocalCommandsDispatchClosedRefusalAndEquivalentRenderers(t *testing.T) {
	for _, row := range []struct {
		name, action string
		args         []string
	}{
		{"domain", "domain-rename", []string{"rename", "--name", "staging"}},
		{"prepare", "recipient-preparation", []string{"recipients", "add", "--recipient", "member", "--mode", "current"}},
		{"reference", "recipient-reference-rename", []string{"recipients", "rename", "--recipient", "member", "--new-reference", "reader"}},
		{"recovery", "recovery", []string{"recover"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := append(append([]string{}, row.args...), "--source", filepath.Join(t.TempDir(), "absent.json"), "--source-format", "json")
			for _, structured := range []bool{false, true} {
				selected := append([]string{}, args...)
				if structured {
					selected = append(selected, "--json")
				}
				var out, diagnostic bytes.Buffer
				if code := run(selected, &out, &diagnostic); code != 2 {
					t.Fatal("missing source did not refuse", code)
				}
				if !structured {
					label := map[string]string{"domain-rename": "Domain rename", "recipient-preparation": "Recipient preparation", "recipient-reference-rename": "Recipient reference rename", "recovery": "Local edit recovery"}[row.action]
					if !strings.HasPrefix(out.String(), label+": refused\n") || !strings.Contains(out.String(), "Local files: not-recorded\n") || json.Valid(out.Bytes()) {
						t.Fatal("human refusal lost the action or local outcome", out.String())
					}
					continue
				}
				fields := localCommandFields(t, out.Bytes(), true)
				if string(fields["local_edit"]) != `"`+row.action+`"` || string(fields["outcome"]) != `"refused"` || string(fields["target"]) != "null" {
					t.Fatal("refusal lost the recognized action or exposed an unadmitted target")
				}
			}
		})
	}
}
