package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestCommandJSONModeFollowsParsedFlags(t *testing.T) {
	for _, command := range [][]string{{"apply"}, {"publish"}, {"rekey"}, {"recipients", "retire"}, {"generated", "list"}, {"inspect"}, {"receipt"}, {"manifest"}, {"materialize"}, {"gc", "plan"}, {"init"}, {"plan"}, {"abandon", "list"}, {"keys", "replace", "--target", "authority"}} {
		t.Run(strings.Join(command, "-"), func(t *testing.T) {
			for _, row := range []struct {
				name       string
				args       []string
				structured bool
			}{
				{"string-value", []string{"--source", "--json", "--source-format", "invalid"}, false},
				{"explicit-false-and-string-value", []string{"--json=false", "--source", "--json", "--source-format", "invalid"}, false},
				{"positional-stops-flags", []string{"unparsed", "--json"}, false},
				{"separator-stops-flags", []string{"--", "--json"}, false},
				{"parsed-true", []string{"--json", "--source-format", "invalid"}, true},
				{"parsed-false", []string{"--json=false", "--source-format", "invalid"}, false},
				{"malformed-boolean", []string{"--json=invalid"}, false},
				{"malformed-boolean-before-json", []string{"--json=invalid", "--json"}, false},
				{"malformed-boolean-after-json", []string{"--json", "--json=invalid"}, true},
				{"missing-value-after-json", []string{"--json", "--source"}, true},
				{"unknown-flag-before-json", []string{"--unknown-option", "--json"}, false},
				{"unknown-flag-after-json", []string{"--json", "--unknown-option"}, true},
				{"unknown-flag-after-false", []string{"--json=false", "--unknown-option", "--json"}, false},
			} {
				t.Run(row.name, func(t *testing.T) {
					var out, diagnostic bytes.Buffer
					args := append(append([]string(nil), command...), row.args...)
					if code := run(args, &out, &diagnostic); code != 2 || out.Len() == 0 || json.Valid(out.Bytes()) != row.structured {
						t.Fatalf("refusal ignored consumed flags: exit=%d json=%t want=%t output=%q diagnostic=%q", code, json.Valid(out.Bytes()), row.structured, out.String(), diagnostic.String())
					}
				})
			}
		})
	}
	t.Run("accepted-name-value", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source.json")
		args := []string{"--source", path, "--out", filepath.Join(filepath.Dir(path), "successor", "source.json"), "--source-format", "json", "--name", "--json", "--log-level", "off"}
		var out, diagnostic bytes.Buffer
		calls := 0
		code := runAccessMutationWithExecutor(t.Context(), contract.OperationEnvelopeRekey, args, &out, &diagnostic, func(_ context.Context, kind uint16, request contract.ID, command accessMutationCommand) compositionfull.MaintenanceCommandResult {
			calls++
			if kind != contract.OperationEnvelopeRekey || command.name != "--json" {
				t.Fatal("string value changed operation or target")
			}
			return maintenanceCLIResult(core.PublicApplyResult{RequestID: request, Result: core.Result{Outcome: core.Contention}})
		})
		if calls != 1 || code != 3 || json.Valid(out.Bytes()) || !strings.Contains(out.String(), "contention") {
			t.Fatal("string value selected structured output", calls, code, out.String(), diagnostic.String())
		}
	})
	t.Run("rejected-duplicate-preserves-prefix", func(t *testing.T) {
		for _, command := range [][]string{{"rekey"}, {"recipients", "retire"}, {"inspect"}, {"receipt"}, {"manifest"}, {"materialize"}, {"gc", "plan"}} {
			t.Run(strings.Join(command, "-"), func(t *testing.T) {
				for _, row := range []struct {
					args       []string
					structured bool
				}{
					{[]string{"--json", "--json=false"}, true},
					{[]string{"--json=false", "--json"}, false},
				} {
					var out, diagnostic bytes.Buffer
					args := append(append([]string(nil), command...), row.args...)
					if code := run(args, &out, &diagnostic); code != 2 || json.Valid(out.Bytes()) != row.structured {
						t.Fatalf("rejected duplicate changed accepted prefix: exit=%d json=%t want=%t output=%q diagnostic=%q", code, json.Valid(out.Bytes()), row.structured, out.String(), diagnostic.String())
					}
				}
			})
		}
	})
	t.Run("apply-boolean-order", func(t *testing.T) {
		for _, row := range []struct {
			args       []string
			structured bool
		}{
			{[]string{"--json", "--json=false"}, false},
			{[]string{"--json=false", "--json"}, true},
		} {
			var out, diagnostic bytes.Buffer
			if code := runApply(row.args, &out, &diagnostic); code != 2 || json.Valid(out.Bytes()) != row.structured {
				t.Fatal("parsed Boolean order changed", code, out.String(), diagnostic.String())
			}
		}
	})
	t.Run("unknown-dispatch-convention", func(t *testing.T) {
		for _, row := range []struct {
			args       []string
			structured bool
		}{
			{[]string{"unknown", "--json"}, true},
			{[]string{"unknown", "--json", "--json=false"}, false},
			{[]string{"unknown", "--", "--json"}, false},
		} {
			var out, diagnostic bytes.Buffer
			if code := run(row.args, &out, &diagnostic); code != 2 || json.Valid(out.Bytes()) != row.structured || diagnostic.String() != "unsupported command\n" {
				t.Fatal("unknown dispatch output convention changed", code, out.String(), diagnostic.String())
			}
		}
	})
}

// full_only: false
func TestCommandInputFormatFlagNames(t *testing.T) {
	for _, command := range [][]string{{"prepare"}, {"init"}, {"set"}, {"apply"}, {"publish"}, {"rename"}, {"recover"}, {"recipients", "add"}, {"recipients", "rename"}, {"recipients", "retire"}, {"rekey"}, {"generated", "list"}, {"abandon", "list"}, {"keys", "replace"}, {"inspect"}, {"receipt"}, {"manifest"}, {"materialize"}, {"plan"}} {
		t.Run(strings.Join(command, "-"), func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			args := append(append([]string(nil), command...), "--help")
			if code := run(args, &out, &diagnostic); code != 0 || diagnostic.Len() != 0 {
				t.Fatal("help failed", code, out.String(), diagnostic.String())
			}
			want := "source-format"
			if command[0] == "plan" {
				want = "trusted-format"
			}
			if !strings.Contains(out.String(), "-"+want) || strings.Contains(out.String(), "--format") || strings.Contains(out.String(), "  -format ") {
				t.Fatalf("help must name the input format exactly: %s", out.String())
			}
		})
	}
	t.Run("retired-source-flag-refuses-before-execution", func(t *testing.T) {
		var out, diagnostic bytes.Buffer
		code := runInitWithInitializer(t.Context(), []string{"--json", "--source", "/absolute/source.json", "--format", "json"}, &out, &diagnostic,
			func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error) {
				t.Fatal("retired format flag reached initialization")
				return compositionfull.InitializationResult{}, nil
			})
		if code != 2 || !json.Valid(out.Bytes()) {
			t.Fatal("retired format flag did not produce a structured refusal", code, out.String(), diagnostic.String())
		}
	})
}

// full_only: false
func TestCommandHelpListsSupportedOptions(t *testing.T) {
	for _, row := range []struct {
		args []string
		want []string
	}{
		{[]string{"--help"}, []string{"prepare", "init", "set", "apply", "plan", "publish", "generated", "inspect", "receipt", "manifest", "materialize", "abandon", "gc", "keys", "rename", "recipients", "recover", "rekey"}},
		{[]string{"prepare", "--help"}, []string{"--source", "--source-format", "upgrade", "normal-signing-key", "telemetry-config"}},
		{[]string{"init", "--help"}, []string{"--source", "--source-format", "json", "log-level"}},
		{[]string{"apply", "--help"}, []string{"--source", "publish", "retire-generator", "republish-after-unknown"}},
		{[]string{"publish", "--help"}, []string{"--source", "--source-format", "telemetry-config"}},
		{[]string{"plan", "--help"}, []string{"trusted", "candidate-format", "show-secret", "publish"}},
		{[]string{"rename", "--help"}, []string{"--source", "name", "log-level"}},
		{[]string{"recover", "--help"}, []string{"--source", "--source-format", "telemetry-config"}},
		{[]string{"recipients", "--help"}, []string{"add", "rename", "retire"}},
		{[]string{"recipients", "add", "--help"}, []string{"recipient", "mode", "display-name", "encryption-key"}},
		{[]string{"recipients", "rename", "--help"}, []string{"recipient", "new-reference"}},
		{[]string{"recipients", "retire", "--help"}, []string{"recipient", "out", "--source"}},
		{[]string{"rekey", "--help"}, []string{"name", "out", "--source"}},
		{[]string{"generated", "--help"}, []string{"list", "retire", "accept-retirement-risk", "cleanup"}},
		{[]string{"generated", "list", "--help"}, []string{"--source", "--source-format", "json"}},
		{[]string{"generated", "retire", "--help"}, []string{"operation", "duty", "attempt"}},
		{[]string{"generated", "accept-retirement-risk", "--help"}, []string{"operation", "duty", "attempt"}},
		{[]string{"generated", "cleanup", "--help"}, []string{"operation", "duty", "attempt"}},
		{[]string{"abandon", "--help"}, []string{"list", "plan", "apply", "receipt"}},
		{[]string{"abandon", "list", "--help"}, []string{"--source", "--source-format", "json"}},
		{[]string{"abandon", "plan", "--help"}, []string{"target", "out"}},
		{[]string{"abandon", "apply", "--help"}, []string{"plan", "--source"}},
		{[]string{"abandon", "receipt", "--help"}, []string{"operation", "--source"}},
		{[]string{"keys", "--help"}, []string{"replace", "authority", "recovery", "recipient"}},
		{[]string{"keys", "replace", "--help"}, []string{"target", "authorizer", "signing", "encryption", "decrypt-with"}},
		{[]string{"gc", "--help"}, []string{"plan", "apply", "operation"}},
		{[]string{"inspect", "--help"}, []string{"--source", "capacity", "cursor", "log-level"}},
		{[]string{"receipt", "--help"}, []string{"--source", "operation", "log-level"}},
		{[]string{"manifest", "--help"}, []string{"--source", "plugin", "empty-selection", "log-level"}},
		{[]string{"materialize", "--help"}, []string{"--source", "name", "recipient", "log-level"}},
	} {
		t.Run(strings.Join(row.args, "-"), func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			if code := run(row.args, &out, &diagnostic); code != 0 || diagnostic.Len() != 0 {
				t.Fatal("help reached command refusal", code, out.String(), diagnostic.String())
			}
			for _, text := range row.want {
				if !strings.Contains(out.String(), text) {
					t.Errorf("help omits %q: %s", text, out.String())
				}
			}
		})
	}
	t.Run("set-input-stays-with-command", func(t *testing.T) {
		var out, diagnostic bytes.Buffer
		code := runSetWithSetter(t.Context(), []string{"--help"}, io.NopCloser(strings.NewReader("")), &out, &diagnostic,
			func(context.Context, string, configuration.Format, string, io.ReadCloser, compositionfull.SetOptions) (*compositionfull.SetResult, error) {
				t.Fatal("help executed set")
				return nil, nil
			})
		if code != 0 || diagnostic.Len() != 0 || !strings.Contains(out.String(), "base64") || !strings.Contains(out.String(), "confidential") {
			t.Fatal("set help omitted supported options", code, out.String(), diagnostic.String())
		}
	})
	t.Run("short-output", func(t *testing.T) {
		var diagnostic bytes.Buffer
		if code := run([]string{"--help"}, commandShortWriter{}, &diagnostic); code != 2 {
			t.Fatal("incomplete help output succeeded", code)
		}
	})
}
