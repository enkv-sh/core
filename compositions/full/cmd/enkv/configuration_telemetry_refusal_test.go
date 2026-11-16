package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
)

// full_only: false
func TestRecognizedConfigurationTelemetrySetupRefusalsReturnOneJSONResult(t *testing.T) {
	for _, command := range []struct{ name, operation, sourceOption string }{
		{"init", "initialize-empty-domain", "--source"},
		{"apply", "apply-declaration", "--source"},
		{"plan", "compare-public-configuration", "--trusted"},
		{"set", "set-confidential", "--source"},
	} {
		for _, condition := range []string{"invalid-log-level", "missing-configuration", "unavailable-directory", "input-close-failure"} {
			if condition == "input-close-failure" && command.name != "set" {
				continue
			}
			t.Run(command.name+"/"+condition, func(t *testing.T) {
				for _, name := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
					t.Setenv(name, "")
				}
				directory := t.TempDir()
				path := filepath.Join(directory, "private-source-sentinel.json")
				formatOption := "--source-format"
				if command.sourceOption == "--trusted" {
					formatOption = "--trusted-format"
				}
				args := []string{"--json", command.sourceOption, path, formatOption, "json"}
				if command.name == "set" {
					args = append(args, "--name", "entry", "--confidential=true")
				}
				message := "telemetry configuration refused"
				switch condition {
				case "invalid-log-level", "input-close-failure":
					args = append(args, "--log-level", "private-log-level-sentinel")
				case "missing-configuration":
					args = append(args, "--telemetry-config", filepath.Join(directory, "private-telemetry-sentinel.json"))
				case "unavailable-directory":
					working := filepath.Join(directory, "working")
					if err := os.Mkdir(working, 0700); err != nil {
						t.Fatal(err)
					}
					t.Chdir(working)
					t.Setenv("PWD", "")
					// Exceed both the native getcwd buffer and Go's 1,024-byte
					// parent-walk limit. Relative syscalls avoid Getwd during setup.
					for depth := 0; depth < 350; depth++ {
						if err := os.Mkdir("nested-directory", 0700); err != nil {
							t.Fatal(err)
						}
						if err := syscall.Chdir("nested-directory"); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := os.Getwd(); err == nil {
						t.Fatal("deep current directory did not establish the intended setup failure")
					}
					message = "application directory is unavailable"
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				input := &setCommandInput{}
				if condition == "input-close-failure" {
					input.closeErr = errors.New("private-close-error-sentinel")
				}
				var out, diagnostic bytes.Buffer
				var code int
				switch command.name {
				case "init":
					code = runInitWithInitializer(ctx, args, &out, &diagnostic, func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error) {
						t.Fatal("telemetry setup failure entered initialization")
						return compositionfull.InitializationResult{}, nil
					})
				case "apply":
					code = runApplyContext(ctx, args, &out, &diagnostic)
				case "plan":
					code = runPlanContext(ctx, args, &out, &diagnostic)
				case "set":
					code = runSetWithSetter(ctx, args, input, &out, &diagnostic, func(context.Context, string, configuration.Format, string, io.ReadCloser, compositionfull.SetOptions) (*compositionfull.SetResult, error) {
						t.Fatal("telemetry setup failure entered confidential preparation")
						return nil, nil
					})
					if input.reads != 0 || input.closes != 1 {
						t.Error("telemetry refusal lost unread input ownership")
					}
				}
				if code != 2 || !strings.Contains(diagnostic.String(), message) || strings.Contains(diagnostic.String(), "requires --") {
					t.Errorf("setup refusal lost its owning diagnostic: code=%d, diagnostic=%q", code, diagnostic.String())
				}
				var result struct {
					Schema      string `json:"schema"`
					Operation   string `json:"operation_kind"`
					OperationID string `json:"operation_id"`
					State       string `json:"state_result"`
					Identity    struct {
						Schema, Stage, Code string
						OperationID         string `json:"operation_id"`
					} `json:"request_identity"`
					Replay        string `json:"replay_identity"`
					Receipt       string `json:"receipt_hex"`
					CommitUnknown bool   `json:"commit_may_have_occurred"`
				}
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatal("telemetry setup failure did not return one JSON result", err)
				}
				id, err := hex.DecodeString(result.OperationID)
				if err != nil || len(id) != 32 || bytes.Equal(id, make([]byte, 32)) {
					t.Error("telemetry refusal lost operation correlation")
				}
				if result.Schema != "ProductResult/v1" || result.Operation != command.operation || result.State != "refused" || result.Identity.Schema != "PreAdmissionRequestIdentity/v1" || result.Identity.OperationID != result.OperationID || result.Identity.Stage != "dispatch" || result.Identity.Code == "" || result.Replay != "none" || result.Receipt != "" || result.CommitUnknown {
					t.Error("telemetry failure lost safe operation-specific refusal")
				}
				for _, forbidden := range []string{path, "private-log-level-sentinel", "private-telemetry-sentinel", "private-close-error-sentinel"} {
					if bytes.Contains(out.Bytes(), []byte(forbidden)) || bytes.Contains(diagnostic.Bytes(), []byte(forbidden)) {
						t.Error("private setup input escaped refusal")
					}
				}
			})
		}
	}
}
