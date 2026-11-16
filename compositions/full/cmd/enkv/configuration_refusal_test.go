package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

// full_only: false
func TestRecognizedConfigurationInvalidFieldsReturnOneJSONRefusal(t *testing.T) {
	for _, command := range []struct {
		name, operation, sourceOption string
		run                           func([]string, io.Writer, io.Writer) int
	}{
		{"init", "initialize-empty-domain", "--source", func(args []string, out, diagnostic io.Writer) int {
			return runInitWithInitializer(context.Background(), args, out, diagnostic, func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error) {
				t.Fatal("invalid init options opened initialization")
				return compositionfull.InitializationResult{}, nil
			})
		}},
		{"apply", "apply-declaration", "--source", runApply},
		{"plan", "compare-public-configuration", "--trusted", runPlan},
	} {
		for _, condition := range []string{"empty-source", "invalid-format", "unexpected-argument", "unknown-option", "incomplete-format-selection"} {
			t.Run(command.name+"/"+condition, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "private-source-sentinel")
				// This path cannot supply a configuration. The result must identify
				// dispatch refusal without needing source capture.
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				formatOption := "--source-format"
				if command.sourceOption == "--trusted" {
					formatOption = "--trusted-format"
				}
				args := []string{"--json", command.sourceOption, path, formatOption, "json"}
				switch condition {
				case "empty-source":
					args = []string{"--json", command.sourceOption, "", formatOption, "json"}
				case "invalid-format":
					args[len(args)-1] = "private-format-sentinel"
				case "unexpected-argument":
					args = append(args, "private-argument-sentinel")
				case "unknown-option":
					args = append(args, "--private-option-sentinel")
				case "incomplete-format-selection":
					if command.name == "plan" {
						args = append(args, "--candidate-format", "yaml")
					} else {
						args = []string{"--json", command.sourceOption, path, formatOption, ""}
					}
				}
				var out, diagnostic bytes.Buffer
				if code := command.run(args, &out, &diagnostic); code != 2 {
					t.Errorf("invalid fields returned exit %d", code)
				}
				var record struct {
					Schema        string         `json:"schema"`
					Operation     string         `json:"operation_kind"`
					OperationID   string         `json:"operation_id"`
					State         string         `json:"state_result"`
					Identity      map[string]any `json:"request_identity"`
					Replay        string         `json:"replay_identity"`
					Receipt       string         `json:"receipt_hex"`
					CommitUnknown bool           `json:"commit_may_have_occurred"`
				}
				if err := json.Unmarshal(out.Bytes(), &record); err != nil {
					t.Fatal("recognized invalid fields did not return one JSON result", err)
				}
				id, err := hex.DecodeString(record.OperationID)
				if err != nil || len(id) != len(contract.ID{}) || bytes.Equal(id, make([]byte, len(id))) {
					t.Error("recognized invalid fields lost operation correlation")
				}
				if record.Schema != "ProductResult/v1" || record.Operation != command.operation || record.State != "refused" || record.Replay != "none" || record.Receipt != "" || record.CommitUnknown {
					t.Error("invalid fields lost recognized operation refusal")
				}
				if record.Identity["schema"] != "PreAdmissionRequestIdentity/v1" || record.Identity["operation_id"] != record.OperationID {
					t.Error("invalid fields lost pre-admission identity")
				}
				for _, field := range []string{"stage", "code"} {
					if value, ok := record.Identity[field].(string); !ok || value == "" {
						t.Errorf("invalid fields lost failure %s", field)
					}
				}
				if record.Identity["stage"] != "dispatch" {
					t.Error("invalid options reached a later operation stage")
				}
				for _, forbidden := range []string{path, "private-format-sentinel", "private-argument-sentinel", "private-option-sentinel", "private-relative-sentinel"} {
					if bytes.Contains(out.Bytes(), []byte(forbidden)) || bytes.Contains(diagnostic.Bytes(), []byte(forbidden)) {
						t.Error("invalid field value escaped refusal")
					}
				}
			})
		}
	}
}
