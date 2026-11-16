package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationFileQueriesReportSourceOrigin(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(context.Context, string, io.Writer) error
	}{
		{"domain", func(ctx context.Context, path string, out io.Writer) error {
			return InspectConfigurationFile(ctx, contract.ID{1}, path, configuration.JSON).WriteJSON(ctx, out)
		}},
		{"recipient", func(ctx context.Context, path string, out io.Writer) error {
			return InspectConfigurationRecipientFile(ctx, contract.ID{1}, path, configuration.JSON, contract.ID{2}).WriteJSON(ctx, out)
		}},
		{"receipt-list", func(ctx context.Context, path string, out io.Writer) error {
			return ListConfigurationReceiptsFile(ctx, contract.ID{1}, path, configuration.JSON).WriteJSON(ctx, out)
		}},
		{"receipt-detail", func(ctx context.Context, path string, out io.Writer) error {
			return ReadConfigurationReceiptFile(ctx, contract.ID{1}, path, configuration.JSON, contract.ID{2}).WriteJSON(ctx, out)
		}},
		{"capacity", func(ctx context.Context, path string, out io.Writer) error {
			return InspectConfigurationCapacityFile(ctx, core.CapacityInspectionRequest{RequestNonce: contract.ID{1}}, path, configuration.JSON).WriteJSON(ctx, out)
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source.json")
			if err := os.WriteFile(path, []byte(`{"schema":"wrong"}`), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var out bytes.Buffer
			if err := row.run(ctx, path, &out); err != nil {
				t.Fatal(err)
			}
			var wire struct {
				SourceFailure *ConfigurationSourceFailure `json:"source_failure"`
			}
			if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
				t.Fatal(err)
			}
			want := ConfigurationSourceFailure{SourceID: "source", Path: path, Field: "schema", Reason: "unsupported-schema", Line: 1, Column: 11, Precision: "exact"}
			if wire.SourceFailure == nil || *wire.SourceFailure != want {
				t.Fatalf("source origin lost: %s", out.Bytes())
			}
		})
	}
}

// full_only: false
func TestConfigurationQuerySourceFailureRequiresSourceAdmission(t *testing.T) {
	for _, damage := range []string{"dispatch", "provider-construction", "authenticated-query", "successful-query", "other-input", "unsafe-field"} {
		t.Run(damage, func(t *testing.T) {
			base, err := NewDomainInspectionRefusal(0)
			if err != nil {
				t.Fatal(err)
			}
			base.PreAdmission.Stage = "parse"
			f := &ConfigurationSourceFailure{SourceID: "source", Field: "schema", Reason: "unsupported-schema", Line: 1, Column: 11, Precision: "exact"}
			switch damage {
			case "dispatch":
				base.PreAdmission.Stage = "dispatch"
			case "provider-construction":
				base.PreAdmission.Stage = "construction"
			case "authenticated-query":
				base.RequestIdentity = contract.ID{1}
			case "successful-query":
				base.StateResult = core.PublicQuerySuccess
				base.Result.Outcome = core.ObservedCurrent
			case "other-input":
				f.SourceID = "candidate"
			case "unsafe-field":
				f.Field = "private-provider-error-body"
			}
			result := ConfigurationInspectionResult{PublicDomainInspectionResult: base, SourceFailure: f}
			var out bytes.Buffer
			if err := result.WriteJSON(t.Context(), &out); err == nil || out.Len() != 0 {
				t.Fatal("unowned source failure crossed the output boundary", err, out.String())
			}
		})
	}
}
