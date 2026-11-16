package compositionfull

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
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationComparisonDiagnosticUsesPhysicalSourceImage(t *testing.T) {
	for _, condition := range []string{"generated-schema", "missing-dependency", "missing-prepared-secret"} {
		t.Run(condition, func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			if err := source.pair.Close(); err != nil {
				t.Fatal(err)
			}
			configurationSetWritable(t, source)
			if err := os.Chmod(source.path, 0600); err != nil {
				t.Fatal(err)
			}
			// Independent line layouts distinguish the physical files. The
			// generated token starts at line5/column11; its editable reference
			// starts at line4/column16. Both are fixed literal positions.
			generated := []byte("\n\n\n{\n\"schema\": \"unsupported\"\n}\n")
			if condition == "missing-prepared-secret" {
				var prepared map[string]any
				if json.Unmarshal(source.generatedBytes, &prepared) != nil {
					t.Fatal("generated fixture unavailable")
				}
				delete(prepared["secrets"].(map[string]any), "secret")
				body, err := json.MarshalIndent(prepared, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				generated = append([]byte("\n\n\n"), body...)
			}
			reference := ".enkv/prod.generated.json"
			var editable map[string]any
			if json.Unmarshal(source.editableBytes, &editable) != nil {
				t.Fatal("editable fixture unavailable")
			}
			delete(editable, "generated")
			ordinary, err := json.Marshal(editable)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("{\n\n\n  \"generated\": \"" + reference + "\",\n" + string(ordinary[1:]))
			if err := os.WriteFile(source.path, body, 0444); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(source.generated); err != nil {
				t.Fatal(err)
			}
			if condition != "missing-dependency" {
				if err := os.WriteFile(filepath.Join(filepath.Dir(source.path), filepath.FromSlash(reference)), generated, 0444); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range []string{filepath.Dir(source.path), filepath.Dir(source.generated)} {
				if os.Chmod(path, 0555) != nil {
					t.Fatal("read-only source fixture unavailable")
				}
			}
			before := configurationApplySourceImage(t, filepath.Dir(source.path))
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			result := CompareConfigurationFiles(ctx, contract.Hash([]byte("physical source diagnostic")), source.path, configuration.JSON, "", 0)
			if result.Observation != nil || len(result.Diagnostics) != 1 || result.SourceFailure == nil {
				t.Fatal("source refusal lost its exact physical location")
			}
			stage := "parse"
			if condition == "missing-dependency" {
				stage = "capture"
			}
			if result.Context.OperationID.IsZero() || result.PreAdmission == nil || result.PreAdmission.Stage != stage {
				t.Fatal("physical source diagnostic lost its operation or failure stage")
			}
			wantSource, wantLine, wantColumn := "trusted.generated", uint64(5), uint64(11)
			if condition == "missing-dependency" {
				wantSource, wantLine, wantColumn = "trusted", 4, 16
			}
			if condition == "missing-prepared-secret" {
				at := bytes.Index(body, []byte(`"secret":{`))
				if at < 0 {
					t.Fatal("editable entry location fixture unavailable")
				}
				at += len(`"secret":`)
				wantSource = "trusted"
				wantLine = uint64(1 + bytes.Count(body[:at], []byte{'\n'}))
				wantColumn = uint64(at - bytes.LastIndexByte(body[:at], '\n'))
			}
			location := result.SourceFailure
			if condition != "generated-schema" && (location.Precision != "context" || result.Diagnostics[0].SourceLocation != nil) {
				t.Fatal("enclosing source context reported as exact fault")
			}
			wantPath := source.path
			if condition == "generated-schema" {
				wantPath = filepath.Join(filepath.Dir(source.path), filepath.FromSlash(reference))
			}
			if location.SourceID != wantSource || location.Line != wantLine || location.Column != wantColumn || location.Path != wantPath {
				t.Fatal("diagnostic coordinates/path were assigned to another physical source", *location)
			}
			configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
			if condition == "generated-schema" {
				configurationSetWritable(t, source)
				if err := os.Rename(wantPath, wantPath+".moved"); err != nil {
					t.Fatal(err)
				}
				source.path = filepath.Join(t.TempDir(), "another-descriptor.json")
				body, err := RenderComparisonJSON(result)
				var wire struct {
					Failure *ConfigurationSourceFailure `json:"source_failure"`
				}
				if err != nil || json.Unmarshal(body, &wire) != nil || wire.Failure == nil || wire.Failure.Path != wantPath {
					t.Fatal("detached result changed after source capture closed and companion moved", err)
				}
			}
		})
	}
}

// full_only: false
func TestConfigurationSourceFailureKeepsSafeOriginAndContext(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		diagnostic   configuration.Diagnostic
		precision    string
		wantLocation bool
	}{
		{"candidate-schema", "candidate", configuration.Diagnostic{Field: "schema", Reason: "unsupported-schema", Line: 3, Column: 9}, "exact", true},
		{"generated-schema", "trusted", configuration.Diagnostic{Generated: true, Field: "schema", Reason: "unsupported-schema", Line: 5, Column: 11}, "exact", true},
		{"enclosing-entry", "trusted", configuration.Diagnostic{Field: "entries.item", Reason: "missing-required-field", Line: 7, Column: 3, Context: true}, "context", false},
		{"unknown-position", "trusted", configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := configurationComparisonFailure(t.Context(), contract.ID{}, contract.ID{}, tc.source, &tc.diagnostic)
			f := result.SourceFailure
			source := tc.source
			if tc.diagnostic.Generated {
				source += ".generated"
			}
			wantReason := tc.diagnostic.Reason
			if wantReason == "restore-exact-generated-file" {
				wantReason = "missing-required-field"
			}
			if f == nil || f.SourceID != source || f.Field != tc.diagnostic.Field || f.Reason != wantReason || f.Line != tc.diagnostic.Line || f.Column != tc.diagnostic.Column || f.Precision != tc.precision {
				t.Fatalf("source failure lost safe origin facts: %+v", f)
			}
			if (result.Diagnostics[0].SourceLocation != nil) != tc.wantLocation {
				t.Fatal("enclosing context was reported as an exact fault")
			}
			planned := configurationPlanningResult(result)
			if planned.SourceFailure != f {
				t.Fatal("planning lost its source failure")
			}
		})
	}
}

// full_only: false
func TestConfigurationSourceFailureRendersSafeSingleton(t *testing.T) {
	result, err := NewComparisonRefusal(configuration.YAML)
	if err != nil {
		t.Fatal(err)
	}
	result.PreAdmission.Stage = "parse"
	result.SourceFailure = &ConfigurationSourceFailure{SourceID: "candidate", Field: "schema", Reason: "unsupported-schema", Line: 3, Column: 9, Precision: "exact"}
	check := func(body []byte, err error, human bool) {
		t.Helper()
		if err != nil {
			t.Fatal("source failure render refused", err)
		}
		if human {
			if !strings.Contains(string(body), "Input candidate: unsupported-schema; field schema; exact location 3:9") {
				t.Fatal("human source failure lost semantic facts", string(body))
			}
			return
		}
		var wire struct {
			Failure *ConfigurationSourceFailure `json:"source_failure"`
		}
		if json.Unmarshal(body, &wire) != nil || wire.Failure == nil || *wire.Failure != *result.SourceFailure {
			t.Fatal("JSON source failure changed", string(body))
		}
	}
	for _, human := range []bool{false, true} {
		var body []byte
		var err error
		if human {
			body, err = RenderComparisonHuman(result)
		} else {
			body, err = RenderComparisonJSON(result)
		}
		check(body, err, human)
		planned := configurationPlanningResult(result)
		if human {
			body, err = RenderPlanningHuman(planned)
		} else {
			body, err = RenderPlanningJSON(planned)
		}
		check(body, err, human)
	}
	for _, damage := range []func(*ConfigurationSourceFailure){
		func(f *ConfigurationSourceFailure) { f.Field = "private-key-sentinel" },
		func(f *ConfigurationSourceFailure) { f.Reason = "private-error-sentinel" },
		func(f *ConfigurationSourceFailure) { f.SourceID = "/private/source" },
		func(f *ConfigurationSourceFailure) { f.Column = 0 },
		func(f *ConfigurationSourceFailure) { f.Precision = "approximate" },
	} {
		f := *result.SourceFailure
		damage(&f)
		invalid := result
		invalid.SourceFailure = &f
		if body, err := RenderComparisonJSON(invalid); err == nil || body != nil {
			t.Fatal("unsafe source failure was rendered")
		}
	}
}
