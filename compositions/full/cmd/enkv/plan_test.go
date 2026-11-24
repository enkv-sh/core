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

	compositionfull "enkv.sh/compositions/full"
)

// full_only: false
func TestPlanRejectsInvalidTrustedAndCandidateSelections(t *testing.T) {
	for _, args := range [][]string{{"--trusted", ""}, {"--trusted", "/absent"}, {"--trusted", "/absent", "--trusted-format", "automatic"},
		{"--trusted", "/absent", "--trusted-format", "json", "--candidate", "/other"}, {"--trusted", "/absent", "--trusted-format", "json", "--candidate-format", "yaml"},
		{"--config", "/absent", "--trusted-format", "json"}, {"--trusted", "/absent", "--trusted-format", "json", "unexpected"}} {
		var out, diagnostic bytes.Buffer
		if code := runPlan(args, &out, &diagnostic); code != 2 || !strings.Contains(out.String(), "Plan incomplete: refused") || !strings.Contains(diagnostic.String(), "--trusted") {
			t.Fatal("ambiguous plan source was accepted", code, out.String(), diagnostic.String())
		}
	}
}

// full_only: false
func TestPlanMalformedSourceReturnsSafeStructuredRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.json")
	body := []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
	if err := os.WriteFile(path, body, 0444); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	code := runPlan([]string{"--trusted", path, "--trusted-format", "json", "--json"}, &out, &diagnostic)
	var result struct {
		Schema, Operation, State string
		Payload                  struct {
			Verdict             string
			DiagnosticsComplete bool `json:"diagnostics_complete"`
			Diagnostics         []any
		}
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || code != 2 || result.Schema != "ProductResult/v1" || result.Payload.Verdict != "unable to verify" || !result.Payload.DiagnosticsComplete || len(result.Payload.Diagnostics) != 1 {
		t.Fatal("source refusal result differs", code, err, out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("secret-sentinel")) || bytes.Contains(out.Bytes(), []byte("raw-parser-error-sentinel")) || bytes.Contains(diagnostic.Bytes(), []byte("secret-sentinel")) || bytes.Contains(diagnostic.Bytes(), []byte(path)) {
		t.Fatal("source content or private path escaped plan diagnostics")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("failed plan changed source", err)
	}
}

// full_only: false
func TestPlanPublicationRefusalRetainsRequestedProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(path, []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`), 0444); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	code := runPlan([]string{"--trusted", path, "--trusted-format", "json", "--json", "--publish"}, &out, &diagnostic)
	var result struct {
		Payload struct {
			Publication *struct {
				Schema     string            `json:"schema"`
				Complete   bool              `json:"complete"`
				ReasonCode uint8             `json:"reason_code"`
				Entries    []json.RawMessage `json:"entries"`
			} `json:"publication"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || code != 2 || result.Payload.Publication == nil || result.Payload.Publication.Schema != "PublicationPreview/v2" || result.Payload.Publication.Complete || result.Payload.Publication.ReasonCode == 0 || len(result.Payload.Publication.Entries) != 0 {
		t.Fatal("requested publication discovery became absent or successful after source refusal", code, err, out.String())
	}
	if strings.Contains(diagnostic.String(), "plan requires") || bytes.Contains(out.Bytes(), []byte("secret-sentinel")) || bytes.Contains(diagnostic.Bytes(), []byte(path)) {
		t.Fatal("publication option was rejected or private source facts escaped", diagnostic.String())
	}
}

// full_only: false
func TestPlanCancellationAndOutputFailureHaveNoSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("{}"), 0444); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	cancel()
	var out, diagnostic bytes.Buffer
	if code := runPlanContext(ctx, []string{"--trusted", path, "--trusted-format", "json", "--json"}, &out, &diagnostic); code != 2 || !bytes.Contains(out.Bytes(), []byte("cancelled")) {
		t.Fatal("canceled source read reported success", code, out.String())
	}
	if code := runPlan([]string{"--trusted", path, "--trusted-format", "json", "--json"}, commandShortWriter{}, &diagnostic); code != 2 || !strings.Contains(diagnostic.String(), "output failed") {
		t.Fatal("partial plan output reported success", code)
	}
	diagnostic.Reset()
	if code := runPlan([]string{"--trusted", path, "--trusted-format", "json", "--json"}, &commandNewlineShortWriter{}, &diagnostic); code != 2 || !strings.Contains(diagnostic.String(), "output failed") {
		t.Fatal("partial plan output terminator reported success", code)
	}
}

// full_only: false
func TestPlanGeneratedDependencyRefusalNamesExactSourceAndRestoration(t *testing.T) {
	const setup = `"schema":"enkv/configuration/v3","domain":{"name":"prod","provider":"aws","store":{"region":"us-east-1","bucket":"fixture-bucket","prefix":"fixture","expected_owner":"123456789012"},"authority":{"display_name":"","signing_key":"arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111","encryption_key":"arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"},"recovery":{"enabled":false}},"recipients":{},"entries":{},"outputs":{"destinations":{},"routing":{}}}`
	reference := ".enkv/prod.generated.json"
	for _, condition := range []string{"missing", "non-regular"} {
		t.Run(condition, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "source.json")
			body := []byte("{\n  \"generated\": \"" + reference + "\",\n" + setup)
			if err := os.WriteFile(path, body, 0444); err != nil {
				t.Fatal(err)
			}
			if condition == "non-regular" {
				if err := os.Mkdir(filepath.Join(dir, reference), 0700); err != nil {
					t.Fatal(err)
				}
			}
			var out, diagnostic bytes.Buffer
			code := runPlan([]string{"--trusted", path, "--trusted-format", "json", "--json"}, &out, &diagnostic)
			var result struct {
				SourceFailure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
				Payload       struct {
					Verdict     string
					Diagnostics []struct {
						Reason string
						Source struct {
							ID           string `json:"source_id"`
							Line, Column uint64
						} `json:"source_location"`
					}
				}
			}
			if err := json.Unmarshal(out.Bytes(), &result); err != nil || code != 2 || result.Payload.Verdict != "unable to verify" || len(result.Payload.Diagnostics) != 1 {
				t.Fatal("generated dependency refusal differs", code, err, out.String())
			}
			row := result.Payload.Diagnostics[0]
			wantReason, wantSourceReason := "missing-required-field", "restore-exact-generated-file"
			if condition == "non-regular" {
				wantReason, wantSourceReason = "invalid-input", "invalid-generated-path"
			}
			location := result.SourceFailure
			if row.Reason != wantReason || row.Source.ID != "" || row.Source.Line != 0 || row.Source.Column != 0 || location == nil || location.SourceID != "trusted" || location.Path != path || location.Reason != wantSourceReason || location.Precision != "context" || location.Line != 2 || location.Column != 16 || strings.Contains(diagnostic.String(), "Restore the exact generated JSON file") != (condition == "missing") {
				t.Fatal("generated dependency lost safe source context or precise restoration eligibility", row, location, diagnostic.String())
			}
			if bytes.Contains(diagnostic.Bytes(), []byte(path)) {
				t.Fatal("source path escaped into diagnostics")
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("refusal changed editable source", err)
			}
		})
	}
}

func planIntentRun(t *testing.T, args []string) (int, []byte, string) {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "plan-result-*")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var diagnostic bytes.Buffer
	code := runPlanContext(ctx, args, output, &diagnostic)
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, body, diagnostic.String()
}

// full_only: false
func TestPlanCandidatePresenceRequiresCompleteNonemptyPair(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "trusted.json")
	if err := os.WriteFile(trusted, []byte(`{"schema":"unsupported-plan-intent-fixture"}`), 0444); err != nil {
		t.Fatal(err)
	}
	for _, private := range []bool{false, true} {
		mode := "public"
		if private {
			mode = "private"
		}
		for _, row := range []struct {
			name string
			args []string
		}{
			{"both-empty", []string{"--candidate=", "--candidate-format="}},
			{"empty-candidate-only", []string{"--candidate="}},
			{"empty-format-only", []string{"--candidate-format="}},
			{"empty-path-valid-format", []string{"--candidate=", "--candidate-format=json"}},
			{"valid-path-empty-format", []string{"--candidate=" + filepath.Join(t.TempDir(), "candidate.json"), "--candidate-format="}},
			{"unsupported-format", []string{"--candidate=" + filepath.Join(t.TempDir(), "candidate.json"), "--candidate-format=automatic"}},
		} {
			t.Run(mode+"/"+row.name, func(t *testing.T) {
				args := []string{"--trusted", trusted, "--trusted-format", "json", "--json", "--publish"}
				if private {
					args = append(args, "--check-secrets")
				}
				args = append(args, row.args...)
				code, body, diagnostic := planIntentRun(t, args)
				var result struct {
					Schema, Operation, State string
					Identity                 struct{ Stage, Code string } `json:"request_identity"`
					Payload                  struct {
						Verdict     string
						Publication *struct {
							Schema     string
							Complete   bool
							ReasonCode uint8             `json:"reason_code"`
							Entries    []json.RawMessage `json:"entries"`
						}
					}
				}
				if err := json.Unmarshal(body, &result); err != nil || code != 2 || !strings.Contains(diagnostic, "plan requires") || result.Schema != "ProductResult/v1" || result.Identity.Stage != "dispatch" || result.Identity.Code != "invalid-input" || result.Payload.Verdict != "unable to verify" {
					t.Fatal("explicit candidate input became trusted-only execution", code, err, diagnostic, string(body))
				}
				publication := result.Payload.Publication
				if publication == nil || publication.Schema != "PublicationPreview/v2" || publication.Complete || publication.ReasonCode == 0 || len(publication.Entries) != 0 {
					t.Fatal("candidate refusal lost requested incomplete publication", string(body))
				}
				if bytes.Contains(body, []byte(trusted)) || strings.Contains(diagnostic, trusted) {
					t.Fatal("candidate grammar refusal disclosed a private source path")
				}
			})
		}
	}
	t.Run("human-publication-refusal", func(t *testing.T) {
		code, body, diagnostic := planIntentRun(t, []string{"--trusted", trusted, "--trusted-format", "json", "--candidate=", "--candidate-format=", "--publish"})
		if code != 2 || !strings.Contains(diagnostic, "plan requires") || !bytes.Contains(body, []byte("Plan incomplete: refused")) || !bytes.Contains(body, []byte("Publication preview: incomplete; 0 targets.")) {
			t.Fatal("human candidate refusal lost intent or requested publication", code, diagnostic, string(body))
		}
	})
}

// full_only: false
func TestPlanCandidateAbsenceAndValidRepresentationsReachExactSource(t *testing.T) {
	trusted, _, _, _ := setCommandPreparedSource(t)
	malformed := filepath.Join(t.TempDir(), "malformed-trusted.json")
	if err := os.WriteFile(malformed, []byte(`{"schema":"unsupported-plan-intent-fixture"}`), 0444); err != nil {
		t.Fatal(err)
	}
	for _, private := range []bool{false, true} {
		mode := "public"
		if private {
			mode = "private"
		}
		for _, format := range []string{"omitted", "json", "yaml"} {
			t.Run(mode+"/"+format, func(t *testing.T) {
				path, expectedSource := malformed, "trusted"
				var extra []string
				if format != "omitted" {
					path, expectedSource = trusted, "candidate"
					candidate := filepath.Join(t.TempDir(), "candidate."+format)
					body := []byte(`{"schema":"unsupported-plan-intent-fixture"}`)
					if format == "yaml" {
						body = []byte("schema: unsupported-plan-intent-fixture\n")
					}
					if err := os.WriteFile(candidate, body, 0444); err != nil {
						t.Fatal(err)
					}
					extra = []string{"--candidate", candidate, "--candidate-format", format}
				}
				args := []string{"--trusted", path, "--trusted-format", "json", "--json"}
				if private {
					args = append(args, "--check-secrets")
				}
				args = append(args, extra...)
				code, body, diagnostic := planIntentRun(t, args)
				var result struct {
					Payload struct {
						Verdict     string
						Diagnostics []struct {
							Reason string
							Source *struct {
								ID string `json:"source_id"`
							} `json:"source_location"`
						}
					}
				}
				if err := json.Unmarshal(body, &result); err != nil || code != 2 || strings.Contains(diagnostic, "plan requires") || result.Payload.Verdict != "unable to verify" || len(result.Payload.Diagnostics) != 1 {
					t.Fatal("candidate form did not reach source comparison", code, err, diagnostic, string(body))
				}
				row := result.Payload.Diagnostics[0]
				if row.Reason != "unsupported-schema" || row.Source == nil || row.Source.ID != expectedSource {
					t.Fatal("candidate presence or representation selected another source", expectedSource, row, string(body))
				}
			})
		}
	}
}

type commandShortWriter struct{}

func (commandShortWriter) Write(body []byte) (int, error) { return len(body) - 1, nil }

type commandNewlineShortWriter struct{}

func (w *commandNewlineShortWriter) Write(body []byte) (int, error) {
	if len(body) > 0 && body[len(body)-1] == '\n' {
		return len(body) - 1, nil
	}
	return len(body), nil
}
