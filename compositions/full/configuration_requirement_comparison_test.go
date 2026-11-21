package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func assertConfigurationRequirementComparison(t *testing.T, body []byte, want string) {
	t.Helper()
	var record map[string]json.RawMessage
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal("configuration result is not JSON", err)
	}
	var got, expected any
	if err := json.Unmarshal(record["installation_requirements"], &got); err != nil {
		t.Fatal("configuration result lacks separate installation requirement facts", err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("source requirement comparison differs: got=%s want=%s", record["installation_requirements"], want)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(record["payload"], &payload); err != nil {
		t.Fatal("configuration result lost the Product payload", err)
	}
	if _, present := payload["installation_requirements"]; present {
		t.Fatal("local installation preferences entered the Product payload")
	}
}

// full_only: false
func TestConfigurationRequirementComparisonPreservesSourceFacts(t *testing.T) {
	for _, condition := range []struct {
		name    string
		private bool
		self    bool
		fail    bool
	}{
		{"public-match", false, false, false},
		{"public-self", false, true, false},
		{"public-construction-failure", false, false, true},
		{"private-construction-failure", true, false, true},
	} {
		t.Run(condition.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			configDirectory, err := os.UserConfigDir()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(configDirectory, "enkv"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(configDirectory, "enkv", "plugins.json"), []byte("invalid settings must not be read"), 0600); err != nil {
				t.Fatal(err)
			}
			trusted := configurationReaderPairWithOutputs(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
				if condition.private {
					configurationReaderWithoutOutputs(editable, generated)
				}
				editable["plugins"] = map[string]any{"generic-json": map[string]any{"version": "1.0.0"}}
			})
			candidate := configurationReaderPairWithOutputs(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
				if condition.private {
					configurationReaderWithoutOutputs(editable, generated)
				}
				editable["plugins"] = map[string]any{
					"aws-secrets-manager":      map[string]any{},
					"cloudflare-account-token": map[string]any{"version": "3.0.0"},
					"generic-json":             map[string]any{"version": "2.0.0"},
				}
			})
			proposed := candidate.pair
			want := `{"complete":true,"differences":[{"name":"aws-secrets-manager","trusted":null,"candidate":{}},{"name":"cloudflare-account-token","trusted":null,"candidate":{"version":"3.0.0"}},{"name":"generic-json","trusted":{"version":"1.0.0"},"candidate":{"version":"2.0.0"}}]}`
			if condition.self {
				proposed = nil
				want = `{"complete":true,"differences":[]}`
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			requestID := contract.Hash([]byte("source-only installation requirement comparison"))
			calls := 0
			var body []byte
			if condition.private {
				result := planConfiguration(ctx, requestID, trusted.pair, proposed, contract.PlanningOptions{Purpose: contract.PlanningEquality}, nil,
					func(context.Context, PlanningConfig) (*core.InstalledPlanning, error) {
						calls++
						return nil, errors.New("controlled planning construction failure")
					})
				if result.StateResult != contract.ReaderUnavailable || result.Verdict != contract.ComparisonUnable || result.PrivateComplete || result.EvidenceLimit != contract.PlanningEvidenceLimit || PlanningExitCode(result) != 3 {
					t.Fatal("source preferences changed private failure facts", result)
				}
				body, err = RenderPlanningJSON(result)
			} else {
				h := &readerHTTPFixture{archive: trusted.archive, reads: map[string]int{}}
				open := configurationReaderOpener(t, trusted, h, &calls)
				if condition.fail {
					open = func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
						calls++
						return nil, errors.New("controlled Reader construction failure")
					}
				}
				result := compareReaderFixture(ctx, requestID, trusted.pair, proposed, open)
				if condition.fail {
					if result.StateResult != contract.ReaderUnavailable || result.Verdict != contract.ComparisonUnable || ComparisonExitCode(result) != 3 {
						t.Fatal("source preferences changed public failure facts", result)
					}
				} else if result.StateResult != contract.ReaderSuccess || result.Verdict != contract.ComparisonMatch || len(result.Diagnostics) != 0 || ComparisonExitCode(result) != 0 {
					t.Fatal("source preferences changed the authenticated domain verdict", result)
				}
				if result.EvidenceLimit != contract.ComparisonEvidenceLimit {
					t.Fatal("source preferences changed the domain evidence limit")
				}
				body, err = RenderComparisonJSON(result)
				h.assertNoEffects(t)
			}
			if calls != 1 || err != nil {
				t.Fatal("configuration comparison did not reach and render the selected domain boundary", calls, err)
			}
			assertConfigurationRequirementComparison(t, body, want)
			trusted.assertUnchanged(t)
			candidate.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationRequirementsCompareEffectiveNamesAndOwnPreferences(t *testing.T) {
	trusted := &configuration.Model{Plugins: []configuration.PluginRequirement{{Name: "generic-json", Version: "1.0.0"}}}
	candidate := &configuration.Model{Plugins: []configuration.PluginRequirement{{Name: "generic-json", Version: "1.0.0"}}}
	if got := compareConfigurationRequirements(trusted, candidate); !got.Complete || len(got.Differences) != 0 || got.Differences == nil {
		t.Fatal("identical implied and explicit requirements differ", got)
	}
	candidate.Entries = []configuration.Entry{{Generated: &configuration.Generator{Plugin: "cloudflare-account-token"}}}
	candidate.Plugins = append(candidate.Plugins, configuration.PluginRequirement{Name: "cloudflare-account-token"})
	got := compareConfigurationRequirements(trusted, candidate)
	if !got.Complete || len(got.Differences) != 1 || got.Differences[0].Name != "cloudflare-account-token" || got.Differences[0].Trusted != nil || got.Differences[0].Candidate == nil || got.Differences[0].Candidate.Version != "" {
		t.Fatal("present unpinned requirement lost its empty object", got)
	}
	candidate.Plugins[1].Version = "2.0.0"
	owned := configurationPluginRequirement(candidate, "cloudflare-account-token")
	*candidate = configuration.Model{}
	if owned.Name != "cloudflare-account-token" || owned.Version != "2.0.0" {
		t.Fatal("ordinary preference depends on released model", owned)
	}
	got = compareConfigurationRequirements(trusted, nil)
	if got.Complete || got.Differences == nil || len(got.Differences) != 0 {
		t.Fatal("incomplete projection claims differences", got)
	}
}

// full_only: false
func TestConfigurationRequirementRenderersBoundClosedRowsAndTerminal(t *testing.T) {
	names := make([]string, 128)
	before, after := &configuration.Model{}, &configuration.Model{}
	version := "1.0.0-" + strings.Repeat("a", 122)
	for i := range names {
		names[i] = fmt.Sprintf("%03d", i) + strings.Repeat("p", 252)
		row := configuration.PluginRequirement{Name: names[i], Version: version}
		if i < 64 {
			before.Plugins = append(before.Plugins, row)
		} else {
			after.Plugins = append(after.Plugins, row)
		}
	}
	comparison := compareConfigurationRequirements(before, after)
	if !comparison.Complete || len(comparison.Differences) != 128 {
		t.Fatal("complete source requirement union was truncated", comparison)
	}

	public := generatedPlanningResultFixture()
	public.InstallationRequirements = comparison
	body, err := RenderComparisonJSON(public)
	if err != nil || len(body) != cap(body) {
		t.Fatal("maximum source comparison refused", err)
	}
	var wire struct {
		Requirements json.RawMessage `json:"installation_requirements"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || len(wire.Requirements) > 128*1024+128 {
		t.Fatal("source comparison exceeds its independent account", err)
	}
	rows := make([]string, 0, len(names))
	for i, name := range names {
		selected := `{"version":"` + version + `"}`
		trusted, candidate := "null", selected
		if i < 64 {
			trusted, candidate = selected, "null"
		}
		rows = append(rows, `{"name":"`+name+`","trusted":`+trusted+`,"candidate":`+candidate+`}`)
	}

	want := `{"complete":true,"differences":[` + strings.Join(rows, ",") + `]}`
	assertConfigurationRequirementComparison(t, body, want)
	human, err := RenderComparisonHuman(public)
	if err != nil || !bytes.Contains(human, []byte("Local plugin selection comparison: complete; 128 differences.\n")) || bytes.Count(human, []byte("\n  Plugin ")) != 128 || len(human) != cap(human) {
		t.Fatal("human output changed the separate source requirement facts", err)
	}
	for i, name := range names {
		trusted, candidate := "absent", fmt.Sprintf("%q", version)
		if i < 64 {
			trusted, candidate = candidate, trusted
		}
		row := fmt.Sprintf("  Plugin %q; trusted %s; candidate %s\n", name, trusted, candidate)
		if !bytes.Contains(human, []byte(row)) {
			t.Fatal("human output lost an exact source selection difference", i)
		}
	}
	private := configurationPlanningResult(public)
	private.PrivateComplete = true
	private.DisplayDelivery = contract.PlanningDeliveryComplete
	private.SelectedRecords, private.CompletedRecords = 1, 1
	private.PrivateEntries = []contract.PlanningRelation{{Name: "secret", Form: contract.PlanningRetained, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}}
	result, err := RenderPlanningJSON(private)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := RenderPlanningCommandJSON(private)
	var compact bytes.Buffer
	if err := json.Compact(&compact, result); err != nil {
		t.Fatal("ordinary plan result is not JSON", err)
	}
	expected := append([]byte(`{"kind":"plan-result","result":`), compact.Bytes()...)
	expected = append(expected, '}', '\n')
	if err != nil || len(terminal) != cap(terminal) || !bytes.Equal(terminal, expected) {
		t.Fatal("terminal framing changed or retained excess backing", err)
	}
	for _, condition := range []struct {
		name   string
		change func(*InstallationRequirementComparison)
	}{
		{"nil-differences", func(v *InstallationRequirementComparison) { v.Differences = nil }},
		{"incomplete-with-differences", func(v *InstallationRequirementComparison) { v.Complete = false }},
		{"too-many", func(v *InstallationRequirementComparison) { v.Differences = append(v.Differences, v.Differences[0]) }},
		{"duplicate", func(v *InstallationRequirementComparison) { v.Differences[1] = v.Differences[0] }},
		{"invalid-name", func(v *InstallationRequirementComparison) { v.Differences[6].Name = "../unknown" }},
		{"both-absent", func(v *InstallationRequirementComparison) {
			v.Differences[6].Trusted = nil
			v.Differences[6].Candidate = nil
		}},
		{"equal", func(v *InstallationRequirementComparison) { v.Differences[6].Trusted = v.Differences[6].Candidate }},
		{"invalid-version", func(v *InstallationRequirementComparison) {
			v.Differences[6].Candidate = &InstallationRequirement{Version: "*"}
		}},
	} {
		t.Run(condition.name, func(t *testing.T) {
			malformed := comparison
			malformed.Differences = append([]InstallationRequirementDifference(nil), comparison.Differences...)
			condition.change(&malformed)
			public.InstallationRequirements = malformed
			private.InstallationRequirements = malformed
			if body, err := RenderComparisonJSON(public); err != ErrReaderResult || body != nil || ComparisonExitCode(public) != 2 {
				t.Fatal("malformed source comparison escaped", err)
			}
			if body, err := RenderPlanningCommandJSON(private); err != ErrReaderResult || body != nil || PlanningExitCode(private) != 2 {
				t.Fatal("malformed source planning escaped", err)
			}
		})
	}
}

// full_only: false
func TestConfigurationTrustedUnresolvedSourcePrecedesMalformedCandidate(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "public", true: "private"}[private], func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, func(editable, _ map[string]any) {
				editable["plugins"] = map[string]any{"generic-json": map[string]any{"version": "1.0.0"}}
			})
			var editable map[string]any
			if err := json.Unmarshal(source.editableBytes, &editable); err != nil {
				t.Fatal(err)
			}
			delete(editable, "generated")
			body, err := json.Marshal(editable)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "unresolved.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			trusted, err := configuration.Capture(ctx, path, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := trusted.Close(); err != nil {
					t.Error(err)
				}
			})
			model, err := configuration.Parse(ctx, trusted)
			if err != nil || model.Resolved {
				t.Fatal("fixture does not contain a valid unresolved source", err)
			}
			malformed := &configuration.Pair{Format: configuration.YAML}
			calls := 0
			request := contract.Hash([]byte("trusted unresolved refusal priority"))
			var diagnostics []contract.Diagnostic
			var identity *core.PreAdmissionRequestIdentity
			var encoded []byte
			if private {
				result := planConfiguration(ctx, request, trusted, malformed, contract.PlanningOptions{Purpose: contract.PlanningEquality}, nil, func(context.Context, PlanningConfig) (*core.InstalledPlanning, error) {
					calls++
					return nil, errors.New("unexpected construction")
				})
				if result.StateResult != contract.ReaderRefused || PlanningExitCode(result) != 2 {
					t.Fatal("unresolved trusted planning did not refuse", result)
				}
				diagnostics, identity = result.Diagnostics, result.PreAdmission
				encoded, err = RenderPlanningJSON(result)
			} else {
				result := compareConfiguration(ctx, request, trusted, malformed, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
					calls++
					return nil, errors.New("unexpected construction")
				})
				if result.StateResult != contract.ReaderRefused || ComparisonExitCode(result) != 2 {
					t.Fatal("unresolved trusted comparison did not refuse", result)
				}
				diagnostics, identity = result.Diagnostics, result.PreAdmission
				encoded, err = RenderComparisonJSON(result)
			}
			if err != nil || calls != 0 || len(diagnostics) != 1 || diagnostics[0].Reason != contract.ReasonMissingRequiredField || identity == nil || identity.Format != "json" || identity.Stage != "parse" {
				t.Fatal("malformed candidate replaced the trusted-source refusal", diagnostics, identity, calls, err)
			}
			assertConfigurationRequirementComparison(t, encoded, `{"complete":false,"differences":[]}`)
			unchanged, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(unchanged, body) {
				t.Fatal("early refusal changed the trusted source", err)
			}
			source.assertUnchanged(t)
		})
	}
}
