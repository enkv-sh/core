package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
)

// full_only: false
func TestPreparationAssociationsAndRoutineHumanViews(t *testing.T) {
	t.Run("dependency-source-subjects", func(t *testing.T) {
		model := &configuration.Model{
			Entries: []configuration.Entry{
				{Name: "a", EntrySpan: 0, Generated: &configuration.Generator{Plugin: "shared-plugin", Settings: []byte(`{}`)}},
				{Name: "b", EntrySpan: 1, Generated: &configuration.Generator{Plugin: "shared-plugin", Settings: []byte(`{}`)}},
				{Name: "c", EntrySpan: 2, Generated: &configuration.Generator{Intent: dependencyCanonicalIntent(false)}},
			},
			Spans: []configuration.Span{{Kind: configuration.SpanEntry, Index: 2}, {Kind: configuration.SpanEntry, Index: 0}, {Kind: configuration.SpanEntry, Index: 1}},
		}
		checks, err := configurationDependencyChecks(model)
		if err != nil || len(checks) != 2 {
			t.Fatal("equivalent requirement checks did not deduplicate", err, checks)
		}
		for _, check := range checks {
			body, err := json.Marshal(check)
			var row struct {
				Plugin   *string  `json:"plugin"`
				Reason   string   `json:"reason"`
				Subjects []uint16 `json:"subjects"`
			}
			if err != nil || json.Unmarshal(body, &row) != nil {
				t.Fatal("requirement JSON refused", err)
			}
			if row.Plugin == nil {
				if row.Reason != "selection-required" || !reflect.DeepEqual(row.Subjects, []uint16{1}) {
					t.Fatal("missing selection lost exact source subject", string(body))
				}
			} else if !reflect.DeepEqual(row.Subjects, []uint16{0, 2}) {
				t.Fatal("deduplication lost source-order subjects", string(body))
			}
		}
	})
	t.Run("initialization-pair", func(t *testing.T) {
		r := initializationRenderingFixture(t)
		body, err := RenderInitializationHuman(r, nil)
		if err != nil || !bytes.Contains(body, []byte(r.EditablePath)) || !bytes.Contains(body, []byte(r.GeneratedPath)) || bytes.Contains(body, []byte(r.ManifestPath)) {
			t.Fatal("initialization pair projection differs", err, string(body))
		}
	})
	t.Run("apply-uncertainty", func(t *testing.T) {
		r := suppliedApplyResultFixture(t)
		r.Preparation = &core.ApplyPreparationFacts{VerifiedPreparations: 2, AcknowledgedCreates: 1, PossibleUnacknowledgedCreate: true}
		body, err := RenderApplyHuman(r)
		if err != nil || bytes.Contains(body, []byte("Local preparations:")) || bytes.Contains(body, []byte("Changed subjects:")) || !bytes.Contains(body, []byte("create may have occurred without acknowledgement")) || !bytes.Contains(body, []byte(readerID(r.OperationID))) {
			t.Fatal("apply summary lost actual uncertainty or kept internal counts", err, string(body))
		}
	})
	t.Run("apply-no-op", func(t *testing.T) {
		body, err := RenderApplyHuman(suppliedApplyNoopResultFixture())
		if err != nil || !bytes.Contains(body, []byte("No changes were applied.")) || bytes.Contains(body, []byte("No transition details")) {
			t.Fatal("no-op lacks a clear result", err, string(body))
		}
	})
	t.Run("local-rename-and-cleanup-paths", func(t *testing.T) {
		source := configurationSetPair(t, "aws", configuration.JSON, nil)
		if err := source.pair.Close(); err != nil {
			t.Fatal(err)
		}
		configurationSetWritable(t, source)
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		result, err := RenameConfigurationDomain(ctx, source.path, configuration.JSON, "renamed")
		if err != nil {
			t.Fatal(err)
		}
		_, generated := result.delivery.Paths()
		body, err := RenderLocalEditHuman(result, nil)
		if err != nil || !bytes.Contains(body, []byte(generated)) || bytes.Contains(body, []byte(source.path)) {
			t.Fatal("rename hides its changed generated location or repeats editable input", err, string(body))
		}
		result.cleanupFail = true
		body, err = RenderLocalEditHuman(result, nil)
		if err != nil || !bytes.Contains(body, []byte(source.path)) || !bytes.Contains(body, []byte(generated)) || !bytes.Contains(body, []byte("Local cleanup did not complete.")) {
			t.Fatal("known cleanup failure hides files needed for action", err, string(body))
		}
	})
	t.Run("manifest-artifact-first", func(t *testing.T) {
		r := completeManifestFileResultFixture()
		body, err := RenderManifestFileHuman(r)
		if err != nil || !strings.HasPrefix(string(body), "Manifest file: \"/tmp/manifest.json\"") || bytes.Contains(body, []byte("Settings (Base64)")) || bytes.Contains(body, []byte("Renderer artifact:")) || !bytes.Contains(body, []byte("Result-stream delivery is not observed")) {
			t.Fatal("manifest projection hides artifact or delivery limit", err, string(body))
		}
	})
	t.Run("materialize-artifact-first", func(t *testing.T) {
		r := materializationRenderingCleanupResult(t)
		var out bytes.Buffer
		if err := WriteMaterializationHuman(t.Context(), &out, r); err != nil || !strings.HasPrefix(out.String(), "Materialize file: \"/private/application.env\"") || !strings.Contains(out.String(), "Private residue:") || !strings.Contains(out.String(), "Candidate cleanup: failed") {
			t.Fatal("materialize projection hides target or cleanup", err, out.String())
		}
	})
}

// full_only: false
func TestPrepareSubjectAssociationsStayBoundedAndOwned(t *testing.T) {
	maximum := func() prepareResultFacts {
		facts := prepareResultFactsForTest()
		facts.Outcome = "incomplete"
		facts.Dependencies.AllDeclaredReady = false
		for _, role := range []string{"generator", "manifest-generator", "output"} {
			count := 512
			switch role {
			case "output":
				count = 64
			case "manifest-generator":
				count = 1
			}
			subjects := make([]uint16, count)
			for i := range subjects {
				subjects[i] = uint16(i)
			}
			facts.Dependencies.Requirements = append(facts.Dependencies.Requirements, PrepareDependencyRequirement{Role: role, Subjects: subjects, ProtocolVersion: 1, Status: "missing", Reason: "selection-required"})
		}
		return facts
	}
	t.Run("complete-deduplicated-maximum", func(t *testing.T) {
		result := &PrepareResult{facts: maximum()}
		body, err := RenderPrepareJSON(result)
		if err != nil || len(body) > 1572864 {
			t.Fatal("577 exact subjects refused", err)
		}
		var wire struct {
			Dependencies struct {
				Requirements []struct {
					Subjects []uint16 `json:"subjects"`
				} `json:"requirements"`
			} `json:"dependencies"`
		}
		if json.Unmarshal(body, &wire) != nil || len(wire.Dependencies.Requirements) != 3 {
			t.Fatal("complete deduplicated vector changed", string(body))
		}
		for row, count := range []int{512, 1, 64} {
			subjects := wire.Dependencies.Requirements[row].Subjects
			if len(subjects) != count {
				t.Fatal("subject set truncated", row, len(subjects))
			}
			for i, subject := range subjects {
				if subject != uint16(i) {
					t.Fatal("subject set changed", row, i, subject)
				}
			}
		}
		human, err := RenderPrepareHuman(result)
		if err != nil || !bytes.Contains(human, []byte("Entry declaration 512 (source order)")) || !bytes.Contains(human, []byte("Destination declaration 64 (source order)")) {
			t.Fatal("human subject set truncated", err)
		}
	})
	for _, condition := range []string{"missing", "duplicate", "spare-capacity", "wrong-range", "cross-row-duplicate", "missing-input-overflow", "absent-plugin-not-installed", "selected-plugin-selection-required"} {
		t.Run(condition, func(t *testing.T) {
			facts := maximum()
			switch condition {
			case "missing":
				facts.Dependencies.Requirements[0].Subjects = nil
			case "duplicate":
				facts.Dependencies.Requirements[0].Subjects = []uint16{0, 0}
			case "spare-capacity":
				facts.Dependencies.Requirements[0].Subjects = make([]uint16, 1, 2)
			case "wrong-range":
				facts.Dependencies.Requirements[2].Subjects = []uint16{64}
			case "cross-row-duplicate":
				facts.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{0}, ProtocolVersion: 1, Status: "missing", Reason: "selection-required"}, {Role: "generator", Subjects: []uint16{0}, Contract: "other", ProtocolVersion: 1, Status: "missing", Reason: "selection-required"}}
			case "missing-input-overflow":
				facts.MissingInputs = []string{"missing"}
			case "absent-plugin-not-installed":
				facts.Dependencies.Requirements[0].Reason = "not-installed"
			case "selected-plugin-selection-required":
				facts.Dependencies.Requirements[0].Plugin = dependencyPluginName("selected")
			}
			result := &PrepareResult{facts: facts}
			for _, render := range []func(*PrepareResult) ([]byte, error){RenderPrepareJSON, RenderPrepareHuman} {
				if body, err := render(result); err == nil || body != nil {
					t.Fatal("invalid subjects reached output")
				}
			}
		})
	}
	t.Run("destination-source-order", func(t *testing.T) {
		source := configurationApplyPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
			editable["outputs"] = map[string]any{"destinations": map[string]any{"a": map[string]any{"plugin": "first-plugin", "settings": map[string]any{}}, "z": map[string]any{"plugin": "second-plugin", "settings": map[string]any{}}}, "routing": map[string]any{}}
		})
		if err := source.pair.Close(); err != nil {
			t.Fatal(err)
		}
		configurationSetWritable(t, source)
		if err := os.Chmod(source.path, 0600); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(source.path)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.ReplaceAll(body, []byte(`"a":`), []byte(`"zz":`))
		body = bytes.ReplaceAll(body, []byte(`"z":`), []byte(`"aa":`))
		if err := os.WriteFile(source.path, body, 0600); err != nil {
			t.Fatal(err)
		}
		pair, err := configuration.Capture(context.Background(), source.path, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := pair.Close(); err != nil {
				t.Error(err)
			}
		}()
		model, err := configuration.Parse(t.Context(), pair)
		if err != nil || len(model.Outputs) != 2 || model.Outputs[0].DestinationID != "aa" || model.Outputs[0].SourceIndex != 1 || model.Outputs[1].SourceIndex != 0 {
			t.Fatal("normalized bindings lost captured order", err)
		}
		checks, err := configurationDependencyChecks(model)
		if err != nil || len(checks) != 2 || prepareDependencyPlugin(checks[0]) != "first-plugin" || !reflect.DeepEqual(checks[0].Subjects, []uint16{0}) || !reflect.DeepEqual(checks[1].Subjects, []uint16{1}) {
			t.Fatal("requirements use normalized order", checks, err)
		}
		model.Outputs[0].SourceIndex = 63
		if !reflect.DeepEqual(checks[1].Subjects, []uint16{1}) {
			t.Fatal("requirement subjects borrow mutable model state")
		}
	})
}
