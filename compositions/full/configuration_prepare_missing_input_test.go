package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPrepareMissingInputsIsAlwaysACompleteArray(t *testing.T) {
	for _, status := range []string{"unclassified", "not-attempted", "refused", "failed", "pre-candidate"} {
		t.Run(status, func(t *testing.T) {
			result, err := NewPrepareRefusal()
			if err != nil {
				t.Fatal(err)
			}
			if status != "unclassified" {
				result.facts = prepareResultFactsForTest()
				result.facts.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
				result.facts.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
				result.facts.Outcome = "refused"
				switch status {
				case "not-attempted", "refused":
					result.facts.Recovery = prepareRecoveryFacts{Status: status}
				case "failed":
					result.facts.Recovery = prepareRecoveryFacts{Status: status}
					result.facts.Outcome = "incomplete"
				case "pre-candidate":
					result.facts.Outcome = "incomplete"
					result.facts.Diagnostics = []prepareDiagnostic{{Reason: "delivery-failed", Subject: "delivery"}}
				}
			}
			body, err := RenderPrepareJSON(result)
			if err != nil {
				t.Fatal("legal pre-candidate result did not render", err)
			}
			var record map[string]json.RawMessage
			if err := json.Unmarshal(body, &record); err != nil {
				t.Fatal(err)
			}
			var missing []any
			if row, present := record["missing_inputs"]; !present || json.Unmarshal(row, &missing) != nil || missing == nil || len(missing) != 0 {
				t.Fatal("result lacks an explicit empty complete missing-input array", string(record["missing_inputs"]))
			}
		})
	}
}

// full_only: false
func TestPrepareMissingCompanionRecordsCompleteMissingInputVector(t *testing.T) {
	projection, basis, selected := configurationReconstructionProjection(t, "aws")
	current, err := ReconstructionConfiguration(t.Context(), projection, basis, ReconstructionConfigurationOptions{Name: "restored", FileID: contract.ID{0x74}})
	projection.Close()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"missing-first", "missing-second"}
	for _, entry := range current.Entries {
		if entry.Name == names[0] || entry.Name == names[1] {
			t.Fatal("missing-input fixture accidentally selected a committed entry")
		}
	}
	current.Entries = []configuration.Entry{{Name: names[0], Secret: true}, {Name: names[1], Secret: true}}
	current.Outputs, current.Routes = nil, nil
	current.Public.Groups = contract.PublicField[[][]string]{State: contract.PublicPresent, Value: [][]string{}}
	if err := configuration.RefreshPublic(current); err != nil {
		t.Fatal(err)
	}
	var source bytes.Buffer
	if err := configuration.EmitEditable(&source, current, configuration.YAML); err != nil {
		t.Fatal("surviving missing-input source fixture is invalid", err)
	}
	body := append([]byte("# preserve missing input declarations exactly\n"), source.Bytes()...)
	path := filepath.Join(t.TempDir(), "surviving.yaml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(filepath.Dir(path), current.Generated)
	request := prepareRecoveryRequestForTest(configurationReaderSource{archive: selected.archive}, path, configuration.YAML)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	opens := 0
	open := func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
		opens++
		return core.NewInstalledReconstruction(core.ReconstructionInstallation{Candidate: selected, Normal: selected,
			Construct: func(context.Context, contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
				return selected, core.Result{}
			},
			Verify: func(_ context.Context, pins contract.ReconstructionVerificationPins, _ time.Time) (core.ReconstructionVerifier, error) {
				return &configurationReconstructionVerifier{source: selected, pins: pins}, nil
			}, CloseInstalled: func() {}})
	}
	checkResult := func(result *PrepareResult, branch string, wantNames []string) {
		t.Helper()
		encoded, err := RenderPrepareJSON(result)
		if err != nil {
			t.Fatal("missing-input result failed closed rendering", err)
		}
		var record struct {
			Branch        string `json:"branch"`
			Outcome       string `json:"outcome"`
			MissingInputs []struct {
				Name       string `json:"name"`
				Reason     string `json:"reason"`
				NextAction string `json:"next_action"`
			} `json:"missing_inputs"`
			Dependencies struct {
				Assessment string `json:"assessment"`
				AllReady   bool   `json:"all_declared_ready"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(encoded, &record); err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(record.MissingInputs))
		for _, row := range record.MissingInputs {
			if row.Reason != "supplied-input-missing" || row.NextAction != "set" {
				t.Fatal("missing input lost its closed reason or required action")
			}
			got = append(got, row.Name)
		}
		wantOutcome, wantExit := "incomplete", 2
		if len(wantNames) == 0 {
			wantOutcome, wantExit = "complete", 0
		}
		if record.Branch != branch || record.Outcome != wantOutcome || PrepareExitCode(result, nil) != wantExit || record.MissingInputs == nil || !reflect.DeepEqual(got, wantNames) || record.Dependencies.Assessment != "complete" || record.Dependencies.AllReady != (len(wantNames) == 0) {
			t.Fatal("prepare lost the complete exact missing-input set or readiness", string(encoded))
		}
	}
	result, err := prepareConfiguration(ctx, request, open)
	if err != nil {
		if result != nil {
			t.Logf("safe prepare phase facts: recovery=%+v delivery=%+v diagnostics=%+v", result.facts.Recovery, result.facts.Delivery, result.facts.Diagnostics)
		}
		t.Fatal("authenticated recovery refused positively missing input declarations", err)
	}
	checkResult(result, "reconstruction", names)
	if opens != 1 || result.facts.Recovery.Status != "complete" || result.facts.Delivery.Outcome != "recorded" || len(configurationMissingInputRecords(t, generated)) != 0 {
		t.Fatal("missing inputs prevented authenticated companion delivery or acquired placeholder rows")
	}
	after, statErr := os.Lstat(path)
	saved, readErr := os.ReadFile(path)
	if statErr != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(saved, body) {
		t.Fatal("missing-input recovery changed surviving source bytes or native identity", statErr, readErr)
	}
	configurationMissingInputsStayStrict(t, path, configuration.YAML)
	request.Recovery = nil
	for step := 0; step <= len(names); step++ {
		again, err := prepareConfiguration(ctx, request, open)
		if err != nil {
			t.Fatal("existing-pair prepare refused validated missing inputs", err)
		}
		checkResult(again, "existing", names[step:])
		if opens != 1 {
			t.Fatal("existing incomplete pair repeated authenticated reconstruction")
		}
		if step == len(names) {
			break
		}
		input := &configurationSetInput{Reader: bytes.NewReader([]byte("actual recovered input"))}
		set, err := SetConfiguration(ctx, path, configuration.YAML, names[step], input, SetOptions{Confidential: true})
		if err != nil || set == nil || set.StateResult != SetSuccess || input.closes != 1 || input.reads == 0 {
			t.Fatal("targeted set could not advance the exact missing set", err)
		}
	}
}

// full_only: false
func TestPrepareExistingMissingInputsKeepsCompleteVectorAtCapacity(t *testing.T) {
	names := make([]string, 512)
	names[0], names[1] = "", strings.Repeat("\x01", 256)
	for i := 2; i < len(names); i++ {
		names[i] = fmt.Sprintf("missing-%03d", i)
	}
	sort.Strings(names)
	source := configurationMissingInputPair(t, configuration.JSON, names)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	opens := 0
	result, err := prepareConfiguration(ctx, PrepareRequest{Source: source.path, Format: configuration.JSON}, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
		opens++
		return nil, ErrPrepare
	})
	if err != nil || opens != 0 {
		t.Fatal("valid existing preparation did not enumerate all absent input records locally", opens, err)
	}
	body, err := RenderPrepareJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	var missing []map[string]string
	if json.Unmarshal(record["missing_inputs"], &missing) != nil || len(missing) != len(names) {
		t.Fatal("missing vector was truncated to diagnostic capacity")
	}
	for i, row := range missing {
		if len(row) != 3 || row["name"] != names[i] || row["reason"] != "supplied-input-missing" || row["next_action"] != "set" {
			t.Fatal("missing row changed exact name, order, or closed shape", i)
		}
	}
	if len(result.facts.Diagnostics) != 0 || result.facts.Outcome != "incomplete" || result.facts.Dependencies.AllDeclaredReady || PrepareExitCode(result, nil) != 2 {
		t.Fatal("complete vector was duplicated into diagnostics or granted operation readiness")
	}
	human, err := RenderPrepareHuman(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if !strings.Contains(string(human), fmt.Sprintf("%q", name)) {
			t.Fatal("human output omitted an exact missing input", name)
		}
	}
	source.assertUnchanged(t)
}

// full_only: false
func TestPrepareMissingInputFactsAndSharedBounds(t *testing.T) {
	missingFacts := func() prepareResultFacts {
		facts := prepareResultFactsForTest()
		facts.MissingInputs = []string{"", "sibling"}
		facts.Outcome, facts.Dependencies.AllDeclaredReady = "incomplete", false
		return facts
	}
	for _, condition := range []struct {
		name string
		code int
		edit func(*prepareResultFacts)
	}{
		{"recorded", 2, func(*prepareResultFacts) {}},
		{"pending", 3, func(f *prepareResultFacts) {
			f.Delivery = prepareDeliveryFacts{Outcome: "pending"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "unknown"
		}},
		{"unknown", 3, func(f *prepareResultFacts) {
			f.Delivery = prepareDeliveryFacts{Outcome: "unknown"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "unknown"
		}},
		{"recovery-owned", 3, func(f *prepareResultFacts) {
			f.Delivery.CleanupFailed = true
			f.Delivery.RecoverySource = f.Delivery.EditablePath
		}},
		{"evidence-unavailable", 3, func(f *prepareResultFacts) {
			f.Dependencies.MinimumAdministrativeReady = false
			f.Diagnostics = []prepareDiagnostic{{Reason: "source-unavailable", Subject: "source"}}
		}},
	} {
		t.Run(condition.name, func(t *testing.T) {
			facts := missingFacts()
			condition.edit(&facts)
			result := &PrepareResult{facts: facts}
			body, err := RenderPrepareJSON(result)
			var record struct {
				Missing []map[string]string `json:"missing_inputs"`
			}
			if err != nil || json.Unmarshal(body, &record) != nil || len(record.Missing) != 2 || PrepareExitCode(result, nil) != condition.code || result.SetupRequired() {
				t.Fatal("validated vector lost delivery/evidence precedence", err)
			}
			for i, row := range record.Missing {
				if len(row) != 3 || row["name"] != facts.MissingInputs[i] || row["reason"] != "supplied-input-missing" || row["next_action"] != "set" {
					t.Fatal("validated vector was changed during presentation")
				}
			}
			if PrepareExitCode(result, ErrPrepareResult) != condition.code {
				t.Fatal("presentation failure erased missing input or delivery precedence")
			}
		})
	}
	for _, condition := range []struct {
		name string
		edit func(*prepareResultFacts)
	}{
		{"complete", func(f *prepareResultFacts) { f.Outcome = "complete" }},
		{"all-ready", func(f *prepareResultFacts) { f.Dependencies.AllDeclaredReady = true }},
		{"duplicate", func(f *prepareResultFacts) { f.MissingInputs = []string{"same", "same"} }},
		{"unordered", func(f *prepareResultFacts) { f.MissingInputs = []string{"z", "a"} }},
		{"invalid-utf8", func(f *prepareResultFacts) { f.MissingInputs = []string{string([]byte{0xff})} }},
		{"name-first-excess", func(f *prepareResultFacts) { f.MissingInputs = []string{strings.Repeat("x", 257)} }},
		{"vector-first-excess", func(f *prepareResultFacts) {
			f.MissingInputs = make([]string, 513)
			for i := range f.MissingInputs {
				f.MissingInputs[i] = fmt.Sprintf("%03d", i)
			}
		}},
		{"unclassified", func(f *prepareResultFacts) { f.Branch = "unclassified" }},
		{"recovery-failed", func(f *prepareResultFacts) { f.Recovery = prepareRecoveryFacts{Status: "failed"} }},
	} {
		t.Run(condition.name, func(t *testing.T) {
			facts := missingFacts()
			condition.edit(&facts)
			if body, err := RenderPrepareJSON(&PrepareResult{facts: facts}); err == nil || body != nil {
				t.Fatal("contradictory or incomplete missing vector rendered")
			}
		})
	}
	t.Run("shared-generator-and-missing-account", func(t *testing.T) {
		facts := missingFacts()
		facts.MissingInputs = []string{strings.Repeat("\x01", 256)}
		for i := 0; i < 576; i++ {
			role, protocol := "generator", uint32(5)
			if i == 511 {
				role = "manifest-generator"
			} else if i > 511 {
				role, protocol = "output", 6
			}
			subject := uint16(i)
			if i == 511 {
				subject = 0
			} else if i > 511 {
				subject = uint16(i - 512)
			}
			facts.Dependencies.Requirements = append(facts.Dependencies.Requirements, PrepareDependencyRequirement{Role: role, Subjects: []uint16{subject}, Contract: fmt.Sprintf("%04d", i), ProtocolVersion: protocol, Status: "missing", Reason: "selection-required"})
		}
		body, err := RenderPrepareJSON(&PrepareResult{facts: facts})
		if err != nil || len(body) > 1572864 || len(body) != cap(body) {
			t.Fatal("511 generator + 1 missing + 64 output + 1 renderer rows did not share their account", err)
		}
		facts.Dependencies.Requirements = facts.Dependencies.Requirements[:511]
		facts.Dependencies.Requirements = append(facts.Dependencies.Requirements, PrepareDependencyRequirement{Role: "generator", Subjects: []uint16{511}, Contract: "0511", ProtocolVersion: 5, Status: "missing", Reason: "selection-required"})
		if body, err := RenderPrepareJSON(&PrepareResult{facts: facts}); err == nil || body != nil {
			t.Fatal("512 generators plus one missing input escaped the shared entry bound")
		}
	})
}
