package compositionfull

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/sdk/artifact"
)

func prepareResultFactsForTest() prepareResultFacts {
	return prepareResultFacts{RequestID: strings.Repeat("1", 64), Branch: "reconstruction",
		Recovery: prepareRecoveryFacts{Status: "complete", Domain: strings.Repeat("2", 64), Head: strings.Repeat("3", 64)},
		Delivery: prepareDeliveryFacts{Outcome: "recorded", EditablePath: "/private/configuration.json", GeneratedPath: "/private/.enkv/prod.generated.json",
			Readback: &prepareReadbackFacts{EditableDigest: strings.Repeat("4", 64), GeneratedDigest: strings.Repeat("5", 64)}},
		Dependencies: PrepareDependencyAssessment{Assessment: "complete", MinimumAdministrativeReady: true, AllDeclaredReady: true, Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}},
		Outcome:      "complete", Diagnostics: []prepareDiagnostic{}}
}

// full_only: false
func TestPrepareResultIncludesNonNullInstallations(t *testing.T) {
	result, err := NewPrepareRefusal()
	if err != nil {
		t.Fatal(err)
	}
	record := prepareResultWire(t, result)
	dependencies := record["dependencies"].(map[string]any)
	installations, ok := dependencies["installations"].([]any)
	if !ok || installations == nil || len(installations) != 0 {
		t.Fatal("unattempted dependency assessment lacks an empty installations array", dependencies)
	}
}

// full_only: false
func TestPrepareResultClosedCombinationsAndBounds(t *testing.T) {
	t.Run("fresh-recognized-refusal", func(t *testing.T) {
		first, err := NewPrepareRefusal()
		if err != nil {
			t.Fatal(err)
		}
		second, err := NewPrepareRefusal()
		if err != nil {
			t.Fatal(err)
		}
		got, other := prepareResultWire(t, first), prepareResultWire(t, second)
		if got["request_id"] == other["request_id"] {
			t.Fatal("refusal reused invocation correlation")
		}
		delete(got, "request_id")
		want := map[string]any{"schema": "enkv/prepare-result/v2", "operation": "prepare", "branch": "unclassified", "outcome": "refused",
			"missing_inputs": []any{},
			"recovery":       map[string]any{"status": "not-attempted"}, "local_delivery": map[string]any{"outcome": "not-recorded", "cleanup_failed": false},
			"dependencies": map[string]any{"assessment": "not-attempted", "minimum_administrative_ready": false, "all_declared_ready": false, "requirements": []any{}, "installations": []any{}, "settings_failure": nil},
			"diagnostics":  []any{map[string]any{"reason": "invalid-request", "subject": "request"}}}
		if !reflect.DeepEqual(got, want) || PrepareExitCode(first, nil) != 2 {
			t.Fatal("recognized refusal changed its exact safe facts", got)
		}
	})
	for _, condition := range []struct {
		name string
		edit func(*prepareResultFacts)
		code int
	}{
		{"recorded-complete", func(*prepareResultFacts) {}, 0},
		{"absent-before-reconstruction", func(f *prepareResultFacts) {
			f.Recovery = prepareRecoveryFacts{Status: "not-attempted"}
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "refused"
		}, 2},
		{"recovery-refused", func(f *prepareResultFacts) {
			f.Recovery = prepareRecoveryFacts{Status: "refused"}
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "refused"
			f.Diagnostics = []prepareDiagnostic{{Reason: "trust-invalid", Subject: "recovery"}}
		}, 2},
		{"recovery-failed", func(f *prepareResultFacts) {
			f.Recovery = prepareRecoveryFacts{Status: "failed"}
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "incomplete"
			f.Diagnostics = []prepareDiagnostic{{Reason: "state-invalid", Subject: "recovery"}}
		}, 2},
		{"recovered-before-delivery", func(f *prepareResultFacts) {
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "incomplete"
			f.Diagnostics = []prepareDiagnostic{{Reason: "delivery-failed", Subject: "delivery"}}
		}, 2},
		{"recorded-dependency-missing", func(f *prepareResultFacts) {
			f.Dependencies.AllDeclaredReady = false
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "output", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-plugin"), Contract: strings.Repeat("6", 64), ProtocolVersion: 6, Status: "missing", Reason: "not-installed"}}
			f.Outcome = "incomplete"
			f.Diagnostics = []prepareDiagnostic{{Reason: "dependency-missing", Subject: "dependencies"}}
		}, 2},
		{"recorded-dependency-unavailable", func(f *prepareResultFacts) {
			f.Dependencies.AllDeclaredReady = false
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-plugin"), Contract: strings.Repeat("6", 64), ProtocolVersion: 5, Status: "unavailable", Reason: "unavailable"}}
			f.Outcome = "incomplete"
			f.Diagnostics = []prepareDiagnostic{{Reason: "dependency-unavailable", Subject: "dependencies"}}
		}, 3},
		{"recorded-cleanup-no-marker", func(f *prepareResultFacts) { f.Delivery.CleanupFailed = true; f.Outcome = "incomplete" }, 2},
		{"recorded-cleanup-with-marker", func(f *prepareResultFacts) {
			f.Delivery.CleanupFailed = true
			f.Delivery.RecoverySource = f.Delivery.EditablePath
			f.Outcome = "incomplete"
		}, 3},
		{"pending-without-confirmed-marker", func(f *prepareResultFacts) {
			f.Delivery = prepareDeliveryFacts{Outcome: "pending"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "unknown"
		}, 3},
		{"unknown-without-confirmed-marker", func(f *prepareResultFacts) {
			f.Delivery = prepareDeliveryFacts{Outcome: "unknown"}
			f.Dependencies = PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
			f.Outcome = "unknown"
		}, 3},
		{"existing-complete", func(f *prepareResultFacts) {
			f.Branch = "existing"
			f.Recovery = prepareRecoveryFacts{Status: "not-attempted"}
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
		}, 0},
		{"source-unavailable-retains-assessment", func(f *prepareResultFacts) {
			f.Branch = "existing"
			f.Recovery = prepareRecoveryFacts{Status: "not-attempted"}
			f.Delivery = prepareDeliveryFacts{Outcome: "not-recorded"}
			f.Dependencies.MinimumAdministrativeReady = false
			f.Dependencies.AllDeclaredReady = false
			f.Outcome = "incomplete"
			f.Diagnostics = []prepareDiagnostic{{Reason: "source-unavailable", Subject: "source"}}
		}, 3},
	} {
		t.Run(condition.name, func(t *testing.T) {
			facts := prepareResultFactsForTest()
			condition.edit(&facts)
			result := &PrepareResult{facts: facts}
			record := prepareResultWire(t, result)
			if record["outcome"] != facts.Outcome || PrepareExitCode(result, nil) != condition.code {
				t.Fatal("legal result lost its outcome or exit priority", record)
			}
			wantPresentation := 2
			if condition.code == 3 {
				wantPresentation = 3
			}
			if PrepareExitCode(result, errors.New("private-presentation-sentinel")) != wantPresentation {
				t.Fatal("presentation changed operation exit priority")
			}
			first, err := RenderPrepareJSON(result)
			if err != nil {
				t.Fatal(err)
			}
			clear(first)
			second, err := RenderPrepareJSON(result)
			if err != nil || !json.Valid(second) || !reflect.DeepEqual(prepareResultWire(t, result), record) {
				t.Fatal("caller-owned output changed immutable operation facts", err)
			}
			human, err := RenderPrepareHuman(result)
			recoveryText := "Recovery: " + facts.Recovery.Status + "\n"
			if facts.Recovery.Status == "complete" {
				recoveryText = "Configuration restoration: complete.\n"
			}
			localText := "Local files: " + facts.Delivery.Outcome + "\n"
			if facts.Branch == "existing" {
				recoveryText, localText = "Existing configuration selected.\n", ""
				if strings.Contains(string(human), "Local files:") {
					t.Fatal("existing pair repeated routine delivery detail")
				}
			}
			if err != nil || !strings.Contains(string(human), "Prepare: "+facts.Outcome+"\n") || !strings.Contains(string(human), recoveryText) || !strings.Contains(string(human), localText) {
				t.Fatal("human rendering lost phase facts", err)
			}
			for _, diagnostic := range facts.Diagnostics {
				if !strings.Contains(string(human), "Issue "+diagnostic.Subject+": "+diagnostic.Reason+"\n") {
					t.Fatal("human rendering lost a diagnostic", diagnostic)
				}
			}
		})
	}
	for _, condition := range []struct {
		name string
		edit func(*prepareResultFacts)
	}{
		{"zero-correlation", func(f *prepareResultFacts) { f.RequestID = strings.Repeat("0", 64) }},
		{"unclassified-complete", func(f *prepareResultFacts) { f.Branch = "unclassified" }},
		{"existing-reconstruction", func(f *prepareResultFacts) { f.Branch = "existing" }},
		{"recovery-without-head", func(f *prepareResultFacts) { f.Recovery.Head = "" }},
		{"unattempted-with-proof", func(f *prepareResultFacts) { f.Recovery.Status = "not-attempted" }},
		{"recorded-without-readback", func(f *prepareResultFacts) { f.Delivery.Readback = nil }},
		{"recorded-without-generated-path", func(f *prepareResultFacts) { f.Delivery.GeneratedPath = "" }},
		{"complete-with-cleanup-failure", func(f *prepareResultFacts) { f.Delivery.CleanupFailed = true }},
		{"complete-with-marker", func(f *prepareResultFacts) { f.Delivery.RecoverySource = f.Delivery.EditablePath }},
		{"complete-without-readiness", func(f *prepareResultFacts) { f.Dependencies.AllDeclaredReady = false }},
		{"all-ready-without-administration", func(f *prepareResultFacts) { f.Dependencies.MinimumAdministrativeReady = false }},
		{"unattempted-with-readiness", func(f *prepareResultFacts) { f.Dependencies.Assessment = "not-attempted" }},
		{"verified-without-artifact", func(f *prepareResultFacts) {
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "output", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-plugin"), Contract: strings.Repeat("6", 64), ProtocolVersion: 6, Status: "verified", Reason: "none"}}
		}},
		{"failed-requirement-with-all-ready", func(f *prepareResultFacts) {
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "output", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-plugin"), Contract: strings.Repeat("6", 64), ProtocolVersion: 6, Status: "missing", Reason: "not-installed"}}
		}},
		{"unknown-requirement-status", func(f *prepareResultFacts) {
			f.Dependencies.AllDeclaredReady, f.Outcome = false, "incomplete"
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "output", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-plugin"), Contract: strings.Repeat("6", 64), ProtocolVersion: 6, Status: "downloaded", Reason: "none"}}
		}},
		{"unknown-requirement-reason", func(f *prepareResultFacts) {
			f.Dependencies.AllDeclaredReady, f.Outcome = false, "incomplete"
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "output", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-plugin"), Contract: strings.Repeat("6", 64), ProtocolVersion: 6, Status: "missing", Reason: "private-provider-error"}}
		}},
		{"null-plugin-with-artifact", func(f *prepareResultFacts) {
			digest := strings.Repeat("6", 64)
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{0}, Contract: "private/v1", ProtocolVersion: 5, Artifact: &digest, Status: "verified", Reason: "none"}}
		}},
		{"plugin-path", func(f *prepareResultFacts) {
			f.Dependencies.AllDeclaredReady = false
			f.Outcome = "incomplete"
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{0}, Plugin: dependencyPluginName("../private"), ProtocolVersion: 5, Status: "missing", Reason: "not-installed"}}
		}},
		{"contract-first-excess", func(f *prepareResultFacts) {
			f.Dependencies.AllDeclaredReady = false
			f.Outcome = "incomplete"
			f.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{0}, Plugin: dependencyPluginName("private"), Contract: strings.Repeat("x", 257), ProtocolVersion: 5, Status: "missing", Reason: "not-installed"}}
		}},
		{"unknown-diagnostic", func(f *prepareResultFacts) {
			f.Diagnostics = []prepareDiagnostic{{Reason: "private-provider-error", Subject: "source"}}
		}},
		{"diagnostic-first-excess", func(f *prepareResultFacts) {
			f.Diagnostics = make([]prepareDiagnostic, 65)
			for i := range f.Diagnostics {
				f.Diagnostics[i] = prepareDiagnostic{Reason: "dependency-missing", Subject: "dependencies"}
			}
		}},
		{"path-first-excess", func(f *prepareResultFacts) { f.Delivery.EditablePath = "/" + strings.Repeat("a", 4096) }},
	} {
		t.Run(condition.name, func(t *testing.T) {
			facts := prepareResultFactsForTest()
			condition.edit(&facts)
			if body, err := RenderPrepareJSON(&PrepareResult{facts: facts}); err == nil || body != nil {
				t.Fatal("invalid result escaped closed grammar")
			}
		})
	}
	t.Run("largest-escaped-requirement", func(t *testing.T) {
		digest := strings.Repeat("6", 64)
		row := PrepareDependencyRequirement{Role: "manifest-generator", Subjects: []uint16{0}, Plugin: dependencyPluginName(strings.Repeat("p", 255)), Contract: strings.Repeat("\x01", 256), ProtocolVersion: ^uint32(0), Artifact: &digest, Status: "incompatible", Reason: "unsupported-protocol"}
		// Complete JSON syntax plus maximal escaped settings, plugin name,
		// u32, digest, longest legal status/reason and renderer ordinal yield 2,025 bytes.
		independent, err := json.Marshal(row)
		if err != nil || len(independent) != 2025 {
			t.Fatal("independent maximum requirement row", len(independent), err)
		}
		facts := prepareResultFactsForTest()
		facts.Outcome = "incomplete"
		facts.Dependencies.AllDeclaredReady = false
		facts.Dependencies.Requirements = []PrepareDependencyRequirement{row}
		body, err := RenderPrepareJSON(&PrepareResult{facts: facts})
		var wire struct {
			Dependencies struct {
				Requirements []json.RawMessage `json:"requirements"`
			} `json:"dependencies"`
		}
		if err != nil || json.Unmarshal(body, &wire) != nil || len(wire.Dependencies.Requirements) != 1 || !resultJSONFactsEqual(wire.Dependencies.Requirements[0], independent) {
			t.Fatal("largest attainable requirement was refused or changed", err)
		}
	})
	t.Run("requirement-and-escaped-path-accounts", func(t *testing.T) {
		facts := prepareResultFactsForTest()
		facts.Delivery.EditablePath = "/" + strings.Repeat("\x01", 4095)
		facts.Delivery.GeneratedPath = "/" + strings.Repeat("\x02", 4095)
		facts.Delivery.RecoverySource = "/" + strings.Repeat("\x03", 4095)
		facts.Delivery.CleanupFailed, facts.Outcome = true, "incomplete"
		for i := 0; i < 577; i++ {
			artifact := fmt.Sprintf("%064x", i+1)
			role := "generator"
			if i >= 513 {
				role = "output"
			}
			semantic, version := strings.Repeat("\x01", 252)+fmt.Sprintf("%04d", i), ^uint32(0)
			if i == 512 {
				role = "manifest-generator"
			}
			subject := uint16(i)
			if i == 512 {
				subject = 0
			} else if i >= 513 {
				subject = uint16(i - 513)
			}
			facts.Dependencies.Requirements = append(facts.Dependencies.Requirements, PrepareDependencyRequirement{Role: role, Subjects: []uint16{subject}, Plugin: dependencyPluginName(strings.Repeat("p", 255)), Contract: semantic, ProtocolVersion: version, Artifact: &artifact, Status: "verified", Reason: "none"})
		}
		for i := 0; i < 64; i++ {
			name := fmt.Sprintf("%03d", i) + strings.Repeat("p", 252)
			digest, previous := artifact.Digest{byte(i + 1)}, artifact.Digest{byte(i + 80)}
			version := "1.0.0-" + strings.Repeat("a", 122)
			facts.Dependencies.Installations = append(facts.Dependencies.Installations, plugininstallation.Installation{Name: name, Role: "manifest-generator", Version: version, Artifact: &digest, Platform: "linux/amd64", Source: "official", Status: "verified", Reason: "none", Previous: &plugininstallation.Previous{Version: version, Artifact: previous, Platform: "linux/amd64", Source: "official"}, Changed: true})
		}
		for i := 0; i < 64; i++ {
			facts.Diagnostics = append(facts.Diagnostics, prepareDiagnostic{Reason: "cleanup-failed", Subject: "delivery"})
		}
		settingsPath := "/" + strings.Repeat("\x04", 4095)
		facts.Dependencies.Assessment = "incomplete"
		facts.Dependencies.AllDeclaredReady = false
		facts.Dependencies.SettingsFailure = &plugininstallation.SettingsFailure{Stage: "settings", Object: "plugins.json", Path: &settingsPath, Reason: "limit-exceeded", Location: &artifact.SettingsLocation{Byte: 1048576, Line: 1048577, Column: 1048577, Precision: "context"}, Action: "correct-settings"}
		body, err := RenderPrepareJSON(&PrepareResult{facts: facts})
		if err != nil || len(body) > 1572864 {
			t.Fatal("independently bounded result refused", len(body), err)
		}
		var record struct {
			Dependencies struct {
				Requirements  []json.RawMessage `json:"requirements"`
				Installations []json.RawMessage `json:"installations"`
			} `json:"dependencies"`
			Diagnostics []json.RawMessage `json:"diagnostics"`
		}
		if err := json.Unmarshal(body, &record); err != nil {
			t.Fatal(err)
		}
		if len(record.Dependencies.Requirements) != 577 || len(record.Dependencies.Installations) != 64 || len(record.Diagnostics) != 64 {
			t.Fatal("bounded result truncated required facts")
		}
		// Ordinary JSON encoding derives the literal row account independently
		// of RenderPrepareJSON. Contract controls use six bytes each.
		independent, err := json.Marshal(facts.Dependencies.Requirements[0])
		if err != nil || len(independent) != 1976 {
			t.Fatal("independent complete requirement account", len(independent), err)
		}
		for _, row := range record.Dependencies.Requirements {
			if len(row) > 2304 {
				t.Fatal("requirement exceeded its independent account")
			}
		}
		for _, row := range record.Dependencies.Installations {
			if len(row) > 1280 {
				t.Fatal("installation exceeded its independent account")
			}
		}
		for _, row := range record.Diagnostics {
			if len(row) > 128 {
				t.Fatal("diagnostic exceeded its independent account")
			}
		}
		// These are the adopted independent maxima, not values derived by the renderer.
		if 577*2304+576+73728+32768+64*1280+64+26624 != 1545088 {
			t.Fatal("independent result account changed")
		}
		facts.Dependencies.Requirements = append(facts.Dependencies.Requirements, facts.Dependencies.Requirements[0])
		if body, err := RenderPrepareJSON(&PrepareResult{facts: facts}); err == nil || body != nil {
			t.Fatal("first excess requirement escaped")
		}
	})
}

// full_only: false
func TestPrepareInstallationFactsPreserveUpdatesAndRejectContradictions(t *testing.T) {
	current, prior := artifact.Digest{7}, artifact.Digest{8}
	row := plugininstallation.Installation{Name: "generic-json", Role: "manifest-generator", Version: "2.0.0", Artifact: &current, Platform: "linux/amd64", Source: "official", Status: "verified", Reason: "none", Previous: &plugininstallation.Previous{Version: "1.0.0", Artifact: prior, Platform: "linux/amd64", Source: "official"}, Changed: true}
	for _, condition := range []struct {
		name   string
		change func(*prepareResultFacts)
		code   int
	}{
		{"changed", func(*prepareResultFacts) {}, 2},
		{"private-plugin", func(f *prepareResultFacts) { f.Dependencies.Installations[0].Name = "private-renderer" }, 2},
		{"first-selection", func(f *prepareResultFacts) { f.Dependencies.Installations[0].Previous = nil }, 2},
		{"unchanged", func(f *prepareResultFacts) {
			r := &f.Dependencies.Installations[0]
			r.Changed = false
			r.Previous = &plugininstallation.Previous{Version: r.Version, Artifact: current, Platform: r.Platform, Source: r.Source}
		}, 2},
		{"failed-update", func(f *prepareResultFacts) {
			r := &f.Dependencies.Installations[0]
			r.Status, r.Reason, r.Changed = "unavailable", "build-incomplete", false
		}, 3},
		{"source-changed", func(f *prepareResultFacts) {
			f.Dependencies.MinimumAdministrativeReady = false
			f.Diagnostics = []prepareDiagnostic{{Reason: "source-changed", Subject: "source"}}
		}, 2},
	} {
		t.Run(condition.name, func(t *testing.T) {
			facts := prepareResultFactsForTest()
			facts.Outcome = "incomplete"
			facts.Dependencies.AllDeclaredReady = false
			facts.Dependencies.Installations = []plugininstallation.Installation{row}
			condition.change(&facts)
			body, err := RenderPrepareJSON(&PrepareResult{facts: facts})
			if err != nil || len(body) != cap(body) || PrepareExitCode(&PrepareResult{facts: facts}, nil) != condition.code {
				t.Fatal("known installation facts were lost", err)
			}
			var got struct {
				Dependencies struct {
					Installations []plugininstallation.Installation `json:"installations"`
				} `json:"dependencies"`
			}
			if err := json.Unmarshal(body, &got); err != nil || !reflect.DeepEqual(got.Dependencies.Installations, facts.Dependencies.Installations) {
				t.Fatal("update identity or readiness projection changed", err)
			}
		})
	}
	for _, condition := range []struct {
		name   string
		change func(*PrepareDependencyAssessment)
	}{
		{"null-installations", func(v *PrepareDependencyAssessment) { v.Installations = nil }},
		{"first-excess", func(v *PrepareDependencyAssessment) { v.Installations = make([]plugininstallation.Installation, 65) }},
		{"duplicate", func(v *PrepareDependencyAssessment) { v.Installations = append(v.Installations, v.Installations[0]) }},
		{"invalid-name", func(v *PrepareDependencyAssessment) { v.Installations[0].Name = "../unknown" }},
		{"wrong-role", func(v *PrepareDependencyAssessment) { v.Installations[0].Role = "unknown" }},
		{"unknown-source", func(v *PrepareDependencyAssessment) { v.Installations[0].Source = "project" }},
		{"invalid-platform", func(v *PrepareDependencyAssessment) { v.Installations[0].Platform = "any" }},
		{"invalid-version", func(v *PrepareDependencyAssessment) { v.Installations[0].Version = "*" }},
		{"verified-without-version", func(v *PrepareDependencyAssessment) { v.Installations[0].Version = "" }},
		{"verified-without-artifact", func(v *PrepareDependencyAssessment) { v.Installations[0].Artifact = nil }},
		{"changed-failure", func(v *PrepareDependencyAssessment) {
			v.Installations[0].Status = "unavailable"
			v.Installations[0].Reason = "unavailable"
		}},
		{"changed-same-identity", func(v *PrepareDependencyAssessment) {
			r := &v.Installations[0]
			r.Previous = &plugininstallation.Previous{Version: r.Version, Artifact: current, Platform: r.Platform, Source: r.Source}
		}},
		{"unchanged-different-identity", func(v *PrepareDependencyAssessment) { v.Installations[0].Changed = false }},
		{"unknown-status", func(v *PrepareDependencyAssessment) { v.Installations[0].Status = "downloaded" }},
		{"unknown-reason", func(v *PrepareDependencyAssessment) { v.Installations[0].Reason = "private-error" }},
	} {
		t.Run(condition.name, func(t *testing.T) {
			facts := prepareResultFactsForTest()
			facts.Outcome = "incomplete"
			facts.Dependencies.AllDeclaredReady = false
			facts.Dependencies.Installations = []plugininstallation.Installation{row}
			condition.change(&facts.Dependencies)
			if body, err := RenderPrepareJSON(&PrepareResult{facts: facts}); err != ErrPrepareResult || body != nil {
				t.Fatal("contradictory installation facts escaped", err)
			}
		})
	}
}

// full_only: false
func TestPrepareSettingsFailurePreservesCompletedPhases(t *testing.T) {
	makeFacts := func(reason string) prepareResultFacts {
		facts := prepareResultFactsForTest()
		facts.Outcome = "incomplete"
		facts.Dependencies.Assessment = "incomplete"
		facts.Dependencies.AllDeclaredReady = false
		path := "/trusted/plugins.json"
		action, rowReason := "correct-settings", "settings-invalid"
		if reason == "settings-unavailable" {
			action, rowReason = "check-settings-access", "settings-unavailable"
		}
		facts.Dependencies.SettingsFailure = &plugininstallation.SettingsFailure{Stage: "settings", Object: "plugins.json", Path: &path, Reason: reason, Action: action}
		facts.Dependencies.Requirements = []PrepareDependencyRequirement{{Role: "output", Subjects: []uint16{0}, Plugin: dependencyPluginName("private-output"), Status: "not-attempted", Reason: rowReason}}
		return facts
	}
	for _, reason := range []string{"unknown-field", "settings-unavailable"} {
		t.Run(reason, func(t *testing.T) {
			facts := makeFacts(reason)
			result := &PrepareResult{facts: facts}
			body, err := RenderPrepareJSON(result)
			if err != nil {
				t.Fatal("legal completed phases refused", err)
			}
			var wire struct {
				Recovery     prepareRecoveryFacts        `json:"recovery"`
				Delivery     prepareDeliveryFacts        `json:"local_delivery"`
				Dependencies PrepareDependencyAssessment `json:"dependencies"`
				Outcome      string                      `json:"outcome"`
				Diagnostics  []prepareDiagnostic         `json:"diagnostics"`
			}
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(wire.Recovery, facts.Recovery) || !reflect.DeepEqual(wire.Delivery, facts.Delivery) || !wire.Dependencies.MinimumAdministrativeReady || wire.Dependencies.AllDeclaredReady || wire.Outcome != "incomplete" || len(wire.Diagnostics) != 0 || !reflect.DeepEqual(wire.Dependencies.Requirements, facts.Dependencies.Requirements) {
				t.Fatal("settings failure erased completed facts", wire)
			}
			want := 2
			if reason == "settings-unavailable" {
				want = 3
			}
			if PrepareExitCode(result, nil) != want || PrepareExitCode(result, errors.New("writer failed")) != want {
				t.Fatal("presentation failure changed phase exit", result.facts)
			}
			after, err := RenderPrepareJSON(result)
			if err != nil || !bytes.Equal(body, after) {
				t.Fatal("presentation failure changed retained operation facts", err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*prepareResultFacts)
	}{
		{"stage", func(f *prepareResultFacts) { f.Dependencies.SettingsFailure.Stage = "artifact" }},
		{"object", func(f *prepareResultFacts) { f.Dependencies.SettingsFailure.Object = "plugin" }},
		{"reason", func(f *prepareResultFacts) { f.Dependencies.SettingsFailure.Reason = "private-error" }},
		{"action", func(f *prepareResultFacts) { f.Dependencies.SettingsFailure.Action = "retry-reconstruction" }},
		{"missing-path", func(f *prepareResultFacts) { f.Dependencies.SettingsFailure.Path = nil }},
		{"long-path", func(f *prepareResultFacts) { p := strings.Repeat("x", 4097); f.Dependencies.SettingsFailure.Path = &p }},
		{"invalid-utf8-path", func(f *prepareResultFacts) { p := string([]byte{255}); f.Dependencies.SettingsFailure.Path = &p }},
		{"location-bound", func(f *prepareResultFacts) {
			f.Dependencies.SettingsFailure.Location = &artifact.SettingsLocation{Byte: 1048577, Line: 1, Column: 1, Precision: "exact"}
		}},
		{"location-origin", func(f *prepareResultFacts) {
			f.Dependencies.SettingsFailure.Location = &artifact.SettingsLocation{Line: 0, Column: 1, Precision: "exact"}
		}},
		{"location-precision", func(f *prepareResultFacts) {
			f.Dependencies.SettingsFailure.Location = &artifact.SettingsLocation{Line: 1, Column: 1, Precision: "cursor"}
		}},
		{"complete-assessment", func(f *prepareResultFacts) { f.Dependencies.Assessment = "complete" }},
		{"ready", func(f *prepareResultFacts) { f.Dependencies.AllDeclaredReady = true }},
		{"blocked-artifact", func(f *prepareResultFacts) {
			d := strings.Repeat("1", 64)
			f.Dependencies.Requirements[0].Artifact = &d
		}},
		{"blocked-reason", func(f *prepareResultFacts) { f.Dependencies.Requirements[0].Reason = "settings-unavailable" }},
		{"blocked-without-failure", func(f *prepareResultFacts) { f.Dependencies.SettingsFailure = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := makeFacts("unknown-field")
			tc.change(&facts)
			if body, err := RenderPrepareJSON(&PrepareResult{facts: facts}); err == nil || body != nil {
				t.Fatal("contradictory settings facts accepted")
			}
		})
	}
}
