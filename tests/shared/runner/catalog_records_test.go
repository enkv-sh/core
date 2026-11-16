package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestRecordedNamedPointSmokeScheduleKeepsOriginalBytes(t *testing.T) {
	const wire = `{"recovery_mode":"both","selected_scenarios":["state.single-value-update-preserves-other-values/members_64","state.single-value-update-preserves-other-values/members_1"],"repetitions":1,"entries":[{"scenario":"state.single-value-update-preserves-other-values/members_64","sequence":0,"repetition":0,"smoke":true},{"scenario":"state.single-value-update-preserves-other-values/members_1","sequence":1,"repetition":1,"smoke":false}],"full_coverage":false,"smoke_policy":"first-selected-point"}`
	var retained catalog.Schedule
	if err := json.Unmarshal([]byte(wire), &retained); err != nil {
		t.Fatal("original named schedule fixture unavailable", err)
	}
	got, err := reconstructRecordedSchedule(retained)
	if err != nil || !reflect.DeepEqual(got, retained) {
		t.Fatal("old named point smoke schedule lost its exact interpretation", got, err)
	}
	after, err := json.Marshal(retained)
	if err != nil || string(after) != wire {
		t.Fatal("retained named schedule was rewritten", string(after), err)
	}
	for _, damage := range []string{"widened-count", "wrong-later-repetition", "wrong-first-smoke", "reordered-entry", "numeric-override"} {
		t.Run(damage, func(t *testing.T) {
			var changed catalog.Schedule
			if err := json.Unmarshal([]byte(wire), &changed); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "widened-count":
				changed.Repetitions = 3
			case "wrong-later-repetition":
				changed.Entries[1].Repetition = 0
			case "wrong-first-smoke":
				changed.Entries[0].Smoke = false
			case "reordered-entry":
				changed.Entries[0].Scenario, changed.Entries[1].Scenario = changed.Entries[1].Scenario, changed.Entries[0].Scenario
			case "numeric-override":
				changed.MemberCounts = []int{64, 1}
			}
			expected, err := reconstructRecordedSchedule(changed)
			if err == nil && reflect.DeepEqual(expected, changed) {
				t.Fatal("damaged historical named schedule acquired exact execution interpretation")
			}
		})
	}
}

// full_only: false
func TestRecordedNamedSeparateSmokeScheduleKeepsOriginalBytes(t *testing.T) {
	// Each literal retains the old auxiliary smoke and every selected attempt.
	for _, wire := range []string{
		`{"recovery_mode":"both","selected_scenarios":["state.identical-input-keeps-current-state/members_32","state.single-value-update-preserves-other-values/members_32"],"repetitions":1,"entries":[{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":0,"repetition":0,"smoke":true},{"scenario":"state.identical-input-keeps-current-state/members_32","sequence":1,"repetition":1,"smoke":false},{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":2,"repetition":1,"smoke":false}],"full_coverage":false,"smoke_policy":"separate-point"}`,
		`{"recovery_mode":"both","selected_scenarios":["state.identical-input-keeps-current-state/members_32","state.single-value-update-preserves-other-values/members_32"],"repetitions":3,"entries":[{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":0,"repetition":0,"smoke":true},{"scenario":"state.identical-input-keeps-current-state/members_32","sequence":1,"repetition":1,"smoke":false},{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":2,"repetition":1,"smoke":false},{"scenario":"state.identical-input-keeps-current-state/members_32","sequence":3,"repetition":2,"smoke":false},{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":4,"repetition":2,"smoke":false},{"scenario":"state.identical-input-keeps-current-state/members_32","sequence":5,"repetition":3,"smoke":false},{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":6,"repetition":3,"smoke":false}],"full_coverage":false,"smoke_policy":"separate-point"}`,
	} {
		var retained catalog.Schedule
		if err := json.Unmarshal([]byte(wire), &retained); err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("repetitions_%d", retained.Repetitions), func(t *testing.T) {
			got, err := reconstructRecordedSchedule(retained)
			if err != nil || !reflect.DeepEqual(got, retained) {
				t.Fatal("original named separate smoke lost its complete schedule", got, err)
			}
			after, err := json.Marshal(retained)
			if err != nil || string(after) != wire {
				t.Fatal("retained separate smoke schedule was rewritten", string(after), err)
			}
			current, err := catalog.Resolve(catalog.Request{Include: retained.Selected, Repetitions: retained.Repetitions,
				RecoveryMode: retained.RecoveryMode, SmokePolicy: retained.SmokePolicy})
			if err != nil || reflect.DeepEqual(current, retained) {
				t.Fatal("historical duplicate schedule became current execution", err)
			}
			for _, damage := range []string{"count", "order", "sequence", "smoke", "repetition", "mixed-policy", "missing-selected-point", "numeric", "coverage"} {
				t.Run(damage, func(t *testing.T) {
					var changed catalog.Schedule
					if err := json.Unmarshal([]byte(wire), &changed); err != nil {
						t.Fatal(err)
					}
					switch damage {
					case "count":
						changed.Repetitions = 2
					case "order":
						changed.Entries[1].Scenario, changed.Entries[2].Scenario = changed.Entries[2].Scenario, changed.Entries[1].Scenario
					case "sequence":
						changed.Entries[2].Sequence = 1
					case "smoke":
						changed.Entries[2].Smoke = true
					case "repetition":
						changed.Entries[2].Repetition = 0
					case "mixed-policy":
						changed.Entries[0].Repetition = 1
					case "missing-selected-point":
						changed.Selected = changed.Selected[:1]
					case "numeric":
						changed.MemberCounts = []int{32}
					case "coverage":
						changed.FullCoverage = true
					}
					got, err := reconstructRecordedSchedule(changed)
					if err == nil && reflect.DeepEqual(got, changed) {
						t.Fatal("damaged schedule acquired exact historical interpretation", changed)
					}
				})
			}
		})
	}
}

// full_only: false
func TestSelectedSeparateSmokeCountsEachRequestedRepetition(t *testing.T) {
	const point = "state.single-value-update-preserves-other-values/members_32"
	const other = "state.identical-input-keeps-current-state/members_32"
	entries := []catalog.Entry{
		{Scenario: point, Repetition: 1, Smoke: true},
		{Scenario: other, Sequence: 1, Repetition: 1},
		{Scenario: other, Sequence: 2, Repetition: 2},
		{Scenario: point, Sequence: 3, Repetition: 2},
		{Scenario: other, Sequence: 4, Repetition: 3},
		{Scenario: point, Sequence: 5, Repetition: 3},
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{other, point}, Repetitions: 3})
	if err != nil || !reflect.DeepEqual(schedule.Entries, entries) {
		t.Fatal("selected smoke did not retain its exact repetition identities", schedule, err)
	}
	for _, damage := range []string{"passed", "failed", "unjoined"} {
		t.Run(damage, func(t *testing.T) {
			value := runRecord{Suite: "hermetic", Schedule: schedule}
			for _, entry := range entries {
				value.Scenarios = append(value.Scenarios, scenarioResult{Entry: entry, Outcome: "passed",
					Writer: &workerEvidence{Role: "writer", Started: true, Joined: true}})
			}
			want := []scenarioRepetitionGroup{
				{Scenario: other, RequestedExecutions: 3, CompletedExecutions: 3, Outcome: "passed", CaseSequences: []int{1, 2, 4}},
				{Scenario: point, RequestedExecutions: 3, CompletedExecutions: 3, Outcome: "passed", CaseSequences: []int{0, 3, 5}},
			}
			if damage == "failed" {
				value.Scenarios[3].Outcome, want[1].Outcome = "failed", "failed"
			}
			if damage == "unjoined" {
				value.Scenarios[3].Writer.Joined = false
				want[1].CompletedExecutions, want[1].Outcome = 2, "failed"
			}
			got, err := scenarioRepetitionGroups(value)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("selected smoke changed requested N, completed K, or group order", got, want, err)
			}
		})
	}
}

// full_only: false
func TestRecordedCaseDirectoriesKeepOriginalIdentity(t *testing.T) {
	const group = "state.single-value-update-preserves-other-values"
	const leaf = group + "/members_32"
	// SHA-256 of the UTF-8 full leaf, derived with Python hashlib, not catalog.
	const token = "c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981"
	for _, sequence := range []int{0, 9999, 10000} {
		for _, row := range []struct{ name, suffix string }{
			{leaf, token}, {group, "state-single-value-update-preserves-other-values"},
		} {
			entry := catalog.Entry{Scenario: row.name, Sequence: sequence}
			got, err := recordedCaseDirectory(entry)
			if err != nil || got != fmt.Sprintf("%04d-%s", sequence, row.suffix) || strings.Contains(got, "/") {
				t.Fatal("recorded directory changed", entry, got, err)
			}
			_, err = currentCaseDirectory(entry)
			if (err == nil) != (row.name == leaf) {
				t.Fatal("historical identity became current execution", entry, err)
			}
		}
	}
	for _, entry := range []catalog.Entry{
		{Scenario: leaf, Members: 32}, {Scenario: leaf, Sequence: -1},
		{Scenario: group + "/../members_32"}, {Scenario: group + "/members_33/extra"},
		{Scenario: group, Members: 65},
	} {
		if _, err := recordedCaseDirectory(entry); err == nil {
			t.Fatal("invalid retained directory admitted", entry)
		}
	}
}

// full_only: false
func TestRecordedSchedulesKeepCurrentAndHistoricalProtocolsSeparate(t *testing.T) {
	const group = "state.single-value-update-preserves-other-values"
	current, err := catalog.Resolve(catalog.Request{Include: []string{group + "/members_32"}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	historical, err := catalog.HistoricalResolve(catalog.HistoricalRequest{Include: []string{group}, Members: []int{1, 32}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, schedule := range []catalog.Schedule{current, historical} {
		got, err := reconstructRecordedSchedule(schedule)
		if err != nil || !reflect.DeepEqual(got, schedule) {
			t.Fatal("recorded schedule did not preserve exact protocol", got, schedule, err)
		}
	}
	for _, damage := range []string{"numeric", "empty-numeric", "old-smoke-policy", "mixed-current", "mixed-historical"} {
		t.Run(damage, func(t *testing.T) {
			changed := current
			switch damage {
			case "numeric":
				changed.MemberCounts = []int{32}
			case "empty-numeric":
				changed.MemberCounts = []int{}
			case "old-smoke-policy":
				changed = historical
				changed.SmokePolicy = catalog.SmokeSeparatePoint
			case "mixed-current":
				changed.Selected = []string{group + "/members_32", group}
			case "mixed-historical":
				changed = historical
				changed.Selected = []string{group, group + "/members_32"}
			}
			if _, err := reconstructRecordedSchedule(changed); err == nil {
				t.Fatal("mixed identity protocol admitted")
			}
		})
	}
}

// This literal is the complete original named-case policy, including both
// recovery modes. It must not be generated from current execution facts.
func originalNamedGeneratedHistoryPhases(t *testing.T) []records.PhaseResult {
	t.Helper()
	const wire = `[{"recovery_mode":"disabled","sequence":1,"name":"setup","outcome":"passed","measurements_expected":true,"actor":"operator","expected":"generated-history-fixture-ready","actual":"generated-history-fixture-ready"},{"recovery_mode":"disabled","sequence":2,"name":"transition","outcome":"passed","measurements_expected":true,"actor":"operator","expected":"generated-work-enters-once","actual":"generated-work-enters-once"},{"recovery_mode":"disabled","sequence":3,"name":"verification","outcome":"passed","measurements_expected":false,"actor":"operator","expected":"exact-source-and-consumer-rights-preserved","actual":"exact-source-and-consumer-rights-preserved"},{"recovery_mode":"disabled","sequence":4,"name":"transition","outcome":"passed","measurements_expected":true,"actor":"authority-decrypter-0","expected":"original-late-result-recorded","actual":"original-late-result-recorded"},{"recovery_mode":"disabled","sequence":5,"name":"verification","outcome":"passed","measurements_expected":true,"actor":"operator","expected":"result-adoption-does-not-restore-entry","actual":"result-adoption-does-not-restore-entry"},{"recovery_mode":"disabled","sequence":6,"name":"reopen","outcome":"passed","measurements_expected":false,"actor":"authority-decrypter-0","expected":"success","actual":"success"},{"recovery_mode":"disabled","sequence":7,"name":"transition","outcome":"passed","measurements_expected":true,"actor":"authority-decrypter-0","expected":"fresh-generated-final-selected","actual":"fresh-generated-final-selected"},{"recovery_mode":"disabled","sequence":8,"name":"verification","outcome":"passed","measurements_expected":false,"actor":"operator","expected":"closed-work-preserves-current-state","actual":"closed-work-preserves-current-state"},{"recovery_mode":"disabled","sequence":9,"name":"reopen","outcome":"passed","measurements_expected":false,"actor":"authority-decrypter-0","expected":"success","actual":"success"},{"recovery_mode":"enabled","sequence":10,"name":"setup","outcome":"passed","measurements_expected":true,"actor":"operator","expected":"generated-history-fixture-ready","actual":"generated-history-fixture-ready"},{"recovery_mode":"enabled","sequence":11,"name":"transition","outcome":"passed","measurements_expected":true,"actor":"operator","expected":"generated-work-enters-once","actual":"generated-work-enters-once"},{"recovery_mode":"enabled","sequence":12,"name":"verification","outcome":"passed","measurements_expected":false,"actor":"operator","expected":"exact-source-and-consumer-rights-preserved","actual":"exact-source-and-consumer-rights-preserved"},{"recovery_mode":"enabled","sequence":13,"name":"transition","outcome":"passed","measurements_expected":true,"actor":"authority-decrypter-0","expected":"original-late-result-recorded","actual":"original-late-result-recorded"},{"recovery_mode":"enabled","sequence":14,"name":"verification","outcome":"passed","measurements_expected":true,"actor":"operator","expected":"result-adoption-does-not-restore-entry","actual":"result-adoption-does-not-restore-entry"},{"recovery_mode":"enabled","sequence":15,"name":"reopen","outcome":"passed","measurements_expected":false,"actor":"authority-decrypter-0","expected":"success","actual":"success"},{"recovery_mode":"enabled","sequence":16,"name":"transition","outcome":"passed","measurements_expected":true,"actor":"authority-decrypter-0","expected":"fresh-generated-final-selected","actual":"fresh-generated-final-selected"},{"recovery_mode":"enabled","sequence":17,"name":"verification","outcome":"passed","measurements_expected":false,"actor":"operator","expected":"closed-work-preserves-current-state","actual":"closed-work-preserves-current-state"},{"recovery_mode":"enabled","sequence":18,"name":"reopen","outcome":"passed","measurements_expected":false,"actor":"authority-decrypter-0","expected":"success","actual":"success"}]`
	var phases []records.PhaseResult
	if err := json.Unmarshal([]byte(wire), &phases); err != nil {
		t.Fatal("original phase fixture unavailable", err)
	}
	return phases
}

// full_only: false
func TestRecordedNamedGeneratedHistoryKeepsWholeOriginalPolicy(t *testing.T) {
	// The source2 differences are literal facts from the preserved original
	// generatedHistorySteps/measurementOverride declaration, not today's policy.
	source2 := originalNamedGeneratedHistoryPhases(t)
	for _, position := range []int{2, 11} {
		source2[position].Actor, source2[position].MeasurementsExpected = "reader", true
	}
	union := originalNamedGeneratedHistoryPhases(t)
	for _, position := range []int{2, 11} {
		union[position].MeasurementsExpected = true
	}
	// The original combined steps/flags below come from the retained
	// writer. Its twelve-step contract repeats once per explicit recovery mode.
	combinedSteps := []catalog.Step{
		{Name: "setup", Role: "authority", Expected: "complete-fixture-ready"},
		{Name: "transition", Role: "authority", Expected: "mixed-lifecycle-sharing-selected"},
		{Name: "transition", Role: "authority", Expected: "reader-successor-selected-with-exact-material"},
		{Name: "verification", Role: "reader-successor", Expected: "successor-reader-consumes-current-material"},
		{Name: "transition", Role: "authority", Expected: "protected-selected-work-enters-once"},
		{Name: "transition", Role: "replacement-store", Expected: "occupied-current-key-successor-selected"},
		{Name: "verification", Role: "replacement-store", Expected: "accepted-material-and-rights-preserved"},
		{Name: "transition", Role: "authority-decrypter-1", Expected: "original-late-result-recorded"},
		{Name: "verification", Role: "authority", Expected: "result-adoption-does-not-restore-entry"},
		{Name: "transition", Role: "replacement-store", Expected: "recovery-route-restored-or-disabled-refused"},
		{Name: "verification", Role: "replacement-store", Expected: "mode-exact-current-material-and-recovery"},
		{Name: "reopen", Role: "authority-decrypter-1", Expected: "success"},
	}
	var combinedModes []catalog.Step
	for _, recovery := range []string{"disabled", "enabled"} {
		for _, step := range combinedSteps {
			step.RecoveryMode = recovery
			combinedModes = append(combinedModes, step)
		}
	}
	combined := passedStepPhases(combinedModes, map[string]string{"authority": "operator", "reader-successor": "reader-successor", "replacement-store": "replacement-store", "authority-decrypter-1": "authority-decrypter-1"})
	for position := range combined {
		combined[position].MeasurementsExpected = position%12 != 11
	}
	// Preserved generatedHistorySteps expands these enabled-only reciprocal
	// steps. Original withFreshReopens/baseExecution make each reopen local-free.
	reciprocalSteps := []catalog.Step{
		{Name: "setup", Role: "authority", Expected: "generated-history-fixture-ready"},
		{Name: "transition", Role: "authority", Expected: "generated-work-enters-once"},
		{Name: "transition", Role: "replacement-store", Expected: "occupied-current-key-successor-selected"},
		{Name: "verification", Role: "replacement-store", Expected: "generated-material-and-rights-preserved"},
		{Name: "reopen", Role: "authority-decrypter-1", Expected: "success"},
		{Name: "transition", Role: "replacement-store", Expected: "occupied-current-key-successor-selected"},
		{Name: "verification", Role: "replacement-store", Expected: "generated-material-and-rights-preserved"},
		{Name: "reopen", Role: "authority-decrypter-1", Expected: "success"},
		{Name: "transition", Role: "authority-decrypter-1", Expected: "late-result-recorded-and-close-frozen"},
		{Name: "transition", Role: "replacement-store", Expected: "occupied-current-key-successor-selected"},
		{Name: "verification", Role: "replacement-store", Expected: "generated-material-and-stale-final-rights-preserved"},
		{Name: "reopen", Role: "authority-decrypter-2", Expected: "success"},
		{Name: "transition", Role: "replacement-store", Expected: "occupied-current-key-successor-selected"},
		{Name: "verification", Role: "replacement-store", Expected: "generated-material-and-stale-final-rights-preserved"},
		{Name: "reopen", Role: "authority-decrypter-2", Expected: "success"},
		{Name: "transition", Role: "authority-decrypter-2", Expected: "fresh-generated-final-selected"},
		{Name: "verification", Role: "authority-decrypter-2", Expected: "closed-work-preserves-current-state"},
		{Name: "reopen", Role: "authority-decrypter-2", Expected: "success"},
	}
	for position := range reciprocalSteps {
		reciprocalSteps[position].RecoveryMode = "enabled"
	}
	reciprocal := passedStepPhases(reciprocalSteps, map[string]string{"authority": "operator", "replacement-store": "replacement-store", "authority-decrypter-1": "authority-decrypter-1", "authority-decrypter-2": "authority-decrypter-2"})
	for position, step := range reciprocalSteps {
		reciprocal[position].MeasurementsExpected = step.Name != "reopen"
	}
	for _, fixture := range []struct {
		name, scenario string
		original       []records.PhaseResult
		mixedPosition  int
		delegated      []int
		final          map[int]bool
	}{
		{"", "accepted.source-mode0-late-result/source0_late_result", originalNamedGeneratedHistoryPhases(t), 3, []int{3, 6, 12, 15}, nil},
		{"source2", "accepted.source-mode2-late-result/source2_late_result", source2, 3, []int{3, 6, 12, 15}, nil},
		{"union", "accepted.same-value-reader-union/source2_late_result_reader_union", union, 3, []int{3, 6, 12, 15}, map[int]bool{7: true, 16: true}},
		{"combined", "history.secret-lifecycle-and-recovery/plain1_secret1_reader_and_authority_history", combined, 7, []int{7, 19}, nil},
		{"reciprocal", "accepted.source-mode0-reciprocal-loss/source0_four_replacements_late_result", reciprocal, 8, []int{15}, map[int]bool{16: false}},
	} {
		scenario := fixture.scenario
		damages := []string{"original", "previous", "current", "mixed-policy"}
		if fixture.final != nil {
			damages = append(damages, "mixed-final-policy")
		}
		if fixture.name == "" {
			damages = append(damages, "wrong-actor", "wrong-recovery", "wrong-order", "missing-child", "unjoined-child", "source-binding")
		}
		for _, damage := range damages {
			name := damage
			if fixture.name != "" {
				name = fixture.name + "/" + damage
			}
			t.Run(name, func(t *testing.T) {
				_, value := completeRunFixture(t, "memory")
				// The complete regression fixture excludes generated histories.
				// Add this named case while keeping every original obligation.
				cases := append([]string(nil), value.Schedule.Selected...)
				cases = append(cases, scenario)
				schedule, err := catalog.Resolve(catalog.Request{Include: cases, RecoveryMode: value.Schedule.RecoveryMode, Repetitions: value.Schedule.Repetitions, SmokePolicy: value.Schedule.SmokePolicy})
				if err != nil {
					t.Fatal("extended named schedule unavailable", err)
				}
				value.Schedule, value.Resolved.Schedule = schedule, schedule
				definition, _ := catalog.DefinitionFor(scenario)
				for _, role := range definition.RolesForRecovery(value.Resolved.RecoveryMode) {
					if value.Resolved.RoleBindings[role] == "" {
						value.Resolved.RoleBindings[role] = role
						value.Resolved.Participants = append(value.Resolved.Participants, role)
					}
				}
				value.Scenarios = nil
				for _, entry := range schedule.Entries {
					shape, err := recordedFixture(entry.Scenario, entry.Members)
					if err != nil {
						t.Fatal("extended named fixture unavailable", err)
					}
					result := scenarioResult{Entry: entry, Fixture: shape, CorrectnessPassed: true, Outcome: "passed", Cleanup: noCleanup()}
					setScenarioWorkerEvidence(&result, value.Suite, value.Resolved.RoleBindings)
					setScenarioReconstructionFixture(&result, value)
					value.Scenarios = append(value.Scenarios, result)
				}
				if !fullCoverage(value) {
					t.Fatal("extended complete named fixture refused before policy damage")
				}
				found := false
				for index := range value.Scenarios {
					result := &value.Scenarios[index]
					if result.Scenario != scenario {
						continue
					}
					found = true
					result.Writer.Phases = append([]records.PhaseResult(nil), fixture.original...)
					result.Writer.Telemetry = records.Telemetry{Enabled: true, Status: "incomplete", FailureClass: "no_observations"}
					if damage == "previous" || damage == "current" || damage == "mixed-final-policy" {
						for _, position := range fixture.delegated {
							result.Writer.Phases[position].MeasurementsExpected = false
						}
					}
					if damage == "current" {
						for position, measured := range fixture.final {
							result.Writer.Phases[position].MeasurementsExpected = measured
						}
					}
					switch damage {
					case "mixed-final-policy":
						if fixture.name == "reciprocal" {
							result.Writer.Phases[15].MeasurementsExpected = true
							result.Writer.Phases[16].MeasurementsExpected = false
						} else {
							// Correct one recovery block only: whole policies may not mix.
							result.Writer.Phases[7].MeasurementsExpected = true
						}
					case "mixed-policy":
						result.Writer.Phases[fixture.mixedPosition].MeasurementsExpected = false
					case "wrong-actor":
						result.Writer.Phases[3].Actor = "other"
					case "wrong-recovery":
						result.Writer.Phases[3].RecoveryMode = "enabled"
					case "wrong-order":
						result.Writer.Phases[3], result.Writer.Phases[6] = result.Writer.Phases[6], result.Writer.Phases[3]
						result.Writer.Phases[3].Sequence, result.Writer.Phases[6].Sequence = 4, 7
					case "missing-child":
						result.Children = result.Children[1:]
					case "unjoined-child":
						result.Children[0].Joined = false
					case "source-binding":
						value.Correctness.ComponentRun.Source.Revision = strings.Repeat("e", 40)
					}
				}
				if !found {
					t.Fatal("original named case absent")
				}
				before, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if fullCoverage(value) != (damage == "original" || damage == "previous" || damage == "current") {
					t.Fatal("retained whole phase policy acceptance differs", damage)
				}
				after, err := json.Marshal(value)
				if err != nil || string(before) != string(after) {
					t.Fatal("retained reading changed original evidence", err)
				}
			})
		}
	}
}

// full_only: false
func TestCurrentNamedGeneratedHistoryImportRefusesOriginalAndMixedPolicy(t *testing.T) {
	const scenario = "accepted.source-mode0-late-result/source0_late_result"
	for _, policy := range []string{"original", "mixed", "current"} {
		t.Run(policy, func(t *testing.T) {
			inv, result, _ := telemetryImportFixture(t)
			inv.Scenario, result.Scenario, result.Actor = scenario, scenario, "operator"
			participants := map[string]string{"authority": "operator"}
			definition, _ := catalog.DefinitionFor(scenario)
			for _, role := range definition.Roles {
				if role != "authority" {
					participants[role] = role
				}
			}
			if records.WriteJSON(inv.Input, workerInput{RecoveryMode: "both", Participants: participants, Scenarios: []string{scenario}}, 0400) != nil {
				t.Fatal("current input fixture unavailable")
			}
			result.Phases = originalNamedGeneratedHistoryPhases(t)
			if policy == "mixed" {
				result.Phases[3].MeasurementsExpected = false
			}
			if policy == "current" {
				for _, position := range []int{3, 6, 12, 15} {
					result.Phases[position].MeasurementsExpected = false
				}
			}
			execution, known := catalog.ExecutionFor(scenario, "hermetic")
			if !known {
				t.Fatal("current fixture execution unavailable")
			}
			result.Children = make([]records.ChildInvocation, len(execution.ExpandedFreshBefore()))
			result.FreshChecks = nil
			for index, child := range execution.ExpandedFreshAfter() {
				result.FreshChecks = append(result.FreshChecks, records.FreshCheck{Facts: fmt.Sprintf("facts-%d.json", index), RecoveryMode: child.Step.RecoveryMode})
			}
			if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), result, 0600) != nil {
				t.Fatal("current worker fixture unavailable")
			}
			state := &runState{record: runRecord{Suite: "hermetic", Resolved: &resolvedRequest{Mode: "hermetic", RecoveryMode: "both", RoleBindings: participants}}}
			evidence, _, err := state.importWorker(inv, scenario, processResult{Status: "passed", Joined: true}, nil)
			if (err == nil) != (policy == "current") || (evidence.Outcome == "passed") != (policy == "current") {
				t.Fatal("current import admitted a historical or mixed phase claim", policy, err)
			}
		})
	}
}

// full_only: false
func TestCurrentFinalVerificationImportRefusesEarlierPolicies(t *testing.T) {
	for _, fixture := range []struct {
		scenario  string
		original  []bool
		delegated []int
		final     int
		measured  bool
	}{
		{"accepted.source-mode0-reciprocal-loss/source0_four_replacements_late_result", []bool{true, true, true, true, false, true, true, false, true, true, true, false, true, true, false, true, true, false}, []int{15}, 16, false},
		{"accepted.same-value-reader-union/source2_late_result_reader_union", []bool{true, true, true, true, true, false, true, false, false}, []int{3, 6}, 7, true},
	} {
		for _, policy := range []string{"original", "previous", "mixed", "current"} {
			t.Run(fixture.scenario+"/"+policy, func(t *testing.T) {
				inv, result, _ := telemetryImportFixture(t)
				inv.Scenario, result.Scenario, result.Actor = fixture.scenario, fixture.scenario, "operator"
				participants := map[string]string{"authority": "operator"}
				definition, _ := catalog.DefinitionFor(fixture.scenario)
				for _, role := range definition.Roles {
					if role != "authority" {
						participants[role] = role
					}
				}
				if records.WriteJSON(inv.Input, workerInput{RecoveryMode: "both", Participants: participants, Scenarios: []string{fixture.scenario}}, 0400) != nil {
					t.Fatal("current input fixture unavailable")
				}
				execution, known := catalog.ExecutionFor(fixture.scenario, "hermetic")
				if !known {
					t.Fatal("current execution unavailable")
				}
				flags := append([]bool(nil), fixture.original...)
				if policy != "original" {
					for _, step := range fixture.delegated {
						flags[step] = false
					}
				}
				if policy == "current" || policy == "mixed" {
					flags[fixture.final] = fixture.measured
				}
				if policy == "mixed" {
					flags[fixture.delegated[0]] = true
				}
				result.Phases = passedStepPhases(execution.WriterSteps(), participants)
				for position, phase := range execution.Writer {
					result.Phases[position].MeasurementsExpected = flags[phase.StepIndex]
				}
				result.Children = make([]records.ChildInvocation, len(execution.ExpandedFreshBefore()))
				result.FreshChecks = nil
				for index, child := range execution.ExpandedFreshAfter() {
					result.FreshChecks = append(result.FreshChecks, records.FreshCheck{Facts: fmt.Sprintf("facts-%d.json", index), RecoveryMode: child.Step.RecoveryMode})
				}
				if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), result, 0600) != nil {
					t.Fatal("current worker fixture unavailable")
				}
				state := &runState{record: runRecord{Suite: "hermetic", Resolved: &resolvedRequest{Mode: "hermetic", RecoveryMode: "both", RoleBindings: participants}}}
				evidence, _, err := state.importWorker(inv, fixture.scenario, processResult{Status: "passed", Joined: true}, nil)
				if (err == nil) != (policy == "current") || (evidence.Outcome == "passed") != (policy == "current") {
					t.Fatal("current import admitted an earlier or mixed final-verification policy", policy, err)
				}
			})
		}
	}
}
