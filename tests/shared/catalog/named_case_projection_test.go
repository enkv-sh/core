package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type reviewedCase struct {
	Group   string `json:"group"`
	Path    string `json:"path"`
	Members int    `json:"members"`
}

// full_only: false
func TestCurrentRecoveryProjectionPreservesDeclaredExecution(t *testing.T) {
	for _, name := range []string{
		"state.single-value-update-preserves-other-values/members_32",
		"state.historical-bytes-get-new-identities/members_32_three_generations",
		"generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2",
	} {
		t.Run(name, func(t *testing.T) {
			full, known := ExecutionFor(name, "hermetic")
			if !known || len(full.Writer)%2 != 0 {
				t.Fatal("declared two-mode baseline unavailable")
			}
			for _, recovery := range []string{"", "both", "disabled", "enabled"} {
				selected, known := ExecutionForRecovery(name, "hermetic", recovery)
				if !known {
					t.Fatal("declared execution selection refused", recovery)
				}
				if recovery == "" || recovery == "both" {
					if !reflect.DeepEqual(selected, full) {
						t.Fatal("full execution changed through the selection API")
					}
					continue
				}
				if len(selected.Writer) != len(full.Writer)/2 || selected.Writer[0].Step.RecoveryMode != recovery || len(selected.ExpandedFreshAfter()) != 1 {
					t.Fatal("single-mode execution lost its exact writer and after-reader shape")
				}
				if !reflect.DeepEqual(selected.FixtureCapabilities, full.FixtureCapabilities) || selected.Family != full.Family || selected.Mode != full.Mode {
					t.Fatal("mode selection changed the action or fixture capabilities")
				}
				for _, child := range selected.FreshBefore {
					if child.WriterPosition < 0 || child.WriterPosition >= len(selected.Writer) {
						t.Fatal("selected child retained an unfiltered writer position")
					}
					phase := selected.Writer[child.WriterPosition]
					if child.Step.RecoveryMode != recovery || child.Step != phase.Step || child.StepIndex != phase.StepIndex {
						t.Fatal("selected child changed its declaration or points at another writer phase")
					}
				}
				if known, valid := selected.MeasurementFor("writer", 0, selected.Writer[0].Step); !valid || known != selected.Writer[0].MeasurementsExpected {
					t.Fatal("first selected writer phase is not position zero")
				}
			}
			again, _ := ExecutionFor(name, "hermetic")
			if !reflect.DeepEqual(again, full) {
				t.Fatal("narrowing mutated the full catalog declaration")
			}
		})
	}
	name := "reconstruction.zero-secret-genesis/complete_loss_zero_secret_genesis"
	if _, known := ExecutionForRecovery(name, "hermetic", "enabled"); known {
		t.Fatal("undeclared enabled reconstruction cell admitted")
	}
	selected, known := ExecutionForRecovery(name, "hermetic", "disabled")
	full, _ := ExecutionFor(name, "hermetic")
	if !known || !reflect.DeepEqual(selected, full) {
		t.Fatal("declared single reconstruction cell changed its process phases")
	}
	if _, known := ExecutionForRecovery(name, "hermetic", "unsupported"); known {
		t.Fatal("unsupported recovery mode admitted")
	}
}

func reviewedCases(t *testing.T) []reviewedCase {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, err := os.Stat(filepath.Join(directory, "tests", "suites"))
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("repository suites were not found")
		}
		directory = parent
	}
	body, err := os.ReadFile(filepath.Join(directory, "tests", "shared", "catalog", "testdata", "named_case_projection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []reviewedCase
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 253 {
		t.Fatal("reviewed table must retain exactly 253 finite leaves", len(rows))
	}
	return rows
}

// The fixed historical schedule hashes remain in schedule_projection_test.go.
// This comparison proves every new identity selects the same metadata, action,
// participants, fixture and declared cells as those historical facts.
// full_only: false
func TestCurrentCaseProjectionPreservesHistoricalSemantics(t *testing.T) {
	rows := reviewedCases(t)
	wantNames := make([]string, 0, len(rows))
	groups := make(map[string]int)
	seen := make(map[string]bool)
	pointCounts := make(map[int]bool)
	for _, row := range rows {
		wantNames = append(wantNames, row.Path)
		groups[row.Group]++
		if seen[row.Path] {
			t.Fatal("duplicate reviewed leaf", row.Path)
		}
		seen[row.Path] = true
		if row.Group == pointScenario {
			if row.Members < 1 || row.Members > 64 || pointCounts[row.Members] {
				t.Fatal("point members must be distinct finite counts", row)
			}
			pointCounts[row.Members] = true
		} else if row.Members != 0 {
			t.Fatal("a nonpoint leaf acquired a numeric fixture override", row)
		}
		t.Run(row.Path, func(t *testing.T) {
			if name, known := Name(row.Path); !known || name != row.Path {
				t.Fatal("reviewed full leaf not admitted unchanged", name, known)
			}
			old, known := HistoricalDefinitionFor(row.Group)
			if !known {
				t.Fatal("historical group metadata missing", row.Group)
			}
			shape, err := HistoricalFixtureShape(row.Group, row.Members)
			if err != nil {
				t.Fatal(err)
			}
			want := old
			want.Name, want.Fixture = row.Path, shape
			want.MinMembers, want.MaxMembers = 0, 0
			// These original writer positions delegate their complete action
			// to a measured fresh child. All other historical facts stay exact.
			delegated := map[string][]int{
				"accepted.source-mode0-late-result":     {3, 6, 12, 15},
				"accepted.source-mode1-late-result":     {3, 6, 12, 15},
				"accepted.source-mode2-late-result":     {3, 6, 12, 15},
				"accepted.same-value-reader-union":      {3, 6, 12, 15},
				"accepted.source-mode0-reciprocal-loss": {15},
				"accepted.source-mode1-reciprocal-loss": {15},
				"accepted.source-mode2-reciprocal-loss": {15},
				"history.secret-lifecycle-and-recovery": {7, 19},
			}[row.Group]
			if len(delegated) != 0 {
				want.Executions = maps.Clone(old.Executions)
				execution := want.Executions["hermetic"]
				execution.Writer = slices.Clone(execution.Writer)
				for _, position := range delegated {
					if position >= len(execution.Writer) || !execution.Writer[position].MeasurementsExpected {
						t.Fatal("original delegated writer observation policy changed", position)
					}
					execution.Writer[position].MeasurementsExpected = false
				}
				// Cached final assertions and the reader-union's actual Consume
				// and receipt/Open work have distinct current requirements.
				closed := map[string]map[int]bool{
					"accepted.source-mode0-reciprocal-loss": {16: false},
					"accepted.source-mode1-reciprocal-loss": {16: false},
					"accepted.source-mode2-reciprocal-loss": {16: false},
					"accepted.same-value-reader-union":      {7: true, 16: true},
				}[row.Group]
				for position, measured := range closed {
					if position >= len(execution.Writer) || execution.Writer[position].MeasurementsExpected == measured {
						t.Fatal("original final verification observation policy changed", position)
					}
					execution.Writer[position].MeasurementsExpected = measured
				}
				want.Executions["hermetic"] = execution
			}
			if row.Group == "publication.lost-process" {
				want.Title = "Selected publication: reservation retired without send"
			}
			got, known := DefinitionFor(row.Path)
			if !known || !reflect.DeepEqual(got, want) {
				t.Fatal("current case changed reviewed metadata or observation ownership", got, want)
			}
			if shape, err := FixtureShape(row.Path); err != nil || !reflect.DeepEqual(shape, want.Fixture) {
				t.Fatal("current fixture differs from its fixed reviewed shape", shape, err)
			}
			oldSizes, oldFragmented, oldErr := HistoricalFixtureSizes(row.Group, row.Members)
			newSizes, newFragmented, newErr := FixtureSizes(row.Path)
			if oldErr != nil || newErr != nil || !slices.Equal(oldSizes, newSizes) || oldFragmented != newFragmented {
				t.Fatal("fixture placement changed", oldErr, newErr)
			}
			oldAction, _ := historicalBehavior(row.Group)
			newAction, known := Behavior(row.Path)
			if !known || newAction != oldAction {
				t.Fatal("named leaf changed its shared action", oldAction, newAction)
			}
			for _, mode := range []string{"hermetic", "live", "unsupported"} {
				oldExecution, oldKnown := HistoricalExecutionFor(row.Group, mode)
				newExecution, newKnown := ExecutionFor(row.Path, mode)
				if declared, known := old.Executions[mode]; known != oldKnown || !reflect.DeepEqual(declared, oldExecution) {
					t.Fatal("historical execution differs from its retained declaration", mode)
				}
				if expected, known := want.Executions[mode]; known != newKnown || !reflect.DeepEqual(expected, newExecution) {
					t.Fatal("execution phases, capabilities or observation ownership changed", mode)
				}
			}
			for _, recovery := range []string{"disabled", "enabled", "both", "unsupported"} {
				if !slices.Equal(RolesForScenarios([]string{row.Path}, recovery), historicalRolesForScenarios([]string{row.Group}, recovery)) {
					t.Fatal("participant roles changed", recovery)
				}
				// Current narrowing can only select cells already declared by the
				// full execution. Retained historical single-mode fallback stays
				// available exclusively through its historical reader.
				var declared []RecoveryProcessCell
				for _, cell := range HistoricalConfigurationRecoveryCells(row.Group, "both") {
					if recovery == "both" || recovery == cell.Recovery {
						declared = append(declared, cell)
					}
				}
				if !reflect.DeepEqual(ConfigurationRecoveryCells(row.Path, recovery), declared) {
					t.Fatal("current reconstruction selection fabricated or omitted a declared cell", recovery)
				}
			}
			oldAuthority, oldKnown := authorityReplacementGroup(row.Group)
			newAuthority, newKnown := AuthorityReplacement(row.Path)
			if oldKnown != newKnown || oldAuthority != newAuthority {
				t.Fatal("authority replacement condition changed")
			}
			oldHistory, oldKnown := generatedHistoryGroup(row.Group)
			newHistory, newKnown := GeneratedHistory(row.Path)
			if oldKnown != newKnown || oldHistory != newHistory {
				t.Fatal("generated history condition changed")
			}
			oldRecovery, oldKnown := HistoricalConfigurationRecovery(row.Group)
			newRecovery, newKnown := ConfigurationRecovery(row.Path)
			if oldKnown != newKnown || !reflect.DeepEqual(oldRecovery, newRecovery) {
				t.Fatal("reconstruction condition changed")
			}
			oldPublication, oldKnown := publicationGroup(row.Group)
			newPublication, newKnown := Publication(row.Path)
			if oldKnown != newKnown || oldPublication != newPublication {
				t.Fatal("publication condition changed")
			}
			oldLive, oldKnown := HistoricalLivePublication(row.Group)
			newLive, newKnown := LivePublication(row.Path)
			if oldKnown != newKnown || oldLive != newLive {
				t.Fatal("live output scope or namespace changed")
			}
		})
	}
	names, definitions := Names(), Definitions()
	namesEqual := slices.Equal(names, wantNames)
	if !namesEqual || len(definitions) != len(rows) || len(groups) != 190 || len(pointCounts) != 64 {
		t.Fatalf("current inventory differs from the reviewed complete table: names_equal=%t names=%d want_names=%d definitions=%d reviewed_rows=%d expected_leaves=253 groups=%d expected_groups=190 points=%d expected_points=64",
			namesEqual, len(names), len(wantNames), len(definitions), len(rows), len(groups), len(pointCounts))
	}
	for _, group := range historicalNames() {
		wantChildren := 1
		if group == pointScenario {
			wantChildren = 64
		}
		if groups[group] != wantChildren {
			t.Fatal("historical group does not have its exact reviewed children", group)
		}
		if _, known := Name(group); known {
			t.Fatal("historical group admitted for current execution", group)
		}
		if _, known := DefinitionFor(group); known {
			t.Fatal("historical group admitted as current metadata", group)
		}
		if _, err := Resolve(Request{Include: []string{group}, Repetitions: 1}); err == nil {
			t.Fatal("historical group admitted as current schedule", group)
		}
		if _, known := Behavior(group); known {
			t.Fatal("historical group admitted as current action", group)
		}
		if _, known := AuthorityReplacement(group); known {
			t.Fatal("historical group admitted as current replacement", group)
		}
		if _, known := GeneratedHistory(group); known {
			t.Fatal("historical group admitted as current history", group)
		}
		if _, known := ConfigurationRecovery(group); known || ConfigurationRecoveryCells(group, "both") != nil {
			t.Fatal("historical group admitted as current reconstruction", group)
		}
		if _, known := Publication(group); known {
			t.Fatal("historical group admitted as current publication", group)
		}
		if _, known := LivePublication(group); known {
			t.Fatal("historical group admitted as current live publication", group)
		}
		if _, err := FixtureShape(group); err == nil {
			t.Fatal("historical group admitted as current fixture", group)
		}
		if roles := RolesForScenarios([]string{group}, "both"); roles != nil {
			t.Fatal("historical group admitted as current participants", group)
		}
	}
}

// full_only: false
func TestCurrentCaseDirectoryBindingsAreFiniteAndDistinct(t *testing.T) {
	seen := make(map[string]string)
	for _, row := range reviewedCases(t) {
		token, err := CaseDirectoryToken(row.Path)
		if err != nil || len(token) != 64 || strings.ContainsAny(token, "/\\.") {
			t.Fatal("case token is not a flat SHA256 hex binding", row.Path, token, err)
		}
		for _, c := range token {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatal("case token contains nonhex characters", token)
			}
		}
		if previous, exists := seen[token]; exists {
			t.Fatal("two admitted cases share a directory token", previous, row.Path)
		}
		seen[token] = row.Path
	}
	// Independently calculated with Python hashlib, never derived by the API
	// under test. These witnesses include point variants and external scope.
	for name, want := range map[string]string{
		"state.single-value-update-preserves-other-values/members_1":                                               "fd352af80f13bd5f56a2b0e3ae8b615591835767a0179591f7610a9169f9a416",
		"state.single-value-update-preserves-other-values/members_32":                                              "c2b1ece74d4795f96fc27a467324d41147e34a736c84f0fa7972738f5cf75981",
		"capacity.fragmented-state-preserves-complete-update/members_64_fragmented":                                "03b95fc836f4653e450ff037007bc7b6ad2cc6e560308258c3804084a1705e99",
		"publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete": "c895ca5e8223eb879e051677fc3fa64c51aadc7e8da05e04122451c6e5d44d48",
	} {
		if token, err := CaseDirectoryToken(name); err != nil || token != want {
			t.Fatal("full identity was not bound to its literal expected digest", name, token, err)
		}
	}
	if MaxCasePathBytes != 128 {
		t.Fatal("logical path bound changed")
	}
	for _, name := range []string{
		"", pointScenario, "../members_32", pointScenario + "/../members_32",
		pointScenario + "/members_32/extra", pointScenario + "/members_32\\extra",
		pointScenario + "/MEMBERS_32", pointScenario + "/members_032",
		pointScenario + "/members_32\x00", pointScenario + "/members_32%2fextra",
		pointScenario + "/members_32 ", "state..group/members_32",
		"state.-group/members_32", "state.group/_members_32",
		"state.group/members_32_", strings.Repeat("a", 129),
		pointScenario + "/" + strings.Repeat("a", 128),
	} {
		if token, err := CaseDirectoryToken(name); err == nil || token != "" {
			t.Fatal("unadmitted path received a directory binding", token, err)
		}
		if _, known := Name(name); known {
			t.Fatal("unadmitted path received current execution identity")
		}
	}
}

// full_only: false
func TestCurrentFamilyListsPreserveOrdinaryCoverage(t *testing.T) {
	rows := reviewedCases(t)
	ordinary := make(map[string]string)
	for _, row := range rows {
		if row.Group != pointScenario || row.Members == 32 {
			ordinary[row.Group] = row.Path
		}
	}
	for _, recovery := range []string{"disabled", "enabled", "both"} {
		for _, lists := range []struct {
			name         string
			old, current []string
		}{
			{"ordinary", historicalNames(), OrdinaryNames()},
			{"regression", historicalRegressionNamesForRecovery(recovery), RegressionNamesForRecovery(recovery)},
			{"current-key", currentKeyReplacementGroupNames(recovery), CurrentKeyReplacementNames(recovery)},
			{"generated-history", generatedHistoryGroupNames(recovery), GeneratedHistoryNames(recovery)},
			{"generated", generatedGroupNames(), GeneratedNames()},
			{"generated-live", generatedLiveGroupNames(), GeneratedLiveNames()},
			{"generated-lifecycle", generatedLifecycleLiveGroupNames(), GeneratedLifecycleLiveNames()},
			{"operator", authorityOperatorLiveGroupNames(), AuthorityOperatorLiveNames()},
			{"reconstruction", configurationRecoveryGroupNames(), ConfigurationRecoveryNames()},
			{"reconstruction-generated", configurationRecoveryGeneratedGroupNames(), ConfigurationRecoveryGeneratedNames()},
			{"publication", publicationGroupNames(), PublicationNames()},
			{"publication-live", livePublicationGroupNames(), LivePublicationNames()},
		} {
			want := make([]string, len(lists.old))
			for i, old := range lists.old {
				want[i] = ordinary[old]
			}
			if !slices.Equal(lists.current, want) {
				t.Fatal("ordinary family membership or order changed", lists.name, recovery)
			}
		}
		oldSchedule, oldErr := HistoricalResolve(HistoricalRequest{Include: historicalRegressionNamesForRecovery(recovery), RecoveryMode: recovery, Repetitions: 2})
		newSchedule, newErr := Resolve(Request{Include: RegressionNamesForRecovery(recovery), RecoveryMode: recovery, Repetitions: 2})
		if oldErr != nil || newErr != nil || !oldSchedule.FullCoverage || !newSchedule.FullCoverage || len(newSchedule.Entries) != 2*len(newSchedule.Selected) || len(newSchedule.Entries) != len(oldSchedule.Entries)-1 {
			t.Fatal("ordinary schedule lost complete selected repetitions", recovery, oldErr, newErr)
		}
		want := []Entry{{Scenario: ordinary[pointScenario], Repetition: 1, Smoke: true}}
		for _, old := range oldSchedule.Entries[1:] {
			if old.Scenario == pointScenario && old.Repetition == 1 {
				continue
			}
			old.Scenario, old.Sequence = ordinary[old.Scenario], len(want)
			want = append(want, old)
		}
		if !reflect.DeepEqual(newSchedule.Entries, want) || !slices.Equal(newSchedule.Selected, RegressionNamesForRecovery(recovery)) {
			t.Fatal("ordinary selected cases or their repetition order changed", recovery)
		}
	}
}

// full_only: false
func TestCurrentCaseSmokePoliciesPreserveExactCardinality(t *testing.T) {
	point := "state.single-value-update-preserves-other-values/members_32"
	for _, policy := range []SmokePolicy{"", SmokeSeparatePoint} {
		schedule, err := Resolve(Request{Include: []string{point}, Repetitions: 1, SmokePolicy: policy})
		want := []Entry{{Scenario: point, Repetition: 1, Smoke: true}}
		if err != nil || schedule.SmokePolicy != SmokeSeparatePoint || !reflect.DeepEqual(schedule.Entries, want) || schedule.MemberCounts != nil {
			t.Fatal("direct ordinary point did not supply its selected smoke", schedule, err)
		}
	}
	for _, names := range [][]string{
		{point},
		{"state.single-value-update-preserves-other-values/members_64", "state.single-value-update-preserves-other-values/members_1", point},
	} {
		schedule, err := Resolve(Request{Include: names, Repetitions: 1, SmokePolicy: SmokeFirstSelectedPoint})
		if err != nil || len(schedule.Entries) != len(names) || schedule.SmokePolicy != SmokeFirstSelectedPoint || schedule.FullCoverage || schedule.MemberCounts != nil {
			t.Fatal("diagnostic schedule acquired extra smoke or coverage", schedule, err)
		}
		for i, name := range names {
			want := Entry{Scenario: name, Sequence: i, Repetition: 1}
			if i == 0 {
				want.Smoke = true
			}
			if schedule.Entries[i] != want {
				t.Fatal("diagnostic entry lost requested order or first smoke", i, schedule.Entries[i], want)
			}
		}
	}
	allPoint := make([]string, 64)
	for i := range allPoint {
		allPoint[i] = fmt.Sprintf("state.single-value-update-preserves-other-values/members_%d", i+1)
	}
	schedule, err := Resolve(Request{Include: allPoint, Repetitions: 1, SmokePolicy: SmokeFirstSelectedPoint})
	if err != nil || len(schedule.Entries) != 64 || !slices.Equal(schedule.Selected, allPoint) {
		t.Fatal("complete finite point diagnostics are not schedulable", err)
	}
	for _, request := range []Request{
		{Include: []string{allPoint[0]}, Repetitions: 1},
		{Include: []string{point, allPoint[63]}, Repetitions: 1},
		{Include: []string{"state.identical-input-keeps-current-state/members_32"}, Repetitions: 1, SmokePolicy: SmokeFirstSelectedPoint},
		{Include: []string{point, point}, Repetitions: 1, SmokePolicy: SmokeFirstSelectedPoint},
		{Include: []string{point}, Repetitions: 0, SmokePolicy: SmokeFirstSelectedPoint},
		{Include: []string{point}, Repetitions: 101, SmokePolicy: SmokeFirstSelectedPoint},
		{Include: []string{point}, Repetitions: 1, SmokePolicy: "unknown"},
	} {
		if schedule, err := Resolve(request); err == nil || !reflect.DeepEqual(schedule, Schedule{}) {
			t.Fatal("invalid smoke policy or widened diagnostic selection returned work", request, schedule, err)
		}
	}
}

// full_only: false
func TestCurrentCaseSeparateSmokeCountsSelectedRepetitions(t *testing.T) {
	const point = "state.single-value-update-preserves-other-values/members_32"
	const other = "state.identical-input-keeps-current-state/members_32"
	for _, row := range []struct {
		name        string
		names       []string
		repetitions int
		entries     []Entry
	}{
		{"later-point", []string{other, point}, 1, []Entry{
			{Scenario: point, Repetition: 1, Smoke: true},
			{Scenario: other, Sequence: 1, Repetition: 1},
		}},
		{"later-point-repeated", []string{other, point}, 3, []Entry{
			{Scenario: point, Repetition: 1, Smoke: true},
			{Scenario: other, Sequence: 1, Repetition: 1},
			{Scenario: other, Sequence: 2, Repetition: 2},
			{Scenario: point, Sequence: 3, Repetition: 2},
			{Scenario: other, Sequence: 4, Repetition: 3},
			{Scenario: point, Sequence: 5, Repetition: 3},
		}},
		{"first-point-repeated", []string{point, other}, 3, []Entry{
			{Scenario: point, Repetition: 1, Smoke: true},
			{Scenario: other, Sequence: 1, Repetition: 1},
			{Scenario: point, Sequence: 2, Repetition: 2},
			{Scenario: other, Sequence: 3, Repetition: 2},
			{Scenario: point, Sequence: 4, Repetition: 3},
			{Scenario: other, Sequence: 5, Repetition: 3},
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, policy := range []SmokePolicy{"", SmokeSeparatePoint} {
				got, err := Resolve(Request{Include: row.names, Repetitions: row.repetitions, SmokePolicy: policy})
				want := Schedule{RecoveryMode: "both", Selected: row.names, Repetitions: row.repetitions,
					Entries: row.entries, SmokePolicy: SmokeSeparatePoint}
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("selected smoke changed requested order or complete repetitions", got, want, err)
				}
			}
		})
	}
}

// full_only: false
func TestCurrentCaseRepetitionsPreserveSmokeCardinality(t *testing.T) {
	point := "state.single-value-update-preserves-other-values/members_32"
	for _, row := range []struct {
		name   string
		policy SmokePolicy
		names  []string
	}{
		{"selected-point", SmokeFirstSelectedPoint, []string{
			"state.single-value-update-preserves-other-values/members_64",
			"state.single-value-update-preserves-other-values/members_1",
		}},
		{"auxiliary-smoke", SmokeSeparatePoint, []string{
			"state.identical-input-keeps-current-state/members_32",
			"state.historical-bytes-get-new-identities/members_32_three_generations",
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			schedule, err := Resolve(Request{Include: row.names, Repetitions: 3, SmokePolicy: row.policy})
			if err != nil {
				t.Fatal("three complete case executions were refused", err)
			}
			want := []Entry{}
			if row.policy == SmokeSeparatePoint {
				want = append(want, Entry{Scenario: point, Smoke: true})
			}
			for repetition := 1; repetition <= 3; repetition++ {
				for _, name := range row.names {
					entry := Entry{Scenario: name, Sequence: len(want), Repetition: repetition}
					entry.Smoke = row.policy == SmokeFirstSelectedPoint && len(want) == 0
					want = append(want, entry)
				}
			}
			if !reflect.DeepEqual(schedule.Entries, want) || !slices.Equal(schedule.Selected, row.names) || schedule.Repetitions != 3 || schedule.FullCoverage || schedule.MemberCounts != nil {
				t.Fatal("smoke changed N, selected case order, or coverage", schedule, want)
			}
		})
	}
}

// full_only: false
func TestHistoricalCatalogKeepsExactScheduleWireBytes(t *testing.T) {
	for _, test := range []struct {
		request HistoricalRequest
		wire    string
	}{
		{HistoricalRequest{Include: []string{pointScenario}, Repetitions: 1}, `{"recovery_mode":"both","selected_scenarios":["state.single-value-update-preserves-other-values"],"repetitions":1,"entries":[{"scenario":"state.single-value-update-preserves-other-values","sequence":0,"repetition":0,"smoke":true},{"scenario":"state.single-value-update-preserves-other-values","sequence":1,"repetition":1,"smoke":false}],"full_coverage":false}`},
		{HistoricalRequest{Include: []string{pointScenario}, Members: []int{32}, Repetitions: 1}, `{"recovery_mode":"both","selected_scenarios":["state.single-value-update-preserves-other-values"],"selected_member_counts":[32],"repetitions":1,"entries":[{"scenario":"state.single-value-update-preserves-other-values","members":32,"sequence":0,"repetition":0,"smoke":true}],"full_coverage":false}`},
	} {
		schedule, err := HistoricalResolve(test.request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(schedule)
		if err != nil || string(body) != test.wire || schedule.SmokePolicy != "" {
			t.Fatal("historical canonical schedule bytes changed", string(body), err)
		}
		var decoded Schedule
		if err := json.Unmarshal([]byte(test.wire), &decoded); err != nil || !reflect.DeepEqual(decoded, schedule) {
			t.Fatal("historical schedule cannot round-trip unchanged", err)
		}
	}
}
