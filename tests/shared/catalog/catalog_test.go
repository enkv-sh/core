package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type policyPhase struct {
	Purpose              FreshPurpose
	Role                 string
	Count                int
	WriterPosition       int
	StepIndex            int
	RecoveryMode         string
	MeasurementsExpected bool
}

type executionPolicyFacts struct {
	Process             []policyPhase
	Mode                string
	Family              ScenarioFamily
	FixtureCapabilities []FixtureCapability
	Writer              []policyPhase
	FreshBefore         []policyPhase
	FreshAfter          []policyPhase
}

func executionPolicy(execution Execution) executionPolicyFacts {
	policy := executionPolicyFacts{Mode: execution.Mode, Family: execution.Family, FixtureCapabilities: append([]FixtureCapability(nil), execution.FixtureCapabilities...)}
	for _, phase := range execution.Process {
		policy.Process = append(policy.Process, policyPhase{Role: phase.Step.Role, StepIndex: phase.StepIndex, RecoveryMode: phase.Step.RecoveryMode})
	}
	for _, phase := range execution.Writer {
		policy.Writer = append(policy.Writer, policyPhase{Role: phase.Step.Role, StepIndex: phase.StepIndex, RecoveryMode: phase.Step.RecoveryMode, MeasurementsExpected: phase.MeasurementsExpected})
	}
	for _, child := range execution.FreshBefore {
		policy.FreshBefore = append(policy.FreshBefore, policyPhase{Purpose: child.Purpose, Role: child.Role, Count: child.Count, WriterPosition: child.WriterPosition, StepIndex: child.StepIndex, RecoveryMode: child.Step.RecoveryMode, MeasurementsExpected: child.MeasurementsExpected})
	}
	for _, child := range execution.FreshAfter {
		policy.FreshAfter = append(policy.FreshAfter, policyPhase{Purpose: child.Purpose, Role: child.Role, Count: child.Count, WriterPosition: child.WriterPosition, StepIndex: child.StepIndex, RecoveryMode: child.Step.RecoveryMode, MeasurementsExpected: child.MeasurementsExpected})
	}
	return policy
}

func catalogExecution(name, mode string) Execution {
	execution, known := HistoricalExecutionFor(name, mode)
	if !known {
		panic("catalog execution fixture unavailable")
	}
	return execution
}

func executionWriterSteps(name, mode string) []Step {
	return catalogExecution(name, mode).WriterSteps()
}

func executionBeforeSteps(name, mode string) []Step {
	children := catalogExecution(name, mode).ExpandedFreshBefore()
	steps := make([]Step, 0, len(children))
	for _, child := range children {
		steps = append(steps, child.Step)
	}
	return steps
}

// full_only: false
func TestAuthorityOperatorLiveExecutionUsesPublicFixtureAndIndependentConsumer(t *testing.T) {
	cells := 0
	for _, name := range authorityOperatorLiveGroupNames() {
		definition, known := HistoricalDefinitionFor(name)
		execution, executable := HistoricalExecutionFor(name, "live")
		roles := []string{"authority", "reader", "cleanup", "recipient-consumer"}
		if name == authorityOperatorLiveGroupNames()[1] {
			roles = append(roles, "successor")
		}
		if !known || !executable || !slices.Equal(definition.Roles, roles) ||
			execution.Family != FamilyAuthorityOperator || !slices.Equal(execution.FixtureCapabilities, []FixtureCapability{FixtureState, FixturePublicConfiguration}) ||
			len(execution.Writer) != 3 || len(execution.FreshBefore) != 0 || len(execution.FreshAfter) != 1 ||
			execution.FreshAfter[0].Purpose != FreshReopen || execution.FreshAfter[0].Role != "recipient-consumer" ||
			execution.FreshAfter[0].Step.Role != "recipient-consumer" || execution.FreshAfter[0].Step.Expected != "success" {
			t.Fatal("operator public roles, fixture or independent consumption differs", name)
		}
		for _, provider := range []string{"aws", "gcp"} {
			for _, recovery := range definition.RecoveryModes {
				if !slices.Contains(definition.Pairings, "live/"+provider+"/recovery-"+recovery) {
					t.Fatal("operator provider/Recovery cell is missing", name, provider, recovery)
				}
				cells++
			}
		}
	}
	if cells != 8 {
		t.Fatal("operator provider/Recovery cell inventory differs", cells)
	}
}

// full_only: false
func TestDisabledRecoveryOperatorRefusalIsRegisteredForBothProviders(t *testing.T) {
	names := authorityOperatorLiveGroupNames()
	if len(names) != 3 || names[2] != "operator.disabled-recovery-refuses-authority-replacement-through-cli" {
		t.Fatal("disabled Recovery production operator case is absent", names)
	}
	definition, known := HistoricalDefinitionFor(names[2])
	if !known || !reflect.DeepEqual(definition.RecoveryModes, []string{"disabled"}) ||
		!reflect.DeepEqual(definition.Providers, []string{"gcp", "aws"}) ||
		!reflect.DeepEqual(definition.Pairings, []string{"live/gcp/recovery-disabled", "live/aws/recovery-disabled"}) ||
		len(definition.Steps) != 4 || definition.Steps[1].Expected != "disabled-recovery-replacement-refused-without-private-work" {
		t.Fatal("disabled Recovery operator inventory does not require its exact refusal", definition)
	}
}

func executionPostExitRole(name string) string {
	definition, _ := HistoricalDefinitionFor(name)
	execution := catalogExecution(name, definition.Modes[0])
	return execution.FreshAfter[0].Role
}

func executionPostExitExpected(name string) string {
	definition, _ := HistoricalDefinitionFor(name)
	execution := catalogExecution(name, definition.Modes[0])
	return execution.FreshAfter[0].Step.Expected
}

func declaredMeasurement(name, mode, owner string, position int) (bool, bool) {
	execution, known := HistoricalExecutionFor(name, mode)
	if !known {
		return false, false
	}
	var step Step
	switch owner {
	case "writer":
		if position < 0 || position >= len(execution.Writer) {
			return false, false
		}
		step = execution.Writer[position].Step
	case "fresh_before":
		children := execution.ExpandedFreshBefore()
		if len(children) == 0 {
			return false, false
		}
		step = children[0].Step
	case "fresh_after":
		step = execution.FreshAfter[0].Step
	default:
		return false, false
	}
	return execution.MeasurementFor(owner, position, step)
}

// full_only: false
func TestCurrentKeyReplacementSelectionHasAuthorityCases(t *testing.T) {
	schedule, err := HistoricalResolve(HistoricalRequest{Include: currentKeyReplacementGroupNames("both"), Repetitions: 1})
	if err != nil {
		t.Fatal("current-key replacement selection is unavailable", err)
	}
	if len(schedule.Selected) != 27 {
		t.Fatal("replacement selection omits its reader or authority cases", len(schedule.Selected))
	}
}

// full_only: false
func TestCurrentKeyReplacementScheduleNamesAndModesAreExact(t *testing.T) {
	for _, mode := range []string{"disabled", "enabled", "both"} {
		schedule, err := HistoricalResolve(HistoricalRequest{Include: currentKeyReplacementGroupNames("both"), RecoveryMode: mode, Repetitions: 1})
		want := 27
		if mode == "disabled" {
			want = 7
		}
		if err != nil || len(schedule.Selected) != want || schedule.RecoveryMode != mode || schedule.FullCoverage {
			t.Fatal("replacement schedule differs", mode, schedule, err)
		}
		full, err := HistoricalResolve(HistoricalRequest{Include: historicalRegressionNames(), RecoveryMode: mode, Repetitions: 1})
		wantFull := 97
		if mode == "disabled" {
			wantFull = 60
		}
		if err != nil || !full.FullCoverage || len(full.Selected) != wantFull || full.RecoveryMode != mode {
			t.Fatal("full regression lost explicit applicable recovery scope", mode, len(full.Selected), wantFull, err)
		}
		for _, name := range schedule.Selected {
			definition, ok := HistoricalDefinitionFor(name)
			if !ok || len(definition.RolesForRecovery(mode)) == 0 {
				t.Fatal("scheduled incompatible case", mode, name)
			}
			if c, ok := authorityReplacementGroup(name); ok {
				if !slices.Contains(definition.Roles, "replacement-store") || !slices.Contains(definition.Roles, executionPostExitRole(name)) {
					t.Fatal("replacement omitted exact store or current decrypter role", name)
				}
				roles := definition.RolesForRecovery(mode)
				if c.Operation == 1 && c.Mask&2 != 0 && mode != "both" {
					wanted, absent := "recovery-decrypter-0", "authority-decrypter-0"
					if mode == "disabled" {
						wanted, absent = absent, wanted
					}
					if !slices.Contains(roles, wanted) || slices.Contains(roles, absent) {
						t.Fatal("normal KEK source follows approval instead of surviving recovery mode", name, mode)
					}
				}
				if c.Operation == 3 && c.Mask&8 != 0 && (!slices.Contains(roles, "authority-decrypter-0") || slices.Contains(roles, "recovery-decrypter-0")) {
					t.Fatal("recovery KEK replacement retained its lost private source", name)
				}
			}
		}
	}
	if _, err := HistoricalResolve(HistoricalRequest{Include: []string{"access.recovery-combined-k2-current-material"}, RecoveryMode: "disabled", Repetitions: 1}); err == nil {
		t.Fatal("selection with no compatible case was accepted")
	}
	if _, err := HistoricalResolve(HistoricalRequest{RecoveryMode: "unsupported", Repetitions: 1}); err == nil {
		t.Fatal("unknown recovery scope was accepted")
	}
	for _, name := range currentKeyReplacementGroupNames("both") {
		definition, _ := HistoricalDefinitionFor(name)
		steps := executionWriterSteps(name, "hermetic")
		for _, step := range steps {
			if !slices.Contains(definition.RecoveryModes, step.RecoveryMode) {
				t.Fatal("hermetic plan invents an unsupported recovery mode", name)
			}
		}
		if len(steps) != len(definition.Steps)*len(definition.RecoveryModes) {
			t.Fatal("hermetic plan omits supported mode steps", name)
		}
	}
}

// full_only: false
func TestCurrentKeyReplacementPrivateWitnessStepsHaveExactActors(t *testing.T) {
	for _, name := range currentKeyReplacementGroupNames("both") {
		definition, _ := HistoricalDefinitionFor(name)
		var witnesses []Step
		for _, step := range definition.Steps {
			if step.Expected == "current-private-probe-success" || step.Expected == "wrong-binding-provider-refusal" || step.Expected == "authenticated-provider-denial" {
				witnesses = append(witnesses, step)
			}
		}
		if name != "access.normal-combined-k3-current-material" {
			if len(witnesses) != 0 {
				t.Fatal("private witness ran outside its declared case", name)
			}
			continue
		}
		wanted := []Step{{Name: "verification", Role: "authority-decrypter-1", Expected: "current-private-probe-success"}, {Name: "verification", Role: "authority-decrypter-1", Expected: "wrong-binding-provider-refusal"}, {Name: "verification", Role: "recovery-decrypter-0", Expected: "authenticated-provider-denial"}}
		if !reflect.DeepEqual(witnesses, wanted) {
			t.Fatal("private witness actor/result distinction changed")
		}
	}
}

// full_only: false
func TestReciprocalAuthoritySequenceUsesCurrentGenerations(t *testing.T) {
	for _, material := range []bool{false, true} {
		suffix := "zero-material"
		if material {
			suffix = "current-material"
		}
		name := "access.reciprocal-authority-" + suffix
		c, ok := authorityReplacementGroup(name)
		want := []AuthorityReplacementCase{
			{Operation: 1, Mask: 3, Approval: 2, Material: material},
			{Operation: 3, Mask: 12, Approval: 1, Material: material},
			{Operation: 1, Mask: 2, Approval: 2, Material: material},
			{Operation: 3, Mask: 8, Approval: 1, Material: material},
		}
		if !ok || !reflect.DeepEqual(c.Stages(), want) {
			t.Fatal("reciprocal scenario does not repeat both KEK replacements with current authority", name)
		}
		definition, _ := HistoricalDefinitionFor(name)
		roles := []string{"authority", "recovery", "replacement-store", "normal-signer-1", "recovery-signer-0", "recovery-signer-1", "authority-decrypter-1", "authority-decrypter-2", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2"}
		slices.Sort(roles)
		slices.Sort(definition.Roles)
		if !reflect.DeepEqual(definition.Roles, roles) || executionPostExitRole(name) != "authority-decrypter-2" {
			t.Fatal("reciprocal scenario omits current routes or reinstalls obsolete private routes", name)
		}
		wantSteps := 10
		if material {
			wantSteps++
		}
		for _, mode := range []string{"hermetic", "live"} {
			steps := executionWriterSteps(name, mode)
			if len(steps) != wantSteps || len(executionBeforeSteps(name, mode)) != 1 || steps[len(steps)-1].Name != "reopen" || steps[len(steps)-1].Role != "authority-decrypter-2" {
				t.Fatal("reciprocal scenario lacks four complete checks and one final current restart", name, mode)
			}
		}
	}
}

// full_only: false
func TestCatalogRolesAndScenarioOutcomes(t *testing.T) {
	for _, definition := range HistoricalDefinitions() {
		if definition.Name == "" || definition.Title == "" || definition.Description == "" || len(definition.Steps) == 0 {
			t.Fatal("incomplete definition")
		}
		roles := []string{"authority", "recovery"}
		if historicalHasFixtureCapability(definition.Name, FixtureObserver) {
			roles = append(roles, executionPostExitRole(definition.Name))
		}
		if historicalHasFixtureCapability(definition.Name, FixtureSecretState) && executionPostExitRole(definition.Name) != "authority" {
			roles = append(roles, executionPostExitRole(definition.Name))
		}
		if definition.Name == "secret.complete-supplied-sharing-preserves-current-access" {
			roles = append(roles, "reader")
		}
		if c, history := generatedHistoryGroup(definition.Name); history {
			roles = []string{"authority", "recovery", "replacement-store", "normal-signer-0", "authority-decrypter-0"}
			if c.Reciprocal {
				roles = append(roles, "recovery-signer-0", "authority-decrypter-1", "authority-decrypter-2", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2")
			}
			if c.SourceMode == 2 {
				roles = append(roles, "reader")
				if !c.Union {
					roles = append(roles, "denied-reader")
				}
			}
		}
		if row, public := HistoricalPublicConfiguration(definition.Name); public {
			roles = row.Roles
		}
		execution := catalogExecution(definition.Name, definition.Modes[0])
		if row, recovery := HistoricalConfigurationRecovery(definition.Name); recovery {
			roles = expectedConfigurationRecoveryRoles(row.Condition)
		}
		if execution.Family == FamilyCombinedHistory {
			roles = []string{"authority", "recovery", "reader", "denied-reader", "reader-successor", "replacement-store", "normal-signer-0", "recovery-signer-0", "authority-decrypter-0", "authority-decrypter-1", "recovery-decrypter-0", "recovery-decrypter-1"}
		}
		if execution.Family == FamilyAuthorityOperator {
			roles = []string{"authority", "reader", "cleanup", "recipient-consumer"}
			if definition.Name == authorityOperatorLiveGroupNames()[1] {
				roles = append(roles, "successor")
			}
		}
		_, authorityCase := authorityReplacementGroup(definition.Name)
		if !authorityCase && !reflect.DeepEqual(roles, definition.Roles) {
			t.Fatalf("scenario %s role contract differs: got %v, want %v", definition.Name, definition.Roles, roles)
		}
		for _, step := range definition.Steps {
			if step.Expected == "" || !slices.Contains(definition.Roles, step.Role) {
				t.Fatal("incomplete step")
			}
		}
		if historicalHasFixtureCapability(definition.Name, FixtureObserver) {
			last := definition.Steps[len(definition.Steps)-1]
			want := "success"
			if historicalHasFixtureCapability(definition.Name, FixtureReadRefusal) {
				want = "access-refused"
			}
			if last.Role != executionPostExitRole(definition.Name) || last.Expected != want {
				t.Fatal("scenario lost expected result")
			}
		}
	}
	full, err := HistoricalResolve(HistoricalRequest{Include: historicalRegressionNames(), Repetitions: 1})
	if err != nil || !full.FullCoverage || len(full.Selected) != 97 {
		t.Fatal("component regression obligation changed")
	}
	for _, name := range full.Selected {
		if historicalHasFixtureCapability(name, FixtureObserver) {
			t.Fatal("conflicting witness added to regression obligation")
		}
	}
}

// full_only: false
func TestDamagedStatePlansRequireTheObservedFreshRefusal(t *testing.T) {
	for name, expected := range map[string]string{
		"evidence.missing-selected-child-prevents-open": "unavailable",
		"evidence.corrupt-selected-child-prevents-open": "integrity-failure",
	} {
		t.Run(name, func(t *testing.T) {
			definition, known := HistoricalDefinitionFor(name)
			if !known || len(definition.Steps) != 4 || definition.Steps[3] != (Step{Name: "reopen", Role: "authority", Expected: expected}) || executionPostExitExpected(name) != expected {
				t.Fatal("damaged-state plan lost its exact reopen result")
			}
			if !reflect.DeepEqual(executionWriterSteps(name, "hermetic"), expectedHermeticModeSteps(definition.Steps)) || !reflect.DeepEqual(executionWriterSteps(name, "live"), definition.Steps[:3]) || len(executionBeforeSteps(name, "hermetic")) != 2 || len(executionBeforeSteps(name, "live")) != 0 {
				t.Fatal("plan changed the mode's process boundary")
			}
		})
	}
}

// full_only: false
func TestFixtureShapes(t *testing.T) {
	for _, scenario := range scenarios {
		if scenario.execution.family != FamilyState || scenario.explicitShape || scenario.members != 0 || scenario.smallBytes != 0 || scenario.largeCount != 0 {
			continue
		}
		t.Run(scenario.name, func(t *testing.T) {
			checkFixture(t, scenario.name, 0, 32, 1, 0, 32, false)
		})
	}
	checkFixture(t, "state.transient-before-send-rerun", 0, 1, 1, 0, 1, false)
	tests := []struct {
		name       string
		members    int
		smallBytes int
		largeCount int
		rawBytes   int
		fragmented bool
	}{
		{"capacity.compact-state-preserves-complete-update", 64, 4096, 6, 630784, false},
		{"capacity.fragmented-state-preserves-complete-update", 64, 4096, 6, 630784, true},
		{"capacity.maximum-member-count-preserves-complete-update", 512, 4096, 51, 5230592, false},
		{"capacity.maximum-size-state-refuses-growth-and-allows-update", 512, 16384, 0, 8388608, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkFixture(t, test.name, 0, test.members, test.smallBytes, test.largeCount, test.rawBytes, test.fragmented)
		})
	}
	for _, members := range []int{1, 2, 16, 32, 64} {
		checkFixture(t, "state.single-value-update-preserves-other-values", members, members, 1, 0, members, false)
	}
}

func checkFixture(t *testing.T, name string, override, members, smallBytes, largeCount, rawBytes int, fragmented bool) {
	t.Helper()
	shape, err := HistoricalFixtureShape(name, override)
	if err != nil {
		t.Fatal(err)
	}
	if shape.Members != members || shape.SmallValueCount != members-largeCount || shape.SmallValueBytes != smallBytes || shape.LargeValueCount != largeCount || shape.RawValueBytes != rawBytes || shape.Fragmented != fragmented || shape.ValueSeed != "member_index_modulo_256" {
		t.Fatalf("fixture %s/%d = %+v", name, override, shape)
	}
	if largeCount == 0 && shape.LargeValueBytes != nil || largeCount != 0 && (shape.LargeValueBytes == nil || *shape.LargeValueBytes != 65536) {
		t.Fatalf("fixture %s has incorrect large value size", name)
	}
	sizes, gotFragmented, err := HistoricalFixtureSizes(name, override)
	if err != nil || len(sizes) != members || gotFragmented != fragmented {
		t.Fatalf("sizes %s/%d: count %d, fragmented %v, error %v", name, override, len(sizes), gotFragmented, err)
	}
	total := 0
	for i, size := range sizes {
		want := smallBytes
		if i >= members-largeCount {
			want = 65536
		}
		if size != want {
			t.Errorf("member %d size = %d, want %d", i, size, want)
		}
		total += size
	}
	if total != rawBytes {
		t.Errorf("fixture body bytes = %d, want %d", total, rawBytes)
	}
	if len(sizes) == 0 {
		return
	}
	sizes[0] = -1
	freshSizes, _, err := HistoricalFixtureSizes(name, override)
	if err != nil || freshSizes[0] < 0 {
		t.Fatal("fixture sizes alias earlier output")
	}
}

// full_only: false
func TestResolveExplicitFullSchedule(t *testing.T) {
	schedule, err := HistoricalResolve(HistoricalRequest{Include: historicalRegressionNames(), Repetitions: 2})
	if err != nil {
		t.Fatal(err)
	}
	names := historicalRegressionNames()
	if !reflect.DeepEqual(schedule.Selected, names) || schedule.MemberCounts != nil || schedule.Repetitions != 2 || !schedule.FullCoverage || len(schedule.Entries) != 195 {
		t.Fatalf("full schedule = %+v", schedule)
	}
	want := Entry{Scenario: pointScenario, Sequence: 0, Repetition: 0, Smoke: true}
	if schedule.Entries[0] != want {
		t.Fatalf("smoke = %+v, want %+v", schedule.Entries[0], want)
	}
	for repetition := 1; repetition <= 2; repetition++ {
		for i, name := range names {
			index := 1 + (repetition-1)*len(names) + i
			want := Entry{Scenario: name, Sequence: index, Repetition: repetition}
			if schedule.Entries[index] != want {
				t.Errorf("entry %d = %+v, want %+v", index, schedule.Entries[index], want)
			}
		}
	}
}

// full_only: false
func TestResolvePreservesExplicitSelectionOrder(t *testing.T) {
	schedule, err := HistoricalResolve(HistoricalRequest{Include: []string{"state.historical-bytes-get-new-identities", "state.identical-input-keeps-current-state"}, Repetitions: 2})
	if err != nil {
		t.Fatal(err)
	}
	want := Schedule{
		RecoveryMode: "both",
		Selected:     []string{"state.historical-bytes-get-new-identities", "state.identical-input-keeps-current-state"}, Repetitions: 2,
		Entries: []Entry{
			{Scenario: pointScenario, Sequence: 0, Repetition: 0, Smoke: true},
			{Scenario: "state.historical-bytes-get-new-identities", Sequence: 1, Repetition: 1},
			{Scenario: "state.identical-input-keeps-current-state", Sequence: 2, Repetition: 1},
			{Scenario: "state.historical-bytes-get-new-identities", Sequence: 3, Repetition: 2},
			{Scenario: "state.identical-input-keeps-current-state", Sequence: 4, Repetition: 2},
		},
	}
	if !reflect.DeepEqual(schedule, want) {
		t.Fatalf("selected schedule = %+v, want %+v", schedule, want)
	}
}

// full_only: false
func TestResolveRecordsInapplicableRecoveryCases(t *testing.T) {
	include := []string{
		"accepted.source-mode2-reciprocal-loss",
		"state.identical-input-keeps-current-state",
		"access.recovery-combined-k2-current-material",
		"accepted.source-mode0-late-result",
		"accepted.source-mode0-reciprocal-loss",
	}
	for _, mode := range []string{"disabled", "enabled", "both"} {
		t.Run(mode, func(t *testing.T) {
			schedule, err := HistoricalResolve(HistoricalRequest{Include: include, RecoveryMode: mode, Repetitions: 2})
			if err != nil {
				t.Fatal(err)
			}
			selected := include
			var notApplicable []string
			if mode == "disabled" {
				selected = []string{"state.identical-input-keeps-current-state", "accepted.source-mode0-late-result"}
				notApplicable = []string{"accepted.source-mode2-reciprocal-loss", "access.recovery-combined-k2-current-material", "accepted.source-mode0-reciprocal-loss"}
			}
			if !slices.Equal(schedule.Selected, selected) || !slices.Equal(schedule.NotApplicable, notApplicable) || len(schedule.Entries) != 1+2*len(selected) {
				t.Fatalf("recovery selection lost ordered evidence: %+v", schedule)
			}
			for _, entry := range schedule.Entries {
				if slices.Contains(notApplicable, entry.Scenario) {
					t.Fatal("inapplicable case was scheduled", entry)
				}
			}
			body, err := json.Marshal(schedule)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			raw, recorded := fields["not_applicable"]
			if recorded != (mode == "disabled") {
				t.Fatal("inapplicable evidence presence differs", string(body))
			}
			if recorded {
				var got []string
				if err := json.Unmarshal(raw, &got); err != nil || !slices.Equal(got, notApplicable) {
					t.Fatal("inapplicable evidence differs", string(raw), err)
				}
			}
		})
	}
}

// full_only: false
func TestSavedSuitesUseConcreteScenarios(t *testing.T) {
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
	files, err := filepath.Glob(filepath.Join(directory, "tests", "suites", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal("saved suites were not found", err)
	}
	saved := make(map[string][]string)
	smokePolicies := make(map[string]SmokePolicy)
	owners := make(map[string]string)
	for _, filename := range files {
		file, err := os.Open(filename)
		if err != nil {
			t.Fatal(err)
		}
		var suite struct {
			SchemaVersion int      `json:"schema_version"`
			Name          string   `json:"name"`
			Description   string   `json:"description"`
			RequiredRoles []string `json:"required_roles"`
			Scenarios     []string `json:"scenarios"`
		}
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&suite)
		trailingErr := decoder.Decode(new(any))
		closeErr := file.Close()
		if decodeErr != nil || !errors.Is(trailingErr, io.EOF) || closeErr != nil {
			t.Fatal(filename, decodeErr, trailingErr, closeErr)
		}
		if suite.SchemaVersion != 2 || suite.Name != strings.TrimSuffix(filepath.Base(filename), ".json") {
			t.Fatal("suite identity differs", filename)
		}
		if strings.TrimSpace(suite.Description) == "" {
			t.Error("saved suite needs a description", filename)
		}
		policy := SmokeSeparatePoint
		if suite.Name == "state-point-diagnostic" {
			policy = SmokeFirstSelectedPoint
		} else if suite.Name == "authority-operator" || slices.ContainsFunc(suite.Scenarios, func(name string) bool {
			return strings.HasPrefix(name, "public-configuration.")
		}) {
			policy = SmokePublicConfiguration
		}
		schedule, err := Resolve(Request{Include: suite.Scenarios, Repetitions: 1, SmokePolicy: policy})
		if err != nil || !slices.Equal(schedule.Selected, suite.Scenarios) || len(schedule.NotApplicable) != 0 {
			t.Fatal("suite must list concrete unique scenarios", filename, err)
		}
		if want := RolesForScenarios(suite.Scenarios, "both"); !slices.Equal(suite.RequiredRoles, want) {
			t.Fatal("suite required roles differ from its scenarios", filename, suite.RequiredRoles, want)
		}
		saved[suite.Name] = suite.Scenarios
		smokePolicies[suite.Name] = policy
		for _, scenario := range suite.Scenarios {
			if owner, exists := owners[scenario]; exists {
				// The diagnostic suite intentionally includes the ordinary
				// point32 witness; all other focused ownership stays unique.
				diagnosticOverlap := scenario == "state.single-value-update-preserves-other-values/members_32" &&
					(owner == "state-smoke" && suite.Name == "state-point-diagnostic" || owner == "state-point-diagnostic" && suite.Name == "state-smoke")
				publicOverlap := strings.HasPrefix(scenario, "public-configuration.") && (owner == "public-configuration" && suite.Name == "public-configuration-functional" || owner == "public-configuration-functional" && suite.Name == "public-configuration")
				if !diagnosticOverlap && !publicOverlap {
					t.Errorf("scenario %s occurs in both %s and %s", scenario, owner, suite.Name)
				}
			}
			owners[scenario] = suite.Name
		}
	}
	for _, scenario := range Names() {
		if _, present := owners[scenario]; !present {
			t.Error("scenario has no focused suite", scenario)
		}
	}

	diagnostic := saved["state-point-diagnostic"]
	if len(diagnostic) != 64 {
		t.Fatal("point diagnostic suite must enumerate all 64 leaves", len(diagnostic))
	}
	for i, name := range diagnostic {
		want := fmt.Sprintf("state.single-value-update-preserves-other-values/members_%d", i+1)
		if name != want {
			t.Fatal("point diagnostic membership or order differs", i, name, want)
		}
	}
	commonRecovery := slices.DeleteFunc(ConfigurationRecoveryNames(), func(name string) bool {
		row, known := ConfigurationRecovery(name)
		if !known {
			t.Fatal("configuration recovery case missing", name)
		}
		return row.AWSOnly || row.Generated
	})
	generatedRecovery := []string{
		"reconstruction.mixed-generated/complete_loss_mixed_generated",
		"reconstruction.generated-repeated-later/complete_loss_generated_repeated_later",
		"reconstruction.generated-active/complete_loss_generated_active",
		"reconstruction.generated-retiring/complete_loss_generated_retiring",
		"reconstruction.generated-uncertain/complete_loss_generated_uncertain",
	}
	if len(commonRecovery) != 39 || len(ConfigurationRecoveryNames()) != 45 {
		t.Fatal("configuration recovery suite partition changed", len(commonRecovery), len(ConfigurationRecoveryNames()))
	}
	for name, want := range map[string][]string{
		"current-key-replacement":          CurrentKeyReplacementNames("both"),
		"accepted-work-recovery":           GeneratedHistoryNames("both"),
		"generated-lifecycle":              GeneratedLifecycleLiveNames(),
		"configuration-recovery":           commonRecovery,
		"configuration-recovery-aws-owner": {"reconstruction.wrong-owner/complete_loss_wrong_owner"},
		"configuration-recovery-generated": generatedRecovery,
		"generated-synthetic":              GeneratedNames()[3:],
		"authority-operator":               AuthorityOperatorLiveNames(),
		"publication":                      PublicationNames(),
		"public-inspection-receipts":       {"public-configuration.inspection-receipts/inspection_receipts"},
	} {
		if !slices.Equal(saved[name], want) {
			t.Fatal("saved suite coverage or order changed", name, saved[name])
		}
	}
	publicNames := []string{
		"public-configuration.standard-discovery/standard_discovery",
		"public-configuration.empty-initialization/empty_initialization",
		"public-configuration.required-public-denied/required_public_denied",
		"public-configuration.normal-signing-denied/normal_signing_denied",
		"public-configuration.authority-private-denied/authority_private_denied",
		"public-configuration.recovery-signing-denied/recovery_signing_denied",
		"public-configuration.recovery-private-denied/recovery_private_denied",
		"public-configuration.portable-validation/portable_validation",
		"public-configuration.fresh-secret-apply/fresh_secret_apply",
		"public-configuration.retained-input-access/retained_input_access",
		"public-configuration.readonly-unknown-outcomes/readonly_unknown_outcomes",
		"public-configuration.recipient-lifecycle/recipient_lifecycle",
	}
	for name, want := range map[string][]string{"public-configuration": publicNames, "public-configuration-functional": publicNames[1:], "public-configuration-operator": {"public-configuration.credential-discovery/credential_discovery"}, "public-configuration-replacement": {"public-configuration.keys-replace-authority-signing-by-authority/keys_replace_authority_signing_by_authority", "public-configuration.keys-replace-authority-signing-by-recovery/keys_replace_authority_signing_by_recovery", "public-configuration.keys-replace-authority-encryption-by-authority/keys_replace_authority_encryption_by_authority", "public-configuration.keys-replace-authority-encryption-by-recovery/keys_replace_authority_encryption_by_recovery", "public-configuration.keys-replace-authority-both-by-authority/keys_replace_authority_both_by_authority", "public-configuration.keys-replace-authority-both-by-recovery/keys_replace_authority_both_by_recovery", "public-configuration.keys-replace-recovery-signing-by-authority/keys_replace_recovery_signing_by_authority", "public-configuration.keys-replace-recovery-signing-by-recovery/keys_replace_recovery_signing_by_recovery", "public-configuration.keys-replace-recovery-encryption-by-authority/keys_replace_recovery_encryption_by_authority", "public-configuration.keys-replace-recovery-encryption-by-recovery/keys_replace_recovery_encryption_by_recovery", "public-configuration.keys-replace-recovery-both-by-authority/keys_replace_recovery_both_by_authority", "public-configuration.keys-replace-recovery-both-by-recovery/keys_replace_recovery_both_by_recovery", "public-configuration.keys-replace-recipient/keys_replace_recipient", "public-configuration.keys-replace-required-public-denied/keys_replace_required_public_denied", "public-configuration.keys-replace-normal-signing-denied/keys_replace_normal_signing_denied", "public-configuration.keys-replace-authority-private-denied/keys_replace_authority_private_denied", "public-configuration.keys-replace-recovery-signing-denied/keys_replace_recovery_signing_denied", "public-configuration.keys-replace-recovery-private-denied/keys_replace_recovery_private_denied", "public-configuration.keys-replace-operator-both/keys_replace_operator_both"}} {
		if !slices.Equal(saved[name], want) {
			t.Fatal("public suite scope differs", name, saved[name])
		}
	}
	for _, mode := range []string{"disabled", "enabled", "both"} {
		for name := range saved {
			policy := smokePolicies[name]
			var selected, notApplicable []string
			for _, scenario := range saved[name] {
				definition, _ := DefinitionFor(scenario)
				if len(definition.RolesForRecovery(mode)) == 0 {
					notApplicable = append(notApplicable, scenario)
				} else {
					selected = append(selected, scenario)
				}
			}
			schedule, err := Resolve(Request{Include: saved[name], RecoveryMode: mode, Repetitions: 1, SmokePolicy: policy})
			if len(selected) == 0 {
				if err == nil || err.Error() != "case selection has no cases for the recovery mode" || !reflect.DeepEqual(schedule, Schedule{}) {
					t.Fatal("saved suite without applicable cases did not refuse exactly", name, mode, schedule, err)
				}
				continue
			}
			if err != nil {
				t.Fatal(name, mode, err)
			}
			wantEntries := len(selected) + 1
			if policy != SmokeSeparatePoint || slices.Contains(selected, pointScenario+"/members_32") {
				wantEntries = len(selected)
			}
			if !slices.Equal(schedule.Selected, selected) || !slices.Equal(schedule.NotApplicable, notApplicable) || schedule.FullCoverage || len(schedule.Entries) != wantEntries || !schedule.Entries[0].Smoke {
				t.Fatal("saved suite scope or smoke differs", name, mode, schedule)
			}
		}
	}
}

// full_only: false
func TestGeneratedLifecycleScenarioIDsAndPairingsAreExact(t *testing.T) {
	want := []string{
		"generated.mixed-apply-selects-complete-set",
		"generated.retirement-acknowledgement-closes",
		"generated.auto-retirement-acknowledgement-closes",
		"generated.active-retirement-residue",
		"generated.parked-retirement-residue",
		"generated.conflicting-retirement-stays-open",
		"generated.cleanup-source0-closes",
		"generated.cleanup-source2-closes",
		"generated.cleanup-repeated-ambiguity-closes",
		"generated.cleanup-detached-hazard-closes",
		"generated.cleanup-deleting-hazard-closes",
	}
	if !slices.Equal(generatedGroupNames(), want) {
		t.Fatal("generated lifecycle scenario IDs differ", generatedGroupNames())
	}
	pairings := []string{
		"hermetic/memory/recovery-disabled", "hermetic/memory/recovery-enabled",
	}
	for _, name := range want {
		definition, ok := HistoricalDefinitionFor(name)
		execution, executionKnown := HistoricalExecutionFor(name, "hermetic")
		steps := []Step{{Name: "reopen", Role: "authority", Expected: "success"}}
		purposes := []FreshPurpose{FreshReopen}
		if execution.Family == FamilyGeneratedRetirement {
			setup := Step{Name: "setup", Role: "authority", Expected: "generated-fixture-and-exact-authority-ready"}
			steps = append([]Step{setup, setup}, steps...)
			purposes = append([]FreshPurpose{FreshGeneratedRecord, FreshGeneratedRecord}, purposes...)
		}
		if execution.Family == FamilyGeneratedCleanup {
			setup := Step{Name: "setup", Role: "authority", Expected: "generated-fixture-and-exact-authority-ready"}
			transition := Step{Name: "transition", Role: "authority", Expected: definition.Steps[1].Expected}
			if name == "generated.cleanup-deleting-hazard-closes" {
				steps = append([]Step{setup, setup, transition}, steps...)
				purposes = append([]FreshPurpose{FreshGeneratedRecord, FreshGeneratedRecord, FreshGeneratedRecord}, purposes...)
			} else if name != "generated.cleanup-detached-hazard-closes" {
				steps = append([]Step{transition, transition}, steps...)
				purposes = append([]FreshPurpose{FreshGeneratedRecord, FreshGeneratedRecord}, purposes...)
			} else {
				steps = append([]Step{transition}, steps...)
				purposes = append([]FreshPurpose{FreshGeneratedRecord}, purposes...)
			}
		}
		if name == "generated.retirement-acknowledgement-closes" || name == "generated.auto-retirement-acknowledgement-closes" {
			steps = slices.Insert(steps, 2, Step{Name: "transition", Role: "authority", Expected: definition.Steps[1].Expected})
			purposes = slices.Insert(purposes, 2, FreshGeneratedRecord)
		}
		wantChildren := expectedHermeticModeSteps(steps)
		wantPurposes := append(append([]FreshPurpose(nil), purposes...), purposes...)
		var gotPurposes []FreshPurpose
		for _, child := range execution.ExpandedFreshBefore() {
			gotPurposes = append(gotPurposes, child.Purpose)
		}
		wantPairings, wantModes, wantProviders := pairings, []string{"hermetic"}, []string{"memory"}
		if slices.Contains(generatedLiveGroupNames(), name) {
			wantPairings = append(append([]string(nil), pairings...), "live/gcp/recovery-disabled", "live/gcp/recovery-enabled", "live/aws/recovery-disabled", "live/aws/recovery-enabled")
			wantModes, wantProviders = []string{"hermetic", "live"}, []string{"memory", "gcp", "aws"}
		}
		if !ok || !executionKnown || !slices.Equal(definition.Pairings, wantPairings) || !slices.Equal(definition.RecoveryModes, []string{"disabled", "enabled"}) || !slices.Equal(definition.Modes, wantModes) || !slices.Equal(definition.Providers, wantProviders) ||
			len(executionBeforeSteps(name, "hermetic")) != len(wantChildren) || !slices.Equal(executionBeforeSteps(name, "hermetic"), wantChildren) || !slices.Equal(gotPurposes, wantPurposes) {
			t.Fatal("generated lifecycle pairing differs", name, definition)
		}
	}
}

// full_only: false
func TestResolveMemberSweep(t *testing.T) {
	counts := []int{1, 2, 16, 32, 64}
	schedule, err := HistoricalResolve(HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Members: counts, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(schedule.MemberCounts, counts) || schedule.Repetitions != 1 || schedule.FullCoverage || len(schedule.Entries) != len(counts) {
		t.Fatalf("member sweep = %+v", schedule)
	}
	for i, count := range counts {
		want := Entry{Scenario: pointScenario, Members: count, Sequence: i, Repetition: 1}
		if i == 0 {
			want.Smoke, want.Repetition = true, 0
		}
		if schedule.Entries[i] != want {
			t.Errorf("entry %d = %+v, want %+v", i, schedule.Entries[i], want)
		}
	}
}

// full_only: false
func TestResolveCoverage(t *testing.T) {
	reversed := historicalNames()
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	tests := []struct {
		name string
		req  HistoricalRequest
		full bool
	}{
		{"explicit full set", HistoricalRequest{Include: historicalRegressionNames(), Repetitions: 1}, true},
		{"reordered full set", HistoricalRequest{Include: reversed, Repetitions: 1}, true},
		{"focused", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Repetitions: 1}, false},
		{"smoke does not replace selection", HistoricalRequest{Include: slices.DeleteFunc(historicalRegressionNames(), func(name string) bool { return name == pointScenario }), Repetitions: 1}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule, err := HistoricalResolve(test.req)
			if err != nil || schedule.FullCoverage != test.full {
				t.Fatalf("coverage = %v, error = %v", schedule.FullCoverage, err)
			}
		})
	}
	maximum, err := HistoricalResolve(HistoricalRequest{Include: historicalRegressionNames(), Repetitions: 100})
	if err != nil || len(maximum.Entries) != 9701 {
		t.Fatalf("maximum repetitions: %d entries, error = %v", len(maximum.Entries), err)
	}
}

// full_only: false
func TestResolveRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		req  HistoricalRequest
	}{
		{"missing repetitions", HistoricalRequest{}},
		{"negative repetitions", HistoricalRequest{Repetitions: -1}},
		{"excess repetitions", HistoricalRequest{Repetitions: 101}},
		{"missing include", HistoricalRequest{Repetitions: 1}},
		{"empty include", HistoricalRequest{Include: []string{}, Repetitions: 1}},
		{"all alias", HistoricalRequest{Include: []string{"all"}, Repetitions: 1}},
		{"replacement alias", HistoricalRequest{Include: []string{"current-key-replacement"}, Repetitions: 1}},
		{"accepted alias", HistoricalRequest{Include: []string{"accepted-work-recovery"}, Repetitions: 1}},
		{"blank include", HistoricalRequest{Include: []string{""}, Repetitions: 1}},
		{"unknown include", HistoricalRequest{Include: []string{"credential-like-secret"}, Repetitions: 1}},
		{"duplicate include", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values", "state.single-value-update-preserves-other-values"}, Repetitions: 1}},
		{"all with another name", HistoricalRequest{Include: []string{"all", "state.single-value-update-preserves-other-values"}, Repetitions: 1}},
		{"duplicate all", HistoricalRequest{Include: []string{"all", "all"}, Repetitions: 1}},
		{"no applicable scenario", HistoricalRequest{Include: []string{"accepted.source-mode0-reciprocal-loss"}, RecoveryMode: "disabled", Repetitions: 1}},
		{"empty member sweep", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Members: []int{}, Repetitions: 1}},
		{"duplicate members", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Members: []int{1, 1}, Repetitions: 1}},
		{"zero members", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Members: []int{0}, Repetitions: 1}},
		{"negative members", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Members: []int{-1}, Repetitions: 1}},
		{"excess members", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Members: []int{65}, Repetitions: 1}},
		{"members with all scenarios", HistoricalRequest{Include: historicalRegressionNames(), Members: []int{1}, Repetitions: 1}},
		{"members with unchanged", HistoricalRequest{Include: []string{"state.identical-input-keeps-current-state"}, Members: []int{1}, Repetitions: 1}},
		{"members with capacity", HistoricalRequest{Include: []string{"capacity.compact-state-preserves-complete-update"}, Members: []int{1}, Repetitions: 1}},
		{"members with repeated point", HistoricalRequest{Include: []string{"state.single-value-update-preserves-other-values"}, Members: []int{1}, Repetitions: 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule, err := HistoricalResolve(test.req)
			if err == nil || !reflect.DeepEqual(schedule, Schedule{}) {
				t.Fatalf("invalid request returned schedule %+v, error %v", schedule, err)
			}
			if len(err.Error()) > 120 || strings.Contains(err.Error(), "credential-like-secret") {
				t.Fatalf("error contains unbounded input: %q", err)
			}
		})
	}
}

// full_only: false
func TestFixtureRejectsUnsupportedParameters(t *testing.T) {
	for _, test := range []struct {
		name    string
		members int
	}{{"credential-like-secret", 0}, {"all", 0}, {"", 0}, {"state.single-value-update-preserves-other-values", -1}, {"state.single-value-update-preserves-other-values", 65}, {"state.identical-input-keeps-current-state", 1}, {"capacity.compact-state-preserves-complete-update", 64}} {
		shape, shapeErr := HistoricalFixtureShape(test.name, test.members)
		sizes, fragmented, sizesErr := HistoricalFixtureSizes(test.name, test.members)
		if shapeErr == nil || sizesErr == nil || !reflect.DeepEqual(shape, Shape{}) || sizes != nil || fragmented {
			t.Errorf("invalid fixture returned shape %+v, sizes %v, errors %v/%v", shape, sizes, shapeErr, sizesErr)
		}
		for _, err := range []error{shapeErr, sizesErr} {
			if err != nil && (len(err.Error()) > 120 || strings.Contains(err.Error(), "credential-like-secret")) {
				t.Errorf("error contains unbounded input: %q", err)
			}
		}
	}
}

// full_only: false
func TestResolveDoesNotMutateOrRetainCallerSlices(t *testing.T) {
	request := HistoricalRequest{Include: []string{"accepted.source-mode0-reciprocal-loss", pointScenario}, RecoveryMode: "disabled", Members: []int{64, 1}, Repetitions: 1}
	original := HistoricalRequest{Include: []string{"accepted.source-mode0-reciprocal-loss", pointScenario}, RecoveryMode: "disabled", Members: []int{64, 1}, Repetitions: 1}
	schedule, err := HistoricalResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(request, original) {
		t.Fatal("Resolve modified caller slices")
	}
	request.Include[0], request.Include[1], request.Members[0] = "state.historical-bytes-get-new-identities", "state.identical-input-keeps-current-state", 2
	if !reflect.DeepEqual(schedule.Selected, []string{pointScenario}) || !reflect.DeepEqual(schedule.NotApplicable, []string{"accepted.source-mode0-reciprocal-loss"}) || !reflect.DeepEqual(schedule.MemberCounts, []int{64, 1}) || schedule.Entries[0].Members != 64 {
		t.Fatal("schedule retains caller slices")
	}
	schedule.Selected[0], schedule.NotApplicable[0], schedule.MemberCounts[0] = "state.historical-bytes-get-new-identities", "accepted.source-mode1-reciprocal-loss", 3
	fresh, err := HistoricalResolve(original)
	if err != nil || !reflect.DeepEqual(fresh.Selected, []string{pointScenario}) || !reflect.DeepEqual(fresh.NotApplicable, []string{"accepted.source-mode0-reciprocal-loss"}) || !reflect.DeepEqual(fresh.MemberCounts, []int{64, 1}) {
		t.Fatal("schedule output aliases later output")
	}
}

// full_only: false
func TestLifecycleFixtureShapes(t *testing.T) {
	for _, test := range []struct {
		name                                      string
		members, smallBytes, largeCount, rawBytes int
	}{
		{"lifecycle.empty-state-preserves-domain-and-readd", 0, 0, 0, 0},
		{"secret.empty-domain-first-selection-survives-restart", 0, 0, 0, 0},
		{"lifecycle.mixed-membership-preserves-retained-records", 32, 1, 0, 32},
		{"capacity.maximum-disjoint-replacement-reuses-successor-slots", 512, 0, 128, 8388608},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkFixture(t, test.name, 0, test.members, test.smallBytes, test.largeCount, test.rawBytes, false)
			if _, err := HistoricalFixtureShape(test.name, 1); err == nil {
				t.Fatal("fixed lifecycle shape accepted a member sweep")
			}
		})
	}
}

// full_only: false
func TestLifecyclePlansRequireFreshOpenAfterEachSelection(t *testing.T) {
	for _, test := range []struct {
		name  string
		fresh int
	}{
		{"lifecycle.empty-state-preserves-domain-and-readd", 3},
		{"lifecycle.mixed-membership-preserves-retained-records", 1},
		{"capacity.maximum-disjoint-replacement-reuses-successor-slots", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			definition, known := HistoricalDefinitionFor(test.name)
			if !known {
				t.Fatal("missing lifecycle scenario")
			}
			for _, mode := range []string{"hermetic", "live"} {
				wantSteps, wantFresh := definition.Steps, test.fresh
				if mode == "hermetic" {
					wantSteps, wantFresh = expectedHermeticModeSteps(definition.Steps), 2*test.fresh
				}
				if len(executionBeforeSteps(test.name, mode)) != wantFresh || !reflect.DeepEqual(executionWriterSteps(test.name, mode), wantSteps) {
					t.Fatal("lifecycle scenario lost a required fresh-process selection check")
				}
			}
		})
	}
}

// full_only: false
func TestEveryWriterHasExplicitRecoveryInitializationRole(t *testing.T) {
	for _, d := range HistoricalDefinitions() {
		for _, mode := range []string{"enabled", "disabled", "both"} {
			count := 0
			for _, role := range d.RolesForRecovery(mode) {
				if role == "recovery" {
					count++
				}
			}
			want := 1
			if execution, public := d.Executions["live"]; public && execution.HasFixtureCapability(FixturePublicConfiguration) {
				want = 0
				for _, row := range expectedPublicScheduleRows(expectedScheduleCell{mode: "live", provider: "aws", recovery: mode}) {
					if row.Name == d.Name && slices.Contains(row.Roles, "recovery") {
						want = 1
					}
				}
			}
			if mode == "disabled" || mode != "both" && !slices.Contains(d.RecoveryModes, mode) {
				want = 0
			}
			if count != want {
				t.Fatalf("%s mode=%s recovery roles=%d want=%d", d.Name, mode, count, want)
			}
		}
	}
}

func expectedHermeticModeSteps(steps []Step) []Step {
	disabled, enabled := append([]Step(nil), steps...), append([]Step(nil), steps...)
	for i := range disabled {
		disabled[i].RecoveryMode = "disabled"
		enabled[i].RecoveryMode = "enabled"
	}
	return append(disabled, enabled...)
}

// full_only: false
func TestGeneratedHistoryFreshChildrenKeepOrderRoleAndPurpose(t *testing.T) {
	for _, name := range generatedHistoryGroupNames("both") {
		if catalogExecution(name, "hermetic").Family == FamilyCombinedHistory {
			continue
		}
		c, _ := generatedHistoryGroup(name)
		want := []Step{
			{Name: "transition", Role: "authority-decrypter-0", Expected: "original-late-result-recorded"},
			{Name: "reopen", Role: "authority-decrypter-0", Expected: "success"},
			{Name: "transition", Role: "authority-decrypter-0", Expected: "fresh-generated-final-selected"},
			{Name: "reopen", Role: "authority-decrypter-0", Expected: "success"},
		}
		if c.Reciprocal {
			want = []Step{
				{Name: "reopen", Role: "authority-decrypter-1", Expected: "success", RecoveryMode: "enabled"},
				{Name: "reopen", Role: "authority-decrypter-1", Expected: "success", RecoveryMode: "enabled"},
				{Name: "transition", Role: "authority-decrypter-1", Expected: "late-result-recorded-and-close-frozen", RecoveryMode: "enabled"},
				{Name: "reopen", Role: "authority-decrypter-2", Expected: "success", RecoveryMode: "enabled"},
				{Name: "reopen", Role: "authority-decrypter-2", Expected: "success", RecoveryMode: "enabled"},
				{Name: "transition", Role: "authority-decrypter-2", Expected: "fresh-generated-final-selected", RecoveryMode: "enabled"},
				{Name: "reopen", Role: "authority-decrypter-2", Expected: "success", RecoveryMode: "enabled"},
			}
		} else {
			want = expectedHermeticModeSteps(want)
		}
		wantPurposes := []FreshPurpose{FreshGeneratedRecord, FreshReopen, FreshGeneratedFinal, FreshReopen, FreshGeneratedRecord, FreshReopen, FreshGeneratedFinal, FreshReopen}
		if c.Reciprocal {
			wantPurposes = []FreshPurpose{FreshReopen, FreshReopen, FreshGeneratedRecord, FreshReopen, FreshReopen, FreshGeneratedFinal, FreshReopen}
		}
		execution := catalogExecution(name, "hermetic")
		var gotPurposes []FreshPurpose
		for _, child := range execution.ExpandedFreshBefore() {
			gotPurposes = append(gotPurposes, child.Purpose)
		}
		if got := executionBeforeSteps(name, "hermetic"); !reflect.DeepEqual(got, want) || len(got) != len(want) || !slices.Equal(gotPurposes, wantPurposes) {
			t.Fatalf("%s child order, role or purpose differs: got %+v, want %+v", name, got, want)
		}
		if _, known := HistoricalExecutionFor(name, "live"); known || executionPostExitRole(name) != want[len(want)-1].Role {
			t.Fatal("generated history admitted live dispatch or lost its final reopen role", name, executionPostExitRole(name))
		}
	}
}

// full_only: false
func TestExecutionFactsBindFreshChildrenToWriterPhases(t *testing.T) {
	for _, definition := range HistoricalDefinitions() {
		for _, mode := range definition.Modes {
			execution, known := HistoricalExecutionFor(definition.Name, mode)
			if !known {
				t.Fatal("execution facts unavailable", definition.Name, mode)
			}
			previousPosition := -1
			for _, child := range execution.FreshBefore {
				if child.Count < 1 || child.Purpose == "" || child.Role != child.Step.Role || child.WriterPosition < previousPosition || child.WriterPosition >= len(execution.Writer) || execution.Writer[child.WriterPosition].Step != child.Step {
					t.Fatal("fresh child is not bound to its ordered writer phase", definition.Name, mode, child)
				}
				previousPosition = child.WriterPosition
			}
		}
	}
	for _, input := range [][2]string{{"unknown", "live"}, {"accepted.source-mode0-late-result", "unknown"}} {
		if _, known := HistoricalExecutionFor(input[0], input[1]); known {
			t.Fatal("unknown child schedule admitted")
		}
	}
}

// full_only: false
func TestRetirementAcknowledgementChildrenAreRecordedBeforeReopen(t *testing.T) {
	want := expectedHermeticModeSteps([]Step{
		{Name: "setup", Role: "authority", Expected: "generated-fixture-and-exact-authority-ready"},
		{Name: "setup", Role: "authority", Expected: "generated-fixture-and-exact-authority-ready"},
		{Name: "transition", Role: "authority", Expected: "exact-retirement-acknowledgement-selected"},
		{Name: "reopen", Role: "authority", Expected: "success"},
	})
	name := "generated.retirement-acknowledgement-closes"
	if got := executionBeforeSteps(name, "hermetic"); !reflect.DeepEqual(got, want) || len(got) != len(want) {
		t.Fatalf("retirement acknowledgement child order or purpose differs: got %+v, want %+v", got, want)
	}
}

// full_only: false
func TestMeasurementExpectationsDescribeActualPhaseWork(t *testing.T) {
	for _, test := range []struct {
		name, mode, owner string
		position          int
		want              bool
	}{
		{"access.normal-kek-k2-zero-material", "hermetic", "writer", 2, false},
		{"access.normal-kek-k2-current-material", "hermetic", "writer", 2, true},
		{"access.recovery-kek-k2-zero-material", "hermetic", "writer", 2, true},
		{"access.reciprocal-authority-zero-material", "hermetic", "writer", 2, false},
		{"access.reciprocal-authority-zero-material", "hermetic", "writer", 4, true},
		{"access.reciprocal-authority-current-material", "hermetic", "writer", 2, true},
		{"access.normal-combined-k3-current-material", "hermetic", "writer", 4, false},
		{"access.normal-combined-k3-current-material", "hermetic", "writer", 5, false},
		{"access.normal-combined-k3-current-material", "hermetic", "writer", 6, false},
		{"access.normal-combined-k3-current-material", "live", "writer", 4, true},
		{"access.normal-combined-k3-current-material", "live", "writer", 5, true},
		{"access.normal-combined-k3-current-material", "live", "writer", 6, true},
		{"accepted.source-mode0-late-result", "hermetic", "writer", 2, false},
		{"accepted.source-mode2-late-result", "hermetic", "writer", 2, true},
		{"accepted.source-mode0-late-result", "hermetic", "writer", 7, false},
		{"evidence.missing-selected-child-prevents-open", "hermetic", "writer", 1, false},
		{"evidence.missing-selected-child-prevents-open", "live", "writer", 1, true},
		{"state.single-value-update-preserves-other-values", "hermetic", "writer", 3, false},
		{"state.single-value-update-preserves-other-values", "hermetic", "fresh_before", 0, true},
		{"state.single-value-update-preserves-other-values", "live", "fresh_after", 0, true},
		{combinedHistoryScenario, "hermetic", "writer", 10, true},
		{combinedHistoryScenario, "hermetic", "fresh_before", 0, true},
	} {
		got, valid := declaredMeasurement(test.name, test.mode, test.owner, test.position)
		if !valid || got != test.want {
			t.Fatalf("measurement expectation %s/%s/%s/%d = %t, %t", test.name, test.mode, test.owner, test.position, got, valid)
		}
	}
	if _, valid := declaredMeasurement("unknown", "hermetic", "writer", 0); valid {
		t.Fatal("unknown phase measurement contract admitted")
	}
	for _, name := range []string{
		"accepted.source-mode0-reciprocal-loss/source0_four_replacements_late_result",
		"accepted.source-mode1-reciprocal-loss/source1_four_replacements_late_result",
		"accepted.source-mode2-reciprocal-loss/source2_four_replacements_late_result",
	} {
		for _, recovery := range []string{"both", "enabled"} {
			t.Run(name+"/"+recovery+"/mixed_record", func(t *testing.T) {
				execution, known := ExecutionForRecovery(name, "hermetic", recovery)
				if !known {
					t.Fatal("current reciprocal execution unavailable")
				}
				matched := 0
				for _, child := range execution.ExpandedFreshBefore() {
					if child.StepIndex != 8 || child.Purpose != FreshGeneratedRecord {
						continue
					}
					matched++
					want := Step{Name: "transition", Role: "authority-decrypter-1", Expected: "late-result-recorded-and-close-frozen", RecoveryMode: "enabled"}
					if child.WriterPosition < 0 || child.WriterPosition >= len(execution.Writer) || child.Step != want || !child.MeasurementsExpected {
						t.Fatal("mixed record lost its exact measured child")
					}
					phase := execution.Writer[child.WriterPosition]
					expected, valid := execution.MeasurementFor("writer", child.WriterPosition, want)
					if phase.StepIndex != 8 || phase.Step != want || !phase.MeasurementsExpected || !valid || !expected {
						t.Fatal("record child discharged mixed writer preparation and cold reopen")
					}
				}
				if matched != 1 {
					t.Fatal("mixed record does not have exactly one declared child")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedHistoryPostExitRoleMatchesFinalReopen(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
	}{
		{"accepted.source-mode0-late-result", "authority-decrypter-0"},
		{"accepted.same-value-reader-union", "authority-decrypter-0"},
		{"accepted.source-mode2-reciprocal-loss", "authority-decrypter-2"},
	} {
		steps := executionWriterSteps(test.name, "hermetic")
		if len(steps) == 0 || steps[len(steps)-1].Name != "reopen" || steps[len(steps)-1].Role != test.want || executionPostExitRole(test.name) != test.want {
			t.Fatalf("fresh role %s = %q; final step: %+v", test.name, executionPostExitRole(test.name), steps)
		}
	}
}

// full_only: false
func TestExecutionFactsDoNotUseDescriptiveLabelsAsPolicy(t *testing.T) {
	for _, definition := range HistoricalDefinitions() {
		declared, known := lookupGroup(definition.Name)
		if !known {
			t.Fatal("scenario declaration unavailable", definition.Name)
		}
		for _, mode := range definition.Modes {
			execution, known := HistoricalExecutionFor(definition.Name, mode)
			if !known {
				t.Fatal("scenario execution facts unavailable", definition.Name, mode)
			}
			before := executionPolicy(execution)
			changedSteps := append([]Step(nil), definition.Steps...)
			for index := range changedSteps {
				changedSteps[index].Name = "changed-phase-name"
				changedSteps[index].Expected = "changed-description"
			}
			changed := resolveExecution(declared, changedSteps, definition.RecoveryModes, mode)
			if after := executionPolicy(changed); !reflect.DeepEqual(after, before) {
				t.Fatal("descriptive label changed execution policy", definition.Name, mode)
			}
		}
	}
}

// full_only: false
func TestExecutionFactsRejectIncompleteOrContradictoryDeclarations(t *testing.T) {
	definition, known := HistoricalDefinitionFor("accepted.source-mode0-late-result")
	if !known {
		t.Fatal("generated history definition unavailable")
	}
	execution, known := HistoricalExecutionFor(definition.Name, "hermetic")
	if !known || validateExecution(definition, execution) != nil {
		t.Fatal("valid generated history execution facts refused")
	}
	for _, test := range []struct {
		name   string
		change func(*Execution)
	}{
		{"missing_writer", func(e *Execution) { e.Writer = e.Writer[1:] }},
		{"duplicate_writer", func(e *Execution) { e.Writer = append(e.Writer, e.Writer[len(e.Writer)-1]) }},
		{"reordered_writer", func(e *Execution) { e.Writer[0], e.Writer[1] = e.Writer[1], e.Writer[0] }},
		{"missing_child", func(e *Execution) { e.FreshBefore = e.FreshBefore[1:] }},
		{"duplicate_child", func(e *Execution) { e.FreshBefore = append(e.FreshBefore, e.FreshBefore[0]) }},
		{"reordered_children", func(e *Execution) { e.FreshBefore[0], e.FreshBefore[1] = e.FreshBefore[1], e.FreshBefore[0] }},
		{"wrong_child_role", func(e *Execution) { e.FreshBefore[0].Role = "authority" }},
		{"wrong_child_purpose", func(e *Execution) { e.FreshBefore[0].Purpose = "unknown" }},
		{"missing_child_count", func(e *Execution) { e.FreshBefore[0].Count = 0 }},
		{"missing_after", func(e *Execution) { e.FreshAfter = nil }},
		{"wrong_after_role", func(e *Execution) { e.FreshAfter[0].Role = "authority" }},
		{"unknown_family", func(e *Execution) { e.Family = "unknown" }},
		{"missing_capability", func(e *Execution) { e.FixtureCapabilities = e.FixtureCapabilities[1:] }},
		{"unknown_capability", func(e *Execution) { e.FixtureCapabilities[0] = "unknown" }},
		{"duplicate_capability", func(e *Execution) { e.FixtureCapabilities = append(e.FixtureCapabilities, e.FixtureCapabilities[0]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneExecution(execution)
			test.change(&changed)
			if validateExecution(definition, changed) == nil {
				t.Fatal("invalid execution facts accepted")
			}
		})
	}
	if _, known := HistoricalExecutionFor("unknown", "hermetic"); known {
		t.Fatal("unknown scenario execution admitted")
	}
}

// Resource-role facts follow the complete-loss case inputs, independent of the
// catalog role builder. Disabled-mode filtering is checked separately.
func expectedConfigurationRecoveryRoles(condition string) []string {
	roles := []string{"authority", "recovery", "replacement-store", "normal-signer-0", "authority-decrypter-0", "recovery-signer-0", "recovery-decrypter-0"}
	switch condition {
	case "normal-signer-replaced", "normal-signer-by-recovery", "normal-combined-replaced", "normal-restored-by-recovery", "adequate-anchor-fallback", "wrong-anchor", "recovery-only-inadequate":
		roles = append(roles, "normal-signer-1")
	case "normal-combined-repeated", "generated-repeated-later":
		roles = append(roles, "normal-signer-1", "normal-signer-2")
	}
	switch condition {
	case "authority-kek-replaced", "authority-kek-by-recovery", "normal-combined-replaced", "normal-restored-by-recovery", "adequate-anchor-fallback":
		roles = append(roles, "authority-decrypter-1")
	case "normal-combined-repeated", "generated-repeated-later":
		roles = append(roles, "authority-decrypter-1", "authority-decrypter-2")
	}
	switch condition {
	case "recovery-signer-replaced", "recovery-signer-by-recovery", "recovery-combined-replaced", "recovery-combined-by-recovery":
		roles = append(roles, "recovery-signer-1")
	}
	switch condition {
	case "recovery-kek-replaced", "recovery-kek-by-recovery", "recovery-combined-replaced", "recovery-combined-by-recovery", "recovery-proof-recovery-only", "recovery-proof-both", "recovery-proof-normal-only", "recovery-proof-two-normal":
		roles = append(roles, "recovery-decrypter-1")
	}
	switch condition {
	case "reader-replacement":
		roles = append(roles, "reader-successor")
	case "required-public-denied":
		roles = append(roles, "denied-observer")
	case "required-authority-denied":
		roles = append(roles, "denied-reader")
	}
	return roles
}

// full_only: false
func TestCurrentGeneratedHistoryObservationOwners(t *testing.T) {
	for _, name := range GeneratedHistoryNames("both") {
		for _, recovery := range []string{"both", "disabled", "enabled"} {
			execution, known := ExecutionForRecovery(name, "hermetic", recovery)
			if !known {
				definition, _ := DefinitionFor(name)
				if recovery != "both" && !slices.Contains(definition.RecoveryModes, recovery) {
					continue
				}
				t.Fatal("current history execution unavailable", name, recovery)
			}
			history, _ := GeneratedHistory(name)
			for position, phase := range execution.Writer {
				if execution.Family == FamilyGeneratedHistory && phase.Step.Expected == "closed-work-preserves-current-state" {
					t.Run(fmt.Sprintf("%s/%s/closed_state/%d", name, recovery, position), func(t *testing.T) {
						if phase.MeasurementsExpected != history.Union {
							t.Fatal("final verification must measure reader-union operations, not cached-state assertions")
						}
						for _, child := range execution.ExpandedFreshAfter() {
							if !child.MeasurementsExpected || child.Purpose != FreshReopen {
								t.Fatal("post-exit reopen lost its required observation", child)
							}
						}
					})
				}
				delegated := execution.Family == FamilyCombinedHistory && phase.StepIndex == 7 ||
					execution.Family == FamilyGeneratedHistory && (!history.Reciprocal && (phase.StepIndex == 3 || phase.StepIndex == 6) || history.Reciprocal && phase.StepIndex == 15)
				if !delegated {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%d", name, recovery, position), func(t *testing.T) {
					if phase.MeasurementsExpected {
						t.Fatal("wholly delegated action still requires writer-local measurements")
					}
					matched := 0
					for _, child := range execution.ExpandedFreshBefore() {
						if child.WriterPosition != position {
							continue
						}
						matched++
						purpose := FreshGeneratedRecord
						if phase.StepIndex == 6 || history.Reciprocal && phase.StepIndex == 15 {
							purpose = FreshGeneratedFinal
						}
						if child.StepIndex != phase.StepIndex || child.Step != phase.Step || child.Role != phase.Step.Role || child.Purpose != purpose || !child.MeasurementsExpected {
							t.Fatal("delegated action lost its exact measured child", child)
						}
					}
					if matched != 1 {
						t.Fatal("delegated action does not require exactly one child", matched)
					}
				})
			}
		}
	}
}
