package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
)

const MaxCasePathBytes = 128

type SmokePolicy string

const (
	SmokeSeparatePoint       SmokePolicy = "separate-point"
	SmokeFirstSelectedPoint  SmokePolicy = "first-selected-point"
	SmokePublicConfiguration SmokePolicy = "public-configuration-first"
)

type Request struct {
	RecoveryMode string
	Include      []string
	Repetitions  int
	SmokePolicy  SmokePolicy
}

type caseIdentity struct {
	group, path string
	members     int
}

// lookupCase admits only finite, complete case paths. The logical path is
// retained in evidence; CaseDirectoryToken supplies its flat filesystem name.
func lookupCase(name string) (caseIdentity, bool) {
	if !validCasePath(name) {
		return caseIdentity{}, false
	}
	for _, row := range caseIdentities {
		if row.path == name {
			return row, true
		}
	}
	return caseIdentity{}, false
}

func validCasePath(name string) bool {
	if len(name) > MaxCasePathBytes {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) != 2 || !validCaseSegment(parts[1], '_') {
		return false
	}
	for _, segment := range strings.Split(parts[0], ".") {
		if !validCaseSegment(segment, '-') {
			return false
		}
	}
	return true
}

func validCaseSegment(segment string, separator byte) bool {
	if segment == "" || segment[0] == separator || segment[len(segment)-1] == separator {
		return false
	}
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != separator {
			return false
		}
	}
	return true
}

// CaseDirectoryToken binds one admitted logical case to one flat directory
// token. Callers add their sequence and worker-role prefix/suffix separately.
func CaseDirectoryToken(name string) (string, error) {
	if _, known := lookupCase(name); !known {
		return "", errors.New("unknown case identity")
	}
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:]), nil
}

func Name(name string) (string, bool) {
	row, known := lookupCase(name)
	return row.path, known
}

func Names() []string {
	names := make([]string, len(caseIdentities))
	for i, row := range caseIdentities {
		names[i] = row.path
	}
	return names
}

func Definitions() []Definition {
	definitions := make([]Definition, 0, len(caseIdentities))
	for _, row := range caseIdentities {
		definition, _ := DefinitionFor(row.path)
		definitions = append(definitions, definition)
	}
	return definitions
}

func DefinitionFor(name string) (Definition, bool) {
	row, known := lookupCase(name)
	if !known {
		return Definition{}, false
	}
	s, known := lookupGroup(row.group)
	if !known {
		return Definition{}, false
	}
	definition := define(s)
	definition.Name = row.path
	definition.Fixture = fixtureShape(s, row.members)
	definition.MinMembers, definition.MaxMembers = 0, 0
	// Current named executions require observations where the action runs.
	// Historical group declarations retain their original policy.
	if s.history != nil {
		execution := definition.Executions["hermetic"]
		for position, phase := range execution.Writer {
			delegated := execution.Family == FamilyCombinedHistory && phase.StepIndex == 7 ||
				execution.Family == FamilyGeneratedHistory && (!s.history.Reciprocal && (phase.StepIndex == 3 || phase.StepIndex == 6) || s.history.Reciprocal && phase.StepIndex == 15)
			if delegated {
				execution.Writer[position].MeasurementsExpected = false
			}
			if execution.Family == FamilyGeneratedHistory &&
				(s.history.Reciprocal && phase.StepIndex == 16 || !s.history.Reciprocal && phase.StepIndex == 7) {
				// Most final verification checks inspect cached selected state.
				// Reader union also consumes a value and cold-opens its receipt.
				execution.Writer[position].MeasurementsExpected = s.history.Union
			}
		}
		definition.Executions["hermetic"] = execution
	}
	if row.group == "publication.lost-process" {
		definition.Title = "Selected publication: reservation retired without send"
	}
	return definition, true
}

func ExecutionFor(name, mode string) (Execution, bool) {
	definition, known := DefinitionFor(name)
	if !known {
		return Execution{}, false
	}
	execution, known := definition.Executions[mode]
	if !known || validateExecution(definition, execution) != nil {
		return Execution{}, false
	}
	return cloneExecution(execution), true
}

// ExecutionForRecovery narrows only current execution facts. Full execution
// remains the default; retained historical execution uses its original reader.
func ExecutionForRecovery(name, mode, recovery string) (Execution, bool) {
	execution, known := ExecutionFor(name, mode)
	if !known {
		return Execution{}, false
	}
	if recovery == "" || recovery == "both" {
		return execution, true
	}
	definition, _ := DefinitionFor(name)
	if !slices.Contains(definition.RecoveryModes, recovery) || mode == "hermetic" && execution.Family == FamilyConfigurationRecovery && len(ConfigurationRecoveryCells(name, recovery)) == 0 {
		return Execution{}, false
	}
	selected := func(step Step) bool { return step.RecoveryMode == "" || step.RecoveryMode == recovery }
	positions := make(map[int]int, len(execution.Writer))
	writer := execution.Writer[:0]
	for position, phase := range execution.Writer {
		if selected(phase.Step) {
			positions[position] = len(writer)
			writer = append(writer, phase)
		}
	}
	execution.Writer = writer
	before := execution.FreshBefore[:0]
	for _, child := range execution.FreshBefore {
		if position, retained := positions[child.WriterPosition]; retained && selected(child.Step) {
			child.WriterPosition = position
			before = append(before, child)
		}
	}
	execution.FreshBefore = before
	execution.FreshAfter = slices.DeleteFunc(execution.FreshAfter, func(child FreshChild) bool { return !selected(child.Step) })
	execution.Process = slices.DeleteFunc(execution.Process, func(phase ProcessPhase) bool { return !selected(phase.Step) })
	return execution, true
}

func currentGroup(name string) (scenario, bool) {
	row, known := lookupCase(name)
	if !known {
		return scenario{}, false
	}
	return lookupGroup(row.group)
}

func Behavior(name string) (string, bool) {
	s, known := currentGroup(name)
	if !known {
		return "", false
	}
	return behavior(s), true
}

func HasFixtureCapability(name string, capability FixtureCapability) bool {
	definition, known := DefinitionFor(name)
	if !known || len(definition.Modes) == 0 {
		return false
	}
	execution, known := ExecutionFor(name, definition.Modes[0])
	return known && execution.HasFixtureCapability(capability)
}

func RolesForScenarios(names []string, mode string) []string {
	if len(names) == 0 || mode != "disabled" && mode != "enabled" && mode != "both" {
		return nil
	}
	var roles []string
	for _, name := range names {
		definition, known := DefinitionFor(name)
		if !known {
			return nil
		}
		required := definition.RolesForRecovery(mode)
		for _, role := range required {
			if !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
	}
	return roles
}

func FixtureShape(name string) (Shape, error) {
	row, known := lookupCase(name)
	if !known {
		return Shape{}, errors.New("unknown case identity")
	}
	s, known := lookupGroup(row.group)
	if !known {
		return Shape{}, errors.New("unknown case identity")
	}
	return fixtureShape(s, row.members), nil
}

func FixtureSizes(name string) ([]int, bool, error) {
	shape, err := FixtureShape(name)
	if err != nil {
		return nil, false, err
	}
	return sizesForShape(shape), shape.Fragmented, nil
}

func sizesForShape(shape Shape) []int {
	sizes := make([]int, shape.Members)
	for i := range sizes {
		sizes[i] = shape.SmallValueBytes
		if i >= shape.SmallValueCount {
			sizes[i] = *shape.LargeValueBytes
		}
	}
	return sizes
}

func ordinaryCase(group string) string {
	for _, row := range caseIdentities {
		if row.group == group && (group != pointScenario || row.members == 32) {
			return row.path
		}
	}
	return ""
}

func ordinaryCases(groups []string) []string {
	names := make([]string, len(groups))
	for i, group := range groups {
		names[i] = ordinaryCase(group)
	}
	return names
}

// OrdinaryNames preserves one case per existing scenario, including point32.
// Additional point sizes remain in the separate diagnostic selection.
func OrdinaryNames() []string { return ordinaryCases(historicalNames()) }

func GeneratedNames() []string              { return ordinaryCases(generatedGroupNames()) }
func GeneratedLifecycleLiveNames() []string { return ordinaryCases(generatedLifecycleLiveGroupNames()) }
func GeneratedLiveNames() []string          { return ordinaryCases(generatedLiveGroupNames()) }
func AuthorityOperatorLiveNames() []string  { return ordinaryCases(authorityOperatorLiveGroupNames()) }
func RegressionNames() []string             { return RegressionNamesForRecovery("both") }
func RegressionNamesForRecovery(mode string) []string {
	return ordinaryCases(historicalRegressionNamesForRecovery(mode))
}
func CurrentKeyReplacementNames(mode string) []string {
	return ordinaryCases(currentKeyReplacementGroupNames(mode))
}
func GeneratedHistoryNames(mode string) []string {
	return ordinaryCases(generatedHistoryGroupNames(mode))
}
func ConfigurationRecoveryNames() []string { return ordinaryCases(configurationRecoveryGroupNames()) }
func ConfigurationRecoveryGeneratedNames() []string {
	return ordinaryCases(configurationRecoveryGeneratedGroupNames())
}
func PublicationNames() []string     { return ordinaryCases(publicationGroupNames()) }
func LivePublicationNames() []string { return ordinaryCases(livePublicationGroupNames()) }

func AuthorityReplacement(name string) (AuthorityReplacementCase, bool) {
	row, known := lookupCase(name)
	if !known {
		return AuthorityReplacementCase{}, false
	}
	return authorityReplacementGroup(row.group)
}

func GeneratedHistory(name string) (GeneratedHistoryCase, bool) {
	row, known := lookupCase(name)
	if !known {
		return GeneratedHistoryCase{}, false
	}
	return generatedHistoryGroup(row.group)
}

func ConfigurationRecovery(name string) (ConfigurationRecoveryCase, bool) {
	row, known := lookupCase(name)
	if !known {
		return ConfigurationRecoveryCase{}, false
	}
	return HistoricalConfigurationRecovery(row.group)
}

func ConfigurationRecoveryCells(name, recovery string) []RecoveryProcessCell {
	row, known := lookupCase(name)
	if !known {
		return nil
	}
	if recovery != "both" && recovery != "disabled" && recovery != "enabled" {
		return nil
	}
	var selected []RecoveryProcessCell
	for _, cell := range HistoricalConfigurationRecoveryCells(row.group, "both") {
		if recovery == "both" || recovery == cell.Recovery {
			selected = append(selected, cell)
		}
	}
	return selected
}

func Publication(name string) (PublicationCase, bool) {
	row, known := lookupCase(name)
	if !known {
		return PublicationCase{}, false
	}
	return publicationGroup(row.group)
}

func LivePublication(name string) (LivePublicationCase, bool) {
	row, known := lookupCase(name)
	if !known {
		return LivePublicationCase{}, false
	}
	return HistoricalLivePublication(row.group)
}

func Resolve(request Request) (Schedule, error) {
	if request.RecoveryMode == "" {
		request.RecoveryMode = "both"
	}
	if request.RecoveryMode != "disabled" && request.RecoveryMode != "enabled" && request.RecoveryMode != "both" {
		return Schedule{}, errors.New("unknown recovery mode")
	}
	if request.Repetitions < 1 || request.Repetitions > 100 {
		return Schedule{}, errors.New("repetitions must be from 1 through 100")
	}
	allPublic := len(request.Include) != 0
	for _, name := range request.Include {
		if !HasFixtureCapability(name, FixturePublicConfiguration) {
			allPublic = false
		}
	}
	if request.SmokePolicy == "" {
		request.SmokePolicy = SmokeSeparatePoint
		if allPublic {
			request.SmokePolicy = SmokePublicConfiguration
		}
	}
	if request.SmokePolicy == SmokePublicConfiguration && !allPublic {
		return Schedule{}, errors.New("public smoke requires only public configuration cases")
	}
	if request.SmokePolicy != SmokeSeparatePoint && request.SmokePolicy != SmokeFirstSelectedPoint && request.SmokePolicy != SmokePublicConfiguration {
		return Schedule{}, errors.New("unknown smoke policy")
	}
	if len(request.Include) == 0 || len(request.Include) > len(caseIdentities) {
		return Schedule{}, errors.New("case selection must contain known unique cases")
	}
	var selected, notApplicable []string
	seen := make(map[string]bool, len(request.Include))
	for _, name := range request.Include {
		row, known := lookupCase(name)
		if !known || seen[name] {
			return Schedule{}, errors.New("case selection must contain known unique cases")
		}
		seen[name] = true
		if HasFixtureCapability(name, FixturePublicConfiguration) && allPublic && request.SmokePolicy != SmokePublicConfiguration {
			return Schedule{}, errors.New("public configuration cannot use injected smoke fixtures")
		}
		if request.SmokePolicy == SmokeFirstSelectedPoint && row.group != pointScenario ||
			request.SmokePolicy == SmokeSeparatePoint && row.group == pointScenario && row.members != 32 {
			return Schedule{}, errors.New("point diagnostic cases require first-selected-point smoke")
		}
		definition, _ := DefinitionFor(name)
		if len(definition.RolesForRecovery(request.RecoveryMode)) == 0 {
			notApplicable = append(notApplicable, name)
		} else {
			selected = append(selected, name)
		}
	}
	if len(selected) == 0 {
		return Schedule{}, errors.New("case selection has no cases for the recovery mode")
	}
	if request.SmokePolicy == SmokeFirstSelectedPoint && len(selected) > maxMembers {
		return Schedule{}, errors.New("point diagnostics require at most 64 cases")
	}
	full := true
	for _, required := range RegressionNamesForRecovery(request.RecoveryMode) {
		if !slices.Contains(selected, required) {
			full = false
		}
	}
	schedule := Schedule{RecoveryMode: request.RecoveryMode, Selected: selected, NotApplicable: notApplicable,
		Repetitions: request.Repetitions, FullCoverage: full, SmokePolicy: request.SmokePolicy}
	smoke := ordinaryCase(pointScenario)
	selectedSmoke := request.SmokePolicy == SmokeSeparatePoint && slices.Contains(selected, smoke)
	if request.SmokePolicy == SmokeSeparatePoint {
		entry := Entry{Scenario: smoke, Smoke: true}
		if selectedSmoke {
			entry.Repetition = 1
		}
		schedule.Entries = append(schedule.Entries, entry)
	}
	for repetition := 1; repetition <= request.Repetitions; repetition++ {
		for _, name := range selected {
			if selectedSmoke && repetition == 1 && name == smoke {
				continue
			}
			entry := Entry{Scenario: name, Sequence: len(schedule.Entries), Repetition: repetition}
			entry.Smoke = (request.SmokePolicy == SmokeFirstSelectedPoint || request.SmokePolicy == SmokePublicConfiguration) && len(schedule.Entries) == 0
			schedule.Entries = append(schedule.Entries, entry)
		}
	}
	return schedule, nil
}
