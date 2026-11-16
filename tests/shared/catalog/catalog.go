// Package catalog defines the scenarios shared by hermetic and live execution.
package catalog

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

const (
	minMembers              = 1
	maxMembers              = 64
	pointScenario           = "state.single-value-update-preserves-other-values"
	combinedHistoryScenario = "history.secret-lifecycle-and-recovery"
)

// HistoricalRequest reconstructs saved legacy evidence; it does not authorize
// a new execution of an old group identity.
type HistoricalRequest struct {
	RecoveryMode string
	Include      []string
	Members      []int
	Repetitions  int
}

type Entry struct {
	Scenario   string `json:"scenario"`
	Members    int    `json:"members,omitempty"`
	Sequence   int    `json:"sequence"`
	Repetition int    `json:"repetition"`
	Smoke      bool   `json:"smoke"`
}

type Schedule struct {
	RecoveryMode  string      `json:"recovery_mode"`
	Selected      []string    `json:"selected_scenarios"`
	NotApplicable []string    `json:"not_applicable,omitempty"`
	MemberCounts  []int       `json:"selected_member_counts,omitempty"`
	Repetitions   int         `json:"repetitions"`
	Entries       []Entry     `json:"entries"`
	FullCoverage  bool        `json:"full_coverage"`
	SmokePolicy   SmokePolicy `json:"smoke_policy,omitempty"`
}

type Shape struct {
	Members         int    `json:"members"`
	SmallValueCount int    `json:"small_value_count"`
	SmallValueBytes int    `json:"small_value_bytes"`
	LargeValueCount int    `json:"large_value_count"`
	LargeValueBytes *int   `json:"large_value_bytes"`
	RawValueBytes   int    `json:"raw_value_bytes"`
	Fragmented      bool   `json:"fragmented"`
	ValueSeed       string `json:"value_seed"`
}

type Definition struct {
	RecoveryModes        []string             `json:"recovery_modes"`
	Name                 string               `json:"scenario"`
	Title                string               `json:"title"`
	Description          string               `json:"description"`
	Modes                []string             `json:"modes"`
	Roles                []string             `json:"roles"`
	DistinctParticipants bool                 `json:"distinct_participants"`
	Providers            []string             `json:"providers"`
	Pairings             []string             `json:"pairings,omitempty"`
	Steps                []Step               `json:"steps"`
	Fixture              Shape                `json:"fixture"`
	RolesByRecovery      map[string][]string  `json:"roles_by_recovery"`
	Executions           map[string]Execution `json:"executions"`
	MinMembers           int                  `json:"min_members,omitempty"`
	MaxMembers           int                  `json:"max_members,omitempty"`
}

// RolesForRecovery resolves optional initialization qualification. All scenario
// steps remain required. Hermetic execution exercises both explicit modes.
func (d Definition) RolesForRecovery(mode string) []string {
	return append([]string(nil), d.RolesByRecovery[mode]...)
}

// RolesForScenarios returns the first-use ordered union of roles required by
// the selected scenarios. A nil result refuses an unknown scenario or recovery
// mode. Suite files use "both" so their declaration is independent of the
// workflow mode that later selects the suite.
func historicalRolesForScenarios(names []string, mode string) []string {
	if len(names) == 0 || mode != "disabled" && mode != "enabled" && mode != "both" {
		return nil
	}
	var roles []string
	for _, name := range names {
		definition, known := HistoricalDefinitionFor(name)
		if !known {
			return nil
		}
		for _, role := range definition.RolesForRecovery(mode) {
			if !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
	}
	return roles
}

type Step struct {
	RecoveryMode string `json:"recovery_mode,omitempty"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	Expected     string `json:"expected"`
}

type ScenarioFamily string

const (
	FamilyState                 ScenarioFamily = "state"
	FamilyFirstSelection        ScenarioFamily = "first-selection"
	FamilySuppliedLifecycle     ScenarioFamily = "supplied-lifecycle"
	FamilySuppliedSharing       ScenarioFamily = "supplied-sharing"
	FamilySuppliedAtomic        ScenarioFamily = "supplied-atomic"
	FamilyReaderReplacement     ScenarioFamily = "reader-replacement"
	FamilyAuthorityReplacement  ScenarioFamily = "authority-replacement"
	FamilyGeneratedHistory      ScenarioFamily = "generated-history"
	FamilyCombinedHistory       ScenarioFamily = "combined-history"
	FamilyGeneratedApply        ScenarioFamily = "generated-apply"
	FamilyGeneratedRetirement   ScenarioFamily = "generated-retirement"
	FamilyGeneratedCleanup      ScenarioFamily = "generated-cleanup"
	FamilyAuthorityOperator     ScenarioFamily = "authority-operator"
	FamilyPublicConfiguration   ScenarioFamily = "public-configuration"
	FamilyConfigurationRecovery ScenarioFamily = "configuration-recovery"
	FamilyPublication           ScenarioFamily = "publication"
)

type FixtureCapability string

const (
	FixtureState                 FixtureCapability = "state"
	FixtureSecretState           FixtureCapability = "secret-state"
	FixtureSecretConsumption     FixtureCapability = "secret-consumption"
	FixtureObserver              FixtureCapability = "observer"
	FixtureReadRefusal           FixtureCapability = "read-refusal"
	FixtureSecretRefusal         FixtureCapability = "secret-refusal"
	FixtureReaderSuccessor       FixtureCapability = "reader-successor"
	FixtureSyntheticAuthority    FixtureCapability = "synthetic-authority"
	FixtureGeneratedProcess      FixtureCapability = "generated-process"
	FixtureSelectedStateDamage   FixtureCapability = "selected-state-damage"
	FixturePublicConfiguration   FixtureCapability = "public-configuration"
	FixtureConfigurationRecovery FixtureCapability = "configuration-recovery"
	FixturePublication           FixtureCapability = "publication"
)

type FreshPurpose string

const (
	FreshReopen          FreshPurpose = "reopen"
	FreshGeneratedRecord FreshPurpose = "generated-record"
	FreshGeneratedFinal  FreshPurpose = "generated-final"
)

type WriterPhase struct {
	StepIndex            int  `json:"step_index"`
	Step                 Step `json:"step"`
	MeasurementsExpected bool `json:"measurements_expected"`
}

type FreshChild struct {
	Purpose              FreshPurpose `json:"purpose"`
	Role                 string       `json:"role"`
	Count                int          `json:"count"`
	WriterPosition       int          `json:"writer_position,omitempty"`
	StepIndex            int          `json:"step_index"`
	Step                 Step         `json:"step"`
	MeasurementsExpected bool         `json:"measurements_expected"`
}

type ProcessPhase struct {
	StepIndex int  `json:"step_index"`
	Step      Step `json:"step"`
}

type Execution struct {
	Process             []ProcessPhase      `json:"process,omitempty"`
	Mode                string              `json:"mode"`
	Family              ScenarioFamily      `json:"family"`
	FixtureCapabilities []FixtureCapability `json:"fixture_capabilities"`
	Writer              []WriterPhase       `json:"writer"`
	FreshBefore         []FreshChild        `json:"fresh_before"`
	FreshAfter          []FreshChild        `json:"fresh_after"`
}

func (execution Execution) WriterSteps() []Step {
	steps := make([]Step, 0, len(execution.Writer))
	for _, phase := range execution.Writer {
		steps = append(steps, phase.Step)
	}
	return steps
}

func (execution Execution) HasFixtureCapability(capability FixtureCapability) bool {
	return slices.Contains(execution.FixtureCapabilities, capability)
}

func (execution Execution) ExpandedFreshBefore() []FreshChild {
	var children []FreshChild
	for _, child := range execution.FreshBefore {
		for range child.Count {
			copy := child
			copy.Count = 1
			children = append(children, copy)
		}
	}
	return children
}

func (execution Execution) ExpandedFreshAfter() []FreshChild {
	var children []FreshChild
	for _, child := range execution.FreshAfter {
		for range child.Count {
			copy := child
			copy.Count = 1
			children = append(children, copy)
		}
	}
	return children
}

func (execution Execution) MeasurementFor(role string, position int, step Step) (bool, bool) {
	if position < 0 {
		return false, false
	}
	switch role {
	case "writer":
		if position >= len(execution.Writer) || execution.Writer[position].Step != step {
			return false, false
		}
		return execution.Writer[position].MeasurementsExpected, true
	case "fresh_before":
		if position != 0 {
			return false, false
		}
		for _, child := range execution.FreshBefore {
			if child.Step == step {
				return child.MeasurementsExpected, true
			}
		}
	case "fresh_after":
		if position != 0 {
			return false, false
		}
		for _, child := range execution.FreshAfter {
			if child.Step == step {
				return child.MeasurementsExpected, true
			}
		}
	}
	return false, false
}

type declaredChild struct {
	step    int
	purpose FreshPurpose
	role    string
	count   int
}

type measurementOverride struct {
	step                     int
	hermetic, live           bool
	applyHermetic, applyLive bool
}

type executionDeclaration struct {
	family             ScenarioFamily
	capabilities       []FixtureCapability
	children           []declaredChild
	postExit           declaredChild
	measurements       []measurementOverride
	freshExpected      string
	liveFinalAfterOnly bool
}

func baseExecution(family ScenarioFamily, finalStep int, capabilities ...FixtureCapability) executionDeclaration {
	reopen := declaredChild{step: finalStep, purpose: FreshReopen, role: "authority", count: 1}
	return executionDeclaration{
		family: family, capabilities: append([]FixtureCapability{FixtureState}, capabilities...),
		children: []declaredChild{reopen}, postExit: reopen, freshExpected: "success",
		measurements: []measurementOverride{{step: finalStep, hermetic: false, live: false, applyHermetic: true, applyLive: true}},
	}
}

func withMeasurements(declaration executionDeclaration, overrides ...measurementOverride) executionDeclaration {
	declaration.measurements = append(declaration.measurements, overrides...)
	return declaration
}

func withLiveFinalAfterOnly(declaration executionDeclaration) executionDeclaration {
	declaration.liveFinalAfterOnly = true
	return declaration
}

func withFreshOutcome(declaration executionDeclaration, role, expected string) executionDeclaration {
	declaration.postExit.role, declaration.freshExpected = role, expected
	for index := range declaration.children {
		if declaration.children[index].step == declaration.postExit.step && declaration.children[index].purpose == FreshReopen {
			declaration.children[index].role = role
		}
	}
	return declaration
}

func withFreshReopens(declaration executionDeclaration, children ...declaredChild) executionDeclaration {
	declaration.children = append(declaration.children, children...)
	for _, child := range children {
		declaration.measurements = append(declaration.measurements, measurementOverride{step: child.step, hermetic: false, live: false, applyHermetic: true, applyLive: true})
	}
	return declaration
}

type scenario struct {
	history       *GeneratedHistoryCase
	authority     *AuthorityReplacementCase
	name          string
	behavior      string
	roles         []string
	distinct      bool
	title         string
	description   string
	transition    string
	members       int
	smallBytes    int
	largeCount    int
	fragmented    bool
	memberCounts  bool
	explicitShape bool
	pairings      []string
	execution     executionDeclaration
}

// Ordinary scenarios use a 32-member fixture. Lifecycle shapes are explicit.
var baseScenarios = append(append([]scenario{

	{
		name:        "state.identical-input-keeps-current-state",
		execution:   baseExecution(FamilyState, 3),
		title:       "Identical input keeps current state",
		description: "Compare the complete unchanged input, authenticate current output configuration without writes or signing, then verify the current state.",
		transition:  "unchanged-without-mutation",
	},
	{
		name: pointScenario, memberCounts: true,
		execution:   baseExecution(FamilyState, 3),
		title:       "One value changes and all other values remain",
		description: "Update one value, preserve the complete remaining state, then open that state with the authority participant in a fresh process.",
		transition:  "single-value-update-selected",
	},
	{
		name: "state.transient-before-send-rerun", members: 1, smallBytes: 1, explicitShape: true,
		execution:   baseExecution(FamilyState, 3),
		title:       "A transport failure permits one fresh same-domain apply",
		description: "Save the desired plain input and independent domain basis before a controlled before-send failure; a fresh invocation then verifies or selects the same goal.",
		transition:  "same-domain-transport-recovery",
	},
	{
		name:        "state.same-page-updates-preserve-other-pages",
		execution:   baseExecution(FamilyState, 3),
		title:       "Same-page updates preserve other pages",
		description: "Update two values on one member page and verify the complete state and unchanged pages.",
		transition:  "same-page-updates-selected",
	},
	{
		name:        "state.cross-page-updates-preserve-other-values",
		execution:   baseExecution(FamilyState, 3),
		title:       "Cross-page updates preserve other values",
		description: "Update values on two member pages and verify the complete remaining state.",
		transition:  "cross-page-updates-selected",
	},
	{
		name:        "selection.concurrent-writers-select-one-complete-state",
		execution:   baseExecution(FamilyState, 3),
		title:       "Concurrent writers select one complete state",
		description: "Prepare competing updates from one predecessor and verify the single winning state and the losing selection evidence.",
		transition:  "one-winner-with-exact-loser-evidence",
	},
	{
		name:        "storage.equal-immutable-objects-allow-selection",
		execution:   withMeasurements(baseExecution(FamilyState, 5), measurementOverride{step: 2, hermetic: false, live: true, applyHermetic: true, applyLive: true}),
		title:       "Equal immutable objects allow selection",
		description: "Reuse pre-existing equal immutable bytes after conditional rejection and select the complete successor state.",
		transition:  "equal-objects-read-back-and-state-selected",
	},
	{
		name:        "storage.conflicting-immutable-object-refuses-selection",
		execution:   withMeasurements(baseExecution(FamilyState, 5), measurementOverride{step: 2, hermetic: false, live: true, applyHermetic: true, applyLive: true}),
		title:       "Conflicting immutable bytes prevent selection",
		description: "Reject a conflicting immutable object before signing or selection and preserve the original state.",
		transition:  "integrity-failure-immutable-conflict-without-selection",
	},
	{
		name:        "state.historical-bytes-get-new-identities",
		execution:   withFreshReopens(baseExecution(FamilyState, 13), declaredChild{step: 4, purpose: FreshReopen, role: "authority", count: 1}, declaredChild{step: 7, purpose: FreshReopen, role: "authority", count: 1}, declaredChild{step: 10, purpose: FreshReopen, role: "authority", count: 1}),
		title:       "Historical bytes receive new identities",
		description: "Verify three generations, fresh identities when prior bytes return, and refusal of the retained stale candidate.",
	},
	{
		name:        "evidence.missing-selected-child-prevents-open",
		execution:   withFreshOutcome(withLiveFinalAfterOnly(withMeasurements(baseExecution(FamilyState, 3, FixtureSelectedStateDamage), measurementOverride{step: 1, hermetic: false, live: true, applyHermetic: true, applyLive: true})), "authority", "unavailable"),
		title:       "A missing selected child prevents open",
		description: "Remove a selected child and require the exact missing-object evidence outcome when the complete state opens.",
	},
	{
		name:        "evidence.corrupt-selected-child-prevents-open",
		execution:   withFreshOutcome(withLiveFinalAfterOnly(withMeasurements(baseExecution(FamilyState, 3, FixtureSelectedStateDamage), measurementOverride{step: 1, hermetic: false, live: true, applyHermetic: true, applyLive: true})), "authority", "integrity-failure"),
		title:       "A corrupt selected child prevents open",
		description: "Replace a selected child with corrupt bytes and require integrity failure when the complete state opens.",
	},
	{
		name:        "selection.prepared-candidate-keeps-current-state",
		execution:   baseExecution(FamilyState, 3),
		title:       "Preparation preserves the selected state",
		description: "Prepare an update without selecting its HEAD and verify the original complete state in a fresh process.",
		transition:  "candidate-prepared-without-head-selection",
	},
	{
		name:        "selection.selected-candidate-survives-fresh-open",
		execution:   baseExecution(FamilyState, 3),
		title:       "The selected candidate survives a fresh open",
		description: "Select an update and verify the complete successor state in a fresh process.",
		transition:  "successor-selected-with-authenticated-closure",
	},
	{
		name:        "storage.lost-create-reply-recovers-from-readback",
		execution:   baseExecution(FamilyState, 3),
		title:       "Readback resolves a lost create reply",
		description: "Discard one completed child-create reply, recover from immutable readback, and verify the selected successor state.",
		transition:  "lost-create-reply-recovered-and-state-selected",
	},
	{
		name:        "selection.lost-head-reply-recovers-from-observation",
		execution:   baseExecution(FamilyState, 3),
		title:       "Observation resolves a lost HEAD reply",
		description: "Discard one completed HEAD-selection reply and verify the complete successor through authenticated observation.",
		transition:  "lost-head-reply-recovered-with-authenticated-closure",
	},
	{
		name:        "capacity.compact-state-preserves-complete-update",
		execution:   baseExecution(FamilyState, 3),
		title:       "A compact state supports a complete update",
		description: "Update a compact 64-member state with small and large values and verify its complete contents.",
		transition:  "compact-state-update-selected",
		members:     64, smallBytes: 4096, largeCount: 6,
	},
	{
		name:        "capacity.fragmented-state-preserves-complete-update",
		execution:   baseExecution(FamilyState, 3),
		title:       "A fragmented state supports a complete update",
		description: "Update a fragmented 64-member state with small and large values and verify its complete contents.",
		transition:  "fragmented-state-update-selected",
		members:     64, smallBytes: 4096, largeCount: 6, fragmented: true,
	},
	{
		name:        "capacity.maximum-member-count-preserves-complete-update",
		execution:   baseExecution(FamilyState, 3),
		title:       "The maximum member count supports a complete update",
		description: "Update a 512-member state with small and large values and verify its complete contents.",
		transition:  "maximum-member-state-update-selected",
		members:     512, smallBytes: 4096, largeCount: 51,
	},
	{
		name:        "capacity.maximum-size-state-refuses-growth-and-allows-update",
		execution:   baseExecution(FamilyState, 3),
		title:       "The maximum-size state refuses growth and permits replacement",
		description: "Refuse an oversized successor before writes, then update every value within the eight-MiB limit and verify the complete state.",
		transition:  "growth-refused-and-same-size-update-selected",
		members:     512, smallBytes: 16384,
	},
	{
		name:          "lifecycle.empty-state-preserves-domain-and-readd",
		execution:     withFreshReopens(baseExecution(FamilyState, 10), declaredChild{step: 4, purpose: FreshReopen, role: "authority", count: 1}, declaredChild{step: 7, purpose: FreshReopen, role: "authority", count: 1}),
		title:         "Empty state preserves the domain and permits fresh membership",
		description:   "Verify an empty no-op, additions, removal of the last members, and selected re-add with new incarnations; prune obsolete objects and reopen each selection.",
		explicitShape: true,
	},
	{
		name:        "lifecycle.mixed-membership-preserves-retained-records",
		execution:   baseExecution(FamilyState, 3),
		title:       "Mixed membership preserves retained records",
		description: "Retain, update, remove and add members together, reuse successor-free slots, preserve untouched pages, and reopen after obsolete-object pruning.",
		transition:  "mixed-membership-selected-with-exact-identities",
		members:     32, smallBytes: 1, explicitShape: true,
	},
	{
		name:        "capacity.maximum-disjoint-replacement-reuses-successor-slots",
		execution:   baseExecution(FamilyState, 3),
		title:       "Maximum disjoint replacement reuses successor slots",
		description: "Replace 512 members with 512 disjoint names of 256 bytes, with 128 maximum-size values and 384 empty values on each side; reopen after obsolete-object pruning.",
		transition:  "maximum-disjoint-replacement-selected-with-exact-identities",
		members:     512, largeCount: 128, explicitShape: true,
	},
	{name: "genesis.empty-domain-reopens", execution: baseExecution(FamilyFirstSelection, 3), title: "Empty domain reopens", description: "Initialize an empty domain and authenticate it in a fresh process.", transition: "empty-domain-publicly-authenticated", explicitShape: true},
	{name: "secret.empty-domain-first-selection-survives-restart", execution: withFreshOutcome(baseExecution(FamilyFirstSelection, 3, FixtureSecretState, FixtureSecretConsumption), "reader", "success"), title: "First secret in an empty domain survives restart", description: "Select a shared secret directly from empty genesis and deliver through an independent Recipient after writer exit.", transition: "first-secret-selected-with-exact-membership", roles: []string{"reader"}, explicitShape: true},
	{name: "secret.authority-only-survives-restart", execution: baseExecution(FamilyFirstSelection, 3, FixtureSecretState, FixtureSecretConsumption), title: "Authority secret survives restart", description: "Seal and select the first authority-only secret, then deliver through a fresh Authority Recipient.", transition: "first-secret-selected-with-exact-membership", members: 1, smallBytes: 1, explicitShape: true},
	{name: "secret.shared-reader-survives-restart", execution: withFreshOutcome(baseExecution(FamilyFirstSelection, 3, FixtureSecretState, FixtureSecretConsumption), "reader", "success"), title: "Shared secret survives restart", description: "Select a shared first secret and deliver through the Recipient without Authority private credentials.", transition: "first-secret-selected-with-exact-membership", roles: []string{"reader"}, members: 1, smallBytes: 1, explicitShape: true},
	{name: "secret.provider-refuses-reader", execution: withFreshOutcome(baseExecution(FamilyFirstSelection, 3, FixtureSecretState, FixtureSecretConsumption, FixtureSecretRefusal), "denied-reader", "secret-access-refused"), title: "Private key access is refused", description: "Authenticate public state, then require the actual private KMS route to refuse the separately authenticated Recipient.", transition: "first-secret-selected-with-exact-membership", roles: []string{"denied-reader"}, members: 1, smallBytes: 1, explicitShape: true},
	{name: "secret.complete-supplied-lifecycle-preserves-material", execution: baseExecution(FamilySuppliedLifecycle, 8, FixtureSecretState, FixtureSecretConsumption), title: "Complete supplied lifecycle preserves exact material", description: "Apply mixed additions, randomized equal seals, updates, removal and historical-source re-addition; preserve unchanged neighbors and consume the complete re-added state after restart.", members: 17, smallBytes: 1, explicitShape: true},
	{name: "secret.complete-supplied-sharing-preserves-current-access", execution: baseExecution(FamilySuppliedSharing, 7, FixtureSecretState, FixtureSecretConsumption), title: "Supplied sharing preserves current access", description: "Grant an unchanged mixed set through public recipient keys, consume through the independent Recipient route, exclude that Recipient with fresh secret protection, and verify current denial without claiming historical revocation.", roles: []string{"reader"}, members: 1, smallBytes: 1, explicitShape: true},
	{name: "secret.competing-supplied-candidates-preserve-atomic-outcomes", execution: baseExecution(FamilySuppliedAtomic, 6, FixtureSecretState, FixtureSecretConsumption), title: "Competing supplied candidates preserve atomic outcomes", description: "Prepare an abandoned mixed candidate, select a competitor through real conditional HEAD update, refuse the stale candidate, then resolve an injected lost reply from complete selected evidence and reopen in a fresh process.", members: 2, smallBytes: 1, explicitShape: true},
	{name: "access.reader-replacement-preserves-current-material", execution: withFreshOutcome(baseExecution(FamilyReaderReplacement, 5, FixtureSecretState, FixtureSecretConsumption, FixtureReaderSuccessor), "reader-successor", "success"), title: "Recipient key replacement preserves current material", description: "Replace one Recipient binding through Authority access, refuse an absent entry's sealed input with the prior binding set, and consume the unchanged selected material through the successor Recipient key after restart.", roles: []string{"reader-successor"}, members: 1, smallBytes: 1, explicitShape: true},
	{name: "access.observer-sees-selected-state", behavior: pointScenario, execution: withFreshOutcome(baseExecution(FamilyState, 3, FixtureObserver), "observer", "success"),
		title: "Observer credentials open the selected state", description: "Route a fresh read through the observer and verify complete state visibility; this does not test Product sharing or recipient authorization.", transition: "single-value-update-selected"},
	{name: "access.distinct-observer-sees-selected-state", behavior: pointScenario, distinct: true, execution: withFreshOutcome(baseExecution(FamilyState, 3, FixtureObserver), "observer", "success"),
		title: "Distinct participants open the selected state", description: "Require distinct participants and verify complete state visibility; live GCP also checks distinct credential identities.", transition: "single-value-update-selected"},
	{name: "access.provider-refuses-observer", behavior: pointScenario, distinct: true, execution: withFreshOutcome(baseExecution(FamilyState, 3, FixtureObserver, FixtureReadRefusal), "denied-observer", "access-refused"),
		title: "The provider refuses the observer read", description: "Require exact provider access refusal through the observer route after the authority selects a complete state.", transition: "single-value-update-selected"},
}, authorityReplacementScenarios()...), append(append(generatedHistoryScenarios(), generatedScenarios()...), authorityOperatorScenarios()...)...)

var scenarios = append(append(append(baseScenarios, configurationRecoveryScenarios()...), publicationScenarios()...), publicConfigurationScenarios()...)

func historicalNames() []string {
	names := make([]string, len(scenarios))
	for i, scenario := range scenarios {
		names[i] = scenario.name
	}
	return names
}

// HistoricalDefinitions returns legacy metadata for evidence interpretation.
func HistoricalDefinitions() []Definition {
	definitions := make([]Definition, len(scenarios))
	for i, scenario := range scenarios {
		definitions[i] = define(scenario)
	}
	return definitions
}

func HistoricalDefinitionFor(name string) (Definition, bool) {
	scenario, known := lookupGroup(name)
	if !known {
		return Definition{}, false
	}
	return define(scenario), true
}

func define(scenario scenario) Definition {
	definition := Definition{
		Name: scenario.name, Title: scenario.title, Description: scenario.description,
		Modes: []string{"hermetic", "live"}, Roles: []string{"authority", "recovery"}, Providers: []string{"memory", "gcp", "aws"}, DistinctParticipants: scenario.distinct,
		Steps: scenarioSteps(scenario), Fixture: fixtureShape(scenario, 0),
		RecoveryModes: []string{"disabled", "enabled"},
		Pairings:      append([]string(nil), scenario.pairings...),
	}
	if scenario.authority != nil && scenario.authority.requiresRecovery() || scenario.history != nil && scenario.history.Reciprocal {
		definition.RecoveryModes = []string{"enabled"}
	}
	if row, ok := HistoricalConfigurationRecovery(scenario.name); ok {
		if row.EnabledOnly {
			definition.RecoveryModes = []string{"enabled"}
		}
		if row.AWSOnly {
			definition.Providers = []string{"memory", "aws"}
		}
	}
	if hermeticOnlyFamily(scenario.execution.family) {
		definition.Modes, definition.Providers = []string{"hermetic"}, []string{"memory"}
	}
	if slices.Contains(generatedLiveGroupNames(), scenario.name) {
		definition.Modes, definition.Providers = []string{"hermetic", "live"}, []string{"memory", "gcp", "aws"}
	}
	if scenario.execution.family == FamilyPublication {
		definition.Modes, definition.Providers = []string{"hermetic"}, []string{"memory"}
	}
	if row, live := HistoricalLivePublication(scenario.name); live {
		definition.Modes, definition.Providers = []string{"live"}, []string{"aws", "gcp"}
		switch row.Scope {
		case "aws-secrets-manager":
			definition.Providers = []string{"aws"}
		case "gcp-secret-manager":
			definition.Providers = []string{"gcp"}
		}
	}
	if row, public := HistoricalPublicConfiguration(scenario.name); public {
		definition.Modes, definition.Providers = []string{"live"}, []string{"aws", "gcp"}
		definition.Roles = slices.Clone(row.Roles)
		if row.EnabledOnly {
			definition.RecoveryModes = []string{"enabled"}
		}
		if row.DisabledOnly {
			definition.RecoveryModes = []string{"disabled"}
		}
	}
	if scenario.execution.family == FamilyAuthorityOperator {
		definition.Modes, definition.Providers = []string{"live"}, []string{"gcp", "aws"}
		definition.Roles = slices.Clone(scenario.roles)
		switch scenario.name {
		case "operator.replace-authority-then-abandon-through-cli":
			definition.RecoveryModes = []string{"enabled"}
		case "operator.disabled-recovery-refuses-authority-replacement-through-cli":
			definition.RecoveryModes = []string{"disabled"}
		}
	}
	for _, role := range scenario.roles {
		if role != "authority" && role != "recovery" && !slices.Contains(definition.Roles, role) {
			definition.Roles = append(definition.Roles, role)
		}
	}
	if scenario.memberCounts {
		definition.MinMembers, definition.MaxMembers = minMembers, maxMembers
	}
	if slices.Contains(scenario.execution.capabilities, FixtureObserver) {
		definition.Roles = append(definition.Roles, scenario.execution.postExit.role)
		definition.Providers = []string{"memory", "gcp"}
	}
	definition.Executions = make(map[string]Execution, len(definition.Modes))
	for _, mode := range definition.Modes {
		definition.Executions[mode] = resolveExecution(scenario, definition.Steps, definition.RecoveryModes, mode)
	}
	definition.RolesByRecovery = make(map[string][]string, 3)
	for _, mode := range []string{"disabled", "enabled", "both"} {
		if mode == "both" || slices.Contains(definition.RecoveryModes, mode) {
			definition.RolesByRecovery[mode] = declaredRolesForRecovery(scenario, definition.Roles, mode)
		}
	}
	return definition
}

func declaredRolesForRecovery(scenario scenario, declared []string, mode string) []string {
	roles := make([]string, 0, len(declared))
	for _, role := range declared {
		if scenario.execution.family == FamilyPublicConfiguration && role == "successor" && mode == "disabled" {
			continue
		}
		if scenario.execution.family == FamilyConfigurationRecovery && mode == "disabled" && strings.HasPrefix(role, "recovery-") {
			continue
		}
		if scenario.execution.family == FamilyCombinedHistory {
			if mode == "disabled" && (role == "recovery-signer-0" || role == "recovery-decrypter-0" || role == "recovery-decrypter-1") || mode == "enabled" && role == "authority-decrypter-0" {
				continue
			}
		}
		if scenario.authority != nil && scenario.authority.Operation == 1 && scenario.authority.Mask&2 != 0 && scenario.authority.Approval == 1 {
			if mode == "disabled" && role == "recovery-decrypter-0" || mode == "enabled" && role == "authority-decrypter-0" {
				continue
			}
		}
		if role != "recovery" || mode != "disabled" {
			roles = append(roles, role)
		}
	}
	return roles
}

func hermeticOnlyFamily(family ScenarioFamily) bool {
	return family == FamilyGeneratedHistory || family == FamilyCombinedHistory || family == FamilyGeneratedApply || family == FamilyGeneratedRetirement || family == FamilyGeneratedCleanup
}

func resolveExecution(scenario scenario, steps []Step, recoveryModes []string, mode string) Execution {
	execution := Execution{
		Mode:                mode,
		Family:              scenario.execution.family,
		FixtureCapabilities: append([]FixtureCapability(nil), scenario.execution.capabilities...),
	}
	if scenario.execution.family == FamilyConfigurationRecovery {
		if row, ok := HistoricalConfigurationRecovery(scenario.name); mode == "live" && ok {
			if row.Generated {
				execution.FixtureCapabilities = append(execution.FixtureCapabilities, FixtureGeneratedProcess)
			}
			if configurationRecoveryHistory(row.Condition) {
				execution.FixtureCapabilities = append(execution.FixtureCapabilities, FixtureSyntheticAuthority)
			}
			if row.Condition == "reader-replacement" {
				execution.FixtureCapabilities = append(execution.FixtureCapabilities, FixtureReaderSuccessor)
			}
		}
		for index, step := range steps {
			if mode == "live" && (index == 1 || index == 2) {
				if index == 2 {
					step.Name = "transition"
				}
				execution.Writer = append(execution.Writer, WriterPhase{StepIndex: index, Step: step, MeasurementsExpected: true})
			} else if mode != "live" || index >= 3 {
				execution.Process = append(execution.Process, ProcessPhase{StepIndex: index, Step: step})
			}
		}
		if row, ok := HistoricalConfigurationRecovery(scenario.name); mode == "live" && ok && (row.Condition == "generated-retiring" || row.Condition == "generated-uncertain") {
			execution.FreshBefore = []FreshChild{{Purpose: FreshGeneratedRecord, Role: "authority", Count: 2, WriterPosition: 1, StepIndex: 2, Step: execution.Writer[1].Step, MeasurementsExpected: true}}
		}
		return execution
	}
	if mode == "live" && slices.Contains(generatedLiveGroupNames(), scenario.name) {
		execution.FixtureCapabilities = slices.DeleteFunc(execution.FixtureCapabilities, func(capability FixtureCapability) bool {
			return capability == FixtureSyntheticAuthority
		})
	}
	appendWriter := func(stepIndex int, recovery string) {
		step := steps[stepIndex]
		step.RecoveryMode = recovery
		expected := true
		for _, override := range scenario.execution.measurements {
			if override.step != stepIndex {
				continue
			}
			if mode == "hermetic" && override.applyHermetic {
				expected = override.hermetic
			}
			if mode == "live" && override.applyLive {
				expected = override.live
			}
		}
		execution.Writer = append(execution.Writer, WriterPhase{StepIndex: stepIndex, Step: step, MeasurementsExpected: expected})
	}
	switch mode {
	case "hermetic":
		for _, recovery := range recoveryModes {
			for stepIndex := range steps {
				appendWriter(stepIndex, recovery)
			}
		}
	case "live":
		limit := len(steps)
		if scenario.execution.liveFinalAfterOnly {
			limit--
		}
		for stepIndex := 0; stepIndex < limit; stepIndex++ {
			appendWriter(stepIndex, "")
		}
	}
	for writerPosition, phase := range execution.Writer {
		for _, declared := range scenario.execution.children {
			if declared.step == phase.StepIndex {
				execution.FreshBefore = append(execution.FreshBefore, FreshChild{
					Purpose: declared.purpose, Role: declared.role, Count: declared.count,
					WriterPosition: writerPosition, StepIndex: phase.StepIndex, Step: phase.Step,
					MeasurementsExpected: true,
				})
			}
		}
	}
	if mode == "live" && scenario.name == "generated.mixed-apply-selects-complete-set" {
		execution.FreshBefore = slices.Insert(execution.FreshBefore, 0, FreshChild{
			Purpose: FreshGeneratedRecord, Role: "authority", Count: 1,
			WriterPosition: 1, StepIndex: 1, Step: execution.Writer[1].Step,
			MeasurementsExpected: true,
		})
	}
	declared := scenario.execution.postExit
	if declared.count > 0 && declared.step >= 0 && declared.step < len(steps) {
		appendAfter := func(recovery string) {
			step := steps[declared.step]
			step.Role, step.RecoveryMode = declared.role, recovery
			execution.FreshAfter = append(execution.FreshAfter, FreshChild{
				Purpose: declared.purpose, Role: declared.role, Count: declared.count,
				WriterPosition: -1, StepIndex: declared.step, Step: step, MeasurementsExpected: true,
			})
		}
		switch mode {
		case "hermetic":
			for _, recovery := range recoveryModes {
				appendAfter(recovery)
			}
		case "live":
			appendAfter("")
		}
	}
	return execution
}

func HistoricalExecutionFor(name, mode string) (Execution, bool) {
	definition, known := HistoricalDefinitionFor(name)
	if !known {
		return Execution{}, false
	}
	execution, known := definition.Executions[mode]
	if !known || validateExecution(definition, execution) != nil {
		return Execution{}, false
	}
	return cloneExecution(execution), true
}

func historicalHasFixtureCapability(name string, capability FixtureCapability) bool {
	definition, known := HistoricalDefinitionFor(name)
	if !known || len(definition.Modes) == 0 {
		return false
	}
	execution, known := HistoricalExecutionFor(name, definition.Modes[0])
	return known && execution.HasFixtureCapability(capability)
}

func cloneExecution(execution Execution) Execution {
	execution.FixtureCapabilities = append([]FixtureCapability(nil), execution.FixtureCapabilities...)
	execution.Process = append([]ProcessPhase(nil), execution.Process...)
	execution.Writer = append([]WriterPhase(nil), execution.Writer...)
	execution.FreshBefore = append([]FreshChild(nil), execution.FreshBefore...)
	execution.FreshAfter = append([]FreshChild(nil), execution.FreshAfter...)
	return execution
}

func validateExecution(definition Definition, execution Execution) error {
	canonical, known := definition.Executions[execution.Mode]
	if !known || !validScenarioFamily(execution.Family) || len(execution.FixtureCapabilities) == 0 || execution.Family != FamilyConfigurationRecovery && (len(execution.Writer) == 0 || len(execution.FreshAfter) == 0) {
		return errors.New("execution facts incomplete")
	}
	seenCapabilities := make(map[FixtureCapability]bool, len(execution.FixtureCapabilities))
	for _, capability := range execution.FixtureCapabilities {
		if !validFixtureCapability(capability) || seenCapabilities[capability] {
			return errors.New("execution fixture capabilities invalid")
		}
		seenCapabilities[capability] = true
	}
	if !seenCapabilities[FixtureState] {
		return errors.New("execution state fixture capability missing")
	}
	if execution.Family == FamilyConfigurationRecovery {
		if len(execution.FreshAfter) != 0 || execution.Mode == "hermetic" && len(execution.FreshBefore) != 0 || execution.Mode == "hermetic" && (len(execution.Writer) != 0 || len(execution.Process) != 5) || execution.Mode == "live" && (len(execution.Writer) != 2 || len(execution.Process) != 2) || !reflect.DeepEqual(canonical, execution) {
			return errors.New("reconstruction process declaration differs")
		}
		return nil
	}
	if len(execution.Process) != 0 {
		return errors.New("ordinary execution carries reconstruction processes")
	}
	for position, phase := range execution.Writer {
		if phase.StepIndex < 0 || phase.StepIndex >= len(definition.Steps) || phase.Step.Role != definition.Steps[phase.StepIndex].Role || phase.Step.Name != definition.Steps[phase.StepIndex].Name || phase.Step.Expected != definition.Steps[phase.StepIndex].Expected {
			return errors.New("writer execution facts invalid")
		}
		if position > 0 {
			previous := execution.Writer[position-1]
			if phase.Step.RecoveryMode == previous.Step.RecoveryMode && phase.StepIndex != previous.StepIndex+1 {
				return errors.New("writer execution facts reordered")
			}
		}
	}
	type childIdentity struct {
		writerPosition int
		stepIndex      int
		purpose        FreshPurpose
	}
	seenChildren := make(map[childIdentity]bool, len(execution.FreshBefore))
	for index, child := range execution.FreshBefore {
		identity := childIdentity{writerPosition: child.WriterPosition, stepIndex: child.StepIndex, purpose: child.Purpose}
		if child.Count < 1 || child.Role == "" || child.Role != child.Step.Role || !validFreshPurpose(child.Purpose) || child.WriterPosition < 0 || child.WriterPosition >= len(execution.Writer) || child.StepIndex != execution.Writer[child.WriterPosition].StepIndex || child.Step != execution.Writer[child.WriterPosition].Step || index > 0 && child.WriterPosition < execution.FreshBefore[index-1].WriterPosition || seenChildren[identity] {
			return errors.New("fresh-before execution facts invalid")
		}
		seenChildren[identity] = true
	}
	for index, child := range execution.FreshAfter {
		if child.Count != 1 || child.Role == "" || child.Role != child.Step.Role || child.Purpose != FreshReopen || child.WriterPosition != -1 || child.StepIndex != len(definition.Steps)-1 || child.Step.Name != definition.Steps[child.StepIndex].Name || index > 0 && child.Step.RecoveryMode == execution.FreshAfter[index-1].Step.RecoveryMode {
			return errors.New("fresh-after execution facts invalid")
		}
	}
	if !reflect.DeepEqual(canonical, execution) {
		return errors.New("execution facts differ from the catalog declaration")
	}
	return nil
}

func validScenarioFamily(family ScenarioFamily) bool {
	return slices.Contains([]ScenarioFamily{
		FamilyState, FamilyFirstSelection, FamilySuppliedLifecycle, FamilySuppliedSharing,
		FamilySuppliedAtomic, FamilyReaderReplacement, FamilyAuthorityReplacement,
		FamilyGeneratedHistory, FamilyCombinedHistory, FamilyGeneratedApply,
		FamilyGeneratedRetirement, FamilyGeneratedCleanup,
		FamilyAuthorityOperator, FamilyConfigurationRecovery, FamilyPublication, FamilyPublicConfiguration,
	}, family)
}

func validFixtureCapability(capability FixtureCapability) bool {
	return slices.Contains([]FixtureCapability{
		FixtureState, FixtureSecretState, FixtureSecretConsumption, FixtureObserver,
		FixtureReadRefusal, FixtureSecretRefusal, FixtureReaderSuccessor, FixtureSyntheticAuthority,
		FixtureGeneratedProcess, FixtureSelectedStateDamage,
		FixtureConfigurationRecovery, FixturePublication, FixturePublicConfiguration,
	}, capability)
}

func validFreshPurpose(purpose FreshPurpose) bool {
	return purpose == FreshReopen || purpose == FreshGeneratedRecord || purpose == FreshGeneratedFinal
}

func HasStepOutcome(outcome string) bool {
	for _, scenario := range scenarios {
		for _, step := range scenarioSteps(scenario) {
			if step.Expected == outcome {
				return true
			}
		}
	}
	return false
}

func scenarioSteps(scenario scenario) []Step {
	if scenario.execution.family == FamilyPublicConfiguration {
		return publicConfigurationSteps()
	}
	if scenario.execution.family == FamilyPublication {
		return publicationSteps(scenario.transition)
	}
	if scenario.execution.family == FamilyConfigurationRecovery {
		return configurationRecoverySteps()
	}
	if scenario.execution.family == FamilyCombinedHistory {
		return []Step{
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
	}
	if scenario.history != nil {
		return generatedHistorySteps(*scenario.history)
	}
	if scenario.execution.family == FamilyGeneratedApply || scenario.execution.family == FamilyGeneratedRetirement || scenario.execution.family == FamilyGeneratedCleanup {
		return []Step{
			{Name: "setup", Role: "authority", Expected: "generated-fixture-and-exact-authority-ready"},
			{Name: "transition", Role: "authority", Expected: scenario.transition},
			{Name: "verification", Role: "authority", Expected: "generated-state-obligations-and-effects-exact"},
			{Name: "reopen", Role: "authority", Expected: "success"},
		}
	}
	if scenario.execution.family == FamilyAuthorityOperator {
		verification := "later-list-and-original-receipt-after-ordinary-progress"
		if scenario.name == authorityOperatorLiveGroupNames()[2] {
			verification = "disabled-recovery-preserves-selected-work"
		}
		return []Step{
			{Name: "setup", Role: "authority", Expected: "selected-generated-work-ready"},
			{Name: "transition", Role: "authority", Expected: scenario.transition},
			{Name: "verification", Role: "authority", Expected: verification},
			{Name: "reopen", Role: "recipient-consumer", Expected: "success"},
		}
	}
	steps := []Step{{Name: "setup", Role: "authority", Expected: "complete-fixture-ready"}}
	if scenario.authority != nil {
		if scenario.authority.Material {
			steps = append(steps, Step{Name: "transition", Role: "authority", Expected: "current-authority-secret-ready"})
		}
		for range scenario.authority.Stages() {
			steps = append(steps, Step{Name: "transition", Role: "replacement-store", Expected: "exact-current-authority-successor-selected"}, Step{Name: "verification", Role: "replacement-store", Expected: "current-material-and-receipts-preserved"})
			if scenario.authority.PrivateWitnesses() {
				steps = append(steps, Step{Name: "verification", Role: "authority-decrypter-1", Expected: "current-private-probe-success"}, Step{Name: "verification", Role: "authority-decrypter-1", Expected: "wrong-binding-provider-refusal"}, Step{Name: "verification", Role: "recovery-decrypter-0", Expected: "authenticated-provider-denial"})
			}
		}
		steps = append(steps, Step{Name: "reopen", Role: scenario.execution.postExit.role, Expected: scenario.execution.freshExpected})
		return steps
	}
	switch behavior(scenario) {
	case "access.reader-replacement-preserves-current-material":
		return append(steps, Step{Name: "transition", Role: "authority", Expected: "shared-current-material-and-discardable-source-ready"}, Step{Name: "transition", Role: "authority", Expected: "reader-successor-selected-with-exact-material"}, Step{Name: "verification", Role: "reader-successor", Expected: "successor-reader-consumes-current-material"}, Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"}, Step{Name: "reopen", Role: "reader-successor", Expected: "success"})
	case "secret.complete-supplied-sharing-preserves-current-access":
		return append(steps,
			Step{Name: "transition", Role: "authority", Expected: "authority-only-mixed-set-selected"},
			Step{Name: "transition", Role: "authority", Expected: "unchanged-value-grant-preserves-existing-protection"},
			Step{Name: "verification", Role: "reader", Expected: "granted-reader-consumes-through-own-private-route"},
			Step{Name: "transition", Role: "authority", Expected: "exclusion-refreshes-secret-and-preserves-recovery"},
			Step{Name: "verification", Role: "reader", Expected: "excluded-current-access-refused-and-captured-value-remains-readable"},
			Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"},
			Step{Name: "reopen", Role: "authority", Expected: "success"},
		)
	case "secret.competing-supplied-candidates-preserve-atomic-outcomes":
		for _, result := range []string{"mixed-secret-predecessor-selected", "mixed-candidate-prepared-without-selection", "competing-mixed-selection-refuses-original-stale-condition", "injected-lost-head-reply-resolves-from-complete-mixed-state"} {
			steps = append(steps, Step{Name: "transition", Role: "authority", Expected: result})
		}
		return append(steps,
			Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"},
			Step{Name: "reopen", Role: "authority", Expected: "success"},
		)
	case "secret.complete-supplied-lifecycle-preserves-material":
		for _, result := range []string{"mixed-secret-addition-selected", "randomized-equal-seals-unchanged-without-canonical-effects", "mixed-supplied-change-preserves-retained-material", "historical-source-update-selects-fresh-material", "last-supplied-removal-selects-empty-state", "historical-source-readd-selects-new-incarnation"} {
			steps = append(steps, Step{Name: "transition", Role: "authority", Expected: result})
		}
		return append(steps,
			Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"},
			Step{Name: "reopen", Role: "authority", Expected: "success"},
		)
	case "evidence.missing-selected-child-prevents-open":
		return append(steps,
			Step{Name: "setup", Role: "authority", Expected: "selected-child-removed"},
			Step{Name: "verification", Role: "authority", Expected: "evidence-unavailable-missing-selected-object"},
			Step{Name: "reopen", Role: "authority", Expected: "unavailable"},
		)
	case "evidence.corrupt-selected-child-prevents-open":
		return append(steps,
			Step{Name: "setup", Role: "authority", Expected: "selected-child-corrupted"},
			Step{Name: "verification", Role: "authority", Expected: "integrity-failure"},
			Step{Name: "reopen", Role: "authority", Expected: "integrity-failure"},
		)
	case "storage.equal-immutable-objects-allow-selection", "storage.conflicting-immutable-object-refuses-selection":
		steps = append(steps,
			Step{Name: "transition", Role: "authority", Expected: "successor-compared-and-admitted"},
			Step{Name: "setup", Role: "authority", Expected: "immutable-objects-seeded"},
		)
	case "lifecycle.empty-state-preserves-domain-and-readd":
		steps = append(steps, Step{Name: "transition", Role: "authority", Expected: "empty-input-unchanged-without-effects"})
		for _, result := range []string{"members-added-with-fresh-identities", "empty-state-selected-with-recipient-support", "members-readded-with-new-incarnations"} {
			steps = append(steps,
				Step{Name: "transition", Role: "authority", Expected: result},
				Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"},
				Step{Name: "reopen", Role: "authority", Expected: "success"},
			)
		}
		return steps
	case "state.historical-bytes-get-new-identities":
		steps = append(steps, Step{Name: "transition", Role: "authority", Expected: "stale-candidate-prepared"})
		for range 3 {
			steps = append(steps,
				Step{Name: "transition", Role: "authority", Expected: "generation-selected-with-fresh-identities"},
				Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"},
				Step{Name: "reopen", Role: "authority", Expected: "success"},
			)
		}
		return append(steps,
			Step{Name: "transition", Role: "authority", Expected: "contention-stale-precondition-without-rebase"},
			Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"},
			Step{Name: "reopen", Role: "authority", Expected: "success"},
		)
	}
	reader := scenario.execution.postExit.role
	expected := scenario.execution.freshExpected
	return append(steps,
		Step{Name: "transition", Role: "authority", Expected: scenario.transition},
		Step{Name: "verification", Role: "authority", Expected: "complete-state-matches"},
		Step{Name: "reopen", Role: reader, Expected: expected},
	)
}

// HistoricalName recognizes only a legacy group identity.
func HistoricalName(name string) (string, bool) {
	s, ok := lookupGroup(name)
	return s.name, ok
}

// Behavior selects the Go action implementation shared by named variants.
func historicalBehavior(name string) (string, bool) {
	s, ok := lookupGroup(name)
	return behavior(s), ok
}
func behavior(s scenario) string {
	if s.behavior != "" {
		return s.behavior
	}
	return s.name
}

func generatedGroupNames() []string {
	var names []string
	for _, s := range scenarios {
		if s.execution.family == FamilyGeneratedApply || s.execution.family == FamilyGeneratedRetirement || s.execution.family == FamilyGeneratedCleanup {
			names = append(names, s.name)
		}
	}
	return names
}

// GeneratedLiveNames lists scenarios whose conditions can be produced by the
// installed Cloudflare artifact and exact AWS/GCP resources.
func generatedLifecycleLiveGroupNames() []string {
	return []string{
		"generated.mixed-apply-selects-complete-set",
		"generated.retirement-acknowledgement-closes",
		"generated.auto-retirement-acknowledgement-closes",
	}
}

func generatedLiveGroupNames() []string {
	return append(generatedLifecycleLiveGroupNames(), configurationRecoveryGeneratedGroupNames()...)
}

func authorityOperatorLiveGroupNames() []string {
	return []string{"operator.abandon-selected-work-through-cli", "operator.replace-authority-then-abandon-through-cli",
		"operator.disabled-recovery-refuses-authority-replacement-through-cli"}
}

func authorityOperatorScenarios() []scenario {
	base := baseExecution(FamilyAuthorityOperator, 3, FixturePublicConfiguration)
	base.children = nil
	base.liveFinalAfterOnly = true
	base.postExit.role = "recipient-consumer"
	roles := []string{"authority", "reader", "cleanup", "recipient-consumer"}
	return []scenario{
		{name: authorityOperatorLiveGroupNames()[0], title: "Authority reviews and abandons selected work", description: "Fresh native processes list selected work, deliver an exact plan, refuse its stale application, deliver a new plan and apply it once. Later ordinary progress preserves list discovery and the original receipt; an independent Recipient consumes preserved values after writer exit.", transition: "stale-plan-refused-fresh-plan-selected-history-discovered", members: 1, smallBytes: 1, explicitShape: true, roles: roles,
			pairings: []string{"live/gcp/recovery-disabled", "live/gcp/recovery-enabled", "live/aws/recovery-disabled", "live/aws/recovery-enabled"}, execution: base},
		{name: authorityOperatorLiveGroupNames()[1], title: "Recovery replaces Authority signing before abandonment", description: "A native keys replacement uses surviving Recovery and successor signing, delivers a separate source pair, and preserves the original source. Native abandonment then refuses a stale plan, applies a new plan once, and discovers retained history after ordinary progress; independent Recipient consumption remains available.", transition: "recovery-signing-replacement-then-reviewed-abandonment", members: 1, smallBytes: 1, explicitShape: true, roles: append(slices.Clone(roles), "successor"),
			pairings: []string{"live/gcp/recovery-enabled", "live/aws/recovery-enabled"}, execution: base},
		{name: authorityOperatorLiveGroupNames()[2], title: "Disabled Recovery refuses Authority replacement", description: "A native keys replacement refuses disabled Recovery before provider work or output delivery. The selected work, complete receipt windows and independent private consumption remain available.", transition: "disabled-recovery-replacement-refused-without-private-work", members: 1, smallBytes: 1, explicitShape: true, roles: roles,
			pairings: []string{"live/gcp/recovery-disabled", "live/aws/recovery-disabled"}, execution: base},
	}
}

// RegressionNames covers both providers; observer witnesses support only GCP and memory.
func historicalRegressionNames() []string { return historicalRegressionNamesForRecovery("both") }

func historicalRegressionNamesForRecovery(mode string) []string {
	names := []string{}
	for _, s := range scenarios {
		definition := define(s)
		if slices.Contains(definition.Modes, "live") && slices.Contains(definition.Modes, "hermetic") && !slices.Contains(s.execution.capabilities, FixtureObserver) &&
			!slices.Contains(generatedLiveGroupNames(), s.name) && !slices.Contains(authorityOperatorLiveGroupNames(), s.name) && s.execution.family != FamilyPublication && len(definition.RolesForRecovery(mode)) != 0 {
			names = append(names, s.name)
		}
	}
	return names
}

func generatedScenarios() []scenario {
	hermeticPairings := []string{
		"hermetic/memory/recovery-disabled", "hermetic/memory/recovery-enabled",
	}
	rows := []struct {
		name, title, description, transition string
		family                               ScenarioFamily
		synthetic                            bool
		setupRecords, transitionRecords      int
	}{
		{"generated.mixed-apply-selects-complete-set", "Mixed generated apply selects one complete set", "Record both original generated results, reject incomplete or invalid original ownership, then select and verify the complete mixed supplied/generated set.", "complete-mixed-generated-set-selected-once", FamilyGeneratedApply, false, 0, 0},
		{"generated.retirement-acknowledgement-closes", "Exact retirement acknowledgement closes its slot", "The admitted local Cloudflare process deletes the authenticated old target once; acknowledgement closes only the fixed class and cold inspection retains its ceiling.", "exact-retirement-acknowledgement-selected", FamilyGeneratedRetirement, true, 2, 1},
		{"generated.auto-retirement-acknowledgement-closes", "Automatic retirement acknowledgement closes its slot", "The complete successor is selected with automatic retirement before the admitted local Cloudflare process deletes the authenticated old target once; acknowledgement closes only the fixed class.", "exact-auto-retirement-acknowledgement-selected", FamilyGeneratedRetirement, true, 2, 1},
		{"generated.active-retirement-residue", "Active retirement ambiguity retains exact residue", "The admitted local Cloudflare process returns malformed delete evidence; one fresh K2 transition records the ambiguity and the exact possible-live Hazard.", "active-retirement-residue-selected", FamilyGeneratedRetirement, true, 2, 0},
		{"generated.parked-retirement-residue", "Parked retirement ambiguity retains exact residue", "The admitted local Cloudflare process returns rejected delete evidence; parking retains the Duty before a separate fresh retirement-to-residue transition releases the slot into the exact Hazard.", "parked-retirement-residue-selected", FamilyGeneratedRetirement, true, 2, 0},
		{"generated.conflicting-retirement-stays-open", "Conflicting delete identity keeps retirement open", "The admitted local Cloudflare process returns a different token identity; restart retains the exact Duty and evidence and refuses residue closure.", "conflicting-retirement-duty-preserved", FamilyGeneratedRetirement, true, 2, 0},
		{"generated.cleanup-source0-closes", "Native source-0 cleanup closes exact owners", "A failed two-create aggregate selects its unselected Duty and owned-unusable Hazard before two admitted Cloudflare deletes close and release the exact source-0 owners.", "exact-source0-cleanup-selected-and-released", FamilyGeneratedCleanup, false, 0, 2},
		{"generated.cleanup-source2-closes", "Native source-2 cleanup preserves its canonical", "A failed two-create aggregate selects its cleanup owners and retained canonical source, replaces current authority access, then admitted Cloudflare deletes close and release only the exact owners.", "exact-source2-cleanup-selected-and-released", FamilyGeneratedCleanup, false, 0, 2},
		{"generated.cleanup-repeated-ambiguity-closes", "Native cleanup ambiguity permits fresh exact work", "Each exact cleanup owner records two native ambiguous delete invocations without receipts or restored sends, then a fresh admitted acknowledgement closes and releases it.", "repeated-cleanup-ambiguity-selected-and-released", FamilyGeneratedCleanup, false, 0, 2},
		{"generated.cleanup-detached-hazard-closes", "Native detached Hazard cleanup closes", "A signed fixture contains one detached Hazard backed by kind-13 create evidence, with no live original Attempt or invented Duty; one admitted Cloudflare delete then closes and releases it.", "detached-hazard-cleanup-selected-and-released", FamilyGeneratedCleanup, false, 0, 1},
		{"generated.cleanup-deleting-hazard-closes", "Native deleting Hazard cleanup closes", "An ambiguous retirement becomes its exact possible-live Hazard before a fresh admitted Cloudflare cleanup acknowledgement closes it, releases the observed cleanup inbox and retains the unobserved original inbox as possible garbage.", "deleting-hazard-cleanup-selected-and-released", FamilyGeneratedCleanup, false, 2, 1},
	}
	all := make([]scenario, 0, len(rows))
	for _, row := range rows {
		capabilities := []FixtureCapability{FixtureGeneratedProcess}
		if row.synthetic {
			capabilities = append(capabilities, FixtureSyntheticAuthority)
		}
		execution := baseExecution(row.family, 3, capabilities...)
		if row.setupRecords != 0 {
			execution.children = append(execution.children, declaredChild{step: 0, purpose: FreshGeneratedRecord, role: "authority", count: row.setupRecords})
		}
		if row.transitionRecords != 0 {
			execution.children = append(execution.children, declaredChild{step: 1, purpose: FreshGeneratedRecord, role: "authority", count: row.transitionRecords})
		}
		pairings := append([]string(nil), hermeticPairings...)
		if slices.Contains(generatedLiveGroupNames(), row.name) {
			pairings = append(pairings, "live/gcp/recovery-disabled", "live/gcp/recovery-enabled", "live/aws/recovery-disabled", "live/aws/recovery-enabled")
		}
		all = append(all, scenario{name: row.name, title: row.title, description: row.description, transition: row.transition, explicitShape: true, pairings: pairings, execution: execution})
	}
	return all
}

// HistoricalResolve reconstructs the exact legacy schedule for evidence checks.
// A reconstructed schedule supplies no execution or cleanup authority.
func HistoricalResolve(request HistoricalRequest) (Schedule, error) {
	if request.RecoveryMode == "" {
		request.RecoveryMode = "both"
	}
	if request.RecoveryMode != "disabled" && request.RecoveryMode != "enabled" && request.RecoveryMode != "both" {
		return Schedule{}, errors.New("unknown recovery mode")
	}
	if request.Repetitions < 1 || request.Repetitions > 100 {
		return Schedule{}, errors.New("repetitions must be from 1 through 100")
	}
	selected, notApplicable, err := selectHistoricalNames(request.Include, request.RecoveryMode)
	if err != nil {
		return Schedule{}, err
	}
	if len(selected) == 0 {
		return Schedule{}, errors.New("scenario selection has no cases for the recovery mode")
	}
	if request.Members != nil {
		memberScenario, _ := lookupGroup(selected[0])
		if len(request.Members) == 0 || len(selected) != 1 || !memberScenario.memberCounts || request.Repetitions != 1 {
			return Schedule{}, errors.New("member sweep requires one point selection and one repetition")
		}
		if len(request.Members) > maxMembers {
			return Schedule{}, errors.New("member sweep requires unique counts from 1 through 64")
		}
		seen := make(map[int]bool, len(request.Members))
		for _, count := range request.Members {
			if count < minMembers || count > maxMembers || seen[count] {
				return Schedule{}, errors.New("member sweep requires unique counts from 1 through 64")
			}
			seen[count] = true
		}
	}
	schedule := Schedule{
		RecoveryMode:  request.RecoveryMode,
		NotApplicable: notApplicable,
		Selected:      selected, MemberCounts: append([]int(nil), request.Members...),
		Repetitions: request.Repetitions, FullCoverage: historicalRegressionSelectedForRecovery(selected, request.RecoveryMode),
	}
	if request.Members != nil {
		for i, count := range request.Members {
			entry := Entry{Scenario: selected[0], Members: count, Sequence: i, Repetition: 1}
			if i == 0 {
				entry.Smoke, entry.Repetition = true, 0
			}
			schedule.Entries = append(schedule.Entries, entry)
		}
		return schedule, nil
	}
	schedule.Entries = append(schedule.Entries, Entry{Scenario: pointScenario, Smoke: true})
	for repetition := 1; repetition <= request.Repetitions; repetition++ {
		for _, name := range selected {
			schedule.Entries = append(schedule.Entries, Entry{Scenario: name, Sequence: len(schedule.Entries), Repetition: repetition})
		}
	}
	return schedule, nil
}

func selectHistoricalNames(include []string, recovery string) (selected, notApplicable []string, err error) {
	if len(include) == 0 {
		return nil, nil, errors.New("scenario selection must not be empty")
	}
	if err := validateHistoricalNames(include); err != nil {
		return nil, nil, err
	}
	for _, name := range include {
		definition, _ := HistoricalDefinitionFor(name)
		if len(definition.RolesForRecovery(recovery)) == 0 {
			notApplicable = append(notApplicable, name)
		} else {
			selected = append(selected, name)
		}
	}
	return selected, notApplicable, nil
}

func validateHistoricalNames(names []string) error {
	if len(names) > len(scenarios) {
		return errors.New("scenario names must be known and unique")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		canonical, known := HistoricalName(name)
		if !known || seen[canonical] {
			return errors.New("scenario names must be known and unique")
		}
		seen[canonical] = true
	}
	return nil
}

func HistoricalFixtureShape(name string, members int) (Shape, error) {
	scenario, known := lookupGroup(name)
	if !known {
		return Shape{}, errors.New("unknown scenario")
	}
	if members < 0 || members > maxMembers || members != 0 && !scenario.memberCounts {
		return Shape{}, errors.New("member count requires a point scenario with 1 through 64 members")
	}
	return fixtureShape(scenario, members), nil
}

// HistoricalFixtureSizes and HistoricalFixtureShape use the same placement of
// large members after all small members.
func HistoricalFixtureSizes(name string, members int) ([]int, bool, error) {
	shape, err := HistoricalFixtureShape(name, members)
	if err != nil {
		return nil, false, err
	}
	return sizesForShape(shape), shape.Fragmented, nil
}

func lookupGroup(name string) (scenario, bool) {
	for _, scenario := range scenarios {
		if scenario.name == name {
			return scenario, true
		}
	}
	return scenario{}, false
}

func fixtureShape(scenario scenario, members int) Shape {
	count, smallBytes := scenario.members, scenario.smallBytes
	if !scenario.explicitShape && count == 0 {
		count = 32
	}
	if !scenario.explicitShape && smallBytes == 0 {
		smallBytes = 1
	}
	if members != 0 {
		count = members
	}
	shape := Shape{
		Members: count, SmallValueCount: count - scenario.largeCount, SmallValueBytes: smallBytes,
		LargeValueCount: scenario.largeCount, Fragmented: scenario.fragmented,
		ValueSeed: "member_index_modulo_256",
	}
	shape.RawValueBytes = shape.SmallValueCount * smallBytes
	if shape.LargeValueCount > 0 {
		largeBytes := 65536
		shape.LargeValueBytes = &largeBytes
		shape.RawValueBytes += shape.LargeValueCount * largeBytes
	}
	return shape
}

func historicalRegressionSelectedForRecovery(selected []string, mode string) bool {
	for _, required := range historicalRegressionNamesForRecovery(mode) {
		if !slices.Contains(selected, required) {
			return false
		}
	}
	return true
}

// AuthorityReplacementCase is an exact shared action. A reciprocal entry
// restores each pair, then repeats both KEK replacements using current keys.
type AuthorityReplacementCase struct {
	Operation, Mask, Approval uint8
	Material, Reciprocal      bool
}

func (c AuthorityReplacementCase) requiresRecovery() bool {
	return c.Reciprocal || c.Operation != 1 || c.Approval == 2
}

func (c AuthorityReplacementCase) PrivateWitnesses() bool {
	return !c.Reciprocal && c.Operation == 1 && c.Mask == 3 && c.Approval == 2 && c.Material
}

func (c AuthorityReplacementCase) Stages() []AuthorityReplacementCase {
	if !c.Reciprocal {
		return []AuthorityReplacementCase{c}
	}
	return []AuthorityReplacementCase{
		{Operation: 1, Mask: 3, Approval: 2, Material: c.Material},
		{Operation: 3, Mask: 12, Approval: 1, Material: c.Material},
		{Operation: 1, Mask: 2, Approval: 2, Material: c.Material},
		{Operation: 3, Mask: 8, Approval: 1, Material: c.Material},
	}
}

func authorityReplacementGroup(name string) (AuthorityReplacementCase, bool) {
	s, ok := lookupGroup(name)
	if !ok || s.authority == nil {
		return AuthorityReplacementCase{}, false
	}
	return *s.authority, true
}

// CurrentKeyReplacementNames lists replacement cases supported by the mode.
func currentKeyReplacementGroupNames(mode string) []string {
	var names []string
	for _, s := range scenarios {
		if (s.execution.family == FamilyReaderReplacement || s.execution.family == FamilyAuthorityReplacement) && len(define(s).RolesForRecovery(mode)) != 0 {
			names = append(names, s.name)
		}
	}
	return names
}

func authorityReplacementScenarios() []scenario {
	var all []scenario
	add := func(name string, c AuthorityReplacementCase) {
		roles := []string{"replacement-store"}
		role := func(name string) {
			if !slices.Contains(roles, name) {
				roles = append(roles, name)
			}
		}
		if c.Reciprocal {
			for _, name := range []string{"normal-signer-1", "recovery-signer-0", "recovery-signer-1", "authority-decrypter-1", "authority-decrypter-2", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2"} {
				role(name)
			}
		} else {
			if c.Approval == 1 {
				role("normal-signer-0")
			} else {
				role("recovery-signer-0")
			}
			if c.Mask&1 != 0 {
				role("normal-signer-1")
			}
			if c.Mask&4 != 0 {
				role("recovery-signer-1")
			}
			if c.Mask&(2|8) != 0 {
				if c.Mask&2 != 0 {
					role("recovery-decrypter-0")
					if !c.requiresRecovery() {
						role("authority-decrypter-0")
					}
				} else {
					role("authority-decrypter-0")
				}
				if c.Mask&2 != 0 {
					role("authority-decrypter-1")
				} else {
					role("recovery-decrypter-1")
				}
			}
			if c.Mask&2 != 0 {
				role("authority-decrypter-1")
			} else {
				role("authority-decrypter-0")
			}
		}
		freshRole := "authority-decrypter-0"
		if c.Reciprocal {
			freshRole = "authority-decrypter-2"
		} else if c.Mask&2 != 0 {
			freshRole = "authority-decrypter-1"
		}
		capabilities := []FixtureCapability{FixtureSyntheticAuthority}
		if c.Material {
			capabilities = append(capabilities, FixtureSecretState, FixtureSecretConsumption)
		}
		stages := c.Stages()
		finalStep := 1 + len(stages)*2
		if c.Material {
			finalStep++
		}
		if c.PrivateWitnesses() {
			finalStep += len(stages) * 3
		}
		execution := withFreshOutcome(baseExecution(FamilyAuthorityReplacement, finalStep, capabilities...), freshRole, "success")
		position := 1
		if c.Material {
			position++
		}
		for stage := range stages {
			measurement := c.Material || !c.Reciprocal && c.Operation != 1 || c.Reciprocal && stage > 0
			execution = withMeasurements(execution, measurementOverride{step: position + 1, hermetic: measurement, live: measurement, applyHermetic: true, applyLive: true})
			position += 2
			if c.PrivateWitnesses() {
				for offset := 0; offset < 3; offset++ {
					execution = withMeasurements(execution, measurementOverride{step: position + offset, hermetic: false, live: true, applyHermetic: true, applyLive: true})
				}
				position += 3
			}
		}
		all = append(all, scenario{name: name, authority: &c, roles: roles, members: 1, smallBytes: 1, explicitShape: true, execution: execution, title: "Current authority replacement preserves selected state", description: "Qualify each exact successor, preserve selected material and receipts, deliver the current public basis durably, and consume through the current recipient after restart. Recovery modes are explicit schedule requirements."})
	}
	for _, row := range []struct {
		name            string
		operation, mask uint8
	}{{"normal-signer", 1, 1}, {"normal-kek", 1, 2}, {"normal-combined", 1, 3}, {"recovery-signer", 3, 4}, {"recovery-kek", 3, 8}, {"recovery-combined", 3, 12}} {
		for _, approval := range []uint8{1, 2} {
			for _, material := range []bool{false, true} {
				suffix := "zero-material"
				if material {
					suffix = "current-material"
				}
				add(fmt.Sprintf("access.%s-k%d-%s", row.name, approval+1, suffix), AuthorityReplacementCase{Operation: row.operation, Mask: row.mask, Approval: approval, Material: material})
			}
		}
	}
	for _, material := range []bool{false, true} {
		suffix := "zero-material"
		if material {
			suffix = "current-material"
		}
		add("access.reciprocal-authority-"+suffix, AuthorityReplacementCase{Material: material, Reciprocal: true})
	}
	return all
}

// GeneratedHistoryCase keeps the former deferred-history matrix on the real
// generated operation and final-selection path.
type GeneratedHistoryCase struct {
	SourceMode        uint8
	Union, Reciprocal bool
}

func generatedHistoryGroup(name string) (GeneratedHistoryCase, bool) {
	s, ok := lookupGroup(name)
	if !ok || s.history == nil {
		return GeneratedHistoryCase{}, false
	}
	return *s.history, true
}
func generatedHistoryGroupNames(mode string) []string {
	var names []string
	for _, s := range scenarios {
		if s.history != nil && len(define(s).RolesForRecovery(mode)) != 0 {
			names = append(names, s.name)
		}
	}
	return names
}
func generatedHistoryScenarios() []scenario {
	var all []scenario
	add := func(name, title string, c GeneratedHistoryCase) {
		roles := []string{"replacement-store", "normal-signer-0", "authority-decrypter-0"}
		if c.Reciprocal {
			roles = append(roles, "recovery-signer-0", "authority-decrypter-1", "authority-decrypter-2", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2")
		}
		if c.SourceMode == 2 {
			roles = append(roles, "reader")
			if !c.Union {
				roles = append(roles, "denied-reader")
			}
		}
		copy := c
		capabilities := []FixtureCapability{FixtureGeneratedProcess, FixtureSecretState}
		if c.Reciprocal {
			capabilities = append(capabilities, FixtureSyntheticAuthority)
		}
		freshRole := "authority-decrypter-0"
		finalStep := 8
		if c.Reciprocal {
			freshRole = "authority-decrypter-2"
			finalStep = 17
		}
		execution := withFreshOutcome(baseExecution(FamilyGeneratedHistory, finalStep, capabilities...), freshRole, "success")
		if c.Reciprocal {
			execution = withFreshReopens(execution,
				declaredChild{step: 4, purpose: FreshReopen, role: "authority-decrypter-1", count: 1},
				declaredChild{step: 7, purpose: FreshReopen, role: "authority-decrypter-1", count: 1},
				declaredChild{step: 11, purpose: FreshReopen, role: "authority-decrypter-2", count: 1},
				declaredChild{step: 14, purpose: FreshReopen, role: "authority-decrypter-2", count: 1},
			)
			execution.children = append(execution.children,
				declaredChild{step: 8, purpose: FreshGeneratedRecord, role: "authority-decrypter-1", count: 1},
				declaredChild{step: 15, purpose: FreshGeneratedFinal, role: "authority-decrypter-2", count: 1},
			)
		} else {
			execution = withFreshReopens(execution, declaredChild{step: 5, purpose: FreshReopen, role: "authority-decrypter-0", count: 1})
			execution.children = append(execution.children,
				declaredChild{step: 3, purpose: FreshGeneratedRecord, role: "authority-decrypter-0", count: 1},
				declaredChild{step: 6, purpose: FreshGeneratedFinal, role: "authority-decrypter-0", count: 1},
			)
			execution = withMeasurements(execution,
				measurementOverride{step: 2, hermetic: c.SourceMode == 2, applyHermetic: true},
				measurementOverride{step: 7, hermetic: false, applyHermetic: true},
			)
		}
		all = append(all, scenario{history: &copy, name: name, title: title, description: "Reserve one generated operation, preserve its entered effect and source authority through replacement, adopt its original late result, and select its complete final set.", roles: roles, members: 1, smallBytes: 1, explicitShape: true, execution: execution})
	}
	for mode := uint8(0); mode <= 2; mode++ {
		add(fmt.Sprintf("accepted.source-mode%d-late-result", mode), fmt.Sprintf("Generated source mode%d preserves its late result", mode), GeneratedHistoryCase{SourceMode: mode})
	}
	add("accepted.same-value-reader-union", "Current readers do not add generated source authority", GeneratedHistoryCase{SourceMode: 2, Union: true})
	for mode := uint8(0); mode <= 2; mode++ {
		add(fmt.Sprintf("accepted.source-mode%d-reciprocal-loss", mode), fmt.Sprintf("Generated source mode%d survives repeated current key loss", mode), GeneratedHistoryCase{SourceMode: mode, Reciprocal: true})
	}
	combined := GeneratedHistoryCase{SourceMode: 2}
	combinedExecution := withFreshOutcome(baseExecution(FamilyCombinedHistory, 11, FixtureGeneratedProcess, FixtureSecretState, FixtureReaderSuccessor, FixtureSyntheticAuthority), "authority-decrypter-1", "success")
	combinedExecution.children = append(combinedExecution.children, declaredChild{step: 7, purpose: FreshGeneratedRecord, role: "authority-decrypter-1", count: 1})
	all = append(all, scenario{name: combinedHistoryScenario, history: &combined, title: "Secret lifecycle and recovery preserve one history", description: "Update and share one selected history, replace its Recipient key, reserve generated work, replace current authority access, adopt the original late result, and either replace recovery access or prove its exact disabled-mode refusal.", roles: []string{"reader", "denied-reader", "reader-successor", "replacement-store", "normal-signer-0", "recovery-signer-0", "authority-decrypter-0", "authority-decrypter-1", "recovery-decrypter-0", "recovery-decrypter-1"}, members: 1, smallBytes: 1, explicitShape: true, execution: combinedExecution})
	return all
}
func generatedHistorySteps(c GeneratedHistoryCase) []Step {
	steps := []Step{{Name: "setup", Role: "authority", Expected: "generated-history-fixture-ready"}, {Name: "transition", Role: "authority", Expected: "generated-work-enters-once"}}
	if c.Reciprocal {
		for i := 0; i < 2; i++ {
			steps = append(steps, Step{Name: "transition", Role: "replacement-store", Expected: "occupied-current-key-successor-selected"}, Step{Name: "verification", Role: "replacement-store", Expected: "generated-material-and-rights-preserved"}, Step{Name: "reopen", Role: "authority-decrypter-1", Expected: "success"})
		}
		steps = append(steps, Step{Name: "transition", Role: "authority-decrypter-1", Expected: "late-result-recorded-and-close-frozen"})
		for i := 0; i < 2; i++ {
			steps = append(steps, Step{Name: "transition", Role: "replacement-store", Expected: "occupied-current-key-successor-selected"}, Step{Name: "verification", Role: "replacement-store", Expected: "generated-material-and-stale-final-rights-preserved"}, Step{Name: "reopen", Role: "authority-decrypter-2", Expected: "success"})
		}
		return append(steps, Step{Name: "transition", Role: "authority-decrypter-2", Expected: "fresh-generated-final-selected"}, Step{Name: "verification", Role: "authority-decrypter-2", Expected: "closed-work-preserves-current-state"}, Step{Name: "reopen", Role: "authority-decrypter-2", Expected: "success"})
	}
	role := "authority"
	if c.SourceMode == 2 && !c.Union {
		role = "reader"
	}
	return append(steps, Step{Name: "verification", Role: role, Expected: "exact-source-and-consumer-rights-preserved"}, Step{Name: "transition", Role: "authority-decrypter-0", Expected: "original-late-result-recorded"}, Step{Name: "verification", Role: "authority", Expected: "result-adoption-does-not-restore-entry"}, Step{Name: "reopen", Role: "authority-decrypter-0", Expected: "success"}, Step{Name: "transition", Role: "authority-decrypter-0", Expected: "fresh-generated-final-selected"}, Step{Name: "verification", Role: "authority", Expected: "closed-work-preserves-current-state"}, Step{Name: "reopen", Role: "authority-decrypter-0", Expected: "success"})
}
