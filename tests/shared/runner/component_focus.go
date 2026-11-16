package main

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

const componentPackage = "enkv.sh/core"

// Focus describes partial work. Its presence never grants complete-profile credit.
type componentFocus struct {
	Tests   []string `json:"tests"`
	Package string   `json:"package"`
}

type componentPreparation struct {
	Source            records.Source       `json:"source"`
	Toolchain         string               `json:"toolchain"`
	BuildClosure      assemblyClosure      `json:"build_closure"`
	Classifications   []testClassification `json:"classifications"`
	Inventory         []string             `json:"inventory"`
	NotSelected       []string             `json:"not_selected,omitempty"`
	ExecutionProof    string               `json:"execution_proof"`
	ParentPreparation string               `json:"parent_preparation"`
}

func componentFocusSelection(request string) (string, error) {
	if !validComponentName(request) {
		return "", errors.New("component focus requires a literal test or subtest name")
	}
	return literalTestSelection(request), nil
}

// Each Go -run segment is an exact literal, including dynamic child punctuation.
func literalTestSelection(request string) string {
	segments := strings.Split(request, "/")
	for i, segment := range segments {
		segments[i] = "^" + regexp.QuoteMeta(segment) + "$"
	}
	return strings.Join(segments, "/")
}

// Selecting a child keeps its parent's process isolation.
func componentFocusProcessClass(request string) string {
	owner, _, _ := strings.Cut(request, "/")
	if slices.Contains(ordinaryMemoryComponents, owner) {
		return "fresh-exclusive"
	}
	return "ordinary"
}

// Selection and process class are semantic facts. Scheduling weights and group
// labels are execution-owned placement facts, not retained proof authority.
func resolveComponentFocus(names []string, classifications []testClassification, profile string, requests []string) (selected, excluded []string, focus *componentFocus, err error) {
	selected, excluded, err = selectComponentInventory(names, classifications, profile)
	if err != nil {
		return
	}
	if profile == "full" && !slices.Contains(selected, maximumCapacityComponent) {
		err = errors.New("component inventory lacks its maximum-capacity proof")
		return
	}
	// These source-owned dependencies are selection facts, independent of any
	// estimate or physical group label. Retained proof must preserve them too.
	for _, bundle := range componentHelperProofGroups {
		required := false
		for _, name := range bundle[1:] {
			required = required || slices.Contains(selected, name)
		}
		if !required {
			continue
		}
		if !slices.Contains(selected, bundle[0]) {
			err = errors.New("component helper lacks its selected proving parent")
			return
		}

	}
	if len(requests) == 0 {
		return
	}
	if err = validateRequestedTests(requests); err != nil {
		return
	}
	for _, request := range requests {
		if _, err = componentFocusSelection(request); err != nil {
			return
		}
		owner, _, child := strings.Cut(request, "/")
		if !slices.Contains(names, owner) {
			err = fmt.Errorf("component test %s is not in the compiled inventory", owner)
			return
		}
		if !slices.Contains(selected, owner) {
			err = fmt.Errorf("component test %s is excluded from profile %s", owner, profile)
			return
		}
		switch owner {
		case "TestHermeticRun", "TestHermeticChild":
			err = errors.New("component coordinator entrypoint cannot run as an ordinary test")
			return
		case "TestFreshProcessChild", "TestScenarioPhaseFailureChild", "TestWriterTerminationChild":
			parent := ""
			for _, bundle := range componentHelperProofGroups {
				if slices.Contains(bundle[1:], owner) {
					parent = bundle[0]
				}
			}
			if child || parent == "" || !slices.Contains(requests, parent) {
				err = errors.New("component helper requires its complete invoking parent")
				return
			}
		case "TestHermeticWorkerEntrypointsNeedExplicitInvocation":
			if child {
				err = errors.New("select the complete negative helper parent, not an individual skip probe")
				return
			}
		}
	}
	focus = &componentFocus{Tests: slices.Clone(requests), Package: componentPackage}
	return
}

// Validate complete placement first. Narrowing must not hide a broken assembly.
func resolveComponentGroups(names []string, classifications []testClassification, profile string, requests []string, parallel int, estimates map[string]float64) (selected, excluded []string, groups []componentGroup, focus *componentFocus, err error) {
	selected, excluded, focus, err = resolveComponentFocus(names, classifications, profile, requests)
	if err != nil {
		return
	}
	groupRoots := selected
	if focus != nil {
		groupRoots = requestedTestRoots(requests)
	}
	selectedClassifications := make([]testClassification, 0, len(groupRoots))
	for _, root := range groupRoots {
		for _, classification := range classifications {
			if classification.Name == root {
				selectedClassifications = append(selectedClassifications, classification)
			}
		}
	}
	groups, err = componentGroupsForProfile(groupRoots, selectedClassifications, profile, parallel, estimates)
	if err != nil {
		return
	}
	if focus == nil {
		groups, err = partitionComponentGroups(names, groups, estimates)
		return
	}
	var narrowed []componentGroup
	for _, group := range groups {
		var paths []string
		for _, request := range requests {
			root, _, _ := strings.Cut(request, "/")
			if slices.Contains(group.Tests, root) {
				paths = append(paths, request)
			}
		}
		partitions, partitionErr := literalTestGroups(paths)
		if partitionErr != nil {
			err = partitionErr
			return
		}
		for _, partition := range partitions {
			item := componentGroup{Name: fmt.Sprintf("selected-%d", len(narrowed)+1), Tests: partition.Roots,
				Requests: partition.Tests, Selection: partition.Selection, Exclusive: group.Exclusive, Worker: group.Worker}
			for _, root := range partition.Roots {
				item.EstimatedSeconds += testEstimate(estimates, root)
			}
			narrowed = append(narrowed, item)
		}
	}
	groups = narrowed
	return
}

// A focused pass proves the requested node and the parent work that ran with it.
// It cannot supply complete-profile or positive helper-invocation proof.
func completeFocusedComponentEvidence(checks checkEvidence) bool {
	if checks.Focus == nil || checks.Focus.Package != componentPackage || len(checks.Focus.Tests) == 0 || checks.Outcome != "passed" || !checks.TestsComplete || !validRaceOptions(checks.Race, checks.RaceOptions) {
		return false
	}
	_, excluded, focus, err := resolveComponentFocus(checks.Inventory, checks.Classifications, checks.Profile, checks.Focus.Tests)
	groups, placementOK := retainedComponentGroups(checks)
	if err != nil || focus == nil || !slices.Equal(focus.Tests, checks.Focus.Tests) || !slices.Equal(excluded, checks.NotSelected) || !placementOK {
		return false
	}
	selection := "literal requested test paths in exact process groups"
	if len(groups) == 1 {
		selection = groups[0].Selection
	}
	if checks.Selection != selection {
		return false
	}
	groupNames := map[string]bool{}
	for index, group := range checks.Groups {
		if groupNames[group.Name] || !telemetryLabel.MatchString(group.Name) || group.TestCount != len(groups[index].Tests) || group.Outcome != "passed" {
			return false
		}
		groupNames[group.Name] = true
	}
	if checks.EventTimeSource != "post_join_test2json" || checks.Diagnostics == nil || checks.Diagnostics.Preparation != "passed" ||
		len(checks.Diagnostics.Commands) == 0 || len(checks.Diagnostics.Commands) > maximumCheckCommands {
		return false
	}
	tests, conversions := 0, 0
	testGroups, conversionGroups := map[string]bool{}, map[string]bool{}
	for _, command := range checks.Diagnostics.Commands {
		if !command.Started || !command.Joined || command.Process != "passed" || command.RaceObservation != "not_observed" ||
			command.ToolCleanup != "passed" && command.ToolCleanup != "not_required" && command.ToolCleanup != "not_owner" {
			return false
		}
		switch command.Phase {
		case "preparation":
			_, module := registeredModule(command.Scope)
			if !telemetryLabel.MatchString(command.Scope) && !module || command.Events != "not_run" || command.RequestedNode != "" {
				return false
			}
		case "test":
			tests++
			if !groupNames[command.Scope] || testGroups[command.Scope] || command.Events != "not_run" || command.RequestedNode != "passed" {
				return false
			}
			testGroups[command.Scope] = true
		case "conversion":
			conversions++
			if !groupNames[command.Scope] || conversionGroups[command.Scope] || command.Events != "valid" || command.RequestedNode != "" {
				return false
			}
			conversionGroups[command.Scope] = true
		default:
			return false
		}
	}
	return tests == len(groups) && conversions == len(groups) && completeRequestedComponentTerminals(focus.Tests, checks.Tests)
}

func completeRequestedComponentTerminals(requests []string, tests []componentTest) bool {
	names := make([]string, 0, len(tests))
	outcomes := map[string]string{}
	const negativeParent = "TestHermeticWorkerEntrypointsNeedExplicitInvocation"
	for _, test := range tests {
		names = append(names, test.Name)
		outcomes[test.Name] = test.Outcome
	}
	for _, test := range tests {
		allowedSkip := slices.Contains(requests, negativeParent) && slices.Contains([]string{negativeParent + "/writer", negativeParent + "/fresh", negativeParent + "/fixture"}, test.Name)
		allowedSkip = allowedSkip || completedHelperInvocation(test.Name, "hermetic", outcomes)
		if test.Outcome != "passed" && (test.Outcome != "skipped" || !allowedSkip) {
			return false
		}
	}
	if !validRequestedTestNames(requests, names) {
		return false
	}
	for _, request := range requests {
		switch request {
		case negativeParent:
			if outcomes[negativeParent+"/writer"] != "skipped" || outcomes[negativeParent+"/fresh"] != "skipped" || outcomes[negativeParent+"/fixture"] != "skipped" {
				return false
			}
		case "TestCompletedIntentSourceStorePrune":
			if outcomes[request+"/results_8"] != "passed" || outcomes[request+"/results_16"] != "passed" {
				return false
			}
		case "TestWriterTerminationPreservesCompleteSelection":
			if !completedHelperInvocation("TestWriterTerminationChild", "hermetic", outcomes) {
				return false
			}
		}
	}
	return true
}

// A passing ancestor or sibling cannot prove that the exact requested node ran.
func exactFocusedTestEvidence(request string, tests []componentTest, allowedSkip func(string) bool) bool {
	passed := false
	for _, test := range tests {
		if test.Name != request && !strings.HasPrefix(test.Name, request+"/") && !strings.HasPrefix(request, test.Name+"/") {
			return false
		}
		if test.Outcome != "passed" && (test.Outcome != "skipped" || allowedSkip == nil || !allowedSkip(test.Name)) {
			return false
		}
		passed = passed || test.Name == request && test.Outcome == "passed"
	}
	return passed
}

// Retained ownership is checked against selection and resource contracts. New
// estimates and later invocation capacities cannot change a completed result.
func retainedComponentGroups(checks checkEvidence) ([]componentGroup, bool) {
	if checks.Focus == nil || checks.Parallelism < 1 || checks.Parallelism > componentGroupCount || len(checks.Groups) == 0 {
		return nil, false
	}
	roots := requestedTestRoots(checks.Focus.Tests)
	rows := make([]testClassification, 0, len(roots))
	for _, root := range roots {
		for _, row := range checks.Classifications {
			if row.Name == root {
				rows = append(rows, row)
			}
		}
	}
	classes, err := componentGroupsForProfile(roots, rows, checks.Profile, 1, nil)
	if err != nil {
		return nil, false
	}
	exclusive := map[string]bool{}
	for _, group := range classes {
		for _, name := range group.Tests {
			exclusive[name] = group.Exclusive
		}
	}
	owners, requests := map[string]string{}, map[string]bool{}
	rootGroups := map[string]int{}
	var groups []componentGroup
	for index, saved := range checks.Groups {
		if len(saved.Tests) == 0 || saved.TestCount != len(saved.Tests) || saved.Exclusive && saved.Worker != 0 || !saved.Exclusive && (saved.Worker < 1 || saved.Worker > checks.Parallelism) {
			return nil, false
		}
		parts, err := literalTestGroups(saved.Requests)
		if err != nil || len(parts) != 1 || !slices.Equal(parts[0].Roots, saved.Tests) || parts[0].Selection != saved.Selection {
			return nil, false
		}
		for _, request := range saved.Requests {
			if requests[request] || !slices.Contains(checks.Focus.Tests, request) {
				return nil, false
			}
			requests[request] = true
		}
		owner := fmt.Sprintf("worker-%d", saved.Worker)
		if saved.Exclusive {
			// Exact child partitions may repeat an exclusive root, in sequence.
			owner = "exclusive"
		}
		for _, name := range saved.Tests {
			class, known := exclusive[name]
			if !known || class != saved.Exclusive || owners[name] != "" && owners[name] != owner || slices.Contains(ordinaryMemoryComponents, name) && len(saved.Tests) != 1 {
				return nil, false
			}
			owners[name] = owner
			rootGroups[name] = index
		}
		groups = append(groups, componentGroup{Name: saved.Name, Tests: slices.Clone(saved.Tests), Requests: slices.Clone(saved.Requests), Selection: saved.Selection, Exclusive: saved.Exclusive, Worker: saved.Worker})
	}
	if len(requests) != len(checks.Focus.Tests) || len(owners) != len(roots) {
		return nil, false
	}
	for _, bundle := range componentHelperProofGroups {
		for _, helper := range bundle[1:] {
			if owners[helper] != "" && owners[bundle[0]] != "" && (owners[helper] != owners[bundle[0]] || rootGroups[helper] != rootGroups[bundle[0]]) {
				return nil, false
			}
		}
	}
	if _, err := componentGroupSelections(checks.Inventory, groups, true); err != nil {
		return nil, false
	}
	return groups, true
}
