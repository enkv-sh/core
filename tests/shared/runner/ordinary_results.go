package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

const maximumOrdinaryTests = 8192

const maximumOrdinaryTestResults = records.MaximumJSONBytes / len(`{"package":"p","name":"TestA","outcome":"pass"},`)

type ordinaryEvent struct {
	Time        *time.Time `json:"Time,omitempty"`
	Action      string     `json:"Action"`
	Package     string     `json:"Package"`
	ImportPath  string     `json:"ImportPath,omitempty"`
	Test        string     `json:"Test,omitempty"`
	Elapsed     *float64   `json:"Elapsed,omitempty"`
	Output      string     `json:"Output,omitempty"`
	OutputType  string     `json:"OutputType,omitempty"`
	FailedBuild string     `json:"FailedBuild,omitempty"`
	Key         string     `json:"Key,omitempty"`
	Value       string     `json:"Value,omitempty"`
	Path        string     `json:"Path,omitempty"`
}

type ordinaryTest struct {
	Package        string                          `json:"package"`
	Name           string                          `json:"name"`
	Outcome        string                          `json:"outcome"`
	StartedAt      *time.Time                      `json:"started_at,omitempty"`
	FinishedAt     *time.Time                      `json:"finished_at,omitempty"`
	ElapsedSeconds *float64                        `json:"elapsed_seconds,omitempty"`
	Relation       *retainedSecretMaterialRelation `json:"relation,omitempty"`
}

type ordinaryPackage struct {
	Name            string               `json:"name"`
	Tests           []string             `json:"tests,omitempty"`
	Inventory       []string             `json:"inventory,omitempty"`
	Classifications []testClassification `json:"classifications,omitempty"`
	NotSelected     []string             `json:"not_selected,omitempty"`
}

type ordinaryStepEvidence struct {
	Toolchain           string                       `json:"toolchain"`
	Profile             string                       `json:"profile"`
	RunnerGroups        []runnerGroupEvidence        `json:"runner_groups,omitempty"`
	EventTimeSource     string                       `json:"event_time_source,omitempty"`
	Diagnostics         *checkDiagnostics            `json:"diagnostics,omitempty"`
	Focus               *ordinaryFocus               `json:"focus,omitempty"`
	Preparation         *ordinaryPreparation         `json:"preparation,omitempty"`
	PreparationFailures []ordinaryPreparationFailure `json:"preparation_failures,omitempty"`
	Execution           []ordinaryExecution          `json:"execution,omitempty"`
	SelectedComplete    bool                         `json:"selected_complete,omitempty"`
	Race                *bool                        `json:"race,omitempty"`
	RaceOptions         string                       `json:"race_options"`
	Packages            []ordinaryPackage            `json:"packages"`
	Tests               []ordinaryTest               `json:"tests"`
	Complete            bool                         `json:"complete"`
}

var ordinaryTestlessCommands = map[string]bool{
	"enkv.sh/plugins/generators/local-random-secret/cmd/enkv-generator-local-random-secret":  true,
	"enkv.sh/tests/fixtures/output-contract-test/cmd/enkv-output-contract-test":              true,
	"enkv.sh/plugins/outputs/github-actions/cmd/enkv-output-github-repository":               true,
	"enkv.sh/plugins/outputs/github-actions/cmd/enkv-output-github-organization":             true,
	"enkv.sh/plugins/outputs/github-actions/cmd/enkv-output-github-environment":              true,
	"enkv.sh/plugins/outputs/aws-secrets-manager/cmd/enkv-output-aws-secrets-manager":        true,
	"enkv.sh/plugins/outputs/gcp-secret-manager/cmd/enkv-output-gcp-secret-manager":          true,
	"enkv.sh/plugins/generators/cloudflare-account-token/cmd/enkv-generator-cloudflare":      true,
	"enkv.sh/plugins/generators/cloudflare-account-token/cmd/enkv-generator-cloudflare-test": true,
}

// Each controlled entry point skips in the outer runner. The parent case
// checks the matching child role and its joined worker record.
var ordinaryRunnerHelperProofs = map[string]string{
	"enkv.sh/core/internal/testmain\x00TestLiveRun":      "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent/passed",
	"enkv.sh/core/internal/testmain\x00TestLiveChild":    "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent/passed",
	"enkv.sh/core/internal/testmain\x00TestLiveCleanup":  "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent/passed",
	"enkv.sh/core/internal/testmain\x00TestLiveRecovery": "TestCoordinatorAssertionEvidencePreservesTypedRerun/valid_marker",
}

var ordinaryProviderHelperProofs = map[string]string{
	"enkv.sh/compositions/aws\x00TestConfigurationRecoveryLiveParentControl": "TestConfigurationRecoveryLiveParentInvokesControl",
	"enkv.sh/providers/gcp\x00TestConfigurationRecoveryLiveParentControl":    "TestConfigurationRecoveryLiveParentInvokesControl",
}

func ordinaryEventsFrom(body []byte) ([]ordinaryEvent, error) {
	if len(body) == 0 || len(body) > maximumToolOutputBytes || body[len(body)-1] != '\n' {
		return nil, errors.New("ordinary test event stream is empty, truncated, or over its bound")
	}
	var events []ordinaryEvent
	for line := range bytes.SplitSeq(body, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		event, err := decodeTestEvent(line)
		if err != nil {
			return nil, errors.New("ordinary test event is invalid")
		}
		if event.Action != "build-output" {
			events = append(events, event)
		}
	}
	if len(events) == 0 {
		return nil, errors.New("ordinary test event stream has no events")
	}
	return events, nil
}

func validateOrdinaryEvents(body []byte, want map[string][]string, helperProofs map[string]string) ([]ordinaryTest, error) {
	results, _, err := parseOrdinaryEvents(body, want, helperProofs)
	return results, err
}

func parseOrdinaryEvents(body []byte, want map[string][]string, helperProofs map[string]string) ([]ordinaryTest, string, error) {
	return parseOrdinaryProfileEvents(body, want, helperProofs, nil, nil)
}

func parseOrdinarySelectedEvents(body []byte, want map[string][]string, helperProofs map[string]string, evidence *ordinaryStepEvidence, capture *limitedOutput) ([]ordinaryTest, string, error) {
	empty := map[string]bool{}
	for _, pkg := range evidence.Packages {
		if names, found := want[pkg.Name]; found && len(names) == 0 && len(pkg.Inventory) != 0 && validOrdinaryPackageSelection(pkg, evidence.Profile) {
			empty[pkg.Name] = true
		}
	}
	return parseOrdinaryProfileEvents(body, want, helperProofs, empty, capture)
}

func parseOrdinaryProfileEvents(body []byte, want map[string][]string, helperProofs map[string]string, empty map[string]bool, capture *limitedOutput) ([]ordinaryTest, string, error) {
	rootCount := 0
	for _, names := range want {
		if len(names) > maximumOrdinaryTests-rootCount {
			return nil, "unavailable", errors.New("ordinary compiled inventory exceeds its bound")
		}
		rootCount += len(names)
	}
	testless := make(map[string]bool, len(ordinaryTestlessCommands)+len(empty))
	for pkg, allowed := range ordinaryTestlessCommands {
		testless[pkg] = allowed
	}
	for pkg, allowed := range empty {
		testless[pkg] = allowed
	}
	state, err := newTestEventState(want, maximumOrdinaryTestResults, validOrdinaryName, testless)
	if err != nil {
		return nil, "unavailable", err
	}
	state.emptySelected = empty
	if len(body) == 0 || len(body) > maximumToolOutputBytes {
		status := "unavailable"
		if len(body) > maximumToolOutputBytes {
			status = "overflow"
		}
		return nil, status, errors.New("ordinary test event stream is empty or over its bound")
	}
	stream := &testEventStream{state: state, privateErrorOutput: capture}
	_, _ = stream.Write(body)
	completionErr := stream.complete()
	results := state.ordinaryTests()
	for pkg, outcomes := range state.states {
		for name, outcome := range outcomes {
			if outcome != "skip" {
				continue
			}
			proof, allowed := helperProofs[pkg+"\x00"+name]
			if !allowed || strings.Contains(name, "/") || outcomes[proof] != "pass" || !slices.Contains(want[pkg], strings.Split(proof, "/")[0]) {
				return results, stream.status(), errors.Join(completionErr, fmt.Errorf("ordinary test %s skipped without exact helper invocation proof", name))
			}
		}
	}
	return results, stream.status(), completionErr
}

func ordinaryFocusEventError(results []ordinaryTest, focus ordinaryFocus, completionErr error) error {
	groups, err := literalTestGroups(focus.Tests)
	if err != nil {
		return errors.Join(completionErr, err)
	}
	seen := make(map[string]int, len(results))
	for _, result := range results {
		maximum := 0
		for _, group := range groups {
			if slices.ContainsFunc(group.Tests, func(request string) bool { return requestedTestContains(request, result.Name) }) {
				maximum++
			}
		}
		seen[result.Name]++
		if result.Package != focus.Package || seen[result.Name] > maximum {
			return errors.Join(completionErr, errors.New("ordinary focus ran outside the requested subtree or repeated a result"))
		}
	}
	if completionErr == nil && !ordinaryFocusedTerminals(results, focus) {
		return errors.New("ordinary focus lacks exact requested pass")
	}
	return completionErr
}

func ordinaryRequestedNode(results []ordinaryTest, focus ordinaryFocus) string {
	status := "passed"
	for _, request := range focus.Tests {
		found := false
		for _, result := range results {
			if result.Package != focus.Package || result.Name != request {
				continue
			}
			found = true
			switch result.Outcome {
			case "fail":
				return "failed"
			case "skip":
				status = "skipped"
			case "incomplete":
				return "incomplete"
			case "not_run":
				return "missing"
			}
		}
		if !found {
			return "missing"
		}
	}
	return status
}

func ordinaryUnstartedRequests(results []ordinaryTest, focus ordinaryFocus, outcome string) []ordinaryTest {
	for _, request := range focus.Tests {
		if !slices.ContainsFunc(results, func(row ordinaryTest) bool { return row.Package == focus.Package && row.Name == request }) {
			results = append(results, ordinaryTest{Package: focus.Package, Name: request, Outcome: outcome})
		}
	}
	return results
}

func ordinaryUnobservedOutcome(events string, captureComplete bool) string {
	if !captureComplete || events != "valid" && events != "incomplete" {
		return "incomplete"
	}
	return "not_run"
}

func ordinaryIncompleteStarts(results []ordinaryTest) {
	for index := range results {
		if results[index].Outcome == "not_run" {
			results[index].Outcome = "incomplete"
		}
	}
}

// Both inventory and execution use the delegated test allocation. Callers
// retain their timeout flags; capacity has one owner even for prepared focus.
func ordinaryCapacityFlags(ctx context.Context, flags []string) []string {
	resolved := make([]string, 0, len(flags)+1)
	for _, flag := range flags {
		if !strings.HasPrefix(flag, "-parallel=") {
			resolved = append(resolved, flag)
		}
	}
	return append(resolved, fmt.Sprintf("-parallel=%d", executionCapacityFromContext(ctx).Parallel))
}

func listOrdinaryPackages(ctx context.Context, root, directory string, buildFlags, patterns []string, diagnostics *checkDiagnostics) ([]listedOrdinaryPackage, error) {
	value, _, err := invocationArtifactValue(ctx, root, root, "ordinary-packages", struct {
		Directory       string
		Flags, Patterns []string
	}{directory, buildFlags, patterns}, func(string) ([]listedOrdinaryPackage, error) {
		return discoverOrdinaryPackages(ctx, root, directory, buildFlags, patterns, diagnostics)
	})
	return value, err
}

func discoverOrdinaryPackages(ctx context.Context, root, directory string, buildFlags, patterns []string, diagnostics *checkDiagnostics) ([]listedOrdinaryPackage, error) {
	listArgs := append(append([]string{"list"}, compilerBuildFlags(buildFlags, raceEnabled(ctx))...), "-e", "-json=ImportPath,Dir,GoFiles,TestGoFiles,XTestGoFiles")
	listBody, facts, err := runGoRecorded(ctx, root, directory, append(listArgs, patterns...)...)
	err = containProcessFailure(ctx, err)
	if diagnostics != nil {
		facts.Phase = "preparation"
		err = errors.Join(err, diagnostics.append(facts))
	}
	if err != nil {
		return nil, err
	}
	packages, err := decodeObjects[listedOrdinaryPackage](listBody)
	if err != nil || len(packages) == 0 {
		return nil, errors.New("ordinary package discovery is incomplete")
	}
	identities := make(map[string]bool, len(packages))
	for _, pkg := range packages {
		if pkg.ImportPath == "" {
			return nil, errors.New("ordinary package discovery lacks an identity")
		}
		if identities[pkg.ImportPath] {
			return nil, errors.New("ordinary package discovery repeated a package")
		}
		identities[pkg.ImportPath] = true
	}
	return packages, nil
}

func discoverOrdinaryInventory(ctx context.Context, root, directory string, buildFlags, patterns []string, runPattern string, diagnostics *checkDiagnostics, testFlags ...string) (map[string][]string, []ordinaryPackage, error) {
	packages, err := listOrdinaryPackages(ctx, root, directory, buildFlags, patterns, diagnostics)
	if err != nil {
		return nil, nil, err
	}
	return discoverListedOrdinaryInventory(ctx, root, directory, buildFlags, patterns, runPattern, packages, diagnostics, testFlags...)
}

func discoverListedOrdinaryInventory(ctx context.Context, root, directory string, buildFlags, patterns []string, runPattern string, packages []listedOrdinaryPackage, diagnostics *checkDiagnostics, testFlags ...string) (wanted map[string][]string, inventory []ordinaryPackage, err error) {
	want := make(map[string][]string, len(packages))
	var retained []ordinaryPackage
	var selected *regexp.Regexp
	if runPattern != "" {
		selected, err = regexp.Compile(runPattern)
		if err != nil {
			return nil, nil, err
		}
	}
	output := ordinaryInventoryOutput(testFlags)
	fallback := filepath.Dir(output)
	owned, release, err := ordinaryPackageDirectory(ctx, fallback)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, release()) }()
	for _, pkg := range packages {
		actualPatterns := []string{pkg.ImportPath}
		if pkg.ImportPath == "command-line-arguments" {
			actualPatterns = patterns
		}
		compiled, err := prepareOrdinaryPackage(ctx, root, directory, buildFlags, actualPatterns, pkg, owned, diagnostics)
		if err != nil {
			return nil, nil, err
		}
		if output != "" && compiled.binary != "" {
			if err := linkInvocationFile(compiled.binary, output); err != nil {
				return nil, nil, err
			}
		}
		row := compiled.inventory
		row.Tests, row.NotSelected = nil, nil
		for _, name := range row.Inventory {
			if selected == nil || selected.MatchString(name) {
				row.Tests = append(row.Tests, name)
			} else {
				row.NotSelected = append(row.NotSelected, name)
			}
		}
		want[pkg.ImportPath] = slices.Clone(row.Tests)
		retained = append(retained, row)
	}
	return want, retained, nil
}

func appendOrdinaryInventory(evidence *ordinaryStepEvidence, want map[string][]string, retained []ordinaryPackage) error {
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		index := slices.IndexFunc(retained, func(pkg ordinaryPackage) bool { return pkg.Name == name })
		if index < 0 {
			return errors.New("ordinary selected package lacks retained classification")
		}
		row := retained[index]
		row.Tests = slices.Clone(want[name])
		row.NotSelected = slices.DeleteFunc(slices.Clone(row.Inventory), func(root string) bool { return slices.Contains(row.Tests, root) })
		evidence.Packages = append(evidence.Packages, row)
	}
	return nil
}

// Both complete and focused callers use the same command owner and event parser.
func executeOrdinaryInventory(parent, ctx context.Context, root, directory string, buildFlags, patterns []string, runPattern string, want map[string][]string, helperProofs map[string]string, focus *ordinaryFocus, evidence *ordinaryStepEvidence, testFlags ...string) error {
	args := append(append(append([]string{"test"}, compilerBuildFlags(buildFlags, raceEnabled(ctx))...), ordinaryCapacityFlags(ctx, testFlags)...), "-count=1", "-json")
	if runPattern != "" {
		args = append(args, "-run="+runPattern)
	}
	if evidence.Diagnostics == nil {
		evidence.Diagnostics = &checkDiagnostics{Preparation: "passed"}
	}
	evidence.EventTimeSource = "go_test_json"
	body, facts, runErr := runGoRecorded(ctx, root, directory, append(args, patterns...)...)
	facts.Phase = "test"
	if runErr != nil {
		var failure *toolFailure
		if errors.As(runErr, &failure) && failure.process.Joined && !failure.overflow {
			body = failure.stdout
		}
	}
	results, events, validationErr := parseOrdinarySelectedEvents(body, want, helperProofs, evidence, nil)
	facts.Events = events
	captureComplete := facts.Joined
	var commandFailure *toolFailure
	if errors.As(runErr, &commandFailure) && commandFailure.overflow {
		captureComplete = false
	}
	unobserved := ordinaryUnobservedOutcome(events, captureComplete)
	if !facts.Started && facts.Joined {
		unobserved = "not_run"
	}
	if unobserved == "incomplete" {
		ordinaryIncompleteStarts(results)
	}
	if focus != nil && len(focus.Tests) != 0 {
		facts.RequestedNode = ordinaryRequestedNode(results, *focus)
		if facts.RequestedNode == "missing" && unobserved == "incomplete" {
			facts.RequestedNode = "unavailable"
		}
		results = ordinaryUnstartedRequests(results, *focus, unobserved)
		validationErr = ordinaryFocusEventError(results, *focus, validationErr)
	}
	if facts.Joined {
		var failure *toolFailure
		if errors.As(runErr, &failure) && failure.overflow {
			facts.Events = "overflow"
		}
	} else {
		facts.Events, facts.RequestedNode = "unavailable", "unavailable"
	}
	if !facts.Started && focus != nil && len(focus.Tests) != 0 {
		facts.RequestedNode = "unavailable"
	}
	if facts.RequestedNode == "missing" && facts.Events != "valid" {
		facts.RequestedNode = "unavailable"
	}
	evidence.Tests = append(evidence.Tests, results...)
	return errors.Join(containTestFailure(parent, runErr, validationErr), parent.Err(), evidence.Diagnostics.append(facts))
}

type ordinaryPreparationFailure struct {
	Directory string   `json:"directory"`
	Patterns  []string `json:"patterns"`
	Inventory string   `json:"inventory"`
	Reason    string   `json:"reason"`
}
