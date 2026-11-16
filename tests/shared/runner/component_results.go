package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

const (
	maximumComponentInventory      = 4096
	maximumComponentTimings        = 4096
	maximumComponentSelectionBytes = 64 << 10
	// Saved rows may omit elapsed_seconds and still mean zero. A compact array
	// needs at least this shortest accepted name/outcome row and a separator
	// per entry; the enclosing record and newline only reduce the count.
	maximumComponentTests = records.MaximumJSONBytes / len(`{"name":"TestA","outcome":"passed"},`)
)

const (
	// The native Linux 128-record race check alone can exceed 30 minutes.
	componentGroupAllowance   time.Duration = 0
	componentCheckTimeout                   = 90 * time.Minute
	componentInventoryTimeout               = time.Minute
	maximumCapacityComponent                = "TestGeneratedMaximumSelectedSetFitsAccessReplacementOverlap"
	componentGroupCount                     = 4
)

// Each of these live-arena proofs needs a process with no preceding test history.
var ordinaryMemoryComponents = []string{
	"TestOutputConfigurationMaximumPolicyTransitionMemory",
	"TestOutputConfigurationMaximumRoutingTransitionMemory",
	"TestOutputConfigurationMaximumEqualSourceConversionMemory",
	"TestOutputConfigurationMaximumPreparationPreCanceledMemory",
	"TestOutputConfigurationMaximumLastConfigurationReadCanceledMemory",
	"TestOutputConfigurationMaximumLastLargeReadbackUnavailableMemory",
	"TestOutputConfigurationMaximumSigningRefusedMemory",
	"TestOutputConfigurationMaximumSelectionPreCanceledMemory",
	"TestOutputConfigurationMaximumSelectionUnknownWithEffectMemory",
	"TestOutputConfigurationMaximumSelectionUnknownWithoutEffectMemory",
	"TestOrdinaryOutputMemoryNativeArtifact",
	"TestOutputConfigurationGeneratedMaximumTransitionMemory",
}

// The first root proves the dependent helper/probe roots in each group.
// Share these finite source contracts between placement and retained proof.
var componentHelperProofGroups = [][]string{
	{"TestThreeGenerationHistoryAndStaleCandidate", "TestFreshProcessChild", "TestHermeticWorkerEntrypointsNeedExplicitInvocation"},
	{"TestScenarioPhaseRetainsFailureEvidence", "TestScenarioPhaseFailureChild"},
	{"TestWriterTerminationPreservesCompleteSelection", "TestWriterTerminationChild"},
}

type componentTest struct {
	Name            string                          `json:"name"`
	Outcome         string                          `json:"outcome"`
	ElapsedSeconds  float64                         `json:"elapsed_seconds"`
	ElapsedObserved *bool                           `json:"elapsed_observed,omitempty"`
	StartedAt       *time.Time                      `json:"started_at,omitempty"`
	FinishedAt      *time.Time                      `json:"finished_at,omitempty"`
	Relation        *retainedSecretMaterialRelation `json:"relation,omitempty"`
}

type componentGroupEvidence struct {
	Tests            []string `json:"tests"`
	Requests         []string `json:"requests,omitempty"`
	Selection        string   `json:"selection,omitempty"`
	Exclusive        bool     `json:"exclusive,omitempty"`
	Worker           int      `json:"worker,omitempty"`
	Name             string   `json:"name"`
	Outcome          string   `json:"outcome"`
	ElapsedSeconds   float64  `json:"elapsed_seconds"`
	EstimatedSeconds float64  `json:"estimated_seconds"`
	TestCount        int      `json:"test_count"`
}

type componentTiming struct {
	Test           string  `json:"test"`
	Phase          string  `json:"phase"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
}

func collectComponentNames(body []byte) ([]string, bool) {
	if len(body) > maximumToolOutputBytes {
		return nil, false
	}
	var names []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maximumToolOutputBytes)
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" {
			continue
		}
		if !validComponentName(name) || strings.Contains(name, "/") || seen[name] || len(names) >= maximumComponentInventory {
			return names, false
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, len(names) != 0 && scanner.Err() == nil
}

func collectComponentTimings(body []byte, tests []componentTest) ([]componentTiming, bool) {
	if len(body) > maximumToolOutputBytes || len(tests) > maximumComponentTests {
		return nil, false
	}
	observed := make(map[string]bool, len(tests))
	for _, test := range tests {
		observed[test.Name] = true
	}
	var timings []componentTiming
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maximumToolOutputBytes)
	for scanner.Scan() {
		_, marker, found := strings.Cut(scanner.Text(), "capacity-timing ")
		if !found {
			continue
		}
		fields := strings.Fields(marker)
		if len(fields) != 3 || len(timings) >= maximumComponentTimings {
			return timings, false
		}
		name, hasName := strings.CutPrefix(fields[0], "test=")
		phase, hasPhase := strings.CutPrefix(fields[1], "phase=")
		duration, hasDuration := strings.CutPrefix(fields[2], "elapsed=")
		elapsed, err := time.ParseDuration(duration)
		if !hasName || !hasPhase || !hasDuration || !validComponentName(name) || !observed[name] ||
			phase != "fixture" && phase != "operation" && phase != "fresh-child" || err != nil || elapsed < 0 {
			return timings, false
		}
		timings = append(timings, componentTiming{Test: name, Phase: phase, ElapsedSeconds: elapsed.Seconds()})
	}
	return timings, scanner.Err() == nil
}

type componentGroup struct {
	Worker           int
	Requests         []string
	Selection        string
	Name             string
	Tests            []string
	EstimatedSeconds float64
	Exclusive        bool
}

func selectComponentInventory(names []string, classifications []testClassification, profile string) (selected, notSelected []string, err error) {
	if profile != "full" && profile != "dev" {
		return nil, nil, errors.New("unknown component profile")
	}
	if len(names) == 0 || len(names) > maximumComponentInventory {
		return nil, nil, errors.New("component inventory is empty or exceeds its bound")
	}
	eligible, _, classificationErr := selectClassifiedTests(names, classifications, profile)
	if classificationErr != nil {
		return nil, nil, classificationErr
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !validComponentName(name) || strings.Contains(name, "/") || seen[name] {
			return nil, nil, errors.New("component inventory contains an invalid or repeated top-level test")
		}
		seen[name] = true

		if !slices.Contains(eligible, name) {
			notSelected = append(notSelected, name)
			continue
		}

		selected = append(selected, name)
	}
	if len(selected) == 0 {
		return nil, notSelected, errors.New("component profile selects no tests")
	}
	return selected, notSelected, nil
}

func componentGroupsForProfile(names []string, classifications []testClassification, profile string, parallel int, estimates map[string]float64) ([]componentGroup, error) {
	if len(names) == 0 || len(names) > maximumComponentInventory || parallel < 1 || parallel > componentGroupCount {
		return nil, errors.New("component grouping requires a bounded selected inventory and parallel allowance")
	}
	_, omitted, err := selectClassifiedTests(names, classifications, profile)
	if err != nil || len(omitted) != 0 {
		return nil, errors.Join(errors.New("component grouping requires explicit selected classifications"), err)
	}
	selected, exclusive := map[string]bool{}, map[string]bool{}
	for index, name := range names {
		if !validComponentName(name) || strings.Contains(name, "/") {
			return nil, errors.New("component grouping requires a valid selected inventory")
		}
		selected[name], exclusive[name] = true, classifications[index].Exclusive
	}
	var groups []componentGroup
	for _, name := range ordinaryMemoryComponents {
		if selected[name] {
			groups = append(groups, componentGroup{Name: "memory-" + strings.ToLower(name), Tests: []string{name}, EstimatedSeconds: testEstimate(estimates, name), Exclusive: true})
			delete(selected, name)
		}
	}
	for _, bundle := range componentHelperProofGroups {
		required := false
		for _, name := range bundle[1:] {
			required = required || selected[name]
		}
		if !required {
			continue
		}
		needsExclusive := false
		for _, name := range bundle {
			needsExclusive = needsExclusive || selected[name] && exclusive[name]
		}
		if needsExclusive {
			for _, name := range bundle {
				if selected[name] {
					exclusive[name] = true
				}
			}
		}
	}
	sharedExclusive := componentGroup{Name: "exclusive", Exclusive: true}
	var normalNames []string
	for _, name := range names {
		if selected[name] {
			normalNames = append(normalNames, name)
		}
	}
	var bundles [][]string
	for _, bundle := range componentRootBundles(normalNames) {
		if exclusive[bundle[0]] {
			sharedExclusive.Tests = append(sharedExclusive.Tests, bundle...)
		} else {
			bundles = append(bundles, bundle)
		}
	}
	items := make([]normalPlacementItem, len(bundles))
	for i, bundle := range bundles {
		items[i].key = strings.Join(bundle, "\x00")
		for _, name := range bundle {
			items[i].estimatedSeconds += testEstimate(estimates, name)
		}
	}
	var normal []componentGroup
	for worker, indices := range normalPlacement(items, parallel) {
		group := componentGroup{Name: fmt.Sprintf("ordinary-%d", worker+1), Worker: worker + 1}
		for _, index := range indices {
			group.Tests = append(group.Tests, bundles[index]...)
			group.EstimatedSeconds += items[index].estimatedSeconds
		}
		slices.Sort(group.Tests)
		normal = append(normal, group)
	}
	groups = append(normal, groups...)
	if len(sharedExclusive.Tests) != 0 {
		slices.Sort(sharedExclusive.Tests)
		for _, name := range sharedExclusive.Tests {
			sharedExclusive.EstimatedSeconds += testEstimate(estimates, name)
		}
		groups = append(groups, sharedExclusive)
	}
	return groups, nil
}

func componentRootBundles(names []string) [][]string {
	selected, assigned := map[string]bool{}, map[string]bool{}
	for _, name := range names {
		selected[name] = true
	}
	var bundles [][]string
	for _, name := range names {
		if assigned[name] {
			continue
		}
		bundle := []string{name}
		for _, required := range componentHelperProofGroups {
			if slices.Contains(required, name) {
				bundle = nil
				for _, member := range required {
					if selected[member] {
						bundle = append(bundle, member)
					}
				}
				break
			}
		}
		slices.Sort(bundle)
		for _, member := range bundle {
			assigned[member] = true
		}
		bundles = append(bundles, bundle)
	}
	return bundles
}

func partitionComponentGroups(inventory []string, groups []componentGroup, estimates map[string]float64) ([]componentGroup, error) {
	var result []componentGroup
	for _, group := range groups {
		if _, err := componentGroupSelections(inventory, []componentGroup{group}, false); err == nil {
			result = append(result, group)
			continue
		} else if group.Exclusive {
			return nil, err
		}
		// A worker's complete selection can exceed both native encodings after
		// placement. Split only its physical filters, keeping helper bundles
		// and worker ownership intact.
		part := componentGroup{Worker: group.Worker}
		ordinal := 0
		flush := func() {
			ordinal++
			part.Name = fmt.Sprintf("%s-part-%d", group.Name, ordinal)
			result = append(result, part)
			part = componentGroup{Worker: group.Worker}
		}
		for _, bundle := range componentRootBundles(group.Tests) {
			candidate := append(slices.Clone(part.Tests), bundle...)
			if _, err := componentSelection(candidate); err != nil {
				if len(part.Tests) == 0 {
					return nil, err
				}
				flush()
				if _, err := componentSelection(bundle); err != nil {
					return nil, err
				}
			}
			part.Tests = append(part.Tests, bundle...)
			for _, name := range bundle {
				part.EstimatedSeconds += testEstimate(estimates, name)
			}
		}
		if len(part.Tests) != 0 {
			flush()
		}
	}
	return result, nil
}

func componentEstimate(name string) float64 {
	return testEstimate(componentEstimates, name)
}

func componentSelection(names []string) (string, error) {
	if len(names) == 0 {
		return "", errors.New("component group is empty")
	}
	parts := make([]string, len(names))
	for index, name := range names {
		if !validComponentName(name) || strings.Contains(name, "/") {
			return "", errors.New("component group contains an invalid top-level test")
		}
		parts[index] = regexp.QuoteMeta(name)
	}
	selection := "^(" + strings.Join(parts, "|") + ")$"
	if len(selection) > maximumComponentSelectionBytes {
		return "", errors.New("component group selection exceeds its bound")
	}
	return selection, nil
}

type componentProcessSelection struct{ run, skip string }

func componentGroupSelections(inventory []string, groups []componentGroup, focused bool) ([]componentProcessSelection, error) {
	if len(inventory) == 0 || len(inventory) > maximumComponentInventory {
		return nil, errors.New("component process selection requires its bounded compiled inventory")
	}
	known := make(map[string]bool, len(inventory))
	for _, name := range inventory {
		if !validComponentName(name) || strings.Contains(name, "/") || known[name] {
			return nil, errors.New("component process selection has invalid or duplicate compiled roots")
		}
		known[name] = true
	}
	assigned := make(map[string]bool, len(inventory))
	selections := make([]componentProcessSelection, 0, len(groups))
	for _, group := range groups {
		selected := make(map[string]bool, len(group.Tests))
		for _, name := range group.Tests {
			if !known[name] || selected[name] || !focused && assigned[name] {
				return nil, errors.New("component process selection contains unknown or duplicate assigned roots")
			}
			selected[name], assigned[name] = true, true
		}
		if focused {
			if len(selected) == 0 || group.Selection == "" || len(group.Selection) > maximumComponentSelectionBytes {
				return nil, errors.New("component literal process selection exceeds its bound or is empty")
			}
			selections = append(selections, componentProcessSelection{run: group.Selection})
			continue
		}
		run, err := componentSelection(group.Tests)
		if err == nil {
			selections = append(selections, componentProcessSelection{run: run})
			continue
		}
		if len(selected) == 0 {
			return nil, err
		}
		// The complement includes every other compiled root, including roots
		// already executed in a memory process and roots excluded by profile.
		var excluded []string
		for _, name := range inventory {
			if !selected[name] {
				excluded = append(excluded, name)
			}
		}
		run, skip := `^Test[A-Za-z0-9_]+$`, ""
		if len(excluded) != 0 {
			skip, err = componentSelection(excluded)
			if err != nil {
				return nil, err
			}
		}
		if len(run)+len(skip) > maximumComponentSelectionBytes {
			return nil, errors.New("component process run and skip selection exceeds its bound")
		}
		selections = append(selections, componentProcessSelection{run: run, skip: skip})
	}
	return selections, nil
}

func componentEvidenceMatchesInventory(names []string, tests []componentTest) bool {
	if len(names) == 0 || len(names) > maximumComponentInventory || len(tests) == 0 || len(tests) > maximumComponentTests {
		return false
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		if !validComponentName(name) || strings.Contains(name, "/") {
			return false
		}
		if _, exists := wanted[name]; exists {
			return false
		}
		wanted[name] = false
	}
	observed := make(map[string]bool, len(tests))
	for _, test := range tests {
		if !validComponentName(test.Name) || observed[test.Name] {
			return false
		}
		observed[test.Name] = true
		top, _, subtest := strings.Cut(test.Name, "/")
		seen, known := wanted[top]
		if !known || !subtest && seen {
			return false
		}
		if !subtest {
			wanted[top] = true
		}
	}
	for _, seen := range wanted {
		if !seen {
			return false
		}
	}
	return true
}

func selectedComponentEvidence(checks checkEvidence, suite string) ([]string, bool) {
	if suite == "live" {
		if checks.AssemblyNeutral == nil {
			return nil, false
		}
		selected, err := liveAssemblyCheckNames(checks.CompiledInventory, checks.AssemblySources, checks.Classifications, checks.Profile, *checks.AssemblyNeutral)
		omitted := slices.DeleteFunc(slices.Clone(checks.CompiledInventory), func(name string) bool { return slices.Contains(selected, name) })
		selection, selectionErr := componentSelection(selected)
		return selected, err == nil && selectionErr == nil && slices.Equal(selected, checks.Inventory) && selection == checks.Selection && slices.Equal(omitted, checks.NotSelected)
	}
	if suite != "hermetic" {
		return nil, false
	}
	selected, notSelected, err := selectComponentInventory(checks.Inventory, checks.Classifications, checks.Profile)
	if err != nil || !slices.Equal(notSelected, checks.NotSelected) {
		return nil, false
	}
	if checks.Profile == "full" && !slices.Contains(selected, maximumCapacityComponent) {
		return nil, false
	}
	return selected, true
}

func executeComponentInventory(parent context.Context, root, binary string, environment []string) (processResult, []string, *limitedOutput, *limitedOutput) {
	ctx, cancel := context.WithTimeout(parent, componentInventoryTimeout)
	defer cancel()
	command := exec.Command(binary, "-test.list=^Test")
	command.Dir, command.Env = root, environment
	stdout, stderr := &limitedOutput{}, &limitedOutput{}
	command.Stdout, command.Stderr = stdout, stderr
	process := superviseProcess(ctx, command)
	var names []string
	complete := false
	if process.Joined {
		names, complete = collectComponentNames(stdout.Bytes())
		if stdout.overflow || stderr.overflow {
			if process.Status == "passed" {
				process.Status = "output_limit_exceeded"
			}
			process.Cause = errors.Join(process.Cause, errors.New("component inventory output exceeds its bound"))
		} else if process.Status == "passed" && !complete {
			process.Status = "process_failed"
			process.Cause = errors.New("component inventory is incomplete")
		}
	}
	return process, names, stdout, stderr
}

func appendComponentCapture(destination *limitedOutput, phase string, source *limitedOutput) {
	_, _ = fmt.Fprintf(destination, "Phase: %s\n", phase)
	_, _ = destination.Write(source.Bytes())
	if source.overflow {
		destination.overflow = true
	}
}

// Capture actual assertion and failure-frame bytes during the existing decode.
// Passing output cannot displace these private bytes or change public statuses.
func (b *limitedOutput) capturePrivateComponentError(event ordinaryEvent) {
	if event.Action != "output" || event.OutputType != "error" &&
		(event.OutputType != "frame" || !strings.HasPrefix(strings.TrimSpace(event.Output), "--- FAIL: ")) {
		return
	}
	const limit = assemblyDiagnosticOutputLimit
	if b.privateErrorOutput == nil {
		b.privateErrorOutput = make([]byte, 0, limit)
	}
	for _, part := range []string{"[" + event.Package + " " + event.Test + "] ", event.Output} {
		if len(part) >= limit {
			b.privateErrorOutput = append(b.privateErrorOutput[:0], part[len(part)-limit:]...)
			b.privateErrorStart = 0
			b.privateErrorOverflow = true
			continue
		}
		if len(b.privateErrorOutput) < limit {
			n := min(len(part), limit-len(b.privateErrorOutput))
			b.privateErrorOutput = append(b.privateErrorOutput, part[:n]...)
			part = part[n:]
		}
		if len(part) == 0 {
			continue
		}
		b.privateErrorOverflow = true
		n := copy(b.privateErrorOutput[b.privateErrorStart:], part)
		copy(b.privateErrorOutput, part[n:])
		b.privateErrorStart = (b.privateErrorStart + len(part)) % limit
	}
}

// Give each failed group's actual errors their final diagnostic share before
// raw context. Later passing output cannot displace a retained assertion.
func appendFailedComponentCapture(destination *limitedOutput, phase string, source *limitedOutput, allowance int) {
	if allowance < componentCaptureMinimum(phase) {
		destination.overflow = true
		if allowance > 0 {
			heading := fmt.Sprintf("Failed phase: %s (capture capacity unavailable)\n", phase)
			_, _ = destination.Write([]byte(heading[:min(len(heading), allowance)]))
		}
		return
	}
	heading := fmt.Sprintf("Failed phase: %s (upstream truncated: %t)\n", phase, source.overflow)
	_, _ = io.WriteString(destination, heading)
	available := allowance - len(heading)
	if len(source.privateErrorOutput) != 0 {
		errorAllowance := available / 2
		bodyLimit := errorAllowance - len("Private assertion output (truncated: false):\n")
		truncated := source.privateErrorOverflow || len(source.privateErrorOutput) > bodyLimit
		errorHeading := fmt.Sprintf("Private assertion output (truncated: %t):\n", truncated)
		body := source.privateErrorOutput
		if source.privateErrorStart != 0 {
			body = make([]byte, len(source.privateErrorOutput))
			n := copy(body, source.privateErrorOutput[source.privateErrorStart:])
			copy(body[n:], source.privateErrorOutput[:source.privateErrorStart])
		}
		if len(body) > bodyLimit {
			body = body[len(body)-bodyLimit:]
		}
		_, _ = io.WriteString(destination, errorHeading)
		_, _ = destination.Write(body)
		available -= len(errorHeading) + len(body)
	}
	const rawHeading = "Raw capture prefix:\n"
	_, _ = io.WriteString(destination, rawHeading)
	available -= len(rawHeading)
	body := source.Bytes()
	if len(body) <= available {
		_, _ = destination.Write(body)
	} else {
		const omitted = "\nRaw capture middle omitted: true\nRaw capture tail:\n"
		available -= len(omitted)
		prefix := available / 2
		_, _ = destination.Write(body[:prefix])
		_, _ = io.WriteString(destination, omitted)
		_, _ = destination.Write(body[len(body)-(available-prefix):])
	}
	if source.overflow {
		destination.overflow = true
	}
}

func componentPhaseFailure(phase string, process processResult) processResult {
	if process.Status != "passed" {
		if process.Cause == nil {
			process.Cause = errors.New("component process failed without a cause")
		}
		process.Cause = fmt.Errorf("component phase %s: %w", phase, process.Cause)
	}
	return process
}

func componentOutputFailure(process processResult, err error) processResult {
	process.Status = "process_failed"
	process.Cause = errors.Join(process.Cause, fmt.Errorf("component progress output: %w", err))
	return process
}

func executeProfileComponentChecks(initial *checkDiagnostics, parent context.Context, root, binary string, converter preparedTestEventConverter, buildFlags, environment []string, profile string, requested []string, parallelism int, output io.Writer, owner *assembly) (process processResult, evidence checkEvidence, stdout, stderr *limitedOutput) {
	barrier := repetitionBarrierFromContext(parent, nil)
	defer func() {
		if barrier != nil && (!process.Joined || process.Status != "passed" && !containedCheckFailure(parent, process.Cause)) {
			barrier.stopped.Store(true)
		}
	}()

	started := time.Now()
	if output == nil {
		output = io.Discard
	}
	defer func() {
		if evidence.Diagnostics != nil && evidence.Diagnostics.Preparation == "pending" && process.Status != "passed" {
			evidence.Diagnostics.Preparation = "failed"
		}
		if err := writeSlowestComponentTests(output, evidence.Tests); err != nil {
			process = componentOutputFailure(process, err)
		}
		evidence.Outcome = process.Status
		evidence.ElapsedSeconds = time.Since(started).Seconds()
	}()
	stdout, stderr = &limitedOutput{}, &limitedOutput{}
	evidence.Profile, evidence.Race, evidence.RaceOptions = profile, raceEnabled(parent), acceptedRaceOptions(raceEnabled(parent))
	evidence.EventTimeSource = "post_join_test2json"
	evidence.Diagnostics = initial
	if evidence.Diagnostics == nil {
		evidence.Diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	if len(requested) != 0 {
		evidence.Focus = &componentFocus{Tests: slices.Clone(requested), Package: componentPackage}
	}
	evidence.Parallelism = parallelism
	if owner != nil && owner.componentSelection != nil {
		sourceOwner, key := owner.preparationOwner, owner.preparationKey
		if sourceOwner == nil {
			sourceOwner = owner.componentSelection
			key = profile + "\x00" + strings.Join(requested, "\x00")
		}
		if err := evidence.Diagnostics.retainAcquisition(sourceOwner, key, owner.componentSelection.evidence.Diagnostics); err != nil {
			return processResult{Status: "process_failed", Joined: true, Cause: err}, evidence, stdout, stderr
		}
	}
	ownPlan := !evidence.Diagnostics.hasPlan()
	if ownPlan {
		future, err := componentEntryCommands(owner, converter)
		if err != nil {
			return processResult{Status: "process_failed", Joined: true, Cause: err}, evidence, stdout, stderr
		}
		if err := evidence.Diagnostics.reserveCommands(future); err != nil {
			return processResult{Status: "process_failed", Joined: true, Cause: err}, evidence, stdout, stderr
		}
		defer evidence.Diagnostics.cancelReservations()
	}

	if owner != nil {
		if owner.Closure.Race != raceEnabled(parent) {
			return processResult{Status: "process_failed", Joined: true, Cause: errors.New("component race policy differs from assembly")}, evidence, stdout, stderr
		}
		if err := checkAssemblyRace(parent, *owner); err != nil {
			return processResult{Status: "process_failed", Joined: true, Cause: err}, evidence, stdout, stderr
		}
	}
	if profile != "full" && profile != "dev" {
		process.Status, process.Cause = "process_failed", errors.New("unknown component profile")
		return process, evidence, stdout, stderr
	}
	if parallelism < 1 || parallelism > componentGroupCount {
		process.Status, process.Cause = "process_failed", errors.New("component parallelism is outside the group bound")
		return process, evidence, stdout, stderr
	}
	if _, err := fmt.Fprintf(output, "components (%s): inventory\n", profile); err != nil {
		return componentOutputFailure(process, err), evidence, stdout, stderr
	}
	if err := checkProgress(output, "preparation", "inventory"); err != nil {
		return componentOutputFailure(process, err), evidence, stdout, stderr
	}
	if owner != nil {
		if err := checkAssemblyRace(parent, *owner); err != nil {
			return processResult{Status: "process_failed", Joined: toolCommandsJoined(err), Cause: err}, evidence, stdout, stderr
		}
	}
	prepared := (*preparedComponentChecks)(nil)
	if owner != nil {
		prepared = owner.componentSelection
	}
	sharedPreparation := prepared != nil
	if prepared == nil {
		var prepareErr error
		prepared, evidence.Diagnostics, prepareErr = prepareComponentChecks(evidence.Diagnostics, parent, root, binary, buildFlags, environment, profile, requested, owner)
		if prepareErr != nil {
			process.Status, process.Cause, process.Joined = "process_failed", prepareErr, toolCommandsJoined(prepareErr)
			return process, evidence, stdout, stderr
		}
	}
	if prepared.profile != profile || !slices.Equal(prepared.requested, requested) {
		return processResult{Status: "process_failed", Joined: true, Cause: errors.New("component prepared selection changed")}, evidence, stdout, stderr
	}
	if barrier == nil {
		barrier = &prepared.dispatch
	}
	currentDiagnostics := evidence.Diagnostics
	evidence = prepared.evidenceCopy()
	evidence.Diagnostics = currentDiagnostics
	if !sharedPreparation && converter.preparation != nil && (owner == nil || !owner.converterRecorded) {
		if err := evidence.Diagnostics.consumeCommands([]checkCommandFacts{preparationReservationFact("test2json", true)}); err != nil {
			return processResult{Status: "process_failed", Joined: true, Cause: err}, evidence, stdout, stderr
		}
		if err := evidence.Diagnostics.append(*converter.preparation); err != nil {
			return processResult{Status: "process_failed", Joined: true, Cause: err}, evidence, stdout, stderr
		}
	}
	evidence.Parallelism = parallelism
	selected, _, groups, focus, placementErr := resolveComponentGroups(evidence.Inventory, evidence.Classifications, profile, requested, parallelism, prepared.estimates)
	if placementErr != nil {
		evidence.Diagnostics.Preparation = "failed"
		return processResult{Status: "process_failed", Joined: true, Cause: placementErr}, evidence, stdout, stderr
	}
	phaseOut, phaseErr := prepared.stdout, prepared.stderr
	selections, selectionErr := componentGroupSelections(evidence.Inventory, groups, focus != nil)
	if selectionErr != nil {
		evidence.Diagnostics.Preparation = "failed"
		return processResult{Status: "process_failed", Joined: true, Cause: selectionErr}, evidence, stdout, stderr
	}
	process = processResult{Status: "passed", Joined: true}
	// Every started group retains one test and one conversion command. Refuse
	// an oversized plan before dispatch rather than execute work without room
	// for all command joins, events and cleanup facts.
	if err := reserveComponentVerificationCommands(evidence.Diagnostics, nil, groups, owner); err != nil {
		evidence.Diagnostics.Preparation = "failed"
		process.Status, process.Cause = "process_failed", err
		return
	}
	if _, err := componentCaptureShare(groups); err != nil {
		evidence.Diagnostics.Preparation = "failed"
		process.Status, process.Cause = "process_failed", err
		return
	}
	evidence.Diagnostics.Preparation = "passed"
	if focus != nil {
		evidence.Focus = focus
		selected = requestedTestRoots(requested)
		evidence.Selection = "literal requested test paths in exact process groups"
		if len(groups) == 1 {
			evidence.Selection = groups[0].Selection
		}
		if _, err := fmt.Fprintf(output, "components: requested tests %v; parent setup and suffix assertions remain required\n", requested); err != nil {
			return componentOutputFailure(process, err), evidence, stdout, stderr
		}
	}
	if _, err := fmt.Fprintf(output, "components (%s): %d selected, %d not selected; %d groups, parallelism %d\n", profile, len(selected), len(evidence.NotSelected), len(groups), parallelism); err != nil {
		return componentOutputFailure(process, err), evidence, stdout, stderr
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	type groupResult struct {
		index          int
		terminated     bool
		process        processResult
		evidence       checkEvidence
		stdout, stderr *limitedOutput
	}
	results := make(chan groupResult, parallelism)
	completed := make([]*groupResult, len(groups))
	dispatched := make([]bool, len(groups))
	next, active := 0, 0
	exclusiveActive, packageStopped := false, false
	activeWorkers := map[int]bool{}
	for next < len(groups) || active != 0 {
		for next < len(groups) && active < parallelism && !exclusiveActive && !packageStopped && ctx.Err() == nil {
			dispatch := next
			for dispatch < len(groups) && !groups[dispatch].Exclusive && (dispatched[dispatch] || activeWorkers[groups[dispatch].Worker]) {
				dispatch++
			}
			if dispatch == len(groups) || groups[dispatch].Exclusive && (dispatch != next || active != 0) {
				break
			}
			group := groups[dispatch]
			selection := selections[dispatch]
			if _, err := fmt.Fprintf(output, "components (%s): starting group %s (%d tests, estimated %.0fs)\n", profile, group.Name, len(group.Tests), group.EstimatedSeconds); err != nil {
				process = componentOutputFailure(process, err)
				cancel()
				break
			}
			if err := checkProgress(output, "test", group.Name); err != nil {
				process = componentOutputFailure(process, err)
				cancel()
				break
			}
			if owner != nil {
				if err := checkAssemblyRace(ctx, *owner); err != nil {
					if ctx.Err() != nil {
						reservationErr := evidence.Diagnostics.consumeCommands([]checkCommandFacts{componentReservationFact("test", group.Name), componentReservationFact("conversion", group.Name)})
						refused := recordTestDispatchFailure(evidence.Diagnostics, group.Name, strings.Join(group.Requests, ", "), errors.Join(ctx.Err(), reservationErr), 0)
						process.Status, process.Cause = refused.Status, errors.Join(process.Cause, refused.Cause)
						process.Joined = process.Joined && refused.Joined
					} else {
						process.Status, process.Cause = "process_failed", errors.Join(process.Cause, err)
						process.Joined = process.Joined && toolCommandsJoined(err)
						evidence.Diagnostics.Preparation = "failed"
					}
					cancel()
					break
				}
			}
			if err := evidence.Diagnostics.consumeCommands([]checkCommandFacts{componentReservationFact("test", group.Name), componentReservationFact("conversion", group.Name)}); err != nil {
				process.Status, process.Cause = "process_failed", errors.Join(process.Cause, err)
				cancel()
				break
			}
			go func(index int, selection componentProcessSelection) {
				started := time.Now()
				leave, waitErr := barrier.enter(ctx, groups[index].Exclusive)
				if waitErr != nil {
					cancel()
					e := checkEvidence{Selection: selection.run, Diagnostics: &checkDiagnostics{Preparation: "passed"}}
					p := recordTestDispatchFailure(e.Diagnostics, componentPackage, strings.Join(groups[index].Requests, ", "), waitErr, time.Since(started))
					e.Outcome, e.ElapsedSeconds = p.Status, time.Since(started).Seconds()
					results <- groupResult{index: index, process: p, evidence: e, stdout: &limitedOutput{}, stderr: &limitedOutput{}}
					return
				}
				safeToContinue := false
				defer func() { leave(safeToContinue) }()
				child, admissionErr := admitTestExecution(ctx, groups[index].Exclusive)
				if admissionErr != nil {
					cancel()
					e := checkEvidence{Selection: selection.run, Diagnostics: &checkDiagnostics{Preparation: "passed"}}
					p := recordTestDispatchFailure(e.Diagnostics, componentPackage, strings.Join(groups[index].Requests, ", "), admissionErr, time.Since(started))
					e.Outcome, e.ElapsedSeconds = p.Status, time.Since(started).Seconds()
					results <- groupResult{index: index, process: p, evidence: e, stdout: &limitedOutput{}, stderr: &limitedOutput{}}
					return
				}
				p, e, out, errOut := executeComponentNativeChecks(withExecutionParallel(child, 1), root, binary, converter, selection, groups[index].Tests, environment)
				if focus != nil && e.Diagnostics != nil {
					for i := range e.Diagnostics.Commands {
						if e.Diagnostics.Commands[i].Phase == "test" {
							e.Diagnostics.Commands[i].RequestedNode = componentRequestedNodes(e.Tests, groups[index].Requests, p, e.Diagnostics)
						}
					}
				}
				if focus != nil && p.Status == "passed" && !completeRequestedComponentTerminals(groups[index].Requests, e.Tests) {
					p.Status = "process_failed"
					p.Cause = containTestFailure(parent, nil, errors.New("component selection lacks its exact requested terminals"))
					e.Outcome, e.TestsComplete = p.Status, false
				}
				if p.Status == "passed" && p.Joined && !componentEvidenceMatchesInventory(groups[index].Tests, e.Tests) {
					p.Status, p.Cause = "process_failed", errors.New("component group evidence does not match its assigned inventory")
					e.Outcome, e.TestsComplete = p.Status, false
				}

				safeToContinue = p.Joined && (p.Status == "passed" || containedCheckFailure(parent, p.Cause))
				if !safeToContinue {
					barrier.stopped.Store(true)
					cancel()
				}
				terminated := packageProcessTerminated(p)
				for _, test := range e.Tests {
					terminated = terminated || test.Outcome == "incomplete" || test.Outcome == "not_run"
				}
				results <- groupResult{index: index, terminated: terminated, process: p, evidence: e, stdout: out, stderr: errOut}
			}(dispatch, selection)
			dispatched[dispatch] = true
			for next < len(groups) && dispatched[next] {
				next++
			}
			active++
			exclusiveActive = group.Exclusive
			activeWorkers[group.Worker] = true
		}
		if active == 0 {
			break
		}
		result := <-results
		active--
		completed[result.index] = &result
		packageStopped = packageStopped || result.terminated
		group := groups[result.index]
		delete(activeWorkers, group.Worker)
		if group.Exclusive {
			exclusiveActive = false
		}
		phaseProcess := componentPhaseFailure(group.Name, result.process)
		process.Started = process.Started || phaseProcess.Started
		process.Joined = process.Joined && phaseProcess.Joined
		if phaseProcess.Status != "passed" && (process.Status == "passed" || process.Status == "interrupted") {
			process.Status = phaseProcess.Status
		}
		if _, err := fmt.Fprintf(output, "components (%s): group %s %s in %.2fs\n", profile, group.Name, phaseProcess.Status, result.evidence.ElapsedSeconds); err != nil {
			process = componentOutputFailure(process, err)
			cancel()
		}
	}
	failedGroups := 0
	for _, result := range completed {
		if result != nil && result.process.Joined && result.process.Status != "passed" {
			failedGroups++
		}
	}
	if failedGroups != 0 {
		// The actual group plan was checked before dispatch. Fewer failed groups
		// can only increase the safe capture share.
		allowance := assemblyDiagnosticOutputLimit / failedGroups
		stdout.buffer.Reset()
		stderr.buffer.Reset()
		for index, result := range completed {
			if result != nil && result.process.Joined && result.process.Status != "passed" {
				appendFailedComponentCapture(stdout, groups[index].Name, result.stdout, allowance)
				appendFailedComponentCapture(stderr, groups[index].Name, result.stderr, allowance)
			}
		}
		appendComponentCapture(stdout, "inventory", phaseOut)
		appendComponentCapture(stderr, "inventory", phaseErr)
	}
	// Fold results in planned order. Only this goroutine writes shared progress,
	// evidence and capture buffers, and all started workers have returned.
	var failures []error
	for index, result := range completed {
		group := groups[index]
		if result == nil {
			paths := group.Tests
			if len(group.Requests) != 0 {
				paths = group.Requests
			}
			for _, path := range paths {
				observed := false
				evidence.Tests = append(evidence.Tests, componentTest{Name: path, Outcome: "not_run", ElapsedObserved: &observed})
			}
			evidence.Groups = append(evidence.Groups, componentGroupResult(group, "not_run", 0))
			continue
		}
		if cause := componentPhaseFailure(group.Name, result.process).Cause; cause != nil {
			failures = append(failures, cause)
		}
		if result.process.Joined {
			appendComponentCapture(stdout, group.Name, result.stdout)
			appendComponentCapture(stderr, group.Name, result.stderr)
		}
		evidence.Tests = append(evidence.Tests, result.evidence.Tests...)
		evidence.Timings = append(evidence.Timings, result.evidence.Timings...)
		if result.evidence.Diagnostics != nil {
			for _, facts := range result.evidence.Diagnostics.Commands {
				facts.Scope = group.Name
				if err := evidence.Diagnostics.append(facts); err != nil {
					process.Status = "process_failed"
					failures = append(failures, err)
				}
			}
		}
		evidence.Groups = append(evidence.Groups, componentGroupResult(group, result.process.Status, result.evidence.ElapsedSeconds))
	}
	process.Cause = errors.Join(append(failures, process.Cause)...)
	if !process.Joined {
		process.Status = "group_stop_failed"
	} else if process.Status == "passed" && ctx.Err() != nil {
		process.Status, process.Cause = processContextStatus(ctx.Err()), errors.Join(process.Cause, ctx.Err())
	}
	if process.Status != "passed" {
		return process, evidence, stdout, stderr
	}
	if stdout.overflow || stderr.overflow || len(evidence.Timings) > maximumComponentTimings || (focus == nil && !componentEvidenceMatchesInventory(selected, evidence.Tests) || focus != nil && !completeRequestedComponentTerminals(focus.Tests, evidence.Tests)) {
		process.Status = "process_failed"
		process.Cause = errors.New("partitioned component test evidence is incomplete")
		evidence.Outcome = process.Status
		return process, evidence, stdout, stderr
	}
	process = processResult{Status: "passed", Started: true, Joined: true}
	evidence.Outcome, evidence.TestsComplete = process.Status, true
	if focus == nil && hasUnavailableClassifications(evidence.Classifications) {
		process.Status, process.Cause = "process_failed", &localCheckFailure{cause: errors.New("compiled test classification is unavailable; complete profile cannot be reported")}
		evidence.Outcome, evidence.TestsComplete = process.Status, false
	}
	if focus != nil && !completeFocusedComponentEvidence(evidence) {
		process.Status, process.Cause = "process_failed", errors.New("focused component evidence lacks the exact passing node or required child proof")
		evidence.Outcome, evidence.TestsComplete = process.Status, false
	}
	return process, evidence, stdout, stderr
}

func writeSlowestComponentTests(output io.Writer, tests []componentTest) error {
	var topLevel []componentTest
	for _, test := range tests {
		if !strings.Contains(test.Name, "/") {
			topLevel = append(topLevel, test)
		}
	}
	sort.Slice(topLevel, func(i, j int) bool {
		_, leftKnown := componentElapsed(topLevel[i])
		_, rightKnown := componentElapsed(topLevel[j])
		if leftKnown != rightKnown {
			return leftKnown
		}
		if !leftKnown {
			return topLevel[i].Name < topLevel[j].Name
		}
		if topLevel[i].ElapsedSeconds == topLevel[j].ElapsedSeconds {
			return topLevel[i].Name < topLevel[j].Name
		}
		return topLevel[i].ElapsedSeconds > topLevel[j].ElapsedSeconds
	})
	if len(topLevel) != 0 {
		if _, err := fmt.Fprintln(output, "components: slowest top-level tests (durations include subtests)"); err != nil {
			return err
		}
	}
	for _, test := range topLevel[:min(len(topLevel), 5)] {
		duration := "unknown"
		if elapsed, known := componentElapsed(test); known {
			duration = fmt.Sprintf("%.2fs", elapsed)
		}
		if _, err := fmt.Fprintf(output, "  %s: %s (%s)\n", test.Name, duration, test.Outcome); err != nil {
			return err
		}
	}
	return nil
}

func executeComponentChecks(parent context.Context, root, binary string, eventConverter preparedTestEventConverter, selection string, names, environment []string) (processResult, checkEvidence, *limitedOutput, *limitedOutput) {
	return executeComponentNativeChecks(parent, root, binary, eventConverter, componentProcessSelection{run: selection}, names, environment)
}

func executeComponentNativeChecks(parent context.Context, root, binary string, eventConverter preparedTestEventConverter, selection componentProcessSelection, names, environment []string) (processResult, checkEvidence, *limitedOutput, *limitedOutput) {
	started := time.Now()
	stdout, stderr := &limitedOutput{}, &limitedOutput{}
	evidence := checkEvidence{Outcome: "process_failed", Selection: selection.run, EventTimeSource: "post_join_test2json", Diagnostics: &checkDiagnostics{Preparation: "passed"}}
	state, err := newTestEventState(map[string][]string{componentPackage: names}, maximumComponentTests, validComponentName, nil)
	if err != nil || len(names) > maximumComponentInventory {
		evidence.Diagnostics.Preparation = "failed"
		return processResult{Status: "process_failed", Joined: true, Cause: errors.Join(err, errors.New("component event inventory refused"))}, evidence, stdout, stderr
	}
	allowances := make(map[string]time.Duration, len(names))
	for _, name := range names {
		allowances[name] = componentCheckTimeout
	}
	deadline, deadlineErr := newNativeTestDeadline(parent, allowances, componentCheckTimeout, stdout)
	if deadlineErr != nil {
		return processResult{Status: "process_failed", Joined: true, Cause: deadlineErr}, evidence, stdout, stderr
	}
	defer deadline.cancel(context.Canceled)
	ctx := deadline.ctx
	args := []string{"-test.v=test2json", "-test.timeout=" + deadline.backstop.String(), fmt.Sprintf("-test.parallel=%d", executionCapacityFromContext(ctx).Parallel)}
	if selection.run != "" {
		args = append(args, "-test.run="+selection.run)
	}
	if selection.skip != "" {
		args = append(args, "-test.skip="+selection.skip)
	}
	command := exec.Command(binary, args...)
	command.Dir, command.Env = root, environment
	command.Stdout, command.Stderr = deadline, stderr
	testStarted := time.Now()
	process := deadline.joined(superviseProcess(ctx, command))
	native := process
	var custodyErr error
	testFacts := commandFacts("test", componentPackage, process, time.Since(testStarted))
	if process.Joined {
		testFacts.RaceObservation = observedRace(true, stdout.Bytes(), stderr.Bytes())
	}
	custodyErr = evidence.Diagnostics.append(testFacts)
	if !process.Joined {
		process.Status, process.Cause = "group_stop_failed", errors.Join(process.Cause, custodyErr)
		evidence.Outcome, evidence.ElapsedSeconds = process.Status, time.Since(started).Seconds()
		return process, evidence, stdout, stderr
	}
	stream := &testEventStream{state: state, privateErrorOutput: stdout}
	converterErr := &limitedOutput{}
	converter := exec.Command(eventConverter.binary, "-t", "-p", componentPackage)
	converter.Dir, converter.Env = root, goEnvironment()
	converter.Stdin, converter.Stdout, converter.Stderr = bytes.NewReader(stdout.Bytes()), stream, converterErr
	conversionStarted := time.Now()
	conversionContext, cancelConversion := deadline.conversionContext()
	defer cancelConversion()
	conversion := deadline.converted(conversionContext, superviseTestEventConversion(conversionContext, converter))
	conversionFacts := commandFacts("conversion", componentPackage, conversion, time.Since(conversionStarted))
	conversionFacts.Events = "unavailable"
	if conversion.Joined {
		conversionFacts.Events = stream.status()
		conversionFacts.RaceObservation = observedRace(true, nil, converterErr.Bytes())
	}
	custodyErr = errors.Join(custodyErr, evidence.Diagnostics.append(conversionFacts))
	process.Joined = process.Joined && conversion.Joined
	if !process.Joined {
		process.Status, process.Cause = "group_stop_failed", errors.Join(native.Cause, conversion.Cause, custodyErr)
	} else {
		eventErr := stream.complete()
		if stdout.overflow || stderr.overflow || converterErr.overflow || conversion.Status != "passed" || !conversion.Started {
			state.unobservedOutcome = "incomplete"
		}
		evidence.Tests = state.componentTests()
		var nativeErr error
		if native.Status != "passed" {
			nativeErr = &toolFailure{operation: "component test", process: native}
		}
		process.Cause = containTestFailure(parent, nativeErr, eventErr)
		if conversion.Status != "passed" || !conversion.Started {
			custodyErr = errors.Join(custodyErr, conversion.Cause, errors.New("component test conversion failed"))
		}
		if converterErr.Len() != 0 || converterErr.overflow {
			appendComponentCapture(stderr, "test2json", converterErr)
		}
		var timingsComplete bool
		evidence.Timings, timingsComplete = collectComponentTimings(stdout.Bytes(), evidence.Tests)
		if !timingsComplete {
			custodyErr = errors.Join(custodyErr, errors.New("component timing evidence incomplete"))
		}
		if stdout.overflow || stderr.overflow {
			if len(evidence.Diagnostics.Commands) != 0 {
				evidence.Diagnostics.Commands[len(evidence.Diagnostics.Commands)-1].Events = "overflow"
			}
			if process.Status == "passed" {
				process.Status = "output_limit_exceeded"
			}
			custodyErr = errors.Join(custodyErr, errors.New("component check output exceeds its bound"))
		}
		shutdownErr := deadline.shutdownError(conversionContext)
		process.Cause = errors.Join(process.Cause, custodyErr, shutdownErr, parent.Err())
		if shutdownErr != nil {
			process.Status = processContextStatus(shutdownErr)
		}
		if process.Status == "passed" && process.Cause != nil {
			process.Status = "process_failed"
		}
		evidence.TestsComplete = process.Status == "passed" && process.Cause == nil
	}
	evidence.Outcome, evidence.ElapsedSeconds = process.Status, time.Since(started).Seconds()
	return process, evidence, stdout, stderr
}

func componentRequestedNode(tests []componentTest, requested string, process processResult, diagnostics *checkDiagnostics) string {
	if !process.Started || !process.Joined {
		return "unavailable"
	}
	for _, test := range tests {
		if test.Name == requested {
			return test.Outcome
		}
	}
	if diagnostics != nil {
		for _, command := range diagnostics.Commands {
			if command.Phase == "conversion" && command.Started && command.Joined && command.Process == "passed" && command.Events == "valid" {
				return "missing"
			}
		}
	}
	return "unavailable"
}

type preparedComponentChecks struct {
	dispatch       repetitionBarrier
	stdout, stderr *limitedOutput
	profile        string
	requested      []string
	selected       []string
	estimates      map[string]float64
	focus          *componentFocus
	evidence       checkEvidence
}

func (prepared *preparedComponentChecks) evidenceCopy() checkEvidence {
	value := prepared.evidence
	if value.Diagnostics != nil {
		diagnostics := *value.Diagnostics
		diagnostics.Commands = slices.Clone(diagnostics.Commands)
		value.Diagnostics = &diagnostics
	}
	if value.Focus != nil {
		focus := *value.Focus
		focus.Tests = slices.Clone(focus.Tests)
		value.Focus = &focus
	}
	return value
}

func prepareComponentChecks(initial *checkDiagnostics, ctx context.Context, root, binary string, flags, environment []string, profile string, requested []string, owner *assembly) (prepared *preparedComponentChecks, diagnostics *checkDiagnostics, err error) {
	diagnostics = initial
	if diagnostics == nil {
		diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	if !diagnostics.hasPlan() {
		future, e := componentPreparationCommands(owner)
		if e != nil {
			return nil, diagnostics, e
		}
		if e = diagnostics.reserveCommands(future); e != nil {
			return nil, diagnostics, e
		}
		defer diagnostics.cancelReservations()
	}
	defer func() {
		if err != nil {
			diagnostics.Preparation = "failed"
		}
	}()
	if owner != nil {
		if err := checkAssemblyRace(ctx, *owner); err != nil {
			return nil, diagnostics, diagnostics.recordPreparationFailure(err)
		}
	}
	evidence := checkEvidence{Profile: profile, Race: raceEnabled(ctx), RaceOptions: acceptedRaceOptions(raceEnabled(ctx)), EventTimeSource: "post_join_test2json", Diagnostics: diagnostics}
	value := assembly{Binary: binary, buildFlags: flags, Closure: assemblyClosure{Race: raceEnabled(ctx)}}
	if owner != nil {
		value = *owner
	}
	inventory, err := prepareCompiledInventory(ctx, root, value, environment, "inventory", diagnostics)
	if err != nil {
		return nil, diagnostics, err
	}
	names, stdout, stderr := inventory.names, inventory.stdout, inventory.stderr
	evidence.Inventory, evidence.Classifications = names, inventory.classifications
	selected, omitted, focus, err := resolveComponentFocus(names, evidence.Classifications, profile, requested)
	if err != nil {
		return nil, diagnostics, err
	}
	if owner != nil {
		if err := checkAssemblyRace(ctx, *owner); err != nil {
			return nil, diagnostics, diagnostics.recordPreparationFailure(err)
		}
	}
	evidence.NotSelected, evidence.Focus = omitted, focus
	evidence.Diagnostics.Preparation = "passed"
	return &preparedComponentChecks{profile: profile, requested: slices.Clone(requested), selected: selected, estimates: maps.Clone(componentEstimates), focus: focus, evidence: evidence, stdout: stdout, stderr: stderr}, diagnostics, nil
}

func componentEntryCommands(owner *assembly, converter preparedTestEventConverter) ([]checkCommandFacts, error) {
	var future []checkCommandFacts
	if owner == nil || owner.componentSelection == nil {
		v, e := componentPreparationCommands(owner)
		if e != nil {
			return nil, e
		}
		future = append(future, v...)
		if converter.preparation != nil && (owner == nil || !owner.converterRecorded) {
			future = append(future, preparationReservationFact("test2json", true))
		}
	}
	return future, nil
}

func componentPreparationCommands(owner *assembly) ([]checkCommandFacts, error) {
	var future []checkCommandFacts
	future = append(future, preparationReservationFact("inventory", false))
	return future, nil
}
func componentVerificationFuture(groups []componentGroup, owner *assembly) ([]checkCommandFacts, error) {
	var future []checkCommandFacts
	for _, group := range groups {
		future = append(future, componentReservationFact("test", group.Name), componentReservationFact("conversion", group.Name))
	}
	return future, nil
}
func reserveComponentCommands(current, shared *checkDiagnostics, groups []componentGroup) error {
	if _, err := componentCaptureShare(groups); err != nil {
		return err
	}
	proof := &checkDiagnostics{Preparation: "pending"}
	if shared != nil {
		proof.Commands = append(proof.Commands, shared.Commands...)
	}
	if current != nil {
		proof.Commands = append(proof.Commands, current.Commands...)
	}
	future, _ := componentVerificationFuture(groups, nil)
	return proof.reserveCommands(future)
}
func reserveComponentVerificationCommands(current, shared *checkDiagnostics, groups []componentGroup, owner *assembly) error {
	if _, err := componentCaptureShare(groups); err != nil {
		return err
	}
	future, err := componentVerificationFuture(groups, owner)
	if err != nil {
		return err
	}
	return current.reserveCommands(future)
}
func componentCaptureMinimum(name string) int {
	h := len(fmt.Sprintf("Failed phase: %s (upstream truncated: false)\n", name))
	e := len("Private assertion output (truncated: false):\n")
	r := len("Raw capture prefix:\n")
	o := len("\nRaw capture middle omitted: true\nRaw capture tail:\n")
	return h + max(2*(e+1), 2*(r+o+2))
}
func componentCaptureShare(groups []componentGroup) (int, error) {
	if len(groups) == 0 {
		return 0, nil
	}
	share := assemblyDiagnosticOutputLimit / len(groups)
	for _, group := range groups {
		if share < componentCaptureMinimum(group.Name) {
			return 0, errors.New("component failure capture plan exceeds its bound")
		}
	}
	return share, nil
}

func componentReservationFact(phase, scope string) checkCommandFacts {
	maximumSeconds := math.MaxFloat64
	return checkCommandFacts{Phase: phase, Scope: scope, Process: "group_stop_failed", WallSeconds: &maximumSeconds,
		Events: "unavailable", ToolCleanup: "retained_unjoined", RequestedNode: "unavailable", RaceObservation: "not_observed"}
}

func componentRequestedNodes(tests []componentTest, requested []string, process processResult, diagnostics *checkDiagnostics) string {
	if process.Started && process.Joined && completeRequestedComponentTerminals(requested, tests) {
		return "passed"
	}
	for _, request := range requested {
		if status := componentRequestedNode(tests, request, process, diagnostics); status != "passed" {
			return status
		}
	}
	return "passed"
}

func componentGroupResult(group componentGroup, outcome string, elapsed float64) componentGroupEvidence {
	return componentGroupEvidence{Name: group.Name, Outcome: outcome, ElapsedSeconds: elapsed,
		EstimatedSeconds: group.EstimatedSeconds, TestCount: len(group.Tests), Tests: slices.Clone(group.Tests),
		Requests: slices.Clone(group.Requests), Selection: group.Selection, Exclusive: group.Exclusive, Worker: group.Worker}
}
