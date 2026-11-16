package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestPrivateComponentErrorCaptureKeepsExactSuffix(t *testing.T) {
	const prefix = "[pkg TestRoot] "
	const phaseHeading = "Failed phase: fixture (upstream truncated: false)\n"
	const errorHeading = "Private assertion output (truncated: false):\n"
	const limit = assemblyDiagnosticOutputLimit
	for _, row := range []struct {
		name  string
		parts []string
	}{
		{"empty", nil},
		{"exact-fit", []string{strings.Repeat("e", limit-len(prefix))}},
		{"one-byte-over", []string{strings.Repeat("e", limit-len(prefix)+1)}},
		{"several-wraps", []string{strings.Repeat("ab", limit/3), strings.Repeat("c\x00d", limit/4), strings.Repeat("\xc3\xa9", limit/3), " final assertion\n"}},
		{"oversized-output", []string{"first", strings.Repeat("o", limit), "last"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			var capture limitedOutput
			var all strings.Builder
			for _, part := range row.parts {
				capture.capturePrivateComponentError(ordinaryEvent{Action: "output", OutputType: "error", Package: "pkg", Test: "TestRoot", Output: part})
				all.WriteString(prefix)
				all.WriteString(part)
				capture.capturePrivateComponentError(ordinaryEvent{Action: "output", OutputType: "frame", Output: "--- PASS: TestRoot (0.01s)\n"})
				capture.capturePrivateComponentError(ordinaryEvent{Action: "output", Output: "unrelated passing noise"})
			}
			want := all.String()
			truncated := len(want) > limit
			if truncated {
				want = want[len(want)-limit:]
			}
			if capture.privateErrorOverflow != truncated || capture.overflow || len(capture.privateErrorOutput) > limit {
				t.Fatal("private suffix bound or independent overflow flags changed")
			}
			for range 2 {
				var rendered limitedOutput
				appendFailedComponentCapture(&rendered, "fixture", &capture, len(phaseHeading)+2*(limit+len(errorHeading)))
				body := phaseHeading
				if want != "" {
					body += fmt.Sprintf("Private assertion output (truncated: %t):\n", truncated) + want
				}
				body += "Raw capture prefix:\n"
				if rendered.String() != body {
					t.Fatal("private capture changed exact suffix order, bytes or repeated rendering")
				}
			}
		})
	}
	t.Run("failure-frame-and-oversized-prefix", func(t *testing.T) {
		var capture limitedOutput
		pkg := strings.Repeat("p", limit)
		output := " \t--- FAIL: TestRoot (0.01s)\n"
		capture.capturePrivateComponentError(ordinaryEvent{Action: "output", OutputType: "frame", Package: pkg, Test: "TestRoot", Output: output})
		capture.capturePrivateComponentError(ordinaryEvent{Action: "pass", OutputType: "error", Output: "must not be captured"})
		all := "[" + pkg + " TestRoot] " + output
		var rendered limitedOutput
		appendFailedComponentCapture(&rendered, "fixture", &capture, len(phaseHeading)+2*(limit+len(errorHeading)))
		want := phaseHeading + "Private assertion output (truncated: true):\n" + all[len(all)-limit:] + "Raw capture prefix:\n"
		if !capture.privateErrorOverflow || rendered.String() != want {
			t.Fatal("failure frame bytes or oversized prefix suffix changed")
		}
	})
}

// full_only: false
func TestComponentSubtestEvidenceExceedsTopLevelInventoryBound(t *testing.T) {
	for _, groupCount := range []int{1, componentGroupCount} {
		t.Run(fmt.Sprintf("groups=%d", groupCount), func(t *testing.T) {
			var inventory []string
			var merged []componentTest
			for group := 0; group < groupCount; group++ {
				name := fmt.Sprintf("TestGroup%d", group)
				inventory = append(inventory, name)
				events := []ordinaryEvent{{Action: "start"}, {Action: "run", Test: name}}
				for i := group; i < 4097; i += groupCount {
					child := fmt.Sprintf("%s/case%d", name, i)
					events = append(events, ordinaryEvent{Action: "run", Test: child}, ordinaryEvent{Action: "pass", Test: child, Elapsed: observedOrdinaryElapsed(0.01)})
				}
				events = append(events, ordinaryEvent{Action: "pass", Test: name, Elapsed: observedOrdinaryElapsed(0.02)}, ordinaryEvent{Action: "pass"})
				tests, complete := componentEventResults([]string{name}, events...)
				if !complete {
					t.Fatalf("valid bounded group lost terminals: group=%d records=%d", group, len(tests))
				}
				merged = append(merged, tests...)
			}
			if len(merged) != 4097+groupCount || !componentEvidenceMatchesInventory(inventory, merged) {
				t.Fatalf("valid merged evidence refused: tops=%d records=%d", len(inventory), len(merged))
			}
			checks := checkEvidence{Profile: "dev", TestsComplete: true, Inventory: inventory, Classifications: componentFixtureClassifications(inventory), Tests: merged}
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "checks.json")
			if err := records.WriteJSON(path, checks, 0600); err != nil {
				t.Fatal(err)
			}
			var retained checkEvidence
			if err := records.ReadJSON(path, &retained); err != nil || !completeComponentEvidence(retained, "hermetic", "memory") || !reflect.DeepEqual(checks, retained) {
				t.Fatal("saved component evidence lost complete terminal records", err)
			}
		})
	}
}

// full_only: false
func TestProfileComponentChecksRetainAllSubtestsAcrossGroups(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "component-subtests")
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestLargeA", "TestLargeB", "TestLargeC", "TestLargeD")
	script := "#!/bin/sh\ncase \"$*\" in\n" +
		" *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\nesac\n" +
		"for name in " + strings.Join(inventory, " ") + "; do\n" +
		" case \"$*\" in " + componentShellSelectedName + ")\n" +
		" printf '%s\\n' \"=== RUN   $name\"\n" +
		" case \"$name\" in TestLarge*)\n" +
		" i=0; while [ \"$i\" -lt 1025 ]; do\n" +
		" printf '%s\\n' \"=== RUN   $name/case$i\" \"--- PASS: $name/case$i (0.01s)\"\n" +
		" i=$((i + 1)); done ;; esac\n" +
		" printf '%s\\n' \"--- PASS: $name (0.02s)\" ;; esac\ndone\nprintf '%s\\n' PASS\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	process, evidence, stdout, stderr := executeFixtureProfileComponentChecks(t, nil, context.Background(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentFixtureClassifications(inventory)), os.Environ(), "full", singleTestRequest(""), 3, nil, nil)
	if process.Status != "passed" || !process.Joined || !evidence.TestsComplete || len(evidence.Tests) != len(inventory)+4*1025 || stdout.overflow || stderr.overflow {
		t.Fatalf("partitioned subtest records incomplete: status=%s joined=%t complete=%t tops=%d records=%d cause=%v", process.Status, process.Joined, evidence.TestsComplete, len(evidence.Inventory), len(evidence.Tests), process.Cause)
	}
	if !completeComponentEvidence(evidence, "hermetic", "memory") {
		t.Fatal("merged complete group evidence was refused")
	}
}

// full_only: false
func TestComponentEvidenceBoundsFollowInventoryAndRecordEnvelopes(t *testing.T) {
	if maximumComponentTests != records.MaximumJSONBytes/len(`{"name":"TestA","outcome":"passed"},`) {
		t.Fatal("terminal bound differs from the shortest accepted compact JSON row")
	}
	for _, count := range []int{4096, 4097} {
		var body strings.Builder
		var names []string
		var tests []componentTest
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("TestInventory%d", i)
			fmt.Fprintln(&body, name)
			names = append(names, name)
			tests = append(tests, componentTest{Name: name, Outcome: "passed"})
		}
		_, complete := collectComponentNames([]byte(body.String()))
		_, _, selectionErr := selectComponentInventory(names, componentFixtureClassifications(names), "dev")
		if complete != (count == 4096) || (selectionErr == nil) != complete || componentEvidenceMatchesInventory(names, tests) != complete {
			t.Fatalf("inventory bound differs across callers: count=%d collected=%t selected=%t", count, complete, selectionErr == nil)
		}
	}
	oversized := make([]componentTest, maximumComponentTests+1)
	checks := checkEvidence{Profile: "dev", TestsComplete: true, Inventory: []string{"TestA"}, Tests: oversized}
	if componentEvidenceMatchesInventory(checks.Inventory, oversized) || completeComponentEvidence(checks, "hermetic", "memory") {
		t.Fatal("evidence exceeding the existing record envelope passed")
	}
	body := bytes.Repeat([]byte{'\n'}, maximumToolOutputBytes+1)
	if _, complete := collectComponentNames(body); complete {
		t.Fatal("inventory collector accepted an overbound capture")
	}
	if _, complete := collectComponentTimings(body, nil); complete {
		t.Fatal("timing collector accepted an overbound capture")
	}
}

// full_only: false
func TestComponentInventoryPartitionsEveryTopLevelTest(t *testing.T) {
	body := []byte("TestAlpha\nTestBeta\nTestGamma\n" + maximumCapacityComponent + "\nTestDelta\nTestEpsilon\nTestOmega\n")
	names, complete := collectComponentNames(body)
	if !complete || len(names) != 7 {
		t.Fatalf("component inventory differs: %q %t", names, complete)
	}
	groups, err := componentGroupsForProfile(names, componentProfileFixtureClassifications(names), "full", 4, componentEstimates)
	if err != nil || len(groups) != 4 || groups[0].Name != "ordinary-1" || groups[0].Exclusive {
		t.Fatalf("component groups differ: %+v %v", groups, err)
	}
	seen := map[string]bool{}
	for _, group := range groups {
		selection, err := componentSelection(group.Tests)
		if err != nil {
			t.Fatal(err)
		}
		matcher := regexp.MustCompile(selection)
		for _, name := range names {
			if matcher.MatchString(name) {
				if seen[name] {
					t.Fatal("component inventory entry selected twice", name)
				}
				seen[name] = true
			}
		}
	}
	if len(seen) != len(names) {
		t.Fatal("component groups lost an inventory entry", seen)
	}
	evidence := []componentTest{
		{Name: maximumCapacityComponent, Outcome: "passed"},
		{Name: "TestAlpha", Outcome: "passed"},
		{Name: "TestAlpha/case", Outcome: "passed"},
		{Name: "TestBeta", Outcome: "passed"},
		{Name: "TestGamma", Outcome: "passed"},
		{Name: "TestDelta", Outcome: "passed"},
		{Name: "TestEpsilon", Outcome: "passed"},
		{Name: "TestOmega", Outcome: "skipped"},
	}
	if !componentEvidenceMatchesInventory(names, evidence) {
		t.Fatal("complete partitioned evidence was refused")
	}
	for _, invalid := range [][]byte{
		[]byte("TestAlpha\nTestAlpha\n"),
		[]byte("TestAlpha/case\n"),
		[]byte("private output\n"),
	} {
		if _, complete := collectComponentNames(invalid); complete {
			t.Fatal("invalid component inventory passed", string(invalid))
		}
	}
	small, err := componentGroupsForProfile([]string{"TestAlpha"}, componentFixtureClassifications([]string{"TestAlpha"}), "full", 4, componentEstimates)
	if err != nil || len(small) != 1 || !slices.Equal(small[0].Tests, []string{"TestAlpha"}) {
		t.Fatal("small admitted inventory did not keep its package process", small, err)
	}
	if _, _, _, _, err := resolveComponentGroups([]string{"TestAlpha"}, componentFixtureClassifications([]string{"TestAlpha"}), "full", nil, 4, componentEstimates); err == nil {
		t.Fatal("full profile admission without the maximum proof passed")
	}
}

// full_only: false
func TestComponentProfilesDeriveDailyCoverageFromExplicitClassification(t *testing.T) {
	capacity := []string{
		"TestSuccessionJointMaximumMemory",
		"TestGeneratedRecordPrefixPerformance",
		"TestGeneratedMaximumSelectedSetFitsAccessReplacementOverlap",
		"TestGeneratedPurpose3CleanupAtJointMemberAndGenerationMaximum",
		"TestGeneratedMaximumDeclarationReservationMemory",
	}
	for _, name := range ordinaryMemoryTestInventory() {
		if name != "TestOrdinaryOutputMemoryNativeArtifact" {
			capacity = append(capacity, name)
		}
	}
	ordinary := []string{"TestOrdinary", "TestNewlyAdded", "TestGeneratedMaximumDeclarationReservationMemoryRefusal", "TestOrdinaryOutputMemoryNativeArtifact"}
	inventory := append(slices.Clone(capacity), ordinary...)
	for _, profile := range []string{"full", "dev"} {
		selected, notSelected, err := selectComponentInventory(inventory, componentProfileFixtureClassifications(inventory), profile)
		if err != nil {
			t.Fatal(err)
		}
		if profile == "full" && (!slices.Equal(selected, inventory) || len(notSelected) != 0) {
			t.Fatal("full profile changed the complete inventory", selected, notSelected)
		}
		if profile == "dev" && (!slices.Equal(selected, ordinary) || !slices.Equal(notSelected, capacity)) {
			t.Fatal("dev profile did not retain small behavior and native accounting while excluding maximum proofs", selected, notSelected)
		}
		groups, err := componentGroupsForProfile(selected, componentProfileFixtureClassifications(selected), profile, 4, componentEstimates)
		if err != nil {
			t.Fatal(err)
		}
		var grouped []string
		for _, group := range groups {
			grouped = append(grouped, group.Tests...)
		}
		slices.Sort(grouped)
		slices.Sort(selected)
		if !slices.Equal(grouped, selected) {
			t.Fatal("profile grouping lost or repeated a selected test")
		}
	}
	for _, profile := range []string{"", "ordinary", "DEV"} {
		if _, _, err := selectComponentInventory(inventory, componentProfileFixtureClassifications(inventory), profile); err == nil {
			t.Fatal("unknown profile passed", profile)
		}
	}
	for _, inventory := range [][]string{
		nil,
		{"TestState", "TestState"},
		{"TestState/subtest"},
		{"private output"},
		{"TestSuccessionJointMaximumMemory", "TestSuccessionJointMaximumMemory", "TestOrdinary"},
		capacity,
	} {
		if _, _, err := selectComponentInventory(inventory, componentProfileFixtureClassifications(inventory), "dev"); err == nil {
			t.Fatal("invalid or empty daily inventory passed", inventory)
		}
	}
}

// full_only: false
func TestComponentProfilesRejectPlatformSelection(t *testing.T) {
	names := []string{"TestSmall"}
	if _, _, err := selectComponentInventory(names, componentFixtureClassifications(names), "linux-native"); err == nil {
		t.Fatal("retired platform component profile was accepted")
	}
}

// full_only: false
func TestComponentExecutionEvidenceRejectsInventoryGaps(t *testing.T) {
	inventory := []string{"TestAlpha", "TestBeta"}
	complete := []componentTest{{Name: "TestAlpha", Outcome: "passed"}, {Name: "TestAlpha/case", Outcome: "passed"}, {Name: "TestBeta", Outcome: "passed"}}
	if !componentEvidenceMatchesInventory(inventory, complete) {
		t.Fatal("complete inventory was refused")
	}
	for _, tests := range [][]componentTest{
		complete[:2],
		append(slices.Clone(complete), complete[0]),
		append(slices.Clone(complete), complete[1]),
		append(slices.Clone(complete), componentTest{Name: "TestUnexpected", Outcome: "passed"}),
		append(slices.Clone(complete), componentTest{Name: "TestUnexpected/case", Outcome: "passed"}),
		{{Name: "TestAlpha/case", Outcome: "passed"}, {Name: "TestBeta", Outcome: "passed"}},
	} {
		if componentEvidenceMatchesInventory(inventory, tests) {
			t.Fatal("missing, repeated, or unselected execution evidence passed", tests)
		}
	}
	if componentEvidenceMatchesInventory([]string{"TestAlpha", "TestBeta", "TestAlpha"}, complete) {
		t.Fatal("a repeated inventory name passed")
	}
}

// full_only: false
func TestRetainedComponentProfilesValidateTheirSelection(t *testing.T) {
	for _, profile := range []string{"full", "dev"} {
		t.Run(profile, func(t *testing.T) {
			inventory := []string{maximumCapacityComponent, "TestOrdinary"}
			selected, notSelected, err := selectComponentInventory(inventory, componentProfileFixtureClassifications(inventory), profile)
			if err != nil {
				t.Fatal(err)
			}
			checks := checkEvidence{Profile: profile, TestsComplete: true, Inventory: inventory, Classifications: componentProfileFixtureClassifications(inventory), NotSelected: notSelected}
			for _, name := range selected {
				checks.Tests = append(checks.Tests, componentTest{Name: name, Outcome: "passed"})
			}
			if !completeComponentEvidence(checks, "hermetic", "memory") {
				t.Fatal("selected profile inventory was refused")
			}
			missing := checks
			missing.Tests = slices.Clone(checks.Tests[:len(checks.Tests)-1])
			if completeComponentEvidence(missing, "hermetic", "memory") {
				t.Fatal("missing selected test qualified")
			}
			wrongPartition := checks
			wrongPartition.NotSelected = append(slices.Clone(notSelected), "TestOrdinary")
			if completeComponentEvidence(wrongPartition, "hermetic", "memory") {
				t.Fatal("changed selected/not-selected partition qualified")
			}
			if profile == "full" {
				noMaximum := checks
				noMaximum.Inventory = []string{"TestOrdinary"}
				noMaximum.Tests = []componentTest{{Name: "TestOrdinary", Outcome: "passed"}}
				if completeComponentEvidence(noMaximum, "hermetic", "memory") {
					t.Fatal("full profile without maximum proof qualified")
				}
			}
		})
	}
	live := checkEvidence{Profile: "full", TestsComplete: true, Inventory: []string{"TestControlled"}, Tests: []componentTest{{Name: "TestControlled", Outcome: "passed"}}}
	setComponentFixtureInventory(t, &live, "gcp")
	if !completeComponentEvidence(live, "live", "gcp") {
		t.Fatal("live selected-only inventory was refused")
	}
	live.NotSelected = []string{"TestOther"}
	if completeComponentEvidence(live, "live", "gcp") {
		t.Fatal("live record invented a not-selected partition")
	}
}

// full_only: false
func TestProfileComponentChecksRecordSelectionGroupsAndTiming(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "component-profile")
	inventory := []string{
		"TestOrdinary", "TestNewlyAdded",
		"TestSuccessionJointMaximumMemory", "TestGeneratedRecordPrefixPerformance",
		"TestGeneratedMaximumSelectedSetFitsAccessReplacementOverlap",
		"TestGeneratedPurpose3CleanupAtJointMemberAndGenerationMaximum",
		"TestGeneratedMaximumDeclarationReservationMemory",
	}
	inventory = append(inventory, ordinaryMemoryTestInventory()...)
	script := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		"  *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\n" +
		"esac\n" +
		"for name in " + strings.Join(inventory, " ") + "; do\n" +
		"  case \"$*\" in\n" +
		"    " + componentShellSelectedName + ") printf '%s\\n' \"=== RUN   $name\" \"capacity-timing test=$name phase=fixture elapsed=12ms\" \"--- PASS: $name (0.25s)\" ;;\n" +
		"  esac\n" +
		"done\n" +
		"printf '%s\\n' PASS\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"full", "dev"} {
		t.Run(profile, func(t *testing.T) {
			var output bytes.Buffer
			process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, context.Background(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentProfileFixtureClassifications(inventory)), os.Environ(), profile, singleTestRequest(""), 1, &output, nil)
			selected, notSelected, err := selectComponentInventory(inventory, componentProfileFixtureClassifications(inventory), profile)
			if err != nil || process.Status != "passed" || !process.Joined || !evidence.TestsComplete || evidence.Profile != profile || evidence.Outcome != "passed" {
				t.Fatalf("profile failed: %+v %+v %v", process, evidence, err)
			}
			if !slices.Equal(evidence.Inventory, inventory) || !slices.Equal(evidence.NotSelected, notSelected) || !componentEvidenceMatchesInventory(selected, evidence.Tests) {
				t.Fatal("profile lost its selection or observed inventory", evidence)
			}
			isolated := 12
			if profile == "dev" {
				isolated = 1
			}
			expectedGroups := isolated + 1
			if len(evidence.Groups) != expectedGroups || len(evidence.Timings) != len(selected) || evidence.ElapsedSeconds <= 0 {
				t.Fatal("profile lost its group or duration evidence", evidence)
			}
			for _, group := range evidence.Groups {
				if group.Outcome != "passed" || group.ElapsedSeconds <= 0 || !strings.Contains(output.String(), "starting group "+group.Name) {
					t.Fatal("group status, duration, or progress differs", group, output.String())
				}
			}
			for _, test := range evidence.Tests {
				if test.ElapsedSeconds != 0.25 {
					t.Fatal("Go test elapsed time was not retained", test)
				}
			}
			for _, timing := range evidence.Timings {
				if timing.Phase != "fixture" || timing.ElapsedSeconds != 0.012 {
					t.Fatal("fixture timing was not retained", timing)
				}
			}
			if !strings.Contains(output.String(), "slowest top-level tests") {
				t.Fatal("slowest tests were not printed", output.String())
			}
		})
	}
	process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, context.Background(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentProfileFixtureClassifications(inventory)), os.Environ(), "unknown", singleTestRequest(""), 1, nil, nil)
	if process.Started || process.Status != "process_failed" || evidence.TestsComplete || evidence.Outcome != "process_failed" {
		t.Fatal("unknown profile reached component execution", process, evidence)
	}
}

type componentProgressFailureWriter struct {
	match string
	err   error
}

func (w componentProgressFailureWriter) Write(body []byte) (int, error) {
	if bytes.Contains(body, []byte(w.match)) {
		return 0, w.err
	}
	return len(body), nil
}

// full_only: false
func TestProfileComponentChecksPropagateProgressAndSummaryFailures(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "component-output")

	inventory := append(ordinaryMemoryTestInventory(), "TestOrdinary")
	script := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		" *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\n" +
		"esac\nfor name in " + strings.Join(inventory, " ") + "; do\n" +
		" case \"$*\" in " + componentShellSelectedName + ")\n" +
		" printf '%s\\n' \"=== RUN   $name\"\n" +
		" if [ \"$name\" = TestOrdinary ] && [ \"${ENKV_COMPONENT_FAIL:-0}\" != 0 ]; then\n" +
		"  printf '%s\\n' \"--- FAIL: $name (0.25s)\" FAIL; exit 1\n" +
		" fi\n printf '%s\\n' \"--- PASS: $name (0.25s)\" ;;\n esac\ndone\nprintf '%s\\n' PASS\n"

	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, match := range []string{
		"phase=preparation", "phase=test",
		": inventory", fmt.Sprintf(": %d selected", len(inventory)), ": starting group", ": group ordinary-1 ",
		"slowest top-level tests", "  TestOrdinary: ",
	} {
		t.Run(match, func(t *testing.T) {
			writeErr := errors.New("controlled output failure")
			writer := componentProgressFailureWriter{match: match, err: writeErr}
			process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, context.Background(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentFixtureClassifications(inventory)), os.Environ(), "dev", singleTestRequest(""), 1, writer, nil)
			if process.Status != "process_failed" || evidence.Outcome != "process_failed" || !errors.Is(process.Cause, writeErr) {
				t.Fatal("output failure was lost", process, evidence)
			}
			if (match == ": inventory" || match == "phase=preparation") && process.Started {
				t.Fatal("component process started after initial output failed")
			}
		})
	}
	for _, match := range []string{": group ordinary-1 ", "slowest top-level tests", "  TestOrdinary: "} {
		t.Run("prior-failure/"+match, func(t *testing.T) {
			t.Setenv("ENKV_COMPONENT_FAIL", "1")
			writeErr := errors.New("controlled output failure")
			writer := componentProgressFailureWriter{match: match, err: writeErr}
			process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, context.Background(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentFixtureClassifications(inventory)), os.Environ(), "dev", singleTestRequest(""), 1, writer, nil)
			if process.Status != "process_failed" || evidence.Outcome != "process_failed" || !errors.Is(process.Cause, writeErr) || !strings.Contains(process.Cause.Error(), "exit status 1") {
				t.Fatal("output failure replaced the component failure", process, evidence)
			}
		})
	}
}

// full_only: false
func TestComponentTimingsRequireObservedNamesAndBoundedPhases(t *testing.T) {
	tests := []componentTest{{Name: "TestCapacity", Outcome: "passed"}, {Name: "TestCapacity/failure", Outcome: "passed"}}
	body := "capacity_test.go:12: capacity-timing test=TestCapacity phase=fixture elapsed=2.25s\n" +
		"capacity_test.go:24: capacity-timing test=TestCapacity/failure phase=operation elapsed=1m0.25s\n" +
		"capacity_test.go:30: capacity-timing test=TestCapacity/failure phase=fresh-child elapsed=500ms\n" +
		"capacity_test.go:34: capacity-timing test=TestCapacity/failure phase=operation elapsed=1ms\n"
	timings, complete := collectComponentTimings([]byte(body), tests)
	if !complete || len(timings) != 4 || timings[0] != (componentTiming{Test: "TestCapacity", Phase: "fixture", ElapsedSeconds: 2.25}) || timings[1].ElapsedSeconds != 60.25 || timings[2].ElapsedSeconds != 0.5 || timings[3].ElapsedSeconds != 0.001 {
		t.Fatal("phase intervals were not preserved separately", timings, complete)
	}
	for _, marker := range []string{
		"test=TestUnobserved phase=fixture elapsed=1s",
		"test=TestCapacity phase=secret elapsed=1s",
		"test=TestCapacity phase=fixture elapsed=-1s",
		"test=TestCapacity phase=fixture elapsed=NaNs",
		"test=TestCapacity phase=fixture elapsed=1s private",
		"test=TestCapacity phase=fixture",
		"test=TestCapacity/private@host phase=fixture elapsed=1s",
	} {
		if _, complete := collectComponentTimings([]byte("capacity-timing "+marker+"\n"), tests); complete {
			t.Fatal("invalid phase measurement passed", marker)
		}
	}
	if _, complete := collectComponentTimings([]byte(strings.Repeat("capacity-timing test=TestCapacity phase=fixture elapsed=1s\n", 4097)), tests); complete {
		t.Fatal("too many timing measurements passed")
	}
	if timings, complete := collectComponentTimings([]byte("ordinary output\n"), tests); !complete || len(timings) != 0 {
		t.Fatal("tests without phase instrumentation were refused")
	}
}

// full_only: false
func TestSlowestComponentTestsDoNotDoubleCountSubtests(t *testing.T) {
	tests := []componentTest{
		{Name: "TestParent", Outcome: "passed", ElapsedSeconds: 20},
		{Name: "TestParent/child", Outcome: "passed", ElapsedSeconds: 19},
		{Name: "TestNext", Outcome: "passed", ElapsedSeconds: 10},
		{Name: "TestThird", Outcome: "passed", ElapsedSeconds: 5},
		{Name: "TestFourth", Outcome: "passed", ElapsedSeconds: 4},
		{Name: "TestFifth", Outcome: "passed", ElapsedSeconds: 3},
		{Name: "TestSixth", Outcome: "passed", ElapsedSeconds: 2},
	}
	before := slices.Clone(tests)
	var output bytes.Buffer
	if err := writeSlowestComponentTests(&output, tests); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "/child") || strings.Contains(output.String(), "TestSixth") || !strings.Contains(output.String(), "TestFifth: 3.00s") || strings.Index(output.String(), "TestParent") > strings.Index(output.String(), "TestNext") {
		t.Fatal("slowest output mixed parent and subtest durations", output.String())
	}
	if !slices.Equal(tests, before) {
		t.Fatal("slowest output changed execution order")
	}
	t.Run("elapsed-availability", func(t *testing.T) {
		rows := []componentTest{
			{Name: "TestUnknown", Outcome: "incomplete", ElapsedObserved: boolPointer(false)},
			{Name: "TestZero", Outcome: "passed", ElapsedObserved: boolPointer(true)},
			{Name: "TestHistorical", Outcome: "passed"},
		}
		var output bytes.Buffer
		if err := writeSlowestComponentTests(&output, rows); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"TestUnknown: unknown", "TestZero: 0.00s", "TestHistorical: 0.00s"} {
			if !strings.Contains(output.String(), want) {
				t.Error("slowest summary changed elapsed availability or historical meaning", want, output.String())
			}
		}
	})
}

func componentEventResults(names []string, events ...ordinaryEvent) ([]componentTest, bool) {
	state, err := newTestEventState(map[string][]string{componentPackage: names}, maximumComponentTests, validComponentName, nil)
	if err != nil {
		return nil, false
	}
	for i := range events {
		if events[i].Package == "" {
			events[i].Package = componentPackage
		}
	}
	stream := &testEventStream{state: state}
	_, _ = stream.Write(ordinaryEvents(events...))
	return state.componentTests(), stream.complete() == nil
}

func observedOrdinaryElapsed(value float64) *float64 { return &value }

// full_only: false
func TestComponentNamesAndStatusesComeFromExecution(t *testing.T) {
	events := []ordinaryEvent{
		{Action: "start"}, {Action: "run", Test: "TestState"}, {Action: "run", Test: "TestState/changed"},
		{Action: "pause", Test: "TestState/changed"}, {Action: "cont", Test: "TestState/changed"},
		{Action: "output", Test: "TestState/changed", Output: "private output must not enter records\n", OutputType: "error"},
		{Action: "attr", Test: "TestState/changed", Key: "dimension", Value: "small"},
		{Action: "artifacts", Test: "TestState/changed", Path: "private-artifacts"},
		{Action: "pass", Test: "TestState/changed", Elapsed: observedOrdinaryElapsed(0.01)}, {Action: "pass", Test: "TestState", Elapsed: observedOrdinaryElapsed(0.02)}, {Action: "pass"},
	}
	results, complete := componentEventResults([]string{"TestState"}, events...)
	if !complete || len(results) != 2 || results[0].ElapsedSeconds != 0.02 || results[0].ElapsedObserved == nil || !*results[0].ElapsedObserved || !reflect.DeepEqual(results[1], componentTest{Name: "TestState/changed", Outcome: "passed", ElapsedSeconds: 0.01, ElapsedObserved: boolPointer(true)}) {
		t.Fatalf("component event proof differs: %+v %t", results, complete)
	}
	skipped, complete := componentEventResults([]string{"TestHelper"}, ordinaryEvent{Action: "start"}, ordinaryEvent{Action: "run", Test: "TestHelper"}, ordinaryEvent{Action: "skip", Test: "TestHelper"}, ordinaryEvent{Action: "pass"})
	if !complete || len(skipped) != 1 || !reflect.DeepEqual(skipped[0], componentTest{Name: "TestHelper", Outcome: "skipped", ElapsedObserved: boolPointer(false)}) {
		t.Fatal("helper was counted as passed")
	}
	for _, invalid := range [][]ordinaryEvent{
		events[:len(events)-1],
		append(slices.Clone(events[:3]), events[2:]...),
		append(slices.Clone(events[:8]), events[9:]...),
		{{Action: "start"}, {Action: "pass", Test: "TestState"}, {Action: "pass"}},
		{{Action: "start"}, {Action: "run", Test: "TestState"}, {Action: "pass", Test: "TestState", Elapsed: observedOrdinaryElapsed(-1)}, {Action: "pass"}},
		{{Action: "start"}, {Action: "run", Test: "TestOther"}, {Action: "pass", Test: "TestOther"}, {Action: "pass"}},
	} {
		if _, complete := componentEventResults([]string{"TestState"}, invalid...); complete {
			t.Fatal("incomplete or invalid event proof accepted")
		}
	}
	for _, body := range [][]byte{[]byte("partial"), []byte("{}\n"), bytes.Repeat([]byte{'x'}, maximumToolOutputBytes+1)} {
		state, err := newTestEventState(map[string][]string{componentPackage: {"TestState"}}, maximumComponentTests, validComponentName, nil)
		if err != nil {
			t.Fatal(err)
		}
		stream := &testEventStream{state: state}
		_, _ = stream.Write(body)
		if stream.complete() == nil {
			t.Fatal("damaged event stream accepted")
		}
	}
}

// full_only: false
func TestComponentDiscoveryAcceptsBoundedGoNames(t *testing.T) {
	for _, name := range []string{
		"TestRecovery/2026-09-08/03-11-01+1000-fixture",
		"TestSelection/member=32/duplicate#01",
		"TestBranches/[0_1_2]",
		"Test" + strings.Repeat("A", 251),
	} {
		top, _, child := strings.Cut(name, "/")
		events := []ordinaryEvent{{Action: "start"}, {Action: "run", Test: top}}
		if child {
			events = append(events, ordinaryEvent{Action: "run", Test: name}, ordinaryEvent{Action: "pass", Test: name, Elapsed: observedOrdinaryElapsed(0.01)})
		}
		events = append(events, ordinaryEvent{Action: "pass", Test: top, Elapsed: observedOrdinaryElapsed(0.01)}, ordinaryEvent{Action: "pass"})
		results, complete := componentEventResults([]string{top}, events...)
		if !complete || !reflect.DeepEqual(results[len(results)-1], componentTest{Name: name, Outcome: "passed", ElapsedSeconds: 0.01, ElapsedObserved: boolPointer(true)}) {
			t.Fatalf("valid name refused: %q %+v", name, results)
		}
	}
	for _, name := range []string{"Test" + strings.Repeat("A", 252), "TestState/private text", "TestState/<unsafe>", "TestState/credential@example.com"} {
		if validComponentName(name) {
			t.Fatalf("unsafe or overlong name accepted: %q", name)
		}
	}
}

// full_only: false
func TestComponentDiscoveryCountBoundKeepsFinalStatuses(t *testing.T) {
	for _, count := range []int{4095, 4096, 4097, maximumOrdinaryTests + 1} {
		events := []ordinaryEvent{{Action: "start"}, {Action: "run", Test: "TestState"}}
		for i := 0; i < count; i++ {
			events = append(events, ordinaryEvent{Action: "run", Test: fmt.Sprintf("TestState/case%d", i)})
		}
		for i := 0; i < count; i++ {
			events = append(events, ordinaryEvent{Action: "pass", Test: fmt.Sprintf("TestState/case%d", i), Elapsed: observedOrdinaryElapsed(0.01)})
		}
		events = append(events, ordinaryEvent{Action: "pass", Test: "TestState"}, ordinaryEvent{Action: "pass"})
		results, complete := componentEventResults([]string{"TestState"}, events...)
		if !complete || len(results) != count+1 {
			t.Fatalf("count %d: complete=%t recorded=%d", count, complete, len(results))
		}
		for _, result := range results {
			if result.Outcome != "passed" {
				t.Fatal("lost terminal", result)
			}
		}
	}
}

func helperComponentEvidence(provider, helper string) []componentTest {
	tests := []componentTest{{Name: "TestControlled", Outcome: "passed"}, {Name: helper, Outcome: "skipped"}}
	pass := func(name string) { tests = append(tests, componentTest{Name: name, Outcome: "passed"}) }
	switch helper {
	case "TestFreshProcessChild":
		parent := "TestThreeGenerationHistoryAndStaleCandidate"
		if provider != "memory" {
			parent = "TestLiveInventoryFreshProcess"
		}
		pass(parent)
	case "TestWriterTerminationChild":
		pass("TestWriterTerminationPreservesCompleteSelection")
		for _, barrier := range []string{"before-first-create", "after-first-page-readback", "after-root-readback", "after-cas-acceptance", "after-authenticated-observation"} {
			pass("TestWriterTerminationPreservesCompleteSelection/" + barrier)
		}
	case "TestScenarioPhaseFailureChild":
		pass("TestScenarioPhaseRetainsFailureEvidence")
	case "TestHermeticWorkerEntrypointsNeedExplicitInvocation/writer", "TestHermeticWorkerEntrypointsNeedExplicitInvocation/fresh", "TestHermeticWorkerEntrypointsNeedExplicitInvocation/fixture":
		pass("TestHermeticWorkerEntrypointsNeedExplicitInvocation")
		if strings.HasSuffix(helper, "/fixture") {
			pass("TestThreeGenerationHistoryAndStaleCandidate")
		}
	}
	if provider == "memory" {
		pass(maximumCapacityComponent)
	}
	return tests
}

func componentFixtureInventory(tests []componentTest) []string {
	var inventory []string
	for _, test := range tests {
		if !strings.Contains(test.Name, "/") {
			inventory = append(inventory, test.Name)
		}
	}
	return inventory
}

func setComponentFixtureInventory(t *testing.T, checks *checkEvidence, provider string) {
	t.Helper()
	if provider != "memory" {
		for _, name := range []string{"TestFreshProcessChild", "TestLiveInventoryFreshProcess"} {
			if !slices.Contains(componentFixtureInventory(checks.Tests), name) {
				outcome := "passed"
				if name == "TestFreshProcessChild" {
					outcome = "skipped"
				}
				checks.Tests = append(checks.Tests, componentTest{Name: name, Outcome: outcome})
			}
		}
	}
	checks.Inventory = componentFixtureInventory(checks.Tests)
	setComponentFixtureMetadata(t, checks, provider)
}

func setComponentFixtureMetadata(t *testing.T, checks *checkEvidence, provider string) {
	t.Helper()
	checks.Classifications = componentFixtureClassifications(checks.Inventory)
	if provider == "memory" {
		return
	}
	checks.CompiledInventory = slices.Clone(checks.Inventory)
	checks.AssemblySources = map[string]string{}
	for _, name := range checks.Inventory {
		checks.AssemblySources[name] = "tests/live/providers/" + provider + "/fixture_test.go"
	}
	// Full controlled preflight omits Core tests and coordinator entrypoints.
	// These omissions must not become missing full live scenario coverage.
	checks.NotSelected = nil
	for _, name := range []string{"TestCoreUnowned", "TestLiveRun"} {
		if !slices.Contains(checks.CompiledInventory, name) {
			checks.CompiledInventory = append(checks.CompiledInventory, name)
			checks.NotSelected = append(checks.NotSelected, name)
		}
	}
	checks.AssemblySources["TestLiveRun"] = "tests/live/runner/worker_test.go"
	checks.Classifications = componentFixtureClassifications(checks.CompiledInventory)
	neutral := false
	checks.AssemblyNeutral = &neutral
	if checks.Profile == "" {
		checks.Profile = "full"
	}
	selection, err := componentSelection(checks.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	checks.Selection = selection
}

// full_only: false
func TestSkippedHelpersRequireExactAssemblyAndCompletedParents(t *testing.T) {
	for _, provider := range []string{"memory", "gcp", "aws"} {
		for _, helper := range []string{
			"TestWriterTerminationChild", "TestHermeticRun", "TestHermeticChild", "TestScenarioPhaseFailureChild",
			"TestHermeticWorkerEntrypointsNeedExplicitInvocation/writer", "TestHermeticWorkerEntrypointsNeedExplicitInvocation/fresh", "TestHermeticWorkerEntrypointsNeedExplicitInvocation/fixture",
			"TestFreshProcessChild", "TestOrdinaryRequired", "TestOrdinaryRequired/subtest", "TestHermeticChild/unlisted", "TestHermeticWorkerEntrypointsNeedExplicitInvocation/unlisted",
		} {
			t.Run(provider+"/"+helper, func(t *testing.T) {
				_, value := completeRunFixture(t, provider)
				checks := value.BuildClosure.LocalChecks
				if value.Suite == "hermetic" {
					checks = value.Correctness.ComponentRun.Checks
				}
				checks.Tests = helperComponentEvidence(provider, helper)
				setComponentFixtureInventory(t, checks, provider)
				allowed := helper == "TestFreshProcessChild" || provider == "memory" && !strings.Contains(helper, "OrdinaryRequired") && !strings.HasSuffix(helper, "/unlisted")
				if fullCoverage(value) != allowed {
					t.Fatal("helper classification did not match its assembly and invocation")
				}
				for index := 2; index < len(checks.Tests); index++ {
					for _, outcome := range []string{"missing", "wrong", "failed", "skipped"} {
						t.Run(fmt.Sprintf("parent%d-%s", index, outcome), func(t *testing.T) {
							original := checks.Tests
							checks.Tests = append([]componentTest(nil), original...)
							defer func() { checks.Tests = original }()
							switch outcome {
							case "missing":
								checks.Tests = append(checks.Tests[:index], checks.Tests[index+1:]...)
							case "wrong":
								checks.Tests[index].Name += "Extra"
							default:
								checks.Tests[index].Outcome = outcome
							}
							if fullCoverage(value) {
								t.Fatal("helper skip passed without its exact completed invoking parent")
							}
						})
					}
				}
			})
		}
	}
}

// full_only: false
func TestHelperSkipsCannotReplaceRealWorkerEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*runRecord)
	}{
		{"absent-writer", func(value *runRecord) { value.Scenarios[0].Writer = nil }},
		{"absent-fresh-before", func(value *runRecord) { value.Scenarios[0].Children = nil }},
		{"absent-fresh-after", func(value *runRecord) { value.Scenarios[0].PostExit = nil }},
		{"missing-writer-phases", func(value *runRecord) { value.Scenarios[0].Writer.Phases = nil }},
		{"missing-fresh-phases", func(value *runRecord) { value.Scenarios[0].PostExit[0].Phases = nil }},
		{"wrong-fresh-facts", func(value *runRecord) { value.Scenarios[0].PostExit[0].Phases[0].Actual = "incomplete" }},
		{"incomplete-fresh-phase", func(value *runRecord) { value.Scenarios[0].PostExit[0].Phases[0].Outcome = "incomplete" }},
		{"skipped-writer", func(value *runRecord) { value.Scenarios[0].Writer.Process = "skipped" }},
		{"failed-fresh", func(value *runRecord) { value.Scenarios[0].PostExit[0].Process = "failed" }},
		{"incomplete-fresh", func(value *runRecord) { value.Scenarios[0].PostExit[0].Outcome = "incomplete" }},
		{"unjoined-writer", func(value *runRecord) { value.Scenarios[0].Writer.Joined = false }},
		{"unjoined-fresh", func(value *runRecord) { value.Scenarios[0].PostExit[0].Joined = false }},
		{"all-skipped", func(value *runRecord) {
			for i := range value.Correctness.ComponentRun.Checks.Tests {
				value.Correctness.ComponentRun.Checks.Tests[i].Outcome = "skipped"
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, value := completeRunFixture(t, "memory")
			value.Correctness.ComponentRun.Checks.Tests = []componentTest{{Name: "TestControlled", Outcome: "passed"}, {Name: "TestHermeticRun", Outcome: "skipped"}, {Name: "TestHermeticChild", Outcome: "skipped"}}
			value.Correctness.ComponentRun.Checks.Inventory = []string{"TestControlled", "TestHermeticRun", "TestHermeticChild", maximumCapacityComponent}
			value.Correctness.ComponentRun.Checks.Tests = append(value.Correctness.ComponentRun.Checks.Tests, componentTest{Name: maximumCapacityComponent, Outcome: "passed"})
			setComponentFixtureMetadata(t, value.Correctness.ComponentRun.Checks, "memory")
			if !fullCoverage(value) {
				t.Fatal("complete helper invocation fixture was refused")
			}
			test.change(&value)
			if fullCoverage(value) {
				t.Fatal("helper skip replaced missing real invocation evidence")
			}
		})
	}
}

// This expected inventory is fixed independently of the runner registry.
func ordinaryMemoryTestInventory() []string {
	return []string{
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
}

// full_only: false
func TestOrdinaryMemoryComponentsHaveDedicatedGroups(t *testing.T) {
	memory := ordinaryMemoryTestInventory()
	for _, test := range []struct {
		name     string
		names    []string
		ordinary int
	}{
		{"only_memory", slices.Clone(memory), 0},
		{"only_ordinary", []string{"TestAlpha", "TestBeta", "TestGamma", "TestDelta", "TestEpsilon"}, 4},
		{"mixed", append(slices.Clone(memory), "TestAlpha", "TestBeta", "TestGamma", "TestDelta", "TestEpsilon"), 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := slices.Clone(test.names)
			groups, err := componentGroupsForProfile(test.names, componentFixtureClassifications(test.names), "dev", 4, componentEstimates)
			isolated := 0
			for _, name := range test.names {
				if slices.Contains(memory, name) {
					isolated++
				}
			}
			if err != nil || len(groups) != isolated+test.ordinary || !slices.Equal(before, test.names) {
				t.Fatalf("group partition differs: groups=%+v err=%v", groups, err)
			}
			seen := map[string]bool{}
			labels := map[string]bool{}
			for _, group := range groups {
				if len(group.Tests) == 0 || labels[group.Name] {
					t.Fatal("empty or duplicate group", group)
				}
				labels[group.Name] = true
				for _, name := range group.Tests {
					if seen[name] {
						t.Fatal("test grouped twice", name)
					}
					seen[name] = true
					if slices.Contains(memory, name) && len(group.Tests) != 1 {
						t.Fatal("memory case shares its process", group)
					}
				}
			}
			if len(seen) != len(test.names) {
				t.Fatal("test omitted from partition")
			}
			reversed := slices.Clone(test.names)
			slices.Reverse(reversed)
			again, err := componentGroupsForProfile(reversed, componentFixtureClassifications(reversed), "dev", 4, componentEstimates)
			if err != nil || !reflect.DeepEqual(groups, again) {
				t.Fatal("discovery order changes groups", again, err)
			}
		})
	}
}

// full_only: false
func TestComponentGroupsRejectAnotherGroupsTerminals(t *testing.T) {
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestOrdinary")
	groups, err := componentGroupsForProfile(inventory, componentFixtureClassifications(inventory), "full", 1, componentEstimates)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong=%t", wrong), func(t *testing.T) {
			root := t.TempDir()
			binary := filepath.Join(root, "wrong-group")
			script := "#!/bin/sh\ncase \"$*\" in\n *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\nesac\nselection=''\nfor argument in \"$@\"; do\n case \"$argument\" in\n  -test.run=*) [ -z \"$selection\" ] || exit 2; selection=\"$argument\" ;;\n  -test.v=test2json|-test.timeout=*|-test.parallel=*) ;;\n  *) exit 2 ;;\n esac\ndone\n[ -n \"$selection\" ] || exit 2\ncase \"$selection\" in\n"
			for i, group := range groups {
				selection, err := componentSelection(group.Tests)
				if err != nil {
					t.Fatal(err)
				}
				actual := group.Tests
				if wrong && i == 0 {
					actual = groups[1].Tests
				}
				if wrong && i == 1 {
					actual = groups[0].Tests
				}
				script += " '-test.run=" + selection + "')\n"
				for _, name := range actual {
					script += " printf '%s\\n' '=== RUN   " + name + "' '--- PASS: " + name + " (0.01s)'\n"
				}
				script += " ;;\n"
			}
			script += " *) exit 2 ;;\nesac\nprintf '%s\\n' PASS\n"
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			process, evidence, stdout, _ := executeFixtureProfileComponentChecks(t, nil, t.Context(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentFixtureClassifications(inventory)), os.Environ(), "full", singleTestRequest(""), 1, nil, nil)
			if !wrong {
				if process.Status != "passed" || !process.Joined || !evidence.TestsComplete || len(evidence.Groups) != len(groups) || !completeComponentEvidence(evidence, "hermetic", "memory") {
					t.Fatalf("assigned group inventory did not qualify: process=%+v evidence=%+v", process, evidence)
				}
				return
			}
			if !strings.Contains(string(stdout.Bytes()), "=== RUN   "+groups[1].Tests[0]) || !strings.Contains(string(stdout.Bytes()), "--- PASS: "+groups[1].Tests[0]) || process.Cause == nil || !strings.Contains(process.Cause.Error(), "ran unlisted test "+groups[1].Tests[0]) {
				t.Fatalf("fixture did not supply another group's terminals: process=%+v stdout=%s", process, stdout.Bytes())
			}
			if process.Status != "process_failed" || !process.Joined || evidence.TestsComplete || len(evidence.Groups) != len(groups) || evidence.Groups[0].Outcome != "process_failed" {
				t.Fatalf("another group's terminals were credited: process=%+v evidence=%+v", process, evidence)
			}
			for index, group := range evidence.Groups[1:] {
				if group.Name != groups[index+1].Name || group.Outcome != "not_run" || group.TestCount != len(groups[index+1].Tests) {
					t.Fatal("later group was replaced, dispatched or lost after invalid terminals", group)
				}
			}
		})
	}
}

const componentShellSelectedName = `*"($name)"*|*"($name|"*|*"|$name)"*|*"|$name|"*`

// full_only: false
func TestOrdinaryMemoryChecksRejectMissingSelectedTerminal(t *testing.T) {
	const native = "TestOrdinaryOutputMemoryNativeArtifact"
	const generated = "TestOutputConfigurationGeneratedMaximumTransitionMemory"
	for _, row := range []struct {
		name, profile          string
		memory, selectedMemory []string
	}{
		{"darwin-full", "full", ordinaryMemoryTestInventory(), ordinaryMemoryTestInventory()},
		{"darwin-dev", "dev", ordinaryMemoryTestInventory(), []string{native}},
		{"linux-full", "full", []string{generated}, []string{generated}},
	} {
		for _, missing := range row.selectedMemory {
			t.Run(row.name+"-"+missing, func(t *testing.T) {
				inventory := append(slices.Clone(row.memory), maximumCapacityComponent, "TestControlPlain")
				root := t.TempDir()
				binary := filepath.Join(root, "missing-terminal")
				script := "#!/bin/sh\ncase \"$*\" in *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;; esac\nfor name in " + strings.Join(inventory, " ") + "; do\n [ \"$name\" = " + missing + " ] && continue\n case \"$*\" in " + componentShellSelectedName + ") printf '%s\\n' \"=== RUN   $name\" \"--- PASS: $name (0.01s)\" ;; esac\ndone\nprintf '%s\\n' PASS\n"
				if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, t.Context(), root, binary, testEventConverterFixture(t, root), componentMetadataBuildFlags(t, root, componentProfileFixtureClassifications(inventory)), os.Environ(), row.profile, singleTestRequest(""), 1, nil, nil)
				if process.Status != "process_failed" || !process.Joined || evidence.Diagnostics == nil || evidence.Diagnostics.Preparation != "passed" || evidence.TestsComplete || completeComponentEvidence(evidence, "hermetic", "memory") || process.Cause == nil || !strings.Contains(process.Cause.Error(), missing) {
					t.Fatal("missing selected terminal acquired completion or failed before execution", missing, process, evidence)
				}
				failed := slices.IndexFunc(evidence.Groups, func(group componentGroupEvidence) bool {
					return group.Name == "memory-"+strings.ToLower(missing) && group.Outcome == "process_failed" && group.TestCount == 1
				})
				if failed < 0 {
					t.Fatal("missing terminal did not fail its selected process owner", missing, evidence.Groups)
				}
			})
		}
	}
}

// full_only: false
func TestOrdinaryMemoryGroupsIgnoreSchedulingCost(t *testing.T) {
	before := componentEstimates
	t.Cleanup(func() { componentEstimates = before })
	for _, profile := range []string{"full", "dev"} {
		t.Run(profile, func(t *testing.T) {
			inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestControlPlain")
			selected, _, err := selectComponentInventory(inventory, componentFixtureClassifications(inventory), profile)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range ordinaryMemoryTestInventory() {
				if !slices.Contains(selected, name) {
					t.Fatal("profile excludes a required ordinary memory case", name)
				}
			}
			for _, cost := range []float64{0.001, 1e9} {
				componentEstimates = map[string]float64{}
				for _, name := range ordinaryMemoryTestInventory() {
					componentEstimates[name] = cost
				}
				groups, err := componentGroupsForProfile(selected, componentFixtureClassifications(selected), profile, 1, componentEstimates)
				if err != nil {
					t.Fatal(err)
				}
				if len(groups) != len(ordinaryMemoryTestInventory())+1 {
					t.Fatal("selected case partition differs", groups)
				}
				for i, name := range ordinaryMemoryTestInventory() {
					if !slices.Equal(groups[i+1].Tests, []string{name}) || groups[i+1].EstimatedSeconds != cost {
						t.Fatal("estimate changed memory isolation", groups[i+1])
					}
				}
				ordinary := groups[0]
				if ordinary.Name != "ordinary-1" || ordinary.Exclusive || !slices.Equal(ordinary.Tests, []string{"TestControlPlain", maximumCapacityComponent}) || ordinary.EstimatedSeconds != 2 {
					t.Fatal("memory estimates changed the normal worker selection", ordinary)
				}
			}
		})
	}
}
