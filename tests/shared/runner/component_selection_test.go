package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func longComponentSelectionRoots(prefix string, count int) []string {
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("Test%s%04d%s", prefix, i, strings.Repeat("Long", 55))
	}
	return names
}

// full_only: false
func TestComponentNativeSelectionsKeepBoundedExactGroups(t *testing.T) {
	selected := longComponentSelectionRoots("Selected", 300)
	const memory = "TestOrdinaryOutputMemoryNativeArtifact"
	const fullOnly = "TestExcludedFullOnly"
	inventory := append(slices.Clone(selected), memory, fullOnly)
	groups := []componentGroup{{Name: "memory", Tests: []string{memory}}, {Name: "ordinary", Tests: selected}}
	if _, err := componentSelection(selected); err == nil {
		t.Fatal("fixture does not exceed the positive selection bound")
	}
	encodings, err := componentGroupSelections(inventory, groups, false)
	if err != nil || len(encodings) != 2 || encodings[0].skip != "" || encodings[1].skip == "" {
		t.Fatal("bounded complement did not preserve the complete process groups", encodings, err)
	}
	for i, encoding := range encodings {
		if len(encoding.run)+len(encoding.skip) > maximumComponentSelectionBytes {
			t.Fatal("run and skip exceeded their shared byte allowance")
		}
		run := regexp.MustCompile(encoding.run)
		var skip *regexp.Regexp
		if encoding.skip != "" {
			skip = regexp.MustCompile(encoding.skip)
		}
		for _, name := range inventory {
			actual := run.MatchString(name) && (skip == nil || !skip.MatchString(name))
			if actual != slices.Contains(groups[i].Tests, name) {
				t.Fatal("native encoding changed assigned roots", i, name, actual)
			}
		}
	}
	for _, row := range []struct {
		name      string
		inventory []string
		groups    []componentGroup
	}{
		{"duplicate-inventory", append(slices.Clone(inventory), memory), groups},
		{"unknown-root", inventory, []componentGroup{{Tests: []string{"TestUnknown"}}}},
		{"duplicate-root", inventory, []componentGroup{{Tests: []string{memory, memory}}}},
		{"duplicate-assignment", inventory, []componentGroup{{Tests: []string{memory}}, {Tests: []string{memory}}}},
		{"both-encodings-too-large", append(slices.Clone(inventory), longComponentSelectionRoots("Excluded", 300)...), groups},
	} {
		t.Run(row.name, func(t *testing.T) {
			if encodings, err := componentGroupSelections(row.inventory, row.groups, false); err == nil || encodings != nil {
				t.Fatal("invalid later group exposed a partial dispatch plan", encodings, err)
			}
		})
	}
	paths := []componentGroup{{Tests: []string{"TestParent"}, Selection: literalTestSelection("TestParent/one[child]")}, {Tests: []string{"TestParent"}, Selection: literalTestSelection("TestParent/two+child")}}
	encodings, err = componentGroupSelections([]string{"TestParent"}, paths, true)
	if err != nil || len(encodings) != len(paths) {
		t.Fatal("literal child partitions were refused", encodings, err)
	}
	for i, encoding := range encodings {
		if encoding.run != paths[i].Selection || encoding.skip != "" {
			t.Fatal("complement encoding changed a literal child selection", encoding)
		}
	}
}

// full_only: false
func TestComponentNativeComplementKeepsOneProcessAndExcludedRoots(t *testing.T) {
	root := t.TempDir()
	writeLocalGoFixture(t, root, "core/go.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
	selected := longComponentSelectionRoots("Selected", 300)
	const memory = "TestOrdinaryOutputMemoryNativeArtifact"
	const excluded = "TestExcludedFullOnly"
	var source strings.Builder
	source.WriteString(`package core
import ("encoding/json"; "os"; "testing")
var entered int
func observe(t *testing.T) {
 t.Helper()
 file, err := os.OpenFile(os.Getenv("ENKV_COMPONENT_SELECTION_WITNESS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 err = json.NewEncoder(file).Encode(struct{Name string; PID, State int}{t.Name(), os.Getpid(), entered})
 if closeErr := file.Close(); err != nil || closeErr != nil { t.Fatal(err, closeErr) }
 entered++
 t.Run("literal[child]", func(t *testing.T) {})
}
`)
	for _, name := range append(slices.Clone(selected), memory) {
		fmt.Fprintf(&source, "// full_only: false\nfunc %s(t *testing.T) { observe(t) }\n", name)
	}
	fmt.Fprintf(&source, "// full_only: true\nfunc %s(t *testing.T) { t.Fatal(\"excluded root executed\") }\n", excluded)
	writeLocalGoFixture(t, root, "core/selection_test.go", source.String())
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "selection.test")
	flags := compilerBuildFlags([]string{"-mod=readonly"}, raceEnabled(ctx))
	args := append([]string{"test"}, flags...)
	args = append(args, "-c", "-o", binary, ".")
	if _, err := runGo(ctx, root, "core", args...); err != nil {
		t.Fatal("compile native complement fixture", err)
	}
	witness := filepath.Join(t.TempDir(), "observations.jsonl")
	env := environment(goEnvironment(), map[string]string{"ENKV_COMPONENT_SELECTION_WITNESS": witness})
	converter := testEventConverterFixture(t, root)
	process, evidence, _, _ := executeFixtureProfileComponentChecks(t, nil, ctx, root, binary, converter, flags, env, "dev", nil, 1, io.Discard, nil)
	if process.Status != "passed" || !process.Started || !process.Joined || process.Cause != nil || !evidence.TestsComplete || len(evidence.Groups) != 2 || !slices.Equal(evidence.NotSelected, []string{excluded}) || !completeComponentEvidence(evidence, "hermetic", "memory") {
		t.Fatal("native complement lost exact profile completion or process custody", process, evidence)
	}
	for _, fact := range evidence.Diagnostics.Commands {
		if fact.Phase == "test" || fact.Phase == "conversion" {
			wantEvents := "not_run"
			if fact.Phase == "conversion" {
				wantEvents = "valid"
			}
			if !fact.Started || !fact.Joined || fact.Process != "passed" || fact.Events != wantEvents {
				t.Fatal("native complement lost positively joined test/conversion evidence", fact)
			}
		}
	}
	body, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := decodeObjects[struct {
		Name       string
		PID, State int
	}](body)
	if err != nil || len(rows) != len(selected)+1 || rows[len(selected)].Name != memory || rows[len(selected)].State != 0 {
		t.Fatal("native complement omitted roots or repeated the memory root", len(rows), err)
	}
	ordinaryPID := rows[0].PID
	if ordinaryPID <= 0 || rows[len(selected)].PID == ordinaryPID {
		t.Fatal("fresh memory process lost isolation", rows[0], rows[len(selected)])
	}
	for i, row := range rows[:len(selected)] {
		if row.Name != selected[i] || row.PID != ordinaryPID || row.State != i {
			t.Fatal("complete ordinary group was split, reordered or widened", i, row)
		}
	}
}

// full_only: false
func TestComponentPlacementKeepsLargeAcceptedInventory(t *testing.T) {
	const parent, helper = "TestScenarioPhaseRetainsFailureEvidence", "TestScenarioPhaseFailureChild"
	inventory := append(longComponentSelectionRoots("LargeInventory", 1198), parent, helper)
	for _, parallel := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("parallel=%d", parallel), func(t *testing.T) {
			selected, omitted, groups, focus, err := resolveComponentGroups(inventory, componentFixtureClassifications(inventory), "dev", nil, parallel, nil)
			if err != nil || focus != nil || len(omitted) != 0 || !slices.Equal(selected, inventory) {
				t.Fatal("normal placement changed its accepted complete selection", err)
			}
			encodings, err := componentGroupSelections(inventory, groups, false)
			if err != nil || len(encodings) != len(groups) {
				t.Fatal("parallel placement refused an accepted bounded native selection", err, len(groups))
			}
			seen, workers := map[string]int{}, map[int]bool{}
			helperGroup, parentGroup := -1, -1
			for i, group := range groups {
				if group.Exclusive || group.Worker < 1 || group.Worker > parallel {
					t.Fatal("normal roots left their assigned capacity", group)
				}
				workers[group.Worker] = true
				if len(encodings[i].run)+len(encodings[i].skip) > maximumComponentSelectionBytes {
					t.Fatal("native partition exceeded its selection bound")
				}
				run := regexp.MustCompile(encodings[i].run)
				var skip *regexp.Regexp
				if encodings[i].skip != "" {
					skip = regexp.MustCompile(encodings[i].skip)
				}
				for _, name := range inventory {
					matched := run.MatchString(name) && (skip == nil || !skip.MatchString(name))
					if matched != slices.Contains(group.Tests, name) {
						t.Fatal("native partition differs from its exact assigned roots", i, name)
					}
					if matched {
						seen[name]++
					}
				}
				if slices.Contains(group.Tests, helper) {
					helperGroup = i
				}
				if slices.Contains(group.Tests, parent) {
					parentGroup = i
				}
			}
			if len(workers) != parallel || len(seen) != len(inventory) || parentGroup < 0 || helperGroup != parentGroup {
				t.Fatal("bounded native partitions lost workers, roots or helper custody", len(workers), len(seen), helperGroup, parentGroup)
			}
			for name, count := range seen {
				if count != 1 {
					t.Fatal("complete root has multiple native owners", name, count)
				}
			}
		})
	}
}
