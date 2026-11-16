package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func ordinaryEvents(events ...ordinaryEvent) []byte {
	var body bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&body).Encode(event); err != nil {
			panic(err)
		}
	}
	return body.Bytes()
}

// full_only: false
func TestOrdinaryChecksAcceptGoMetadata(t *testing.T) {
	const pkg = "example.org/ordinary"
	body := ordinaryEvents(
		ordinaryEvent{Action: "start", Package: pkg},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "attr", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "artifacts", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "pass", Package: pkg},
	)
	if _, err := validateOrdinaryEvents(body, map[string][]string{pkg: {"TestAlpha"}}, nil); err != nil {
		t.Fatal("supported Go metadata broke execution proof", err)
	}
}

// full_only: false
func TestOrdinaryChecksRequireCompleteExecution(t *testing.T) {
	const pkg = "example.org/ordinary"
	t.Run("package-subtests-exceed-old-per-root-row-limit", func(t *testing.T) {
		events := []ordinaryEvent{{Action: "start", Package: pkg}}
		for index, root := range []string{"TestFirst", "TestSecond"} {
			events = append(events, ordinaryEvent{Action: "run", Package: pkg, Test: root})
			for child := range 4096 + index {
				name := fmt.Sprintf("%s/case_%04d", root, child)
				events = append(events, ordinaryEvent{Action: "run", Package: pkg, Test: name}, ordinaryEvent{Action: "pass", Package: pkg, Test: name})
			}
			events = append(events, ordinaryEvent{Action: "pass", Package: pkg, Test: root})
		}
		events = append(events, ordinaryEvent{Action: "pass", Package: pkg})
		results, err := validateOrdinaryEvents(ordinaryEvents(events...), map[string][]string{pkg: {"TestFirst", "TestSecond"}}, nil)
		if err != nil || len(results) != 8195 {
			t.Fatalf("compatible package subtests lost terminal rows: got %d want 8195: %v", len(results), err)
		}
		for _, result := range results {
			if result.Package != pkg || result.Outcome != "pass" {
				t.Fatal("package subtest changed its exact terminal", result)
			}
		}
	})
	want := map[string][]string{pkg: {"TestAlpha", "TestBeta", "ExampleRead", "FuzzDecode"}}
	complete := []ordinaryEvent{
		{Action: "start", Package: pkg},
		{Action: "run", Package: pkg, Test: "TestAlpha"},
		{Action: "run", Package: pkg, Test: "TestAlpha/child"},
		{Action: "pass", Package: pkg, Test: "TestAlpha/child"},
		{Action: "pass", Package: pkg, Test: "TestAlpha"},
		{Action: "run", Package: pkg, Test: "TestBeta"},
		{Action: "pass", Package: pkg, Test: "TestBeta"},
		{Action: "run", Package: pkg, Test: "ExampleRead"},
		{Action: "pass", Package: pkg, Test: "ExampleRead"},
		{Action: "run", Package: pkg, Test: "FuzzDecode"},
		{Action: "run", Package: pkg, Test: "FuzzDecode/seed#0"},
		{Action: "pass", Package: pkg, Test: "FuzzDecode/seed#0"},
		{Action: "pass", Package: pkg, Test: "FuzzDecode"},
		{Action: "pass", Package: pkg},
	}
	if _, err := validateOrdinaryEvents(ordinaryEvents(complete...), want, nil); err != nil {
		t.Fatal("complete ordinary execution refused:", err)
	}
	for _, test := range []struct {
		name   string
		events []ordinaryEvent
	}{
		{"top_level_skip", replaceOrdinaryEvent(complete, 6, ordinaryEvent{Action: "skip", Package: pkg, Test: "TestBeta"})},
		{"subtest_skip", replaceOrdinaryEvent(complete, 3, ordinaryEvent{Action: "skip", Package: pkg, Test: "TestAlpha/child"})},
		{"subtest_failure", replaceOrdinaryEvent(complete, 3, ordinaryEvent{Action: "fail", Package: pkg, Test: "TestAlpha/child"})},
		{"missing_top_level", append([]ordinaryEvent{}, complete[:5]...)},
		{"missing_terminal", append(append([]ordinaryEvent{}, complete[:6]...), complete[7:]...)},
		{"duplicate_terminal", append(append([]ordinaryEvent{}, complete[:7]...), complete[6:]...)},
		{"missing_subtest_terminal", append(append([]ordinaryEvent{}, complete[:3]...), complete[4:]...)},
		{"missing_package_terminal", complete[:len(complete)-1]},
		{"duplicate_package_terminal", append(append([]ordinaryEvent{}, complete...), ordinaryEvent{Action: "pass", Package: pkg})},
		{"zero_test_required_package", []ordinaryEvent{{Action: "start", Package: pkg}, {Action: "skip", Package: pkg}}},
		{"omitted_package", []ordinaryEvent{{Action: "start", Package: "example.org/other"}, {Action: "pass", Package: "example.org/other"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateOrdinaryEvents(ordinaryEvents(test.events...), want, nil); err == nil {
				t.Fatal("incomplete ordinary execution passed")
			}
		})
	}
	for name, body := range map[string][]byte{
		"truncated_json":  []byte(`{"Action":"start","Package":"` + pkg),
		"invalid_event":   []byte(`{"Action":"unknown","Package":"` + pkg + `"}` + "\n"),
		"trailing_damage": append(ordinaryEvents(complete...), []byte("partial")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateOrdinaryEvents(body, want, nil); err == nil {
				t.Fatal("damaged event stream passed")
			}
		})
	}
	t.Run("failure-preserves-later-packages", func(t *testing.T) {
		const later = "example.org/later"
		failed := []ordinaryEvent{
			{Action: "start", Package: pkg},
			{Action: "run", Package: pkg, Test: "TestAlpha"},
			{Action: "fail", Package: pkg, Test: "TestAlpha"},
			{Action: "fail", Package: pkg},
			{Action: "start", Package: later},
			{Action: "run", Package: later, Test: "TestBeta"},
		}
		for _, spec := range []struct {
			name      string
			following []ordinaryEvent
			observed  map[string]string
		}{
			{"second-failure", []ordinaryEvent{
				{Action: "fail", Package: later, Test: "TestBeta"},
				{Action: "fail", Package: later},
			}, map[string]string{pkg + "\x00TestAlpha": "fail", later + "\x00TestBeta": "fail", later + "\x00TestNeverStarted": "not_run"}},
			{"second-incomplete", []ordinaryEvent{
				{Action: "run", Package: later, Test: "TestBeta/finished"},
				{Action: "fail", Package: later, Test: "TestBeta/finished"},
				{Action: "run", Package: later, Test: "TestBeta/waiting"},
			}, map[string]string{pkg + "\x00TestAlpha": "fail", later + "\x00TestBeta": "incomplete", later + "\x00TestBeta/finished": "fail", later + "\x00TestBeta/waiting": "incomplete", later + "\x00TestNeverStarted": "not_run"}},
		} {
			t.Run(spec.name, func(t *testing.T) {
				events := append(append([]ordinaryEvent{}, failed...), spec.following...)
				results, err := validateOrdinaryEvents(ordinaryEvents(events...), map[string][]string{pkg: {"TestAlpha"}, later: {"TestBeta", "TestNeverStarted"}}, nil)
				if err == nil {
					t.Fatal("failed execution qualified")
				}
				observed := make(map[string]string, len(results))
				for _, result := range results {
					key := result.Package + "\x00" + result.Name
					if result.Name == "TestNeverStarted" && (result.StartedAt != nil || result.FinishedAt != nil || result.ElapsedSeconds != nil) {
						t.Fatal("unstarted selection acquired execution timestamps", result)
					}
					if _, repeated := observed[key]; repeated {
						t.Fatal("failure evidence repeated an observed test")
					}
					observed[key] = result.Outcome
				}
				if !reflect.DeepEqual(observed, spec.observed) {
					t.Fatalf("failure lost completed or unfinished selections: got %v want %v", observed, spec.observed)
				}
			})
		}
	})
	t.Run("failure-prefix-before-damage", func(t *testing.T) {
		prefix := ordinaryEvents(
			ordinaryEvent{Action: "start", Package: pkg},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha/failed"},
			ordinaryEvent{Action: "fail", Package: pkg, Test: "TestAlpha/failed"},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha/waiting"},
		)
		for _, spec := range []struct{ name, tail string }{
			{"malformed", "not-json\n"},
			{"truncated", `{"Action":"fail","Package":"` + pkg},
			{"malformed-before-later-events", "not-json\n" + string(ordinaryEvents(
				ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha/after-damage"},
				ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha/after-damage"},
			))},
		} {
			t.Run(spec.name, func(t *testing.T) {
				body := append(append([]byte{}, prefix...), spec.tail...)
				results, err := validateOrdinaryEvents(body, map[string][]string{pkg: {"TestAlpha", "TestNeverStarted"}}, nil)
				if err == nil {
					t.Fatal("damaged execution qualified")
				}
				observed := make(map[string]string, len(results))
				for _, result := range results {
					if result.Package != pkg {
						t.Fatal("damaged execution invented a package")
					}
					if _, repeated := observed[result.Name]; repeated {
						t.Fatal("damaged execution repeated an observation")
					}
					observed[result.Name] = result.Outcome
				}
				want := map[string]string{"TestAlpha": "incomplete", "TestAlpha/failed": "fail", "TestAlpha/waiting": "incomplete", "TestNeverStarted": "incomplete"}
				for _, result := range results {
					if result.Name == "TestNeverStarted" && (result.StartedAt != nil || result.FinishedAt != nil || result.ElapsedSeconds != nil) {
						t.Fatal("damaged capture invented unobserved execution timestamps", result)
					}
				}
				if !reflect.DeepEqual(observed, want) {
					t.Fatalf("damaged tail erased its valid failure prefix or invented a terminal: got %v want %v", observed, want)
				}
			})
		}
	})
}

func replaceOrdinaryEvent(events []ordinaryEvent, index int, event ordinaryEvent) []ordinaryEvent {
	copyOf := append([]ordinaryEvent{}, events...)
	copyOf[index] = event
	return copyOf
}

// full_only: false
func TestTestEventRowsPreserveObservedTiming(t *testing.T) {
	const started = "2026-10-08T06:00:00Z"
	const finished = "2026-10-08T06:00:02Z"
	for _, spec := range []struct {
		name, runTime, terminalFields string
		wantStarted, wantFinished     string
		wantElapsed                   float64
		elapsedObserved               bool
		incomplete                    bool
	}{
		{name: "explicit-zero", runTime: `,"Time":"` + started + `"`, terminalFields: `,"Time":"` + finished + `","Elapsed":0`, wantStarted: started, wantFinished: finished, elapsedObserved: true},
		{name: "reported-elapsed", runTime: `,"Time":"` + started + `"`, terminalFields: `,"Time":"` + finished + `","Elapsed":0.25`, wantStarted: started, wantFinished: finished, wantElapsed: 0.25, elapsedObserved: true},
		{name: "unobserved"},
		{name: "terminal-time-only", terminalFields: `,"Time":"` + finished + `"`, wantFinished: finished},
		{name: "incomplete", runTime: `,"Time":"` + started + `"`, wantStarted: started, incomplete: true},
	} {
		t.Run(spec.name, func(t *testing.T) {
			body := fmt.Appendf(nil, "{\"Action\":\"start\",\"Package\":%q}\n{\"Action\":\"run\",\"Package\":%q,\"Test\":\"TestTiming\"%s}\n", componentPackage, componentPackage, spec.runTime)
			if !spec.incomplete {
				body = fmt.Appendf(body, "{\"Action\":\"pass\",\"Package\":%q,\"Test\":\"TestTiming\"%s}\n{\"Action\":\"pass\",\"Package\":%q}\n", componentPackage, spec.terminalFields, componentPackage)
			}
			checkRow := func(t *testing.T, rows any, component bool) {
				t.Helper()
				encoded, err := json.Marshal(rows)
				if err != nil {
					t.Fatal(err)
				}
				var saved []map[string]any
				if err := json.Unmarshal(encoded, &saved); err != nil || len(saved) != 1 {
					t.Fatal("timing evidence lost its one observed test", string(encoded), err)
				}
				row := saved[0]
				for _, field := range []struct{ name, want string }{{"started_at", spec.wantStarted}, {"finished_at", spec.wantFinished}} {
					got, present := row[field.name]
					if field.want == "" {
						if present {
							t.Errorf("unobserved %s was invented: %v", field.name, got)
						}
					} else if got != field.want {
						t.Errorf("observed %s was lost: got %v want %s", field.name, got, field.want)
					}
				}
				elapsed, present := row["elapsed_seconds"]
				if spec.elapsedObserved {
					if !present || elapsed != spec.wantElapsed {
						t.Errorf("reported elapsed was lost or inferred from timestamps: got %v want %v", elapsed, spec.wantElapsed)
					}
				} else if !component && present {
					t.Error("unreported ordinary elapsed was invented", elapsed)
				}
				if component && row["elapsed_observed"] != spec.elapsedObserved {
					t.Error("component elapsed availability does not distinguish explicit zero from unknown", row)
				}
			}
			t.Run("ordinary", func(t *testing.T) {
				rows, err := validateOrdinaryEvents(body, map[string][]string{componentPackage: {"TestTiming"}}, nil)
				if (err != nil) != spec.incomplete {
					t.Fatal("timing changed execution qualification", err)
				}
				checkRow(t, rows, false)
			})
			t.Run("component", func(t *testing.T) {
				state, err := newTestEventState(map[string][]string{componentPackage: {"TestTiming"}}, maximumComponentTests, validComponentName, nil)
				if err != nil {
					t.Fatal(err)
				}
				stream := &testEventStream{state: state}
				_, _ = stream.Write(body)
				if (stream.complete() != nil) != spec.incomplete {
					t.Fatal("timing changed component event qualification")
				}
				checkRow(t, state.componentTests(), true)
			})
		})
	}
}

// full_only: false
func TestOrdinaryChecksAcceptOnlyProvedHelperSkips(t *testing.T) {
	const pkg = "enkv.sh/core/internal/testmain"
	want := map[string][]string{pkg: {"TestLiveRun", "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent"}}
	events := []ordinaryEvent{
		{Action: "start", Package: pkg},
		{Action: "run", Package: pkg, Test: "TestLiveRun"},
		{Action: "skip", Package: pkg, Test: "TestLiveRun"},
		{Action: "run", Package: pkg, Test: "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent"},
		{Action: "run", Package: pkg, Test: "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent/passed"},
		{Action: "pass", Package: pkg, Test: "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent/passed"},
		{Action: "pass", Package: pkg, Test: "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent"},
		{Action: "pass", Package: pkg},
	}
	if _, err := validateOrdinaryEvents(ordinaryEvents(events...), want, ordinaryRunnerHelperProofs); err != nil {
		t.Fatal("proved helper skip refused:", err)
	}
	for _, test := range []struct {
		name   string
		events []ordinaryEvent
	}{
		{"bare_skip", append(append([]ordinaryEvent{}, events[:3]...), ordinaryEvent{Action: "pass", Package: pkg})},
		{"parent_without_role_case", append(append([]ordinaryEvent{}, events[:4]...), events[6:]...)},
		{"unrelated_parent", replaceOrdinaryEvent(events, 4, ordinaryEvent{Action: "run", Package: pkg, Test: "TestOther/passed"})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateOrdinaryEvents(ordinaryEvents(test.events...), want, ordinaryRunnerHelperProofs); err == nil {
				t.Fatal("helper skip without exact role proof passed")
			}
		})
	}
}

// full_only: false
func TestOrdinaryChecksAllowOnlyDeclaredTestlessPackages(t *testing.T) {
	const pkg = "enkv.sh/plugins/generators/cloudflare-account-token/cmd/enkv-generator-cloudflare"
	stream := ordinaryEvents(ordinaryEvent{Action: "start", Package: pkg}, ordinaryEvent{Action: "skip", Package: pkg})
	if _, err := validateOrdinaryEvents(stream, map[string][]string{pkg: nil}, nil); err != nil {
		t.Fatal("declared testless command refused:", err)
	}
	if _, err := validateOrdinaryEvents(stream, map[string][]string{"example.org/unlisted": nil}, nil); err == nil || !strings.Contains(err.Error(), "package") {
		t.Fatal("unlisted testless package passed:", err)
	}
}

// full_only: false
func TestOrdinaryChecksAcceptSlashInOneSubtestName(t *testing.T) {
	const pkg = "example.org/ordinary"
	body := ordinaryEvents(
		ordinaryEvent{Action: "start", Package: pkg},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha/1/4"},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha/1/4"},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "pass", Package: pkg},
	)
	if _, err := validateOrdinaryEvents(body, map[string][]string{pkg: {"TestAlpha"}}, nil); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestOrdinaryChecksAcceptLongSubtestName(t *testing.T) {
	const pkg = "example.org/ordinary"
	name := "TestAlpha/" + strings.Repeat("x", 300)
	body := ordinaryEvents(
		ordinaryEvent{Action: "start", Package: pkg},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "run", Package: pkg, Test: name},
		ordinaryEvent{Action: "pass", Package: pkg, Test: name},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "pass", Package: pkg},
	)
	if _, err := validateOrdinaryEvents(body, map[string][]string{pkg: {"TestAlpha"}}, nil); err != nil {
		t.Fatal("valid long subtest refused:", err)
	}
}

// full_only: false
func TestOrdinaryChecksAcceptSiblingNameWithSlashPrefix(t *testing.T) {
	const pkg = "example.org/ordinary"
	body := ordinaryEvents(
		ordinaryEvent{Action: "start", Package: pkg},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha/providers/aws"},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha/providers/aws"},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha/providers/aws/google.golang.org/api/storage/v1"},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha/providers/aws/google.golang.org/api/storage/v1"},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "pass", Package: pkg},
	)
	if _, err := validateOrdinaryEvents(body, map[string][]string{pkg: {"TestAlpha"}}, nil); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestOrdinaryCommandDiscoversAndChecksTheSamePackage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/ordinary\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "package"), 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "package", "package_test.go")
	passing := "package sample\nimport (\"flag\"; \"testing\")\n// full_only: false\nfunc TestAlpha(t *testing.T) { if got := flag.Lookup(\"test.timeout\").Value.String(); got != \"10m0s\" { t.Fatalf(\"timeout=%s\", got) }; t.Run(\"child\", func(t *testing.T) {}) }\n"
	if err := os.WriteFile(source, []byte(passing), 0600); err != nil {
		t.Fatal(err)
	}
	var evidence ordinaryStepEvidence
	err := executeOrdinaryCommand(context.Background(), root, ".", "full", []string{"-mod=readonly"}, []string{"./package"}, "", nil, &evidence)
	if err != nil || len(evidence.Packages) != 1 || len(evidence.Packages[0].Tests) != 1 ||
		evidence.Packages[0].Tests[0] != "TestAlpha" || len(evidence.Tests) != 2 {
		t.Fatalf("ordinary command inventory or terminals differ: evidence=%+v error=%v", evidence, err)
	}
	var public map[string]any
	encoded, err := json.Marshal(evidence)
	if err != nil || json.Unmarshal(encoded, &public) != nil {
		t.Fatal("ordinary command evidence could not be serialized", err)
	}
	if public["event_time_source"] != "go_test_json" {
		t.Error("ordinary event timestamps lack execution provenance", public["event_time_source"])
	}
	checkRecordedCommand(t, evidence, "test", "passed", "valid")
	if err := os.WriteFile(source, []byte(strings.Replace(passing, "func(t *testing.T) {}", "func(t *testing.T) { t.Skip(\"required\") }", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	evidence = ordinaryStepEvidence{}
	if err := executeOrdinaryCommand(context.Background(), root, ".", "full", []string{"-mod=readonly"}, []string{"./package"}, "", nil, &evidence); err == nil {
		t.Fatal("real skipped subtest passed ordinary validation")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package", "package.go"), []byte("package sample\n"), 0600); err != nil {
		t.Fatal(err)
	}
	evidence = ordinaryStepEvidence{}
	if err := executeOrdinaryCommand(context.Background(), root, ".", "full", []string{"-mod=readonly"}, []string{"./package"}, "", nil, &evidence); err == nil {
		t.Fatal("real required package without tests passed ordinary discovery")
	}
}

func checkRecordedCommand(t *testing.T, evidence any, phase, process, events string) {
	t.Helper()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Diagnostics struct {
			Commands []struct {
				Phase, Scope, Process string
				Started, Joined       *bool
				WallSeconds           *float64 `json:"wall_seconds"`
				Events                string
				ToolCleanup           string `json:"tool_cleanup"`
			}
		}
	}
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal("check command facts could not be read", err)
	}
	found := false
	for _, command := range saved.Diagnostics.Commands {
		if command.Phase != phase {
			continue
		}
		if found {
			t.Fatal("one controlled command was recorded more than once", phase)
		}
		found = true
		if command.Scope == "" || command.Process != process || command.Events != events || command.ToolCleanup != "not_required" ||
			command.Started == nil || !*command.Started || command.Joined == nil || !*command.Joined || command.WallSeconds == nil || *command.WallSeconds <= 0 {
			t.Error("joined command lost separate execution, event, duration or cleanup facts", phase, command)
		}
	}
	if !found {
		t.Error("controlled command has no retained diagnostic facts", phase)
	}
}

// full_only: false
func TestOrdinaryCommandFactsKeepMissingAndIncompleteNodes(t *testing.T) {
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "example.org/ordinary"
	for _, spec := range []struct {
		name, process, events, requested string
		following                        []ordinaryEvent
		exit                             int
		tail                             string
	}{
		{"missing", "passed", "valid", "missing", []ordinaryEvent{{Action: "pass", Package: pkg, Test: "TestParent"}, {Action: "pass", Package: pkg}}, 0, ""},
		{"incomplete", "process_failed", "incomplete", "incomplete", []ordinaryEvent{{Action: "run", Package: pkg, Test: "TestParent/child"}}, 1, ""},
		{"malformed-before-child", "process_failed", "malformed", "unavailable", nil, 1, "not-json\n"},
		{"truncated-before-child", "process_failed", "truncated", "unavailable", nil, 1, `{"Action":"run"`},
		{"failed-child-before-damage", "process_failed", "malformed", "failed", []ordinaryEvent{{Action: "run", Package: pkg, Test: "TestParent/child"}, {Action: "fail", Package: pkg, Test: "TestParent/child"}}, 1, "not-json\n"},
		{"incomplete-child-before-damage", "process_failed", "malformed", "incomplete", []ordinaryEvent{{Action: "run", Package: pkg, Test: "TestParent/child"}}, 1, "not-json\n"},
	} {
		t.Run(spec.name, func(t *testing.T) {
			root := t.TempDir()
			writeLocalGoFixture(t, root, "go.mod", "module "+pkg+"\n\ngo 1.27.0\n")
			events := append([]ordinaryEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: "TestParent"}}, spec.following...)
			body := string(ordinaryEvents(events...)) + spec.tail
			script := `#!/bin/sh
if [ "$#" -eq 4 ] && [ "$1" = mod ] && [ "$2" = edit ] && [ "$3" = -json ]; then
 case "$4" in -modfile=?*) exec ` + shellQuote(realGo) + ` "$@" ;; esac
fi
` + "printf '%s' '" + strings.ReplaceAll(body, "'", "'\"'\"'") + "'\nexit " + fmt.Sprint(spec.exit) + "\n"
			if err := os.WriteFile(filepath.Join(root, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			focus := ordinaryFocus{Package: pkg, Tests: []string{"TestParent/child"}}
			var evidence ordinaryStepEvidence
			err := executeOrdinaryInventory(t.Context(), t.Context(), root, ".", nil, []string{"."}, "^TestParent$/^child$", map[string][]string{pkg: {"TestParent"}}, nil, &focus, &evidence)
			if err == nil || evidence.Complete || evidence.SelectedComplete {
				t.Fatal("absent selected terminal acquired completion authority")
			}
			checkRecordedCommand(t, evidence, "test", spec.process, spec.events)
			encoded, err := json.Marshal(evidence)
			var saved struct {
				Diagnostics struct {
					Commands []struct {
						Phase     string
						Requested string `json:"requested_node"`
					}
				}
			}
			if err != nil || json.Unmarshal(encoded, &saved) != nil || len(saved.Diagnostics.Commands) != 1 || saved.Diagnostics.Commands[0].Requested != spec.requested {
				t.Error("missing and started-but-incomplete selection were merged", string(encoded), err)
			}
		})
	}
}

// full_only: false
func TestOrdinaryEventStatusDoesNotGrantCompletion(t *testing.T) {
	const pkg = "example.org/ordinary"
	prefix := []ordinaryEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: "TestAlpha"}}
	for _, spec := range []struct {
		name, status, tail, observed, unstarted string
		following                               []ordinaryEvent
	}{
		{name: "well-formed-failure", status: "valid", observed: "fail", unstarted: "not_run", following: []ordinaryEvent{{Action: "fail", Package: pkg, Test: "TestAlpha"}, {Action: "fail", Package: pkg}}},
		{name: "incomplete", status: "incomplete", observed: "incomplete", unstarted: "not_run"},
		{name: "malformed", status: "malformed", tail: "not-json\n", observed: "incomplete", unstarted: "incomplete"},
		{name: "truncated", status: "truncated", tail: `{"Action":"fail"`, observed: "incomplete", unstarted: "incomplete"},
	} {
		t.Run(spec.name, func(t *testing.T) {
			events := append(append([]ordinaryEvent{}, prefix...), spec.following...)
			body := append(ordinaryEvents(events...), spec.tail...)
			rows, status, err := parseOrdinaryEvents(body, map[string][]string{pkg: {"TestAlpha", "TestNeverStarted"}}, nil)
			want := []ordinaryTest{{Package: pkg, Name: "TestAlpha", Outcome: spec.observed}, {Package: pkg, Name: "TestNeverStarted", Outcome: spec.unstarted}}
			if err == nil || status != spec.status || !reflect.DeepEqual(rows, want) {
				t.Error("event availability was confused with qualification or lost observed scope", status, rows, err)
			}
		})
	}
}

// full_only: false
func TestOrdinaryCommandKeepsTimeoutOutOfPackageDiscovery(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/ordinary\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "package"), 0700); err != nil {
		t.Fatal(err)
	}
	source := "package sample\nimport (\"flag\"; \"testing\")\n// full_only: false\nfunc TestTimeout(t *testing.T) { if got := flag.Lookup(\"test.timeout\").Value.String(); got != \"15m0s\" { t.Fatalf(\"timeout=%s\", got) } }\n"
	if err := os.WriteFile(filepath.Join(root, "package", "package_test.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name        string
		pattern     string
		packageName string
	}{
		{"package", "./package", "example.org/ordinary/package"},
		{"launcher_files", "./package/package_test.go", "command-line-arguments"},
	} {
		t.Run(row.name, func(t *testing.T) {
			var evidence ordinaryStepEvidence
			err := executeOrdinaryCommand(t.Context(), root, ".", "full", []string{"-mod=readonly"}, []string{row.pattern}, "", nil, &evidence, "-timeout=15m")
			if err != nil || len(evidence.Packages) != 1 || evidence.Packages[0].Name != row.packageName ||
				len(evidence.Packages[0].Tests) != 1 || evidence.Packages[0].Tests[0] != "TestTimeout" ||
				len(evidence.Tests) != 1 || evidence.Tests[0].Outcome != "pass" {
				t.Fatalf("ordinary timeout path differs: evidence=%+v error=%v", evidence, err)
			}
		})
	}
}

// full_only: false
func TestOrdinaryProviderHelperRequiresSamePackageCompletedParent(t *testing.T) {
	const helper = "TestConfigurationRecoveryLiveParentControl"
	const parent = "TestConfigurationRecoveryLiveParentInvokesControl"
	for _, pkg := range []string{"enkv.sh/compositions/aws", "enkv.sh/providers/gcp"} {
		t.Run(pkg, func(t *testing.T) {
			proofs := map[string]string{pkg + "\x00" + helper: parent}
			events := []ordinaryEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: helper}, {Action: "skip", Package: pkg, Test: helper}, {Action: "run", Package: pkg, Test: parent}, {Action: "pass", Package: pkg, Test: parent}, {Action: "pass", Package: pkg}}
			want := map[string][]string{pkg: {helper, parent}}
			if _, err := validateOrdinaryEvents(ordinaryEvents(events...), want, proofs); err != nil {
				t.Fatal("same-package completed helper parent refused", err)
			}
			for _, row := range []struct {
				name   string
				events []ordinaryEvent
				want   map[string][]string
				proofs map[string]string
			}{
				{"wrong-package", events, want, map[string]string{"other/package\x00" + helper: parent}},
				{"missing-parent", events[:3], map[string][]string{pkg: {helper}}, proofs},
				{"failed-parent", replaceOrdinaryEvent(events, 4, ordinaryEvent{Action: "fail", Package: pkg, Test: parent}), want, proofs},
				{"unknown-helper", events, want, nil},
			} {
				t.Run(row.name, func(t *testing.T) {
					if _, err := validateOrdinaryEvents(ordinaryEvents(row.events...), row.want, row.proofs); err == nil {
						t.Fatal("unproved helper accepted")
					}
				})
			}
		})
	}
}

// full_only: false
func TestOrdinaryOutputCommandRegistrations(t *testing.T) {
	commands := []string{
		"enkv.sh/plugins/outputs/aws-secrets-manager/cmd/enkv-output-aws-secrets-manager",
		"enkv.sh/plugins/outputs/gcp-secret-manager/cmd/enkv-output-gcp-secret-manager",
		"enkv.sh/plugins/outputs/github-actions/cmd/enkv-output-github-repository",
		"enkv.sh/plugins/outputs/github-actions/cmd/enkv-output-github-environment",
		"enkv.sh/plugins/outputs/github-actions/cmd/enkv-output-github-organization",
		"enkv.sh/tests/fixtures/output-contract-test/cmd/enkv-output-contract-test",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			pkg := command
			body := ordinaryEvents(ordinaryEvent{Action: "start", Package: pkg}, ordinaryEvent{Action: "skip", Package: pkg})
			if _, err := validateOrdinaryEvents(body, map[string][]string{pkg: nil}, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
	const unknown = "enkv.sh/tests/fixtures/output-contract-test/cmd/unknown"
	body := ordinaryEvents(ordinaryEvent{Action: "start", Package: unknown}, ordinaryEvent{Action: "skip", Package: unknown})
	if _, err := validateOrdinaryEvents(body, map[string][]string{unknown: nil}, nil); err == nil {
		t.Fatal("unknown testless command accepted")
	}
}

func resolveOneOrdinaryFocusFixture(artifacts []ordinaryArtifact, requested ordinaryFocus) (ordinaryFocus, ordinaryArtifact, error) {
	selections, err := resolveOrdinaryFocusSet(artifacts, requested)
	if err != nil {
		return requested, ordinaryArtifact{}, err
	}
	if len(selections) != 1 {
		return requested, ordinaryArtifact{}, errors.New("ordinary focus requires one artifact")
	}
	focus := selections[0]
	index := slices.IndexFunc(artifacts, func(artifact ordinaryArtifact) bool { return artifact.Owner == focus.Artifact })
	return focus, artifacts[index], nil
}

// full_only: false
func TestOrdinaryFocusResolvesOneArtifact(t *testing.T) {
	artifacts := []ordinaryArtifact{
		{Owner: "tests/shared/runner", Package: "example.org/runner", Tests: []string{"TestParent", "ExampleRead", "FuzzDecode", "TestÉcriture"}},
		{Owner: "tests/shared/records", Package: "example.org/records", Tests: []string{"TestRecord"}},
		{Owner: "tests/shared/catalog", Package: "example.org/catalog", Tests: []string{"TestCatalog"}},
		{Owner: "tests/scripts/bootstrap.go", Package: "command-line-arguments", Tests: []string{"TestLauncher"}},
	}
	for index := range artifacts {
		setOrdinaryArtifactFixtureMetadata(&artifacts[index])
	}
	for _, requested := range []string{"TestParent/child[1]", "ExampleRead", "FuzzDecode/seed#0", "TestLauncher/empty", "TestÉcriture"} {
		focus, artifact, err := resolveOneOrdinaryFocusFixture(artifacts, ordinaryFocus{Tests: []string{requested}})
		if err != nil || focus.Artifact != artifact.Owner || literalTestSelection(focus.Tests[0]) != literalTestSelection(requested) {
			t.Fatal("ordinary owner or literal selector differs", focus, err)
		}
		if len(artifacts[0].Tests) != 4 || len(artifacts) != 4 {
			t.Fatal("focus mutated admitted inventories")
		}
	}
	for _, row := range []struct {
		name      string
		artifacts []ordinaryArtifact
		focus     ordinaryFocus
	}{
		{"missing", artifacts, ordinaryFocus{Tests: []string{"TestMissing"}}},
		{"duplicate-root", append(append([]ordinaryArtifact{}, artifacts...), ordinaryArtifact{Owner: "another-artifact", Package: "command-line-arguments", Tests: []string{"TestParent"}}), ordinaryFocus{Tests: []string{"TestParent/child"}}},
		{"duplicate-artifact", append(append([]ordinaryArtifact{}, artifacts...), artifacts[0]), ordinaryFocus{Tests: []string{"TestParent"}}},
		{"empty-inventory", []ordinaryArtifact{{Owner: "owner", Package: "example.org/empty"}}, ordinaryFocus{Tests: []string{"TestParent"}}},
		{"helper", []ordinaryArtifact{{Owner: "tests/shared/runner", Package: "enkv.sh/core/internal/testmain", Tests: []string{"TestLiveRun"}}}, ordinaryFocus{Tests: []string{"TestLiveRun"}}},
		{"provider-helper", []ordinaryArtifact{{Owner: "compositions/aws", Package: "enkv.sh/compositions/aws", Tests: []string{"TestConfigurationRecoveryLiveParentControl"}}}, ordinaryFocus{PackagePath: "compositions/aws", Tests: []string{"TestConfigurationRecoveryLiveParentControl"}}},
		{"profile-excluded", []ordinaryArtifact{{Owner: "tests/shared/runner", Package: "example.org/runner", Tests: []string{"TestSmall"}, CompiledTests: []string{"TestSmall", "TestParent"}}}, ordinaryFocus{Tests: []string{"TestParent"}}},
	} {
		t.Run(row.name, func(t *testing.T) {
			for index := range row.artifacts {
				if row.name == "profile-excluded" {
					row.artifacts[index].Profile = "dev"
					row.artifacts[index].Classifications = componentFixtureClassifications(row.artifacts[index].CompiledTests)
					row.artifacts[index].Classifications[1].FullOnly = boolPointer(true)
				} else if row.artifacts[index].Profile == "" {
					setOrdinaryArtifactFixtureMetadata(&row.artifacts[index])
				}
			}
			if _, _, err := resolveOneOrdinaryFocusFixture(row.artifacts, row.focus); err == nil {
				t.Fatal("invalid owner admission passed")
			}
		})
	}
}

// full_only: false
func TestOrdinaryFocusRequiresExactExecution(t *testing.T) {
	const pkg = "example.org/ordinary"
	focus := ordinaryFocus{Package: pkg, Tests: []string{"TestParent/child"}}
	want := map[string][]string{pkg: {"TestParent"}}
	complete := []ordinaryEvent{
		{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: "TestParent"},
		{Action: "run", Package: pkg, Test: focus.Tests[0]}, {Action: "pass", Package: pkg, Test: focus.Tests[0]},
		{Action: "pass", Package: pkg, Test: "TestParent"}, {Action: "pass", Package: pkg},
	}
	if _, err := validateOrdinaryFocusedEvents(ordinaryEvents(complete...), want, nil, focus); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name   string
		events []ordinaryEvent
	}{
		{"ancestor-only", append(append([]ordinaryEvent{}, complete[:2]...), complete[4:]...)},
		{"missing-child-terminal", append(append([]ordinaryEvent{}, complete[:3]...), complete[4:]...)},
		{"failed-ancestor", replaceOrdinaryEvent(complete, 4, ordinaryEvent{Action: "fail", Package: pkg, Test: "TestParent"})},
		{"failed-child", replaceOrdinaryEvent(complete, 3, ordinaryEvent{Action: "fail", Package: pkg, Test: focus.Tests[0]})},
		{"skipped-child", replaceOrdinaryEvent(complete, 3, ordinaryEvent{Action: "skip", Package: pkg, Test: focus.Tests[0]})},
		{"sibling", append(append(append([]ordinaryEvent{}, complete[:4]...), ordinaryEvent{Action: "run", Package: pkg, Test: "TestParent/other"}, ordinaryEvent{Action: "pass", Package: pkg, Test: "TestParent/other"}), complete[4:]...)},
		{"duplicate-terminal", append(append([]ordinaryEvent{}, complete[:4]...), complete[3:]...)},
		{"unrelated-top", replaceOrdinaryEvent(complete, 2, ordinaryEvent{Action: "run", Package: pkg, Test: "TestOther"})},
		{"wrong-package", replaceOrdinaryEvent(complete, 2, ordinaryEvent{Action: "run", Package: "other", Test: focus.Tests[0]})},
		{"missing-package-terminal", complete[:5]},
	} {
		t.Run(row.name, func(t *testing.T) {
			results, err := validateOrdinaryFocusedEvents(ordinaryEvents(row.events...), want, nil, focus)
			if err == nil {
				t.Fatal("false selected success passed")
			}
			if row.name == "missing-child-terminal" || row.name == "failed-child" {
				outcome := "incomplete"
				if row.name == "failed-child" {
					outcome = "fail"
				}
				found := false
				for _, result := range results {
					if result.Package == pkg && result.Name == focus.Tests[0] {
						if found || result.Outcome != outcome {
							t.Fatal("selected child observation was repeated or changed", results)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("failed focus lost the child that actually started", results)
				}
			}
		})
	}
	body := ordinaryEvents(complete...)
	for _, damaged := range [][]byte{body[:len(body)-1], append(body, []byte("partial")...), []byte(strings.Repeat("x", maximumToolOutputBytes+1))} {
		if _, err := validateOrdinaryFocusedEvents(damaged, want, nil, focus); err == nil {
			t.Fatal("truncated or overflowing focused events passed")
		}
	}
	slashFocus := focus
	slashFocus.Tests = []string{"TestParent/child/deep"}
	slashEvents := append([]ordinaryEvent{}, complete...)
	slashEvents[2].Test, slashEvents[3].Test = slashFocus.Tests[0], slashFocus.Tests[0]
	if _, err := validateOrdinaryFocusedEvents(ordinaryEvents(slashEvents...), want, nil, slashFocus); err != nil {
		t.Fatal("slash-bearing child incorrectly required virtual ancestors", err)
	}
}

// full_only: false
func TestOrdinaryFocusEvidenceCannotClaimComplete(t *testing.T) {
	const pkg = "example.org/ordinary"
	artifact := ordinaryArtifact{Owner: "core/contract", Package: pkg, Tests: []string{"TestParent", "ExampleRead"}}
	setOrdinaryArtifactFixtureMetadata(&artifact)
	focus, _, err := resolveOneOrdinaryFocusFixture([]ordinaryArtifact{artifact}, ordinaryFocus{PackagePath: "core/contract", Tests: []string{"TestParent/child"}})
	if err != nil {
		t.Fatal(err)
	}
	evidence := ordinaryStepEvidence{Profile: "full", Race: raceSetting(true), RaceOptions: raceOptions, Focus: &focus, Preparation: &ordinaryPreparation{Artifacts: []ordinaryArtifact{artifact}, AdmittedPackages: []string{"core/contract", "core/other"}, NotSelectedPackages: []string{"core/other"}, NotSelected: []ordinaryPackage{{Name: pkg, Tests: []string{"ExampleRead"}}}}, Execution: []ordinaryExecution{{Artifact: artifact.Owner, Package: pkg, Tests: []string{"TestParent"}}}, Packages: []ordinaryPackage{{Name: pkg, Tests: []string{"TestParent"}, Inventory: artifact.CompiledTests, Classifications: artifact.Classifications, NotSelected: []string{"ExampleRead"}}}, Tests: []ordinaryTest{{Package: pkg, Name: "TestParent/child", Outcome: "pass"}, {Package: pkg, Name: "TestParent", Outcome: "pass"}}, SelectedComplete: true}
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var saved ordinaryStepEvidence
	if err := json.Unmarshal(body, &saved); err != nil || !validOrdinaryFocusedEvidence(saved) || completeOrdinaryEvidence(saved) {
		t.Fatal("selected evidence round trip differs", err)
	}
	for _, damage := range []func(*ordinaryStepEvidence){
		func(e *ordinaryStepEvidence) { e.Complete = true }, func(e *ordinaryStepEvidence) { e.Focus = nil; e.Complete = true },
		func(e *ordinaryStepEvidence) { e.Focus = nil; e.Preparation = nil; e.Complete = true },
		func(e *ordinaryStepEvidence) { e.Execution[0].Tests = nil }, func(e *ordinaryStepEvidence) { e.Execution[0].Package = "other" },
		func(e *ordinaryStepEvidence) { e.Tests = e.Tests[1:] }, func(e *ordinaryStepEvidence) { e.SelectedComplete = false },
		func(e *ordinaryStepEvidence) { e.Race = nil }, func(e *ordinaryStepEvidence) { e.Race = raceSetting(false) },
		func(e *ordinaryStepEvidence) { e.RaceOptions = "atexit_sleep_ms=0" },
	} {
		var broken ordinaryStepEvidence
		if err := json.Unmarshal(body, &broken); err != nil {
			t.Fatal(err)
		}
		damage(&broken)
		if validOrdinaryFocusedEvidence(broken) || completeOrdinaryEvidence(broken) {
			t.Fatal("tampered or removed focus claimed qualification")
		}
	}
}

// full_only: false
func TestOrdinaryFocusRealLiteralChildren(t *testing.T) {
	root := t.TempDir()
	const pkg = "example.org/ordinary/package"
	writeLocalGoFixture(t, root, "go.mod", "module example.org/ordinary\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "package/package_test.go", `package sample
import ("encoding/json"; "os"; "testing")
func observe(t *testing.T) {
 f,err:=os.OpenFile(os.Getenv("ENKV_LITERAL_PACKAGE_WITNESS"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600)
 if err!=nil { t.Fatal(err) }
 err=json.NewEncoder(f).Encode(struct{Name string; PID int}{t.Name(),os.Getpid()})
 if closeErr:=f.Close(); err!=nil || closeErr!=nil { t.Fatal(err,closeErr) }
}
// full_only: false
func TestParent(t *testing.T){
 observe(t)
 for _,name:=range []string{"child[1]","other","deep/path"}{ t.Run(name,func(t *testing.T){}) }
 t.Run("left",func(t *testing.T){t.Run("one",func(t *testing.T){});t.Run("two",func(t *testing.T){})})
 t.Run("right/deep",func(t *testing.T){})
}
// full_only: false
func TestOther(t *testing.T){observe(t)}
`)
	ctx := withExecutionParallel(withRacePolicy(t.Context(), false), 1)
	listed, err := listOrdinaryPackages(ctx, root, ".", []string{"-mod=readonly"}, []string{"./package"}, nil)
	if err != nil || len(listed) != 1 {
		t.Fatal(listed, err)
	}
	compiled, err := prepareOrdinaryPackage(ctx, root, ".", []string{"-mod=readonly"}, []string{"./package"}, listed[0], t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	goroot, err := runGo(ctx, root, ".", "env", "GOROOT")
	if err != nil {
		t.Fatal(err)
	}
	converter := testEventConverterFixture(t, root)
	for _, test := range []struct {
		name      string
		requests  []string
		processes int
		passed    bool
	}{
		{"complete-roots", []string{"TestParent", "TestOther"}, 1, true},
		{"literal-siblings", []string{"TestParent/child[1]", "TestParent/other"}, 1, true},
		{"slash-child", []string{"TestParent/deep/path"}, 1, true},
		{"different-depth", []string{"TestParent/left/one", "TestParent/right/deep"}, 2, true},
		{"missing-child", []string{"TestParent/missing"}, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			witness := filepath.Join(t.TempDir(), "processes.jsonl")
			t.Setenv("ENKV_LITERAL_PACKAGE_WITNESS", witness)
			focus := ordinaryFocus{Package: pkg, Tests: slices.Clone(test.requests)}
			artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Directory: ".", Package: pkg, Tests: requestedTestRoots(test.requests), Classifications: compiled.inventory.Classifications, TestFlags: []string{"-timeout=5s"}}, binary: compiled.binary, cwd: compiled.cwd, converter: converter, requests: slices.Clone(test.requests)}
			evidence := ordinaryStepEvidence{Focus: &focus, Diagnostics: &checkDiagnostics{Preparation: "passed"}}
			err := executePreparedOrdinary(ctx, root, artifact, strings.TrimSpace(string(goroot)), map[string][]string{pkg: artifact.Tests}, &evidence)
			if (err == nil) != test.passed || test.passed && !ordinaryFocusedTerminals(evidence.Tests, focus) {
				t.Fatal("literal selected outcomes differ", test.requests, evidence.Tests, err)
			}
			commands := 0
			for _, fact := range evidence.Diagnostics.Commands {
				if !fact.Started || !fact.Joined || fact.Process != "passed" || fact.Events != "valid" {
					t.Fatal("literal selection lost actual process/event facts", fact)
				}
				if fact.Phase == "test" {
					commands++
				}
			}
			if commands != test.processes {
				t.Fatal("literal selection has the wrong process ownership", commands, test.processes)
			}
			body, readErr := os.ReadFile(witness)
			rows, decodeErr := decodeObjects[struct {
				Name string
				PID  int
			}](body)
			if readErr != nil || decodeErr != nil {
				t.Fatal(readErr, decodeErr)
			}
			pids := map[int]bool{}
			for _, row := range rows {
				if row.PID <= 0 {
					t.Fatal(row)
				}
				pids[row.PID] = true
			}
			if len(pids) != test.processes {
				t.Fatal("literal requests used repeated or omitted process owners", rows)
			}
			if !test.passed {
				if !slices.ContainsFunc(evidence.Tests, func(row ordinaryTest) bool {
					return row.Name == "TestParent/missing" && row.Outcome == "not_run" && row.StartedAt == nil && row.FinishedAt == nil && row.ElapsedSeconds == nil
				}) {
					t.Fatal("missing child acquired a passing or invented terminal", evidence.Tests)
				}
			}
		})
	}
}

// full_only: false
func TestOrdinaryCommandRespectsExecutionCapacity(t *testing.T) {
	for _, mode := range []string{"ordinary", "packages_and_tests"} {
		for _, parallel := range []int{1, 2, 4} {
			t.Run(fmt.Sprintf("%s/parallel_%d", mode, parallel), func(t *testing.T) {
				root := t.TempDir()
				control := t.TempDir()
				writeLocalGoFixture(t, root, "go.mod", "module example.org/capacity\n\ngo 1.27.0\n")
				if err := os.Mkdir(filepath.Join(control, "active"), 0700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("ENKV_ORDINARY_CAPACITY_FIXTURE", control)
				packageSlots, testSlots := 1, parallel
				if mode == "packages_and_tests" {
					testSlots = min(2, parallel)
					packageSlots = parallel / testSlots
				}
				const fixture = `package capacity

import (
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "sync/atomic"
 "testing"
 "time"
)

var active, peak, started, completed atomic.Int32

func TestMain(m *testing.M) {
 flag.Parse()
 if flag.Lookup("test.list").Value.String() != "" { os.Exit(m.Run()) }
 code := m.Run()
 parallel, err := strconv.Atoi(flag.Lookup("test.parallel").Value.String())
 if err != nil || parallel != %d { fmt.Fprintln(os.Stderr, "command capacity was not delegated", parallel); code = 2 }
 body, err := json.Marshal(struct { Parallel int; Peak, Started, Completed int32 }{parallel, peak.Load(), started.Load(), completed.Load()})
 if err != nil { fmt.Fprintln(os.Stderr, err); code = 2 } else if err := os.WriteFile(filepath.Join(os.Getenv("ENKV_ORDINARY_CAPACITY_FIXTURE"), "%s.json"), body, 0600); err != nil { fmt.Fprintln(os.Stderr, err); code = 2 }
 os.Exit(code)
}

func wait(t *testing.T, ready func() (bool, error)) {
 t.Helper()
 for {
  ok, err := ready()
  if err != nil { t.Fatal(err) }
  if ok { return }
  select {
  case <-t.Context().Done(): t.Fatal("fixture gate canceled", t.Context().Err())
  case <-time.After(time.Millisecond):
  }
 }
}

func observe(t *testing.T, entering bool) {
 t.Helper()
 root := os.Getenv("ENKV_ORDINARY_CAPACITY_FIXTURE")
 lock := filepath.Join(root, "observer-lock")
 wait(t, func() (bool, error) {
  err := os.Mkdir(lock, 0700)
  if os.IsExist(err) { return false, nil }
  return err == nil, err
 })
 defer func() { if err := os.Remove(lock); err != nil { t.Error(err) } }()
 id := "%s-" + t.Name()
 marker := filepath.Join(root, "active", id)
 if !entering {
  if err := os.Remove(marker); err != nil { t.Fatal(err) }
  return
 }
 if err := os.Mkdir(marker, 0700); err != nil { t.Fatal(err) }
 entries, err := os.ReadDir(filepath.Join(root, "active"))
 if err != nil { t.Fatal(err) }
 if len(entries) > %d { t.Errorf("active tests %%d exceed assigned share", len(entries)) }
 body, err := json.Marshal(struct { PID, Active int }{os.Getpid(), len(entries)})
 if err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(root, id+".json"), body, 0600); err != nil { t.Fatal(err) }
}

func participant(t *testing.T) {
 t.Parallel()
 started.Add(1)
 live := active.Add(1)
 defer func() { active.Add(-1); completed.Add(1) }()
 for old := peak.Load(); live > old; old = peak.Load() { if peak.CompareAndSwap(old, live) { break } }
 observe(t, true)
 defer observe(t, false)
 wait(t, func() (bool, error) {
  _, err := os.Stat(filepath.Join(os.Getenv("ENKV_ORDINARY_CAPACITY_FIXTURE"), "release"))
  if os.IsNotExist(err) { return false, nil }
  return err == nil, err
 })
 t.Run("leaf[a]+b", func(t *testing.T) {})
}

// full_only: false
func TestAlpha(t *testing.T) { participant(t) }
// full_only: false
func TestBeta(t *testing.T) { participant(t) }
// full_only: false
func TestDelta(t *testing.T) { participant(t) }
// full_only: false
func TestGamma(t *testing.T) { participant(t) }
`
				for _, pkg := range []string{"first", "second"} {
					writeLocalGoFixture(t, root, pkg+"/capacity_test.go", fmt.Sprintf(fixture, testSlots, pkg, pkg, parallel))
				}
				ctx, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 4096}}), 90*time.Second)
				defer cancel()
				done := make(chan struct{})
				var evidence ordinaryStepEvidence
				var runErr error
				go func() {
					defer close(done)
					if mode == "ordinary" {
						runErr = executeOrdinaryCommand(ctx, root, ".", "full", []string{"-mod=readonly"}, []string{"./first", "./second"}, "", nil, &evidence, "-timeout=30s")
						return
					}
					// Exercise the common command owner with both Go scheduling
					// controls active. The expected bound above is independent.
					evidence = ordinaryStepEvidence{Race: raceSetting(false), Diagnostics: &checkDiagnostics{Preparation: "pending"}}
					want, retained, err := discoverOrdinaryInventory(ctx, root, ".", []string{"-mod=readonly"}, []string{"./first", "./second"}, "", evidence.Diagnostics)
					if err != nil {
						runErr = err
						return
					}
					evidence.Diagnostics.Preparation = "passed"
					if err := appendOrdinaryInventory(&evidence, want, retained); err != nil {
						runErr = err
						return
					}
					body, facts, err := runGoRecorded(ctx, root, ".", "test", "-mod=readonly", "-p=4", "-parallel=2", "-count=1", "-timeout=30s", "-json", "./first", "./second")
					facts.Phase = "test"
					var eventErr error
					evidence.Tests, facts.Events, eventErr = parseOrdinaryEvents(body, want, nil)
					runErr = errors.Join(err, eventErr, evidence.Diagnostics.append(facts))
				}()
				defer func() {
					cancel()
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("capacity command did not join after cancellation")
					}
				}()
				failCommand := func(message string) {
					t.Helper()
					var failure *toolFailure
					if errors.As(runErr, &failure) {
						t.Fatalf("%s: %v; stdout=%s; stderr=%s", message, runErr, failure.stdout, failure.stderr)
					}
					t.Fatal(message, runErr)
				}
				// Every marker remains present until this positive first-wave
				// observation. No sleep duration establishes the capacity claim.
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				var firstWave []os.DirEntry
				for {
					entries, err := os.ReadDir(filepath.Join(control, "active"))
					if err != nil {
						t.Fatal(err)
					}
					if len(entries) >= parallel {
						firstWave = entries
						break
					}
					select {
					case <-done:
						failCommand("command ended before its assigned wave")
					case <-ctx.Done():
						t.Fatal("assigned wave did not start", ctx.Err())
					case <-ticker.C:
					}
				}
				if len(firstWave) != parallel {
					t.Errorf("active tests exceed assigned share: got %d want %d", len(firstWave), parallel)
				}
				wavePackages := map[string]int{}
				for _, entry := range firstWave {
					pkg, _, _ := strings.Cut(entry.Name(), "-")
					wavePackages[pkg]++
				}
				if len(wavePackages) != packageSlots {
					t.Errorf("active package count: got %v want %d packages", wavePackages, packageSlots)
				}
				for _, count := range wavePackages {
					if count != testSlots {
						t.Errorf("active tests per package: got %v want %d", wavePackages, testSlots)
					}
				}
				if err := os.WriteFile(filepath.Join(control, "release"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("released capacity command did not complete", ctx.Err())
				}
				if runErr != nil {
					failCommand("capacity command failed")
				}
				if evidence.Race == nil || *evidence.Race || evidence.RaceOptions != "" || evidence.Diagnostics == nil || evidence.Diagnostics.Preparation != "passed" {
					t.Error("ordinary command lost accepted race/preparation evidence")
				}
				if evidence.Diagnostics != nil {
					testCommands := 0
					for _, command := range evidence.Diagnostics.Commands {
						if !command.Started || !command.Joined || command.Process != "passed" || command.RaceObservation != "not_observed" || command.Phase == "test" && command.Events != "valid" {
							t.Errorf("capacity command did not positively join/pass: %+v", command)
						}
						if command.Phase == "test" {
							testCommands++
						}
					}
					// Neither fixture package contains the special runner memory
					// roots that require separate Go commands. Go's -p control
					// schedules both ordinary package binaries in this one command.
					if testCommands != 1 {
						t.Error("multiple packages lost their single command owner", testCommands)
					}
				}
				want := map[string][]string{"example.org/capacity/first": {"TestAlpha", "TestBeta", "TestDelta", "TestGamma"}, "example.org/capacity/second": {"TestAlpha", "TestBeta", "TestDelta", "TestGamma"}}
				inventory := map[string][]string{}
				for _, pkg := range evidence.Packages {
					if _, duplicate := inventory[pkg.Name]; duplicate {
						t.Error("duplicate package inventory", pkg.Name)
					}
					inventory[pkg.Name] = pkg.Tests
				}
				if !reflect.DeepEqual(inventory, want) {
					t.Errorf("selected package inventories: got %v want %v", inventory, want)
				}
				terminals, expected := map[string]string{}, map[string]string{}
				for _, terminal := range evidence.Tests {
					key := terminal.Package + "/" + terminal.Name
					if _, duplicate := terminals[key]; duplicate {
						t.Error("duplicate terminal", key)
					}
					terminals[key] = terminal.Outcome
				}
				for pkg, names := range want {
					for _, name := range names {
						expected[pkg+"/"+name], expected[pkg+"/"+name+"/leaf[a]+b"] = "pass", "pass"
					}
				}
				if !reflect.DeepEqual(terminals, expected) {
					t.Errorf("completed terminals: got %v want %v", terminals, expected)
				}
				owners := map[int]bool{}
				globalPeak := 0
				for _, pkg := range []string{"first", "second"} {
					body, err := os.ReadFile(filepath.Join(control, pkg+".json"))
					var facts struct {
						Parallel                 int
						Peak, Started, Completed int32
					}
					if err != nil || json.Unmarshal(body, &facts) != nil {
						t.Fatal("package capacity receipt unavailable", pkg, err)
					}
					if facts.Parallel != testSlots || facts.Peak < 1 || facts.Peak > int32(testSlots) || facts.Started != 4 || facts.Completed != 4 {
						t.Errorf("package %s capacity receipt differs: %+v", pkg, facts)
					}
					packagePID := 0
					for _, name := range want["example.org/capacity/"+pkg] {
						body, err := os.ReadFile(filepath.Join(control, pkg+"-"+name+".json"))
						var observed struct{ PID, Active int }
						if err != nil || json.Unmarshal(body, &observed) != nil || observed.PID <= 0 || observed.Active < 1 || observed.Active > parallel {
							t.Fatal("cross-package active observation differs", pkg, name, observed, err)
						}
						if packagePID != 0 && packagePID != observed.PID {
							t.Fatal("one package used multiple fixture processes")
						}
						packagePID = observed.PID
						globalPeak = max(globalPeak, observed.Active)
					}
					owners[packagePID] = true
				}
				if globalPeak != parallel || len(owners) != 2 {
					t.Error("combined active bound or distinct package processes differ", globalPeak, owners)
				}
				if active, err := os.ReadDir(filepath.Join(control, "active")); err != nil || len(active) != 0 {
					t.Error("active fixture remains after joined command", active, err)
				}
				if _, err := os.Stat(filepath.Join(control, "observer-lock")); !os.IsNotExist(err) {
					t.Error("observer remains after joined command", err)
				}
			})
		}
	}
}
