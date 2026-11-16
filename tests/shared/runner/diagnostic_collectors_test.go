package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestOrdinaryDiagnosticCollectorsPreserveFailedCommand(t *testing.T) {
	t.Run("unit", func(t *testing.T) {
		root, _, _ := overlayFixture(t)
		writeLocalGoFixture(t, root, "telemetry/go.mod", "module enkv.sh/telemetry\n\ngo 1.27.0\n")
		for _, row := range []struct{ directory, assertion string }{
			{"passed", ""},
			{"zzfailed", `t.Fatal("controlled private unit assertion")`},
		} {
			body := "package fixture\nimport \"testing\"\n// full_only: false\nfunc TestAlpha(t *testing.T) { " + row.assertion + " }\n"
			writeLocalGoFixture(t, root, "telemetry/"+row.directory+"/controlled_unit_test.go", body)
		}
		ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 1), 45*time.Second)
		defer cancel()
		var evidence ordinaryStepEvidence
		err := runUnitProfileEvidence(ctx, root, map[string][]string{"telemetry": {"./passed", "./zzfailed"}}, "dev", io.Discard, &evidence)
		var failure *toolFailure
		if err == nil || evidence.Complete || !errors.As(err, &failure) || failure.operation != "prepared ordinary test" ||
			!failure.process.Started || !failure.process.Joined || !strings.Contains(string(failure.stdout), "controlled private unit assertion") {
			t.Fatal("unit collector lost the actual failed test command", err)
		}
		wantCommands := []struct{ phase, scope, process string }{
			{"preparation", "telemetry", "passed"},
			{"preparation", "telemetry", "passed"},
			{"preparation", "enkv.sh/telemetry/passed", "passed"},
			{"preparation", "telemetry", "passed"},
			{"preparation", "enkv.sh/telemetry/zzfailed", "passed"},
			{"preparation", "test2json", "passed"},
			{"test", "enkv.sh/telemetry/passed", "passed"},
			{"conversion", "enkv.sh/telemetry/passed", "passed"},
			{"test", "enkv.sh/telemetry/zzfailed", "process_failed"},
			{"conversion", "enkv.sh/telemetry/zzfailed", "passed"},
		}
		if evidence.Diagnostics == nil || len(evidence.Diagnostics.Commands) != len(wantCommands) {
			t.Fatal("unit fixture did not retain every discovery, build, inventory, test and conversion command", evidence.Diagnostics)
		}
		for i, want := range wantCommands {
			command := evidence.Diagnostics.Commands[i]
			if command.Scope != want.scope || command.Phase != want.phase || command.Process != want.process || !command.Started || !command.Joined {
				t.Fatal("unit fixture changed ordered command facts", i, command)
			}
		}
		if len(evidence.Tests) != 2 || evidence.Tests[0].Package != "enkv.sh/telemetry/passed" ||
			evidence.Tests[0].Name != "TestAlpha" || evidence.Tests[0].Outcome != "pass" ||
			evidence.Tests[1].Package != "enkv.sh/telemetry/zzfailed" || evidence.Tests[1].Name != "TestAlpha" || evidence.Tests[1].Outcome != "fail" {
			t.Fatal("unit collector lost passing or failed package terminals", evidence.Tests)
		}
		var private bytes.Buffer
		if writeErr := writeAssemblyDiagnosticBody(&private, err); writeErr != nil {
			t.Fatal(writeErr)
		}
		if !strings.Contains(private.String(), "Operation: prepared ordinary test\n") ||
			!strings.Contains(private.String(), "controlled_unit_test.go:4: controlled private unit assertion") {
			t.Fatal("unit diagnostic collector hid the joined failed command output")
		}
	})
	for _, zeroExit := range []bool{false, true} {
		name := "unit_large_failed_prefix"
		if zeroExit {
			name = "unit_zero_exit_failed_events"
		}
		t.Run(name, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			writeLocalGoFixture(t, root, "telemetry/go.mod", "module enkv.sh/telemetry\n\ngo 1.27.0\n")
			imports := ""
			if zeroExit {
				imports = `; "os"`
			}
			source := fmt.Sprintf(`package fixture
import ("strings"; "testing"%s)
// full_only: false
func TestAlphaBefore(t *testing.T) { t.Log(strings.Repeat("passing noise\n", %d)) }
// full_only: false
func TestBravoFailure(t *testing.T) { t.Error("controlled private unit assertion") }
// full_only: false
func TestCharlieAfter(t *testing.T) { t.Log(strings.Repeat("passing noise\n", %d)) }
`, imports, assemblyDiagnosticOutputLimit/len("passing noise\n")+1, assemblyDiagnosticOutputLimit/len("passing noise\n")+1)
			if zeroExit {
				source += "func TestMain(m *testing.M) { m.Run(); os.Exit(0) }\n"
			} else {
				source += `
// full_only: false
func TestDeltaPanic(t *testing.T) { go func() { panic("controlled private unit panic") }(); select {} }
// full_only: false
func TestZuluUnstarted(t *testing.T) { t.Fatal("unfinished root restarted") }
`
			}
			writeLocalGoFixture(t, root, "telemetry/controlled_unit_test.go", source)
			ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 1), 45*time.Second)
			defer cancel()
			var evidence ordinaryStepEvidence
			err := runUnitProfileEvidence(ctx, root, map[string][]string{"telemetry": {"."}}, "dev", io.Discard, &evidence)
			var completion *testCompletionFailure
			if err == nil || evidence.Complete || !errors.As(err, &completion) || !errors.Is(err, completion) || zeroExit && containedCheckFailure(ctx, err) {
				t.Fatal("large-output fixture lost its typed event failure or changed continuation", err)
			}
			processStatus, eventStatus := "process_failed", "incomplete"
			if zeroExit {
				processStatus, eventStatus = "passed", "valid"
			}
			var failure *toolFailure
			if !errors.As(err, &failure) {
				t.Error("large-output event failure lost its native diagnostic owner")
			} else if failure.operation != "prepared ordinary test" || failure.process.Status != processStatus ||
				!failure.process.Started || !failure.process.Joined || (failure.process.Cause == nil) != zeroExit {
				t.Fatal("large-output event failure changed actual native process facts", failure.process)
			}
			wantOutcomes := map[string]string{"TestAlphaBefore": "pass", "TestBravoFailure": "fail", "TestCharlieAfter": "pass"}
			if !zeroExit {
				wantOutcomes["TestDeltaPanic"], wantOutcomes["TestZuluUnstarted"] = "incomplete", "not_run"
			}
			if len(evidence.Tests) != len(wantOutcomes) {
				t.Fatal("large-output failure lost selected test rows", evidence.Tests)
			}
			for _, row := range evidence.Tests {
				if row.Package != "enkv.sh/telemetry" || wantOutcomes[row.Name] != row.Outcome {
					t.Fatal("large-output failure changed completed or unfinished results", row)
				}
				delete(wantOutcomes, row.Name)
				if row.Name == "TestZuluUnstarted" && (row.StartedAt != nil || row.FinishedAt != nil || row.ElapsedSeconds != nil) {
					t.Fatal("unstarted root acquired invented execution facts", row)
				}
			}
			tests, conversions := 0, 0
			if evidence.Diagnostics == nil {
				t.Fatal("large-output fixture lost command facts")
			}
			for _, command := range evidence.Diagnostics.Commands {
				if !command.Started || !command.Joined {
					t.Fatal("large-output failure lacks positive command settlement", command)
				}
				switch command.Phase {
				case "test":
					tests++
					if command.Process != processStatus || command.Events != eventStatus {
						t.Fatal("event failure changed the native process or event facts", command)
					}
				case "conversion":
					conversions++
					if command.Process != "passed" || command.Events != eventStatus {
						t.Fatal("joined conversion changed the failed event facts", command)
					}
				}
			}
			if tests != 1 || conversions != 1 {
				t.Fatal("failed package restarted or lost its conversion", tests, conversions)
			}
			var private bytes.Buffer
			if writeErr := writeAssemblyDiagnosticBody(&private, err); writeErr != nil {
				t.Fatal(writeErr)
			}
			wantDetails := []string{"Operation: prepared ordinary test\n", "controlled_unit_test.go:6: controlled private unit assertion"}
			if !zeroExit {
				wantDetails = append(wantDetails, "panic: controlled private unit panic")
			}
			for _, want := range wantDetails {
				if !strings.Contains(private.String(), want) {
					t.Error("passing output displaced private failure details", want)
				}
			}
			if private.Len() > assemblyDiagnosticFileLimit {
				t.Fatal("large-output failure exceeded the existing diagnostic bound", private.Len())
			}
		})
	}
	for _, overflow := range []bool{false, true} {
		name := "runner"
		if overflow {
			name = "runner_append_overflow"
		}
		t.Run(name, func(t *testing.T) {
			const pkg = "example.org/runner"
			cause := errors.New("controlled command cause")
			failure := &toolFailure{operation: "go test", process: processResult{Status: "process_failed", Started: true, Joined: true, Cause: cause},
				stdout: ordinaryEvents(
					ordinaryEvent{Action: "start", Package: pkg},
					ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
					ordinaryEvent{Action: "output", Package: pkg, Test: "TestAlpha", Output: "controlled_runner_test.go:9: controlled private runner assertion\n"},
					ordinaryEvent{Action: "fail", Package: pkg, Test: "TestAlpha"},
					ordinaryEvent{Action: "fail", Package: pkg})}
			groups := []runnerGroup{{Name: "failed", Packages: []ordinaryPackage{{Name: pkg, Tests: []string{"TestAlpha"}}}}}
			var evidence ordinaryStepEvidence
			if overflow {
				// Earlier diagnostics fill the existing bound. The current failed
				// command must remain visible when its own facts cannot be appended.
				evidence.Diagnostics = &checkDiagnostics{Preparation: "passed", Commands: make([]checkCommandFacts, maximumCheckCommands)}
			}
			calls := 0
			err := runRunnerGroups(withExecutionParallel(t.Context(), 1), groups, io.Discard, &evidence,
				func(_ context.Context, group runnerGroup) (ordinaryStepEvidence, error) {
					calls++
					count := 36
					if overflow {
						count = 128
					}
					local := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
					for i := range count {
						process := "passed"
						if group.Name == "failed" && i == count-1 {
							process = "process_failed"
						}
						local.Diagnostics.Commands = append(local.Diagnostics.Commands, checkCommandFacts{
							Phase: "test", Scope: fmt.Sprintf("command-%03d", i), Process: process, Started: true, Joined: true, Events: "valid"})
					}
					return local, failure
				})
			var retained *toolFailure
			if calls != len(groups) || !errors.Is(err, cause) || !errors.As(err, &retained) || retained != failure || evidence.Complete ||
				len(evidence.RunnerGroups) != len(groups) || evidence.RunnerGroups[len(groups)-1].Outcome != "failed" {
				t.Fatal("runner collector lost the original failed command or admitted uncompleted work", err)
			}
			if overflow {
				if evidence.RunnerGroups[0].Outcome != "failed" || len(evidence.Diagnostics.Commands) != maximumCheckCommands ||
					!strings.Contains(err.Error(), "check command diagnostics exceed their bound") {
					t.Fatal("runner collector lost diagnostic append failure", err)
				}
			} else {
				if len(evidence.Diagnostics.Commands) != 36 {
					t.Fatal("runner collector lost successful command facts")
				}
				for i, command := range evidence.Diagnostics.Commands {
					if command.Scope != fmt.Sprintf("failed/command-%03d", i) || !command.Started || !command.Joined {
						t.Fatal("runner collector changed scope or join facts", command)
					}
				}
			}
			var private bytes.Buffer
			if writeErr := writeAssemblyDiagnosticBody(&private, err); writeErr != nil {
				t.Fatal(writeErr)
			}
			if !strings.Contains(private.String(), "Operation: go test\n") ||
				!strings.Contains(private.String(), "Command cause (truncated: false): controlled command cause") ||
				!strings.Contains(private.String(), "controlled_runner_test.go:9: controlled private runner assertion") {
				t.Fatal("runner diagnostic collector hid the failed command cause or private output")
			}
			if overflow && (!strings.Contains(private.String(), "check command diagnostics exceed their bound") ||
				!strings.Contains(private.String(), "Additional cause branches truncated: true")) {
				t.Fatal("runner append overflow was hidden or diagnostic branch bound was removed")
			}
		})
	}
}
