package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testEventConverterSourceFixture(t *testing.T) string {
	t.Helper()
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "core/go.mod", "module enkv.sh/core\n\ngo 1.27.0\n")
	return root
}

func testEventConverterFixture(t *testing.T, _ string) preparedTestEventConverter {
	t.Helper()
	root := testEventConverterSourceFixture(t)
	ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 1), time.Minute)
	defer cancel()
	converter, _, err := prepareTestEventConverter(ctx, root, t.TempDir())
	if err != nil {
		t.Fatal("prepare test event converter", err)
	}
	return converter
}

func boundTestEventConverterFixture(t *testing.T, binary string) preparedTestEventConverter {
	t.Helper()
	digest, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	return preparedTestEventConverter{binary: binary, sha256: digest}
}

// full_only: false
func TestPreparedTestEventConverterKeepsColdBuildOutOfConversion(t *testing.T) {
	root, toolchain := testEventConverterSourceFixture(t), t.TempDir()
	tools := filepath.Join(toolchain, "bin")
	if err := os.Mkdir(tools, 0700); err != nil {
		t.Fatal(err)
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	// Model a cold builtin tool without clearing shared caches. Preparation
	// owns the delayed build; replay must not invoke a late `go tool`.
	const coldBuildSeconds = 6
	wrapper := "#!/bin/sh\nif [ \"$1\" = tool ] && [ \"${2-}\" = test2json ]; then echo converter-build-during-conversion >&2; exit 99; fi\nfor argument in \"$@\"; do if [ \"$argument\" = cmd/test2json ]; then sleep 6; fi; done\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(tools, "go"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), 1), time.Minute)
	defer cancel()
	converter, facts, err := prepareTestEventConverter(ctx, root, t.TempDir())
	if err != nil || facts.Phase != "preparation" || facts.Process != "passed" || !facts.Started || !facts.Joined || facts.WallSeconds == nil || *facts.WallSeconds < coldBuildSeconds {
		t.Fatal("cold converter build did not belong to joined preparation", facts, err)
	}
	const name = "TestPreparedConverter"
	binary := filepath.Join(root, "test-binary")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' '=== RUN   "+name+"' '--- PASS: "+name+" (0.00s)' PASS\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"ordinary", "component"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "ordinary" {
				evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
				artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Package: componentPackage, Tests: []string{name}}, binary: binary, cwd: root, converter: converter}
				setPreparedOrdinaryFixtureMetadata(t, &artifact)
				if err := executePreparedOrdinary(ctx, root, artifact, toolchain, map[string][]string{componentPackage: {name}}, &evidence); err != nil || len(evidence.Tests) != 1 || evidence.Tests[0].Outcome != "pass" {
					t.Fatal("ordinary conversion depended on a warm Go tool cache", err, evidence.Tests)
				}
				return
			}
			process, evidence, _, _ := executeComponentChecks(ctx, root, binary, converter, literalTestSelection(name), []string{name}, os.Environ())
			if process.Status != "passed" || !process.Joined || !evidence.TestsComplete {
				t.Fatal("component conversion depended on a warm Go tool cache", process, evidence)
			}
		})
	}
}

// full_only: false
func TestPreparedTestEventConverterKeepsHardHorizonAndCancellationTail(t *testing.T) {
	const name = "TestConverterLifetime"
	for _, kind := range []string{"ordinary", "component"} {
		for _, condition := range []string{"hard-before-admission", "hard-during-conversion", "deadline-during-hang"} {
			t.Run(kind+"/"+condition, func(t *testing.T) {
				root := t.TempDir()
				sourceMarker, conversionMarker := filepath.Join(root, "source-entered"), filepath.Join(root, "conversion-entered")
				binary, converterBinary := filepath.Join(root, "test-binary"), filepath.Join(root, "test2json")
				source := "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > " + shellQuote(sourceMarker) + "\n"
				if condition == "hard-before-admission" {
					source += "while :; do sleep 1; done\n"
				} else {
					source += "printf '%s\\n' '=== RUN   " + name + "' '--- PASS: " + name + " (0.00s)' PASS\n"
				}
				if err := os.WriteFile(binary, []byte(source), 0700); err != nil {
					t.Fatal(err)
				}
				converterBody := "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > " + shellQuote(conversionMarker) + "\nexec sleep 120\n"
				if err := os.WriteFile(converterBinary, []byte(converterBody), 0700); err != nil {
					t.Fatal(err)
				}
				converter := boundTestEventConverterFixture(t, converterBinary)
				artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Package: componentPackage, Tests: []string{name}}, binary: binary, cwd: root, converter: converter}
				setPreparedOrdinaryFixtureMetadata(t, &artifact)
				observer, cancelObserver := context.WithTimeout(t.Context(), 45*time.Second)
				owner := newInvocationLifetime(observer)
				work := owner.work
				cancelWork := func() {}
				var deadline time.Time
				if condition == "deadline-during-hang" {
					deadline = time.Now().Add(10 * time.Second)
					work, cancelWork = context.WithDeadline(work, deadline)
				}
				type outcome struct {
					err               error
					diagnostics       *checkDiagnostics
					componentComplete bool
				}
				done, joined := make(chan outcome, 1), make(chan struct{})
				t.Cleanup(func() {
					owner.close()
					cancelWork()
					cancelObserver()
					select {
					case <-joined:
					case <-time.After(12 * time.Second):
						t.Error("converter fixture caller did not join after hard stop")
					}
				})
				go func() {
					defer close(joined)
					if kind == "ordinary" {
						evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
						err := executePreparedOrdinary(work, root, artifact, "", map[string][]string{componentPackage: {name}}, &evidence)
						done <- outcome{err: err, diagnostics: evidence.Diagnostics}
						return
					}
					process, evidence, _, _ := executeComponentChecks(work, root, binary, converter, literalTestSelection(name), []string{name}, os.Environ())
					done <- outcome{process.Cause, evidence.Diagnostics, process.Status == "passed" || evidence.TestsComplete}
				}()
				marker := conversionMarker
				if condition == "hard-before-admission" {
					marker = sourceMarker
				}
				waitProcessMarker(t, observer, marker)
				// Allow both existing five-second settlement stages, the one-second
				// pipe wait and two seconds of scheduling margin after cancellation.
				const settlementAllowance = 5*time.Second + 5*time.Second + time.Second + 2*time.Second
				var completionDeadline time.Time
				if condition == "deadline-during-hang" {
					if work.Err() != nil {
						t.Fatal("converter was not admitted before the work deadline", work.Err())
					}
					<-work.Done()
					if owner.hard.Err() != nil {
						t.Fatal("normal work deadline also ended the hard horizon")
					}
					completionDeadline = deadline.Add(5*time.Second + settlementAllowance)
				} else {
					owner.hardStop()
					completionDeadline = time.Now().Add(settlementAllowance)
				}
				completionTimer := time.NewTimer(time.Until(completionDeadline))
				defer completionTimer.Stop()
				var result outcome
				select {
				case result = <-done:
				case <-completionTimer.C:
					t.Fatal("converter exceeded replay and physical settlement allowances", condition)
				case <-observer.Done():
					t.Fatal("converter escaped its finite owner lifetime", observer.Err())
				}
				cause, conversionStatus := context.Canceled, "interrupted"
				if condition == "deadline-during-hang" {
					cause, conversionStatus = context.DeadlineExceeded, "timed_out"
					if time.Now().Before(deadline.Add(5 * time.Second)) {
						t.Fatal("hanging converter did not receive the existing five-second cancellation tail")
					}
				}
				if !errors.Is(result.err, cause) || kind == "component" && result.componentComplete || result.diagnostics == nil || result.diagnostics.Preparation != "passed" || len(result.diagnostics.Commands) != 2 {
					t.Fatal("converter lifetime lost owner failure or command facts", result.err, result.componentComplete, result.diagnostics)
				}
				sourceFacts, conversionFacts := result.diagnostics.Commands[0], result.diagnostics.Commands[1]
				if sourceFacts.Phase != "test" || !sourceFacts.Started || !sourceFacts.Joined || conversionFacts.Phase != "conversion" || conversionFacts.Process != conversionStatus || !conversionFacts.Joined {
					t.Fatal("source or converter was not positively joined", sourceFacts, conversionFacts)
				}
				if condition == "hard-before-admission" {
					if conversionFacts.Started {
						t.Fatal("hard stop admitted a new converter process", conversionFacts)
					}
					if _, err := os.Stat(conversionMarker); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("converter entered after its hard horizon ended", err)
					}
				} else if sourceFacts.Process != "passed" || !conversionFacts.Started {
					t.Fatal("converter lifetime case did not follow a passed joined source", sourceFacts, conversionFacts)
				}
			})
		}
	}
}

// full_only: false
func TestPreparedTestEventConverterReportsMissingOrCorruptExecutable(t *testing.T) {
	testPreparedConverterExecution(t, false)
}

// full_only: false
func TestPreparedTestEventConverterUsesCompletedExecutableAfterTestExit(t *testing.T) {
	testPreparedConverterExecution(t, true)
}

func testPreparedConverterExecution(t *testing.T, afterExit bool) {
	t.Helper()
	const name = "TestPreparedConverter"
	prepared := testEventConverterFixture(t, "")
	original, err := os.ReadFile(prepared.binary)
	if err != nil {
		t.Fatal(err)
	}
	changes := []string{"missing", "corrupt", "invalid-events"}
	if afterExit {
		changes = append(changes, "changed")
	}
	for _, kind := range []string{"ordinary", "component"} {
		for _, change := range changes {
			for _, exit := range []struct {
				name string
				code int
			}{{"passing", 0}, {"failing", 23}} {
				t.Run(kind+"/"+change+"/"+exit.name, func(t *testing.T) {
					root := t.TempDir()
					binary, converterBinary := filepath.Join(root, "test-binary"), filepath.Join(root, "test2json")
					entered, exited := filepath.Join(root, "entered"), filepath.Join(root, "exited")
					if err := os.WriteFile(converterBinary, original, 0700); err != nil {
						t.Fatal(err)
					}
					converter := boundTestEventConverterFixture(t, converterBinary)
					mutation := "rm " + shellQuote(converterBinary)
					switch change {
					case "corrupt":
						mutation = "printf corrupt > " + shellQuote(converterBinary)
					case "invalid-events":
						mutation = "printf '%s\\n' '#!/bin/sh' 'printf invalid-events' > " + shellQuote(converterBinary)
					case "changed":
						mutation = "printf '%s\\n' '#!/bin/sh' " + shellQuote("exec "+shellQuote(prepared.binary)+" \"$@\"") + " > " + shellQuote(converterBinary)
					}
					script := "#!/bin/sh\nset -eu\nprintf entered > " + shellQuote(entered) + "\n"
					if afterExit {
						script += mutation + "\n"
					} else {
						command := exec.Command("sh", "-eu", "-c", mutation)
						if body, err := command.CombinedOutput(); err != nil {
							t.Fatal("converter fixture mutation failed", err, string(body))
						}
					}
					script += "printf '%s\\n' '=== RUN   " + name + "' '--- PASS: " + name + " (0.00s)' PASS\nprintf exited > " + shellQuote(exited) + fmt.Sprintf("\nexit %d\n", exit.code)
					if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					var runErr error
					var diagnostics *checkDiagnostics
					success := change == "changed" && exit.code == 0
					if kind == "ordinary" {
						evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
						artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Package: componentPackage, Tests: []string{name}}, binary: binary, cwd: root, converter: converter}
						setPreparedOrdinaryFixtureMetadata(t, &artifact)
						runErr = executePreparedOrdinary(ctx, root, artifact, "", map[string][]string{componentPackage: {name}}, &evidence)
						diagnostics = evidence.Diagnostics
						if change == "changed" && (len(evidence.Tests) != 1 || evidence.Tests[0].Name != name || evidence.Tests[0].Outcome != "pass") {
							t.Fatal("ordinary conversion lost exact selected result", evidence.Tests)
						}
						for _, result := range evidence.Tests {
							if result.Name != name || change != "changed" && result.Outcome == "pass" {
								t.Fatal("invalid conversion produced a passing or foreign result", evidence.Tests)
							}
						}
					} else {
						process, evidence, _, _ := executeComponentChecks(ctx, root, binary, converter, literalTestSelection(name), []string{name}, os.Environ())
						runErr, diagnostics = process.Cause, evidence.Diagnostics
						if (process.Status == "passed") != success || !process.Started || !process.Joined || evidence.TestsComplete != success || len(evidence.Tests) != 1 || evidence.Tests[0].Name != name || (evidence.Tests[0].Outcome == "passed") != (change == "changed") {
							t.Fatal("component conversion lost process or selected result", process, evidence)
						}
					}
					if (runErr == nil) != success {
						t.Fatal("converter execution returned the wrong outcome", runErr)
					}
					if strings.Contains(fmt.Sprint(runErr), "prepared test event converter") {
						t.Fatal("conversion restored a prepared executable currentness gate", runErr)
					}
					var exitError *exec.ExitError
					if exit.code != 0 && (!errors.As(runErr, &exitError) || exitError.ExitCode() != exit.code) {
						t.Fatal("conversion lost original test exit failure", runErr)
					}
					if diagnostics == nil || diagnostics.Preparation != "passed" || len(diagnostics.Commands) != 2 {
						t.Fatal("conversion did not retain both command facts", diagnostics)
					}
					source, conversion := diagnostics.Commands[0], diagnostics.Commands[1]
					status := "passed"
					if exit.code != 0 {
						status = "process_failed"
					}
					conversionStarted := change == "changed" || change == "invalid-events"
					if source.Phase != "test" || source.Process != status || !source.Started || !source.Joined || conversion.Phase != "conversion" || conversion.Started != conversionStarted || !conversion.Joined || (conversion.Process == "passed") != conversionStarted || conversion.WallSeconds == nil || source.WallSeconds == nil {
						t.Fatal("source or converter execution facts differ", source, conversion)
					}
					if change != "changed" && conversion.Events == "valid" {
						t.Fatal("missing or invalid converter produced valid selected events", conversion)
					}
					for _, marker := range []struct{ path, content string }{{entered, "entered"}, {exited, "exited"}} {
						if body, err := os.ReadFile(marker.path); err != nil || string(body) != marker.content {
							t.Fatal("test body did not reach its controlled exit", marker.path, string(body), err)
						}
					}
				})
			}
		}
	}
}
