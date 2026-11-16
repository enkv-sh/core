package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const preparationStdoutCanary = "SYNTHETIC_PREPARATION_STDOUT_SECRET"
const preparationStderrCanary = "SYNTHETIC_PREPARATION_STDERR_SECRET"

func assertClosedPreparationError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil || err.Error() != "check failed; phase=preparation; diagnostics: no durable run owner" {
		t.Fatal("preparation did not return the closed failure fields")
	}
	// The terminal is public even when telemetry is disabled.
	var terminal bytes.Buffer
	fmt.Fprintln(&terminal, err)
	for _, surface := range []string{err.Error(), terminal.String()} {
		for _, value := range append([]string{preparationStdoutCanary, preparationStderrCanary}, forbidden...) {
			if value != "" && strings.Contains(surface, value) {
				t.Fatal("private preparation data reached a public failure surface")
			}
		}
	}
}

// full_only: false
func TestLivePreparationErrorsCloseToolOutput(t *testing.T) {
	t.Run("cleanup-command-preflight-failure", testCleanupCommandPreparationFailure)
	for _, owner := range []string{"suite", "preflight", "workflow", "workflow-local-before-live", "hermetic", "direct-suite", "command-run", "command-plan"} {
		for _, phase := range []string{"binding", "assembly"} {
			t.Run(owner+"/"+phase, func(t *testing.T) {
				hermetic := owner == "hermetic" || owner == "direct-suite" || strings.HasPrefix(owner, "command-")
				root, bootstrap, _ := overlayFixture(t)
				if phase == "assembly" {
					modfile := "tests/live/providers/gcp/live.mod"
					if hermetic {
						modfile = "tests/hermetic/hermetic.mod"
					}
					writeLocalGoFixture(t, root, modfile, "module "+componentPackage+"\n\ngo 1.27.0\n")
					if owner == "workflow-local-before-live" {
						writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
					}
				}
				initializeWorkflowExecutionFixture(t, root)
				ctx := withResourceLocks(withRacePolicy(withExecutionParallel(t.Context(), 1), false), resourceLockFixture(t))
				realGo, err := exec.LookPath("go")
				if err != nil {
					t.Fatal(err)
				}
				realGo, err = filepath.EvalSymlinks(realGo)
				if err != nil {
					t.Fatal(err)
				}
				control := t.TempDir()
				compilerMarker := filepath.Join(control, "compiler-calls")
				condition := `[ "$1" = env ]`
				if phase == "assembly" {
					condition = `[ "$1" = list ]`
				}
				// Only the selected failing command is replaced. Source and Go
				// environment observations come from their real local owners.
				script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> " + shellQuote(compilerMarker) + "\nif " + condition + "; then\n printf '%s\\n' " + shellQuote(preparationStdoutCanary) + "\n printf '%s\\n' " + shellQuote(preparationStderrCanary) + " >&2\n exit 19\nfi\nexec " + shellQuote(realGo) + " \"$@\"\n"
				if err := os.WriteFile(filepath.Join(control, "go"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
				request := runRequest{Suite: "live", Provider: "gcp", Resolved: &resolvedRequest{Race: false}}
				var output bytes.Buffer
				preparedPresent := false
				var acquired *checkDiagnostics
				var partialSource string

				switch owner {
				case "suite", "hermetic":
					if owner == "hermetic" {
						request.Suite, request.Provider = "hermetic", "memory"
					}
					prepared, prepareErr := prepareSuite(nil, ctx, root, bootstrap, request, &output)
					err = prepareErr
					preparedPresent = prepared != nil
					if prepared != nil {
						partialSource = prepared.binding.source.Revision
						acquired = prepared.inventory.preparationDiagnostics()
						defer func() {
							if closeErr := prepared.close(ctx); closeErr != nil {
								t.Error("close local preparation", closeErr)
							}
						}()
					}
				case "preflight":
					prepared, prepareErr := prepareLivePreflight(ctx, root, bootstrap, "gcp", defaultExecutionPolicy())
					err = prepareErr
					preparedPresent = prepared != nil
					if prepared != nil {
						partialSource = prepared.binding.source.Revision
						acquired = prepared.inventory.currentPrefix
						defer func() {
							if closeErr := prepared.close(ctx); closeErr != nil {
								t.Error("close local preflight", closeErr)
							}
						}()
					}
				case "workflow", "workflow-local-before-live":
					plan := workflowPlan{SchemaVersion: 1, Name: "closed-preparation", Profile: "full", Execution: defaultExecutionPolicy(), Steps: []resolvedWorkflowStep{{ID: "live", Kind: "run", Selected: true, Run: &resolvedRequest{Mode: "live", Provider: "gcp"}, request: request}}}
					if owner == "workflow-local-before-live" {
						plan.Steps = append([]resolvedWorkflowStep{{ID: "local", Kind: "unit", Selected: true, Packages: map[string][]string{"core": {"./..."}}}}, plan.Steps...)
					}
					prepared, prepareErr := prepareWorkflow(ctx, root, bootstrap, plan, &output)
					err = prepareErr
					preparedPresent = prepared != nil
					if prepared != nil {
						partialSource = prepared.binding.source.Revision
						_, commandErr := executeCommandWorkflow(ctx, root, bootstrap, prepared, prepareErr, &output)
						err = commandErr

						defer func() {
							if closeErr := prepared.close(ctx); closeErr != nil {
								t.Error("close local workflow", closeErr)
							}
						}()
					}
				case "direct-suite":
					request.Suite, request.Provider = "hermetic", "memory"
					_, commandErr := runSuite(ctx, root, bootstrap, request, &output)
					err = commandErr

				case "command-run", "command-plan":
					input := t.TempDir()
					suite, environment := filepath.Join(input, "suite.json"), filepath.Join(input, "environment.json")
					saveSelection(t, suite, suiteFixture("failed-preparation", []string{"state.single-value-update-preserves-other-values/members_32"}))
					saveSelection(t, environment, memoryEnvironment())
					command := strings.TrimPrefix(owner, "command-")
					admissions := 0
					if owner == "command-plan" {
						ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
							admissions++
							return ctx, errors.New("preview requested resource admission")
						}))
					}
					err = runCommand(ctx, root, bootstrap, []string{command, "--suite", suite, "--environment", environment}, &output)
					if owner == "command-plan" {
						var preview workflowPreview
						if err != nil || json.Unmarshal(output.Bytes(), &preview) != nil || preview.Kind != "selection_preview" || len(preview.Steps) != 1 || !preview.Steps[0].Selected || len(preview.Unresolved) == 0 || admissions != 0 {
							t.Fatal("preview executed or claimed compiled preparation", err, admissions)
						}
						if _, statErr := os.Stat(compilerMarker); !os.IsNotExist(statErr) {
							t.Fatal("preview invoked a compiler", statErr)
						}
						for _, directory := range []string{"tests/live/runs", "tests/hermetic/runs", "tests/workflows/runs"} {
							if _, statErr := os.Stat(filepath.Join(root, directory)); !os.IsNotExist(statErr) {
								t.Fatal("preview created execution state", directory, statErr)
							}
						}
						if strings.Contains(output.String(), preparationStdoutCanary) || strings.Contains(output.String(), preparationStderrCanary) {
							t.Fatal("preview exposed compiler output")
						}
						return
					}
				}
				var failure *toolFailure
				if !errors.As(err, &failure) || failure.operation != map[string]string{"binding": "go env", "assembly": "go list"}[phase] || !failure.process.Started || !failure.process.Joined || failure.process.Status != "process_failed" || !toolCommandsJoined(err) {
					t.Fatal("preparation did not preserve the failing local command and positive join")
				}
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 19 || !bytes.Contains(failure.stdout, []byte(preparationStdoutCanary)) || !bytes.Contains(failure.stderr, []byte(preparationStderrCanary)) {
					t.Fatal("private command failure or its bounded output was lost")
				}
				if failure.facts == nil || !failure.facts.Started || !failure.facts.Joined || failure.facts.Process != "process_failed" || failure.facts.WallSeconds == nil {
					t.Fatal("preparation command facts were lost")
				}
				if owner == "suite" || owner == "preflight" || strings.HasPrefix(owner, "workflow") || owner == "hermetic" {
					if !preparedPresent || phase == "assembly" && partialSource == "" {
						t.Fatal("failed preparation lost its owner or available partial source binding", preparedPresent, partialSource)
					}
					if !strings.HasPrefix(owner, "workflow") && (acquired == nil || len(acquired.Commands) == 0) {
						t.Fatal("failed preparation owner lost its acquired command facts", acquired)
					}
				}

				if hermetic {
					if !strings.Contains(err.Error(), preparationStdoutCanary) || !strings.Contains(err.Error(), preparationStderrCanary) {
						t.Fatal("hermetic preparation hid its bounded failure detail")
					}
				} else {
					assertClosedPreparationError(t, err, root, control, "-overlay=", failure.process.Cause.Error())
					if strings.Contains(output.String(), preparationStdoutCanary) || strings.Contains(output.String(), preparationStderrCanary) {
						t.Fatal("preparation progress leaked raw command output")
					}
				}
			})
		}
	}
}

func refusePreparationCompilerEnvironment(t *testing.T) {
	t.Helper()
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	control := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = env ]; then printf '%s\\n' controlled-preflight-binding-failure >&2; exit 19; fi\nexec " + shellQuote(realGo) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(control, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func testCleanupCommandPreparationFailure(t *testing.T) {
	root, _, _, request, _ := awsGrantedRecoveryFixture(t)
	ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
	before := preparationRecoverySnapshot(t, root)
	refusePreparationCompilerEnvironment(t)
	var output bytes.Buffer

	err := runCommand(ctx, root, bootstrap, []string{"cleanup", request.RunID, "--limits", request.Limits, "--race"}, &output)
	var failure *toolFailure
	if !errors.As(err, &failure) || failure.operation != "go env" || !failure.process.Started || !failure.process.Joined {
		t.Fatal("cleanup command did not reach the controlled preflight binding failure", err)
	}
	assertClosedPreparationError(t, err, root)

	if after := preparationRecoverySnapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("failed cleanup preparation changed retained state")
	}
}

// full_only: false
func TestLivePreparationAndClosedOwnerErrorsStayClosed(t *testing.T) {
	t.Run("retained-current-results", testPreparedFailureResults)
	ctx := t.Context()
	root := t.TempDir()
	privatePath := filepath.Join(root, preparationStderrCanary)
	plan := workflowPlan{Steps: []resolvedWorkflowStep{{Selected: true, Run: &resolvedRequest{Mode: "live"}}}}
	for _, row := range []struct {
		name    string
		prepare func() error
	}{
		{"suite", func() error {
			owner, err := prepareSuite(nil, ctx, root, privatePath, runRequest{Suite: "live"}, io.Discard)
			if owner != nil {
				t.Fatal("early suite acquired an owner")
			}
			return err
		}},
		{"workflow", func() error {
			owner, err := prepareWorkflow(ctx, root, privatePath, plan, io.Discard)
			if owner != nil {
				t.Fatal("early workflow acquired an owner")
			}
			return err
		}},
		{"preflight", func() error {
			owner, err := prepareLivePreflight(ctx, root, privatePath, "gcp", defaultExecutionPolicy())
			if owner != nil {
				t.Fatal("early preflight acquired an owner")
			}
			return err
		}},
		{"cleanup", func() error {
			owner, err := prepareCleanup(ctx, root, privatePath, cleanupRequest{}, io.Discard)
			if owner != nil {
				t.Fatal("early cleanup acquired an owner")
			}
			return err
		}},
	} {
		t.Run("bootstrap/"+row.name, func(t *testing.T) {
			err := row.prepare()
			assertClosedPreparationError(t, err, privatePath, root)
			var cause *os.PathError
			if !errors.As(err, &cause) || cause.Path != privatePath {
				t.Fatal("bootstrap path cause was discarded")
			}
		})
	}
	binding := preparationBinding{ctx: ctx, live: true}
	suite := &preparedSuite{assemblyPreparations: ctx, request: runRequest{Suite: "live"}, binding: binding, joined: true, closed: true}
	preflight := &preparedLivePreflight{binding: binding, joined: true, closed: true}
	planBody, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	workflow := &preparedWorkflow{assemblyPreparations: ctx, planIdentity: digestBytes(planBody), plan: plan, class: rootAdmission{Live: true}, binding: binding, joined: true, closed: true}
	// Assembly binding must retain the safe error from a closed owner.
	for _, row := range []struct {
		name   string
		verify func(context.Context, string) error
	}{
		{"suite", suite.verify}, {"preflight", preflight.verify},
		{"workflow", workflow.verify},
		{"cleanup", (&preparedCleanup{closed: true}).verify},
		{"suite-bind", func(ctx context.Context, root string) error { return suite.bindActual(ctx, root, &assembly{}) }},
		{"preflight-bind", func(ctx context.Context, root string) error { return preflight.bindActual(ctx, root, &assembly{}) }},
	} {
		t.Run("closed-owner/"+row.name, func(t *testing.T) {
			err := row.verify(ctx, root)
			assertClosedPreparationError(t, err, privatePath, root)
			var failure *checkFailure
			if !errors.As(err, &failure) || failure.cause == nil || !strings.Contains(failure.cause.Error(), "closed") {
				t.Fatal("closed-owner cause was discarded", err)
			}
		})
	}
}

// Synthetic closed facts isolate projection at the existing direct wrappers.
// The real binding/assembly cases above prove physical command ownership.
func testPreparedFailureResults(t *testing.T) {
	for _, kind := range []string{"suite", "cleanup"} {
		for _, caller := range []string{"prepared", "direct"} {
			t.Run(kind+"/"+caller, func(t *testing.T) {
				root := t.TempDir()
				private := filepath.Join(root, preparationStderrCanary)
				ctx := withRacePolicy(withExecutionParallel(t.Context(), 1), true)
				policy := executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
				id := strings.Repeat("a", 32)
				diagnostics := &checkDiagnostics{Preparation: "failed", Commands: []checkCommandFacts{
					{Phase: "preparation", Scope: "prefix", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"},
					{Phase: "preparation", Scope: "failed", Process: "process_failed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "passed", RaceObservation: "not_observed"},
				}}
				binding := preparationBinding{ctx: ctx, live: true, race: true}
				inventory := assembly{Closure: assemblyClosure{raceMissing: true, LocalChecks: &checkEvidence{raceMissing: true, Diagnostics: diagnostics}}}
				preflight := &preparedLivePreflight{binding: binding, inventory: inventory, class: rootAdmission{Live: true, Execution: policy}, joined: true}
				if kind != "suite" {
					current, err := newCurrentDirectory("enkv-preparation-result-fixture-")
					if err != nil {
						t.Fatal(err)
					}
					preflight.current = current
					t.Cleanup(func() {
						if !preflight.closed {
							if err := preflight.close(ctx); err != nil {
								t.Error(err)
							}
						}
					})
				}
				var output bytes.Buffer

				var err error
				switch kind {
				case "suite":
					request := runRequest{Suite: "live", Provider: "gcp", Profile: "full", Resolved: &resolvedRequest{Mode: "live", Provider: "gcp", Profile: "full", Race: true}, execution: policy}
					prepared := &preparedSuite{assemblyPreparations: ctx, request: request, binding: binding, inventory: inventory, class: rootAdmission{Live: true, Execution: policy}, joined: true, closed: true}
					if caller == "prepared" {
						_, err = runPreparedSuite(ctx, root, "", prepared, &output)
					} else {
						_, err = runSuite(context.WithValue(ctx, preparedSuiteContextKey{}, prepared), root, "", request, &output)
					}

					if closeErr := prepared.close(ctx); closeErr != nil {
						t.Fatal(closeErr)
					}
				case "cleanup":
					request := cleanupRequest{RunID: id, race: true, execution: policy}
					prepared := &preparedCleanup{request: request, preflight: preflight, class: rootAdmission{Live: true, Execution: policy}, closed: true}
					if caller == "prepared" {
						_, err = runPreparedCleanup(ctx, root, "", prepared, &output)
					} else {
						_, err = runCleanup(context.WithValue(ctx, preparedCleanupContextKey{}, prepared), root, "", request, &output)
					}

					if closeErr := prepared.close(ctx); closeErr != nil {
						t.Fatal(closeErr)
					}

				}
				assertClosedPreparationError(t, err, private, root)

				for _, fact := range diagnostics.Commands {

					line := fmt.Sprintf("Check phase=preparation scope=%s process=%s started=%t joined=%t ", fact.Scope, fact.Process, fact.Started, fact.Joined)
					if strings.Count(output.String(), line) != 1 {
						t.Fatal("direct failure omitted or repeated terminal preparation facts", line, output.String())
					}
				}

			})
		}
	}
}

// full_only: false
func TestLivePreparationCloseErrorsKeepAllCausesClosed(t *testing.T) {
	joinedCause, unjoinedCause := errors.New(preparationStdoutCanary), errors.New(preparationStderrCanary)
	joined := &toolFailure{operation: "private close operation", process: processResult{Status: "failed", Started: true, Joined: true, Cause: joinedCause}, stdout: []byte(preparationStdoutCanary)}
	unjoined := &toolFailure{operation: "private unjoined close operation", process: processResult{Status: "failed", Started: true, Cause: unjoinedCause}}
	group := &preparedOrdinaryGroup{ctx: t.Context(), joined: true, cancel: func() {}, lease: func(context.Context, bool) error { return errors.Join(joined, unjoined) }}
	workflow := &preparedWorkflow{class: rootAdmission{Live: true}, joined: true, ordinary: map[string]*preparedOrdinaryGroup{"local": group}}
	err := workflow.close(t.Context())
	assertClosedPreparationError(t, err, "private close operation", "private unjoined close operation")
	var original *toolFailure
	if !errors.As(err, &original) || original != joined || !errors.Is(err, joinedCause) || !errors.Is(err, unjoinedCause) || toolCommandsJoined(err) {
		t.Fatal("joined close branches lost a private cause or unsettled command")
	}
	if err := workflow.close(t.Context()); err != nil {
		t.Fatal("closed workflow repeated finalization")
	}
	closed := safeCheckFailure("assembly", "retained", joined)
	if safePreparationFailure(closed) != closed || !checkDiagnosticsSaved(closed) {
		t.Fatal("an existing closed failure lost its retained diagnostic facts")
	}
	noOwner := safeCheckFailure("preparation", "none", joined)
	directory := t.TempDir()
	saved := retainCheckFailure(directory, "preparation.log", "assembly", noOwner)
	retained, ok := saved.(*checkFailure)
	if !ok || retained == noOwner || retained.phase != "assembly" || retained.diagnostic != "retained" || retained.cause != noOwner || !errors.Is(saved, joinedCause) {
		t.Fatal("diagnostic storage did not publish its new phase and retained status")
	}
	body, readErr := os.ReadFile(filepath.Join(directory, "private", "preparation.log"))
	if readErr != nil || !bytes.Contains(body, []byte(preparationStdoutCanary)) {
		t.Fatal("diagnostic storage did not retain the private underlying cause")
	}
	if safePreparationFailure(saved) != saved {
		t.Fatal("preparation conversion replaced the diagnostic storage owner's status")
	}
}
