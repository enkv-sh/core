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
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestComponentRepetitionsAttachConverterPreparationOnce(t *testing.T) {
	root := workflowExecutionFixture(t)
	build := t.TempDir()
	const requested = "TestConverterOwner"
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, requested)
	// Empty roots provide compiled selection metadata, not Product capacity proof.
	flags := componentMetadataBuildFlags(t, root, componentProfileFixtureClassifications(inventory))
	writeLocalGoFixture(t, root, "core/fixture.go", "package core\n")
	overlay := filepath.Join(build, "overlay.json")
	if err := os.WriteFile(overlay, []byte(`{"Replace":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	flags = append(flags, "-overlay="+overlay)
	ctx, cancel := context.WithTimeout(withRacePolicy(workflowTestContext(t, root), false), 2*time.Minute)
	defer cancel()
	journalOwner, err := newCurrentDirectory("enkv-component-verification-journal-")
	if err != nil {
		t.Fatal(err)
	}
	journalSettled := false
	t.Cleanup(func() {
		if !journalSettled {
			t.Log("retained component verification journal:", journalOwner.path)
			return
		}
		if err := journalOwner.remove(true); err != nil {
			t.Error(err)
		}
	})
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(journalOwner.path, "commands")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> " + shellQuote(journal) + " || exit 93\nexec " + shellQuote(realGo) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(journalOwner.path, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", journalOwner.path+string(os.PathListSeparator)+os.Getenv("PATH"))
	actualFlags := compilerBuildFlags(flags, raceEnabled(ctx))
	binary := filepath.Join(build, "converter-owner.test")
	args := append([]string{"test"}, actualFlags...)
	if _, err := runGo(ctx, root, "core", append(args, "-c", "-o", binary, ".")...); err != nil {
		t.Fatal(err)
	}
	binaryHash, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	overlayHash, err := assemblyFileSHA256(overlay)
	if err != nil {
		t.Fatal(err)
	}
	converter, preparation, err := prepareTestEventConverter(ctx, root, build)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.Phase != "preparation" || preparation.Scope != "test2json" || preparation.Process != "passed" || !preparation.Started || !preparation.Joined || converter.preparation == nil || !reflect.DeepEqual(*converter.preparation, preparation) {
		t.Fatal("converter preparation lacks its real passed build and positive join", preparation)
	}
	owner := assembly{root: root, Binary: binary, converter: converter, buildFlags: flags,
		Closure: assemblyClosure{BinarySHA256: binaryHash, OverlaySHA256: overlayHash, Race: false, RaceOptions: acceptedRaceOptions(false)}}
	bindAssemblyFailureSources(t, &owner, build)
	if err := checkAssemblyRace(ctx, owner); err != nil {
		t.Fatal("small compiled owner is not current", err)
	}
	env := workerEnvironment("")
	if !t.Run("failed-selection-retains-inventory-prefix", func(t *testing.T) {
		process, evidence, _, _ := executeProfileComponentChecks(nil, ctx, root, binary, converter, flags, env, "dev", singleTestRequest("TestUnavailablePreparationRoot"), 1, io.Discard, &owner)
		if process.Status != "process_failed" || process.Cause == nil || process.Started || !process.Joined || evidence.TestsComplete || len(evidence.Tests) != 0 || owner.componentSelection != nil {
			t.Fatal("failed component selection published execution or a runnable selection", process, evidence)
		}
		if evidence.Diagnostics == nil || evidence.Diagnostics.Preparation != "failed" || len(evidence.Diagnostics.Commands) != 1 {
			t.Fatal("failed component selection lost its acquired inventory prefix", evidence.Diagnostics)
		}
		for index, scope := range []string{"inventory"} {
			fact := evidence.Diagnostics.Commands[index]
			if fact.Phase != "preparation" || fact.Scope != scope || fact.Process != "passed" || !fact.Started || !fact.Joined {
				t.Fatal("component prefix no longer describes its real completed preparation commands", fact)
			}
		}
	}) {
		t.Fatal("component selection prerequisite failed before workflow dispatch")
	}
	selection, _, err := prepareComponentChecks(nil, ctx, root, binary, flags, env, "dev", singleTestRequest(requested), &owner)
	if err != nil {
		t.Fatal(err)
	}
	// This input isolates shared dispatch and workflow attachment. Full workflow
	// preparation must independently register the converter with this owner.
	if err := selection.evidence.Diagnostics.retainAcquisition(&converter, "converter", &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{preparation}}); err != nil {
		t.Fatal(err)
	}
	owner.componentSelection = selection
	preparedEvidence, err := json.Marshal(selection.evidence)
	if err != nil {
		t.Fatal(err)
	}
	preparedGroups, err := json.Marshal(selection.estimates)
	if err != nil {
		t.Fatal(err)
	}
	preparedConverter, err := json.Marshal(converter.preparation)
	if err != nil {
		t.Fatal(err)
	}
	preparedSelected := slices.Clone(selection.selected)
	wantPreparation := slices.Clone(selection.evidence.Diagnostics.Commands)
	if len(wantPreparation) != 2 {
		t.Fatal("shared acquisition lost inventory or converter construction", len(wantPreparation))
	}
	group := newPreparedComponentGroup(ctx)
	defer group.cancel()
	group.assembled = owner
	steps := expandWorkflowRepetitions(resolvedWorkflowStep{ID: "repeated", Kind: "component-tests", Selected: true, Profile: "dev", Focus: selection.focus}, 2)
	plan := workflowPlan{SchemaVersion: 1, Name: "converter-preparation-owner", Profile: "dev", Race: false,
		Execution: executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: normalExecutionMemoryMiB}}, Steps: steps,
		prepared: &preparedWorkflow{components: map[string]*preparedComponentGroup{"repeated": group}, joined: true}}
	plan.prepared.plan = plan
	group.assembled.preparationOwner, group.assembled.preparationKey = group, "repeated"
	var output bytes.Buffer
	initials := map[string]*checkDiagnostics{}
	initialBytes := map[string][]byte{}
	initialSnapshots := map[string]*checkDiagnostics{}
	calls := 0
	constructorJournal, err := os.ReadFile(journal)
	if err != nil || len(constructorJournal) == 0 {
		t.Fatal("completed component constructor journal unavailable", err)
	}
	result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(child context.Context, step resolvedWorkflowStep, out io.Writer, _ string) (workflowStepExecution, error) {
		calls++
		initial := step.currentPrefix
		if initial == nil {
			initial = &checkDiagnostics{Preparation: "pending"}
		}
		prefixCount := len(initial.Commands)
		if prefixCount != 0 && prefixCount != 2 {
			return workflowStepExecution{}, errors.New("callback received an incomplete shared acquisition")
		}
		initial.Preparation = "passed"
		initials[step.ID] = initial
		initialSnapshots[step.ID] = initial.snapshot()
		body, marshalErr := json.Marshal(initial)
		if marshalErr != nil {
			return workflowStepExecution{}, marshalErr
		}
		initialBytes[step.ID] = body
		process, checks, _, _ := executeProfileComponentChecks(initial, child, root, binary, converter, flags, env, step.Profile, step.Focus.Tests, 1, out, &group.assembled)
		if writeErr := writeCheckDiagnostics(out, checks.Diagnostics); writeErr != nil {
			return workflowStepExecution{Component: &componentRunRecord{Outcome: "failed", Checks: &checks}}, writeErr
		}
		record := &componentRunRecord{Outcome: process.Status, BuildClosure: &owner.Closure, Checks: &checks}
		if process.Status != "passed" || !process.Started || !process.Joined || !completeFocusedComponentEvidence(checks) {
			return workflowStepExecution{Component: record}, fmt.Errorf("component repetition %s failed: process=%+v cause=%v checks=%+v", step.ID, process, process.Cause, checks)
		}
		return workflowStepExecution{Component: record}, nil
	})
	journalSettled = toolCommandsJoined(err) && sourceCommandsJoined(err)
	if err != nil || result.Outcome != "passed" || calls != 2 || len(result.Steps) != 2 {
		t.Fatal("shared component workflow did not complete both serial executions", err, result.Outcome, calls, output.String())
	}
	journalBody, journalErr := os.ReadFile(journal)
	if journalErr != nil || !bytes.HasPrefix(journalBody, constructorJournal) {
		t.Fatal("component execution changed its completed constructor journal", journalErr)
	}
	executionJournal := journalBody[len(constructorJournal):]
	if len(executionJournal) != 0 {
		t.Fatal("borrowing repeated compiler work", string(executionJournal))
	}
	converterFacts := 0
	for index, step := range result.Steps {
		execution := result.executions[step.ID]
		if execution.Component == nil || execution.Component.Checks == nil || step.Outcome != "passed" {
			t.Fatal("component repetition lost its actual execution", step.ID)
		}
		checks := execution.Component.Checks
		if !completeFocusedComponentEvidence(*checks) || completeComponentEvidence(*checks, "hermetic", "memory") || checks.Profile != "dev" || checks.Race || checks.RaceOptions != acceptedRaceOptions(false) || checks.Selection != "^TestConverterOwner$" || checks.Focus == nil || checks.Focus.Tests[0] != requested || requestedTestRoots(checks.Focus.Tests)[0] != requested {
			t.Error("repetition changed its focused selection or accepted race settings", step.ID, checks)
		}
		if len(checks.Tests) != 1 || checks.Tests[0].Name != requested || checks.Tests[0].Outcome != "passed" || checks.Tests[0].StartedAt == nil || checks.Tests[0].FinishedAt == nil {
			t.Error("repetition lost its exact selected terminal", step.ID, checks.Tests)
		}
		var preparations []checkCommandFacts
		tests, conversions, attachedConverter := 0, 0, 0
		for _, command := range checks.Diagnostics.Commands {
			if !command.Started || !command.Joined || command.Process != "passed" {
				t.Error("component command lacks its positive join", step.ID, command)
			}
			switch command.Phase {
			case "preparation":
				preparations = append(preparations, command)
				if command.Scope == preparation.Scope {
					attachedConverter++
					converterFacts++
					if !reflect.DeepEqual(command, preparation) {
						t.Error("workflow changed the original converter build fact", step.ID, command, preparation)
					}
				}
			case "test", "conversion":
				wantEvents, wantNode := "valid", ""
				if command.Phase == "test" {
					wantEvents, wantNode = "not_run", "passed"
				}
				if len(checks.Groups) != 1 || command.Scope != checks.Groups[0].Name || command.RaceObservation != "not_observed" || command.Events != wantEvents || command.RequestedNode != wantNode {
					t.Error("component dispatch lost its exact scope, race observation or valid events", step.ID, command)
				}
				if command.Phase == "test" {
					tests++
				} else {
					conversions++
				}
			default:
				t.Error("unexpected shared component command", step.ID, command)
			}
		}
		wantConverter, prefixCount := 0, 0
		if index == 0 {
			wantConverter, prefixCount = 1, 2
		}
		if execution.Preparation != nil && len(execution.Preparation.Commands) != 0 {
			t.Fatal("same-owner handoff left a duplicate preparation complement", step.ID)
		}
		initial := initials[step.ID]
		frozen := initialSnapshots[step.ID]
		if initial == nil || checks.Diagnostics != initial || frozen == nil || len(frozen.Commands) != prefixCount {
			t.Fatal("component repetition lost its current owner or frozen prefix", step.ID)
		}
		if index == 0 && !reflect.DeepEqual(frozen.Commands[:2], wantPreparation) {
			t.Fatal("first activity changed the shared acquisition", step.ID)
		}
		wantCommands := slices.Clone(frozen.Commands)
		if len(preparations) != prefixCount {
			t.Fatal("borrowing added preparation facts", step.ID, len(preparations))
		}
		afterInitial, initialErr := json.Marshal(frozen)
		if initialErr != nil || !bytes.Equal(initialBytes[step.ID], afterInitial) {
			t.Error("execution changed the frozen version snapshot", step.ID, initialErr)
		}
		if tests != 1 || conversions != 1 || attachedConverter != wantConverter || !reflect.DeepEqual(preparations, wantCommands) {
			t.Error("shared preparation must attach once to the first execution", step.ID, "tests", tests, "conversions", conversions, "converter facts", attachedConverter, "preparation", preparations, "want", wantCommands)
		}
	}
	if converterFacts != 1 {
		t.Error("converter build fact did not have one execution owner", converterFacts)
	}

	factRows := 0
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "Check phase=") && strings.Contains(line, " process=") {
			factRows++
		}
	}
	// Shared inventory and converter facts plus two native test/conversion pairs.
	if factRows != 7 || strings.Count(output.String(), "Check phase=preparation scope=core process=passed started=true joined=true ") != 0 || strings.Count(output.String(), "Check phase=preparation scope=test2json process=passed started=true joined=true ") != 1 {
		t.Error("terminal did not give each fresh and shared command one owner", factRows, output.String())
	}
	if len(result.RepetitionGroups) != 1 || result.RepetitionGroups[0].RequestedExecutions != 2 || result.RepetitionGroups[0].CompletedExecutions != 2 || result.RepetitionGroups[0].Outcome != "passed" {
		t.Error("shared workflow lost repetition completion", result.RepetitionGroups)
	}
	afterEvidence, evidenceErr := json.Marshal(selection.evidence)
	afterGroups, groupsErr := json.Marshal(selection.estimates)
	afterConverter, converterErr := json.Marshal(converter.preparation)
	if evidenceErr != nil || groupsErr != nil || converterErr != nil || !bytes.Equal(preparedEvidence, afterEvidence) || !bytes.Equal(preparedGroups, afterGroups) || !bytes.Equal(preparedConverter, afterConverter) || !slices.Equal(preparedSelected, selection.selected) || selection.profile != "dev" || !slices.Equal(selection.requested, []string{requested}) || group.assembled.converter.binary != converter.binary || group.assembled.converter.sha256 != converter.sha256 {
		t.Error("component executions changed immutable prepared facts", evidenceErr, groupsErr, converterErr)
	}
	if err := converter.verify(); err != nil {
		t.Error("component executions changed retained converter bytes", err)
	}
}

// full_only: false
func TestSharedComponentQueueCapacityIncludesPreparationBeforeDispatch(t *testing.T) {
	t.Run("generic-discovery-stays-256", func(t *testing.T) {
		d := &checkDiagnostics{Preparation: "pending"}
		fact := preparationReservationFact("core", false)
		for range 256 {
			if err := d.append(fact); err != nil {
				t.Fatal(err)
			}
		}
		if maximumCheckCommands != 256 || d.append(fact) == nil {
			t.Fatal("unplanned discovery exceeded its unchanged bound")
		}
	})
	t.Run("closed-small-plan-and-copy-resume-bounded-acquisition", func(t *testing.T) {
		fact := checkCommandFacts{Phase: "preparation", Scope: "core", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed"}
		closed := &checkDiagnostics{Preparation: "passed"}
		future := []checkCommandFacts{preparationReservationFact("core", false), preparationReservationFact("core", false)}
		if err := closed.reserveCommands(future); err != nil {
			t.Fatal(err)
		}
		if err := closed.consumeCommands(future); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := closed.append(fact); err != nil {
				t.Fatal(err)
			}
		}
		var initialOutput bytes.Buffer
		if err := writeCheckDiagnostics(&initialOutput, closed); err != nil {
			t.Fatal(err)
		}
		closed.cancelReservations()
		if closed.hasPlan() || closed.commandLimit() != 256 || closed.attempted != 2 || !closed.headerAttempted {
			t.Fatal("small close did not restore discovery or retain delivery state")
		}
		snapshot := closed.snapshot()
		acquiredSource := closed.snapshot()
		sourceBefore, err := json.Marshal(acquiredSource)
		if err != nil {
			t.Fatal(err)
		}
		copied := &checkDiagnostics{Preparation: "passed"}
		if err := copied.retainAcquisition(acquiredSource, "binding", acquiredSource); err != nil {
			t.Fatal(err)
		}
		var copiedOutput bytes.Buffer
		if err := writeCheckDiagnostics(&copiedOutput, copied); err != nil {
			t.Fatal(err)
		}
		if err := copied.reserveCommands(future[:1]); err != nil {
			t.Fatal(err)
		}
		copied.cancelReservations()
		if copied.hasPlan() || copied.commandLimit() != 256 || !copied.hasAcquisition(acquiredSource, "binding") || copied.attempted != 2 || !copied.headerAttempted {
			t.Fatal("small acquisition close lost generic admission, claims, or delivery")
		}
		fixture, err := newCurrentDirectory("enkv-closed-small-plan-")
		if err != nil {
			t.Fatal(err)
		}
		settled := false
		t.Cleanup(func() {
			if !settled {
				t.Log("retained closed-small fixture:", fixture.path)
				return
			}
			if err := fixture.remove(true); err != nil {
				t.Error(err)
			}
		})
		if err := os.Mkdir(filepath.Join(fixture.path, "core"), 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(fixture.path, "commands")
		script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> " + shellQuote(marker) + "\nprintf 'go version controlled\\n'\n"
		if err := os.WriteFile(filepath.Join(fixture.path, "go"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", fixture.path+string(os.PathListSeparator)+os.Getenv("PATH"))
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		joined := true
		run := func(d *checkDiagnostics) ([]byte, checkCommandFacts, error) {
			settled = false
			body, facts, cause := d.runGoRecordedEnvironment(ctx, fixture.path, "core", nil, "version")
			joined = joined && toolCommandsJoined(cause) && sourceCommandsJoined(cause) && (facts.Process == "" || facts.Joined)
			settled = joined
			return body, facts, cause
		}
		for _, item := range []struct {
			name  string
			owner *checkDiagnostics
		}{{"cancelled", closed}, {"snapshot", snapshot}, {"copied", copied}} {
			body, actual, cause := run(item.owner)
			if cause != nil || !strings.HasPrefix(string(body), "go version ") || !actual.Started || !actual.Joined || actual.Process != "passed" || len(item.owner.Commands) != 3 {
				t.Fatal("small closed owner refused its next generic Go command", item.name, cause, actual)
			}
			for len(item.owner.Commands) < 255 {
				if err := item.owner.append(fact); err != nil {
					t.Fatal(item.name, err)
				}
			}
			_, actual, cause = run(item.owner)
			if cause != nil || !actual.Started || !actual.Joined || len(item.owner.Commands) != 256 {
				t.Fatal("last generic Go acquisition refused", item.name, cause, actual)
			}
			before, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			_, actual, cause = run(item.owner)
			after, readErr := os.ReadFile(marker)
			if cause == nil || !reflect.DeepEqual(actual, checkCommandFacts{}) || len(item.owner.Commands) != 256 || readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("first generic command beyond256 started", item.name, cause, actual, readErr)
			}
		}
		sourceAfter, err := json.Marshal(acquiredSource)
		if err != nil {
			t.Fatal(err)
		}
		if !copied.hasAcquisition(acquiredSource, "binding") || copied.attempted != 2 || closed.attempted != 2 || !bytes.Equal(sourceBefore, sourceAfter) {
			t.Fatal("same-owner close/acquisition lost claims, delivery, or frozen source facts")
		}
		// A separate ordinary body reservation still supports all8192 selected
		// processes. It grants no extra unplanned preparation Go commands.
		ordinary := &checkDiagnostics{Preparation: "passed", Commands: slices.Clone(closed.Commands)}
		if err := ordinary.reserveOrdinaryCommands([]ordinaryCommandReservation{{scope: "core", processes: 8192, factsPerProcess: 1}}); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal(err)
		}
		_, actual, cause := run(ordinary)
		after, readErr := os.ReadFile(marker)
		if cause == nil || !reflect.DeepEqual(actual, checkCommandFacts{}) || readErr != nil || !bytes.Equal(before, after) {
			t.Fatal("ordinary body credits admitted extra preparation Go", cause, actual, readErr)
		}
		for range 8192 {
			if err := ordinary.append(componentReservationFact("test", "ordinary-body")); err != nil {
				t.Fatal("ordinary body capacity changed", err)
			}
		}
		if len(ordinary.Commands) != 256+8192 || ordinary.ordinaryCommandBytes == 0 || ordinary.append(fact) == nil {
			t.Fatal("ordinary incremental body reservation changed")
		}
	})
	t.Run("finite-plan-last-row-and-exhausted-nested-refusal", func(t *testing.T) {
		fact := preparationReservationFact("core", false)
		future := make([]checkCommandFacts, 257)
		for index := range future {
			future[index] = fact
		}
		d := &checkDiagnostics{Preparation: "pending"}
		if err := d.reserveCommands(future); err != nil {
			t.Fatal("finite257-row plan refused", err)
		}
		if d.append(fact) == nil {
			t.Fatal("unplanned row stole mandatory credits")
		}
		for _, forecast := range future {
			if err := d.consumeCommands([]checkCommandFacts{forecast}); err != nil {
				t.Fatal(err)
			}
			if err := d.append(forecast); err != nil {
				t.Fatal(err)
			}
		}
		if !d.hasPlan() || len(d.Commands) != 257 || d.append(fact) == nil {
			t.Fatal("exhausted active plan minted another row")
		}
		fixture, err := newCurrentDirectory("enkv-exhausted-plan-")
		if err != nil {
			t.Fatal(err)
		}
		settled := false
		t.Cleanup(func() {
			if !settled {
				t.Log("retained exhausted-plan fixture:", fixture.path)
				return
			}
			if err := fixture.remove(true); err != nil {
				t.Error(err)
			}
		})
		if err := os.Mkdir(filepath.Join(fixture.path, "core"), 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(fixture.path, "started")
		script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> " + shellQuote(marker) + "\nprintf 'go version controlled\\n'\n"
		if err := os.WriteFile(filepath.Join(fixture.path, "go"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", fixture.path+string(os.PathListSeparator)+os.Getenv("PATH"))
		// This is the nested-helper admission rule: an exhausted ACTIVE plan
		// does not grant the nested helper authority to reserve a new block.
		if !d.hasPlan() {
			if err := d.reserveCommands([]checkCommandFacts{fact}); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, acquired, runErr := d.runGoRecordedEnvironment(ctx, fixture.path, "core", nil, "version")
		settled = toolCommandsJoined(runErr) && sourceCommandsJoined(runErr)
		if runErr == nil || !reflect.DeepEqual(acquired, checkCommandFacts{}) || len(d.Commands) != 257 {
			t.Fatal("exhausted nested command acquired unplanned facts", runErr, acquired)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("exhausted nested command started", err)
		}
		empty := &checkDiagnostics{Preparation: "pending"}
		if err := empty.reserveCommands(nil); err != nil || !empty.hasPlan() {
			t.Fatal("explicit zero-row plan lost its ownership", err)
		}
		if !empty.hasPlan() {
			if err := empty.reserveCommands([]checkCommandFacts{fact}); err != nil {
				t.Fatal(err)
			}
		}
		_, zeroFacts, zeroErr := empty.runGoRecordedEnvironment(ctx, fixture.path, "core", nil, "version")
		settled = settled && toolCommandsJoined(zeroErr) && sourceCommandsJoined(zeroErr)
		if zeroErr == nil || !reflect.DeepEqual(zeroFacts, checkCommandFacts{}) || len(empty.Commands) != 0 {
			t.Fatal("zero plan admitted an unforecasted command", zeroErr, zeroFacts)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("zero plan dispatched a command", err)
		}
		empty.cancelReservations()
		d.cancelReservations()
		if d.hasPlan() || d.consumeCommands([]checkCommandFacts{fact}) == nil {
			t.Fatal("closed plan retained execution authority")
		}
		largeSnapshot := d.snapshot()
		largeAcquisition := d.snapshot()
		largeCopy := &checkDiagnostics{Preparation: "passed"}
		if err := largeCopy.retainAcquisition(largeAcquisition, "large", largeAcquisition); err != nil {
			t.Fatal(err)
		}
		largeOwners := []*checkDiagnostics{d, largeSnapshot, largeCopy}
		for _, owner := range largeOwners {
			var terminal bytes.Buffer
			if owner.hasPlan() || owner.commandLimit() != 257 {
				t.Fatal("large closed prefix acquired executable credits")
			}
			if err := writeCheckDiagnostics(&terminal, owner); err != nil || strings.Count(terminal.String(), "Check phase=") != 257 {
				t.Fatal("large closed facts were not publishable", err)
			}
			_, acquired, cause := owner.runGoRecordedEnvironment(ctx, fixture.path, "core", nil, "version")
			settled = settled && toolCommandsJoined(cause) && sourceCommandsJoined(cause)
			if cause == nil || !reflect.DeepEqual(acquired, checkCommandFacts{}) || len(owner.Commands) != 257 {
				t.Fatal("large closed prefix dispatched without a new plan", cause, acquired)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("large closed prefix started unplanned Go", err)
			}
		}
		for _, owner := range largeOwners {
			if err := owner.reserveCommands([]checkCommandFacts{fact}); err != nil {
				t.Fatal(err)
			}
			settled = false
			body, acquired, cause := owner.runGoRecordedEnvironment(ctx, fixture.path, "core", nil, "version")
			settled = toolCommandsJoined(cause) && sourceCommandsJoined(cause) && acquired.Joined
			if cause != nil || !strings.HasPrefix(string(body), "go version ") || !acquired.Started || !acquired.Joined || acquired.Process != "passed" || len(owner.Commands) != 258 {
				t.Fatal("new explicit plan failed to admit large-prefix command", cause, acquired)
			}
			owner.cancelReservations()
		}
		observed, err := os.ReadFile(marker)
		if err != nil || len(strings.Fields(string(observed))) != 3 {
			t.Fatal("large-prefix plans changed physical command count", err, string(observed))
		}

	})
	t.Run("finite-plan-encoded-last-byte", func(t *testing.T) {
		future := []checkCommandFacts{preparationReservationFact("core", true), preparationReservationFact("core", false)}
		prefix := checkCommandFacts{Phase: "preparation", Scope: "", Process: "passed", Started: true, Joined: true, Events: "not_run", ToolCleanup: "not_required", RaceObservation: "not_observed", ModulePreparation: &modulePreparationFacts{Process: "passed", Started: true, Joined: true}}
		body, err := json.Marshal(checkDiagnostics{Preparation: "pending", Commands: append([]checkCommandFacts{prefix}, future...)})
		if err != nil {
			t.Fatal(err)
		}
		prefix.Scope = strings.Repeat("x", (32<<20)-len(body)-1)
		last := &checkDiagnostics{Preparation: "pending", Commands: []checkCommandFacts{prefix}}
		before, _ := json.Marshal(last)
		if err := last.reserveCommands(future); err != nil {
			t.Fatal("last encoded plan byte refused", err)
		}
		after, _ := json.Marshal(last)
		if !bytes.Equal(before, after) {
			t.Fatal("forecast published placeholders or omitted module join credits")
		}
		if err := last.consumeCommands(future); err != nil {
			t.Fatal(err)
		}
		for _, fact := range future {
			if err := last.append(fact); err != nil {
				t.Fatal(err)
			}
		}
		closed, err := json.Marshal(last)
		if err != nil || len(closed)+1 != 32<<20 {
			t.Fatal("independent last-byte encoding disagrees", err, len(closed)+1)
		}
		prefix.Scope += "x"
		first := &checkDiagnostics{Preparation: "pending", Commands: []checkCommandFacts{prefix}}
		if err := first.reserveCommands(future); err == nil {
			t.Fatal("first byte beyond finite32MiB plan accepted")
		}
		fixture, err := newCurrentDirectory("enkv-byte-admission-command-")
		if err != nil {
			t.Fatal(err)
		}
		settled := false
		t.Cleanup(func() {
			if !settled {
				t.Log("retained byte-admission fixture:", fixture.path)
				return
			}
			if err := fixture.remove(true); err != nil {
				t.Error(err)
			}
		})
		module, err := sourcePath(fixture.path, outputTestModule)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(module, "cmd", outputTestCommand), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte("module "+modulePath(outputTestModule)+"\n\ngo 1.27.0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(module, "cmd", outputTestCommand, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		descriptorPath, err := sourcePath(testRepositoryRoot(t), outputTestModule+"/cmd/"+outputTestCommand+"/plugin.json")
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := os.ReadFile(descriptorPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(module, "cmd", outputTestCommand, "plugin.json"), descriptor, 0600); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(fixture.path, "go-started")
		script := "#!/bin/sh\nprintf started > " + shellQuote(marker) + "\nexit 19\n"
		if err := os.WriteFile(filepath.Join(fixture.path, "go"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", fixture.path+string(os.PathListSeparator)+os.Getenv("PATH"))
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		artifact, buildErr := buildOutputTestArtifactOwned(first, ctx, fixture.path, fixture.path, false)
		settled = toolCommandsJoined(buildErr) && sourceCommandsJoined(buildErr)
		if buildErr == nil || !strings.Contains(buildErr.Error(), "byte bound") || artifact != nil || len(first.Commands) != 1 {
			t.Fatal("owned output construction did not refuse its byte budget first", buildErr, artifact)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("over-byte owned construction dispatched Go", err)
		}

	})
	t.Run("measured-42-group-15-prefix-one-output-lower-bound", func(t *testing.T) {
		// This synthetic admission witness uses the measured G42/P15/F1
		// lower bound. It is not a complete-route count or an assembly fixture.
		const groups, prefixRows, outputs = 42, 15, 1
		passed := preparationReservationFact("core", false)
		passed.Process, passed.Started, passed.Joined = "passed", true, true
		prefix := make([]checkCommandFacts, prefixRows)
		for index := range prefix {
			prefix[index] = passed
			if index < 8 {
				prefix[index].ModulePreparation = &modulePreparationFacts{Process: "passed", Started: true, Joined: true}
			}
		}
		var future []checkCommandFacts
		for range groups + 2 {
			for _, module := range []bool{true, true, false, false} {
				future = append(future, preparationReservationFact("core", module))
			}
			for range 2 * outputs {
				future = append(future, preparationReservationFact(outputTestModule, true))
			}
		}
		for index := range groups {
			for _, phase := range []string{"test", "conversion"} {
				future = append(future, componentReservationFact(phase, fmt.Sprintf("measured-group-%d", index+1)))
			}
		}
		d := &checkDiagnostics{Preparation: "pending", Commands: slices.Clone(prefix)}
		frozen, _ := json.Marshal(d)
		if err := d.reserveCommands(future); err != nil {
			t.Fatal("measured finite lower bound refused", err)
		}
		if d.commandLimit() != 363 || len(d.Commands) != 15 {
			t.Fatal("measured rows/physical joins differ", d.commandLimit())
		}
		after, _ := json.Marshal(d)
		if !bytes.Equal(frozen, after) {
			t.Fatal("planned facts were published before acquisition")
		}
		if err := d.consumeCommands(future); err != nil {
			t.Fatal(err)
		}
		for _, fact := range future {
			if err := d.append(fact); err != nil {
				t.Fatal(err)
			}
		}

		d.cancelReservations()
		frozenSource := d.snapshot()
		current := &checkDiagnostics{Preparation: "passed"}
		if err := current.retainAcquisition(frozenSource, "measured", frozenSource); err != nil || len(current.Commands) != 363 {
			t.Fatal("large frozen source was clipped to generic discovery", err)
		}
		var terminal bytes.Buffer
		if err := writeCheckDiagnostics(&terminal, current); err != nil || strings.Count(terminal.String(), "Check phase=") != 547 {
			t.Fatal("large fact-only acquisition lost publication", err)
		}

	})
	t.Run("distinct-source-claims-and-fresh-snapshots", func(t *testing.T) {
		fact := preparationReservationFact("core", true)
		source := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}, ordinaryCommandLimit: 8192, ordinaryCommandBytes: 12345}
		first, second := new(int), new(int)
		d := &checkDiagnostics{Preparation: "pending"}
		before, _ := json.Marshal(source)
		for _, owner := range []*int{first, second, first} {
			if err := d.retainAcquisition(owner, "shared", source); err != nil {
				t.Fatal(err)
			}
		}
		if len(d.Commands) != 2 || !d.hasAcquisition(first, "shared") || !d.hasAcquisition(second, "shared") || d.ordinaryCommandLimit != 0 || d.ordinaryCommandBytes != 0 {
			t.Fatal("source identity collapsed or copied future ordinary credits")
		}
		var output bytes.Buffer
		if err := writeCheckDiagnostics(&output, d); err != nil {
			t.Fatal(err)
		}
		d.Preparation = "failed"
		if err := writeCheckDiagnostics(&output, d); err != nil {
			t.Fatal(err)
		}
		if strings.Count(output.String(), "Check phase=") != 4 || !strings.HasSuffix(output.String(), "Check preparation=failed; commands=2\n") {
			t.Fatal("status-only header replayed facts", output.String())
		}
		if err := d.reserveCommands([]checkCommandFacts{fact}); err != nil {
			t.Fatal(err)
		}
		failed := source.snapshot()
		failed.Preparation = "failed"
		status := &checkDiagnostics{Preparation: "passed"}
		if err := status.retainAcquisition(first, "failed", failed); err != nil || status.Preparation != "failed" {
			t.Fatal("failed source status lost", err)
		}
		pending := source.snapshot()
		pending.Preparation = "pending"
		if err := status.retainAcquisition(second, "pending", pending); err != nil || status.Preparation != "failed" {
			t.Fatal("failed current owner downgraded", err)
		}
		open := &checkDiagnostics{Preparation: "passed"}
		if err := open.retainAcquisition(first, "pending", pending); err != nil || open.Preparation != "pending" {
			t.Fatal("pending source status lost", err)
		}
		fresh := d.snapshot()
		if fresh.hasPlan() || fresh.attempted != 0 || fresh.deliveryFailed || fresh.weightsValid || fresh.hasAcquisition(first, "shared") {
			t.Fatal("fresh snapshot copied delivery, claims, or future credits")
		}
		after, _ := json.Marshal(source)
		if !bytes.Equal(before, after) || source.ordinaryCommandLimit != 8192 || source.ordinaryCommandBytes != 12345 {
			t.Fatal("source acquisition changed")
		}
	})
	t.Run("same-invocation-claim-handoff", func(t *testing.T) {
		owner := new(int)
		fact := preparationReservationFact("core", false)
		source := &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{fact}}
		previous := &checkDiagnostics{Preparation: "passed"}
		if err := previous.retainAcquisition(owner, "provider", source); err != nil {
			t.Fatal(err)
		}
		var terminal bytes.Buffer
		if err := writeCheckDiagnostics(&terminal, previous); err != nil {
			t.Fatal(err)
		}
		// The real previous result structurally retains its facts before the
		// next case receives only the matching source identity claim.
		retained := []workflowStepExecution{{Preparation: previous}}
		next := &checkDiagnostics{Preparation: "pending"}
		if err := next.inheritAcquisitionClaim(owner, "provider", retained[0].Preparation); err != nil {
			t.Fatal(err)
		}
		if !next.hasAcquisition(owner, "provider") || len(next.Commands) != 0 || next.Preparation != "pending" || next.attempted != 0 || next.headerAttempted || next.weightsValid || next.hasPlan() {
			t.Fatal("claim handoff copied facts or activity state")
		}
		if err := next.retainAcquisition(owner, "provider", source); err != nil || len(next.Commands) != 0 || len(retained[0].Preparation.Commands) != 1 {
			t.Fatal("same invocation duplicated or lost acquired facts", err)
		}
		missing := new(int)
		if err := next.inheritAcquisitionClaim(missing, "provider", previous); err == nil || next.hasAcquisition(missing, "provider") {
			t.Fatal("missing source claim invented")
		}
		freshInvocation := next.snapshot()
		if freshInvocation.hasAcquisition(owner, "provider") {
			t.Fatal("new invocation inherited recovery claims")
		}
		if err := freshInvocation.retainAcquisition(owner, "provider", source); err != nil || len(freshInvocation.Commands) != 1 {
			t.Fatal("new invocation lost its independent acquisition", err)
		}
	})
	t.Run("partial-delivery-never-retries", func(t *testing.T) {
		for _, position := range []int{1, 2, 3} {
			t.Run(fmt.Sprint(position), func(t *testing.T) {
				cause := errors.New("partial diagnostic write")
				writer := &componentPartialDiagnosticWriter{failAt: position, cause: cause}
				fact := preparationReservationFact("core", true)
				d := &checkDiagnostics{Preparation: "pending", Commands: []checkCommandFacts{fact}}
				if err := writeCheckDiagnostics(writer, d); !errors.Is(err, cause) {
					t.Fatal("sticky writer cause lost", err)
				}
				wantAttempted := 1
				if position == 1 {
					wantAttempted = 0
				}
				if d.attempted != wantAttempted {
					t.Fatal("attempt ordinal claims undelivered facts", d.attempted, position)
				}
				calls, body := writer.calls, writer.String()
				// Later command facts remain available after a failed terminal write.
				if err := d.append(fact); err != nil {
					t.Fatal(err)
				}
				d.Preparation = "failed"
				if err := writeCheckDiagnostics(writer, d); !errors.Is(err, cause) || writer.calls != calls || writer.String() != body {
					t.Fatal("failed terminal delivery was retried or lost its cause", err)
				}

				fresh := d.snapshot()
				var replay bytes.Buffer
				if err := writeCheckDiagnostics(&replay, fresh); err != nil || strings.Count(replay.String(), "Check phase=") != 4 {
					t.Fatal("fresh activity inherited failed delivery", err)
				}
			})
		}
	})
	t.Run("failure-capture-minimum-share", func(t *testing.T) {
		name := "memory-" + strings.Repeat("long-group-name-", 8)
		h := len("Failed phase: " + name + " (upstream truncated: false)\n")
		e := len("Private assertion output (truncated: false):\n")
		r := len("Raw capture prefix:\n")
		o := len("\nRaw capture middle omitted: true\nRaw capture tail:\n")
		minimum := h + max(2*(e+1), 2*(r+o+2))
		lastCount := (256 << 10) / minimum
		last := make([]componentGroup, lastCount)
		for index := range last {
			last[index].Name = name
		}
		share, err := componentCaptureShare(last)
		if err != nil || share < minimum {
			t.Fatal("last positive failure share refused", err, share, minimum)
		}
		first := append(slices.Clone(last), componentGroup{Name: name})
		if _, err := componentCaptureShare(first); err == nil {
			t.Fatal("first failure share without all positive marker portions admitted")
		}
		if share, err := componentCaptureShare(nil); err != nil || share != 0 {
			t.Fatal("empty queue capture share is unsafe", share, err)
		}
		source := &limitedOutput{privateErrorOutput: []byte("assertion-tail!")}
		_, _ = source.Write([]byte("A" + strings.Repeat("x", 4*minimum) + "Z"))
		for _, allowance := range []int{0, 1, h - 1, minimum - 1} {
			destination := &limitedOutput{}
			appendFailedComponentCapture(destination, name, source, allowance)
			if !destination.overflow || len(destination.Bytes()) > max(0, allowance) {
				t.Fatal("small direct capture failed to remain bounded", allowance, len(destination.Bytes()))
			}
		}
		destination := &limitedOutput{}
		appendFailedComponentCapture(destination, name, source, minimum)
		body := string(destination.Bytes())
		if !strings.Contains(body, "Private assertion output (truncated:") || !strings.Contains(body, "!") || !strings.Contains(body, "Raw capture prefix:\nA") || !strings.HasSuffix(body, "Z") || len(body) > minimum {
			t.Fatal("minimum share lost a positive assertion/raw portion", len(body), minimum, body)
		}
	})
	root := workflowExecutionFixture(t)
	build := t.TempDir()
	const groupCount = 4096
	inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent)
	for len(inventory) < groupCount {
		inventory = append(inventory, fmt.Sprintf("TestSharedQueue%03d", len(inventory)))
	}
	classifications := componentProfileFixtureClassifications(inventory)
	requests := make([]string, len(inventory))
	for index := range classifications {
		fullOnly := true
		classifications[index].FullOnly = &fullOnly
		requests[index] = classifications[index].Name + "/leaf"
	}
	// Distinct child paths require separate literal selectors. Their bodies
	// establish selection and capacity preflight without test dispatch.
	flags := componentMetadataBuildFlags(t, root, classifications)
	writeLocalGoFixture(t, root, "core/fixture.go", "package core\n")
	writeLocalGoFixture(t, root, "core/dispatch_test.go", `package core
import ("os"; "strings"; "testing")
func TestMain(m *testing.M) {
 for _, argument := range os.Args[1:] {
  if strings.HasPrefix(argument, "-test.list=") { os.Exit(m.Run()) }
 }
 if err := os.WriteFile(os.Getenv("ENKV_COMPONENT_CAPACITY_MARKER"), []byte("started\n"), 0600); err != nil { os.Exit(8) }
 os.Exit(7)
}
`)
	overlay := filepath.Join(build, "overlay.json")
	if err := os.WriteFile(overlay, []byte(`{"Replace":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	flags = append(flags, "-overlay="+overlay)
	ctx, cancel := context.WithTimeout(withRacePolicy(workflowTestContext(t, root), false), 2*time.Minute)
	defer cancel()
	actualFlags := compilerBuildFlags(flags, raceEnabled(ctx))
	binary := filepath.Join(build, "shared-queue.test")
	args := append([]string{"test"}, actualFlags...)
	if _, err := runGo(ctx, root, "core", append(args, "-c", "-o", binary, ".")...); err != nil {
		t.Fatal(err)
	}
	binaryHash, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	overlayHash, err := assemblyFileSHA256(overlay)
	if err != nil {
		t.Fatal(err)
	}
	converter, preparation, err := prepareTestEventConverter(ctx, root, build)
	if err != nil {
		t.Fatal(err)
	}
	owner := assembly{root: root, Binary: binary, converter: converter, buildFlags: flags,
		Closure: assemblyClosure{BinarySHA256: binaryHash, OverlaySHA256: overlayHash, Race: false, RaceOptions: acceptedRaceOptions(false)}}
	bindAssemblyFailureSources(t, &owner, build)
	marker := filepath.Join(build, "group-started")
	env := environment(workerEnvironment(""), map[string]string{"ENKV_COMPONENT_CAPACITY_MARKER": marker})
	selection, _, err := prepareComponentChecks(nil, ctx, root, binary, flags, env, "full", requests, &owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := selection.evidence.Diagnostics.retainAcquisition(&converter, "converter", &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{preparation}}); err != nil {
		t.Fatal(err)
	}
	owner.componentSelection = selection
	_, _, selectionGroups, _, err := resolveComponentGroups(selection.evidence.Inventory, selection.evidence.Classifications, selection.profile, selection.requested, 1, selection.estimates)
	if err != nil {
		t.Fatal(err)
	}
	if len(selectionGroups) != groupCount || !slices.Equal(selection.selected, inventory) || !slices.Equal(selection.evidence.Inventory, inventory) || len(selection.evidence.Diagnostics.Commands) != 2 || len(selection.evidence.NotSelected) != 0 || !sameTestClassifications(selection.evidence.Classifications, classifications) {
		t.Fatalf("shared capacity fixture: groups=%d selected=%d inventory=%d preparation_commands=%d omitted=%d", len(selectionGroups), len(selection.selected), len(selection.evidence.Inventory), len(selection.evidence.Diagnostics.Commands), len(selection.evidence.NotSelected))
	}
	for _, group := range selectionGroups {
		if len(group.Tests) != 1 {
			t.Fatal("capacity fixture did not prepare singleton groups", group)
		}
	}
	preparations := map[string]int{}
	for _, command := range selection.evidence.Diagnostics.Commands {
		if command.Phase != "preparation" || command.Process != "passed" || !command.Started || !command.Joined || command.RaceObservation != "not_observed" || command.Events != "not_run" || command.ToolCleanup != "passed" && command.ToolCleanup != "not_required" {
			t.Fatal("shared preparation lacks a real passed command and positive join", command)
		}
		preparations[command.Scope]++
	}
	if !reflect.DeepEqual(preparations, map[string]int{"inventory": 1, "test2json": 1}) || converter.preparation == nil || !reflect.DeepEqual(*converter.preparation, preparation) {
		t.Fatal("shared capacity fixture lost distinct inventory, classification or converter preparation", preparations)
	}
	if maximumComponentInventory != 4096 || groupCount != maximumComponentInventory {
		t.Fatal("physical refusal fixture changed the compiled inventory bound")
	}
	if _, err := componentCaptureShare(selectionGroups); err == nil {
		t.Fatal("physical fixture does not reach the finite failure-capture refusal")
	}
	preparedFacts, err := json.Marshal([]any{selection.evidence, selection.estimates, selection.selected, selection.profile, selection.requested, selection.focus, owner.converter.binary, owner.converter.sha256, owner.converter.preparation, owner.Closure})
	if err != nil {
		t.Fatal(err)
	}
	originalPath := os.Getenv("PATH")
	guard, err := newCurrentDirectory("enkv-capacity-refusal-command-")
	if err != nil {
		t.Fatal(err)
	}
	guardSettled := false
	t.Cleanup(func() {
		if !guardSettled {
			t.Log("retained refusal command fixture:", guard.path)
			return
		}
		if err := guard.remove(true); err != nil {
			t.Error(err)
		}
	})
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goMarker := filepath.Join(guard.path, "go-started")
	script := "#!/bin/sh\nprintf started > " + shellQuote(goMarker) + "\nexec " + shellQuote(realGo) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(guard.path, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", guard.path+string(os.PathListSeparator)+originalPath)
	process, evidence, _, _ := executeProfileComponentChecks(nil, ctx, root, binary, converter, flags, env, "full", requests, 1, io.Discard, &owner)
	guardSettled = process.Joined && toolCommandsJoined(process.Cause) && sourceCommandsJoined(process.Cause)
	if _, err := os.Stat(goMarker); !errors.Is(err, os.ErrNotExist) {
		t.Error("known capture refusal dispatched a preparation command", err)
	}
	if process.Status != "process_failed" || process.Cause == nil || !strings.Contains(process.Cause.Error(), "capture") || process.Started || !process.Joined || evidence.TestsComplete || len(evidence.Groups) != 0 || len(evidence.Tests) != 0 {
		t.Errorf("shared queue refusal: process=%s started=%t joined=%t tests_complete=%t groups=%d tests=%d cause=%v", process.Status, process.Started, process.Joined, evidence.TestsComplete, len(evidence.Groups), len(evidence.Tests), process.Cause)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Error("a shared component group started before total command capacity was checked", err)
	}
	if evidence.Diagnostics == nil {
		t.Error("shared capacity refusal lost its preparation status", evidence.Diagnostics)
	} else {
		if evidence.Diagnostics.Preparation != "failed" {
			t.Error("shared capacity refusal did not report failed preparation", evidence.Diagnostics.Preparation)
		}
		for _, command := range evidence.Diagnostics.Commands {
			if command.Phase != "preparation" || !command.Started || !command.Joined || command.Process != "passed" {
				t.Error("capacity refusal retained execution rows or incomplete preparation", command)
			}
		}
	}
	afterFacts, factsErr := json.Marshal([]any{selection.evidence, selection.estimates, selection.selected, selection.profile, selection.requested, selection.focus, owner.converter.binary, owner.converter.sha256, owner.converter.preparation, owner.Closure})
	if factsErr != nil || !bytes.Equal(preparedFacts, afterFacts) {
		t.Error("capacity refusal changed complete immutable prepared facts", factsErr)
	}
	if !guardSettled {
		t.Fatal("refusal command owner did not settle before restoring PATH")
	}
	t.Setenv("PATH", originalPath)
	if err := checkAssemblyRace(ctx, owner); err != nil {
		guardSettled = guardSettled && toolCommandsJoined(err) && sourceCommandsJoined(err)
		t.Error("capacity refusal changed the retained compiled owner", err)
	}
	if err := converter.verify(); err != nil {
		t.Error("capacity refusal changed the retained converter", err)
	}
}

// A partial write at a header, module row, or main row is an attempted delivery.
type componentPartialDiagnosticWriter struct {
	bytes.Buffer
	failAt, calls int
	cause         error
}

func (writer *componentPartialDiagnosticWriter) Write(body []byte) (int, error) {
	writer.calls++
	if writer.calls == writer.failAt {
		n := len(body) / 2
		_, _ = writer.Buffer.Write(body[:n])
		return n, writer.cause
	}
	return writer.Buffer.Write(body)
}
