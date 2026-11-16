package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type componentRunRecord struct {
	preparation   *checkDiagnostics
	SchemaVersion int                 `json:"schema_version"`
	RunID         string              `json:"run_id"`
	Source        records.Source      `json:"source"`
	Supervisor    *recordedSupervisor `json:"supervisor,omitempty"`
	Toolchain     string              `json:"toolchain"`
	StartedAt     time.Time           `json:"started_at"`
	FinishedAt    *time.Time          `json:"finished_at,omitempty"`
	Outcome       string              `json:"outcome"`
	BuildClosure  *assemblyClosure    `json:"build_closure,omitempty"`
	Checks        *checkEvidence      `json:"checks,omitempty"`
	Failure       *records.Failure    `json:"failure,omitempty"`
}

// Only a component step in this invocation can supply a prepared assembly.
// Saved records are evidence; they do not authorize reuse of a past result.
type componentRun struct {
	record       componentRunRecord
	assembled    assembly
	privateOwner privateDirectory
	evidencePath string
}

func (value componentRunRecord) passedFor(source records.Source, toolchain string) bool {
	return value.SchemaVersion == records.SchemaVersion && records.ValidRunID(value.RunID) &&
		validSource(value.Source) && sameSource(value.Source, source) && value.Toolchain != "" && value.Toolchain == toolchain &&
		!value.StartedAt.IsZero() && value.FinishedAt != nil && !value.FinishedAt.Before(value.StartedAt) &&
		value.Outcome == "passed" && value.Failure == nil && value.BuildClosure != nil && !value.BuildClosure.raceMissing &&
		value.BuildClosure.Suite == "hermetic" && value.BuildClosure.Provider == "memory" && validRaceSettings(value.BuildClosure.Race, value.BuildClosure.RaceOptions, value.BuildClosure.RaceExitSleepMillis) &&
		value.Checks != nil && !value.Checks.raceMissing && value.Checks.Race == value.BuildClosure.Race && validRaceOptions(value.Checks.Race, value.Checks.RaceOptions) && value.Checks.Selection != "" &&
		(value.Checks.Profile == "dev" || value.Checks.Profile == "full") &&
		value.Checks.Outcome == "passed" && completeComponentEvidence(*value.Checks, "hermetic", "memory")
}

func runComponents(ctx context.Context, root, bootstrap, profile string, requested []string, parallelism int, output io.Writer, group *preparedComponentGroup) (*componentRun, error) {
	return runComponentsOwned(nil, ctx, root, bootstrap, profile, requested, parallelism, output, group)
}
func runComponentsOwned(initial *checkDiagnostics, ctx context.Context, root, bootstrap, profile string, requested []string, parallelism int, output io.Writer, group *preparedComponentGroup) (run *componentRun, err error) {
	if group != nil {
		ctx = useInvocationArtifacts(ctx, group.ctx)
	}
	ctx, owner := withInvocationArtifacts(ctx)
	defer func() {
		tail, cancel := finalizationContext(ctx)
		defer cancel()
		err = errors.Join(err, owner.close(tail, toolCommandsJoined(err)))
	}()
	releaseArtifacts, borrowErr := borrowInvocationArtifacts(ctx)
	if borrowErr != nil {
		return nil, borrowErr
	}
	defer func() { releaseArtifacts(toolCommandsJoined(err)) }()

	parent := ctx
	continuationParent := ctx
	defer func() {
		if err != nil {
			err = errors.Join(err, writeAssemblyDiagnosticBody(output, err))
			var standalone *repetitionBarrier
			if group != nil && group.assembled.componentSelection != nil {
				standalone = &group.assembled.componentSelection.dispatch
			}
			if barrier := repetitionBarrierFromContext(ctx, standalone); barrier != nil && (!containedCheckFailure(parent, err) || continuationParent.Err() != nil) {
				barrier.stopped.Store(true)
			}
		}
	}()
	if group != nil {
		if raceEnabled(ctx) != raceEnabled(group.ctx) {
			return nil, errors.New("component prepared race policy changed")
		}
		var cancel context.CancelFunc
		ctx, cancel = group.duration.executionContext(ctx)
		continuationParent = group.duration.execution
		defer cancel()
	}
	if len(requested) != 0 {
		ctx = cacheOnlyGoContext(ctx)
	}
	profile, err = resolveVerificationProfile(profile)
	if err != nil {
		return nil, err
	}
	binding, err := prepareBindingOwned(nil, ctx, root, false)
	if err != nil {
		return nil, err
	}
	source := binding.source
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	id := hex.EncodeToString(random[:])
	current, err := newCurrentDirectory("enkv-components-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if run == nil {
			err = errors.Join(err, current.remove(true))
		}
	}()
	directory, err := current.createRun(id)
	if err != nil {
		return nil, err
	}
	private, err := createPrivateDirectory("", "hermetic", id, directory)
	if err != nil {
		return nil, err
	}
	private.current = current
	run = &componentRun{privateOwner: private, record: componentRunRecord{
		SchemaVersion: records.SchemaVersion, RunID: id, Source: source, StartedAt: started, Outcome: "incomplete",
		preparation: &checkDiagnostics{Preparation: "pending"},
	}}
	if initial != nil {
		run.record.preparation = initial
	}
	stage := "build"
	printsPreparation := true
	defer func() {
		if err != nil && run.record.Checks == nil {
			err = run.record.preparation.recordPreparationFailure(err)
		}
		if printsPreparation {
			err = errors.Join(err, writeCheckDiagnostics(output, run.record.preparation))
		}
		finished := time.Now().UTC()
		run.record.FinishedAt, run.record.Outcome = &finished, "passed"
		if err != nil {
			run.record.Outcome = "failed"
			run.record.Failure = &records.Failure{Class: "component_step_failed", Stage: stage}
		}
		_, printErr := fmt.Fprintf(output, "Components %s\n", run.record.Outcome)
		err = errors.Join(err, printErr)
		if printErr != nil {
			run.record.Outcome = "failed"
			run.record.Failure = &records.Failure{Class: "component_step_failed", Stage: stage}
		}
	}()
	d := run.record.preparation
	var future []checkCommandFacts
	future = append(future, preparationReservationFact("core", false))
	reused := group != nil && group.assembled.componentSelection != nil
	if reused {
		owner, key := group.assembled.preparationOwner, group.assembled.preparationKey
		if owner == nil {
			owner = group
			key = profile + "\x00" + strings.Join(requested, "\x00")
		}
		if err := d.retainAcquisition(owner, key, group.assembled.componentSelection.evidence.Diagnostics); err != nil {
			return run, err
		}
		future = append(future, preparationReservationFact("core", false))
		entry, e := componentEntryCommands(&group.assembled, group.assembled.converter)
		if e != nil {
			return run, e
		}
		future = append(future, entry...)
	} else {
		construction, e := assemblyConstructionCommands(assemblyBindings{})
		if e != nil {
			return run, e
		}
		if group != nil {
			future = append(future, preparationReservationFact("core", false))
		}
		future = append(future, construction...)
		future = append(future, preparationReservationFact("test2json", true))
		if group != nil {
			future = append(future, preparationReservationFact("core", false))
		}
	}
	if err := d.reserveCommands(future); err != nil {
		return run, err
	}
	defer d.cancelReservations()
	run.record.Toolchain = binding.toolchain
	run.record.preparation.Preparation = "passed"
	build := filepath.Join(private.path, "build")
	if group == nil || group.assembled.Binary == "" {
		if err := os.Mkdir(build, 0700); err != nil {
			return run, err
		}

	}
	if group == nil {
		run.assembled, err = buildAssembly(d.runGoEnvironment, d, ctx, root, "hermetic", "memory", bootstrap, build)
		if err == nil {
			if e := d.consumeCommands([]checkCommandFacts{preparationReservationFact("test2json", true)}); e != nil {
				return run, e
			}
			var facts checkCommandFacts
			run.assembled.converter, facts, err = prepareTestEventConverter(ctx, root, build)
			if facts.Process != "" {
				err = errors.Join(err, d.append(facts))
				run.assembled.converterRecorded = true
			}
		}
	} else {
		run.assembled, err = group.prepareContext(d.runGoEnvironment, d, ctx, root, bootstrap, profile, requested, source, run.record.Toolchain, build)
	}
	if err != nil {
		return run, err
	}
	run.assembled.currentPrefix = d
	if !reused {
		entry, e := componentEntryCommands(&run.assembled, run.assembled.converter)
		if e != nil {
			return run, e
		}
		if e := d.reserveCommands(entry); e != nil {
			return run, e
		}
	}
	run.record.BuildClosure = &run.assembled.Closure
	stage = "checks"
	printsPreparation = false
	checks, err := checkComponents(run.record.preparation, ctx, root, directory, run.assembled.Binary, run.assembled.converter, run.assembled.buildFlags, run.assembled.FailureSources, profile, requested, parallelism, output, &run.assembled)
	run.record.Checks = &checks
	return run, err
}
