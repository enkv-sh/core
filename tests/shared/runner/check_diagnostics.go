package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// Repeated ordinary checks retain compile, execution and conversion facts per
// package, in addition to module inventory. Component groups retain two rows.
// Keep a finite command bound independent of test/result output bounds.
const maximumCheckCommands = 256

type checkDiagnostics struct {
	Preparation          string              `json:"preparation"`
	Commands             []checkCommandFacts `json:"commands,omitempty"`
	ordinaryCommandLimit int
	ordinaryCommandBytes int
	plannedCommandLimit  int
	planned              bool
	planActive           bool
	held                 diagnosticWeights
	weights              diagnosticWeights
	weightsValid         bool
	attempted            int
	lastAttemptedStatus  string
	headerAttempted      bool
	deliveryFailed       bool
	deliveryError        error
	acquisitions         map[checkAcquisition]struct{}
}

type checkAcquisition struct {
	owner any
	key   string
}

type diagnosticWeights struct{ rows, bytes int }

func (w diagnosticWeights) add(other diagnosticWeights) diagnosticWeights {
	return diagnosticWeights{w.rows + other.rows, w.bytes + other.bytes}
}

func (d *checkDiagnostics) snapshot() *checkDiagnostics {
	if d == nil {
		return nil
	}
	copy := *d
	copy.Commands = slices.Clone(d.Commands)
	copy.ordinaryCommandLimit, copy.ordinaryCommandBytes = 0, 0
	copy.planned, copy.plannedCommandLimit = len(copy.Commands) > maximumCheckCommands, len(copy.Commands)
	copy.planActive, copy.held, copy.weights, copy.weightsValid = false, diagnosticWeights{}, diagnosticWeights{}, false
	copy.attempted, copy.lastAttemptedStatus, copy.headerAttempted = 0, "", false
	copy.deliveryFailed, copy.deliveryError, copy.acquisitions = false, nil, nil
	return &copy
}

type modulePreparationFacts struct {
	Process     string   `json:"process"`
	Started     bool     `json:"started"`
	Joined      bool     `json:"joined"`
	WallSeconds *float64 `json:"wall_seconds,omitempty"`
}

func (facts *modulePreparationFacts) passed() bool {
	return facts == nil || facts.Process == "passed" && facts.Started && facts.Joined
}

type checkCommandFacts struct {
	ModulePreparation *modulePreparationFacts `json:"module_preparation,omitempty"`
	Phase             string                  `json:"phase"`
	Scope             string                  `json:"scope"`
	Process           string                  `json:"process"`
	Started           bool                    `json:"started"`
	Joined            bool                    `json:"joined"`
	WallSeconds       *float64                `json:"wall_seconds,omitempty"`
	Events            string                  `json:"events"`
	ToolCleanup       string                  `json:"tool_cleanup"`
	RequestedNode     string                  `json:"requested_node,omitempty"`
	RaceObservation   string                  `json:"race_observation"`
}

type ordinaryCommandReservation struct {
	scope                      string
	processes, factsPerProcess int
}

func (d *checkDiagnostics) commandLimit() int {
	if d.planned {
		return d.plannedCommandLimit
	}
	if d.ordinaryCommandLimit != 0 {
		return d.ordinaryCommandLimit
	}
	return maximumCheckCommands
}

func (d *checkDiagnostics) reserveOrdinaryCommands(planned []ordinaryCommandReservation) error {
	if d.planActive {
		return errors.New("ordinary execution cannot replace an active diagnostic plan")
	}
	d.planned, d.weightsValid = false, false
	if len(d.Commands) > maximumCheckCommands {
		return errors.New("ordinary preparation command diagnostics exceed their bound")
	}
	used, err := checkCommandBytes(d.Commands)
	if err != nil {
		return err
	}
	remaining := records.MaximumJSONBytes - used - len(`,"commands":[]`)
	if remaining < 0 {
		return errors.New("ordinary command diagnostic bytes exceed their bound")
	}
	processes, commands := 0, len(d.Commands)
	maximumSeconds := math.MaxFloat64
	for _, item := range planned {
		if item.processes < 0 || item.processes > maximumOrdinaryProcesses-processes || item.factsPerProcess < 1 || item.factsPerProcess > 2 {
			return errors.New("ordinary process selection exceeds its bound")
		}
		processes += item.processes
		worst := checkCommandFacts{ModulePreparation: &modulePreparationFacts{Process: "group_stop_failed", WallSeconds: &maximumSeconds},
			Phase: "preparation", Scope: item.scope, Process: "group_stop_failed", WallSeconds: &maximumSeconds,
			Events: "unavailable", ToolCleanup: "retained_unjoined", RequestedNode: "unavailable", RaceObservation: "not_observed"}
		encoded, err := json.Marshal(worst)
		if err != nil {
			return err
		}
		count := item.processes * item.factsPerProcess
		if count > remaining/(len(encoded)+1) {
			return errors.New("ordinary command diagnostic bytes exceed their bound")
		}
		remaining -= count * (len(encoded) + 1)
		commands += count
	}
	d.ordinaryCommandLimit = commands
	d.ordinaryCommandBytes = 0
	return nil
}

func (d *checkDiagnostics) append(command checkCommandFacts) error {
	if len(d.Commands) >= d.commandLimit() {
		return errors.New("check command diagnostics exceed their bound")
	}
	// Ordinary execution keeps its existing incremental byte path. Its future
	// process reservation is separate from a finite preparation activity plan.
	if !d.planned && d.ordinaryCommandLimit != 0 {
		encoded, err := json.Marshal(command)
		if err != nil {
			return err
		}
		used := d.ordinaryCommandBytes
		if used == 0 {
			used, err = checkCommandBytes(d.Commands)
			if err != nil {
				return err
			}
			used += len(`,"commands":[]`)
		}
		if len(encoded)+1 > records.MaximumJSONBytes-used {
			return errors.New("ordinary command diagnostic bytes exceed their bound")
		}
		d.ordinaryCommandBytes = used + len(encoded) + 1
		if d.weightsValid {
			weight, err := diagnosticCommandWeights([]checkCommandFacts{command})
			if err != nil {
				return err
			}
			d.weights = d.weights.add(weight)
		}
	} else {
		weight, err := d.admitCommand(command)
		if err != nil {
			return err
		}
		d.weights = d.weights.add(weight)
	}
	d.Commands = append(d.Commands, command)
	return nil
}

func (d *checkDiagnostics) recordPreparationFailure(cause error) error {
	d.Preparation = "failed"
	if _, shared := cause.(*sharedArtifactFailure); shared {
		return cause
	}
	var failure *toolFailure
	if !errors.As(cause, &failure) || failure.facts == nil {
		return cause
	}
	if failure.factsOwner == d {
		return cause
	}
	facts := *failure.facts
	facts.Phase = "preparation"
	return errors.Join(cause, d.append(facts))
}

func (d *checkDiagnostics) runGo(ctx context.Context, root, directory string, args ...string) ([]byte, error) {
	return d.runGoEnvironment(ctx, root, directory, nil, args...)
}

func (d *checkDiagnostics) runGoEnvironment(ctx context.Context, root, directory string, env []string, args ...string) ([]byte, error) {
	body, _, err := d.runGoRecordedEnvironment(ctx, root, directory, env, args...)
	return body, err
}

func (d *checkDiagnostics) runGoRecordedEnvironment(ctx context.Context, root, directory string, env []string, args ...string) ([]byte, checkCommandFacts, error) {
	if !d.planActive && len(d.Commands) >= maximumCheckCommands {
		return nil, checkCommandFacts{}, errors.New("preparation command diagnostics exceed their bound")
	}
	module := false
	if len(args) != 0 {
		switch args[0] {
		case "build", "test", "list", "vet":
			module = true
		case "mod":
			module = len(args) > 1 && args[1] == "verify"
		}
	}
	worst := preparationReservationFact(directory, module)
	if d.hasPlan() {
		if err := d.consumeCommands([]checkCommandFacts{worst}); err != nil {
			return nil, checkCommandFacts{}, err
		}
	}
	if _, err := d.admitCommand(worst); err != nil {
		return nil, checkCommandFacts{}, err
	}
	body, facts, cause := runGoRecordedEnvironment(ctx, root, directory, env, args...)
	facts.Phase = "preparation"
	finalErr := d.append(facts)
	if finalErr != nil {
		// The command has already been acquired. Preserve its facts even when
		// final admission reports an unexpected mismatch with its forecast.
		d.Commands = append(d.Commands, facts)
		d.weightsValid = false
	}
	var failure *toolFailure
	if errors.As(cause, &failure) {
		failure.factsOwner = d
	}
	if cause != nil || finalErr != nil {
		d.Preparation = "failed"
	}
	return body, facts, errors.Join(cause, finalErr)
}

func (d *checkDiagnostics) prepend(commands []checkCommandFacts) error {
	if len(commands) == 0 {
		return nil
	}
	if d.attempted != 0 {
		return errors.New("cannot prepend commands after diagnostic delivery was attempted")
	}
	if len(commands) > d.commandLimit()-len(d.Commands) {
		return errors.New("repetition command diagnostics exceed their bound")
	}
	merged := append(slices.Clone(commands), d.Commands...)
	weight, err := diagnosticCommandWeights(merged)
	if err != nil {
		return err
	}
	if err := checkDiagnosticBudget(weight.add(d.held), d.commandLimit()); err != nil {
		return err
	}
	if d.ordinaryCommandLimit != 0 && !d.planned {
		used, err := checkCommandBytes(merged)
		if err != nil {
			return err
		}
		d.ordinaryCommandBytes = used
	}
	d.Commands, d.weights, d.weightsValid = merged, weight, true
	return nil
}

func preparationReservationFact(scope string, module bool) checkCommandFacts {
	seconds := math.MaxFloat64
	fact := checkCommandFacts{Phase: "preparation", Scope: scope, Process: "group_stop_failed", WallSeconds: &seconds, Events: "unavailable", ToolCleanup: "retained_unjoined", RequestedNode: "unavailable", RaceObservation: "not_observed"}
	if module {
		fact.ModulePreparation = &modulePreparationFacts{Process: "group_stop_failed", WallSeconds: &seconds}
	}
	return fact
}

func (d *checkDiagnostics) hasAcquisition(owner any, key string) bool {
	_, exists := d.acquisitions[checkAcquisition{owner, key}]
	return exists
}

func (d *checkDiagnostics) retainAcquisition(owner any, key string, source *checkDiagnostics) error {
	if source == nil {
		return nil
	}
	if source == d {
		return errors.New("current diagnostics cannot fork themselves as acquisition")
	}
	if d.hasAcquisition(owner, key) {
		return nil
	}
	if err := d.initializeWeights(); err != nil {
		return err
	}
	weight, err := diagnosticCommandWeights(source.Commands)
	if err != nil {
		return err
	}
	total := d.weights.add(weight).add(d.held)
	if err := checkDiagnosticBudget(total, total.rows); err != nil {
		return err
	}
	d.Commands = append(d.Commands, source.Commands...)
	d.ordinaryCommandBytes = 0
	d.weights = d.weights.add(weight)
	d.planned, d.plannedCommandLimit = d.planActive || total.rows > maximumCheckCommands, total.rows
	if d.acquisitions == nil {
		d.acquisitions = map[checkAcquisition]struct{}{}
	}
	d.acquisitions[checkAcquisition{owner, key}] = struct{}{}
	if source.Preparation == "failed" || d.Preparation != "failed" && source.Preparation == "pending" {
		d.Preparation = source.Preparation
	}
	return nil
}

// A later recovery case can inherit one claim only after its caller has kept
// the previous case's facts in the same invocation's recovery results.
func (d *checkDiagnostics) inheritAcquisitionClaim(owner any, key string, previous *checkDiagnostics) error {
	if previous == nil || !previous.hasAcquisition(owner, key) {
		return errors.New("previous recovery owner has no acquired source claim")
	}
	if d.acquisitions == nil {
		d.acquisitions = map[checkAcquisition]struct{}{}
	}
	d.acquisitions[checkAcquisition{owner, key}] = struct{}{}
	return nil
}

// A plan belongs to the activity until its owner cancels the reservation scope.
// Exhausting its credits never permits a nested helper to start another plan.
func (d *checkDiagnostics) hasPlan() bool { return d.planActive }

func (d *checkDiagnostics) reserveCommands(future []checkCommandFacts) error {
	if err := d.initializeWeights(); err != nil {
		return err
	}
	weight, err := diagnosticCommandWeights(future)
	if err != nil {
		return err
	}
	total := d.weights.add(d.held).add(weight)
	if err := checkDiagnosticBudget(total, total.rows); err != nil {
		return err
	}
	d.planned, d.plannedCommandLimit, d.planActive = true, total.rows, true
	d.held = d.held.add(weight)
	return nil
}

func (d *checkDiagnostics) consumeCommands(future []checkCommandFacts) error {
	if len(future) == 0 {
		return nil
	}
	weight, err := diagnosticCommandWeights(future)
	if err != nil {
		return err
	}
	if !d.planActive || weight.rows > d.held.rows || weight.bytes > d.held.bytes {
		return errors.New("diagnostic command reservation underflow")
	}
	d.held = diagnosticWeights{d.held.rows - weight.rows, d.held.bytes - weight.bytes}
	return nil
}

func (d *checkDiagnostics) cancelReservations() {
	wasActive := d.planActive
	d.held, d.planActive = diagnosticWeights{}, false
	// A closed small activity returns to bounded discovery. A larger retained
	// prefix remains publishable, but it has no authority for another command.
	d.planned = len(d.Commands) > maximumCheckCommands
	d.plannedCommandLimit = len(d.Commands)
	if wasActive {
		// Explicit preparation may have appended while this separate ordinary
		// byte counter was dormant. Reinitialize it once, then stay incremental.
		d.ordinaryCommandBytes = 0
	}
}

func (d *checkDiagnostics) initializeWeights() error {
	if d.weightsValid && d.weights.rows == len(d.Commands) {
		return nil
	}
	weight, err := diagnosticCommandWeights(d.Commands)
	if err != nil {
		return err
	}
	d.weights, d.weightsValid = weight, true
	return nil
}

func (d *checkDiagnostics) admitCommand(command checkCommandFacts) (diagnosticWeights, error) {
	if err := d.initializeWeights(); err != nil {
		return diagnosticWeights{}, err
	}
	weight, err := diagnosticCommandWeights([]checkCommandFacts{command})
	if err != nil {
		return diagnosticWeights{}, err
	}
	if err := checkDiagnosticBudget(d.weights.add(d.held).add(weight), d.commandLimit()); err != nil {
		return diagnosticWeights{}, err
	}
	return weight, nil
}

func diagnosticCommandWeights(commands []checkCommandFacts) (diagnosticWeights, error) {
	var weight diagnosticWeights
	for _, fact := range commands {
		body, err := json.Marshal(fact)
		if err != nil {
			return diagnosticWeights{}, err
		}
		weight.rows++
		weight.bytes += len(body)

	}
	return weight, nil
}

func checkDiagnosticBudget(weight diagnosticWeights, limit int) error {
	if weight.rows > limit {
		return errors.New("check command diagnostics exceed their finite plan")
	}
	commandBytes := weight.bytes + len(`{"preparation":"pending"}`) + 1
	if weight.rows != 0 {
		commandBytes = weight.bytes + len(`{"preparation":"pending","commands":[]}`) + weight.rows
	}
	if commandBytes > records.MaximumJSONBytes {
		return errors.New("diagnostic commands exceed their byte bound")
	}
	return nil
}

func checkCommandBytes(commands []checkCommandFacts) (int, error) {
	body, err := json.Marshal(checkDiagnostics{Preparation: "pending", Commands: commands})
	if err != nil {
		return 0, err
	}
	if len(body)+1 > records.MaximumJSONBytes {
		return 0, errors.New("ordinary command diagnostic bytes exceed their bound")
	}
	return len(body) + 1, nil
}

func commandFacts(phase, scope string, process processResult, elapsed time.Duration) checkCommandFacts {
	seconds := elapsed.Seconds()
	return checkCommandFacts{Phase: phase, Scope: scope, Process: process.Status,
		Started: process.Started, Joined: process.Joined, WallSeconds: &seconds,
		Events: "not_run", ToolCleanup: "not_required", RaceObservation: "unavailable"}
}

func recordTestDispatchFailure(diagnostics *checkDiagnostics, scope, requested string, cause error, elapsed time.Duration) processResult {
	process := processResult{Status: processContextStatus(cause), Joined: true, Cause: cause}
	facts := commandFacts("test", scope, process, elapsed)
	if requested != "" {
		facts.RequestedNode = "unavailable"
	}
	if err := diagnostics.append(facts); err != nil {
		process.Status, process.Cause = "process_failed", errors.Join(process.Cause, err)
	}
	return process
}

func observedRace(joined bool, stdout, stderr []byte) string {
	if !joined {
		return "unavailable"
	}
	if bytes.Contains(stdout, []byte("WARNING: DATA RACE")) || bytes.Contains(stderr, []byte("WARNING: DATA RACE")) {
		return "observed"
	}
	return "not_observed"
}

func checkProgress(output io.Writer, phase, scope string) error {
	if output == nil {
		return nil
	}
	if _, err := fmt.Fprintf(output, "Check phase=%s scope=%s\n", phase, scope); err != nil {
		return errors.Join(errors.New("verification progress output failed"), err)
	}
	return nil
}

func writeCheckDiagnostics(output io.Writer, diagnostics *checkDiagnostics) error {
	if output == nil || diagnostics == nil {
		return nil
	}
	if diagnostics.deliveryFailed {
		return diagnostics.deliveryError
	}
	if len(diagnostics.Commands) > diagnostics.commandLimit() || diagnostics.attempted > len(diagnostics.Commands) {
		return errors.New("check command diagnostics exceed their delivery bound")
	}
	if diagnostics.headerAttempted && diagnostics.attempted == len(diagnostics.Commands) && diagnostics.lastAttemptedStatus == diagnostics.Preparation {
		return nil
	}
	write := func(body string) error {
		n, err := output.Write([]byte(body))
		if err == nil && n != len(body) {
			err = io.ErrShortWrite
		}
		if err != nil {
			diagnostics.deliveryFailed, diagnostics.deliveryError = true, err
		}
		return err
	}
	diagnostics.headerAttempted, diagnostics.lastAttemptedStatus = true, diagnostics.Preparation
	if err := write(fmt.Sprintf("Check preparation=%s; commands=%d\n", diagnostics.Preparation, len(diagnostics.Commands))); err != nil {
		return err
	}
	for index := diagnostics.attempted; index < len(diagnostics.Commands); index++ {
		command := diagnostics.Commands[index]
		diagnostics.attempted = index + 1
		if preparation := command.ModulePreparation; preparation != nil {
			wall := "unknown"
			if preparation.WallSeconds != nil {
				wall = fmt.Sprintf("%.3fs", *preparation.WallSeconds)
			}
			if err := write(fmt.Sprintf("Check phase=module-preparation scope=%s process=%s started=%t joined=%t wall=%s\n", command.Scope, preparation.Process, preparation.Started, preparation.Joined, wall)); err != nil {
				return err
			}
		}
		wall := "unknown"
		if command.WallSeconds != nil {
			wall = fmt.Sprintf("%.3fs", *command.WallSeconds)
		}
		if err := write(fmt.Sprintf("Check phase=%s scope=%s process=%s started=%t joined=%t wall=%s events=%s tool_cleanup=%s race_observation=%s requested_node=%s\n",
			command.Phase, command.Scope, command.Process, command.Started, command.Joined, wall, command.Events, command.ToolCleanup, command.RaceObservation, command.RequestedNode)); err != nil {
			return err
		}
	}
	return nil
}

// The message is closed runner metadata. Unwrap retains all original causes
// for ownership decisions and private diagnostics; it is never a scrubbed copy.
type checkFailure struct {
	phase, diagnostic string
	cause             error
}

func (f *checkFailure) Error() string {
	phase := f.phase
	if phase != "preparation" && phase != "test" && phase != "workflow" && phase != "assembly" {
		phase = "check"
	}
	message := "check failed; phase=" + phase
	switch f.diagnostic {
	case "retained":
		return message + "; diagnostics: retained privately"
	case "path_refused":
		return message + "; private diagnostics path refused"
	case "create_failed":
		return message + "; private diagnostics could not be created"
	case "save_failed":
		return message + "; private diagnostics could not be saved"
	default:
		return message + "; diagnostics: no durable run owner"
	}
}

func (f *checkFailure) Unwrap() error { return f.cause }

// Every required diagnostic save must succeed, including later branches of
// joined failures. A safe public error wrapper does not prove delivery.
func checkDiagnosticsSaved(cause error) bool {
	var saved func(error, int) bool
	saved = func(err error, depth int) bool {
		if err == nil {
			return true
		}
		if depth >= 64 {
			return false
		}
		if failure, ok := err.(*checkFailure); ok && failure.diagnostic != "retained" {
			return false
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapped.Unwrap() {
				if !saved(child, depth+1) {
					return false
				}
			}
		case interface{ Unwrap() error }:
			return saved(wrapped.Unwrap(), depth+1)
		}
		return true
	}
	return saved(cause, 0)
}

func safeCheckFailure(phase, diagnostic string, cause error) error {
	if cause == nil {
		return nil
	}
	return &checkFailure{phase: phase, diagnostic: diagnostic, cause: cause}
}

// Use the existing bounded assembly diagnostic writer and the invocation's
// private directory. No retained record grants cleanup or recovery authority.
func retainCheckFailure(directory, name, phase string, cause error) error {
	if cause == nil {
		return nil
	}
	private, err := records.SafePath(directory, "private")
	if err == nil {
		err = os.MkdirAll(private, 0700)
	}
	if err != nil {
		return safeCheckFailure(phase, "path_refused", errors.Join(cause, err))
	}
	path, err := records.SafePath(directory, filepath.Join("private", name))
	if err != nil || filepath.Base(name) != name || strings.ContainsAny(name, "\\\r\n") {
		return safeCheckFailure(phase, "path_refused", errors.Join(cause, err))
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return safeCheckFailure(phase, "create_failed", errors.Join(cause, err))
	}
	if err := writeAssemblyDiagnostic(file, cause); err != nil {
		return safeCheckFailure(phase, "save_failed", errors.Join(cause, err))
	}
	return safeCheckFailure(phase, "retained", cause)
}

func componentElapsed(test componentTest) (float64, bool) {
	return test.ElapsedSeconds, test.ElapsedObserved == nil || *test.ElapsedObserved
}
