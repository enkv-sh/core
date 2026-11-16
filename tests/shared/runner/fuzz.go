package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

const maximumFuzzProgressRecords = 400

const fuzzTarget = "FuzzCanonicalRecords"
const fuzzDuration = 10 * time.Minute
const fuzzTimeout = 15 * time.Minute

type fuzzSpecification struct {
	Name, Module, Package, Target string
}

var fuzzSpecifications = []fuzzSpecification{
	{"format", "core", "./format", fuzzTarget},
	{"contract", "core", "./contract", "FuzzFirstFlowRecords"},
	{"crypto", "crypto", "./internal/custody", "FuzzCustodyOpen"},
}

func fuzzSpecificationFor(module, pkg, target string) (fuzzSpecification, bool) {
	for _, spec := range fuzzSpecifications {
		if spec.Module == module && spec.Package == pkg && spec.Target == target {
			return spec, true
		}
	}
	return fuzzSpecification{}, false
}

func (s fuzzSpecification) importPath() string {
	return modulePath(s.Module) + "/" + strings.TrimPrefix(s.Package, "./")
}

func fuzzCompilerFlags(spec fuzzSpecification, overlay string, race bool) []string {
	flags := []string{"-overlay=" + overlay, "-mod=readonly"}
	if spec.Module == "core" {
		flags = append(flags, "-modfile=../tests/hermetic/hermetic.mod")
	}
	return compilerBuildFlags(flags, race)
}

type fuzzProgress struct {
	ElapsedSeconds uint64 `json:"elapsed_seconds"`
	Executions     uint64 `json:"executions"`
	Interesting    uint64 `json:"new_interesting"`
	CorpusEntries  uint64 `json:"corpus_entries"`
}

type fuzzEvidence struct {
	preparation           *checkDiagnostics
	ModulePreparation     *modulePreparationFacts  `json:"module_preparation,omitempty"`
	Supervisor            *recordedSupervisor      `json:"supervisor,omitempty"`
	Execution             *recordedExecutionPolicy `json:"execution,omitempty"`
	SchemaVersion         int                      `json:"schema_version"`
	RunID                 string                   `json:"run_id"`
	Source                records.Source           `json:"source"`
	Toolchain             string                   `json:"toolchain"`
	GOOS                  string                   `json:"goos"`
	GOARCH                string                   `json:"goarch"`
	Module                string                   `json:"module"`
	Package               string                   `json:"package"`
	Target                string                   `json:"target"`
	Arguments             []string                 `json:"arguments"`
	Native                *checkCommandFacts       `json:"native,omitempty"`
	Conversion            *checkCommandFacts       `json:"conversion,omitempty"`
	TimeoutSeconds        int                      `json:"timeout_seconds"`
	StartedAt             time.Time                `json:"started_at"`
	FinishedAt            *time.Time               `json:"finished_at,omitempty"`
	Outcome               string                   `json:"outcome"`
	Process               string                   `json:"process"`
	Joined                bool                     `json:"joined"`
	ExitCode              *int                     `json:"exit_code,omitempty"`
	SeedCorpusSHA256      string                   `json:"seed_corpus_sha256"`
	GeneratedCorpusSHA256 string                   `json:"generated_corpus_sha256,omitempty"`
	GeneratedCorpusFiles  int                      `json:"generated_corpus_files"`
	BaselineExecutions    uint64                   `json:"baseline_executions"`
	GeneratedExecutions   uint64                   `json:"generated_executions"`
	Closure               *assemblyClosure         `json:"closure,omitempty"`
	Progress              []fuzzProgress           `json:"progress"`
	Failure               *records.Failure         `json:"failure,omitempty"`
}

// The source identity binds built-in seeds. This digest separately binds the
// retained regression corpus; the campaign starts with an empty private cache.
func fuzzCorpusIdentity(directory string) (string, int, error) {
	hash := sha256.New()
	count := 0
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("fuzz corpus file refused")
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		fmt.Fprintf(hash, "%d:%s:%x\n", len(name), filepath.ToSlash(name), sum)
		count++
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(directory); errors.Is(statErr, os.ErrNotExist) {
			err = nil
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), count, err
}

func selectFuzzTargets(names []string) ([]fuzzSpecification, error) {
	if names == nil {
		return slices.Clone(fuzzSpecifications), nil
	}
	if len(names) == 0 {
		return nil, errors.New("fuzz target selection must not be empty")
	}
	var selected []fuzzSpecification
	for i, name := range names {
		index := slices.IndexFunc(fuzzSpecifications, func(spec fuzzSpecification) bool { return spec.Name == name })
		if index < 0 || slices.Contains(names[:i], name) {
			return nil, errors.New("fuzz targets must be known and unique: format, contract, crypto")
		}
		selected = append(selected, fuzzSpecifications[index])
	}
	return selected, nil
}

// Fuzz targets run serially and receive the complete invocation allocation.
// Own requested fields before any preparation can create a stored receipt.
func resolveFuzzExecution(ctx context.Context, supplied executionPolicy) (executionPolicy, error) {
	return executionWithinContext(ctx, supplied)
}

func runFuzz(ctx context.Context, root string, names []string, policy executionPolicy, output io.Writer) (results []*fuzzEvidence, err error) {
	prepared, _ := ctx.Value(preparedFuzzContextKey{}).(*preparedFuzz)
	if prepared == nil {
		prepared, err = prepareFuzz(nil, ctx, root, names, policy, output)
		if prepared != nil {
			defer func() {
				tail, cancel := finalizationContext(ctx)
				defer cancel()
				err = errors.Join(err, prepared.close(tail))
			}()
		}
		if err != nil {
			return results, err
		}
		return runPreparedFuzz(ctx, root, prepared, output)
	}
	if err := prepared.verify(ctx, root); err != nil {
		return results, err
	}

	if err := ctx.Err(); err != nil {
		return results, err
	}
	policy, err = resolveFuzzExecution(ctx, policy)
	if err != nil {
		return results, err
	}
	selected, err := selectFuzzTargets(names)
	if err != nil {
		return results, err
	}
	source := prepared.binding.source
	for index, spec := range selected {
		record, runErr := runFuzzTarget(ctx, root, spec, source, policy, output)
		if record != nil {
			if index == 0 {
				record.preparation = prepared.preparation.snapshot()
				runErr = errors.Join(runErr, writeCheckDiagnostics(output, record.preparation))
			}
			results = append(results, record)
		}
		if runErr != nil {
			return results, runErr
		}
	}
	return results, nil
}

func runFuzzTarget(ctx context.Context, root string, spec fuzzSpecification, source records.Source, policy executionPolicy, output io.Writer) (record *fuzzEvidence, err error) {
	ctx, artifactOwner := withInvocationArtifacts(ctx)
	if artifactOwner != nil {
		defer func() {
			err = errors.Join(err, artifactOwner.close(ctx, toolCommandsJoined(err) && (record == nil || record.Process == "not_started" || record.Joined)))
		}()
	}
	policy, err = resolveFuzzExecution(ctx, policy)
	if err != nil {
		return record, err
	}
	var binding preparationBinding
	if prepared, _ := ctx.Value(preparedFuzzContextKey{}).(*preparedFuzz); prepared != nil {
		binding = prepared.binding
	} else {
		binding, err = prepareBindingOwned(nil, ctx, root, false)
		if err != nil {
			return record, err
		}
	}
	var identity [8]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return record, errors.New("fuzz identity unavailable")
	}
	started := time.Now()
	id := started.UTC().Format("20060102T150405Z-") + hex.EncodeToString(identity[:])
	currentFiles, err := newCurrentDirectory("enkv-fuzz-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, writeAssemblyDiagnosticBody(output, err))
		}
		joined := toolCommandsJoined(err) && (record == nil || (record.Process == "not_started" || record.Joined) && (record.ModulePreparation == nil || record.ModulePreparation.Joined))
		err = errors.Join(err, currentFiles.remove(joined))
		if record != nil {
			if err != nil {
				record.Outcome = "failed"
			}
			_, printErr := fmt.Fprintf(output, "Fuzz campaign %s\n", record.Outcome)
			err = errors.Join(err, printErr)
			if printErr != nil {
				record.Outcome = "failed"
			}
		}
	}()
	directory, err := currentFiles.createRun(id)
	if err != nil {
		return nil, err
	}
	private, err := createPrivateDirectory("", "hermetic", id, directory)
	if err != nil {
		return nil, err
	}
	recordedPolicy := recordExecutionPolicy(policy)
	record = &fuzzEvidence{Execution: &recordedPolicy, SchemaVersion: records.SchemaVersion, RunID: id, Source: source, Toolchain: binding.toolchain, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Module: spec.Module, Package: spec.Package, Target: spec.Target, Arguments: fuzzRuntimeArguments(spec, filepath.Join(private.path, "cache"), executionCapacityFromContext(ctx).Parallel), TimeoutSeconds: int(fuzzTimeout / time.Second), StartedAt: started, Outcome: "incomplete", Process: "not_started", Progress: []fuzzProgress{}}
	stage := "dependencies"
	defer func() {
		finished := time.Now()
		record.FinishedAt = &finished
		if err != nil {
			record.Outcome = "failed"
			record.Failure = &records.Failure{Class: "fuzz_campaign_failed", Stage: stage}
		}
	}()
	artifact, err := prepareFuzzArtifact(ctx, root, private.path, spec, nil)
	if err != nil {
		return record, err
	}
	record.Closure, record.SeedCorpusSHA256 = &artifact.closure, artifact.seedDigests[spec.Target]
	if record.SeedCorpusSHA256 == "" {
		return record, errors.New("actual fuzz target was not prepared")
	}
	if prepared, _ := ctx.Value(preparedFuzzContextKey{}).(*preparedFuzz); prepared != nil {
		if err := prepared.verify(ctx, root); err != nil {
			return record, err
		}
	}
	cache := filepath.Join(private.path, "cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		return record, err
	}
	if _, err := os.Stat(artifact.corpus); err == nil {
		if err := os.CopyFS(filepath.Join(private.path, "testdata/fuzz"), os.DirFS(artifact.corpus)); err != nil {
			return record, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return record, err
	}
	stage = "campaign"
	command := exec.Command(artifact.executable.binary, record.Arguments...)
	command.Dir, command.Env = private.path, invocationGoEnvironment(ctx)
	if err := executeFuzz(ctx, command, artifact.converter, fuzzTimeout, private.path, record); err != nil {
		return record, err
	}
	stage = "corpus"
	record.GeneratedCorpusSHA256, record.GeneratedCorpusFiles, err = fuzzCorpusIdentity(filepath.Join(cache, "fuzz", spec.importPath(), spec.Target))
	if err != nil {
		return record, err
	}
	record.Outcome = "passed"
	return record, nil
}

func executeFuzz(parent context.Context, command *exec.Cmd, converter preparedTestEventConverter, timeout time.Duration, private string, record *fuzzEvidence) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var stdout, stderr limitedOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	started := time.Now()
	process := superviseProcess(ctx, command)
	native := commandFacts("test", record.Module+"/"+strings.TrimPrefix(record.Package, "./"), process, time.Since(started))
	if process.Joined {
		native.RaceObservation = observedRace(true, stdout.Bytes(), stderr.Bytes())
	}
	record.Native = &native
	record.Process, record.Joined = process.Status, process.Joined
	if !process.Joined {
		return errors.New("fuzz process group did not settle")
	}
	if command.ProcessState != nil {
		code := command.ProcessState.ExitCode()
		record.ExitCode = &code
	}
	diagnostic := fmt.Sprintf("Process: %s\nJoined: %t\nCause: %v\nStdout (truncated: %t):\n%s\nStderr (truncated: %t):\n%s", process.Status, process.Joined, process.Cause, stdout.overflow, stdout.Bytes(), stderr.overflow, stderr.Bytes())
	if err := os.WriteFile(filepath.Join(private, "fuzz.log"), []byte(diagnostic), 0600); err != nil {
		return safeCheckFailure("test", "save_failed", err)
	}
	spec, known := fuzzSpecificationFor(record.Module, record.Package, record.Target)
	if !known {
		return errors.New("fuzz target owner refused")
	}
	events, conversionError := &limitedOutput{}, &limitedOutput{}
	conversion := exec.Command(converter.binary, "-t", "-p", spec.importPath())
	conversion.Dir, conversion.Env = private, command.Env
	conversion.Stdin, conversion.Stdout, conversion.Stderr = bytes.NewReader(stdout.Bytes()), events, conversionError
	conversionStarted := time.Now()
	converted := superviseTestEventConversion(ctx, conversion)
	facts := commandFacts("conversion", spec.importPath(), converted, time.Since(conversionStarted))
	record.Conversion = &facts
	if converted.Status != "passed" || !converted.Joined || events.overflow || conversionError.overflow {
		failure := &toolFailure{operation: "fuzz result conversion", process: converted, facts: &facts}
		if converted.Joined {
			failure.stdout, failure.stderr = events.Bytes(), conversionError.Bytes()
		}
		return failure
	}
	progress, parseErr := parseFuzzProgress(events.Bytes(), spec)
	record.Progress = progress
	baseline, generated, countErr := fuzzExecutionCounts(progress)
	if countErr == nil {
		record.BaselineExecutions, record.GeneratedExecutions = baseline, generated
	}
	if process.Status != "passed" || record.ExitCode == nil || *record.ExitCode != 0 {
		return errors.New("fuzz process failed; see private diagnostics")
	}
	if stdout.overflow || stderr.overflow {
		return errors.New("fuzz output exceeds its bound")
	}
	if parseErr != nil {
		return parseErr
	}
	if countErr != nil || progress[len(progress)-1].ElapsedSeconds < uint64(fuzzDuration/time.Second) || generated == 0 {
		return errors.New("complete generated-input campaign evidence missing")
	}
	return nil
}

var fuzzProgressLine = regexp.MustCompile(`^fuzz: elapsed: ([0-9]+(?:m[0-9]+)?)s, execs: ([0-9]+) \([^\n]*\), new interesting: ([0-9]+) \(total: ([0-9]+)\)\n$`)

func parseFuzzProgress(body []byte, spec fuzzSpecification) ([]fuzzProgress, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	progress := []fuzzProgress{}
	passed := false
	for {
		var event struct{ Action, Package, Test, Output string }
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return progress, errors.New("fuzz output record invalid")
		}
		if event.Package != spec.importPath() {
			continue
		}
		if event.Action == "pass" && event.Test == spec.Target {
			passed = true
		}
		if event.Action != "output" || event.Test != spec.Target {
			continue
		}
		match := fuzzProgressLine.FindStringSubmatch(event.Output)
		if match == nil {
			continue
		}
		duration, err := time.ParseDuration(match[1] + "s")
		if err != nil {
			return progress, errors.New("fuzz elapsed evidence invalid")
		}
		p := fuzzProgress{ElapsedSeconds: uint64(duration / time.Second)}
		for i, value := range []*uint64{&p.Executions, &p.Interesting, &p.CorpusEntries} {
			parsed, err := strconv.ParseUint(match[i+2], 10, 64)
			if err != nil {
				return progress, errors.New("fuzz count evidence invalid")
			}
			*value = parsed
		}
		if len(progress) >= maximumFuzzProgressRecords {
			return progress, errors.New("fuzz progress evidence invalid")
		}
		progress = append(progress, p)
	}
	if !passed {
		return progress, errors.New("fuzz target pass evidence missing")
	}
	_, _, err := fuzzExecutionCounts(progress)
	return progress, err
}

// Go's execution total includes one replay per baseline corpus entry. New
// interesting entries extend the corpus without changing that baseline.
func fuzzExecutionCounts(progress []fuzzProgress) (baseline, generated uint64, err error) {
	if len(progress) == 0 || len(progress) > maximumFuzzProgressRecords {
		return 0, 0, errors.New("fuzz progress evidence invalid")
	}
	for i, sample := range progress {
		if sample.Interesting >= sample.CorpusEntries {
			return 0, 0, errors.New("fuzz baseline evidence invalid")
		}
		currentBaseline := sample.CorpusEntries - sample.Interesting
		if sample.Executions < currentBaseline || sample.Interesting > sample.Executions-currentBaseline {
			return 0, 0, errors.New("fuzz generated count evidence invalid")
		}
		if i > 0 && (currentBaseline != baseline || sample.ElapsedSeconds < progress[i-1].ElapsedSeconds || sample.Executions < progress[i-1].Executions || sample.Interesting < progress[i-1].Interesting) {
			return 0, 0, errors.New("fuzz progress evidence invalid")
		}
		baseline, generated = currentBaseline, sample.Executions-currentBaseline
	}
	return baseline, generated, nil
}

// Historical records predate invocation policy and used exactly two workers.
// A present field is current evidence and must be complete, closed and valid.
