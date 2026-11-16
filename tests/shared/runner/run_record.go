package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"time"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

type runRecord struct {
	historicalLimits      *recordedCleanupLimits
	ExecutionSource       *records.Source           `json:"execution_source,omitempty"`
	ExportFilesStatus     string                    `json:"export_files_status,omitempty"`
	Supervisor            *recordedSupervisor       `json:"supervisor,omitempty"`
	Execution             recordedExecutionPolicy   `json:"execution"`
	Profile               string                    `json:"profile"`
	CoverageScope         string                    `json:"coverage_scope"`
	ScenarioCoverage      bool                      `json:"scenario_coverage"`
	SchemaVersion         int                       `json:"schema_version"`
	RunID                 string                    `json:"run_id"`
	Native                nativeTuple               `json:"native"`
	Suite                 string                    `json:"suite"`
	Provider              string                    `json:"provider"`
	Target                string                    `json:"target"`
	StartedAt             time.Time                 `json:"started_at"`
	FinishedAt            *time.Time                `json:"finished_at,omitempty"`
	Outcome               string                    `json:"outcome"`
	Source                records.Source            `json:"source"`
	Toolchain             string                    `json:"toolchain"`
	Schedule              catalog.Schedule          `json:"schedule"`
	RepetitionGroups      []scenarioRepetitionGroup `json:"repetition_groups,omitempty"`
	Resolved              *resolvedRequest          `json:"resolved_request,omitempty"`
	ActorIdentities       *actorIdentityEvidence    `json:"actor_identities,omitempty"`
	FullCoverage          bool                      `json:"full_coverage"`
	Scenarios             []scenarioResult          `json:"scenarios"`
	CaseReceipts          []caseReceiptRef          `json:"case_receipts,omitempty"`
	Correctness           correctnessEvidence       `json:"correctness"`
	Cleanup               records.Cleanup           `json:"cleanup"`
	Telemetry             records.Telemetry         `json:"telemetry"`
	EffectiveTelemetry    *effectiveTelemetry       `json:"effective_telemetry,omitempty"`
	Diagnostics           records.Diagnostics       `json:"diagnostics"`
	BuildClosure          *assemblyClosure          `json:"build_closure,omitempty"`
	Context               *runContext               `json:"context,omitempty"`
	Limits                *limits                   `json:"limits,omitempty"`
	RecoveryRunID         string                    `json:"recovery_run_id,omitempty"`
	ContinuationRootRunID string                    `json:"continuation_root_run_id,omitempty"`
	CleanupRecoveryBasis  *cleanupRecoveryBasis     `json:"cleanup_recovery_basis,omitempty"`
	Failure               *records.Failure          `json:"failure,omitempty"`
}

func (record runRecord) MarshalJSON() ([]byte, error) {
	type plainRunRecord runRecord
	body, err := json.Marshal(plainRunRecord(record))
	if err != nil {
		return nil, err
	}
	return restoreCleanupLimits(body, record.Limits, record.historicalLimits)
}

type correctnessEvidence struct {
	Passed           bool                `json:"passed"`
	EvidenceComplete bool                `json:"evidence_complete"`
	ComponentRun     *componentRunRecord `json:"component_run,omitempty"`
}

type scenarioResult struct {
	StockPluginEvidence         *records.StockPluginEvidenceRef         `json:"stock_plugin_evidence,omitempty"`
	StockPluginRecovery         *records.StockPluginRecoveryEvidence    `json:"stock_plugin_recovery,omitempty"`
	PublicConfigurationEvidence *records.PublicConfigurationEvidenceRef `json:"public_configuration_evidence,omitempty"`
	OutputScheduled             uint32                                  `json:"output_scheduled,omitempty"`
	OutputsSHA256               string                                  `json:"outputs_sha256,omitempty"`
	Reconstruction              []configurationRecoveryEvidence         `json:"reconstruction,omitempty"`
	catalog.Entry
	Title               string                     `json:"title,omitempty"`
	CorrectnessPassed   bool                       `json:"correctness_passed"`
	Fixture             catalog.Shape              `json:"fixture"`
	Outcome             string                     `json:"outcome"`
	Failure             *records.Failure           `json:"failure,omitempty"`
	Writer              *workerEvidence            `json:"writer,omitempty"`
	FirstFailure        *records.Failure           `json:"first_failure,omitempty"`
	Rerun               *workerEvidence            `json:"same_domain_rerun,omitempty"`
	Children            []workerEvidence           `json:"children"`
	PostExit            []workerEvidence           `json:"post_exit_reopens"`
	Cleanup             records.Cleanup            `json:"cleanup"`
	CleanupWorker       *workerEvidence            `json:"cleanup_worker,omitempty"`
	CleanupAttempts     []cleanupAttemptEvidence   `json:"cleanup_attempts,omitempty"`
	CleanupRetryBlocker string                     `json:"cleanup_retry_blocker,omitempty"`
	BudgetReserved      *records.BudgetReservation `json:"budget_reserved,omitempty"`
	WorkloadElapsed     time.Duration              `json:"workload_elapsed_nanos"`
	CleanupElapsed      time.Duration              `json:"cleanup_elapsed_nanos"`
}

// Cleanup attempts are public receipts, not authority to retry. Exact target
// identity and the conditional delete token stay in the private inventory.
type cleanupAttemptEvidence struct {
	Ordinal     uint8           `json:"ordinal"`
	Decision    string          `json:"decision"`
	TargetIndex *uint32         `json:"target_index,omitempty"`
	Worker      *workerEvidence `json:"worker,omitempty"`
	Cleanup     records.Cleanup `json:"cleanup"`
	Elapsed     time.Duration   `json:"elapsed_nanos"`
}

// Public evidence contains no input paths, facts, cloud identifiers or error text.
type workerEvidence struct {
	Race             *bool                             `json:"race,omitempty"`
	ExportFiles      []retainedTelemetryFile           `json:"export_files,omitempty"`
	Assertions       *records.AssertionEvidence        `json:"assertions,omitempty"`
	RaceOptions      string                            `json:"race_options,omitempty"`
	RecoveryMode     string                            `json:"recovery_mode,omitempty"`
	Worker           string                            `json:"worker"`
	Role             string                            `json:"role"`
	Actor            string                            `json:"actor,omitempty"`
	Outcome          string                            `json:"outcome"`
	Process          string                            `json:"process"`
	Started          bool                              `json:"started,omitempty"`
	Joined           bool                              `json:"joined"`
	MemoryPeakBytes  uint64                            `json:"memory_peak_bytes,omitempty"`
	MemoryLimitBytes uint64                            `json:"memory_limit_bytes,omitempty"`
	Phases           []records.PhaseResult             `json:"phases"`
	Telemetry        records.Telemetry                 `json:"telemetry"`
	Diagnostics      records.Diagnostics               `json:"diagnostics"`
	Deliveries       map[string]records.DeliveryStatus `json:"deliveries,omitempty"`
	SDKCallbacks     uint64                            `json:"sdk_callbacks,omitempty"`
	Failure          *records.Failure                  `json:"failure,omitempty"`
	StoreFailure     *records.StoreFailure             `json:"store_failure,omitempty"`
	HarnessFailure   *records.HarnessFailure           `json:"harness_failure,omitempty"`
}

type runContext struct {
	Region              string            `json:"region"`
	CredentialRoute     string            `json:"credential_route"`
	ConfigurationSHA256 string            `json:"configuration_sha256"`
	ResourceHashes      map[string]string `json:"resource_hashes"`
}

func safeRunContext(settings liveSettings) *runContext {
	body, _ := json.Marshal(resourceIdentity(settings))
	value := &runContext{Region: settings["region"], CredentialRoute: "service_account_file", ConfigurationSHA256: digestBytes(body), ResourceHashes: map[string]string{}}
	if settings["provider"] == "aws" {
		value.CredentialRoute = "shared_credentials_file"
	}
	if settings["sdk_mode"] == "aws-sso" {
		value.CredentialRoute = "aws_sso"
	} else if settings["sdk_mode"] == "gcp-user-adc" {
		value.CredentialRoute = "gcp_user_adc"
	} else if settings["sdk_mode"] == "aws-assume-role" {
		value.CredentialRoute = "aws_assume_role"
	} else if settings["sdk_mode"] == "aws-shared-credentials" {
		value.CredentialRoute = "aws_shared_credentials"
	} else if settings["sdk_mode"] == "gcp-service-account-adc" {
		value.CredentialRoute = "gcp_service_account_adc"
	} else if settings["sdk_mode"] == "gcp-impersonated-adc" {
		value.CredentialRoute = "gcp_impersonated_adc"
	}
	for _, key := range publicResourceFields {
		if input, present := settings[key]; present {
			value.ResourceHashes[key] = digestBytes([]byte(input))
		}
	}
	return value
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type runState struct {
	workerRecords            map[string]bool
	preparation              *checkDiagnostics
	reconstructionReserved   bool
	preparationFolded        bool
	current                  *currentDirectory
	recovery                 *liveRecovery
	exportFilesError         error
	evidenceDirectories      map[string]os.FileInfo
	publicConfigurationFiles map[string]retainedPublicConfigurationFile
	publicationProfiles      []selectedOutputProfile
	publicationBuild         string
	recoverySetup            *assembly
	recoveryArtifacts        map[string]configurationRecoveryArtifact
	failureSources           *records.FailureSourceBinding
	root, directory, private string
	record                   runRecord
	snapshots                [][]records.Snapshot
	diagnostics              []records.Diagnostics
	telemetryIncomplete      bool
	privateOwner             privateDirectory
	actorSettings            map[string]liveSettings
	generator                *generatorReference
	publicConfiguration      *publicConfigurationArtifact
	stockPlugins             *records.StockPluginAcceptanceInput
	publicOutputs            *records.PublicOutputScopes
	telemetrySettings        *observability.Resolved
}

func (s *runState) hermeticCaseState(result scenarioResult) *runState {
	return &runState{
		root: s.root, directory: s.directory, private: s.private,
		recoverySetup: s.recoverySetup, recoveryArtifacts: s.recoveryArtifacts,
		failureSources: s.failureSources, telemetrySettings: s.telemetrySettings,
		actorSettings: s.actorSettings, generator: s.generator,
		publicConfiguration: s.publicConfiguration, publicOutputs: s.publicOutputs,
		publicationProfiles: s.publicationProfiles, publicationBuild: s.publicationBuild,
		record: runRecord{
			Execution: s.record.Execution, Profile: s.record.Profile, SchemaVersion: s.record.SchemaVersion,
			RunID: s.record.RunID, Native: s.record.Native, Suite: s.record.Suite,
			Provider: s.record.Provider, Target: s.record.Target, StartedAt: s.record.StartedAt,
			Source: s.record.Source, Toolchain: s.record.Toolchain, Schedule: s.record.Schedule,
			Resolved: s.record.Resolved, BuildClosure: s.record.BuildClosure,
			Outcome: "incomplete", Scenarios: []scenarioResult{result}, Cleanup: noCleanup(),
			Telemetry:   records.Telemetry{Enabled: s.record.Telemetry.Enabled},
			Diagnostics: records.Diagnostics{Enabled: s.record.Diagnostics.Enabled},
		},
	}
}

func scenarioNotRun(result scenarioResult) bool {
	return result.Outcome == "not_run" && !result.CorrectnessPassed && result.Failure == nil && result.FirstFailure == nil &&
		result.Writer == nil && result.Rerun == nil && len(result.Children) == 0 && len(result.PostExit) == 0 &&
		len(result.Reconstruction) == 0 && result.CleanupWorker == nil && len(result.CleanupAttempts) == 0 &&
		result.Cleanup == noCleanup() && result.CleanupRetryBlocker == "" && result.BudgetReserved == nil &&
		result.WorkloadElapsed == 0 && result.CleanupElapsed == 0 && result.OutputScheduled == 0 &&
		result.OutputsSHA256 == "" && result.PublicConfigurationEvidence == nil && result.StockPluginEvidence == nil && result.StockPluginRecovery == nil
}

func newRunState(root string, request runRequest, source records.Source, toolchain string) (state *runState, retErr error) {
	policy, err := resolveExecution(request.execution.Requested, executionRequest{})
	if err != nil {
		return nil, err
	}
	runtimeResolved := request.execution.Resolved
	if runtimeResolved != (executionCapacity{}) {
		if err := validateExecutionCapacity(runtimeResolved); err != nil {
			return nil, err
		}
		maximum := executionForClass(policy, true).Resolved
		if runtimeResolved.Parallel > maximum.Parallel || runtimeResolved.MemoryLimitMiB > maximum.MemoryLimitMiB {
			return nil, errors.New("run capacity exceeds its invocation allowance")
		}
		policy.Resolved = runtimeResolved
	}
	request.execution = policy
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errors.New("run identity unavailable")
	}
	id := hex.EncodeToString(random[:])
	started := time.Now()
	var directory string
	var current *currentDirectory
	defer func() {
		if state == nil && current != nil {
			retErr = errors.Join(retErr, current.remove(true))
		}
	}()
	var recovery *liveRecovery
	ownerRoot := root
	if request.Suite == "live" {
		directory, err = createRunDirectory(root, "live", id, started)
		if err == nil {
			identity, statErr := os.Lstat(directory)
			if statErr != nil {
				return nil, statErr
			}
			recovery = &liveRecovery{directory: directory, owner: currentDirectory{path: directory, identity: identity}}
		}
	} else {
		current, err = newCurrentDirectory("enkv-run-")
		if err == nil {
			directory, err = current.createRun(id)
		}
		ownerRoot = ""
	}
	if err != nil {
		return nil, err
	}
	private, err := createPrivateDirectory(ownerRoot, request.Suite, id, directory)
	if err != nil {
		return nil, errors.New("private run directory unavailable")
	}
	settings := request.telemetrySettings
	if settings == nil {
		defaults, err := observability.Resolve(observability.Config{SchemaVersion: 1}, observability.Options{})
		if err != nil {
			return nil, err
		}
		settings = &defaults
	}
	copy := settings.Clone()
	settings = &copy
	summary := summarizeTelemetry(*settings, observability.Options{})
	if request.effectiveTelemetry != nil {
		summary.ConfigurationSource = request.effectiveTelemetry.ConfigurationSource
		summary.LevelOverrideSource = request.effectiveTelemetry.LevelOverrideSource
	}
	enabled := len(settings.MetricExporters) != 0
	status := "disabled"
	if enabled {
		status = "incomplete"
	}
	diagnosticsEnabled := settings.LogLevel != observability.Off && (settings.Console || len(settings.LogExporters) != 0)
	diagnosticStatus := "disabled"
	if diagnosticsEnabled {
		diagnosticStatus = "incomplete"
	}
	return &runState{root: root, directory: directory, current: current, recovery: recovery, private: private.path, privateOwner: private, telemetrySettings: settings,
		record: runRecord{
			Execution: recordExecutionPolicy(request.execution), Profile: request.Profile, SchemaVersion: records.SchemaVersion, RunID: id, Native: nativeTuple{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, Suite: request.Suite, Provider: request.Provider,
			Target: request.Target, StartedAt: started.UTC(), Outcome: "incomplete", Source: source, ContinuationRootRunID: request.workflowRunID,
			Toolchain: toolchain, Schedule: request.Schedule, Resolved: request.Resolved, Scenarios: []scenarioResult{}, Cleanup: unresolvedCleanup(),
			Telemetry:          records.Telemetry{Enabled: enabled, Status: status, Definitions: telemetry.Definitions()},
			EffectiveTelemetry: summary,
			Diagnostics:        records.Diagnostics{Enabled: diagnosticsEnabled, Status: diagnosticStatus},
		}}, nil
}

func runPath(root, suite, kind, id string) (string, error) {
	if suite != "hermetic" && suite != "live" || kind != "runs" && kind != "reports" || !records.ValidRunID(id) {
		return "", errors.New("run lookup refused")
	}
	owner, err := records.SafePath(root, filepath.Join("tests", suite, kind))
	if err != nil {
		return "", errors.New("run lookup refused")
	}
	path, err := records.ResolveRun(owner, id)
	if errors.Is(err, os.ErrNotExist) {
		// Retained flat fixtures and pre-migration records remain readable.
		// Creation of real outputs uses newRunPath instead.
		return records.SafePath(owner, id)
	}
	return path, err
}

func newRunPath(root, suite, id string, started time.Time) (string, error) {
	if suite != "hermetic" && suite != "live" {
		return "", errors.New("run directory refused")
	}
	relative, err := records.RunRelative(id, started)
	if err != nil {
		return "", err
	}
	return records.SafePath(root, filepath.Join("tests", suite, "runs", relative))
}

func createRunDirectory(root, suite, id string, started time.Time) (string, error) {
	directory, err := newRunPath(root, suite, id, started)
	if err != nil {
		return "", err
	}
	for _, path := range []string{filepath.Dir(filepath.Dir(directory)), filepath.Dir(directory)} {
		if _, err := records.SafePath(path, "private"); err != nil || os.MkdirAll(path, 0700) != nil || os.Chmod(path, 0700) != nil {
			return "", errors.New("run parent directory unavailable")
		}
	}
	if os.Mkdir(directory, 0700) != nil {
		return "", errors.New("run directory unavailable")
	}
	return directory, nil
}

func (s *runState) save() error {
	groups, err := scenarioRepetitionGroups(s.record)
	if err != nil {
		return err
	}
	s.record.RepetitionGroups = groups
	_, measurement := combineTelemetry(s.record.Telemetry.Enabled, s.snapshots...)
	if measurement.Enabled {
		if s.telemetryIncomplete {
			measurement.Status, measurement.FailureClass = "incomplete", "worker_evidence_incomplete"
		}

	}
	s.record.Telemetry = measurement
	s.record.Diagnostics = combineDiagnostics(s.record.Diagnostics.Enabled, s.diagnostics)
	if s.recovery != nil {
		return s.recovery.save(s.record)
	}
	return nil
}

func combineDiagnostics(enabled bool, workers []records.Diagnostics) records.Diagnostics {
	combined := records.Diagnostics{Enabled: enabled, Status: "disabled"}
	if !enabled {
		return combined
	}
	combined.Status = "incomplete"
	if len(workers) != 0 {
		combined.Status = "complete"
	}
	for _, worker := range workers {
		combined.Accepted += worker.Accepted
		combined.Written += worker.Written
		combined.DroppedContention += worker.DroppedContention
		combined.DroppedFull += worker.DroppedFull
		combined.DroppedClosed += worker.DroppedClosed
		combined.DroppedWriter += worker.DroppedWriter
		combined.Rejected += worker.Rejected
		if worker.Status != "complete" {
			combined.Status = "partial"
			if combined.FailureClass == "" {
				combined.FailureClass = worker.FailureClass
			}
		}
	}
	return combined
}

func (s *runState) fail(class, stage string) {
	if s.record.Failure == nil {
		s.record.Failure = &records.Failure{Class: class, Stage: stage}
	}
	s.record.Outcome = "failed"
}

func unresolvedCleanup() records.Cleanup {
	return records.Cleanup{Outcome: "unresolved", Failure: &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}}
}

func noCleanup() records.Cleanup { return records.Cleanup{Outcome: "not_applicable"} }

func cleanupPassed(value records.Cleanup) bool {
	return value.Outcome == "passed" && value.RemainingOwnedObjects != nil && *value.RemainingOwnedObjects == 0 && value.UnknownEffects != nil && *value.UnknownEffects == 0
}

func fullCoverage(value runRecord) bool {
	return completeScenarioCoverage(value, true)
}

// selectedLiveCoverage proves every entry in one saved live-cell selection.
// It does not claim that the selection covers the whole regression catalog.
func selectedLiveCoverage(value runRecord) bool {
	return value.Suite == "live" && completeScenarioCoverage(value, false)
}

func completeScenarioCoverage(value runRecord, requireRegression bool) bool {
	if value.Profile != "full" || value.CoverageScope != value.Suite+"_scenarios" || requireRegression && !value.FullCoverage || value.RecoveryRunID != "" || value.Failure != nil || !value.Correctness.Passed || !value.Correctness.EvidenceComplete || value.Outcome != "passed" {
		return false
	}
	if !validCleanupHistory(value) || validateScenarioRepetitionGroups(value) != nil {
		return false
	}
	if !validSource(value.Source) || value.StartedAt.IsZero() || value.FinishedAt == nil || value.FinishedAt.Before(value.StartedAt) || value.Toolchain == "" || value.BuildClosure == nil || value.BuildClosure.raceMissing || !validRaceSettings(value.BuildClosure.Race, value.BuildClosure.RaceOptions, value.BuildClosure.RaceExitSleepMillis) || value.BuildClosure.Suite != value.Suite || value.BuildClosure.Provider != value.Provider || value.Cleanup.Failure != nil {
		return false
	}
	var checks *checkEvidence
	switch value.Suite {
	case "hermetic":
		components := value.Correctness.ComponentRun
		if components == nil || !components.passedFor(value.Source, value.Toolchain) || components.FinishedAt.After(value.StartedAt) || value.Provider != "memory" || value.Cleanup.Outcome != "not_applicable" {
			return false
		}
		checks = components.Checks
	case "live":
		checks = value.BuildClosure.LocalChecks
		if value.Provider != "gcp" && value.Provider != "aws" || !runCleanupPassed(value) || checks == nil || checks.Outcome != "passed" || checks.Selection == "" || !hexString(value.BuildClosure.BinarySHA256, sha256HexLength) || !hexString(value.BuildClosure.OverlaySHA256, sha256HexLength) {
			return false
		}
	default:
		return false
	}
	if value.Resolved == nil || value.Resolved.raceMissing || value.Resolved.Profile != "full" || value.Resolved.Race != value.BuildClosure.Race || checks.Profile != "full" || checks.raceMissing || checks.Race != value.BuildClosure.Race || value.Suite == "hermetic" && len(checks.NotSelected) != 0 || (value.Resolved.Mode != value.Suite || value.Resolved.Provider != value.Provider || !reflect.DeepEqual(value.Resolved.Schedule, value.Schedule)) {
		return false
	}
	if value.Schedule.RecoveryMode != value.Resolved.RecoveryMode {
		return false
	}
	expected, err := reconstructRecordedSchedule(value.Schedule)
	if err != nil || requireRegression && !expected.FullCoverage || !reflect.DeepEqual(expected, value.Schedule) || len(value.Scenarios) != len(expected.Entries) {
		return false
	}
	seen := map[string]bool{}
	for i, result := range value.Scenarios {
		participants, err := value.Resolved.scenarioParticipants(result.Scenario)
		if err != nil {
			return false
		}
		shape, err := recordedFixture(result.Scenario, result.Members)
		execution, executionKnown := recordedExecutionForRecovery(result.Scenario, value.Suite, value.Resolved.RecoveryMode)
		if execution.Family == catalog.FamilyConfigurationRecovery {
			if err != nil || !executionKnown || !reflect.DeepEqual(shape, result.Fixture) || result.Entry != expected.Entries[i] || result.Failure != nil || result.Outcome != "passed" || !result.CorrectnessPassed || !reconstructionScenarioComplete(result, value) {
				return false
			}
			continue
		}
		if len(result.Reconstruction) != 0 {
			return false
		}
		expectedChildren := len(execution.ExpandedFreshBefore())
		if result.Rerun != nil && recordedSameDomainRecovery(result.Scenario) && value.Suite == "live" {
			expectedChildren = 0
		}
		if err != nil || !executionKnown || !reflect.DeepEqual(shape, result.Fixture) || result.Entry != expected.Entries[i] || result.Failure != nil || result.Outcome != "passed" || !result.CorrectnessPassed || result.Writer == nil || result.Writer.Role != "writer" || len(result.PostExit) != len(execution.ExpandedFreshAfter()) || len(result.Children) != expectedChildren || result.Cleanup.Failure != nil || result.CleanupRetryBlocker != "" {
			return false
		}
		recovered := result.Rerun != nil
		if recovered {
			if value.Suite != "live" || !recordedSameDomainRecovery(result.Scenario) || result.FirstFailure == nil || *result.FirstFailure != (records.Failure{Class: "store_transport_exhausted", Stage: "transition"}) || result.Writer.Process != "process_failed" || !result.Writer.Joined || result.Writer.StoreFailure == nil || !validTransportFailure(records.WorkerResult{Role: "writer", Outcome: "failed", Failure: result.Writer.Failure, StoreFailure: result.Writer.StoreFailure, Phases: result.Writer.Phases}) || result.Rerun.Role != "rerun" {
				return false
			}
		} else if result.FirstFailure != nil || recordedSameDomainRecovery(result.Scenario) && value.Suite == "live" {
			return false
		}
		if value.Suite == "live" && (!scenarioCleanupPassed(result) || result.CleanupWorker == nil || result.CleanupWorker.Role != "cleanup") {
			return false
		}
		if value.Suite == "hermetic" && (result.Cleanup.Outcome != "not_applicable" || result.CleanupWorker != nil) {
			return false
		}
		before := execution.ExpandedFreshBefore()
		for index, worker := range result.Children {
			step := before[index].Step
			if worker.Role != "fresh_before" || worker.RecoveryMode != step.RecoveryMode || !completeWorkerPhases(worker.Role, worker.Actor, worker.Phases, result.Scenario, value.Suite, participants, nil, worker.RecoveryMode, &step) {
				return false
			}
		}
		for index, worker := range result.PostExit {
			if worker.Role != "fresh_after" || worker.RecoveryMode != expectedFreshMode(result.Scenario, value.Suite, "fresh_after", index, value.Resolved.RecoveryMode) {
				return false
			}
		}
		for _, worker := range scenarioWorkers(result) {
			if _, current := catalog.Name(result.Scenario); current && value.Suite == "hermetic" && worker.Role == "writer" {
				selection := worker.RecoveryMode
				if selection == "" {
					selection = "both"
				}
				if selection != value.Resolved.RecoveryMode {
					return false
				}
			}
			firstFailed := recovered && worker.Role == "writer"
			if worker.Assertions != nil && (worker.Assertions.Validate() != nil || worker.Assertions.Marker == "contradictory_failure_marker" || !firstFailed && !worker.Assertions.PermitsSuccess()) {
				return false
			}
			if seen[worker.Worker] || !telemetryLabel.MatchString(worker.Worker) || !raceObservationMatches(worker.Race, worker.RaceOptions, value.BuildClosure.Race) || !firstFailed && (worker.Failure != nil || worker.Outcome != "passed" || worker.Process != "passed") || firstFailed && (worker.Failure == nil || worker.Outcome == "passed" || worker.Process != "process_failed") || !worker.Joined || len(worker.Phases) == 0 || len(worker.Phases) > maximumWorkerPhases {
				return false
			}
			seen[worker.Worker] = true
			if !firstFailed && worker.Role != "fresh_before" && !completeRecordedWorkerPhases(worker.Role, worker.Actor, worker.Phases, result.Scenario, value.Suite, participants, &result.Cleanup, worker.RecoveryMode, nil) {
				return false
			}
		}
	}
	// Helper skips are admitted only after every scheduled worker has complete
	// successful invocation evidence, including fresh-reader phases and joins.
	return completeComponentEvidence(*checks, value.Suite, value.Provider)
}

func completeComponentEvidence(checks checkEvidence, suite, provider string) bool {
	if hasUnavailableClassifications(checks.Classifications) {
		return false
	}
	if checks.Focus != nil || checks.AssemblyFocus != nil || checks.AssemblyPreparation != nil {
		return false
	}
	if checks.raceMissing || !validRaceOptions(checks.Race, checks.RaceOptions) || !checks.TestsComplete || len(checks.Tests) == 0 || len(checks.Tests) > maximumComponentTests {
		return false
	}
	if suite != "hermetic" && suite != "live" || suite == "hermetic" && provider != "memory" || suite == "live" && provider != "gcp" && provider != "aws" {
		return false
	}
	if suite == "live" {
		owned, err := liveAssemblyTestSources(checks.AssemblySources, provider)
		if err != nil || !maps.Equal(owned, checks.AssemblySources) {
			return false
		}
	}
	selected, valid := selectedComponentEvidence(checks, suite)
	if !valid || !componentEvidenceMatchesInventory(selected, checks.Tests) {
		return false
	}
	seen := map[string]string{}
	passed := false
	for _, test := range checks.Tests {
		if !validComponentName(test.Name) || seen[test.Name] != "" || test.Outcome != "passed" && test.Outcome != "skipped" {
			return false
		}
		seen[test.Name] = test.Outcome
		passed = passed || test.Outcome == "passed"
	}
	for _, test := range checks.Tests {
		if test.Outcome == "skipped" && !completedHelperInvocation(test.Name, suite, seen) {
			return false
		}
	}
	return passed
}

func completedHelperInvocation(name, suite string, outcomes map[string]string) bool {
	if name == "TestFreshProcessChild" {
		parent := "TestThreeGenerationHistoryAndStaleCandidate"
		if suite == "live" {
			parent = "TestLiveInventoryFreshProcess"
		}
		return outcomes[parent] == "passed"
	}
	if suite != "hermetic" {
		return false
	}
	switch name {
	case "TestHermeticRun", "TestHermeticChild":
		return true
	case "TestScenarioPhaseFailureChild":
		return outcomes["TestScenarioPhaseRetainsFailureEvidence"] == "passed"
	case "TestHermeticWorkerEntrypointsNeedExplicitInvocation/writer", "TestHermeticWorkerEntrypointsNeedExplicitInvocation/fresh":
		return outcomes["TestHermeticWorkerEntrypointsNeedExplicitInvocation"] == "passed"
	case "TestHermeticWorkerEntrypointsNeedExplicitInvocation/fixture":
		return outcomes["TestHermeticWorkerEntrypointsNeedExplicitInvocation"] == "passed" && outcomes["TestThreeGenerationHistoryAndStaleCandidate"] == "passed"
	case "TestWriterTerminationChild":
		parent := "TestWriterTerminationPreservesCompleteSelection"
		if outcomes[parent] != "passed" {
			return false
		}
		for _, barrier := range []string{"before-first-create", "after-first-page-readback", "after-root-readback", "after-cas-acceptance", "after-authenticated-observation"} {
			if outcomes[parent+"/"+barrier] != "passed" {
				return false
			}
		}
		return true
	}
	return false
}

func scenarioWorkers(result scenarioResult) []workerEvidence {
	var out []workerEvidence
	if result.Writer != nil {
		out = append(out, *result.Writer)
	}
	if result.Rerun != nil {
		out = append(out, *result.Rerun)
	}
	out = append(out, result.Children...)
	out = append(out, result.PostExit...)
	if result.CleanupWorker != nil {
		out = append(out, *result.CleanupWorker)
	}
	return out
}

func validPhase(value string) bool {
	return slices.Contains([]string{"authentication", "resource_check", "setup", "transition", "reopen", "verification", "cleanup"}, value)
}

type liveRecovery struct {
	owner           currentDirectory
	directory       string
	executionSource *records.Source
}

func (owner liveRecovery) save(value runRecord) error {
	if value.Suite != "live" {
		return errors.New("live recovery suite differs")
	}
	return records.WriteJSON(filepath.Join(owner.directory, "run.json"), value, 0600)
}

// Historical live packets contain this locator. It grants no current authority.
type recordedSupervisor struct {
	InvocationID  string `json:"invocation_id"`
	SourceBinding string `json:"source_binding"`
	Path          string `json:"path"`
}

type retainedTelemetryFile struct {
	Signal string `json:"signal"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func (owner liveRecovery) complete(value runRecord) error {
	if value.Failure != nil || len(value.Scenarios) == 0 || !runProcessesJoined(value) {
		return errors.New("live recovery remains incomplete")
	}
	for _, result := range value.Scenarios {
		if result.Outcome != "passed" || !scenarioCleanupPassed(result) {
			return errors.New("live recovery remains incomplete")
		}
	}
	return owner.owner.remove(true)
}

type liveRecoveryContextKey struct{}
