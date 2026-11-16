package records

import (
	"context"
	"errors"
	"os"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/telemetry"
)

// WorkerRecorder owns one process's SDK and files. Callers register children and
// fresh checks in Result, then Save before they start the corresponding work.
// Phase boundaries and changes to Result belong to the calling test goroutine.
// Product goroutines may record telemetry concurrently through the SDK.
type WorkerRecorder struct {
	Result WorkerResult

	failure         *FailureRecorder
	invocation      Invocation
	collector       *Collector
	runtime         *observability.Runtime
	invocationCall  *telemetry.Call
	snapshots       []Snapshot
	sequence        uint64
	catalogPosition int
	mode            string
	active          uint64
	observed        bool
	finished        bool
	finishErr       error
}

func NewWorker(inv Invocation, provider, scenario string, failure *FailureRecorder) (*WorkerRecorder, error) {
	if inv.Validate() != nil || inv.Scenario != scenario {
		return nil, errRecord
	}
	for _, name := range []string{"worker.json", "telemetry.json"} {
		path, err := SafePath(inv.OutputDir, name)
		if err != nil {
			return nil, errRecord
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return nil, errRecord
		}
	}
	if failure == nil {
		var err error
		failure, err = NewFailureRecorder(inv)
		if err != nil {
			return nil, err
		}
	}
	if !failure.belongsTo(inv) {
		return nil, errRecord
	}
	mode := "hermetic"
	if provider == "aws" || provider == "gcp" {
		mode = "live"
	}
	execution, known := inv.execution(mode)
	if !known || inv.Role == "fresh_after" && len(execution.FreshAfter) == 0 {
		return nil, errRecord
	}
	var settings observability.Resolved
	if inv.TelemetrySettings != nil {
		settings = inv.TelemetrySettings.Clone()
	} else {
		var err error
		settings, err = observability.Resolve(observability.Config{SchemaVersion: 1}, observability.Options{})
		if err != nil {
			return nil, errRecord
		}
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: inv.OutputDir, ManualMetrics: true})
	if err != nil {
		return nil, errRecord
	}
	invocationCall := telemetry.StartWithDetails(runtime.Context(context.Background()), telemetry.ProviderWorker, telemetry.OpWorkerInvocation,
		(telemetry.DiagnosticDetails{}).WithInvocationID(inv.RunID).WithWorkerID(inv.Worker))
	worker := &WorkerRecorder{
		invocation:     inv,
		failure:        failure,
		runtime:        runtime,
		invocationCall: invocationCall,
		collector:      NewCollector(runtime),
		snapshots:      []Snapshot{},
		Result: WorkerResult{
			SchemaVersion: SchemaVersion, RunID: inv.RunID, Worker: inv.Worker,
			Role: inv.Role, Actor: "authority", Scenario: scenario, Outcome: "incomplete",
			Phases: []PhaseResult{}, Children: []ChildInvocation{}, FreshChecks: []FreshCheck{},
			Telemetry:   Telemetry{Status: "disabled"},
			Diagnostics: Diagnostics{Status: "disabled"},
		},
	}
	worker.mode = mode
	if inv.Role == "fresh_after" {
		worker.Result.Actor = execution.FreshAfter[0].Role
	}
	if worker.collector.Enabled() {
		worker.Result.Telemetry = Telemetry{Enabled: true, Status: "incomplete", Source: "telemetry.json", Definitions: telemetry.Definitions()}
	}
	if runtime.LogsEnabled() {
		worker.Result.Diagnostics = Diagnostics{Enabled: true, Status: "incomplete"}
	}
	if err := worker.Save(); err != nil {
		invocationCall.Finish(telemetry.ResultFailure)
		worker.collector.Close(context.Background())
		return nil, err
	}
	return worker, nil
}

// Context attaches this worker's invocation-owned telemetry capability.
func (w *WorkerRecorder) Context(ctx context.Context) context.Context {
	if w == nil || w.runtime == nil || ctx == nil {
		return ctx
	}
	if w.invocationCall != nil {
		return telemetry.PrivateContext(ctx, w.invocationCall.Context())
	}
	return w.runtime.Context(ctx)
}

func (w *WorkerRecorder) Save() error {
	if w == nil || w.Result.SchemaVersion != SchemaVersion || w.Result.RunID != w.invocation.RunID || w.Result.Worker != w.invocation.Worker || w.Result.Role != w.invocation.Role {
		return errRecord
	}
	if w.Result.HarnessFailure != nil && !w.Result.HarnessFailure.Validate() ||
		w.Result.Cleanup != nil && w.Result.Cleanup.HarnessFailure != nil && !w.Result.Cleanup.HarnessFailure.Validate() {
		return errRecord
	}
	owner, _, _, err := PrivateOwner(w.invocation.OutputDir)
	if err != nil {
		return errRecord
	}
	children := make(map[string]bool, len(w.Result.Children))
	for _, child := range w.Result.Children {
		if !labelPattern.MatchString(child.Worker) || child.Worker == w.Result.Worker || children[child.Worker] {
			return errRecord
		}
		path, err := SafePath(owner, child.Invocation)
		if err != nil {
			return errRecord
		}
		invocation, err := LoadInvocation(path)
		if err != nil || invocation.RunID != w.Result.RunID || invocation.Worker != child.Worker {
			return errRecord
		}
		children[child.Worker] = true
	}
	for _, check := range w.Result.FreshChecks {
		path, err := SafePath(w.invocation.StateDir, check.Facts)
		if err != nil || !regular(path) {
			return errRecord
		}
	}
	path, err := SafePath(w.invocation.OutputDir, "worker.json")
	if err != nil {
		return errRecord
	}
	return WriteJSON(path, w.Result, 0o600)
}

func (w *WorkerRecorder) BeginPhase(name string, expected bool) (uint64, error) {
	if w == nil || w.finished || w.active != 0 || !validFailurePhase(name) || w.sequence >= MaximumWorkerPhases {
		return 0, errRecord
	}
	w.sequence++
	if err := w.failure.begin(name, w.sequence); err != nil {
		return 0, err
	}
	w.active = w.sequence
	w.observed = false
	w.Result.Phases = append(w.Result.Phases, PhaseResult{Sequence: w.sequence, Name: name, Outcome: "incomplete", MeasurementsExpected: expected, Actor: w.Result.Actor, Expected: "success", Actual: "incomplete"})
	return w.sequence, w.Save()
}

// BeginStep records the scenario's expectation before its Go action starts.
func (w *WorkerRecorder) BeginStep(step catalog.Step, participant string) (uint64, error) {
	if step.RecoveryMode != "" && step.RecoveryMode != "disabled" && step.RecoveryMode != "enabled" {
		return 0, errRecord
	}
	if !labelPattern.MatchString(participant) || !catalog.HasStepOutcome(step.Expected) {
		return 0, errRecord
	}
	execution, known := w.invocation.execution(w.mode)
	if !known {
		return 0, errRecord
	}
	measurementsExpected, valid := execution.MeasurementFor(w.Result.Role, w.catalogPosition, step)
	if !valid {
		return 0, errRecord
	}
	sequence, err := w.BeginPhase(step.Name, measurementsExpected)
	if err != nil {
		return 0, err
	}
	w.catalogPosition++
	phase := &w.Result.Phases[len(w.Result.Phases)-1]
	phase.Actor, phase.Expected = participant, step.Expected
	phase.RecoveryMode = step.RecoveryMode
	return sequence, w.Save()
}

// ObservePhase preserves an explicit result, including an incomplete result.
// EndPhase may infer an assertion result only when no observation was supplied.
func (w *WorkerRecorder) ObservePhase(sequence uint64, actual string) error {
	if w == nil || w.finished || sequence == 0 || sequence != w.active {
		return errRecord
	}
	w.Result.Phases[len(w.Result.Phases)-1].Actual = actual
	w.observed = true
	return w.Save()
}

func (w *WorkerRecorder) EndPhase(ctx context.Context, sequence uint64, passed bool) error {
	if w == nil || w.finished || sequence == 0 || sequence != w.active || len(w.Result.Phases) == 0 {
		return errRecord
	}
	phase := &w.Result.Phases[len(w.Result.Phases)-1]
	if phase.Sequence != sequence {
		return errRecord
	}
	if !w.observed && phase.Actual == "incomplete" {
		phase.Actual = "failed"
		if passed {
			phase.Actual = phase.Expected
		}
	}
	phase.Outcome = "failed"
	if passed && phase.Actual == phase.Expected {
		phase.Outcome = "passed"
	}
	w.collect(ctx, sequence, phase.Name, phase.MeasurementsExpected, "")
	w.active = 0
	if err := w.Save(); err != nil {
		return err
	}
	if phase.Outcome == "passed" {
		return w.failure.complete(phase.Name, sequence)
	}
	return nil
}

func (w *WorkerRecorder) Finish(ctx context.Context, passed bool) error {
	if w == nil {
		return errRecord
	}
	if w.finished {
		return w.finishErr
	}
	w.finished = true
	if w.active != 0 {
		phase := w.Result.Phases[len(w.Result.Phases)-1]
		w.collect(ctx, phase.Sequence, phase.Name, phase.MeasurementsExpected, "phase_not_finished")
		w.active = 0
	}
	for _, phase := range w.Result.Phases {
		passed = passed && phase.Outcome == "passed"
	}
	if w.invocationCall != nil {
		outcome := telemetry.ResultFailure
		if passed && w.Result.Failure == nil {
			outcome = telemetry.ResultSuccess
		}
		w.invocationCall.Finish(outcome)
	}
	w.sequence++
	w.collect(ctx, w.sequence, "final", false, "")
	if !w.collector.Close(ctx) {
		w.telemetryFailure("shutdown_failed")
	}
	if w.collector.Enabled() && w.Result.Telemetry.FailureClass == "" {
		w.Result.Telemetry.Status = "complete"
	}
	w.Result.Outcome = "failed"
	if passed && w.Result.Failure == nil {
		w.Result.Outcome = "passed"
	} else if w.Result.Failure == nil {
		w.Result.Failure = &Failure{Class: "worker_failed", Stage: "execution"}
	}
	w.Result.Diagnostics = w.diagnosticEvidence()
	statuses := w.runtime.DeliveryStatuses()
	w.Result.Deliveries = make(map[string]DeliveryStatus, len(statuses))
	for name, status := range statuses {
		w.Result.Deliveries[name] = DeliveryStatus{Accepted: &status.Accepted, Written: &status.Written,
			Dropped: &status.Dropped, Failed: &status.Failed, Incomplete: &status.Incomplete}
	}
	w.Result.SDKCallbacks = w.runtime.SDKCallbackCount()
	w.finishErr = w.Save()
	return w.finishErr
}

func (w *WorkerRecorder) diagnosticEvidence() Diagnostics {
	if w.runtime == nil || !w.runtime.LogsEnabled() {
		return Diagnostics{Status: "disabled"}
	}
	capture := w.runtime.RecorderStatus()
	console := w.runtime.LogStatus("console")
	out := Diagnostics{Enabled: true, Status: "complete", Accepted: capture.Accepted,
		Written: console.Written, DroppedContention: capture.DroppedContention,
		DroppedFull: capture.DroppedFull, DroppedClosed: capture.DroppedClosed,
		DroppedWriter: console.Dropped + console.Failed, Rejected: capture.Rejected}
	if source := w.runtime.LogFileSource(); source != "" {
		file := w.runtime.LogStatus(w.logFileExporterName())
		out.Written += file.Written
		out.DroppedWriter += file.Dropped + file.Failed
		if file.Written != 0 {
			out.Source = source
		}
		if file.Incomplete {
			out.Status, out.FailureClass = "incomplete", "delivery_failed"
		}
	}
	if console.Incomplete || out.DroppedContention != 0 || out.DroppedFull != 0 || out.DroppedClosed != 0 || out.Rejected != 0 {
		out.Status, out.FailureClass = "incomplete", "delivery_failed"
	}
	return out
}

func (w *WorkerRecorder) logFileExporterName() string {
	if w.invocation.TelemetrySettings == nil {
		return ""
	}
	for _, name := range w.invocation.TelemetrySettings.LogExporters {
		if w.invocation.TelemetrySettings.ActiveExporters[name].Type == "otlp_file" {
			return name
		}
	}
	return ""
}

func (w *WorkerRecorder) collect(ctx context.Context, sequence uint64, phase string, expected bool, failure string) {
	if !w.collector.Enabled() {
		return
	}
	snapshot := w.collector.Collect(ctx, w.invocation.RunID, w.invocation.Worker, phase)
	snapshot.Sequence = sequence
	if snapshot.Status == "complete" && failure != "" {
		snapshot.Status, snapshot.FailureClass = "incomplete", failure
	} else if snapshot.Status == "complete" && expected && !PositiveObservation(snapshot.Metrics) {
		snapshot.Status, snapshot.FailureClass = "incomplete", "no_observations"
	}
	if snapshot.Status != "complete" {
		w.telemetryFailure(snapshot.FailureClass)
	}
	w.snapshots = append(w.snapshots, snapshot)
	path, err := SafePath(w.invocation.OutputDir, "telemetry.json")
	if err != nil || WriteJSON(path, w.snapshots, 0o600) != nil {
		w.telemetryFailure("write_failed")
	}
}

func (w *WorkerRecorder) telemetryFailure(class string) {
	w.Result.Telemetry.Status = "incomplete"
	if w.Result.Telemetry.FailureClass == "" {
		w.Result.Telemetry.FailureClass = class
	}
}

// PositiveObservation reports positive phase measurements other than the worker invocation.
func PositiveObservation(metrics []Metric) bool {
	for _, measurement := range metrics {
		// The worker invocation starts before any phase and returns after all
		// phases. Its own measurements cannot satisfy a phase's expectation.
		if measurement.Attributes["provider"] == string(telemetry.ProviderWorker) && measurement.Attributes["operation"] == string(telemetry.OpWorkerInvocation) {
			continue
		}
		if measurement.Value != nil && *measurement.Value > 0 || measurement.Count != nil && *measurement.Count > 0 {
			return true
		}
	}
	return false
}
