package main

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"

	"enkv.sh/compositions/observability"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

var telemetryName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_./-]{0,254}$`)
var telemetryUnit = regexp.MustCompile(`^[A-Za-z0-9{}./%*^_-]{0,63}$`)

// Telemetry is optional evidence. None of these functions changes a worker's
// correctness result, budget reservation, or cleanup decision.
func loadWorkerTelemetry(inv records.Invocation, worker records.WorkerResult, enabled bool) ([]records.Snapshot, records.Telemetry) {
	out := []records.Snapshot{}
	summary := importedTelemetry(enabled)
	if !enabled {
		return out, summary
	}
	summary.Source = "telemetry.json"
	if inv.Validate() != nil || worker.SchemaVersion != records.SchemaVersion || worker.RunID != inv.RunID || worker.Worker != inv.Worker || worker.Role != inv.Role {
		incompleteTelemetry(&summary, "worker_identity_invalid")
		return out, summary
	}
	if !worker.Telemetry.Enabled || worker.Telemetry.Status != "complete" || worker.Telemetry.FailureClass != "" {
		incompleteTelemetry(&summary, telemetryFailureClass(worker.Telemetry.FailureClass))
	}
	path, err := records.SafePath(inv.OutputDir, "telemetry.json")
	var raw []json.RawMessage
	if err != nil || records.ReadJSON(path, &raw) != nil {
		incompleteTelemetry(&summary, "telemetry_unavailable")
		return out, summary
	}

	phases := make(map[uint64]records.PhaseResult, len(worker.Phases))
	var lastPhase uint64
	for index, phase := range worker.Phases {
		if phase.Sequence != uint64(index)+1 || !telemetryLabel.MatchString(phase.Name) || phase.Outcome != "passed" && phase.Outcome != "failed" && phase.Outcome != "incomplete" {
			incompleteTelemetry(&summary, "phase_history_invalid")
			return out, summary
		}
		phases[phase.Sequence] = phase
		lastPhase = phase.Sequence
	}
	seen := make(map[uint64]int, len(raw))
	var previous uint64
	for _, body := range raw {
		candidate, invalidMetric, err := decodeTelemetryCandidate(body)
		if err != nil {
			incompleteTelemetry(&summary, "snapshot_invalid")
			continue
		}
		snapshot, valid := projectTelemetrySnapshot(candidate)
		if !valid || snapshot.RunID != inv.RunID || snapshot.Worker != inv.Worker {
			incompleteTelemetry(&summary, "snapshot_invalid")
			continue
		}
		if snapshot.Sequence <= previous {
			incompleteTelemetry(&summary, "phase_history_invalid")
		}
		previous = snapshot.Sequence
		phase, isPhase := phases[snapshot.Sequence]
		isFinal := snapshot.Sequence == lastPhase+1 && snapshot.Phase == "final"
		if !isPhase && !isFinal || isPhase && snapshot.Phase != phase.Name {
			incompleteTelemetry(&summary, "phase_history_invalid")
			continue
		}
		if invalidMetric {
			incompleteSnapshot(&snapshot, "invalid_metric")
		}
		if isPhase && phase.Outcome == "incomplete" {
			incompleteSnapshot(&snapshot, "phase_not_finished")
		}
		if isPhase && phase.MeasurementsExpected && !records.PositiveObservation(snapshot.Metrics) {
			incompleteSnapshot(&snapshot, "no_observations")
		}
		seen[snapshot.Sequence]++
		out = append(out, snapshot)
	}
	for sequence := uint64(1); sequence <= lastPhase+1; sequence++ {
		if seen[sequence] != 1 {
			incompleteTelemetry(&summary, "phase_history_incomplete")
		}
	}
	var combined records.Telemetry
	out, combined = combineTelemetry(true, out)
	if combined.Status != "complete" {
		incompleteTelemetry(&summary, combined.FailureClass)
	}
	return out, summary
}

// Decode metrics separately so one malformed row does not erase other
// observations from the collection. Unknown fields are not projected.
func decodeTelemetryCandidate(body []byte) (records.Snapshot, bool, error) {
	var decoded struct {
		records.Snapshot
		Metrics []json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return records.Snapshot{}, false, err
	}
	candidate := decoded.Snapshot
	candidate.Metrics = []records.Metric{}
	invalidMetric := decoded.Metrics == nil
	for _, row := range decoded.Metrics {
		var metric records.Metric
		if json.Unmarshal(row, &metric) != nil {
			invalidMetric = true
			continue
		}
		candidate.Metrics = append(candidate.Metrics, metric)
	}
	return candidate, invalidMetric, nil
}

// combineTelemetry retains collections, rather than summing unlike metrics or
// overlapping durations. Ambiguous duplicate collections are omitted entirely.
func combineTelemetry(enabled bool, groups ...[]records.Snapshot) ([]records.Snapshot, records.Telemetry) {
	out := []records.Snapshot{}
	summary := importedTelemetry(enabled)
	if !enabled {
		return out, summary
	}
	type identity struct {
		run, worker string
		sequence    uint64
	}
	counts := make(map[identity]int)
	for _, group := range groups {
		for _, candidate := range group {
			snapshot, valid := projectTelemetrySnapshot(candidate)
			if !valid {
				incompleteTelemetry(&summary, "snapshot_invalid")
				continue
			}
			key := identity{snapshot.RunID, snapshot.Worker, snapshot.Sequence}
			counts[key]++
			if counts[key] > 1 {
				incompleteTelemetry(&summary, "duplicate_snapshot")
			}
			if snapshot.Status != "complete" {
				incompleteTelemetry(&summary, snapshot.FailureClass)
			}
			out = append(out, snapshot)
		}
	}
	unique := out[:0]
	for _, snapshot := range out {
		if counts[identity{snapshot.RunID, snapshot.Worker, snapshot.Sequence}] == 1 {
			unique = append(unique, snapshot)
		}
	}
	out = unique
	sort.Slice(out, func(i, j int) bool {
		if out[i].Worker != out[j].Worker {
			return out[i].Worker < out[j].Worker
		}
		if out[i].Sequence != out[j].Sequence {
			return out[i].Sequence < out[j].Sequence
		}
		return out[i].RunID < out[j].RunID
	})
	if len(out) == 0 {
		incompleteTelemetry(&summary, "no_observations")
	}
	return out, summary
}

func importedTelemetry(enabled bool) records.Telemetry {
	if !enabled {
		return records.Telemetry{Status: "disabled"}
	}
	return records.Telemetry{Enabled: true, Status: "complete", Definitions: telemetry.Definitions()}
}

func incompleteTelemetry(summary *records.Telemetry, class string) {
	summary.Status = "incomplete"
	class = telemetryFailureClass(class)
	// Several workers can fail independently. Keep the summary stable when
	// their collections arrive in a different order.
	if summary.FailureClass == "" || class < summary.FailureClass {
		summary.FailureClass = class
	}
}

func incompleteSnapshot(snapshot *records.Snapshot, class string) {
	snapshot.Status = "incomplete"
	if snapshot.FailureClass == "" {
		snapshot.FailureClass = telemetryFailureClass(class)
	}
}

func telemetryFailureClass(class string) string {
	switch class {
	case "setup_failed", "collection_failed", "unsafe_attributes", "invalid_metric", "phase_not_finished", "no_observations", "write_failed", "shutdown_failed",
		"worker_identity_invalid", "telemetry_unavailable", "snapshot_invalid", "phase_history_invalid", "phase_history_incomplete", "duplicate_snapshot":
		return class
	default:
		return "collection_incomplete"
	}
}

func projectTelemetrySnapshot(candidate records.Snapshot) (records.Snapshot, bool) {
	if candidate.SchemaVersion != records.TelemetryVersion || !records.ValidRunID(candidate.RunID) || !telemetryLabel.MatchString(candidate.Worker) || candidate.Sequence == 0 || !telemetryLabel.MatchString(candidate.Phase) || candidate.Temporality != "delta" || candidate.Status != "complete" && candidate.Status != "incomplete" || candidate.CollectedAt.IsZero() || candidate.CollectedAt.Year() < 1 || candidate.CollectedAt.Year() > 9999 {
		return records.Snapshot{}, false
	}
	out := records.Snapshot{
		SchemaVersion: records.TelemetryVersion, RunID: candidate.RunID, Worker: candidate.Worker,
		Sequence: candidate.Sequence, Phase: candidate.Phase, Status: candidate.Status,
		CollectedAt: candidate.CollectedAt.UTC(), Temporality: "delta", Metrics: []records.Metric{},
	}
	if len(candidate.Resource) != 0 || len(candidate.Scopes) != 0 {
		scopes := make(map[string]observability.Scope, len(candidate.Scopes))
		for component, name := range candidate.Scopes {
			scopes[component] = observability.Scope{Name: name}
		}
		metadata := observability.Resolved{LogLevel: observability.Warn, Console: true, Resource: candidate.Resource, Scopes: scopes}
		if metadata.Validate() != nil {
			incompleteSnapshot(&out, "unsafe_attributes")
		} else {
			out.Resource = metadata.Clone().Resource
			out.Scopes = make(map[string]string, len(candidate.Scopes))
			for component, name := range candidate.Scopes {
				out.Scopes[component] = name
			}
		}
	}
	if candidate.Status != "complete" || candidate.FailureClass != "" {
		incompleteSnapshot(&out, candidate.FailureClass)
	}
	if candidate.Metrics == nil {
		incompleteSnapshot(&out, "invalid_metric")
	}
	for _, candidateMetric := range candidate.Metrics {
		metric, valid := projectTelemetryMetric(candidateMetric)
		if !valid {
			incompleteSnapshot(&out, "invalid_metric")
			continue
		}
		out.Metrics = append(out.Metrics, metric)
	}
	return out, true
}

func projectTelemetryMetric(candidate records.Metric) (records.Metric, bool) {
	if !telemetryName.MatchString(candidate.Name) || !telemetryUnit.MatchString(candidate.Unit) || !telemetry.ValidAttributes(candidate.Attributes) {
		return records.Metric{}, false
	}
	out := records.Metric{Name: candidate.Name, Unit: candidate.Unit, Kind: candidate.Kind, Attributes: map[string]string{}}
	for key, value := range candidate.Attributes {
		out.Attributes[key] = value
	}
	switch candidate.Kind {
	case "sum", "gauge":
		if candidate.Value == nil || !telemetryNumber(*candidate.Value) || candidate.Count != nil || candidate.Sum != nil || len(candidate.Bounds) != 0 || len(candidate.Buckets) != 0 {
			return records.Metric{}, false
		}
		value := *candidate.Value
		out.Value = &value
	case "histogram":
		if candidate.Value != nil || candidate.Count == nil || candidate.Sum == nil || !telemetryNumber(*candidate.Sum) || len(candidate.Buckets) != len(candidate.Bounds)+1 {
			return records.Metric{}, false
		}
		for index, bound := range candidate.Bounds {
			if !telemetryNumber(bound) || index > 0 && bound <= candidate.Bounds[index-1] {
				return records.Metric{}, false
			}
		}
		var total uint64
		for _, count := range candidate.Buckets {
			if count > math.MaxUint64-total {
				return records.Metric{}, false
			}
			total += count
		}
		if total != *candidate.Count || total == 0 && *candidate.Sum != 0 {
			return records.Metric{}, false
		}
		count, sum := *candidate.Count, *candidate.Sum
		out.Count, out.Sum = &count, &sum
		out.Bounds = append([]float64{}, candidate.Bounds...)
		out.Buckets = append([]uint64{}, candidate.Buckets...)
	default:
		return records.Metric{}, false
	}
	return out, true
}

func telemetryNumber(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}
