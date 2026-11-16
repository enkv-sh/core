package records

import (
	"os"
	"path/filepath"
	"strings"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
)

type Invocation struct {
	Scenario          string                  `json:"scenario"`
	Nonce             string                  `json:"nonce"`
	FreshBefore       []InvocationBinding     `json:"fresh_before,omitempty"`
	FailureSources    *FailureSourceBinding   `json:"failure_sources,omitempty"`
	RecoveryMode      string                  `json:"recovery_mode,omitempty"`
	TelemetrySettings *observability.Resolved `json:"telemetry_settings,omitempty"`
	SchemaVersion     int                     `json:"schema_version"`
	RunID             string                  `json:"run_id"`
	Worker            string                  `json:"worker"`
	Role              string                  `json:"role"`
	Input             string                  `json:"input"`
	StateDir          string                  `json:"state_dir"`
	OutputDir         string                  `json:"output_dir"`
	Facts             string                  `json:"facts,omitempty"`
}

func LoadInvocation(path string) (Invocation, error) {
	var invocation Invocation
	if ReadJSON(path, &invocation) != nil || invocation.Validate() != nil || filepath.Dir(path) != invocation.OutputDir {
		return Invocation{}, errRecord
	}
	return invocation, nil
}

// LoadRecordedInvocation reads retained worker evidence without admitting a new
// invocation. Execution callers must use LoadInvocation and Validate.
func LoadRecordedInvocation(path string) (Invocation, error) {
	var inv Invocation
	if ReadJSON(path, &inv) != nil || inv.validate(true) != nil || filepath.Dir(path) != inv.OutputDir {
		return Invocation{}, errRecord
	}
	return inv, nil
}

func (inv Invocation) Validate() error { return inv.validate(false) }

func (inv Invocation) validate(historical bool) error {
	if err := inv.validateEvidence(historical); err != nil {
		return err
	}
	for _, path := range []string{inv.OutputDir, inv.StateDir, inv.Input} {
		if _, _, _, err := PrivateOwner(path); err != nil {
			return err
		}
	}
	if inv.FailureSources != nil && (safeAbsolute(inv.FailureSources.Path) != nil || !regular(inv.FailureSources.Path)) || !directory(inv.OutputDir) || !directory(inv.StateDir) || !regular(inv.Input) {
		return errRecord
	}
	if inv.Facts != "" {
		path, err := SafePath(inv.StateDir, inv.Facts)
		if err != nil || !regular(path) {
			return errRecord
		}
	}
	return nil
}

// ValidateEvidence checks immutable invocation metadata and lexical owners.
// It admits no execution. Retained-evidence readers must separately authenticate
// the copied input, results and source-map bytes at their physical owner.
func (inv Invocation) ValidateEvidence() error { return inv.validateEvidence(false) }

func (inv Invocation) validateEvidence(historical bool) error {
	_, current := catalog.Name(inv.Scenario)
	if !current {
		if _, known := catalog.HistoricalName(inv.Scenario); !known || !historical && inv.Role != "cleanup" {
			return errRecord
		}
	}
	if !validHex(inv.Nonce, 16) || len(inv.FreshBefore) > MaximumWorkerChildren || inv.Role != "writer" && len(inv.FreshBefore) != 0 {
		return errRecord
	}
	workers, nonces := map[string]bool{inv.Worker: true}, map[string]bool{inv.Nonce: true}
	for _, child := range inv.FreshBefore {
		if !labelPattern.MatchString(child.Worker) || !validHex(child.Nonce, 16) || workers[child.Worker] || nonces[child.Nonce] {
			return errRecord
		}
		workers[child.Worker], nonces[child.Nonce] = true, true
	}
	if inv.FailureSources != nil && (!filepath.IsAbs(inv.FailureSources.Path) || filepath.Clean(inv.FailureSources.Path) != inv.FailureSources.Path || strings.ContainsRune(inv.FailureSources.Path, 0) || !validHex(inv.FailureSources.SHA256, 32)) {
		return errRecord
	}
	if inv.TelemetrySettings != nil && inv.TelemetrySettings.Validate() != nil {
		return errRecord
	}
	if inv.SchemaVersion != SchemaVersion || !ValidRunID(inv.RunID) || !labelPattern.MatchString(inv.Worker) || !validRole(inv.Role) {
		return errRecord
	}
	outputOwner, outputRuns, outputID, err := evidencePrivateOwner(inv.OutputDir)
	if err != nil || outputID != inv.RunID {
		return errRecord
	}
	stateOwner, stateRuns, _, err := evidencePrivateOwner(inv.StateDir)
	if err != nil || stateRuns != outputRuns || stateOwner != outputOwner && inv.Role != "cleanup" {
		return errRecord
	}
	inputOwner, inputRuns, _, err := evidencePrivateOwner(inv.Input)
	if err != nil || inputRuns != outputRuns || inputOwner != outputOwner && (inv.Role != "cleanup" || inputOwner != stateOwner) {
		return errRecord
	}
	fresh := inv.Role == "fresh_before" || inv.Role == "fresh_after"
	if inv.RecoveryMode != "" {
		selectedWriter := current && (inv.Role == "writer" || inv.Role == "rerun")
		if (!fresh && !selectedWriter) || inv.RecoveryMode != "disabled" && inv.RecoveryMode != "enabled" && (!selectedWriter || inv.RecoveryMode != "both") {
			return errRecord
		}
	}
	if fresh && inv.Facts == "" || !fresh && inv.Facts != "" {
		return errRecord
	}
	if inv.Facts != "" {
		if filepath.IsAbs(inv.Facts) || filepath.Clean(inv.Facts) != inv.Facts || strings.ContainsRune(inv.Facts, 0) || inv.Facts == "." || inv.Facts == ".." || strings.HasPrefix(inv.Facts, ".."+string(os.PathSeparator)) {
			return errRecord
		}
	}
	return nil
}

func validRole(role string) bool {
	switch role {
	case "writer", "rerun", "fresh_before", "fresh_after", "cleanup", "checks":
		return true
	default:
		return false
	}
}

// PrivateOwner returns the canonical private directory, suite runs directory,
// and original run ID for a path. Invocation.Validate binds these owners to the
// caller role; locating an owner alone does not authorize cross-run access.
func PrivateOwner(path string) (owner, runs, id string, err error) {
	if safeAbsolute(path) != nil {
		return "", "", "", errRecord
	}
	return evidencePrivateOwner(path)
}

func evidencePrivateOwner(path string) (owner, runs, id string, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return "", "", "", errRecord
	}
	for current := path; current != filepath.Dir(current); current = filepath.Dir(current) {
		if filepath.Base(current) != "private" {
			continue
		}
		run := filepath.Dir(current)
		for parent, depth := filepath.Dir(run), 0; depth < 2; parent, depth = filepath.Dir(parent), depth+1 {
			if filepath.Base(parent) != "runs" {
				continue
			}
			relative, relErr := filepath.Rel(parent, run)
			parsed, parseErr := ParseRunRelative(relative)
			if relErr != nil || parseErr != nil || owner != "" {
				return "", "", "", errRecord
			}
			owner, runs, id = current, parent, parsed
		}
	}
	if owner == "" {
		return "", "", "", errRecord
	}
	return owner, runs, id, nil
}

func regular(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// Old cleanup identity is interpreted only for cleanup. The live worker still
// has to admit the exact retained-input grant before it can perform effects.
func (inv Invocation) execution(mode string) (catalog.Execution, bool) {
	if _, current := catalog.Name(inv.Scenario); current {
		return catalog.ExecutionForRecovery(inv.Scenario, mode, inv.RecoveryMode)
	}
	if inv.Role == "cleanup" {
		return catalog.HistoricalExecutionFor(inv.Scenario, mode)
	}
	return catalog.Execution{}, false
}
