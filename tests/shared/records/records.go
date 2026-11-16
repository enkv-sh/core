package records

import (
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

const SchemaVersion = 2
const TelemetryVersion = 2

type Failure struct {
	Class string `json:"class"`
	Stage string `json:"stage"`
}

// StoreFailure carries only typed Core and Store dispositions. Worker log text
// and provider error strings are never recovery authority.
type StoreFailure struct {
	StoreReason           string `json:"store_reason"`
	Outcome               string `json:"outcome"`
	Reason                string `json:"reason"`
	CommitMayHaveOccurred bool   `json:"commit_may_have_occurred"`
}

// HarnessFailure retains only reviewed test-harness facts. It is diagnostic;
// it grants no cleanup or Product retry authority. TargetIndex names a row in
// the private inventory, output inventory or generator ledger, never a provider identifier.
type HarnessFailure struct {
	Operation      string  `json:"operation"`
	Stage          string  `json:"stage"`
	Cause          string  `json:"cause"`
	Effect         string  `json:"effect"`
	HTTPStatus     *uint16 `json:"http_status,omitempty"`
	EnvelopeStatus *uint16 `json:"envelope_status,omitempty"`
	ProviderCode   string  `json:"provider_code,omitempty"`
	TargetKind     string  `json:"target_kind,omitempty"`
	TargetIndex    *uint32 `json:"target_index,omitempty"`
	Attempt        uint8   `json:"attempt"`
}

func (f HarnessFailure) Validate() bool {
	switch f.Operation {
	case "setup_check", "object_cleanup", "generator_cleanup", "output_cleanup":
	default:
		return false
	}
	switch f.Stage {
	case "admission", "authentication", "configuration_check", "writer_join", "ownership_read", "ownership_check", "conditional_create", "conditional_delete", "response_intake", "acknowledgement", "post_delete_read", "persistence", "ledger":
	default:
		return false
	}
	switch f.Cause {
	case "cancelled", "deadline", "transport", "missing_response", "early_eof", "body_overflow", "invalid_encoding", "invalid_length", "malformed_envelope", "access_refused", "condition_refused", "provider_refused", "invalid_acknowledgement", "ownership_mismatch", "persistence_failed", "budget_exhausted", "evidence_unavailable", "unknown_effect", "invalid_request", "authentication_refused":
	default:
		return false
	}
	switch f.Effect {
	case "no_send", "unknown", "acknowledged", "no_effect":
	default:
		return false
	}
	for _, status := range []*uint16{f.HTTPStatus, f.EnvelopeStatus} {
		if status != nil && (*status < 100 || *status > 599) {
			return false
		}
	}
	if f.Attempt > 3 {
		return false
	}
	switch f.ProviderCode {
	case "", "PreconditionFailed", "ConditionalRequestConflict", "AccessDenied", "InternalError", "NoSuchLifecycleConfiguration", "ReplicationConfigurationNotFoundError":
	default:
		return false
	}
	switch f.TargetKind {
	case "":
		if f.TargetIndex != nil {
			return false
		}
	case "inventory", "generator_ledger", "output_inventory":
		if f.TargetIndex == nil || *f.TargetIndex > 1000000 {
			return false
		}
	default:
		return false
	}
	if f.Operation == "setup_check" && f.TargetKind != "" ||
		f.TargetKind == "inventory" && f.Operation != "object_cleanup" ||
		f.TargetKind == "generator_ledger" && f.Operation != "generator_cleanup" ||
		f.TargetKind == "output_inventory" && f.Operation != "output_cleanup" ||
		f.Operation == "output_cleanup" && f.TargetKind != "output_inventory" {
		return false
	}
	if f.Effect == "acknowledged" && f.Stage != "persistence" && f.Stage != "post_delete_read" {
		return false
	}
	if f.Effect == "no_send" && f.Attempt != 0 {
		return false
	}
	return true
}

// RecoveryHandoff contains only the public basis and a plain desired test
// goal. It is saved in the private local run directory before mutation.
type RecoveryHandoff struct {
	Version  int                  `json:"version"`
	RunID    string               `json:"run_id"`
	Scenario string               `json:"scenario"`
	Prefix   string               `json:"prefix"`
	Domain   contract.ID          `json:"domain"`
	Genesis  RecoveryGenesisIDs   `json:"genesis"`
	Basis    []byte               `json:"basis"`
	Desired  []RecoveryPlainValue `json:"desired"`
}

type RecoveryGenesisIDs struct {
	Init               contract.ID `json:"init"`
	Domain             contract.ID `json:"domain"`
	DescriptorArtifact contract.ID `json:"descriptor_artifact"`
	ManifestArtifact   contract.ID `json:"manifest_artifact"`
}

type RecoveryPlainValue struct {
	Name       string        `json:"name"`
	Recipients []contract.ID `json:"recipients"`
	Value      []byte        `json:"value"`
}

type Metric struct {
	Name       string            `json:"name"`
	Unit       string            `json:"unit"`
	Attributes map[string]string `json:"attributes"`
	Kind       string            `json:"kind"`
	Value      *float64          `json:"value,omitempty"`
	Count      *uint64           `json:"count,omitempty"`
	Sum        *float64          `json:"sum,omitempty"`
	Bounds     []float64         `json:"bounds,omitempty"`
	Buckets    []uint64          `json:"buckets,omitempty"`
}

type Snapshot struct {
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id"`
	Worker        string            `json:"worker"`
	Sequence      uint64            `json:"sequence"`
	Phase         string            `json:"phase"`
	Status        string            `json:"status"`
	FailureClass  string            `json:"failure_class,omitempty"`
	CollectedAt   time.Time         `json:"collected_at"`
	Temporality   string            `json:"temporality"`
	Metrics       []Metric          `json:"metrics"`
	Resource      map[string]any    `json:"resource,omitempty"`
	Scopes        map[string]string `json:"scopes,omitempty"`
}

type Telemetry struct {
	Enabled      bool                   `json:"enabled"`
	Status       string                 `json:"status"`
	FailureClass string                 `json:"failure_class,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Definitions  []telemetry.Definition `json:"definitions,omitempty"`
}

type Diagnostics struct {
	Enabled           bool   `json:"enabled"`
	Status            string `json:"status"`
	FailureClass      string `json:"failure_class,omitempty"`
	Source            string `json:"source,omitempty"`
	Accepted          uint64 `json:"accepted"`
	Written           uint64 `json:"written"`
	DroppedContention uint64 `json:"dropped_contention"`
	DroppedFull       uint64 `json:"dropped_full"`
	DroppedClosed     uint64 `json:"dropped_closed"`
	DroppedWriter     uint64 `json:"dropped_writer"`
	Rejected          uint64 `json:"rejected"`
}

type PhaseResult struct {
	RecoveryMode         string `json:"recovery_mode,omitempty"`
	Sequence             uint64 `json:"sequence"`
	Name                 string `json:"name"`
	Outcome              string `json:"outcome"`
	MeasurementsExpected bool   `json:"measurements_expected"`
	Actor                string `json:"actor,omitempty"`
	Expected             string `json:"expected,omitempty"`
	Actual               string `json:"actual,omitempty"`
}

type ChildInvocation struct {
	Process    *FreshChildProcess `json:"process,omitempty"`
	Worker     string             `json:"worker"`
	Invocation string             `json:"invocation"`
}

type FreshCheck struct {
	RecoveryMode string `json:"recovery_mode,omitempty"`
	Facts        string `json:"facts"`
}

type BudgetReservation struct {
	Requests         uint64 `json:"requests"`
	BodyBytes        uint64 `json:"body_bytes"`
	Objects          uint64 `json:"objects"`
	ObjectBytes      uint64 `json:"object_bytes"`
	GeneratorCreates uint64 `json:"generator_creates"`
	GeneratorRetires uint64 `json:"generator_retires"`
}

type Cleanup struct {
	Outcome               string             `json:"outcome"`
	RemainingOwnedObjects *int64             `json:"remaining_owned_objects"`
	UnknownEffects        *int64             `json:"unknown_effects"`
	Failure               *Failure           `json:"failure,omitempty"`
	HarnessFailure        *HarnessFailure    `json:"harness_failure,omitempty"`
	BudgetReserved        *BudgetReservation `json:"budget_reserved,omitempty"`
}

type WorkerResult struct {
	Assertions     *AssertionEvidence        `json:"-"`
	SchemaVersion  int                       `json:"schema_version"`
	RunID          string                    `json:"run_id"`
	Worker         string                    `json:"worker"`
	Role           string                    `json:"role"`
	Actor          string                    `json:"actor,omitempty"`
	Scenario       string                    `json:"scenario"`
	Outcome        string                    `json:"outcome"`
	Failure        *Failure                  `json:"failure,omitempty"`
	StoreFailure   *StoreFailure             `json:"store_failure,omitempty"`
	HarnessFailure *HarnessFailure           `json:"harness_failure,omitempty"`
	Phases         []PhaseResult             `json:"phases"`
	Children       []ChildInvocation         `json:"children"`
	FreshChecks    []FreshCheck              `json:"fresh_checks"`
	Telemetry      Telemetry                 `json:"telemetry"`
	Diagnostics    Diagnostics               `json:"diagnostics"`
	Deliveries     map[string]DeliveryStatus `json:"deliveries,omitempty"`
	SDKCallbacks   uint64                    `json:"sdk_callbacks,omitempty"`
	BudgetReserved *BudgetReservation        `json:"budget_reserved,omitempty"`
	Cleanup        *Cleanup                  `json:"cleanup,omitempty"`
}
