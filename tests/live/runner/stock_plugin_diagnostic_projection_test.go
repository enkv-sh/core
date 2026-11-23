package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestStockDiagnosticProjectionPreservesStaleSealedInputRefusal(t *testing.T) {
	for _, test := range []struct{ name, reason, fault string }{
		{"current-refusal", string(contract.ReasonStaleSealedInputBinding), ""},
		{"unrecognized-reason", "PRIVATE UNKNOWN REASON", "invalid-enum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"schema":"ProductResult/v1","operation_kind":"apply-declaration","state_result":"refused","effect_summary":"effect-no-change","output_summary":"not-applicable","diagnostics":[{"subject":{"kind":"entry","name":"PRIVATE ENTRY\nNAME"},"path":[{"field":"source"}],"outcome":"unable to verify","reason":%q,"raw_error":"PRIVATE RAW ERROR"}]}`, test.reason)
			projection, fault := stockProjectDiagnostic([]byte(body))
			if fault != test.fault || bytes.Contains(projection, []byte("PRIVATE")) || bytes.Contains(projection, []byte(`"name":`)) || bytes.Contains(projection, []byte(`"raw_error":`)) {
				t.Fatal("diagnostic reason classification or private-data exclusion differs", fault)
			}
			if test.fault != "" {
				return
			}
			var observed struct {
				State       string `json:"state_result"`
				Diagnostics []struct {
					Subject         map[string]string
					Path            []struct{ Field string }
					Outcome, Reason string
				}
			}
			if json.Unmarshal(projection, &observed) != nil || observed.State != "refused" || len(observed.Diagnostics) != 1 {
				t.Fatal("known refusal lost its complete diagnostic")
			}
			diagnostic := observed.Diagnostics[0]
			if diagnostic.Reason != "stale-sealed-input-binding" || diagnostic.Outcome != "unable to verify" || len(diagnostic.Subject) != 1 || diagnostic.Subject["kind"] != "entry" || len(diagnostic.Path) != 1 || diagnostic.Path[0].Field != "source" {
				t.Fatal("known refusal lost its closed reason, subject kind or source field")
			}
		})
	}
}

const stockDiagnosticFileLimit = records.MaximumStockPluginDiagnosticBytes
const stockDiagnosticHeaderAllowance = 4 << 10

// A diagnostic is an observation of approved fields only. It supplies no
// cleanup, replay, or Product-completeness authority.
type stockDiagnostic struct {
	Schema              uint8           `json:"schema"`
	RunID               string          `json:"run_id"`
	Ordinal             uint32          `json:"ordinal"`
	Worker              string          `json:"worker"`
	Nonce               string          `json:"nonce"`
	Phase               string          `json:"phase"`
	CLISHA256           string          `json:"cli_sha256"`
	ResultSHA256        string          `json:"result_sha256"`
	DigestScope         string          `json:"digest_scope"`
	CapturedBytes       uint32          `json:"captured_bytes"`
	StdoutOverflow      bool            `json:"stdout_overflow"`
	StderrOverflow      bool            `json:"stderr_overflow"`
	StderrCapturedBytes uint32          `json:"stderr_captured_bytes"`
	Started             bool            `json:"started"`
	WaitReturned        bool            `json:"wait_returned"`
	WaitHasProcessState bool            `json:"wait_has_process_state"`
	ProductJoined       bool            `json:"product_joined"`
	TimedOut            bool            `json:"timed_out"`
	StartSaveFailed     bool            `json:"start_save_failed"`
	CLIChanged          bool            `json:"cli_changed"`
	Status              string          `json:"status"`
	Fault               string          `json:"fault,omitempty"`
	Uncaptured          []string        `json:"uncaptured"`
	Result              json.RawMessage `json:"result,omitempty"`
}

type stockDiagnosticProjection struct{ fault string }
type stockDiagnosticObject map[string]json.RawMessage

func stockDiagnosticLabel(value string) bool {
	if len(value) == 0 || len(value) > 96 || value[0] < 'a' && (value[0] < '0' || value[0] > '9') || value[0] > 'z' {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func stockDiagnosticHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func stockDiagnosticMetadata(value stockDiagnostic) bool {
	return records.ValidRunID(value.RunID) && value.Ordinal < 64 && stockDiagnosticLabel(value.Worker) && stockDiagnosticLabel(value.Phase) && stockDiagnosticHex(value.Nonce, 16) && stockDiagnosticHex(value.CLISHA256, 32) && stockDiagnosticHex(value.ResultSHA256, 32)
}

func (p *stockDiagnosticProjection) fail(where string) {
	if p.fault == "" {
		p.fault = where
	}
}

func stockDiagnosticNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// Each scalar is decoded, checked, then freshly encoded. No source string or
// source JSON fragment is copied into the result without this closed check.
func (p *stockDiagnosticProjection) scalar(out stockDiagnosticObject, in map[string]json.RawMessage, name, kind string) {
	if p.fault != "" {
		return
	}
	raw, ok := in[name]
	if !ok {
		return
	}
	if stockDiagnosticNull(raw) {
		out[name] = json.RawMessage("null")
		return
	}
	var encoded []byte
	var err error
	switch kind {
	case "id":
		var value string
		if jsonv2.Unmarshal(raw, &value) != nil || !stockDiagnosticHex(value, 32) {
			p.fail("invalid-id")
			return
		}
		encoded, err = json.Marshal(value)
	case "word":
		var value string
		if jsonv2.Unmarshal(raw, &value) != nil || !stockDiagnosticWord(value) {
			p.fail("invalid-enum")
			return
		}
		encoded, err = json.Marshal(value)
	case "bool":
		var value bool
		if jsonv2.Unmarshal(raw, &value) != nil {
			p.fail("invalid-bool")
			return
		}
		encoded, err = json.Marshal(value)
	case "uint":
		var value uint64
		decimal := bytes.TrimSpace(raw)
		if len(decimal) == 0 || len(decimal) > 1 && decimal[0] == '0' {
			p.fail("invalid-number")
			return
		}
		for _, c := range decimal {
			if c < '0' || c > '9' {
				p.fail("invalid-number")
				return
			}
		}
		if jsonv2.Unmarshal(decimal, &value) != nil {
			p.fail("invalid-number")
			return
		}
		encoded, err = json.Marshal(value)
	default:
		p.fail("invalid-schema")
		return
	}
	if err != nil {
		p.fail("encoding-failed")
		return
	}
	out[name] = encoded
}

func (p *stockDiagnosticProjection) fields(out stockDiagnosticObject, in map[string]json.RawMessage, kind string, names ...string) {
	for _, name := range names {
		p.scalar(out, in, name, kind)
	}
}

func (p *stockDiagnosticProjection) pathPresence(out stockDiagnosticObject, in map[string]json.RawMessage, name string) {
	if p.fault != "" {
		return
	}
	raw, ok := in[name]
	if !ok {
		return
	}
	if stockDiagnosticNull(raw) {
		out[name+"_present"] = json.RawMessage("null")
		return
	}
	var value string
	if jsonv2.Unmarshal(raw, &value) != nil {
		p.fail("invalid-path")
		return
	}
	if value == "" {
		out[name+"_present"] = json.RawMessage("false")
	} else {
		out[name+"_present"] = json.RawMessage("true")
	}
}

func (p *stockDiagnosticProjection) stockFormatMatch(out stockDiagnosticObject, in map[string]json.RawMessage) {
	const name = "format_contract_id"
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return
	}
	if stockDiagnosticNull(raw) {
		out[name+"_stock_match"] = json.RawMessage("null")
		return
	}
	var value string
	if jsonv2.Unmarshal(raw, &value) != nil {
		p.fail("invalid-format")
		return
	}
	if value == "example/ini-reference/v1" {
		out[name+"_stock_match"] = json.RawMessage("true")
	} else {
		out[name+"_stock_match"] = json.RawMessage("false")
	}
}

func stockDiagnosticDecodeObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var value map[string]json.RawMessage
	if jsonv2.Unmarshal(raw, &value) != nil || value == nil {
		return nil, false
	}
	return value, true
}

func stockDiagnosticEncodeObject(value stockDiagnosticObject) (json.RawMessage, error) {
	return json.Marshal(value)
}

// The nested manifest issuance uses the same Product envelope as the root.
func (p *stockDiagnosticProjection) productEnvelope(out stockDiagnosticObject, in map[string]json.RawMessage) {
	p.fields(out, in, "word", "schema", "operation", "operation_kind", "state_result", "effect_summary", "output_summary", "evidence_ceiling", "operation_payload")
	p.fields(out, in, "id", "operation_id", "request_id", "domain_id", "head_revision_id", "requested_revision_id", "observed_revision_id", "observed_snapshot_id", "snapshot_id")
	p.fields(out, in, "bool", "commit_may_have_occurred")
	p.textOrID(out, in, "replay_identity")
	p.pathPresence(out, in, "receipt_hex")
	for _, name := range []string{"context", "request_identity", "observation"} {
		p.projectMember(out, in, name)
	}
}

func (p *stockDiagnosticProjection) projectMember(out stockDiagnosticObject, in map[string]json.RawMessage, name string) {
	value, exists := in[name]
	if !exists || p.fault != "" {
		return
	}
	if stockDiagnosticNull(value) {
		out[name] = json.RawMessage("null")
		return
	}
	trimmed := bytes.TrimSpace(value)
	if (name == "request_identity" || name == "artifact") && len(trimmed) > 0 && trimmed[0] == '"' {
		if name == "request_identity" {
			p.textOrID(out, in, name)
		} else {
			p.scalar(out, in, name, "id")
		}
		return
	}
	out[name] = p.projectObject(value, name)
}

var stockDiagnosticWords = []string{
	string(contract.ReasonStaleSealedInputBinding),
	"selection-required",
	"clean-owned-failure-residue",
	"init", "initialize", "initialize-domain", "initialize-empty-domain", "apply-declaration", "set-confidential", "plan", "plan-declaration", "generated-list", "retire-generated-generation", "publish", "materialize", "materialize-secret", "issue-consumption-manifest", "prepare", "output-delete", "delete-output", "remove-generated", "reconstruct", "compare", "compare-public-configuration", "inspect", "inspect-state",
	"success", "exact-resume", "no-op", "refused", "unavailable", "contention", "commit-outcome-unknown", "positive-defect", "profile-blocked", "root-loss-unsupported", "snapshot-size-refusal", "possible-live-residue-accepted", "retirement-pending", "effect-pending", "effect-partial", "effect-unknown", "effect-terminal-failure", "stale-generated-epoch", "generated-intent-conflict", "effect-no-change", "effect-complete", "effect-mixed-terminal", "effect-failed", "not-applicable", "output-complete", "output-pending", "output-partial", "output-unknown", "output-failed", "output-no-change", "output-mixed-terminal",
	"complete", "incomplete", "not-attempted", "not-observed", "not-created", "renamed", "replaced", "not-replaced", "unknown", "verified", "failed", "unclassified", "fresh", "reconstruction", "recorded", "not-recorded", "ready", "missing", "unavailable", "not-installed", "not-assessed", "invalid", "present", "none", "failed-terminal", "not-started", "prepared", "transmitted", "succeeded", "confirmed-no-effect", "possible-live", "closed-with-residue", "late-effect", "create", "delete", "retirement", "unselected-generated-cleanup", "create-empty", "create-with-value", "write-value", "update-policy", "delete-owned", "delete-reserved-slot", "not-sent", "acknowledged", "rejected", "managed", "deletion-acknowledged", "invalidation-confirmed", "provider-facts", "canonical", "mixed-completion", "not-qualified", "qualified", "other", "manual", "auto", "pending", "unobserved", "generated retire", "generated cleanup", "generated accept-retirement-risk", "apply", "unable to verify", "difference", "entry", "recipient", "output_binding", "output_target", "routing_rule", "domain", "store", "authority", "recovery", "configuration", "observation", "preflight", "candidate-create", "candidate-write", "candidate-sync", "candidate-verify", "rename", "directory-sync", "installed-verify", "close", "cleanup", "invalid-target", "source-alias", "reserved-path", "canceled", "deadline-exceeded", "io-failure", "verification-mismatch", "competing-replacement", "cleanup-failure", "removed", "cancelled", "unsupported", "unavailable", "required-public-fact-unavailable", "invalid-input", "missing-required-field", "duplicate-key", "duplicate-member", "unresolved-reference", "invalid-utf8", "limit-exceeded", "invalid-field-combination", "unsupported-schema", "unsupported-profile", "trust-basis-invalid", "domain-basis-invalid", "store-basis-invalid", "expired", "head-invalid", "proof-invalid", "selected-object-invalid", "selected-relation-invalid", "evidence-unavailable", "selected-object-unavailable", "read-contention", "diagnostics-incomplete", "unsupported-apply-change", "invalid-request", "state-invalid", "dependency-missing", "dependency-unavailable", "delivery-failed", "trust-invalid", "request", "recovery", "delivery", "dependencies", "source", "generated", "presentation", "existing", "source-invalid", "source-unavailable", "pending-edit", "target-occupied", "unsafe-path", "state-unavailable", "secret-unverifiable", "delivery-unknown", "cleanup-failed", "dependency-invalid", "source-changed", "presentation-failed", "tampered", "incompatible", "occurred", "admission", "load", "authentication", "encoding", "staging", "candidate-close", "candidate-verification", "installed-verification", "installed-close", "directory-close", "sink-close", "unauthorized-selection", "missing-selection", "root-loss", "changing-selection", "required-read-unavailable", "integrity-contradiction", "private-route-unavailable", "invalid-admission", "unrepresentable-value", "capacity-limit", "profile-unqualified",

	"", "ProductResult/v1", "ManifestFileResult/v2", "enkv/prepare-result/v2", "PreAdmissionRequestIdentity/v1", "PublicationPreview/v2", "PublicationEvidence/v3", "OutputPayload/v3", "selected", "not-selected", "generator", "output", "manifest-generator", "not-entered", "may-have-entered", "unproved", "qualified-no-effect", "observed", "both", "proposed", "acknowledged-equal", "unpublished", "value-changed", "binding-changed", "policy-changed", "retained-deletion", "secret-unchecked", "generated-unavailable", "blocked", "warning", "conflict", "capacity", "input", "target", "deadline", "prepared-source", "public-configuration", "public-basis", "prepared-keys", "candidate-bounds", "prepared-recipient", "candidate", "candidate-target", "local-cleanup", "input-close", "context", "output", "capture", "parse", "declaration", "construction", "resolution", "installation", "initialize", "rekey", "retire", "dispatch", "rotate-value-entry-value", "accept-generated-retirement-residue", "clean-owned-failure-residue", "identity-mismatch", "signature-invalid", "record-invalid", "platform-mismatch", "version-mismatch", "unsupported-protocol", "build-incomplete", "enkv/configuration/v3", "direct-candidate", "json", "yaml", "local", "official", "darwin/arm64", "linux/amd64", "presence", "name", "class", "source", "plain_value", "memberships", "generated", "epoch", "resource_contract", "config_contract", "lifecycle", "content_intent", "retirement", "completion", "display_name", "destination", "encodings", "groups", "encryption_provider", "encryption_selector", "encryption_public_key", "encryption_fingerprint", "wrap_profile", "protection_class", "targets", "provider", "canonical_target", "consumer_locator", "service_contract", "canonical_settings", "capabilities", "create_value_bounds", "write_value_bounds", "locator_requires_creation", "target_contract", "target_data", "payload_encoding", "consumer_policy", "destinations", "domain_id", "construction_profile", "region", "bucket", "prefix", "expected_owner", "recipient_id", "signing_provider", "signing_selector", "signing_public_key", "signing_fingerprint", "signing_role", "signing_profile", "enabled", "InitPayload/v1", "ComparisonPayload/v1", "ManifestPayload/v3", "MaterializationPayload/v1", "SealedArtifactPayload/v1", "ArtifactRequestIdentity/v1", "TransitionPayload/v1", "exact-local-pair-readback", "match", "mismatch", "partial", "unchecked", "entries", "plain_values", "secret_settings", "memberships", "recipients", "encryption", "generated", "outputs", "routing", "domain_store", "authority_recovery", "compatibility_profiles", "expected-entry-absent", "observed-entry-absent", "expected-setting-absent", "observed-setting-absent", "field-differs", "set-differs", "bytes-differ", "rotate", "unchanged", "policy-change", "access-change", "policy-and-access-change", "source-change", "removal", "after-successor-selection", "after-absence-selection", "no-output", "no-matching-service", "supplied", "plain", "secret",
}

func stockDiagnosticWord(value string) bool { return slices.Contains(stockDiagnosticWords, value) }

// projectObject only walks the fixed Product result containers used by this
// stock case. Unknown properties are deliberately not copied.
func (p *stockDiagnosticProjection) projectObject(raw json.RawMessage, context string) json.RawMessage {
	in, ok := stockDiagnosticDecodeObject(raw)
	if !ok {
		p.fail("invalid-object")
		return nil
	}
	out := stockDiagnosticObject{}
	var objects, rows, ids []string
	switch context {
	case "root":
		p.productEnvelope(out, in)
		p.fields(out, in, "word", "branch", "outcome", "source_cleanup", "result_delivery", "failure_reason")
		p.fields(out, in, "bool", "effects_available", "summary_counts_available", "related_work_available", "receipt_observation")
		p.fields(out, in, "uint", "reason_code", "current_domain_warning_bits", "deletion_acknowledged_count", "invalidation_confirmed_count", "unknown_count")
		p.fields(out, in, "word", "canonical_outcome")
		objects = []string{"effect_warnings", "summary_counts", "effects_commitment", "related_duties_commitment", "related_hazards_commitment", "active_operation", "transition", "view", "payload", "result", "issuance", "delivery", "failure", "artifact", "dependencies", "local_delivery", "recovery"}
		rows = []string{"effects", "outputs", "attempts", "duties", "hazards", "current_generations", "pending_releases", "next_actions", "diagnostics"}
		ids = []string{"related_duty_ids", "related_hazard_ids", "current_domain_duty_ids", "current_domain_hazard_ids"}
	case "request_identity":
		p.fields(out, in, "word", "schema", "operation_kind", "stage", "code", "source_schema", "source_profile", "format")
		p.fields(out, in, "id", "operation_id", "request_nonce", "input_file_id", "predecessor_digest", "recipient_image_digest", "sealed_artifact_digest")
		objects = []string{"target"}
	case "context":
		p.fields(out, in, "word", "operation")
		p.fields(out, in, "id", "operation_id", "request_id", "expected_domain_id")
	case "result":
		p.fields(out, in, "word", "state", "status", "stage", "code")
		for _, name := range []string{"outcome", "reason", "evidence"} {
			p.numberOrWord(out, in, name)
		}
		p.fields(out, in, "bool", "commit_may_have_occurred")
		p.fields(out, in, "id", "operation_id", "request_id", "requested_revision_id", "observed_revision_id", "observed_snapshot_id", "head_revision_id")
	case "observation":
		p.fields(out, in, "id", "domain_id", "head_revision_id", "snapshot_id")
	case "effect_warnings", "warnings":
		p.fields(out, in, "bool", "possible_live_residue", "possible_garbage", "late_effect", "invalidation_not_confirmed")
	case "summary_counts":
		p.fields(out, in, "uint", "effects", "outputs", "duties", "hazards", "changed_access", "succeeded", "failed", "neutral", "pending", "unknown", "preserved_residue", "no_effect_predecessors")
	case "effects_commitment", "related_duties_commitment", "related_hazards_commitment", "changed_subject_commitment":
		p.fields(out, in, "uint", "count", "length")
		p.fields(out, in, "id", "digest", "identity_root_digest")
	case "effects", "outputs", "attempts", "duties", "hazards", "current_generations", "pending_releases", "next_actions", "active_operation", "facts", "target":
		p.fields(out, in, "id", "domain_id", "operation_id", "attempt_id", "original_operation_id", "original_attempt_id", "duty_id", "hazard_id", "resource_incarnation_id", "generation_id", "descriptor_id", "executor_id", "credential_route_id", "resource_contract_id", "result_contract_id", "projection_commitment", "coordinate_id", "config_contract_id", "transmission_id", "result_id", "owner_id", "resource_digest", "lineage_id", "planned_value_slot_id", "planned_resource_incarnation_id", "predecessor_attempt_id", "retiring_duty_id", "cleanup_result_contract_id", "entry_incarnation_id", "origin_operation_id", "origin_attempt_id", "phase_id", "frontier_attempt_id", "inbox_id", "original_result_id", "selected_handoff_digest", "handoff_revision_id")
		p.fields(out, in, "word", "action", "kind", "command", "operation_kind", "state", "status", "exposure", "disposition", "outcome", "completion_class", "evidence_ceiling", "lifecycle_mode", "retirement_policy")
		p.fields(out, in, "bool", "retry_consumed", "remote_value_may_remain", "late_write_risk", "fenced", "cleanup_implementation_qualified")
		p.fields(out, in, "uint", "epoch", "object_length", "eligibility", "summary_class", "phase", "stage", "step")
		p.numberOrWord(out, in, "reason")
		if context == "facts" {
			for _, name := range []string{"replacement", "candidate_verification", "installed_verification", "native_completion", "plaintext_disk_disclosure", "candidate_cleanup"} {
				p.numberOrWord(out, in, name)
			}
			p.pathPresence(out, in, "residue_path")
		}
		if context == "target" {
			p.pathPresence(out, in, "path")
		}
		switch context {
		case "facts":
			objects = []string{"warnings", "evidence", "failure", "cleanup_failure"}
		case "target":
		default:
			objects = []string{"facts", "target"}
			rows = []string{"progress"}
		}
	case "payload", "view", "transition":
		p.fields(out, in, "word", "schema", "verdict", "basis", "origin")
		p.fields(out, in, "id", "init_id", "store_id", "domain_id", "snapshot_id", "head_revision_id", "ready_head_revision_id", "predecessor_revision_id", "requested_revision_id", "observed_revision_id", "descriptor_artifact_id", "manifest_artifact_id", "descriptor_digest", "artifact_digest", "selection_digest", "input_file_id", "predecessor_digest", "sealed_artifact_digest", "request_identity")
		p.fields(out, in, "uint", "artifact_length")
		p.stockFormatMatch(out, in)
		p.fields(out, in, "bool", "complete", "conditional", "domain_wide_warning", "diagnostics_complete")
		objects = []string{"publication", "effect_warnings", "result", "target", "recipient", "renderer", "readback", "facts", "changed_subject_commitment"}
		rows = []string{"entries", "included_entries", "excluded_entries", "actions", "outputs", "checked_scope", "diagnostics", "generated_entries"}
		ids = []string{"live_duty_ids", "live_hazard_ids"}
	case "publication":
		p.fields(out, in, "word", "schema", "basis", "origin")
		p.fields(out, in, "bool", "complete", "conditional", "domain_wide_warning")
		p.fields(out, in, "uint", "reason_code")
		rows = []string{"entries", "actions"}
	case "entries", "preview_entries":
		p.fields(out, in, "id", "coordinate_id", "binding_id", "entry_incarnation_id", "value_state_id")
		p.fields(out, in, "word", "basis", "origin")
		p.fields(out, in, "bool", "complete", "conditional", "domain_wide_warning", "remote_value_may_remain", "late_write_risk")
		p.fields(out, in, "uint", "reason_code", "slot", "value_source", "confidentiality_class")
		if context == "preview_entries" {
			p.projectWords(out, in, "actions")
		} else {
			rows = []string{"actions"}
		}
		ids = []string{"blocker_ids"}
	case "included_entries", "excluded_entries":
		p.fields(out, in, "id", "entry_incarnation_id")
		p.numberOrWord(out, in, "reason")
	case "actions":
		p.fields(out, in, "id", "projection_commitment", "attempt_id", "coordinate_id")
		p.fields(out, in, "word", "action", "disposition")
		p.fields(out, in, "uint", "reason_code")
		p.fields(out, in, "bool", "remote_value_may_remain", "late_write_risk")
		objects = []string{"evidence"}
		ids = []string{"blocker_ids"}
	case "evidence":
		p.fields(out, in, "word", "schema", "entry", "class")
		p.fields(out, in, "id", "response_contract_digest", "digest", "attempt_id", "result_id")
		p.fields(out, in, "uint", "normalized_status", "count", "length")
	case "progress":
		p.fields(out, in, "id", "attempt_id", "result_id")
		p.fields(out, in, "uint", "required_steps", "completed_steps")
		p.fields(out, in, "word", "completion_class")
		objects = []string{"evidence"}
	case "checked_scope":
		p.fields(out, in, "word", "family", "status")
	case "generated_entries":
		p.fields(out, in, "id", "current_incarnation_id", "current_generation_id", "active_operation_id", "retiring_duty_id", "retiring_incarnation_id", "retiring_generation_id", "retiring_resource_id", "retiring_original_operation_id", "retiring_original_attempt_id")
		p.fields(out, in, "word", "requested_action", "current_source", "requested_source", "current_confidentiality", "requested_confidentiality", "current_lifecycle_mode", "requested_lifecycle_mode", "current_retirement_policy", "requested_retirement_policy", "retirement_consequence", "future_content", "public_secret_content")
		p.fields(out, in, "uint", "current_epoch", "requested_epoch", "retiring_epoch")
		p.projectPlanningWords(out, in, "changed_public_fields")
		p.projectPlanningWords(out, in, "observed_blockers")
	case "recipient":
		p.fields(out, in, "id", "recipient_id")
		p.fields(out, in, "uint", "subject_kind")
		objects = []string{"binding"}
	case "binding":
		p.fields(out, in, "id", "binding_id", "binding_incarnation_id", "fingerprint")
		p.fields(out, in, "uint", "binding_serial", "provider", "protection_class")
	case "renderer":
		p.fields(out, in, "id", "protocol_id", "descriptor_id", "executor_id", "artifact_contract_id", "dependency_manifest_id", "artifact_id", "artifact_sha256")
		p.fields(out, in, "uint", "artifact_length")
	case "requirements", "installations":
		p.fields(out, in, "word", "role", "status", "reason", "platform", "source")
		p.fields(out, in, "id", "artifact")
		p.fields(out, in, "uint", "protocol_version")
		p.fields(out, in, "bool", "changed")
		objects = []string{"previous"}
	case "diagnostics":
		p.fields(out, in, "word", "reason", "outcome", "stage", "code")
		if value, ok := in["subject"]; ok && len(bytes.TrimSpace(value)) > 0 && bytes.TrimSpace(value)[0] == '"' {
			p.scalar(out, in, "subject", "word")
		} else {
			objects = []string{"subject"}
		}
		objects = append(objects, "source_location")
		rows = []string{"path"}
	case "subject":
		p.fields(out, in, "word", "kind")
	case "path":
		p.fields(out, in, "word", "field")
	case "source_location":
		p.fields(out, in, "uint", "line", "column")
	case "issuance":
		p.productEnvelope(out, in)
		p.fields(out, in, "word", "failure_reason")
		objects = []string{"payload", "result"}
		rows = []string{"diagnostics"}
	case "delivery", "failure", "cleanup_failure", "artifact", "dependencies", "local_delivery", "recovery", "previous", "readback":
		p.fields(out, in, "word", "schema", "failure_reason", "outcome", "status", "assessment", "branch", "code", "result_delivery", "source_cleanup", "candidate_cleanup", "candidate_verification", "installed_verification", "native_completion", "replacement", "plaintext_disk_disclosure")
		p.numberOrWord(out, in, "reason")
		p.numberOrWord(out, in, "stage")
		p.fields(out, in, "id", "digest", "renderer_artifact_id", "domain", "head", "editable_digest", "generated_digest")
		if context == "previous" {
			p.scalar(out, in, "artifact", "id")
		}
		p.fields(out, in, "uint", "length", "protocol_version")
		if context == "artifact" {
			p.stockFormatMatch(out, in)
		}
		p.fields(out, in, "bool", "all_declared_ready", "minimum_administrative_ready", "changed", "cleanup_failed")
		for _, name := range []string{"path", "destination", "target_path", "editable_path", "generated_path", "manifest_path", "recovery_source", "residue_path"} {
			p.pathPresence(out, in, name)
		}
		switch context {
		case "delivery":
			objects = []string{"artifact", "failure"}
		case "local_delivery":
			objects = []string{"readback"}
		case "dependencies":
			rows = []string{"requirements", "installations"}
		}
	default:
		p.fail("unsupported-container")
	}
	for _, name := range objects {
		p.projectMember(out, in, name)
	}
	for _, name := range rows {
		if context == "root" && name == "outputs" && p.projectStringCount(out, in, name) {
			continue
		}
		rowContext := name
		if context == "publication" && name == "entries" {
			rowContext = "preview_entries"
		}
		p.projectRows(out, in, name, rowContext)
	}
	for _, name := range ids {
		p.projectIDs(out, in, name)
	}
	body, err := stockDiagnosticEncodeObject(out)
	if err != nil {
		p.fail("encoding-failed")
		return nil
	}
	return body
}

func (p *stockDiagnosticProjection) textOrID(out stockDiagnosticObject, in map[string]json.RawMessage, name string) {
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return
	}
	var value string
	if jsonv2.Unmarshal(raw, &value) == nil && value == "none" {
		p.scalar(out, in, name, "word")
		return
	}
	p.scalar(out, in, name, "id")
}

func (p *stockDiagnosticProjection) numberOrWord(out stockDiagnosticObject, in map[string]json.RawMessage, name string) {
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return
	}
	value := bytes.TrimSpace(raw)
	kind := "uint"
	if len(value) != 0 && value[0] == '"' {
		kind = "word"
	}
	p.scalar(out, in, name, kind)
}

// A set result's outputs are paths. Preserve only the count, never the paths.
func (p *stockDiagnosticProjection) projectStringCount(out stockDiagnosticObject, in map[string]json.RawMessage, name string) bool {
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return false
	}
	if stockDiagnosticNull(raw) {
		out[name+"_count"] = json.RawMessage("null")
		return true
	}
	var rows []json.RawMessage
	if jsonv2.Unmarshal(raw, &rows) != nil || rows == nil {
		return false
	}
	for _, row := range rows {
		valueBytes := bytes.TrimSpace(row)
		if len(valueBytes) == 0 || valueBytes[0] != '"' {
			return false
		}
		var value string
		if jsonv2.Unmarshal(row, &value) != nil {
			return false
		}
	}
	body, err := json.Marshal(len(rows))
	if err != nil {
		p.fail("encoding-failed")
		return true
	}
	out[name+"_count"] = body
	return true
}

func (p *stockDiagnosticProjection) projectWords(out stockDiagnosticObject, in map[string]json.RawMessage, name string) {
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return
	}
	if stockDiagnosticNull(raw) {
		out[name] = json.RawMessage("null")
		return
	}
	var rows []json.RawMessage
	if jsonv2.Unmarshal(raw, &rows) != nil || rows == nil {
		p.fail("invalid-array")
		return
	}
	values := make([]json.RawMessage, 0, len(rows))
	for _, item := range rows {
		var value string
		if jsonv2.Unmarshal(item, &value) != nil || !slices.Contains([]string{"create-empty", "create-with-value", "write-value", "update-policy", "delete-owned", "delete-reserved-slot"}, value) {
			p.fail("invalid-enum")
			break
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			p.fail("encoding-failed")
			break
		}
		values = append(values, encoded)
	}
	body, err := json.Marshal(values)
	if err != nil {
		p.fail("encoding-failed")
		return
	}
	out[name] = body
}

func (p *stockDiagnosticProjection) projectPlanningWords(out stockDiagnosticObject, in map[string]json.RawMessage, name string) {
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return
	}
	if stockDiagnosticNull(raw) {
		out[name] = json.RawMessage("null")
		return
	}
	var rows []json.RawMessage
	if jsonv2.Unmarshal(raw, &rows) != nil || rows == nil {
		p.fail("invalid-array")
		return
	}
	allowed := []string{"presence", "class", "source", "memberships", "epoch", "config_contract", "resource_contract", "lifecycle", "content_intent", "retirement", "completion", "stale-generated-epoch", "initial-generated-epoch-not-zero", "generated-intent-conflict", "confidentiality-conversion", "retiring-generation-present", "active-operation-present"}
	values := make([]json.RawMessage, 0, len(rows))
	for _, item := range rows {
		var value string
		if jsonv2.Unmarshal(item, &value) != nil || !slices.Contains(allowed, value) {
			p.fail("invalid-enum")
			break
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			p.fail("encoding-failed")
			break
		}
		values = append(values, encoded)
	}
	body, err := json.Marshal(values)
	if err != nil {
		p.fail("encoding-failed")
		return
	}
	out[name] = body
}

func (p *stockDiagnosticProjection) projectRows(out stockDiagnosticObject, in map[string]json.RawMessage, name, rowContext string) {
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return
	}
	if stockDiagnosticNull(raw) {
		out[name] = json.RawMessage("null")
		return
	}
	var rows []json.RawMessage
	if jsonv2.Unmarshal(raw, &rows) != nil || rows == nil {
		p.fail("invalid-array")
		return
	}
	projected := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		item := p.projectObject(row, rowContext)
		if item != nil {
			projected = append(projected, item)
		}
		if p.fault != "" {
			break
		}
	}
	body, err := json.Marshal(projected)
	if err != nil {
		p.fail("encoding-failed")
		return
	}
	out[name] = body
}

func (p *stockDiagnosticProjection) projectIDs(out stockDiagnosticObject, in map[string]json.RawMessage, name string) {
	raw, ok := in[name]
	if !ok || p.fault != "" {
		return
	}
	if stockDiagnosticNull(raw) {
		out[name] = json.RawMessage("null")
		return
	}
	var rows []json.RawMessage
	if jsonv2.Unmarshal(raw, &rows) != nil || rows == nil {
		p.fail("invalid-array")
		return
	}
	values := make([]json.RawMessage, 0, len(rows))
	for _, item := range rows {
		var text string
		if jsonv2.Unmarshal(item, &text) != nil || !stockDiagnosticHex(text, 32) {
			p.fail("invalid-id")
			break
		}
		value, err := json.Marshal(text)
		if err != nil {
			p.fail("encoding-failed")
			break
		}
		values = append(values, value)
	}
	body, err := json.Marshal(values)
	if err != nil {
		p.fail("encoding-failed")
		return
	}
	out[name] = body
}

func stockProjectDiagnostic(body []byte) (json.RawMessage, string) {
	if len(body) == 0 || len(body) > operatorCLICaptureLimit || !jsontext.Value(body).IsValid() {
		return nil, "malformed"
	}
	object, ok := stockDiagnosticDecodeObject(body)
	if !ok {
		return nil, "malformed"
	}
	var schema string
	if jsonv2.Unmarshal(object["schema"], &schema) != nil || !slices.Contains([]string{"ProductResult/v1", "ManifestFileResult/v2", "enkv/prepare-result/v2", "PreAdmissionRequestIdentity/v1", "PublicationPreview/v2"}, schema) {
		return nil, "unsupported-schema"
	}
	p := stockDiagnosticProjection{}
	result := p.projectObject(body, "root")
	return result, p.fault
}

func stockDiagnosticPath(inv records.Invocation, ordinal uint32) string {
	return filepath.Join(inv.StateDir, fmt.Sprintf("stock-result-%02d.json", ordinal))
}

// retainStockDiagnostic writes only a closed observation, and never supplies
// cleanup, replay, or Product-completeness authority.
func retainStockDiagnostic(inv records.Invocation, value stockDiagnostic, body []byte) (string, uint32, string, error) {
	value.Schema = 1
	value.ResultSHA256 = bodyDigest(body)
	value.DigestScope = "complete"
	value.CapturedBytes = uint32(len(body))
	value.Status = "observed"
	value.Uncaptured = []string{"names", "filesystem-paths", "locators", "values", "warning-text", "source-identifiers", "semantic-completeness"}
	if value.StdoutOverflow {
		value.DigestScope = "captured-prefix"
	}
	value.Result, value.Fault = stockProjectDiagnostic(body)
	if !value.Started {
		value.Fault = "start-failed"
	}
	if value.StdoutOverflow {
		value.Fault = "stdout-overflow"
	}
	if value.Fault != "" || !value.ProductJoined || value.StderrOverflow || value.TimedOut || value.StartSaveFailed || value.CLIChanged {
		value.Status = "partial"
		if len(value.Result) == 0 {
			value.Status = "unavailable"
		}
	}
	if !stockDiagnosticMetadata(value) || len(body) > operatorCLICaptureLimit || value.StderrCapturedBytes > operatorCLICaptureLimit {
		return "", 0, "write-failed", errInventory
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > 3*len(body)+stockDiagnosticHeaderAllowance || len(encoded)+1 > stockDiagnosticFileLimit {
		return "", 0, "write-failed", errInventory
	}
	path := stockDiagnosticPath(inv, value.Ordinal)
	if err := records.WriteJSONExclusive(path, value, stockDiagnosticFileLimit); err != nil {
		return "", 0, "write-failed", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return "", 0, "write-failed", errInventory
	}
	readback, err := records.ReadJSONBytes(path, stockDiagnosticFileLimit)
	expected := append(encoded, '\n')
	if err != nil || !bytes.Equal(readback, expected) {
		return "", 0, "write-failed", errInventory
	}
	return bodyDigest(expected), uint32(len(expected)), value.Status, nil
}
