package records

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

const PublicConfigurationEvidenceVersion uint16 = 1
const MaximumPublicConfigurationSnapshotBytes = 32 << 20
const MaximumPublicConfigurationManifestBytes = 64 << 10
const MaximumPublicConfigurationCaptures = 64
const MaximumPublicConfigurationCaptureBytes = 1 << 20

// Current public executions have one writer and one final fresh worker. The
// coordinator retains the original cleanup plus at most two cleanup retries
// (retryLiveCleanup's ordinal2..3 loop), including failed joined attempts.
const maximumPublicConfigurationWorkers = 5
const maximumPublicConfigurationIntents = 500000
const maximumPublicConfigurationAttempts = 1000000

// These are intake ceilings, not claims that a generic admitted request budget
// produces this many rows. The selected public graph bound is recorded separately.

// This private wire owner preserves the original ledger JSON spelling. It is
// never copied as a raw retained export: Source and ControlledInventory stay private.
type PublicConfigurationOwnership struct {
	Outputs                                *PublicOutputEvidence `json:"outputs,omitempty"`
	Version                                int                   `json:"version"`
	RunID, Prefix, Binding, Source, Domain string
	PreflightEmpty                         bool
	ControlledInventory                    string `json:"controlled_inventory,omitempty"`
	Captures                               []PublicConfigurationCaptureRegistration
	Deleted                                []string
}
type PublicConfigurationCaptureRegistration struct {
	Path, SHA256                                             string
	Complete                                                 bool
	Ordinal                                                  uint16
	ParentWorker, ParentNonce, ParentRole, Actor, NativeKind string
	ExitCode                                                 int
	Bytes                                                    uint64
}

type PublicConfigurationToken struct {
	Family contract.Family `json:"family"`
	Value  []byte          `json:"value"`
}
type PublicConfigurationEvidenceRef struct {
	SchemaVersion uint16 `json:"schema_version"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Bytes         uint64 `json:"bytes"`
}
type PublicConfigurationWorkerJoin struct {
	Worker           string `json:"worker"`
	Nonce            string `json:"nonce"`
	Role             string `json:"role"`
	Actor            string `json:"actor"`
	InvocationSHA256 string `json:"invocation_sha256"`
	ResultSHA256     string `json:"result_sha256"`
	Started          bool   `json:"started"`
	Joined           bool   `json:"joined"`
	Process          string `json:"process"`
}
type PublicConfigurationEvidenceBinding struct {
	RunID, Scenario, Provider, RecoveryMode, Prefix, Binding string
	Workers                                                  []PublicConfigurationWorkerJoin
	Source                                                   Source
	CaseIdentitySHA256, BuildClosureSHA256, OverlaySHA256    string
}
type PublicConfigurationEvidenceSnapshot struct {
	Outputs                  *PublicOutputEvidence                 `json:"outputs,omitempty"`
	Generator                *PublicConfigurationGeneratorEvidence `json:"generator,omitempty"`
	Version                  uint16                                `json:"version"`
	RunID                    string                                `json:"run_id"`
	Scenario                 string                                `json:"scenario"`
	Provider                 string                                `json:"provider"`
	RecoveryMode             string                                `json:"recovery_mode"`
	Prefix                   string                                `json:"prefix"`
	Binding                  string                                `json:"binding"`
	PreflightEmpty           bool                                  `json:"preflight_empty"`
	Domains                  []contract.ID                         `json:"domains"`
	Captures                 []PublicConfigurationCaptureReceipt   `json:"captures"`
	Controlled               *PublicConfigurationInventoryEvidence `json:"controlled,omitempty"`
	Cleanup                  PublicConfigurationInventoryEvidence  `json:"cleanup"`
	OriginalOwnershipSHA256  string                                `json:"original_ownership_sha256"`
	OriginalControlledSHA256 string                                `json:"original_controlled_sha256,omitempty"`
	OriginalCleanupSHA256    string                                `json:"original_cleanup_sha256,omitempty"`
}
type PublicConfigurationCaptureReceipt struct {
	Ordinal        uint16 `json:"ordinal"`
	ParentWorker   string `json:"parent_worker"`
	ParentNonce    string `json:"parent_nonce"`
	ParentRole     string `json:"parent_role"`
	Actor          string `json:"actor"`
	NativeKind     string `json:"native_kind"`
	SourceRelative string `json:"source_relative"`
	Complete       bool   `json:"complete"`
	ExitCode       int    `json:"exit_code"`
	SHA256         string `json:"sha256"`
	Bytes          uint64 `json:"bytes"`
}
type PublicConfigurationInventoryEvidence struct {
	RunID                     string                              `json:"run_id"`
	Prefix                    string                              `json:"prefix"`
	Binding                   string                              `json:"binding"`
	Domain                    contract.ID                         `json:"domain"`
	Intents                   []PublicConfigurationObjectIntent   `json:"intents"`
	Deleted                   []PublicConfigurationDeleted        `json:"deleted"`
	CleanupAttempts           []PublicConfigurationCleanupAttempt `json:"cleanup_attempts"`
	TokenSource               *PublicConfigurationTokenSource     `json:"token_source"`
	OriginalTokenSourceSHA256 string                              `json:"original_token_source_sha256"`
}
type PublicConfigurationTokenSource struct {
	Version      uint16                                `json:"version"`
	RunID        string                                `json:"run_id"`
	Prefix       string                                `json:"prefix"`
	Binding      string                                `json:"binding"`
	Domain       contract.ID                           `json:"domain"`
	Observations []PublicConfigurationTokenObservation `json:"observations"`
}
type PublicConfigurationTokenObservation struct {
	Kind           string                   `json:"kind"`
	Index          uint32                   `json:"index"`
	TargetIntent   uint32                   `json:"target_intent"`
	AttemptOrdinal uint8                    `json:"attempt_ordinal"`
	Key            string                   `json:"key"`
	Digest         string                   `json:"digest"`
	Bytes          uint64                   `json:"bytes"`
	Token          PublicConfigurationToken `json:"token"`
}
type PublicConfigurationObjectIntent struct {
	Key            string                    `json:"key"`
	Digest         string                    `json:"digest"`
	Bytes          uint64                    `json:"bytes"`
	Kind           string                    `json:"kind"`
	ConditionToken *PublicConfigurationToken `json:"condition_token,omitempty"`
	State          string                    `json:"state"`
}
type PublicConfigurationDeleted struct {
	Key    string `json:"key"`
	Cutoff uint32 `json:"cutoff"`
}
type PublicConfigurationCleanupAttempt struct {
	TargetIntent uint32                   `json:"target_intent"`
	Ordinal      uint8                    `json:"ordinal"`
	Recovery     string                   `json:"recovery,omitempty"`
	GrantRunID   string                   `json:"grant_run_id,omitempty"`
	CaseSHA256   string                   `json:"case_sha256,omitempty"`
	LimitsSHA256 string                   `json:"limits_sha256,omitempty"`
	Key          string                   `json:"key"`
	Digest       string                   `json:"digest"`
	Bytes        uint64                   `json:"bytes"`
	Token        PublicConfigurationToken `json:"token"`
	Cutoff       uint32                   `json:"cutoff"`
	State        string                   `json:"state"`
	Failure      *HarnessFailure          `json:"failure,omitempty"`
}
type PublicConfigurationEvidenceFile struct {
	Kind    string `json:"kind"`
	Ordinal uint16 `json:"ordinal"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Bytes   uint64 `json:"bytes"`
}
type PublicConfigurationEvidenceManifest struct {
	Version            uint16                            `json:"version"`
	RunID              string                            `json:"run_id"`
	Scenario           string                            `json:"scenario"`
	Provider           string                            `json:"provider"`
	RecoveryMode       string                            `json:"recovery_mode"`
	Source             Source                            `json:"source"`
	CaseIdentitySHA256 string                            `json:"case_identity_sha256"`
	BuildClosureSHA256 string                            `json:"build_closure_sha256"`
	OverlaySHA256      string                            `json:"overlay_sha256"`
	Workers            []PublicConfigurationWorkerJoin   `json:"workers"`
	Snapshot           PublicConfigurationEvidenceFile   `json:"snapshot"`
	Captures           []PublicConfigurationEvidenceFile `json:"captures"`
}

// Validate binds a public reference to the caller's exact case sequence. It
// does not read files, admit a worker or grant continuation/cleanup authority.
func (v PublicConfigurationEvidenceRef) Validate(sequence int) error {
	if sequence < 0 || v.SchemaVersion != PublicConfigurationEvidenceVersion ||
		v.Path != fmt.Sprintf("evidence/public-configuration/%04d/manifest.json", sequence) ||
		!validHex(v.SHA256, 32) || v.Bytes == 0 || v.Bytes > MaximumPublicConfigurationManifestBytes {
		return errRecord
	}
	return nil
}

func publicEvidenceFamily(provider string) contract.Family {
	if provider == "aws" {
		return contract.AWS
	}
	if provider == "gcp" {
		return contract.GCP
	}
	return 0
}
func publicEvidenceIdentity(run, scenario, provider, recovery, prefix, binding string) bool {
	return ValidRunID(run) && catalog.HasFixtureCapability(scenario, catalog.FixturePublicConfiguration) &&
		publicEvidenceFamily(provider).Valid() && (recovery == "enabled" || recovery == "disabled") &&
		contract.StorePrefixValid(publicEvidenceFamily(provider), prefix) &&
		strings.HasPrefix(prefix, "enkv-test/"+run+"/") && validHex(binding, 32)
}
func publicEvidenceToken(t PublicConfigurationToken, family contract.Family) bool {
	return t.Family == family && (contract.TokenView{Family: t.Family, Value: t.Value}).Valid()
}
func publicEvidenceObject(prefix, key string) bool {
	if len(key) > 1024 {
		return false
	}
	if key == prefix+"/HEAD" {
		return true
	}
	rest, ok := strings.CutPrefix(key, prefix+"/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 && len(parts) != 4 || !validHex(parts[0], 32) || parts[0] == strings.Repeat("0", 64) {
		return false
	}
	if len(parts) == 3 {
		return (parts[1] == "result" || parts[1] == "configuration") && validHex(parts[2], 32) && parts[2] != strings.Repeat("0", 64)
	}
	switch parts[1] {
	case "member", "recipient", "access", "support", "admin-index", "root":
	default:
		return false
	}
	index, err := strconv.ParseUint(parts[2], 10, 16)
	return err == nil && strconv.FormatUint(index, 10) == parts[2] && validHex(parts[3], 32) && parts[3] != strings.Repeat("0", 64)
}
func publicEvidenceObjectFacts(prefix, key, digest string, size uint64) bool {
	return publicEvidenceObject(prefix, key) && validHex(digest, 32) && size > 0 && size <= contract.MaxValueEntryPageLength
}
func publicEvidenceNativeKind(kind string) bool {
	return kind == "cli" || kind == "consumer"
}
func publicEvidenceCaptureRelative(path string) bool {
	value, ok := strings.CutPrefix(path, "public-command-")
	if !ok {
		return false
	}
	value, ok = strings.CutSuffix(value, "/capture.jsonl")
	if !ok {
		return false
	}
	n, err := strconv.ParseUint(value, 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == value
}
func publicEvidenceWorker(v PublicConfigurationWorkerJoin) bool {
	if !labelPattern.MatchString(v.Worker) || !validHex(v.Nonce, 16) || !validRole(v.Role) ||
		v.Actor != "" && !labelPattern.MatchString(v.Actor) || !validHex(v.InvocationSHA256, 32) || !validHex(v.ResultSHA256, 32) {
		return false
	}
	switch v.Process {
	case "passed", "process_failed", "timed_out", "interrupted", "resource_limit", "output_limit_exceeded":
		return v.Started && v.Joined
	default:
		return false
	}
}
func publicEvidenceWorkers(values []PublicConfigurationWorkerJoin) bool {
	if len(values) == 0 || len(values) > maximumPublicConfigurationWorkers {
		return false
	}
	workers, nonces := map[string]bool{}, map[string]bool{}
	for _, v := range values {
		if !publicEvidenceWorker(v) || workers[v.Worker] || nonces[v.Nonce] {
			return false
		}
		workers[v.Worker], nonces[v.Nonce] = true, true
	}
	roles := map[string]int{}
	for _, row := range values {
		switch row.Role {
		case "writer", "fresh_after", "cleanup":
		default:
			return false
		}
		roles[row.Role]++
	}
	return roles["writer"] == 1 && roles["fresh_after"] == 1 && roles["cleanup"] >= 1 && roles["cleanup"] <= 3
}

// Validate checks original observation shape. The inventory owner supplies
// provenance before JSON string serialization; this method never reconstructs it.
func (v PublicConfigurationTokenSource) Validate() error {
	if v.Version != PublicConfigurationEvidenceVersion || !ValidRunID(v.RunID) ||
		!validHex(v.Binding, 32) || v.Domain.IsZero() || len(v.Prefix) == 0 || len(v.Prefix) > contract.MaxStorePrefixLength ||
		len(v.Observations) > maximumPublicConfigurationIntents+maximumPublicConfigurationAttempts {
		return errRecord
	}
	seen := map[struct {
		kind  string
		index uint32
	}]bool{}
	for _, row := range v.Observations {
		key := struct {
			kind  string
			index uint32
		}{row.Kind, row.Index}
		if seen[key] || !publicEvidenceObjectFacts(v.Prefix, row.Key, row.Digest, row.Bytes) ||
			!(contract.TokenView{Family: row.Token.Family, Value: row.Token.Value}).Valid() {
			return errRecord
		}
		seen[key] = true
		switch row.Kind {
		case "intent-condition":
			if row.Index >= maximumPublicConfigurationIntents || row.TargetIntent != row.Index || row.AttemptOrdinal != 0 {
				return errRecord
			}
		case "cleanup-condition":
			if row.Index >= maximumPublicConfigurationAttempts || row.TargetIntent >= maximumPublicConfigurationIntents || row.AttemptOrdinal < 1 || row.AttemptOrdinal > 4 {
				return errRecord
			}
		default:
			return errRecord
		}
	}
	return nil
}

func (v PublicConfigurationInventoryEvidence) validate(run, prefix, binding string, family contract.Family) error {
	if v.RunID != run || v.Prefix != prefix || v.Binding != binding || v.Domain.IsZero() ||
		len(v.Intents) > maximumPublicConfigurationIntents || len(v.CleanupAttempts) > maximumPublicConfigurationAttempts ||
		len(v.Deleted) > len(v.Intents) || v.TokenSource == nil || !validHex(v.OriginalTokenSourceSHA256, 32) || v.TokenSource.Validate() != nil ||
		v.TokenSource.RunID != run || v.TokenSource.Prefix != prefix || v.TokenSource.Binding != binding || v.TokenSource.Domain != v.Domain {
		return errRecord
	}
	tokens := 0
	for _, row := range v.Intents {
		if !publicEvidenceObjectFacts(prefix, row.Key, row.Digest, row.Bytes) {
			return errRecord
		}
		switch row.Kind {
		case "create_head", "create", "compare_and_swap", "fixture_create":
		default:
			return errRecord
		}
		if row.Kind == "compare_and_swap" {
			if row.ConditionToken == nil || !publicEvidenceToken(*row.ConditionToken, family) {
				return errRecord
			}
			tokens++
		} else if row.ConditionToken != nil {
			return errRecord
		}
		switch row.State {
		case "pending", "unknown", "acknowledged", "refused", "not_sent":
		case "observed":
			if row.Kind != "create" && row.Kind != "create_head" {
				return errRecord
			}
		default:
			return errRecord
		}
	}
	deleted := map[string]bool{}
	for _, row := range v.Deleted {
		if !publicEvidenceObject(prefix, row.Key) || deleted[row.Key] || uint64(row.Cutoff) > uint64(len(v.Intents)) {
			return errRecord
		}
		deleted[row.Key] = true
	}
	for _, row := range v.CleanupAttempts {
		if uint64(row.TargetIntent) >= uint64(len(v.Intents)) || row.Ordinal < 1 || row.Ordinal > 4 || row.Cutoff > row.TargetIntent ||
			!publicEvidenceToken(row.Token, family) {
			return errRecord
		}
		target := v.Intents[row.TargetIntent]
		if target.Key != row.Key || target.Digest != row.Digest || target.Bytes != row.Bytes {
			return errRecord
		}
		switch row.State {
		case "pending", "acknowledged":
			if row.Failure != nil {
				return errRecord
			}
		case "failed":
			if row.Failure == nil {
				return errRecord
			}
		case "settled":
		default:
			return errRecord
		}
		if row.Failure != nil && !row.Failure.Validate() {
			return errRecord
		}
		switch row.Recovery {
		case "":
			if row.Ordinal != 1 || row.GrantRunID != "" || row.CaseSHA256 != "" || row.LimitsSHA256 != "" {
				return errRecord
			}
		case "gcp_exact_generation":
			if row.Ordinal < 2 || row.Ordinal > 3 || row.GrantRunID != "" || row.CaseSHA256 != "" || row.LimitsSHA256 != "" {
				return errRecord
			}
		case "gcp_exact_generation_grant", "aws_retired_fixture_grant", "admission_no_send_grant":
			if row.Ordinal < 2 || !ValidRunID(row.GrantRunID) || !validHex(row.CaseSHA256, 32) || !validHex(row.LimitsSHA256, 32) {
				return errRecord
			}
		default:
			return errRecord
		}
		tokens++
	}
	if tokens != len(v.TokenSource.Observations) {
		return errRecord
	}
	// Exact positional bijection; array order and all original occurrences stay intact.
	for _, row := range v.TokenSource.Observations {
		if row.Token.Family != family {
			return errRecord
		}
		if row.Kind == "intent-condition" {
			if uint64(row.Index) >= uint64(len(v.Intents)) {
				return errRecord
			}
			target := v.Intents[row.Index]
			if target.Kind != "compare_and_swap" || target.ConditionToken == nil || row.Key != target.Key || row.Digest != target.Digest || row.Bytes != target.Bytes ||
				row.Token.Family != target.ConditionToken.Family || !bytes.Equal(row.Token.Value, target.ConditionToken.Value) {
				return errRecord
			}
		} else {
			if uint64(row.Index) >= uint64(len(v.CleanupAttempts)) {
				return errRecord
			}
			target := v.CleanupAttempts[row.Index]
			if row.TargetIntent != target.TargetIntent || row.AttemptOrdinal != target.Ordinal || row.Key != target.Key || row.Digest != target.Digest || row.Bytes != target.Bytes ||
				row.Token.Family != target.Token.Family || !bytes.Equal(row.Token.Value, target.Token.Value) {
				return errRecord
			}
		}
	}
	return nil
}

func (v PublicConfigurationEvidenceSnapshot) Validate(expected PublicConfigurationEvidenceBinding) error {
	if v.Version != PublicConfigurationEvidenceVersion || !publicEvidenceIdentity(v.RunID, v.Scenario, v.Provider, v.RecoveryMode, v.Prefix, v.Binding) ||
		v.RunID != expected.RunID || v.Scenario != expected.Scenario || v.Provider != expected.Provider || v.RecoveryMode != expected.RecoveryMode ||
		v.Prefix != expected.Prefix || expected.Binding != "" && v.Binding != expected.Binding || !validHex(v.OriginalOwnershipSHA256, 32) ||
		!v.PreflightEmpty || len(v.Captures) == 0 || len(v.Captures) > MaximumPublicConfigurationCaptures || len(v.Domains) > MaximumPublicConfigurationCaptures {
		return errRecord
	}
	publicCase, _ := catalog.PublicConfiguration(v.Scenario)
	if publicCase.Output != (v.Outputs != nil) || v.Outputs != nil && (v.Outputs.Version == 3 && publicCase.Condition != "manifest" || v.Outputs.Validate(len(v.Captures), publicCase.OutputScopes(v.Provider)) != nil) {
		return errRecord
	}
	if v.Outputs != nil {
		cleanup, observation := v.Captures[v.Outputs.CleanupCaptureOrdinal], v.Captures[v.Outputs.ObservationCaptureOrdinal]
		if !cleanup.Complete || !observation.Complete || cleanup.ExitCode != 0 || observation.ExitCode != 0 || cleanup.ParentRole != "cleanup" || observation.ParentRole != "cleanup" || cleanup.NativeKind != "cli" || observation.NativeKind != "cli" || cleanup.ParentWorker != observation.ParentWorker || cleanup.ParentNonce != observation.ParentNonce {
			return errRecord
		}
	}
	generated := catalog.HasFixtureCapability(v.Scenario, catalog.FixtureGeneratedProcess)
	if generated != (v.Generator != nil) || v.Generator != nil && v.Generator.Validate(v.RunID, v.Scenario) != nil {
		return errRecord
	}
	domains := map[contract.ID]bool{}
	for _, id := range v.Domains {
		if id.IsZero() || domains[id] {
			return errRecord
		}
		domains[id] = true
	}
	if v.Outputs != nil && v.Outputs.Version == 3 {
		for _, row := range v.Outputs.PassiveCoordinates {
			if !domains[row.Before.DomainID] || row.Before.DomainID != v.Cleanup.Domain {
				return errRecord
			}
		}
	}
	parents := map[string]PublicConfigurationWorkerJoin{}
	if expected.Workers != nil {
		if !publicEvidenceWorkers(expected.Workers) {
			return errRecord
		}
		for _, row := range expected.Workers {
			parents[row.Worker] = row
		}
	}
	paths := map[string]bool{}
	for i, row := range v.Captures {
		if row.Ordinal != uint16(i) || !labelPattern.MatchString(row.ParentWorker) || !validHex(row.ParentNonce, 16) || !validRole(row.ParentRole) ||
			!labelPattern.MatchString(row.Actor) || !publicEvidenceNativeKind(row.NativeKind) || !publicEvidenceCaptureRelative(row.SourceRelative) ||
			paths[row.SourceRelative] || row.ExitCode < 0 || row.ExitCode > 255 || row.Bytes > MaximumPublicConfigurationCaptureBytes ||
			!row.Complete || !validHex(row.SHA256, 32) || row.Bytes == 0 {
			return errRecord
		}
		paths[row.SourceRelative] = true
		if expected.Workers != nil {
			parent, ok := parents[row.ParentWorker]
			if !ok || row.ParentNonce != parent.Nonce || row.ParentRole != parent.Role {
				return errRecord
			}
		}
	}
	family := publicEvidenceFamily(v.Provider)
	if v.Controlled != nil {
		if !validHex(v.OriginalControlledSHA256, 32) || v.Controlled.validate(v.RunID, v.Prefix, v.Binding, family) != nil {
			return errRecord
		}
	} else if v.OriginalControlledSHA256 != "" {
		return errRecord
	}
	if !validHex(v.OriginalCleanupSHA256, 32) || v.Cleanup.validate(v.RunID, v.Prefix, v.Binding, family) != nil {
		return errRecord
	}
	return nil
}

func (v PublicConfigurationEvidenceManifest) Validate(expected PublicConfigurationEvidenceBinding) error {
	if v.Version != PublicConfigurationEvidenceVersion || v.RunID != expected.RunID || v.Scenario != expected.Scenario || v.Provider != expected.Provider ||
		v.RecoveryMode != expected.RecoveryMode || !ValidRunID(v.RunID) || !catalog.HasFixtureCapability(v.Scenario, catalog.FixturePublicConfiguration) ||
		!publicEvidenceFamily(v.Provider).Valid() || v.RecoveryMode != "enabled" && v.RecoveryMode != "disabled" ||
		!reflect.DeepEqual(v.Source, expected.Source) || !validHex(v.Source.Revision, 20) ||
		v.Source.PublicSourcesSHA256 != "" && !validHex(v.Source.PublicSourcesSHA256, 32) ||
		v.Source.Dirty && (v.Source.DirtyDiffSHA256 == nil || !validHex(*v.Source.DirtyDiffSHA256, 32)) || !v.Source.Dirty && v.Source.DirtyDiffSHA256 != nil ||
		!validHex(v.CaseIdentitySHA256, 32) || v.CaseIdentitySHA256 != expected.CaseIdentitySHA256 ||
		!validHex(v.BuildClosureSHA256, 32) || v.BuildClosureSHA256 != expected.BuildClosureSHA256 ||
		!validHex(v.OverlaySHA256, 32) || v.OverlaySHA256 != expected.OverlaySHA256 || !publicEvidenceWorkers(v.Workers) ||
		expected.Workers != nil && !reflect.DeepEqual(v.Workers, expected.Workers) ||
		v.Snapshot.Kind != "snapshot" || v.Snapshot.Ordinal != 0 || v.Snapshot.Path != "ownership.json" ||
		!validHex(v.Snapshot.SHA256, 32) || v.Snapshot.Bytes == 0 || v.Snapshot.Bytes > MaximumPublicConfigurationSnapshotBytes ||
		len(v.Captures) == 0 || len(v.Captures) > MaximumPublicConfigurationCaptures {
		return errRecord
	}
	for i, row := range v.Captures {
		if row.Kind != "native-capture" || row.Ordinal != uint16(i) || row.Path != fmt.Sprintf("captures/%04d.jsonl", i) ||
			!validHex(row.SHA256, 32) || row.Bytes == 0 || row.Bytes > MaximumPublicConfigurationCaptureBytes {
			return errRecord
		}
	}
	return nil
}

// Reject unknown and duplicate fields before typed decoding. The closed DTO's
// maximum nesting depth is below12; no arbitrary metadata tree is admitted.
func publicEvidenceJSON(body []byte, limit int, value any) error {
	if len(body) == 0 || len(body) > limit {
		return errRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	fields := map[reflect.Type]map[string]reflect.Type{}
	var item func(reflect.Type, int) error
	item = func(typ reflect.Type, depth int) error {
		if depth > 12 {
			return errRecord
		}
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		token, err := decoder.Token()
		if err != nil {
			return errRecord
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				if typ.Kind() != reflect.Struct {
					return errRecord
				}
				allowed := fields[typ]
				if allowed == nil {
					allowed = map[string]reflect.Type{}
					for i := 0; i < typ.NumField(); i++ {
						field := typ.Field(i)
						name := strings.Split(field.Tag.Get("json"), ",")[0]
						if name == "-" {
							continue
						}
						if name == "" {
							name = field.Name
						}
						allowed[name] = field.Type
					}
					fields[typ] = allowed
				}
				seen := map[string]bool{}
				for decoder.More() {
					token, err := decoder.Token()
					if err != nil {
						return errRecord
					}
					key, ok := token.(string)
					if !ok || seen[key] {
						return errRecord
					}
					next, known := allowed[key]
					if !known {
						return errRecord
					}
					seen[key] = true
					if item(next, depth+1) != nil {
						return errRecord
					}
				}
				token, err = decoder.Token()
				if err != nil || token != json.Delim('}') {
					return errRecord
				}
			case '[':
				if typ.Kind() != reflect.Array && typ.Kind() != reflect.Slice {
					return errRecord
				}
				// Token.Value is base64 JSON, not an alternate numeric-array codec.
				if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
					return errRecord
				}
				count := 0
				for decoder.More() {
					if item(typ.Elem(), depth+1) != nil {
						return errRecord
					}
					count++
				}
				if typ.Kind() == reflect.Array && count != typ.Len() {
					return errRecord
				}
				token, err = decoder.Token()
				if err != nil || token != json.Delim(']') {
					return errRecord
				}
			default:
				return errRecord
			}
		}
		return nil
	}
	if item(reflect.TypeOf(value).Elem(), 0) != nil {
		return errRecord
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errRecord
	}
	return decodeJSON(body, value)
}
func ReadPublicConfigurationEvidenceSnapshotBytes(body []byte, expected PublicConfigurationEvidenceBinding) (PublicConfigurationEvidenceSnapshot, error) {
	var value PublicConfigurationEvidenceSnapshot
	if publicEvidenceJSON(body, MaximumPublicConfigurationSnapshotBytes, &value) != nil || value.Validate(expected) != nil {
		return PublicConfigurationEvidenceSnapshot{}, errRecord
	}
	return value, nil
}
func ReadPublicConfigurationEvidenceSnapshot(path string, expected PublicConfigurationEvidenceBinding) (PublicConfigurationEvidenceSnapshot, error) {
	body, err := ReadJSONBytes(path, MaximumPublicConfigurationSnapshotBytes)
	if err != nil {
		return PublicConfigurationEvidenceSnapshot{}, err
	}
	return ReadPublicConfigurationEvidenceSnapshotBytes(body, expected)
}
func WritePublicConfigurationEvidenceSnapshot(path string, value PublicConfigurationEvidenceSnapshot) error {
	expected := PublicConfigurationEvidenceBinding{RunID: value.RunID, Scenario: value.Scenario, Provider: value.Provider, RecoveryMode: value.RecoveryMode, Prefix: value.Prefix, Binding: value.Binding}
	if value.Validate(expected) != nil {
		return errRecord
	}
	return WriteJSONExclusive(path, value, MaximumPublicConfigurationSnapshotBytes)
}
func ReadPublicConfigurationEvidenceManifestBytes(body []byte, expected PublicConfigurationEvidenceBinding) (PublicConfigurationEvidenceManifest, error) {
	var value PublicConfigurationEvidenceManifest
	if publicEvidenceJSON(body, MaximumPublicConfigurationManifestBytes, &value) != nil || value.Validate(expected) != nil {
		return PublicConfigurationEvidenceManifest{}, errRecord
	}
	return value, nil
}
func ReadPublicConfigurationEvidenceManifest(path string, expected PublicConfigurationEvidenceBinding) (PublicConfigurationEvidenceManifest, error) {
	body, err := ReadJSONBytes(path, MaximumPublicConfigurationManifestBytes)
	if err != nil {
		return PublicConfigurationEvidenceManifest{}, err
	}
	return ReadPublicConfigurationEvidenceManifestBytes(body, expected)
}
