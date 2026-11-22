package records

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"enkv.sh/core/contract"
)

const (
	FailureSchemaVersion          = 1
	OperationFailureSchemaVersion = 2
	MaximumFailureBytes           = 4 << 10
	MaximumWorkerPhases           = 256
	MaximumWorkerChildren         = 64
	MaximumOperationFacts         = 1024
	maximumFailureSourcesBytes    = 1 << 20
)

type InvocationBinding struct {
	Worker string `json:"worker"`
	Nonce  string `json:"nonce"`
}

type FailureSourceBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// FailureSources is derived from the admitted overlay and resolved modules.
// Keys are exact compiler paths, including the selected module versions.
type FailureSources struct {
	SchemaVersion int               `json:"schema_version"`
	BinarySHA256  string            `json:"binary_sha256"`
	OverlaySHA256 string            `json:"overlay_sha256"`
	Paths         map[string]string `json:"paths"`
}

type FailureIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id"`
	Worker        string `json:"worker"`
	Role          string `json:"role"`
	Scenario      string `json:"scenario"`
	Nonce         string `json:"nonce"`
}

type CompletedCheckpoint struct {
	Code     string `json:"code"`
	Sequence uint64 `json:"sequence"`
}

type FailureMarker struct {
	FailureIdentity
	Phase            string                 `json:"phase"`
	Sequence         uint64                 `json:"sequence"`
	Code             string                 `json:"code"`
	Source           string                 `json:"source"`
	Line             int                    `json:"line"`
	Completed        CompletedCheckpoint    `json:"completed"`
	OperationFailure *OperationFailureFacts `json:"operation_failure,omitempty"`
}

type FailureCheckpoint struct {
	FailureIdentity
	Completed        CompletedCheckpoint `json:"completed"`
	MarkerWriteError bool                `json:"marker_write_error,omitempty"`
}

// AssertionEvidence is the closed public projection. Private locations,
// assertion codes, nonces and assertion arguments never enter it.
type AssertionEvidence struct {
	Marker           string                 `json:"marker"`
	Checkpoint       string                 `json:"checkpoint"`
	Completed        CompletedCheckpoint    `json:"completed"`
	MarkerWriteError bool                   `json:"marker_write_error,omitempty"`
	OperationFailure *OperationFailureFacts `json:"operation_failure,omitempty"`
}

// QualifiedSafeFacts contains only validated family disposition and reason. The
// caller must qualify the source SafeFacts before constructing this value.
type QualifiedSafeFacts struct {
	Disposition uint8 `json:"disposition"`
	Reason      uint8 `json:"reason"`
}

// OperationFailureFacts is the closed projection of one exact generated
// operation. Code zero is allowed only before a Crypto result exists. It
// contains no private IDs, payloads or provider text.
type OperationFailureFacts struct {
	SchemaVersion int                       `json:"schema_version"`
	Operation     string                    `json:"operation"`
	Stage         string                    `json:"stage"`
	Category      string                    `json:"category"`
	Code          contract.CryptoResultCode `json:"code"`
	Effect        string                    `json:"effect"`
	FactsStatus   string                    `json:"facts_status"`
	SafeFacts     *QualifiedSafeFacts       `json:"safe_facts,omitempty"`
}

func (f OperationFailureFacts) Validate() error {
	if f.SchemaVersion != OperationFailureSchemaVersion {
		return errRecord
	}
	switch f.Operation {
	case "generated_create", "generated_retire":
	default:
		return errRecord
	}
	switch f.Stage {
	case "pre_invocation":
		if f.Category != "unavailable" || f.Code != 0 || f.FactsStatus != "facts_unavailable" {
			return errRecord
		}
	case "entry", "authority", "owner", "return", "deadline", "pipe", "launch", "result_read", "wait", "status", "decode", "binding", "facts", "seal":
		if f.Category != "invalid" && f.Category != "unavailable" && f.Category != "cancelled" && f.Category != "expired" && f.Category != "protocol" && f.Category != "already_used" || f.Code == contract.CryptoSuccess || f.FactsStatus != "facts_unavailable" {
			return errRecord
		}
	case "completed":
		if f.Category != "none" || f.FactsStatus != "qualified" || f.Code != contract.CryptoSuccess {
			return errRecord
		}
	default:
		return errRecord
	}
	if f.Stage != "pre_invocation" && !f.Code.Valid() {
		return errRecord
	}
	switch f.Effect {
	case "no_send", "unknown", "complete", "owned_unusable", "no_effect", "delete_acknowledged":
	default:
		return errRecord
	}
	switch f.FactsStatus {
	case "facts_unavailable":
		if f.SafeFacts != nil || f.Effect != "no_send" && f.Effect != "unknown" {
			return errRecord
		}
		if f.Effect == "no_send" && f.Stage != "pre_invocation" && f.Stage != "entry" && f.Stage != "authority" && f.Stage != "owner" && f.Stage != "deadline" && f.Stage != "pipe" {
			return errRecord
		}
	case "qualified":
		v := f.SafeFacts
		if v == nil || v.Disposition < contract.GeneratorDispositionCompleteCreate || v.Disposition > contract.GeneratorDispositionConflictingBinding ||
			v.Reason > contract.GeneratorReasonIdentityConflict {
			return errRecord
		}
		switch v.Disposition {
		case contract.GeneratorDispositionCompleteCreate:
			if f.Operation != "generated_create" || f.Effect != "complete" || v.Reason != contract.GeneratorReasonNone {
				return errRecord
			}
		case contract.GeneratorDispositionOwnedUnusableCreate:
			if f.Operation != "generated_create" || f.Effect != "owned_unusable" || v.Reason < contract.GeneratorReasonMissingValue || v.Reason > contract.GeneratorReasonInactive {
				return errRecord
			}
		case contract.GeneratorDispositionConfirmedNoEffect:
			if f.Operation != "generated_create" || f.Effect != "no_effect" {
				return errRecord
			}
		case contract.GeneratorDispositionRetirementAcknowledged:
			if f.Operation != "generated_retire" || f.Effect != "delete_acknowledged" || v.Reason != contract.GeneratorReasonNone {
				return errRecord
			}
		case contract.GeneratorDispositionUnknown:
			if f.Effect != "unknown" || v.Reason < contract.GeneratorReasonMalformed {
				return errRecord
			}
		default:
			if f.Operation != "generated_retire" || f.Effect != "unknown" || v.Reason != contract.GeneratorReasonNone {
				return errRecord
			}
		}
	default:
		return errRecord
	}
	return nil
}

func cloneOperationFailure(f OperationFailureFacts) OperationFailureFacts {
	if f.SafeFacts != nil {
		facts := *f.SafeFacts
		f.SafeFacts = &facts
	}
	return f
}

// OperationFailureRef is scoped to one recorder and one active phase. It is
// never serialized. The owning helper selects it before its failing assertion.
type OperationFailureRef struct {
	owner    *FailureRecorder
	phase    string
	sequence uint64
	facts    OperationFailureFacts
}

func NewInvocationNonce() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errRecord
	}
	return hex.EncodeToString(bytes[:]), nil
}

func validHex(value string, bytes int) bool {
	if len(value) != bytes*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func failureIdentity(inv Invocation) FailureIdentity {
	return FailureIdentity{SchemaVersion: FailureSchemaVersion, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Scenario: inv.Scenario, Nonce: inv.Nonce}
}

func validFailureSource(source string) bool {
	if source == "" || len(source) > 256 || path.IsAbs(source) || path.Clean(source) != source || !strings.HasSuffix(source, ".go") {
		return false
	}
	for _, r := range source {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '/' && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	for _, component := range strings.Split(source, "/") {
		if component == ".." || component == "." || component == "" {
			return false
		}
	}
	root, _, _ := strings.Cut(source, "/")
	switch root {
	case "core", "crypto", "tests", "providers", "compositions", "protocols", "telemetry":
		return true
	case "sdk":
		parts := strings.Split(source, "/")
		if len(parts) == 5 && parts[1] == "examples" && parts[2] == "ini-reference-manifest" && parts[3] == "consumer" {
			return true
		}
		if len(parts) == 3 {
			return parts[1] == "manifest-generator" || parts[1] == "artifact"
		}
		return len(parts) == 4 && (parts[1] == "manifest-generator" && parts[2] == "jsonwriter" || parts[1] == "artifact" && parts[2] == "credentialroute")
	case "plugins":
		parts := strings.Split(source, "/")
		if len(parts) != 4 {
			return false
		}
		if parts[1] == "manifest-generators" {
			return parts[2] == "generic-json" || parts[2] == "opentofu-tfvars-json"
		}
		if parts[2] == "artifact" {
			return parts[1] == "cloudflare"
		}
		if parts[2] == "credential" {
			return parts[1] == "aws-output" || parts[1] == "gcp-output"
		}
		if parts[2] != "profile" {
			return false
		}
		switch parts[1] {
		case "cloudflare", "local-random-secret", "aws-output", "gcp-output", "github-output":
			return true
		}
	}
	return false
}

func (sources FailureSources) Validate() error {
	if sources.SchemaVersion != FailureSchemaVersion || !validHex(sources.BinarySHA256, sha256.Size) || !validHex(sources.OverlaySHA256, sha256.Size) || len(sources.Paths) == 0 {
		return errRecord
	}
	for caller, source := range sources.Paths {
		if len(caller) > 512 || strings.ContainsAny(caller, "\\\r\n\x00") || path.Clean(caller) != caller || !validFailureSource(source) {
			return errRecord
		}
		versionedModule := ""
		switch {
		case strings.HasPrefix(source, "sdk/artifact/"):
			versionedModule = "enkv.sh/sdk/artifact"
		case strings.HasPrefix(source, "plugins/cloudflare/artifact/"):
			versionedModule = "enkv.sh/plugins/generators/cloudflare-account-token"
		case strings.HasPrefix(source, "sdk/manifest-generator/"):
			versionedModule = "enkv.sh/sdk/manifest-generator"
		case strings.HasPrefix(source, "plugins/manifest-generators/"):
			separator := strings.LastIndexByte(source, '/')
			versionedModule = "enkv.sh/" + source[:separator]
		}
		if versionedModule != "" {
			remainder, owner := strings.CutPrefix(caller, versionedModule+"@")
			version, _, separated := strings.Cut(remainder, "/")
			if !owner || !separated || !strings.HasPrefix(version, "v") {
				return errRecord
			}
		}
		if !failureSourceMatchesOwner(caller, source) {
			return errRecord
		}
	}
	return nil
}

func ReadFailureSources(binding FailureSourceBinding) (FailureSources, error) {
	var sources FailureSources
	if !validHex(binding.SHA256, sha256.Size) {
		return sources, errRecord
	}
	body, err := ReadJSONBytes(binding.Path, maximumFailureSourcesBytes)
	if err != nil {
		return sources, errRecord
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != binding.SHA256 || decodeJSON(body, &sources) != nil || sources.Validate() != nil {
		return FailureSources{}, errRecord
	}
	return sources, nil
}

func validFailurePhase(code string) bool {
	switch code {
	case "authentication", "resource_check", "setup", "transition", "reopen", "verification", "cleanup":
		return true
	}
	return false
}

func (c CompletedCheckpoint) valid() bool {
	return c.Code == "none" && c.Sequence == 0 || validFailurePhase(c.Code) && c.Sequence > 0 && c.Sequence <= MaximumWorkerPhases
}

// ValidateIdentity checks a retained marker independently of its build source map.
// The original importer retains source qualification in AssertionEvidence.
func (m FailureMarker) ValidateIdentity(inv Invocation) error {
	if m.FailureIdentity != failureIdentity(inv) || !validHex(inv.Nonce, 16) || !m.Completed.valid() || !validFailureSource(m.Source) || m.Line <= 0 || m.Completed.Sequence > m.Sequence || m.Sequence > MaximumWorkerPhases || m.Completed.Sequence == m.Sequence && m.Sequence != 0 && m.Completed.Code != m.Phase {
		return errRecord
	}
	if m.OperationFailure != nil && m.OperationFailure.Validate() != nil {
		return errRecord
	}
	if (m.Phase != "bootstrap" || m.Sequence != 0) && (!validFailurePhase(m.Phase) || m.Sequence == 0) {
		return errRecord
	}
	switch m.Code {
	case "fatal", "fatalf", "error", "errorf", "fail_now", "fail":
	default:
		return errRecord
	}
	return nil
}

func (m FailureMarker) Validate(inv Invocation, sources FailureSources) error {
	if m.ValidateIdentity(inv) != nil {
		return errRecord
	}
	for _, source := range sources.Paths {
		if source == m.Source {
			return nil
		}
	}
	return errRecord
}

func (c FailureCheckpoint) Validate(inv Invocation) error {
	if c.FailureIdentity != failureIdentity(inv) || !validHex(inv.Nonce, 16) || !c.Completed.valid() {
		return errRecord
	}
	return nil
}

// FailureRecorder owns assertion, selected operation, and completed-phase facts. It never reads
// WorkerRecorder.Result, which belongs to the test goroutine.
type FailureRecorder struct {
	mu               sync.Mutex
	invocation       Invocation
	sources          FailureSources
	phase            string
	sequence         uint64
	completed        CompletedCheckpoint
	claimed          bool
	markerWriteError bool
	operationFacts   uint16
	selected         *OperationFailureRef
}

func NewFailureRecorder(inv Invocation) (*FailureRecorder, error) {
	if inv.Validate() != nil {
		return nil, errRecord
	}
	directory, err := os.Lstat(inv.OutputDir)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 {
		return nil, errRecord
	}
	for _, name := range []string{"failure.json", "checkpoint.json"} {
		file, err := SafePath(inv.OutputDir, name)
		if err != nil {
			return nil, errRecord
		}
		if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
			return nil, errRecord
		}
	}
	var sources FailureSources
	if inv.FailureSources != nil {
		var err error
		sources, err = ReadFailureSources(*inv.FailureSources)
		if err != nil {
			return nil, err
		}
	}
	return &FailureRecorder{invocation: inv, sources: sources, phase: "bootstrap", completed: CompletedCheckpoint{Code: "none"}}, nil
}

func (r *FailureRecorder) belongsTo(inv Invocation) bool {
	if r == nil || failureIdentity(r.invocation) != failureIdentity(inv) || r.invocation.OutputDir != inv.OutputDir {
		return false
	}
	if r.invocation.FailureSources == nil || inv.FailureSources == nil {
		return r.invocation.FailureSources == nil && inv.FailureSources == nil
	}
	return *r.invocation.FailureSources == *inv.FailureSources
}

func (r *FailureRecorder) begin(phase string, sequence uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !validFailurePhase(phase) || sequence == 0 || sequence > MaximumWorkerPhases || sequence <= r.sequence {
		return errRecord
	}
	r.phase, r.sequence = phase, sequence
	r.selected = nil
	return nil
}

// CaptureOperationFailure stores one immutable, closed fact in memory. It does
// not choose which operation a later assertion describes.
func (r *FailureRecorder) CaptureOperationFailure(facts OperationFailureFacts) (*OperationFailureRef, error) {
	if r == nil || facts.Validate() != nil {
		return nil, errRecord
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed || r.operationFacts >= MaximumOperationFacts {
		return nil, errRecord
	}
	r.operationFacts++
	return &OperationFailureRef{owner: r, phase: r.phase, sequence: r.sequence, facts: cloneOperationFailure(facts)}, nil
}

// SelectOperationFailure binds the exact captured operation to the next first
// assertion. A callback that was not selected cannot enter the marker.
func (r *FailureRecorder) SelectOperationFailure(ref *OperationFailureRef) error {
	if r == nil || ref == nil {
		return errRecord
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed || ref.owner != r || ref.phase != r.phase || ref.sequence != r.sequence {
		return errRecord
	}
	r.selected = ref
	return nil
}

func (r *FailureRecorder) complete(phase string, sequence uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if phase != r.phase || sequence != r.sequence {
		return errRecord
	}
	completed := CompletedCheckpoint{Code: phase, Sequence: sequence}
	if err := r.saveCheckpoint(completed); err != nil {
		return err
	}
	r.completed = completed
	return nil
}

func (r *FailureRecorder) saveCheckpoint(completed CompletedCheckpoint) error {
	directory, err := os.Lstat(r.invocation.OutputDir)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 {
		return errRecord
	}
	record := FailureCheckpoint{FailureIdentity: failureIdentity(r.invocation), Completed: completed, MarkerWriteError: r.markerWriteError}
	if record.Validate(r.invocation) != nil {
		return errRecord
	}
	body, err := json.Marshal(record)
	if err != nil || len(body)+1 > MaximumFailureBytes {
		return errRecord
	}
	return WriteJSON(filepath.Join(r.invocation.OutputDir, "checkpoint.json"), record, 0o600)
}

// Record accepts fixed facts only. The first assertion owns the attempt even
// when its source cannot be resolved or its file cannot be published.
func (r *FailureRecorder) Record(code, caller string, line int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed {
		return
	}
	r.claimed = true
	marker := FailureMarker{FailureIdentity: failureIdentity(r.invocation), Phase: r.phase, Sequence: r.sequence, Code: code, Source: r.sources.Paths[caller], Line: line, Completed: r.completed}
	if r.selected != nil {
		facts := cloneOperationFailure(r.selected.facts)
		marker.OperationFailure = &facts
	}
	if marker.Validate(r.invocation, r.sources) != nil {
		return
	}
	if WriteJSONExclusive(filepath.Join(r.invocation.OutputDir, "failure.json"), marker, MaximumFailureBytes) != nil {
		r.markerWriteError = true
		// A public write-error fact exists only if this independent save succeeds.
		// Otherwise import reports the file state and process outcome it observes.
		if r.saveCheckpoint(r.completed) != nil {
			return
		}
	}
}

func failureFile(inv Invocation, name string) (string, string) {
	file, err := SafePath(inv.OutputDir, name)
	if err != nil {
		return "", "invalid"
	}
	directory, err := os.Lstat(inv.OutputDir)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 {
		return "", "invalid"
	}
	info, err := os.Lstat(file)
	if errors.Is(err, os.ErrNotExist) {
		return file, "absent"
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return file, "invalid"
	}
	return file, "present"
}

// InspectAssertions does not depend on worker.json. A process killed before an
// assertion retains absence and the last durable completed checkpoint.
func InspectAssertions(inv Invocation, passed bool) AssertionEvidence {
	evidence := AssertionEvidence{Marker: "no_failure_marker", Checkpoint: "no_checkpoint", Completed: CompletedCheckpoint{Code: "none"}}
	checkpoint, state := failureFile(inv, "checkpoint.json")
	if state != "absent" {
		evidence.Checkpoint = "invalid_checkpoint"
		var value FailureCheckpoint
		if state == "present" && ReadJSONLimit(checkpoint, &value, MaximumFailureBytes) == nil && value.Validate(inv) == nil {
			evidence.Checkpoint, evidence.Completed, evidence.MarkerWriteError = "valid_checkpoint", value.Completed, value.MarkerWriteError
		}
	}
	marker, state := failureFile(inv, "failure.json")
	if state == "absent" {
		return evidence
	}
	evidence.Marker = "invalid_failure_marker"
	if state != "present" {
		return evidence
	}
	var sources FailureSources
	sourceErr := errRecord
	if inv.FailureSources != nil {
		sources, sourceErr = ReadFailureSources(*inv.FailureSources)
	}
	var value FailureMarker
	if sourceErr == nil && ReadJSONLimit(marker, &value, MaximumFailureBytes) == nil && value.Validate(inv, sources) == nil {
		evidence.Marker = "valid_failure_marker"
		if value.OperationFailure != nil {
			facts := cloneOperationFailure(*value.OperationFailure)
			evidence.OperationFailure = &facts
		}
		if passed {
			evidence.Marker = "contradictory_failure_marker"
		}
	}
	return evidence
}

func (e AssertionEvidence) Validate() error {
	switch e.Marker {
	case "no_failure_marker", "valid_failure_marker", "invalid_failure_marker", "contradictory_failure_marker":
	default:
		return errRecord
	}
	switch e.Checkpoint {
	case "no_checkpoint", "invalid_checkpoint":
		if e.Completed != (CompletedCheckpoint{Code: "none"}) || e.MarkerWriteError {
			return errRecord
		}
	case "valid_checkpoint":
		if !e.Completed.valid() {
			return errRecord
		}
	default:
		return errRecord
	}
	if e.OperationFailure != nil && (e.Marker != "valid_failure_marker" && e.Marker != "contradictory_failure_marker" || e.OperationFailure.Validate() != nil) {
		return errRecord
	}
	return nil
}

func (e *AssertionEvidence) PermitsSuccess() bool {
	return e == nil || e.Validate() == nil && e.Marker == "no_failure_marker" && e.Checkpoint != "invalid_checkpoint" && !e.MarkerWriteError
}

type TestSourceOverlay struct{ Source, Target, Owner string }

func TestAdmissionOverlays() []TestSourceOverlay {
	return []TestSourceOverlay{
		{"tests/generatorhost/environment.go", "compositions/generatorhost/zz_test_environment.go", "generator host"},
		{"tests/crypto/admission.go", "crypto/zz_test_admission.go", "Crypto"},
		{"tests/gcp/admission.go", "providers/gcp/zz_test_admission.go", "GCP"},
		{"tests/gcpcredentials/admission.go", "providers/gcp/credentials/zz_test_admission.go", "GCP credentials"},
		{"tests/full/admission.go", "compositions/full/zz_test_admission.go", "full composition"},
	}
}

func LiveTestSupportOverlays() []TestSourceOverlay {
	return []TestSourceOverlay{
		{"tests/live/custody/output_box.go", "crypto/testsupport/custody/zz_test_output_box.go", "live output custody"},
	}
}

func failureSourceMatchesOwner(caller, source string) bool {
	for _, row := range failureModuleSources {
		remainder, ok := strings.CutPrefix(caller, row.Module)
		if !ok || remainder == "" {
			continue
		}
		if remainder[0] == '@' {
			version, rest, found := strings.Cut(remainder[1:], "/")
			if !found || version == "" || strings.ContainsAny(version, " @") {
				continue
			}
			remainder = "/" + rest
		}
		if !strings.HasPrefix(remainder, "/") {
			continue
		}
		relative := strings.TrimPrefix(remainder, "/")
		if source == row.Selector+"/"+relative {
			return true
		}
		if row.Selector == "core" && source != "tests/live/custody/output_box.go" && strings.HasPrefix(source, "tests/") &&
			!strings.HasPrefix(source, "tests/crypto/") && !strings.HasPrefix(source, "tests/gcp/") && !strings.HasPrefix(source, "tests/gcpcredentials/") && !strings.HasPrefix(source, "tests/full/") {
			return true
		}
		if row.Selector == "crypto" && strings.HasPrefix(source, "tests/crypto/") && relative == "zz_test_"+strings.TrimPrefix(source, "tests/crypto/") {
			return true
		}
		for _, overlay := range append(TestAdmissionOverlays(), LiveTestSupportOverlays()...) {
			if source == overlay.Source && row.Selector+"/"+relative == overlay.Target {
				return true
			}
		}
		return false
	}
	return false
}
