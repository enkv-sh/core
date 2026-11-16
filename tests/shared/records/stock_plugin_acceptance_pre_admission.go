package records

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
)

const StockPluginRecoveryPreAdmissionClaim = "stock-recovery-pre-admission-claim.json"
const StockPluginRecoveryAdditionalAccountingName = "stock-recovery-additional-accounting.json"

// The reviewed retained command used the operator's 64 KiB capture on each pipe.
const stockRecoveryHistoricalCaptureBytes = 64 << 10

// This historical producer sets request identity before candidate persistence,
// selection and generated dispatch. Other producers need their own source proof;
// PreAdmission words alone are not a general no-effect capability.
func StockPluginRecoveryProducerCompatible(v StockPluginArtifact) bool {
	return v.CLI.SHA256 == "6d8c3f44151bdcacef3587350dd08dfceeb841ff4d4997c0c1e829dfa7fa9f1e" && v.CLI.Length == 62903682 &&
		v.Source.Algorithm == "enkv-raw-git-tree-v1" && v.Source.Revision == "4b92ec84a6fd1f2883b373f76b1096d52935db8d" &&
		v.Source.Tree == "9dd848f6a4bcb594af4ba5ad9e5fc1ebb79c2c5b" && !v.Source.Dirty && !v.Source.ObservationIncomplete && v.Source.DirtyDiffSHA256 == nil
}

type StockPluginRecoveryPinnedFile struct {
	File StockPluginFile `json:"file"`
	Mode uint32          `json:"mode"`
}

// ReadStockPluginRecoveryPin reads only an explicitly retained file, never a tree
// or an SDK credential home. Empty stderr is the sole zero-length input here.
func ReadStockPluginRecoveryPin(file StockPluginFile, empty bool) (StockPluginRecoveryPinnedFile, []byte, error) {
	for _, component := range strings.Split(file.Path, string(filepath.Separator)) {
		if component == ".aws" || component == ".config" {
			return StockPluginRecoveryPinnedFile{}, nil, errRecord
		}
	}
	if !file.valid(MaximumJSONBytes) && (!empty || file.Length != 0 || file.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" || !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path) {
		return StockPluginRecoveryPinnedFile{}, nil, errRecord
	}
	if _, err := SafePath(filepath.Dir(file.Path), filepath.Base(file.Path)); err != nil {
		return StockPluginRecoveryPinnedFile{}, nil, errRecord
	}
	before, err := os.Lstat(file.Path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0400 && before.Mode().Perm() != 0600 || uint64(before.Size()) != file.Length {
		return StockPluginRecoveryPinnedFile{}, nil, errRecord
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return StockPluginRecoveryPinnedFile{}, nil, errRecord
	}
	body, err := ReadJSONBytes(file.Path, MaximumJSONBytes)
	after, statErr := os.Lstat(file.Path)
	digest := sha256.Sum256(body)
	if err != nil || statErr != nil || !SameLocalFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || uint64(len(body)) != file.Length || hex.EncodeToString(digest[:]) != file.SHA256 {
		return StockPluginRecoveryPinnedFile{}, nil, errRecord
	}
	return StockPluginRecoveryPinnedFile{File: file, Mode: uint32(before.Mode().Perm())}, body, nil
}

func (p StockPluginRecoveryPinnedFile) Verify() error {
	actual, _, err := ReadStockPluginRecoveryPin(p.File, p.File.Length == 0)
	if err != nil || actual != p {
		return errRecord
	}
	return nil
}

type StockPluginRecoveryPreAdmission struct {
	Predecessor  StockPluginRecoveryPredecessor  `json:"predecessor"`
	CommandIndex StockPluginFile                 `json:"command_index"`
	Diagnostic   StockPluginFile                 `json:"diagnostic"`
	Accounting   StockPluginFile                 `json:"accounting"`
	Files        []StockPluginRecoveryPinnedFile `json:"files"`
}

func (p StockPluginRecoveryPreAdmission) Validate(v StockPluginRecoveryInput) error {
	state := filepath.Dir(v.OriginalInput.Path)
	prior := p.Predecessor
	output := filepath.Dir(prior.Invocation.Path)
	if !ValidRunID(prior.RunID) || prior.RunID == v.OriginalRunID || prior.RunID == v.RecoveryRunID || v.Predecessor == nil || prior.RunID == v.Predecessor.RunID ||
		prior.Claim.Path != filepath.Join(state, "stock-recovery-successor-claim.json") || p.Accounting.Path != filepath.Join(state, StockPluginRecoveryAdditionalAccountingName) ||
		p.CommandIndex.Path != filepath.Join(output, "stock-plugin-evidence.json") || p.Diagnostic.Path != filepath.Join(output, fmt.Sprintf("stock-result-%02d.json", v.OriginalCommands)) ||
		prior.Result.Path != filepath.Join(output, "stock-recovery.json") || prior.Worker.Path != filepath.Join(output, "worker.json") || prior.Failure.Path != filepath.Join(output, "failure.json") ||
		len(p.Files) == 0 || len(p.Files) > 96 {
		return errRecord
	}
	for _, file := range append(p.Predecessor.Files(), p.CommandIndex, p.Diagnostic, p.Accounting) {
		if !file.valid(MaximumJSONBytes) {
			return errRecord
		}
	}
	for i, pin := range p.Files {
		if pin.Mode != 0400 && pin.Mode != 0600 || !pin.File.valid(MaximumJSONBytes) && pin.File.Length != 0 || i != 0 && p.Files[i-1].File.Path >= pin.File.Path {
			return errRecord
		}
	}
	return nil
}

func (p StockPluginRecoveryPredecessor) Files() []StockPluginFile {
	return []StockPluginFile{p.Claim, p.Run, p.Input, p.Invocation, p.Result, p.Worker, p.Failure}
}

func (p StockPluginRecoveryPreAdmission) VerifyFiles(v StockPluginRecoveryInput) error {
	if p.Validate(v) != nil {
		return errRecord
	}
	verify := func(file StockPluginFile) bool {
		return slices.ContainsFunc(p.Files, func(pin StockPluginRecoveryPinnedFile) bool { return pin.File == file && pin.Verify() == nil })
	}
	if !verify(p.Accounting) || !verify(v.Accounting) {
		return errRecord
	}
	required := append(p.Predecessor.Files(), p.CommandIndex, p.Diagnostic, p.Accounting, v.OriginalRun, v.OriginalInput, v.OriginalEvidence, v.OriginalGrant, v.Accounting)
	required = append(required, v.Predecessor.Files()...)
	required = append(required, v.Sources...)
	var accounting StockPluginRecoveryAdditionalAccounting
	if ReadStockPluginRecoveryAdditionalAccounting(p.Accounting.Path, &accounting) != nil || accounting.Validate(v.OriginalRunID, p.Predecessor.RunID, v.Accounting) != nil || !accounting.ReviewedProducer() {
		return errRecord
	}
	required = append(required, accounting.Files()...)
	if !verify(accounting.Packet) {
		return errRecord
	}
	var prior StockPluginRecoveryInput
	if ReadJSON(p.Predecessor.Claim.Path, &prior) != nil || prior.PreAdmission != nil || prior.Predecessor == nil || !reflect.DeepEqual(prior.Predecessor, v.Predecessor) || prior.RecoveryRunID != p.Predecessor.RunID {
		return errRecord
	}
	var packet struct {
		References []struct {
			Path, SHA256 string
			Bytes        uint64
		} `json:"references"`
	}
	body, err := ReadJSONBytes(accounting.Packet.Path, MaximumJSONBytes)
	if err != nil || json.Unmarshal(body, &packet) != nil {
		return errRecord
	}
	for _, ref := range packet.References {
		file := StockPluginFile{Path: ref.Path, SHA256: ref.SHA256, Length: ref.Bytes}
		required = append(required, file)
	}
	var originalAccounting StockPluginRecoveryAccounting
	if ReadJSON(v.Accounting.Path, &originalAccounting) != nil {
		return errRecord
	}
	for _, diagnostic := range originalAccounting.Diagnostics {
		required = append(required, diagnostic.Scope, diagnostic.Result)
	}
	for _, file := range required {
		if !slices.ContainsFunc(p.Files, func(pin StockPluginRecoveryPinnedFile) bool { return pin.File == file }) {
			return errRecord
		}
	}
	for _, pin := range p.Files {
		if !slices.Contains(required, pin.File) || pin.Verify() != nil {
			return errRecord
		}
	}
	return nil
}

// All additional inputs remain immutable and are separate from the original
// accounting and both spent claims.
type StockPluginRecoveryAdditionalAccounting struct {
	Schema              uint16          `json:"schema"`
	Complete            bool            `json:"complete"`
	OriginalRunID       string          `json:"original_run_id"`
	FailedRecoveryRunID string          `json:"failed_recovery_run_id"`
	BaseAccounting      StockPluginFile `json:"base_accounting"`
	Intent              StockPluginFile `json:"intent"`
	Completion          StockPluginFile `json:"completion"`
	Result              StockPluginFile `json:"result"`
	Capture             StockPluginFile `json:"capture"`
	Stdout              StockPluginFile `json:"stdout"`
	Stderr              StockPluginFile `json:"stderr"`
	Policy              StockPluginFile `json:"policy"`
	Packet              StockPluginFile `json:"packet"`
	SourceArchive       StockPluginFile `json:"source_archive"`
	Terminal            StockPluginFile `json:"terminal"`
	TerminalProvenance  StockPluginFile `json:"terminal_provenance"`
	TerminalLog         StockPluginFile `json:"terminal_log"`
	Timing              StockPluginFile `json:"timing"`
	Settlement          StockPluginFile `json:"settlement"`
}

func (v StockPluginRecoveryAdditionalAccounting) Files() []StockPluginFile {
	return []StockPluginFile{v.BaseAccounting, v.Intent, v.Completion, v.Result, v.Capture, v.Stdout, v.Stderr, v.Policy, v.Packet, v.SourceArchive, v.Terminal, v.TerminalProvenance, v.TerminalLog, v.Timing, v.Settlement}
}

func (v StockPluginRecoveryAdditionalAccounting) Validate(original, failed string, base StockPluginFile) error {
	if v.Schema != 1 || !v.Complete || v.OriginalRunID != original || v.FailedRecoveryRunID != failed || !ValidRunID(original) || !ValidRunID(failed) || original == failed || v.BaseAccounting != base {
		return errRecord
	}
	seen := map[string]bool{}
	for _, file := range v.Files() {
		if seen[file.Path] || !file.valid(MaximumJSONBytes) && file != v.Stderr {
			return errRecord
		}
		seen[file.Path] = true
	}
	if v.Stderr.Length != 0 || v.Stderr.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return errRecord
	}
	return nil
}

func (v StockPluginRecoveryAdditionalAccounting) ReviewedProducer() bool {
	return v.Packet.SHA256 == "d111777c916fe9ce0b30a53493facab64e630cabf3b877563430905f8a260976" &&
		v.SourceArchive.SHA256 == "25c0066f28cf0f9c2ebe5880a318c134176996ec1960d98166c974cb1032ce19"
}

func ReadStockPluginRecoveryAdditionalAccounting(path string, value *StockPluginRecoveryAdditionalAccounting) error {
	body, err := ReadJSONBytes(path, MaximumJSONBytes)
	if err != nil || publicEvidenceJSON(body, MaximumJSONBytes, value) != nil {
		return errRecord
	}
	var fields map[string]json.RawMessage
	var stderr map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || json.Unmarshal(fields["stderr"], &stderr) != nil || len(stderr) != 3 || !bytes.Equal(bytes.TrimSpace(stderr["length"]), []byte("0")) {
		return errRecord
	}
	return nil
}

// This is a projection from the complete bounded stdout digest, not a provider
// observation. Its meaning depends on the exact historical producer above.
type stockRecoveryPreAdmissionDiagnostic struct {
	Schema              uint16                          `json:"schema"`
	RunID               string                          `json:"run_id"`
	Ordinal             uint32                          `json:"ordinal"`
	Worker              string                          `json:"worker"`
	Nonce               string                          `json:"nonce"`
	Phase               string                          `json:"phase"`
	CLISHA256           string                          `json:"cli_sha256"`
	ResultSHA256        string                          `json:"result_sha256"`
	DigestScope         string                          `json:"digest_scope"`
	CapturedBytes       uint32                          `json:"captured_bytes"`
	StdoutOverflow      *bool                           `json:"stdout_overflow"`
	StderrOverflow      *bool                           `json:"stderr_overflow"`
	StderrCapturedBytes *uint32                         `json:"stderr_captured_bytes"`
	Started             *bool                           `json:"started"`
	WaitReturned        *bool                           `json:"wait_returned"`
	WaitHasProcessState *bool                           `json:"wait_has_process_state"`
	ProductJoined       *bool                           `json:"product_joined"`
	TimedOut            *bool                           `json:"timed_out"`
	StartSaveFailed     *bool                           `json:"start_save_failed"`
	CLIChanged          *bool                           `json:"cli_changed"`
	Status              string                          `json:"status"`
	Uncaptured          []string                        `json:"uncaptured"`
	Result              stockRecoveryPreAdmissionResult `json:"result"`
}

type stockRecoveryPreAdmissionResult struct {
	Schema      string `json:"schema"`
	Operation   string `json:"operation_kind"`
	State       string `json:"state_result"`
	OperationID string `json:"operation_id"`
	RequestID   string `json:"request_id"`
	DomainID    string `json:"domain_id"`
	Identity    struct {
		Schema        string `json:"schema"`
		OperationID   string `json:"operation_id"`
		Operation     string `json:"operation_kind"`
		Stage         string `json:"stage"`
		Code          string `json:"code"`
		SourceSchema  string `json:"source_schema"`
		SourceProfile string `json:"source_profile"`
		Format        string `json:"format"`
		Nonce         string `json:"request_nonce"`
	} `json:"request_identity"`
	Replay      string     `json:"replay_identity"`
	Payload     *struct{}  `json:"payload"`
	Effect      string     `json:"effect_summary"`
	Output      string     `json:"output_summary"`
	Evidence    string     `json:"evidence_ceiling"`
	Commit      *bool      `json:"commit_may_have_occurred"`
	Diagnostics []struct{} `json:"diagnostics"`
}

func (v StockPluginRecoveryEvidence) ValidatePreAdmission(input StockPluginRecoveryInput, grant StockPluginGrant, artifact StockPluginArtifact, inv Invocation, original, index StockPluginEvidence, body []byte) error {
	if !StockPluginRecoveryProducerCompatible(artifact) || input.Predecessor == nil || input.PreAdmission != nil || input.Validate(v.OriginalRunID, v.RecoveryRunID) != nil || grant.Validate() != nil || grant.RunID != input.OriginalRunID || grant.LimitsSHA256 != input.OriginalLimitsSHA256 || inv.ValidateEvidence() != nil || inv.RunID != input.RecoveryRunID || inv.Role != "cleanup" || inv.Scenario != StockPluginScenario ||
		v.Schema != 1 || v.AdmissionSHA256 != input.ClaimSHA256() || v.CLISHA256 != artifact.CLI.SHA256 || v.OriginalGrant != grant || v.Prefix != grant.Prefix || v.FixtureID != grant.Fixture.FixtureID ||
		v.OriginalRunSHA256 != input.OriginalRun.SHA256 || v.OriginalEvidenceSHA256 != input.OriginalEvidence.SHA256 || v.AccountingSHA256 != input.Accounting.SHA256 ||
		v.ProductAllowance != input.ProductRemaining || v.OriginalCommands != input.OriginalCommands || v.PriorCommands != input.PriorCommands ||
		v.ProductReserved == nil || *v.ProductReserved != StockPluginRecoveryCommandReservation() || v.ProductElapsedSeconds == 0 || v.ProductElapsedSeconds > input.ProductRemaining.ElapsedSeconds ||
		v.Reflection != "incomplete" || v.Retirement != "incomplete" || v.ResidualExposure != "possible-live" || v.StoreCleanup != "not-entered" ||
		v.ListResultSHA256 != "" || v.WorkRevisionID != "" || v.WorkSnapshotID != "" || v.PrefixObservation != nil || len(v.Commands) != 1 || uint32(len(original.Commands)) != input.OriginalCommands {
		return errRecord
	}
	command := v.Commands[0]
	if command.Ordinal != input.OriginalCommands || command.Role != "apply" || command.Actor == "" || command.Phase != "failed-writer-cleanup" || command.Worker != inv.Worker || command.Nonce != inv.Nonce ||
		!command.Started || !command.Joined || command.ExitCode != 3 || command.ResultSHA256 != v.ProductResultSHA256 || !validHex(command.ResultSHA256, 32) || command.DiagnosticStatus != "observed" || uint32(len(body)) != command.DiagnosticBytes {
		return errRecord
	}
	digest := sha256.Sum256(body)
	want := original
	want.Commands = append(slices.Clone(original.Commands), command)
	if command.DiagnosticSHA256 != hex.EncodeToString(digest[:]) || !reflect.DeepEqual(index, want) {
		return errRecord
	}
	var d stockRecoveryPreAdmissionDiagnostic
	if publicEvidenceJSON(body, MaximumStockPluginDiagnosticBytes, &d) != nil || d.Schema != 1 || d.RunID != input.OriginalRunID || d.Ordinal != command.Ordinal || d.Worker != command.Worker || d.Nonce != command.Nonce || d.Phase != command.Phase || d.CLISHA256 != artifact.CLI.SHA256 || d.ResultSHA256 != command.ResultSHA256 || d.DigestScope != "complete" || d.CapturedBytes == 0 || d.CapturedBytes > stockRecoveryHistoricalCaptureBytes || d.Status != "observed" || d.StderrCapturedBytes == nil || *d.StderrCapturedBytes > stockRecoveryHistoricalCaptureBytes ||
		!reflect.DeepEqual(d.Uncaptured, []string{"names", "filesystem-paths", "locators", "values", "warning-text", "source-identifiers", "semantic-completeness"}) {
		return errRecord
	}
	for _, value := range []*bool{d.Started, d.WaitReturned, d.WaitHasProcessState, d.ProductJoined} {
		if value == nil || !*value {
			return errRecord
		}
	}
	for _, value := range []*bool{d.StdoutOverflow, d.StderrOverflow, d.TimedOut, d.StartSaveFailed, d.CLIChanged} {
		if value == nil || *value {
			return errRecord
		}
	}
	var envelope map[string]json.RawMessage
	var resultFields map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil || json.Unmarshal(envelope["result"], &resultFields) != nil || string(resultFields["payload"]) != "null" {
		return errRecord
	}
	r, q := d.Result, d.Result.Identity
	if r.Schema != "ProductResult/v1" || r.Operation != "clean-owned-failure-residue" || r.State != "unavailable" || !validHex(r.OperationID, 32) || !validHex(r.RequestID, 32) || !validHex(r.DomainID, 32) || r.OperationID == strings.Repeat("0", 64) || r.RequestID == strings.Repeat("0", 64) || r.DomainID == strings.Repeat("0", 64) ||
		q.Schema != "PreAdmissionRequestIdentity/v1" || q.OperationID != r.OperationID || q.Operation != r.Operation || q.Stage != "observation" || q.Code != "evidence-unavailable" || q.SourceSchema != "enkv/configuration/v3" || q.SourceProfile != "direct-candidate" || q.Format != "json" || q.Nonce != r.RequestID ||
		r.Replay != "none" || r.Payload != nil || r.Effect != "effect-no-change" || r.Output != "not-applicable" || r.Evidence != "unavailable" || r.Commit == nil || *r.Commit || r.Diagnostics == nil || len(r.Diagnostics) != 0 {
		return errRecord
	}
	return nil
}
