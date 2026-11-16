package records

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// Accounting is a local assertion that the listed retained diagnostics are the
// complete additional history. Their exact scope and result bytes are checked
// by the recovery owner before it derives a remaining Product allowance.
type StockPluginRecoveryAccounting struct {
	Schema                 uint16                          `json:"schema"`
	RunID                  string                          `json:"run_id"`
	Complete               bool                            `json:"complete"`
	OriginalRunSHA256      string                          `json:"original_run_sha256"`
	OriginalInputSHA256    string                          `json:"original_input_sha256"`
	OriginalEvidenceSHA256 string                          `json:"original_evidence_sha256"`
	OriginalGrantSHA256    string                          `json:"original_grant_sha256"`
	Sources                []StockPluginFile               `json:"sources"`
	Diagnostics            []StockPluginRecoveryDiagnostic `json:"diagnostics"`
}

type StockPluginRecoveryDiagnostic struct {
	Scope  StockPluginFile `json:"scope"`
	Result StockPluginFile `json:"result"`
}

type StockPluginRecoveryOriginal struct {
	OperationID      string `json:"operation_id"`
	AttemptID        string `json:"attempt_id"`
	OwnerID          string `json:"owner_id"`
	HazardID         string `json:"hazard_id"`
	ResourceID       string `json:"resource_id"`
	DescriptorID     string `json:"descriptor_id"`
	ExecutorID       string `json:"executor_id"`
	CredentialRoute  string `json:"credential_route_id"`
	ResultContractID string `json:"result_contract_id"`
}

type StockPluginRecoveryPredecessor struct {
	RunID      string          `json:"run_id"`
	Claim      StockPluginFile `json:"claim"`
	Run        StockPluginFile `json:"run"`
	Input      StockPluginFile `json:"input"`
	Invocation StockPluginFile `json:"invocation"`
	Result     StockPluginFile `json:"result"`
	Worker     StockPluginFile `json:"worker"`
	Failure    StockPluginFile `json:"failure"`
}

type StockPluginRecoveryInput struct {
	Predecessor          *StockPluginRecoveryPredecessor  `json:"predecessor,omitempty"`
	PreAdmission         *StockPluginRecoveryPreAdmission `json:"pre_admission,omitempty"`
	Schema               uint16                           `json:"schema"`
	OriginalRunID        string                           `json:"original_run_id"`
	RecoveryRunID        string                           `json:"recovery_run_id"`
	OriginalRun          StockPluginFile                  `json:"original_run"`
	OriginalInput        StockPluginFile                  `json:"original_input"`
	OriginalEvidence     StockPluginFile                  `json:"original_evidence"`
	OriginalGrant        StockPluginFile                  `json:"original_grant"`
	Accounting           StockPluginFile                  `json:"accounting"`
	Sources              []StockPluginFile                `json:"sources"`
	Originals            []StockPluginRecoveryOriginal    `json:"originals"`
	OriginalLimitsSHA256 string                           `json:"original_limits_sha256"`
	CleanupLimitsSHA256  string                           `json:"cleanup_limits_sha256"`
	ProductRemaining     LiveLimits                       `json:"product_remaining"`
	OriginalCommands     uint32                           `json:"original_commands"`
	PriorCommands        uint32                           `json:"prior_commands"`
	PriorVerifications   uint32                           `json:"prior_verifications"`
}

func (v StockPluginRecoveryInput) Validate(original, recovery string) error {
	if v.Schema != 1 || !ValidRunID(original) || !ValidRunID(recovery) || original == recovery ||
		v.OriginalRunID != original || v.RecoveryRunID != recovery ||
		!validHex(v.OriginalLimitsSHA256, 32) || !validHex(v.CleanupLimitsSHA256, 32) ||
		v.OriginalCommands == 0 || v.OriginalCommands > v.PriorCommands || v.PriorCommands > MaximumStockPluginCommands-2 || v.PriorVerifications > MaximumStockPluginVerifications ||
		len(v.Sources) != 2 || len(v.Originals) == 0 || len(v.Originals) > 128 || v.ProductRemaining.Requests < 256 || v.ProductRemaining.BodyBytes < 32<<20 ||
		v.ProductRemaining.Objects < 128 || v.ProductRemaining.ObjectBytes < 32<<20 || v.ProductRemaining.GeneratorRetires < 3 || v.ProductRemaining.ElapsedSeconds < 240 {
		return errRecord
	}
	if prior := v.Predecessor; prior != nil {
		if !ValidRunID(prior.RunID) || prior.RunID == original || prior.RunID == recovery || prior.Claim.Path != filepath.Join(filepath.Dir(v.OriginalInput.Path), "stock-recovery-claim.json") {
			return errRecord
		}
		for _, file := range prior.Files() {
			if !file.valid(MaximumJSONBytes) {
				return errRecord
			}
		}
	}
	if p := v.PreAdmission; p != nil {
		if v.Predecessor == nil || p.Validate(v) != nil {
			return errRecord
		}
	}
	for _, file := range []StockPluginFile{v.OriginalRun, v.OriginalInput, v.OriginalEvidence, v.OriginalGrant, v.Accounting} {
		if !file.valid(MaximumJSONBytes) {
			return errRecord
		}
	}
	for i, file := range v.Sources {
		if !file.valid(8<<20) || i != 0 && v.Sources[i-1].Path >= file.Path {
			return errRecord
		}
	}
	for i, original := range v.Originals {
		for _, id := range []string{original.OperationID, original.AttemptID, original.OwnerID, original.HazardID, original.ResourceID, original.DescriptorID, original.ExecutorID, original.CredentialRoute, original.ResultContractID} {
			if !validHex(id, 32) || id == strings.Repeat("0", 64) {
				return errRecord
			}
		}
		if i != 0 && v.Originals[i-1].HazardID >= original.HazardID {
			return errRecord
		}
	}
	return nil
}

func (v StockPluginRecoveryInput) ClaimName() string {
	if v.PreAdmission != nil {
		return StockPluginRecoveryPreAdmissionClaim
	}
	if v.Predecessor != nil {
		return "stock-recovery-successor-claim.json"
	}
	return "stock-recovery-claim.json"
}

// Claims are published with this canonical encoding and one final newline.
func (v StockPluginRecoveryInput) ClaimSHA256() string {
	body, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append(body, '\n'))
	return hex.EncodeToString(digest[:])
}

// This result describes recovery of failed work. It is never a successful stock
// lifecycle assertion and is written under the new cleanup worker's owner.
type StockPluginRecoveryEvidence struct {
	AdmissionSHA256        string                    `json:"admission_sha256,omitempty"`
	Schema                 uint16                    `json:"schema"`
	OriginalRunID          string                    `json:"original_run_id"`
	RecoveryRunID          string                    `json:"recovery_run_id"`
	Prefix                 string                    `json:"prefix"`
	FixtureID              string                    `json:"fixture_id"`
	CLISHA256              string                    `json:"cli_sha256"`
	OriginalRunSHA256      string                    `json:"original_run_sha256"`
	OriginalEvidenceSHA256 string                    `json:"original_evidence_sha256"`
	AccountingSHA256       string                    `json:"accounting_sha256"`
	OriginalGrant          StockPluginGrant          `json:"original_grant"`
	ProductAllowance       LiveLimits                `json:"product_allowance"`
	OriginalCommands       uint32                    `json:"original_commands"`
	PriorCommands          uint32                    `json:"prior_commands"`
	Commands               []StockPluginCommand      `json:"commands"`
	ProductReserved        *BudgetReservation        `json:"product_reserved"`
	ProductElapsedSeconds  uint64                    `json:"product_elapsed_seconds"`
	ProductResultSHA256    string                    `json:"product_result_sha256,omitempty"`
	ListResultSHA256       string                    `json:"list_result_sha256,omitempty"`
	WorkRevisionID         string                    `json:"work_revision_id,omitempty"`
	WorkSnapshotID         string                    `json:"work_snapshot_id,omitempty"`
	Reflection             string                    `json:"reflection"`
	Retirement             string                    `json:"retirement"`
	ResidualExposure       string                    `json:"residual_exposure"`
	StoreCleanup           string                    `json:"store_cleanup"`
	PrefixObservation      *StockPluginPrefixCleanup `json:"prefix_observation,omitempty"`
}

func (v StockPluginRecoveryEvidence) ValidateClosed(input StockPluginRecoveryInput, grant StockPluginGrant, cliSHA256 string) error {
	if input.Validate(v.OriginalRunID, v.RecoveryRunID) != nil || grant.Validate() != nil || v.AdmissionSHA256 != input.ClaimSHA256() ||
		v.CLISHA256 != cliSHA256 || !validHex(v.CLISHA256, 32) || v.OriginalRunSHA256 != input.OriginalRun.SHA256 ||
		v.OriginalEvidenceSHA256 != input.OriginalEvidence.SHA256 || v.AccountingSHA256 != input.Accounting.SHA256 ||
		grant.LimitsSHA256 != input.OriginalLimitsSHA256 || v.OriginalGrant != grant || v.ProductAllowance != input.ProductRemaining ||
		v.OriginalCommands != input.OriginalCommands || v.PriorCommands != input.PriorCommands {
		return errRecord
	}
	return v.ValidateRecorded(v.OriginalRunID, v.RecoveryRunID)
}

func (v StockPluginRecoveryEvidence) ValidateRecorded(original, recovery string) error {
	grant := v.OriginalGrant
	if v.Schema != 1 || !ValidRunID(original) || !ValidRunID(recovery) || original == recovery || v.OriginalRunID != original || v.RecoveryRunID != recovery ||
		!validHex(v.AdmissionSHA256, 32) || grant.Validate() != nil || v.OriginalRunID != grant.RunID || v.Prefix != grant.Prefix || v.FixtureID != grant.Fixture.FixtureID ||
		!validHex(v.CLISHA256, 32) || !validHex(v.OriginalRunSHA256, 32) || !validHex(v.OriginalEvidenceSHA256, 32) || !validHex(v.AccountingSHA256, 32) ||
		!validHex(v.WorkRevisionID, 32) || !validHex(v.WorkSnapshotID, 32) ||
		v.OriginalCommands == 0 || v.OriginalCommands > v.PriorCommands || v.PriorCommands > MaximumStockPluginCommands-2 ||
		v.ProductReserved == nil || v.ProductReserved.GeneratorCreates != 0 ||
		v.ProductReserved.Requests < 256 || v.ProductReserved.BodyBytes < 32<<20 || v.ProductReserved.Objects < 128 || v.ProductReserved.ObjectBytes < 32<<20 || v.ProductReserved.GeneratorRetires < 3 || v.ProductElapsedSeconds == 0 ||
		v.ProductReserved.Requests > v.ProductAllowance.Requests || v.ProductReserved.BodyBytes > v.ProductAllowance.BodyBytes ||
		v.ProductReserved.Objects > v.ProductAllowance.Objects || v.ProductReserved.ObjectBytes > v.ProductAllowance.ObjectBytes ||
		v.ProductReserved.GeneratorRetires > v.ProductAllowance.GeneratorRetires || v.ProductElapsedSeconds > v.ProductAllowance.ElapsedSeconds ||
		len(v.Commands) != 2 || v.Reflection != "observed" && v.Reflection != "not-required" ||
		v.Retirement != "deletion-acknowledged" && v.Retirement != "not-required" || v.ResidualExposure != "none" ||
		v.StoreCleanup != "observed-empty" || v.PrefixObservation == nil || v.PrefixObservation.Validate(grant) != nil {
		return errRecord
	}
	for i, command := range v.Commands {
		role, phase := "apply", "failed-writer-cleanup"
		if i == 1 {
			role, phase = "reader", "generated-list"
		}
		if command.Ordinal != v.OriginalCommands+uint32(i) || command.Role != role || command.Phase != phase ||
			command.Actor == "" || command.Worker == "" || !validHex(command.Nonce, 16) || !command.Started || !command.Joined || command.ExitCode != 0 ||
			!validHex(command.ResultSHA256, 32) || !validHex(command.DiagnosticSHA256, 32) || command.DiagnosticBytes == 0 ||
			command.DiagnosticBytes > MaximumStockPluginDiagnosticBytes || command.DiagnosticStatus != "observed" ||
			i != 0 && (command.Worker != v.Commands[0].Worker || command.Nonce != v.Commands[0].Nonce) {
			return errRecord
		}
	}
	if v.ProductResultSHA256 != v.Commands[0].ResultSHA256 || v.ListResultSHA256 != v.Commands[1].ResultSHA256 ||
		!strings.HasPrefix(v.Prefix, "enkv-test/"+v.OriginalRunID+"/") {
		return errRecord
	}
	return nil
}

// The first cleanup command reserves its complete cost before retaining intent.
func StockPluginRecoveryCommandReservation() BudgetReservation {
	return BudgetReservation{Requests: 128, BodyBytes: 16 << 20, Objects: 128, ObjectBytes: 32 << 20, GeneratorRetires: 3}
}

// No dispatch does not establish closure of the original provider work.
func (v StockPluginRecoveryEvidence) ValidateNoDispatch(input StockPluginRecoveryInput, grant StockPluginGrant, cliSHA256 string) error {
	if input.Predecessor != nil || input.Validate(v.OriginalRunID, v.RecoveryRunID) != nil || grant.Validate() != nil ||
		v.Schema != 1 || v.OriginalRunID != input.OriginalRunID || v.RecoveryRunID != input.RecoveryRunID ||
		v.AdmissionSHA256 != "" && v.AdmissionSHA256 != input.ClaimSHA256() ||
		v.Prefix != grant.Prefix || v.FixtureID != grant.Fixture.FixtureID || v.CLISHA256 != cliSHA256 ||
		v.OriginalGrant != grant || grant.RunID != input.OriginalRunID || grant.LimitsSHA256 != input.OriginalLimitsSHA256 ||
		v.OriginalRunSHA256 != input.OriginalRun.SHA256 || v.OriginalEvidenceSHA256 != input.OriginalEvidence.SHA256 || v.AccountingSHA256 != input.Accounting.SHA256 ||
		v.ProductAllowance != input.ProductRemaining || v.OriginalCommands != input.OriginalCommands || v.PriorCommands != input.PriorCommands ||
		v.Commands == nil || len(v.Commands) != 0 || v.ProductReserved == nil || *v.ProductReserved != StockPluginRecoveryCommandReservation() || v.ProductElapsedSeconds == 0 || v.ProductElapsedSeconds > input.ProductRemaining.ElapsedSeconds ||
		v.ProductReserved.GeneratorCreates != 0 || v.ProductReserved.Requests > input.ProductRemaining.Requests || v.ProductReserved.BodyBytes > input.ProductRemaining.BodyBytes ||
		v.ProductReserved.Objects > input.ProductRemaining.Objects || v.ProductReserved.ObjectBytes > input.ProductRemaining.ObjectBytes || v.ProductReserved.GeneratorRetires > input.ProductRemaining.GeneratorRetires ||
		v.Reflection != "not-entered" || v.Retirement != "not-entered" || v.ResidualExposure != "unknown" || v.StoreCleanup != "not-entered" ||
		v.ProductResultSHA256 != "" || v.ListResultSHA256 != "" || v.WorkRevisionID != "" || v.WorkSnapshotID != "" || v.PrefixObservation != nil {
		return errRecord
	}
	return nil
}

// ValidateClaim authenticates the selected admission and its retained predecessors.
// The runner has already checked terminal process ownership before publishing it.
func (v StockPluginRecoveryInput) ValidateClaim(state string) error {
	path, err := SafePath(state, v.ClaimName())
	var selected StockPluginRecoveryInput
	body, readErr := ReadJSONBytes(path, MaximumJSONBytes)
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != v.ClaimSHA256() || err != nil || readErr != nil || decodeJSON(body, &selected) != nil || !reflect.DeepEqual(selected, v) {
		return errRecord
	}
	if v.Predecessor == nil {
		return nil
	}
	p := v.Predecessor
	if p.ValidateFiles() != nil {
		return errRecord
	}
	var first StockPluginRecoveryInput
	if ReadJSON(p.Claim.Path, &first) != nil || first.Predecessor != nil || first.PreAdmission != nil || first.RecoveryRunID != p.RunID {
		return errRecord
	}
	if v.PreAdmission != nil && v.PreAdmission.VerifyFiles(v) != nil {
		return errRecord
	}
	return nil
}

func (p StockPluginRecoveryPredecessor) ValidateFiles() error {
	for _, file := range p.Files() {
		body, err := ReadJSONBytes(file.Path, MaximumJSONBytes)
		digest := sha256.Sum256(body)
		if err != nil || uint64(len(body)) != file.Length || hex.EncodeToString(digest[:]) != file.SHA256 {
			return errRecord
		}
	}
	var inv Invocation
	invErr := ReadJSON(p.Invocation.Path, &inv)
	var marker FailureMarker
	if invErr != nil || inv.ValidateEvidence() != nil || ReadJSONLimit(p.Failure.Path, &marker, MaximumFailureBytes) != nil || marker.ValidateIdentity(inv) != nil {
		return errRecord
	}
	output := filepath.Dir(p.Invocation.Path)
	for _, name := range []string{"stock-plugin-evidence.json", "stock-prefix-cleanup.json", "checkpoint.json"} {
		path, err := SafePath(output, name)
		if err != nil {
			return errRecord
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errRecord
		}
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) > 256 {
		return errRecord
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), "stock-result-") {
			return errRecord
		}
		if strings.HasPrefix(entry.Name(), "stock-command-") {
			if !entry.IsDir() {
				return errRecord
			}
			children, err := os.ReadDir(filepath.Join(output, entry.Name()))
			if err != nil || len(children) != 0 {
				return errRecord
			}
		}
	}
	return nil
}

func ReadStockPluginRecoveryEvidence(path string) (StockPluginRecoveryEvidence, error) {
	body, err := ReadJSONBytes(path, MaximumStockPluginEvidenceBytes)
	var value StockPluginRecoveryEvidence
	if err != nil || publicEvidenceJSON(body, MaximumStockPluginEvidenceBytes, &value) != nil {
		return StockPluginRecoveryEvidence{}, errRecord
	}
	return value, nil
}
