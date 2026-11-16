package compositionfull

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
)

var ErrLocalEditResult = errors.New("local configuration result rendering refused")

// LocalEditResult retains only bounded public facts and opaque native receipts.
// It grants no domain transition, operation receipt or replay permission.
type LocalEditResult struct {
	action      string
	outcome     string
	target      any
	delivery    *configuration.PairDelivery
	unknown     *configuration.UnknownEdit
	pending     *configuration.PendingEdit
	paths       [2]string
	cleanupFail bool
}

type domainRenameTarget struct {
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}
type recipientPreparationTarget struct {
	Reference string                   `json:"reference"`
	Mode      RecipientPreparationMode `json:"mode"`
}
type recipientReferenceTarget struct {
	OldReference string `json:"old_reference"`
	NewReference string `json:"new_reference"`
}
type recoveryEditTarget struct {
	Source string `json:"source"`
}
type localEditReadback struct {
	EditableDigest  string  `json:"editable_digest"`
	GeneratedDigest *string `json:"generated_digest"`
}
type localEditDelivery struct {
	Outcome        string             `json:"outcome"`
	EditablePath   *string            `json:"editable_path"`
	GeneratedPath  *string            `json:"generated_path"`
	Readback       *localEditReadback `json:"readback"`
	RecoverySource *string            `json:"recovery_source"`
	CleanupFailed  bool               `json:"cleanup_failed"`
}
type localEditRecord struct {
	Schema        string                      `json:"schema"`
	Action        string                      `json:"local_edit"`
	Outcome       string                      `json:"outcome"`
	Target        any                         `json:"target"`
	Delivery      localEditDelivery           `json:"local_delivery"`
	Warnings      []string                    `json:"warning_summary"`
	SourceFailure *ConfigurationSourceFailure `json:"source_failure,omitempty"`
}

// NewLocalEditRefusal exposes no source or target facts for invalid dispatch.
func NewLocalEditRefusal(action string) (*LocalEditResult, error) {
	switch action {
	case "domain-rename", "recipient-preparation", "recipient-reference-rename", "recovery":
		return &LocalEditResult{action: action, outcome: "refused"}, nil
	default:
		return nil, ErrLocalEditResult
	}
}

func localResultPath(path string) bool {
	return path == "" || utf8.ValidString(path) && len(path) <= 4096 && !strings.ContainsRune(path, 0) && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func localResultReference(reference string) bool {
	return reference != "" && len(reference) <= 256 && utf8.ValidString(reference)
}

func localResultName(name string) bool {
	_, err := configuration.GeneratedPath(name)
	return err == nil
}

func localTargetValid(action string, target any) bool {
	if target == nil {
		return true
	}
	switch target := target.(type) {
	case domainRenameTarget:
		return action == "domain-rename" && localResultName(target.OldName) && localResultName(target.NewName)
	case recipientPreparationTarget:
		return action == "recipient-preparation" && localResultReference(target.Reference) && (target.Mode == RecipientPreparationCurrent || target.Mode == RecipientPreparationCreate)
	case recipientReferenceTarget:
		return action == "recipient-reference-rename" && localResultReference(target.OldReference) && localResultReference(target.NewReference)
	case recoveryEditTarget:
		return action == "recovery" && target.Source != "" && localResultPath(target.Source)
	}
	return false
}

func localEditResultRecord(r *LocalEditResult, deliveryErr error) (localEditRecord, error) {
	if r == nil || !localTargetValid(r.action, r.target) {
		return localEditRecord{}, ErrLocalEditResult
	}
	if _, err := NewLocalEditRefusal(r.action); err != nil {
		return localEditRecord{}, err
	}
	record := localEditRecord{Schema: "LocalEditResult/v1", Action: r.action, Outcome: r.outcome, Target: r.target,
		Delivery: localEditDelivery{Outcome: "not-recorded", CleanupFailed: r.cleanupFail}, Warnings: []string{}}
	record.SourceFailure = configurationSourceFailure("source", deliveryErr)
	if !validConfigurationSourceFailure(record.SourceFailure) || record.SourceFailure != nil && (r.outcome != "refused" || r.delivery != nil) {
		return localEditRecord{}, ErrLocalEditResult
	}
	if r.outcome != "refused" && r.outcome != "edited" && r.outcome != "pending" && r.outcome != "unknown" {
		return localEditRecord{}, ErrLocalEditResult
	}
	paths := r.paths
	if r.delivery != nil {
		editable, generated, err := r.delivery.Digests()
		if err != nil {
			return localEditRecord{}, ErrLocalEditResult
		}
		paths[0], paths[1] = r.delivery.Paths()
		record.Delivery.Outcome = "recorded"
		record.Delivery.Readback = &localEditReadback{EditableDigest: hex.EncodeToString(editable[:])}
		if paths[1] != "" {
			digest := hex.EncodeToString(generated[:])
			record.Delivery.Readback.GeneratedDigest = &digest
		}
		record.Delivery.CleanupFailed = record.Delivery.CleanupFailed || r.delivery.CleanupFailed() || deliveryErr != nil
	}
	var recovery string
	if source, valid := r.delivery.RecoverySource(); valid {
		recovery = source
	} else if source, valid := r.unknown.RecoverySource(); valid {
		recovery = source
	} else if source, valid := r.pending.RecoverySource(); valid {
		recovery = source
	}
	if recovery != "" {
		record.Outcome, record.Delivery.Outcome = "pending", "pending"
		record.Delivery.RecoverySource = &recovery
		record.Warnings = append(record.Warnings, "Run recover with the recovery source and original format to finish the saved local edit.")
	} else if r.outcome == "unknown" {
		if record.Delivery.Readback != nil {
			return localEditRecord{}, ErrLocalEditResult
		}
		record.Delivery.Outcome = "unknown"
		record.Warnings = append(record.Warnings, "Local delivery is uncertain; retain the pair and any saved local transaction.")
	} else if r.outcome == "pending" || r.outcome == "edited" && r.delivery == nil {
		return localEditRecord{}, ErrLocalEditResult
	}
	if record.Delivery.CleanupFailed {
		record.Warnings = append(record.Warnings, "Local cleanup did not complete.")
	}
	if r.action == "domain-rename" && r.delivery != nil {
		record.Warnings = append(record.Warnings, "Update external references to the generated path.")
	}
	for i, path := range paths {
		if path != "" {
			if i == 0 {
				record.Delivery.EditablePath = &paths[i]
			} else {
				record.Delivery.GeneratedPath = &paths[i]
			}
		}
	}
	allPaths := []string{paths[0], paths[1], recovery}
	if target, ok := r.target.(recoveryEditTarget); ok {
		allPaths = append(allPaths, target.Source)
	}
	for _, path := range allPaths {
		if !localResultPath(path) {
			return localEditRecord{}, ErrLocalEditResult
		}
	}
	if !validSetResultPaths(allPaths) {
		return localEditRecord{}, ErrLocalEditResult
	}
	return record, nil
}

func RenderLocalEditJSON(r *LocalEditResult, deliveryErr error) ([]byte, error) {
	record, err := localEditResultRecord(r, deliveryErr)
	if err != nil {
		return nil, err
	}
	// Four escaped paths cost at most 98,304 bytes, two recipient references
	// 3,072, readback hex 128, source failure 2,048, and framing/warnings 4,096.
	// This fits the existing compact ceiling. The closed maximum depth is 3.
	return renderReadableResultJSON(256<<10, ErrLocalEditResult, func(w *resultStreamWriter) {
		q := queryBegin(w)
		q.field("schema", record.Schema)
		q.field("local_edit", record.Action)
		q.field("outcome", record.Outcome)
		q.field("target", record.Target)
		q.object("local_delivery", func(d *queryObject) {
			d.field("outcome", record.Delivery.Outcome)
			d.field("editable_path", record.Delivery.EditablePath)
			d.field("generated_path", record.Delivery.GeneratedPath)
			d.field("readback", record.Delivery.Readback)
			d.field("recovery_source", record.Delivery.RecoverySource)
			d.field("cleanup_failed", record.Delivery.CleanupFailed)
		})
		q.field("warning_summary", record.Warnings)
		if record.SourceFailure != nil {
			q.field("source_failure", record.SourceFailure)
		}
		q.end()
	})
}

func RenderLocalEditHuman(r *LocalEditResult, deliveryErr error) ([]byte, error) {
	record, err := localEditResultRecord(r, deliveryErr)
	if err != nil {
		return nil, err
	}
	label := map[string]string{"domain-rename": "Domain rename", "recipient-preparation": "Recipient preparation", "recipient-reference-rename": "Recipient reference rename", "recovery": "Local edit recovery"}[record.Action]
	var out strings.Builder
	fmt.Fprintf(&out, "%s: %s\n", label, record.Outcome)
	switch target := record.Target.(type) {
	case domainRenameTarget:
		fmt.Fprintf(&out, "Domain: %q -> %q\n", target.OldName, target.NewName)
	case recipientPreparationTarget:
		fmt.Fprintf(&out, "Recipient: %q (%s)\n", target.Reference, target.Mode)
	case recipientReferenceTarget:
		fmt.Fprintf(&out, "Recipient reference: %q -> %q\n", target.OldReference, target.NewReference)
	case recoveryEditTarget:
		fmt.Fprintf(&out, "Recovery source: %q\n", target.Source)
	}
	fmt.Fprintf(&out, "Local files: %s\n", record.Delivery.Outcome)
	for _, path := range []struct {
		label string
		value *string
	}{{"Editable file", record.Delivery.EditablePath}, {"Generated file", record.Delivery.GeneratedPath}, {"Recovery source", record.Delivery.RecoverySource}} {
		if path.value != nil && (path.label == "Recovery source" || record.Action == "domain-rename" && path.label == "Generated file" || deliveryErr != nil || record.Delivery.CleanupFailed || record.Outcome != "edited" || record.Action == "recovery") {
			fmt.Fprintf(&out, "%s: %q\n", path.label, *path.value)
		}
	}
	out.WriteString(configurationSourceFailureHuman(record.SourceFailure))
	for _, warning := range record.Warnings {
		fmt.Fprintf(&out, "Warning: %s\n", warning)
	}
	return []byte(out.String()), nil
}

func LocalEditExitCode(r *LocalEditResult, deliveryErr error) int {
	record, err := localEditResultRecord(r, deliveryErr)
	if err != nil {
		return 2
	}
	if record.Outcome == "pending" || record.Outcome == "unknown" {
		return 3
	}
	if record.Outcome != "edited" || record.Delivery.CleanupFailed || deliveryErr != nil {
		return 2
	}
	return 0
}
