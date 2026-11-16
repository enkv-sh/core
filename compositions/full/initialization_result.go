package compositionfull

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var ErrInitializationResult = errors.New("initialization result rendering refused")

type initializationPayloadRecord struct {
	Schema               string `json:"schema"`
	InitID               string `json:"init_id"`
	DomainID             string `json:"domain_id"`
	DescriptorArtifactID string `json:"descriptor_artifact_id"`
	ManifestArtifactID   string `json:"manifest_artifact_id"`
	DescriptorDigest     string `json:"descriptor_digest"`
	StoreID              string `json:"store_id"`
	ReadyHeadRevisionID  string `json:"ready_head_revision_id"`
	SnapshotID           string `json:"snapshot_id"`
}

type initializationDeliveryRecord struct {
	Outcome        string             `json:"outcome"`
	EditablePath   string             `json:"editable_path,omitempty"`
	GeneratedPath  string             `json:"generated_path,omitempty"`
	ManifestPath   string             `json:"manifest_path,omitempty"`
	RecoverySource string             `json:"recovery_source,omitempty"`
	Readback       *setReadbackRecord `json:"readback,omitempty"`
	CleanupFailed  bool               `json:"cleanup_failed"`
}

type initializationResultRecord struct {
	SourceFailure         *ConfigurationSourceFailure        `json:"source_failure,omitempty"`
	Schema                string                             `json:"schema"`
	Operation             string                             `json:"operation_kind"`
	State                 contract.InitializationStateResult `json:"state_result"`
	Effect                string                             `json:"effect_summary"`
	Output                string                             `json:"output_summary"`
	OperationID           string                             `json:"operation_id,omitempty"`
	RequestIdentity       any                                `json:"request_identity,omitempty"`
	ReplayIdentity        string                             `json:"replay_identity,omitempty"`
	RequestedRevision     string                             `json:"requested_revision_id,omitempty"`
	ObservedRevision      string                             `json:"observed_revision_id,omitempty"`
	ObservedSnapshot      string                             `json:"observed_snapshot_id,omitempty"`
	CommitMayHaveOccurred bool                               `json:"commit_may_have_occurred"`
	EvidenceCeiling       string                             `json:"evidence_ceiling"`
	Warnings              []string                           `json:"warning_summary"`
	OperationPayload      string                             `json:"operation_payload"`
	Payload               *initializationPayloadRecord       `json:"payload,omitempty"`
	ReceiptHex            string                             `json:"receipt_hex,omitempty"`
	Delivery              initializationDeliveryRecord       `json:"local_delivery"`
}

func initializationRecord(r InitializationResult, deliveryErr error) (initializationResultRecord, error) {
	invalid := func() (initializationResultRecord, error) {
		return initializationResultRecord{}, ErrInitializationResult
	}
	if r.EffectSummary != "effect-no-change" || r.Result.Reason > core.CustodyUnavailable || r.Result.Evidence > core.AuthenticatedClosure || r.Result.StoreReason > contract.ReasonProof {
		return invalid()
	}
	ready := false
	switch r.StateResult {
	case contract.InitializationSuccess, contract.InitializationExactResume:
		ready = true
		if r.Result.Outcome != core.ObservedCurrent || r.Result.Evidence != core.AuthenticatedClosure || r.Result.Reason != core.NoReason || r.Result.StoreReason != contract.ReasonNone || r.Result.CommitMayHaveOccurred {
			return invalid()
		}
	case contract.InitializationRefused:
		if r.Result.Outcome != core.AdmissionRefused {
			return invalid()
		}
	case contract.InitializationUnavailable:
		if r.Result.Outcome != core.EvidenceUnavailable && r.Result.Outcome != core.RootLossUnsupported {
			return invalid()
		}
	case contract.InitializationContention:
		if r.Result.Outcome != core.Contention {
			return invalid()
		}
	case contract.InitializationCommitUnknown:
		if r.Result.Outcome != core.UnresolvedCommit {
			return invalid()
		}
	case contract.InitializationPositiveDefect:
		if r.Result.Outcome != core.IntegrityFailure {
			return invalid()
		}
	default:
		return invalid()
	}
	record := initializationResultRecord{Schema: "ProductResult/v1", Operation: "initialize-empty-domain", State: r.StateResult, Effect: r.EffectSummary, Output: "not-applicable",
		OperationID: readerID(r.OperationID), RequestedRevision: readerID(r.Result.RequestedRevision), ObservedRevision: readerID(r.Result.ObservedRevision), ObservedSnapshot: readerID(r.Result.ObservedSnapshotID),
		CommitMayHaveOccurred: r.Result.CommitMayHaveOccurred, EvidenceCeiling: "unavailable", Warnings: []string{}, OperationPayload: "none",
		Delivery: initializationDeliveryRecord{Outcome: "not-attempted", EditablePath: r.EditablePath, GeneratedPath: r.GeneratedPath, ManifestPath: r.ManifestPath, CleanupFailed: errors.Is(deliveryErr, errConfigurationObservationCleanup)}}
	record.SourceFailure = configurationSourceFailure("source", deliveryErr)
	if !validConfigurationAdmissionSourceFailure(record.SourceFailure, r.PreAdmission, r.RequestIdentity, r.Result) || record.SourceFailure != nil && r.ManifestPath != "" {
		return invalid()
	}
	if !r.RequestIdentity.IsZero() {
		record.RequestIdentity = readerID(r.RequestIdentity)
	}
	if r.PreAdmission != nil {
		identity, ok := preAdmissionIdentity(record.Operation, r.OperationID, r.PreAdmission)
		if !ok || !r.RequestIdentity.IsZero() || ready || r.Payload != nil || len(r.Receipt) != 0 || r.Result.CommitMayHaveOccurred {
			return invalid()
		}
		record.RequestIdentity, record.ReplayIdentity = identity, "none"
	}
	if ready {
		p := r.Payload
		if p == nil {
			return invalid()
		}
		for _, id := range []contract.ID{p.InitID, p.DomainID, p.DescriptorArtifactID, p.ManifestArtifactID, p.DescriptorDigest, p.StoreID, p.HeadRevisionID, p.SnapshotID, r.RequestIdentity} {
			if id.IsZero() {
				return invalid()
			}
		}
		if r.OperationID != p.InitID || r.Result.ObservedRevision != p.HeadRevisionID || r.Result.ObservedSnapshotID != p.SnapshotID || !r.Result.RequestedRevision.IsZero() && r.Result.RequestedRevision != p.HeadRevisionID {
			return invalid()
		}
		receipt, err := contract.InspectCompactMutationReceipt(r.Receipt)
		if err != nil || receipt.OperationKind != contract.OperationInitializeDomain || receipt.DomainID != p.DomainID || receipt.OperationID != p.InitID || receipt.RequestIdentityDigest != r.RequestIdentity ||
			receipt.RequestedRevisionID != p.HeadRevisionID || receipt.ObservedRevisionID != p.HeadRevisionID || receipt.StateResult != contract.ReceiptStateSuccess || receipt.EffectSummary != contract.ReceiptEffectNoChange || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected {
			return invalid()
		}
		record.OperationPayload = "InitPayload/v1"
		record.EvidenceCeiling = "canonical"
		record.Payload = &initializationPayloadRecord{Schema: "InitPayload/v1", InitID: readerID(p.InitID), DomainID: readerID(p.DomainID), DescriptorArtifactID: readerID(p.DescriptorArtifactID), ManifestArtifactID: readerID(p.ManifestArtifactID), DescriptorDigest: readerID(p.DescriptorDigest), StoreID: readerID(p.StoreID), ReadyHeadRevisionID: readerID(p.HeadRevisionID), SnapshotID: readerID(p.SnapshotID)}
		record.ReceiptHex = hex.EncodeToString(r.Receipt)
	} else if r.Payload != nil || len(r.Receipt) != 0 {
		return invalid()
	}
	if r.EditablePath != "" || r.GeneratedPath != "" || r.ManifestPath != "" {
		record.Delivery.Outcome = "recorded"
	}
	if deliveryErr != nil && r.DeliveryAttempted {
		record.Delivery.Outcome = "failed"
	}
	var unknown *configuration.UnknownEdit
	if errors.As(deliveryErr, &unknown) && unknown != nil {
		record.Delivery.Outcome = "unknown"
		if delivery, valid := unknown.Readback(); valid {
			editable, generated, err := delivery.Digests()
			if err != nil {
				return invalid()
			}
			ep, gp := delivery.Paths()
			if r.EditablePath != "" && r.EditablePath != ep || r.GeneratedPath != "" && r.GeneratedPath != gp {
				return invalid()
			}
			record.Delivery.EditablePath, record.Delivery.GeneratedPath = ep, gp
			record.Delivery.Readback = &setReadbackRecord{EditableDigest: hex.EncodeToString(editable[:]), GeneratedDigest: hex.EncodeToString(generated[:])}
			record.Delivery.CleanupFailed = record.Delivery.CleanupFailed || delivery.CleanupFailed()
			record.Delivery.Outcome = "recorded"
			record.Warnings = append(record.Warnings, "The local pair was read back. Later cleanup failed. This does not establish domain initialization.")
		}
		if source, valid := unknown.RecoverySource(); valid {
			record.Delivery.Outcome = "pending"
			record.Delivery.RecoverySource = source
			record.Warnings = append(record.Warnings, "A saved local edit is pending. Run recover with the recovery source and original format. This does not resume domain initialization.")
		} else if record.Delivery.Readback == nil {
			record.Warnings = append(record.Warnings, "Local delivery is unconfirmed. No exact recovery source was established; do not repeat initialization automatically.")
		}
	}
	if r.StateResult == contract.InitializationCommitUnknown {
		record.Warnings = append(record.Warnings, "The HEAD change may have occurred. Retain the delivered files for exact observation.")
	}
	if !validSetResultPaths([]string{record.Delivery.EditablePath, record.Delivery.GeneratedPath, record.Delivery.ManifestPath, record.Delivery.RecoverySource}) {
		return invalid()
	}
	return record, nil
}

// RenderInitializationJSON retains the Core outcome and local delivery facts on
// separate axes. A local path never establishes an authenticated ready domain.
func RenderInitializationJSON(r InitializationResult, deliveryErr error) ([]byte, error) {
	record, err := initializationRecord(r, deliveryErr)
	if err != nil {
		return nil, err
	}
	// Success has four escaped native paths, fixed IDs and a receipt.
	// Source refusal has three paths and the bounded source singleton.
	// Both complete alternatives fit 128 KiB.
	// The closed delivery/readback schema has depth at most three.
	return renderReadableResultJSON(128<<10, ErrInitializationResult, func(w *resultStreamWriter) {
		q := queryBegin(w)
		if record.SourceFailure != nil {
			q.field("source_failure", record.SourceFailure)
		}
		q.field("schema", record.Schema)
		q.field("operation_kind", record.Operation)
		q.field("state_result", record.State)
		q.field("effect_summary", record.Effect)
		q.field("output_summary", record.Output)
		if record.OperationID != "" {
			q.field("operation_id", record.OperationID)
		}
		if record.RequestIdentity != nil {
			q.field("request_identity", record.RequestIdentity)
		}
		if record.ReplayIdentity != "" {
			q.field("replay_identity", record.ReplayIdentity)
		}
		if record.RequestedRevision != "" {
			q.field("requested_revision_id", record.RequestedRevision)
		}
		if record.ObservedRevision != "" {
			q.field("observed_revision_id", record.ObservedRevision)
		}
		if record.ObservedSnapshot != "" {
			q.field("observed_snapshot_id", record.ObservedSnapshot)
		}
		q.field("commit_may_have_occurred", record.CommitMayHaveOccurred)
		q.field("evidence_ceiling", record.EvidenceCeiling)
		q.field("warning_summary", record.Warnings)
		q.field("operation_payload", record.OperationPayload)
		if record.Payload != nil {
			q.field("payload", record.Payload)
		}
		if record.ReceiptHex != "" {
			q.field("receipt_hex", record.ReceiptHex)
		}
		q.field("local_delivery", record.Delivery)
		q.end()
	})
}

func RenderInitializationHuman(r InitializationResult, deliveryErr error) ([]byte, error) {
	record, err := initializationRecord(r, deliveryErr)
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Initialization: %s\nLocal files: %s\n", record.State, record.Delivery.Outcome)
	if record.OperationID != "" {
		fmt.Fprintf(&out, "Operation ID: %s\n", record.OperationID)
	}
	if identity, ok := record.RequestIdentity.(string); ok {
		fmt.Fprintf(&out, "Request identity: %s\n", identity)
	}
	if record.Delivery.CleanupFailed {
		out.WriteString("Warning: local cleanup failed; retain the reported files.\n")
	}
	out.WriteString(configurationSourceFailureHuman(record.SourceFailure))
	for _, field := range []struct{ label, value string }{{"Editable file", record.Delivery.EditablePath}, {"Generated file", record.Delivery.GeneratedPath}, {"Recovery source", record.Delivery.RecoverySource}} {
		if field.value != "" {
			fmt.Fprintf(&out, "%s: %q\n", field.label, field.value)
		}
	}
	if record.Payload != nil {
		fmt.Fprintf(&out, "Domain: %s\n", record.Payload.DomainID)
	}
	if record.CommitMayHaveOccurred {
		out.WriteString("The domain change may have occurred. Retain the delivered files for exact observation.\n")
	}
	if identity, ok := record.RequestIdentity.(preAdmissionIdentityRecord); ok {
		fmt.Fprintf(&out, "Failure stage: %s; reason %s\n", identity.Stage, identity.Code)
	}
	for _, warning := range record.Warnings {
		fmt.Fprintf(&out, "Warning: %s\n", warning)
	}
	return []byte(out.String()), nil
}

func InitializationExitCode(r InitializationResult, deliveryErr error) int {
	record, err := initializationRecord(r, deliveryErr)
	if err != nil {
		return 2
	}
	if record.Delivery.Outcome == "pending" || record.Delivery.Outcome == "unknown" {
		return 3
	}
	if deliveryErr != nil {
		return 2
	}
	switch r.StateResult {
	case contract.InitializationSuccess, contract.InitializationExactResume:
		return 0
	case contract.InitializationUnavailable, contract.InitializationContention, contract.InitializationCommitUnknown:
		return 3
	default:
		return 2
	}
}
