package compositionfull

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// SetStateResult describes confidential local artifact preparation. This adapter
// does not implement an exact-resume path.
type SetStateResult string

const (
	SetSuccess        SetStateResult = "success"
	SetRefused        SetStateResult = "refused"
	SetProfileBlocked SetStateResult = "profile-blocked"
	SetUnavailable    SetStateResult = "unavailable"
	SetPositiveDefect SetStateResult = "positive-defect"
)

type SetArtifactTarget struct {
	DomainID contract.ID
	Name     string
}
type SetPairReadback struct{ EditableDigest, GeneratedDigest contract.ID }

// SealedArtifactPayload contains ciphertext-derived and public source facts only.
// The renderer verifies its readback against the result's opaque native receipt.
type SealedArtifactPayload struct {
	InputFileID, PredecessorDigest contract.ID
	Target                         SetArtifactTarget
	SealedArtifactDigest           contract.ID
	Readback                       SetPairReadback
}

type ArtifactRequestIdentity struct {
	InputFileID, PredecessorDigest                           contract.ID
	Target                                                   SetArtifactTarget
	RecipientImageDigest, SealedArtifactDigest, RequestNonce contract.ID
}

type SetPreAdmissionIdentity struct{ Stage, Code string }

// SetResult describes a local proposal. It establishes neither domain readiness
// nor permission or eligibility to apply that proposal. Plain editing is separate.
type SetResult struct {
	EditablePath, GeneratedPath string
	Confidential                bool
	StateResult                 SetStateResult
	OperationID, RequestNonce   contract.ID
	RequestIdentity             *ArtifactRequestIdentity
	PreAdmission                *SetPreAdmissionIdentity
	Payload                     *SealedArtifactPayload
	sourceFormat                configuration.Format
	delivery                    *configuration.PairDelivery
	fixedPayload                SealedArtifactPayload
	fixedRequest                ArtifactRequestIdentity
	localFailure                *configuration.UnknownEdit
	failurePaths                [2]string
}

var ErrSetResult = errors.New("configuration set result rendering refused")

type setTargetRecord struct {
	DomainID string `json:"domain_id"`
	Name     string `json:"name"`
}
type setReadbackRecord struct {
	EditableDigest  string `json:"editable_digest"`
	GeneratedDigest string `json:"generated_digest"`
}
type sealedArtifactPayloadRecord struct {
	Schema               string            `json:"schema"`
	InputFileID          string            `json:"input_file_id"`
	PredecessorDigest    string            `json:"predecessor_digest"`
	Target               setTargetRecord   `json:"target"`
	SealedArtifactDigest string            `json:"sealed_artifact_digest"`
	Readback             setReadbackRecord `json:"readback"`
}
type artifactRequestRecord struct {
	Schema               string          `json:"schema"`
	InputFileID          string          `json:"input_file_id"`
	PredecessorDigest    string          `json:"predecessor_digest"`
	Target               setTargetRecord `json:"target"`
	RecipientImageDigest string          `json:"recipient_image_digest"`
	SealedArtifactDigest string          `json:"sealed_artifact_digest"`
	RequestNonce         string          `json:"request_nonce"`
}
type setDeliveryRecord struct {
	Outcome        string `json:"outcome"`
	EditablePath   string `json:"editable_path,omitempty"`
	GeneratedPath  string `json:"generated_path,omitempty"`
	RecoverySource string `json:"recovery_source,omitempty"`
	CleanupFailed  bool   `json:"cleanup_failed"`
}
type setProductRecord struct {
	SourceFailure    *ConfigurationSourceFailure  `json:"source_failure,omitempty"`
	Schema           string                       `json:"schema"`
	Operation        string                       `json:"operation_kind"`
	OperationID      string                       `json:"operation_id"`
	State            SetStateResult               `json:"state_result"`
	Effect           string                       `json:"effect_summary"`
	Output           string                       `json:"output_summary"`
	RequestIdentity  any                          `json:"request_identity"`
	ReplayIdentity   string                       `json:"replay_identity"`
	EvidenceCeiling  string                       `json:"evidence_ceiling"`
	Effects          []string                     `json:"effects"`
	Outputs          []string                     `json:"outputs"`
	Duties           []string                     `json:"duties"`
	Hazards          []string                     `json:"hazards"`
	OperationPayload string                       `json:"operation_payload"`
	Payload          *sealedArtifactPayloadRecord `json:"payload,omitempty"`
	CapsulePolicy    string                       `json:"capsule_policy"`
	Warnings         []string                     `json:"warning_summary"`
	Delivery         setDeliveryRecord            `json:"local_delivery"`
}

func setTargetWire(t SetArtifactTarget) setTargetRecord {
	return setTargetRecord{readerID(t.DomainID), t.Name}
}
func setProductResult(r *SetResult, deliveryErr error) (setProductRecord, error) {
	invalid := func() (setProductRecord, error) { return setProductRecord{}, ErrSetResult }
	if r == nil || !r.Confidential || r.OperationID.IsZero() || r.RequestNonce.IsZero() {
		return invalid()
	}
	switch r.StateResult {
	case SetSuccess, SetRefused, SetProfileBlocked, SetUnavailable, SetPositiveDefect:
	default:
		return invalid()
	}
	sourceFailure := configurationSourceFailure("source", deliveryErr)
	if !validConfigurationSourceFailure(sourceFailure) || sourceFailure != nil && (r.PreAdmission == nil || r.StateResult == SetSuccess || r.Payload != nil || r.RequestIdentity != nil || r.delivery != nil) {
		return invalid()
	}
	record := setProductRecord{SourceFailure: sourceFailure, Schema: "ProductResult/v1", Operation: contract.SetConfidentialOperation, OperationID: readerID(r.OperationID), State: r.StateResult, Effect: "not-applicable", Output: "not-applicable", RequestIdentity: "none", ReplayIdentity: "none", EvidenceCeiling: "unavailable", Effects: []string{}, Outputs: []string{}, Duties: []string{}, Hazards: []string{}, OperationPayload: "none", CapsulePolicy: "none", Warnings: []string{}, Delivery: setDeliveryRecord{Outcome: "not-recorded", EditablePath: r.EditablePath, GeneratedPath: r.GeneratedPath, CleanupFailed: errors.Is(deliveryErr, errConfigurationObservationCleanup)}}
	if r.RequestIdentity != nil {
		q := r.RequestIdentity
		if *q != r.fixedRequest || q.InputFileID.IsZero() || q.PredecessorDigest.IsZero() || q.Target.DomainID.IsZero() || q.RecipientImageDigest.IsZero() || q.SealedArtifactDigest.IsZero() || q.RequestNonce != r.RequestNonce || len(q.Target.Name) > contract.CryptoMaxName || !utf8.ValidString(q.Target.Name) {
			return invalid()
		}
		record.RequestIdentity = artifactRequestRecord{Schema: "ArtifactRequestIdentity/v1", InputFileID: readerID(q.InputFileID), PredecessorDigest: readerID(q.PredecessorDigest), Target: setTargetWire(q.Target), RecipientImageDigest: readerID(q.RecipientImageDigest), SealedArtifactDigest: readerID(q.SealedArtifactDigest), RequestNonce: readerID(q.RequestNonce)}
	} else {
		if r.PreAdmission == nil || !validSetFailureStage(r.PreAdmission.Stage) || !validSetFailureStage(r.PreAdmission.Code) {
			return invalid()
		}
		format := ""
		switch r.sourceFormat {
		case configuration.JSON:
			format = "json"
		case configuration.YAML:
			format = "yaml"
		}
		record.RequestIdentity = preAdmissionIdentityRecord{Schema: "PreAdmissionRequestIdentity/v1", OperationID: readerID(r.OperationID), OperationKind: contract.SetConfidentialOperation, Stage: r.PreAdmission.Stage, Code: r.PreAdmission.Code, RequestNonce: readerID(r.RequestNonce), SourceSchema: "enkv/configuration/v3", SourceProfile: "direct-candidate", Format: format}
	}
	if r.StateResult == SetSuccess {
		if r.Payload == nil || r.RequestIdentity == nil || *r.Payload != r.fixedPayload {
			return invalid()
		}
		p := r.Payload
		q := r.RequestIdentity
		editable, generated, err := r.delivery.Digests()
		if err != nil || generated == ([32]byte{}) {
			return invalid()
		}
		ep, gp := r.delivery.Paths()
		if ep != r.EditablePath || gp != r.GeneratedPath || p.InputFileID != q.InputFileID || p.PredecessorDigest != q.PredecessorDigest || p.Target != q.Target || p.SealedArtifactDigest != q.SealedArtifactDigest || p.Readback.EditableDigest != contract.ID(editable) || p.Readback.GeneratedDigest != contract.ID(generated) {
			return invalid()
		}
		record.OperationPayload = "SealedArtifactPayload/v1"
		record.EvidenceCeiling = "exact-local-pair-readback"
		record.Payload = &sealedArtifactPayloadRecord{Schema: record.OperationPayload, InputFileID: readerID(p.InputFileID), PredecessorDigest: readerID(p.PredecessorDigest), Target: setTargetWire(p.Target), SealedArtifactDigest: readerID(p.SealedArtifactDigest), Readback: setReadbackRecord{readerID(p.Readback.EditableDigest), readerID(p.Readback.GeneratedDigest)}}
		record.Delivery.Outcome = "recorded"
		if deliveryErr != nil {
			record.Delivery.CleanupFailed = true
			record.Warnings = append(record.Warnings, "The local pair was read back. Later cleanup failed; retain the confirmed paths.")
		}
	} else if r.Payload != nil || r.delivery != nil {
		return invalid()
	}
	var unknown *configuration.UnknownEdit
	if errors.As(deliveryErr, &unknown) && r.StateResult != SetSuccess {
		source, valid := unknown.RecoverySource()
		if r.StateResult != SetUnavailable || unknown == nil || r.localFailure != unknown || r.failurePaths != [2]string{r.EditablePath, r.GeneratedPath} {
			return invalid()
		}
		record.Delivery.Outcome = "unknown"
		if valid {
			record.Delivery.Outcome = "pending"
			record.Delivery.RecoverySource = source
			record.Warnings = append(record.Warnings, "A saved local edit is pending. Run recover with the recovery source and original format. Do not supply the value again.")
		} else {
			record.Warnings = append(record.Warnings, "Local delivery is unconfirmed. No recovery source was established; retain local files and do not repeat this edit automatically.")
		}
	} else if source, valid := r.delivery.RecoverySource(); valid {
		record.Delivery.Outcome = "pending"
		record.Delivery.RecoverySource = source
		record.Warnings = append(record.Warnings, "The local pair was read back. Run recover with the recovery source and original format to finish cleanup.")
	}
	if !validSetResultPaths([]string{r.EditablePath, r.GeneratedPath, record.Delivery.RecoverySource}) {
		return invalid()
	}
	return record, nil
}

func validSetFailureStage(s string) bool {
	switch s {
	case "dispatch", "input", "target", "deadline", "source", "prepared-source", "public-configuration", "public-basis", "prepared-keys", "candidate-bounds", "prepared-recipient", "candidate", "candidate-target", "delivery", "local-cleanup", "input-close", "cancelled", "unavailable", "refused", "profile-blocked", "positive-defect":
		return true
	}
	return false
}

// RenderSetJSON emits a Product result for confidential preparation. Plain editing
// has a separate local-edit result and cannot carry a sealed artifact payload.
func RenderSetJSON(r *SetResult, deliveryErr error) ([]byte, error) {
	if r == nil {
		return nil, ErrSetResult
	}
	if !r.Confidential {
		record, err := setPlainResult(r, deliveryErr)
		if err != nil {
			return nil, err
		}
		return renderReadableResultJSON(256<<10, ErrSetResult, func(w *resultStreamWriter) {
			q := queryBegin(w)
			if record.SourceFailure != nil {
				q.field("source_failure", record.SourceFailure)
			}
			q.field("local_edit", record.LocalEdit)
			q.field("outcome", record.Outcome)
			q.field("local_delivery", record.Delivery)
			q.field("warning_summary", record.Warnings)
			q.end()
		})
	}
	record, err := setProductResult(r, deliveryErr)
	if err != nil {
		return nil, err
	}
	// Three escaped paths cost at most 73,728 bytes, two target names 3,072,
	// fixed IDs and identity/payload fields 8,192, source failure 2,048 and
	// framing/warnings 4,096: below the existing 256 KiB metadata allowance.
	// The closed identity/payload target/readback schema has depth at most 4.
	return renderReadableResultJSON(256<<10, ErrSetResult, func(w *resultStreamWriter) {
		q := queryBegin(w)
		if record.SourceFailure != nil {
			q.field("source_failure", record.SourceFailure)
		}
		q.field("schema", record.Schema)
		q.field("operation_kind", record.Operation)
		q.field("operation_id", record.OperationID)
		q.field("state_result", record.State)
		q.field("effect_summary", record.Effect)
		q.field("output_summary", record.Output)
		q.field("request_identity", record.RequestIdentity)
		q.field("replay_identity", record.ReplayIdentity)
		q.field("evidence_ceiling", record.EvidenceCeiling)
		q.field("effects", record.Effects)
		q.field("outputs", record.Outputs)
		q.field("duties", record.Duties)
		q.field("hazards", record.Hazards)
		q.field("operation_payload", record.OperationPayload)
		if record.Payload != nil {
			q.field("payload", record.Payload)
		}
		q.field("capsule_policy", record.CapsulePolicy)
		q.field("warning_summary", record.Warnings)
		q.field("local_delivery", record.Delivery)
		q.end()
	})
}

type setPlainRecord struct {
	SourceFailure *ConfigurationSourceFailure `json:"source_failure,omitempty"`
	LocalEdit     string                      `json:"local_edit"`
	Outcome       string                      `json:"outcome"`
	Delivery      setDeliveryRecord           `json:"local_delivery"`
	Warnings      []string                    `json:"warning_summary"`
}

func setPlainResult(r *SetResult, deliveryErr error) (setPlainRecord, error) {
	if r.Payload != nil || r.RequestIdentity != nil {
		return setPlainRecord{}, ErrSetResult
	}
	sourceFailure := configurationSourceFailure("source", deliveryErr)
	if !validConfigurationSourceFailure(sourceFailure) || sourceFailure != nil && (r.StateResult == SetSuccess || r.delivery != nil) {
		return setPlainRecord{}, ErrSetResult
	}
	record := setPlainRecord{SourceFailure: sourceFailure, LocalEdit: "plain", Outcome: "refused", Warnings: []string{}, Delivery: setDeliveryRecord{Outcome: "not-recorded", EditablePath: r.EditablePath, GeneratedPath: r.GeneratedPath, CleanupFailed: errors.Is(deliveryErr, errConfigurationObservationCleanup)}}
	var unknown *configuration.UnknownEdit
	if errors.As(deliveryErr, &unknown) && r.StateResult != SetSuccess {
		source, valid := unknown.RecoverySource()
		if r.StateResult != SetUnavailable || unknown == nil || r.localFailure != unknown || r.failurePaths != [2]string{r.EditablePath, r.GeneratedPath} {
			return setPlainRecord{}, ErrSetResult
		}
		record.Outcome = "unknown"
		record.Delivery.Outcome = "unknown"
		if valid {
			record.Outcome = "pending"
			record.Delivery.Outcome = "pending"
			record.Delivery.RecoverySource = source
			record.Warnings = append(record.Warnings, "A saved local edit is pending. Run recover with the recovery source and original format.")
		} else {
			record.Warnings = append(record.Warnings, "Local delivery is unconfirmed. No recovery source was established; retain local files and do not repeat this edit automatically.")
		}
	} else if r.EditablePath != "" {
		if _, _, err := r.delivery.Digests(); err != nil || r.StateResult != SetSuccess {
			return setPlainRecord{}, ErrSetResult
		}
		editable, generated := r.delivery.Paths()
		if editable != r.EditablePath || generated != r.GeneratedPath {
			return setPlainRecord{}, ErrSetResult
		}
		record.Outcome = "edited"
		record.Delivery.Outcome = "recorded"
		if deliveryErr != nil {
			record.Delivery.CleanupFailed = true
			record.Warnings = append(record.Warnings, "The local pair was read back. Later cleanup failed; retain the confirmed paths.")
		}
	}
	if source, valid := r.delivery.RecoverySource(); valid {
		record.Outcome = "pending"
		record.Delivery.Outcome = "pending"
		record.Delivery.RecoverySource = source
		record.Warnings = append(record.Warnings, "Run recover with the recovery source and original format to finish local cleanup.")
	}
	if !validSetResultPaths([]string{r.EditablePath, r.GeneratedPath, record.Delivery.RecoverySource}) {
		return setPlainRecord{}, ErrSetResult
	}
	return record, nil
}

// The raw metadata allowance precedes JSON escaping. Even six-byte escaping
// keeps this small fixed result below 256 KiB; ciphertext is never serialized.
func validSetResultPaths(paths []string) bool {
	if len(paths) > 8 {
		return false
	}
	total := 0
	for _, p := range paths {
		if !utf8.ValidString(p) || len(p) > 4096 || len(p) > (32<<10)-total {
			return false
		}
		total += len(p)
	}
	return true
}

func RenderSetHuman(r *SetResult, deliveryErr error) ([]byte, error) {
	if r == nil {
		return nil, ErrSetResult
	}
	var out strings.Builder
	var delivery setDeliveryRecord
	var warnings []string
	var sourceFailure *ConfigurationSourceFailure
	if !r.Confidential {
		record, err := setPlainResult(r, deliveryErr)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&out, "Plain value edit: %s\n", record.Outcome)
		delivery, warnings, sourceFailure = record.Delivery, record.Warnings, record.SourceFailure
	} else {
		record, err := setProductResult(r, deliveryErr)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&out, "Supplied secret preparation: %s\n", record.State)
		if record.Payload != nil {
			fmt.Fprintf(&out, "Entry: %q\n", record.Payload.Target.Name)
		} else if identity, ok := record.RequestIdentity.(artifactRequestRecord); ok {
			fmt.Fprintf(&out, "Entry: %q\n", identity.Target.Name)
		}
		if identity, ok := record.RequestIdentity.(preAdmissionIdentityRecord); ok {
			fmt.Fprintf(&out, "Failure stage: %s; reason %s\n", identity.Stage, identity.Code)
		}
		delivery, warnings, sourceFailure = record.Delivery, record.Warnings, record.SourceFailure
	}
	fmt.Fprintf(&out, "Local files: %s\n", delivery.Outcome)
	if delivery.CleanupFailed {
		out.WriteString("Warning: local cleanup failed; retain the reported files.\n")
	}
	for _, field := range []struct{ label, value string }{{"Editable file", delivery.EditablePath}, {"Generated file", delivery.GeneratedPath}, {"Recovery source", delivery.RecoverySource}} {
		if field.value != "" && (field.label == "Recovery source" || deliveryErr != nil || delivery.CleanupFailed || delivery.Outcome != "recorded") {
			fmt.Fprintf(&out, "%s: %q\n", field.label, field.value)
		}
	}
	out.WriteString(configurationSourceFailureHuman(sourceFailure))
	for _, warning := range warnings {
		fmt.Fprintf(&out, "Warning: %s\n", warning)
	}
	if delivery.Outcome == "recorded" {
		out.WriteString("This local edit does not apply or publish the value.\n")
	}
	return []byte(out.String()), nil
}

func SetExitCode(r *SetResult, deliveryErr error) int {
	if r == nil {
		return 2
	}
	if !r.Confidential {
		record, err := setPlainResult(r, deliveryErr)
		if err != nil {
			return 2
		}
		if record.Outcome == "unknown" || record.Outcome == "pending" {
			return 3
		}
		if deliveryErr != nil || record.Outcome != "edited" {
			return 2
		}
		return 0
	}
	record, err := setProductResult(r, deliveryErr)
	if err != nil {
		return 2
	}
	if record.Delivery.Outcome == "pending" {
		return 3
	}
	switch r.StateResult {
	case SetSuccess:
		if deliveryErr != nil {
			return 2
		}
		return 0
	case SetUnavailable:
		return 3
	default:
		return 2
	}
}
