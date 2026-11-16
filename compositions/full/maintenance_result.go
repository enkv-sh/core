package compositionfull

import (
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

const maintenanceSourceEvidenceLimit = "Checked current source relations only; later apply and private access require admission."

type maintenanceResultRecord struct {
	transitionResultRecord
	Delivery                     maintenanceDeliveryRecord     `json:"delivery"`
	SourceUsability              string                        `json:"source_usability"`
	SourceUsabilityEvidenceLimit string                        `json:"source_usability_evidence_limit"`
	CurrentWarningBits           uint8                         `json:"current_warning_bits"`
	Observation                  *maintenanceObservationRecord `json:"maintenance_observation,omitempty"`
	RequestedTarget              *maintenanceTargetRecord      `json:"requested_target,omitempty"`
}

type maintenanceTargetRecord struct {
	EntryName   *string `json:"entry_name"`
	RecipientID *string `json:"recipient_id"`
}

func maintenanceRequestedTarget(operation uint16, s *core.MaintenanceSuccessor, domain, operationID, requestIdentity contract.ID) (*maintenanceTargetRecord, error) {
	if s == nil {
		return nil, nil
	}
	if domain.IsZero() || operationID.IsZero() || requestIdentity.IsZero() || s.DomainID != domain || s.OperationID != operationID || s.RequestIdentity != requestIdentity || s.OperationKind != operation {
		return nil, errApplyResult
	}
	switch operation {
	case contract.OperationEnvelopeRekey:
		if !boundedReaderText(s.Name, contract.CryptoMaxName) || s.Recipient != (contract.RecipientBindingReference{}) || s.Retirement != nil || s.RekeyTarget == nil || s.RekeyTarget.Name != s.Name || s.RekeyTarget.Slot >= contract.CryptoMaxValueEntries || s.RekeyTarget.Incarnation.IsZero() || s.RekeyTarget.Material.IsZero() || s.RekeyTarget.BeforePublicEntryDigest.IsZero() {
			return nil, errApplyResult
		}
		name := strings.Clone(s.Name)
		return &maintenanceTargetRecord{EntryName: &name}, nil
	case contract.OperationRetireRecipientIdentity:
		if s.Name != "" || s.Recipient.RecipientID.IsZero() || s.Recipient.PublicBindingDigest.IsZero() || s.RekeyTarget != nil || s.Retirement == nil || s.Retirement.RecipientID != s.Recipient.RecipientID {
			return nil, errApplyResult
		}
		id := readerID(s.Recipient.RecipientID)
		return &maintenanceTargetRecord{RecipientID: &id}, nil
	}
	return nil, errApplyResult
}

type maintenanceDeliveryRecord struct {
	ReplacementCommandDelivery
	PairPins      *replacementPinRecord `json:"pair_pins,omitempty"`
	EditablePath  string                `json:"editable_path,omitempty"`
	GeneratedPath string                `json:"generated_path,omitempty"`
	Readback      *setReadbackRecord    `json:"readback,omitempty"`
}

type maintenanceObservationRecord struct {
	Schema                  string `json:"schema"`
	OriginalOperation       uint16 `json:"original_operation_kind"`
	OriginalOperationID     string `json:"original_operation_id"`
	OriginalRequestIdentity string `json:"original_request_identity"`
	Receipt                 string `json:"receipt_hex,omitempty"`
	CandidateCurrent        bool   `json:"candidate_current"`
	SourceUsabilityChecked  bool   `json:"source_usability_checked"`
	SourceUsable            bool   `json:"source_usable"`
	EvidenceLimit           string `json:"evidence_limit"`
}

func maintenanceCommandProjection(operation uint16, result MaintenanceCommandResult) (maintenanceResultRecord, error) {
	v := maintenanceResultRecord{Delivery: maintenanceDeliveryRecord{ReplacementCommandDelivery: result.Delivery}, SourceUsability: result.SourceUsability, SourceUsabilityEvidenceLimit: maintenanceSourceEvidenceLimit}
	if result.SourceFailure != nil && (result.Generated != nil || result.Cleanup != nil || result.RetirementBlockers != nil || result.Payload != nil || len(result.Receipt) != 0 || result.Delivery.Status == "delivered" || result.localDelivery != nil || result.Observation != nil && (result.Observation.Query != nil || len(result.Observation.Receipt) != 0)) {
		return v, errApplyResult
	}
	if operation != contract.OperationEnvelopeRekey && operation != contract.OperationRetireRecipientIdentity {
		return v, errApplyResult
	}
	switch v.Delivery.Status {
	case "not-attempted", "existing", "unproved", "delivered", "pending", "read-back":
	default:
		return v, errApplyResult
	}
	switch v.SourceUsability {
	case "unchecked", "confirmed", "unusable":
	default:
		return v, errApplyResult
	}
	if v.Delivery.Path != "" && !configuration.SuccessorOutputPathValid(v.Delivery.Path) {
		return v, errApplyResult
	}
	if result.OutputPins != nil {
		if !result.OutputPins.Valid() {
			return v, errApplyResult
		}
		pins := replacementPins(*result.OutputPins)
		v.Delivery.PairPins = &pins
	}
	if result.localDelivery != nil {
		v.Delivery.EditablePath, v.Delivery.GeneratedPath = result.localDelivery.Paths()
		ed, gd, err := result.localDelivery.Digests()
		if err != nil {
			return v, err
		}
		v.Delivery.Readback = &setReadbackRecord{readerID(contract.ID(ed)), readerID(contract.ID(gd))}
	}
	if !validSetResultPaths([]string{v.Delivery.Path, v.Delivery.EditablePath, v.Delivery.GeneratedPath, v.Delivery.RecoverySource}) {
		return v, errApplyResult
	}
	if result.Observation == nil {
		if v.SourceUsability == "confirmed" && (result.Result.Outcome != core.ObservedCurrent || v.Delivery.Status != "delivered" || result.OutputPins == nil || result.Successor == nil || result.Successor.OperationKind != operation || result.Successor.DomainID != result.DomainID || result.Successor.OperationID != result.OperationID || result.Successor.RequestIdentity != result.RequestIdentity || result.Successor.FileIdentity != result.OutputPins.FileID) {
			return v, errApplyResult
		}
		if v.SourceUsability == "unusable" {
			return v, errApplyResult
		}
		v.CurrentWarningBits = result.WarningBits
		projected, err := transitionResultProjection(result.PublicApplyResult, operation)
		v.transitionResultRecord = projected
		if !validConfigurationAdmissionSourceFailure(result.SourceFailure, result.PreAdmission, result.RequestIdentity, result.Result) || result.SourceFailure != nil && !validSourceFailureDiagnostics(result.SourceFailure, result.Diagnostics) {
			return v, errApplyResult
		}
		v.SourceFailure = result.SourceFailure
		if err != nil {
			return v, err
		}
		v.RequestedTarget, err = maintenanceRequestedTarget(operation, result.Successor, result.DomainID, result.OperationID, result.RequestIdentity)
		return v, err
	}
	observed := result.Observation
	if !validConfigurationAdmissionSourceFailure(result.SourceFailure, observed.PreAdmission, observed.RequestIdentity, observed.Result) {
		return v, errApplyResult
	}
	if observed.CurrentWarningBits & ^uint8(31) != 0 || observed.RequestID.IsZero() || observed.OperationID.IsZero() || observed.Result.CommitMayHaveOccurred {
		return v, errApplyResult
	}
	if observed.Correlation.OperationKind != contract.OperationEnvelopeRekey && observed.Correlation.OperationKind != contract.OperationRetireRecipientIdentity {
		return v, errApplyResult
	}
	v.transitionResultRecord = transitionResultRecord{Schema: "ProductResult/v1", Operation: "mutation-receipt", State: string(observed.StateResult), Effect: "not-applicable", Output: "not-applicable", Request: readerID(observed.RequestID), OperationID: readerID(observed.OperationID), Domain: readerID(observed.DomainID), ReplayIdentity: "none", Evidence: "unavailable", Warnings: abandonWarnings(observed.CurrentWarningBits), Diagnostics: []readerDiagnosticRecord{}}
	v.CurrentWarningBits = observed.CurrentWarningBits
	v.SourceFailure = result.SourceFailure
	expectedState := contract.ReaderRefused
	switch observed.Result.Outcome {
	case core.ObservedCurrent:
		expectedState = contract.ReaderSuccess
	case core.AdmissionRefused:
	case core.IntegrityFailure:
		expectedState = contract.ReaderPositiveDefect
	case core.EvidenceUnavailable, core.Contention:
		expectedState = contract.ReaderUnavailable
	case core.RootLossUnsupported:
		expectedState = core.ReplacementRootLossUnsupported
	default:
		return v, errApplyResult
	}
	if observed.StateResult != expectedState {
		return v, errApplyResult
	}
	if observed.Query == nil && (observed.Result.Outcome != core.AdmissionRefused && observed.Result.Outcome != core.EvidenceUnavailable || !observed.RequestIdentity.IsZero() || len(observed.Receipt) != 0 || observed.CandidateCurrent || observed.SourceUsabilityChecked) {
		return v, errApplyResult
	}
	if v.SourceUsability == "confirmed" && (!observed.SourceUsabilityChecked || !observed.SourceUsable) || v.SourceUsability == "unusable" && (!observed.SourceUsabilityChecked || observed.SourceUsable) || v.SourceUsability == "unchecked" && observed.SourceUsabilityChecked {
		return v, errApplyResult
	}
	if observed.PreAdmission != nil {
		q := observed.PreAdmission
		if observed.Query != nil || q.SourceSchema != "enkv/configuration/v3" || q.SourceProfile != "installed-public-maintenance" || q.Format != "json" && q.Format != "yaml" || q.RequestNonce != observed.RequestID || !validPreAdmissionStage(q.Stage) || !validReaderReason(contract.DiagnosticReason(q.Code)) {
			return v, errApplyResult
		}
		expected := maintenanceObservationRefusal(context.Background(), observed.RequestID, observed.Correlation.OperationKind, configuration.JSON, q.Stage, nil)
		if expected.OperationID != observed.OperationID {
			return v, errApplyResult
		}
		v.RequestIdentity = preAdmissionIdentityRecord{Schema: "PreAdmissionRequestIdentity/v1", OperationID: readerID(observed.OperationID), OperationKind: "mutation-receipt", Stage: q.Stage, Code: q.Code, RequestNonce: readerID(q.RequestNonce), SourceSchema: q.SourceSchema, SourceProfile: q.SourceProfile, Format: q.Format}
	} else if observed.Query == nil {
		return v, errApplyResult
	}
	if observed.Query != nil {
		if !observed.Query.Valid() || observed.RequestIdentity != observed.Query.Digest || observed.Query.RequestNonce != observed.RequestID || observed.Query.ExpectedDomain != observed.DomainID || !reflect.DeepEqual(observed.Query.Correlation, observed.Correlation) || result.OutputPins == nil || observed.Query.OutputPins != *result.OutputPins || observed.Query.OutputPath != v.Delivery.Path {
			return v, errApplyResult
		}
		v.RequestIdentity = readerID(observed.RequestIdentity)
	}
	if observed.Result.Evidence == core.AuthenticatedClosure {
		v.Evidence = "canonical"
	}
	if observed.SourceUsabilityChecked && (observed.Query == nil || observed.Query.Observation == nil) {
		return v, errApplyResult
	}
	if observed.Result.Outcome == core.ObservedCurrent && len(observed.Receipt) == 0 {
		return v, errApplyResult
	}
	if len(observed.Receipt) != 0 {
		receipt, err := contract.InspectCompactMutationReceipt(observed.Receipt)
		candidate, candidateErr := format.DecodeHead(observed.Correlation.SignedCandidate)
		if err != nil || candidateErr != nil || observed.Result.Outcome != core.ObservedCurrent || receipt.StateResult != contract.ReceiptStateSuccess || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.DomainID != observed.DomainID || receipt.OperationKind != observed.Correlation.OperationKind || receipt.OperationID != observed.Correlation.OperationID || receipt.RequestIdentityDigest != observed.Correlation.RequestIdentity || receipt.PredecessorRevisionID != candidate.Core.PreviousRevision || receipt.RequestedRevisionID != candidate.Core.Revision || receipt.ObservedRevisionID != candidate.Core.Revision {
			return v, errApplyResult
		}
	}
	v.Observation = &maintenanceObservationRecord{Schema: "MaintenanceObservation/v1", OriginalOperation: observed.Correlation.OperationKind, OriginalOperationID: readerID(observed.Correlation.OperationID), OriginalRequestIdentity: readerID(observed.Correlation.RequestIdentity), Receipt: hex.EncodeToString(observed.Receipt), CandidateCurrent: observed.CandidateCurrent, SourceUsabilityChecked: observed.SourceUsabilityChecked, SourceUsable: observed.SourceUsable, EvidenceLimit: maintenanceSourceEvidenceLimit}
	if observed.Query != nil {
		var err error
		v.RequestedTarget, err = maintenanceRequestedTarget(operation, &observed.Correlation, observed.DomainID, observed.Correlation.OperationID, observed.Correlation.RequestIdentity)
		if err != nil {
			return v, err
		}
	}
	return v, nil
}

func RenderMaintenanceCommandJSON(operation uint16, result MaintenanceCommandResult) ([]byte, error) {
	v, err := maintenanceCommandProjection(operation, result)
	if err != nil {
		return nil, err
	}
	// Four escaped paths, the source singleton, both receipt allowances,
	// pins/readback, fixed context and target use at most 195110 compact bytes
	// within the 256 KiB reserve. The maximum depth is six.
	return renderReadableResultJSON(generatedResultOutputLimit+(256<<10), errApplyResult, func(w *resultStreamWriter) {
		q := queryBegin(w)
		transitionResultFields(q, v.transitionResultRecord)
		q.field("delivery", v.Delivery)
		q.field("source_usability", v.SourceUsability)
		q.field("source_usability_evidence_limit", v.SourceUsabilityEvidenceLimit)
		q.field("current_warning_bits", v.CurrentWarningBits)
		if v.RequestedTarget != nil {
			q.field("requested_target", v.RequestedTarget)
		}
		if v.Observation != nil {
			q.field("maintenance_observation", v.Observation)
		}
		q.end()
	})
}

func RenderMaintenanceCommandHuman(operation uint16, result MaintenanceCommandResult) ([]byte, error) {
	v, err := maintenanceCommandProjection(operation, result)
	if err != nil {
		return nil, err
	}
	return renderReaderResultBound(int(generatedResultOutputLimit+(256<<10)), func(w *readerResultWriter) {
		human := readerHumanFactWriter{w}
		if result.Observation == nil {
			writeTransitionHuman(human, result.PublicApplyResult, v.transitionResultRecord)
		} else {
			observed := v.Observation
			label := map[uint16]string{contract.OperationEnvelopeRekey: "Envelope rekey observation", contract.OperationRetireRecipientIdentity: "Recipient retirement observation"}[observed.OriginalOperation]
			w.literal(label + ": " + v.State + "\nOperation ID: " + v.OperationID + "\n")
			if v.Domain != "" {
				w.literal("Domain: " + v.Domain + "\n")
			}
			w.literal(configurationSourceFailureHuman(v.SourceFailure))
			if observed.OriginalOperationID != "" {
				w.literal("Original operation: " + observed.OriginalOperationID + "\n")
			}
			if observed.OriginalRequestIdentity != "" {
				w.literal("Original request identity: " + observed.OriginalRequestIdentity + "\n")
			}
			if observed.SourceUsabilityChecked {
				w.literal(fmt.Sprintf("Current source relation checked; usable: %t; candidate current: %t\n", observed.SourceUsable, observed.CandidateCurrent))
			} else {
				w.literal("Current source relation was not checked.\n")
			}
			if observed.Receipt != "" {
				w.literal("An exact stored mutation receipt is available.\n")
			}
			for _, diagnostic := range v.Diagnostics {
				writeReaderDiagnosticHuman(human, diagnostic)
			}
			for _, warning := range v.Warnings {
				w.literal("Warning: " + warning + "\n")
			}
		}
		if target := v.RequestedTarget; target != nil {
			if target.EntryName != nil {
				w.literal(fmt.Sprintf("Requested entry: %q\n", *target.EntryName))
			} else {
				w.literal("Requested recipient: " + *target.RecipientID + "\n")
			}
		} else {
			w.literal("Target details are unavailable in this result; retain the operation ID.\n")
		}
		w.literal("Successor delivery: " + v.Delivery.Status + "\n")
		writeSuccessorDeliveryHuman(human, v.Delivery.ReplacementCommandDelivery, v.Delivery.EditablePath, v.Delivery.GeneratedPath)
		if v.Delivery.Failed {
			w.literal("Warning: local successor delivery failed.\n")
		}
		if v.Delivery.CleanupFailed {
			w.literal("Warning: local cleanup failed; retain the reported files.\n")
		}
		if v.Delivery.RecoverySource != "" {
			w.literal("Next action: run recover with the reported recovery source and its original source format. This finishes only the saved local file edit.\n")
		}
		w.literal("Source usability: " + v.SourceUsability + "\n" + v.SourceUsabilityEvidenceLimit + "\n")
		if v.SourceUsability == "confirmed" && v.Delivery.RecoverySource == "" {
			w.literal("Use the successor file as the source for the next command.\n")
		}
	})
}

type readerHumanFactWriter struct{ writer *readerResultWriter }

func (w readerHumanFactWriter) text(s string) { w.writer.literal(s) }
func (w readerHumanFactWriter) value(v any)   { w.writer.json(v, generatedResultRowLimit) }

func writeSuccessorDeliveryHuman(w generatedFactWriter, d ReplacementCommandDelivery, editable, generated string) {
	path := d.Path
	if path == "" {
		path = editable
	}
	if path != "" {
		w.text(fmt.Sprintf("Successor file: %q\n", path))
	}
	if editable != "" && editable != path {
		w.text(fmt.Sprintf("Editable file: %q\n", editable))
	}
	showGenerated := generated != "" && generated != path && generated != editable && (d.Failed || d.CleanupFailed || d.Status == "pending" || d.Status == "unproved")
	if showGenerated {
		w.text(fmt.Sprintf("Generated file: %q\n", generated))
	}
	if d.RecoverySource != "" {
		if d.RecoverySource == path {
			w.text("Recovery uses this successor file.\n")
		} else if d.RecoverySource == editable || showGenerated && d.RecoverySource == generated {
			w.text("Recovery uses the reported local file.\n")
		} else {
			w.text(fmt.Sprintf("Recovery source: %q\n", d.RecoverySource))
		}
	}
}
