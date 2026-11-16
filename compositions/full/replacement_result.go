package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var errReplacementResult = errors.New("replacement result rendering refused")

type replacementResultRecord struct {
	SourceFailure         *ConfigurationSourceFailure    `json:"source_failure,omitempty"`
	OperationPayload      string                         `json:"operation_payload"`
	Effects               []struct{}                     `json:"effects"`
	Outputs               []struct{}                     `json:"outputs"`
	Duties                []struct{}                     `json:"duties"`
	Hazards               []struct{}                     `json:"hazards"`
	Capsule               string                         `json:"capsule_policy"`
	Payload               json.RawMessage                `json:"payload"`
	StoredReceipt         *replacementReceiptRecord      `json:"stored_receipt,omitempty"`
	Schema                string                         `json:"schema"`
	Operation             string                         `json:"operation_kind"`
	State                 string                         `json:"state_result"`
	Effect                string                         `json:"effect_summary"`
	Output                string                         `json:"output_summary"`
	Request               string                         `json:"request_id"`
	OperationID           string                         `json:"operation_id,omitempty"`
	RequestIdentity       json.RawMessage                `json:"request_identity"`
	Replay                string                         `json:"replay_identity"`
	Domain                string                         `json:"domain_id,omitempty"`
	Requested             string                         `json:"requested_revision_id,omitempty"`
	Observed              string                         `json:"observed_revision_id,omitempty"`
	Snapshot              string                         `json:"observed_snapshot_id,omitempty"`
	Evidence              string                         `json:"evidence_ceiling"`
	CommitMayHaveOccurred bool                           `json:"commit_may_have_occurred"`
	Warnings              uint8                          `json:"current_warning_bits"`
	WarningSummary        []string                       `json:"warning_summary"`
	CoreResult            administrativeCoreResultRecord `json:"result"`
	Transition            *applyTransitionRecord         `json:"-"`
	Selection             *replacementSelectionRecord    `json:"-"`
	Receipt               *replacementReceiptRecord      `json:"-"`
	Query                 *replacementQueryRecord        `json:"query,omitempty"`
	NoWork                *replacementNoWorkRecord       `json:"no_work_observation,omitempty"`
	Diagnostics           []readerDiagnosticRecord       `json:"diagnostics"`
	Delivery              replacementDeliveryRecord      `json:"delivery"`
}
type replacementDeliveryRecord struct {
	ReplacementCommandDelivery
	EditablePath  string             `json:"editable_path,omitempty"`
	GeneratedPath string             `json:"generated_path,omitempty"`
	Readback      *setReadbackRecord `json:"readback,omitempty"`
}
type replacementNoWorkRecord struct {
	Schema      string `json:"schema"`
	RequestCore string `json:"request_core_digest"`
}
type replacementSelectionRecord struct {
	View              string `json:"view"`
	Schema            string `json:"schema"`
	RequestedControl  string `json:"requested_control_hex"`
	CurrentControl    string `json:"current_control_hex"`
	SourceUsable      bool   `json:"successor_source_usable"`
	CandidateSelected bool   `json:"candidate_selected"`
	EvidenceLimit     string `json:"evidence_limit"`
}
type replacementReceiptRecord struct {
	Schema            string `json:"schema"`
	Bytes             string `json:"receipt_hex"`
	Operation         uint16 `json:"original_operation_kind"`
	OperationID       string `json:"original_operation_id"`
	RequestIdentity   string `json:"original_request_identity"`
	State             uint16 `json:"original_state_result"`
	WarningBits       uint64 `json:"original_warning_bits"`
	CandidateSelected bool   `json:"candidate_selected"`
	EvidenceLimit     string `json:"evidence_limit"`
}
type replacementPinRecord struct {
	File            string `json:"file_id"`
	Format          uint8  `json:"format"`
	EditableDigest  string `json:"editable_digest"`
	GeneratedDigest string `json:"generated_digest"`
	EditableLength  uint64 `json:"editable_length"`
	GeneratedLength uint64 `json:"generated_length"`
	HasGenerated    bool   `json:"has_generated"`
}

func replacementPins(p core.AdministrativeSourcePins) replacementPinRecord {
	return replacementPinRecord{readerID(p.FileID), p.Format, readerID(p.EditableDigest), readerID(p.GeneratedDigest), p.EditableLength, p.GeneratedLength, p.HasGenerated}
}

type replacementQueryRecord struct {
	Schema             string                         `json:"schema"`
	Operation          core.ReplacementReadOperation  `json:"operation"`
	SemanticOperation  uint16                         `json:"semantic_operation"`
	ExpectedDomain     string                         `json:"expected_domain"`
	Store              string                         `json:"store_id"`
	Coordinate         string                         `json:"coordinate_id"`
	NonBody            string                         `json:"non_body_id"`
	Descriptor         string                         `json:"store_descriptor_digest"`
	SourceBasis        string                         `json:"source_basis_digest"`
	SuccessorBasis     string                         `json:"successor_basis_digest"`
	AuthenticatedBasis string                         `json:"authenticated_basis_digest,omitempty"`
	SourcePins         replacementPinRecord           `json:"source_pins"`
	OutputPins         replacementPinRecord           `json:"output_pins"`
	Observation        *readerObservationRecord       `json:"observation"`
	Nonce              string                         `json:"request_nonce"`
	Target             core.ReplacementTarget         `json:"target"`
	RequiredKind       uint16                         `json:"required_stored_kind"`
	Authorizer         uint8                          `json:"authorizer"`
	Signing            string                         `json:"signing_selector,omitempty"`
	Encryption         string                         `json:"encryption_selector,omitempty"`
	Material           core.ReplacementMaterialSource `json:"material_source"`
	OriginalOperation  string                         `json:"original_operation_id"`
	OriginalIdentity   string                         `json:"original_request_identity"`
	Candidate          string                         `json:"candidate_digest"`
	Requested          string                         `json:"requested_revision_id"`
	Recipient          string                         `json:"recipient_id,omitempty"`
	Digest             string                         `json:"digest"`
}

func replacementQuery(q *core.ReplacementQueryIdentity) *replacementQueryRecord {
	if q == nil {
		return nil
	}
	v := &replacementQueryRecord{Schema: q.Schema, Operation: q.Operation, SemanticOperation: q.SemanticOperation, ExpectedDomain: readerID(q.ExpectedDomain), Store: readerID(q.StoreID), Coordinate: readerID(q.CoordinateID), NonBody: readerID(q.NonBodyID), Descriptor: readerID(q.StoreDescriptorDigest), SourceBasis: readerID(q.SourceBasisDigest), SuccessorBasis: readerID(q.SuccessorBasisDigest), AuthenticatedBasis: readerID(q.AuthenticatedBasisDigest), SourcePins: replacementPins(q.SourcePins), OutputPins: replacementPins(q.OutputPins), Nonce: readerID(q.RequestNonce), Target: q.Target, RequiredKind: q.RequiredStoredKind, Authorizer: q.Goal.ApprovalRole, Signing: q.Goal.SigningSelector, Encryption: q.Goal.EncryptionSelector, Material: q.Goal.MaterialSource, OriginalOperation: readerID(q.OriginalOperationID), OriginalIdentity: readerID(q.OriginalRequestIdentity), Candidate: readerID(q.CandidateDigest), Requested: readerID(q.RequestedRevisionID), Recipient: readerID(q.RecipientID), Digest: readerID(q.Digest)}
	if q.Observation != nil {
		v.Observation = readerObservation(q.Observation.DomainID, q.Observation.Revision, q.Observation.Snapshot)
	}
	return v
}
func replacementState(r core.Result) (string, bool) {
	switch r.Outcome {
	case core.ObservedCurrent:
		return "success", true
	case core.Unchanged:
		return "no-op", true
	case core.Contention:
		return "contention", true
	case core.UnresolvedCommit:
		return "commit-outcome-unknown", true
	case core.IntegrityFailure:
		return "positive-defect", true
	case core.EvidenceUnavailable:
		return "unavailable", true
	case core.RootLossUnsupported:
		return "root-loss-unsupported", true
	case core.AdmissionRefused:
		if r.Reason == core.CapacityExceeded {
			return "snapshot-size-refusal", true
		}
		return "refused", true
	}
	return "", false
}
func replacementBase(operation string, request, operationID, identity, domain contract.ID, r core.Result, warnings uint8) (replacementResultRecord, error) {
	state, ok := replacementState(r)
	details, validDetails := administrativeCoreResult(r)
	v := replacementResultRecord{Schema: "ProductResult/v1", OperationPayload: "none", Effects: []struct{}{}, Outputs: []struct{}{}, Duties: []struct{}{}, Hazards: []struct{}{}, Capsule: "none", Operation: operation, State: state, Effect: "not-applicable", Output: "not-applicable", Request: readerID(request), OperationID: readerID(operationID), Domain: readerID(domain), Requested: readerID(r.RequestedRevision), Observed: readerID(r.ObservedRevision), Snapshot: readerID(r.ObservedSnapshotID), Evidence: "unavailable", Replay: "none", Warnings: warnings, WarningSummary: abandonWarnings(warnings), CoreResult: details, CommitMayHaveOccurred: r.CommitMayHaveOccurred, Diagnostics: []readerDiagnosticRecord{}}
	v.RequestIdentity, _ = json.Marshal("none")
	if !identity.IsZero() {
		v.RequestIdentity, _ = json.Marshal(readerID(identity))
	}
	if r.Evidence == core.AuthenticatedClosure {
		v.Evidence = "canonical"
	}
	if !ok || !validDetails || request.IsZero() || operationID.IsZero() || warnings&^uint8(31) != 0 || r.CommitMayHaveOccurred && r.Outcome != core.UnresolvedCommit {
		return v, errReplacementResult
	}
	return v, nil
}
func replacementPreAdmission(v *replacementResultRecord, q *core.PreAdmissionRequestIdentity, operationID, identity contract.ID, r core.Result) error {
	if q == nil {
		return nil
	}
	p, ok := preAdmissionIdentity(v.Operation, operationID, q)
	if !ok || !identity.IsZero() || (r.Outcome == core.Unchanged || r.Outcome == core.ObservedCurrent || r.Outcome == core.UnresolvedCommit) || r.CommitMayHaveOccurred || r.Evidence != core.NoEvidence {
		return errReplacementResult
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	v.RequestIdentity = b
	return nil
}
func replacementTransition(p *core.TransitionPayload, r core.Result) (*applyTransitionRecord, error) {
	if p == nil {
		return nil, nil
	}
	if r.Outcome != core.ObservedCurrent && r.Outcome != core.Contention && r.Outcome != core.UnresolvedCommit || p.PredecessorRevisionID.IsZero() || p.RequestedRevisionID.IsZero() || p.RequestedRevisionID != r.RequestedRevision || p.ObservedRevisionID != r.ObservedRevision || p.ChangedSubjects.Count == 0 || p.ChangedSubjects.Count > contract.MutationChangedSubjectLimit || p.ChangedSubjects.IdentityRootDigest.IsZero() || len(p.LiveDutyIDs) > 65535 || len(p.LiveHazardIDs) > 65535 {
		return nil, errReplacementResult
	}
	v := &applyTransitionRecord{Schema: "TransitionPayload/v1", Predecessor: readerID(p.PredecessorRevisionID), Requested: readerID(p.RequestedRevisionID), Observed: readerID(p.ObservedRevisionID), ChangedSubjects: applySubjectCommitmentRecord{p.ChangedSubjects.Count, readerID(p.ChangedSubjects.IdentityRootDigest)}, Duties: []string{}, Hazards: []string{}}
	for _, rows := range []struct {
		from []contract.ID
		to   *[]string
	}{{p.LiveDutyIDs, &v.Duties}, {p.LiveHazardIDs, &v.Hazards}} {
		seen := make(map[contract.ID]struct{}, len(rows.from))
		for _, id := range rows.from {
			if id.IsZero() {
				return nil, errReplacementResult
			}
			if _, ok := seen[id]; ok {
				return nil, errReplacementResult
			}
			seen[id] = struct{}{}
			*rows.to = append(*rows.to, readerID(id))
		}
	}
	return v, nil
}
func replacementReceipt(raw []byte, kind uint16) (contract.CompactMutationReceipt, *replacementReceiptRecord, error) {
	row, err := contract.InspectCompactMutationReceipt(raw)
	if err != nil || row.OperationKind != kind {
		return row, nil, errReplacementResult
	}
	var effect uint16
	switch kind {
	case contract.OperationReplaceRecoveryKeysAndRoot:
		effect = contract.ReceiptEffectNotApplicable
	case contract.OperationRotateRecipientKeyBinding:
		effect = contract.ReceiptEffectNoChange
	default:
		return row, nil, errReplacementResult
	}
	if row.EffectSummary != effect {
		return row, nil, errReplacementResult
	}
	return row, &replacementReceiptRecord{Schema: "ReceiptPayload/v1", Bytes: hex.EncodeToString(raw), Operation: row.OperationKind, OperationID: readerID(row.OperationID), RequestIdentity: readerID(row.RequestIdentityDigest), State: row.StateResult, WarningBits: row.WarningBits}, nil
}
func replacementFreshProjection(result ReplacementCommandResult, r *core.PublicReplacementResult, operation string, kind uint16) (replacementResultRecord, error) {
	v, err := replacementBase(operation, r.RequestID, r.OperationID, r.RequestIdentity, r.DomainID, r.Result, r.WarningBits)
	if err != nil {
		return v, err
	}
	if err = replacementPreAdmission(&v, result.PreAdmission, r.OperationID, r.RequestIdentity, r.Result); err != nil {
		return v, err
	}
	if len(r.Diagnostics) > 2 {
		return v, errReplacementResult
	}
	for _, row := range r.Diagnostics {
		d, ok := readerDiagnostic(row)
		if !ok {
			return v, errReplacementResult
		}
		v.Diagnostics = append(v.Diagnostics, d)
	}
	if result.PreAdmission != nil && (r.Payload != nil || len(r.Receipt) != 0 || r.NoWorkObservation != nil) {
		return v, errReplacementResult
	}
	v.Transition, err = replacementTransition(r.Payload, r.Result)
	if err != nil {
		return v, err
	}
	if v.Transition != nil {
		if r.RequestIdentity.IsZero() || r.DomainID.IsZero() || result.PreAdmission != nil {
			return v, errReplacementResult
		}
		v.Replay = readerID(r.RequestIdentity)
	}
	if r.Result.Outcome == core.Unchanged {
		n := r.NoWorkObservation
		if kind != contract.OperationReplaceAuthorityKeys || n == nil || n.OperationID != r.OperationID || n.RequestIdentity != r.RequestIdentity || n.RequestCoreDigest.IsZero() || r.DomainID.IsZero() || r.RequestIdentity.IsZero() || r.Result.Evidence != core.AuthenticatedClosure || r.Result.Reason != core.NoReason || r.Result.StoreReason != contract.ReasonNone || r.Result.ObservedRevision.IsZero() || r.Result.ObservedSnapshotID.IsZero() || !r.Result.RequestedRevision.IsZero() || r.Payload != nil || len(r.Receipt) != 0 || r.Result.CommitMayHaveOccurred || result.Delivery.Status != "not-created" {
			return v, errReplacementResult
		}
		v.NoWork = &replacementNoWorkRecord{Schema: "NoWorkObservationIdentity/v1", RequestCore: readerID(n.RequestCoreDigest)}
	} else if r.NoWorkObservation != nil {
		return v, errReplacementResult
	}
	if r.Result.Outcome == core.ObservedCurrent && (r.Result.RequestedRevision.IsZero() || r.Result.RequestedRevision != r.Result.ObservedRevision || r.Result.ObservedSnapshotID.IsZero() || r.Result.Reason != core.NoReason && r.Result.Reason != core.CustodyUnavailable || r.Result.StoreReason != contract.ReasonNone || v.Transition == nil || r.Result.Evidence != core.AuthenticatedClosure || r.Result.CommitMayHaveOccurred || result.Delivery.Status != "delivered") {
		return v, errReplacementResult
	}
	if kind == contract.OperationReplaceAuthorityKeys {
		if len(r.Receipt) != 0 {
			return v, errReplacementResult
		}
	} else {
		if r.Result.Outcome == core.ObservedCurrent && len(r.Receipt) == 0 {
			return v, errReplacementResult
		}
		if len(r.Receipt) != 0 {
			row, p, err := replacementReceipt(r.Receipt, kind)
			if err != nil || r.Result.Outcome != core.ObservedCurrent || r.Payload == nil || row.DomainID != r.DomainID || row.OperationID != r.OperationID || row.RequestIdentityDigest != r.RequestIdentity || row.PredecessorRevisionID != r.Payload.PredecessorRevisionID || row.RequestedRevisionID != r.Payload.RequestedRevisionID || row.ObservedRevisionID != r.Payload.ObservedRevisionID || row.StateResult != contract.ReceiptStateSuccess || row.OutputSummary != contract.ReceiptOutputNotApplicable || row.EvidenceCeiling != contract.ReceiptEvidenceCanonical || row.SummaryCounts[contract.ReceiptDutyCount] != 0 || row.SummaryCounts[contract.ReceiptHazardCount] != 0 || row.SummaryCounts[contract.ReceiptEffectCount] != 0 || row.SummaryCounts[contract.ReceiptOutputCount] != 0 || row.CanonicalOutcome != contract.ReceiptCanonicalSelected || row.ChangedSubjects.Count != r.Payload.ChangedSubjects.Count || row.ChangedSubjects.Digest != r.Payload.ChangedSubjects.IdentityRootDigest {
				return v, errReplacementResult
			}
			warnings, _, err := contract.DecodeReceiptWarningBits(row.OperationKind, row.WarningBits)
			if err != nil || warnings != r.WarningBits {
				return v, errReplacementResult
			}
			v.Receipt = p
		}
	}
	if r.RequestIdentity.IsZero() && result.PreAdmission == nil {
		return v, errReplacementResult
	}
	if !r.RequestIdentity.IsZero() && r.NoWorkObservation == nil {
		v.Replay = readerID(r.RequestIdentity)
	}
	return v, nil
}
func replacementReadProjection(r *core.PublicReplacementObservationResult) (replacementResultRecord, error) {
	operation, kind := "", uint16(0)
	switch r.Target {
	case core.ReplacementTargetAuthority:
		operation = "keys-replace-observe"
		kind = contract.OperationReplaceAuthorityKeys
	case core.ReplacementTargetRecovery:
		operation = "keys-replace-receipt"
		kind = contract.OperationReplaceRecoveryKeysAndRoot
	case core.ReplacementTargetRecipient:
		operation = "keys-replace-receipt"
		kind = contract.OperationRotateRecipientKeyBinding
	default:
		return replacementResultRecord{}, errReplacementResult
	}
	v, err := replacementBase(operation, r.RequestID, r.OperationID, r.RequestIdentity, r.DomainID, r.Result, r.CurrentWarningBits)
	if err != nil {
		return v, err
	}
	if string(r.Operation) != operation || r.UnderlyingOperation != kind || r.Result.CommitMayHaveOccurred || r.Result.Outcome == core.Unchanged || r.Result.Outcome == core.UnresolvedCommit || r.Result.Outcome == core.Contention {
		return v, errReplacementResult
	}
	expectedState := v.State
	if r.Result.Outcome == core.AdmissionRefused && r.Result.Reason == core.CapacityExceeded {
		expectedState = "refused"
	}
	switch r.StateResult {
	case contract.ReaderSuccess, contract.ReaderRefused, contract.ReaderProfileBlocked, contract.ReaderPositiveDefect, contract.ReaderUnavailable, core.ReplacementRootLossUnsupported:
		v.State = string(r.StateResult)
	default:
		return v, errReplacementResult
	}
	if v.State != expectedState {
		return v, errReplacementResult
	}
	if r.PreAdmission != nil {
		p := r.PreAdmission
		unavailable := r.Result.Outcome == core.EvidenceUnavailable && r.Result.Reason == core.ReadUnavailable && r.StateResult == contract.ReaderUnavailable &&
			p.Stage == "construction" && p.Code == string(contract.ReasonEvidenceUnavailable) && r.Result.StoreReason == contract.ReasonNone &&
			r.Result.RequestedRevision.IsZero() && r.Result.ObservedRevision.IsZero() && r.Result.ObservedSnapshotID.IsZero() && r.CurrentWarningBits == 0
		if p.SourceProfile != "installed-public-replacement" || p.SourceSchema != "enkv/configuration/v3" || p.Format != "json" && p.Format != "yaml" || p.RequestNonce != r.RequestID || !validPreAdmissionStage(p.Stage) || !validReaderReason(contract.DiagnosticReason(p.Code)) || !r.RequestIdentity.IsZero() || r.Result.Outcome != core.AdmissionRefused && !unavailable || r.Result.Evidence != core.NoEvidence {
			return v, errReplacementResult
		}
		identity := preAdmissionIdentityRecord{Schema: "PreAdmissionRequestIdentity/v1", OperationID: readerID(r.OperationID), OperationKind: operation, Stage: p.Stage, Code: p.Code, RequestNonce: readerID(p.RequestNonce), SourceSchema: p.SourceSchema, SourceProfile: p.SourceProfile, Format: p.Format}
		v.RequestIdentity, err = json.Marshal(identity)
		if err != nil {
			return v, err
		}
	}
	if r.PreAdmission != nil {
		if r.Query != nil || r.Selection != nil || r.Receipt != nil {
			return v, errReplacementResult
		}
		return v, nil
	}
	q := r.Query
	if q == nil || !q.Valid() || q.Operation != r.Operation || q.Target != r.Target || (r.Target == core.ReplacementTargetAuthority && q.RequiredStoredKind != 0 || r.Target != core.ReplacementTargetAuthority && q.RequiredStoredKind != kind) || q.RequestNonce != r.RequestID || q.Digest != r.RequestIdentity || q.ExpectedDomain != r.DomainID {
		return v, errReplacementResult
	}
	v.Query = replacementQuery(q)
	if r.Selection != nil || r.Receipt != nil {
		if q.Observation == nil || q.Observation.DomainID != r.DomainID || q.Observation.Revision != r.Result.ObservedRevision || q.Observation.Snapshot != r.Result.ObservedSnapshotID {
			return v, errReplacementResult
		}
	}
	if r.StateResult == contract.ReaderSuccess && (r.Result.Reason != core.NoReason || r.Result.StoreReason != contract.ReasonNone) {
		return v, errReplacementResult
	}
	if r.Selection != nil {
		p := r.Selection
		if r.Target != core.ReplacementTargetAuthority || r.Receipt != nil || q.Observation == nil || r.Result.Evidence != core.AuthenticatedClosure || p.EvidenceLimit != "historical-attribution-unavailable" || p.CandidateSelected && !p.SuccessorSourceUsable || p.CandidateSelected && q.Observation.Revision != q.RequestedRevisionID || p.SuccessorSourceUsable != (r.StateResult == contract.ReaderSuccess) || p.RequestedControl.DomainID != q.ExpectedDomain || p.CurrentControl.DomainID != q.ExpectedDomain || p.RequestedControl.StoreID != q.StoreID || p.CurrentControl.StoreID != q.StoreID || p.RequestedControl.CoordinateID != q.CoordinateID || p.CurrentControl.CoordinateID != q.CoordinateID || p.RequestedControl.NonBodyID != q.NonBodyID || p.CurrentControl.NonBodyID != q.NonBodyID {
			return v, errReplacementResult
		}
		requested, e1 := contract.EncodeControlCore(p.RequestedControl)
		current, e2 := contract.EncodeControlCore(p.CurrentControl)
		comparable := p.RequestedControl
		monotone := p.CurrentControl.AccessIncarnationID != comparable.AccessIncarnationID || p.CurrentControl.AccessGeneration >= comparable.AccessGeneration
		comparable.AccessIncarnationID = p.CurrentControl.AccessIncarnationID
		comparable.AccessGeneration = p.CurrentControl.AccessGeneration
		normalized, e3 := contract.EncodeControlCore(comparable)
		if e1 != nil || e2 != nil || e3 != nil || len(requested) > 65535 || len(current) > 65535 || p.SuccessorSourceUsable != (monotone && bytes.Equal(normalized, current)) {
			return v, errReplacementResult
		}
		v.Selection = &replacementSelectionRecord{Schema: contract.InspectionPayloadSchema, View: "current-selection", RequestedControl: hex.EncodeToString(requested), CurrentControl: hex.EncodeToString(current), SourceUsable: p.SuccessorSourceUsable, CandidateSelected: p.CandidateSelected, EvidenceLimit: p.EvidenceLimit}
	}
	if r.Receipt != nil {
		p := r.Receipt
		row, payload, err := replacementReceipt(p.ReceiptBytes, kind)
		if err != nil || row != p.Receipt || r.Target == core.ReplacementTargetAuthority || r.Selection != nil || q.Observation == nil || r.StateResult != contract.ReaderSuccess || r.Result.Evidence != core.AuthenticatedClosure || p.EvidenceLimit != "retained-original-receipt-currentness-separate" || row.DomainID != q.ExpectedDomain || row.OperationID != q.OriginalOperationID || row.RequestIdentityDigest != q.OriginalRequestIdentity || row.RequestedRevisionID != q.RequestedRevisionID || p.CandidateSelected && q.Observation.Revision != q.RequestedRevisionID {
			return v, errReplacementResult
		}
		payload.CandidateSelected = p.CandidateSelected
		payload.EvidenceLimit = p.EvidenceLimit
		v.Receipt = payload
	}
	if r.StateResult == contract.ReaderSuccess && r.Selection == nil && r.Receipt == nil {
		return v, errReplacementResult
	}
	return v, nil
}
func replacementProjection(r ReplacementCommandResult) (replacementResultRecord, error) {
	count := 0
	for _, yes := range []bool{r.Authority != nil, r.Recovery != nil, r.Recipient != nil, r.Observation != nil} {
		if yes {
			count++
		}
	}
	if count != 1 {
		return replacementResultRecord{}, errReplacementResult
	}
	if r.SourceFailure != nil {
		if r.Delivery.Status == "delivered" || r.localDelivery != nil {
			return replacementResultRecord{}, errReplacementResult
		}
		for _, mutation := range []*core.PublicReplacementResult{r.Authority, r.Recovery, r.Recipient} {
			if mutation != nil && (mutation.Payload != nil || len(mutation.Receipt) != 0 || mutation.NoWorkObservation != nil || len(mutation.Diagnostics) > 2 || len(mutation.Diagnostics) != 0 && !validSourceFailureDiagnostics(r.SourceFailure, mutation.Diagnostics)) {
				return replacementResultRecord{}, errReplacementResult
			}
		}
		if r.Observation != nil && (r.Observation.Selection != nil || r.Observation.Receipt != nil) {
			return replacementResultRecord{}, errReplacementResult
		}
		admission, identity, details := r.PreAdmission, contract.ID{}, core.Result{}
		switch {
		case r.Authority != nil:
			identity, details = r.Authority.RequestIdentity, r.Authority.Result
		case r.Recovery != nil:
			identity, details = r.Recovery.RequestIdentity, r.Recovery.Result
		case r.Recipient != nil:
			identity, details = r.Recipient.RequestIdentity, r.Recipient.Result
		case r.Observation != nil:
			admission, identity, details = r.Observation.PreAdmission, r.Observation.RequestIdentity, r.Observation.Result
		}
		if !validConfigurationAdmissionSourceFailure(r.SourceFailure, admission, identity, details) {
			return replacementResultRecord{}, errReplacementResult
		}
	}
	if r.Delivery.Path != "" && !configuration.SuccessorOutputPathValid(r.Delivery.Path) {
		return replacementResultRecord{}, errReplacementResult
	}
	switch r.Delivery.Status {
	case "not-attempted", "not-created", "delivered", "unproved", "existing", "pending", "read-back":
	default:
		return replacementResultRecord{}, errReplacementResult
	}
	if r.Delivery.Status == "pending" {
		if r.Observation != nil || !r.Delivery.Failed || r.recoverySource == "" || r.Delivery.RecoverySource != r.recoverySource || !configuration.SuccessorOutputPathValid(r.recoverySource) {
			return replacementResultRecord{}, errReplacementResult
		}
	} else if r.Delivery.RecoverySource != "" || r.recoverySource != "" {
		return replacementResultRecord{}, errReplacementResult
	}
	if r.Delivery.Status == "read-back" && (r.localDelivery == nil || !r.Delivery.Failed || r.Observation != nil) {
		return replacementResultRecord{}, errReplacementResult
	}
	var v replacementResultRecord
	var err error
	switch {
	case r.Authority != nil:
		v, err = replacementFreshProjection(r, r.Authority, "keys-replace-authority", contract.OperationReplaceAuthorityKeys)
	case r.Recovery != nil:
		v, err = replacementFreshProjection(r, r.Recovery, "keys-replace-recovery", contract.OperationReplaceRecoveryKeysAndRoot)
	case r.Recipient != nil:
		v, err = replacementFreshProjection(r, r.Recipient, "keys-replace-recipient", contract.OperationRotateRecipientKeyBinding)
	case r.Observation != nil:
		if r.PreAdmission != nil || r.Delivery.Status != "existing" {
			return v, errReplacementResult
		}
		v, err = replacementReadProjection(r.Observation)
	}
	v.Delivery.ReplacementCommandDelivery = r.Delivery
	v.SourceFailure = r.SourceFailure
	if err != nil {
		return v, err
	}
	if r.localDelivery != nil {
		if r.Observation != nil || r.Delivery.Status != "read-back" && r.Delivery.Status != "delivered" && r.Delivery.Status != "pending" || r.localDelivery.CleanupFailed() && !r.Delivery.CleanupFailed {
			return v, errReplacementResult
		}
		ed, gd, err := r.localDelivery.Digests()
		if err != nil {
			return v, errReplacementResult
		}
		v.Delivery.EditablePath, v.Delivery.GeneratedPath = r.localDelivery.Paths()
		v.Delivery.Readback = &setReadbackRecord{readerID(contract.ID(ed)), readerID(contract.ID(gd))}
	}
	if !validSetResultPaths([]string{v.Delivery.Path, v.Delivery.EditablePath, v.Delivery.GeneratedPath, v.Delivery.RecoverySource}) {
		return v, errReplacementResult
	}
	if r.Delivery.Status == "pending" {
		v.WarningSummary = append(v.WarningSummary, "A saved local edit is pending. Run recover with the recovery source and original format. This does not resume key replacement.")
	}
	switch {
	case v.Transition != nil:
		v.OperationPayload = "TransitionPayload/v1"
		v.StoredReceipt = v.Receipt
	case v.Selection != nil:
		v.OperationPayload = contract.InspectionPayloadSchema
	case r.Observation != nil && v.Receipt != nil:
		v.OperationPayload = "ReceiptPayload/v1"
	}
	return v, err
}

// These writers borrow the result immutably through return. Validation precedes
// output, so malformed closed forms do not produce a partial semantic result.
func WriteReplacementJSON(ctx context.Context, w io.Writer, r ReplacementCommandResult) error {
	return writeReplacement(ctx, w, r, false)
}
func WriteReplacementHuman(ctx context.Context, w io.Writer, r ReplacementCommandResult) error {
	return writeReplacement(ctx, w, r, true)
}
func writeReplacement(ctx context.Context, w io.Writer, r ReplacementCommandResult, human bool) error {
	if ctx == nil || w == nil {
		return errReplacementResult
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v, err := replacementProjection(r)
	if err != nil {
		return err
	}
	// Complete compact account: both 65535-ID transition sibling sets,
	// the generated diagnostic/transition reserve, four escaped 4096-byte paths,
	// the bounded replacement query/selectors/receipt and one source singleton.
	// Every nested record is closed; maximum structural depth is six.
	const compactMaximum = generatedResultOutputLimit + (256 << 10)
	if !human {
		return writeReadableResultJSON(ctx, w, compactMaximum, errReplacementResult, func(out *resultStreamWriter) { q := queryBegin(out); replacementResultFields(q, v); q.end() })
	}
	return writeResultStream(ctx, w, compactMaximum, errReplacementResult, func(out *resultStreamWriter) {
		out.text("Key replacement: " + v.State + "\nOperation: " + v.Operation + "\n")
		if v.OperationID != "" {
			out.text("Operation ID: " + v.OperationID + "\n")
		}
		if v.Domain != "" {
			out.text("Domain: " + v.Domain + "\n")
		}
		admission := r.PreAdmission
		if admission == nil && r.Observation != nil {
			admission = r.Observation.PreAdmission
		}
		administrativeIdentityHuman(out, contract.ID{}, admission)
		if v.CommitMayHaveOccurred {
			out.text("Warning: the commit may have occurred. Retain the operation ID and obtain its observation before another mutation.\n")
		}
		out.text("Successor files: " + v.Delivery.Status + "\n")
		writeSuccessorDeliveryHuman(out, v.Delivery.ReplacementCommandDelivery, v.Delivery.EditablePath, v.Delivery.GeneratedPath)
		out.text(configurationSourceFailureHuman(v.SourceFailure))
		for _, diagnostic := range v.Diagnostics {
			writeReaderDiagnosticHuman(out, diagnostic)
		}
		for _, warning := range v.WarningSummary {
			out.text("Warning: " + warning + "\n")
		}
		if v.Delivery.Failed {
			out.text("Warning: local successor delivery failed.\n")
		}
		if v.Delivery.CleanupFailed {
			out.text("Warning: local cleanup failed; retain the reported files.\n")
		}
		if v.Selection != nil {
			out.text(fmt.Sprintf("Current selection: successor source usable: %t; candidate selected: %t\n", v.Selection.SourceUsable, v.Selection.CandidateSelected))
			if v.Selection.SourceUsable && v.Delivery.RecoverySource == "" {
				out.text("Use the successor file as the source for the next command.\n")
			}
		}
		if v.Receipt != nil {
			out.text("Stored receipt operation: " + v.Receipt.OperationID + "\n")
		}
		if query := v.Query; query != nil {
			target := ""
			switch query.Target {
			case core.ReplacementTargetAuthority:
				target = "authority"
			case core.ReplacementTargetRecovery:
				target = "recovery"
			case core.ReplacementTargetRecipient:
				target = "recipient"
			}
			out.text("Requested replacement target: " + target + "\n")
			if query.OriginalOperation != "" {
				out.text("Requested original operation: " + query.OriginalOperation + "\n")
			}
			if query.OriginalIdentity != "" {
				out.text("Requested original identity: " + query.OriginalIdentity + "\n")
			}
		} else {
			target := "authority"
			if r.Recovery != nil || r.Observation != nil && r.Observation.Target == core.ReplacementTargetRecovery {
				target = "recovery"
			} else if r.Recipient != nil || r.Observation != nil && r.Observation.Target == core.ReplacementTargetRecipient {
				target = "recipient"
			}
			out.text("Requested replacement target: " + target + "\n")
		}
	})
}
func ReplacementCommandExitCode(r ReplacementCommandResult) int {
	v, err := replacementProjection(r)
	if err != nil {
		return 2
	}
	if r.Delivery.Status == "pending" {
		return 3
	}
	if r.Delivery.Failed || r.Delivery.CleanupFailed {
		return 2
	}
	if v.State == "success" || v.State == "no-op" {
		return 0
	}
	if v.State == "contention" || v.State == "unavailable" || v.State == "commit-outcome-unknown" {
		return 3
	}
	return 2
}

func replacementResultFields(q *queryObject, v replacementResultRecord) {
	if v.SourceFailure != nil {
		q.field("source_failure", v.SourceFailure)
	}
	q.field("operation_payload", v.OperationPayload)
	q.field("effects", v.Effects)
	q.field("outputs", v.Outputs)
	q.field("duties", v.Duties)
	q.field("hazards", v.Hazards)
	q.field("capsule_policy", v.Capsule)
	switch {
	case v.Transition != nil:
		q.object("payload", func(o *queryObject) { transitionPayloadFields(o, v.Transition) })
	case v.Selection != nil:
		q.field("payload", v.Selection)
	case v.OperationPayload == "ReceiptPayload/v1":
		q.field("payload", v.Receipt)
	default:
		q.field("payload", "none")
	}
	if v.StoredReceipt != nil {
		q.field("stored_receipt", v.StoredReceipt)
	}
	q.field("schema", v.Schema)
	q.field("operation_kind", v.Operation)
	q.field("state_result", v.State)
	q.field("effect_summary", v.Effect)
	q.field("output_summary", v.Output)
	q.field("request_id", v.Request)
	if v.OperationID != "" {
		q.field("operation_id", v.OperationID)
	}
	q.field("request_identity", v.RequestIdentity)
	q.field("replay_identity", v.Replay)
	for _, field := range []struct{ name, value string }{{"domain_id", v.Domain}, {"requested_revision_id", v.Requested}, {"observed_revision_id", v.Observed}, {"observed_snapshot_id", v.Snapshot}} {
		if field.value != "" {
			q.field(field.name, field.value)
		}
	}
	q.field("evidence_ceiling", v.Evidence)
	q.field("commit_may_have_occurred", v.CommitMayHaveOccurred)
	q.field("current_warning_bits", v.Warnings)
	q.field("warning_summary", v.WarningSummary)
	q.field("result", v.CoreResult)
	if v.Query != nil {
		q.field("query", v.Query)
	}
	if v.NoWork != nil {
		q.field("no_work_observation", v.NoWork)
	}
	q.array("diagnostics", len(v.Diagnostics), func(i int) { q.w.value(v.Diagnostics[i]) })
	q.field("delivery", v.Delivery)
}
