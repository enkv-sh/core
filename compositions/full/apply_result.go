package compositionfull

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var errApplyResult = errors.New("apply result rendering refused")

type applySubjectCommitmentRecord struct {
	Count              uint32 `json:"count"`
	IdentityRootDigest string `json:"identity_root_digest"`
}

type applyTransitionRecord struct {
	Schema          string                       `json:"schema"`
	Predecessor     string                       `json:"predecessor_revision_id"`
	Requested       string                       `json:"requested_revision_id"`
	Observed        string                       `json:"observed_revision_id,omitempty"`
	ChangedSubjects applySubjectCommitmentRecord `json:"changed_subject_commitment"`
	Duties          []string                     `json:"live_duty_ids"`
	Hazards         []string                     `json:"live_hazard_ids"`
}

type transitionResultRecord struct {
	SourceFailure         *ConfigurationSourceFailure        `json:"source_failure,omitempty"`
	Schema                string                             `json:"schema"`
	Operation             string                             `json:"operation_kind"`
	State                 string                             `json:"state_result"`
	Effect                string                             `json:"effect_summary"`
	Output                string                             `json:"output_summary"`
	Request               string                             `json:"request_id"`
	OperationID           string                             `json:"operation_id,omitempty"`
	RequestIdentity       any                                `json:"request_identity,omitempty"`
	ReplayIdentity        string                             `json:"replay_identity"`
	Domain                string                             `json:"domain_id,omitempty"`
	Requested             string                             `json:"requested_revision_id,omitempty"`
	Observed              string                             `json:"observed_revision_id,omitempty"`
	CommitMayHaveOccurred bool                               `json:"commit_may_have_occurred"`
	Evidence              string                             `json:"evidence_ceiling"`
	Warnings              []string                           `json:"warning_summary"`
	Preparation           *applyPreparationRecord            `json:"preparation,omitempty"`
	Payload               *applyTransitionRecord             `json:"payload"`
	Diagnostics           []readerDiagnosticRecord           `json:"diagnostics"`
	Receipt               string                             `json:"receipt_hex,omitempty"`
	RetirementBlockers    *recipientRetirementBlockersRecord `json:"recipient_retirement_blockers,omitempty"`
}

func transitionResultProjection(r core.PublicApplyResult, operation uint16) (transitionResultRecord, error) {
	v := transitionResultRecord{Schema: "ProductResult/v1", Effect: "not-applicable", Output: "not-applicable", Request: readerID(r.RequestID),
		OperationID: readerID(r.OperationID), Domain: readerID(r.DomainID), Requested: readerID(r.Result.RequestedRevision), Observed: readerID(r.Result.ObservedRevision),
		ReplayIdentity: "none", CommitMayHaveOccurred: r.Result.CommitMayHaveOccurred, Evidence: "unavailable", Warnings: []string{}, Diagnostics: []readerDiagnosticRecord{}}
	var err error
	v.Preparation, err = applyPreparationProjection(r.Preparation)
	if err != nil {
		return v, err
	}
	expectedEffect := uint16(contract.ReceiptEffectNotApplicable)
	switch operation {
	case contract.OperationApplyDeclaration:
		v.Operation, v.Effect = "apply-declaration", "effect-no-change"
		expectedEffect = contract.ReceiptEffectNoChange
	case contract.OperationRemoveSecretValueEntryAccess:
		v.Operation = "remove-secret-value-entry-access"
	case contract.OperationEnvelopeRekey:
		v.Operation = "envelope-rekey"
	case contract.OperationRetireRecipientIdentity:
		v.Operation = "retire-recipient-identity"
	case contract.OperationRetireGeneratedGeneration, contract.OperationCleanOwnedFailureResidue:
		v.Operation, v.Effect = generatedOperationName(operation), "effect-no-change"
		expectedEffect = contract.ReceiptEffectNoChange
	case contract.OperationAcceptGeneratedRetirementResidue:
		v.Operation = generatedOperationName(operation)
	default:
		return v, errApplyResult
	}
	blockers, err := retirementBlockerProjection(r, operation)
	if err != nil {
		return v, err
	}
	v.RetirementBlockers = blockers
	if !r.RequestIdentity.IsZero() {
		v.RequestIdentity = readerID(r.RequestIdentity)
	}
	if r.PreAdmission != nil {
		identity, ok := preAdmissionIdentity(v.Operation, r.OperationID, r.PreAdmission)
		if !ok || !r.RequestIdentity.IsZero() || r.Payload != nil || len(r.Receipt) != 0 || r.Result.CommitMayHaveOccurred {
			return v, errApplyResult
		}
		v.RequestIdentity = identity
	}
	switch r.Result.Outcome {
	case core.ObservedCurrent:
		v.State = "success"
	case core.Unchanged:
		if operation != contract.OperationApplyDeclaration {
			return v, errApplyResult
		}
		v.State = "no-op"
	case core.Contention:
		v.State = "contention"
	case core.UnresolvedCommit:
		v.State = "commit-outcome-unknown"
	case core.IntegrityFailure:
		v.State = "positive-defect"
	case core.EvidenceUnavailable:
		v.State = "unavailable"
	case core.RootLossUnsupported:
		v.State = "root-loss-unsupported"
	case core.AdmissionRefused:
		v.State = "refused"
		if r.Result.Reason == core.CapacityExceeded {
			v.State = "snapshot-size-refusal"
		} else if operation == contract.OperationApplyDeclaration {
			switch r.Result.Reason {
			case core.StaleGeneratedEpoch:
				v.State = "stale-generated-epoch"
			case core.GeneratedIntentConflict:
				v.State = "generated-intent-conflict"
			}
		}
	default:
		return v, errApplyResult
	}
	if r.Result.Evidence == core.AuthenticatedClosure {
		v.Evidence = "canonical"
	}
	if r.WarningBits & ^uint8(31) != 0 {
		return v, errApplyResult
	}
	visibleWarningBits := r.WarningBits
	if r.Payload != nil && len(r.Payload.LiveHazardIDs) != 0 {
		visibleWarningBits |= core.WarningOrphanGeneratedEffect
	}
	v.Warnings = applyWarningTexts(visibleWarningBits)
	if len(r.Diagnostics) > core.MaxApplyResultDiagnostics {
		return v, errApplyResult
	}
	for _, row := range r.Diagnostics {
		d, ok := readerDiagnostic(row)
		if !ok {
			return v, errApplyResult
		}
		v.Diagnostics = append(v.Diagnostics, d)
	}
	if p := r.Payload; p != nil {
		if r.Result.Outcome != core.ObservedCurrent && r.Result.Outcome != core.Contention && r.Result.Outcome != core.UnresolvedCommit || r.OperationID.IsZero() || p.PredecessorRevisionID.IsZero() || p.RequestedRevisionID.IsZero() ||
			p.RequestedRevisionID != r.Result.RequestedRevision || p.ObservedRevisionID != r.Result.ObservedRevision || p.ChangedSubjects.Count == 0 || p.ChangedSubjects.Count > contract.MutationChangedSubjectLimit || p.ChangedSubjects.IdentityRootDigest.IsZero() || len(p.LiveDutyIDs) > 65535 || len(p.LiveHazardIDs) > 65535 {
			return v, errApplyResult
		}
		v.Payload = &applyTransitionRecord{Schema: "TransitionPayload/v1", Predecessor: readerID(p.PredecessorRevisionID), Requested: readerID(p.RequestedRevisionID), Observed: readerID(p.ObservedRevisionID),
			ChangedSubjects: applySubjectCommitmentRecord{p.ChangedSubjects.Count, readerID(p.ChangedSubjects.IdentityRootDigest)}, Duties: []string{}, Hazards: []string{}}
		for _, rows := range []struct {
			from []contract.ID
			to   *[]string
		}{{p.LiveDutyIDs, &v.Payload.Duties}, {p.LiveHazardIDs, &v.Payload.Hazards}} {
			*rows.to = make([]string, len(rows.from))
			for at, id := range rows.from {
				if id.IsZero() || at > 0 && bytes.Compare(rows.from[at-1][:], id[:]) >= 0 {
					return v, errApplyResult
				}
				(*rows.to)[at] = readerID(id)
			}
		}
	}
	if r.Result.Outcome == core.ObservedCurrent && (v.Payload == nil || len(r.Receipt) == 0 || r.RequestIdentity.IsZero() || r.DomainID.IsZero() || r.Result.Evidence != core.AuthenticatedClosure || r.Result.CommitMayHaveOccurred) {
		return v, errApplyResult
	}
	if r.Result.Outcome == core.Unchanged && (r.OperationID.IsZero() || r.RequestIdentity.IsZero() || r.DomainID.IsZero() || r.Result.ObservedRevision.IsZero() || !r.Result.RequestedRevision.IsZero() || r.Result.Evidence != core.AuthenticatedClosure || r.Result.CommitMayHaveOccurred || r.Payload != nil || len(r.Receipt) != 0) {
		return v, errApplyResult
	}
	if v.Payload != nil {
		if r.RequestIdentity.IsZero() || r.DomainID.IsZero() {
			return v, errApplyResult
		}
		v.ReplayIdentity = readerID(r.RequestIdentity)
	}
	if len(r.Receipt) != 0 {
		row, err := contract.InspectCompactMutationReceipt(r.Receipt)
		if err != nil || r.Result.Outcome != core.ObservedCurrent || v.Payload == nil || row.OperationKind != operation || row.CanonicalOutcome != contract.ReceiptCanonicalSelected || row.StateResult != contract.ReceiptStateSuccess || row.EffectSummary != expectedEffect || row.OutputSummary != contract.ReceiptOutputNotApplicable || row.EvidenceCeiling != contract.ReceiptEvidenceCanonical || row.SummaryCounts[contract.ReceiptDutyCount] != uint32(len(r.Payload.LiveDutyIDs)) || row.SummaryCounts[contract.ReceiptHazardCount] != uint32(len(r.Payload.LiveHazardIDs)) || row.OperationID != r.OperationID || row.RequestIdentityDigest != r.RequestIdentity || row.DomainID != r.DomainID || row.RequestedRevisionID != r.Payload.RequestedRevisionID || row.ObservedRevisionID != r.Payload.ObservedRevisionID || row.PredecessorRevisionID != r.Payload.PredecessorRevisionID || row.ChangedSubjects.Count != r.Payload.ChangedSubjects.Count || row.ChangedSubjects.Digest != r.Payload.ChangedSubjects.IdentityRootDigest {
			return v, errApplyResult
		}
		warnings, effects, err := contract.DecodeReceiptWarningBits(row.OperationKind, row.WarningBits)
		var expectedEffects uint64
		if len(r.Payload.LiveHazardIDs) != 0 {
			expectedEffects = contract.ReceiptWarningPossibleLive
		}
		if err != nil || warnings != r.WarningBits || effects != expectedEffects {
			return v, errApplyResult
		}
		v.Receipt = hex.EncodeToString(r.Receipt)
	}
	return v, nil
}

func RenderApplyJSON(r core.PublicApplyResult) ([]byte, error) {
	if r.Generated != nil {
		if r.Generated.OperationKind != contract.OperationApplyDeclaration && r.Generated.OperationKind != contract.OperationRotateValueEntryValue {
			return nil, errApplyResult
		}
		return RenderGeneratedMutationJSON(r, r.Generated.OperationKind)
	}
	v, err := transitionResultProjection(r, contract.OperationApplyDeclaration)
	if err != nil {
		return nil, err
	}
	return renderTransitionResultJSON(v)
}

func RenderApplyHuman(r core.PublicApplyResult) ([]byte, error) {
	if r.Generated != nil {
		if r.Generated.OperationKind != contract.OperationApplyDeclaration && r.Generated.OperationKind != contract.OperationRotateValueEntryValue {
			return nil, errApplyResult
		}
		return RenderGeneratedMutationHuman(r, r.Generated.OperationKind)
	}
	v, err := transitionResultProjection(r, contract.OperationApplyDeclaration)
	if err != nil {
		return nil, err
	}
	return renderTransitionHuman(r, v)
}

func renderTransitionHuman(r core.PublicApplyResult, v transitionResultRecord) ([]byte, error) {
	return renderGeneratedResult(func(w *generatedResultWriter) { writeTransitionHuman(w, r, v) })
}

func writeTransitionHuman(w generatedFactWriter, r core.PublicApplyResult, v transitionResultRecord) {
	label := map[string]string{"apply-declaration": "Apply", "envelope-rekey": "Envelope rekey", "retire-recipient-identity": "Recipient retirement", "retire-generated-generation": "Generated retirement", "clean-owned-failure-residue": "Generated cleanup", "accept-generated-retirement-residue": "Generated retirement risk"}[v.Operation]
	if label == "" {
		label = v.Operation
	}
	w.text(label + ": " + v.State + "\n")
	if v.Operation == "retire-generated-generation" || v.Operation == "clean-owned-failure-residue" || v.Operation == "accept-generated-retirement-residue" {
		w.text("Effect result: " + v.Effect + "\n")
	}
	if v.State == "no-op" {
		w.text("No changes were applied. This observation does not authorize replay.\n")
	}
	for _, row := range []struct{ label, value string }{{"Domain", v.Domain}, {"Operation ID", v.OperationID}, {"Requested revision", v.Requested}, {"Observed revision", v.Observed}} {
		if row.value != "" {
			w.text(row.label + ": " + row.value + "\n")
		}
	}
	if identity, ok := v.RequestIdentity.(preAdmissionIdentityRecord); ok {
		w.text("Failure stage: " + identity.Stage + "; reason " + identity.Code + "\n")
	}
	w.text(configurationSourceFailureHuman(v.SourceFailure))
	if v.Preparation != nil {
		p := v.Preparation
		if p.PossibleUnacknowledgedCreate {
			w.text("Warning: a local preparation create may have occurred without acknowledgement.\n")
		}
	}
	if p := v.Payload; p != nil {
		for _, id := range p.Duties {
			w.text("Current duty: " + id + "\n")
		}
		for _, id := range p.Hazards {
			w.text("Current hazard: " + id + "\n")
		}
	} else if v.State != "no-op" {
		w.text("No transition details are available.\n")
	}
	if p := v.RetirementBlockers; p != nil {
		w.text(fmt.Sprintf("Retirement blockers: %d\n", p.Total))
		for _, row := range p.Rows {
			w.text("Material " + row.Material + "; " + row.OwnerKind + " " + row.Owner + "\n")
		}
		if p.Total > uint32(len(p.Rows)) {
			w.text(fmt.Sprintf("The result shows %d of %d blockers.\n", len(p.Rows), p.Total))
		}
	}
	for _, diagnostic := range r.Diagnostics {
		writeDiagnosticHuman(w, diagnostic)
	}
	for _, warning := range v.Warnings {
		w.text("Warning: " + warning + "\n")
	}
	if r.Result.CommitMayHaveOccurred {
		w.text("Warning: the HEAD change may have occurred. Observe the selected revision before another mutation.\n")
	}
	if v.Receipt != "" {
		w.text("An exact stored mutation receipt is available.\n")
	}
}

func applyWarningTexts(bits uint8) []string {
	warnings := []string{}
	for _, warning := range []struct {
		bit  uint8
		text string
	}{
		{core.WarningOrphanGeneratedEffect, "An old generated effect may still be live."},
		{core.WarningLateDestructiveEffect, "An old destructive request may act after this exit."},
		{core.WarningPublicationOrderValue, "An old publication may replace a newer value."},
		{core.WarningDiscardedExactEvidence, "Original completion and remote cleanup remain unproved; exact discarded evidence cannot be recovered from this exit."},
		{core.WarningPossibleStoreGarbage, "Immutable store garbage may remain after this exit."},
	} {
		if bits&warning.bit != 0 {
			warnings = append(warnings, warning.text)
		}
	}
	return warnings
}
