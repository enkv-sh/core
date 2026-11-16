package compositionfull

import (
	"context"
	"fmt"
	"io"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func WriteReceiptListJSON(ctx context.Context, out io.Writer, r core.PublicReceiptListResult) error {
	return writeReceiptList(ctx, out, r, false, nil)
}
func WriteReceiptListHuman(ctx context.Context, out io.Writer, r core.PublicReceiptListResult) error {
	return writeReceiptList(ctx, out, r, true, nil)
}
func WriteReceiptDetailJSON(ctx context.Context, out io.Writer, r core.PublicReceiptDetailResult) error {
	return writeReceiptDetail(ctx, out, r, false, nil)
}
func WriteReceiptDetailHuman(ctx context.Context, out io.Writer, r core.PublicReceiptDetailResult) error {
	return writeReceiptDetail(ctx, out, r, true, nil)
}

func receiptCurrent(q *queryObject, observation core.PublicObservation, bits uint8, warnings core.PublicDomainWarnings) {
	if q.human {
		q.w.text("Current query observation:\n")
		inspectionObservationHuman(q.w, observation)
	} else {
		q.object("observation", func(o *queryObject) { queryObservation(o, observation) })
	}
	q.field("current_domain_warning_bits", bits)
	q.object("current_warnings", func(o *queryObject) { queryDomainWarnings(o, warnings) })
}
func receiptSummaryFields(q *queryObject, v core.ReceiptSummary) {
	if q.human {
		q.field("operation_id", readerID(v.OperationID))
		q.line("Operation kind: " + receiptOperationHuman(v.OperationKind) + "\n")
		q.line("Canonical outcome: " + receiptCanonicalHuman(v.CanonicalOutcome) + "\n")
		q.line("State result: " + receiptStateHuman(v.StateResult) + "\n")
		q.id("observed_revision_id", v.ObservedRevisionID)
		q.id("requested_revision_id", v.RequestedRevisionID)
		q.field("warning_bits", v.WarningBits)
		q.line("Evidence ceiling: " + generatedEvidence(v.EvidenceCeiling) + "\n")
		writeReceiptWarnings(q.w, v.OperationKind, v.WarningBits)
		return
	}
	q.id("operation_id", v.OperationID)
	q.field("operation_kind", v.OperationKind)
	q.field("canonical_outcome", v.CanonicalOutcome)
	q.field("state_result", v.StateResult)
	q.id("observed_revision_id", v.ObservedRevisionID)
	q.id("requested_revision_id", v.RequestedRevisionID)
	q.field("warning_bits", v.WarningBits)
	q.field("evidence_ceiling", v.EvidenceCeiling)
}

func writeReceiptList(ctx context.Context, out io.Writer, r core.PublicReceiptListResult, human bool, sourceFailure *ConfigurationSourceFailure) error {
	if err := r.Validate(); err != nil {
		return ErrPublicQueryResult
	}
	var emit func(*queryObject)
	var warnings func(*resultStreamWriter)
	kind := "none"
	if p := r.Payload; p != nil {
		kind = "ReceiptPayload/v1"
		emit = func(q *queryObject) {
			q.field("schema", kind)
			q.field("form", "list")
			receiptCurrent(q, p.Observation, p.CurrentDomainWarningBits, p.CurrentWarnings)
			q.array("receipts", len(p.Receipts), func(i int) { o := q.begin(); receiptSummaryFields(o, p.Receipts[i]); o.end() })
		}
		warnings = func(w *resultStreamWriter) {
			w.text("Retained terminal results, newest selection first. This list is not complete operation or effect history.\n")
			writeCurrentQueryWarnings(w, p.CurrentDomainWarningBits)

		}
	}
	return writePublicQuery(ctx, out, r.PublicQueryResult, human, kind, emit, warnings, sourceFailure)
}
func writeReceiptDetail(ctx context.Context, out io.Writer, r core.PublicReceiptDetailResult, human bool, sourceFailure *ConfigurationSourceFailure) error {
	if err := r.Validate(); err != nil {
		return ErrPublicQueryResult
	}
	var emit func(*queryObject)
	var warnings func(*resultStreamWriter)
	kind := "none"
	if p := r.Payload; p != nil {
		kind = "ReceiptPayload/v1"
		emit = func(q *queryObject) {
			q.field("schema", kind)
			q.field("form", "detail")
			receiptCurrent(q, p.Observation, p.CurrentDomainWarningBits, p.CurrentWarnings)
			if q.human {
				q.w.text("Original receipt:\n")
				receiptFields(q, p.Receipt)
			} else {
				q.object("receipt", func(o *queryObject) { receiptFields(o, p.Receipt) })
				q.field("encoded_receipt", p.EncodedReceipt)
			}
			q.field("authenticity", p.Authenticity)
			q.field("retention", p.Retention)
		}
		warnings = func(w *resultStreamWriter) {
			w.text("The receipt reports its original result. Current observation and warnings are separate.\n")
			writeCurrentQueryWarnings(w, p.CurrentDomainWarningBits)
		}
	}
	return writePublicQuery(ctx, out, r.PublicQueryResult, human, kind, emit, warnings, sourceFailure)
}

func writeReceiptWarnings(w *resultStreamWriter, operation uint16, bits uint64) {
	domain, effects, err := contract.DecodeReceiptWarningBits(operation, bits)
	if err != nil {
		w.err = ErrPublicQueryResult
		return
	}
	writeCurrentQueryWarnings(w, domain)
	if effects&contract.ReceiptWarningPossibleLive != 0 && domain&core.WarningOrphanGeneratedEffect == 0 {
		w.text("Warning: The old effect can still be live. A succeeded frontier does not close this hazard.\n")
	}
	if effects&contract.ReceiptWarningInvalidationNotConfirmed != 0 {
		w.text("Warning: Deletion was acknowledged; invalidation is not confirmed.\n")
	}
}

func receiptFields(q *queryObject, v contract.CompactMutationReceipt) {
	if q.human {
		receiptDetailHuman(q, v)
		return
	}
	q.field("schema", v.Schema)
	q.field("operation_kind", v.OperationKind)
	q.field("state_result", v.StateResult)
	q.field("effect_summary", v.EffectSummary)
	q.field("output_summary", v.OutputSummary)
	q.field("evidence_ceiling", v.EvidenceCeiling)
	q.id("domain_id", v.DomainID)
	q.id("operation_id", v.OperationID)
	q.id("request_identity_digest", v.RequestIdentityDigest)
	q.id("predecessor_revision_id", v.PredecessorRevisionID)
	q.id("requested_revision_id", v.RequestedRevisionID)
	q.id("observed_revision_id", v.ObservedRevisionID)
	q.field("canonical_outcome", v.CanonicalOutcome)
	queryDescriptor(q, "changed_subjects", v.ChangedSubjects)
	queryDescriptor(q, "complete_result", v.CompleteResult)
	q.field("warning_bits", v.WarningBits)
	q.array("summary_counts", len(v.SummaryCounts), func(i int) { q.value(v.SummaryCounts[i]) })
	q.field("acknowledged_count", v.AcknowledgedCount)
	q.field("confirmed_count", v.ConfirmedCount)
	q.field("unknown_count", v.UnknownCount)
	q.field("administrative_target_kind", v.AdministrativeTargetKind)
	q.field("administrative_warning_changes", v.AdministrativeWarningChanges)
	q.id("administrative_target_id", v.AdministrativeTargetID)
	q.id("administrative_disposition", v.AdministrativeDisposition)
	q.field("administrative_original_evidence", v.AdministrativeOriginalEvidence)
	q.field("administrative_page_delta", v.AdministrativePageDelta)
	q.field("administrative_byte_delta", v.AdministrativeByteDelta)
	q.id("administrative_group_id", v.AdministrativeGroupID)
}

func writeCurrentQueryWarnings(w *resultStreamWriter, bits uint8) {
	if bits&core.WarningOrphanGeneratedEffect != 0 {
		w.text("Warning: The old effect can still be live. A succeeded frontier does not close this hazard.\n")
	}
	if bits&core.WarningLateDestructiveEffect != 0 {
		w.text("Warning: An old destructive request can act after this observation.\n")
	}
	if bits&(core.WarningPublicationOrderValue|core.WarningDiscardedExactEvidence) != 0 {
		w.text("Warning: Publication acknowledgement does not prove current remote order or value. A late write can still change the destination.\n")
	}
	if bits&core.WarningDiscardedExactEvidence != 0 {
		w.text("Warning: Discarded exact evidence cannot be recovered from this observation.\n")
	}
	if bits&core.WarningPossibleStoreGarbage != 0 {
		w.text("Warning: Immutable store garbage can remain.\n")
	}
}

func receiptCanonicalHuman(outcome uint8) string {
	return map[uint8]string{contract.ReceiptCanonicalSelected: "selected", contract.ReceiptCanonicalNotSelected: "not-selected"}[outcome]
}
func receiptStateHuman(state uint16) string {
	if state == contract.ReceiptStateWorkEnded {
		return "work-ended"
	}
	return generatedReceiptState(state)
}
func receiptOperationHuman(kind uint16) string {
	if name := generatedOperationName(kind); name != "" {
		return name
	}
	return map[uint16]string{contract.OperationInitializeDomain: "initialize-domain", contract.OperationRemoveSecretValueEntryAccess: "remove-secret-value-entry-access", contract.OperationRotateRecipientKeyBinding: "rotate-recipient-key-binding", contract.OperationRetireRecipientIdentity: "retire-recipient-identity", contract.OperationEnvelopeRekey: "envelope-rekey", contract.OperationRebindStoreConstruction: "rebind-store-construction", contract.OperationConfigureCommercialAttachment: "configure-commercial-attachment", contract.OperationReplaceRecoveryKeysAndRoot: "replace-recovery-keys-and-root", contract.OperationEndSelectedWork: "end-selected-work"}[kind]
}
func receiptDetailHuman(q *queryObject, v contract.CompactMutationReceipt) {
	receiptSummaryFields(q, core.ReceiptSummary{OperationID: v.OperationID, OperationKind: v.OperationKind, CanonicalOutcome: v.CanonicalOutcome, StateResult: v.StateResult, ObservedRevisionID: v.ObservedRevisionID, RequestedRevisionID: v.RequestedRevisionID, WarningBits: v.WarningBits, EvidenceCeiling: v.EvidenceCeiling})
	q.id("domain_id", v.DomainID)
	q.id("request_identity_digest", v.RequestIdentityDigest)
	q.id("predecessor_revision_id", v.PredecessorRevisionID)
	q.field("effect_summary", generatedEffectSummary(v.EffectSummary))
	q.field("output_summary", "not-applicable")
	q.field("changed_subject_count", v.ChangedSubjects.Count)
	q.field("complete_result_count", v.CompleteResult.Count)
	labels := []string{"effects", "outputs", "duties", "hazards", "changed_access", "success", "failure", "neutral", "pending", "unknown", "preserved_residue", "no_effect_predecessor"}
	for i, count := range v.SummaryCounts {
		q.w.text(fmt.Sprintf("Original summary %s: %d\n", labels[i], count))
	}
	q.field("acknowledged_count", v.AcknowledgedCount)
	q.field("confirmed_count", v.ConfirmedCount)
	q.field("unknown_count", v.UnknownCount)
	if v.AdministrativeTargetKind != 0 {
		q.field("administrative_target_kind", abandonKind(v.AdministrativeTargetKind))
		q.id("administrative_target_id", v.AdministrativeTargetID)
		q.id("administrative_group_id", v.AdministrativeGroupID)
		q.id("administrative_disposition", v.AdministrativeDisposition)
		q.field("administrative_original_evidence", abandonEvidence(v.AdministrativeOriginalEvidence))
		q.field("administrative_warning_changes", v.AdministrativeWarningChanges)
		q.field("administrative_page_delta", v.AdministrativePageDelta)
		q.field("administrative_byte_delta", v.AdministrativeByteDelta)
	}
}
