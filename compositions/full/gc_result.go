package compositionfull

import (
	"context"
	"errors"
	"fmt"
	"io"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var ErrGCResult = errors.New("GC result rendering refused")

// Only fixed vocabulary, decimal scalars, booleans and hexadecimal IDs are
// rendered. A target has four 32-byte IDs, bounded enums and no free text;
// 2048 bytes covers its complete field framing. A candidate needs at most 512
// bytes. Each failure's full Core/write tuple needs at most 2048. The 8192-byte
// header covers all commitments, observation, summaries, delivery and human
// envelope. This JSON/YAML bound is separate from the sibling binary preimage.
const gcCompactResultLimit = uint64(8192+2048*contract.GCTargetLimit+512*contract.GCTargetLimit+2048*4) + 2048

// MaxGCResultJSONBytes includes readable layout of the complete native result.
const MaxGCResultJSONBytes = 67 * gcCompactResultLimit

func WriteGCApplyJSON(ctx context.Context, out io.Writer, result GCApplyResult) error {
	return writeGCApply(ctx, out, result, false)
}
func WriteGCApplyHuman(ctx context.Context, out io.Writer, result GCApplyResult) error {
	return writeGCApply(ctx, out, result, true)
}

func writeGCApply(ctx context.Context, out io.Writer, result GCApplyResult, human bool) error {
	r := result.Operation
	if ctx == nil || out == nil || r.Validate() != nil || r.OutputSummary != contract.ReceiptOutputNotApplicable || !validConfigurationAdmissionSourceFailure(result.SourceFailure, result.PreAdmission, r.RequestIdentity, r.Result) || result.SourceFailure != nil && r.Payload != nil {
		return ErrGCResult
	}
	identity, err := gcApplyRequestIdentity(result)
	if err != nil {
		return err
	}
	effect, evidence := generatedEffectSummary(r.EffectSummary), generatedEvidence(r.EvidenceCeiling)
	if effect == "" || evidence == "" {
		return ErrGCResult
	}
	write := func(w *resultStreamWriter) {
		if human {
			gcApplyHuman(w, result, effect, evidence)
			return
		}
		q := queryBegin(w)
		q.field("schema", "ProductResult/v1")
		if result.SourceFailure != nil {
			q.field("source_failure", result.SourceFailure)
		}
		q.field("operation_kind", r.Operation)
		q.field("state_result", r.StateResult)
		q.field("effect_summary", effect)
		q.field("output_summary", "not-applicable")
		q.field("evidence_ceiling", evidence)
		q.id("request_id", r.RequestID)
		q.id("operation_id", r.OperationID)
		q.field("request_identity", identity)
		q.id("domain_id", r.DomainID)
		replay := "none"
		if r.StateResult != "no-op" && !r.RequestIdentity.IsZero() {
			replay = readerID(r.RequestIdentity)
		}
		q.field("replay_identity", replay)
		q.field("delivery", result.Delivery)
		q.object("result", func(o *queryObject) { queryGCCoreResult(o, r.Result) })
		q.object("summary_counts", func(o *queryObject) {
			o.field("success", r.SummaryCounts[0])
			o.field("failure", r.SummaryCounts[1])
			o.field("pending", r.SummaryCounts[2])
			o.field("unknown", r.SummaryCounts[3])
		})
		if p := r.Payload; p != nil {
			q.field("operation_payload", "CleanupPayload/v1")
			q.object("payload", func(o *queryObject) {
				o.field("schema", "CleanupPayload/v1")
				o.id("plan_digest", p.PlanDigest)
				o.id("request_identity", p.RequestIdentity)
				o.id("mark_digest", p.MarkDigest)
				o.id("enumeration_digest", p.EnumerationDigest)
				o.field("enumeration_limit", "one-page-no-snapshot")
				queryGCDescriptor(o, "targets_descriptor", p.TargetsDescriptor)
				o.object("observation", func(a *queryObject) { queryObservation(a, p.Observation) })
				o.field("active", p.Active)
				o.field("closed", p.Closed)
				o.field("selection_uncertain", p.SelectionUncertain)
				o.field("remaining_count", p.RemainingCount)
				o.field("progress_ordinal", p.ProgressOrdinal)
				o.object("sibling_results", func(a *queryObject) {
					a.field("count", p.SiblingResults.Count)
					a.id("root_digest", p.SiblingResults.RootDigest)
				})
				o.array("targets", len(p.Targets), func(i int) {
					row := p.Targets[i]
					a := queryBegin(o.w)
					queryStoreObject(a, row.Object)
					a.field("length", row.Length)
					a.id("digest", row.Digest)
					a.object("selected", func(b *queryObject) {
						b.field("consumed", row.Selected.Consumed)
						b.field("disposition", row.Selected.Disposition)
						b.id("evidence_digest", row.Selected.EvidenceDigest)
					})
					a.field("observed", row.Observed)
					a.id("observed_evidence", row.ObservedEvidence)
					a.field("observation_reason", row.ObservationReason)
					a.field("permission_owned", row.PermissionOwned)
					a.field("delete_attempted", row.DeleteAttempted)
					a.object("delete_result", func(b *queryObject) { queryGCWriteResult(b, row.DeleteResult) })
					token, err := core.GCTargetEffectToken(row)
					if err != nil {
						w.err = ErrGCResult
						return
					}
					a.field("effect", token)
					a.end()
				})
				o.array("candidates", len(p.Candidates), func(i int) {
					a := queryBegin(o.w)
					queryGCCandidate(a, p.Candidates[i])
					a.end()
				})
				o.array("failures", len(p.Failures), func(i int) {
					f := p.Failures[i]
					a := queryBegin(o.w)
					a.field("phase", f.Phase)
					a.object("result", func(b *queryObject) { queryGCCoreResult(b, f.Result) })
					a.object("write", func(b *queryObject) { queryGCWriteResult(b, f.Write) })
					a.end()
				})
			})
		} else {
			q.field("operation_payload", "none")
			q.field("payload", nil)
		}
		q.end()
		w.text("\n")
	}
	if !human {
		return writeReadableResultJSON(ctx, out, gcCompactResultLimit, ErrGCResult, write)
	}
	return writeResultStream(ctx, out, gcCompactResultLimit, ErrGCResult, write)
}

func gcApplyHuman(w *resultStreamWriter, result GCApplyResult, effect, evidence string) {
	r := result.Operation
	w.text(r.Operation + ": " + r.StateResult + "\n")
	w.text(configurationSourceFailureHuman(result.SourceFailure))
	administrativeIdentityHuman(w, r.OperationID, result.PreAdmission)
	if r.Result.Outcome != core.ObservedCurrent && r.Result.Outcome != core.Unchanged || r.Result.Reason != core.NoReason || r.Result.CommitMayHaveOccurred {
		administrativeCoreHuman(w, "Result", r.Result)
	}
	w.text("Effect: " + effect + "; evidence ceiling: " + evidence + ".\n")
	c := r.SummaryCounts
	w.text(fmt.Sprintf("Deletion: %d succeeded, %d failed, %d pending, %d unknown.\n", c[0], c[1], c[2], c[3]))
	if p := r.Payload; p != nil {
		if p.SelectionUncertain {
			w.text("Selection is uncertain.\n")
		}
		w.text(fmt.Sprintf("Selected cleanup: active=%t; closed=%t; remaining=%d.\n", p.Active, p.Closed, p.RemainingCount))
		for _, row := range p.Targets {
			token, err := core.GCTargetEffectToken(row)
			if err != nil {
				w.err = ErrGCResult
				return
			}
			w.text(fmt.Sprintf("Target %s (namespace=%d, kind=%d, index=%d): %s; %d/%d transmissions consumed; selected %s; observed %s.\n", readerID(row.Object.ObjectID), row.Object.Namespace, row.Object.Kind, row.Object.Index, token, row.Selected.Consumed, contract.GCTransmissionLimit, gcDispositionHuman(row.Selected.Disposition), gcDispositionHuman(row.Observed)))
			if row.ObservationReason != contract.ReasonNone {
				w.text("Observation blocked: " + administrativeStoreReasonHuman(row.ObservationReason) + ".\n")
			}
			if row.DeleteAttempted {
				w.text("Delete call: " + gcWriteStatusHuman(row.DeleteResult.Status) + " / " + administrativeStoreReasonHuman(row.DeleteResult.Reason))
				if row.DeleteResult.NotSent {
					w.text("; confirmed not sent")
				}
				w.text(".\n")
			}
		}
		for _, failure := range p.Failures {
			phase := [...]string{"", "select", "reacquire", "reserve", "record-progress", "close"}[failure.Phase]
			administrativeCoreHuman(w, "Phase "+phase, failure.Result)
			w.text(fmt.Sprintf("Phase write: %s / %s; not sent=%t.\n", gcWriteStatusHuman(failure.Write.Status), administrativeStoreReasonHuman(failure.Write.Reason), failure.Write.NotSent))
		}
		if p.RemainingCount != 0 && p.ProgressOrdinal != 0 && !p.Closed {
			w.text("Next: gc apply --operation " + readerID(r.OperationID) + " with the source configuration; current admission is checked again.\n")
		}
	}
	if result.Delivery.CleanupFailed {
		w.text("Local cleanup failed.\n")
	}
}

func gcDispositionHuman(v contract.GCTargetDisposition) string {
	return [...]string{"not-observed", "pending", "unknown", "absent", "changed", "terminal-failure", "retryable-not-sent"}[v]
}

func gcWriteStatusHuman(v contract.WriteStatus) string {
	return [...]string{"not-attempted", "acknowledged", "precondition", "conflict", "unknown", "refused"}[v]
}

func queryGCCoreResult(o *queryObject, r core.Result) {
	// Core validates these closed enums. Numeric fields retain every accepted
	// Core fact without another renderer-owned failure classification table.
	o.field("outcome", r.Outcome)
	o.field("reason", r.Reason)
	o.field("store_reason", r.StoreReason)
	o.id("requested_revision_id", r.RequestedRevision)
	o.id("observed_revision_id", r.ObservedRevision)
	o.id("observed_snapshot_id", r.ObservedSnapshotID)
	o.field("evidence", r.Evidence)
	o.field("commit_may_have_occurred", r.CommitMayHaveOccurred)
}
func queryGCWriteResult(o *queryObject, r contract.WriteResult) {
	o.field("status", r.Status)
	o.field("reason", r.Reason)
	o.field("not_sent", r.NotSent)
}

func gcApplyRequestIdentity(result GCApplyResult) (any, error) {
	r, q := result.Operation, result.PreAdmission
	if q != nil {
		if !r.RequestIdentity.IsZero() || r.Payload != nil || r.Result.CommitMayHaveOccurred || q.RequestNonce != r.RequestID {
			return nil, ErrGCResult
		}
		identity, ok := preAdmissionIdentity(core.GCApplyOperation, r.OperationID, q)
		if !ok {
			return nil, ErrGCResult
		}
		return identity, nil
	}
	if r.RequestIdentity.IsZero() {
		return nil, ErrGCResult
	}
	return readerID(r.RequestIdentity), nil
}

func GCApplyExitCode(r GCApplyResult) int {
	if r.Operation.Validate() != nil {
		return 2
	}
	if _, err := gcApplyRequestIdentity(r); err != nil {
		return 2
	}
	if r.Operation.Result.CommitMayHaveOccurred {
		return 3
	}
	if r.Delivery.CleanupFailed {
		return 2
	}
	if r.Operation.StateResult == "success" || r.Operation.StateResult == "no-op" {
		return 0
	}
	if r.Operation.StateResult == "gc-partial-garbage" || r.Operation.StateResult == "effect-pending" || r.Operation.StateResult == "effect-partial" || r.Operation.StateResult == "effect-unknown" || r.Operation.Result.Outcome == core.Contention || r.Operation.Result.Outcome == core.EvidenceUnavailable || r.Operation.Result.Outcome == core.UnresolvedCommit {
		return 3
	}
	return 2
}
