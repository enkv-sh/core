package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var ErrAbandonmentResult = errors.New("abandonment result rendering refused")

// These conservative envelopes cover the closed field vocabulary. Related IDs
// are counted separately: each uint16 index renders as at most 67 JSON bytes.
// No declared row or relationship is omitted to fit an output buffer.
const administrativeGroupJSONBytes uint64 = 1459
const administrativeGCJSONBytes uint64 = 1024 + 160*contract.GCTargetLimit
const administrativeReceiptJSONBytes uint64 = 2480
const administrativeHeaderJSONBytes uint64 = 3339 + 597 + AbandonmentPlanLimit

type administrativeObservationRecord struct {
	Domain   string `json:"domain_id"`
	Revision string `json:"head_revision_id"`
	Snapshot string `json:"snapshot_id"`
}
type administrativeArtifactRecord struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Length uint64 `json:"length"`
}
type administrativeQueryRecord struct {
	Schema             string                           `json:"schema"`
	Operation          core.AdministrativeOperation     `json:"operation_kind"`
	SemanticOperation  uint16                           `json:"semantic_operation"`
	ExpectedDomain     string                           `json:"expected_domain_id"`
	StoreID            string                           `json:"store_id"`
	CoordinateID       string                           `json:"coordinate_id"`
	NonBodyID          string                           `json:"non_body_id"`
	Basis              string                           `json:"public_basis_digest"`
	StoreDescriptor    string                           `json:"store_descriptor_digest"`
	Source             abandonSourceRecord              `json:"source"`
	Observation        *administrativeObservationRecord `json:"observation"`
	Nonce              string                           `json:"request_nonce"`
	RequestedOperation string                           `json:"requested_operation_id,omitempty"`
	RequiredKind       uint16                           `json:"required_stored_kind,omitempty"`
	Target             string                           `json:"target_group_id,omitempty"`
	Plan               string                           `json:"plan_identity,omitempty"`
	ArtifactPath       string                           `json:"artifact_path,omitempty"`
	Artifact           *administrativeArtifactRecord    `json:"artifact,omitempty"`
	Digest             string                           `json:"digest"`
}

func administrativeArtifact(a *core.AdministrativeArtifact) *administrativeArtifactRecord {
	if a == nil {
		return nil
	}
	return &administrativeArtifactRecord{a.Path, readerID(a.Digest), a.Length}
}
func administrativeQuery(q *core.AdministrativeQueryIdentity) administrativeQueryRecord {
	v := administrativeQueryRecord{Schema: q.Schema, Operation: q.Operation, SemanticOperation: q.SemanticOperation, ExpectedDomain: readerID(q.ExpectedDomain), StoreID: readerID(q.StoreID), CoordinateID: readerID(q.CoordinateID), NonBodyID: readerID(q.NonBodyID), Basis: readerID(q.PublicBasisDigest), StoreDescriptor: readerID(q.StoreDescriptorDigest), Source: abandonSource(q.SourcePins), Nonce: readerID(q.RequestNonce), RequestedOperation: readerID(q.RequestedOperationID), RequiredKind: q.RequiredStoredKind, Target: readerID(q.TargetGroupID), Plan: readerID(q.PlanIdentity), ArtifactPath: q.ArtifactPath, Artifact: administrativeArtifact(q.Artifact), Digest: readerID(q.Digest)}
	if q.Observation != nil {
		v.Observation = &administrativeObservationRecord{readerID(q.Observation.DomainID), readerID(q.Observation.Revision), readerID(q.Observation.Snapshot)}
	}
	return v
}
func abandonWarnings(bits uint8) []string {
	out := []string{}
	for _, v := range []struct {
		bit  uint8
		text string
	}{{1, "An old generated effect may still be live."}, {2, "An old destructive request may act after this exit."}, {4, "An old publication may replace a newer value."}, {8, "Original completion and remote cleanup remain unproved; exact discarded evidence cannot be recovered from this exit."}, {16, "Immutable store garbage may remain after this exit."}} {
		if bits&v.bit != 0 {
			out = append(out, v.text)
		}
	}
	return out
}

const abandonPossibleLiveWarning = "The old effect can still be live; a successful frontier does not close it. No qualified cleanup path is established by this administrative view."

func abandonRowWarnings(bits uint8, evidence uint16) []string {
	out := abandonWarnings(bits)
	if evidence&contract.AdministrativeEvidencePossibleLive != 0 {
		out = append(out, abandonPossibleLiveWarning)
	}
	if evidence&contract.AdministrativeEvidenceAcknowledged != 0 {
		out = append(out, "An effect was acknowledged; invalidation is not confirmed for every original effect.")
	}
	return out
}
func abandonEvidence(bits uint16) []string {
	out := []string{}
	for _, v := range []struct {
		bit  uint16
		text string
	}{{contract.AdministrativeEvidenceMissing, "missing"}, {contract.AdministrativeEvidenceQualifiedUnknown, "qualified-unknown"}, {contract.AdministrativeEvidenceTerminalFailure, "terminal-failure"}, {contract.AdministrativeEvidenceAcknowledged, "qualified-acknowledgement"}, {contract.AdministrativeEvidenceContradiction, "contradiction"}, {contract.AdministrativeEvidenceConfirmed, "qualified-no-effect-or-scoped-unusability"}, {contract.AdministrativeEvidencePossibleLive, "possible-live"}, {contract.AdministrativeEvidenceReleasePending, "release-pending"}, {contract.AdministrativeEvidenceReleaseUnknown, "release-unknown"}, {contract.AdministrativeEvidenceReleaseUnobserved, "release-unobserved"}} {
		if bits&v.bit != 0 {
			out = append(out, v.text)
		}
	}
	return out
}
func abandonKind(kind uint8) string {
	switch kind {
	case 1:
		return "generated-parent"
	case 2:
		return "generated-duty"
	case 3:
		return "generated-hazard"
	case 4:
		return "inbox-release"
	case 5:
		return "publication-coordinate"
	case 6:
		return "publication-marker"
	case contract.AdministrativeGC:
		return "gc"
	}
	return ""
}
func AbandonmentExitCode(r AbandonmentResult) int {
	if r.Delivery.CleanupFailed || r.Delivery.PlanFailed {
		return 2
	}
	switch r.Operation.Result.Outcome {
	case core.ObservedCurrent:
		return 0
	case core.Contention, core.EvidenceUnavailable, core.UnresolvedCommit:
		return 3
	}
	return 2
}

// WriteAdministrativeJSON borrows the complete owned result immutably until
// return. Preflight validates all rows before the first output byte. Rendering
// retains one bounded row at a time and resolves indices in this same snapshot.
func WriteAdministrativeJSON(ctx context.Context, out io.Writer, r AbandonmentResult) error {
	return writeAdministrative(ctx, out, r, false)
}
func WriteAdministrativeHuman(ctx context.Context, out io.Writer, r AbandonmentResult) error {
	return writeAdministrative(ctx, out, r, true)
}
func writeAdministrative(ctx context.Context, out io.Writer, r AbandonmentResult, human bool) error {
	if ctx == nil || out == nil {
		return ErrAbandonmentResult
	}
	pathBytes := uint64(0)
	if r.Operation.Query != nil {
		if len(r.Operation.Query.ArtifactPath) > 4096 {
			return ErrAbandonmentResult
		}
		pathBytes = uint64(len(r.Operation.Query.ArtifactPath))
	}
	// E <= floor((512MiB-115-247G)/2); dropping the nonnegative G term
	// remains a safe envelope. This is not a reachable-admission claim.
	limit := 6*uint64(contract.MaxChildPages)*contract.MaxRequiredSupportPageLength + administrativeHeaderJSONBytes + 24*pathBytes + 65535*administrativeGroupJSONBytes + 67*((uint64(contract.MaxChildPages)*contract.MaxRequiredSupportPageLength-115)/2) + 2*contract.MutationReceiptWindowLimit*administrativeReceiptJSONBytes + 2048
	if !human {
		// The closed administrative records have depth below eight; opaque
		// canonical images are scalar Base64. No full result backing is retained.
		return writeReadableResultJSON(ctx, out, limit, ErrAbandonmentResult, func(w *resultStreamWriter) { administrativeResult(w, r) })
	}
	first := resultStreamWriter{ctx: ctx, limit: limit, limitError: ErrAbandonmentResult}
	administrativeResult(&first, r)
	if first.err != nil {
		return first.err
	}
	return writeResultStream(ctx, out, limit, ErrAbandonmentResult, func(w *resultStreamWriter) { administrativeHuman(w, r) })
}
func administrativeResult(w *resultStreamWriter, r AbandonmentResult) {
	p := r.Operation
	if !validConfigurationAdmissionSourceFailure(r.SourceFailure, p.PreAdmission, p.RequestIdentity, p.Result) {
		w.err = ErrAbandonmentResult
		return
	}
	switch p.Operation {
	case core.AdministrativeList, core.AdministrativePlan, core.AdministrativeApply, core.AdministrativeReceipt:
	default:
		w.err = ErrAbandonmentResult
		return
	}
	count := 0
	for _, ok := range []bool{p.List != nil, p.Plan != nil, p.End != nil, p.Receipt != nil} {
		if ok {
			count++
		}
	}
	if !administrativeStateValid(p) {
		w.err = ErrAbandonmentResult
		return
	}
	if count > 1 || p.CurrentWarningBits&^31 != 0 || p.StateResult == "" || p.Result.Outcome == core.ObservedCurrent && count != 1 || p.Result.Outcome != core.ObservedCurrent && count != 0 {
		w.err = ErrAbandonmentResult
		return
	}
	if p.List != nil && p.Operation != core.AdministrativeList || p.Plan != nil && p.Operation != core.AdministrativePlan || p.End != nil && p.Operation != core.AdministrativeApply || p.Receipt != nil && p.Operation != core.AdministrativeReceipt {
		w.err = ErrAbandonmentResult
		return
	}
	if p.PreAdmission != nil && (p.Query != nil || !p.RequestIdentity.IsZero() || count != 0) || p.Operation != core.AdministrativeApply && p.PreAdmission == nil && p.Query == nil || p.Operation == core.AdministrativeApply && p.Query != nil {
		w.err = ErrAbandonmentResult
		return
	}
	if p.Query != nil {
		q := p.Query
		if q.Schema != "QueryRequestIdentity/v1" || q.Operation != p.Operation || q.RequestNonce != p.RequestID || q.Digest.IsZero() || q.Digest != p.RequestIdentity || q.ExpectedDomain != p.DomainID || q.PublicBasisDigest.IsZero() || q.StoreDescriptorDigest.IsZero() || q.StoreID.IsZero() || q.CoordinateID.IsZero() || q.NonBodyID.IsZero() || !q.SourcePins.Valid() {
			w.err = ErrAbandonmentResult
			return
		}
		if q.Observation != nil && (q.Observation.DomainID != p.DomainID || q.Observation.Revision.IsZero() || q.Observation.Snapshot.IsZero()) {
			w.err = ErrAbandonmentResult
			return
		}
		if !administrativeQueryShape(q) {
			w.err = ErrAbandonmentResult
			return
		}
	}
	w.text(`{"schema":"ProductResult/v1","operation_kind":`)
	w.value(p.Operation)
	if r.SourceFailure != nil {
		w.text(`,"source_failure":`)
		w.value(r.SourceFailure)
	}
	w.text(`,"state_result":`)
	w.value(p.StateResult)
	w.text(`,"effect_summary":"not-applicable","output_summary":"not-applicable","operation_id":`)
	w.value(readerID(p.OperationID))
	w.text(`,"request_id":`)
	w.value(readerID(p.RequestID))
	w.text(`,"domain_id":`)
	w.value(readerID(p.DomainID))
	w.text(`,"request_identity":`)
	if p.Query != nil {
		w.value(administrativeQuery(p.Query))
	} else if p.PreAdmission != nil {
		identity, ok := preAdmissionIdentity(string(p.Operation), p.OperationID, p.PreAdmission)
		if !ok {
			w.err = ErrAbandonmentResult
			return
		}
		w.value(identity)
	} else if !p.RequestIdentity.IsZero() {
		w.value(readerID(p.RequestIdentity))
	} else {
		w.text("null")
	}
	w.text(`,"result":`)
	record, ok := administrativeCoreResult(p.Result)
	if !ok {
		w.err = ErrAbandonmentResult
		return
	}
	w.value(record)
	w.text(`,"evidence_ceiling":`)
	if p.Result.Evidence == core.AuthenticatedClosure {
		w.value("canonical")
	} else {
		w.value("unavailable")
	}
	w.text(`,"replay_identity":`)
	if p.Operation == core.AdministrativeApply && !p.RequestIdentity.IsZero() {
		w.value(readerID(p.RequestIdentity))
	} else {
		w.value("none")
	}
	w.text(`,"commit_may_have_occurred":`)
	w.value(p.Result.CommitMayHaveOccurred)
	w.text(`,"warning_summary":`)
	w.value(abandonWarnings(p.CurrentWarningBits))
	w.text(`,"delivery":`)
	w.value(r.Delivery)
	w.text(`,"effects":[],"outputs":[],"duties":[],"hazards":[],"capsule_policy":"none","operation_payload":`)
	payload := "none"
	switch {
	case p.List != nil, p.Plan != nil:
		payload = contract.InspectionPayloadSchema
	case p.End != nil:
		payload = "EndSelectedWorkPayload/v1"
	case p.Receipt != nil:
		payload = "ReceiptPayload/v1"
	}
	w.value(payload)
	w.text(`,"payload":`)
	switch {
	case p.List != nil:
		if p.Query.Observation == nil || p.List.Revision != p.Query.Observation.Revision || p.List.Snapshot != p.Query.Observation.Snapshot || p.List.WarningBits != p.CurrentWarningBits {
			w.err = ErrAbandonmentResult
			return
		}
		for _, row := range p.List.Abandonments {
			if row.Receipt.DomainID != p.DomainID {
				w.err = ErrAbandonmentResult
				return
			}
		}
		administrativeList(w, *p.List)
	case p.Plan != nil:
		plan := p.Plan
		if p.Query == nil || p.Query.Observation == nil || p.Query.ArtifactPath != plan.ArtifactPath || !reflect.DeepEqual(p.Query.Artifact, plan.Artifact) || plan.Artifact == nil || !r.Delivery.PlanCreated || !r.Delivery.PlanSynced || !r.Delivery.PlanReadback || r.Delivery.PlanFailed || p.Query.TargetGroupID != plan.Preview.TargetGroupID || p.Query.PlanIdentity != plan.Preview.Identity || p.Query.Observation.Revision != plan.Preview.PredecessorRevision {
			w.err = ErrAbandonmentResult
			return
		}
		if _, err := abandonPreview(plan.Preview).owned(); err != nil {
			w.err = err
			return
		}
		w.text(`{"schema":`)
		w.value(contract.InspectionPayloadSchema)
		w.text(`,"view":"administrative-plan","preview":`)
		w.value(abandonPreview(plan.Preview))
		w.text(`,"risk":`)
		w.value(abandonRisk(plan.Preview))
		w.text(`,"artifact_path":`)
		w.value(plan.ArtifactPath)
		w.text(`,"artifact":`)
		w.value(administrativeArtifact(plan.Artifact))
		w.text("}")
	case p.End != nil:
		end := p.End
		receipt, err := contract.InspectCompactMutationReceipt(end.ReceiptBytes)
		preview := end.Preview
		if _, validErr := abandonPreview(preview).owned(); validErr != nil {
			w.err = validErr
			return
		}
		if err != nil || receipt != end.Receipt || receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != p.OperationID || receipt.RequestIdentityDigest != p.RequestIdentity || receipt.DomainID != p.DomainID || receipt.ObservedRevisionID != p.Result.ObservedRevision || receipt.RequestedRevisionID != p.Result.RequestedRevision || uint8(receipt.WarningBits) != p.CurrentWarningBits || receipt.AdministrativeGroupID != preview.TargetGroupID || receipt.PredecessorRevisionID != preview.PredecessorRevision || receipt.AdministrativeTargetID != preview.TargetID || receipt.AdministrativeTargetKind != preview.TargetKind || receipt.AdministrativeOriginalEvidence != preview.SelectedEvidenceSummary || uint8(receipt.WarningBits) != preview.WarningBits || receipt.AdministrativeWarningChanges != preview.WarningBits&^preview.BeforeWarningBits || receipt.AdministrativePageDelta != int16(preview.AfterChildCount)-int16(preview.BeforeChildCount) || receipt.AdministrativeByteDelta != int64(preview.AfterChildBytes)-int64(preview.BeforeChildBytes) || len(preview.EndedGroupIDs) == 0 || len(preview.EndedGroupIDs) > 65535 {
			w.err = ErrAbandonmentResult
			return
		}
		w.text(`{"schema":"EndSelectedWorkPayload/v1","preview":`)
		w.value(abandonPreview(preview))
		w.text(`,"risk":`)
		w.value(abandonRisk(preview))
		w.text(`,"original_completion":"not-established","physical_cleanup":"not-established","selected_rights":"ended","exclusive_capacity":"released-as-receipted","shared_support":"retained","receipt":`)
		administrativeReceipt(w, core.AuthorityAbandonment{Receipt: receipt, ReceiptBytes: end.ReceiptBytes})
		w.text("}")
	case p.Receipt != nil:
		if p.Query.Observation == nil || p.Receipt.Receipt.OperationID != p.Query.RequestedOperationID || p.Receipt.Receipt.DomainID != p.DomainID {
			w.err = ErrAbandonmentResult
			return
		}
		administrativeReceipt(w, *p.Receipt)
	default:
		w.text("null")
	}
	w.text("}\n")
}

func administrativeIdentityHuman(w *resultStreamWriter, operation contract.ID, admission *core.PreAdmissionRequestIdentity) {
	if !operation.IsZero() {
		w.text("Operation: " + readerID(operation) + ".\n")
	}
	if admission != nil {
		w.text("Admission: " + admission.Stage + " / " + admission.Code + ".\n")
	}
}

func administrativeCoreHuman(w *resultStreamWriter, label string, result core.Result) {
	r, ok := administrativeCoreResult(result)
	if !ok {
		w.err = ErrAbandonmentResult
		return
	}
	w.text(label + ": " + r.Outcome + " / " + r.Reason)
	if r.StoreReason != "" {
		w.text(" (store: " + r.StoreReason + ")")
	}
	if r.CommitMayHaveOccurred {
		w.text("; commit may have occurred")
	}
	w.text(".\n")
	if !result.RequestedRevision.IsZero() {
		w.text("Requested revision: " + r.Requested + ".\n")
	}
	if !result.ObservedRevision.IsZero() {
		w.text("Observed revision: " + r.Observed + ".\n")
	}
	if !result.ObservedSnapshotID.IsZero() {
		w.text("Observed snapshot: " + readerID(result.ObservedSnapshotID) + ".\n")
	}
}

func administrativeStoreReasonHuman(reason contract.Reason) string {
	return [...]string{"none", "access", "transport", "malformed", "condition", "construction", "limit", "proof"}[reason]
}

func administrativeEvidenceHuman(w *resultStreamWriter, evidence uint16, warnings uint8) {
	w.text("Evidence: " + strings.Join(abandonEvidence(evidence), ", ") + ".\n")
	for _, warning := range abandonRowWarnings(warnings, evidence) {
		w.text(warning + "\n")
	}
}

func administrativeHuman(w *resultStreamWriter, r AbandonmentResult) {
	p := r.Operation
	w.text(string(p.Operation) + ": " + string(p.StateResult) + "\n")
	w.text(configurationSourceFailureHuman(r.SourceFailure))
	administrativeIdentityHuman(w, p.OperationID, p.PreAdmission)
	if p.Result.Outcome != core.ObservedCurrent || p.Result.Reason != core.NoReason || p.Result.CommitMayHaveOccurred {
		administrativeCoreHuman(w, "Result", p.Result)
	}
	for _, warning := range abandonWarnings(p.CurrentWarningBits) {
		w.text("Current warning: " + warning + "\n")
	}
	if list := p.List; list != nil {
		for _, group := range list.Groups {
			w.text(fmt.Sprintf("Target %s (%s): owner=%s; target=%s; duty=%d; selectable=%t; blocks changed mutation=%t; capacity=%d pages, %d bytes.\n", readerID(group.GroupID), abandonKind(group.OwnerKind), readerID(group.OwnerID), readerID(group.TargetID), group.DutyKind, group.Selectable, group.BlocksChangedMutation, group.ChargedPages, group.ChargedBytes))
			if !group.RequiredParentGroupID.IsZero() {
				w.text("Required parent: " + readerID(group.RequiredParentGroupID) + ".\n")
			}
			if group.OriginalOperation != nil {
				w.text("Original operation: " + readerID(group.OriginalOperation.OperationID) + ".\n")
			}
			administrativeEvidenceHuman(w, group.SelectedEvidenceSummary, list.WarningBits)
			if len(group.RelatedGroupIndexes) != 0 {
				w.text("Related groups:")
				for _, at := range group.RelatedGroupIndexes {
					w.text(" ")
					w.value(readerID(list.Groups[at].GroupID))
				}
				w.text("\n")
			}
			if gc := group.GC; gc != nil {
				w.text(fmt.Sprintf("GC progress: %d remaining; ordinal=%d; targets=%d.\n", gc.RemainingCount, gc.Ordinal, gc.TargetsDescriptor.Count))
				for at, target := range gc.Targets {
					w.text(fmt.Sprintf("GC target %d: %s; transmissions=%d/%d.\n", at, gcDispositionHuman(target.Disposition), target.Consumed, contract.GCTransmissionLimit))
				}
			}
		}
		for _, receipt := range list.Abandonments {
			administrativeReceiptHuman(w, receipt)
		}
		if len(list.Groups) == 0 && len(list.Abandonments) == 0 {
			w.text("No current targets or retained abandonments.\n")
		}
	}
	if p.Plan != nil {
		administrativePreviewHuman(w, p.Plan.Preview)
		w.text("Plan delivered and verified: ")
		w.value(p.Plan.ArtifactPath)
		w.text(".\nNext: review the plan before abandon apply --plan ")
		w.value(p.Plan.ArtifactPath)
		w.text(".\n")
	}
	if p.End != nil {
		administrativePreviewHuman(w, p.End.Preview)
		w.text("Selected rights ended. Original completion and physical cleanup are not established.\n")
		w.text("Exclusive capacity was released as receipted; shared support remains.\n")
	}
	if p.Receipt != nil {
		administrativeReceiptHuman(w, *p.Receipt)
	}
	if p.Operation == core.AdministrativeApply && p.Result.CommitMayHaveOccurred {
		w.text("Next: abandon receipt --operation " + readerID(p.OperationID) + " with the source configuration. An absent receipt does not prove failure.\n")
	}
	if p.Plan == nil && (r.Delivery.PlanCreated || r.Delivery.PlanSynced || r.Delivery.PlanReadback || r.Delivery.PlanFailed) {
		if p.Query != nil && p.Query.ArtifactPath != "" {
			w.text("Plan file: ")
			w.value(p.Query.ArtifactPath)
			w.text(".\n")
		}
		for _, fact := range []struct {
			name string
			done bool
		}{{"Plan creation", r.Delivery.PlanCreated}, {"Plan synchronization", r.Delivery.PlanSynced}, {"Plan readback", r.Delivery.PlanReadback}} {
			if fact.done {
				w.text(fact.name + " completed.\n")
			} else {
				w.text(fact.name + " is not established.\n")
			}
		}
	}
	if r.Delivery.PlanFailed {
		w.text("Plan delivery failed.\n")
	}
	if r.Delivery.CleanupFailed {
		w.text("Local cleanup failed.\n")
	}
}

func administrativePreviewHuman(w *resultStreamWriter, p core.EndWorkPreview) {
	w.text(fmt.Sprintf("Disposition target: %s (%s); owner=%s; target=%s; duty=%d.\n", readerID(p.TargetGroupID), abandonKind(p.TargetKind), readerID(p.TargetOwnerID), readerID(p.TargetID), p.DutyKind))
	w.text("Groups ending:")
	for _, id := range p.EndedGroupIDs {
		w.text(" ")
		w.value(readerID(id))
	}
	w.text("\n")
	w.text(fmt.Sprintf("Capacity: %d -> %d pages; %d -> %d bytes.\n", p.BeforeChildCount, p.AfterChildCount, p.BeforeChildBytes, p.AfterChildBytes))
	w.text(fmt.Sprintf("Dependent groups: %d; removed support: %d pages, %d bytes.\n", p.DependentGroups.Count, p.RemovedSupport.Count, p.RemovedSupport.Length))
	administrativeEvidenceHuman(w, p.SelectedEvidenceSummary, p.WarningBits)
	for _, warning := range abandonWarnings(p.WarningBits &^ p.BeforeWarningBits) {
		w.text("Disposition adds warning: " + warning + "\n")
	}
	w.text("Selected values, access and shared support remain. Exact ended-work history and future adoption rights are discarded by the disposition.\n")
	w.text(abandonLateEffects + ".\n")
}

func administrativeReceiptHuman(w *resultStreamWriter, row core.AuthorityAbandonment) {
	r := row.Receipt
	w.text(fmt.Sprintf("Retained abandonment %s: work-ended; group=%s; target=%s; kind=%s; capacity delta=%d pages, %d bytes.\n", readerID(r.OperationID), readerID(r.AdministrativeGroupID), readerID(r.AdministrativeTargetID), abandonKind(r.AdministrativeTargetKind), r.AdministrativePageDelta, r.AdministrativeByteDelta))
	if row.OriginalOperation != nil {
		w.text("Original operation: " + readerID(row.OriginalOperation.OperationID) + ".\n")
	}
	w.text("Historical ")
	administrativeEvidenceHuman(w, r.AdministrativeOriginalEvidence, uint8(r.WarningBits))
	w.text("Original completion and physical cleanup are not established by this receipt.\n")
}

type administrativeGroupRecord struct {
	Group             string            `json:"group_id"`
	Kind              string            `json:"kind"`
	Owner             string            `json:"owner_id"`
	Target            string            `json:"target_id"`
	OwnerKind         uint8             `json:"owner_kind"`
	DutyKind          uint8             `json:"duty_kind"`
	Evidence          uint16            `json:"selected_evidence_summary"`
	EvidenceFacts     []string          `json:"original_evidence_facts"`
	Pages             uint16            `json:"charged_pages"`
	Bytes             uint64            `json:"charged_bytes"`
	Blocks            bool              `json:"blocks_changed_mutation"`
	RequiredParent    string            `json:"required_parent_group_id,omitempty"`
	Selectable        bool              `json:"selectable"`
	OriginalOperation string            `json:"original_operation_id,omitempty"`
	Warnings          []string          `json:"warnings"`
	GC                *gcProgressRecord `json:"gc,omitempty"`
}

func administrativeList(w *resultStreamWriter, v core.AuthorityInspection) {
	if len(v.Groups) > 65535 || len(v.Abandonments) > 2*contract.MutationReceiptWindowLimit || v.WarningBits&^31 != 0 {
		w.err = ErrAbandonmentResult
		return
	}
	w.text(`{"schema":`)
	w.value(contract.InspectionPayloadSchema)
	w.text(`,"view":"administrative-list","revision":`)
	w.value(readerID(v.Revision))
	w.text(`,"snapshot":`)
	w.value(readerID(v.Snapshot))
	w.text(`,"current_warning_summary":`)
	w.value(abandonWarnings(v.WarningBits))
	w.text(`,"targets":[`)
	var relations uint64
	for i, g := range v.Groups {
		if i > 0 {
			w.text(",")
		}
		if g.GroupID.IsZero() || g.OwnerID.IsZero() || g.TargetID.IsZero() || abandonKind(g.OwnerKind) == "" || !contract.AdministrativeEvidenceValid(g.SelectedEvidenceSummary) || i > 0 && bytes.Compare(v.Groups[i-1].GroupID[:], g.GroupID[:]) >= 0 {
			w.err = ErrAbandonmentResult
			return
		}
		relations += uint64(len(g.RelatedGroupIndexes))
		if uint64(len(v.Groups))*247+2*relations+115 > uint64(contract.MaxChildPages)*contract.MaxRequiredSupportPageLength {
			w.err = ErrAbandonmentResult
			return
		}
		row := administrativeGroupRecord{Group: readerID(g.GroupID), Kind: abandonKind(g.OwnerKind), Owner: readerID(g.OwnerID), Target: readerID(g.TargetID), OwnerKind: g.OwnerKind, DutyKind: g.DutyKind, Evidence: g.SelectedEvidenceSummary, EvidenceFacts: abandonEvidence(g.SelectedEvidenceSummary), Pages: g.ChargedPages, Bytes: g.ChargedBytes, Blocks: g.BlocksChangedMutation, RequiredParent: readerID(g.RequiredParentGroupID), Selectable: g.Selectable, Warnings: abandonRowWarnings(v.WarningBits, g.SelectedEvidenceSummary)}
		if g.OriginalOperation != nil {
			if g.OriginalOperation.OperationID.IsZero() {
				w.err = ErrAbandonmentResult
				return
			}
			row.OriginalOperation = readerID(g.OriginalOperation.OperationID)
		}
		if (g.OwnerKind == contract.AdministrativeGC) != (g.GC != nil) {
			w.err = ErrAbandonmentResult
			return
		}
		var gcErr error
		row.GC, gcErr = publicGCProgress(g.GC)
		if gcErr != nil {
			w.err = ErrAbandonmentResult
			return
		}
		rowLimit := administrativeGroupJSONBytes
		if row.GC != nil {
			rowLimit += administrativeGCJSONBytes
		}
		body, err := json.Marshal(row)
		if err != nil || uint64(len(body)) > rowLimit {
			w.err = ErrAbandonmentResult
			return
		}
		w.text(string(body[:len(body)-1]))
		w.text(`,"related_group_ids":[`)
		for j, index := range g.RelatedGroupIndexes {
			if int(index) >= len(v.Groups) || int(index) == i || j > 0 && g.RelatedGroupIndexes[j-1] >= index {
				w.err = ErrAbandonmentResult
				return
			}
			if j > 0 {
				w.text(",")
			}
			w.value(readerID(v.Groups[index].GroupID))
		}
		w.text("]}")
	}
	w.text(`],"abandonments":[`)
	for i, row := range v.Abandonments {
		if i > 0 {
			w.text(",")
		}
		administrativeReceipt(w, row)
	}
	w.text("]}")
}
func administrativeReceipt(w *resultStreamWriter, row core.AuthorityAbandonment) {
	r, err := contract.InspectCompactMutationReceipt(row.ReceiptBytes)
	if err != nil || r != row.Receipt || r.OperationKind != contract.OperationEndSelectedWork {
		w.err = ErrAbandonmentResult
		return
	}
	v := struct {
		Schema            string   `json:"schema"`
		Operation         string   `json:"operation_id"`
		Kind              uint16   `json:"operation_kind"`
		StoredState       string   `json:"stored_state_result"`
		Group             string   `json:"group_id"`
		Target            string   `json:"target_id"`
		TargetKind        uint8    `json:"target_kind"`
		Disposition       string   `json:"disposition_id"`
		OriginalEvidence  []string `json:"original_evidence_facts"`
		Warnings          []string `json:"historical_warning_summary"`
		WarningChanges    uint8    `json:"warning_changes"`
		Pages             int16    `json:"page_delta"`
		Bytes             int64    `json:"byte_delta"`
		Raw               string   `json:"receipt_hex"`
		Authenticity      string   `json:"authenticity"`
		EvidenceCeiling   string   `json:"evidence_ceiling"`
		Retention         string   `json:"retention"`
		OriginalOperation string   `json:"original_operation_id,omitempty"`
	}{Schema: "ReceiptPayload/v1", Operation: readerID(r.OperationID), Kind: r.OperationKind, StoredState: "work-ended", Group: readerID(r.AdministrativeGroupID), Target: readerID(r.AdministrativeTargetID), TargetKind: r.AdministrativeTargetKind, Disposition: readerID(r.AdministrativeDisposition), OriginalEvidence: abandonEvidence(r.AdministrativeOriginalEvidence), Warnings: abandonRowWarnings(uint8(r.WarningBits), r.AdministrativeOriginalEvidence), WarningChanges: r.AdministrativeWarningChanges, Pages: r.AdministrativePageDelta, Bytes: r.AdministrativeByteDelta, Raw: hexReceipt(row.ReceiptBytes), Authenticity: "current-public-authentication", EvidenceCeiling: "canonical", Retention: "retained"}
	if row.OriginalOperation != nil {
		if row.OriginalOperation.OperationID.IsZero() {
			w.err = ErrAbandonmentResult
			return
		}
		v.OriginalOperation = readerID(row.OriginalOperation.OperationID)
	}
	body, err := json.Marshal(v)
	if err != nil || uint64(len(body)) > administrativeReceiptJSONBytes {
		w.err = ErrAbandonmentResult
		return
	}
	w.text(string(body))
}
func hexReceipt(body []byte) string {
	return hex.EncodeToString(body)
}

func administrativeStateValid(p core.PublicAdministrativeResult) bool {
	if p.Operation != core.AdministrativeApply && (p.Result.CommitMayHaveOccurred || p.Result.Outcome == core.UnresolvedCommit || p.Result.Outcome == core.Contention) {
		return false
	}
	state := ""
	switch p.Result.Outcome {
	case core.ObservedCurrent:
		state = "success"
		if p.Operation == core.AdministrativeApply {
			state = "work-ended"
		}
	case core.Contention:
		state = "contention"
	case core.UnresolvedCommit:
		state = "commit-outcome-unknown"
	case core.IntegrityFailure:
		state = "positive-defect"
	case core.EvidenceUnavailable:
		state = "unavailable"
	case core.RootLossUnsupported:
		state = "root-loss-unsupported"
	case core.AdmissionRefused:
		state = "refused"
		if p.Result.Reason == core.CapacityExceeded && p.Operation == core.AdministrativeApply {
			state = "snapshot-size-refusal"
		}
	}
	return state != "" && string(p.StateResult) == state
}

type administrativeCoreResultRecord struct {
	Outcome               string `json:"outcome"`
	Reason                string `json:"reason"`
	StoreReason           string `json:"store_reason,omitempty"`
	Observed              string `json:"observed_revision,omitempty"`
	Requested             string `json:"requested_revision,omitempty"`
	CommitMayHaveOccurred bool   `json:"commit_may_have_occurred"`
}

func administrativeCoreResult(r core.Result) (administrativeCoreResultRecord, bool) {
	outcomes := []string{"", "unchanged", "observed_current", "contention", "unresolved_commit", "integrity_failure", "evidence_unavailable", "root_loss_unsupported", "admission_refused"}
	reasons := []string{"none", "admission_invalid", "construction_mismatch", "invalid_format", "invalid_proof", "invalid_reference", "invalid_relation", "missing_selected_object", "read_unavailable", "immutable_conflict", "capacity_exceeded", "invalid_intent", "signing_unavailable", "write_uncertain", "stale_precondition", "different_selection", "already_used", "custody_unavailable", "stale_generated_epoch", "generated_intent_conflict"}
	stores := []string{"", "access", "transport", "malformed", "condition", "construction", "limit", "proof"}
	if int(r.Outcome) >= len(outcomes) || r.Outcome == 0 || int(r.Reason) >= len(reasons) || int(r.StoreReason) >= len(stores) {
		return administrativeCoreResultRecord{}, false
	}
	return administrativeCoreResultRecord{outcomes[r.Outcome], reasons[r.Reason], stores[r.StoreReason], readerID(r.ObservedRevision), readerID(r.RequestedRevision), r.CommitMayHaveOccurred}, true
}

func administrativeQueryShape(q *core.AdministrativeQueryIdentity) bool {
	switch q.Operation {
	case core.AdministrativeList:
		return q.SemanticOperation == 15 && q.RequestedOperationID.IsZero() && q.RequiredStoredKind == 0 && q.TargetGroupID.IsZero() && q.PlanIdentity.IsZero() && q.ArtifactPath == "" && q.Artifact == nil
	case core.AdministrativePlan:
		if q.SemanticOperation != 15 || !q.RequestedOperationID.IsZero() || q.RequiredStoredKind != 0 || q.TargetGroupID.IsZero() || !filepath.IsAbs(q.ArtifactPath) || filepath.Clean(q.ArtifactPath) != q.ArtifactPath || q.ArtifactPath == "/" || len(q.ArtifactPath) > 4096 || q.Observation == nil && !q.PlanIdentity.IsZero() {
			return false
		}
		return q.Artifact == nil || q.Observation != nil && !q.PlanIdentity.IsZero() && q.Artifact.Path == q.ArtifactPath && !q.Artifact.Digest.IsZero() && q.Artifact.Length > 0 && q.Artifact.Length <= AbandonmentPlanLimit
	case core.AdministrativeReceipt:
		return q.SemanticOperation == 16 && !q.RequestedOperationID.IsZero() && q.RequiredStoredKind == contract.OperationEndSelectedWork && q.TargetGroupID.IsZero() && q.PlanIdentity.IsZero() && q.ArtifactPath == "" && q.Artifact == nil
	}
	return false
}

type gcTargetProgressRecord struct {
	Consumed    uint8                        `json:"consumed"`
	Disposition contract.GCTargetDisposition `json:"disposition"`
	Evidence    string                       `json:"evidence_digest"`
}
type gcProgressRecord struct {
	Plan          string                   `json:"plan_digest"`
	TargetsDigest string                   `json:"targets_digest"`
	TargetsLength uint64                   `json:"targets_length"`
	TargetCount   uint32                   `json:"target_count"`
	Request       string                   `json:"request_identity"`
	Observation   string                   `json:"observation_digest"`
	Remaining     uint16                   `json:"remaining_count"`
	Ordinal       uint32                   `json:"progress_ordinal"`
	Targets       []gcTargetProgressRecord `json:"targets"`
}

func publicGCProgress(v *contract.GCProgress) (*gcProgressRecord, error) {
	if v == nil {
		return nil, nil
	}
	if !v.Valid() {
		return nil, ErrAbandonmentResult
	}
	out := &gcProgressRecord{Plan: readerID(v.PlanDigest), TargetsDigest: readerID(v.TargetsDescriptor.Digest), TargetsLength: v.TargetsDescriptor.Length, TargetCount: v.TargetsDescriptor.Count, Request: readerID(v.RequestIdentity), Observation: readerID(v.ObservationDigest), Remaining: v.RemainingCount, Ordinal: v.Ordinal, Targets: make([]gcTargetProgressRecord, len(v.Targets))}
	for i, row := range v.Targets {
		out.Targets[i] = gcTargetProgressRecord{row.Consumed, row.Disposition, readerID(row.EvidenceDigest)}
	}
	return out, nil
}
