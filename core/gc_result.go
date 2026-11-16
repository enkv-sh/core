package core

import (
	"crypto/sha256"
	"strings"

	"enkv.sh/core/contract"
)

type GCPhaseFailure struct {
	Phase  contract.GCPhase
	Result Result
	Write  contract.WriteResult
}
type GCTargetResult struct {
	Object            contract.StoreObjectIdentity
	Length            uint32
	Digest            contract.ID
	Selected          contract.GCTargetProgress
	Observed          contract.GCTargetDisposition
	ObservationReason contract.Reason
	ObservedEvidence  contract.ID
	DeleteAttempted   bool
	DeleteResult      contract.WriteResult
	PermissionOwned   bool
}
type GCSiblingCommitment struct {
	Count      uint32
	RootDigest contract.ID
}
type GCNoWorkObservation struct {
	FullHEADDigest, TokenDigest contract.ID
	Snapshot                    contract.Ref
}
type GCCleanupPayload struct {
	PlanDigest, RequestIdentity, MarkDigest, EnumerationDigest contract.ID
	TargetsDescriptor                                          contract.GCDescriptor
	SiblingResults                                             GCSiblingCommitment
	Observation                                                PublicObservation
	NoWork                                                     *GCNoWorkObservation
	Active, Closed, SelectionUncertain                         bool
	RemainingCount                                             uint16
	ProgressOrdinal                                            uint32
	Targets                                                    []GCTargetResult
	Candidates                                                 []contract.GCCandidate
	Failures                                                   []GCPhaseFailure
}
type PublicGCResult struct {
	Operation                                         string
	RequestID, OperationID, RequestIdentity, DomainID contract.ID
	Result                                            Result
	StateResult                                       string
	EffectSummary, OutputSummary, EvidenceCeiling     uint16
	// SummaryCounts are success, failure, pending and unknown, in that order.
	SummaryCounts [4]uint32
	Payload       *GCCleanupPayload
}

const GCResultVectorMaxBytes = 50401
const gcSiblingRowLength = 145

func gcStateCode(state string) uint8 {
	switch state {
	case "success":
		return 1
	case "no-op":
		return 2
	case "gc-partial-garbage":
		return 3
	case "effect-pending":
		return 4
	case "effect-partial":
		return 5
	case "effect-unknown":
		return 6
	case "effect-terminal-failure":
		return 7
	case "contention":
		return 8
	case "commit-outcome-unknown":
		return 9
	case "refused":
		return 10
	case "unavailable":
		return 11
	case "positive-defect":
		return 12
	case "root-loss-unsupported":
		return 13
	case "snapshot-size-refusal":
		return 14
	}
	return 0
}

func gcResultFactsValid(v Result) bool {
	if v.Outcome < Unchanged || v.Outcome > AdmissionRefused || v.Reason > GeneratedIntentConflict || v.Evidence > AuthenticatedClosure || v.StoreReason > contract.ReasonProof || v.Outcome == UnresolvedCommit && !v.CommitMayHaveOccurred {
		return false
	}
	if v.CommitMayHaveOccurred {
		if v.RequestedRevision.IsZero() {
			return false
		}
		switch v.Outcome {
		case UnresolvedCommit, IntegrityFailure, RootLossUnsupported, AdmissionRefused:
		default:
			return false
		}
	}
	if v.Evidence == AuthenticatedClosure && (v.ObservedRevision.IsZero() || v.ObservedSnapshotID.IsZero()) {
		return false
	}
	if v.Outcome == ObservedCurrent {
		return v.Evidence == AuthenticatedClosure && !v.RequestedRevision.IsZero() && v.RequestedRevision == v.ObservedRevision && v.Reason == NoReason && v.StoreReason == contract.ReasonNone
	}
	return true
}
func gcResultWriteValid(v contract.WriteResult) bool {
	_, bad := gcNormalizeWriteResult(v)
	return !bad
}
func gcTargetResultValid(v GCTargetResult) bool {
	if limit := contract.StoreObjectLimit(v.Object); limit == 0 || v.Length == 0 || v.Length > limit || v.Digest.IsZero() {
		return false
	}
	p := v.Selected
	if p.Consumed > contract.GCTransmissionLimit || p.Disposition < contract.GCTargetPending || p.Disposition > contract.GCTargetRetryableNotSent || (p.Disposition == contract.GCTargetAbsent || p.Disposition == contract.GCTargetRetryableNotSent) == p.EvidenceDigest.IsZero() || p.Disposition == contract.GCTargetRetryableNotSent && (p.Consumed == 0 || p.Consumed >= contract.GCTransmissionLimit) {
		return false
	}
	if v.ObservationReason > contract.ReasonProof {
		return false
	}
	switch v.Observed {
	case 0, contract.GCTargetPending:
		if v.ObservationReason != contract.ReasonNone || !v.ObservedEvidence.IsZero() {
			return false
		}
	case contract.GCTargetUnknown:
		if v.ObservationReason == contract.ReasonNone || !v.ObservedEvidence.IsZero() {
			return false
		}
	case contract.GCTargetAbsent:
		if v.ObservedEvidence.IsZero() || v.ObservationReason != contract.ReasonNone {
			return false
		}
	case contract.GCTargetChanged:
		if v.ObservationReason != contract.ReasonCondition || !v.ObservedEvidence.IsZero() {
			return false
		}
	default:
		return false
	}
	if p.Disposition == contract.GCTargetAbsent && v.Observed != 0 && v.Observed != contract.GCTargetAbsent {
		return false
	}
	if v.PermissionOwned && p.Consumed == 0 {
		return false
	}
	if v.PermissionOwned && !v.DeleteAttempted && p.Disposition != contract.GCTargetPending {
		return false
	}
	if v.DeleteAttempted {
		return v.PermissionOwned && gcResultWriteValid(v.DeleteResult)
	}
	return v.DeleteResult == (contract.WriteResult{})
}

// GCTargetEffectToken describes this invocation's provider-call evidence.
// Selected remaining garbage and future dispatch rights are separate facts.
func GCTargetEffectToken(v GCTargetResult) (string, error) {
	if !gcTargetResultValid(v) {
		return "", contract.ErrRecord
	}
	if v.DeleteAttempted && v.DeleteResult.Status == contract.WritePrecondition {
		return "confirmed-no-effect", nil
	}
	if v.Selected.Disposition == contract.GCTargetAbsent || v.Observed == contract.GCTargetAbsent {
		return "succeeded", nil
	}
	if v.DeleteAttempted {
		w := v.DeleteResult
		if w.NotSent && (w.Status == contract.WriteUnknown && (w.Reason == contract.ReasonTransport || w.Reason == contract.ReasonAccess) || w.Status == contract.WriteRefused) {
			return "not-started", nil
		}
		if w.Status == contract.WriteRefused {
			return "failed-terminal", nil
		}
		return "unknown", nil
	}
	if v.PermissionOwned {
		return "prepared", nil
	}
	if v.Selected.Disposition == contract.GCTargetTerminalFailure {
		return "failed-terminal", nil
	}
	if v.Selected.Consumed == 0 || v.Selected.Disposition == contract.GCTargetRetryableNotSent {
		return "not-started", nil
	}
	return "unknown", nil
}

func gcSummary(r PublicGCResult) ([4]uint32, uint16, string, error) {
	var counts [4]uint32
	if r.Payload == nil {
		return counts, contract.ReceiptEffectNotApplicable, gcStateResult(r.Result), nil
	}
	for _, row := range r.Payload.Targets {
		token, err := GCTargetEffectToken(row)
		if err != nil {
			return counts, 0, "", err
		}
		switch token {
		case "succeeded", "confirmed-no-effect":
			counts[0]++
		case "failed-terminal":
			counts[1]++
		case "not-started", "prepared":
			counts[2]++
		case "unknown":
			counts[3]++
		}
	}
	var input [contract.ReceiptSummaryCount]uint32
	input[contract.ReceiptSummarySuccessCount], input[contract.ReceiptSummaryFailureCount], input[contract.ReceiptSummaryPendingCount], input[contract.ReceiptSummaryUnknownCount] = counts[0], counts[1], counts[2], counts[3]
	summary := generatedMutationEffectSummary(input)
	p := r.Payload
	if len(p.Targets) == 0 {
		return counts, summary, "no-op", nil
	}
	if p.Closed {
		if p.RemainingCount != 0 {
			return counts, summary, "gc-partial-garbage", nil
		}
		return counts, summary, "success", nil
	}
	if p.ProgressOrdinal == 0 {
		return counts, summary, gcStateResult(r.Result), nil
	}
	if summary == contract.ReceiptEffectComplete {
		return counts, summary, gcStateResult(r.Result), nil
	}
	return counts, summary, generatedInvocationEffectState(summary), nil
}

func gcValidateResult(r PublicGCResult) error {
	if r.Operation != GCApplyOperation || !gcResultFactsValid(r.Result) || gcStateCode(r.StateResult) == 0 {
		return contract.ErrRecord
	}
	if r.RequestID.IsZero() {
		if r != (PublicGCResult{Operation: GCApplyOperation, OperationID: r.OperationID, Result: refused(AdmissionInvalid), StateResult: "refused"}) {
			return contract.ErrRecord
		}
		return nil
	}
	counts, summary, state, err := gcSummary(r)
	if err != nil {
		return err
	}
	if r.StateResult != state || r.SummaryCounts != counts || r.EffectSummary != summary || r.OutputSummary != contract.ReceiptOutputNotApplicable {
		return contract.ErrRecord
	}
	p := r.Payload
	if p == nil {
		if !r.RequestIdentity.IsZero() || r.Result.Outcome == ObservedCurrent || r.Result.Outcome == Unchanged || r.EvidenceCeiling != 0 {
			return contract.ErrRecord
		}
		return nil
	}
	if r.OperationID.IsZero() || r.DomainID.IsZero() || r.RequestIdentity.IsZero() || p.PlanDigest.IsZero() || p.MarkDigest.IsZero() || p.EnumerationDigest.IsZero() || p.RequestIdentity != contract.Hash(append([]byte("ENKV/GC-REQUEST/v1\x00"), p.PlanDigest[:]...)) || len(p.Targets) > contract.GCTargetLimit || len(p.Candidates) > contract.GCTargetLimit || len(p.Failures) > 4 || !p.TargetsDescriptor.ValidTargets() || p.TargetsDescriptor.Count != uint32(len(p.Targets)) {
		return contract.ErrRecord
	}
	if p.Observation.DomainID != r.DomainID || p.Observation.HeadRevisionID.IsZero() || p.Observation.SnapshotID.IsZero() || p.Observation.RootDigest.IsZero() || p.Active && p.Closed || p.Closed && p.SelectionUncertain {
		return contract.ErrRecord
	}
	if r.StateResult == "no-op" {
		identity, err := gcNoWorkRequestIdentity(r)
		if err != nil || r.RequestIdentity != identity {
			return contract.ErrRecord
		}
	} else if p.NoWork != nil || r.RequestIdentity != p.RequestIdentity {
		return contract.ErrRecord
	}
	remaining := 0
	previous := ""
	for _, row := range p.Targets {
		if !gcTargetResultValid(row) {
			return contract.ErrRecord
		}
		key, err := contract.StoreObjectKey("gc", r.DomainID, row.Object)
		if err != nil || previous != "" && strings.Compare(previous, key) >= 0 {
			return contract.ErrRecord
		}
		previous = key
		if row.Selected.Disposition != contract.GCTargetAbsent {
			remaining++
		}
		if p.ProgressOrdinal == 0 && (row.Selected.Consumed != 0 || row.Selected.Disposition != contract.GCTargetPending || !row.Selected.EvidenceDigest.IsZero() || row.PermissionOwned || row.DeleteAttempted) {
			return contract.ErrRecord
		}
	}
	if remaining != int(p.RemainingCount) || p.ProgressOrdinal == 0 && (p.Active || p.Closed) || p.ProgressOrdinal != 0 && len(p.Targets) == 0 {
		return contract.ErrRecord
	}
	seen := make([]bool, len(p.Targets))
	for _, c := range p.Candidates {
		if c.Classification < contract.GCCandidateProtected || c.Classification > contract.GCCandidateUnverifiable || c.Reason > contract.GCReasonUnavailable || c.Classification != contract.GCCandidateUnverifiable && c.KeyDigest.IsZero() {
			return contract.ErrRecord
		}
		if c.Classification == contract.GCCandidateEligible {
			if int(c.TargetIndex) >= len(seen) || seen[c.TargetIndex] || c.Reason != contract.GCReasonNone || c.KeyDigest.IsZero() {
				return contract.ErrRecord
			}
			seen[c.TargetIndex] = true
		} else if c.TargetIndex != 65535 {
			return contract.ErrRecord
		}
	}
	for _, v := range seen {
		if !v {
			return contract.ErrRecord
		}
	}
	previousPhase := contract.GCPhase(0)
	for _, failure := range p.Failures {
		if failure.Phase < contract.GCSelect || failure.Phase > contract.GCClose || failure.Phase <= previousPhase || previousPhase == contract.GCSelect && failure.Phase == contract.GCReacquire || failure.Result.Outcome == Unchanged || !gcResultFactsValid(failure.Result) || failure.Write != (contract.WriteResult{}) && !gcResultWriteValid(failure.Write) {
			return contract.ErrRecord
		}
		previousPhase = failure.Phase
	}
	wantEvidence := uint16(contract.ReceiptEvidenceProviderFacts)
	if len(p.Targets) == 0 {
		wantEvidence = contract.ReceiptEvidenceCanonical
	}
	if r.EvidenceCeiling != wantEvidence {
		return contract.ErrRecord
	}
	switch r.StateResult {
	case "no-op":
		if len(p.Targets) != 0 || p.Active || p.Closed || p.ProgressOrdinal != 0 || p.SelectionUncertain || len(p.Failures) != 0 || r.Result.Outcome != Unchanged || r.Result.Evidence != AuthenticatedClosure || r.Result.CommitMayHaveOccurred || r.Result.ObservedRevision != p.Observation.HeadRevisionID || r.Result.ObservedSnapshotID != p.Observation.SnapshotID {
			return contract.ErrRecord
		}
	case "success", "gc-partial-garbage":
		if !p.Closed || p.Active || r.Result.Outcome != ObservedCurrent || r.Result.Evidence != AuthenticatedClosure || r.Result.CommitMayHaveOccurred || r.Result.RequestedRevision != p.Observation.HeadRevisionID || r.Result.ObservedRevision != p.Observation.HeadRevisionID || r.Result.ObservedSnapshotID != p.Observation.SnapshotID {
			return contract.ErrRecord
		}
		if r.StateResult == "success" && (remaining != 0 || summary != contract.ReceiptEffectComplete) {
			return contract.ErrRecord
		}
		if r.StateResult == "gc-partial-garbage" && remaining == 0 {
			return contract.ErrRecord
		}
	}
	return nil
}

func gcNoWorkRequestIdentity(r PublicGCResult) (contract.ID, error) {
	p := r.Payload
	if p == nil || p.NoWork == nil {
		return contract.ID{}, contract.ErrRecord
	}
	v := p.NoWork
	if v.Snapshot.Domain != r.DomainID || v.Snapshot.Object != p.Observation.SnapshotID || v.Snapshot.Digest != p.Observation.RootDigest {
		return contract.ID{}, contract.ErrRecord
	}
	return contract.GCNoWorkObservationIdentity(contract.GCNoWorkObservation{
		OperationID: r.OperationID, DomainID: r.DomainID, RequestCoreDigest: p.RequestIdentity,
		HEADRevisionID: p.Observation.HeadRevisionID, HEADDigest: v.FullHEADDigest, TokenDigest: v.TokenDigest,
		Snapshot: v.Snapshot, WorkBasis: contract.DescriptorVector{Digest: p.TargetsDescriptor.Digest, Length: p.TargetsDescriptor.Length, Count: p.TargetsDescriptor.Count}, Nonce: r.RequestID,
	})
}

func writeGCResultFacts(w *cleanupHashWriter, v Result) {
	w.u8(uint8(v.Outcome))
	w.u8(uint8(v.Reason))
	w.u8(uint8(v.Evidence))
	w.boolean(v.CommitMayHaveOccurred)
	w.u8(uint8(v.StoreReason))
	w.id(v.RequestedRevision)
	w.id(v.ObservedRevision)
	w.id(v.ObservedSnapshotID)
}
func writeGCStoreResult(w *cleanupHashWriter, v contract.WriteResult) {
	w.u8(uint8(v.Status))
	w.u8(uint8(v.Reason))
	w.boolean(v.NotSent)
}
func writeGCSibling(w *cleanupHashWriter, v GCTargetResult) {
	w.u8(uint8(v.Object.Namespace))
	w.u8(uint8(v.Object.Kind))
	w.u16(v.Object.Index)
	w.id(v.Object.ObjectID)
	w.u32(v.Length)
	w.id(v.Digest)
	w.u8(v.Selected.Consumed)
	w.u8(uint8(v.Selected.Disposition))
	w.id(v.Selected.EvidenceDigest)
	w.u8(uint8(v.Observed))
	w.u8(uint8(v.ObservationReason))
	w.id(v.ObservedEvidence)
	w.boolean(v.DeleteAttempted)
	writeGCStoreResult(w, v.DeleteResult)
	w.boolean(v.PermissionOwned)
}

// GCSiblingResults commits complete token-free operational facts. The original
// target descriptor is an opaque plan commitment, not this result vector.
func GCSiblingResults(r PublicGCResult) (GCSiblingCommitment, error) {
	if err := gcValidateResult(r); err != nil {
		return GCSiblingCommitment{}, err
	}
	if r.Payload == nil {
		return GCSiblingCommitment{}, contract.ErrRecord
	}
	p := r.Payload
	h := sha256.New()
	w := cleanupHashWriter{h: h}
	w.raw([]byte("ENKV/GC-SIBLING-PRODUCT-RESULTS/v1\x00"))
	w.u16(40)
	for _, id := range []contract.ID{r.DomainID, r.OperationID, r.RequestIdentity, r.RequestID, p.PlanDigest} {
		w.id(id)
	}
	w.u8(gcStateCode(r.StateResult))
	w.u16(r.EffectSummary)
	w.u16(r.OutputSummary)
	w.u16(r.EvidenceCeiling)
	for _, n := range r.SummaryCounts {
		w.u32(n)
	}
	writeGCResultFacts(&w, r.Result)
	for _, id := range []contract.ID{p.Observation.DomainID, p.Observation.HeadRevisionID, p.Observation.SnapshotID, p.Observation.RootDigest} {
		w.id(id)
	}
	w.boolean(p.Active)
	w.boolean(p.Closed)
	w.boolean(p.SelectionUncertain)
	w.u16(p.RemainingCount)
	w.u32(p.ProgressOrdinal)
	w.id(p.TargetsDescriptor.Digest)
	w.u64(p.TargetsDescriptor.Length)
	w.u32(p.TargetsDescriptor.Count)
	w.id(p.MarkDigest)
	w.id(p.EnumerationDigest)
	w.u16(uint16(len(p.Candidates)))
	for _, c := range p.Candidates {
		w.id(c.KeyDigest)
		w.u8(uint8(c.Classification))
		w.u16(c.TargetIndex)
		w.u8(uint8(c.Reason))
		w.u64(c.ListedLength)
	}
	w.u8(uint8(len(p.Failures)))
	for _, f := range p.Failures {
		w.u8(uint8(f.Phase))
		writeGCResultFacts(&w, f.Result)
		writeGCStoreResult(&w, f.Write)
	}
	w.u32(uint32(len(p.Targets)))
	for _, row := range p.Targets {
		w.u32(gcSiblingRowLength)
		writeGCSibling(&w, row)
	}
	if w.err != nil {
		return GCSiblingCommitment{}, w.err
	}
	if w.length > GCResultVectorMaxBytes {
		return GCSiblingCommitment{}, contract.ErrRecordCapacity
	}
	var digest contract.ID
	copy(digest[:], h.Sum(nil))
	return GCSiblingCommitment{Count: uint32(len(p.Targets)), RootDigest: digest}, nil
}

// RefreshGCResult updates only derived summary and delivery commitments. It
// never changes the actual Core result, selected progress or local attempts.
func RefreshGCResult(r *PublicGCResult) error {
	if r == nil {
		return contract.ErrRecord
	}
	if r.Payload != nil {
		r.Payload.SiblingResults = GCSiblingCommitment{}
	}
	counts, summary, state, err := gcSummary(*r)
	if err != nil {
		return err
	}
	next := *r
	next.SummaryCounts = counts
	next.EffectSummary = summary
	next.OutputSummary = contract.ReceiptOutputNotApplicable
	next.StateResult = state
	next.EvidenceCeiling = 0
	if next.Payload != nil {
		next.EvidenceCeiling = contract.ReceiptEvidenceProviderFacts
		if len(next.Payload.Targets) == 0 {
			next.EvidenceCeiling = contract.ReceiptEvidenceCanonical
		}
	}
	if err := gcValidateResult(next); err != nil {
		return err
	}
	if next.Payload != nil {
		descriptor, err := GCSiblingResults(next)
		if err != nil {
			return err
		}
		next.Payload.SiblingResults = descriptor
	}
	*r = next
	return nil
}
func (r PublicGCResult) Validate() error {
	if err := gcValidateResult(r); err != nil {
		return err
	}
	if r.Payload == nil {
		return nil
	}
	descriptor, err := GCSiblingResults(r)
	if err != nil {
		return err
	}
	if descriptor != r.Payload.SiblingResults {
		return contract.ErrRecord
	}
	return nil
}

func gcResultForPlan(out PublicGCResult, plan contract.GCPlan, observation PublicObservation) PublicGCResult {
	digest, _ := contract.GCPlanDigest(plan)
	request, _ := contract.GCPlanRequestIdentity(plan)
	targets, _ := contract.GCTargetsDescriptor(plan.Targets)
	out.OperationID, out.RequestIdentity, out.DomainID = plan.OperationID, request, plan.DomainID
	p := &GCCleanupPayload{PlanDigest: digest, RequestIdentity: request, MarkDigest: plan.MarkDigest, EnumerationDigest: plan.EnumerationDigest, TargetsDescriptor: targets, Observation: observation, RemainingCount: uint16(len(plan.Targets)), Candidates: append([]contract.GCCandidate(nil), plan.Candidates...)}
	for _, row := range plan.Targets {
		p.Targets = append(p.Targets, GCTargetResult{Object: row.Object, Length: row.Length, Digest: row.Digest, Selected: contract.GCTargetProgress{Disposition: contract.GCTargetPending}})
	}
	out.Payload = p
	return out
}
func gcApplyProgress(out *PublicGCResult, progress contract.GCProgress, active bool) {
	out.Payload.RemainingCount = progress.RemainingCount
	out.Payload.ProgressOrdinal = progress.Ordinal
	out.Payload.Active = active
	for i, row := range progress.Targets {
		out.Payload.Targets[i].Selected = row
	}
}
func gcSelectedProgress(out *PublicGCResult, progress contract.GCProgress, active bool, state *StateSession) {
	gcApplyProgress(out, progress, active)
	out.Payload.Observation = PublicObservation{DomainID: state.root.Domain, HeadRevisionID: state.head.Core.Revision, SnapshotID: state.root.Snapshot, RootDigest: state.head.Core.Root.Digest}
}
