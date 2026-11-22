package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math"
	"slices"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

// GeneratedCleanupSiblingResults validates and commits the complete typed
// sibling Product rows. It does not read state or include its own descriptor.
// Callers must refresh it after adding any delivery diagnostic.
func GeneratedCleanupSiblingResults(r PublicApplyResult) (GeneratedCleanupSiblingCommitment, error) {
	var empty GeneratedCleanupSiblingCommitment
	p, g := r.Cleanup, r.Generated
	if p == nil || p.Schema != 1 || r.Payload != nil || len(r.Receipt) != 0 || g == nil || g.OperationKind != contract.OperationCleanOwnedFailureResidue || r.DomainID.IsZero() || r.OperationID.IsZero() || r.RequestIdentity.IsZero() || r.RequestID.IsZero() {
		return empty, contract.ErrRecord
	}
	if err := validateGeneratedCleanup(r); err != nil {
		return empty, err
	}
	count := uint32(1)
	if p.Basis.Kind == GeneratedCleanupNoWork {
		count = 0
	}
	h := sha256.New()
	w := cleanupHashWriter{h: h}
	w.raw([]byte("ENKV/CLEANUP-SIBLING-PRODUCT-RESULTS/v3\x00"))
	w.u16(contract.OperationCleanOwnedFailureResidue)
	w.id(r.DomainID)
	w.id(r.OperationID)
	w.id(r.RequestIdentity)
	w.u32(count)
	if count != 0 {
		measure := cleanupHashWriter{}
		writeGeneratedCleanupRow(&measure, r)
		if measure.err != nil {
			return empty, measure.err
		}
		if measure.length > math.MaxUint32 {
			return empty, contract.ErrRecordCapacity
		}
		w.u32(uint32(measure.length))
		writeGeneratedCleanupRow(&w, r)
	}
	if w.err != nil {
		return empty, w.err
	}
	var digest contract.ID
	copy(digest[:], h.Sum(nil))
	return GeneratedCleanupSiblingCommitment{Count: count, RootDigest: digest}, nil
}

// RefreshGeneratedCleanupResult leaves the authoritative mutation result and
// owned facts intact on error, and clears the invalid delivery commitment.
func RefreshGeneratedCleanupResult(r *PublicApplyResult) error {
	if r == nil {
		return contract.ErrRecord
	}
	if r.Cleanup == nil {
		return nil
	}
	r.Cleanup.SiblingResults = GeneratedCleanupSiblingCommitment{}
	descriptor, err := GeneratedCleanupSiblingResults(*r)
	if err != nil {
		return err
	}
	r.Cleanup.SiblingResults = descriptor
	return nil
}

type cleanupHashWriter struct {
	h      hash.Hash
	length uint64
	err    error
}

func (w *cleanupHashWriter) raw(b []byte) {
	if w.err != nil {
		return
	}
	if w.h != nil {
		_, w.err = w.h.Write(b)
	}
	w.length += uint64(len(b))
}
func (w *cleanupHashWriter) u8(v uint8) { w.raw([]byte{v}) }
func (w *cleanupHashWriter) u16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.raw(b[:])
}
func (w *cleanupHashWriter) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.raw(b[:])
}
func (w *cleanupHashWriter) u64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.raw(b[:])
}
func (w *cleanupHashWriter) id(v contract.ID) { w.raw(v[:]) }
func (w *cleanupHashWriter) optionalID(v contract.ID) {
	w.boolean(!v.IsZero())
	if !v.IsZero() {
		w.id(v)
	}
}
func (w *cleanupHashWriter) boolean(v bool) {
	if v {
		w.u8(1)
	} else {
		w.u8(0)
	}
}
func (w *cleanupHashWriter) blob(v []byte) {
	if uint64(len(v)) > math.MaxUint32 {
		w.err = contract.ErrRecordCapacity
		return
	}
	w.u32(uint32(len(v)))
	w.raw(v)
}
func (w *cleanupHashWriter) text(v string) { w.blob([]byte(v)) }
func (w *cleanupHashWriter) encoded(v []byte, err error) {
	if err != nil {
		w.err = err
		return
	}
	w.blob(v)
}
func (w *cleanupHashWriter) target(v *contract.GeneratorTarget) {
	w.boolean(v != nil)
	if v != nil {
		w.encoded(contract.EncodeGeneratorTarget(*v))
	}
}
func (w *cleanupHashWriter) ids(v []contract.ID) {
	w.u32(uint32(len(v)))
	for _, id := range v {
		w.id(id)
	}
}
func cleanupWarnings(v GeneratedResultWarnings) uint8 {
	var b uint8
	if v.PossibleLiveResidue {
		b |= 1
	}
	if v.LateEffect {
		b |= 2
	}
	if v.InvalidationNotConfirmed {
		b |= 4
	}
	return b
}
func (w *cleanupHashWriter) progress(v []contract.GeneratorProgress) {
	w.u32(uint32(len(v)))
	for _, p := range v {
		w.encoded(contract.EncodeGeneratorProgress(p))
	}
}
func (w *cleanupHashWriter) retirement(v uint8) {
	w.boolean(v != 0)
	if v != 0 {
		w.u8(v)
	}
}
func writeGeneratedCleanupRow(w *cleanupHashWriter, r PublicApplyResult) {
	p, g := r.Cleanup, r.Generated
	b := p.Basis
	w.u8(uint8(b.Kind))
	w.id(b.PlanGraphID)
	w.u8(uint8(b.SourceKind))
	w.id(b.SourceID)
	w.id(b.OriginalOwnerID)
	w.id(b.OriginalOperationID)
	w.id(b.OriginalAttemptID)
	w.boolean(b.OriginalResult != nil)
	if b.OriginalResult != nil {
		w.encoded(contract.EncodeGeneratorResultReference(*b.OriginalResult))
	}
	w.target(b.Target)
	w.id(r.RequestID)
	w.optionalID(p.PredecessorRevisionID)
	w.optionalID(r.Result.RequestedRevision)
	w.optionalID(r.Result.ObservedRevision)
	w.boolean(r.Result.CommitMayHaveOccurred)
	w.id(p.RemainingWorkBasis.HeadRevisionID)
	ref, err := contract.AppendRef(nil, p.RemainingWorkBasis.Snapshot, contract.CanonicalSchema)
	if err != nil {
		w.err = err
	} else {
		w.raw(ref)
	}
	w.text(g.StateResult)
	w.u8(g.CanonicalOutcome)
	w.u16(g.EffectSummary)
	w.u16(0)
	w.u16(g.EvidenceCeiling)
	w.boolean(g.SummaryCountsAvailable)
	for _, n := range g.SummaryCounts {
		w.u32(n)
	}
	w.u32(g.AcknowledgedCount)
	w.u32(g.ConfirmedCount)
	w.u32(g.UnknownCount)
	w.u8(r.WarningBits)
	w.u8(cleanupWarnings(g.Warnings))
	w.boolean(g.EffectsAvailable)
	w.u32(uint32(len(g.Effects)))
	for _, f := range g.Effects {
		w.encoded(contract.EncodeGeneratedAttemptRecord(f.Record))
		w.u8(f.Action)
		w.text(f.Name)
		w.id(f.EntryIncarnationID)
		w.u64(f.Epoch)
		w.id(f.PlannedValueSlotID)
		w.id(f.ResourceDigest)
		w.target(f.Target)
		w.optionalID(f.GenerationID)
		w.optionalID(f.DutyID)
		w.optionalID(f.HazardID)
		w.u8(f.Reason)
		w.u16(f.EvidenceCeiling)
		w.u8(uint8(f.SummaryClass))
		w.progress(f.Progress)
		w.u8(cleanupWarnings(f.Warnings))
	}
	w.boolean(g.RelatedWorkAvailable)
	w.u32(uint32(len(g.Duties)))
	for _, f := range g.Duties {
		w.encoded(contract.EncodeGeneratedDutyRecord(f.Record))
		w.target(f.Target)
		w.optionalID(f.GenerationID)
		w.retirement(f.RetirementMode)
		w.progress(f.Progress)
		w.u16(f.EvidenceCeiling)
		w.u8(cleanupWarnings(f.Warnings))
	}
	w.u32(uint32(len(g.Hazards)))
	for _, f := range g.Hazards {
		w.encoded(contract.EncodeGeneratedHazardRecord(f.Record))
		w.target(f.Target)
		w.optionalID(f.GenerationID)
		w.retirement(f.RetirementMode)
		w.u16(f.EvidenceCeiling)
		w.u8(cleanupWarnings(f.Warnings))
		w.optionalID(f.CleanupResultContractID)
		w.boolean(f.CleanupImplementationQualified)
	}
	w.ids(p.RemainingDutyIDs)
	w.ids(p.RemainingHazardIDs)
	w.ids(p.RemainingInboxIDs)
	w.u32(uint32(len(r.Diagnostics)))
	for _, d := range r.Diagnostics {
		writeCleanupDiagnostic(w, d)
	}
}

func cleanupIDsValid(v []contract.ID) bool {
	for j, id := range v {
		if id.IsZero() || j > 0 && compareGeneratedIDs(v[j-1], id) >= 0 {
			return false
		}
	}
	return true
}
func cleanupText(v string, max int) bool { return len(v) <= max && utf8.ValidString(v) }
func cleanupCeiling(v uint16) bool {
	return v >= contract.ReceiptEvidenceCanonical && v <= contract.ReceiptEvidenceMixedCompletion
}
func cleanupTargetMatches(t *contract.GeneratorTarget, domainResource, configContract, resourceContract contract.ID) bool {
	return t == nil || t.ResourceID == domainResource && t.ConfigContractID == configContract && t.ResourceContractID == resourceContract
}

func cleanupTargetFreeCreateReflection(r PublicApplyResult, f GeneratedEffectFact) bool {
	b, g := r.Cleanup.Basis, r.Generated
	if b.Kind != GeneratedCleanupReflection || b.SourceKind != contract.GeneratedHazardSupportKind || b.OriginalResult == nil ||
		f.Action != contract.GeneratorActionCreate || f.Record.SemanticLifecycleMode() != contract.GeneratorLifecycleManaged ||
		f.Record.Stage != contract.GeneratedStageTerminal || !f.ResourceDigest.IsZero() || f.Target != nil || !f.DutyID.IsZero() ||
		f.EvidenceCeiling != contract.ReceiptEvidenceCanonical || f.Reason != contract.GeneratorReasonNone || f.Record.FailureReason != 0 ||
		f.Record.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) ||
		f.Record.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || len(f.Progress) != 0 ||
		g.AcknowledgedCount != 0 || g.ConfirmedCount != 0 {
		return false
	}
	hazardID, err := contract.GeneratorHazardID(f.Record.DomainID, f.Record.AttemptID)
	if err != nil || hazardID != b.SourceID {
		return false
	}
	if target := b.Target; target != nil && (target.LifecycleMode != f.Record.SemanticLifecycleMode() ||
		target.Name != f.Name || target.IncarnationID != f.EntryIncarnationID || target.Epoch != f.Epoch ||
		target.OriginalOperationID != f.Record.OperationID || target.OriginalAttemptID != f.Record.AttemptID ||
		!cleanupTargetMatches(target, f.Record.ResourceID, f.Record.ConfigContractID, f.Record.ResourceContractID) ||
		target.ResultContractID != f.Record.ResultContractID || target.CompletionClass != f.Record.CompletionClass) {
		return false
	}
	if f.Record.State == contract.GeneratedEffectConfirmedNoEffect {
		return f.SummaryClass == contract.ReceiptSummarySuccessCount && f.HazardID.IsZero() && b.Target == nil &&
			len(g.Hazards) == 0 && f.Record.History == contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
	}
	if f.Record.State != contract.GeneratedEffectClosedWithResidue || f.SummaryClass != contract.ReceiptSummaryUnknownCount ||
		f.HazardID != b.SourceID || len(g.Hazards) != 1 {
		return false
	}
	h := g.Hazards[0]
	return h.Target == nil && h.Record.HazardID == b.SourceID && h.Record.DomainID == f.Record.DomainID &&
		h.Record.OriginalOperationID == f.Record.OperationID && h.Record.OriginalAttemptID == f.Record.AttemptID && h.Record.OwnerID == f.Record.OwnerID &&
		h.Record.ResourceID == f.Record.ResourceID && h.Record.ConfigContractID == f.Record.ConfigContractID && h.Record.ResourceContractID == f.Record.ResourceContractID &&
		h.Record.ExecutorID == f.Record.ExecutorID && h.Record.CredentialRouteID == f.Record.CredentialRouteID && h.Record.DescriptorID == f.Record.DescriptorID && h.Record.ResultContractID == f.Record.ResultContractID &&
		h.Record.CompletionClass == f.Record.CompletionClass &&
		h.Record.Exposure == contract.GeneratedExposurePossibleLive && h.Record.Fenced == 1 && h.Record.Eligibility == 0 &&
		h.Record.History == f.Record.History && h.Record.Target == contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) &&
		h.Record.OriginalResults == contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults)
}

func validateGeneratedCleanup(r PublicApplyResult) error {
	p, g := r.Cleanup, r.Generated
	b := p.Basis
	if !generatedCleanupResultStateValid(r) {
		return contract.ErrRecord
	}
	if r.WarningBits&^uint8(31) != 0 || g.ReceiptObservation || !cleanupCeiling(g.EvidenceCeiling) || g.CanonicalOutcome < contract.ReceiptCanonicalSelected || g.CanonicalOutcome > contract.ReceiptCanonicalNotSelected || g.EffectSummary > contract.ReceiptEffectFailed || p.RemainingWorkBasis.HeadRevisionID.IsZero() || p.RemainingWorkBasis.Snapshot.Kind != contract.RootKind || p.RemainingWorkBasis.Snapshot.Domain != r.DomainID || !p.RemainingWorkBasis.Snapshot.ValidFor(contract.CanonicalSchema) {
		return contract.ErrRecord
	}
	switch g.StateResult {
	case "no-op", "success", "effect-pending", "effect-partial", "effect-unknown", "effect-terminal-failure", "contention", "commit-outcome-unknown", "refused", "positive-defect", "unavailable":
	default:
		return contract.ErrRecord
	}
	if uint64(len(p.RemainingDutyIDs))+uint64(len(p.RemainingHazardIDs))+uint64(len(p.RemainingInboxIDs)) > GeneratedResultWorkLimit {
		return contract.ErrRecordCapacity
	}
	for _, ids := range [][]contract.ID{p.RemainingDutyIDs, p.RemainingHazardIDs, p.RemainingInboxIDs} {
		if !cleanupIDsValid(ids) {
			return contract.ErrRecord
		}
	}
	switch b.Kind {
	case GeneratedCleanupNoWork:
		if !b.PlanGraphID.IsZero() || b.SourceKind != 0 || !b.SourceID.IsZero() || !b.OriginalOwnerID.IsZero() || !b.OriginalOperationID.IsZero() || !b.OriginalAttemptID.IsZero() || b.OriginalResult != nil || b.Target != nil || g.StateResult != "no-op" || r.Result.Outcome != Unchanged || !g.EffectsAvailable || !g.RelatedWorkAvailable || !g.SummaryCountsAvailable || len(g.Effects) != 0 || len(g.Duties) != 0 || len(g.Hazards) != 0 {
			return contract.ErrRecord
		}
	case GeneratedCleanupReflection, GeneratedCleanupOwnedTarget:
		if b.PlanGraphID.IsZero() || b.SourceKind != contract.GeneratedDutySupportKind && b.SourceKind != contract.GeneratedHazardSupportKind || b.SourceID.IsZero() || b.OriginalOwnerID.IsZero() || b.OriginalOperationID.IsZero() || b.OriginalAttemptID.IsZero() || p.PredecessorRevisionID.IsZero() {
			return contract.ErrRecord
		}
		if b.Kind == GeneratedCleanupOwnedTarget && b.Target == nil {
			return contract.ErrRecord
		}
		if b.Kind == GeneratedCleanupReflection {
			if b.OriginalResult == nil {
				return contract.ErrRecord
			}
			if _, err := contract.EncodeGeneratorResultReference(*b.OriginalResult); err != nil {
				return err
			}
		} else if b.OriginalResult != nil {
			return contract.ErrRecord
		}
		if b.Target != nil {
			if _, err := contract.EncodeGeneratorTarget(*b.Target); err != nil {
				return err
			}
		}
	default:
		return contract.ErrRecord
	}
	if !g.SummaryCountsAvailable && (g.SummaryCounts != [contract.ReceiptSummaryCount]uint32{} || g.AcknowledgedCount != 0 || g.ConfirmedCount != 0 || g.UnknownCount != 0) {
		return contract.ErrRecord
	}
	if !g.EffectsAvailable && (len(g.Effects) != 0 || g.EffectsCommitment != nil) || !g.RelatedWorkAvailable && (len(g.Duties) != 0 || len(g.Hazards) != 0 || len(g.RelatedDutyIDs) != 0 || len(g.RelatedHazardIDs) != 0 || g.RelatedDutiesCommitment != nil || g.RelatedHazardsCommitment != nil) {
		return contract.ErrRecord
	}
	// A cleanup invocation fixes one target. Related source work can contain both
	// its Duty and Hazard, but never an unrelated operational vector.
	if len(g.Effects) > 1 || len(g.Duties) > 1 || len(g.Hazards) > 1 || len(g.RelatedDutyIDs) != len(g.Duties) || len(g.RelatedHazardIDs) != len(g.Hazards) {
		return contract.ErrRecord
	}
	if !cleanupIDsValid(g.RelatedDutyIDs) || !cleanupIDsValid(g.RelatedHazardIDs) {
		return contract.ErrRecord
	}
	if g.RelatedWorkAvailable && b.Kind != GeneratedCleanupNoWork {
		if b.SourceKind == contract.GeneratedDutySupportKind && containsCleanupID(p.RemainingDutyIDs, b.SourceID) && !containsCleanupID(g.RelatedDutyIDs, b.SourceID) {
			return contract.ErrRecord
		}
		if b.SourceKind == contract.GeneratedHazardSupportKind && containsCleanupID(p.RemainingHazardIDs, b.SourceID) && !containsCleanupID(g.RelatedHazardIDs, b.SourceID) {
			return contract.ErrRecord
		}
	}
	var effects, duties, hazards []contract.SupportRecord
	var classes [contract.ReceiptSummaryCount]uint32
	for _, f := range g.Effects {
		targetFree := cleanupTargetFreeCreateReflection(r, f)
		if f.Reason == GeneratedReasonRetirementResourceMismatch {
			if f.Action != contract.GeneratorActionDelete || f.Record.LifecycleMode != contract.GeneratorLifecycleManaged || f.Record.State != contract.GeneratedEffectUnknown ||
				f.Record.Stage != contract.GeneratedStageTerminal || f.EvidenceCeiling != contract.ReceiptEvidenceCanonical || f.Warnings.InvalidationNotConfirmed {
				return contract.ErrRecord
			}
		} else if f.Reason > contract.GeneratorReasonIdentityConflict {
			lateCreate := b.Kind == GeneratedCleanupReflection && b.OriginalResult != nil && f.Record.State == contract.GeneratedEffectClosedWithResidue
			if f.Reason != GeneratedReasonValueEncoding || f.Action != contract.GeneratorActionCreate || f.Record.LifecycleMode != contract.GeneratorLifecycleManaged ||
				(f.Record.State != contract.GeneratedEffectFailedTerminal && !lateCreate) || f.Target == nil || f.EvidenceCeiling != contract.ReceiptEvidenceProviderFacts {
				return contract.ErrRecord
			}
		}
		if f.Record.DomainID != r.DomainID || f.Record.OperationID != b.OriginalOperationID || f.Record.AttemptID != b.OriginalAttemptID || f.Record.OwnerID != b.OriginalOwnerID || f.Action != contract.GeneratorActionCreate && f.Action != contract.GeneratorActionDelete || !cleanupText(f.Name, contract.CryptoMaxName) || f.EntryIncarnationID.IsZero() || f.PlannedValueSlotID.IsZero() || f.ResourceDigest.IsZero() && !targetFree || f.Action == contract.GeneratorActionCreate && f.Record.State == contract.GeneratedEffectConfirmedNoEffect && !targetFree || !cleanupCeiling(f.EvidenceCeiling) || f.SummaryClass < contract.ReceiptSummarySuccessCount || f.SummaryClass > contract.ReceiptNoEffectPredecessorCount || !cleanupTargetMatches(f.Target, f.Record.ResourceID, f.Record.ConfigContractID, f.Record.ResourceContractID) {
			return contract.ErrRecord
		}
		if f.Target != nil && (f.Target.Name != f.Name || f.Target.IncarnationID != f.EntryIncarnationID || f.Target.Epoch != f.Epoch || f.Target.ResourceDigest != f.ResourceDigest || b.Target == nil || *f.Target != *b.Target) {
			return contract.ErrRecord
		}
		if !f.DutyID.IsZero() && !containsCleanupID(g.RelatedDutyIDs, f.DutyID) || !f.HazardID.IsZero() && !containsCleanupID(g.RelatedHazardIDs, f.HazardID) {
			return contract.ErrRecord
		}
		body, err := contract.EncodeGeneratedAttemptRecord(f.Record)
		if err != nil {
			return err
		}
		effects = append(effects, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: f.Record.AttemptID, Body: body})
		classes[f.SummaryClass]++
		if err := validateCleanupProgress(f.Progress); err != nil {
			return err
		}
		if err := validateCleanupProgressDescriptor(f.Record.Progress, f.Progress); err != nil {
			// A controlled release can retain stronger exact ACK/confirmation
			// proofs while preserving its historical Attempt record.
			if !generatedInvocationCompletionValid(f, contract.GeneratedCompletionConfirmed) {
				return err
			}
		}
		if b.OriginalResult != nil && b.OriginalResult.ResultID != f.Record.ResultID {
			return contract.ErrRecord
		}
	}
	for j, f := range g.Duties {
		if f.Record.DomainID != r.DomainID || f.Record.DutyID != g.RelatedDutyIDs[j] || !cleanupCeiling(f.EvidenceCeiling) || f.RetirementMode > contract.GeneratedRetirementAuto || !cleanupTargetMatches(f.Target, f.Record.ResourceID, f.Record.ConfigContractID, f.Record.ResourceContractID) {
			return contract.ErrRecord
		}
		if !containsCleanupID(p.RemainingDutyIDs, f.Record.DutyID) || (f.GenerationID.IsZero() != (f.RetirementMode == 0)) {
			return contract.ErrRecord
		}
		if err := validateCleanupTargetDescriptor(f.Record.Target, f.Target); err != nil {
			return err
		}
		if err := validateCleanupProgressDescriptor(f.Record.Progress, f.Progress); err != nil {
			return err
		}
		if f.Target != nil && b.Target != nil && *f.Target != *b.Target {
			return contract.ErrRecord
		}
		body, err := contract.EncodeGeneratedDutyRecord(f.Record)
		if err != nil {
			return err
		}
		duties = append(duties, contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: f.Record.DutyID, Body: body})
		if err := validateCleanupProgress(f.Progress); err != nil {
			return err
		}
	}
	for j, f := range g.Hazards {
		if f.Record.DomainID != r.DomainID || f.Record.HazardID != g.RelatedHazardIDs[j] || !cleanupCeiling(f.EvidenceCeiling) || f.RetirementMode > contract.GeneratedRetirementAuto || !cleanupTargetMatches(f.Target, f.Record.ResourceID, f.Record.ConfigContractID, f.Record.ResourceContractID) || f.CleanupImplementationQualified && f.CleanupResultContractID.IsZero() {
			return contract.ErrRecord
		}
		if !containsCleanupID(p.RemainingHazardIDs, f.Record.HazardID) || (f.GenerationID.IsZero() != (f.RetirementMode == 0)) {
			return contract.ErrRecord
		}
		if err := validateCleanupTargetDescriptor(f.Record.Target, f.Target); err != nil {
			return err
		}
		if f.Target != nil && b.Target != nil && *f.Target != *b.Target {
			return contract.ErrRecord
		}
		if f.EvidenceCeiling != contract.ReceiptEvidenceCanonical || f.Warnings.PossibleLiveResidue != (f.Record.Exposure == contract.GeneratedExposurePossibleLive) || f.Warnings.LateEffect != (f.Record.Exposure == contract.GeneratedExposureLateEffect) || f.Warnings.InvalidationNotConfirmed {
			return contract.ErrRecord
		}
		body, err := contract.EncodeGeneratedHazardRecord(f.Record)
		if err != nil {
			return err
		}
		hazards = append(hazards, contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: f.Record.HazardID, Body: body})
	}
	for _, set := range []struct {
		available bool
		kind      contract.MutationResultRecordKind
		rows      []contract.SupportRecord
		expected  *contract.GeneratorDescriptor
	}{{g.EffectsAvailable, contract.MutationResultEffects, effects, g.EffectsCommitment}, {g.RelatedWorkAvailable, contract.MutationResultDuties, duties, g.RelatedDutiesCommitment}, {g.RelatedWorkAvailable, contract.MutationResultHazards, hazards, g.RelatedHazardsCommitment}} {
		if set.available {
			actual, err := contract.MutationResultRecordDescriptor(set.kind, r.DomainID, set.rows)
			if err != nil {
				return err
			}
			if set.expected == nil || actual != *set.expected {
				return contract.ErrRecord
			}
		}
	}
	if g.SummaryCountsAvailable {
		if g.EffectsAvailable {
			if g.SummaryCounts[contract.ReceiptEffectCount] != uint32(len(g.Effects)) {
				return contract.ErrRecord
			}
			for j := contract.ReceiptSummarySuccessCount; j <= contract.ReceiptNoEffectPredecessorCount; j++ {
				if g.SummaryCounts[j] != classes[j] {
					return contract.ErrRecord
				}
			}
		}
		if g.RelatedWorkAvailable && (g.SummaryCounts[contract.ReceiptDutyCount] != uint32(len(g.Duties)) || g.SummaryCounts[contract.ReceiptHazardCount] != uint32(len(g.Hazards))) {
			return contract.ErrRecord
		}
		if g.EffectsAvailable {
			var ack, confirmed uint32
			for _, f := range g.Effects {
				if f.SummaryClass != contract.ReceiptSummarySuccessCount {
					continue
				}
				if f.Record.State == contract.GeneratedEffectConfirmedNoEffect && cleanupTargetFreeCreateReflection(r, f) {
					continue
				}
				if !generatedInvocationCompletionValid(f, f.Record.CompletionClass) {
					return contract.ErrRecord
				}
				if f.Record.CompletionClass == contract.GeneratedCompletionAcknowledged {
					ack++
				} else {
					confirmed++
				}
			}
			if ack != g.AcknowledgedCount || confirmed != g.ConfirmedCount {
				return contract.ErrRecord
			}
		}
		if g.SummaryCounts[contract.ReceiptOutputCount] != 0 || g.UnknownCount != g.SummaryCounts[contract.ReceiptSummaryUnknownCount]+g.SummaryCounts[contract.ReceiptPreservedResidueCount] || uint64(g.AcknowledgedCount)+uint64(g.ConfirmedCount) > uint64(g.SummaryCounts[contract.ReceiptSummarySuccessCount]) || g.EffectSummary != generatedOperationEffectSummary(g.OperationKind, g.SummaryCounts) {
			return contract.ErrRecord
		}
	}
	if len(r.Diagnostics) > MaxApplyResultDiagnostics {
		return contract.ErrRecordCapacity
	}
	for _, d := range r.Diagnostics {
		if !cleanupDiagnosticValid(d) {
			return contract.ErrRecord
		}
	}
	return nil
}
func containsCleanupID(v []contract.ID, id contract.ID) bool {
	for _, a := range v {
		if a == id {
			return true
		}
	}
	return false
}
func validateCleanupProgress(rows []contract.GeneratorProgress) error {
	if uint64(len(rows)) > GeneratedResultProgressLimit {
		return contract.ErrRecordCapacity
	}
	for j, p := range rows {
		if _, err := contract.EncodeGeneratorProgress(p); err != nil {
			return err
		}
		if j > 0 && rows[j-1].CompletedSteps >= p.CompletedSteps {
			return contract.ErrRecord
		}
	}
	return nil
}

func validateCleanupTargetDescriptor(descriptor contract.GeneratorDescriptor, target *contract.GeneratorTarget) error {
	var rows [][]byte
	if target != nil {
		body, err := contract.EncodeGeneratorTarget(*target)
		if err != nil {
			return err
		}
		rows = [][]byte{body}
	}
	actual, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, rows)
	if err != nil {
		return err
	}
	if actual != descriptor {
		return contract.ErrRecord
	}
	return nil
}
func validateCleanupProgressDescriptor(descriptor contract.GeneratorDescriptor, progress []contract.GeneratorProgress) error {
	rows := make([][]byte, len(progress))
	for j, p := range progress {
		body, err := contract.EncodeGeneratorProgress(p)
		if err != nil {
			return err
		}
		rows[j] = body
	}
	slices.SortFunc(rows, func(a, b []byte) int { return bytes.Compare(a[2:66], b[2:66]) })
	actual, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorProgress, rows)
	if err != nil {
		return err
	}
	if actual != descriptor {
		return contract.ErrRecord
	}
	return nil
}

func generatedCleanupResultStateValid(r PublicApplyResult) bool {
	state := r.Generated.StateResult
	if r.Result.Outcome != ObservedCurrent && r.Generated.CanonicalOutcome != contract.ReceiptCanonicalNotSelected {
		return false
	}
	if r.Result.CommitMayHaveOccurred != (r.Result.Outcome == UnresolvedCommit) {
		return false
	}
	switch r.Result.Outcome {
	case Unchanged:
		return r.Cleanup.Basis.Kind == GeneratedCleanupNoWork && state == "no-op" && r.Result.Evidence == AuthenticatedClosure
	case ObservedCurrent:
		if r.Cleanup.Basis.Kind == GeneratedCleanupNoWork || r.Result.Evidence != AuthenticatedClosure || r.Result.ObservedRevision.IsZero() || r.Cleanup.RemainingWorkBasis.HeadRevisionID != r.Result.ObservedRevision || !r.Result.RequestedRevision.IsZero() && r.Result.RequestedRevision != r.Result.ObservedRevision || !r.Result.ObservedSnapshotID.IsZero() && r.Result.ObservedSnapshotID != r.Cleanup.RemainingWorkBasis.Snapshot.Object {
			return false
		}
		switch state {
		case "success", "effect-pending", "effect-partial", "effect-unknown", "effect-terminal-failure":
			return true
		}
	case Contention:
		return state == "contention"
	case UnresolvedCommit:
		return state == "commit-outcome-unknown" && !r.Result.RequestedRevision.IsZero()
	case AdmissionRefused:
		return state == "refused"
	case IntegrityFailure:
		return state == "positive-defect"
	case EvidenceUnavailable:
		return state == "unavailable"
	}
	return false
}
