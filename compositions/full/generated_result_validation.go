package compositionfull

import (
	"bytes"
	"slices"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func validGeneratedTarget(target *contract.GeneratorTarget, resource, config, resourceContract contract.ID, mode contract.GeneratorLifecycleMode) bool {
	if target == nil {
		return true
	}
	_, err := contract.EncodeGeneratorTarget(*target)
	return err == nil && target.ResourceID == resource && target.ConfigContractID == config && target.ResourceContractID == resourceContract && target.LifecycleMode == mode
}
func validGeneratedProgress(rows []contract.GeneratorProgress) bool {
	for i, row := range rows {
		if _, err := contract.EncodeGeneratorProgress(row); err != nil || i > 0 && rows[i-1].CompletedSteps >= row.CompletedSteps {
			return false
		}
	}
	return true
}
func validGeneratedFactRows(domain contract.ID, effects []core.GeneratedEffectFact, duties []core.GeneratedDutyFact, hazards []core.GeneratedHazardFact) bool {
	if domain.IsZero() || uint64(len(effects)) > core.GeneratedResultEffectLimit || uint64(len(duties))+uint64(len(hazards)) > core.GeneratedResultWorkLimit {
		return false
	}
	var progress uint64
	for _, v := range effects {
		r := v.Record
		if _, err := contract.GeneratedAttemptRecordLength(r); err != nil || r.DomainID != domain ||
			v.Action != contract.GeneratorActionCreate && v.Action != contract.GeneratorActionDelete || !boundedReaderText(v.Name, contract.CryptoMaxName) ||
			v.EntryIncarnationID.IsZero() || v.PlannedValueSlotID.IsZero() || generatedEvidence(v.EvidenceCeiling) == "" || v.EvidenceCeiling == 0 ||
			v.SummaryClass != 0 && (v.SummaryClass < contract.ReceiptSummarySuccessCount || v.SummaryClass > contract.ReceiptNoEffectPredecessorCount) ||
			!validGeneratedTarget(v.Target, r.ResourceID, r.ConfigContractID, r.ResourceContractID, r.LifecycleMode) || !validGeneratedProgress(v.Progress) {
			return false
		}
		if r.LifecycleMode == contract.GeneratorLifecycleNone {
			if v.Action != contract.GeneratorActionCreate || !v.ResourceDigest.IsZero() || v.Target != nil || len(v.Progress) != 0 || !v.HazardID.IsZero() ||
				v.Warnings != (core.GeneratedResultWarnings{}) || v.Reason != r.FailureReason ||
				r.FailureReason != 0 && v.EvidenceCeiling != contract.ReceiptEvidenceCanonical ||
				v.EvidenceCeiling != contract.ReceiptEvidenceCanonical && v.EvidenceCeiling != contract.ReceiptEvidenceProviderFacts ||
				r.State != contract.GeneratedEffectSucceeded && !v.GenerationID.IsZero() {
				return false
			}
			continue
		}
		if v.Target != nil && (v.Target.Name != v.Name || v.Target.IncarnationID != v.EntryIncarnationID || v.Target.Epoch != v.Epoch || v.Target.ResourceDigest != v.ResourceDigest || v.Target.CompletionClass != r.CompletionClass) {
			return false
		}
		if v.Target == nil && !v.GenerationID.IsZero() {
			return false
		}
		progress += uint64(len(v.Progress))
	}
	for _, v := range duties {
		r := v.Record
		if _, err := contract.GeneratedDutyRecordLength(r); err != nil || r.DomainID != domain || !validGeneratedTarget(v.Target, r.ResourceID, r.ConfigContractID, r.ResourceContractID, r.LifecycleMode) || !validGeneratedProgress(v.Progress) || generatedEvidence(v.EvidenceCeiling) == "" || v.EvidenceCeiling == 0 || v.RetirementMode > contract.GeneratedRetirementAuto {
			return false
		}
		if r.LifecycleMode == contract.GeneratorLifecycleNone {
			if v.Target != nil || len(v.Progress) != 0 || !v.GenerationID.IsZero() || v.RetirementMode != 0 ||
				v.Warnings != (core.GeneratedResultWarnings{}) || v.EvidenceCeiling != contract.ReceiptEvidenceCanonical {
				return false
			}
			continue
		}
		if v.Target == nil && (!v.GenerationID.IsZero() || v.RetirementMode != 0) {
			return false
		}
		progress += uint64(len(v.Progress))
	}
	for _, v := range hazards {
		r := v.Record
		if _, err := contract.GeneratedHazardRecordLength(r); err != nil || r.DomainID != domain || !validGeneratedTarget(v.Target, r.ResourceID, r.ConfigContractID, r.ResourceContractID, contract.GeneratorLifecycleManaged) || generatedEvidence(v.EvidenceCeiling) == "" || v.EvidenceCeiling == 0 || v.RetirementMode > contract.GeneratedRetirementAuto {
			return false
		}
		if v.Target == nil && (!v.GenerationID.IsZero() || v.RetirementMode != 0) {
			return false
		}
		if v.CleanupImplementationQualified && (v.Target == nil || v.CleanupResultContractID.IsZero()) {
			return false
		}
	}
	return progress <= core.GeneratedResultProgressLimit
}
func validGeneratedIDs(ids []contract.ID) bool {
	if uint64(len(ids)) > core.GeneratedResultWorkLimit {
		return false
	}
	for i, id := range ids {
		if id.IsZero() || i > 0 && bytes.Compare(ids[i-1][:], id[:]) >= 0 {
			return false
		}
	}
	return true
}
func validGeneratedDescriptor(value *contract.GeneratorDescriptor, count int) bool {
	return value == nil || value.Valid() && uint64(value.Count) == uint64(count)
}
func generatedOperationName(kind uint16) string {
	switch kind {
	case contract.OperationApplyDeclaration:
		return "apply-declaration"
	case contract.OperationRotateValueEntryValue:
		return "rotate-value-entry-value"
	case contract.OperationRetireGeneratedGeneration:
		return "retire-generated-generation"
	case contract.OperationAcceptGeneratedRetirementResidue:
		return "accept-generated-retirement-residue"
	case contract.OperationCleanOwnedFailureResidue:
		return "clean-owned-failure-residue"
	}
	return ""
}
func generatedReceiptState(v uint16) string {
	switch v {
	case contract.ReceiptStateSuccess:
		return "success"
	case contract.ReceiptStateExactResume:
		return "exact-resume"
	case contract.ReceiptStatePossibleLiveResidueAccepted:
		return "possible-live-residue-accepted"
	case contract.ReceiptStateRetirementPending:
		return "retirement-pending"
	case contract.ReceiptStateEffectUnknown:
		return "effect-unknown"
	case contract.ReceiptStateEffectTerminalFailure:
		return "effect-terminal-failure"
	}
	return ""
}
func generatedStateExitCode(state string) (int, bool) {
	switch state {
	case "success", "no-op", "exact-resume", "possible-live-residue-accepted":
		return 0, true
	case "retirement-pending", "effect-pending", "effect-partial", "effect-unknown", "contention", "commit-outcome-unknown", "unavailable":
		return 3, true
	case "effect-terminal-failure", "positive-defect", "refused", "snapshot-size-refusal":
		return 2, true
	}
	return 2, false
}

func validGeneratedState(state string) bool {
	_, known := generatedStateExitCode(state)
	return known
}

func validateGeneratedInvocation(r core.PublicApplyResult, operation uint16) error {
	if !validApplyPreparation(r.Preparation) {
		return errApplyResult
	}
	g := r.Generated
	if g == nil || g.OperationKind != operation || generatedOperationName(operation) == "" || r.RequestID.IsZero() || r.OperationID.IsZero() || r.RequestIdentity.IsZero() || r.DomainID.IsZero() || r.PreAdmission != nil || r.RetirementBlockers != nil ||
		!validGeneratedState(g.StateResult) || generatedEffectSummary(g.EffectSummary) == "" || generatedEvidence(g.EvidenceCeiling) == "" || g.EvidenceCeiling == 0 ||
		g.CanonicalOutcome != contract.ReceiptCanonicalSelected && g.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || r.WarningBits & ^uint8(31) != 0 || len(r.Diagnostics) > core.MaxApplyResultDiagnostics {
		return errApplyResult
	}
	if r.Result.Outcome != core.ObservedCurrent && g.CanonicalOutcome != contract.ReceiptCanonicalNotSelected {
		switch r.Result.Outcome {
		case core.Contention, core.UnresolvedCommit, core.AdmissionRefused, core.IntegrityFailure, core.EvidenceUnavailable:
			if !g.HasObservedCanonicalSelection(r.DomainID, r.OperationID, r.RequestIdentity) {
				return errApplyResult
			}
		default:
			return errApplyResult
		}
	}
	for _, d := range r.Diagnostics {
		if _, ok := readerDiagnostic(d); !ok {
			return errApplyResult
		}
	}
	if !g.EffectsAvailable && (len(g.Effects) != 0 || g.EffectsCommitment != nil) || !g.RelatedWorkAvailable && (len(g.Duties) != 0 || len(g.Hazards) != 0 || len(g.RelatedDutyIDs) != 0 || len(g.RelatedHazardIDs) != 0 || g.RelatedDutiesCommitment != nil || g.RelatedHazardsCommitment != nil) {
		return errApplyResult
	}
	if !g.SummaryCountsAvailable && (g.SummaryCounts != [contract.ReceiptSummaryCount]uint32{} || g.AcknowledgedCount != 0 || g.ConfirmedCount != 0 || g.UnknownCount != 0 || g.EffectsAvailable || g.RelatedWorkAvailable || g.ReceiptObservation) {
		return errApplyResult
	}
	if g.SummaryCountsAvailable && (uint64(g.UnknownCount) != uint64(g.SummaryCounts[contract.ReceiptSummaryUnknownCount])+uint64(g.SummaryCounts[contract.ReceiptPreservedResidueCount]) ||
		uint64(g.AcknowledgedCount)+uint64(g.ConfirmedCount)+uint64(g.UnknownCount) > uint64(g.SummaryCounts[contract.ReceiptEffectCount])) {
		return errApplyResult
	}
	if !validGeneratedFactRows(r.DomainID, g.Effects, g.Duties, g.Hazards) || !validGeneratedIDs(g.RelatedDutyIDs) || !validGeneratedIDs(g.RelatedHazardIDs) ||
		!validGeneratedDescriptor(g.EffectsCommitment, len(g.Effects)) || !validGeneratedDescriptor(g.RelatedDutiesCommitment, len(g.Duties)) || !validGeneratedDescriptor(g.RelatedHazardsCommitment, len(g.Hazards)) {
		return errApplyResult
	}
	if g.RelatedWorkAvailable {
		if len(g.Duties) != len(g.RelatedDutyIDs) || len(g.Hazards) != len(g.RelatedHazardIDs) {
			return errApplyResult
		}
		for i, v := range g.Duties {
			if v.Record.DutyID != g.RelatedDutyIDs[i] {
				return errApplyResult
			}
		}
		for i, v := range g.Hazards {
			if v.Record.HazardID != g.RelatedHazardIDs[i] {
				return errApplyResult
			}
		}
	}
	for _, effect := range g.Effects {
		if !generatedPreservedHazardWarning(effect) {
			continue
		}
		at, found := slices.BinarySearchFunc(g.RelatedHazardIDs, effect.HazardID, compareGeneratedResultIDs)
		if !g.RelatedWorkAvailable || effect.HazardID.IsZero() || !found {
			return errApplyResult
		}
		hazard := g.Hazards[at]
		a, h := effect.Record, hazard.Record
		if h.OriginalOperationID != a.OperationID || h.OriginalAttemptID != a.AttemptID || h.OwnerID != a.OwnerID || h.ResourceID != a.ResourceID || h.DescriptorID != a.DescriptorID || h.ConfigContractID != a.ConfigContractID || h.ResourceContractID != a.ResourceContractID || h.ExecutorID != a.ExecutorID || h.CredentialRouteID != a.CredentialRouteID || h.ResultContractID != a.ResultContractID ||
			effect.Target != nil && hazard.Target != nil && *effect.Target != *hazard.Target {
			return errApplyResult
		}
	}
	if g.EffectsAvailable {
		var counts [contract.ReceiptSummaryCount]uint32
		var acknowledged, confirmed uint32
		for _, v := range g.Effects {
			if v.SummaryClass < contract.ReceiptSummarySuccessCount || v.SummaryClass > contract.ReceiptNoEffectPredecessorCount {
				return errApplyResult
			}
			counts[v.SummaryClass]++
			if v.Action == contract.GeneratorActionDelete && v.SummaryClass == contract.ReceiptSummarySuccessCount {
				if v.Record.CompletionClass == contract.GeneratedCompletionAcknowledged && v.EvidenceCeiling == contract.ReceiptEvidenceAcknowledged {
					acknowledged++
				} else if v.Record.CompletionClass == contract.GeneratedCompletionConfirmed && v.EvidenceCeiling == contract.ReceiptEvidenceConfirmed {
					confirmed++
				}
			}
		}
		if g.AcknowledgedCount > acknowledged || g.ConfirmedCount > confirmed || uint64(g.SummaryCounts[contract.ReceiptEffectCount]) != uint64(len(g.Effects)) {
			return errApplyResult
		}
		for i := contract.ReceiptSummarySuccessCount; i <= contract.ReceiptNoEffectPredecessorCount; i++ {
			if counts[i] != g.SummaryCounts[i] {
				return errApplyResult
			}
		}
	}
	if g.ReceiptObservation && (g.EffectsAvailable || g.RelatedWorkAvailable || len(r.Receipt) == 0 || r.Result.Outcome != core.ObservedCurrent || r.Result.Evidence != core.AuthenticatedClosure || r.Result.CommitMayHaveOccurred) {
		return errApplyResult
	}
	if p := r.Payload; p != nil {
		if p.PredecessorRevisionID.IsZero() || p.RequestedRevisionID.IsZero() || p.ChangedSubjects.Count > contract.MutationChangedSubjectLimit || p.ChangedSubjects.IdentityRootDigest.IsZero() || !validGeneratedIDs(p.LiveDutyIDs) || !validGeneratedIDs(p.LiveHazardIDs) {
			return errApplyResult
		}
		if !g.ReceiptObservation && (p.RequestedRevisionID != r.Result.RequestedRevision || len(r.Receipt) == 0 && p.ObservedRevisionID != r.Result.ObservedRevision) {
			return errApplyResult
		}
	}
	unresolved := r.Result.Outcome == core.UnresolvedCommit
	if r.Result.CommitMayHaveOccurred != unresolved || (g.StateResult == "commit-outcome-unknown") != unresolved ||
		(g.StateResult == "contention") != (r.Result.Outcome == core.Contention) || unresolved && r.Result.RequestedRevision.IsZero() {
		return errApplyResult
	}
	if operation == contract.OperationCleanOwnedFailureResidue {
		if r.Payload != nil || r.Cleanup == nil || len(r.Receipt) != 0 {
			return errApplyResult
		}
		commitment, err := core.GeneratedCleanupSiblingResults(r)
		if err != nil || commitment != r.Cleanup.SiblingResults {
			return errApplyResult
		}
	} else if r.Cleanup != nil {
		return errApplyResult
	}
	if len(r.Receipt) != 0 {
		row, err := contract.InspectCompactMutationReceipt(r.Receipt)
		p := r.Payload
		if err != nil || operation == contract.OperationCleanOwnedFailureResidue || r.Result.Outcome != core.ObservedCurrent || r.Result.Evidence != core.AuthenticatedClosure || p == nil || row.OperationKind != operation || row.OperationID != r.OperationID || row.RequestIdentityDigest != r.RequestIdentity || row.DomainID != r.DomainID ||
			row.StateResult == 0 || generatedReceiptState(row.StateResult) != g.StateResult || row.CanonicalOutcome != g.CanonicalOutcome || row.EffectSummary != g.EffectSummary || row.EvidenceCeiling != g.EvidenceCeiling || row.SummaryCounts != g.SummaryCounts || row.AcknowledgedCount != g.AcknowledgedCount || row.ConfirmedCount != g.ConfirmedCount || row.UnknownCount != g.UnknownCount ||
			row.PredecessorRevisionID != p.PredecessorRevisionID || row.RequestedRevisionID != p.RequestedRevisionID || row.ObservedRevisionID != p.ObservedRevisionID || row.ChangedSubjects.Count != p.ChangedSubjects.Count || row.ChangedSubjects.Digest != p.ChangedSubjects.IdentityRootDigest {
			return errApplyResult
		}
		if !g.ReceiptObservation && (r.Result.RequestedRevision != row.RequestedRevisionID || r.Result.ObservedRevision != row.RequestedRevisionID) {
			return errApplyResult
		}
	}
	return nil
}

func compareGeneratedResultIDs(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) }

func generatedPreservedHazardWarning(v core.GeneratedEffectFact) bool {
	return v.SummaryClass == contract.ReceiptPreservedResidueCount &&
		(v.Record.State == contract.GeneratedEffectPossibleLive || v.Record.State == contract.GeneratedEffectClosedWithResidue)
}

func generatedMutationHazardWarnings(g *core.GeneratedInvocationResult) []bool {
	var required []bool
	for _, effect := range g.Effects {
		if !generatedPreservedHazardWarning(effect) {
			continue
		}
		if required == nil {
			required = make([]bool, len(g.Hazards))
		}
		at, _ := slices.BinarySearchFunc(g.RelatedHazardIDs, effect.HazardID, compareGeneratedResultIDs)
		required[at] = true
	}
	return required
}
