package compositionfull

import (
	"fmt"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func renderGeneratedListHuman(r core.PublicGeneratedListResult, sourceFailure *ConfigurationSourceFailure, location *resultStoreLocation) ([]byte, error) {
	return renderGeneratedResult(func(w *generatedResultWriter) {
		w.text("Generated work: " + string(r.StateResult) + "\n")
		w.text(configurationSourceFailureHuman(sourceFailure))
		if r.FailureReason != "" {
			w.text("Reason: " + string(r.FailureReason) + "\n")
		}
		v := r.View
		if v == nil {
			return
		}
		w.text("Domain: " + readerID(v.DomainID) + "\nObserved revision: " + readerID(v.RevisionID) + "\nSnapshot: " + readerID(v.SnapshotID) + "\n")
		writeResultStoreLocationHuman(w, location)
		for _, warning := range applyWarningTexts(v.DomainWarningBits) {
			w.text("Warning: " + warning + "\n")
		}
		inspectionActiveHuman(w, v.ActiveOperation)
		writeGeneratedQueryRowsHuman(w, core.InspectionGeneratedWork{CurrentGenerations: v.CurrentGenerations, Effects: v.Effects, Duties: v.Duties, Hazards: v.Hazards, PendingReleases: v.PendingReleases, NextActions: v.NextActions}, v.ActiveOperation == nil)
		if v.PossibleGarbage {
			w.text("Warning: unreferenced Store objects may remain.\n")
		}
	})
}

func writeResultStoreLocationHuman(w generatedFactWriter, location *resultStoreLocation) {
	if location == nil {
		return
	}
	p := location.fields()
	w.text(fmt.Sprintf("Configured Store: %s; region %q; bucket %q; prefix %q\n", p["provider"], p["region"], p["bucket"], p["prefix"]))
}

func writeGeneratedEffectHuman(w generatedFactWriter, p core.GeneratedEffectFact) {
	r := p.Record
	w.text(fmt.Sprintf("Generated %s %q: %s; stage %s; epoch %d\n", map[uint8]string{contract.GeneratorActionCreate: "create", contract.GeneratorActionDelete: "delete"}[p.Action], p.Name, generatedEffectState(r.State), generatedStageHuman(r.Stage), p.Epoch))
	w.text("  Operation: " + readerID(r.OperationID) + "; attempt: " + readerID(r.AttemptID) + "; lineage: " + readerID(r.LineageID) + "\n")
	w.text("  Inbox: " + readerID(r.InboxID) + "; result: " + readerID(r.ResultID) + "; transmission: " + readerID(r.TransmissionID) + "\n")
	w.text("  Entry incarnation: " + readerID(p.EntryIncarnationID) + "; planned resource incarnation: " + readerID(r.ResourceID) + "; planned value slot: " + readerID(p.PlannedValueSlotID) + "\n")
	for _, field := range []struct {
		label string
		id    contract.ID
	}{{"Predecessor attempt", r.PredecessorAttemptID}, {"Generation", p.GenerationID}, {"Duty", p.DutyID}, {"Hazard", p.HazardID}} {
		if !field.id.IsZero() {
			w.text("  " + field.label + ": " + readerID(field.id) + "\n")
		}
	}
	w.text(fmt.Sprintf("  Evidence ceiling: %s; retry consumed: %t\n", generatedEvidence(p.EvidenceCeiling), r.RetryUsed == 1))
	if p.Reason != 0 {
		w.text("  Reason: " + generatedQueryReason(p) + "\n")
	}
	writeGeneratedQueryTargetHuman(w, p.Target, p.Progress)
	writeGeneratedQueryWarningsHuman(w, p.Warnings)
}

func writeGeneratedDutyHuman(w generatedFactWriter, p core.GeneratedDutyFact) {
	r := p.Record
	w.text(fmt.Sprintf("Duty %s: %s; %s; step %d; lifecycle %s; retirement %s\n", readerID(r.DutyID), generatedDutyKindHuman(r.Kind), generatedEffectState(r.Status), r.Step, generatedLifecycle(r.LifecycleMode), inspectionRetirementHuman(p.RetirementMode)))
	w.text("  Owner: " + readerID(r.OwnerID) + "; resource incarnation: " + readerID(r.ResourceID) + "\n")
	w.text("  Original operation: " + readerID(r.OriginalOperationID) + "; original attempt: " + readerID(r.OriginalAttemptID) + "\n")
	if !p.GenerationID.IsZero() {
		w.text("  Generation: " + readerID(p.GenerationID) + "\n")
	}
	w.text("  Evidence ceiling: " + generatedEvidence(p.EvidenceCeiling) + "\n")
	writeGeneratedQueryTargetHuman(w, p.Target, p.Progress)
	writeGeneratedQueryWarningsHuman(w, p.Warnings)
}

func writeGeneratedHazardHuman(w generatedFactWriter, p core.GeneratedHazardFact) {
	r := p.Record
	exposure := map[uint8]string{contract.GeneratedExposurePossibleLive: "possible-live", contract.GeneratedExposureLateEffect: "late-effect"}
	eligibility := "none"
	if r.Eligibility != 0 {
		eligibility = exposure[r.Eligibility]
	}
	w.text(fmt.Sprintf("Hazard %s: %s; fenced %t; cleanup eligibility %s; cleanup implementation qualified %t\n", readerID(r.HazardID), exposure[r.Exposure], r.Fenced == 1, eligibility, p.CleanupImplementationQualified))
	w.text("  Owner: " + readerID(r.OwnerID) + "; resource incarnation: " + readerID(r.ResourceID) + "\n")
	w.text("  Original operation: " + readerID(r.OriginalOperationID) + "; original attempt: " + readerID(r.OriginalAttemptID) + "\n")
	if !p.GenerationID.IsZero() {
		w.text("  Generation: " + readerID(p.GenerationID) + "\n")
	}
	w.text("  Evidence ceiling: " + generatedEvidence(p.EvidenceCeiling) + "; retirement " + inspectionRetirementHuman(p.RetirementMode) + "\n")
	writeGeneratedQueryTargetHuman(w, p.Target, nil)
	writeGeneratedQueryWarningsHuman(w, p.Warnings)
}

func writePendingResultCleanupHuman(w generatedFactWriter, rows []core.GeneratedPendingResultCleanup) {
	for _, p := range rows {
		state := map[uint8]string{contract.GeneratedReleasePending: "pending", contract.GeneratedReleaseUnknown: "unknown", contract.GeneratedReleaseUnobserved: "unobserved"}[p.State]
		action := map[uint8]string{contract.GeneratorActionCreate: "create", contract.GeneratorActionDelete: "delete"}[p.Action]
		w.text("Pending Store result cleanup: " + state + "\nInbox: " + readerID(p.InboxID) + "\nOriginal operation: " + readerID(p.OriginalOperationID) + "\nOriginal attempt: " + readerID(p.OriginalAttemptID) + "\n")
		switch p.State {
		case contract.GeneratedReleasePending:
			w.text("Store result deletion is pending.\n")
		case contract.GeneratedReleaseUnknown:
			w.text("Store result deletion outcome is unknown; retain the exact Inbox ID.\n")
		case contract.GeneratedReleaseUnobserved:
			w.text("No Store result deletion outcome was observed; absence is not established.\n")
		}
		w.text("Original result: " + readerID(p.OriginalResultID) + "; original action: " + action + "; effect: " + generatedEffectState(p.EffectState) + "\n")
		w.text("Handoff revision: " + readerID(p.HandoffRevisionID) + "\n")
		if completion := generatedCompletion(p.CompletionClass); completion != "" {
			w.text("Remote completion: " + completion + ". This does not confirm Store result cleanup.\n")
		} else {
			w.text("Remote completion class: unavailable in these facts.\n")
		}
	}
}

func writeGeneratedNextActionsHuman(w generatedFactWriter, actions []core.GeneratedNextAction) {
	if len(actions) == 0 {
		w.text("No supported generated-work action is available.\n")
		return
	}
	for _, p := range actions {
		w.text("Supported next action: " + p.Command)
		for _, field := range []struct {
			label string
			id    contract.ID
		}{{"operation", p.OperationID}, {"duty", p.DutyID}, {"attempt", p.AttemptID}} {
			if !field.id.IsZero() {
				w.text("; " + field.label + " " + readerID(field.id))
			}
		}
		w.text("\n")
	}
}

func generatedStageHuman(stage uint8) string {
	return map[uint8]string{contract.GeneratedStageRetainedResult: "retained-result", contract.GeneratedStageObservation: "observation", contract.GeneratedStageExactRetry: "exact-retry", contract.GeneratedStageResidue: "residue", contract.GeneratedStageTerminal: "terminal"}[stage]
}
func generatedDutyKindHuman(kind uint8) string {
	return map[uint8]string{contract.GeneratedDutyCreate: "create", contract.GeneratedDutyRetirement: "retirement", contract.GeneratedDutyUnselectedCleanup: "unselected-generated-cleanup"}[kind]
}

func writeGeneratedQueryRowsHuman(w generatedFactWriter, v core.InspectionGeneratedWork, noActive bool) {
	if noActive && len(v.CurrentGenerations) == 0 && len(v.Effects) == 0 && len(v.Duties) == 0 && len(v.Hazards) == 0 && len(v.PendingReleases) == 0 && len(v.NextActions) == 0 {
		w.text("No generated work or current generations were observed.\n")
	}
	for _, p := range v.CurrentGenerations {
		w.text(fmt.Sprintf("Current generation %q: %s; epoch %d; lifecycle %s; retirement %s\n", p.Name, readerID(p.GenerationID), p.Epoch, generatedLifecycle(p.LifecycleMode), inspectionRetirementHuman(p.RetirementMode)))
		w.text("  Entry incarnation: " + readerID(p.EntryIncarnationID) + "; resource incarnation: " + readerID(p.ResourceID) + "\n")
		w.text("  Original operation: " + readerID(p.OriginOperationID) + "; original attempt: " + readerID(p.OriginAttemptID) + "\n")
		w.text("  Configuration contract: " + readerID(p.ConfigContractID) + "\n")
		if p.LifecycleMode == contract.GeneratorLifecycleManaged {
			w.text("  Resource contract: " + readerID(p.ResourceContractID) + "\n")
		}
		if completion := generatedCompletion(p.CompletionClass); completion != "" {
			w.text("  Remote completion: " + completion + "\n")
		}
		if !p.RetiringDutyID.IsZero() {
			w.text("  Retiring duty: " + readerID(p.RetiringDutyID) + "\n")
		}
	}
	for _, p := range v.Effects {
		writeGeneratedEffectHuman(w, p)
	}
	for _, p := range v.Duties {
		writeGeneratedDutyHuman(w, p)
	}
	for _, p := range v.Hazards {
		writeGeneratedHazardHuman(w, p)
	}
	writeGeneratedHazardWarnings(w, v.Hazards, nil)
	writePendingResultCleanupHuman(w, v.PendingReleases)
	writeGeneratedNextActionsHuman(w, v.NextActions)
}

func generatedQueryReason(p core.GeneratedEffectFact) string {
	if p.Record.LifecycleMode == contract.GeneratorLifecycleNone {
		return map[uint8]string{contract.GeneratorFailureInvalid: "invalid", contract.GeneratorFailureUnavailable: "unavailable", contract.GeneratorFailureCancelled: "cancelled", contract.GeneratorFailureExpired: "expired", contract.GeneratorFailureProtocol: "protocol"}[p.Reason]
	}
	return map[uint8]string{contract.GeneratorReasonMissingValue: "missing-value", contract.GeneratorReasonInvalidValue: "invalid-value", contract.GeneratorReasonControls: "controls", contract.GeneratorReasonInactive: "inactive", contract.GeneratorReasonMalformed: "malformed", contract.GeneratorReasonOverflow: "overflow", contract.GeneratorReasonRejected: "rejected", contract.GeneratorReasonTransport: "transport", contract.GeneratorReasonDeadline: "deadline", contract.GeneratorReasonIdentityConflict: "identity-conflict"}[p.Reason]
}
func writeGeneratedQueryTargetHuman(w generatedFactWriter, p *contract.GeneratorTarget, progress []contract.GeneratorProgress) {
	if p == nil {
		w.text("  Target: unavailable\n")
	} else {
		w.text(fmt.Sprintf("  Target %q: entry incarnation %s; resource incarnation %s; epoch %d; lifecycle %s\n", p.Name, readerID(p.IncarnationID), readerID(p.ResourceID), p.Epoch, generatedLifecycle(p.LifecycleMode)))
		w.text("  Configuration contract: " + readerID(p.ConfigContractID) + "; resource contract: " + readerID(p.ResourceContractID) + "; result contract: " + readerID(p.ResultContractID) + "\n")
		w.text("  Target original operation: " + readerID(p.OriginalOperationID) + "; original attempt: " + readerID(p.OriginalAttemptID) + "\n")
		if completion := generatedCompletion(p.CompletionClass); completion != "" {
			w.text("  Remote completion: " + completion + "\n")
		}
	}
	for _, p := range progress {
		w.text(fmt.Sprintf("  Progress for attempt %s; result %s: required steps %d; completed steps %d; completion %s\n", readerID(p.AttemptID), readerID(p.ResultID), p.RequiredSteps, p.CompletedSteps, generatedCompletion(p.CompletionClass)))
	}
}
func writeGeneratedQueryWarningsHuman(w generatedFactWriter, v core.GeneratedResultWarnings) {
	if v.PossibleLiveResidue {
		w.text("  Warning: A generated effect can still be live.\n")
	}
	if v.LateEffect {
		w.text("  Warning: An earlier generated request can still act.\n")
	}
	if v.InvalidationNotConfirmed {
		w.text("  Warning: Deletion was acknowledged; invalidation is not confirmed.\n")
	}
}
