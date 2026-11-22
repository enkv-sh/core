package compositionfull

import (
	"fmt"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func renderGeneratedMutationHuman(r core.PublicApplyResult, operation uint16, location *resultStoreLocation) ([]byte, error) {
	g := r.Generated
	return renderGeneratedResult(func(w *generatedResultWriter) {
		label := map[uint16]string{contract.OperationApplyDeclaration: "Apply", contract.OperationRotateValueEntryValue: "Value rotation", contract.OperationRetireGeneratedGeneration: "Generated retirement", contract.OperationAcceptGeneratedRetirementResidue: "Generated retirement risk", contract.OperationCleanOwnedFailureResidue: "Generated cleanup"}[operation]
		w.text(label + ": " + g.StateResult + "\nOperation ID: " + readerID(r.OperationID) + "\nDomain: " + readerID(r.DomainID) + "\n")
		writeResultStoreLocationHuman(w, location)
		if g.ReceiptObservation {
			w.text("Historical receipt observation; current work details can be unavailable.\n")
		}
		if !r.Result.RequestedRevision.IsZero() {
			w.text("Requested revision: " + readerID(r.Result.RequestedRevision) + "\n")
		}
		if !r.Result.ObservedRevision.IsZero() {
			w.text("Observed revision: " + readerID(r.Result.ObservedRevision) + "\n")
		}
		if p := r.Payload; p != nil && !p.ObservedRevisionID.IsZero() && p.ObservedRevisionID != r.Result.ObservedRevision {
			w.text("Original receipt observed revision: " + readerID(p.ObservedRevisionID) + "\n")
		}
		if r.Result.CommitMayHaveOccurred {
			if r.Cleanup != nil && r.Cleanup.Basis.Kind == core.GeneratedCleanupInboxRelease {
				w.text("Warning: the HEAD change may have occurred. Use inspect to check this temporary Inbox before another cleanup.\n")
			} else {
				w.text("Warning: the HEAD change may have occurred. Observe the operation before another mutation.\n")
			}
		}
		if p := r.Preparation; p != nil {
			if p.PossibleUnacknowledgedCreate {
				w.text("Warning: a local preparation create may have occurred without acknowledgement.\n")
			}
		}
		if g.SummaryCountsAvailable {
			names := [...]string{"effects", "outputs", "duties", "hazards", "changed access", "succeeded", "failed", "neutral", "pending", "unknown", "preserved residue", "no-effect predecessors"}
			for i, count := range g.SummaryCounts {
				w.text(fmt.Sprintf("%s: %d\n", names[i], count))
			}
			w.text(fmt.Sprintf("Deletion acknowledgements: %d; confirmed invalidations: %d; unknown results: %d\n", g.AcknowledgedCount, g.ConfirmedCount, g.UnknownCount))
		} else {
			w.text("Summary counts are unavailable.\n")
		}
		if g.EffectsAvailable {
			for _, row := range g.Effects {
				writeGeneratedEffectHuman(w, row)
			}
		} else {
			w.text("Effect details are unavailable.\n")
		}
		if g.RelatedWorkAvailable {
			for _, id := range g.RelatedDutyIDs {
				w.text("Related duty: " + readerID(id) + "\n")
			}
			for _, id := range g.RelatedHazardIDs {
				w.text("Related hazard: " + readerID(id) + "\n")
			}
			for _, row := range g.Duties {
				writeGeneratedDutyHuman(w, row)
			}
			for _, row := range g.Hazards {
				writeGeneratedHazardHuman(w, row)
			}
		} else {
			w.text("Related work details are unavailable.\n")
		}
		if p := r.Payload; p != nil && !g.ReceiptObservation {
			for _, id := range p.LiveDutyIDs {
				w.text("Current duty: " + readerID(id) + "\n")
			}
			for _, id := range p.LiveHazardIDs {
				w.text("Current hazard: " + readerID(id) + "\n")
			}
		}
		if p := r.Cleanup; p != nil {
			writeGeneratedCleanupHuman(w, p)
			if p.Basis.Kind == core.GeneratedCleanupInboxRelease && g.StateResult == "effect-unknown" {
				w.text("Temporary inbox deletion is unresolved. Run generated cleanup with the same --inbox ID to check the Store again.\n")
			}
		}
		for _, diagnostic := range r.Diagnostics {
			writeDiagnosticHuman(w, diagnostic)
			if r.Cleanup != nil && r.Cleanup.Basis.Kind == core.GeneratedCleanupInboxRelease && r.Result.Outcome != core.ObservedCurrent &&
				diagnostic.Subject == (contract.DiagnosticSubject{Kind: contract.SubjectStore}) && len(diagnostic.Path) == 1 && diagnostic.Path[0] == contract.FieldPresence &&
				diagnostic.Outcome == contract.DiagnosticUnable && diagnostic.Reason == contract.ReasonEvidenceUnavailable {
				w.text("The Store did not confirm deletion. Use inspect to check this temporary Inbox before another cleanup.\n")
			}
		}
		writeGeneratedHazardWarnings(w, g.Hazards, generatedMutationHazardWarnings(g))
		if g.Warnings.LateEffect {
			w.text("Warning: an earlier effect can act after this exit.\n")
		}
		if g.Warnings.InvalidationNotConfirmed {
			w.text("Warning: invalidation is not confirmed.\n")
		}
		bits := r.WarningBits
		if r.Payload != nil && len(r.Payload.LiveHazardIDs) != 0 {
			bits |= core.WarningOrphanGeneratedEffect
		}
		for _, warning := range applyWarningTexts(bits) {
			w.text("Warning: " + warning + "\n")
		}
		if g.Warnings.PossibleLiveResidue && len(g.Hazards) == 0 {
			w.text("Warning: an old generated effect can still be live. Details are unavailable in this result.\n")
		}
		if len(r.Receipt) != 0 {
			receipt, err := contract.InspectCompactMutationReceipt(r.Receipt)
			if err != nil {
				w.err = errApplyResult
				return
			}
			domain, effects, err := contract.DecodeReceiptWarningBits(operation, receipt.WarningBits)
			if err != nil {
				w.err = errApplyResult
				return
			}
			w.text("An exact stored mutation receipt is available.\n")
			for _, warning := range applyWarningTexts(domain) {
				w.text("Original receipt warning: " + warning + "\n")
			}
			if effects&contract.ReceiptWarningPossibleLive != 0 && domain&core.WarningOrphanGeneratedEffect == 0 {
				w.text("Original receipt warning: A generated effect can still be live.\n")
			}
			if effects&contract.ReceiptWarningInvalidationNotConfirmed != 0 {
				w.text("Original receipt warning: Deletion was acknowledged; invalidation is not confirmed.\n")
			}
		}
	})
}

func writeGeneratedCleanupHuman(w generatedFactWriter, p *core.GeneratedCleanupPayload) {
	b := p.Basis
	w.text("Cleanup basis: " + map[core.GeneratedCleanupBasisKind]string{core.GeneratedCleanupNoWork: "no work", core.GeneratedCleanupReflection: "retained result reflection", core.GeneratedCleanupOwnedTarget: "owned target", core.GeneratedCleanupInboxRelease: "temporary inbox release"}[b.Kind] + "\n")
	if b.Kind == core.GeneratedCleanupInboxRelease {
		w.text("Temporary Inbox: " + readerID(b.SourceID) + "\n")
	}
	for _, row := range []struct {
		label string
		id    contract.ID
	}{{"Cleanup plan", b.PlanGraphID}, {"Cleanup source", b.SourceID}, {"Original owner", b.OriginalOwnerID}, {"Original operation", b.OriginalOperationID}, {"Original attempt", b.OriginalAttemptID}} {
		if !row.id.IsZero() {
			w.text(row.label + ": " + readerID(row.id) + "\n")
		}
	}
	if b.OriginalResult != nil {
		w.text("Original result: " + readerID(b.OriginalResult.ResultID) + "\n")
	}
	if b.Target != nil {
		writeGeneratedQueryTargetHuman(w, b.Target, nil)
	}
	w.text("Remaining work observed at revision: " + readerID(p.RemainingWorkBasis.HeadRevisionID) + "\n")
	for _, row := range []struct {
		label string
		ids   []contract.ID
	}{{"Remaining duty", p.RemainingDutyIDs}, {"Remaining hazard", p.RemainingHazardIDs}, {"Remaining Inbox", p.RemainingInboxIDs}} {
		for _, id := range row.ids {
			w.text(row.label + ": " + readerID(id) + "\n")
		}
	}
	w.text("Remaining identities describe the reported observation; they do not establish currentness after a competing or unknown commit.\n")
	w.text("Supported next actions are unavailable in this invocation result. Use generated list on the same trusted source to read current supported actions.\n")
}
