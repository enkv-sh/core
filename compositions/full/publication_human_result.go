package compositionfull

import (
	"fmt"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func renderPublicationHuman(r core.PublicPublicationResult, state, summary string, sourceFailure *ConfigurationSourceFailure) ([]byte, error) {
	return renderReaderResultBound(publicationCompactResultLimit, func(w *readerResultWriter) {
		w.literal("Publication: " + state + "\n")
		w.literal("Output result: " + summary + "\n")
		if !r.OperationID.IsZero() {
			w.literal("Operation ID: " + readerID(r.OperationID) + "\n")
		}
		if !r.DomainID.IsZero() {
			w.literal("Domain: " + readerID(r.DomainID) + "\n")
		}
		w.literal(configurationSourceFailureHuman(sourceFailure))
		if result, ok := administrativeCoreResult(r.Result); ok && result.Reason != "none" {
			w.literal("Reason: " + result.Reason + "\n")
		}
		if r.ExecutableCleanupFailed {
			w.literal("Warning: executable cleanup failed.\n")
		}
		if r.CleanupFailed {
			w.literal("Warning: source cleanup failed.\n")
		}
		if r.Output == nil {
			return
		}
		v := r.Output
		w.literal("Snapshot: " + readerID(v.SnapshotID) + "\nSelection: " + readerID(v.SelectionDigest) + "\n")
		if v.DomainWideWarning != 0 {
			w.literal("Warning: this Domain has an unresolved publication warning.\n")
		}
		for i, target := range v.Entries {
			description := r.Descriptions[i]
			if description.Origin == core.PublicationTargetRetainedDeletion {
				w.literal("Retained deletion target\n")
			} else {
				w.literal(fmt.Sprintf("Entry: %q\n", *description.EntryName))
			}
			if description.DestinationID != nil {
				w.literal(fmt.Sprintf("Destination: %q\n", *description.DestinationID))
			}
			w.literal(fmt.Sprintf("Service: %q\nTarget: %q\n", description.ServiceContractID, description.CanonicalTarget))
			w.literal("Coordinate: " + readerID(target.CoordinateID) + "\n")
			for _, original := range target.Actions {
				p := publicationAction(original)
				action := "no action"
				if p.Action != nil {
					action = *p.Action
				}
				w.literal(action + ": " + p.Disposition + "\n")
				if p.Attempt != nil {
					w.literal("Attempt: " + *p.Attempt + "\n")
				}
				if p.Projection != nil {
					w.literal("Projection: " + *p.Projection + "\n")
				}
				if p.Reason != 0 {
					reason, _ := administrativeCoreResult(core.Result{Outcome: core.AdmissionRefused, Reason: core.Reason(p.Reason)})
					w.literal("Action reason: " + reason.Reason + "\n")
				}
				for _, id := range p.Blockers {
					w.literal("Blocker: " + id + "\n")
				}
				if evidence := p.Evidence; evidence != nil {
					w.literal(fmt.Sprintf("Evidence: %s; entry %s; normalized status %d\n", evidence.Class, evidence.Entry, evidence.Status))
					w.literal("Response contract: " + evidence.Response + "\n")
					for _, field := range []struct{ label, value string }{{"Safe request", evidence.Request}, {"Safe resource", evidence.Resource}, {"Consumer location", evidence.Locator}} {
						if field.value != "" {
							w.literal(fmt.Sprintf("%s: %q\n", field.label, field.value))
						}
					}
				}
				if p.Remote {
					w.literal("Warning: a remote value may remain.\n")
				}
				if p.Late {
					w.literal("Warning: a late write can still change the destination.\n")
				}
				if original.Disposition == contract.PublicationOutcomeUnknown {
					w.literal("Warning: the publication outcome is unknown.\n")
				}
				if original.Disposition == contract.PublicationOutcomeAcknowledged || original.Disposition == contract.PublicationOutcomeUnknown || p.Late {
					w.literal("Acknowledgement does not prove remote currentness, absence, invalidation or ordering.\n")
				}
			}
		}
	})
}
