package compositionfull

import (
	"fmt"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func validManifestRender(r core.PublicManifestResult) bool {
	count := readerResultWriter{maximum: contract.MaxManifestResultJSONBytes}
	writeManifestResult(&count, r, false)
	return !count.failed
}

func writeManifestHuman(w *readerResultWriter, r core.PublicManifestResult) {
	w.literal("Manifest: " + string(r.StateResult) + "\n")
	if r.FailureReason != "" {
		w.literal("Reason: " + string(r.FailureReason) + "\n")
	}
	if !r.Context.OperationID.IsZero() {
		w.literal("Operation ID: " + readerID(r.Context.OperationID) + "\n")
	}
	if !r.Context.RequestID.IsZero() {
		w.literal("Request ID: " + readerID(r.Context.RequestID) + "\n")
	}
	if !r.TargetRecipientID.IsZero() {
		w.literal("Target recipient: " + readerID(r.TargetRecipientID) + "\n")
	}
	if o := r.Observation; o != nil {
		w.literal("Domain: " + readerID(contract.ID(o.DomainID)) + "\nObserved revision: " + readerID(contract.ID(o.HEADRevisionID)) + "\nSnapshot: " + readerID(contract.ID(o.SnapshotID)) + "\n")
	}
	if scope := r.RequestScope; scope != nil {
		w.literal(fmt.Sprintf("Format: %q\nSelection: %s; %s\n", scope.FormatContractID, scope.Selection.TargetMode, scope.Selection.EntryMode))
		if scope.ServiceFilter != nil {
			w.literal(fmt.Sprintf("Service filter: %q\n", *scope.ServiceFilter))
		}
	}
	if p := r.Payload; p != nil {
		w.literal(fmt.Sprintf("Artifact: %d bytes; digest %s\nEvidence limit: %s\n", p.ArtifactLength, readerID(p.ArtifactDigest), p.EvidenceLimit))
		for _, row := range p.IncludedEntries {
			w.literal(fmt.Sprintf("Included entry %q; incarnation %s\n", row.Name, readerID(contract.ID(row.EntryIncarnationID))))
		}
		for _, row := range p.ExcludedEntries {
			w.literal(fmt.Sprintf("Excluded entry %q; incarnation %s; %s\n", row.Name, readerID(contract.ID(row.EntryIncarnationID)), row.Reason))
		}
	}
}

func renderManifestFileHuman(r ManifestFileResult) ([]byte, error) {
	if !validManifestFileResult(r) || r.ResultDelivery != ManifestResultNotObserved || !validManifestRender(r.Issuance) {
		return nil, ErrManifestFileResult
	}
	return renderReaderResultBound(manifestFileCompactResultLimit, func(w *readerResultWriter) {
		if r.Delivery.TargetPath != "" {
			w.literal(fmt.Sprintf("Manifest file: %q\n", r.Delivery.TargetPath))
		}
		writeManifestHuman(w, r.Issuance)
		w.literal(configurationSourceFailureHuman(r.SourceFailure))
		d := r.Delivery
		w.literal("Local replacement: " + string(d.Replacement) + "\nCandidate verification: " + string(d.CandidateVerification) + "\nInstalled verification: " + string(d.InstalledVerification) + "\nNative completion: " + string(d.NativeCompletion) + "\nCandidate cleanup: " + string(d.CandidateCleanup) + "\n")
		if d.ResiduePath != "" {
			w.literal(fmt.Sprintf("Residue file: %q\n", d.ResiduePath))
		}
		if f := d.Failure; f != nil {
			w.literal("Local delivery failure: " + string(f.Stage) + "; " + string(f.Reason) + "\n")
		}
		w.literal("Source cleanup: " + string(r.SourceCleanup) + "\nResult-stream delivery is not observed by this result.\n")
	})
}
