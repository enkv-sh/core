package core

import (
	"context"
	"unsafe"

	"enkv.sh/core/contract"
)

// Both public variants own their facts before selection. No StateSession,
// selected graph, ciphertext, or Store reader is retained by this capture.
type generatedCleanupResultCapture struct {
	*generatedInvocationResultCapture
	observedPayload, selectedPayload   *GeneratedCleanupPayload
	observedWarnings, selectedWarnings uint8
	payload                            *GeneratedCleanupPayload
	warnings                           uint8
	backingBytes                       uint64
}

func newGeneratedCleanupResultCapture(ctx context.Context, before *StateSession, work *generatedSelection, common *generatedInvocationResultCapture, basis GeneratedCleanupBasis, predecessor contract.ID, proposal *generatedReservation, checkpoint *generatedSelectionCheckpoint) (*generatedCleanupResultCapture, error) {
	capture := &generatedCleanupResultCapture{generatedInvocationResultCapture: common, observedWarnings: before.root.WarningBits}
	var err error
	if checkpoint != nil && checkpoint.valid {
		prior := checkpoint.cleanup
		if !checkpoint.matchesBefore(before) || prior == nil || prior.Schema != 1 || prior.PredecessorRevisionID != predecessor ||
			prior.RemainingWorkBasis.HeadRevisionID != before.head.Core.Revision || prior.RemainingWorkBasis.Snapshot != before.head.Core.Root || !sameGeneratedCleanupBasis(prior.Basis, basis) {
			return nil, contract.ErrRecord
		}
		capture.observedPayload = prior
	} else {
		capture.observedPayload, err = captureGeneratedCleanupPayload(before, work, basis, predecessor)
		if err != nil {
			return nil, err
		}
	}
	if proposal != nil {
		selected, err := proposal.state.selectedGeneratedWork(ctx)
		if err != nil {
			return nil, err
		}
		capture.selectedPayload, err = captureGeneratedCleanupPayload(proposal.state, selected, basis, predecessor)
		if err != nil {
			return nil, err
		}
		capture.selectedWarnings = proposal.state.root.WarningBits
	}
	backing, err := generatedCleanupPayloadBackingBytes(capture.observedPayload, capture.selectedPayload)
	if err != nil {
		return nil, err
	}
	capture.backingBytes = common.backingBytes + backing + uint64(unsafe.Sizeof(*capture))
	return capture, nil
}

func (capture *generatedCleanupResultCapture) observe(ctx context.Context, actual *StateSession, result Result) (*GeneratedInvocationResult, error) {
	facts, err := capture.generatedInvocationResultCapture.observe(ctx, actual, result)
	if err != nil {
		return nil, err
	}
	capture.payload, capture.warnings = capture.observedPayload, capture.observedWarnings
	if facts == &capture.selected {
		capture.payload, capture.warnings = capture.selectedPayload, capture.selectedWarnings
		capture.observedPayload = nil
	} else {
		capture.selectedPayload = nil
	}
	return facts, nil
}
func (capture *generatedCleanupResultCapture) attach(out *PublicApplyResult) {
	out.Cleanup = capture.payload
	out.WarningBits = capture.warnings
	out.Payload = nil
	out.Receipt = nil
}

func (capture *generatedCleanupResultCapture) prevalidate(out PublicApplyResult, i ApplyInstallation) error {
	for _, variant := range []struct {
		facts    *GeneratedInvocationResult
		payload  *GeneratedCleanupPayload
		warnings uint8
	}{{&capture.observed, capture.observedPayload, capture.observedWarnings}, {&capture.selected, capture.selectedPayload, capture.selectedWarnings}} {
		if variant.payload == nil {
			continue
		}
		out.Generated, out.Cleanup, out.WarningBits = variant.facts, variant.payload, variant.warnings
		out.Payload, out.Receipt = nil, nil
		// These local closed observations validate shape before any selection.
		// They do not create a checkpoint or claim that a CAS occurred.
		out.Result = Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, ObservedRevision: variant.payload.RemainingWorkBasis.HeadRevisionID, ObservedSnapshotID: variant.payload.RemainingWorkBasis.Snapshot.Object}
		switch variant.facts.StateResult {
		case "commit-outcome-unknown":
			out.Result = Result{Outcome: UnresolvedCommit, RequestedRevision: capture.candidate.head.Core.Revision, CommitMayHaveOccurred: true}
		case "contention":
			out.Result.Outcome = Contention
		case "refused":
			out.Result.Outcome = AdmissionRefused
		case "positive-defect":
			out.Result.Outcome = IntegrityFailure
		case "unavailable":
			out.Result.Outcome = EvidenceUnavailable
		case "no-op":
			out.Result.Outcome = Unchanged
		}
		qualifyGeneratedInvocationResult(i, &out)
		if _, err := GeneratedCleanupSiblingResults(out); err != nil {
			return err
		}
	}
	return nil
}

func generatedCleanupBasisForEffect(work *generatedSelection, kind GeneratedCleanupBasisKind, source generatedRecordKey, effect GeneratedEffectFact, result []byte) (GeneratedCleanupBasis, error) {
	graph, err := work.retainedGraph(effect.Record.OperationID)
	if err != nil {
		return GeneratedCleanupBasis{}, err
	}
	basis := GeneratedCleanupBasis{Kind: kind, PlanGraphID: graph.UsePlan.PlanGraphID, SourceKind: source.kind, SourceID: source.id,
		OriginalOwnerID: effect.Record.OwnerID, OriginalOperationID: effect.Record.OperationID, OriginalAttemptID: effect.Record.AttemptID, Target: effect.Target}
	if len(result) != 0 {
		basis.OriginalResult = &contract.GeneratorResultReference{Schema: 1, ResultID: effect.Record.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}
	}
	return basis, nil
}

func finishInstalledGeneratedCleanup(i ApplyInstallation, out *PublicApplyResult) {
	qualifyGeneratedInvocationResult(i, out)
	if err := RefreshGeneratedCleanupResult(out); err != nil {
		// The delivery defect does not change what the Store selected.
		cleanupDeliveryDefect(out)
	}
}

func sameGeneratedCleanupBasis(a, b GeneratedCleanupBasis) bool {
	if (a.Target == nil) != (b.Target == nil) || (a.OriginalResult == nil) != (b.OriginalResult == nil) {
		return false
	}
	if a.Target != nil && *a.Target != *b.Target {
		return false
	}
	if a.OriginalResult != nil && *a.OriginalResult != *b.OriginalResult {
		return false
	}
	a.Target, b.Target = nil, nil
	a.OriginalResult, b.OriginalResult = nil, nil
	return a == b
}

func recordInstalledGeneratedCleanupSelection(ctx context.Context, out *PublicApplyResult, actual *StateSession, result Result, capture *generatedCleanupResultCapture, checkpoint *generatedSelectionCheckpoint) {
	// The selector sets the requested revision only after entering its one-use
	// candidate boundary. An earlier local refusal is a preparation stop.
	if result.RequestedRevision.IsZero() && checkpoint.valid {
		*out = checkpoint.preparationFailure(ctx, *out, result)
		return
	}
	out.Result = result
	facts, err := capture.observe(ctx, actual, result)
	if err != nil {
		cleanupDeliveryDefect(out)
	} else {
		out.Generated = facts
		capture.attach(out)
	}
	if !result.RequestedRevision.IsZero() {
		checkpoint.recordSelected(*out)
	}
}
