package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func (g *InstalledGC) executeGC(ctx context.Context, out PublicGCResult, plan contract.GCPlan, head []byte, retained *contract.GCProgress, fresh bool, check func(context.Context) error) PublicGCResult {
	guard, trust, result := g.mutation(ctx, check)
	if guard == nil {
		out.Result = result
		out.StateResult = gcStateResult(result)
		return out
	}
	for _, target := range plan.Targets {
		key, err := contract.StoreObjectKey(guard.store.Descriptor().Prefix, plan.DomainID, target.Object)
		if err != nil {
			out.Result = refused(InvalidRelation)
			return out
		}
		guard.targets[key] = true
	}
	r := g.installation.Reader
	admitted, result := admitBorrowedPublicNormal(ctx, r.reader.expectedDomain, r.reader.expectedStore, r.reader.publicBasis, guard.store, g.installation.CompositionID, nil)
	if admitted.admission == nil {
		out.Result = result
		out.StateResult = gcStateResult(result)
		return out
	}
	key, ok := publicKey(admitted.admission.publicKey)
	if !ok {
		out.Result = refused(InvalidProof)
		return out
	}
	base := &StateSession{admission: *admitted.admission, store: guard.store, key: key, cache: make(map[contract.Ref][]byte)}
	// Inspect HEAD before opening its closure. A changed selection cannot make
	// mutation admission read an original target for a second preflight.
	read := base.storeRead(ctx, base.admission.store.HeadKey, contract.MaxHeadLength)
	if read.Status != contract.ReadOK {
		_, out.Result = base.authenticateHeadResponse(ctx, read)
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	read = ownCandidateRead(read, contract.MaxHeadLength, nil, 0)
	if read.Status != contract.ReadOK || read.Token.Family != base.admission.store.Family {
		out.Result = failure(IntegrityFailure, InvalidFormat)
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	if !bytes.Equal(read.Body, head) {
		out.Result = failure(Contention, DifferentSelection)
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	if fresh && read.Token != plan.PredecessorToken {
		out.Result = failure(Contention, DifferentSelection)
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	anchor, result := base.authenticateHeadResponse(ctx, read)
	if result.Outcome != 0 {
		out.Result = result
		out.StateResult = gcStateResult(result)
		return out
	}
	state, result := base.readCurrentImageFromHead(ctx, anchor, true)
	if state == nil {
		out.Result = result
		out.StateResult = gcStateResult(result)
		return out
	}
	if guard.check(ctx) != contract.ReasonNone {
		out.Result = refused(AdmissionInvalid)
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	admission, err := gcRandomAdmission()
	if err != nil {
		out.Result = refused(AdmissionInvalid)
		return out
	}
	var progress contract.GCProgress
	if fresh {
		progress, err = gcInitialProgress(plan)
	} else {
		var selected contract.GCPlan
		selected, progress, err = state.selectedGCPlan(plan.OperationID)
		if err == nil {
			digest, e := contract.GCPlanDigest(selected)
			if e != nil || digest != out.Payload.PlanDigest || retained == nil || !contract.GCProgressEqual(progress, *retained) {
				err = contract.ErrRecord
			}
		}
	}
	if err != nil {
		out.Result = refused(InvalidRelation)
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	phase := contract.GCSelect
	if !fresh {
		phase = contract.GCReacquire
	}
	if fresh || state.root.ActiveGC.IsZero() {
		step := gcAttemptPhase(ctx, state, plan, admission, phase, &progress, trust, &out)
		if !step.confirmed {
			return gcFailedPhase(out, step)
		}
		state = step.state
	} else if state.root.ActiveGC != plan.OperationID {
		out.Result = refused(InvalidRelation)
		out.StateResult = gcStateResult(out.Result)
		return out
	}
	gcSelectedProgress(&out, progress, true, state)
	physical, err := newGCPhysicalRead(ctx, state.admission.expires, guard.readTarget)
	if err != nil {
		out.Result = refused(AdmissionInvalid)
		return out
	}
	preflight := make([]contract.GCTargetDisposition, len(plan.Targets))
	for i, target := range plan.Targets {
		if progress.Targets[i].Disposition == contract.GCTargetAbsent {
			preflight[i] = contract.GCTargetAbsent
			continue
		}
		if fresh {
			preflight[i] = contract.GCTargetPending
		} else {
			preflight[i], out.Payload.Targets[i].ObservationReason = gcObservation(ctx, physical, state.admission.store, plan.DomainID, target)
		}
		out.Payload.Targets[i].Observed = preflight[i]
		if preflight[i] == contract.GCTargetAbsent {
			out.Payload.Targets[i].ObservedEvidence = gcAbsenceEvidence(state.admission.store, plan, target, progress.Ordinal)
		}
	}
	permissions := make([]*gcDeletePermission, len(plan.Targets))
	reserved := progress.Own()
	anyPermission := false
	for i, row := range progress.Targets {
		if preflight[i] != contract.GCTargetPending || row.Disposition == contract.GCTargetAbsent || row.Consumed >= contract.GCTransmissionLimit || row.Consumed != 0 && row.Disposition != contract.GCTargetRetryableNotSent {
			continue
		}
		anyPermission = true
		reserved.Targets[i] = contract.GCTargetProgress{Consumed: row.Consumed + 1, Disposition: contract.GCTargetPending}
	}
	if anyPermission {
		if reserved.Ordinal == ^uint32(0) {
			out.Result = refused(CapacityExceeded)
			out.StateResult = gcStateResult(out.Result)
			return gcCloseKnown(ctx, state, plan, admission, progress, trust, guard, out)
		}
		reserved.Ordinal++
		step := gcAttemptPhase(ctx, state, plan, admission, contract.GCReserve, &reserved, trust, &out)
		if !step.confirmed {
			return gcCloseFailedPhase(ctx, state, plan, admission, progress, trust, guard, out, step)
		}
		state, progress = step.state, reserved
		gcSelectedProgress(&out, progress, true, state)
	}
	// Determine this reserve's exact changed rows from the predecessor, rather
	// than treating an already-pending selected allowance as a local permission.
	if anyPermission {
		for i, target := range plan.Targets {
			if preflight[i] != contract.GCTargetPending {
				continue
			}
			var old contract.GCTargetProgress
			if fresh {
				old = contract.GCTargetProgress{Disposition: contract.GCTargetPending}
			} else {
				old = retained.Targets[i]
			}
			if old.Disposition == contract.GCTargetAbsent || old.Consumed >= contract.GCTransmissionLimit || old.Consumed != 0 && old.Disposition != contract.GCTargetRetryableNotSent {
				continue
			}
			key, err := contract.StoreObjectKey(state.admission.store.Prefix, plan.DomainID, target.Object)
			if err != nil {
				out.Result = refused(InvalidRelation)
				return out
			}
			permissions[i] = &gcDeletePermission{key: key, target: target, consumed: progress.Targets[i].Consumed}
			out.Payload.Targets[i].PermissionOwned = true
		}
	}
	updated := progress.Own()
	for i, target := range plan.Targets {
		if progress.Targets[i].Disposition == contract.GCTargetAbsent {
			continue
		}
		if ctx.Err() != nil || guard.check(ctx) != contract.ReasonNone {
			out.Result = refused(AdmissionInvalid)
			out.StateResult = gcStateResult(out.Result)
			return out
		}
		permission := permissions[i]
		if permission != nil {
			call := telemetry.StartWithDetails(ctx, telemetry.ProviderCore, telemetry.OpCoreStoreDeleteIfToken, (telemetry.DiagnosticDetails{}).WithPathKind("state_object"))
			call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
			written := guard.delete(telemetry.CallContext(ctx, call), permission)
			finishWrite(call, 0, written)
			out.Payload.Targets[i].DeleteAttempted = true
			out.Payload.Targets[i].DeleteResult = written
		}
		observed, reason := preflight[i], out.Payload.Targets[i].ObservationReason
		if observed != contract.GCTargetAbsent {
			observed, reason = gcObservation(ctx, physical, state.admission.store, plan.DomainID, target)
		}
		out.Payload.Targets[i].Observed, out.Payload.Targets[i].ObservationReason = observed, reason
		if observed == contract.GCTargetAbsent {
			out.Payload.Targets[i].ObservedEvidence = gcAbsenceEvidence(state.admission.store, plan, target, progress.Ordinal)
		} else {
			out.Payload.Targets[i].ObservedEvidence = contract.ID{}
		}
		row := contract.GCTargetProgress{Consumed: progress.Targets[i].Consumed, Disposition: observed}
		if permission == nil && observed != contract.GCTargetAbsent && (progress.Targets[i].Disposition == contract.GCTargetRetryableNotSent || progress.Targets[i].Disposition == contract.GCTargetTerminalFailure) {
			updated.Targets[i] = progress.Targets[i]
			continue
		}
		switch observed {
		case contract.GCTargetAbsent:
			row.EvidenceDigest = out.Payload.Targets[i].ObservedEvidence
		case contract.GCTargetPending:
			if witness := gcNotSentEvidence(state.admission.store, plan, permission, observed, progress.Ordinal); !witness.IsZero() {
				row.Disposition = contract.GCTargetRetryableNotSent
				row.EvidenceDigest = witness
			} else if permission == nil && progress.Targets[i].Disposition == contract.GCTargetRetryableNotSent {
				row = progress.Targets[i]
			} else if permission != nil && permission.result.Status == contract.WriteRefused {
				row.Disposition = contract.GCTargetTerminalFailure
			} else if row.Consumed != 0 {
				row.Disposition = contract.GCTargetUnknown
			}
		}
		updated.Targets[i] = row
	}
	updated.RemainingCount = 0
	for _, row := range updated.Targets {
		if row.Disposition != contract.GCTargetAbsent {
			updated.RemainingCount++
		}
	}
	if !slices.Equal(updated.Targets, progress.Targets) {
		if progress.Ordinal == ^uint32(0) {
			out.Result = refused(CapacityExceeded)
			out.StateResult = gcStateResult(out.Result)
			return gcCloseKnown(ctx, state, plan, admission, progress, trust, guard, out)
		}
		updated.Ordinal++
		step := gcAttemptPhase(ctx, state, plan, admission, contract.GCRecordProgress, &updated, trust, &out)
		if !step.confirmed {
			return gcCloseFailedPhase(ctx, state, plan, admission, progress, trust, guard, out, step)
		}
		state, progress = step.state, updated
		gcSelectedProgress(&out, progress, true, state)
	}
	return gcCloseKnown(ctx, state, plan, admission, progress, trust, guard, out)
}

func gcAttemptPhase(ctx context.Context, state *StateSession, plan contract.GCPlan, admission contract.ID, phase contract.GCPhase, progress *contract.GCProgress, trust contract.Trust, out *PublicGCResult) gcPhaseResult {
	c, result := state.prepareGCPhase(ctx, plan, admission, phase, progress)
	step := gcPhaseResult{state: state, result: result, notSelected: true}
	if c != nil {
		c, result = state.persistCandidate(ctx, c, trust)
		step.result = result
		if c != nil {
			step = state.selectGCCandidate(ctx, c)
		}
	}
	if !step.confirmed || step.write.Status != contract.WriteAcknowledged {
		out.Payload.Failures = append(out.Payload.Failures, GCPhaseFailure{Phase: phase, Result: step.result, Write: step.write})
	}
	return step
}
func gcFailedPhase(out PublicGCResult, step gcPhaseResult) PublicGCResult {
	out.Result = step.result
	out.StateResult = gcStateResult(out.Result)
	if out.Payload != nil {
		out.Payload.SelectionUncertain = out.Result.CommitMayHaveOccurred || out.Result.Outcome == Contention
	}
	return out
}
func gcCloseFailedPhase(ctx context.Context, state *StateSession, plan contract.GCPlan, admission contract.ID, progress contract.GCProgress, trust contract.Trust, guard *installedGCGuard, out PublicGCResult, step gcPhaseResult) PublicGCResult {
	out = gcFailedPhase(out, step)
	if !step.notSelected || step.result.Outcome == IntegrityFailure || step.result.Outcome == Contention || step.result.Outcome == UnresolvedCommit || step.result.Reason == InvalidRelation || step.result.Reason == InvalidProof || ctx.Err() != nil || guard.check(ctx) != contract.ReasonNone {
		return out
	}
	return gcCloseKnown(ctx, state, plan, admission, progress, trust, guard, out)
}
func gcCloseKnown(ctx context.Context, state *StateSession, plan contract.GCPlan, admission contract.ID, progress contract.GCProgress, trust contract.Trust, guard *installedGCGuard, out PublicGCResult) PublicGCResult {
	if state == nil || state.root.ActiveGC != plan.OperationID || ctx.Err() != nil || guard.check(ctx) != contract.ReasonNone {
		return out
	}
	var kept *contract.GCProgress
	if progress.RemainingCount != 0 {
		kept = &progress
	}
	step := gcAttemptPhase(ctx, state, plan, admission, contract.GCClose, kept, trust, &out)
	if !step.confirmed {
		return gcFailedPhase(out, step)
	}
	gcSelectedProgress(&out, progress, false, step.state)
	out.Payload.Closed = true
	out.Payload.SelectionUncertain = false
	out.Result = step.result
	out.StateResult = "gc-partial-garbage"
	if progress.RemainingCount == 0 {
		out.StateResult = "success"
	}
	return out
}
