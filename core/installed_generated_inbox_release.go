package core

import (
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// Release only inboxes handed off by this selection or by earlier steps of its
// now-terminal operation. The original operation result stays at its own HEAD.
// A failed release leaves the authenticated mapping available to inspection.
func releaseInstalledGeneratedInboxes(ctx context.Context, s *StateSession, operation contract.ID, trust contract.Trust, deadline time.Time) {
	if ctx.Err() != nil || s.root.Generated.PendingReleases == 0 || !s.root.Generated.ActiveOwner.IsZero() {
		return
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreGeneratedPrepareLifecycle)
	ctx = telemetry.CallContext(ctx, call)
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		finishCore(call, installedApplyPreparationFailure(err))
		return
	}
	// Each ID has a distinct selected Attempt and release record. Freeze the
	// finite set before the first Store call and visit each ID at most once.
	if uint64(len(work.releases)) > generatedResultReleaseLimit {
		finishCore(call, refused(CapacityExceeded))
		return
	}
	var inboxes []contract.ID
	for _, r := range work.releases {
		if r.release.State == contract.GeneratedReleasePending && (r.release.HandoffRevisionID == s.head.Core.Revision || r.attempt.OperationID == operation) {
			inboxes = append(inboxes, r.release.InboxID)
		}
	}
	slices.SortFunc(inboxes, compareGeneratedIDs)
	outcome := s.observed(Unchanged)
	for _, id := range inboxes {
		if ctx.Err() != nil {
			outcome = installedApplyPreparationFailure(ctx.Err())
			break
		}
		admitted, err := installedGeneratedContext(s, deadline)
		if err != nil {
			outcome = installedApplyPreparationFailure(err)
			break
		}
		permit, err := s.admitGeneratedInboxRelease(ctx, id, admitted)
		if err != nil {
			// A still-needed or conditionally refused inbox does not use this
			// session's selector. Independently eligible siblings can proceed.
			outcome = installedApplyPreparationFailure(err)
			continue
		}
		candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, trust)
		if candidate == nil {
			outcome = result
			break
		}
		next, result := s.selectObserved(ctx, candidate)
		if result.Outcome != ObservedCurrent {
			outcome = result
			break
		}
		if !candidateMatches(next, candidate) {
			outcome = refused(DifferentSelection)
			break
		}
		s = next
		if outcome.Outcome == Unchanged || outcome.Outcome == ObservedCurrent {
			outcome = result
		}
	}
	finishCore(call, outcome)
}
