package core

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

var storeRetryWait = [...]time.Duration{100 * time.Millisecond, 400 * time.Millisecond}

type storeEpisodeKey struct{}

// A write and all of its observations share these limits. The closure has at
// most one HEAD, one root and MaxChildren selected children per observation.
type storeEpisode struct {
	deadline   time.Time
	writes     int
	stages     int
	stageReads int
	readLimit  int
	extended   bool
}

func (e *storeEpisode) beginStage(readLimit int) bool {
	if e.stages == 3 || readLimit <= 0 {
		return false
	}
	e.stages++
	e.stageReads = 0
	e.readLimit = readLimit
	e.extended = false
	return true
}

// extendStage raises the allowance for the current observed image after its
// selected Root and support facts are authenticated. It does not restart a
// read stage or its failure deadline.
func (e *storeEpisode) extendStage(readLimit int) bool {
	if e == nil || e.stages == 0 || e.extended || readLimit <= 0 || readLimit < e.readLimit || readLimit < e.stageReads {
		return false
	}
	e.readLimit = readLimit
	e.extended = true
	return true
}

// extendObservedReadStage charges at most three physical Store attempts for
// each additional exact selected-image read. A normal Open has no episode.
func extendObservedReadStage(ctx context.Context, reads uint64) bool {
	if ctx == nil || ctx.Err() != nil || reads == 0 {
		return false
	}
	episode, ok := ctx.Value(storeEpisodeKey{}).(*storeEpisode)
	if !ok {
		return true
	}
	maxInt := uint64(int(^uint(0) >> 1))
	if episode == nil || episode.readLimit < 0 || reads > maxInt/3 || uint64(episode.readLimit) > maxInt-3*reads {
		return false
	}
	return episode.extendStage(episode.readLimit + int(3*reads))
}

func (e *storeEpisode) readAllowed() bool {
	if e.stages == 0 {
		return true
	}
	if e.stageReads >= e.readLimit {
		return false
	}
	e.stageReads++
	return true
}

func (e *storeEpisode) startFailure(ctx context.Context, expiry time.Time) {
	if !e.deadline.IsZero() {
		return
	}
	e.deadline = time.Now().Add(30 * time.Second)
	if expiry.Before(e.deadline) {
		e.deadline = expiry
	}
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(e.deadline) {
		e.deadline = callerDeadline
	}
}

func (e *storeEpisode) active(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && (e.deadline.IsZero() || time.Now().Before(e.deadline))
}

func (e *storeEpisode) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if e.deadline.IsZero() {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, e.deadline)
}

func (s *StateSession) storeRead(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if ctx == nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonConstruction}
	}
	episode, nested := ctx.Value(storeEpisodeKey{}).(*storeEpisode)
	if !nested {
		episode = &storeEpisode{}
	}
	return recoverStoreRead(ctx, episode, s.admission.expires, func(callCtx context.Context) contract.ReadResult {
		return s.storeReadOnce(callCtx, key, limit)
	})
}

// recoverStoreRead owns one physical read and its finite transport retries.
// The supplied callback must not contain another recovery loop.
func recoverStoreRead(ctx context.Context, episode *storeEpisode, expiry time.Time, physical func(context.Context) contract.ReadResult) contract.ReadResult {
	if ctx == nil || episode == nil || physical == nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonConstruction}
	}
	readOnce := func() contract.ReadResult {
		if !episode.active(ctx) || !episode.readAllowed() {
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
		}
		callCtx, cancel := episode.callContext(ctx)
		defer cancel()
		return physical(callCtx)
	}
	result := readOnce()
	if result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonTransport {
		return result
	}
	result.Body = nil
	result.Token = contract.Token{}
	episode.startFailure(ctx, expiry)
	for _, delay := range storeRetryWait {
		if !waitForStoreRetry(ctx, episode.deadline, delay) {
			result.Reason = contract.ReasonLimit
			return result
		}
		result = readOnce()
		if result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonTransport {
			return result
		}
		result.Body = nil
		result.Token = contract.Token{}
	}
	return result
}

func headObservationLimit() int { return 3 * (contract.MaxChildPages + 3) }

func refusedStoreWrite(written contract.WriteResult) Result {
	if written.Reason == contract.ReasonAccess || written.Reason == contract.ReasonLimit || written.Reason == contract.ReasonTransport {
		result := failure(EvidenceUnavailable, WriteUncertain)
		result.StoreReason = written.Reason
		return result
	}
	return refused(ConstructionMismatch)
}

func (s *StateSession) persistImmutable(ctx context.Context, key string, body []byte, limit uint32) Result {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreStorePersistImmutable)
	call.Checkpoint(telemetry.DiagnosticCandidatePersistence, telemetry.DiagnosticReasonNone)
	ctx = telemetry.CallContext(ctx, call)
	resolved := telemetry.ResultUnknown
	result := func() Result {
		if s == nil || ctx == nil {
			return refused(AdmissionInvalid)
		}
		if ctx.Err() != nil {
			result := s.observed(EvidenceUnavailable)
			result.Reason, result.StoreReason = ReadUnavailable, contract.ReasonLimit
			return result
		}
		frozen := bytes.Clone(body)
		episode := &storeEpisode{}
		ctx = context.WithValue(ctx, storeEpisodeKey{}, episode)
		preparation := applyPreparationFrom(ctx)
		acknowledged := false
		possiblePriorWrite := false
		for send := 0; send < 3; send++ {
			if !episode.active(ctx) || !s.admission.valid(s.store) {
				result := s.observed(EvidenceUnavailable)
				result.Reason = ReadUnavailable
				return result
			}
			episode.writes++
			callCtx, cancel := episode.callContext(ctx)
			written := s.storeCreate(callCtx, key, bytes.Clone(frozen))
			cancel()
			if written.Status == contract.WriteAcknowledged && !acknowledged {
				preparation.record(true, false, false)
				acknowledged = true
			}
			if written.Status == contract.WriteUnknown && !written.NotSent {
				preparation.record(false, false, true)
			}
			if written.Status == contract.WriteRefused {
				if possiblePriorWrite {
					result := failure(EvidenceUnavailable, WriteUncertain)
					result.StoreReason = contract.ReasonTransport
					return result
				}
				return refusedStoreWrite(written)
			}
			if written.Status == contract.WriteUnknown && !written.NotSent {
				possiblePriorWrite = true
			}
			if written.Status == contract.WriteUnknown && written.Reason == contract.ReasonTransport {
				episode.startFailure(ctx, s.admission.expires)
			}
			if !episode.beginStage(3) {
				return failure(EvidenceUnavailable, ReadUnavailable)
			}
			callCtx, cancel = episode.callContext(ctx)
			read := s.storeRead(callCtx, key, limit)
			cancel()
			switch read.Status {
			case contract.ReadOK:
				if !bytes.Equal(read.Body, frozen) {
					return failure(IntegrityFailure, ImmutableConflict)
				}
				preparation.record(false, true, false)
				resolved = telemetry.ResultImmutableVerified
				if acknowledged {
					resolved = telemetry.ResultImmutableCreated
				} else if written.Status == contract.WritePrecondition && !possiblePriorWrite {
					resolved = telemetry.ResultImmutableReused
				}
				return Result{}
			case contract.ReadInvalid:
				return failure(IntegrityFailure, ImmutableConflict)
			case contract.ReadMissing:
				if written.Status == contract.WriteUnknown && written.Reason == contract.ReasonTransport && send < 2 && waitForStoreRetry(ctx, episode.deadline, storeRetryWait[send]) {
					continue
				}
			}
			result := unavailableStoreRead(read)
			if ctx.Err() != nil && result.Outcome == EvidenceUnavailable {
				result.ObservedRevision, result.ObservedSnapshotID, result.Evidence = s.head.Core.Revision, s.root.Snapshot, AuthenticatedClosure
			}
			if read.Status == contract.ReadMissing && possiblePriorWrite {
				result.StoreReason = contract.ReasonTransport
			} else if read.Status == contract.ReadMissing && written.Status == contract.WriteUnknown {
				result.StoreReason = written.Reason
			}
			return result
		}
		return failure(EvidenceUnavailable, ReadUnavailable)
	}()
	if result.Outcome != 0 && ctx != nil && ctx.Err() != nil {
		call.Finish(telemetry.ResultCancelled)
	} else if result.Outcome != 0 {
		finishCore(call, result)
	} else {
		call.Finish(resolved)
	}
	return result
}

func waitForStoreRetry(ctx context.Context, deadline time.Time, delay time.Duration) bool {
	if ctx == nil || ctx.Err() != nil || !time.Now().Add(delay).Before(deadline) {
		return false
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil && time.Now().Before(deadline)
	}
}
