package core

import (
	"context"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type ApplyPublicationStage struct {
	Stage, Reason string
	Result        *PublicPublicationResult
}

type PublicApplyPublicationResult struct {
	Apply       PublicApplyResult
	Publication ApplyPublicationStage
}

// The existing apply gate acquires this owner. Its completion channel stays
// live until publication and all borrowed selected representations have ended.
type applyPublicationCapture struct {
	mu      sync.Mutex
	engine  *InstalledApply
	done    chan struct{}
	handoff *applyPublicationHandoff
	reason  string
	closed  bool
}

func (e *InstalledApply) beginApplyInvocation(capture *applyPublicationCapture) (ApplyInstallation, chan struct{}, bool) {
	if e == nil {
		return ApplyInstallation{}, nil, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.used || e.closed || e.activeDone != nil {
		return ApplyInstallation{}, nil, false
	}
	if capture != nil {
		capture.mu.Lock()
		defer capture.mu.Unlock()
		if capture.closed || capture.engine != nil || capture.done != nil {
			return ApplyInstallation{}, nil, false
		}
	}
	e.used = true
	i := e.installation
	e.installation.PublicConfiguration = contract.PublicConfiguration{}
	done := make(chan struct{})
	e.activeDone, e.publicationCapture = done, capture
	if capture != nil {
		capture.engine, capture.done = e, done
	}
	return i, done, true
}

func (e *InstalledApply) endApplyInvocation(done chan struct{}, capture *applyPublicationCapture) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.activeDone != done {
		return
	}
	e.publicationCapture = nil
	if capture == nil {
		e.activeDone = nil
		close(done)
	}
}

func (c *applyPublicationCapture) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	e, done, h := c.engine, c.done, c.handoff
	c.engine, c.done, c.handoff = nil, nil, nil
	c.mu.Unlock()
	if h != nil {
		h.close()
	}
	if e != nil {
		e.mu.Lock()
		if e.activeDone == done {
			e.publicationCapture, e.activeDone = nil, nil
			close(done)
		}
		e.mu.Unlock()
	}
}

// This classifies completion only. A private capture from an authenticated
// selection boundary is independently required before publication can start.
func applyPublicationComplete(out PublicApplyResult) bool {
	if out.Result.Outcome != ObservedCurrent && out.Result.Outcome != Unchanged {
		return false
	}
	for _, diagnostic := range out.Diagnostics {
		interrupted := diagnostic.Subject.Kind == contract.SubjectObservation && len(diagnostic.Path) == 1 && diagnostic.Path[0] == contract.FieldPresence &&
			(diagnostic.Reason == contract.ReasonCancelled || diagnostic.Reason == contract.ReasonExpired)
		if diagnostic.Outcome == contract.DiagnosticUnable && !interrupted {
			return false
		}
	}
	g := out.Generated
	if g == nil {
		return true
	}
	return g.OperationKind == contract.OperationApplyDeclaration && g.CanonicalOutcome == contract.ReceiptCanonicalSelected &&
		(g.StateResult == "success" || g.StateResult == "exact-resume" || g.StateResult == "no-op") &&
		(g.EffectSummary == contract.ReceiptEffectComplete || g.EffectSummary == contract.ReceiptEffectNoChange)
}

func (e *InstalledApply) captureApplyPublication(ctx context.Context, s *StateSession, complete bool) {
	e.mu.Lock()
	c := e.publicationCapture
	e.mu.Unlock()
	if c == nil || !complete {
		return
	}
	h, err := captureApplyPublicationSelection(ctx, s)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		if h != nil {
			h.close()
		}
		return
	}
	if c.handoff != nil {
		c.handoff.close()
	}
	c.handoff = h
	c.reason = ""
	if err != nil || h == nil {
		c.reason = "selection-unavailable"
	}
}

// ApplyAndPublish preserves two separately admitted results under the caller's
// original deadline. The private selected representation cannot escape return.
func (e *InstalledApply) ApplyAndPublish(ctx context.Context, applyRequestID, publicationRequestID contract.ID, input []ApplyEntryInput, publication *InstalledPublication, republishIDs []contract.ID) PublicApplyPublicationResult {
	capture := &applyPublicationCapture{}
	defer capture.close()
	applyCtx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(applyCtx, telemetry.ProviderCore, telemetry.OpCoreApply)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := e.apply(applyCtx, applyRequestID, input, call, capture)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return e.finishApplyPublication(ctx, out, publicationRequestID, publication, republishIDs, capture)
}

func (e *InstalledApply) ContinueAndPublish(ctx context.Context, applyRequestID, operationID, publicationRequestID contract.ID, publication *InstalledPublication, republishIDs []contract.ID) PublicApplyPublicationResult {
	capture := &applyPublicationCapture{}
	defer capture.close()
	applyCtx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(applyCtx, telemetry.ProviderCore, telemetry.OpCoreApply)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := e.continueGenerated(telemetry.CallContext(applyCtx, call), applyRequestID, operationID, capture)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return e.finishApplyPublication(ctx, out, publicationRequestID, publication, republishIDs, capture)
}

func (e *InstalledApply) finishApplyPublication(ctx context.Context, apply PublicApplyResult, request contract.ID, publication *InstalledPublication, republish []contract.ID, capture *applyPublicationCapture) PublicApplyPublicationResult {
	out := PublicApplyPublicationResult{Apply: apply, Publication: ApplyPublicationStage{Stage: "unstarted", Reason: "apply-incomplete"}}
	if !applyPublicationComplete(apply) {
		return out
	}
	if ctx == nil {
		out.Publication.Reason = "selection-unavailable"
		return out
	}
	if ctx.Err() != nil {
		out.Publication.Reason = "selection-unavailable"
		if ctx.Err() == context.DeadlineExceeded {
			out.Publication.Reason = "deadline-expired"
		}
		return out
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		out.Publication.Reason = "deadline-expired"
		return out
	}
	capture.mu.Lock()
	h, reason := capture.handoff, capture.reason
	capture.mu.Unlock()
	if h == nil || reason != "" || publication == nil {
		out.Publication.Reason = "selection-unavailable"
		return out
	}
	result, reason := publication.publishCaptured(ctx, request, republish, h, e)
	if reason != "" {
		out.Publication.Reason = reason
		return out
	}
	out.Publication = ApplyPublicationStage{Stage: "evaluated", Result: &result}
	return out
}
