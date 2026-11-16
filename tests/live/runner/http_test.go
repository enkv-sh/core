package core

import (
	"context"
	"errors"
	"io"
	"sync"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

type setupRequestBody struct {
	io.ReadCloser
	mu              sync.Mutex
	reads           int
	closing, closed bool
	done            chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

func (b *setupRequestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.reads++
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	b.reads--
	if b.closed && b.reads == 0 {
		close(b.done)
	}
	b.mu.Unlock()
	return n, err
}

func (b *setupRequestBody) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closing = true
		b.mu.Unlock()
		// Close must be able to unblock a Read without waiting for its lock.
		b.closeErr = b.ReadCloser.Close()
		b.mu.Lock()
		b.closed = true
		if b.reads == 0 {
			close(b.done)
		}
		b.mu.Unlock()
	})
	return b.closeErr
}

func (b *setupRequestBody) finished(ctx context.Context) bool {
	if b == nil {
		return true
	}
	select {
	case <-b.done:
		return true
	default:
	}
	select {
	case <-b.done:
		return true
	case <-ctx.Done():
		return false
	}
}

// Setup uses the same bounded logical result names as the provider contract.
func setupWriteResult(status contract.WriteStatus) telemetry.Result {
	switch status {
	case contract.WriteAcknowledged:
		return telemetry.ResultWriteAcknowledged
	case contract.WritePrecondition:
		return telemetry.ResultWritePrecondition
	case contract.WriteConflict:
		return telemetry.ResultWriteConflict
	case contract.WriteUnknown:
		return telemetry.ResultWriteUnknown
	case contract.WriteRefused:
		return telemetry.ResultWriteRefused
	default:
		return telemetry.ResultUnknown
	}
}

func setupCallResult(err error) telemetry.Result {
	if err != nil {
		return telemetry.ResultFailure
	}
	return telemetry.ResultSuccess
}

func setupDiagnosticClass(f records.HarnessFailure) telemetry.DiagnosticReason {
	switch f.Cause {
	case "cancelled":
		return telemetry.DiagnosticReasonCancelled
	case "transport", "missing_response", "early_eof", "deadline":
		return telemetry.DiagnosticReasonReadUnavailable
	case "access_refused", "authentication_refused":
		return telemetry.DiagnosticReasonDenied
	case "condition_refused", "ownership_mismatch":
		return telemetry.DiagnosticReasonStalePrecondition
	case "invalid_encoding", "invalid_length", "malformed_envelope", "invalid_acknowledgement", "invalid_request":
		return telemetry.DiagnosticReasonInvalidFormat
	case "budget_exhausted":
		return telemetry.DiagnosticReasonCapacityExceeded
	default:
		return telemetry.DiagnosticReasonEvidenceUnavailable
	}
}

// The optional diagnostic return uses the same reviewed facts as the worker
// receipt. Neither a raw provider error nor a response body enters telemetry.
func finishSetupCall(call *telemetry.Call, err error) {
	var safe interface{ SafeHarnessFailure() records.HarnessFailure }
	if errors.As(err, &safe) {
		fact := safe.SafeHarnessFailure()
		if fact.Validate() {
			status := 0
			if fact.HTTPStatus != nil {
				status = int(*fact.HTTPStatus)
			}
			call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(setupDiagnosticClass(fact), status))
			reason := telemetry.DiagnosticReasonEvidenceUnavailable
			if fact.Effect == "unknown" {
				reason = telemetry.DiagnosticReasonUncertain
			}
			call.FinishReason(setupCallResult(err), reason)
			return
		}
	}
	call.Finish(setupCallResult(err))
}
