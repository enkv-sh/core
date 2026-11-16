package configuration

import (
	"context"
	"errors"
	"unicode/utf8"

	"enkv.sh/telemetry"
)

type captureFailure struct{ cause error }

func (e captureFailure) Is(target error) bool { return target == ErrCapture }
func (e captureFailure) Error() string        { return ErrCapture.Error() }
func (e captureFailure) Unwrap() error        { return e.cause }

// Capture fixes both explicitly selected files before the caller can use them.
func Capture(ctx context.Context, path string, format Format) (pair *Pair, err error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationCapture)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	next := telemetry.CallContext(ctx, call)
	if ctx == nil {
		next = nil
	}
	pair, err = capturePair(next, path, format)
	returned := false
	defer func() {
		if !returned && pair != nil {
			err = errors.Join(err, pair.Close())
		}
	}()
	if err != nil {
		var diagnostic *Diagnostic
		if errors.As(err, &diagnostic) {
			copy := *diagnostic
			if err != diagnostic {
				copy.cause = err
			}
			err = &copy
		} else {
			err = captureFailure{cause: err}
		}
	} else {
		call.InputBytes(pair.Editable.Size())
		if pair.Generated != nil {
			call.InputBytes(pair.Generated.Size())
		}
	}
	finishSource(call, ctx, err, telemetry.DiagnosticReasonInvalidReference)
	returned = true
	return pair, err
}

// Parse interprets captured public facts. It does not authenticate their basis.
func Parse(ctx context.Context, pair *Pair) (*Model, error) {
	return parseSource(ctx, pair, nil, false)
}

// ParseForPreparation validates every present record and ordinary source join,
// and enumerates all positively absent supplied-secret records. Its model does
// not make an incomplete pair admissible to ordinary operations.
func ParseForPreparation(ctx context.Context, pair *Pair) (*Model, error) {
	return parseSource(ctx, pair, nil, true)
}

// ParseForSet adds the selected source spans to preparation admission. The
// writer must preserve the complete missing set except for its exact target.
func ParseForSet(ctx context.Context, pair *Pair, name string) (*Model, error) {
	return parseSource(ctx, pair, &name, true)
}
func parseSource(ctx context.Context, pair *Pair, selected *string, preparation bool) (*Model, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationParse)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	next := telemetry.CallContext(ctx, call)
	if ctx == nil {
		next = nil
	}
	var m *Model
	var err error
	if selected != nil && (len(*selected) > 256 || !utf8.ValidString(*selected)) {
		err = sourceError("entries", "invalid-selected-name")
	} else {
		m, err = parsePairModel(next, pair, &Model{selected: selected, preparation: preparation})
	}
	if pair != nil && pair.Editable != nil {
		call.InputBytes(pair.Editable.Size())
		if pair.Generated != nil {
			call.InputBytes(pair.Generated.Size())
		}
	}
	finishSource(call, ctx, err, telemetry.DiagnosticReasonInvalidFormat)
	return m, err
}
func finishSource(call *telemetry.Call, ctx context.Context, err error, reason telemetry.DiagnosticReason) {
	if err == nil {
		call.Finish(telemetry.ResultSuccess)
		return
	}
	var diagnostic *Diagnostic
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &diagnostic) && diagnostic.Reason == "cancelled" {
		call.FinishReason(telemetry.ResultCancelled, telemetry.DiagnosticReasonCancelled)
		return
	}
	call.FinishReason(telemetry.ResultAdmissionRefused, reason)
}
