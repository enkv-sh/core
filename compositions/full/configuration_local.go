package compositionfull

import (
	"context"
	"errors"
	"io"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/telemetry"
)

var ErrLocalEdit = errors.New("local configuration edit refused")

type localEditError struct{ cause error }

func (e *localEditError) Error() string { return ErrLocalEdit.Error() }
func (e *localEditError) Unwrap() error { return errors.Join(ErrLocalEdit, e.cause) }

// RenameConfigurationDomain changes the local name and satellite path together.
// It preserves the editable filename and performs no provider operation.
func RenameConfigurationDomain(ctx context.Context, path string, format configuration.Format, name string) (*LocalEditResult, error) {
	return runLocalConfigurationEdit(ctx, "domain-rename", func(ctx context.Context, result *LocalEditResult) (resultErr error) {
		session, err := configuration.BeginRename(ctx, path, format, name)
		if err != nil {
			return err
		}
		defer closeLocalEditSession(session, result, &resultErr)
		model, err := configuration.Parse(ctx, session.Pair())
		if err != nil {
			return err
		}
		result.target = domainRenameTarget{OldName: model.DomainName, NewName: name}
		*model = configuration.Model{}
		admitLocalEditPaths(result, session.Pair())
		candidate, model, err := session.StageRename(ctx)
		if err != nil {
			return err
		}
		return commitLocalEditCandidate(ctx, result, session, candidate, model)
	})
}

// RenameConfigurationRecipientReference changes every local join while retaining
// recipient identity, public bindings and encrypted records.
func RenameConfigurationRecipientReference(ctx context.Context, path string, format configuration.Format, oldReference, newReference string) (*LocalEditResult, error) {
	return RenameConfigurationSelectedRecipient(ctx, path, format, RecipientSelector{Reference: oldReference}, newReference)
}

// RenameConfigurationSelectedRecipient resolves an existing recipient under
// the same edit lock used to rename its local reference.
func RenameConfigurationSelectedRecipient(ctx context.Context, path string, format configuration.Format, selector RecipientSelector, newReference string) (*LocalEditResult, error) {
	return runLocalConfigurationEdit(ctx, "recipient-reference-rename", func(ctx context.Context, result *LocalEditResult) (resultErr error) {
		session, err := configuration.BeginEdit(ctx, path, format)
		if err != nil {
			return err
		}
		defer closeLocalEditSession(session, result, &resultErr)
		oldReference, err := selector.localReference(ctx, session.Pair())
		if err != nil {
			return err
		}
		edit, err := configuration.PrepareRecipientReferenceEdit(ctx, session.Pair(), oldReference, newReference)
		if err != nil {
			return err
		}
		result.target = recipientReferenceTarget{OldReference: oldReference, NewReference: newReference}
		admitLocalEditPaths(result, session.Pair())
		candidate, model, err := session.Stage(ctx, func(out io.Writer) error { return edit.EmitGenerated(ctx, out) },
			func(out io.Writer, reference string) error { return edit.EmitEditable(ctx, out, reference) })
		if err != nil {
			return err
		}
		return commitLocalEditCandidate(ctx, result, session, candidate, model)
	})
}

// RecoverConfigurationEdit completes only the exact saved local transaction.
// It does not reconstruct configuration or perform a domain operation.
func RecoverConfigurationEdit(ctx context.Context, path string, format configuration.Format) (*LocalEditResult, error) {
	return runLocalConfigurationEdit(ctx, "recovery", func(ctx context.Context, result *LocalEditResult) error {
		delivery, err := configuration.RecoverEdit(ctx, path, format)
		result.delivery = delivery
		if delivery != nil {
			source, _ := delivery.Paths()
			result.target = recoveryEditTarget{Source: source}
		} else {
			var pending *configuration.PendingEdit
			if errors.As(err, &pending) {
				if source, valid := pending.RecoverySource(); valid {
					result.target = recoveryEditTarget{Source: source}
				}
			}
		}
		return err
	})
}

func runLocalConfigurationEdit(ctx context.Context, action string, edit func(context.Context, *LocalEditResult) error) (*LocalEditResult, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	if ctx != nil {
		ctx = telemetry.CallContext(ctx, call)
	}
	result, err := NewLocalEditRefusal(action)
	if err == nil {
		if ctx == nil {
			err = ErrLocalEdit
		} else if contextErr := ctx.Err(); contextErr != nil {
			err = contextErr
		} else if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
			err = ErrLocalEdit
		} else {
			err = edit(ctx, result)
		}
	}
	finishLocalEditResult(result, err)
	var cleanupFailed bool
	err, cleanupFailed = closeConfigurationDeliveryState(err)
	if result != nil && cleanupFailed {
		result.cleanupFail = true
	}
	call.Finish(result.TelemetryResult(err))
	if err != nil {
		err = &localEditError{cause: err}
	}
	return result, err
}

func admitLocalEditPaths(result *LocalEditResult, pair *configuration.Pair) {
	result.paths[0] = pair.Editable.OriginalPath()
	if pair.Generated != nil {
		result.paths[1] = pair.Generated.OriginalPath()
	}
}

func closeLocalEditSession(session *configuration.EditSession, result *LocalEditResult, resultErr *error) {
	if err := session.Close(); err != nil {
		result.cleanupFail = true
		*resultErr = errors.Join(*resultErr, err)
	}
}

func commitLocalEditCandidate(ctx context.Context, result *LocalEditResult, session *configuration.EditSession, candidate *configuration.EditCandidate, model *configuration.Model) error {
	if model == nil {
		return ErrLocalEdit
	}
	if model.Resolved {
		validation := validateInstalledConfiguration(ctx, model.Public)
		if !validation.Valid || !validation.DiagnosticsComplete {
			return ErrLocalEdit
		}
	}
	*model = configuration.Model{}
	delivery, err := session.Commit(ctx, candidate)
	result.delivery = delivery
	return err
}

func finishLocalEditResult(result *LocalEditResult, err error) {
	if result == nil {
		return
	}
	if errors.As(err, &result.unknown) {
		if result.delivery == nil {
			result.delivery, _ = result.unknown.Readback()
		}
		if result.unknown.Observation != nil {
			paths := result.unknown.Observation.Paths()
			if len(paths) >= 2 {
				result.paths = [2]string{paths[0], paths[1]}
			}
		}
	}
	errors.As(err, &result.pending)
	if result.delivery != nil {
		result.outcome = "edited"
	} else if result.unknown != nil || result.pending != nil {
		result.outcome = "unknown"
	}
	if _, valid := result.delivery.RecoverySource(); valid {
		result.outcome = "pending"
	} else if _, valid := result.unknown.RecoverySource(); valid {
		result.outcome = "pending"
	} else if _, valid := result.pending.RecoverySource(); valid {
		result.outcome = "pending"
	}
}
