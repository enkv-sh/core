package compositionfull

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// ReplacementCommandResult has three distinct mutation forms and the two
// closed observation forms owned by Core. Exactly one field is populated.
// The operation is never inferred from a receipt returned by lookup.
type ReplacementCommandResult struct {
	SourceFailure  *ConfigurationSourceFailure
	Authority      *core.PublicReplacementResult
	Recovery       *core.PublicReplacementResult
	Recipient      *core.PublicReplacementResult
	Observation    *core.PublicReplacementObservationResult
	PreAdmission   *core.PreAdmissionRequestIdentity
	Delivery       ReplacementCommandDelivery
	recoverySource string
	localDelivery  *configuration.PairDelivery
}

type ReplacementCommandDelivery struct {
	Path           string `json:"path"`
	Status         string `json:"status"`
	Failed         bool   `json:"failed"`
	CleanupFailed  bool   `json:"cleanup_failed"`
	RecoverySource string `json:"recovery_source,omitempty"`
}

func replacementCommandTarget(target configuration.ReplacementTarget) (core.ReplacementTarget, bool) {
	switch target {
	case configuration.ReplaceAuthority:
		return core.ReplacementTargetAuthority, true
	case configuration.ReplaceRecovery:
		return core.ReplacementTargetRecovery, true
	case configuration.ReplaceRecipient:
		return core.ReplacementTargetRecipient, true
	}
	return 0, false
}

func replacementCommandFresh(target configuration.ReplacementTarget, r core.PublicReplacementResult) ReplacementCommandResult {
	switch target {
	case configuration.ReplaceAuthority:
		return ReplacementCommandResult{Authority: &r}
	case configuration.ReplaceRecovery:
		return ReplacementCommandResult{Recovery: &r}
	case configuration.ReplaceRecipient:
		return ReplacementCommandResult{Recipient: &r}
	}
	return ReplacementCommandResult{}
}

func NewReplacementCommandRefusal(target configuration.ReplacementTarget, nonce contract.ID, format configuration.Format) (ReplacementCommandResult, error) {
	if _, ok := replacementCommandTarget(target); !ok || nonce.IsZero() {
		return ReplacementCommandResult{}, configuration.ErrEdit
	}
	operation, q, err := configurationPreAdmission(format, nonce)
	if err != nil {
		return ReplacementCommandResult{}, err
	}
	out := replacementCommandFresh(target, core.PublicReplacementResult{RequestID: nonce, OperationID: operation, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}})
	out.PreAdmission = q
	out.Delivery.Status = "not-attempted"
	return out, nil
}

// ReplaceKeysConfiguration owns source and named-output captures. Existing
// protected target metadata selects observation before source/provider work.
// An existing output can never enter the fresh replacement adapter.
func ReplaceKeysConfiguration(ctx context.Context, nonce contract.ID, sourcePath string, format configuration.Format, request configuration.ReplacementRequest, outputPath string) ReplacementCommandResult {
	return replaceKeysConfiguration(ctx, nonce, sourcePath, format, request, outputPath, defaultReplacementObservationSource)
}

// ReplaceSelectedRecipientKeysConfiguration resolves a recipient selector from
// the captured source before protecting output metadata or changing state.
func ReplaceSelectedRecipientKeysConfiguration(ctx context.Context, nonce contract.ID, sourcePath string, format configuration.Format, request configuration.ReplacementRequest, outputPath string, selector RecipientSelector) ReplacementCommandResult {
	return replaceSelectedKeysConfiguration(ctx, nonce, sourcePath, format, request, outputPath, defaultReplacementObservationSource, selector)
}

func replaceKeysConfiguration(ctx context.Context, nonce contract.ID, sourcePath string, format configuration.Format, request configuration.ReplacementRequest, outputPath string, openObservation func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error)) ReplacementCommandResult {
	return replaceSelectedKeysConfiguration(ctx, nonce, sourcePath, format, request, outputPath, openObservation, RecipientSelector{Reference: request.RecipientReference})
}

func replaceSelectedKeysConfiguration(ctx context.Context, nonce contract.ID, sourcePath string, format configuration.Format, request configuration.ReplacementRequest, outputPath string, openObservation func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error), selector RecipientSelector) (out ReplacementCommandResult) {
	delivery := ReplacementCommandDelivery{Status: "not-attempted"}
	refuse := func(stage string, err error) {
		var construction error
		out, construction = NewReplacementCommandRefusal(request.Target, nonce, format)
		if construction != nil {
			delivery.Failed = true
		}
		if out.PreAdmission != nil {
			out.PreAdmission.Stage = stage
			out.PreAdmission.Code = configurationFailureCode(ctx, err)
		}
		out.Delivery = delivery
		if f := configurationSourceFailure("source", err); f != nil {
			out.SourceFailure = f
		}
	}
	refuseRead := func(target configuration.ReplacementTarget, err error) {
		fixed, ok := replacementCommandTarget(target)
		if !ok {
			refuse("capture", err)
			return
		}
		result, construction := NewReplacementObservationRefusal(fixed, nonce, format)
		if construction != nil {
			out = ReplacementCommandResult{Observation: &result, Delivery: delivery}
			out.Delivery.Failed = true
			return
		}
		if result.PreAdmission != nil {
			result.PreAdmission.Stage = "capture"
			result.PreAdmission.Code = configurationFailureCode(ctx, err)
		}
		out = ReplacementCommandResult{Observation: &result, Delivery: delivery}
		if f := configurationSourceFailure("source", err); f != nil {
			out.SourceFailure = f
		}
	}
	if !selector.valid() || request.RecipientReference != "" && selector.Reference != "" && request.RecipientReference != selector.Reference {
		refuse("declaration", configuration.ErrEdit)
		return out
	}
	if !configuration.SuccessorOutputPathValid(outputPath) {
		refuse("dispatch", configuration.ErrEdit)
		return out
	}
	delivery.Path = outputPath
	if ctx == nil || ctx.Err() != nil || nonce.IsZero() || !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath {
		refuse("context", nil)
		return out
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		refuse("context", context.DeadlineExceeded)
		return out
	}
	capture, err := configuration.CaptureSuccessorOutput(ctx, outputPath, format)
	if err != nil {
		var known *configuration.SuccessorOutputRefusal
		if errors.As(err, &known) {
			delivery.Status = "existing"
			refuseRead(known.Target, err)
		} else {
			refuse("capture", err)
		}
		return out
	}
	var output *configuration.SuccessorOutput
	var pair *configuration.Pair
	defer func() {
		var closeErr error
		if output != nil {
			closeErr = output.Close()
			if delivery := output.LocalDelivery(); delivery != nil {
				out.localDelivery = delivery
				out.Delivery.CleanupFailed = out.Delivery.CleanupFailed || delivery.CleanupFailed()
				if !output.Delivered() {
					out.Delivery.Status = "read-back"
					out.Delivery.Failed = true
				}
			}
			if source, pending := output.RecoverySource(); pending {
				out.recoverySource = source
				out.Delivery.RecoverySource = source
				out.Delivery.Status = "pending"
				out.Delivery.Failed = true
			}
		} else {
			closeErr = capture.Close()
		}
		if pair != nil {
			closeErr = errors.Join(closeErr, pair.Close())
		}
		if closeErr != nil {
			out.Delivery.CleanupFailed = true
		}
	}()
	fixedTarget, existing := capture.Target()
	if existing {
		delivery.Status = "existing"
	}
	pair, err = configuration.Capture(ctx, sourcePath, format)
	if err != nil {
		if existing {
			refuseRead(fixedTarget, err)
		} else {
			refuse("capture", err)
		}
		return out
	}
	if request.Target == configuration.ReplaceRecipient {
		reference, selectionErr := selector.localReference(ctx, pair)
		if selectionErr != nil {
			if existing {
				refuseRead(fixedTarget, selectionErr)
			} else {
				refuse("declaration", selectionErr)
			}
			return out
		}
		if request.RecipientReference != "" && request.RecipientReference != reference {
			if existing {
				refuseRead(fixedTarget, configuration.ErrEdit)
			} else {
				refuse("declaration", configuration.ErrEdit)
			}
			return out
		}
		request.RecipientReference = reference
	} else if !selector.ID.IsZero() || selector.Reference != "" {
		refuse("declaration", configuration.ErrEdit)
		return out
	}
	output, err = configuration.PrepareSuccessorOutputFromCapture(ctx, pair, capture, request)
	if err != nil {
		var known *configuration.SuccessorOutputRefusal
		if errors.As(err, &known) {
			delivery.Status = "existing"
			refuseRead(known.Target, err)
		} else if existing {
			refuseRead(fixedTarget, err)
		} else {
			refuse("declaration", err)
		}
		return out
	}
	if existing {
		observed, cleanupErr, _ := observeReplacementConfigurationOwned(ctx, nonce, pair, output, openObservation)
		out = ReplacementCommandResult{Observation: &observed, Delivery: delivery}
		if cleanupErr != nil {
			out.Delivery.CleanupFailed = true
		}
		return out
	}
	delivery.Status = "unproved"
	result, err := replaceConfigurationKeys(ctx, nonce, pair, request, output)
	if result.Result.Outcome == 0 {
		refuse("construction", err)
		out.Delivery.Failed = true
		return out
	}
	out = replacementCommandFresh(request.Target, result)
	out.Delivery = delivery
	if output.Delivered() {
		out.Delivery.Status = "delivered"
	}
	if result.Result.Outcome == core.Unchanged && request.Target == configuration.ReplaceAuthority {
		out.Delivery.Status = "not-created"
	}
	if result.RequestIdentity.IsZero() && result.Result.Outcome != core.Unchanged {
		operation, q, failure := configurationPreAdmission(format, nonce)
		if failure == nil {
			q.Stage = "construction"
			q.Code = configurationFailureCode(ctx, err)
			out.PreAdmission = q
			for _, r := range []*core.PublicReplacementResult{out.Authority, out.Recovery, out.Recipient} {
				if r != nil && r.OperationID.IsZero() {
					r.OperationID = operation
				}
			}
		} else {
			out.Delivery.Failed = true
		}
	}
	if err != nil {
		out.Delivery.Failed = true
	}
	return out
}
