package compositionfull

import (
	"context"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// InspectConfiguration reads one fixed authenticated observation without changing the input pair.
func InspectConfiguration(ctx context.Context, nonce contract.ID, pair *configuration.Pair) ConfigurationInspectionResult {
	return inspectConfiguration(ctx, nonce, pair, NewDefaultInspectionReader)
}

func inspectConfiguration(ctx context.Context, nonce contract.ID, pair *configuration.Pair, open func(context.Context, InspectionReaderConfig) (*core.InstalledInspectionReader, error)) ConfigurationInspectionResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	base, err := newConfigurationQueryRefusal(core.InspectOperation, nonce, format)
	out := ConfigurationInspectionResult{PublicDomainInspectionResult: core.PublicDomainInspectionResult{PublicQueryResult: base}}
	if err != nil {
		return out
	}
	return inspectConfigurationWithIdentity(ctx, nonce, pair, open, base)
}

func inspectConfigurationWithIdentity(ctx context.Context, nonce contract.ID, pair *configuration.Pair, open func(context.Context, InspectionReaderConfig) (*core.InstalledInspectionReader, error), base core.PublicQueryResult) ConfigurationInspectionResult {
	out := ConfigurationInspectionResult{PublicDomainInspectionResult: core.PublicDomainInspectionResult{PublicQueryResult: base}}
	if open == nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", nil, false)
		return out
	}
	c, pins, model, err := configurationPublicQueryModel(ctx, nonce, pair)
	if err != nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	out.DomainID, _ = capacityReaderScope(c)
	reader, err := open(ctx, InspectionReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: pair.CheckUnchanged})
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", err, true)
		return out
	}
	releaseConfigurationReader(&c)
	defer reader.Close()
	result := reader.Inspect(ctx, core.DomainInspectionRequest{RequestNonce: nonce})
	finishConfigurationQuery(&result.PublicQueryResult, base)
	var location *resultStoreLocation
	if result.View != nil {
		location = newResultStoreLocation(model, result.View.Observation.DomainID, result.Result)
	}
	return ConfigurationInspectionResult{PublicDomainInspectionResult: result, storeLocation: location}
}

func InspectConfigurationFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format) (out ConfigurationInspectionResult) {
	base, err := newConfigurationQueryRefusal(core.InspectOperation, nonce, format)
	out.PublicQueryResult = base
	if err != nil {
		return out
	}
	invoked := false
	err = capturedPublicQuery(ctx, path, format, func(pair *configuration.Pair) {
		invoked = true
		out = inspectConfigurationWithIdentity(ctx, nonce, pair, NewDefaultInspectionReader, base)
	})
	if err != nil {
		out.View = nil
		out.storeLocation = nil
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "capture", err, invoked)
	}
	return out
}

// NewDomainInspectionRefusal creates a closed local refusal without source or provider access.
func NewDomainInspectionRefusal(format configuration.Format) (core.PublicDomainInspectionResult, error) {
	base, err := newConfigurationQueryRefusal(core.InspectOperation, contract.ID{}, format)
	return core.PublicDomainInspectionResult{PublicQueryResult: base}, err
}

// InspectConfigurationRecipient reads one fixed authenticated observation without changing the input pair.
func InspectConfigurationRecipient(ctx context.Context, nonce contract.ID, pair *configuration.Pair, recipientID contract.ID) ConfigurationRecipientInspectionResult {
	return inspectConfigurationRecipient(ctx, nonce, pair, recipientID, NewDefaultInspectionReader)
}

func inspectConfigurationRecipient(ctx context.Context, nonce contract.ID, pair *configuration.Pair, recipientID contract.ID, open func(context.Context, InspectionReaderConfig) (*core.InstalledInspectionReader, error)) ConfigurationRecipientInspectionResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	base, err := newConfigurationQueryRefusal(core.InspectRecipientOperation, nonce, format)
	out := ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: core.PublicRecipientInspectionResult{PublicQueryResult: base}}
	if err != nil {
		return out
	}
	return inspectConfigurationRecipientWithIdentity(ctx, nonce, pair, RecipientSelector{ID: recipientID}, open, base)
}

func inspectConfigurationRecipientWithIdentity(ctx context.Context, nonce contract.ID, pair *configuration.Pair, selector RecipientSelector, open func(context.Context, InspectionReaderConfig) (*core.InstalledInspectionReader, error), base core.PublicQueryResult) ConfigurationRecipientInspectionResult {
	out := ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: core.PublicRecipientInspectionResult{PublicQueryResult: base}}
	if open == nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", nil, false)
		return out
	}
	if !selector.valid() || selector.Reference == "" && selector.ID.IsZero() {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", nil, false)
		return out
	}
	c, pins, model, err := configurationPublicQueryModel(ctx, nonce, pair)
	if err != nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	recipientID, err := selector.resolve(model)
	if err != nil || recipientID.IsZero() {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	out.DomainID, _ = capacityReaderScope(c)
	reader, err := open(ctx, InspectionReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: pair.CheckUnchanged})
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", err, true)
		return out
	}
	releaseConfigurationReader(&c)
	defer reader.Close()
	result := reader.InspectRecipient(ctx, core.RecipientInspectionRequest{RequestNonce: nonce, RecipientID: recipientID})
	finishConfigurationQuery(&result.PublicQueryResult, base)
	return ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: result}
}

func InspectConfigurationRecipientFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, recipientID contract.ID) ConfigurationRecipientInspectionResult {
	return InspectConfigurationSelectedRecipientFile(ctx, nonce, path, format, RecipientSelector{ID: recipientID})
}

// InspectConfigurationSelectedRecipientFile resolves an alias in its captured
// pair before authenticating that exact identity in current Store state.
func InspectConfigurationSelectedRecipientFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, selector RecipientSelector) (out ConfigurationRecipientInspectionResult) {
	base, err := newConfigurationQueryRefusal(core.InspectRecipientOperation, nonce, format)
	out.PublicQueryResult = base
	if err != nil || !selector.valid() || selector.Reference == "" && selector.ID.IsZero() {
		if err == nil {
			configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", nil, false)
		}
		return out
	}
	invoked := false
	err = capturedPublicQuery(ctx, path, format, func(pair *configuration.Pair) {
		invoked = true
		out = inspectConfigurationRecipientWithIdentity(ctx, nonce, pair, selector, NewDefaultInspectionReader, base)
	})
	if err != nil {
		out.View = nil
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "capture", err, invoked)
	}
	return out
}

// NewRecipientInspectionRefusal creates a closed local refusal without source or provider access.
func NewRecipientInspectionRefusal(format configuration.Format) (core.PublicRecipientInspectionResult, error) {
	base, err := newConfigurationQueryRefusal(core.InspectRecipientOperation, contract.ID{}, format)
	return core.PublicRecipientInspectionResult{PublicQueryResult: base}, err
}
