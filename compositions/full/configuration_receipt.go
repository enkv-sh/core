package compositionfull

import (
	"context"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// ListConfigurationReceipts reads one fixed authenticated observation without changing the input pair.
func ListConfigurationReceipts(ctx context.Context, nonce contract.ID, pair *configuration.Pair) ConfigurationReceiptListResult {
	return listConfigurationReceipts(ctx, nonce, pair, NewDefaultReceiptReader)
}

func listConfigurationReceipts(ctx context.Context, nonce contract.ID, pair *configuration.Pair, open func(context.Context, ReceiptReaderConfig) (*core.InstalledReceiptReader, error)) ConfigurationReceiptListResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	base, err := newConfigurationQueryRefusal(core.ReceiptListOperation, nonce, format)
	out := ConfigurationReceiptListResult{PublicReceiptListResult: core.PublicReceiptListResult{PublicQueryResult: base}}
	if err != nil {
		return out
	}
	return listConfigurationReceiptsWithIdentity(ctx, nonce, pair, open, base)
}

func listConfigurationReceiptsWithIdentity(ctx context.Context, nonce contract.ID, pair *configuration.Pair, open func(context.Context, ReceiptReaderConfig) (*core.InstalledReceiptReader, error), base core.PublicQueryResult) ConfigurationReceiptListResult {
	out := ConfigurationReceiptListResult{PublicReceiptListResult: core.PublicReceiptListResult{PublicQueryResult: base}}
	if open == nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", nil, false)
		return out
	}
	c, pins, err := configurationPublicQueryInput(ctx, nonce, pair)
	if err != nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	out.DomainID, _ = capacityReaderScope(c)
	reader, err := open(ctx, ReceiptReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: pair.CheckUnchanged})
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", err, true)
		return out
	}
	releaseConfigurationReader(&c)
	defer reader.Close()
	result := reader.List(ctx, core.ReceiptListRequest{RequestNonce: nonce})
	finishConfigurationQuery(&result.PublicQueryResult, base)
	return ConfigurationReceiptListResult{PublicReceiptListResult: result}
}

func ListConfigurationReceiptsFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format) (out ConfigurationReceiptListResult) {
	base, err := newConfigurationQueryRefusal(core.ReceiptListOperation, nonce, format)
	out.PublicQueryResult = base
	if err != nil {
		return out
	}
	invoked := false
	err = capturedPublicQuery(ctx, path, format, func(pair *configuration.Pair) {
		invoked = true
		out = listConfigurationReceiptsWithIdentity(ctx, nonce, pair, NewDefaultReceiptReader, base)
	})
	if err != nil {
		out.Payload = nil
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "capture", err, invoked)
	}
	return out
}

// NewReceiptListRefusal creates a closed local refusal without source or provider access.
func NewReceiptListRefusal(format configuration.Format) (core.PublicReceiptListResult, error) {
	base, err := newConfigurationQueryRefusal(core.ReceiptListOperation, contract.ID{}, format)
	return core.PublicReceiptListResult{PublicQueryResult: base}, err
}

// ReadConfigurationReceipt reads one fixed authenticated observation without changing the input pair.
func ReadConfigurationReceipt(ctx context.Context, nonce contract.ID, pair *configuration.Pair, operationID contract.ID) ConfigurationReceiptDetailResult {
	return readConfigurationReceipt(ctx, nonce, pair, operationID, NewDefaultReceiptReader)
}

func readConfigurationReceipt(ctx context.Context, nonce contract.ID, pair *configuration.Pair, operationID contract.ID, open func(context.Context, ReceiptReaderConfig) (*core.InstalledReceiptReader, error)) ConfigurationReceiptDetailResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	base, err := newConfigurationQueryRefusal(core.ReceiptDetailOperation, nonce, format)
	out := ConfigurationReceiptDetailResult{PublicReceiptDetailResult: core.PublicReceiptDetailResult{PublicQueryResult: base}}
	if err != nil {
		return out
	}
	return readConfigurationReceiptWithIdentity(ctx, nonce, pair, operationID, open, base)
}

func readConfigurationReceiptWithIdentity(ctx context.Context, nonce contract.ID, pair *configuration.Pair, operationID contract.ID, open func(context.Context, ReceiptReaderConfig) (*core.InstalledReceiptReader, error), base core.PublicQueryResult) ConfigurationReceiptDetailResult {
	out := ConfigurationReceiptDetailResult{PublicReceiptDetailResult: core.PublicReceiptDetailResult{PublicQueryResult: base}}
	if open == nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", nil, false)
		return out
	}
	if operationID.IsZero() {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", nil, false)
		return out
	}
	c, pins, err := configurationPublicQueryInput(ctx, nonce, pair)
	if err != nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	out.DomainID, _ = capacityReaderScope(c)
	reader, err := open(ctx, ReceiptReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: pair.CheckUnchanged})
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", err, true)
		return out
	}
	releaseConfigurationReader(&c)
	defer reader.Close()
	result := reader.Detail(ctx, core.ReceiptDetailRequest{RequestNonce: nonce, OperationID: operationID})
	finishConfigurationQuery(&result.PublicQueryResult, base)
	return ConfigurationReceiptDetailResult{PublicReceiptDetailResult: result}
}

func ReadConfigurationReceiptFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, operationID contract.ID) (out ConfigurationReceiptDetailResult) {
	base, err := newConfigurationQueryRefusal(core.ReceiptDetailOperation, nonce, format)
	out.PublicQueryResult = base
	if err != nil || operationID.IsZero() {
		if err == nil {
			configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", nil, false)
		}
		return out
	}
	invoked := false
	err = capturedPublicQuery(ctx, path, format, func(pair *configuration.Pair) {
		invoked = true
		out = readConfigurationReceiptWithIdentity(ctx, nonce, pair, operationID, NewDefaultReceiptReader, base)
	})
	if err != nil {
		out.Payload = nil
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "capture", err, invoked)
	}
	return out
}

// NewReceiptDetailRefusal creates a closed local refusal without source or provider access.
func NewReceiptDetailRefusal(format configuration.Format) (core.PublicReceiptDetailResult, error) {
	base, err := newConfigurationQueryRefusal(core.ReceiptDetailOperation, contract.ID{}, format)
	return core.PublicReceiptDetailResult{PublicQueryResult: base}, err
}
