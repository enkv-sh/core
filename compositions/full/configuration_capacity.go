package compositionfull

import (
	"context"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func InspectConfigurationCapacity(ctx context.Context, request core.CapacityInspectionRequest, pair *configuration.Pair) ConfigurationCapacityResult {
	return inspectConfigurationCapacity(ctx, request, pair, NewDefaultCapacityReader)
}

func inspectConfigurationCapacity(ctx context.Context, request core.CapacityInspectionRequest, pair *configuration.Pair, open func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error)) (out ConfigurationCapacityResult) {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	base, err := newConfigurationQueryRefusal(core.InspectCapacityOperation, request.RequestNonce, format)
	out.PublicQueryResult = base
	if err != nil || open == nil {
		if err == nil {
			configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", nil, false)
		}
		return out
	}
	return inspectConfigurationCapacityWithIdentity(ctx, request, pair, open, base)
}

func inspectConfigurationCapacityWithIdentity(ctx context.Context, request core.CapacityInspectionRequest, pair *configuration.Pair, open func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error), base core.PublicQueryResult) (out ConfigurationCapacityResult) {
	out.PublicQueryResult = base
	if open == nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", nil, false)
		return out
	}
	c, pins, err := configurationPublicQueryInput(ctx, request.RequestNonce, pair)
	if err != nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	domain, store := capacityReaderScope(c)
	out.DomainID = domain
	// Decode the scoped wrapper before a default reader loads credentials.
	if _, err := core.DecodeGCCursor(request.Cursor, domain, store); err != nil {
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	reader, err := open(ctx, CapacityReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: pair.CheckUnchanged})
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "construction", err, true)
		return out
	}
	releaseConfigurationReader(&c)
	defer reader.Close()
	out.PublicCapacityInspectionResult = reader.InspectCapacity(ctx, request)
	finishConfigurationQuery(&out.PublicQueryResult, base)
	return out
}

func InspectConfigurationCapacityFile(ctx context.Context, request core.CapacityInspectionRequest, path string, format configuration.Format) (out ConfigurationCapacityResult) {
	base, err := newConfigurationQueryRefusal(core.InspectCapacityOperation, request.RequestNonce, format)
	out.PublicQueryResult = base
	if err != nil {
		return out
	}
	invoked := false
	err = capturedPublicQuery(ctx, path, format, func(pair *configuration.Pair) {
		invoked = true
		out = inspectConfigurationCapacityWithIdentity(ctx, request, pair, NewDefaultCapacityReader, base)
	})
	if err != nil {
		out.View = nil
		configurationQueryFailure(ctx, &out.PublicQueryResult, &out.SourceFailure, "capture", err, invoked)
	}
	return out
}

func NewCapacityInspectionRefusal(format configuration.Format) (core.PublicCapacityInspectionResult, error) {
	base, err := newConfigurationQueryRefusal(core.InspectCapacityOperation, contract.ID{}, format)
	return core.PublicCapacityInspectionResult{PublicQueryResult: base}, err
}
