package compositionfull

import (
	"context"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
)

func prepareMissingCompanion(ctx context.Context, request PrepareRequest, result *PrepareResult, open func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error)) error {
	output, source, err := configuration.BeginCompanionReconstruction(ctx, request.Source, request.Format)
	if err != nil {
		if !result.occupiedFailure(err) {
			result.sourceFailure(ctx, err, false)
		}
		return err
	}
	return prepareReconstructionOutput(ctx, request, result, open, output, source)
}

func prepareRecoveryLayoutMatches(request PrepareRecoveryRequest, source *configuration.Model) bool {
	return request.Name == source.DomainName && request.Provider == source.Provider && request.Bucket == source.Store.Bucket &&
		request.Region == source.Store.Region && request.Prefix != nil && *request.Prefix == source.Store.PrefixBeforeHEAD &&
		(request.ExpectedOwner == nil || *request.ExpectedOwner == source.Store.ExpectedOwner)
}
