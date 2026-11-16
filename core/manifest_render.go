package core

import (
	"context"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

func renderManifestArtifact(ctx context.Context, projection *manifest.Projection, renderer manifest.Renderer) ([]byte, manifest.Metadata, readerFailure) {
	if renderer == nil {
		return nil, manifest.Metadata{}, manifestSDKFailure(manifest.InvalidInput)
	}
	if failure := manifest.Validate(ctx, projection); failure != "" {
		return nil, manifest.Metadata{}, manifestSDKFailure(failure)
	}
	result := renderer(ctx, manifest.Borrow(projection))
	transferred := false
	defer func() {
		if !transferred {
			clear(result.Artifact[:cap(result.Artifact)])
		}
	}()
	if failure := manifest.ValidateResult(result); failure != "" {
		return nil, manifest.Metadata{}, manifestSDKFailure(failure)
	}
	if result.Failure != "" {
		return nil, manifest.Metadata{}, manifestSDKFailure(result.Failure)
	}
	metadata, failure := manifest.MeasureArtifact(ctx, result.Artifact)
	if failure != "" {
		return nil, manifest.Metadata{}, manifestSDKFailure(failure)
	}
	transferred = true
	return result.Artifact, metadata, readerFailure{}
}

func manifestSDKFailure(failure manifest.Failure) readerFailure {
	switch failure {
	case manifest.Cancelled:
		return readerRefusal(contract.ReasonCancelled)
	case manifest.Expired:
		return readerRefusal(contract.ReasonExpired)
	case manifest.InvalidUTF8:
		return manifestInputFailure(contract.ReasonInvalidUTF8)
	case manifest.LimitExceeded:
		return manifestInputFailure(contract.ReasonLimitExceeded)
	default:
		return manifestInputFailure(contract.ReasonInvalidInput)
	}
}
