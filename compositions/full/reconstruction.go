package compositionfull

import (
	"context"

	core "enkv.sh/core"
)

func NewReconstruction(ctx context.Context, c ReconstructionConfig) (*core.ReconstructionEngine, error) {
	if !validReconstructionConfig(c) {
		return nil, ErrCell
	}
	return newProviderReconstruction(ctx, c, false)
}

func NewDefaultReconstruction(ctx context.Context, c ReconstructionConfig) (*core.ReconstructionEngine, error) {
	if !validReconstructionConfig(c) {
		return nil, ErrCell
	}
	return newProviderReconstruction(ctx, c, true)
}
