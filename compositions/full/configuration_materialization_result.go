package compositionfull

import (
	"context"
	"enkv.sh/core"
	"io"
)

type ConfigurationMaterializationResult struct {
	core.MaterializationResult
	SourceFailure *ConfigurationSourceFailure
}

func (r ConfigurationMaterializationResult) WriteJSON(ctx context.Context, out io.Writer) error {
	return writeMaterialization(ctx, out, r.MaterializationResult, false, r.SourceFailure)
}
func (r ConfigurationMaterializationResult) WriteHuman(ctx context.Context, out io.Writer) error {
	return writeMaterialization(ctx, out, r.MaterializationResult, true, r.SourceFailure)
}
