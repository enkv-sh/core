package compositionfull

import (
	"context"

	"enkv.sh/core"
)

func NewPlanning(ctx context.Context, c PlanningConfig) (*core.InstalledPlanning, error) {
	return newPlanning(ctx, c, false)
}

// NewDefaultPlanning selects standard credentials only after fixed interpretation.
func NewDefaultPlanning(ctx context.Context, c PlanningConfig) (*core.InstalledPlanning, error) {
	return newPlanning(ctx, c, true)
}

func newPlanning(ctx context.Context, c PlanningConfig, defaults bool) (*core.InstalledPlanning, error) {
	reader, err := readerConfigWithValidator(c.Reader)
	if err != nil {
		return nil, err
	}
	if !validPlanningConfig(c) {
		return nil, ErrCell
	}
	return newProviderPlanning(ctx, c, reader, defaults)
}
