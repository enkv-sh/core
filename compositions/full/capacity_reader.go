package compositionfull

import (
	"context"

	"enkv.sh/core"
)

type CapacityReaderConfig struct {
	ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
}

func NewCapacityReader(ctx context.Context, c CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
	if !validReaderConfig(c.ReaderConfig) {
		return nil, ErrCell
	}
	return newProviderCapacityReader(ctx, c, false)
}

func NewDefaultCapacityReader(ctx context.Context, c CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
	if !validReaderConfig(c.ReaderConfig) {
		return nil, ErrCell
	}
	return newProviderCapacityReader(ctx, c, true)
}
