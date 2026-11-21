package compositionfull

import (
	"context"

	"enkv.sh/core"
)

func NewReader(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
	installed, err := readerConfigWithValidator(c)
	if err != nil {
		return nil, err
	}
	return newProviderReader(ctx, installed, false)
}

// NewDefaultReader selects standard Store credentials with the supplied public interpreter.
func NewDefaultReader(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
	installed, err := readerConfigWithValidator(c)
	if err != nil {
		return nil, err
	}
	return newProviderReader(ctx, installed, true)
}

func readerConfigWithValidator(c ReaderConfig) (ReaderConfig, error) {
	if !validReaderConfig(c) {
		return ReaderConfig{}, ErrCell
	}
	validator := c.checkedRoutes
	if validator == nil {
		validator = core.NewPublicConfigurationValidator(c.InterpretOutput)
	}
	return providerReaderConfigWithValidator(c, validator, c.PrepareManifestRenderer), nil
}
