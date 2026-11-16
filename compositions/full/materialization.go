package compositionfull

import (
	"context"

	"enkv.sh/core"
	"enkv.sh/crypto"
)

type MaterializationConfig struct {
	ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
	Target      *crypto.MaterializationFileTarget
}

// NewMaterialization installs one read-only Recipient operation and exact native target.
func NewMaterialization(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
	if !validReaderConfig(c.ReaderConfig) {
		return nil, ErrCell
	}
	return newProviderMaterialization(ctx, c, false)
}

// NewDefaultMaterialization uses the selected provider's standard credential source.
func NewDefaultMaterialization(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
	if !validReaderConfig(c.ReaderConfig) {
		return nil, ErrCell
	}
	return newProviderMaterialization(ctx, c, true)
}
