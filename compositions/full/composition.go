// Package compositionfull assembles exact provider cells. Each domain uses
// one paired cell; construction never searches, mixes providers or fails over.
package compositionfull

import (
	"context"
	"errors"

	"enkv.sh/core/contract"
)

var ErrCell = errors.New("unsupported full composition cell")

// LoadDefaultConfig selects the standard source only for the chosen domain cell.
func LoadDefaultConfig(ctx context.Context, c Config) (Config, error) {
	if !validConfig(c) {
		return Config{}, ErrCell
	}
	return loadDefaultConfig(ctx, c)
}
func New(ctx context.Context, c Config) (contract.Cell, error) {
	if !validConfig(c) {
		return contract.Cell{}, ErrCell
	}
	return newCell(ctx, c)
}

// NewAuthority keeps the exact provider pair and class checks while leaving
// private KEK and effect construction outside an administrative operation.
func NewAuthority(ctx context.Context, c Config) (contract.Store, contract.Trust, error) {
	if !validConfig(c) {
		return nil, nil, ErrCell
	}
	return newAuthority(ctx, c)
}
