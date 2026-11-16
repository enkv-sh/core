//go:build !darwin && !linux

package plugininstallation

import "context"

func lock(context.Context, string) (func() error, error) { return nil, ErrIncompatible }
