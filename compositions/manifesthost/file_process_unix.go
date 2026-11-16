//go:build (darwin || linux) && cgo

package manifesthost

import (
	"context"
	"errors"
	"os"

	"enkv.sh/compositions/internal/nativeprocess"
)

func startNativeChild(ctx context.Context, path, directory, entrypoint string, files []*os.File) (*nativeprocess.Child, error) {
	child, err := nativeprocess.Start(ctx, path, directory, entrypoint, files)
	switch err {
	case nativeprocess.ErrAdmission:
		err = ErrAdmission
	case nativeprocess.ErrProcess:
		err = ErrProcess
	default:
		if errors.Is(err, nativeprocess.ErrAdmission) {
			err = errors.Join(ErrAdmission, err)
		}
		if errors.Is(err, nativeprocess.ErrProcess) {
			err = errors.Join(ErrProcess, err)
		}
	}
	return child, err
}
