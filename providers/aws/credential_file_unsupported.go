//go:build !darwin && !linux

package awsprovider

import (
	"context"
	"errors"
	"os"
)

func openCredentialFile(context.Context, string) (*os.File, error) {
	return nil, errors.New("credential files are unsupported on this platform")
}

func credentialFileInfoStable(os.FileInfo, os.FileInfo) bool { return false }
