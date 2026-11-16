// Package generatorhost owns the private native generator process boundary.
package generatorhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/generator"
)

type artifactFileReader struct {
	ctx  context.Context
	file *os.File
}

func (reader artifactFileReader) Read(body []byte) (int, error) {
	if reader.ctx != nil && reader.ctx.Err() != nil {
		return 0, reader.ctx.Err()
	}
	return reader.file.Read(body)
}

func (reader artifactFileReader) ReadAt(body []byte, offset int64) (int, error) {
	if reader.ctx != nil && reader.ctx.Err() != nil {
		return 0, reader.ctx.Err()
	}
	return reader.file.ReadAt(body, offset)
}

// Artifact failure sentinels support errors.Is. Missing or invalid evidence
// cannot supply installation readiness or invocation permission.
var (
	ErrArtifactMissing      = errors.New("generator artifact not installed")
	ErrArtifactIdentity     = errors.New("generator artifact identity mismatch")
	ErrArtifactIncompatible = errors.New("generator artifact incompatible")
	ErrArtifactPlatform     = errors.New("generator artifact platform mismatch")
	ErrArtifactUnavailable  = errors.New("generator artifact evidence unavailable")
)

// ValidateRuntimeImplementation checks the common family construction. It does
// not authenticate executable bytes or grant an invocation.
func ValidateRuntimeImplementation(v contract.GeneratorImplementation) error {
	if !validBoundImplementation(v) {
		return ErrAdmission
	}
	return nil
}
func validBoundImplementation(v contract.GeneratorImplementation) bool {
	return v.Validate() == nil && v.ProtocolID == contract.ID(protocol.ProtocolID()) && v.NativeTuple == runtime.GOOS+"/"+runtime.GOARCH
}

// VerifyInstalledArtifact authenticates captured bytes and their complete actual
// build information before credentials or child execution.
func VerifyInstalledArtifact(ctx context.Context, path string, installed *Installation) error {
	if ctx == nil || !filepath.IsAbs(path) || installed == nil {
		return errors.Join(ErrAdmission, ErrArtifactUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if installed.artifact.NativeTuple != runtime.GOOS+"/"+runtime.GOARCH {
		return errors.Join(ErrAdmission, ErrArtifactIncompatible, ErrArtifactPlatform)
	}
	return verifyArtifactBuildInfo(ctx, path, installed)
}
