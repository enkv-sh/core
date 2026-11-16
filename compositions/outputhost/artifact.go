// Package outputhost owns the native output process and private pipe boundary.
package outputhost

import (
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unicode/utf8"

	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
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

// Admission and artifact failure sentinels support errors.Is. They classify
// local evidence failures and do not describe a provider effect.
var (
	ErrAdmission            = errors.New("output artifact admission refused")
	ErrArtifactMissing      = errors.New("output artifact not installed")
	ErrArtifactIdentity     = errors.New("output artifact identity mismatch")
	ErrArtifactIncompatible = errors.New("output artifact incompatible")
	ErrArtifactPlatform     = errors.New("output artifact platform mismatch")
	ErrArtifactUnavailable  = errors.New("output artifact evidence unavailable")
)

// Artifact contains scalar measured-build and declared-contract facts. It
// contains no executable bytes or source-authentication proof; obtain it from
// an Installation rather than constructing invocation authority from these fields.
type Artifact struct {
	Schema                                                      uint16
	ProtocolID, DescriptorID, ArtifactContractID                protocol.ID
	ExecutorID, CredentialRouteID, DependencyManifestID, SHA256 protocol.ID
	Length                                                      uint64
	ConfigContractID, CredentialRouteContractID                 string
	ModulePath, CommandPath, GoVersion, NativeTuple             string
}

func (a Artifact) valid() bool {
	if a.Schema != artifact.FamilySchema || a.ProtocolID != protocol.ProtocolID() || a.DescriptorID.IsZero() || a.ArtifactContractID.IsZero() ||
		a.ExecutorID.IsZero() || a.CredentialRouteID.IsZero() || a.DependencyManifestID.IsZero() || a.SHA256.IsZero() || a.Length == 0 || a.Length > artifact.MaxExecutableBytes ||
		a.NativeTuple != runtime.GOOS+"/"+runtime.GOARCH || !validManifestString(a.ModulePath, true) || !validManifestString(a.CommandPath, true) || !validManifestString(a.GoVersion, true) ||
		len(a.ConfigContractID) == 0 || len(a.ConfigContractID) > artifact.MaxSemanticBytes || !utf8.ValidString(a.ConfigContractID) {
		return false
	}
	route, err := artifact.ParseDigest(a.CredentialRouteContractID)
	return err == nil && !route.IsZero()
}

// VerifyInstalledArtifact authenticates one captured installation without
// opening credentials or launching a process.
func VerifyInstalledArtifact(ctx context.Context, path string, installation *Installation) error {
	if ctx == nil || !filepath.IsAbs(path) || installation == nil {
		return errors.Join(ErrAdmission, ErrArtifactUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if installation.artifact.NativeTuple != runtime.GOOS+"/"+runtime.GOARCH {
		return errors.Join(ErrAdmission, ErrArtifactIncompatible, ErrArtifactPlatform)
	}
	if !installation.valid() {
		return errors.Join(ErrAdmission, ErrArtifactIncompatible)
	}
	return verifyArtifactBuildInfo(ctx, path, installation)
}

func verifyArtifactBuildInfo(ctx context.Context, path string, installation *Installation) (resultErr error) {
	stage, _, err := stageInstallation(ctx, path, installation)
	if err != nil {
		return err
	}
	defer func() {
		if err := stage.close(); err != nil {
			resultErr = errors.Join(resultErr, ErrArtifactUnavailable, err)
		}
		if ctx != nil {
			resultErr = errors.Join(resultErr, ctx.Err())
		}
	}()
	return nil
}

func stageInstallation(ctx context.Context, path string, installation *Installation) (stage *artifactStage, cleanupErr, resultErr error) {
	if !installation.valid() {
		return nil, nil, ErrAdmission
	}
	stage, cleanupErr, err := stageArtifact(ctx, path, installation.artifact)
	if err != nil {
		return nil, cleanupErr, err
	}
	defer func() {
		if resultErr != nil {
			cleanupErr = errors.Join(cleanupErr, stage.close())
			resultErr = errors.Join(resultErr, cleanupErr)
			stage = nil
		}
	}()
	return stage, cleanupErr, verifyExecutableBuildInfo(ctx, stage.executable, installation)
}

func verifyExecutableBuildInfo(ctx context.Context, executable *os.File, installation *Installation) error {
	info, err := buildinfo.Read(io.NewSectionReader(artifactFileReader{ctx, executable}, 0, int64(installation.artifact.Length)))
	if err != nil {
		if ctx != nil {
			err = errors.Join(err, ctx.Err())
		}
		return errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := verifyArtifactInfo(info, installation.manifest); err != nil {
		return errors.Join(ErrAdmission, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
