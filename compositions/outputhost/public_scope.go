package outputhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// PublicValidationScope owns executable copies for one synchronous validation.
// Its zero value is ready for use. Close it after all calls to its validators
// return; construction and Close must not overlap validator calls.
type PublicValidationScope struct {
	executables []*publicExecutable
	closed      bool
}

type publicExecutable struct{ stage *artifactStage }

// NewValidator authenticates one exact installation for this scope. Calls still
// authenticate the installed source and retained executable before each launch.
func (s *PublicValidationScope) NewValidator(ctx context.Context, path string, installation *Installation) (*PublicValidator, error) {
	if s == nil || s.closed || ctx == nil || !filepath.IsAbs(path) || !installation.valid() {
		return nil, ErrAdmission
	}
	stage, _, err := stageInstallation(ctx, path, installation)
	if err != nil {
		return nil, err
	}
	executable := &publicExecutable{stage: stage}
	s.executables = append(s.executables, executable)
	return &PublicValidator{config: Config{ArtifactPath: path, Installation: installation}, retained: executable}, nil
}

// Close removes the retained executables. It reports every disposal failure.
// Validators from the closed scope cannot launch another child.
func (s *PublicValidationScope) Close() (resultErr error) {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	for _, executable := range s.executables {
		resultErr = errors.Join(resultErr, executable.stage.close())
		executable.stage = nil
	}
	s.executables = nil
	return resultErr
}

func (v *PublicValidator) preparePublicInvocation(ctx context.Context) (*artifactStage, string, error) {
	if v.retained == nil {
		stage, _, err := stageInstallation(ctx, v.config.ArtifactPath, v.config.Installation)
		if err != nil {
			return nil, "", err
		}
		return stage, stage.target, nil
	}
	stage := v.retained.stage
	if stage == nil {
		return nil, "", errors.Join(ErrAdmission, ErrArtifactUnavailable)
	}
	if err := authenticatePublicSource(ctx, v.config); err != nil {
		return nil, "", err
	}
	if err := authenticatePublicExecutable(ctx, stage, v.config.Installation); err != nil {
		return nil, "", err
	}
	// Executable storage is shared only within the scope. Each child gets an
	// empty working directory whose cleanup still belongs to that call.
	workspace, _, err := newTemporaryArtifactStage(ctx, ".launch-public", "output")
	if err != nil {
		return nil, "", err
	}
	return workspace, stage.target, nil
}

func authenticatePublicSource(ctx context.Context, config Config) (resultErr error) {
	source, cleanupErr, err := acquireRegularFile(ctx, config.ArtifactPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = errors.Join(ErrArtifactMissing, err)
		}
		return errors.Join(ErrAdmission, cleanupErr, err)
	}
	defer func() {
		if err := source.close(); err != nil {
			resultErr = errors.Join(resultErr, ErrArtifactUnavailable, err)
		}
	}()
	artifact := config.Installation.artifact
	if source.info.Mode().Perm()&0022 != 0 || uint64(source.info.Size()) != artifact.Length {
		return errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	if err := authenticateArtifact(ctx, source.file, artifact.SHA256, artifact.Length); err != nil {
		return err
	}
	return source.unchanged(ctx)
}

func authenticatePublicExecutable(ctx context.Context, stage *artifactStage, installation *Installation) (resultErr error) {
	for _, directory := range []struct {
		file *os.File
		path string
	}{
		{stage.rootFile, stage.ownedRoot},
		{stage.directory, stage.path},
	} {
		held, err := directory.file.Stat()
		named, namedErr := os.Lstat(directory.path)
		if err != nil || namedErr != nil || !named.IsDir() || !os.SameFile(held, named) || !ownedPrivate(held) || held.Mode().Perm() != 0700 {
			return errors.Join(ErrAdmission, ErrArtifactIdentity, err, namedErr)
		}
	}
	file, err := openNativeAt(ctx, stage.directory, filepath.Base(stage.target), unix.O_RDONLY, 0)
	if err != nil {
		return errors.Join(ErrAdmission, ErrArtifactIdentity, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, ErrArtifactUnavailable, err)
		}
	}()
	info, err := file.Stat()
	held, heldErr := stage.executable.Stat()
	named, namedErr := os.Lstat(stage.target)
	if err != nil || heldErr != nil || namedErr != nil || !named.Mode().IsRegular() || !os.SameFile(info, held) || !os.SameFile(info, named) || !ownedPrivate(info) || info.Mode().Perm() != 0500 {
		return errors.Join(ErrAdmission, ErrArtifactIdentity, err, heldErr, namedErr)
	}
	artifact := installation.artifact
	if err := authenticateArtifact(ctx, file, artifact.SHA256, artifact.Length); err != nil {
		return err
	}
	return verifyExecutableBuildInfo(ctx, file, installation)
}
