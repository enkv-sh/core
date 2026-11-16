package outputhost

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"enkv.sh/sdk/artifact"
	"golang.org/x/sys/unix"
)

type artifactStage struct {
	root                            *os.Root
	rootFile, directory, executable *os.File
	name, path, target              string
	ownedRoot                       string
}

type executableCleanupFailure struct{ cause error }

func (e *executableCleanupFailure) Error() string { return e.cause.Error() }
func (e *executableCleanupFailure) Unwrap() error { return e.cause }
func (e *executableCleanupFailure) ExecutableCleanupFailed() bool {
	return e != nil
}

func executableCleanupError(cause error) error {
	if cause == nil {
		return nil
	}
	return &executableCleanupFailure{cause: cause}
}

// newArtifactStage consumes root, including when acquisition fails.
func newArtifactStage(ctx context.Context, root *os.File, name, executable string) (stage *artifactStage, resultErr error) {
	stage, resultErr = createArtifactStage(ctx, &artifactStage{rootFile: root}, name, executable)
	if resultErr != nil {
		resultErr = errors.Join(resultErr, stage.close())
		stage = nil
	}
	return stage, resultErr
}

func createArtifactStage(ctx context.Context, stage *artifactStage, name, executable string) (result *artifactStage, resultErr error) {
	root := stage.rootFile
	stage.root, resultErr = os.OpenRoot(root.Name())
	if resultErr != nil {
		return stage, errors.Join(ErrAdmission, resultErr)
	}
	// Creation and removal must use the same directory, even if its name moved.
	info, err := root.Stat()
	opened, statErr := stage.root.Stat(".")
	if err != nil || statErr != nil || !os.SameFile(info, opened) {
		return stage, errors.Join(ErrAdmission, err, statErr)
	}
	if err := unix.Mkdirat(int(root.Fd()), name, 0700); err != nil {
		return stage, errors.Join(ErrAdmission, err)
	}
	stage.name = name
	stage.path = filepath.Join(root.Name(), name)
	stage.target = filepath.Join(stage.path, executable)
	stage.directory, resultErr = openNativeAt(ctx, root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if resultErr != nil {
		return stage, errors.Join(ErrAdmission, resultErr)
	}
	directoryInfo, err := stage.directory.Stat()
	if err != nil || !directoryInfo.IsDir() || !ownedPrivate(directoryInfo) || directoryInfo.Mode().Perm() != 0700 {
		return stage, errors.Join(ErrAdmission, err)
	}
	return stage, nil
}

func newTemporaryArtifactStage(ctx context.Context, name, executable string) (stage *artifactStage, cleanupErr, resultErr error) {
	temporary, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, nil, errors.Join(ErrAdmission, err)
	}
	path, err := os.MkdirTemp(temporary, ".enkv-output-stage-")
	if err != nil {
		return nil, nil, errors.Join(ErrAdmission, err)
	}
	created, err := os.Lstat(path)
	if err != nil {
		cleanupErr = executableCleanupError(errors.Join(ErrProcess, errStagingCleanup, err))
		return nil, cleanupErr, errors.Join(ErrAdmission, err, cleanupErr)
	}
	root, err := openNativeFile(ctx, path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		cleanupErr = removeTemporaryRoot(path, created)
		return nil, cleanupErr, errors.Join(ErrAdmission, err, cleanupErr)
	}
	stage = &artifactStage{rootFile: root, ownedRoot: path}
	defer func() {
		if resultErr != nil {
			cleanupErr = errors.Join(cleanupErr, stage.close())
			resultErr = errors.Join(resultErr, cleanupErr)
			stage = nil
		}
	}()
	info, err := root.Stat()
	if err != nil || !os.SameFile(created, info) || !ownedPrivate(info) || info.Mode().Perm() != 0700 {
		return stage, nil, errors.Join(ErrAdmission, err)
	}
	stage, resultErr = createArtifactStage(ctx, stage, name, executable)
	return stage, nil, resultErr
}

func removeTemporaryRoot(path string, held os.FileInfo) error {
	named, err := os.Lstat(path)
	if err != nil || held == nil || !os.SameFile(held, named) {
		return executableCleanupError(errors.Join(ErrProcess, errStagingCleanup, err))
	}
	if err := os.Remove(path); err != nil {
		return executableCleanupError(errors.Join(ErrProcess, errStagingCleanup, err))
	}
	return nil
}

func (s *artifactStage) close() error {
	removalErr, resourceErr := s.closeOutcome()
	return errors.Join(removalErr, resourceErr)
}

func (s *artifactStage) closeOutcome() (removalErr, resourceErr error) {
	if s == nil {
		return nil, nil
	}
	if s.name != "" {
		removal := s.root.RemoveAll(s.name)
		if removal != nil {
			removalErr = executableCleanupError(fmt.Errorf("%w: %w: %w", ErrProcess, errStagingCleanup, removal))
		}
		s.name = ""
	}
	if s.executable != nil {
		resourceErr = errors.Join(resourceErr, s.executable.Close())
		s.executable = nil
	}
	if s.directory != nil {
		resourceErr = errors.Join(resourceErr, s.directory.Close())
		s.directory = nil
	}
	if s.root != nil {
		resourceErr = errors.Join(resourceErr, s.root.Close())
		s.root = nil
	}
	if s.ownedRoot != "" {
		info, err := s.rootFile.Stat()
		if err != nil {
			removalErr = errors.Join(removalErr, executableCleanupError(errors.Join(ErrProcess, errStagingCleanup, err)))
		} else {
			removalErr = errors.Join(removalErr, removeTemporaryRoot(s.ownedRoot, info))
		}
		s.ownedRoot = ""
	}
	if s.rootFile != nil {
		resourceErr = errors.Join(resourceErr, s.rootFile.Close())
		s.rootFile = nil
	}
	return removalErr, resourceErr
}

func authenticateArtifact(ctx context.Context, file *os.File, want [32]byte, length uint64) error {
	if length == 0 || length > artifact.MaxExecutableBytes {
		return ErrAdmission
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Join(ErrAdmission, ErrArtifactUnavailable, err)
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != length {
		return errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.Join(ErrAdmission, err)
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(artifactFileReader{ctx, file}, int64(length)+1))
	if err != nil {
		return errors.Join(ErrAdmission, ErrArtifactUnavailable, err)
	}
	if uint64(count) != length {
		return errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	var got [32]byte
	copy(got[:], hash.Sum(nil))
	if got != want {
		return errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (s *artifactStage) authenticate(ctx context.Context, want [32]byte, length uint64) error {
	file, err := openNativeAt(ctx, s.directory, filepath.Base(s.target), unix.O_RDONLY, 0)
	if err != nil {
		return errors.Join(ErrAdmission, err)
	}
	s.executable = file
	info, err := file.Stat()
	if err != nil || !ownedPrivate(info) || info.Mode().Perm() != 0500 {
		return errors.Join(ErrAdmission, err)
	}
	if err := authenticateArtifact(ctx, file, want, length); err != nil {
		return err
	}
	return nil
}
