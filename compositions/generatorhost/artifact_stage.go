package generatorhost

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
	remove                          func(string) error
	ownedRoot                       bool
	settlementUnproven              bool
}

// newArtifactStage consumes root, including when acquisition fails.
func newArtifactStage(ctx context.Context, root *os.File, name, executable string) (*artifactStage, error) {
	return newArtifactStageRoot(ctx, root, name, executable, false)
}
func newArtifactStageRoot(ctx context.Context, root *os.File, name, executable string, owned bool) (stage *artifactStage, resultErr error) {
	stage = &artifactStage{rootFile: root, ownedRoot: owned}
	settled := true
	defer func() {
		if resultErr != nil {
			closeErr := stage.close()
			resultErr = acquisitionFailure(errors.Join(resultErr, closeErr), settled && closeErr == nil)
			stage = nil
		}
	}()
	stage.root, resultErr = os.OpenRoot(root.Name())
	if resultErr != nil {
		// OpenRoot can dispose helper-local handles without a separate close result.
		settled = false
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
		settled = acquisitionSettled(resultErr)
		return stage, errors.Join(ErrAdmission, resultErr)
	}
	directoryInfo, err := stage.directory.Stat()
	if err != nil || !directoryInfo.IsDir() || !fileOwnedByCurrentUID(directoryInfo) || directoryInfo.Mode().Perm() != 0700 {
		return stage, errors.Join(ErrAdmission, err)
	}
	return stage, nil
}

func newTemporaryArtifactStage(ctx context.Context, name, executable string) (*artifactStage, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, acquisitionFailure(ctx.Err(), true)
	}
	parent, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, acquisitionFailure(errors.Join(ErrAdmission, err), true)
	}
	path, err := os.MkdirTemp(parent, "enkv-generator-")
	if err != nil {
		return nil, acquisitionFailure(errors.Join(ErrAdmission, err), true)
	}
	root, err := openNativeFile(context.Background(), path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, acquisitionFailure(fmt.Errorf("%w: %w: temporary root retained at %s: %w", ErrAdmission, ErrArtifactUnavailable, path, err), false)
	}
	return newArtifactStageRoot(ctx, root, name, executable, true)
}

func (s *artifactStage) close() error {
	removal, resources := s.dispose()
	return errors.Join(removal, resources)
}

func (s *artifactStage) dispose() (removalErr, resourceErr error) {
	if s == nil {
		return nil, nil
	}
	if s.name != "" {
		var removal error
		if s.remove != nil {
			removal = s.remove(s.path)
		} else {
			removal = s.root.RemoveAll(s.name)
		}
		if removal != nil {
			removalErr = fmt.Errorf("%w: %w: %w", ErrProcess, errStagingCleanup, removal)
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
	if s.rootFile != nil && s.ownedRoot {
		held, heldErr := s.rootFile.Stat()
		named, namedErr := os.Lstat(s.rootFile.Name())
		if heldErr != nil || namedErr != nil || !named.IsDir() || !os.SameFile(held, named) {
			resourceErr = errors.Join(resourceErr, errStagingCleanup, ErrArtifactUnavailable, heldErr, namedErr)
		} else if err := os.Remove(s.rootFile.Name()); err != nil {
			removalErr = errors.Join(removalErr, ErrProcess, errStagingCleanup, err)
		}
		s.ownedRoot = false
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
		s.settlementUnproven = !acquisitionSettled(err)
		return errors.Join(ErrAdmission, err)
	}
	s.executable = file
	info, err := file.Stat()
	if err != nil || !fileOwnedByCurrentUID(info) || info.Mode().Perm() != 0500 {
		return errors.Join(ErrAdmission, err)
	}
	if err := authenticateArtifact(ctx, file, want, length); err != nil {
		return err
	}
	return nil
}
