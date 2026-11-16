//go:build darwin || linux

package manifesthost

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
	"golang.org/x/sys/unix"
)

type executableStage struct {
	parent, directory  *os.Root
	executable         *os.File
	identity           artifact.DigestLength
	info               os.FileInfo
	path, target, name string
}

func private(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}

func stageExecutable(ctx context.Context, path string, identity artifact.DigestLength) (result *executableStage, resultErr error) {
	if ctx == nil || ctx.Err() != nil || identity.Length == 0 || identity.Length > artifact.MaxExecutableBytes || !filepath.IsAbs(path) {
		return nil, ErrAdmission
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(ErrAdmission, err)
	}
	source := os.NewFile(uintptr(fd), path)
	defer func() {
		resultErr = errors.Join(resultErr, source.Close())
		if resultErr != nil && result != nil {
			resultErr = errors.Join(resultErr, result.close())
			result = nil
		}
	}()
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || uint64(before.Size()) != identity.Length {
		return nil, errors.Join(ErrAdmission, err)
	}
	stage := &executableStage{identity: identity}
	transferred := false
	defer func() {
		if !transferred {
			resultErr = errors.Join(resultErr, stage.close())
		}
	}()
	temporary, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, errors.Join(ErrAdmission, err)
	}
	stage.parent, err = os.OpenRoot(temporary)
	if err != nil {
		return nil, err
	}
	stage.path, err = os.MkdirTemp(temporary, "enkv-manifest-")
	if err != nil {
		return nil, err
	}
	stage.target = filepath.Join(stage.path, "plugin")
	stage.name = filepath.Base(stage.path)
	stage.info, err = stage.parent.Lstat(stage.name)
	if err != nil || !stage.info.IsDir() || !private(stage.info) || stage.info.Mode().Perm() != 0700 {
		return nil, errors.Join(ErrAdmission, err)
	}
	stage.directory, err = os.OpenRoot(stage.path)
	if err != nil {
		return nil, err
	}
	opened, err := stage.directory.Stat(".")
	if err != nil || !os.SameFile(stage.info, opened) {
		return nil, errors.Join(ErrAdmission, err)
	}
	file, err := stage.directory.OpenFile("plugin", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	var window [manifest.PlainWindowBytes]byte
	defer clear(window[:])
	hash := sha256.New()
	var copied uint64
	for copied < identity.Length {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, file.Close())
		}
		n, readErr := source.Read(window[:min(uint64(len(window)), identity.Length-copied)])
		if n > 0 {
			written, writeErr := file.Write(window[:n])
			if writeErr != nil || written != n {
				return nil, errors.Join(io.ErrShortWrite, writeErr, file.Close())
			}
			_, _ = hash.Write(window[:n])
			copied += uint64(n)
		}
		if readErr != nil && (readErr != io.EOF || copied != identity.Length) {
			return nil, errors.Join(readErr, file.Close())
		}
		if n == 0 {
			return nil, errors.Join(io.ErrNoProgress, file.Close())
		}
	}
	var extra [1]byte
	n, eof := source.Read(extra[:])
	if n != 0 || eof != io.EOF {
		return nil, errors.Join(ErrAdmission, eof, file.Close())
	}
	if artifact.Digest(hash.Sum(nil)) != identity.SHA256 {
		return nil, errors.Join(ErrAdmission, file.Close())
	}
	after, statErr := source.Stat()
	named, nameErr := os.Lstat(path)
	if statErr != nil || nameErr != nil || !os.SameFile(before, after) || !os.SameFile(after, named) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() || !named.Mode().IsRegular() {
		return nil, errors.Join(ErrAdmission, statErr, nameErr, file.Close())
	}
	modeErr := file.Chmod(0500)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(modeErr, syncErr, closeErr); err != nil {
		return nil, err
	}
	stage.executable, err = stage.directory.Open("plugin")
	if err != nil {
		return nil, err
	}
	if err := stage.authenticate(ctx); err != nil {
		return nil, err
	}
	transferred = true
	return stage, nil
}

func (s *executableStage) current() error {
	if s == nil || s.parent == nil || s.info == nil {
		return ErrAdmission
	}
	named, err := s.parent.Lstat(s.name)
	if err != nil || !named.IsDir() || !os.SameFile(s.info, named) {
		return errors.Join(ErrAdmission, err)
	}
	return nil
}
func (s *executableStage) authenticate(ctx context.Context) error {
	if err := s.current(); err != nil {
		return err
	}
	info, err := s.executable.Stat()
	named, nameErr := s.directory.Lstat("plugin")
	if err != nil || nameErr != nil || !info.Mode().IsRegular() || !private(info) || info.Mode().Perm() != 0500 || uint64(info.Size()) != s.identity.Length || !os.SameFile(info, named) {
		return errors.Join(ErrAdmission, err, nameErr)
	}
	if _, err := s.executable.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var window [manifest.PlainWindowBytes]byte
	defer clear(window[:])
	hash := sha256.New()
	var count uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := s.executable.Read(window[:])
		if n > 0 {
			count += uint64(n)
			if count > s.identity.Length {
				return ErrAdmission
			}
			_, _ = hash.Write(window[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	if count != s.identity.Length || artifact.Digest(hash.Sum(nil)) != s.identity.SHA256 {
		return ErrAdmission
	}
	return ctx.Err()
}
func (s *executableStage) close() error {
	if s == nil {
		return nil
	}
	var result error
	if s.name != "" && s.parent != nil {
		if err := s.current(); err != nil {
			result = errors.Join(result, err)
		} else {
			result = errors.Join(result, s.parent.RemoveAll(s.name))
		}
	}
	if s.executable != nil {
		result = errors.Join(result, s.executable.Close())
		s.executable = nil
	}
	if s.directory != nil {
		result = errors.Join(result, s.directory.Close())
		s.directory = nil
	}
	if s.parent != nil {
		result = errors.Join(result, s.parent.Close())
		s.parent = nil
	}
	s.name = ""
	return result
}
